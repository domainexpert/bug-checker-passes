//=== StringLiteralWrite.cpp - C Secure Coding Guideline Violation Detector
//===//
//
//                     Security Analysis
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// According to Rule STR30-C of SEI CERT C Coding Standard at
// https://www.securecoding.cert.org/confluence/display/c/SEI+CERT+C+Coding+Standard
// do not attempt to modify string literals.
//
// This analysis detects such violations locally (intra-procedurally).
//
//===----------------------------------------------------------------------===//

#include "StringLiteralWrite.h"

#define DEBUG_TYPE "string-literal-write"
#include "llvm/DebugInfo.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "../../IR/ConstantsContext.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
namespace {
struct StringLiteralWrite : public FunctionPass {
  static char ID;

  StringLiteralWrite() : FunctionPass(ID) {}
  virtual bool runOnFunction(Function &func) {
    AliasAnalysis &AA = getAnalysis<AliasAnalysis>();
    std::vector<Value *> inboundsGepList;

    // In the first step of the analysis, we collect all
    // string literal values.
    for (auto &bb: func) {
      for (auto &i: bb) {
    	switch(i.getOpcode()) {
        case Instruction::GetElementPtr: {
          GetElementPtrInst *inst = dyn_cast<GetElementPtrInst>(&i);
          if (inst->isInBounds()) {
            GlobalVariable *var = dyn_cast<GlobalVariable>(inst->getOperand(0));
            if (var && isa<ConstantDataArray>(var)) {
              inboundsGepList.push_back(inst);
            }
          }
          break;
        }
        default: {
          for (unsigned opIdx = 0, opIdxEnd = i.getNumOperands();
               opIdx < opIdxEnd; ++opIdx) {
            GetElementPtrConstantExpr *expr =
                dyn_cast<GetElementPtrConstantExpr>(i.getOperand(opIdx));
            if (expr) {
              GlobalVariable *var =
                  dyn_cast<GlobalVariable>(expr->getOperand(0));
              if (var && isa<ConstantDataArray>(var->getInitializer())) {
                inboundsGepList.push_back(i.getOperand(opIdx));
              }
            }
          }
          break;
        }
        }
      }
    }

    // In the second step of the analysis we check the aliasing of store
    // instructions pointer arguments to the collected string literals.
    for (auto &bb: func) {
      for (auto &i : bb) {
        if (i.getOpcode() == Instruction::Store) {
          StoreInst *inst = dyn_cast<StoreInst>(&i);
          AliasAnalysis::Location loc1(inst->getPointerOperand());
          for (std::vector<Value *>::iterator
                   gepIter = inboundsGepList.begin(),
                   gepIterEnd = inboundsGepList.end();
               gepIter != gepIterEnd; ++gepIter) {
            AliasAnalysis::Location loc2(*gepIter);
            switch (AA.alias(loc1, loc2)) {
            case AliasAnalysis::MayAlias: {
              if (MDNode *n =
                      i.getMetadata("dbg")) { // Here I is an LLVM instruction
                DILocation loc(n);             // DILocation is in DebugInfo.h
                unsigned line = loc.getLineNumber();
                StringRef file = loc.getFilename();
                StringRef dir = loc.getDirectory();
                llvm::errs() << "Line " << line << " of " << dir.str() << "/"
                             << file.str() << ": Write into string literal\n";
              } else {
                llvm::errs() << "Write into string literal in function "
                             << func.getName().str() << "\n";
              }
              gepIter = --(inboundsGepList.end());
              break;
            }
            default: { break; }
            }
          }
        }
      }
    }

    return false;
  }

  virtual void getAnalysisUsage(AnalysisUsage &AU) const {
    AU.addRequiredTransitive<AliasAnalysis>();
    AU.addPreserved<AliasAnalysis>();
  }
};
}
char StringLiteralWrite::ID = 0;
static RegisterPass<StringLiteralWrite> X("string-literal-write", "Detects writes into string literals");
