//===----- BadCast.cpp - C Secure Coding Guideline Violation Detector -----===//
//
//                     Security Analysis
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// According to Rule EXP36-C of SEI CERT C Coding Standard at
// https://www.securecoding.cert.org/confluence/display/c/SEI+CERT+C+Coding+Standard
// Do not cast pointers into more strictly aligned pointer types.
//
// This analysis detects such violations.
//
//===----------------------------------------------------------------------===//

#include "BadCast.h"

#define DEBUG_TYPE "bad-cast"
#include "llvm/DebugInfo.h"
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include <map>

using namespace llvm;
namespace {
struct BadCast : public FunctionPass {
  static char ID;

  BadCast() : FunctionPass(ID) {}
  virtual bool runOnFunction(Function &F) {
    for (auto &bb: F) {
      for (auto &i: bb) {
        if (i.getOpcode() == Instruction::BitCast) {
          BitCastInst *bcInstr = dyn_cast<BitCastInst>(&i);
          PointerType *srcType = dyn_cast<PointerType>(bcInstr->getSrcTy());
          PointerType *dstType = dyn_cast<PointerType>(bcInstr->getDestTy());
          if (srcType && dstType) {
            IntegerType *srcElemType =
                dyn_cast<IntegerType>(srcType->getElementType());
            IntegerType *dstElemType =
                dyn_cast<IntegerType>(dstType->getElementType());
            if (srcElemType && dstElemType) {
              unsigned srcWidth = srcElemType->getBitWidth();
              unsigned dstWidth = dstElemType->getBitWidth();

              if (dstWidth > srcWidth && dstWidth % srcWidth == 0) {
                llvm::errs() << "WARNING: ";
                if (MDNode *n = i.getMetadata(
                        "dbg")) {    // Here I is an LLVM instruction
                  DILocation loc(n); // DILocation is in DebugInfo.h
                  unsigned line = loc.getLineNumber();
                  StringRef file = loc.getFilename();
                  StringRef dir = loc.getDirectory();
                  llvm::errs() << "Line " << line << " of file " << file.str()
                               << " in " << dir.str() << ": ";
                }
                llvm::errs() << "Bitcast to pointer type with more restrictive "
                                "addressing\n";
              }
            }
          }
        }
      }
    }
    return false;
  }
};
}
char BadCast::ID = 0;
static RegisterPass<BadCast> X("bad-cast", "Discovers bad casts");
