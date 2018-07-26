#!/usr/bin/env bash
#
# Copyright 2016 National University of Singapore
#
# To build the pass you may first want to run:
#
# cd ../../..
# CXXFLAGS="-Wno-c++11-extensions" ./configure
# cd lib/Analysis/StringLiteralWrite
# make
#
# To run the example, do:
#
# clang -emit-llvm -c -g example/str30-1.c
# ./run.sh str30-1.bc

if [ x$1 == x ]; then
    echo "Usage: $0 <bitcode-file>"
    exit 1
fi

opt -load ../../../Debug+Asserts/lib/StringLiteralWrite.so -string-literal-write -o /dev/null < $1 
