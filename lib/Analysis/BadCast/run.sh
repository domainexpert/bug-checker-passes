#!/usr/bin/env bash
#
# Copyright 2016 National University of Singapore
#
# To build the pass you may first want to run:
#
# cd ../../..
# CXXFLAGS="-Wno-c++11-extensions" ./configure
# cd lib/Analysis/BadCast
# make
#
# To run the example, do:
#
# clang -emit-llvm -c -g example/exp36-1.c
# ./run.sh exp36-1.bc

if [ x$1 == x ]; then
    echo "Usage: $0 <bitcode-file>"
    exit 1
fi

opt -load ../../../Debug+Asserts/lib/BadCast.so -bad-cast -o /dev/null < $1 
