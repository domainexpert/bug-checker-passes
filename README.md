Bug Checker Passes

Security analyses implemented on LLVM 3.4.2 to detect the violations of
[SEI CERT C coding standard](https://www.securecoding.cert.org/confluence/display/c/SEI+CERT+C+Coding+Standard).

Copyright (c) 2016 National University of Singapore
See LICENSE.TXT for the license.

LLVM 3.4.2 Copyright (c) 2003-2013 University of Illinois at Urbana-Champaign

Currently, there are two analyses implemented:
* `bad-cast` analysis to detect the violation of Rule EXP36-C in `lib/Analysis/BadCast`.
* `string-literal-write` analysis to detect the violation of Rule STR30-C in `lib/Analysis/StringLiteralWrite`.

See the `run.sh` in each directory for the instruction on how to build and execute the analyses.


