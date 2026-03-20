#!/bin/bash

AFL_LLVM_INSTRUMENT=CLASSIC \
    afl-clang-fast -fsanitize=address,undefined -g -O0 -o toy_afl toy.c

SYMCC="../symcc/build/symcc"
"$SYMCC" \
    -fsanitize=address,undefined \
    -fno-omit-frame-pointer \
    -g -O0 \
    -o toy_symcc \
    toy.c

python3 make_seeds.py