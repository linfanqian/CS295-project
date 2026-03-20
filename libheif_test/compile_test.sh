#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SCRIPT_DIR/test_decode.cpp"

HEIF_SRC="$SCRIPT_DIR/../libheif-1.21.2"
AFL_BUILD="$SCRIPT_DIR/../libheif-afl-build"
SYMCC_BUILD="$SCRIPT_DIR/../libheif-symcc-build"

INCLUDES="-I$HEIF_SRC/libheif/api"
AFL_CXXFLAGS="-g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer"
SYMCC_CXXFLAGS="-g -O0"

echo "[1/2] Compiling test_decode with AFL++..."
AFL_USE_ASAN=1 AFL_USE_UBSAN=1 \
    afl-clang-fast++ $AFL_CXXFLAGS \
        $INCLUDES -I"$AFL_BUILD" \
        -L"$AFL_BUILD/libheif" -lheif \
        -Wl,-rpath,"$AFL_BUILD/libheif" \
        -o "$SCRIPT_DIR/test_decode_afl" \
        "$SRC"

echo "[2/2] Compiling test_decode with SymCC..."
SYMCC="$SCRIPT_DIR/../symcc/build/sym++"
SYMCC_REGULAR_LIBCXX=yes \
    "$SYMCC" $SYMCC_CXXFLAGS \
        $INCLUDES -I"$SYMCC_BUILD" \
        -L"$SYMCC_BUILD/libheif" -lheif \
        -Wl,-rpath,"$SYMCC_BUILD/libheif" \
        -o "$SCRIPT_DIR/test_decode_symcc" \
        "$SRC"

python3 make_seeds.py

echo "Done."
