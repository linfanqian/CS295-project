#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT="$SCRIPT_DIR/output"
TARGET_SYMCC="$SCRIPT_DIR/toy_symcc"
SYMCC_HELPER="$HOME/symcc/util/symcc_fuzzing_helper/target/release/symcc_fuzzing_helper"

usage() {
    echo "Usage: $0"
    exit 1
}

[ $# -ne 0 ] && usage

ASAN_OPTIONS="abort_on_error=1:exitcode=42:symbolize=0" \
    "$SYMCC_HELPER" \
        -o "$OUTPUT" \
        -a afl-primary \
        -n symcc \
        -- "$TARGET_SYMCC"
