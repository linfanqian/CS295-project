#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SEEDS="$SCRIPT_DIR/seeds"
OUTPUT="$SCRIPT_DIR/output"
TARGET_AFL="$SCRIPT_DIR/toy_afl"

usage() {
    echo "Usage: $0 <primary|secondary>"
    echo ""
    echo "Examples:"
    echo "  $0 primary    # starts as -M afl-primary"
    echo "  $0 secondary  # starts as -S afl-secondary"
    exit 1
}

[ $# -lt 1 ] && usage

case "$1" in
    primary)
        ROLE="-M"
        THREAD_NAME="afl-primary"
        rm -rf "$OUTPUT"
        ;;
    secondary)
        ROLE="-S"
        THREAD_NAME="afl-secondary"
        ;;
    *)
        usage
        ;;
esac

AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
ASAN_OPTIONS="abort_on_error=1:exitcode=42:symbolize=0" \
AFL_CRASH_EXITCODE=42 \
    afl-fuzz "$ROLE" "$THREAD_NAME" -i "$SEEDS" -o "$OUTPUT" -t 500 -- "$TARGET_AFL"
