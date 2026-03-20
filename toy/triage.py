#!/usr/bin/env python3
"""
triage.py — Identify which of the 9 planted bugs a crash set found.
Run after fuzzing to produce a bug-coverage table.

Usage:
    python3 triage.py findings_afl/default/crashes "AFL-only"
    python3 triage.py findings_symcc/afl-primary/crashes findings_symcc/symcc/crashes "AFL+SymCC"
"""
import sys, os, struct

BUG_LABELS = {
    1: "Bug1 [Stack/Heap Overflow]      stack overflow (cmd=0x01)               [AFL easy]",
    2: "Bug2 [Stack/Heap Overflow]      heap overflow, 8-byte magic (cmd=0x02)  [SymCC]",
    3: "Bug3 [Integer Underflow]        underflow → heap overflow (cmd=0x03)    [AFL medium]",
    4: "Bug4 [Null Ptr / Uninit]        null deref, key==0x5E (cmd=0x04)        [AFL medium]",
    5: "Bug5 [UAF / Double Free]        use-after-free, sum==0xFF (cmd=0x05)    [SymCC]",
    6: "Bug6 [UAF / Double Free]        double free, bits 4+7 (cmd=0x06)        [AFL medium]",
    7: "Bug7 [Stack/Heap Overflow]      heap overflow, XOR constraints (cmd=0x07) [SymCC]",
    8: "Bug8 [Null Ptr / OOB]           OOB read, AND constraint (cmd=0x08)     [SymCC]",
    9: "Bug9 [UAF / Double Free]        double free, XOR state (cmd=0x09)       [SymCC]",
}

def classify(data):
    if len(data) < 4 or data[0] != 0xAA:
        return None
    cmd = data[1]
    length = struct.unpack_from("<H", data, 2)[0]
    payload = data[4:4+length]

    if cmd == 0x01 and length > 64:
        return 1
    if cmd == 0x02 and len(payload) >= 8 and payload[:8] == bytes([0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE]):
        return 2
    if cmd == 0x03 and len(payload) >= 1 and payload[0] > length:
        return 3
    if cmd == 0x04 and len(payload) >= 1 and payload[0] == 0x5E:
        return 4
    if cmd == 0x05 and len(payload) >= 4 and payload[0] == ord('F') and \
       (payload[1] + payload[2]) & 0xFF == 0xFF and payload[3] == 0x42:
        return 5
    if cmd == 0x06 and len(payload) >= 1 and (payload[0] & 0x90) == 0x90:
        return 6
    if cmd == 0x07 and len(payload) >= 4 and \
       (payload[0] ^ payload[1]) == 0xAA and (payload[2] ^ payload[3]) == 0x55:
        return 7
    if cmd == 0x08 and len(payload) >= 4 and \
       (payload[0] & payload[1]) == 0x3C and \
       (payload[2] + 0x2E) == 0x63 and payload[3] >= 4:
        return 8
    if cmd == 0x09 and len(payload) >= 4 and \
       payload[0] == ord('Z') and (payload[1] ^ payload[0]) == 0x1B and \
       (payload[2] & payload[3]) == 0x57:
        return 9
    return None

def triage_dir(crash_dir):
    found = set()
    if not os.path.isdir(crash_dir):
        return found
    for fname in os.listdir(crash_dir):
        if fname == "README.txt":
            continue
        with open(os.path.join(crash_dir, fname), "rb") as f:
            data = f.read()
        bug = classify(data)
        if bug:
            found.add(bug)
    return found

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        print(f"Usage: {sys.argv[0]} <crashes_dir...> <label>")
        sys.exit(1)

    label = args[-1]
    dirs  = args[:-1]

    found = set()
    for d in dirs:
        found |= triage_dir(d)

    print(f"\n{'='*60}")
    print(f"Results for: {label}")
    print(f"{'='*60}")
    print(f"Bugs found: {len(found)} / {len(BUG_LABELS)}\n")

    for bug_id, desc in sorted(BUG_LABELS.items()):
        marker = "[+]" if bug_id in found else "[ ]"
        print(f"  {marker} {desc}")

    symcc_bugs = {2, 5, 7, 8, 9}
    afl_bugs   = {1, 3, 4, 6}
    if len(found) < len(BUG_LABELS):
        missed = set(BUG_LABELS) - found
        missed_symcc = missed & symcc_bugs
        missed_afl   = missed & afl_bugs
        if missed_symcc:
            print(f"\nMissed SymCC-required bugs: {sorted(missed_symcc)}")
        if missed_afl:
            print(f"Missed AFL-reachable bugs:   {sorted(missed_afl)}")
