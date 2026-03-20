#!/usr/bin/env python3
"""
verify_bugs.py — Prove all 9 planted bugs are real and triggerable.
Run once before fuzzing to confirm your binary + ASan catches each one.
"""
import struct, subprocess, sys, os

BINARY = "./toy_verify"

subprocess.run(
    ["clang", "-fsanitize=address", "-g", "-O0", "-o", BINARY, "src/toy_parser.c"],
    check=True
)
print(f"Built {BINARY}\n")

def pkt(cmd, pay=b""):
    return struct.pack("<BBH", 0xAA, cmd, len(pay)) + pay

tests = [
    ("Bug1  stack overflow      [Stack/Heap Overflow]",
     pkt(0x01, b"A" * 200)),

    ("Bug2  heap overflow       [Stack/Heap Overflow]  (8-byte magic)",
     pkt(0x02, bytes([0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE]) + b"B" * 32)),

    ("Bug3  integer underflow   [Integer Overflow/Underflow]",
     pkt(0x03, bytes([50]) + b"C" * 4)),   # header_size=50, length=5 → underflow

    ("Bug4  null ptr deref      [Null Ptr / Uninit Memory]",
     pkt(0x04, bytes([0x5E]))),             # key == 0x5E → NULL

    ("Bug5  use-after-free      [UAF / Double Free]    (p[1]+p[2]==0xFF)",
     pkt(0x05, bytes([ord('F'), 0x80, 0x7F, 0x42]) + b"hello")),  # 0x80+0x7F=0xFF

    ("Bug6  double free         [UAF / Double Free]    (bits 4+7 set)",
     pkt(0x06, bytes([0x90]) + b"X" + b"D" * 10)),

    ("Bug7  heap overflow       [Stack/Heap Overflow]  (XOR: a^b==0xAA, c^d==0x55)",
     pkt(0x07, bytes([0xFF, 0xFF^0xAA, 0xFF, 0xFF^0x55]) + b"E" * 32)),

    ("Bug8  out-of-bounds read   [OOB Read] (AND: a&b==0x3C, p[2]+0x2E==0x63)",
     pkt(0x08, bytes([0xFF, 0x3C, 0x35, 0x05]))),  # AND==0x3C, 0x35+0x2E==0x63, p[3]=5 → OOB

    ("Bug9  double free         [UAF / Double Free]    (XOR state + AND gate)",
     pkt(0x09, bytes([ord('Z'), ord('Z')^0x1B, 0xFF, 0x57]))),
     # p[0]='Z', p[1]='A' (Z^0x1B), p[2]&p[3]: 0xFF&0x57=0x57 → double free
]

print(f"{'Description':<60} {'Result':<10} {'ASan output'}")
print("-" * 110)
all_pass = True
for name, data in tests:
    r = subprocess.run([BINARY], input=data, capture_output=True, timeout=5)
    crashed = r.returncode != 0
    detail = ""
    if r.stderr:
        for line in r.stderr.decode(errors="replace").splitlines():
            if "ERROR" in line or "SUMMARY" in line:
                detail = line.strip()[:60]
                break
    status = "CRASH" if crashed else "NO CRASH"
    marker = "[+]" if crashed else "[!]"
    print(f"{marker} {name:<58} {status:<10} {detail}")
    if not crashed:
        all_pass = False

print()
if all_pass:
    print("All 9 bugs confirmed triggerable.")
else:
    print("WARNING: some bugs did not crash — check binary/ASan setup.")
    sys.exit(1)
