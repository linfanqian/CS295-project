#!/usr/bin/env python3
"""
Generate one minimal valid seed per command.
Seeds only establish correct packet structure (magic + cmd + length + minimal payload).
They do NOT hint at bug-safe values — AFL and SymCC discover everything from mutation.
"""
import struct, os

OUT = "seeds"
os.makedirs(OUT, exist_ok=True)

def pkt(cmd, payload=b""):
    return struct.pack("<BBH", 0xAA, cmd, len(payload)) + payload

seeds = {
    "seed_cmd1.bin": pkt(0x01, b"\x00" * 8),
    "seed_cmd2.bin": pkt(0x02, b"\x00" * 28),
    "seed_cmd3.bin": pkt(0x03, b"\x00" * 4),
    "seed_cmd4.bin": pkt(0x04, b"\x00"),
    "seed_cmd5.bin": pkt(0x05, b"\x00" * 6),
    "seed_cmd6.bin": pkt(0x06, b"\x00" * 4),
    "seed_cmd7.bin": pkt(0x07, b"\x00" * 6),
    "seed_cmd8.bin": pkt(0x08, b"\x00" * 4),
    "seed_cmd9.bin": pkt(0x09, b"\x00" * 4),
}

for fname, data in seeds.items():
    with open(os.path.join(OUT, fname), "wb") as f:
        f.write(data)

print("Seeds written to", OUT)
for fn, data in seeds.items():
    print(f"  {fn}: {data.hex()}")
