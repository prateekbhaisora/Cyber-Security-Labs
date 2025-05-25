#!/usr/bin/python3

stack_ret_addr = 0x7fffffffe1d8
stack_buf_addr = 0x7fffffffe1cb
 
def main():
    payload = 'A' * (stack_ret_addr - stack_buf_addr)
    print(f"{payload}")

if __name__ == "__main__":
    main()
