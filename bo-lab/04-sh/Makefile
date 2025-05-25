ASFLAGS   := -m64
CFLAGS    := -m64 -g -std=c99 -Wall -Wno-format-overflow -D_GNU_SOURCE -static
LDFLAGS   := -m64

FLAGS     := -fno-stack-protector -z execstack -no-pie -m64 -g -D_FORTIFY_SOURCE=0
SHELLCODE := shellcode.S
SHELLCODE_BIN := shellcode.bin

EXES      := sh run-shellcode
OBJS	  := shellcode.o
BINS      := $(SHELLCODE_BIN) sh-payload.bin

$(SHELLCODE_BIN): $(SHELLCODE:.S=.o)
	objcopy -S -O binary -j .text $< $@

run-shellcode: run-shellcode.c
	gcc $(FLAGS) $< -o $@

sh: sh.c
	gcc $(FLAGS) $< -o $@

%.o: %.S
	gcc $(ASFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(EXES) $(OBJS) $(BINS) 

.PHONY: all
all: $(EXES) $(SHELLCODE_BIN)
