FLAGS = -fno-stack-protector -z execstack -no-pie -m64 -g -D_FORTIFY_SOURCE=0

EXES = rop
BINS = rop-payload.bin

all: $(EXES)

$(EXES):
	gcc $(FLAGS) $@.c -o $@

clean:
	rm -rf $(EXES) $(BINS)
