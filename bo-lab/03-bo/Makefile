FLAGS = -fno-stack-protector -z execstack -no-pie -m64 -g

EXES = copier scanner skip exit

OBJS = copier.o scanner.o skip.o exit.o

BINS = exit_payload.bin

all: $(EXES)

$(EXES):
	gcc $(FLAGS) $@.c -o $@

clean:
	rm -rf $(EXES) $(OBJS) $(BINS)
