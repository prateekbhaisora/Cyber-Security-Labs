CFLAGS = -fcf-protection=none -fno-asynchronous-unwind-tables -m64 -fno-pie -no-pie

all: flags.s foo-bar.s

flags.s: flags.c
	gcc $(CFLAGS) -S -O1 $< -o $@

foo-bar.s: foo-bar.c
	gcc $(CFLAGS) -S $< -o $@

%.o: %.s
	gcc $(CFLAGS) -c $< -o $@

clean:
	@rm -f *.o *.s
