FLAGS = -fno-stack-protector -z execstack -no-pie -m64 -g

EXES = hello args

all: $(EXES)

$(EXES):
	gcc $(FLAGS) $@.c -o $@

clean:
	rm -rf $(EXES)
