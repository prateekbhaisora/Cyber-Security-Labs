# FLAGS = -fno-stack-protector -z execstack -no-pie -m64 -g
FLAGS = -fstack-protector-all -z execstack -no-pie -m64 -g
# FLAGS = -fno-stack-protector -no-pie -m64 -g
# FLAGS = -fno-stack-protector -z execstack -m64 -g

EXES = copier

all: $(EXES)

$(EXES):
	gcc $(FLAGS) $@.c -o $@

clean:
	rm -rf $(EXES)
