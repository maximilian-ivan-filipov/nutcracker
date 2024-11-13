##
#
#
# @file
# @version 0.1
all: build

run-aslr: build
	@echo 0 | sudo tee /proc/sys/kernel/randomize_va_space > /dev/null
	@echo "[+] disabling ASLR"
	./main hackme 1234
	@echo 2 | sudo tee /proc/sys/kernel/randomize_va_space > /dev/null

run: build
	./main hackme 1234

build: main hackme

main: main.c
	gcc -ggdb -o main main.c -Wall -Wextra -pedantic -lcapstone

hackme: hackme.c
	gcc -static -o hackme hackme.c

tree: data.h ttest.c
	gcc -ggdb -o ttest ttest.c -Wall -Wextra -pedantic -lcapstone
	valgrind ./ttest

tree-test: data.h tree_stress_test.c
	gcc -ggdb -o tree_stress_test tree_stress_test.c
	./tree_stress_test 1000000

memory-test: memory.h memory_test.c
	gcc -ggdb -o mem memory_test.c


clean:
	rm *.o main hackme


# end
