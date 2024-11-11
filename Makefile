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
	gcc -o main main.c sds/sds.c -I sds -Wall -Wextra -pedantic -lcapstone

hackme: hackme.c
	gcc -static -o hackme hackme.c

clean:
	rm *.o main hackme


# end
