# Source, Executable, Includes
src = $(wildcard src/*.c)
obj = $(src:.c=.o)
includes = $(wildcard include/*.h)

CC=/usr/bin/gcc
CFLAGS=-g -Wall -pthread -o0 -Werror -Wall -Wextra -Wshadow -Wpointer-arith -Wstrict-prototypes -Wwrite-strings

scanner: $(obj)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) scanner