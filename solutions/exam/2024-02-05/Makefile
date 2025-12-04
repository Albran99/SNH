CFLAGS=-pie -g -z noexecstack -fstack-protector -z relro -z now -fno-inline
all: server

server: server.c
	gcc $(CFLAGS) -o server server.c

.PHONY: clean
clean:
	rm -f server
