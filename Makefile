CC=gcc
LDFLAGS=-pthread -lZydis -lZycore
CFLAGS=-O2 -g -I/usr/include/x86_64-linux-gnu

PROGS=napsy test_page_access

all: $(PROGS)

test_page_access: test_page_access.o memwatcher.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $^ $(CFLAGS)

test:
	./test_page_access

clean:
	rm -f $(PROGS) *.o