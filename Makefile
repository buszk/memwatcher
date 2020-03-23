CC=gcc
LDFLAGS=-pthread -lZydis -lZycore
CFLAGS=-O2 -g -I/usr/include/x86_64-linux-gnu

PROGS=napsy test_access

all: $(PROGS)

test_access: test_access.o memwatcher.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $^ $(CFLAGS)

clean:
	rm -f $(PROGS) *.o