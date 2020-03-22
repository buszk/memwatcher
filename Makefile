CC=gcc
LDFLAGS=-pthread -lZydis -lZycore
CFLAGS=-O2 -g -I/usr/include/x86_64-linux-gnu

PROGS=napsy memwatcher

all: $(PROGS)

memwatcher: memwatcher.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $^ $(CFLAGS)

clean:
	rm -f $(PROGS) $(PROGS:=.o)