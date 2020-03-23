AR=ar
CC=gcc
LDFLAGS=-pthread -lZydis -lZycore
CFLAGS=-O2 -g -I/usr/include/x86_64-linux-gnu
DFLAGS=

PROGS = libmemwatcher.a \
		napsy
TESTS = test_page_access \
	    test_small_region_access \
		test_multipage_region_access \
		test_multiregion_page_access \
		test_segfault

all: $(PROGS) $(TESTS)

debug: DFLAGS+=-DMEMWATCHER_DEBUG
debug: all

libmemwatcher.a: memwatcher.o 
	$(AR) cr $@ $^

memwatcher.o: memwatcher.c memwatcher.h
	$(CC) -c -o $@ $< $(CFLAGS) $(DFLAGS)

test_%: test_%.o memwatcher.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $^ $(CFLAGS)

test:
	./test_page_access
	./test_small_region_access
	./test_multipage_region_access
	./test_multiregion_page_access
	./test_segfault || [ "$$?" = 139 ]

clean:
	rm -f $(PROGS) *.o $(TESTS)
