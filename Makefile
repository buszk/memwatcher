CC=gcc
LDFLAGS=-pthread -lZydis -lZycore
CFLAGS=-O2 -g -I/usr/include/x86_64-linux-gnu

PROGS=napsy
TESTS=test_page_access test_small_region_access test_multipage_region_access\
		test_multiregion_page_access

all: $(PROGS) $(TESTS)

test_%: test_%.o memwatcher.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $^ $(CFLAGS)

test:
	./test_page_access
	./test_small_region_access
	./test_multipage_region_access
	./test_multiregion_page_access

clean:
	rm -f $(PROGS) *.o $(TESTS)
