#include <stdio.h> 
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

#include "memwatcher.h"

#define PAGE_SIZE (1<<12)

void test_segfault_protector()
{
    char *memory;
    int fd;

    // allocate page-aligned memory
    fd = open ("/dev/zero", O_RDONLY); 
    memory = mmap(NULL, PAGE_SIZE, PROT_WRITE, MAP_PRIVATE, fd, 0); 
    assert(memory != NULL);
    close (fd); 
    // obtain a private copy of the page
    memory[0] = 0;

    // Here's the main part ... add the allocated memory to the
    // watchlist. After this call, the memory will be unreadable/unwriteble.
    _watch_address(memory + 0x100, 0x100, PROT_NONE);
    
    // Let's try this out. The following line should cause a SIGSEGV.
    assert(_get_trap_count() == 0);
    memory[0x100] = 1; 
    /* Without this assert, two nearby mem access can coalese to one */
    assert(_get_trap_count() == 1); 
    memory[2] = 1; 
    assert(_get_trap_count() == 1);
    memory[0x150] = 1;
    assert(_get_trap_count() == 2);

    _unwatch_address(memory + 0x100, PROT_READ|PROT_WRITE);

    memory[3] = 1;
    assert(_get_trap_count() == 2);
    memory[0x111] = 1;
    assert(_get_trap_count() == 2);

    // And we're finished.
    munmap (memory, PAGE_SIZE); 
}


int main () 
{
    // Run test
    test_segfault_protector();

    printf("Program exited\n");
    return 0; 
} 