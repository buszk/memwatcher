
#include <sys/mman.h> 
#include <signal.h> 
#include <inttypes.h>


void _watch_address(void *addr, size_t size, int prot);
void _unwatch_address(void *addr, int prot);

/* for test purpose */
uint32_t _get_trap_count();