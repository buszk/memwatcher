// Author: Luka Napotnik <luka.napotnik@gmail.com>
// This code is public domain.
#define __USE_GNU
#include <stdlib.h>
#include <fcntl.h> 
#include <signal.h> 
#include <stdio.h> 
#include <string.h> 
#include <sys/mman.h> 
#include <sys/stat.h> 
#include <sys/types.h> 
#include <unistd.h> 
#include <assert.h>
#include <pthread.h>
#include <ucontext.h>
#include <inttypes.h>

#include <Zydis/Zydis.h>

/* workaround for ucontext.h */
#define REG_RIP 16
#define PAGE_SIZE 0x1000
#define INLINE inline __attribute__((always_inline))

struct _memory_watchlist_addr {
    void *addr;
    size_t size;
    struct _memory_watchlist_addr *next, *prev;
};

struct _callback_info {
    void *page;
    void *next_inst;
    struct _memory_watchlist_addr *watch;
    struct _callback_info *next, *prev;
};

struct _memory_watchlist_addr *_memory_watchlist = NULL;
struct _callback_info *_cb_list = NULL;

pthread_spinlock_t mwl_lock;
pthread_spinlock_t cbl_lock;
struct sigaction sa;

void _sigsegv_protector(int s, siginfo_t *sig_info, void *context);

static void __attribute__((constructor)) _init_memwatcher() {
    int ret;
    ret = pthread_spin_init(&mwl_lock, PTHREAD_PROCESS_PRIVATE);
    if (ret != 0) {
        fprintf(stderr, "Failed to init spin lock\n");
        exit(1);
    }
    ret = pthread_spin_init(&cbl_lock, PTHREAD_PROCESS_PRIVATE);
    if (ret != 0) {
        fprintf(stderr, "Failed to init spin lock\n");
        exit(1);
    }

    // Setup our signal handler 
    memset (&sa, 0, sizeof (sa)); 
    sa.sa_sigaction = &_sigsegv_protector;
    sa.sa_flags = SA_SIGINFO;
    sigaction (SIGSEGV, &sa, NULL); 
}

INLINE void _memwatcher_lock() {
    int ret = pthread_spin_lock(&mwl_lock);
    if (ret != 0) {
        fprintf(stderr, "Failed to lock\n");
        exit(1);
    }
}

INLINE void _memwatcher_unlock() {
    int ret = pthread_spin_unlock(&mwl_lock);
    if (ret != 0) {
        fprintf(stderr, "Failed to unlock\n");
        exit(1);
    }
}

INLINE void _callbackinfo_lock() {
    int ret = pthread_spin_lock(&cbl_lock);
    if (ret != 0) {
        fprintf(stderr, "Failed to lock\n");
        exit(1);
    }
}

INLINE void _callbackinfo_unlock() {
    int ret = pthread_spin_unlock(&cbl_lock);
    if (ret != 0) {
        fprintf(stderr, "Failed to unlock\n");
        exit(1);
    }
}

void _watch_address(void *addr, size_t size, int prot) {
    struct _memory_watchlist_addr *watch_addr = malloc(sizeof(*watch_addr));
    watch_addr->addr = addr;
    watch_addr->size = size;

    _memwatcher_lock();

    if (_memory_watchlist)
        _memory_watchlist->prev = watch_addr;
    // prepend watch to list
    watch_addr->next = _memory_watchlist;
    watch_addr->prev = NULL;
    _memory_watchlist = watch_addr;

    _memwatcher_unlock();

    // now protect the memory map
    mprotect(addr, size, prot);
}

void _unwatch_address(void *addr, int prot) {

    _memwatcher_lock();

    for (struct _memory_watchlist_addr * mwa = _memory_watchlist; 
                    mwa != NULL; mwa = mwa->next) {
        if (mwa->addr == addr) {
            mprotect(mwa->addr, mwa->size, prot);
            if (mwa->prev)
                mwa->prev->next = mwa->next;
            if (mwa->next)
                mwa->next->prev = mwa->prev;
            free(mwa);
            break;
        }
    }

    _memwatcher_unlock();
}

unsigned char _zydis_get_instr_len(void* pc) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    ZydisDecodedInstruction instruction;
    if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, pc, 15, &instruction))) {
            return instruction.length;
    }
    return 0;
}

void* _alloc_ex_page(void* inst, uint8_t inst_len) {
    int fd;
    char *res;
    res = malloc(PAGE_SIZE);
    fd = open ("/dev/zero", O_RDONLY); 
    res = mmap(NULL, PAGE_SIZE, PROT_WRITE, MAP_PRIVATE, fd, 0); 
    close(fd);
    if (res == 0) {
        exit(2);
    }
    printf("%s: Page allocated at %p\n", __func__, res);
    mprotect(res, PAGE_SIZE, PROT_WRITE);
    memcpy(res, inst, inst_len);
    // mov    QWORD PTR [rip+0x0],0x1
    // should trigger another sigsegv
    char asms[] = { 0x48, 0xC7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
    memcpy(res+inst_len, asms, sizeof(asms));
    mprotect(res, PAGE_SIZE, PROT_EXEC|PROT_READ);


    return res;
}

void _sigsegv_protector(int s, siginfo_t *sig_info, void *vcontext)
{
    ucontext_t *context = (ucontext_t*)vcontext;
    unsigned char len = 0;
    void *rip;
    printf("---\n");
    printf("%s: Process received segmentation fault, examening ...\n", __func__);
    printf("%s: cause was address %p\n", __func__, sig_info->si_addr);

    rip = (void*)context->uc_mcontext.gregs[REG_RIP];
    len = _zydis_get_instr_len(rip);
    printf("%s: The next instruction loc: %p\n", __func__, rip);
    printf("%s:                      len: %d\n", __func__, len);
    _memwatcher_lock();

    struct _memory_watchlist_addr *watched_addr = _memory_watchlist;

    for (; watched_addr != NULL; watched_addr = watched_addr->next) {
        if ( sig_info->si_addr >= watched_addr->addr && 
             sig_info->si_addr < watched_addr->addr + watched_addr->size)
            break;
    }

    _callbackinfo_lock();

    struct _callback_info *cb_info = _cb_list;

    for (; cb_info != NULL; cb_info = cb_info->next) {
        if ( sig_info->si_addr >= cb_info->page &&
             sig_info->si_addr < cb_info->page + PAGE_SIZE)
             break;
    }

    if (watched_addr) {
        printf("%s: raised because of invalid r/w acces to address (was in watchlist) ...\n", __func__);
        // printf("The next instruction loc: 0x%016llx\n", context->uc_mcontext.gregs[REG_RIP]);
        // printf("                     len: %d\n", len);
        // context->uc_mcontext.gregs[REG_RIP] += len;
        mprotect (watched_addr->addr, watched_addr->size, PROT_READ | PROT_WRITE);
        void *page = (void*)_alloc_ex_page(rip, len);
        context->uc_mcontext.gregs[REG_RIP] = (uintptr_t)page;
        struct _callback_info *info = malloc(sizeof(struct _callback_info));
        info->page = page;
        info->next_inst = rip+len;
        info->watch = watched_addr;

        if (_cb_list)
            _cb_list->prev = info;
        info->next = _cb_list;
        _cb_list = info;

        printf("---\n");
    }
    else if (cb_info) {
        printf("%s: raised because of trap from callback ...\n", __func__);
        mprotect(cb_info->watch->addr, cb_info->watch->size, PROT_NONE);
        context->uc_mcontext.gregs[REG_RIP] = (uintptr_t)cb_info->next_inst;

        munmap(cb_info->page, PAGE_SIZE);
        if (cb_info->prev) {
            cb_info->prev->next = cb_info->next;
        } 
        else {
            _cb_list = cb_info->next;
        }
        if (cb_info->next) {
            cb_info->next->prev = cb_info->prev;
        }
        free(cb_info);
    } 
    else {
        printf("---\n");
        exit(1);
    }
    // ignore exit above
    _callbackinfo_unlock();
    _memwatcher_unlock();
}

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
    _watch_address(memory, PAGE_SIZE, PROT_NONE);
    
    // Let's try this out. The following line should cause a SIGSEGV.
    memory[1] = 1; 
    memory[9] = 2; 

    _unwatch_address(memory, PROT_READ|PROT_WRITE);

    memory[3] = 3;

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