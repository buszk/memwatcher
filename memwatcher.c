// Author: Luka Napotnik <luka.napotnik@gmail.com>
// This code is public domain.
#define __USE_GNU
#include <stdlib.h>
#include <fcntl.h> 
#include <stdio.h> 
#include <string.h> 
#include <sys/stat.h> 
#include <sys/types.h> 
#include <unistd.h> 
#include <pthread.h>
#include <ucontext.h>

#include <Zydis/Zydis.h>
#include "memwatcher.h"

/* workaround for ucontext.h */
#define REG_RIP 16
#define PAGE_SIZE 0x1000
#define INLINE inline __attribute__((always_inline))


/* 
 * mprotect() works with pages. 
 * We use this data structure to keep tracked pages 
 */
struct _watch_page {
    void  *addr;
    size_t size;
    struct _watch_page *next, *prev;
    uint16_t ref_cnt;
};

/* 
 * tracked regions could be of arbitrary alignment and size
 * We use this data structure to keep tracked regions 
 */
struct _watch_region {
    void  *addr;
    size_t size;
    struct _watch_region *next, *prev;
    uint16_t ref_cnt;
};

/*
 * tracked page and tracked regions has n to n relations
 * We use this data structure to keep track of links
 */
struct _page_region_link {
    struct _watch_page    *page;
    struct _watch_region  *region;
};

/*
 * After a tracked map access triggers a sigsegv, we craft
 * another payload to run and get callback from there to 
 * reenable memory access.
 */
struct _seg_callback {
    void *page;
    void *next_inst;
    struct _watch_page *watch;
    struct _seg_callback *next, *prev;
};

struct _watch_page *_page_watchlist = NULL;
struct _seg_callback *_callback_list = NULL;

pthread_spinlock_t page_list_lock;
pthread_spinlock_t cb_list_lock;
uint32_t count;
struct sigaction sa;

static void _sigsegv_protector(int s, siginfo_t *sig_info, void *context);

/* For testing purpose */
uint32_t _get_trap_count() {
    return count;
}

static void __attribute__((constructor)) _init_memwatcher() {
    int ret;
    ret = pthread_spin_init(&page_list_lock, PTHREAD_PROCESS_PRIVATE);
    if (ret != 0) {
        fprintf(stderr, "Failed to init spin lock\n");
        exit(1);
    }
    ret = pthread_spin_init(&cb_list_lock, PTHREAD_PROCESS_PRIVATE);
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
    int ret = pthread_spin_lock(&page_list_lock);
    if (ret != 0) {
        fprintf(stderr, "Failed to lock\n");
        exit(1);
    }
}

INLINE void _memwatcher_unlock() {
    int ret = pthread_spin_unlock(&page_list_lock);
    if (ret != 0) {
        fprintf(stderr, "Failed to unlock\n");
        exit(1);
    }
}

INLINE void _callbackinfo_lock() {
    int ret = pthread_spin_lock(&cb_list_lock);
    if (ret != 0) {
        fprintf(stderr, "Failed to lock\n");
        exit(1);
    }
}

INLINE void _callbackinfo_unlock() {
    int ret = pthread_spin_unlock(&cb_list_lock);
    if (ret != 0) {
        fprintf(stderr, "Failed to unlock\n");
        exit(1);
    }
}

void _watch_address(void *addr, size_t size, int prot) {
    struct _watch_page *watched_addr = malloc(sizeof(*watched_addr));
    watched_addr->addr = addr;
    watched_addr->size = size;

    _memwatcher_lock();

    if (_page_watchlist)
        _page_watchlist->prev = watched_addr;
    // prepend watch to list
    watched_addr->next = _page_watchlist;
    watched_addr->prev = NULL;
    _page_watchlist = watched_addr;

    _memwatcher_unlock();

    // now protect the memory map
    mprotect(addr, size, prot);
}

void _unwatch_address(void *addr, int prot) {

    _memwatcher_lock();

    for (struct _watch_page * pagep = _page_watchlist; 
                    pagep != NULL; pagep = pagep->next) {
        if (pagep->addr == addr) {
            mprotect(pagep->addr, pagep->size, prot);
            if (pagep->prev)
                pagep->prev->next = pagep->next;
            if (pagep->next)
                pagep->next->prev = pagep->prev;
            free(pagep);
            break;
        }
    }

    _memwatcher_unlock();
}

static uint8_t instr_len(void* pc) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    ZydisDecodedInstruction instruction;
    if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, pc, 15, &instruction))) {
            return instruction.length;
    }
    return 0;
}

static void* _alloc_payload(void* inst, uint8_t inst_len) {
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

static void _sigsegv_protector(int s, siginfo_t *sig_info, void *vcontext)
{
    ucontext_t *context = (ucontext_t*)vcontext;
    unsigned char len = 0;
    void *rip;
    printf("---\n");
    printf("%s: Process received segmentation fault, examening ...\n", __func__);
    printf("%s: cause was address %p\n", __func__, sig_info->si_addr);

    rip = (void*)context->uc_mcontext.gregs[REG_RIP];
    len = instr_len(rip);
    printf("%s: The next instruction loc: %p\n", __func__, rip);
    printf("%s:                      len: %d\n", __func__, len);
    _memwatcher_lock();

    struct _watch_page *watched_addr = _page_watchlist;

    for (; watched_addr != NULL; watched_addr = watched_addr->next) {
        if ( sig_info->si_addr >= watched_addr->addr && 
             sig_info->si_addr < watched_addr->addr + watched_addr->size)
            break;
    }

    _callbackinfo_lock();

    struct _seg_callback *callback = _callback_list;

    for (; callback != NULL; callback = callback->next) {
        if ( sig_info->si_addr >= callback->page &&
             sig_info->si_addr < callback->page + PAGE_SIZE)
             break;
    }

    if (watched_addr) {
        printf("%s: raised because of invalid r/w acces to address (was in watchlist) ...\n", __func__);
        // printf("Fault instruction loc: 0x%016llx, len: %d\n", context->uc_mcontext.gregs[REG_RIP], len);
        // context->uc_mcontext.gregs[REG_RIP] += len;

        mprotect (watched_addr->addr, watched_addr->size, PROT_READ | PROT_WRITE);
        void *payload_page = (void*)_alloc_payload(rip, len);
        context->uc_mcontext.gregs[REG_RIP] = (uintptr_t)payload_page;
        struct _seg_callback *info = malloc(sizeof(struct _seg_callback));
        info->page = payload_page;
        info->next_inst = rip+len;
        info->watch = watched_addr;

        if (_callback_list)
            _callback_list->prev = info;
        info->next = _callback_list;
        _callback_list = info;

        printf("---\n");
    }
    else if (callback) {
        printf("%s: raised because of trap from callback ...\n", __func__);
        mprotect(callback->watch->addr, callback->watch->size, PROT_NONE);
        context->uc_mcontext.gregs[REG_RIP] = (uintptr_t)callback->next_inst;

        munmap(callback->page, PAGE_SIZE);
        if (callback->prev) {
            callback->prev->next = callback->next;
        } 
        else {
            _callback_list = callback->next;
        }
        if (callback->next) {
            callback->next->prev = callback->prev;
        }
        free(callback);
        count ++;
    } 
    else {
        printf("---\n");
        exit(1);
    }
    
    // ignore exit above
    _callbackinfo_unlock();
    _memwatcher_unlock();
}
