// Author: Luka Napotnik <luka.napotnik@gmail.com>
// This code is public domain.
#define __USE_GNU
#include <stdlib.h>
#include <fcntl.h> 
#include <stdio.h> 
#include <stdarg.h>
#include <string.h> 
#include <sys/stat.h> 
#include <sys/types.h> 
#include <unistd.h> 
#include <pthread.h>
#include <ucontext.h>

#include <Zydis/Zydis.h>
#include "memwatcher.h"
#include "list.h"

/* workaround for ucontext.h */
#define REG_RIP 16
#define PAGE_SIZE 0x1000
#define INLINE inline __attribute__((always_inline))
#define MEMWATCHER_STR "MemWatcher"

#define PRINTF(fmt, ...) do { fprintf(stderr, "%s: " fmt, MEMWATCHER_STR, ##__VA_ARGS__); } while(0)
#define PERROR(fmt, ...) do { fprintf(stderr, "%s: Error " fmt "\n", MEMWATCHER_STR, ##__VA_ARGS__); exit(1); } while(0)
#ifdef MEMWATCHER_DEBUG
#define DPRINTF(fmt, ...) do { fprintf(stderr, "%s: " fmt, MEMWATCHER_STR, ##__VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) do {} while(0)
#endif

/* 
 * mprotect() works with pages. 
 * We use this data structure to keep tracked pages 
 */
struct _watch_page {
    struct _watch_page *next, *prev;
    void  *addr;
    size_t size;
    uint16_t region_cnt;
    int prot;
};

/* 
 * tracked regions could be of arbitrary alignment and size
 * We use this data structure to keep tracked regions 
 */
struct _watch_region {
    struct _watch_region *next, *prev;
    void  *addr;
    size_t size;
    uint16_t ref_cnt;
};

/*
 * tracked page and tracked regions has n to n relations
 * We use this data structure to keep track of links
 */
struct _page_region_link {
    struct _page_region_link *next, *prev;
    struct _watch_page    *page;
    struct _watch_region  *region;
};

/*
 * After a tracked map access triggers a sigsegv, we craft
 * another payload to run and get callback from there to 
 * reenable memory access.
 */
struct _seg_callback {
    struct _seg_callback *next, *prev;
    void *page;
    void *next_inst;
    struct _watch_page *watched_page;
    struct _watch_region *watched_region;
};

struct _page_region_link  *_link_list         = NULL;
struct _watch_region      *_region_watchlist  = NULL;
struct _watch_page        *_page_watchlist    = NULL;
struct _seg_callback      *_callback_list     = NULL;

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
    if ((ret = pthread_spin_init(&page_list_lock, PTHREAD_PROCESS_PRIVATE)) != 0) {
        PERROR("init spin lock");
    }
    if ((ret = pthread_spin_init(&cb_list_lock, PTHREAD_PROCESS_PRIVATE)) != 0) {
        PERROR("init spin lock");
    }

    // Setup our signal handler 
    memset (&sa, 0, sizeof (sa)); 
    sa.sa_sigaction = &_sigsegv_protector;
    sa.sa_flags = SA_SIGINFO;
    sigaction (SIGSEGV, &sa, NULL); 
}

INLINE void _pagelist_lock() {
    int ret;
    if ((ret = pthread_spin_lock(&page_list_lock)) != 0) {
        PERROR("lock");
    }
}

INLINE void _pagelist_unlock() {
    int ret;
    if ((ret = pthread_spin_unlock(&page_list_lock)) != 0) {
        PERROR("unlock");
    }
}

INLINE void _cblist_lock() {
    int ret;
    if ((ret = pthread_spin_lock(&cb_list_lock)) != 0) {
        PERROR("lock");
    }
}

INLINE void _callbackinfo_unlock() {
    int ret;
    if ((ret = pthread_spin_unlock(&cb_list_lock)) != 0) {
        PERROR("unlock");
    }
}

void _watch_page(void *addr, int prot) {
    struct _watch_page *pagep;
    list_for_each(pagep, _page_watchlist) {
        if (pagep->addr == addr) {
            if (pagep->prot == prot) {
                DPRINTF("inc\n");
                pagep->region_cnt ++;
            }
            else {
                PERROR("trying to set different protection on the same page");
            }
            return;
        }
    }
    /* new tracked page */
    struct _watch_page *watched_page = malloc(sizeof(*watched_page));
    watched_page->addr = addr;
    watched_page->size = PAGE_SIZE;
    watched_page->prot = prot;
    watched_page->region_cnt = 1;

    LIST_ADD(_page_watchlist, watched_page);

    // now protect the memory map
    mprotect(addr, PAGE_SIZE, prot);
}

void _watch_address(void *addr, size_t size, int prot) {
    struct _watch_region *watched_region = malloc(sizeof(*watched_region));
    watched_region->addr = addr;
    watched_region->size = size;
    watched_region->ref_cnt = 1;
    
    _pagelist_lock();
    struct _watch_region *regionp;
    list_for_each(regionp, _region_watchlist) {
        if ((watched_region->addr >= regionp->addr && watched_region->addr < regionp->addr + regionp->size) ||
             watched_region->addr+watched_region->size > regionp->addr && watched_region->addr+watched_region->size <= regionp->addr + regionp->size ) {
            PERROR("Request region in range\n");
        }
    }

    LIST_ADD(_region_watchlist, watched_region);
    for (uintptr_t page = (uintptr_t)addr & -PAGE_SIZE; 
            page < (uintptr_t)addr + size; page+=PAGE_SIZE) {
        _watch_page((void*)page, prot);
    }

    _pagelist_unlock();

}

void _unwatch_page(void*addr, int prot) {

    struct _watch_page *pagep;
    list_for_each(pagep, _page_watchlist) {
        if (pagep->addr == addr) {
            if (pagep->region_cnt > 1) {
                pagep->region_cnt--;
                DPRINTF("dec\n");
            }
            else {
                mprotect(pagep->addr, pagep->size, prot);
                LIST_DEL(_page_watchlist, pagep);
                free(pagep);
            }
            break;
        }
    }

}

void _unwatch_address(void *addr, int prot) {
    _pagelist_lock();
    struct _watch_region *regionp;
    list_for_each(regionp, _region_watchlist) {
        if (regionp->addr == addr) {
            break;
        }
    }
    if (!regionp) {
        PERROR("unwatch address does not exist");
    }
    for (uintptr_t page = (uintptr_t)regionp->addr & -PAGE_SIZE;
                    page < (uintptr_t)regionp->addr + regionp->size; 
                    page += PAGE_SIZE) {
                _unwatch_page((void*)page, prot);
    }
    if (--regionp->ref_cnt == 0)
        LIST_DEL(_region_watchlist, regionp);
    _pagelist_unlock();
}

static uint8_t _instr_len(void* pc) {
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
    DPRINTF("%s: Page allocated at %p\n", __func__, res);
    mprotect(res, PAGE_SIZE, PROT_WRITE);
    memcpy(res, inst, inst_len);
    // mov    QWORD PTR [rip+0x0],0x1
    // should trigger another sigsegv
    char asms[] = { 0x48, 0xC7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
    memcpy(res+inst_len, asms, sizeof(asms));
    mprotect(res, PAGE_SIZE, PROT_EXEC|PROT_READ);

    return res;
}

static void _real_segfault() {
    PRINTF("segfault\n");
    exit(139);
}

static void _sigsegv_protector(int s, siginfo_t *sig_info, void *vcontext)
{
    ucontext_t *context = (ucontext_t*)vcontext;
    unsigned char len = 0;
    void *rip;
    DPRINTF("---\n");
    DPRINTF("%s: Process received segmentation fault, examening ...\n", __func__);
    DPRINTF("%s: cause was address %p\n", __func__, sig_info->si_addr);

    rip = (void*)context->uc_mcontext.gregs[REG_RIP];
    len = _instr_len(rip);
    DPRINTF("%s: The next instruction loc: %p\n", __func__, rip);
    DPRINTF("%s:                      len: %d\n", __func__, len);
    

    struct _seg_callback *callback;

    list_for_each(callback, _callback_list) {
        if ( sig_info->si_addr >= callback->page &&
             sig_info->si_addr < callback->page + PAGE_SIZE)
             break;
    }

    _cblist_lock();
    _pagelist_lock();

    if (callback) {
        /* change page permission back and set RIP back */
        DPRINTF("%s: raised because of trap from callback ...\n", __func__);
        mprotect(callback->watched_page->addr, callback->watched_page->size, callback->watched_page->prot);
        context->uc_mcontext.gregs[REG_RIP] = (uintptr_t)callback->next_inst;

        /* dealloc callback */
        munmap(callback->page, PAGE_SIZE);
        if (callback->watched_region && --callback->watched_region->ref_cnt == 0) {
            LIST_DEL(_region_watchlist, callback->watched_region);
        }
        
        LIST_DEL(_callback_list, callback);
        if (callback->watched_region) {
            DPRINTF("%s: region watched\n", __func__);
            count ++;
        }
        free(callback);
        DPRINTF("---\n");
        goto release;
    } 

    struct _watch_page *watched_page;

    list_for_each(watched_page, _page_watchlist) {
        if ( sig_info->si_addr >= watched_page->addr && 
             sig_info->si_addr < watched_page->addr + watched_page->size)
            break;
    }

    struct _watch_region *watched_region;
    list_for_each(watched_region, _region_watchlist) {
        if (sig_info->si_addr >= watched_region->addr &&
            sig_info->si_addr < watched_region->addr + watched_region->size)
            break;
    }


    if (watched_page) {
        DPRINTF("%s: raised because of invalid r/w acces to address (was in watchlist) ...\n", __func__);
        // printf("Fault instruction loc: 0x%016llx, len: %d\n", context->uc_mcontext.gregs[REG_RIP], len);
        // context->uc_mcontext.gregs[REG_RIP] += len;

            
        mprotect (watched_page->addr, watched_page->size, PROT_READ | PROT_WRITE);
        void *payload_page = (void*)_alloc_payload(rip, len);
        context->uc_mcontext.gregs[REG_RIP] = (uintptr_t)payload_page;
        struct _seg_callback *cb = malloc(sizeof(struct _seg_callback));
        cb->page = payload_page;
        cb->next_inst = rip+len;
        cb->watched_page = watched_page;
        cb->watched_region = watched_region;
        /* watched_region could be NULL */
        if (watched_region)
            watched_region->ref_cnt ++;

        LIST_ADD(_callback_list, cb);
        

        DPRINTF("---\n");
        goto release;
    }
    

    /* !watched_page && !callback */
    
    /* Real sigsegv */
    DPRINTF("---\n");
    _real_segfault();


release:
    // ignore exit above
    _pagelist_unlock();
    _callbackinfo_unlock();
}
