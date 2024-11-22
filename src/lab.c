#include "lab.h"
#include <errno.h>
#include <sys/mman.h>


size_t btok(size_t bytes) {
    unsigned int count = 0;
    bytes--;
    while(bytes > 0) {bytes >>= 1; count++;}
    return count;
}

struct avail *buddy_calc(struct buddy_pool *pool, struct avail *buddy) {
    return (struct avail *) ((uintptr_t) pool->base ^ (UINT64_C(1) << buddy->kval));
}

void *buddy_malloc(struct buddy_pool *pool, size_t size) {
    if(size == 0 || pool == NULL) {return NULL;}

    unsigned int i = btok(size);
    while(i <= pool->kval_m && pool->avail[i].tag != BLOCK_AVAIL) {i++;}
    if(i > pool->kval_m) {
        perror("buddy: no available block for allocation!");
        errno = ENOMEM;
        return NULL;
    }
    struct avail *L = pool->avail[i].next;
    struct avail *P = L->next;
    pool->avail[i].next = P;
    P->prev = &pool->avail[i];
    L->tag = BLOCK_RESERVED;

    unsigned int fit = false;
    while(!fit) {
        i--;
        L->kval = i;
        P = buddy_calc(pool, L);
        P->tag = BLOCK_AVAIL;
        P->kval = i;
        P->next = P->prev = &pool->avail[i];
        pool->avail[i].next = pool->avail[i].prev = P;
        if(i == btok(size)) {
            fit = true;
        }
    }

    return L;
}

void buddy_free(struct buddy_pool *pool, void *ptr) {
    if(ptr != NULL) {
        struct avail *L = (struct avail *) ptr;
        struct avail *P = buddy_calc(pool, L);
        if(pool->kval_m == L->kval || P->tag == BLOCK_RESERVED || (P->tag == BLOCK_AVAIL && P->kval != L->kval)) {
            L->tag = BLOCK_AVAIL;
            P = pool->avail[L->kval].next;
            L->next = P;
            P->prev = L;
            L->prev = &pool->avail[L->kval];
            pool->avail[L->kval].next = L;
        } else {
            P->prev->next = L->next;
            P->next->prev = L->prev;
            L->kval++;
            if(P < L) {L = P;}
            buddy_free(pool, L);
        }
    }
}

void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size) {}

void buddy_init(struct buddy_pool *pool, size_t size) {
    if(size == 0) {size = UINT64_C(1) << DEFAULT_K;}
    pool->kval_m = btok(size);
    pool->numbytes = UINT64_C(1) << pool->kval_m;

    pool->base = mmap(NULL, pool->numbytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(pool->base == MAP_FAILED) {
        perror("buddy: could not allocate memory pool!");
    }

    for(unsigned int i = 0; i < pool->kval_m; i++) {
        pool->avail[i].next = &pool->avail[i];
        pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].kval = i;
        pool->avail[i].tag = BLOCK_UNUSED;
    }

    pool->avail[pool->kval_m].next = pool->base;
    pool->avail[pool->kval_m].prev = pool->base;
    struct avail *ptr = (struct avail *) pool->base;
    ptr->tag = BLOCK_AVAIL;
    ptr->kval = pool->kval_m;
    ptr->next = &pool->avail[pool->kval_m];
    ptr->prev = &pool->avail[pool->kval_m];
}

void buddy_destroy(struct buddy_pool *pool) {
    int status = munmap(pool->base, pool->numbytes);
    if (status == -1) {
        perror("buddy: destroy failed!");
    }
}