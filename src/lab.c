#include "lab.h"
#include <errno.h>
#include <sys/mman.h>


size_t btok(size_t bytes) {
    unsigned int count = 0;
    bytes--;
    while(bytes > 0) {bytes >>= 1; count++;}
    return count;
}

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