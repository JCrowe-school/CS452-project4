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
    uintptr_t offset = (((uintptr_t) buddy - (uintptr_t) pool->base) ^ UINT64_C(1) << buddy->kval) % pool->numbytes; //modulo to make sure offset doesn't overflow the assigned pool
    return (struct avail *) (pool->base + offset);
}

void *buddy_malloc(struct buddy_pool *pool, size_t size) {
    if(size == 0 || pool == NULL) {return NULL;}

    struct avail *ablock = NULL;
    for(size_t i = btok(size); i <= pool->kval_m; i++) {
        struct avail *curr = pool->avail[i].next;
        do{
            if(curr->tag == BLOCK_AVAIL) {ablock = curr; break;}
        }while(curr->next != pool->avail[i].next);
        if(ablock != NULL) {break;}
    }
    if(ablock == NULL) {
        perror("buddy: no available block for allocation!");
        errno = ENOMEM;
        return NULL;
    }

    struct avail *L = ablock;
    L->tag = BLOCK_RESERVED;

    unsigned int fit = false;
    while(!fit) {
        struct avail *P = buddy_calc(pool, L);
        L->kval--;
        P->kval = L->kval;
        P->tag = BLOCK_AVAIL;
        P->next = pool->avail[P->kval].next;
        P->prev = pool->avail[P->kval].prev;
        pool->avail[P->kval].next->prev = pool->avail[P->kval].prev->next = P;
        if(L->kval == btok(size)) {
            fit = true;
        }
    }

    return (void *)L;
}

void buddy_free(struct buddy_pool *pool, void *ptr) {
    if(ptr != NULL && pool != NULL) {
        struct avail *L = (struct avail *) ptr;
        struct avail *P = buddy_calc(pool, L);
        
        if(P->tag == BLOCK_AVAIL && P->kval == L->kval) {
            if(P < L) {
                struct avail *T = L;
                L = P;
                P = T;
            }

            if(P->prev != P->next) {
                P->prev->next = P->next;
                P->next->prev = P->prev;
            } else {
                pool->avail[P->kval].next = pool->avail[P->kval].prev = &pool->avail[P->kval];
            }
            L->kval++;
            if(L->kval < pool->kval_m) {buddy_free(pool, L);}
        }

        // ensures that L is only inserted once fully freed
        if(L->tag != BLOCK_AVAIL && L->tag != pool->kval_m) { 
            L->tag = BLOCK_AVAIL;
            L->next = pool->avail[L->kval].next;
            L->prev = pool->avail[L->kval].prev;
            pool->avail[L->kval].next->prev = pool->avail[L->kval].prev->next = L;
        } else if(L->tag == pool->kval_m) {
            L->tag = BLOCK_AVAIL;
            L->next = L->prev = &pool->avail[pool->kval_m];
        }
    }
}

//void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size) {}

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