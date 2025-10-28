/* simple_malloc.c
   Minimal educational _malloc/_free/_realloc using sbrk() and a _free list.
   Compile: gcc -pthread -Wall -DTEST_SIMPLE_MALLOC simple_malloc.c -o simple_malloc
*/

#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>


#define ALIGNMENT 8
#define ALIGN_UP(x) (((x) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))

typedef struct block_header {
    size_t size;                // size of payload
    struct block_header *next;  // next free block
    struct block_header *prev;  // prev free block
    int free;                   // 1 if free, 0 if allocated
} block_header;

#define HDR_SIZE ALIGN_UP(sizeof(block_header))

static block_header *free_list = NULL;
static pthread_mutex_t global_malloc_lock = PTHREAD_MUTEX_INITIALIZER;

/* Request more memory from OS */
static block_header *request_space(block_header *last, size_t size) {
    void *req = sbrk(0);
    void *alloc = sbrk(HDR_SIZE + size);
    if (alloc == (void*) -1) return NULL;

    block_header *blk = (block_header*) req;
    blk->size = size;
    blk->next = NULL;
    blk->prev = NULL;
    blk->free = 0;

    (void) last;
    return blk;
}

/* Find a free block using first-fit */
static block_header *find_free_block(size_t size) {
    block_header *curr = free_list;
    while (curr) {
        if (curr->free && curr->size >= size) {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}

/* Remove block from free list */
static void remove_from_free_list(block_header *blk) {
    if (!blk) 
	return;
    if (blk->prev) 
	blk->prev->next = blk->next;
    else 
	free_list = blk->next;

    if (blk->next) 
	blk->next->prev = blk->prev;
    
    blk->next = blk->prev = NULL;
}

/* Add block to front of free list */
static void add_to_free_list(block_header *blk) {
    blk->free = 1;
    blk->next = free_list;
    if (free_list) 
	free_list->prev = blk;
    blk->prev = NULL;
    free_list = blk;
}

/* Split a block if large enough */
static void split_block(block_header *blk, size_t size) {
    if (blk->size >= size + HDR_SIZE + ALIGN_UP(1)) {
        // create new header after requested space
        void *payload = (void*)blk + HDR_SIZE;
        block_header *newblk = (block_header*)((char*)payload + size);
        newblk->size = blk->size - size - HDR_SIZE;
        newblk->free = 1;
        blk->size = size;

        // insert newblk into free list in place of blk
        newblk->next = blk->next;
        if (newblk->next) newblk->next->prev = newblk;
        newblk->prev = blk->prev;
        if (newblk->prev) newblk->prev->next = newblk;
        else free_list = newblk;

        // ensure blk removed from free list (will be allocated)
        blk->next = blk->prev = NULL;
    }
}

/* Coalesce contiguous free blocks (simple linear coalescing on free) */
static void coalesce_all_free() {
    block_header *a = free_list;
    while (a) {
        block_header *b = a->next;
        while (b) {
            // check if a and b are adjacent in memory (a before b)
            void *a_end = (void*)a + HDR_SIZE + a->size;
            if (a_end == (void*)b) {
                // merge: a absorbs b
                a->size += HDR_SIZE + b->size;
                a->next = b->next;
                if (b->next) b->next->prev = a;
                b = a->next;
                continue;
            }
            b = b->next;
        }
        a = a->next;
    }
}

void *_malloc(size_t size) {
    if (size == 0) return NULL;
    size = ALIGN_UP(size);
    pthread_mutex_lock(&global_malloc_lock);

    block_header *blk = find_free_block(size);
    if (blk) {
        remove_from_free_list(blk);
        split_block(blk, size);
        blk->free = 0;
	blk->size = size;
        pthread_mutex_unlock(&global_malloc_lock);
        return (void*)blk + HDR_SIZE;
    }

    // request memory from OS
    block_header *newblk = request_space(NULL, size);
    if (!newblk) {
        pthread_mutex_unlock(&global_malloc_lock);
        return NULL;
    }
    pthread_mutex_unlock(&global_malloc_lock);
    return (void*)newblk + HDR_SIZE;
}

void _free(void *ptr) {
    if (!ptr) return;
    pthread_mutex_lock(&global_malloc_lock);

    block_header *blk = (block_header*)((char*)ptr - HDR_SIZE);
    // simple safety: ensure not already free
    if (blk->free) {
        // double free detected (just ignore in this demo)
        pthread_mutex_unlock(&global_malloc_lock);
        return;
    }
    blk->free = 1;
    // insert to free list
    add_to_free_list(blk);
    // attempt to coalesce adjacent free blocks
    coalesce_all_free();

    pthread_mutex_unlock(&global_malloc_lock);
}

void *_realloc(void *ptr, size_t size) {
    if (!ptr) return _malloc(size);
    if (size == 0) { _free(ptr); return NULL; }

    block_header *blk = (block_header*)((char*)ptr - HDR_SIZE);
    if (blk->size >= size) {
        // shrink in place optionally split
        pthread_mutex_lock(&global_malloc_lock);
        split_block(blk, ALIGN_UP(size));
        pthread_mutex_unlock(&global_malloc_lock);
        return ptr;
    }

    // otherwise allocate new and copy
    void *newptr = _malloc(size);
    if (!newptr) return NULL;
    memcpy(newptr, ptr, blk->size);
    _free(ptr);
    return newptr;
}

/* We can see the heap status */
void heap_status() {
    pthread_mutex_lock(&global_malloc_lock);
    printf("Free list:\n");
    block_header *cur = free_list;
    while (cur) {
        printf("  block %p size=%zu free=%d next=%p\n", (void*)cur, cur->size, cur->free, (void*)cur->next);
        cur = cur->next;
    }
    pthread_mutex_unlock(&global_malloc_lock);
}

#ifdef TEST_SIMPLE_MALLOC
#include <stdlib.h>
int main() {
    char *a = _malloc(20);
    char *b = _malloc(30);
    _free(a);
    heap_status();
    char *c = _malloc(8);
    heap_status();
    _free(b);
    _free(c);
    heap_status();
    return 0;
}
#endif
// gcc -g -Og -std=gnu99 program.c -o program
