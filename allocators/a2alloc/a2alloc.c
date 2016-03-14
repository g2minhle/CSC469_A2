#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include "memlib.h"

// In byte
#define SUPERBLOCK_SIZE 8

/* 
 * It is Abegail - Minh allocator 
 */
struct am_allocator {
  pthread_mutex_t mem_lock;
  struct superblock* heap_list;
  struct superblock* global_heap;
};  

struct mem_block {
  bool is_free;
  uint32_t mem_block_size;
  struct mem_block* next_block;
  struct mem_block* previous_block;
};

struct superblock {
  pid_t thread_id;
  pthread_mutex_t thread_lock;
  struct superblock* next_thread;
  struct superblock* previous_thread;
    
  pthread_mutex_t superblock_lock;
  struct superblock* next_superblock;
  struct superblock* previous_superblock;
  uint32_t free_mem;
};  

/* The mm_malloc routine returns a pointer to an allocated region of at least
 * size bytes. The pointer must be aligned to 8 bytes, and the entire
 * allocated region should lie within the memory region from dseg_lo to dseg_hi.
 */
void *mm_malloc(size_t sz)
{
  // sz is large. allocate the superblock from the OS and return that.
  // get the hash of the current thread.
  // now lock heap_i.
  // scan the list of superblocks in the heap, from most full to least,
  // checking if there is free space.
  // check if there is no superblock that has free space.
  if(1)
  {
    // if so, check the global heap for a superblock
    if (1)
    {
      // allocate S bytes as a superblock.
      // set the owner to heap i
    }
    else
    {
      // u_0 -= s.u;
      // u_i += s.u;
      // a_0 -= S;
      // a_i += S;
    }

  }

  // u_i += sz;
  // s.u += sz;
  // Done modifying the heaps, unlock heap_i.

  (void)sz; /* Avoid warning about unused variable */
  // Return a block from the superblock.
  return NULL;
}

/* The mm_free routine is only guaranteed to work when it is passed pointers
 * to allocated blocks that were returned by previous calls to mm_malloc. The
 * mm_free routine should add the block to the pool of unallocated blocks,
 * making the memory available to future mm_malloc calls.
 */
void mm_free(void *ptr)
{
  (void)ptr; /* Avoid warning about unused variable */

  // check if the block is large
  if (1)
  {
    // it is, so free the superblock to the OS
    // return;
  }

  // find the superblock that ptr is part of
  // lock the superblock
  // heap_i is the owner, so lock heap_i
  // deallocate the block from the superblock
  // u_i -= blk_size;
  // s.u -= blk_size;
  if (1)
  {
    // unlock heap_i
    // unlock the superblock
    // return;
  }

  // check if the superblock is now empty enought ot be punted to the glabl heap.
  if (1)
  {
    // move a mostly empty superblock to the global heap
    // u_0 += s1.u;
    // u_i -= s1.u
    // a_o += S;
    // a_i -= S;
  }
  // unlock heap_i
  // unlock the superblock
}


/* Before calling mm_malloc or mm_free, the application program calls mm_init
 * to perform any necessary initializations, including the allocation of the
 * initial heap area. The return value should be -1 if there was a problem
 * with the initialization, 0 otherwise.
 */
int mm_init(void)
{
	if (dseg_lo == NULL && dseg_hi == NULL) {
		return mem_init(); // mem_init ret: -1 if there was a problem, 0 otherwise
	}
  return 0; // It's already been initialized
}

