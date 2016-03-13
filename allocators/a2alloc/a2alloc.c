#include <stdlib.h>
#include <pthread.h>
#include "memlib.h"

// In byte
#define SUPERBLOCK_SIZE 8
#define TRUE 1
#define FALSE 1

/* 
 * It is Abegail - Minh allocator 
 */
struct am_allocator {
  pthread_mutex_t mem_lock;
  struct superblock* heap_list;
  struct superblock* global_heap;
};  

struct mem_block {
  int is_free;
  size_t mem_block_size;
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
  size_t free_mem;
};  


struct am_allocator*  am_allocator;

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

struct mem_block* allocate_mem_block(struct mem_block* first_mem_block, 
                                      size_t size, 
                                      size_t multiplier) {
  struct mem_block* result_mem_block = NULL;
  struct mem_block* previous_mem_block = NULL;
  pthread_mutex_lock(&foo_mutex);
  struct mem_block* current_mem_block = first_mem_block;
  while (current_mem_block &&
         (current_mem_block->mem_block_size < size || !current_mem_block->is_free)) {
    previous_mem_block = current_mem_block;
    current_mem_block = current_mem_block->next_block;
  }
  
  if(current_mem_block) {
    // Found a memory block to be used
    result_mem_block = current_mem_block;
    allocateMemory = //round up to the nearest blocksize - sizeof(struct mem_block);   
    
    if(allocateMemory != result_mem_block->mem_block_size) { 
      // create a new free mem block
      struct mem_block* new_mem_block = (char*)result_mem_block + sizeof(struct mem_block) + allocateMemory;      
      new_mem_block->is_free = TRUE;
      new_mem_block->next_block = result_mem_block->next_block;
      new_mem_block->previous_block = result_mem_block;
      result_mem_block->next_block = new_mem_block;
    }     
  } else {
    // reached the last block, with no available memory
    if (previous_mem_block->is_free){
      result_mem_block = previous_mem_block;
      // Expand the memory
      mem_sbrk();      
      // Extend the mem_block size 
      result_mem_block->mem_block_size += ;
      
    } else {
      // Expand the memory
      mem_sbrk();      
      // Create a new free mem block
      
      struct mem_block* new_mem_block = (char*)previous_mem_block 
                                        + sizeof(struct mem_block) 
                                        + previous_mem_block->mem_block_size allocateMemory;
      new_mem_block->next_block = NULL;
      new_mem_block->previous_block = previous_mem_block;
      new_mem_block->mem_block_size = allocateMemory = //round up to the nearest blocksize - sizeof(struct mem_block);   
      previous_mem_block->next_block = new_mem_block;
      result_mem_block = new_mem_block;
    }
    //sbrk to get more memory
  }
  result_mem_block->is_free = FALSE;
  pthread_mutex_unlock(&foo_mutex);
  return result_mem_block;
}

/* Before calling mm_malloc or mm_free, the application program calls mm_init
 * to perform any necessary initializations, including the allocation of the
 * initial heap area. The return value should be -1 if there was a problem
 * with the initialization, 0 otherwise.
 */
int mm_init(void)
{
	if (dseg_lo == NULL && dseg_hi == NULL) {
  	// mem_init ret: -1 if there was a problem, 0 otherwise
	  if (mem_init() == -1 ) return -1;
	  
	  /* 
	   * Consider allocate around 5 to 10 superblock in the begining 
	   * because the bencmarker will go multithread right away.
	   * need space for you preserved data as well
	   */
    mem_sbrk ();
	  
	  am_allocator = dseg_lo;
	  am_allocator->heap_list = NULL;
    am_allocator->global_heap = NULL;
    pthread_mutex_init(&am_allocator->mem_lock, NULL);
      
	  struct mem_block* first_mem_block = (struct mem_block*)((char*)am_allocator
	                                      + sizeof(struct am_allocator));	                                      
    pthread_mutex_init(&mute, NULL);
    first_mem_block->next_block = NULL;
    first_mem_block->previous_block = NULL;
    first_mem_block->is_free = TRUE;
    // Total space we have
    first_mem_block->mem_block_size = dseg_hi - dseg_lo + 1;
    // Minus the preserve space
    first_mem_block->mem_block_size = first_mem_block->mem_block_size - sizeof (struct am_allocator);
    // Minus the the memblock itself
    first_mem_block->mem_block_size = first_mem_block->mem_block_size - sizeof (struct mem_block); 
		return 0; 
	}
	// It's already been initialized
  return 0; 
}

