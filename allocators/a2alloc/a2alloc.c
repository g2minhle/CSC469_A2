#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include "memlib.h"
#include "mm_thread.h"

// ======================= Constants =======================

#define TRUE 1
#define FALSE 0
#define LARGE_OBJECT_DATA_SIZE (SUPERBLOCK_DATA_SIZE / 2)
// Superblock size in bytes
// TODO: find out the sb_size
#define SUPERBLOCK_DATA_SIZE 8
#define SUPERBLOCK_SIZE (sizeof(struct superblock) + SUPERBLOCK_DATA_SIZE) 
#define SUPER_BLOCK_ALIGNMENT (sizeof(struct mem_block) + SUPERBLOCK_SIZE)

// ======================= Flags =======================

#define IS_FREE_MASK 0x1
#define IS_LARGE_MASK 0x2

// ======================= Macros =======================

#define GET_FREE_BIT(var) (var->flags & IS_FREE_MASK)
#define SET_FREE_BIT(var) (var->flags |= IS_FREE_MASK)
#define CLEAR_FREE_BIT(var) (var->flags &= !IS_FREE_MASK)

#define GET_LARGE_BIT(var) (var->flags & IS_LARGE_MASK)
#define SET_LARGE_BIT(var) (var->flags |= IS_LARGE_MASK)
#define CLEAR_LARGE_BIT(var) (var->flags &= !IS_LARGE_MASK)

#define GET_DATA_FROM_MEM_BLOCK(var) ((char*)var + sizeof(struct mem_block))
#define GET_MEM_BLOCK_FROM_DATA(var) ((struct mem_block*)(char*)var - sizeof(struct mem_block))

// ======================= Structures =======================

struct allocator_meta {
  pthread_mutex_t mem_lock;
  struct mem_block* first_mem_block;
  pthread_mutex_t heap_list_lock;
  struct thread_meta* heap_list;
  struct thread_meta* global_heap;
};

struct mem_block {
  /*
   * 1st bit: Indicate if the block is free or not
   * 2nd bit: Indicate if the block is a large object or not
   */
  uint8_t flags;
  uint32_t blk_size;
  struct mem_block* next;
  struct mem_block* previous;
};

struct thread_meta {
   pid_t thread_id;
   pthread_mutex_t thread_lock;
   struct thread_meta* next;
};

struct superblock {
  uint32_t free_mem;
  pthread_mutex_t sb_lock;
  struct superblock* next;
  struct superblock* previous;
  struct thread_meta* thread_heap;
};


struct allocator_meta*  mem_allocator;

struct mem_block* allocate_mem_block(struct mem_block* first_mem_block,
                                      size_t size) {
  struct mem_block* result_mem_block = NULL;
  struct mem_block* previous_mem_block = NULL;
  pthread_mutex_lock(&(mem_allocator->mem_lock));
  struct mem_block* current_mem_block = first_mem_block;
  while (
    current_mem_block && (
      current_mem_block->blk_size < size
      || !GET_FREE_BIT(current_mem_block)
    )
  ) {
    /* All we are looking for is a free space that is larger or equal to
     * the size we are looking for.
     * we dont create about aglinment since we make sure that happend
     */
    previous_mem_block = current_mem_block;
    current_mem_block = current_mem_block->next;
  }

  if(current_mem_block) {
    // Found a memory block to be used
    result_mem_block = current_mem_block;
    if(size != result_mem_block->blk_size) {
      uint32_t used_space = size - sizeof(struct mem_block);
      // create a new free mem block
      struct mem_block* new_mem_block = (struct mem_block*)
        (char*)result_mem_block + used_space;
      SET_FREE_BIT(first_mem_block);
      CLEAR_LARGE_BIT(first_mem_block);
      new_mem_block->blk_size = result_mem_block->blk_size - used_space;
      new_mem_block->next = result_mem_block->next;
      new_mem_block->previous = result_mem_block;
      result_mem_block->next = new_mem_block;
    }
  } else {
    // reached the last block, with no available memory
    if (GET_FREE_BIT(previous_mem_block)){
      result_mem_block = previous_mem_block;
      // Expand the memory
      void* result = mem_sbrk(size - result_mem_block->blk_size);
      if (result == NULL) return NULL;
      // Extend the mem_block size
      result_mem_block->blk_size = size;
    } else {
      // Expand the memory
      void* result = mem_sbrk(size + sizeof(struct mem_block));
      if (result == NULL) return NULL;
      // Create a new free mem block

      struct mem_block* new_mem_block = (struct mem_block*)(
        (char*)previous_mem_block
        + sizeof(struct mem_block)
        + previous_mem_block->blk_size
      );
      CLEAR_LARGE_BIT(first_mem_block);
      new_mem_block->blk_size = size;

      new_mem_block->next = NULL;
      new_mem_block->previous = previous_mem_block;

      previous_mem_block->next = new_mem_block;
      result_mem_block = new_mem_block;
    }
  }
  CLEAR_FREE_BIT(result_mem_block);
  pthread_mutex_unlock(&(mem_allocator->mem_lock));
  return result_mem_block;
}

uint32_t find_total_size_need(size_t size, size_t multiplier) {
  uint32_t total_space_including_mem_block = size + sizeof(struct mem_block);
  uint32_t block_count = total_space_including_mem_block / multiplier;
  // usable memory
  uint32_t result = multiplier *  block_count;
  if (result < total_space_including_mem_block) {
    // exact that space or extra
    result += multiplier;
  }
  result -= sizeof(struct mem_block);
  return result;
}

void* allocate_large_object(uint32_t size) {
  // Allocate memory for the global heap meta structure
  uint32_t total_size_need = find_total_size_need(
    size,         
    SUPER_BLOCK_ALIGNMENT
  );
  
  struct mem_block* new_mem_block = allocate_mem_block(
        mem_allocator->first_mem_block,
        total_size_need
  );

  if (new_mem_block == NULL) return NULL;
  
  void* result = (void*)GET_DATA_FROM_MEM_BLOCK(new_mem_block);
  SET_LARGE_BIT(new_mem_block);
  
  return result;
}

struct superblock* allocate_superblocks() {
  // Allocate memory for the global heap meta structure
  uint32_t total_size_need =  find_total_size_need(
    SUPERBLOCK_SIZE,         
    SUPER_BLOCK_ALIGNMENT
  );
  
  struct mem_block* new_mem_block = allocate_mem_block(
        mem_allocator->first_mem_block,
        total_size_need
  );

  if (new_mem_block == NULL) return NULL;
  
  struct superblock* result = (struct superblock*)
    GET_DATA_FROM_MEM_BLOCK(new_mem_block);
  pthread_mutex_init(&result->sb_lock, NULL);
  result->free_mem = SUPERBLOCK_DATA_SIZE;
  return result;
}


struct thread_meta* allocate_thread_meta(pid_t thread_id) {
  // Allocate memory for the global heap meta structure
  uint32_t total_size_need =  find_total_size_need(
    sizeof(struct thread_meta),
    SUPER_BLOCK_ALIGNMENT
  );

  struct mem_block* new_mem_block = allocate_mem_block(
        mem_allocator->first_mem_block,
        total_size_need
  );

  if (new_mem_block == NULL) return NULL;

  struct thread_meta* result = (struct thread_meta*)
    GET_DATA_FROM_MEM_BLOCK(new_mem_block);

  pthread_mutex_init(&result->thread_lock, NULL);
  result->thread_id = 0;
  return result;
}


struct thread_meta* get_current_thread_heap() {
  pid_t thread_id = getTID();
  struct thread_meta* result;
  // This lock make sure what current_thread_heap get is not an illed state pointer
  pthread_mutex_lock(&mem_allocator->heap_list_lock);
  struct thread_meta* current_thread_heap = mem_allocator->heap_list;
  pthread_mutex_unlock(&mem_allocator->heap_list_lock);
  while(current_thread_heap && current_thread_heap->thread_id != thread_id) {
    current_thread_heap = current_thread_heap->next;
  }
  
  result = current_thread_heap;
  if (result == NULL) {
    result = allocate_thread_meta(thread_id);

    // lock thread heap    
    pthread_mutex_lock(&mem_allocator->heap_list_lock);
    
    result->next = mem_allocator->heap_list;
    mem_allocator->heap_list = result->next;
    
    pthread_mutex_unlock(&mem_allocator->heap_list_lock);
  }
  return result;
}


/* Return  superblock from somewhere on theap, where there is a free block of at
 * least sz. This function requires you to have locked the theap before calling.*/
struct superblock* find_free_superblock(struct thread_meta* theap, uint32_t sz){
  // scan the list of superblocks in the heap, from most full to least,
  // checking if there is free space.
  return NULL;
}

/* Acquire theap's heap lock. only return once the heap lock is grabbed. */
void lock_heap(struct thread_meta* theap){

}

/* Unlock the theap's heap lock */
void unlock_heap(struct thread_meta* theap){

}

/* */
struct superblock* thread_acquire_superblock(struct thread_meta* theap, uint32_t sz) {  // ABE
  // before letting a thread acquire a new superblock, lock the global heap
  // as we'll try to get a superblock from the global heap
      // u_0 -= s.u;
      // u_i += s.u;
      // a_0 -= S;
      // a_i += S;

  // acquire_global_lock();
  // now that we have the lock, check if the global heap has any free superblocks
  // if they do, take one of the free superblocks. if not, request more memory.
  //struct mem_block* mblk =  allocate_superblock(); 
  // release the global heap
  //lock thread heap
    //release
    //return superblock;
    
 //else
   //remove fomr list, and return 
   // release global heap
 return NULL;
}


/* The mm_malloc routine returns a pointer to an allocated region of at least
 * size bytes. The pointer must be aligned to 8 bytes, and the entire
 * allocated region should lie within the memory region from dseg_lo to dseg_hi.
 */
void *mm_malloc(size_t sz) // ABE
{
  if (sz > LARGE_OBJECT_DATA_SIZE) {
    // the size ther are trying to allocate is too large to store in a superblock,
    // so allocate a large object
    return allocate_large_object(sz);
  }
  // else, we're using a superblock.

  // ABE: ? // separate thread metadata and make it a single block as well to sure we can hold the thread lock
  // ABE: where do we grab the suberblock lock?

  struct thread_meta* curr_theap = get_current_thread_heap();
  lock_heap(curr_theap);

  // try an get a superblock which has a free space that it large enough to store
  // the wanted data size.
  struct superblock* free_sb = find_free_superblock(curr_theap, sz);
  if (free_sb == NULL){
      free_sb = thread_acquire_superblock(curr_theap, sz);
      if (free_sb == NULL)
      {
        // we have an issue: a new superblock could not be acquired from neither
        // the global heap, nor from global memory.
        //release used locks before returning.
        unlock_heap(curr_theap);
        return NULL;
      }
  }

  // We now have a ptr to a superblock with a free block that we can use.
  void* blk_data = NULL;
  //void* blk_data =  acquire_block(free_sb, sz);

  // release used locks before returning
  unlock_heap(curr_theap);
  return blk_data;
}

/* The mm_free routine is only guaranteed to work when it is passed pointers
 * to allocated blocks that were returned by previous calls to mm_malloc. The
 * mm_free routine should add the block to the pool of unallocated blocks,
 * making the memory available to future mm_malloc calls.
 */
void mm_free(void *ptr) //ABE 
{
  struct mem_block* mem_block = GET_MEM_BLOCK_FROM_DATA(ptr);

  // check if the block is large
  if (GET_LARGE_BIT(mem_block)) {
    SET_FREE_BIT(mem_block);
    return;
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


/*
 * return to global heap
 */
struct superblock* thread_release_superblock() { //Minh
  // lock global heap
  // release global heap  
  return NULL;
}


/* Free mem_block. If mem_block is a superblock, then the heap lock will be 
 * called before setting the memory block to free, and will hold the heap lock.
 * Before consolidating, the 
 * */
void free_mem_block(struct mem_block* mem_block) {  //ABE 
  CLEAR_FREE_BIT(mem_block);
  if (mem_block->next && GET_FREE_BIT(mem_block->next)) {
    // consolidate (current, next)
  }
    
  if (mem_block->previous && GET_FREE_BIT(mem_block->previous)) {  
    // consolidate (current, next)
  }
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
    void* result = mem_sbrk (
      sizeof(struct allocator_meta)
      + SUPER_BLOCK_ALIGNMENT * 10
    );

    if (result == NULL) return -1;

	  mem_allocator = (struct allocator_meta*)dseg_lo;
	  mem_allocator->heap_list = NULL;
    pthread_mutex_init(&mem_allocator->mem_lock, NULL);
    pthread_mutex_init(&mem_allocator->heap_list_lock, NULL);

    mem_allocator->first_mem_block = (struct mem_block*)(
	    (char*)mem_allocator + sizeof(struct allocator_meta)
    );

	  struct mem_block* first_mem_block = mem_allocator->first_mem_block;

    SET_FREE_BIT(first_mem_block);
    CLEAR_LARGE_BIT(first_mem_block);

    first_mem_block->next = NULL;
    first_mem_block->previous = NULL;

    // Total space we have
    first_mem_block->blk_size = dseg_hi - dseg_lo + 1;
    // Minus the preserve space
    first_mem_block->blk_size -= sizeof (struct allocator_meta);
    // Minus the the memblock itself
    first_mem_block->blk_size -= sizeof (struct mem_block);


    mem_allocator->global_heap = allocate_thread_meta(0);

    if (mem_allocator->global_heap == NULL) return -1;

    // Init the global heap meta structure
    mem_allocator->global_heap->next = NULL;

		return 0;
	}
	// It's already been initialized
  return 0;
}

