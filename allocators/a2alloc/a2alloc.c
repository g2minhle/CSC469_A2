#include <stdlib.h>
#include <pthread.h>
#include "memlib.h"

// In byte
#define SUPERBLOCK_SIZE 8
#define LARGE_OBJECT_SIZE 4
#define TRUE 1
#define FALSE 1

/* 
 * It is Abegail - Minh allocator 
 */
struct am_allocator {
  pthread_mutex_t mem_lock;
  struct thread_heap* heap_list;
  struct thread_heap* global_heap_top;
  struct thread_heap* global_heap_bottom;
  pthread_mutex_t heap_list_lock;
};  

struct mem_block {
  int is_free;
  size_t mem_block_size;
  struct mem_block* next_block;
  struct mem_block* previous_block;
};

struct thread_heap {
  pid_t thread_id;
  pthread_mutex_t thread_lock;
  struct superblock* next_thread;
  struct superblock* previous_thread;
};

struct superblock {    
  pthread_mutex_t superblock_lock;
  struct superblock* next_superblock;
  struct superblock* previous_superblock;
  size_t free_mem;
};  

struct am_allocator*  am_allocator;

struct thread_heap* get_current_thread_heap() { - Minh 
  pid_t thread_id = gettpid;
  while() to find the heap with given id
  
  if (result == NULL) {
    // allocate metadata
    struct mem_block* allocate_mem_block(struct mem_block* first_mem_block, 
                                      size_t size, 
                                       size_t multiplier) {
    // lock thread heap
    pthread_mutex_t heap_list_lock;
    
    add itselft to the list
    
    pthread_mutex_t heap_list_lock;
    //
  }
  return struct thread_heap*
}

/* Return  superblock from somewhere on theap, where there is a free block of at
 * least sz. This function requires you to have locked the theap before calling.*/
struct superblock* find_free_superblock(struct thread_heap* theap, uint32_t sz){
  // scan the list of superblocks in the heap, from most full to least,
  // checking if there is free space.

}

/* Acquire theap's heap lock. only return once the heap lock is grabbed. */
void lock_heap(struct thread_heap* theap){

}

/* Unlock the theap's heap lock */
void unlock_heap(struct thread_heap* theap){

}

/* The mm_malloc routine returns a pointer to an allocated region of at least
 * size bytes. The pointer must be aligned to 8 bytes, and the entire
 * allocated region should lie within the memory region from dseg_lo to dseg_hi.
 */
void *mm_malloc(size_t sz) // ABE
{
  if (sz > LARGE_OBJECT_SIZE) {
    // the size ther are trying to allocate is too large to store in a superblock,
    // so allocate a large object
    return allocate_larger_object(sz);
  }
  // else, we're using a superblock.

  // ABE: ? // separate thread metadata and make it a single block as well to sure we can hold the thread lock
  // ABE: where do we grab the suberblock lock?

  struct thread_heap* curr_theap = get_current_thread_heap();
  lock_heap(curr_theap);

  // try an get a superblock which has a free space that it large enough to store
  // the wanted data size.
  struct superblock* free_sb = find_free_superblock(curr_theap);
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
  void* blk_data =  acquire_block(free_sb, sz);

  // release used locks before returning
  unlock_heap(curr_theap);
  return blk_data;
}

/* The mm_free routine is only guaranteed to work when it is passed pointers
 * to allocated blocks that were returned by previous calls to mm_malloc. The
 * mm_free routine should add the block to the pool of unallocated blocks,
 * making the memory available to future mm_malloc calls.
 */
void mm_free(void *ptr) - Abe 
{
  (void)ptr; /* Avoid warning about unused variable */

  // check if the block is large
  // we need to find out how this can be done :( maybe put in a bit in memlock 
  if (1)
  {
    void free_mem_block(struct mem_block* mem_block) {
    // it is, so free the superblock to the OS
    return;
  }

  // find the superblock that ptr is part of  - Abe 
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
    struct superblock* thread_release_superblock() { - Minh
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
struct superblock* thread_release_superblock() { - Minh
  // lock global heap
  // release global heap  
}

struct superblock* thread_accquire_superblock() {  - Abe 
  // lock global heap
  if global heap = null 
    // release global heap
    allocate_mem_block(struct mem_block* first_mem_block, 
                                        size_t size = superlblock size , 
                                        size_t multiplier = superlblock size ) {  
    //lock thread heap
    add new superbloclk
    //release
    return superblock
    
 else
   //remove fomr list, and return 
   // release global heap
}

void free_mem_block(struct mem_block* mem_block) {  - Abe 
  // 
  mem_block->is_free = TRUE;
  if (next free )
    consolidate (current, next)
  if (previous free )
    consolidate (previous, current)
}

char* allocate_larger_object(size) {  - Abe 
  pthread_mutex_lock(&(am_allocator->mem_lock)); 
  allocate_mem_block(struct mem_block* first_mem_block, 
                                      size_t size, 
                                      size_t multiplier); 
                
  pthread_mutex_unlock(&(am_allocator->mem_lock));
  return the data point;
}



struct mem_block* allocate_mem_block(struct mem_block* first_mem_block,  - Minh 
                                      size_t size, 
                                      size_t multiplier) {
  struct mem_block* result_mem_block = NULL;
  struct mem_block* previous_mem_block = NULL;
  pthread_mutex_lock(&(am_allocator->mem_lock));
  struct mem_block* current_mem_block = first_mem_block;
  while (current_mem_block &&
         (current_mem_block->mefor_block_size < size || !current_mem_block->is_free)) {
    // all we are looking for is a free space that is larger or equal to the size we are looking for
    // we dont create about aglinment since we make sure that happend
    previous_mem_block = current_mem_block;
    current_mem_block = current_mem_block->next_block;
  }

  num block = (size + sizeof(struct mem_block)) / multiplier
  // usable memory
  allocateMemory = multiplier *  num block
  if (size + sizeof(struct mem_block)) % multiplier > 0
    // exact that space or extra
    allocateMemory += multiplier
  allocateMemory -  sizeof(struct mem_block)
  
  if(current_mem_block) {
    // Found a memory block to be used
    result_mem_block = current_mem_block;         
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
      mem_sbrk(allocateMemory - result_mem_block->mem_block_size);      
      // Extend the mem_block size 
      result_mem_block->mem_block_size = allocateMemory;
      
    } else {
      // Expand the memory
      mem_sbrk(allocateMemory + sizeof(struct mem_block)  );      
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
  }
  result_mem_block->is_free = FALSE;
  pthread_mutex_unlock(&(am_allocator->mem_lock));
  return result_mem_block;
}

/* Before calling mm_malloc or mm_free, the application program calls mm_init
 * to perform any necessary initializations, including the allocation of the
 * initial heap area. The return value should be -1 if there was a problem
 * with the initialization, 0 otherwise.
 */
int mm_init(void) - Minh 
{
	if (dseg_lo == NULL && dseg_hi == NULL) {
  	// mem_init ret: -1 if there was a problem, 0 otherwise
	  if (mem_init() == -1 ) return -1;
	  
	  /* 
	   * Consider allocate around 5 to 10 superblock in the begining 
	   * because the bencmarker will go multithread right away.
	   * need space for you preserved data as well
	   */
    mem_sbrk (sizeof(struct am_allocator) 
              + (sizeof (struct mem_block) + sizeof(struct superblock)) * 10 );
	  
	  am_allocator = dseg_lo;
	  am_allocator->heap_list = NULL;
    am_allocator->global_heap = NULL;
    pthread_mutex_init(&am_allocator->mem_lock, NULL);
    // init locks
      
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

