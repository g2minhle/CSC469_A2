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
#define SUPERBLOCK_DATA_SIZE 184
#define SUPERBLOCK_SIZE (sizeof(struct superblock) + SUPERBLOCK_DATA_SIZE)
#define SUPER_BLOCK_ALIGNMENT (sizeof(struct mem_block) + SUPERBLOCK_SIZE)

#define CACHE_LINE 64

#define K 0
#define F 0.2

// ======================= Flags =======================

#define IS_FREE_MASK 0x1
#define IS_LARGE_MASK 0x2

// ======================= Macros =======================

#define GET_FREE_BIT(var) (var->flags & IS_FREE_MASK)
#define SET_FREE_BIT(var) (var->flags |= IS_FREE_MASK)
#define CLEAR_FREE_BIT(var) (var->flags &= ~IS_FREE_MASK)

#define GET_LARGE_BIT(var) (var->flags & IS_LARGE_MASK)
#define SET_LARGE_BIT(var) (var->flags |= IS_LARGE_MASK)
#define CLEAR_LARGE_BIT(var) (var->flags &= ~IS_LARGE_MASK)

#define GET_DATA_FROM_MEM_BLOCK(var) ((char*)var + sizeof(struct mem_block))
#define GET_MEM_BLOCK_FROM_DATA(var) ((struct mem_block*)((char*)var - sizeof(struct mem_block)))

#define INIT_LOCK(var) pthread_mutex_init(&(var), NULL)
#define LOCK(var) pthread_mutex_lock(&(var))
#define UNLOCK(var) pthread_mutex_unlock(&(var))

// ======================= Structures =======================

struct allocator_meta {
  pthread_mutex_t mem_lock;
  struct mem_block* first_mem_block;
  pthread_mutex_t heap_list_lock;
  struct thread_meta* heap_list;
  struct thread_meta* global_heap;  
  struct mem_block* free_list;
  struct mem_block* last_mb;
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
  struct mem_block* next_free;
  struct mem_block* previous_free;
};

struct thread_meta {
   pid_t thread_id;
   pthread_mutex_t thread_lock;
   uint64_t used;
   uint32_t sb_count; /* keep track of how many superblocks there are within the heap */
   struct thread_meta* next;
   struct superblock* first_superblock;
};

struct superblock {
  uint32_t free_mem;
  struct superblock* next;
  struct superblock* previous;
  struct thread_meta* thread_heap;
};

struct allocator_meta* mem_allocator; /* The almighty allocator */

/* Given a mem_block to start iterating on, first_mem_block, use the
 * [previous|next]_free pointers to find a suitable memory block that is large
 * enough. The free and usable memory block is stored in free_mem_block.
 * Also keep track of, and sets the previous free mem block <- we didn't have time
 * to remove this without breaking stuff.
 *
 * Note that the free_mem_block can be NULL if a suitable memory block was not
 * found.
 */
void find_free_mem_block_with_free_list(struct mem_block* first_mem_block,
    struct mem_block** free_mem_block,
    struct mem_block** previous_mem_block,
    size_t size) {
  struct mem_block* current_mem_block = first_mem_block;

  /* All we are looking for is a free space that is larger or equal to
   * the size we are looking for. we dont care about alignment, since we will
   * handle such issues later as they arise.
   */
  while (current_mem_block
      && (current_mem_block->blk_size < size || !GET_FREE_BIT(current_mem_block))) {
    *previous_mem_block = current_mem_block;
    current_mem_block = current_mem_block->next_free;
  }

  /* set the free_mem_block -> note that this can be null */
  *free_mem_block = current_mem_block;
}


/* Given a mem_block to start iterating on, first_mem_block, using the next and 
 * previous pointers. Keep iterating until a free mem_block with size
 * available memory is found. Keep track of the mem_block before the
 * free mem_block in previous_mem_block.
 *
 * Not that the free_mem_block can be NULL is a suitable memory block was not
 * found.
 * */
void find_free_mem_block(struct mem_block* first_mem_block,
    struct mem_block** free_mem_block,
    struct mem_block** previous_mem_block,
    size_t size) {
  struct mem_block* current_mem_block = first_mem_block;

  /* All we are looking for is a free space that is larger or equal to
   * the size we are looking for. we dont care about alignment, since we will
   * handle such issues later as they arise.
   */
  while (current_mem_block
      && (current_mem_block->blk_size < size || !GET_FREE_BIT(current_mem_block))) {
    *previous_mem_block = current_mem_block;
    current_mem_block = current_mem_block->next;
  }

  *free_mem_block = current_mem_block;
}

/* Append a passed in memory block to the fron tof the memory allocator's free
 * memory block list.
 */
void add_mem_block_to_free_list(struct mem_block* mb){
  if (mem_allocator->free_list) {
    mem_allocator->free_list->previous_free = mb;
  }
  mb->next_free = mem_allocator->free_list;
  mem_allocator->free_list = mb;
}

/* Remove the passed in memory block from the free list it exists in.
 * Note: this does not NULL out the [next|previous]_free pointers.
 * */
void rm_mem_block_from_free_list(struct mem_block* mb){
  if(mb->next_free) {
    mb->next_free->previous_free = mb->previous_free;
  }
  
  if(mb->previous_free) {
    mb->previous_free->next_free = mb->next_free;
  } else {
    mem_allocator->free_list = mb->next_free;
  }  
}


/* Return the size of memmory allocated */
uint32_t allocate_memory(struct mem_block* result_mem_block, size_t size, bool add_free_list) {
  CLEAR_FREE_BIT(result_mem_block);
  CLEAR_LARGE_BIT(result_mem_block);
  uint32_t space_with_new_mb = size + sizeof(struct mem_block);
  uint32_t extra_space = 0;
  if(space_with_new_mb < result_mem_block->blk_size) {
    // create a new free mem block
    extra_space = sizeof(struct mem_block);
    struct mem_block* new_mem_block = (struct mem_block*)(
      (char*)result_mem_block + space_with_new_mb
    );
    SET_FREE_BIT(new_mem_block);
    CLEAR_LARGE_BIT(new_mem_block);
    new_mem_block->blk_size = result_mem_block->blk_size - space_with_new_mb;
    new_mem_block->next = result_mem_block->next;
    new_mem_block->previous = result_mem_block;
    if (result_mem_block->next) {
      result_mem_block->next->previous = new_mem_block;
    }
    result_mem_block->next = new_mem_block;
    result_mem_block->blk_size = size;
    if (add_free_list == TRUE) {
      add_mem_block_to_free_list(new_mem_block);
      if (result_mem_block == mem_allocator->last_mb) {
        mem_allocator->last_mb = new_mem_block;
      }
    }
  }
  return result_mem_block->blk_size + extra_space;
}

struct mem_block* expand_memory(struct mem_block* previous_mb, size_t size) {
  struct mem_block* result_mb;
  if (GET_FREE_BIT(previous_mb)){
    result_mb = previous_mb;
    // Expand the memory
    void* result = mem_sbrk(size - result_mb->blk_size);
    if (result == NULL) return NULL;
  } else {
    // Expand the memory
    void* result = mem_sbrk(size + sizeof(struct mem_block));
    if (result == NULL) return NULL;

    // Create a new free mem block
    struct mem_block* new_mb = (struct mem_block*)(
      (char*)previous_mb
      + sizeof(struct mem_block)
      + previous_mb->blk_size
    );

    new_mb->next = NULL;
    new_mb->previous = previous_mb;

    previous_mb->next = new_mb;
    result_mb = new_mb;
  }
  CLEAR_FREE_BIT(result_mb);
  CLEAR_LARGE_BIT(result_mb);
  result_mb->blk_size = size;
  return result_mb;
}



/* ABE:??
 * This is try to lock the memory down mem_allocator->mem_lock
 */
struct mem_block* allocate_mem_block(struct mem_block* first_mem_block,
                                      size_t size) {
  struct mem_block* result_mem_block = NULL;
  struct mem_block* previous_mem_block = NULL;
  struct mem_block* free_mem_block = NULL;
  LOCK(mem_allocator->mem_lock);
  find_free_mem_block_with_free_list(mem_allocator->free_list, &free_mem_block, &previous_mem_block, size);

  if(free_mem_block) {
    // Found a memory block to be used
    result_mem_block = free_mem_block;
    allocate_memory(result_mem_block, size, TRUE);
    rm_mem_block_from_free_list(result_mem_block);
  } else {   
    result_mem_block = expand_memory(mem_allocator->last_mb, size);
    mem_allocator->last_mb = result_mem_block;
  }
  UNLOCK(mem_allocator->mem_lock);
  return result_mem_block;
}

uint32_t size_alignment(size_t size, size_t multiplier) {
  uint32_t block_count = size / multiplier;
  uint32_t result = multiplier * block_count;
  
  if (result < size) {
    result += multiplier;
  }

  return result;
}

struct mem_block* allocate_memory_with_super_block_alignment(uint32_t size) {
  uint32_t total_space_including_mem_block = size + sizeof(struct mem_block);
  uint32_t total_size_need = size_alignment(total_space_including_mem_block, 
                                            SUPER_BLOCK_ALIGNMENT);
  total_size_need -= sizeof(struct mem_block);
  return allocate_mem_block(mem_allocator->first_mem_block, total_size_need);
}

/* Allocate at least size amount of memory for a large object on the global heap.
 * Return a pointer to the start of the data/usable memory in the large object.
 */
void* allocate_large_object(uint32_t size) {
  struct mem_block* new_mem_block = 
    allocate_memory_with_super_block_alignment(size);
    
  if (new_mem_block == NULL) return NULL;
  SET_LARGE_BIT(new_mem_block);

  return (void*)(
    GET_DATA_FROM_MEM_BLOCK(new_mem_block)
  );
}

struct superblock* allocate_superblock() {
  struct mem_block* new_mem_block = 
    allocate_memory_with_super_block_alignment(SUPERBLOCK_SIZE);

  if (new_mem_block == NULL) return NULL;

  struct superblock* result = (struct superblock*)(
    GET_DATA_FROM_MEM_BLOCK(new_mem_block)
  );
  
  struct mem_block* mem_block = (struct mem_block*)(
    (char*) result + sizeof(struct superblock)
  );

  mem_block->blk_size = SUPERBLOCK_DATA_SIZE - sizeof(struct mem_block);
  result->free_mem = mem_block->blk_size;

  SET_FREE_BIT(mem_block);
  CLEAR_LARGE_BIT(mem_block);
  mem_block->next = NULL;
  mem_block->previous = NULL;

  return result;
}

struct thread_meta* allocate_thread_meta(pid_t thread_id) {
  struct mem_block* new_mem_block = 
    allocate_memory_with_super_block_alignment(sizeof(struct thread_meta));

  if (new_mem_block == NULL) return NULL;

  struct thread_meta* result = (struct thread_meta*)(
    GET_DATA_FROM_MEM_BLOCK(new_mem_block)
  );

  INIT_LOCK(result->thread_lock);
  result->first_superblock = NULL;
  result->thread_id = thread_id;
  result->used = 0;
  result->sb_count = 0;
  return result;
}


/* Return the currently running thread's heap metadata if it was found in the
 * list of thread metadata. If it was not found in the list, allocate, fill out
 * and add the current thread's heap's metadata to the start of the allocator's
 * thread metadata list. then return the newly added thread metadata. */
struct thread_meta* add_and_find_curr_thread_meta() {
  pid_t thread_id = getTID();
  struct thread_meta* result;

  // NB: this lock could possibly be removed.
  LOCK(mem_allocator->heap_list_lock);
  struct thread_meta* current_thread_heap = mem_allocator->heap_list;
  UNLOCK(mem_allocator->heap_list_lock);

  // Try to find the current thread's heap's metadata in the linked list
  while(current_thread_heap && (current_thread_heap->thread_id != thread_id)) {
    current_thread_heap = current_thread_heap->next;
  }

  result = current_thread_heap;
  if (result == NULL) {
    result = allocate_thread_meta(thread_id);

    // lock the list of thread metadata so that we can add new metadata.
    LOCK(mem_allocator->heap_list_lock);

    result->next = mem_allocator->heap_list;
    mem_allocator->heap_list = result;

    UNLOCK(mem_allocator->heap_list_lock);
  }
  return result;
}


/* Attempt to find a superblock with within the specified local heap, which has an
 * unused block that is of at least size sz. If it finds a superblock meeting
 * the requirements, it will return the locked superblock, while also locking
 * the heap. if it doesn't find a corresponding superblock, it will return NULL
 * while holding the heap lock. */
struct superblock*  find_usable_superblock_on_lheap(struct thread_meta* theap,
                                          struct mem_block** final_free_mem_block, 
                                          size_t sz){
  // scan the list of superblocks in the heap, from most full to least,
  // checking if there is free space.
  struct mem_block* free_mem_block;
  struct mem_block* previous_mem_block;
  struct superblock* final_sb = NULL;
  struct superblock* current_sb = theap->first_superblock;
  while(current_sb) {
    struct mem_block* sb_first_mem_block = (struct mem_block*)(
      (char*)current_sb + sizeof(struct superblock)
    );

    if (!final_sb || current_sb->free_mem < final_sb->free_mem){
      find_free_mem_block(sb_first_mem_block, &free_mem_block, &previous_mem_block, sz);

      if(free_mem_block) {
        *final_free_mem_block = free_mem_block;
        final_sb = current_sb;
      }
    }        
    current_sb =  current_sb->next;
  }

  return final_sb;
}


struct superblock* acquire_superblock_from_global() {
  struct superblock* new_sb;

  LOCK(mem_allocator->global_heap->thread_lock);

  new_sb = mem_allocator->global_heap->first_superblock;
  if (new_sb){
    mem_allocator->global_heap->first_superblock = new_sb->next;

    if (mem_allocator->global_heap->first_superblock) {
      mem_allocator->global_heap->first_superblock->previous = NULL;
    }
  }

  UNLOCK(mem_allocator->global_heap->thread_lock);

  return new_sb;
}

/* Attempt to acquire a new superblock for the requesting heap, which should be
 * locked, where the block is set to at least size sz. If it can acquire a
 * superblock from the global heap (it may need to request more memory for the
 * global heap from global memory), the locked superblock is returned, and the
 * corresponding heap lock is held. Otherwise NULL is returned, and the heap
 * lock is still held. */
struct superblock* thread_acquire_superblock(struct thread_meta* theap, uint32_t sz) {
  struct superblock* new_sb = acquire_superblock_from_global();

  if (new_sb == NULL) {
    new_sb = allocate_superblock();
    if (new_sb == NULL) return NULL; /* we tried, fail here */
  }   

  // otherwise we acquired a superblock, now we just need to set up the metadata.
  new_sb->previous = NULL;
  new_sb->thread_heap = theap;
  
  if (theap->first_superblock) {
    theap->first_superblock->previous = new_sb;
  }
  
  new_sb->next = theap->first_superblock;

  theap->first_superblock = new_sb;
  theap->sb_count++;
  return new_sb;
}

/* try to consolidate the provided (free) memory block with the next memory block
 * which is also free. (Checks that the memory blocks are free should be done
 * before calling this function) */
void consolidate_mem_block(struct mem_block* mem_block, bool in_free_list) {
  if (mem_block->next == mem_allocator->last_mb){
    mem_allocator->last_mb = mem_block;
  }
  
  if (in_free_list){
    rm_mem_block_from_free_list(mem_block->next);
  }
  
  mem_block->blk_size += sizeof(struct mem_block);
  mem_block->blk_size += mem_block->next->blk_size;
  mem_block->next = mem_block->next->next;

  if (mem_block->next) {
    mem_block->next->previous = mem_block;
  }
}

/*
 * Make the mem_block available for others large objects/superpages.
 * This also consolidate the adjacent free mem_block.
 * Any lock must be hold before executing this since this can happen
 * inside or outside a superblock.
 *
 * Return total number of space freed
 */
uint32_t free_mem_block(struct mem_block* mem_block, bool in_free_list ) {
  SET_FREE_BIT(mem_block);
  CLEAR_LARGE_BIT(mem_block);

  uint32_t freed = mem_block->blk_size;

  // consolidate with the next/following memory block
  if (mem_block->next && GET_FREE_BIT(mem_block->next)) {
    consolidate_mem_block(mem_block, in_free_list);
    freed += sizeof(struct mem_block);
  }
  
  if (in_free_list) {
    rm_mem_block_from_free_list(mem_block);
  }

  //consolidate with the previous memory block
  if (mem_block->previous && GET_FREE_BIT(mem_block->previous)) {
    consolidate_mem_block(mem_block->previous, in_free_list);
    freed += sizeof(struct mem_block);
  }

  return freed;
}

/* The mm_malloc routine returns a pointer to an allocated region of at least
 * size bytes. The pointer must be aligned to 8 bytes, and the entire
 * allocated region should lie within the memory region from dseg_lo to dseg_hi.
 */
void *mm_malloc(size_t sz) // ABE
{
  if (sz > LARGE_OBJECT_DATA_SIZE) {
    // the size they are trying to allocate is too large to store in a superblock,
    // so allocate a large object
    return allocate_large_object(sz);
  }

  // else, we're using a superblock.
  struct thread_meta* curr_theap = add_and_find_curr_thread_meta();
  LOCK(curr_theap->thread_lock);

  // if find_usable_superblock_on_lheap succeeds, it will be holding the the free_sb lock
  // and the heap's lock.
  struct mem_block* free_mb = NULL;
  struct superblock* free_sb = find_usable_superblock_on_lheap(curr_theap, &free_mb, sz);
  
  if (free_sb == NULL){
      free_sb = thread_acquire_superblock(curr_theap, sz);
      if (free_sb == NULL)
      {
        // we have an issue: a new superblock could not be acquired from neither
        // the global heap, nor from global memory.
        UNLOCK(curr_theap->thread_lock);
        return NULL;
      }
      struct mem_block* sb_first_mem_block = (struct mem_block*)(
        (char*) free_sb 
        + sizeof(struct superblock)
      );
      struct mem_block* previous_mem_block = NULL;
      find_free_mem_block(sb_first_mem_block, &free_mb, &previous_mem_block, sz);
  }
  
  uint32_t mem_allocated = allocate_memory(free_mb, sz, FALSE);
  free_sb->free_mem -= mem_allocated;
  curr_theap->used += mem_allocated; 
  
  void* blk_data = GET_DATA_FROM_MEM_BLOCK(free_mb);

  // release used locks before returning
  UNLOCK(curr_theap->thread_lock);
  return blk_data;
}


/* Free a large object by freeing the mem_block metadata. */
void free_large_object(struct mem_block* large_object_mem_block) {
  LOCK(mem_allocator->mem_lock);

  free_mem_block(large_object_mem_block, TRUE);

  UNLOCK(mem_allocator->mem_lock);
}

/* Given a ptr, typically to the start of the block of data, try to find the
 * corresponding memory block metadata */
struct mem_block* get_mem_block_from_pointer  (void *ptr) {
  uint32_t mem_allocator_size = size_alignment(sizeof(struct allocator_meta), CACHE_LINE);
  uint32_t block_count = (uint32_t)(
    (
      ( (char*)ptr - (char*)mem_allocator ) 
      - mem_allocator_size
    ) / SUPER_BLOCK_ALIGNMENT
  );

  
  return (struct mem_block*)(
    (char*) mem_allocator 
    + mem_allocator_size
    + SUPER_BLOCK_ALIGNMENT * block_count
  );
}

/* Free a used block, the data ptr, from a superblock. */
void free_block(struct superblock* sb, void *data){
  // Find the corresponding mem_block metadata for data
  struct mem_block* mem_block = GET_MEM_BLOCK_FROM_DATA(data); 
  // actually free the memory block
  uint32_t freed = free_mem_block(mem_block, FALSE);
  sb->free_mem += freed;
  sb->thread_heap->used -= freed;
}

/* Check to see if we can reduce the number of superblocks from a specified
 * thread's heap. Check that the 3 conditions are met before evicting sb
 * 1. the superblock is still free,
 * 2. there are at least K superblocks on the thread's heap
 * 3. the heap has an overall usage of less than F, a percentage.
 */
void reduce_thread_heap(struct thread_meta* theap, struct superblock* sb) {
  uint32_t total_heap_size = SUPERBLOCK_DATA_SIZE * (theap->sb_count - sizeof(struct mem_block));

  // We'll check if any condition is not met in order to return early
  if (sb->free_mem < (SUPERBLOCK_DATA_SIZE-sizeof(struct mem_block))
      || theap->sb_count <= K || (theap->used/(double)total_heap_size) >= F) {
    return;
  }
  
  // Else, the heap is free enough, such that we'll evict a superblock

  // if the superblock we're planning on evicting comes first in the thread's
  // superblock list, then adjust the pointer accordingly.
  if (sb == theap->first_superblock) {
    theap->first_superblock = theap->first_superblock->next;
  }

  // readjust the next and previous pointers accordingly (keep in mind that
  // the list of superblock on a thread's heap are kept in non-circular
  // doubly linked list.
  if (sb->next) {
    sb->next->previous = sb->previous;
  }
  if (sb->previous) {
    sb->previous->next = sb->next;
  }

  // Reduce the number of superblock that the thread heap has
  theap->sb_count--;

  LOCK(mem_allocator->global_heap->thread_lock);

  // Now to move this superblock to the end of the global heap's list of
  // superblocks
  sb->previous = NULL;
  sb->next = mem_allocator->global_heap->first_superblock;
  sb->thread_heap = mem_allocator->global_heap;

  // keep in mind that the global heap has a circular doubly linked list of
  // superblocks.
  if (mem_allocator->global_heap->first_superblock) {
    mem_allocator->global_heap->first_superblock->previous = sb;
  }

  mem_allocator->global_heap->first_superblock = sb;

  UNLOCK(mem_allocator->global_heap->thread_lock);
}

/* The mm_free routine is only guaranteed to work when it is passed pointers
 * to allocated blocks that were returned by previous calls to mm_malloc. The
 * mm_free routine should add the block to the pool of unallocated blocks,
 * making the memory available to future mm_malloc calls.
 */
void mm_free(void *ptr) //ABE
{
  struct mem_block* mem_block = get_mem_block_from_pointer(ptr);

  // check if the block is large
  if (GET_LARGE_BIT(mem_block)) {
    free_large_object(mem_block);
    return;
  }

  // This is a superblock. find the block that needs to be freed
  struct superblock* sb = (struct superblock*) GET_DATA_FROM_MEM_BLOCK(mem_block);
  // since we are freeing a block in sb, 
  // the block is not empty so it wont be move to other places after acquiring sb then the theap
  struct thread_meta* theap = sb->thread_heap;  
  LOCK(theap->thread_lock); 

  // then  lock the superblock since we'll be modifying the contents
  free_block(sb, ptr);

  // this is not the global heap
  // Attempt to evice the current superblock from the thread's heap
  if (theap->thread_id != 0) reduce_thread_heap(theap, sb);
  
  UNLOCK(theap->thread_lock);
}

/* Before calling mm_malloc or mm_free, the application program calls mm_init
 * to perform any necessary initializations, including the allocation of the
 * initial heap area. The return value should be -1 if there was a problem
 * with the initialization, 0 otherwise.
 */
int mm_init(void)
{
  if (dseg_lo != NULL || dseg_hi != NULL) {
    return 0;
  }

  if (mem_init() == -1 ) return -1;

  /*
   * Consider allocate around 5 to 10 superblock in the begining
   * because the bencmarker will go multithread right away.
   * need space for you preserved data as well
   */
  uint32_t mem_allocator_size = size_alignment(sizeof(struct allocator_meta), CACHE_LINE);
  void* result = mem_sbrk (mem_allocator_size + SUPER_BLOCK_ALIGNMENT * 10);

  if (result == NULL) return -1;

  mem_allocator = (struct allocator_meta*) dseg_lo;
  mem_allocator->heap_list = NULL;
  INIT_LOCK(mem_allocator->mem_lock);
  INIT_LOCK(mem_allocator->heap_list_lock);

  mem_allocator->first_mem_block = (struct mem_block*)(
    (char*)dseg_lo + mem_allocator_size
  );
  
  mem_allocator->free_list = mem_allocator->first_mem_block;
  mem_allocator->last_mb = mem_allocator->first_mem_block;
  
  struct mem_block* first_mem_block = mem_allocator->first_mem_block;

  SET_FREE_BIT(first_mem_block);
  CLEAR_LARGE_BIT(first_mem_block);

  first_mem_block->next = NULL;
  first_mem_block->previous = NULL;

  // Total space we have
  first_mem_block->blk_size = dseg_hi - dseg_lo + 1;
  first_mem_block->blk_size -= mem_allocator_size;
  first_mem_block->blk_size -= sizeof (struct mem_block);
  
  mem_allocator->global_heap = allocate_thread_meta(0);
  if (mem_allocator->global_heap == NULL) return -1;

  mem_allocator->global_heap->next = NULL;
  return 0;
}
    
