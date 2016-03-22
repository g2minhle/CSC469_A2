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

#define SUPERBLOCK_DATA_SIZE 48 + 64 * 10
#define SUPERBLOCK_SIZE (sizeof(struct superblock) + SUPERBLOCK_DATA_SIZE)
#define SUPER_BLOCK_ALIGNMENT (sizeof(struct mem_block) + SUPERBLOCK_SIZE)

#define CACHE_LINE 64

#define K 1
#define F 1

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

  pthread_mutex_t heap_list_lock;
  struct heap* heap_list;

  struct heap* global_heap;

  struct mem_block* free_list;
  struct mem_block* first_mb;
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
  /*
   * These pointers are used to link free mb together
   */
  struct mem_block* next_free;
  struct mem_block* previous_free;
};

struct heap {
  pid_t tid;

  uint64_t used;
  /* keep track of how many superblocks there are within the heap */
  uint64_t sb_count;

  pthread_mutex_t heap_lock;
  struct heap* next;
  struct superblock* first_sb;
};

struct superblock {
  uint32_t free_mem;
  uint16_t size_class;

  struct heap* heap;

  struct superblock* next;
  struct superblock* previous;

  struct mem_block* free_list;
};

// ======================= Global variables =======================

/* The almighty allocator */
struct allocator_meta* mem_allocator;

// ======================= Functions =======================

/* Round up the size to the nearest number that is a multiplier of a given value.
 *
 * Args:
 *      size_t size:
 *          The givent size.
 *      size_t multiplier:
 *          The value that result wants to be a multiplier of.
 *
 * Return:
 *      uint32_t:
 *          The nearest number rounding up from size that is a multiplier
 *          of a given value.
 */
uint32_t size_alignment(size_t size, size_t multiplier) {
  uint32_t block_count = size / multiplier;
  uint32_t result = multiplier * block_count;

  if (result < size) {
    result += multiplier;
  }

  return result;
}

/* Figure out the size class of the given size
 * If there is no size class then return the size itsefl
 *
 * Args:
 *      size_t size:
 *          The givent size.
 *
 * Return:
 *      uint32_t:
 *          The size class or the size it self
 */
uint32_t adjust_class_size(size_t size) {
  uint8_t i;

  if (size <= 2) {
    return size_alignment(size, 2);
  } else if (size <= 4) {
    return size_alignment(size, 4);
  } else if (size <= 8) {
    return size_alignment(size, 8);
  } else if (size <= 16) {
    return size_alignment(size, 16);
  } else if (size <= 32) {
    return size_alignment(size, 32);
  } else if (size <= 64) {
    return size_alignment(size, 64);
  } else if (size <= 128) {
    return size_alignment(size, 128);
  } else if (size <= 256) {
    return size_alignment(size, 256);
  } else if (size <= 512) {
    return size_alignment(size, 512);
  } else {
    return size;
  }
}

/* Retun memory block metadata given the start of the block of data.
 *
 * Args:
 *      void *ptr:
 *          The start of the block of data.
 *
 * Return:
 *      struct mem_block*:
 *          The memory block metadata.
 */
struct mem_block* ptr_to_mb (void *ptr) {
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

/* Retun the 1st memory block that fit the given size.
 *
 * Args:
 *      struct mem_block* first_mb:
 *        The 1st mem_block of free mem_block list.
 *      size_t size:
 *        The size the the returned mem block have to fit.
 *
 * Return:
 *      struct mem_block*:
 *        The 1st memory block that fit the given size.
 *        NULL is returned if there is no such mem block.
 */
struct mem_block* find_free_mb(struct mem_block* first_mb, size_t size) {
  struct mem_block* current_mb = first_mb;

  while (current_mb
          && ( current_mb->blk_size < size || !GET_FREE_BIT(current_mb))) {
    /* All we are looking for is a free space that is larger or equal to
     * the size we are looking for. we dont care about alignment, since we will
     * handle such issues later as they arise.
     */
    current_mb = current_mb->next_free;
  }

  return current_mb;
}

/* Append a free memory block to the front of the given mem_block free list.
 *
 * Args:
 *      struct mem_block** free_list:
 *        The free list of mem blocks.
 *      struct mem_block* mb:
 *        The new free mem block.
 */
void add_mb_to_free_list(struct mem_block** free_list, struct mem_block* mb) {
  if (*free_list) {
    (*free_list)->previous_free = mb;
  }
  mb->next_free = *free_list;
  mb->previous_free = NULL;
  *free_list = mb;
}

/* Remove the passed in memory block from the free list it exists in.
 * Note: this does not NULL out the [next|previous]_free pointers.
 *
 * Args:
 *      struct mem_block** free_list:
 *        The free list of mem blocks.
 *      struct mem_block* mb:
 *        The mem block that being removed.
 */
void remove_mb_from_free_list(struct mem_block** free_list,
                                struct mem_block* mb) {
  if(mb->next_free) {
    mb->next_free->previous_free = mb->previous_free;
  }

  if(mb->previous_free) {
    mb->previous_free->next_free = mb->next_free;
  } else {
    *free_list = mb->next_free;
  }
}

/* Append a new superblock to the front of the given heap.
 *
 * Args:
 *      struct heap* heap:
 *        The heap.
 *      struct superblock* sb:
 *        The new superblock.
 */
void add_sb_to_heap(struct heap* heap, struct superblock* sb){
  sb->heap = heap;
  sb->next = heap->first_sb;
  if (heap->first_sb) {
    heap->first_sb->previous = sb;
  }
  heap->first_sb = sb;
  sb->previous = NULL;
  heap->sb_count++;
}

/* Remove the passed in superblock from the heap it exists in.
 * Note: this does not NULL out the [next|previous] pointers.
 *
 * Args:
 *      struct superblock* sb:
 *        The superblock that being removed.
 */
void remove_sb_from_heap(struct superblock* sb){
  struct heap* heap = sb->heap;
  if(sb->next) {
    sb->next->previous = sb->previous;
  }

  if(sb->previous) {
    sb->previous->next = sb->next;
  } else {
    heap->first_sb = sb->next;
  }

  heap->sb_count--;
}

/* Insert a mem block after a given mem_block.
 *.
 * Args:
 *      struct mem_block* previous_mb:
 *        The mem block that the new memblock will be behind.
 *      struct mem_block* new_mb:
 *        The new mem block being added.
 */
void insert_mb(struct mem_block* previous_mb, struct mem_block* new_mb) {
  new_mb->next = previous_mb->next;
  new_mb->previous = previous_mb;
  if (previous_mb->next) {
      previous_mb->next->previous = new_mb;
  }
  previous_mb->next = new_mb;
}

/* Given a memory block, result_mb, set the memory as allocated, and
 * shrink the result_mb's blocksize to the requested size, if there is
 * enough space at the end of the data to include a new mem_block.
 *
 * Args:
 *      struct mem_block* result_mb:
 *        The mem block being allocated.
 *      size_t size:
 *        The size that being allocated.
 *      struct mem_block** free_list:
 *        The list of free mem block that the given mem block is a part of.
 *
 * Return:
 *      uint32_t:
 *        Total space allocated including for the new mem block if it is created.
 */
uint32_t allocate_memory(struct mem_block* result_mb,
                            size_t size,
                            struct mem_block** free_list) {
  remove_mb_from_free_list(free_list, result_mb);
  CLEAR_FREE_BIT(result_mb);
  CLEAR_LARGE_BIT(result_mb);
  uint32_t size_plus_mb = size + sizeof(struct mem_block);
  uint32_t extra_space = 0;

  /* See if there is enough space in result_mb, after allocating size,
   * suck that a new block and corresponding memblock can be added. Otherwise
   * let result_mem->blk_size remain the same size.
   */
  if(size_plus_mb < result_mb->blk_size) {

    extra_space = sizeof(struct mem_block);
    // create a new free mem block
    struct mem_block* new_mb = (struct mem_block*)(
      (char*)result_mb + size_plus_mb
    );

    // initialize the new memory block's values
    SET_FREE_BIT(new_mb);
    CLEAR_LARGE_BIT(new_mb);
    new_mb->blk_size = result_mb->blk_size - size_plus_mb;
    result_mb->blk_size = size;

    insert_mb(result_mb, new_mb);
    add_mb_to_free_list(free_list, new_mb);

    if (result_mb == mem_allocator->last_mb) {
      mem_allocator->last_mb = new_mb;
    }
  }

  return result_mb->blk_size + extra_space;
}

/* Expand the memory the allocator can use. Given the memory block that is at
 * the end of a free list, attach the newly allocated memory block to the end of
 * the free list.
 *
 * Args:
 *      size_t size:
 *        The size that being allocated.
 *      struct mem_block** free_list:
 *        The list of free mem block that the given mem block is a part of.
 *
 * Return:
 *      struct mem_block*:
 *        The new mem block resulting from the expandtion.
 */
struct mem_block* expand_memory(size_t size) {
  struct mem_block* result_mb;
  if (GET_FREE_BIT(mem_allocator->last_mb)){
    result_mb = mem_allocator->last_mb;
    // Expand the memory
    void* result = mem_sbrk(size - result_mb->blk_size);
    if (result == NULL) return NULL;
    remove_mb_from_free_list(&mem_allocator->free_list, result_mb);
  } else {
    // make use of the previous memory block, so that we can ask for less memory
    void* result = mem_sbrk(size + sizeof(struct mem_block));

    // if it didn't work, return
    if (result == NULL) return NULL;

    // try to expand the memory
    struct mem_block* new_mb = (struct mem_block*)(
      (char*) mem_allocator->last_mb
      + sizeof(struct mem_block)
      + mem_allocator->last_mb->blk_size
    );

    new_mb->next = NULL;
    new_mb->previous = mem_allocator->last_mb;
    mem_allocator->last_mb->next = new_mb;
    mem_allocator->last_mb = new_mb;
    result_mb = new_mb;
  }
  CLEAR_FREE_BIT(result_mb);
  CLEAR_LARGE_BIT(result_mb);
  result_mb->blk_size = size;
  return result_mb;
}

/* Return a free memory block on the memory allocator's free list, where the
 * block size is of at least size.
 *
 * Args:
 *      size_t size:
 *        The size that being allocated.
 *
 * Return:
 *      struct mem_block*:
 *        The new mem block,
 */
struct mem_block* allocate_mb(size_t size) {
  struct mem_block* result_mb = NULL;

  // lock the memory allocator before attempting to traverse the free list.
  LOCK(mem_allocator->mem_lock);

  result_mb = find_free_mb(mem_allocator->free_list, size);

  if(result_mb) {
    // Found a memory block to be used
    allocate_memory(result_mb, size, &mem_allocator->free_list);
  } else {
    result_mb = expand_memory(size);
  }

  UNLOCK(mem_allocator->mem_lock);
  return result_mb;
}

/* Return the memory block associated with allocated superblock that is
 * and aligned size.
 *
 * Args:
 *      uint32_t size:
 *        The size that being allocated.
 *
 * Return:
 *      struct mem_block*:
 *        The new mem block.
 */
struct mem_block* allocate_memory_with_sb_alignment(uint32_t size) {
  uint32_t total_space_including_mem_block = size + sizeof(struct mem_block);
  uint32_t total_size_need = size_alignment(total_space_including_mem_block,
                                              SUPER_BLOCK_ALIGNMENT);
  total_size_need -= sizeof(struct mem_block);
  return allocate_mb(total_size_need);
}

/* Allocate at least size amount of memory for a large object on the global heap.
 * Return a pointer to the start of the data/usable memory in the large object.
 *
 * Return:
 *      void*:
 *          The new large object.
 */
void* allocate_large_object(uint32_t size) {
  struct mem_block* new_mb =
    allocate_memory_with_sb_alignment(size);

  if (new_mb == NULL) return NULL;
  SET_LARGE_BIT(new_mb);

  return (void*)(
    GET_DATA_FROM_MEM_BLOCK(new_mb)
  );
}

/* Allocate a new superblock
 *
 * Return:
 *      struct superblock*:
 *          The new superblock.
 */
struct superblock* allocate_superblock() {
  struct mem_block* new_mb =
    allocate_memory_with_sb_alignment(SUPERBLOCK_SIZE);

  if (new_mb == NULL) return NULL;

  struct superblock* result_sb = (struct superblock*)(
    GET_DATA_FROM_MEM_BLOCK(new_mb)
  );

  struct mem_block* mem_block = (struct mem_block*)(
    (char*) result_sb + sizeof(struct superblock)
  );

  mem_block->blk_size = SUPERBLOCK_DATA_SIZE - sizeof(struct mem_block);
  result_sb->free_mem = mem_block->blk_size;
  result_sb->free_list = mem_block;
  SET_FREE_BIT(mem_block);
  CLEAR_LARGE_BIT(mem_block);
  mem_block->next = NULL;
  mem_block->previous = NULL;
  mem_block->next_free = NULL;
  mem_block->previous_free = NULL;

  return result_sb;
}

/* Allocate a new heap
 *
 * Args:
 *      pid_t tid:
 *          The id of current thread
 *
 * Return:
 *      struct heap*:
 *          The new heap.
 */
struct heap* allocate_heap(pid_t tid) {
  struct mem_block* new_mb =
    allocate_memory_with_sb_alignment(sizeof(struct heap));

  if (new_mb == NULL) return NULL;

  struct heap* result_heap = (struct heap*)(
    GET_DATA_FROM_MEM_BLOCK(new_mb)
  );

  INIT_LOCK(result_heap->heap_lock);
  result_heap->first_sb = NULL;
  result_heap->tid = tid;
  result_heap->used = 0;
  result_heap->sb_count = 0;
  return result_heap;
}

/* Return the currently running thread's heap metadata if it was found in the
 * list of heap. If it was not found in the list, allocate, fill out
 * and add the current thread's heap's metadata to the start of the allocator's
 * thread metadata list. then return the newly added heap metadata.
 *
 * Return:
 *      struct heap*:
 *          The current heap.
 */
struct heap* get_or_create_cur_heap() {
  pid_t tid = getTID();
  struct heap* result_heap;

  // NB: this lock probably doesn't need to be used
  LOCK(mem_allocator->heap_list_lock);
  struct heap* cur_heap = mem_allocator->heap_list;
  UNLOCK(mem_allocator->heap_list_lock);

  // Try to find the current thread's heap's metadata in the linked list
  while(cur_heap && (cur_heap->tid != tid)) {
    cur_heap = cur_heap->next;
  }

  result_heap = cur_heap;
  if (result_heap == NULL) {
    result_heap = allocate_heap(tid);

    // lock the list of thread metadata so that we can add new metadata.
    LOCK(mem_allocator->heap_list_lock);

    result_heap->next = mem_allocator->heap_list;
    mem_allocator->heap_list = result_heap;

    UNLOCK(mem_allocator->heap_list_lock);
  }
  return result_heap;
}


/* Attempt to find a superblock with within the specified local heap, which has an
 * unused block that is of at least size sz. If it finds a superblock meeting
 * the requirements, it will return the locked superblock, while also locking
 * the heap. if it doesn't find a corresponding superblock, it will return NULL
 * while holding the heap lock.
 *
 * Args:
 *      struct heap* heap:
 *          The current heap.
 *      struct mem_block** final_free_mb
 *          The free mem block if it is found.
 *      size_t sz:
 *          The size is being looked for.
 *
 * Return:
 *      struct superblock*:
 *          The superlock that has enough free space.
 */
struct superblock* get_free_sb_on_heap(struct heap* heap,
                                          struct mem_block** final_free_mb,
                                          size_t sz){
  // scan the list of superblocks in the heap, from most full to least,
  // checking if there is free space.
  struct superblock* current_sb = heap->first_sb;
  struct superblock* final_sb = NULL;
  struct mem_block* current_mb = NULL;

  while(current_sb) {
    if (current_sb->size_class == sz) {
      current_mb = find_free_mb(current_sb->free_list, sz);
      if (current_mb) {
        *final_free_mb = current_mb;
        final_sb = current_sb;
        return final_sb;
      }
    }
    current_sb =  current_sb->next;
  }

  return final_sb;
}

/* Return a superblock that got removed from global heap.
 *
 * Return:
 *      struct superblock*:
 *          The a superblock that got removed from global heap.
 */
struct superblock* acquire_sb_from_global_heap() {
  struct superblock* new_sb;

  LOCK(mem_allocator->global_heap->heap_lock);

  new_sb = mem_allocator->global_heap->first_sb;
  if (new_sb) {
    remove_sb_from_heap(new_sb);
  }

  UNLOCK(mem_allocator->global_heap->heap_lock);

  return new_sb;
}

/* Attempt to acquire a new superblock for the requesting heap, which should be
 * locked, where the block is set to at least size sz. If it can acquire a
 * superblock from the global heap (it may need to request more memory for the
 * global heap from global memory), the locked superblock is returned, and the
 * corresponding heap lock is held. Otherwise NULL is returned, and the heap
 * lock is still held.
 *
 * Args:
 *      size_t sz:
 *          Size needed.
 *
 * Return:
 *      void *:
 *          Pointer to newly allocated memory.
 */
struct superblock* heap_acquire_new_sb(struct heap* heap, uint32_t sz) {
  struct superblock* new_sb = acquire_sb_from_global_heap();

  if (new_sb == NULL) {
    new_sb = allocate_superblock();
    /* we tried, fail here */
    if (new_sb == NULL) return NULL;
  }

  add_sb_to_heap(heap, new_sb);

  new_sb->size_class = sz;

  return new_sb;
}

/* The mm_malloc routine returns a pointer to an allocated region of at least
 * size bytes. The pointer must be aligned to 8 bytes, and the entire
 * allocated region should lie within the memory region from dseg_lo to dseg_hi.
 *
 * Args:
 *      size_t sz:
 *          Size needed.
 *
 * Return:
 *      void *:
 *          Pointer to newly allocated memory.
 */
void *mm_malloc(size_t sz)
{
  sz = adjust_class_size(sz);

  if (sz > LARGE_OBJECT_DATA_SIZE) {
    // If the size they are trying to allocate is too large to store
    // in a superblock so allocate a large object
    return allocate_large_object(sz);
  }

  // Attemp to create or get the current heap then lock it down
  struct heap* cur_heap = get_or_create_cur_heap();
  LOCK(cur_heap->heap_lock);

  // Find a sb and a mb with suitable free space,
  struct mem_block* free_mb = NULL;
  struct superblock* free_sb = get_free_sb_on_heap(cur_heap, &free_mb, sz);

  if (free_sb == NULL){
      // If there is no free space then get a new sb
      free_sb = heap_acquire_new_sb(cur_heap, sz);
      if (free_sb == NULL)
      {
        // we have an issue: a new superblock could not be acquired from neither
        // the global heap, nor from global memory.
        UNLOCK(cur_heap->heap_lock);
        return NULL;
      }
      free_mb = find_free_mb(free_sb->free_list, sz);
  }

  // Allocate new memmory
  uint32_t mem_allocated = allocate_memory(free_mb, sz, &free_sb->free_list);

  // Move the sb to the head of the heap's sb list
  remove_sb_from_heap(free_sb);
  add_sb_to_heap(cur_heap, free_sb);

  free_sb->free_mem -= mem_allocated;
  cur_heap->used += mem_allocated;

  void* blk_data = GET_DATA_FROM_MEM_BLOCK(free_mb);

  // release used locks before returning
  UNLOCK(cur_heap->heap_lock);
  return blk_data;
}

/* Consolidate the provided free memory block with the next memory block
 * if it is free. Please checks that the memory blocks are free should be done
 * before calling this function
 *
 * Args:
 *      struct mem_block* mem_block:
 *          The mem block that get consolidated.
 *      struct mem_block** free_list:
 *          The list of free mem blocks.
 */
void consolidate_free_mb(struct mem_block* mem_block, struct mem_block** free_list) {
  if (mem_block->next == mem_allocator->last_mb){
    mem_allocator->last_mb = mem_block;
  }

  remove_mb_from_free_list(free_list, mem_block->next);

  mem_block->blk_size += sizeof(struct mem_block);
  mem_block->blk_size += mem_block->next->blk_size;
  mem_block->next = mem_block->next->next;

  if (mem_block->next) {
    mem_block->next->previous = mem_block;
  }
}

/* Make the mem_block available for others large objects/superpages.
 * This also consolidate the adjacent free mem_block.
 * Any lock must be hold before executing this since this can happen
 * inside or outside a superblock.
 *
 * Args:
 *      struct mem_block* mem_block:
 *          The mem block that get deallocated.
 *      struct mem_block** free_list:
 *          The list of free mem blocks.
 *
 * Return:
 *      uint32_t:
 *          The total free space freed.
 */
uint32_t deallocate_mb(struct mem_block* mem_block, struct mem_block** free_list) {
  SET_FREE_BIT(mem_block);
  CLEAR_LARGE_BIT(mem_block);

  uint32_t freed = mem_block->blk_size;

  // consolidate with the next/following memory block
  if (mem_block->next && GET_FREE_BIT(mem_block->next)) {
    consolidate_free_mb(mem_block, free_list);
    freed += sizeof(struct mem_block);
  }

  add_mb_to_free_list(free_list, mem_block);

  //consolidate with the previous memory block
  if (mem_block->previous && GET_FREE_BIT(mem_block->previous)) {
    consolidate_free_mb(mem_block->previous, free_list);
    freed += sizeof(struct mem_block);
  }

  return freed;
}

/* Free a large object given mem block
 *
 * Args:
 *      struct mem_block* large_obj_mb:
 *          Large object mem block
 */
void free_large_obj(struct mem_block* large_obj_mb) {
  LOCK(mem_allocator->mem_lock);

  deallocate_mb(large_obj_mb, &(mem_allocator->free_list));

  UNLOCK(mem_allocator->mem_lock);
}

/* Free a used block from a superblock.
 *
 * Args:
 *      struct superblock* sb:
 *          The current superblock.
 *      void *data:
 *          The pointer to data location to be freed.
 */
void free_block(struct superblock* sb, void *data){
  // Find the corresponding mem_block metadata for data
  struct mem_block* mem_block = GET_MEM_BLOCK_FROM_DATA(data);
  // Actually free the memory block
  uint32_t freed = deallocate_mb(mem_block, &(sb->free_list));
  sb->free_mem += freed;
  sb->heap->used -= freed;
}

/* Reduce the size of given heap by remove the given sb
 * if conditions below are met:
 *    1. the superblock is still free,
 *    2. there are at least K superblocks on the thread's heap
 *    3. the heap has an overall usage of less than F, a percentage.
 *
 * Args:
 *      struct heap* heap:
 *          The current heap.
 *      struct superblock* sb:
 *          The current supberblock.
 */
void reduce_heap_size(struct heap* heap, struct superblock* sb) {
  uint32_t total_heap_size = SUPERBLOCK_DATA_SIZE * (heap->sb_count - sizeof(struct mem_block));

  // We'll check if any condition is not met in order to return early
  if (heap->sb_count <= K
      || sb->free_mem < (SUPERBLOCK_DATA_SIZE - sizeof(struct mem_block))
      || (heap->used/(double)total_heap_size) >= F) {
    return;
  }

  // Remove the sb from the heap
  remove_sb_from_heap(sb);

  LOCK(mem_allocator->global_heap->heap_lock);

  // Add the sb to the global heap
  add_sb_to_heap(mem_allocator->global_heap, sb);

  UNLOCK(mem_allocator->global_heap->heap_lock);
}

/* The mm_free routine is only guaranteed to work when it is passed pointers
 * to allocated blocks that were returned by previous calls to mm_malloc. The
 * mm_free routine should add the block to the pool of unallocated blocks,
 * making the memory available to future mm_malloc calls.
 *
 * Args:
 *      void *ptr: The memory that need to be freed.
 */
void mm_free(void *ptr)
{
  struct mem_block* mem_block = ptr_to_mb(ptr);

  // Check if the block is large.
  if (GET_LARGE_BIT(mem_block)) {
    free_large_obj(mem_block);
    return;
  }
  // This is inside a superblock. Find the sb
  struct superblock* sb = (struct superblock*) GET_DATA_FROM_MEM_BLOCK(mem_block);
  // Since we are freeing a block in sb, and the block is not empty so it is not
  // moved to other heaps. Hence we dont worry about race condition here.
  struct heap* heap = sb->heap;

  LOCK(heap->heap_lock);

  free_block(sb, ptr);

  // Attempt to evice the current sb from the heap if this is not the global heap
  if (heap->tid != 0) reduce_heap_size(heap, sb);

  UNLOCK(heap->heap_lock);
}

/* Init allocator.
 * Before calling mm_malloc or mm_free, the application program calls mm_init
 * to perform any necessary initializations, including the allocation of the
 * initial heap area.
 *
 * Return:
 *      int:
 *          The return value should be -1 if there was a problem
 *          with the initialization, 0 otherwise.
 */
int mm_init(void)
{
  if (dseg_lo != NULL || dseg_hi != NULL) {
    return 0;
  }

  if (mem_init() == -1 ) return -1;

  uint32_t mem_allocator_size = size_alignment(sizeof(struct allocator_meta), CACHE_LINE);
  /* Allocate certain amount of memory in advance */
  void* result = mem_sbrk (mem_allocator_size + SUPER_BLOCK_ALIGNMENT * 2);

  if (result == NULL) return -1;

  // Init the mem allocator
  mem_allocator = (struct allocator_meta*) dseg_lo;
  mem_allocator->heap_list = NULL;
  INIT_LOCK(mem_allocator->mem_lock);
  INIT_LOCK(mem_allocator->heap_list_lock);

  // Init the 1st mem block
  mem_allocator->first_mb = (struct mem_block*)(
    (char*)dseg_lo + mem_allocator_size
  );

  mem_allocator->free_list = mem_allocator->first_mb;
  mem_allocator->last_mb = mem_allocator->first_mb;

  struct mem_block* first_mb = mem_allocator->first_mb;

  SET_FREE_BIT(first_mb);
  CLEAR_LARGE_BIT(first_mb);

  first_mb->next = NULL;
  first_mb->previous = NULL;

  // Total space we have
  first_mb->blk_size = dseg_hi - dseg_lo + 1;
  first_mb->blk_size -= mem_allocator_size;
  first_mb->blk_size -= sizeof (struct mem_block);

  // Allocate space for global heap
  mem_allocator->global_heap = allocate_heap(0);
  if (mem_allocator->global_heap == NULL) return -1;

  mem_allocator->global_heap->next = NULL;
  return 0;
}

