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
#define CLEAR_FREE_BIT(var) (var->flags &= ~IS_FREE_MASK)

#define GET_LARGE_BIT(var) (var->flags & IS_LARGE_MASK)
#define SET_LARGE_BIT(var) (var->flags |= IS_LARGE_MASK)
#define CLEAR_LARGE_BIT(var) (var->flags &= ~IS_LARGE_MASK)

#define GET_DATA_FROM_MEM_BLOCK(var) ((char*)var + sizeof(struct mem_block))
#define GET_MEM_BLOCK_FROM_DATA(var) ((struct mem_block*)(char*)var - sizeof(struct mem_block))

#define LOCK(var) pthread_mutex_lock(&(var))
#define UNLOCK(var) pthread_mutex_unlock(&(var))

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
   struct superblock* first_superblock;
};

struct superblock {
  uint32_t free_mem;
  pthread_mutex_t sb_lock;
  struct superblock* next;
  struct superblock* previous;
  struct thread_meta* thread_heap;
};


struct allocator_meta* mem_allocator;

/* ABE: fns to avoid compilation errors. these are the lock and unlock fns */

void lock_superblock(struct superblock* sb){ }
void unlock_superblock(struct superblock* sb){}
void unlock_heap(struct thread_meta* theap){ }
void lock_global(){ }
void unlock_global(){ }

void find_free_mem_block(struct mem_block* first_mem_block,
                                      struct mem_block** free_mem_block,
                                      struct mem_block** previous_mem_block,
                                      size_t size) {
  struct mem_block* current_mem_block = first_mem_block;
  while (
    current_mem_block && (
      current_mem_block->blk_size < size
      || !GET_FREE_BIT(current_mem_block)
    )
  ) {
    /* All we are looking for is a free space that is larger or equal to
     * the size we are looking for.
     * we dont care about aglinment since we make sure that happend
     */
    *previous_mem_block = current_mem_block;
    current_mem_block = current_mem_block->next;
  }
  *free_mem_block = current_mem_block;
}

/*Return true iff need to allocate new mem_block */
bool use_mem_block_for_allocation(struct mem_block* result_mem_block, size_t size) {
  CLEAR_FREE_BIT(result_mem_block);
  CLEAR_LARGE_BIT(result_mem_block);
  if(size != result_mem_block->blk_size) {    
    uint32_t used_space = size + sizeof(struct mem_block);
    // create a new free mem block
    struct mem_block* new_mem_block = (struct mem_block*)(
      (char*)result_mem_block + used_space
    );
    SET_FREE_BIT(new_mem_block);
    CLEAR_LARGE_BIT(new_mem_block);
    new_mem_block->blk_size = result_mem_block->blk_size - used_space;
    new_mem_block->next = result_mem_block->next;
    new_mem_block->previous = result_mem_block;
    result_mem_block->next = new_mem_block;
    return TRUE;
  }
  return FALSE;
}

/*
 * This is try to lock the memory down mem_allocator->mem_lock
 */
struct mem_block* allocate_mem_block(struct mem_block* first_mem_block,
                                      size_t size) {
  struct mem_block* result_mem_block = NULL;
  struct mem_block* previous_mem_block = NULL;
  struct mem_block* free_mem_block = NULL;
  LOCK(mem_allocator->mem_lock);
  find_free_mem_block(first_mem_block, &free_mem_block, &previous_mem_block, size);

  if(free_mem_block) {
    // Found a memory block to be used
    result_mem_block = free_mem_block;    
    use_mem_block_for_allocation(result_mem_block, size);
  } else {
    // reached the last block, with no available memory
    if (GET_FREE_BIT(previous_mem_block)){
      result_mem_block = previous_mem_block;
      // Expand the memory
      void* result = mem_sbrk(size - result_mem_block->blk_size);
      if (result == NULL) {
        UNLOCK(mem_allocator->mem_lock);
        return NULL;
      }
    } else {
      // Expand the memory
      void* result = mem_sbrk(size + sizeof(struct mem_block));
      if (result == NULL) {
        UNLOCK(mem_allocator->mem_lock);
        return NULL;
      }

      // Create a new free mem block
      struct mem_block* new_mem_block = (struct mem_block*)(
        (char*)previous_mem_block
        + sizeof(struct mem_block)
        + previous_mem_block->blk_size
      );

      new_mem_block->blk_size = size;

      new_mem_block->next = NULL;
      new_mem_block->previous = previous_mem_block;

      previous_mem_block->next = new_mem_block;
      result_mem_block = new_mem_block;
    }
  }
  CLEAR_FREE_BIT(result_mem_block);
  CLEAR_LARGE_BIT(result_mem_block);
  result_mem_block->blk_size = size;
  UNLOCK(mem_allocator->mem_lock);
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

struct superblock* allocate_superblock() {
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
  result->free_mem = SUPERBLOCK_DATA_SIZE - sizeof(struct mem_block);
  
  struct mem_block* mem_block = (struct mem_block*)(
    (char*) result + sizeof(struct superblock)
  );
  
  mem_block->blk_size = result->free_mem;
  
  SET_FREE_BIT(mem_block);
  CLEAR_LARGE_BIT(mem_block);
  mem_block->next = NULL;
  mem_block->previous = NULL;
    
  pthread_mutex_init(&result->sb_lock, NULL);
  
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
  result->thread_id = thread_id;
  return result;
}


struct thread_meta* get_current_thread_heap() {
  pid_t thread_id = getTID();
  struct thread_meta* result;
  // This lock make sure what current_thread_heap get is not an illed state pointer
  LOCK(mem_allocator->heap_list_lock);
  struct thread_meta* current_thread_heap = mem_allocator->heap_list;
  UNLOCK(mem_allocator->heap_list_lock);
  while(current_thread_heap && current_thread_heap->thread_id != thread_id) {
    current_thread_heap = current_thread_heap->next;
  }
  
  result = current_thread_heap;
  if (result == NULL) {
    result = allocate_thread_meta(thread_id);
    
    // lock thread heap    
    LOCK(mem_allocator->heap_list_lock);
    
    result->next = mem_allocator->heap_list;
    mem_allocator->heap_list = result->next;
    
    UNLOCK(mem_allocator->heap_list_lock);
  }
  return result;
}


/* Attempt to find a superblock with within the specified heap, which has an
 * unused block that is of at least size sz. If it finds a superblock meeting
 * the requirements, it will return the locked superblock, while also locking
 * the heap. if it doesn't find a corresponding superblock, it will return NULL
 * while holding the heap lock. */
struct superblock*  find_free_superblock(struct thread_meta* theap,
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
    if (!final_sb
        || current_sb->free_mem < final_sb->free_mem){    
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

void remove_superblock_from_current_list(struct superblock* superblock) {

}

/*
 * Retrun a given superblock to global heap
 */
void thread_release_superblock(struct superblock* superblock) { //Minh
  
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
  
    
  struct superblock* new_sb = acquire_superblock_from_global();
  if (new_sb == NULL) {
    new_sb = allocate_superblock();  
  }
  new_sb->previous = NULL;
  new_sb->thread_heap = theap;
  new_sb->next = theap->first_superblock;

  theap->first_superblock = new_sb;
  return new_sb;  
}

void consolidate_mem_block(struct mem_block* mem_block) {
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
 * Return total number of consolidation. This needed to manage the free usage
 * of a superblock
 */
int free_mem_block(struct mem_block* mem_block) {  
  SET_FREE_BIT(mem_block);
  int consolidation_count = 0;
  if (mem_block->next && GET_FREE_BIT(mem_block->next)) {
    consolidate_mem_block(mem_block);
    consolidation_count++; 
  }
    
  if (mem_block->previous && GET_FREE_BIT(mem_block->previous)) {  
    consolidate_mem_block(mem_block->previous);
    consolidation_count++;
  }
  
  return consolidation_count;
}

/* Allocate a free  block from within a locked superblock. Return a pointer to
 * the data of the block if the allocation worked. Otherwise return NULL. Does
 * not release the superblock lock. */
void* allocate_block(struct superblock* free_sb, struct mem_block* free_mblk, uint32_t sz){
  //LOCK(free_sb->sb_lock);
  bool need_new_mem_block = use_mem_block_for_allocation(free_mblk, sz);
  free_sb->free_mem -= sz;
  if (need_new_mem_block) free_sb->free_mem -= sizeof(struct mem_block);
  return GET_DATA_FROM_MEM_BLOCK(free_mblk);
  //UNLOCK(free_sb->sb_lock);
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
  struct thread_meta* curr_theap = get_current_thread_heap();
  LOCK(curr_theap->thread_lock);

  // if find_free_superblock succeeds, it will be holding the the free_sb lock
  // and the heap's lock.
  struct mem_block* free_mb = NULL;
  struct superblock* free_sb = find_free_superblock(curr_theap, &free_mb, sz);

  if (free_sb == NULL){
      free_sb = thread_acquire_superblock(curr_theap, sz);
      if (free_sb == NULL)
      {
        // we have an issue: a new superblock could not be acquired from neither
        // the global heap, nor from global memory.
        UNLOCK(curr_theap->thread_lock);
        return NULL;
      }
      struct superblock* sb_first_mem_block = (struct superblock*)(
        (char*) free_sb + sizeof(struct superblock)
      );
      struct superblock* previous_mem_block = NULL;
      find_free_mem_block(sb_first_mem_block, &free_mb, &previous_mem_block, sz);
  }
  // We now have a ptr to a superblock with a free block that we can use.
  void* blk_data =  allocate_block(free_sb, free_mb, sz);

  // release used locks before returning  
  UNLOCK(curr_theap->thread_lock);
  return blk_data;
}

void free_large_object(struct mem_block* large_object_mem_block) {
  LOCK(mem_allocator->mem_lock);
  free_mem_block(large_object_mem_block);
  UNLOCK(mem_allocator->mem_lock);
}

struct mem_block* get_mem_block_from_pointer(void *ptr) {
  uint32_t block_count = (uint32_t)(
      (
        ((char*)ptr - (char*)mem_allocator)
        - sizeof(struct allocator_meta) 
      )
      / SUPER_BLOCK_ALIGNMENT
  );
  return (struct mem_block*)(
    (char*) mem_allocator
    + sizeof(struct  allocator_meta)
    + SUPER_BLOCK_ALIGNMENT * block_count 
  );
}

/* Given a thread's heap metadata, if a thread's emptiness is below a threshold,
 * return a locked superblock meant to be free, while holding the heap lock. If
 * the thread is not below the emptiness threshold, return NULL while holding
 * no locks. */
struct superblock*  is_free_enough(struct thread_meta* theap)
{
  // work kind of like a test and test and set. test if it's possibly free enough,
  // then attempt to find the first empty sb locking the superblocks as we traverse.
  // once an empty sb has been found (and locked), lock the heap, determine if it's
  // empty enough, and if it is, return the locked sb while holding the heap lock.
  // determine if the heap seems empty enough.
  // if not return immediately
  return NULL;
}

/* Given a superblock, evict the superblock from the thread's heap, and put it
 * up into the global heap. Consolidation is done in this function. Assume that
 * the sb's lock, the corressponding thread's lock and the global heap lock are
 * held. */
void evict_superblock_to_gheap (struct superblock* sb)
{
}

/* Free a used block from a locked superblock. */
void free_block(struct superblock* sb, void *data){
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
  struct thread_meta* theap = sb->thread_heap;

  // then  lock the superblock since we'll be modifying the contents
  lock_superblock(sb);
  free_block(sb, ptr);
  unlock_superblock(sb);

  // Now to check if the heap's superblock free "level" is low enough to evict
  // a superpage.  if is_free_enough return a sb, then it's also holding
  // free_this's lock and the heap lock.
  struct superblock* free_this = is_free_enough(theap);
  if (free_this)
  {
    lock_global();
    evict_superblock_to_gheap(free_this);
    unlock_global();
    unlock_heap(theap);
    // don't attempt to unlock free_this as it may have been consolidated with
    // another free memory block.
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
    mem_allocator->global_heap->first_superblock = NULL;

    return 0;
  }
  // It's already been initialized
  return 0;
}

