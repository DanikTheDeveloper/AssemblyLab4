#ifndef CACHE_H
#define CACHE_H

#include "dogfault.h"
#include <assert.h>
#include <ctype.h>
#include <getopt.h>
#include <math.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum status_enum {
  CACHE_MISS = 0,
  CACHE_HIT = 1,
  CACHE_EVICT = 2
};

typedef struct _line {
  /* Record cache block (i.e., cache line) address for tracing purpose.
   * Block address (block_addr) is the original cache access address 
   * whose byte offset bits are cleared to 0.
   * Note in lab 4, we do not record the actual data of a cache block.
   */
  unsigned long long block_addr;
  
  bool valid;  // valid bit for the cache block
  unsigned long long tag; // tag bits of the cache block
  
  /* lru_clock is used to maintain the LRU clock of the cache block. 
   * The high lru_clock is, the more recent the cache block is accessed.
   * lru_clock per cache block is updated based on the current global 
   * lru_clock inside its corresponding cache set.
   */
  unsigned long long lru_clock;
  
  /* access_counter is used to implement LFU replacement policy.
   * It tracks how many times the current cache block is accessed.
   */
  int access_counter; 
} Line;

typedef struct _set {
  Line *lines;  // List/Array of cache lines/block in the cache set

  /* global lru_clock inside each cache set, which starts from 0.  
   * Whenever the cache set is accessed, no matter which cache block
   * inside the set is accessed, it increments the global lru_clock by 1.
   */
  unsigned long long lru_clock;
} Set;

typedef struct _cache {
  // Cache parameters, which users configure from the command line
  //-s <num>: Number of set index bits. i.e., number of cache sets = 2^s
  int setBits;
  //-E <num>: Number of lines per set. i.e., associativity, number of ways
  int linesPerSet;
  //-b <num>: Number of block offset bits. i.e., number of bytes per block = 2^b
  int blockBits;

  // Core cache data structure
  Set *sets; // List/Array of cache sets in the cache

  // Cache stats to count the total number of hits, misses, and evictions
  int hit_count;
  int miss_count;
  int eviction_count;
  
  // Cache replacement policy
  // 0: Least Recently Used (LRU), 1: Least Frequently Used (LFU)
  int lfu;

  bool displayTrace; // Used for verbose prints
  char* name; // name for the cache
} Cache;

typedef struct _result {
  int status;                    // 0: miss 1: hit 2: evict
  unsigned long long victim_block_addr; // block address of the victim line.
  unsigned long long insert_block_addr; // block address of inserted line.
} result;

// this function will be removed once we figure out the final solution
void print_result(result r);

/* This is the entry point to operate the cache for a given address in the trace file.
 * First, is increments the global lru_clock in the corresponding cache set for the address.
 * Second, it checks if the address is already in the cache using the "probe_cache" function.
 * If yes, it is a cache hit:
 *     1) call the "hit_cacheline" function to update the counters inside the hit cache 
 *        line, including its lru_clock and access_counter.
 *     2) record a hit status in the return "result" struct and update hit_count 
 * Otherwise, it is a cache miss:
 *     1) call the "insert_cacheline" function, trying to find an empty cache line in the
 *        cache set and insert the address into the empty line. 
 *     2) if the "insert_cacheline" function returns true, record a miss status and the
          inserted block address in the return "result" struct and update miss_count
 *     3) otherwise, if the "insert_cacheline" function returns false:
 *          a) call the "victim_cacheline" function to figure which victim cache line to 
 *             replace based on the cache replacement policy (LRU and LFU).
 *          b) call the "replace_cacheline" function to replace the victim cache line with
 *             the new cache line to insert.
 *          c) record an eviction status, the victim block address, and the inserted block
 *             address in the return "result" struct. Update miss_count and eviction_count.
 */
result operateCache(const unsigned long long address, Cache *cache);

// HELPER FUNCTIONS USEFUL FOR IMPLEMENTING THE CACHE
// Given an address, return the block (aligned) address,
// i.e., byte offset bits are cleared to 0
unsigned long long address_to_block(const unsigned long long address,
                                    const Cache *cache);
// Return the tag of an address
unsigned long long cache_tag(const unsigned long long address,
                             const Cache *cache);
// Return the cache set index of the address
unsigned long long cache_set(const unsigned long long address,
                             const Cache *cache);

// Check if the address is found in the cache. If so, return true. else return false.
bool probe_cache(const unsigned long long address, const Cache *cache);

// Access address in cache. Called only if probe is successful.
// Update the LRU (least recently used) or LFU (least frequently used) counters.
void hit_cacheline(const unsigned long long address, Cache *cache);

/* This function is only called if probe_cache returns false, i.e., the address is
 * not in the cache. In this function, it will try to find an empty (i.e., invalid)
 * cache line for the address to insert. 
 * If it found an empty one:
 *     1) it inserts the address into that cache line (marking it valid).
 *     2) it updates the cache line's lru_clock based on the global lru_clock 
 *        in the cache set and initiates the cache line's access_counter.
 *     3) it returns true.
 * Otherwise, it returns false.  
 */ 
bool insert_cacheline(const unsigned long long address, Cache *cache);

// If there is no empty cacheline, this method figures out which cacheline to replace
// depending on the cache replacement policy (LRU and LFU). It returns the block address
// of the victim cacheline; note we no longer have access to the full address of the victim
unsigned long long victim_cacheline(const unsigned long long address,
				    const Cache *cache);

/* Replace the victim cacheline with the new adddress to insert. Note for the victim cachline,
 * we only have its block address. For the new address to be inserted, we have its full address.
 * Remember to update the new cache line's lru_clock based on the global lru_clock in the cache
 * set and initiate the cache line's access_counter.
 */
void replace_cacheline(const unsigned long long victim_block_addr,
		       const unsigned long long insert_addr, Cache *cache);

// allocate the memory space for the cache with the given cache parameters
// and initialize the cache sets and lines.
// Initialize the cache name to the given name 
void cacheSetUp(Cache *cache, char *name);

// deallocate the memory space for the cache
void deallocate(Cache *cache);

// print out summary stats for the cache
void printSummary(const Cache *cache);
#endif // CACHE_H
