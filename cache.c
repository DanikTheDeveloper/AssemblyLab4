#include "cache.h"
#include "dogfault.h"
#include <assert.h>
#include <ctype.h>
#include <getopt.h>
#include <math.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// DO NOT MODIFY THIS FILE. INVOKE AFTER EACH ACCESS FROM runTrace
void print_result(result r) {
  if (r.status == CACHE_EVICT)
    printf(" [status: miss eviction, victim_block: 0x%llx, insert_block: 0x%llx]",
           r.victim_block_addr, r.insert_block_addr);
  if (r.status == CACHE_HIT)
    printf(" [status: hit]");
  if (r.status == CACHE_MISS)
    printf(" [status: miss, insert_block: 0x%llx]", r.insert_block_addr);
}

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
result operateCache(const unsigned long long address, Cache *cache) {
  
  result r;

  // Increment the global lru_clock for the corresponding set.
  unsigned long long setIndex = cache_set(address, cache);
  cache->sets[setIndex].lru_clock++;

  // Check if the address is in the cache.
  if (probe_cache(address, cache)) {
    // If the address is in the cache, it's a hit.
    hit_cacheline(address, cache);
    r.status = CACHE_HIT;
    cache->hit_count++;
  } else {
    // If the address is not in the cache, it's a miss.
    if (insert_cacheline(address, cache)) {
      // If we could insert the address into an empty line, it's a simple miss.
      r.status = CACHE_MISS;
      r.insert_block_addr = address_to_block(address, cache);
      cache->miss_count++;
    } else {
      // If we could not insert the address because there was no empty line,
      // we need to evict a line.
      unsigned long long victim_block_addr = victim_cacheline(address, cache);
      replace_cacheline(victim_block_addr, address, cache);
      r.status = CACHE_EVICT;
      r.victim_block_addr = victim_block_addr;
      r.insert_block_addr = address_to_block(address, cache);
      cache->miss_count++;
      cache->eviction_count++;
    }
  }
  return r;
}

// HELPER FUNCTIONS USEFUL FOR IMPLEMENTING THE CACHE
// Given an address, return the block (aligned) address,
// i.e., byte offset bits are cleared to 0
unsigned long long address_to_block(const unsigned long long address,
                                const Cache *cache) {
  unsigned long long blockOffsetMask = (1 << cache->blockBits) - 1;
  return address & ~blockOffsetMask;
}

// Return the cache tag of an address
unsigned long long cache_tag(const unsigned long long address,
                             const Cache *cache) {
  unsigned long long blockOffsetMask = (1 << cache->blockBits) - 1;
  unsigned long long setIndexMask = ((1 << (cache->setBits + cache->blockBits)) - 1) & ~blockOffsetMask;
  return (address & ~setIndexMask) >> (cache->blockBits + cache->setBits);
}

// Return the cache set index of the address
unsigned long long cache_set(const unsigned long long address,
                             const Cache *cache) {
  unsigned long long blockOffsetMask = (1 << cache->blockBits) - 1;
  unsigned long long setIndexMask = ((1 << (cache->setBits + cache->blockBits)) - 1) & ~blockOffsetMask;
  return (address & setIndexMask) >> cache->blockBits;
}

// Check if the address is found in the cache. If so, return true. else return false.
bool probe_cache(const unsigned long long address, const Cache *cache) {
  // Extract the block address, set index, and tag from the given address
  unsigned long long blockAddress = address_to_block(address, cache);
  unsigned long long setIndex = cache_set(blockAddress, cache);
  unsigned long long tag = cache_tag(blockAddress, cache);

  // Get the corresponding set from the cache
  Set *set = &cache->sets[setIndex];

  // Check each line in the set
  for (int i = 0; i < cache->linesPerSet; ++i) {
    // If the line is valid and its tag matches the given tag, return true
    if (set->lines[i].valid && set->lines[i].tag == tag) {
      return true;
    }
  }

  // If no match was found, return false
  return false;
}


// Access address in cache. Called only if probe is successful.
// Update the LRU (least recently used) or LFU (least frequently used) counters.
void hit_cacheline(const unsigned long long address, Cache *cache){
  unsigned long long blockAddress = address_to_block(address, cache);
  unsigned long long setIndex = cache_set(blockAddress, cache);
  unsigned long long tag = cache_tag(blockAddress, cache);

  Set *set = &cache->sets[setIndex];

  // Iterate over the cache lines in the set
  for (int i = 0; i < cache->linesPerSet; ++i) {
    if (set->lines[i].valid && set->lines[i].tag == tag) {
      set->lines[i].lru_clock = set->lru_clock;  // update the lru_clock of the cache line
      set->lines[i].access_counter++;             // increment the access_counter of the cache line
      break;
    }
  }
 }

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
bool insert_cacheline(const unsigned long long address, Cache *cache) {
  unsigned long long blockAddress = address_to_block(address, cache);
  unsigned long long setIndex = cache_set(blockAddress, cache); 
  unsigned long long tag = cache_tag(blockAddress, cache);
  
  // Get the corresponding set from the cache
  Set *set = &cache->sets[setIndex];
  
  // Check each line in the set
  for (int i = 0; i < cache->linesPerSet; ++i) {
    // If the line is not valid, insert the address and update lru (global and instance) and return true and initialize access counter.
    if (!set->lines[i].valid) {
    	set->lines[i].tag = tag; 
    	set->lines[i].block_addr = blockAddress;
    	set->lines[i].valid = true;
    	set->lines[i].lru_clock = cache->sets[setIndex].lru_clock;
    	set->lines[i].access_counter = 0;
    	return true;
    }
  } 
  return false;
}

// If there is no empty cacheline, this method figures out which cacheline to replace
// depending on the cache replacement policy (LRU and LFU). It returns the block address
// of the victim cacheline; note we no longer have access to the full address of the victim
unsigned long long victim_cacheline(const unsigned long long address,
                                const Cache *cache) {
  unsigned long long blockAddress = address_to_block(address, cache);
  unsigned long long setIndex = cache_set(blockAddress, cache);

  Set *set = &cache->sets[setIndex];
  int victim_line = 0;
  if(cache->lfu == 0) {
    // Here we use LRU policy to find the victim cache line to replace.
    for (int i = 1; i < cache->linesPerSet; ++i) {
      if (set->lines[i].lru_clock < set->lines[victim_line].lru_clock) {
        victim_line = i;
      }
    }
  }
  else if (cache->lfu == 1) {
    // Here we use LFU policy to find the victim cache line to replace.
    for (int i = 1; i < cache->linesPerSet; ++i) {
      if (set->lines[i].access_counter < set->lines[victim_line].access_counter || ((set->lines[i].access_counter == set->lines[victim_line].access_counter) && set->lines[i].lru_clock < set->lines[victim_line].lru_clock)) {
        victim_line = i;
      }
    }
  }
  return set->lines[victim_line].block_addr;
}

/* Replace the victim cacheline with the new address to insert. Note for the victim cachline,
 * we only have its block address. For the new address to be inserted, we have its full address.
 * Remember to update the new cache line's lru_clock based on the global lru_clock in the cache
 * set and initiate the cache line's access_counter.
 */
void replace_cacheline(const unsigned long long victim_block_addr,
		       const unsigned long long insert_addr, Cache *cache) {
  unsigned long long blockAddress = address_to_block(insert_addr, cache);
  unsigned long long setIndex = cache_set(blockAddress, cache);
  unsigned long long tag = cache_tag(blockAddress, cache);

  Set *set = &cache->sets[setIndex];

  for (int i = 0; i < cache->linesPerSet; ++i) {
    if (set->lines[i].valid && set->lines[i].block_addr == victim_block_addr) {
      // replace the block address of the victim cache line
      set->lines[i].tag = tag;
      set->lines[i].block_addr = insert_addr;                          
      // update the lru_clock of the new cache line
      set->lines[i].lru_clock = cache->sets[setIndex].lru_clock;
      // initiate the access_counter of the new cache line           
      set->lines[i].access_counter = 0;                   
      break;
    }
  }
}

// allocate the memory space for the cache with the given cache parameters
// and initialize the cache sets and lines.
// Initialize the cache name to the given name 
void cacheSetUp(Cache *cache, char *name) {
  cache->name = name;
  cache->sets = (Set*) malloc((1 << cache->setBits) * sizeof(Set));
  for (int i = 0; i < (1 << cache->setBits); ++i) {
    cache->sets[i].lines = (Line*) malloc(cache->linesPerSet * sizeof(Line));
    memset(cache->sets[i].lines, 0, cache->linesPerSet * sizeof(Line));
  }
}


// deallocate the memory space for the cache
void deallocate(Cache *cache) {
  for (int i = 0; i < (1 << cache->setBits); ++i) {
    free(cache->sets[i].lines);
  }
  free(cache->sets);
}


// print out summary stats for the cache
void printSummary(const Cache *cache) {
  printf("%s hits: %d, misses: %d, evictions: %d\n", cache->name, cache->hit_count,
         cache->miss_count, cache->eviction_count);
}
