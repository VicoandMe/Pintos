#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"
#include "devices/timer.h"
#include "threads/synch.h"
#include <list.h>

#define WRITE_BACK_INTERVAL 5*TIMER_FREQ
#define MAX_FILESYS_CACHE_SIZE 64

struct list filesys_cache;
uint32_t filesys_cache_size;
struct lock filesys_cache_lock;

struct cache_entry {
  uint8_t block[BLOCK_SECTOR_SIZE];
  block_sector_t sector;
  bool dirty;
  bool accessed;
  int open_cnt;
  struct list_elem elem;
};

void filesys_cache_init(void);
struct cache_entry *block_in_cache (block_sector_t sector);
struct cache_entry* filesys_cache_block_get (block_sector_t sector, bool dirty);
struct cache_entry* filesys_cache_block_evict (block_sector_t sector,
							       bool dirty);
int block_cache_read (struct block *block, block_sector_t sector, void *buffer);
int block_cache_read_partial (struct block *block, block_sector_t sector,
		          void *buffer, int ofs, int chunk_size);
int block_cache_write (struct block *block, block_sector_t sector, void *buffer);

int block_cache_write_partial (struct block * block, block_sector_t sector,
		          void *buffer, int ofs, int chunk_size, int sector_left);

void filesys_cache_write_to_disk (bool halt);
void thread_func_write_back (void *aux);

#endif
