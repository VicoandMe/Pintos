#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "devices/timer.h"

void filesys_cache_init(void) {
  list_init(&filesys_cache);
  lock_init(&filesys_cache_lock);
  filesys_cache_size = 0;
  thread_create("filesys_cache_writeback", 0, thread_func_write_back, NULL);
}

struct cache_entry* block_in_cache (block_sector_t sector) {
  struct cache_entry *c;
  struct list_elem *e;
  for (e = list_begin(&filesys_cache); e != list_end(&filesys_cache);
	   e = list_next(e)) {
    c = list_entry(e , struct cache_entry, elem);
	if (c -> sector == sector) {
	  return c;
	}
  }
  return NULL;
}

struct cache_entry* filesys_cache_block_get (block_sector_t sector, bool dirty) {
  lock_acquire(&filesys_cache_lock);
  struct cache_entry *c = block_in_cache(sector);
  if (c) {
    c->open_cnt++;
	c->dirty |= dirty;
	c->accessed = true;
	lock_release(&filesys_cache_lock);
	return c;
  }
  c = filesys_cache_block_evict(sector, dirty);
  if (!c) {
	PANIC("Not enough memory for buffer cache.");
  }
  lock_release(&filesys_cache_lock);
  return c;
}

struct cache_entry* filesys_cache_block_evict (block_sector_t sector,
							       bool dirty)
{
	struct cache_entry *c;
	if (filesys_cache_size < MAX_FILESYS_CACHE_SIZE) {
	  filesys_cache_size++;
	  c = malloc(sizeof(struct cache_entry));
	  if (!c) {
	    return NULL;
	  }
	  c->open_cnt = 0;
	  list_push_back(&filesys_cache, &c->elem);
	} else {
	  bool loop = true;
	  while (loop) {
	    struct list_elem *e;
		for (e = list_begin(&filesys_cache); e != list_end(&filesys_cache);
			 e = list_next(e)) {
		  c = list_entry (e, struct cache_entry, elem);

		  if (c -> accessed) {
		    c-> accessed = false;
		  } else {
			  if (c->dirty) {
				block_write(fs_device, c->sector, (uint8_t* )c->block);
			  }
			  loop = false;
			  break;
		  }
		}
	  }
	}
	c->open_cnt++;
	c->sector = sector;
	block_read(fs_device, c->sector, (uint8_t* )c->block);
	c->dirty = dirty;
	c->accessed = true;
	return c;
}

int block_cache_read (struct block *block, block_sector_t sector, void *buffer) {
  uint8_t *buffer_ = buffer;
  struct cache_entry *c = filesys_cache_block_get (sector,false);
  c->accessed = true;
  c->dirty = true;
  c->open_cnt++;
  memcpy(buffer_, (uint8_t* )c->block, BLOCK_SECTOR_SIZE);
  return BLOCK_SECTOR_SIZE;
}

int block_cache_read_partial (struct block *block, block_sector_t sector,
		                     void *buffer, int ofs, int chunk_size) {
  uint8_t *buffer_ = buffer;
  struct cache_entry *c = filesys_cache_block_get (sector,false);
  c->accessed = true;
  c->dirty = true;
  c->open_cnt++;
  uint8_t *bounce = NULL;
  if (bounce == NULL) {
    bounce = malloc (BLOCK_SECTOR_SIZE);
  }
  memcpy(bounce ,(uint8_t* ) c->block, BLOCK_SECTOR_SIZE); 
  memcpy(buffer_, bounce + ofs, chunk_size);
  free(bounce);
  return chunk_size;
}

int block_cache_write (struct block *block, block_sector_t sector, void *buffer) {
  uint8_t *buffer_ = buffer;
  struct cache_entry *c = filesys_cache_block_get (sector,true);
  c->accessed = true;
  c->dirty = true;
  c->open_cnt++;
  memcpy((uint8_t* )c->block, buffer_, BLOCK_SECTOR_SIZE);
  return BLOCK_SECTOR_SIZE;
}

int block_cache_write_partial (struct block * block, block_sector_t sector,
		              void *buffer, int ofs, int chunk_size, int sector_left) {
  uint8_t *buffer_ = buffer;
  struct cache_entry *c = filesys_cache_block_get (sector,true);
  c->accessed = true;
  c->dirty = true;
  c->open_cnt++;
  uint8_t *bounce = NULL;
  if (bounce == NULL) {
    bounce = malloc (BLOCK_SECTOR_SIZE);
  }
  if (ofs > 0 || chunk_size < sector_left)
    memcpy(bounce, (uint8_t* )c->block, BLOCK_SECTOR_SIZE);
  else
	memset(bounce, 0, BLOCK_SECTOR_SIZE);
  memcpy (bounce + ofs, buffer, chunk_size);
  memcpy (c->block,bounce, BLOCK_SECTOR_SIZE);
  free(bounce);
}

void filesys_cache_write_to_disk (bool is_halt) {
  lock_acquire(&filesys_cache_lock);
  struct list_elem *e;
  struct cache_entry *c;
  for (e = list_begin(&filesys_cache); e != list_end(&filesys_cache);
	   e = list_next(e)) {
    c = list_entry(e , struct cache_entry, elem);
	if (c->dirty && c->open_cnt > 0) {
	  c->open_cnt--;
	  block_write (fs_device, c->sector, (uint8_t *)c->block);
	}
  }
  lock_release(&filesys_cache_lock);
}

void thread_func_write_back (void *aux UNUSED) {
  while(1) {
    timer_sleep(5*TIMER_FREQ);
	filesys_cache_write_to_disk(false);
  }
}
