#ifndef FLICKNET_POOL_H
#define FLICKNET_POOL_H

#include "flicknet/resource.h"

#include <stddef.h>

typedef void *(*fn_allocate_fn)(void *context, size_t size);
typedef void (*fn_deallocate_fn)(void *context, void *pointer);

typedef struct {
  void *context;
  fn_allocate_fn allocate;
  fn_deallocate_fn deallocate;
} fn_allocator_t;

typedef struct {
  size_t block_size;
  size_t allocation_size;
  size_t capacity;
  size_t cache_limit;
  size_t total_blocks;
  size_t live_blocks;
  size_t cached_blocks;
  void *free_list;
  fn_budget_t *owned_memory;
  fn_budget_t *pool_bytes;
  fn_budget_class_t budget_class;
  fn_allocator_t allocator;
} fn_pool_t;

typedef struct {
  size_t block_size;
  size_t capacity;
  size_t cache_limit;
  size_t total_blocks;
  size_t live_blocks;
  size_t cached_blocks;
} fn_pool_snapshot_t;

fn_allocator_t fn_allocator_system(void);

/* capacity=0 表示有效的零需求 pool；acquire 将明确返回 FN_LIMIT。 */
fn_result_t fn_pool_init(fn_pool_t *pool, size_t block_size, size_t capacity,
                         size_t cache_limit, fn_budget_t *owned_memory,
                         fn_budget_t *pool_bytes,
                         fn_budget_class_t budget_class,
                         fn_allocator_t allocator);
fn_result_t fn_pool_acquire(fn_pool_t *pool, void **out_block);
fn_result_t fn_pool_release(fn_pool_t *pool, void *block);
fn_result_t fn_pool_trim(fn_pool_t *pool);
fn_result_t fn_pool_destroy(fn_pool_t *pool);
fn_result_t fn_pool_snapshot(const fn_pool_t *pool, fn_pool_snapshot_t *out);

#endif
