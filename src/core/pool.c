#include "flicknet/pool.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FN_POOL_NODE_MAGIC UINT64_C(0x464e504f4f4c3032)

typedef union fn_pool_node fn_pool_node_t;

union fn_pool_node {
  struct {
    fn_pool_node_t *next;
    fn_pool_t *owner;
    uint64_t magic;
    bool live;
  } state;
  max_align_t alignment;
};

static fn_result_t pool_result(fn_status_t code)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE : FN_STAGE_RESOURCE,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static bool pool_class_valid(fn_budget_class_t budget_class)
{
  return (int)budget_class >= (int)FN_BUDGET_ACTIVE &&
         (int)budget_class < (int)FN_BUDGET_CLASS_COUNT;
}

static void *system_allocate(void *context, size_t size)
{
  (void)context;
  return malloc(size);
}

static void system_deallocate(void *context, void *pointer)
{
  (void)context;
  free(pointer);
}

fn_allocator_t fn_allocator_system(void)
{
  const fn_allocator_t allocator = {
    .context = NULL,
    .allocate = system_allocate,
    .deallocate = system_deallocate,
  };
  return allocator;
}

fn_result_t fn_pool_init(fn_pool_t *pool, size_t block_size, size_t capacity,
                         size_t cache_limit, fn_budget_t *owned_memory,
                         fn_budget_t *pool_bytes,
                         fn_budget_class_t budget_class,
                         fn_allocator_t allocator)
{
  size_t allocation_size = 0;

  if (pool == NULL) {
    return pool_result(FN_INVALID);
  }
  memset(pool, 0, sizeof(*pool));
  if (owned_memory == NULL || pool_bytes == NULL ||
      owned_memory == pool_bytes || !pool_class_valid(budget_class) ||
      allocator.allocate == NULL || allocator.deallocate == NULL ||
      cache_limit > capacity || (capacity != 0 && block_size == 0) ||
      !fn_size_add(sizeof(fn_pool_node_t), block_size, &allocation_size)) {
    return pool_result(FN_INVALID);
  }

  pool->block_size = block_size;
  pool->allocation_size = allocation_size;
  pool->capacity = capacity;
  pool->cache_limit = cache_limit;
  pool->owned_memory = owned_memory;
  pool->pool_bytes = pool_bytes;
  pool->budget_class = budget_class;
  pool->allocator = allocator;
  return pool_result(FN_OK);
}

fn_result_t fn_pool_acquire(fn_pool_t *pool, void **out_block)
{
  fn_pool_node_t *node;
  fn_result_t result;

  if (out_block == NULL) {
    return pool_result(FN_INVALID);
  }
  *out_block = NULL;
  if (pool == NULL || pool->owned_memory == NULL ||
      pool->pool_bytes == NULL || pool->allocator.allocate == NULL ||
      pool->allocator.deallocate == NULL ||
      pool->live_blocks > pool->total_blocks ||
      pool->cached_blocks > pool->total_blocks ||
      pool->live_blocks + pool->cached_blocks != pool->total_blocks) {
    return pool_result(FN_INVALID);
  }

  if (pool->cached_blocks != 0) {
    node = pool->free_list;
    if (node == NULL || node->state.magic != FN_POOL_NODE_MAGIC ||
        node->state.owner != pool || node->state.live) {
      return pool_result(FN_INVALID);
    }
    pool->free_list = node->state.next;
    node->state.next = NULL;
    node->state.live = true;
    pool->cached_blocks--;
    pool->live_blocks++;
    *out_block = (void *)(node + 1);
    return pool_result(FN_OK);
  }

  if (pool->total_blocks >= pool->capacity) {
    return pool_result(FN_LIMIT);
  }
  result = fn_budget_reserve_pair(
    pool->owned_memory, pool->allocation_size, pool->pool_bytes,
    pool->block_size, pool->budget_class);
  if (result.code != FN_OK) {
    return result;
  }
  node = pool->allocator.allocate(pool->allocator.context,
                                  pool->allocation_size);
  if (node == NULL) {
    (void)fn_budget_release_pair(
      pool->owned_memory, pool->allocation_size, pool->pool_bytes,
      pool->block_size, pool->budget_class);
    return pool_result(FN_NO_MEMORY);
  }
  node->state.next = NULL;
  node->state.owner = pool;
  node->state.magic = FN_POOL_NODE_MAGIC;
  node->state.live = true;
  pool->total_blocks++;
  pool->live_blocks++;
  *out_block = (void *)(node + 1);
  return pool_result(FN_OK);
}

fn_result_t fn_pool_release(fn_pool_t *pool, void *block)
{
  fn_pool_node_t *node;
  fn_result_t result;

  if (pool == NULL || block == NULL || pool->live_blocks == 0) {
    return pool_result(FN_INVALID);
  }
  node = ((fn_pool_node_t *)block) - 1;
  if (node->state.magic != FN_POOL_NODE_MAGIC ||
      node->state.owner != pool || !node->state.live) {
    return pool_result(FN_INVALID);
  }

  if (pool->cached_blocks < pool->cache_limit) {
    node->state.live = false;
    node->state.next = pool->free_list;
    pool->free_list = node;
    pool->live_blocks--;
    pool->cached_blocks++;
    return pool_result(FN_OK);
  }

  result = fn_budget_release_pair(
    pool->owned_memory, pool->allocation_size, pool->pool_bytes,
    pool->block_size, pool->budget_class);
  if (result.code != FN_OK) {
    return result;
  }
  node->state.live = false;
  node->state.magic = UINT64_C(0);
  pool->allocator.deallocate(pool->allocator.context, node);
  pool->live_blocks--;
  pool->total_blocks--;
  return pool_result(FN_OK);
}

fn_result_t fn_pool_trim(fn_pool_t *pool)
{
  fn_pool_node_t *node;

  if (pool == NULL || pool->owned_memory == NULL ||
      pool->pool_bytes == NULL || pool->allocator.deallocate == NULL) {
    return pool_result(FN_INVALID);
  }
  while (pool->free_list != NULL) {
    fn_result_t result;
    node = pool->free_list;
    if (node->state.magic != FN_POOL_NODE_MAGIC ||
        node->state.owner != pool || node->state.live ||
        pool->cached_blocks == 0 || pool->total_blocks == 0) {
      return pool_result(FN_INVALID);
    }
    result = fn_budget_release_pair(
      pool->owned_memory, pool->allocation_size, pool->pool_bytes,
      pool->block_size, pool->budget_class);
    if (result.code != FN_OK) {
      return result;
    }
    pool->free_list = node->state.next;
    node->state.magic = UINT64_C(0);
    pool->allocator.deallocate(pool->allocator.context, node);
    pool->cached_blocks--;
    pool->total_blocks--;
  }
  return pool_result(FN_OK);
}

fn_result_t fn_pool_destroy(fn_pool_t *pool)
{
  fn_result_t result;
  if (pool == NULL || pool->live_blocks != 0) {
    return pool_result(FN_INVALID);
  }
  result = fn_pool_trim(pool);
  if (result.code != FN_OK) {
    return result;
  }
  memset(pool, 0, sizeof(*pool));
  return pool_result(FN_OK);
}

fn_result_t fn_pool_snapshot(const fn_pool_t *pool, fn_pool_snapshot_t *out)
{
  if (pool == NULL || out == NULL ||
      pool->live_blocks > pool->total_blocks ||
      pool->cached_blocks > pool->total_blocks ||
      pool->live_blocks + pool->cached_blocks != pool->total_blocks) {
    return pool_result(FN_INVALID);
  }
  out->block_size = pool->block_size;
  out->capacity = pool->capacity;
  out->cache_limit = pool->cache_limit;
  out->total_blocks = pool->total_blocks;
  out->live_blocks = pool->live_blocks;
  out->cached_blocks = pool->cached_blocks;
  return pool_result(FN_OK);
}
