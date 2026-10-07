#include "flicknet/pool.h"
#include "flicknet/resource.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
  size_t allocate_calls;
  size_t deallocate_calls;
  size_t fail_on_call;
} fault_allocator_state_t;

static void *fault_allocate(void *context, size_t size)
{
  fault_allocator_state_t *state = context;
  state->allocate_calls++;
  if (state->fail_on_call != 0 &&
      state->allocate_calls == state->fail_on_call) {
    return NULL;
  }
  return malloc(size);
}

static void fault_deallocate(void *context, void *pointer)
{
  fault_allocator_state_t *state = context;
  state->deallocate_calls++;
  free(pointer);
}

static fn_allocator_t make_fault_allocator(fault_allocator_state_t *state)
{
  const fn_allocator_t allocator = {
    .context = state,
    .allocate = fault_allocate,
    .deallocate = fault_deallocate,
  };
  return allocator;
}

static int snapshot_total(const fn_budget_t *budget, size_t expected)
{
  fn_budget_snapshot_t snapshot;
  return fn_budget_snapshot(budget, &snapshot).code == FN_OK &&
         snapshot.total == expected ? 0 : 1;
}

static int check_math_and_defaults(void)
{
  fn_limits_t limits = fn_limits_default();
  size_t value = 0;

  if (!fn_size_add((size_t)2u, (size_t)3u, &value) || value != 5u ||
      fn_size_add(SIZE_MAX, (size_t)1u, &value) ||
      !fn_size_multiply((size_t)7u, (size_t)9u, &value) || value != 63u ||
      fn_size_multiply(SIZE_MAX, (size_t)2u, &value)) {
    return 1;
  }
  if (limits.session_limit != 10000u ||
      limits.owned_memory_limit_bytes != (size_t)128u * 1024u * 1024u ||
      limits.cleanup_reserve_bytes != (size_t)2u * 1024u * 1024u ||
      limits.buffer_pool_limit_bytes != (size_t)32u * 1024u * 1024u ||
      limits.resource_wait_timeout_ms != UINT64_C(1000)) {
    return 2;
  }
  return 0;
}

static int check_budget_contract(void)
{
  fn_budget_t budget;
  fn_budget_snapshot_t before;
  fn_budget_snapshot_t after;

  if (fn_budget_init(&budget, (size_t)100u, (size_t)10u).code != FN_OK ||
      fn_budget_reserve(&budget, FN_BUDGET_ACTIVE,
                        (size_t)90u).code != FN_OK ||
      fn_budget_reserve(&budget, FN_BUDGET_ACTIVE,
                        (size_t)1u).code != FN_LIMIT ||
      fn_budget_reserve(&budget, FN_BUDGET_CLEANUP,
                        (size_t)10u).code != FN_OK ||
      fn_budget_snapshot(&budget, &before).code != FN_OK ||
      before.total != 100u || before.active != 90u || before.cleanup != 10u) {
    return 1;
  }
  if (fn_budget_release(&budget, FN_BUDGET_ACTIVE,
                        (size_t)91u).code != FN_INVALID ||
      fn_budget_snapshot(&budget, &after).code != FN_OK ||
      after.total != before.total || after.epoch != before.epoch) {
    return 2;
  }
  if (fn_budget_release(&budget, FN_BUDGET_ACTIVE,
                        (size_t)20u).code != FN_OK ||
      fn_budget_reclassify(&budget, FN_BUDGET_ACTIVE,
                           FN_BUDGET_RETAINED, (size_t)30u).code != FN_OK ||
      fn_budget_snapshot(&budget, &after).code != FN_OK ||
      after.active != 40u || after.retained != 30u || after.total != 80u ||
      after.epoch == before.epoch) {
    return 3;
  }
  return 0;
}

static int check_pair_atomicity(void)
{
  fn_budget_t total;
  fn_budget_t sub;
  fn_budget_snapshot_t before;
  fn_budget_snapshot_t after;

  if (fn_budget_init(&total, (size_t)100u, (size_t)10u).code != FN_OK ||
      fn_budget_init(&sub, (size_t)20u, (size_t)0u).code != FN_OK ||
      fn_budget_reserve_pair(&total, (size_t)30u, &sub, (size_t)20u,
                             FN_BUDGET_ACTIVE).code != FN_OK ||
      fn_budget_snapshot(&total, &before).code != FN_OK) {
    return 1;
  }
  if (fn_budget_reserve_pair(&total, (size_t)1u, &sub, (size_t)1u,
                             FN_BUDGET_ACTIVE).code != FN_LIMIT ||
      fn_budget_snapshot(&total, &after).code != FN_OK ||
      after.total != before.total || after.epoch != before.epoch ||
      snapshot_total(&sub, (size_t)20u) != 0) {
    return 2;
  }
  if (fn_budget_release_pair(&total, (size_t)30u, &sub, (size_t)20u,
                             FN_BUDGET_ACTIVE).code != FN_OK ||
      snapshot_total(&total, (size_t)0u) != 0 ||
      snapshot_total(&sub, (size_t)0u) != 0) {
    return 3;
  }
  return 0;
}

static int check_pool_contract(void)
{
  fault_allocator_state_t allocator_state = {0};
  fn_budget_t total;
  fn_budget_t sub;
  fn_pool_t pool;
  fn_pool_snapshot_t snapshot;
  void *first = NULL;
  void *second = NULL;
  void *reused = NULL;
  void *extra = NULL;

  if (fn_budget_init(&total, (size_t)1024u, (size_t)64u).code != FN_OK ||
      fn_budget_init(&sub, (size_t)64u, (size_t)0u).code != FN_OK ||
      fn_pool_init(&pool, (size_t)32u, (size_t)2u, (size_t)1u,
                   &total, &sub, FN_BUDGET_ACTIVE,
                   make_fault_allocator(&allocator_state)).code != FN_OK ||
      fn_pool_acquire(&pool, &first).code != FN_OK || first == NULL ||
      fn_pool_acquire(&pool, &second).code != FN_OK || second == NULL ||
      fn_pool_destroy(&pool).code != FN_INVALID ||
      fn_pool_acquire(&pool, &extra).code != FN_LIMIT || extra != NULL) {
    return 1;
  }
  if (fn_pool_release(&pool, first).code != FN_OK ||
      fn_pool_release(&pool, first).code != FN_INVALID ||
      fn_pool_acquire(&pool, &reused).code != FN_OK || reused != first ||
      allocator_state.allocate_calls != 2u) {
    return 2;
  }
  if (fn_pool_release(&pool, second).code != FN_OK ||
      fn_pool_release(&pool, reused).code != FN_OK ||
      fn_pool_snapshot(&pool, &snapshot).code != FN_OK ||
      snapshot.live_blocks != 0u || snapshot.cached_blocks != 1u ||
      snapshot.total_blocks != 1u || allocator_state.deallocate_calls != 1u ||
      snapshot_total(&sub, (size_t)32u) != 0) {
    return 3;
  }
  if (fn_pool_trim(&pool).code != FN_OK ||
      allocator_state.deallocate_calls != 2u ||
      snapshot_total(&total, (size_t)0u) != 0 ||
      snapshot_total(&sub, (size_t)0u) != 0 ||
      fn_pool_destroy(&pool).code != FN_OK) {
    return 4;
  }
  return 0;
}

static int check_pool_fault_and_zero_demand(void)
{
  fault_allocator_state_t allocator_state = {
    .allocate_calls = 0,
    .deallocate_calls = 0,
    .fail_on_call = 1,
  };
  fn_budget_t total;
  fn_budget_t sub;
  fn_pool_t pool;
  void *block = NULL;

  if (fn_budget_init(&total, (size_t)1024u, (size_t)64u).code != FN_OK ||
      fn_budget_init(&sub, (size_t)64u, (size_t)0u).code != FN_OK ||
      fn_pool_init(&pool, (size_t)32u, (size_t)1u, (size_t)0u,
                   &total, &sub, FN_BUDGET_ACTIVE,
                   make_fault_allocator(&allocator_state)).code != FN_OK ||
      fn_pool_acquire(&pool, &block).code != FN_NO_MEMORY || block != NULL ||
      snapshot_total(&total, (size_t)0u) != 0 ||
      snapshot_total(&sub, (size_t)0u) != 0 ||
      fn_pool_destroy(&pool).code != FN_OK) {
    return 1;
  }
  allocator_state.fail_on_call = 0;
  if (fn_pool_init(&pool, (size_t)0u, (size_t)0u, (size_t)0u,
                   &total, &sub, FN_BUDGET_ACTIVE,
                   make_fault_allocator(&allocator_state)).code != FN_OK ||
      fn_pool_acquire(&pool, &block).code != FN_LIMIT || block != NULL ||
      allocator_state.allocate_calls != 1u ||
      fn_pool_destroy(&pool).code != FN_OK) {
    return 2;
  }
  return 0;
}

int main(void)
{
  const int math_check = check_math_and_defaults();
  const int budget_check = check_budget_contract();
  const int pair_check = check_pair_atomicity();
  const int pool_check = check_pool_contract();
  const int fault_check = check_pool_fault_and_zero_demand();

  if (math_check != 0 || budget_check != 0 || pair_check != 0 ||
      pool_check != 0 || fault_check != 0) {
    fprintf(stderr,
            "P02 resource/pool check failed: math=%d budget=%d pair=%d pool=%d fault=%d.\n",
            math_check, budget_check, pair_check, pool_check, fault_check);
    return 1;
  }
  puts("P02 resource budget and bounded pool checks passed.");
  return 0;
}
