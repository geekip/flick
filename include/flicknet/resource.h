#ifndef FLICKNET_RESOURCE_H
#define FLICKNET_RESOURCE_H

#include "flicknet/result.h"

#include <stddef.h>
#include <stdint.h>

typedef enum {
  FN_BUDGET_ACTIVE = 0,
  FN_BUDGET_CANDIDATE,
  FN_BUDGET_RETAINED,
  FN_BUDGET_CLEANUP,
  FN_BUDGET_CLASS_COUNT
} fn_budget_class_t;

typedef struct {
  size_t limit;
  size_t cleanup_reserve;
  size_t used[FN_BUDGET_CLASS_COUNT];
  uint64_t epoch;
} fn_budget_t;

typedef struct {
  size_t limit;
  size_t cleanup_reserve;
  size_t active;
  size_t candidate;
  size_t retained;
  size_t cleanup;
  size_t total;
  uint64_t epoch;
} fn_budget_snapshot_t;

typedef struct {
  size_t session_limit;
  size_t handshake_limit;
  size_t fd_limit;
  size_t owned_memory_limit_bytes;
  size_t cleanup_reserve_bytes;
  size_t buffer_pool_limit_bytes;
  size_t async_operation_limit;
  size_t completion_entry_limit;
  size_t completion_limit_bytes;
  size_t loop_post_entry_limit;
  size_t loop_post_limit_bytes;
  size_t worker_limit;
  size_t worker_job_limit;
  size_t worker_input_limit_bytes;
  size_t worker_result_limit_bytes;
  size_t lazy_waiter_limit;
  size_t lazy_waiter_per_object_limit;
  size_t lazy_waiter_limit_bytes;
  size_t resource_waiter_limit;
  size_t resource_waiter_limit_bytes;
  size_t timer_limit;
  size_t resolver_pending_limit;
  size_t retired_runtime_limit;
  uint64_t resource_wait_timeout_ms;
  uint64_t worker_task_timeout_ms;
} fn_limits_t;

fn_limits_t fn_limits_default(void);

bool fn_size_add(size_t left, size_t right, size_t *out);
bool fn_size_multiply(size_t left, size_t right, size_t *out);

fn_result_t fn_budget_init(fn_budget_t *budget, size_t limit,
                           size_t cleanup_reserve);
fn_result_t fn_budget_reserve(fn_budget_t *budget,
                              fn_budget_class_t budget_class, size_t amount);
fn_result_t fn_budget_release(fn_budget_t *budget,
                              fn_budget_class_t budget_class, size_t amount);
fn_result_t fn_budget_reclassify(fn_budget_t *budget,
                                 fn_budget_class_t from,
                                 fn_budget_class_t to, size_t amount);
fn_result_t fn_budget_snapshot(const fn_budget_t *budget,
                               fn_budget_snapshot_t *out);

/* pair 操作同时检查两个独立账本，任一失败时均不改变状态。 */
fn_result_t fn_budget_reserve_pair(fn_budget_t *total, size_t total_amount,
                                   fn_budget_t *sub, size_t sub_amount,
                                   fn_budget_class_t budget_class);
fn_result_t fn_budget_release_pair(fn_budget_t *total, size_t total_amount,
                                   fn_budget_t *sub, size_t sub_amount,
                                   fn_budget_class_t budget_class);

#endif
