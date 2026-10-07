#include "flicknet/resource.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static fn_result_t resource_result(fn_status_t code)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE : FN_STAGE_RESOURCE,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static bool budget_class_valid(fn_budget_class_t budget_class)
{
  return (int)budget_class >= (int)FN_BUDGET_ACTIVE &&
         (int)budget_class < (int)FN_BUDGET_CLASS_COUNT;
}

bool fn_size_add(size_t left, size_t right, size_t *out)
{
  if (out == NULL || right > SIZE_MAX - left) {
    return false;
  }
  *out = left + right;
  return true;
}

bool fn_size_multiply(size_t left, size_t right, size_t *out)
{
  if (out == NULL || (left != 0 && right > SIZE_MAX / left)) {
    return false;
  }
  *out = left * right;
  return true;
}

static bool budget_totals(const fn_budget_t *budget, size_t *general,
                          size_t *total)
{
  size_t value;
  size_t all;

  if (budget == NULL || budget->cleanup_reserve > budget->limit ||
      !fn_size_add(budget->used[FN_BUDGET_ACTIVE],
                   budget->used[FN_BUDGET_CANDIDATE], &value) ||
      !fn_size_add(value, budget->used[FN_BUDGET_RETAINED], &value) ||
      !fn_size_add(value, budget->used[FN_BUDGET_CLEANUP], &all) ||
      value > budget->limit - budget->cleanup_reserve ||
      budget->used[FN_BUDGET_CLEANUP] > budget->cleanup_reserve ||
      all > budget->limit) {
    return false;
  }
  if (general != NULL) {
    *general = value;
  }
  if (total != NULL) {
    *total = all;
  }
  return true;
}

static fn_result_t budget_can_reserve(const fn_budget_t *budget,
                                      fn_budget_class_t budget_class,
                                      size_t amount)
{
  size_t general;
  size_t total;
  size_t next;

  if (!budget_class_valid(budget_class) ||
      !budget_totals(budget, &general, &total)) {
    return resource_result(FN_INVALID);
  }
  if (!fn_size_add(total, amount, &next) || next > budget->limit) {
    return resource_result(FN_LIMIT);
  }
  if (budget_class == FN_BUDGET_CLEANUP) {
    if (!fn_size_add(budget->used[FN_BUDGET_CLEANUP], amount, &next) ||
        next > budget->cleanup_reserve) {
      return resource_result(FN_LIMIT);
    }
  } else if (!fn_size_add(general, amount, &next) ||
             next > budget->limit - budget->cleanup_reserve) {
    return resource_result(FN_LIMIT);
  }
  return resource_result(FN_OK);
}

static void budget_epoch_advance(fn_budget_t *budget)
{
  if (budget->epoch != UINT64_MAX) {
    budget->epoch++;
  }
}

fn_limits_t fn_limits_default(void)
{
  const size_t kibibyte = (size_t)1024u;
  const size_t mebibyte = kibibyte * kibibyte;
  const fn_limits_t limits = {
    .session_limit = (size_t)10000u,
    .handshake_limit = (size_t)256u,
    .fd_limit = (size_t)32768u,
    .owned_memory_limit_bytes = (size_t)128u * mebibyte,
    .cleanup_reserve_bytes = (size_t)2u * mebibyte,
    .buffer_pool_limit_bytes = (size_t)32u * mebibyte,
    .async_operation_limit = (size_t)4096u,
    .completion_entry_limit = (size_t)4096u,
    .completion_limit_bytes = mebibyte,
    .loop_post_entry_limit = (size_t)1024u,
    .loop_post_limit_bytes = (size_t)256u * kibibyte,
    .worker_limit = (size_t)2u,
    .worker_job_limit = (size_t)64u,
    .worker_input_limit_bytes = (size_t)4u * mebibyte,
    .worker_result_limit_bytes = (size_t)8u * mebibyte,
    .lazy_waiter_limit = (size_t)1024u,
    .lazy_waiter_per_object_limit = (size_t)128u,
    .lazy_waiter_limit_bytes = (size_t)256u * kibibyte,
    .resource_waiter_limit = (size_t)1024u,
    .resource_waiter_limit_bytes = (size_t)256u * kibibyte,
    .timer_limit = (size_t)16384u,
    .resolver_pending_limit = (size_t)64u,
    .retired_runtime_limit = (size_t)2u,
    .resource_wait_timeout_ms = UINT64_C(1000),
    .worker_task_timeout_ms = UINT64_C(30000),
  };
  return limits;
}

fn_result_t fn_budget_init(fn_budget_t *budget, size_t limit,
                           size_t cleanup_reserve)
{
  if (budget == NULL || cleanup_reserve > limit) {
    return resource_result(FN_INVALID);
  }
  memset(budget, 0, sizeof(*budget));
  budget->limit = limit;
  budget->cleanup_reserve = cleanup_reserve;
  return resource_result(FN_OK);
}

fn_result_t fn_budget_reserve(fn_budget_t *budget,
                              fn_budget_class_t budget_class, size_t amount)
{
  fn_result_t result = budget_can_reserve(budget, budget_class, amount);
  if (result.code != FN_OK) {
    return result;
  }
  budget->used[budget_class] += amount;
  return resource_result(FN_OK);
}

fn_result_t fn_budget_release(fn_budget_t *budget,
                              fn_budget_class_t budget_class, size_t amount)
{
  if (budget == NULL || !budget_class_valid(budget_class) ||
      !budget_totals(budget, NULL, NULL) ||
      amount > budget->used[budget_class]) {
    return resource_result(FN_INVALID);
  }
  budget->used[budget_class] -= amount;
  if (amount != 0) {
    budget_epoch_advance(budget);
  }
  return resource_result(FN_OK);
}

fn_result_t fn_budget_reclassify(fn_budget_t *budget,
                                 fn_budget_class_t from,
                                 fn_budget_class_t to, size_t amount)
{
  size_t proposed[FN_BUDGET_CLASS_COUNT];
  fn_budget_t check;

  if (budget == NULL || !budget_class_valid(from) ||
      !budget_class_valid(to) || !budget_totals(budget, NULL, NULL) ||
      amount > budget->used[from]) {
    return resource_result(FN_INVALID);
  }
  if (from == to || amount == 0) {
    return resource_result(FN_OK);
  }
  memcpy(proposed, budget->used, sizeof(proposed));
  proposed[from] -= amount;
  if (!fn_size_add(proposed[to], amount, &proposed[to])) {
    return resource_result(FN_LIMIT);
  }
  check = *budget;
  memcpy(check.used, proposed, sizeof(proposed));
  if (!budget_totals(&check, NULL, NULL)) {
    return resource_result(FN_LIMIT);
  }
  memcpy(budget->used, proposed, sizeof(proposed));
  return resource_result(FN_OK);
}

fn_result_t fn_budget_snapshot(const fn_budget_t *budget,
                               fn_budget_snapshot_t *out)
{
  size_t total;
  if (out == NULL) {
    return resource_result(FN_INVALID);
  }
  memset(out, 0, sizeof(*out));
  if (!budget_totals(budget, NULL, &total)) {
    return resource_result(FN_INVALID);
  }
  out->limit = budget->limit;
  out->cleanup_reserve = budget->cleanup_reserve;
  out->active = budget->used[FN_BUDGET_ACTIVE];
  out->candidate = budget->used[FN_BUDGET_CANDIDATE];
  out->retained = budget->used[FN_BUDGET_RETAINED];
  out->cleanup = budget->used[FN_BUDGET_CLEANUP];
  out->total = total;
  out->epoch = budget->epoch;
  return resource_result(FN_OK);
}

fn_result_t fn_budget_reserve_pair(fn_budget_t *total, size_t total_amount,
                                   fn_budget_t *sub, size_t sub_amount,
                                   fn_budget_class_t budget_class)
{
  fn_result_t result;
  if (total == NULL || sub == NULL || total == sub) {
    return resource_result(FN_INVALID);
  }
  result = budget_can_reserve(total, budget_class, total_amount);
  if (result.code != FN_OK) {
    return result;
  }
  result = budget_can_reserve(sub, budget_class, sub_amount);
  if (result.code != FN_OK) {
    return result;
  }
  total->used[budget_class] += total_amount;
  sub->used[budget_class] += sub_amount;
  return resource_result(FN_OK);
}

fn_result_t fn_budget_release_pair(fn_budget_t *total, size_t total_amount,
                                   fn_budget_t *sub, size_t sub_amount,
                                   fn_budget_class_t budget_class)
{
  if (total == NULL || sub == NULL || total == sub ||
      !budget_class_valid(budget_class) ||
      !budget_totals(total, NULL, NULL) ||
      !budget_totals(sub, NULL, NULL) ||
      total_amount > total->used[budget_class] ||
      sub_amount > sub->used[budget_class]) {
    return resource_result(FN_INVALID);
  }
  total->used[budget_class] -= total_amount;
  sub->used[budget_class] -= sub_amount;
  if (total_amount != 0) {
    budget_epoch_advance(total);
  }
  if (sub_amount != 0) {
    budget_epoch_advance(sub);
  }
  return resource_result(FN_OK);
}
