#ifndef FLICKNET_RUNTIME_H
#define FLICKNET_RUNTIME_H

#include "flicknet/config.h"
#include "flicknet/loop.h"
#include "flicknet/metadata.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct fn_runtime_manager fn_runtime_manager_t;
typedef struct fn_runtime_candidate fn_runtime_candidate_t;
typedef struct fn_runtime fn_runtime_t;
typedef struct fn_runtime_acquire fn_runtime_acquire_t;

typedef enum {
  FN_RUNTIME_RESOURCE_LISTENER = 0,
  FN_RUNTIME_RESOURCE_DIRECT,
  FN_RUNTIME_RESOURCE_SOCKS_PROXY,
  FN_RUNTIME_RESOURCE_RESOLVER
} fn_runtime_resource_kind_t;

typedef enum {
  FN_RUNTIME_DORMANT = 0,
  FN_RUNTIME_STARTING,
  FN_RUNTIME_READY,
  FN_RUNTIME_FAILED,
  FN_RUNTIME_DRAINING
} fn_runtime_resource_state_t;

typedef struct {
  fn_object_ref_t id;
  fn_runtime_resource_kind_t kind;
  size_t config_index;
  char name[FN_CONFIG_NAME_MAX + 1u];
  fn_endpoint_t endpoint;
  fn_user_config_t credentials;
  bool has_credentials;
  bool planned_prepare;
  bool planned_lazy;
} fn_runtime_resource_descriptor_t;

typedef fn_result_t (*fn_runtime_prepare_fn)(
  void *context, const fn_runtime_resource_descriptor_t *descriptor,
  void **out_resource);
typedef fn_result_t (*fn_runtime_lazy_start_fn)(
  void *context, fn_runtime_t *runtime, fn_object_ref_t object);
typedef void (*fn_runtime_resource_release_fn)(
  void *context, const fn_runtime_resource_descriptor_t *descriptor,
  void *resource);

typedef struct {
  void *context;
  fn_runtime_prepare_fn prepare;
  fn_runtime_lazy_start_fn lazy_start;
  fn_runtime_resource_release_fn release;
} fn_runtime_resource_ops_t;

typedef struct {
  fn_loop_t *loop;
  const fn_limits_t *limits;
  fn_budget_t *owned_memory;
  fn_allocator_t allocator;
  fn_runtime_resource_ops_t resources;
} fn_runtime_manager_options_t;

typedef struct {
  uint64_t active_generation;
  size_t candidates;
  size_t retained_runtimes;
  size_t async_operations;
  size_t lazy_waiters;
  size_t lazy_waiter_bytes;
} fn_runtime_manager_snapshot_t;

typedef struct {
  fn_runtime_resource_state_t state;
  size_t waiters;
  fn_result_t last_result;
  uint64_t retry_after_ms;
  uint32_t consecutive_failures;
  bool has_resource;
} fn_runtime_resource_snapshot_t;

typedef void (*fn_runtime_acquire_callback_fn)(
  fn_runtime_acquire_t *operation, void *context, fn_result_t result,
  const fn_runtime_resource_descriptor_t *descriptor, void *resource);

/* fn_runtime_manager_create 固定调用线程为 owner，并借用 loop 与账本。 */
fn_result_t fn_runtime_manager_create(
  const fn_runtime_manager_options_t *options, fn_runtime_manager_t **out);
fn_result_t fn_runtime_manager_destroy(fn_runtime_manager_t **manager);
fn_result_t fn_runtime_manager_snapshot(
  const fn_runtime_manager_t *manager, fn_runtime_manager_snapshot_t *out);

/* fn_runtime_candidate_build 只编译 descriptor，不建立 fd、timer 或 worker。 */
fn_result_t fn_runtime_candidate_build(
  fn_runtime_manager_t *manager, const fn_config_t *config,
  const fn_feature_plan_t *plan, fn_runtime_candidate_t **out);
/* fn_runtime_candidate_prepare 只准备 Plan 标记的必需实例。 */
fn_result_t fn_runtime_candidate_prepare(fn_runtime_candidate_t *candidate);
fn_result_t fn_runtime_candidate_commit(
  fn_runtime_manager_t *manager, fn_runtime_candidate_t **candidate);
fn_result_t fn_runtime_candidate_destroy(fn_runtime_candidate_t **candidate);

uint64_t fn_runtime_generation(const fn_runtime_t *runtime);
fn_feature_plan_t fn_runtime_feature_plan(const fn_runtime_t *runtime);
size_t fn_runtime_object_count(const fn_runtime_t *runtime);
fn_result_t fn_runtime_object_get(
  const fn_runtime_t *runtime, fn_object_ref_t object,
  const fn_runtime_resource_descriptor_t **out);
fn_result_t fn_runtime_object_find(
  const fn_runtime_t *runtime, fn_runtime_resource_kind_t kind,
  const char *name, fn_object_ref_t *out);
fn_result_t fn_runtime_resource_snapshot(
  const fn_runtime_t *runtime, fn_object_ref_t object,
  fn_runtime_resource_snapshot_t *out);

/* fn_runtime_acquire_active 返回调用者持有的一份旧代保护引用。 */
fn_result_t fn_runtime_acquire_active(fn_runtime_manager_t *manager,
                                      fn_runtime_t **out);
fn_result_t fn_runtime_retain(fn_runtime_t *runtime);
fn_result_t fn_runtime_release(fn_runtime_t **runtime);

/* fn_runtime_acquire 在成功返回前预留 terminal，并服从绝对 deadline。 */
fn_result_t fn_runtime_acquire(
  fn_runtime_t *runtime, fn_object_ref_t object, uint64_t deadline_ms,
  fn_runtime_acquire_callback_fn callback, void *context,
  fn_runtime_acquire_t **out);
fn_result_t fn_runtime_acquire_cancel(fn_runtime_acquire_t *operation);
/* fn_runtime_acquire_release 只能在 terminal callback 已开始后调用。 */
fn_result_t fn_runtime_acquire_release(fn_runtime_acquire_t **operation);

/* fn_runtime_lazy_finish 由已接纳的 backend start 在 owner 上恰好调用一次。 */
fn_result_t fn_runtime_lazy_finish(fn_runtime_t *runtime,
                                   fn_object_ref_t object,
                                   fn_result_t result, void *resource);

#endif
