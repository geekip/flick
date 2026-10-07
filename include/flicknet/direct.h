#ifndef FLICKNET_DIRECT_H
#define FLICKNET_DIRECT_H

#include "flicknet/metadata.h"
#include "flicknet/stream.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct fn_direct_connector fn_direct_connector_t;
typedef struct fn_direct_connect fn_direct_connect_t;

typedef struct {
  fn_loop_t *loop;
  const fn_limits_t *limits;
  fn_budget_t *owned_memory;
  fn_budget_t *file_descriptors;
  fn_allocator_t allocator;
  uint64_t connect_timeout_ms;
  bool require_route_guard;
  uint32_t route_mark;
} fn_direct_connector_options_t;

typedef struct {
  size_t active_operations;
  size_t open_sockets;
  size_t attempts;
} fn_direct_connector_snapshot_t;

typedef void (*fn_direct_connect_callback_fn)(
  fn_direct_connect_t *operation, void *context, fn_result_t result,
  fn_stream_t *owned_stream, const fn_endpoint_t *bound_endpoint,
  const fn_endpoint_t *connected_endpoint);

/* fn_direct_connector_create 创建零业务 fd/timer 的 owner-only connector。 */
fn_result_t fn_direct_connector_create(
  const fn_direct_connector_options_t *options,
  fn_direct_connector_t **out);
fn_result_t fn_direct_connector_destroy(fn_direct_connector_t **connector);
fn_result_t fn_direct_connector_snapshot(
  const fn_direct_connector_t *connector,
  fn_direct_connector_snapshot_t *out);

/* fn_direct_connect_start 复制候选；成功 callback 转移一个 Stream。 */
fn_result_t fn_direct_connect_start(
  fn_direct_connector_t *connector, const fn_endpoint_t *target,
  const fn_resolved_t *resolved, uint16_t candidate_mask,
  uint64_t deadline_ms, fn_direct_connect_callback_fn callback,
  void *context, fn_direct_connect_t **out);
/* fn_direct_connect_start_for_purpose 只允许 DIRECT 或 PROXY socket。 */
fn_result_t fn_direct_connect_start_for_purpose(
  fn_direct_connector_t *connector, fn_socket_purpose_t purpose,
  const fn_endpoint_t *target, const fn_resolved_t *resolved,
  uint16_t candidate_mask, uint64_t deadline_ms,
  fn_direct_connect_callback_fn callback, void *context,
  fn_direct_connect_t **out);
fn_result_t fn_direct_connect_cancel(fn_direct_connect_t *operation);
/* fn_direct_connect_release 只能在 terminal callback 已开始后调用。 */
fn_result_t fn_direct_connect_release(fn_direct_connect_t **operation);

#endif
