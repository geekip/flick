#ifndef FLICKNET_SOCKS5_OUTBOUND_H
#define FLICKNET_SOCKS5_OUTBOUND_H

#include "flicknet/direct.h"
#include "flicknet/resolver.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct fn_socks5_outbound_manager fn_socks5_outbound_manager_t;
typedef struct fn_socks5_outbound fn_socks5_outbound_t;

typedef enum {
  FN_SOCKS5_OUT_TCP_CONNECT = 0,
  FN_SOCKS5_OUT_GREETING_WRITE,
  FN_SOCKS5_OUT_METHOD_READ,
  FN_SOCKS5_OUT_AUTH_WRITE,
  FN_SOCKS5_OUT_AUTH_READ,
  FN_SOCKS5_OUT_REQUEST_WRITE,
  FN_SOCKS5_OUT_CONNECT_REPLY_READ,
  FN_SOCKS5_OUT_READY,
  FN_SOCKS5_OUT_CLOSED
} fn_socks5_outbound_state_t;

typedef struct {
  fn_loop_t *loop;
  const fn_limits_t *limits;
  fn_budget_t *owned_memory;
  fn_allocator_t allocator;
  fn_direct_connector_t *tcp_connector;
  fn_resolver_t *resolver;
} fn_socks5_outbound_manager_options_t;

typedef struct {
  size_t active_operations;
  size_t bootstrap_operations;
  size_t protocol_operations;
} fn_socks5_outbound_manager_snapshot_t;

typedef struct {
  fn_socks5_outbound_state_t state;
  size_t input_bytes;
  size_t output_bytes;
  fn_result_t terminal_result;
  fn_endpoint_t proxy_endpoint;
  fn_endpoint_t connected_endpoint;
  fn_endpoint_t bound_endpoint;
} fn_socks5_outbound_snapshot_t;

typedef void (*fn_socks5_outbound_callback_fn)(
  fn_socks5_outbound_t *operation, void *context, fn_result_t result,
  fn_stream_t *owned_stream, const fn_endpoint_t *bound_endpoint,
  const fn_endpoint_t *connected_endpoint);

/* manager 无活跃操作时不持有业务 fd、timer 或 resolver waiter。 */
fn_result_t fn_socks5_outbound_manager_create(
  const fn_socks5_outbound_manager_options_t *options,
  fn_socks5_outbound_manager_t **out);
fn_result_t fn_socks5_outbound_manager_destroy(
  fn_socks5_outbound_manager_t **manager);
fn_result_t fn_socks5_outbound_manager_snapshot(
  const fn_socks5_outbound_manager_t *manager,
  fn_socks5_outbound_manager_snapshot_t *out);

/* start 复制代理节点、凭据和业务目标；成功 callback 转移 READY Stream。 */
fn_result_t fn_socks5_outbound_start(
  fn_socks5_outbound_manager_t *manager,
  const fn_endpoint_t *proxy_endpoint, bool has_credentials,
  const fn_user_config_t *credentials, const fn_endpoint_t *target,
  uint64_t deadline_ms, fn_socks5_outbound_callback_fn callback,
  void *context, fn_socks5_outbound_t **out);
fn_result_t fn_socks5_outbound_cancel(fn_socks5_outbound_t *operation);
/* release 只能在 terminal callback 已开始后调用。 */
fn_result_t fn_socks5_outbound_release(fn_socks5_outbound_t **operation);
fn_result_t fn_socks5_outbound_snapshot(
  const fn_socks5_outbound_t *operation,
  fn_socks5_outbound_snapshot_t *out);

#endif
