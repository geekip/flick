#ifndef FLICKNET_SESSION_H
#define FLICKNET_SESSION_H

#include "flicknet/direct.h"
#include "flicknet/resolver.h"
#include "flicknet/router.h"
#include "flicknet/socks5_outbound.h"

#include <stddef.h>
#include <stdint.h>

typedef struct fn_session_manager fn_session_manager_t;
typedef struct fn_session fn_session_t;
typedef struct fn_inbound_request fn_inbound_request_t;
typedef struct fn_op fn_op_t;

typedef enum {
  FN_SESSION_ACCEPTED = 0,
  FN_SESSION_HANDSHAKING,
  FN_SESSION_ROUTING,
  FN_SESSION_RESOLVING,
  FN_SESSION_CONNECTING,
  FN_SESSION_REPLYING,
  FN_SESSION_RELAYING,
  FN_SESSION_DRAINING,
  FN_SESSION_CLOSING,
  FN_SESSION_CLOSED
} fn_session_state_t;

typedef struct {
  fn_loop_t *loop;
  const fn_limits_t *limits;
  fn_budget_t *owned_memory;
  fn_allocator_t allocator;
  fn_direct_connector_t *direct_connector;
  fn_socks5_outbound_manager_t *socks5_outbound_manager;
  fn_resolver_t *resolver;
  fn_relay_buffer_pool_t *relay_pool;
} fn_session_manager_options_t;

typedef struct {
  uint64_t session_id;
  uint64_t runtime_generation;
  fn_session_state_t state;
  uint64_t created_at_ms;
  uint64_t bytes_up;
  uint64_t bytes_down;
  fn_result_t terminal_result;
  fn_endpoint_t connected_endpoint;
  fn_endpoint_t bound_endpoint;
} fn_session_snapshot_t;

typedef struct {
  size_t active_sessions;
  size_t owned_session_bytes;
  uint64_t next_session_id;
  bool id_exhausted;
} fn_session_manager_snapshot_t;

typedef void (*fn_session_callback_fn)(fn_session_t *session, void *context,
                                       const fn_session_snapshot_t *snapshot);
typedef void (*fn_reply_callback_fn)(fn_op_t *operation, fn_result_t result,
                                     void *context);

typedef struct {
  fn_result_t (*reply_start)(void *adapter_state, fn_result_t outcome,
                             const fn_endpoint_t *bound_endpoint,
                             fn_reply_callback_fn callback, void *context,
                             fn_op_t **out_operation);
  fn_stream_t *(*take_stream)(void *adapter_state);
  void (*destroy)(void *adapter_state);
} fn_inbound_request_ops_t;

fn_result_t fn_session_manager_create(
  const fn_session_manager_options_t *options,
  fn_session_manager_t **out);
fn_result_t fn_session_manager_destroy(fn_session_manager_t **manager);
fn_result_t fn_session_manager_snapshot(
  const fn_session_manager_t *manager, fn_session_manager_snapshot_t *out);

/* fn_inbound_request_create 成功时接管 adapter_state 并保留 Runtime。 */
fn_result_t fn_inbound_request_create(
  fn_runtime_t *runtime, const fn_session_metadata_t *metadata,
  uint64_t accepted_at_ms, const fn_inbound_request_ops_t *static_ops,
  void *adapter_state, fn_budget_t *owned_memory, fn_allocator_t allocator,
  fn_inbound_request_t **out);
/* submit 同步失败后可用原 request 尝试一次失败回复。 */
fn_result_t fn_inbound_request_reply_start(
  fn_inbound_request_t *request, fn_result_t outcome,
  fn_reply_callback_fn callback, void *context, fn_op_t **out_operation);
fn_result_t fn_inbound_request_release(fn_inbound_request_t **request);

fn_result_t fn_op_cancel(fn_op_t *operation);
/* fn_op_release 只能在终结回调已经开始后调用。 */
fn_result_t fn_op_release(fn_op_t **operation);

/* fn_session_submit 仅成功时消费 request。 */
fn_result_t fn_session_submit(fn_session_manager_t *manager,
                              fn_inbound_request_t **request,
                              uint64_t deadline_ms,
                              fn_session_callback_fn callback,
                              void *context, fn_session_t **out);

/* fn_session_start 成功时转移 inbound Stream，并保留 Runtime。 */
fn_result_t fn_session_start(fn_session_manager_t *manager,
                             fn_runtime_t *runtime,
                             fn_stream_t **inbound,
                             const fn_session_metadata_t *metadata,
                             uint64_t deadline_ms,
                             fn_session_callback_fn callback,
                             void *context, fn_session_t **out);
fn_result_t fn_session_close(fn_session_t *session, fn_result_t reason);
fn_result_t fn_session_snapshot(const fn_session_t *session,
                                fn_session_snapshot_t *out);
/* fn_session_release 只能在 terminal callback 已开始后调用。 */
fn_result_t fn_session_release(fn_session_t **session);

#endif
