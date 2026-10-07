#ifndef FLICKNET_SOCKS5_H
#define FLICKNET_SOCKS5_H

#include "flicknet/config.h"
#include "flicknet/loop.h"
#include "flicknet/session.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FN_SOCKS5_WORKSPACE_SIZE 1024u
#define FN_SOCKS5_PREREAD_MAX 16384u

typedef struct fn_socks5_inbound_manager fn_socks5_inbound_manager_t;
typedef struct fn_socks5_inbound fn_socks5_inbound_t;
typedef struct fn_socks5_handshake fn_socks5_handshake_t;

typedef enum {
  FN_SOCKS5_GREETING_READ = 0,
  FN_SOCKS5_METHOD_WRITE,
  FN_SOCKS5_AUTH_READ,
  FN_SOCKS5_AUTH_WRITE,
  FN_SOCKS5_REQUEST_READ,
  FN_SOCKS5_OUTBOUND_WAIT,
  FN_SOCKS5_CONNECT_REPLY_WRITE,
  FN_SOCKS5_FAIL_REPLY_WRITE,
  FN_SOCKS5_RELAY,
  FN_SOCKS5_CLOSED
} fn_socks5_inbound_state_t;

typedef enum {
  FN_SOCKS5_METHOD_NO_AUTH = 0x00,
  FN_SOCKS5_METHOD_USERNAME_PASSWORD = 0x02,
  FN_SOCKS5_METHOD_NO_ACCEPTABLE = 0xff
} fn_socks5_method_t;

typedef enum {
  FN_SOCKS5_REP_SUCCEEDED = 0x00,
  FN_SOCKS5_REP_GENERAL_FAILURE = 0x01,
  FN_SOCKS5_REP_RULESET_DENIED = 0x02,
  FN_SOCKS5_REP_NETWORK_UNREACHABLE = 0x03,
  FN_SOCKS5_REP_HOST_UNREACHABLE = 0x04,
  FN_SOCKS5_REP_CONNECTION_REFUSED = 0x05,
  FN_SOCKS5_REP_TTL_EXPIRED = 0x06,
  FN_SOCKS5_REP_COMMAND_UNSUPPORTED = 0x07,
  FN_SOCKS5_REP_ADDRESS_UNSUPPORTED = 0x08
} fn_socks5_reply_t;

typedef struct {
  fn_loop_t *loop;
  const fn_limits_t *limits;
  fn_budget_t *owned_memory;
  fn_budget_t *buffer_bytes;
  fn_allocator_t allocator;
  const fn_user_config_t *users;
  size_t user_count;
} fn_socks5_inbound_manager_options_t;

typedef struct {
  size_t active_handshakes;
  size_t user_count;
} fn_socks5_inbound_manager_snapshot_t;

typedef struct {
  fn_socks5_inbound_state_t state;
  fn_result_t terminal_result;
  fn_endpoint_t target;
  size_t workspace_bytes;
  size_t output_bytes;
  size_t preread_bytes;
  uint8_t selected_method;
  bool authenticated;
  bool target_ready;
} fn_socks5_inbound_snapshot_t;

fn_result_t fn_socks5_inbound_manager_create(
  const fn_socks5_inbound_manager_options_t *options,
  fn_socks5_inbound_manager_t **out);
fn_result_t fn_socks5_inbound_manager_destroy(
  fn_socks5_inbound_manager_t **manager);
fn_result_t fn_socks5_inbound_manager_snapshot(
  const fn_socks5_inbound_manager_t *manager,
  fn_socks5_inbound_manager_snapshot_t *out);

/* fn_socks5_inbound_open 接纳一个已建立 TCP 连接的握手状态。 */
fn_result_t fn_socks5_inbound_open(fn_socks5_inbound_manager_t *manager,
                                   uint64_t deadline_ms,
                                   fn_socks5_inbound_t **out);
/* feed 可部分接纳；输出未排空时调用者应停止继续读取。 */
fn_result_t fn_socks5_inbound_feed(fn_socks5_inbound_t *inbound,
                                   const uint8_t *data, size_t length,
                                   size_t *consumed);
/* output_peek 返回的借用切片只在下一次状态修改前有效。 */
fn_result_t fn_socks5_inbound_output_peek(
  const fn_socks5_inbound_t *inbound, const uint8_t **data, size_t *length);
fn_result_t fn_socks5_inbound_output_consume(fn_socks5_inbound_t *inbound,
                                             size_t length);
fn_result_t fn_socks5_inbound_target(const fn_socks5_inbound_t *inbound,
                                     fn_endpoint_t *out);
/* connect_result 只在 OUTBOUND_WAIT 注入一次；成功必须携带实际 bound。 */
fn_result_t fn_socks5_inbound_connect_result(
  fn_socks5_inbound_t *inbound, fn_result_t result,
  const fn_endpoint_t *bound_endpoint);
fn_result_t fn_socks5_inbound_eof(fn_socks5_inbound_t *inbound);
fn_result_t fn_socks5_inbound_check_deadline(fn_socks5_inbound_t *inbound,
                                             uint64_t now_ms);
fn_result_t fn_socks5_inbound_cancel(fn_socks5_inbound_t *inbound);
/* preread 只在成功回复完整排空并进入 RELAY 后可见。 */
fn_result_t fn_socks5_inbound_preread_peek(
  const fn_socks5_inbound_t *inbound, const uint8_t **data, size_t *length);
fn_result_t fn_socks5_inbound_preread_consume(fn_socks5_inbound_t *inbound,
                                              size_t length);
fn_result_t fn_socks5_inbound_snapshot(const fn_socks5_inbound_t *inbound,
                                       fn_socks5_inbound_snapshot_t *out);
fn_result_t fn_socks5_inbound_release(fn_socks5_inbound_t **inbound);

typedef void (*fn_socks5_handshake_callback_fn)(
  fn_socks5_handshake_t *handshake, void *context, fn_result_t result,
  fn_inbound_request_t *owned_request);

/* fn_socks5_handshake_start 成功时接管 accepted_stream。 */
fn_result_t fn_socks5_handshake_start(
  fn_socks5_inbound_manager_t *manager, fn_runtime_t *runtime,
  fn_stream_t **accepted_stream, const fn_endpoint_t *source,
  fn_object_ref_t inbound, uint64_t accepted_at_ms, uint64_t deadline_ms,
  fn_socks5_handshake_callback_fn callback, void *context,
  fn_socks5_handshake_t **out);
fn_result_t fn_socks5_handshake_cancel(fn_socks5_handshake_t *handshake);
/* fn_socks5_handshake_release 只能在终结回调已经开始后调用。 */
fn_result_t fn_socks5_handshake_release(fn_socks5_handshake_t **handshake);

/* 映射只读取保存的结构化结果，不读取全局 errno。 */
fn_socks5_reply_t fn_socks5_reply_from_result(fn_result_t result);

#endif
