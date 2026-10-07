#ifndef FLICKNET_PLATFORM_H
#define FLICKNET_PLATFORM_H

#include "flicknet/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  intptr_t value;
} fn_socket_t;

typedef struct {
  fn_result_t result;
  size_t transferred;
} fn_io_result_t;

typedef enum {
  FN_SOCKET_PURPOSE_INBOUND_LISTENER = 0,
  FN_SOCKET_PURPOSE_INBOUND_ACCEPTED,
  FN_SOCKET_PURPOSE_DIRECT,
  FN_SOCKET_PURPOSE_PROXY,
  FN_SOCKET_PURPOSE_DNS_BOOTSTRAP,
  FN_SOCKET_PURPOSE_DNS_UPSTREAM,
  FN_SOCKET_PURPOSE_PROBE,
  FN_SOCKET_PURPOSE_GEO_UPDATE
} fn_socket_purpose_t;

typedef uint32_t fn_socket_option_set_t;

#define FN_SOCKET_OPTION_NONBLOCK  (UINT32_C(1) << 0)
#define FN_SOCKET_OPTION_ROUTE_MARK (UINT32_C(1) << 1)
#define FN_SOCKET_OPTION_TCP_NODELAY (UINT32_C(1) << 2)
#define FN_SOCKET_OPTION_KEEPALIVE (UINT32_C(1) << 3)

typedef struct {
  fn_socket_purpose_t purpose;
  bool require_nonblocking;
  bool require_route_guard;
  uint32_t route_mark;
  bool prefer_tcp_nodelay;
  bool prefer_keepalive;
} fn_socket_policy_t;

typedef struct {
  fn_socket_option_set_t applied;
  fn_socket_option_set_t optional_failed;
  int optional_first_native_code;
} fn_socket_policy_report_t;

fn_socket_t fn_socket_invalid(void);
fn_result_t fn_socket_from_native(intptr_t native_socket, fn_socket_t *out);
bool fn_socket_is_valid(fn_socket_t socket);
intptr_t fn_socket_native(fn_socket_t socket);

/* fn_socket_policy_apply 不改变 Router 结果，只设置可信 purpose 的 socket 属性。 */
fn_result_t fn_socket_policy_apply(fn_socket_t socket,
                                   const fn_socket_policy_t *policy,
                                   fn_socket_policy_report_t *report);

/* fn_socket_read/write 保留部分传输字节；调用者提供失败阶段。 */
fn_io_result_t fn_socket_read(fn_socket_t socket, void *buffer, size_t length,
                              fn_error_stage_t stage);
fn_io_result_t fn_socket_write(fn_socket_t socket, const void *buffer,
                               size_t length, fn_error_stage_t stage);

/* fn_socket_shutdown_write 只关闭写半边，不释放句柄。 */
fn_result_t fn_socket_shutdown_write(fn_socket_t socket,
                                     fn_error_stage_t stage);

/* fn_socket_close 先使句柄失效；重复关闭返回成功。 */
fn_result_t fn_socket_close(fn_socket_t *socket);

#endif
