#ifndef FLICKNET_SOCKET_POLICY_INTERNAL_H
#define FLICKNET_SOCKET_POLICY_INTERNAL_H

#include "flicknet/platform.h"

typedef enum {
  FN_SOCKET_POLICY_OP_NONBLOCK = 0,
  FN_SOCKET_POLICY_OP_ROUTE_MARK,
  FN_SOCKET_POLICY_OP_TCP_NODELAY,
  FN_SOCKET_POLICY_OP_KEEPALIVE
} fn_socket_policy_operation_t;

typedef int (*fn_socket_policy_call_fn)(void *context, fn_socket_t socket,
                                        fn_socket_policy_operation_t operation,
                                        uint32_t value, int *native_error);

typedef struct {
  void *context;
  fn_socket_policy_call_fn call;
} fn_socket_policy_backend_t;

fn_result_t fn_socket_policy_apply_with_backend(
  fn_socket_t socket, const fn_socket_policy_t *policy,
  fn_socket_policy_report_t *report,
  const fn_socket_policy_backend_t *backend);

#endif
