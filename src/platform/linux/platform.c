#define _GNU_SOURCE

#include "flicknet/platform.h"

#include "socket_policy_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static fn_result_t platform_result(fn_status_t code, fn_error_stage_t stage,
                                   int native_code)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE : stage,
                        native_code == 0 ? FN_ERROR_ORIGIN_NONE :
                                           FN_ERROR_ORIGIN_POSIX,
                        (int64_t)native_code);
}

static fn_io_result_t io_result(fn_status_t code, fn_error_stage_t stage,
                                int native_code, size_t transferred)
{
  const fn_io_result_t result = {
    .result = platform_result(code, stage, native_code),
    .transferred = transferred,
  };
  return result;
}

fn_socket_t fn_socket_invalid(void)
{
  const fn_socket_t socket = {.value = (intptr_t)-1};
  return socket;
}

fn_result_t fn_socket_from_native(intptr_t native_socket, fn_socket_t *out)
{
  if (out == NULL) {
    return platform_result(FN_INVALID, FN_STAGE_RESOURCE, 0);
  }
  *out = fn_socket_invalid();
  if (native_socket < 0 || native_socket > (intptr_t)INT_MAX) {
    return platform_result(FN_INVALID, FN_STAGE_RESOURCE, 0);
  }
  out->value = native_socket;
  return platform_result(FN_OK, FN_STAGE_NONE, 0);
}

bool fn_socket_is_valid(fn_socket_t socket)
{
  return socket.value >= 0 && socket.value <= (intptr_t)INT_MAX;
}

intptr_t fn_socket_native(fn_socket_t socket)
{
  return socket.value;
}

static bool socket_purpose_valid(fn_socket_purpose_t purpose)
{
  return (int)purpose >= (int)FN_SOCKET_PURPOSE_INBOUND_LISTENER &&
         (int)purpose <= (int)FN_SOCKET_PURPOSE_GEO_UPDATE;
}

static bool socket_purpose_outbound(fn_socket_purpose_t purpose)
{
  return purpose == FN_SOCKET_PURPOSE_DIRECT ||
         purpose == FN_SOCKET_PURPOSE_PROXY ||
         purpose == FN_SOCKET_PURPOSE_DNS_BOOTSTRAP ||
         purpose == FN_SOCKET_PURPOSE_DNS_UPSTREAM ||
         purpose == FN_SOCKET_PURPOSE_PROBE ||
         purpose == FN_SOCKET_PURPOSE_GEO_UPDATE;
}

static int linux_policy_call(void *context, fn_socket_t socket,
                             fn_socket_policy_operation_t operation,
                             uint32_t value, int *native_error)
{
  const int descriptor = (int)socket.value;
  int option = 1;
  int status = -1;
  (void)context;

  switch (operation) {
    case FN_SOCKET_POLICY_OP_NONBLOCK: {
      const int flags = fcntl(descriptor, F_GETFL, 0);
      if (flags >= 0) {
        status = fcntl(descriptor, F_SETFL, flags | O_NONBLOCK);
      }
      break;
    }
    case FN_SOCKET_POLICY_OP_ROUTE_MARK:
#ifdef SO_MARK
      status = setsockopt(descriptor, SOL_SOCKET, SO_MARK, &value,
                          (socklen_t)sizeof(value));
#else
      errno = ENOTSUP;
#endif
      break;
    case FN_SOCKET_POLICY_OP_TCP_NODELAY:
      status = setsockopt(descriptor, IPPROTO_TCP, TCP_NODELAY, &option,
                          (socklen_t)sizeof(option));
      break;
    case FN_SOCKET_POLICY_OP_KEEPALIVE:
      status = setsockopt(descriptor, SOL_SOCKET, SO_KEEPALIVE, &option,
                          (socklen_t)sizeof(option));
      break;
  }
  if (status != 0 && native_error != NULL) {
    *native_error = errno != 0 ? errno : EIO;
  }
  return status;
}

static fn_result_t apply_required(
  fn_socket_t socket, fn_socket_policy_operation_t operation, uint32_t value,
  fn_socket_option_set_t bit, fn_socket_policy_report_t *report,
  const fn_socket_policy_backend_t *backend)
{
  int native_error = 0;
  if (backend->call(backend->context, socket, operation, value,
                    &native_error) != 0) {
    if (native_error == 0) {
      native_error = EIO;
    }
    return platform_result(FN_IO_ERROR, FN_STAGE_RESOURCE, native_error);
  }
  report->applied |= bit;
  return platform_result(FN_OK, FN_STAGE_NONE, 0);
}

static void apply_optional(
  fn_socket_t socket, fn_socket_policy_operation_t operation,
  fn_socket_option_set_t bit, fn_socket_policy_report_t *report,
  const fn_socket_policy_backend_t *backend)
{
  int native_error = 0;
  if (backend->call(backend->context, socket, operation, UINT32_C(1),
                    &native_error) == 0) {
    report->applied |= bit;
    return;
  }
  report->optional_failed |= bit;
  if (report->optional_first_native_code == 0) {
    report->optional_first_native_code = native_error != 0 ? native_error :
                                                             EIO;
  }
}

/* fn_socket_policy_apply_with_backend 保持必需与可选失败的不同语义。 */
fn_result_t fn_socket_policy_apply_with_backend(
  fn_socket_t socket, const fn_socket_policy_t *policy,
  fn_socket_policy_report_t *report,
  const fn_socket_policy_backend_t *backend)
{
  fn_result_t result;
  if (report != NULL) {
    memset(report, 0, sizeof(*report));
  }
  if (!fn_socket_is_valid(socket) || policy == NULL || report == NULL ||
      backend == NULL || backend->call == NULL ||
      !socket_purpose_valid(policy->purpose) ||
      (policy->require_route_guard &&
       (!socket_purpose_outbound(policy->purpose) ||
        policy->route_mark == UINT32_C(0)))) {
    return platform_result(FN_INVALID, FN_STAGE_RESOURCE, 0);
  }
  if (policy->require_nonblocking) {
    result = apply_required(socket, FN_SOCKET_POLICY_OP_NONBLOCK,
                            UINT32_C(1), FN_SOCKET_OPTION_NONBLOCK,
                            report, backend);
    if (result.code != FN_OK) {
      return result;
    }
  }
  if (policy->require_route_guard) {
    result = apply_required(socket, FN_SOCKET_POLICY_OP_ROUTE_MARK,
                            policy->route_mark,
                            FN_SOCKET_OPTION_ROUTE_MARK, report, backend);
    if (result.code != FN_OK) {
      return result;
    }
  }
  if (policy->prefer_tcp_nodelay) {
    apply_optional(socket, FN_SOCKET_POLICY_OP_TCP_NODELAY,
                   FN_SOCKET_OPTION_TCP_NODELAY, report, backend);
  }
  if (policy->prefer_keepalive) {
    apply_optional(socket, FN_SOCKET_POLICY_OP_KEEPALIVE,
                   FN_SOCKET_OPTION_KEEPALIVE, report, backend);
  }
  return platform_result(FN_OK, FN_STAGE_NONE, 0);
}

fn_result_t fn_socket_policy_apply(fn_socket_t socket,
                                   const fn_socket_policy_t *policy,
                                   fn_socket_policy_report_t *report)
{
  const fn_socket_policy_backend_t backend = {
    .context = NULL,
    .call = linux_policy_call,
  };
  return fn_socket_policy_apply_with_backend(socket, policy, report,
                                             &backend);
}

fn_io_result_t fn_socket_read(fn_socket_t socket, void *buffer, size_t length,
                              fn_error_stage_t stage)
{
  ssize_t received;
  size_t request_length = length;
  if (!fn_socket_is_valid(socket) || (buffer == NULL && length != 0)) {
    return io_result(FN_INVALID, stage, 0, 0);
  }
  if (length == 0) {
    return io_result(FN_OK, FN_STAGE_NONE, 0, 0);
  }
  if (request_length > (size_t)PTRDIFF_MAX) {
    request_length = (size_t)PTRDIFF_MAX;
  }
  received = recv((int)socket.value, buffer, request_length, 0);
  if (received > 0) {
    return io_result(FN_OK, FN_STAGE_NONE, 0, (size_t)received);
  }
  if (received == 0) {
    return io_result(FN_EOF, FN_STAGE_NONE, 0, 0);
  }
  if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
    return io_result(FN_AGAIN, FN_STAGE_NONE, 0, 0);
  }
  return io_result(FN_IO_ERROR, stage, errno, 0);
}

fn_io_result_t fn_socket_write(fn_socket_t socket, const void *buffer,
                               size_t length, fn_error_stage_t stage)
{
  ssize_t sent;
  size_t request_length = length;
  if (!fn_socket_is_valid(socket) || (buffer == NULL && length != 0)) {
    return io_result(FN_INVALID, stage, 0, 0);
  }
  if (length == 0) {
    return io_result(FN_OK, FN_STAGE_NONE, 0, 0);
  }
  if (request_length > (size_t)PTRDIFF_MAX) {
    request_length = (size_t)PTRDIFF_MAX;
  }
  sent = send((int)socket.value, buffer, request_length, MSG_NOSIGNAL);
  if (sent > 0) {
    return io_result(FN_OK, FN_STAGE_NONE, 0, (size_t)sent);
  }
  if (sent == 0 || errno == EAGAIN || errno == EWOULDBLOCK ||
      errno == EINTR) {
    return io_result(FN_AGAIN, FN_STAGE_NONE, 0, 0);
  }
  return io_result(FN_IO_ERROR, stage, errno, 0);
}

fn_result_t fn_socket_shutdown_write(fn_socket_t socket,
                                     fn_error_stage_t stage)
{
  if (!fn_socket_is_valid(socket)) {
    return platform_result(FN_INVALID, stage, 0);
  }
  if (shutdown((int)socket.value, SHUT_WR) != 0) {
    return platform_result(FN_IO_ERROR, stage, errno);
  }
  return platform_result(FN_OK, FN_STAGE_NONE, 0);
}

fn_result_t fn_socket_close(fn_socket_t *socket)
{
  int descriptor;
  if (socket == NULL) {
    return platform_result(FN_INVALID, FN_STAGE_RESOURCE, 0);
  }
  if (socket->value == (intptr_t)-1) {
    *socket = fn_socket_invalid();
    return platform_result(FN_OK, FN_STAGE_NONE, 0);
  }
  if (!fn_socket_is_valid(*socket)) {
    *socket = fn_socket_invalid();
    return platform_result(FN_INVALID, FN_STAGE_RESOURCE, 0);
  }
  descriptor = (int)socket->value;
  *socket = fn_socket_invalid();
  if (close(descriptor) != 0) {
    return platform_result(FN_IO_ERROR, FN_STAGE_RESOURCE, errno);
  }
  return platform_result(FN_OK, FN_STAGE_NONE, 0);
}
