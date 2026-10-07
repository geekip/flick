#define _GNU_SOURCE

#include "resolver_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

typedef enum {
  FN_DNS_IO_UDP_WRITE = 0,
  FN_DNS_IO_UDP_READ,
  FN_DNS_IO_TCP_CONNECT,
  FN_DNS_IO_TCP_WRITE,
  FN_DNS_IO_TCP_PREFIX,
  FN_DNS_IO_TCP_PAYLOAD
} fn_dns_io_state_t;

typedef struct {
  fn_loop_t *loop;
  fn_budget_t *owned_memory;
  fn_budget_t *file_descriptors;
  fn_allocator_t allocator;
  bool require_route_guard;
  uint32_t route_mark;
  size_t live_operations;
} fn_dns_linux_transport_t;

struct fn_dns_transport_operation {
  fn_dns_linux_transport_t *transport;
  fn_dns_transport_callback_fn callback;
  void *callback_context;
  fn_io_watcher_t *watcher;
  fn_timer_t *timer;
  fn_socket_t socket;
  fn_dns_io_state_t state;
  fn_dns_transport_t protocol;
  struct sockaddr_in upstream;
  struct sockaddr_in local;
  uint8_t outgoing[FN_DNS_MESSAGE_UDP_MAX + 2u];
  size_t outgoing_length;
  size_t outgoing_offset;
  uint8_t udp_response[FN_DNS_MESSAGE_UDP_MAX];
  uint8_t prefix[2];
  size_t prefix_used;
  uint8_t *payload;
  size_t payload_length;
  size_t payload_used;
  bool fd_reserved;
};

static fn_result_t linux_dns_result(fn_status_t code, int native_code)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE :
                                               FN_STAGE_RESOLVE,
                        native_code == 0 ? FN_ERROR_ORIGIN_NONE :
                                           FN_ERROR_ORIGIN_POSIX,
                        (int64_t)native_code);
}

static fn_result_t linux_dns_native_result(fn_status_t code,
                                           int64_t native_code)
{
  return fn_result_make(code, FN_STAGE_RESOLVE, FN_ERROR_ORIGIN_DNS,
                        native_code);
}

static bool endpoint_to_sockaddr(const fn_endpoint_t *endpoint,
                                 struct sockaddr_in *out)
{
  if (endpoint == NULL || out == NULL ||
      endpoint->address.kind != FN_ADDR_V4 || endpoint->port == 0) {
    return false;
  }
  memset(out, 0, sizeof(*out));
  out->sin_family = AF_INET;
  out->sin_port = htons(endpoint->port);
  memcpy(&out->sin_addr, endpoint->address.value.v4, 4u);
  return true;
}

static void operation_close_socket(fn_dns_transport_operation_t *operation)
{
  if (fn_socket_is_valid(operation->socket)) {
    (void)fn_socket_close(&operation->socket);
  }
  if (operation->fd_reserved) {
    (void)fn_budget_release(operation->transport->file_descriptors,
                            FN_BUDGET_ACTIVE, 1u);
    operation->fd_reserved = false;
  }
}

static void operation_release_payload(fn_dns_transport_operation_t *operation)
{
  if (operation->payload != NULL) {
    operation->transport->allocator.deallocate(
      operation->transport->allocator.context, operation->payload);
    (void)fn_budget_release(operation->transport->owned_memory,
                            FN_BUDGET_ACTIVE, operation->payload_length);
    operation->payload = NULL;
    operation->payload_length = 0;
    operation->payload_used = 0;
  }
}

static fn_result_t linux_transport_cancel(
  fn_dns_transport_operation_t *operation)
{
  if (operation == NULL || operation->transport == NULL ||
      !fn_loop_is_owner(operation->transport->loop)) {
    return linux_dns_result(FN_INVALID, 0);
  }
  (void)fn_io_watcher_destroy(&operation->watcher);
  (void)fn_timer_destroy(&operation->timer);
  operation_close_socket(operation);
  operation_release_payload(operation);
  return linux_dns_result(FN_OK, 0);
}

static fn_result_t linux_transport_release(
  fn_dns_transport_operation_t **operation_pointer)
{
  fn_dns_transport_operation_t *operation;
  fn_dns_linux_transport_t *transport;
  if (operation_pointer == NULL) {
    return linux_dns_result(FN_INVALID, 0);
  }
  operation = *operation_pointer;
  if (operation == NULL) {
    return linux_dns_result(FN_OK, 0);
  }
  transport = operation->transport;
  if (transport == NULL || !fn_loop_is_owner(transport->loop)) {
    return linux_dns_result(FN_INVALID, 0);
  }
  (void)linux_transport_cancel(operation);
  transport->allocator.deallocate(transport->allocator.context, operation);
  (void)fn_budget_release(transport->owned_memory, FN_BUDGET_ACTIVE,
                          sizeof(*operation));
  transport->live_operations--;
  *operation_pointer = NULL;
  return linux_dns_result(FN_OK, 0);
}

static bool notify_operation(fn_dns_transport_operation_t *operation,
                             fn_result_t result, const uint8_t *response,
                             size_t response_length, bool truncated,
                             bool source_matched, bool local_matched)
{
  return operation->callback(operation, operation->callback_context, result,
                             response, response_length, truncated,
                             source_matched, local_matched);
}

static bool sockaddr_equal(const struct sockaddr_in *left,
                           const struct sockaddr_in *right)
{
  return left->sin_family == right->sin_family &&
         left->sin_port == right->sin_port &&
         left->sin_addr.s_addr == right->sin_addr.s_addr;
}

static void udp_read_ready(fn_dns_transport_operation_t *operation)
{
  struct sockaddr_in source;
  struct iovec vector;
  struct msghdr message;
  uint8_t control[CMSG_SPACE(sizeof(struct in_pktinfo))];
  struct cmsghdr *header;
  ssize_t received;
  bool source_matched;
  bool local_matched = false;
  bool truncated;

  memset(&source, 0, sizeof(source));
  memset(&message, 0, sizeof(message));
  memset(control, 0, sizeof(control));
  vector.iov_base = operation->udp_response;
  vector.iov_len = sizeof(operation->udp_response);
  message.msg_name = &source;
  message.msg_namelen = (socklen_t)sizeof(source);
  message.msg_iov = &vector;
  message.msg_iovlen = 1u;
  message.msg_control = control;
  message.msg_controllen = sizeof(control);
  received = recvmsg((int)fn_socket_native(operation->socket), &message,
                     MSG_TRUNC);
  if (received < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
      return;
    }
    (void)notify_operation(operation, linux_dns_result(FN_IO_ERROR, errno),
                           NULL, 0, false, true, true);
    return;
  }
  source_matched = message.msg_namelen >= (socklen_t)sizeof(source) &&
                   sockaddr_equal(&source, &operation->upstream);
  for (header = CMSG_FIRSTHDR(&message); header != NULL;
       header = CMSG_NXTHDR(&message, header)) {
    if (header->cmsg_level == IPPROTO_IP && header->cmsg_type == IP_PKTINFO &&
        header->cmsg_len >= CMSG_LEN(sizeof(struct in_pktinfo))) {
      const struct in_pktinfo *packet =
        (const struct in_pktinfo *)CMSG_DATA(header);
      local_matched = packet->ipi_addr.s_addr ==
                      operation->local.sin_addr.s_addr;
      break;
    }
  }
  truncated = (message.msg_flags & MSG_TRUNC) != 0 ||
              (size_t)received > sizeof(operation->udp_response);
  (void)notify_operation(
    operation, linux_dns_result(FN_OK, 0), operation->udp_response,
    (size_t)received > sizeof(operation->udp_response) ?
      sizeof(operation->udp_response) : (size_t)received,
    truncated, source_matched, local_matched);
}

static void operation_write_ready(fn_dns_transport_operation_t *operation)
{
  fn_io_result_t io;
  io = fn_socket_write(operation->socket,
                       operation->outgoing + operation->outgoing_offset,
                       operation->outgoing_length - operation->outgoing_offset,
                       FN_STAGE_RESOLVE);
  if (io.result.code == FN_AGAIN) {
    return;
  }
  if (io.result.code != FN_OK) {
    (void)notify_operation(operation, io.result, NULL, 0, false, true, true);
    return;
  }
  operation->outgoing_offset += io.transferred;
  if (operation->outgoing_offset != operation->outgoing_length) {
    return;
  }
  if (operation->protocol == FN_DNS_TRANSPORT_UDP) {
    operation->state = FN_DNS_IO_UDP_READ;
  } else {
    operation->state = FN_DNS_IO_TCP_PREFIX;
  }
  (void)fn_io_watcher_set(operation->watcher, FN_IO_EVENT_READ);
}

static void tcp_connect_ready(fn_dns_transport_operation_t *operation)
{
  int socket_error = 0;
  socklen_t length = (socklen_t)sizeof(socket_error);
  if (getsockopt((int)fn_socket_native(operation->socket), SOL_SOCKET,
                 SO_ERROR, &socket_error, &length) != 0) {
    socket_error = errno;
  }
  if (socket_error != 0) {
    (void)notify_operation(operation,
                           linux_dns_result(FN_CONNECT_ERROR, socket_error),
                           NULL, 0, false, true, true);
    return;
  }
  operation->state = FN_DNS_IO_TCP_WRITE;
  operation_write_ready(operation);
}

static bool tcp_payload_reserve(fn_dns_transport_operation_t *operation)
{
  fn_result_t result;
  operation->payload_length = (size_t)fn_u16_read_be(operation->prefix);
  if (operation->payload_length < 12u) {
    (void)notify_operation(
      operation,
      linux_dns_native_result(FN_PROTOCOL_ERROR, FN_DNS_NATIVE_MALFORMED),
      NULL, 0, false, true, true);
    return false;
  }
  result = fn_budget_reserve(operation->transport->owned_memory,
                             FN_BUDGET_ACTIVE, operation->payload_length);
  if (result.code != FN_OK) {
    (void)notify_operation(operation, result, NULL, 0, false, true, true);
    return false;
  }
  operation->payload = operation->transport->allocator.allocate(
    operation->transport->allocator.context, operation->payload_length);
  if (operation->payload == NULL) {
    (void)fn_budget_release(operation->transport->owned_memory,
                            FN_BUDGET_ACTIVE, operation->payload_length);
    operation->payload_length = 0;
    (void)notify_operation(operation, linux_dns_result(FN_NO_MEMORY, 0),
                           NULL, 0, false, true, true);
    return false;
  }
  operation->state = FN_DNS_IO_TCP_PAYLOAD;
  return true;
}

static void tcp_read_ready(fn_dns_transport_operation_t *operation)
{
  fn_io_result_t io;
  if (operation->state == FN_DNS_IO_TCP_PREFIX) {
    io = fn_socket_read(operation->socket,
                        operation->prefix + operation->prefix_used,
                        sizeof(operation->prefix) - operation->prefix_used,
                        FN_STAGE_RESOLVE);
    if (io.result.code == FN_AGAIN) {
      return;
    }
    if (io.result.code == FN_EOF) {
      fn_result_t result = operation->prefix_used == 0 ?
        linux_dns_result(FN_IO_ERROR, ECONNRESET) :
        linux_dns_native_result(FN_PROTOCOL_ERROR,
                                FN_DNS_NATIVE_TRUNCATED);
      (void)notify_operation(operation, result, NULL, 0, false, true, true);
      return;
    }
    if (io.result.code != FN_OK) {
      (void)notify_operation(operation, io.result, NULL, 0, false, true, true);
      return;
    }
    operation->prefix_used += io.transferred;
    if (operation->prefix_used != sizeof(operation->prefix) ||
        !tcp_payload_reserve(operation)) {
      return;
    }
  }
  if (operation->state == FN_DNS_IO_TCP_PAYLOAD) {
    io = fn_socket_read(operation->socket,
                        operation->payload + operation->payload_used,
                        operation->payload_length - operation->payload_used,
                        FN_STAGE_RESOLVE);
    if (io.result.code == FN_AGAIN) {
      return;
    }
    if (io.result.code == FN_EOF) {
      (void)notify_operation(
        operation,
        linux_dns_native_result(FN_PROTOCOL_ERROR, FN_DNS_NATIVE_TRUNCATED),
        NULL, 0, false, true, true);
      return;
    }
    if (io.result.code != FN_OK) {
      (void)notify_operation(operation, io.result, NULL, 0, false, true, true);
      return;
    }
    operation->payload_used += io.transferred;
    if (operation->payload_used == operation->payload_length) {
      uint8_t *payload = operation->payload;
      size_t payload_length = operation->payload_length;
      fn_dns_linux_transport_t *transport = operation->transport;
      bool consumed;
      operation->payload = NULL;
      operation->payload_length = 0;
      operation->payload_used = 0;
      operation->prefix_used = 0;
      operation->state = FN_DNS_IO_TCP_PREFIX;
      consumed = notify_operation(operation, linux_dns_result(FN_OK, 0),
                                  payload, payload_length, false, true, true);
      transport->allocator.deallocate(transport->allocator.context, payload);
      (void)fn_budget_release(transport->owned_memory,
                              FN_BUDGET_ACTIVE, payload_length);
      if (consumed) {
        return;
      }
    }
  }
}

static void linux_io_ready(fn_io_watcher_t *watcher, uint32_t events,
                           void *context)
{
  fn_dns_transport_operation_t *operation = context;
  (void)watcher;
  if (operation->state == FN_DNS_IO_UDP_WRITE &&
      (events & (FN_IO_EVENT_WRITE | FN_IO_EVENT_ERROR)) != 0) {
    operation_write_ready(operation);
    return;
  }
  if (operation->state == FN_DNS_IO_UDP_READ &&
      (events & (FN_IO_EVENT_READ | FN_IO_EVENT_ERROR)) != 0) {
    udp_read_ready(operation);
    return;
  }
  if (operation->state == FN_DNS_IO_TCP_CONNECT &&
      (events & (FN_IO_EVENT_WRITE | FN_IO_EVENT_ERROR)) != 0) {
    tcp_connect_ready(operation);
    return;
  }
  if (operation->state == FN_DNS_IO_TCP_WRITE &&
      (events & (FN_IO_EVENT_WRITE | FN_IO_EVENT_ERROR)) != 0) {
    operation_write_ready(operation);
    return;
  }
  if ((operation->state == FN_DNS_IO_TCP_PREFIX ||
       operation->state == FN_DNS_IO_TCP_PAYLOAD) &&
      (events & (FN_IO_EVENT_READ | FN_IO_EVENT_ERROR)) != 0) {
    tcp_read_ready(operation);
  }
}

static void linux_timeout(fn_timer_t *timer, void *context)
{
  fn_dns_transport_operation_t *operation = context;
  (void)timer;
  (void)notify_operation(
    operation,
    linux_dns_native_result(FN_TIMEOUT, FN_DNS_NATIVE_NO_RESPONSE),
    NULL, 0, false, true, true);
}

static fn_result_t operation_create_socket(
  fn_dns_transport_operation_t *operation, fn_socket_purpose_t purpose)
{
  fn_dns_linux_transport_t *transport = operation->transport;
  fn_socket_policy_t policy;
  fn_socket_policy_report_t report;
  fn_result_t result;
  int descriptor;
  int packet_info = 1;
  socklen_t local_length = (socklen_t)sizeof(operation->local);
  int socket_type = operation->protocol == FN_DNS_TRANSPORT_UDP ?
                    SOCK_DGRAM : SOCK_STREAM;

  result = fn_budget_reserve(transport->file_descriptors, FN_BUDGET_ACTIVE,
                             1u);
  if (result.code != FN_OK) {
    return result;
  }
  operation->fd_reserved = true;
  descriptor = socket(AF_INET, socket_type | SOCK_CLOEXEC, 0);
  if (descriptor < 0) {
    result = linux_dns_result(FN_IO_ERROR, errno);
    operation_close_socket(operation);
    return result;
  }
  if (fn_socket_from_native((intptr_t)descriptor,
                            &operation->socket).code != FN_OK) {
    (void)close(descriptor);
    operation->socket = fn_socket_invalid();
    operation_close_socket(operation);
    return linux_dns_result(FN_IO_ERROR, EINVAL);
  }
  memset(&policy, 0, sizeof(policy));
  policy.purpose = purpose;
  policy.require_nonblocking = true;
  policy.require_route_guard = transport->require_route_guard;
  policy.route_mark = transport->route_mark;
  policy.prefer_tcp_nodelay = operation->protocol == FN_DNS_TRANSPORT_TCP;
  result = fn_socket_policy_apply(operation->socket, &policy, &report);
  if (result.code != FN_OK) {
    operation_close_socket(operation);
    return result;
  }
  if (operation->protocol == FN_DNS_TRANSPORT_UDP &&
      setsockopt(descriptor, IPPROTO_IP, IP_PKTINFO, &packet_info,
                 (socklen_t)sizeof(packet_info)) != 0) {
    result = linux_dns_result(FN_IO_ERROR, errno);
    operation_close_socket(operation);
    return result;
  }
  if (connect(descriptor, (const struct sockaddr *)&operation->upstream,
              (socklen_t)sizeof(operation->upstream)) != 0 &&
      errno != EINPROGRESS) {
    result = linux_dns_result(operation->protocol == FN_DNS_TRANSPORT_TCP ?
                              FN_CONNECT_ERROR : FN_IO_ERROR, errno);
    operation_close_socket(operation);
    return result;
  }
  memset(&operation->local, 0, sizeof(operation->local));
  if (getsockname(descriptor, (struct sockaddr *)&operation->local,
                  &local_length) != 0) {
    result = linux_dns_result(FN_IO_ERROR, errno);
    operation_close_socket(operation);
    return result;
  }
  if (operation->local.sin_family != AF_INET ||
      ntohs(operation->local.sin_port) == 53u) {
    result = linux_dns_result(FN_IO_ERROR, EADDRINUSE);
    operation_close_socket(operation);
    return result;
  }
  return linux_dns_result(FN_OK, 0);
}

static fn_result_t linux_transport_start(
  void *context, const fn_dns_transport_request_t *request,
  fn_dns_transport_callback_fn callback, void *callback_context,
  fn_dns_transport_operation_t **out)
{
  fn_dns_linux_transport_t *transport = context;
  fn_dns_transport_operation_t *operation;
  fn_result_t result;
  uint32_t interests;
  int descriptor;
  int socket_error = 0;
  socklen_t error_length = (socklen_t)sizeof(socket_error);

  if (out == NULL) {
    return linux_dns_result(FN_INVALID, 0);
  }
  *out = NULL;
  if (transport == NULL || request == NULL || callback == NULL ||
      request->query == NULL || request->query_length == 0 ||
      request->query_length > FN_DNS_MESSAGE_UDP_MAX ||
      !fn_loop_is_owner(transport->loop) ||
      !endpoint_to_sockaddr(&request->upstream, &((struct sockaddr_in){0})) ||
      (request->transport != FN_DNS_TRANSPORT_UDP &&
       request->transport != FN_DNS_TRANSPORT_TCP)) {
    return linux_dns_result(FN_INVALID, 0);
  }
  result = fn_budget_reserve(transport->owned_memory, FN_BUDGET_ACTIVE,
                             sizeof(*operation));
  if (result.code != FN_OK) {
    return result;
  }
  operation = transport->allocator.allocate(transport->allocator.context,
                                             sizeof(*operation));
  if (operation == NULL) {
    (void)fn_budget_release(transport->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*operation));
    return linux_dns_result(FN_NO_MEMORY, 0);
  }
  memset(operation, 0, sizeof(*operation));
  operation->transport = transport;
  operation->callback = callback;
  operation->callback_context = callback_context;
  operation->protocol = request->transport;
  operation->socket = fn_socket_invalid();
  (void)endpoint_to_sockaddr(&request->upstream, &operation->upstream);
  if (request->transport == FN_DNS_TRANSPORT_TCP) {
    fn_u16_write_be(operation->outgoing, (uint16_t)request->query_length);
    memcpy(operation->outgoing + 2u, request->query, request->query_length);
    operation->outgoing_length = request->query_length + 2u;
    operation->state = FN_DNS_IO_TCP_CONNECT;
  } else {
    memcpy(operation->outgoing, request->query, request->query_length);
    operation->outgoing_length = request->query_length;
    operation->state = FN_DNS_IO_UDP_WRITE;
  }
  transport->live_operations++;
  result = operation_create_socket(operation, request->socket_purpose);
  if (result.code != FN_OK) {
    (void)linux_transport_release(&operation);
    return result;
  }
  result = fn_io_watcher_create(transport->loop, operation->socket,
                                linux_io_ready, operation,
                                &operation->watcher);
  if (result.code != FN_OK) {
    (void)linux_transport_release(&operation);
    return result;
  }
  result = fn_timer_start(transport->loop, request->deadline_ms,
                          linux_timeout, operation, &operation->timer);
  if (result.code != FN_OK) {
    (void)linux_transport_release(&operation);
    return result;
  }
  descriptor = (int)fn_socket_native(operation->socket);
  if (request->transport == FN_DNS_TRANSPORT_TCP &&
      getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &socket_error,
                 &error_length) == 0 && socket_error == 0) {
    operation->state = FN_DNS_IO_TCP_WRITE;
  }
  interests = operation->state == FN_DNS_IO_UDP_READ ? FN_IO_EVENT_READ :
                                                      FN_IO_EVENT_WRITE;
  result = fn_io_watcher_set(operation->watcher, interests);
  if (result.code != FN_OK) {
    (void)linux_transport_release(&operation);
    return result;
  }
  *out = operation;
  return linux_dns_result(FN_OK, 0);
}

static fn_result_t linux_random_u16(void *context, uint16_t *out)
{
  fn_dns_linux_transport_t *transport = context;
  ssize_t received;
  if (transport == NULL || out == NULL ||
      !fn_loop_is_owner(transport->loop)) {
    return linux_dns_result(FN_INVALID, 0);
  }
  do {
    received = getrandom(out, sizeof(*out), GRND_NONBLOCK);
  } while (received < 0 && errno == EINTR);
  if (received != (ssize_t)sizeof(*out)) {
    return linux_dns_result(FN_IO_ERROR,
                            received < 0 ? errno : EIO);
  }
  return linux_dns_result(FN_OK, 0);
}

static void linux_transport_destroy(void *context)
{
  fn_dns_linux_transport_t *transport = context;
  fn_allocator_t allocator;
  fn_budget_t *owned_memory;
  if (transport == NULL) {
    return;
  }
  if (transport->live_operations == 0 &&
      fn_loop_is_owner(transport->loop)) {
    allocator = transport->allocator;
    owned_memory = transport->owned_memory;
    allocator.deallocate(allocator.context, transport);
    (void)fn_budget_release(owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*transport));
  }
}

fn_result_t fn_dns_linux_transport_create(
  const fn_resolver_options_t *options, fn_dns_transport_ops_t *out)
{
  fn_dns_linux_transport_t *transport;
  fn_result_t result;
  if (options == NULL || out == NULL || options->loop == NULL ||
      options->owned_memory == NULL || options->file_descriptors == NULL ||
      options->allocator.allocate == NULL ||
      options->allocator.deallocate == NULL ||
      !fn_loop_is_owner(options->loop)) {
    return linux_dns_result(FN_INVALID, 0);
  }
  memset(out, 0, sizeof(*out));
  result = fn_budget_reserve(options->owned_memory, FN_BUDGET_ACTIVE,
                             sizeof(*transport));
  if (result.code != FN_OK) {
    return result;
  }
  transport = options->allocator.allocate(options->allocator.context,
                                           sizeof(*transport));
  if (transport == NULL) {
    (void)fn_budget_release(options->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*transport));
    return linux_dns_result(FN_NO_MEMORY, 0);
  }
  memset(transport, 0, sizeof(*transport));
  transport->loop = options->loop;
  transport->owned_memory = options->owned_memory;
  transport->file_descriptors = options->file_descriptors;
  transport->allocator = options->allocator;
  transport->require_route_guard = options->require_route_guard;
  transport->route_mark = options->route_mark;
  out->context = transport;
  out->start = linux_transport_start;
  out->cancel = linux_transport_cancel;
  out->release = linux_transport_release;
  out->random_u16 = linux_random_u16;
  out->destroy = linux_transport_destroy;
  return linux_dns_result(FN_OK, 0);
}
