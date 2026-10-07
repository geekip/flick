#define _GNU_SOURCE

#include "flicknet/direct.h"

#include "flicknet/clock.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct fn_direct_connector {
  fn_loop_t *loop;
  fn_limits_t limits;
  fn_budget_t *owned_memory;
  fn_budget_t *file_descriptors;
  fn_allocator_t allocator;
  uint64_t connect_timeout_ms;
  bool require_route_guard;
  uint32_t route_mark;
  size_t active_operations;
  size_t open_sockets;
  size_t attempts;
};

struct fn_direct_connect {
  fn_direct_connector_t *connector;
  fn_direct_connect_callback_fn callback;
  void *callback_context;
  fn_completion_ticket_t *ticket;
  fn_timer_t *timer;
  fn_io_watcher_t *watcher;
  fn_socket_t socket;
  fn_stream_t *stream;
  fn_endpoint_t candidates[FN_RESOLVED_MAX];
  fn_endpoint_t bound_endpoint;
  fn_endpoint_t connected_endpoint;
  fn_result_t terminal_result;
  fn_result_t last_io;
  fn_result_t last_network_unreachable;
  fn_result_t last_host_unreachable;
  fn_result_t last_refused;
  fn_socket_purpose_t purpose;
  uint64_t deadline_ms;
  uint16_t candidate_mask;
  size_t candidate_count;
  size_t next_candidate;
  bool fd_reserved;
  bool terminal_queued;
  bool callback_started;
  bool cancel_requested;
  bool has_last_io;
  bool has_network_unreachable;
  bool has_host_unreachable;
  bool has_refused;
  bool attempted_network;
};

static fn_result_t direct_result(fn_status_t code)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE :
                                               FN_STAGE_TCP_CONNECT,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static fn_result_t direct_posix_result(fn_status_t code, int native_code)
{
  return fn_result_make(code, FN_STAGE_TCP_CONNECT, FN_ERROR_ORIGIN_POSIX,
                        (int64_t)native_code);
}

static fn_result_t direct_posix_resource_result(fn_status_t code,
                                                int native_code)
{
  return fn_result_make(code, FN_STAGE_RESOURCE, FN_ERROR_ORIGIN_POSIX,
                        (int64_t)native_code);
}

static bool connector_is_owner(const fn_direct_connector_t *connector)
{
  return connector != NULL && fn_loop_is_owner(connector->loop);
}

static bool operation_is_owner(const fn_direct_connect_t *operation)
{
  return operation != NULL && connector_is_owner(operation->connector);
}

static void direct_close_socket(fn_direct_connect_t *operation)
{
  if (fn_socket_is_valid(operation->socket)) {
    (void)fn_socket_close(&operation->socket);
  }
  if (operation->fd_reserved) {
    (void)fn_budget_release(operation->connector->file_descriptors,
                            FN_BUDGET_ACTIVE, 1u);
    operation->fd_reserved = false;
    operation->connector->open_sockets--;
  }
}

static void direct_stop_candidate(fn_direct_connect_t *operation)
{
  (void)fn_io_watcher_destroy(&operation->watcher);
  (void)fn_timer_destroy(&operation->timer);
  direct_close_socket(operation);
}

static void direct_completion(void *context, fn_result_t result)
{
  fn_direct_connect_t *operation = context;
  fn_direct_connect_callback_fn callback = operation->callback;
  void *callback_context = operation->callback_context;
  fn_stream_t *stream = operation->stream;
  const fn_endpoint_t *bound = NULL;
  const fn_endpoint_t *connected = NULL;

  operation->callback_started = true;
  operation->stream = NULL;
  if (operation->cancel_requested) {
    if (stream != NULL) {
      (void)fn_stream_abort(stream);
      (void)fn_stream_release(&stream);
    }
    result = direct_result(FN_CANCELLED);
  } else if (result.code == FN_OK) {
    bound = &operation->bound_endpoint;
    connected = &operation->connected_endpoint;
  }
  callback(operation, callback_context, result, stream, bound, connected);
}

static void direct_finish(fn_direct_connect_t *operation, fn_result_t result)
{
  if (operation->terminal_queued) {
    return;
  }
  direct_stop_candidate(operation);
  operation->terminal_result = result;
  operation->terminal_queued = true;
  (void)fn_completion_publish(&operation->ticket, result,
                              direct_completion, operation);
}

static fn_result_t endpoint_sockaddr(const fn_endpoint_t *endpoint,
                                     struct sockaddr_in *out)
{
  if (endpoint == NULL || endpoint->address.kind != FN_ADDR_V4 ||
      endpoint->port == 0) {
    return direct_result(FN_INVALID);
  }
  memset(out, 0, sizeof(*out));
  out->sin_family = AF_INET;
  out->sin_port = htons(endpoint->port);
  memcpy(&out->sin_addr, endpoint->address.value.v4, 4u);
  return direct_result(FN_OK);
}

static fn_result_t sockaddr_endpoint(const struct sockaddr_in *address,
                                     fn_endpoint_t *out)
{
  fn_addr_t core_address;
  fn_result_t result;
  if (address == NULL || out == NULL || address->sin_family != AF_INET ||
      address->sin_port == 0) {
    return direct_result(FN_IO_ERROR);
  }
  result = fn_addr_from_v4(&core_address,
                           (const uint8_t *)&address->sin_addr);
  if (result.code != FN_OK) {
    return result;
  }
  return fn_endpoint_make(out, &core_address, ntohs(address->sin_port));
}

static fn_result_t connect_error(int native_code)
{
  switch (native_code) {
    case ECONNREFUSED:
      return direct_posix_result(FN_CONNECTION_REFUSED, native_code);
    case ETIMEDOUT:
      return direct_posix_result(FN_TIMEOUT, native_code);
    case EACCES:
    case EPERM:
      return direct_posix_result(FN_REJECTED, native_code);
    case ENOMEM:
      return direct_posix_resource_result(FN_NO_MEMORY, native_code);
    case ENOBUFS:
    case EMFILE:
    case ENFILE:
      return direct_posix_resource_result(FN_LIMIT, native_code);
    default:
      return direct_posix_result(FN_CONNECT_ERROR, native_code);
  }
}

static bool connect_error_retryable(fn_result_t result)
{
  int native_code;
  if (result.code == FN_REJECTED || result.code == FN_LIMIT ||
      result.code == FN_NO_MEMORY ||
      result.origin != FN_ERROR_ORIGIN_POSIX) {
    return false;
  }
  native_code = (int)result.native_code;
  return native_code != EADDRNOTAVAIL && native_code != EAFNOSUPPORT &&
         native_code != EINVAL;
}

static void record_connect_error(fn_direct_connect_t *operation,
                                 fn_result_t result)
{
  int native_code = result.origin == FN_ERROR_ORIGIN_POSIX ?
                    (int)result.native_code : 0;
  if (native_code == ECONNREFUSED) {
    operation->last_refused = result;
    operation->has_refused = true;
  } else if (native_code == EHOSTUNREACH) {
    operation->last_host_unreachable = result;
    operation->has_host_unreachable = true;
  } else if (native_code == ENETUNREACH) {
    operation->last_network_unreachable = result;
    operation->has_network_unreachable = true;
  } else {
    operation->last_io = result;
    operation->has_last_io = true;
  }
}

static fn_result_t final_connect_error(const fn_direct_connect_t *operation)
{
  if (operation->has_refused) {
    return operation->last_refused;
  }
  if (operation->has_host_unreachable) {
    return operation->last_host_unreachable;
  }
  if (operation->has_network_unreachable) {
    return operation->last_network_unreachable;
  }
  if (operation->has_last_io) {
    return operation->last_io;
  }
  return direct_result(FN_CONNECT_ERROR);
}

static bool next_candidate(fn_direct_connect_t *operation, size_t *out)
{
  while (operation->next_candidate < operation->candidate_count) {
    size_t index = operation->next_candidate++;
    if ((operation->candidate_mask & (UINT16_C(1) << index)) != 0) {
      *out = index;
      return true;
    }
  }
  return false;
}

static fn_result_t direct_begin_next(fn_direct_connect_t *operation);

static void direct_candidate_failed(fn_direct_connect_t *operation,
                                    fn_result_t result)
{
  fn_result_t next_result;
  direct_stop_candidate(operation);
  if (!connect_error_retryable(result)) {
    direct_finish(operation, result);
    return;
  }
  record_connect_error(operation, result);
  next_result = direct_begin_next(operation);
  if (next_result.code != FN_OK) {
    direct_finish(operation, next_result);
  }
}

static void direct_candidate_connected(fn_direct_connect_t *operation)
{
  struct sockaddr_in local;
  socklen_t local_length = (socklen_t)sizeof(local);
  fn_stream_options_t stream_options;
  fn_result_t result;

  memset(&local, 0, sizeof(local));
  if (getsockname((int)fn_socket_native(operation->socket),
                  (struct sockaddr *)&local, &local_length) != 0) {
    direct_finish(operation, direct_posix_result(FN_IO_ERROR, errno));
    return;
  }
  result = sockaddr_endpoint(&local, &operation->bound_endpoint);
  if (result.code != FN_OK) {
    direct_finish(operation, result);
    return;
  }
  (void)fn_io_watcher_destroy(&operation->watcher);
  (void)fn_timer_destroy(&operation->timer);
  memset(&stream_options, 0, sizeof(stream_options));
  stream_options.loop = operation->connector->loop;
  stream_options.owned_memory = operation->connector->owned_memory;
  stream_options.file_descriptors = operation->connector->file_descriptors;
  stream_options.allocator = operation->connector->allocator;
  stream_options.owns_file_descriptor_reservation = true;
  result = fn_stream_socket_create(&stream_options, &operation->socket,
                                   &operation->stream);
  if (result.code != FN_OK) {
    direct_finish(operation, result);
    return;
  }
  operation->fd_reserved = false;
  operation->connector->open_sockets--;
  direct_finish(operation, direct_result(FN_OK));
}

static void direct_io_ready(fn_io_watcher_t *watcher, uint32_t events,
                            void *context)
{
  fn_direct_connect_t *operation = context;
  int socket_error = 0;
  socklen_t length = (socklen_t)sizeof(socket_error);
  (void)watcher;
  (void)events;
  if (getsockopt((int)fn_socket_native(operation->socket), SOL_SOCKET,
                 SO_ERROR, &socket_error, &length) != 0) {
    socket_error = errno;
  }
  if (socket_error != 0) {
    direct_candidate_failed(operation, connect_error(socket_error));
    return;
  }
  direct_candidate_connected(operation);
}

static void direct_timeout(fn_timer_t *timer, void *context)
{
  fn_direct_connect_t *operation = context;
  uint64_t now_ms = 0;
  (void)timer;
  if (fn_monotonic_now_ms(&now_ms).code != FN_OK ||
      now_ms >= operation->deadline_ms) {
    direct_finish(operation, direct_result(FN_TIMEOUT));
    return;
  }
  direct_candidate_failed(
    operation, direct_posix_result(FN_TIMEOUT, ETIMEDOUT));
}

static fn_result_t direct_begin_next(fn_direct_connect_t *operation)
{
  fn_direct_connector_t *connector = operation->connector;
  struct sockaddr_in remote;
  fn_socket_policy_t policy;
  fn_socket_policy_report_t report;
  fn_result_t result;
  uint64_t now_ms;
  uint64_t candidate_deadline;
  size_t candidate_index;
  int descriptor;
  int connect_status;

  if (!next_candidate(operation, &candidate_index)) {
    direct_finish(operation, final_connect_error(operation));
    return direct_result(FN_OK);
  }
  if (fn_monotonic_now_ms(&now_ms).code != FN_OK ||
      now_ms >= operation->deadline_ms) {
    direct_finish(operation, direct_result(FN_TIMEOUT));
    return direct_result(FN_OK);
  }
  result = endpoint_sockaddr(&operation->candidates[candidate_index], &remote);
  if (result.code != FN_OK) {
    return result;
  }
  result = fn_budget_reserve(connector->file_descriptors, FN_BUDGET_ACTIVE,
                             1u);
  if (result.code != FN_OK) {
    return result;
  }
  operation->fd_reserved = true;
  connector->open_sockets++;
  descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (descriptor < 0) {
    result = direct_posix_result(FN_IO_ERROR, errno);
    direct_close_socket(operation);
    return result;
  }
  result = fn_socket_from_native((intptr_t)descriptor, &operation->socket);
  if (result.code != FN_OK) {
    (void)close(descriptor);
    operation->socket = fn_socket_invalid();
    direct_close_socket(operation);
    return result;
  }
  memset(&policy, 0, sizeof(policy));
  policy.purpose = operation->purpose;
  policy.require_nonblocking = true;
  policy.require_route_guard = connector->require_route_guard;
  policy.route_mark = connector->route_mark;
  policy.prefer_tcp_nodelay = true;
  policy.prefer_keepalive = true;
  result = fn_socket_policy_apply(operation->socket, &policy, &report);
  if (result.code != FN_OK) {
    direct_close_socket(operation);
    return result;
  }
  operation->connected_endpoint = operation->candidates[candidate_index];
  connector->attempts++;
  operation->attempted_network = true;
  connect_status = connect(descriptor, (const struct sockaddr *)&remote,
                           (socklen_t)sizeof(remote));
  if (connect_status != 0 && errno != EINPROGRESS) {
    result = connect_error(errno);
    direct_close_socket(operation);
    if (!connect_error_retryable(result)) {
      return result;
    }
    record_connect_error(operation, result);
    return direct_begin_next(operation);
  }
  result = fn_io_watcher_create(connector->loop, operation->socket,
                                direct_io_ready, operation,
                                &operation->watcher);
  if (result.code != FN_OK) {
    direct_close_socket(operation);
    return result;
  }
  if (fn_deadline_after_ms(now_ms, connector->connect_timeout_ms,
                           &candidate_deadline).code != FN_OK) {
    candidate_deadline = UINT64_MAX;
  }
  candidate_deadline = fn_deadline_min(candidate_deadline,
                                       operation->deadline_ms);
  result = fn_timer_start(connector->loop, candidate_deadline,
                          direct_timeout, operation, &operation->timer);
  if (result.code != FN_OK) {
    direct_stop_candidate(operation);
    return result;
  }
  result = fn_io_watcher_set(operation->watcher, FN_IO_EVENT_WRITE);
  if (result.code != FN_OK) {
    direct_stop_candidate(operation);
    return result;
  }
  if (connect_status == 0) {
    direct_candidate_connected(operation);
  }
  return direct_result(FN_OK);
}

static void direct_operation_free(fn_direct_connect_t *operation)
{
  fn_direct_connector_t *connector = operation->connector;
  direct_stop_candidate(operation);
  if (operation->stream != NULL) {
    (void)fn_stream_abort(operation->stream);
    (void)fn_stream_release(&operation->stream);
  }
  connector->active_operations--;
  connector->allocator.deallocate(connector->allocator.context, operation);
  (void)fn_budget_release(connector->owned_memory, FN_BUDGET_ACTIVE,
                          sizeof(*operation));
}

fn_result_t fn_direct_connector_create(
  const fn_direct_connector_options_t *options,
  fn_direct_connector_t **out)
{
  fn_direct_connector_t *connector;
  fn_result_t result;
  if (out == NULL) {
    return direct_result(FN_INVALID);
  }
  *out = NULL;
  if (options == NULL || options->loop == NULL || options->limits == NULL ||
      options->owned_memory == NULL || options->file_descriptors == NULL ||
      options->allocator.allocate == NULL ||
      options->allocator.deallocate == NULL ||
      options->connect_timeout_ms == 0 ||
      !fn_loop_is_owner(options->loop)) {
    return direct_result(FN_INVALID);
  }
  result = fn_budget_reserve(options->owned_memory, FN_BUDGET_ACTIVE,
                             sizeof(*connector));
  if (result.code != FN_OK) {
    return result;
  }
  connector = options->allocator.allocate(options->allocator.context,
                                           sizeof(*connector));
  if (connector == NULL) {
    (void)fn_budget_release(options->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*connector));
    return direct_result(FN_NO_MEMORY);
  }
  memset(connector, 0, sizeof(*connector));
  connector->loop = options->loop;
  connector->limits = *options->limits;
  connector->owned_memory = options->owned_memory;
  connector->file_descriptors = options->file_descriptors;
  connector->allocator = options->allocator;
  connector->connect_timeout_ms = options->connect_timeout_ms;
  connector->require_route_guard = options->require_route_guard;
  connector->route_mark = options->route_mark;
  *out = connector;
  return direct_result(FN_OK);
}

fn_result_t fn_direct_connector_destroy(fn_direct_connector_t **pointer)
{
  fn_direct_connector_t *connector;
  fn_allocator_t allocator;
  fn_budget_t *owned_memory;
  if (pointer == NULL) {
    return direct_result(FN_INVALID);
  }
  connector = *pointer;
  if (connector == NULL) {
    return direct_result(FN_OK);
  }
  if (!connector_is_owner(connector) || connector->active_operations != 0 ||
      connector->open_sockets != 0) {
    return direct_result(FN_INVALID);
  }
  allocator = connector->allocator;
  owned_memory = connector->owned_memory;
  allocator.deallocate(allocator.context, connector);
  (void)fn_budget_release(owned_memory, FN_BUDGET_ACTIVE,
                          sizeof(*connector));
  *pointer = NULL;
  return direct_result(FN_OK);
}

fn_result_t fn_direct_connector_snapshot(
  const fn_direct_connector_t *connector,
  fn_direct_connector_snapshot_t *out)
{
  if (!connector_is_owner(connector) || out == NULL) {
    return direct_result(FN_INVALID);
  }
  out->active_operations = connector->active_operations;
  out->open_sockets = connector->open_sockets;
  out->attempts = connector->attempts;
  return direct_result(FN_OK);
}

static fn_result_t copy_candidates(fn_direct_connect_t *operation,
                                   const fn_endpoint_t *target,
                                   const fn_resolved_t *resolved,
                                   uint16_t candidate_mask)
{
  size_t index;
  if (target->address.kind == FN_ADDR_V4) {
    operation->candidates[0] = *target;
    operation->candidate_count = 1u;
    operation->candidate_mask = UINT16_C(1);
    return direct_result(FN_OK);
  }
  if (target->address.kind != FN_ADDR_DOMAIN || resolved == NULL ||
      resolved->count == 0 || resolved->count > FN_RESOLVED_MAX ||
      candidate_mask == 0) {
    return direct_result(FN_INVALID);
  }
  for (index = 0; index < resolved->count; index++) {
    if (resolved->addresses[index].kind != FN_ADDR_V4) {
      return direct_result(FN_INVALID);
    }
    operation->candidates[index].address = resolved->addresses[index];
    operation->candidates[index].port = target->port;
  }
  operation->candidate_count = resolved->count;
  operation->candidate_mask = candidate_mask &
    (uint16_t)((UINT32_C(1) << resolved->count) - 1u);
  return operation->candidate_mask == 0 ? direct_result(FN_INVALID) :
                                         direct_result(FN_OK);
}

fn_result_t fn_direct_connect_start(
  fn_direct_connector_t *connector, const fn_endpoint_t *target,
  const fn_resolved_t *resolved, uint16_t candidate_mask,
  uint64_t deadline_ms, fn_direct_connect_callback_fn callback,
  void *context, fn_direct_connect_t **out)
{
  return fn_direct_connect_start_for_purpose(
    connector, FN_SOCKET_PURPOSE_DIRECT, target, resolved, candidate_mask,
    deadline_ms, callback, context, out);
}

fn_result_t fn_direct_connect_start_for_purpose(
  fn_direct_connector_t *connector, fn_socket_purpose_t purpose,
  const fn_endpoint_t *target, const fn_resolved_t *resolved,
  uint16_t candidate_mask, uint64_t deadline_ms,
  fn_direct_connect_callback_fn callback, void *context,
  fn_direct_connect_t **out)
{
  fn_direct_connect_t *operation;
  fn_result_t result;
  uint64_t now_ms;
  if (out == NULL) {
    return direct_result(FN_INVALID);
  }
  *out = NULL;
  if (!connector_is_owner(connector) ||
      (purpose != FN_SOCKET_PURPOSE_DIRECT &&
       purpose != FN_SOCKET_PURPOSE_PROXY) ||
      target == NULL || target->port == 0 ||
      callback == NULL ||
      fn_monotonic_now_ms(&now_ms).code != FN_OK) {
    return direct_result(FN_INVALID);
  }
  if (connector->active_operations >=
      connector->limits.async_operation_limit) {
    return fn_result_make(FN_LIMIT, FN_STAGE_RESOURCE,
                          FN_ERROR_ORIGIN_NONE, INT64_C(0));
  }
  if (deadline_ms <= now_ms) {
    return direct_result(FN_TIMEOUT);
  }
  result = fn_budget_reserve(connector->owned_memory, FN_BUDGET_ACTIVE,
                             sizeof(*operation));
  if (result.code != FN_OK) {
    return result;
  }
  operation = connector->allocator.allocate(connector->allocator.context,
                                             sizeof(*operation));
  if (operation == NULL) {
    (void)fn_budget_release(connector->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*operation));
    return direct_result(FN_NO_MEMORY);
  }
  memset(operation, 0, sizeof(*operation));
  operation->connector = connector;
  operation->callback = callback;
  operation->callback_context = context;
  operation->socket = fn_socket_invalid();
  operation->purpose = purpose;
  operation->deadline_ms = deadline_ms;
  result = copy_candidates(operation, target, resolved, candidate_mask);
  if (result.code == FN_OK) {
    result = fn_completion_reserve_terminal(connector->loop,
                                             &operation->ticket);
  }
  if (result.code != FN_OK) {
    connector->allocator.deallocate(connector->allocator.context, operation);
    (void)fn_budget_release(connector->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*operation));
    return result;
  }
  connector->active_operations++;
  result = direct_begin_next(operation);
  if (result.code != FN_OK && !operation->terminal_queued) {
    if (operation->attempted_network) {
      direct_finish(operation, result);
    } else {
      (void)fn_completion_abandon(&operation->ticket);
      direct_operation_free(operation);
      return result;
    }
  }
  *out = operation;
  return direct_result(FN_OK);
}

fn_result_t fn_direct_connect_cancel(fn_direct_connect_t *operation)
{
  if (!operation_is_owner(operation) || operation->callback_started) {
    return direct_result(FN_INVALID);
  }
  operation->cancel_requested = true;
  if (!operation->terminal_queued) {
    direct_finish(operation, direct_result(FN_CANCELLED));
  }
  return direct_result(FN_OK);
}

fn_result_t fn_direct_connect_release(fn_direct_connect_t **pointer)
{
  fn_direct_connect_t *operation;
  if (pointer == NULL) {
    return direct_result(FN_INVALID);
  }
  operation = *pointer;
  if (operation == NULL) {
    return direct_result(FN_OK);
  }
  if (!operation_is_owner(operation) || !operation->callback_started ||
      operation->ticket != NULL || operation->timer != NULL ||
      operation->watcher != NULL || fn_socket_is_valid(operation->socket)) {
    return direct_result(FN_INVALID);
  }
  direct_operation_free(operation);
  *pointer = NULL;
  return direct_result(FN_OK);
}
