#define _GNU_SOURCE

#include "app_internal.h"

#include "flicknet/clock.h"
#include "flicknet/direct.h"
#include "flicknet/resolver.h"
#include "flicknet/runtime.h"
#include "flicknet/session.h"
#include "flicknet/socks5.h"
#include "flicknet/socks5_outbound.h"
#include "flicknet/stream.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define FN_APP_ACCEPT_BATCH 32u
#define FN_APP_RELAY_BLOCK_SIZE 16384u

typedef struct fn_app_listener fn_app_listener_t;
typedef struct fn_app_connection fn_app_connection_t;

struct fn_app_listener {
  fn_app_listener_t *next;
  struct fn_app *app;
  fn_runtime_resource_descriptor_t descriptor;
  fn_socket_t socket;
  fn_io_watcher_t *watcher;
  fn_socks5_inbound_manager_t *inbound_manager;
  fn_budget_class_t budget_class;
  bool listening;
  bool watcher_started;
};

struct fn_app_connection {
  fn_app_connection_t *next;
  struct fn_app *app;
  fn_socks5_handshake_t *handshake;
  fn_inbound_request_t *request;
  fn_op_t *reply_operation;
  fn_session_t *session;
  fn_result_t pending_result;
  uint64_t accepted_at_ms;
};

struct fn_app {
  const fn_config_t *config;
  fn_feature_plan_t plan;
  fn_allocator_t allocator;
  fn_budget_t owned_memory;
  fn_budget_t file_descriptors;
  fn_budget_t buffers;
  fn_loop_t *loop;
  fn_relay_buffer_pool_t *relay_pool;
  fn_direct_connector_t *direct_connector;
  fn_resolver_t *resolver;
  fn_socks5_outbound_manager_t *outbound_manager;
  fn_session_manager_t *session_manager;
  fn_runtime_manager_t *runtime_manager;
  fn_runtime_candidate_t *candidate;
  fn_runtime_t *runtime;
  fn_app_listener_t *listeners;
  fn_app_connection_t *connections;
  fn_logger_t *logger;
  fn_socket_t signal_read;
  fn_socket_t signal_write;
  fn_io_watcher_t *signal_watcher;
  struct sigaction old_sigint;
  struct sigaction old_sigterm;
  struct sigaction old_sigpipe;
#ifdef FN_TEST_INSTRUMENTATION
  struct sigaction old_sigusr1;
  int test_metrics_fd;
  uint64_t test_metrics_sequence;
  bool test_metrics_signal_installed;
#endif
  uint64_t stop_deadline_ms;
  uint64_t accepted_connections;
  uint64_t completed_sessions;
  uint64_t failed_sessions;
  uint64_t bytes_up;
  uint64_t bytes_down;
  size_t active_connections;
  size_t active_handshakes;
  size_t listener_count;
  size_t lazy_objects;
  unsigned handled_signals;
  bool test_mode;
  bool signal_installed;
  bool stopping;
  bool force_stop;
  bool cancel_sent;
  bool entered_running;
  bool runtime_error_set;
  fn_result_t runtime_error;
};

static volatile sig_atomic_t app_signal_count;
static volatile sig_atomic_t app_signal_write_fd = -1;
#ifdef FN_TEST_INSTRUMENTATION
static volatile sig_atomic_t app_metrics_requested;
#endif

static void summary_capture(fn_app_t *app, fn_app_summary_t *summary);
#ifdef FN_TEST_INSTRUMENTATION
static void test_metrics_emit(fn_app_t *app);
#endif

static fn_result_t app_result(fn_status_t code, fn_error_stage_t stage)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE : stage,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static fn_result_t app_posix_result(fn_error_stage_t stage, int native_code)
{
  return fn_result_make(FN_IO_ERROR, stage, FN_ERROR_ORIGIN_POSIX,
                        (int64_t)native_code);
}

static void counter_add(uint64_t *counter, uint64_t amount)
{
  if (UINT64_MAX - *counter < amount) {
    *counter = UINT64_MAX;
  } else {
    *counter += amount;
  }
}

static void app_signal_handler(int signal_number)
{
  int saved_errno = errno;
  uint8_t byte = (uint8_t)signal_number;
  int descriptor = (int)app_signal_write_fd;
#ifdef FN_TEST_INSTRUMENTATION
  if (signal_number == SIGUSR1) {
    app_metrics_requested = 1;
  } else
#endif
  if (app_signal_count < 2) {
    app_signal_count++;
  }
  if (descriptor >= 0) {
    ssize_t ignored = write(descriptor, &byte, sizeof(byte));
    (void)ignored;
  }
  errno = saved_errno;
}

static void app_log(fn_app_t *app, fn_log_level_t level,
                    const char *code, fn_result_t result,
                    const char *message)
{
  if (app->logger != NULL) {
    (void)fn_logger_emit_message(app->logger, level, code, result, message);
  }
}

static void listener_unlink(fn_app_t *app, fn_app_listener_t *listener)
{
  fn_app_listener_t **cursor = &app->listeners;
  while (*cursor != NULL && *cursor != listener) {
    cursor = &(*cursor)->next;
  }
  if (*cursor == listener) {
    *cursor = listener->next;
    listener->next = NULL;
    if (app->listener_count != 0) {
      app->listener_count--;
    }
  }
}

static void listener_release(void *context,
                             const fn_runtime_resource_descriptor_t *descriptor,
                             void *resource)
{
  fn_app_t *app = context;
  fn_app_listener_t *listener = resource;
  fn_budget_class_t budget_class;
  (void)descriptor;
  if (listener == NULL) {
    return;
  }
  budget_class = listener->budget_class;
  listener_unlink(app, listener);
  if (listener->watcher != NULL) {
    (void)fn_io_watcher_destroy(&listener->watcher);
  }
  if (listener->inbound_manager != NULL) {
    (void)fn_socks5_inbound_manager_destroy(&listener->inbound_manager);
  }
  if (fn_socket_is_valid(listener->socket)) {
    (void)fn_socket_close(&listener->socket);
    (void)fn_budget_release(&app->file_descriptors,
                            budget_class, 1u);
  }
  app->allocator.deallocate(app->allocator.context, listener);
  (void)fn_budget_release(&app->owned_memory, budget_class,
                          sizeof(*listener));
}

static fn_result_t listener_prepare(
  void *context, const fn_runtime_resource_descriptor_t *descriptor,
  void **out_resource)
{
  fn_app_t *app = context;
  fn_app_listener_t *listener;
  fn_socket_policy_t policy;
  fn_socket_policy_report_t report;
  struct sockaddr_in address;
  int native_socket;
  int option = 1;
  int native_code;
  fn_result_t result;
  if (out_resource == NULL) {
    return app_result(FN_INVALID, FN_STAGE_PREPARE);
  }
  *out_resource = NULL;
  if (descriptor == NULL ||
      descriptor->kind != FN_RUNTIME_RESOURCE_LISTENER ||
      descriptor->endpoint.address.kind != FN_ADDR_V4 ||
      descriptor->config_index >= app->config->inbound_count) {
    return app_result(FN_INVALID, FN_STAGE_PREPARE);
  }
  result = fn_budget_reserve(&app->owned_memory, FN_BUDGET_CANDIDATE,
                             sizeof(*listener));
  if (result.code != FN_OK) {
    return result;
  }
  listener = app->allocator.allocate(app->allocator.context,
                                     sizeof(*listener));
  if (listener == NULL) {
    (void)fn_budget_release(&app->owned_memory, FN_BUDGET_CANDIDATE,
                            sizeof(*listener));
    return app_result(FN_NO_MEMORY, FN_STAGE_RESOURCE);
  }
  memset(listener, 0, sizeof(*listener));
  listener->app = app;
  listener->descriptor = *descriptor;
  listener->socket = fn_socket_invalid();
  listener->budget_class = FN_BUDGET_CANDIDATE;

  result = fn_budget_reserve(&app->file_descriptors, FN_BUDGET_CANDIDATE,
                             1u);
  if (result.code != FN_OK) {
    app->allocator.deallocate(app->allocator.context, listener);
    (void)fn_budget_release(&app->owned_memory, FN_BUDGET_CANDIDATE,
                            sizeof(*listener));
    return result;
  }
  native_socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                         IPPROTO_TCP);
  if (native_socket < 0) {
    native_code = errno;
    (void)fn_budget_release(&app->file_descriptors, FN_BUDGET_CANDIDATE,
                            1u);
    app->allocator.deallocate(app->allocator.context, listener);
    (void)fn_budget_release(&app->owned_memory, FN_BUDGET_CANDIDATE,
                            sizeof(*listener));
    return app_posix_result(FN_STAGE_PREPARE, native_code);
  }
  result = fn_socket_from_native((intptr_t)native_socket, &listener->socket);
  if (result.code != FN_OK) {
    (void)close(native_socket);
    (void)fn_budget_release(&app->file_descriptors, FN_BUDGET_CANDIDATE,
                            1u);
    app->allocator.deallocate(app->allocator.context, listener);
    (void)fn_budget_release(&app->owned_memory, FN_BUDGET_CANDIDATE,
                            sizeof(*listener));
    return result;
  }
  (void)setsockopt(native_socket, SOL_SOCKET, SO_REUSEADDR, &option,
                   (socklen_t)sizeof(option));
  memset(&policy, 0, sizeof(policy));
  policy.purpose = FN_SOCKET_PURPOSE_INBOUND_LISTENER;
  policy.require_nonblocking = true;
  result = fn_socket_policy_apply(listener->socket, &policy, &report);
  if (result.code != FN_OK) {
    listener_release(app, descriptor, listener);
    return result;
  }
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  memcpy(&address.sin_addr.s_addr,
         descriptor->endpoint.address.value.v4,
         sizeof(descriptor->endpoint.address.value.v4));
  address.sin_port = htons(descriptor->endpoint.port);
  if (bind(native_socket, (const struct sockaddr *)&address,
           (socklen_t)sizeof(address)) != 0) {
    native_code = errno;
    listener_release(app, descriptor, listener);
    return app_posix_result(FN_STAGE_PREPARE, native_code);
  }
  if (!app->test_mode && listen(native_socket, SOMAXCONN) != 0) {
    native_code = errno;
    listener_release(app, descriptor, listener);
    return app_posix_result(FN_STAGE_PREPARE, native_code);
  }
  listener->listening = !app->test_mode;
  listener->next = app->listeners;
  app->listeners = listener;
  app->listener_count++;
  *out_resource = listener;
  return app_result(FN_OK, FN_STAGE_NONE);
}

static fn_result_t listener_lazy_start(void *context, fn_runtime_t *runtime,
                                       fn_object_ref_t object)
{
  (void)context;
  (void)runtime;
  (void)object;
  return app_result(FN_FEATURE_UNAVAILABLE, FN_STAGE_PREPARE);
}

static void connection_unlink(fn_app_t *app, fn_app_connection_t *connection)
{
  fn_app_connection_t **cursor = &app->connections;
  while (*cursor != NULL && *cursor != connection) {
    cursor = &(*cursor)->next;
  }
  if (*cursor == connection) {
    *cursor = connection->next;
    connection->next = NULL;
    if (app->active_connections != 0) {
      app->active_connections--;
    }
  }
}

static void listeners_resume(fn_app_t *app)
{
  fn_app_listener_t *listener;
  if (app->stopping) {
    return;
  }
  for (listener = app->listeners; listener != NULL;
       listener = listener->next) {
    if (listener->watcher != NULL && !listener->watcher_started &&
        fn_io_watcher_set(listener->watcher, FN_IO_EVENT_READ).code ==
          FN_OK) {
      listener->watcher_started = true;
    }
  }
}

static void connection_destroy(fn_app_connection_t *connection)
{
  fn_app_t *app = connection->app;
  connection_unlink(app, connection);
  app->allocator.deallocate(app->allocator.context, connection);
  (void)fn_budget_release(&app->owned_memory, FN_BUDGET_ACTIVE,
                          sizeof(*connection));
  listeners_resume(app);
}

static void request_reply_done(fn_op_t *operation, fn_result_t result,
                               void *context)
{
  fn_app_connection_t *connection = context;
  fn_app_t *app = connection->app;
  (void)result;
  if (operation == connection->reply_operation) {
    (void)fn_op_release(&connection->reply_operation);
  }
  if (connection->request != NULL) {
    (void)fn_inbound_request_release(&connection->request);
  }
  counter_add(&app->failed_sessions, UINT64_C(1));
  connection_destroy(connection);
}

static void session_done(fn_session_t *session, void *context,
                         const fn_session_snapshot_t *snapshot)
{
  fn_app_connection_t *connection = context;
  fn_app_t *app = connection->app;
  if (snapshot != NULL) {
    counter_add(&app->bytes_up, snapshot->bytes_up);
    counter_add(&app->bytes_down, snapshot->bytes_down);
    if (snapshot->terminal_result.code != FN_OK) {
      counter_add(&app->failed_sessions, UINT64_C(1));
      app_log(app, FN_LOG_WARN, "SESSION_FAILED",
              snapshot->terminal_result, "Session ended with an error.");
    }
  }
  counter_add(&app->completed_sessions, UINT64_C(1));
  if (session == connection->session) {
    (void)fn_session_release(&connection->session);
  }
  connection_destroy(connection);
}

static void handshake_done(fn_socks5_handshake_t *handshake, void *context,
                           fn_result_t result,
                           fn_inbound_request_t *owned_request)
{
  fn_app_connection_t *connection = context;
  fn_app_t *app = connection->app;
  uint64_t now_ms;
  uint64_t deadline_ms;
  fn_result_t submit_result;
  if (handshake == connection->handshake) {
    (void)fn_socks5_handshake_release(&connection->handshake);
  }
  if (app->active_handshakes != 0) {
    app->active_handshakes--;
  }
  if (result.code != FN_OK || owned_request == NULL) {
    if (owned_request != NULL) {
      (void)fn_inbound_request_release(&owned_request);
    }
    counter_add(&app->failed_sessions, UINT64_C(1));
    app_log(app, FN_LOG_WARN, "HANDSHAKE_FAILED", result,
            "SOCKS5 handshake failed.");
    connection_destroy(connection);
    return;
  }
  if (fn_monotonic_now_ms(&now_ms).code != FN_OK ||
      fn_deadline_after_ms(now_ms, app->config->timeouts.connect_ms,
                           &deadline_ms).code != FN_OK) {
    submit_result = app_result(FN_INVALID, FN_STAGE_RESOURCE);
  } else {
    submit_result = fn_session_submit(
      app->session_manager, &owned_request, deadline_ms,
      session_done, connection, &connection->session);
  }
  if (submit_result.code == FN_OK) {
    return;
  }
  connection->pending_result = submit_result;
  connection->request = owned_request;
  if (connection->request == NULL ||
      fn_inbound_request_reply_start(
        connection->request, submit_result, request_reply_done, connection,
        &connection->reply_operation).code != FN_OK) {
    if (connection->request != NULL) {
      (void)fn_inbound_request_release(&connection->request);
    }
    counter_add(&app->failed_sessions, UINT64_C(1));
    connection_destroy(connection);
  }
}

static fn_result_t accepted_source(const struct sockaddr_in *native,
                                   fn_endpoint_t *out)
{
  fn_addr_t address;
  fn_result_t result = fn_addr_from_v4(
    &address, (const uint8_t *)&native->sin_addr.s_addr);
  if (result.code != FN_OK) {
    return result;
  }
  return fn_endpoint_make(out, &address, ntohs(native->sin_port));
}

static void listener_accept_one(fn_app_listener_t *listener)
{
  fn_app_t *app = listener->app;
  fn_app_connection_t *connection;
  fn_socket_t accepted_socket = fn_socket_invalid();
  fn_stream_t *stream = NULL;
  fn_stream_options_t stream_options;
  fn_socket_policy_t policy;
  fn_socket_policy_report_t report;
  fn_endpoint_t source;
  struct sockaddr_in native_source;
  socklen_t native_length = (socklen_t)sizeof(native_source);
  uint64_t now_ms;
  uint64_t deadline_ms;
  int descriptor;
  fn_result_t result;

  result = fn_budget_reserve(&app->file_descriptors, FN_BUDGET_ACTIVE, 1u);
  if (result.code != FN_OK) {
    (void)fn_io_watcher_stop(listener->watcher);
    listener->watcher_started = false;
    app_log(app, FN_LOG_WARN, "ACCEPT_RESOURCE_LIMIT", result,
            "Inbound accept paused by the file descriptor budget.");
    return;
  }
  memset(&native_source, 0, sizeof(native_source));
  descriptor = accept4((int)fn_socket_native(listener->socket),
                       (struct sockaddr *)&native_source, &native_length,
                       SOCK_NONBLOCK | SOCK_CLOEXEC);
  if (descriptor < 0) {
    int native_code = errno;
    (void)fn_budget_release(&app->file_descriptors, FN_BUDGET_ACTIVE, 1u);
    if (native_code != EAGAIN && native_code != EWOULDBLOCK &&
        native_code != EINTR) {
      app->runtime_error = app_posix_result(FN_STAGE_ACCEPT, native_code);
      app->runtime_error_set = true;
    }
    return;
  }
  if (fn_socket_from_native((intptr_t)descriptor, &accepted_socket).code !=
      FN_OK) {
    (void)close(descriptor);
    (void)fn_budget_release(&app->file_descriptors, FN_BUDGET_ACTIVE, 1u);
    return;
  }
  memset(&policy, 0, sizeof(policy));
  policy.purpose = FN_SOCKET_PURPOSE_INBOUND_ACCEPTED;
  policy.require_nonblocking = true;
  policy.prefer_tcp_nodelay = true;
  result = fn_socket_policy_apply(accepted_socket, &policy, &report);
  if (result.code != FN_OK ||
      accepted_source(&native_source, &source).code != FN_OK) {
    (void)fn_socket_close(&accepted_socket);
    (void)fn_budget_release(&app->file_descriptors, FN_BUDGET_ACTIVE, 1u);
    return;
  }
  memset(&stream_options, 0, sizeof(stream_options));
  stream_options.loop = app->loop;
  stream_options.owned_memory = &app->owned_memory;
  stream_options.file_descriptors = &app->file_descriptors;
  stream_options.allocator = app->allocator;
  stream_options.owns_file_descriptor_reservation = true;
  result = fn_stream_socket_create(&stream_options, &accepted_socket, &stream);
  if (result.code != FN_OK) {
    (void)fn_socket_close(&accepted_socket);
    (void)fn_budget_release(&app->file_descriptors, FN_BUDGET_ACTIVE, 1u);
    return;
  }
  if (app->active_handshakes >= app->config->limits.handshake_limit ||
      fn_budget_reserve(&app->owned_memory, FN_BUDGET_ACTIVE,
                        sizeof(*connection)).code != FN_OK) {
    (void)fn_stream_release(&stream);
    return;
  }
  connection = app->allocator.allocate(app->allocator.context,
                                        sizeof(*connection));
  if (connection == NULL) {
    (void)fn_budget_release(&app->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*connection));
    (void)fn_stream_release(&stream);
    return;
  }
  memset(connection, 0, sizeof(*connection));
  connection->app = app;
  connection->next = app->connections;
  app->connections = connection;
  app->active_connections++;
  app->active_handshakes++;
  counter_add(&app->accepted_connections, UINT64_C(1));
  if (fn_monotonic_now_ms(&now_ms).code != FN_OK ||
      fn_deadline_after_ms(now_ms, app->config->timeouts.handshake_ms,
                           &deadline_ms).code != FN_OK) {
    result = app_result(FN_INVALID, FN_STAGE_RESOURCE);
  } else {
    connection->accepted_at_ms = now_ms;
    result = fn_socks5_handshake_start(
      listener->inbound_manager, app->runtime, &stream, &source,
      listener->descriptor.id, now_ms, deadline_ms, handshake_done,
      connection, &connection->handshake);
  }
  if (result.code != FN_OK) {
    if (stream != NULL) {
      (void)fn_stream_release(&stream);
    }
    app->active_handshakes--;
    counter_add(&app->failed_sessions, UINT64_C(1));
    connection_destroy(connection);
  }
}

static void listener_ready(fn_io_watcher_t *watcher, uint32_t events,
                           void *context)
{
  fn_app_listener_t *listener = context;
  size_t accepted;
  (void)watcher;
  if ((events & FN_IO_EVENT_ERROR) != 0) {
    listener->app->runtime_error =
      app_result(FN_IO_ERROR, FN_STAGE_ACCEPT);
    listener->app->runtime_error_set = true;
    return;
  }
  if ((events & FN_IO_EVENT_READ) == 0 || listener->app->stopping) {
    return;
  }
  for (accepted = 0; accepted < FN_APP_ACCEPT_BATCH; accepted++) {
    uint64_t before = listener->app->accepted_connections;
    listener_accept_one(listener);
    if (listener->app->accepted_connections == before ||
        listener->app->runtime_error_set || !listener->watcher_started) {
      break;
    }
  }
}

static fn_result_t listener_activate(fn_app_listener_t *listener)
{
  fn_app_t *app = listener->app;
  const fn_inbound_config_t *config =
    &app->config->inbounds[listener->descriptor.config_index];
  fn_socks5_inbound_manager_options_t inbound_options;
  fn_result_t result;
  result = fn_budget_reclassify(&app->owned_memory, FN_BUDGET_CANDIDATE,
                                FN_BUDGET_ACTIVE, sizeof(*listener));
  if (result.code != FN_OK) {
    return result;
  }
  result = fn_budget_reclassify(&app->file_descriptors,
                                FN_BUDGET_CANDIDATE, FN_BUDGET_ACTIVE, 1u);
  if (result.code != FN_OK) {
    (void)fn_budget_reclassify(&app->owned_memory, FN_BUDGET_ACTIVE,
                               FN_BUDGET_CANDIDATE, sizeof(*listener));
    return result;
  }
  listener->budget_class = FN_BUDGET_ACTIVE;
  memset(&inbound_options, 0, sizeof(inbound_options));
  inbound_options.loop = app->loop;
  inbound_options.limits = &app->config->limits;
  inbound_options.owned_memory = &app->owned_memory;
  inbound_options.buffer_bytes = &app->buffers;
  inbound_options.allocator = app->allocator;
  inbound_options.users = config->users;
  inbound_options.user_count = config->user_count;
  result = fn_socks5_inbound_manager_create(&inbound_options,
                                             &listener->inbound_manager);
  if (result.code != FN_OK) {
    return result;
  }
  result = fn_io_watcher_create(app->loop, listener->socket, listener_ready,
                                listener, &listener->watcher);
  if (result.code != FN_OK) {
    return result;
  }
  result = fn_io_watcher_set(listener->watcher, FN_IO_EVENT_READ);
  if (result.code == FN_OK) {
    listener->watcher_started = true;
  }
  return result;
}

static void listeners_stop(fn_app_t *app)
{
  fn_app_listener_t *listener;
  for (listener = app->listeners; listener != NULL;
       listener = listener->next) {
    if (listener->watcher != NULL) {
      (void)fn_io_watcher_stop(listener->watcher);
      listener->watcher_started = false;
    }
  }
}

static void connections_cancel(fn_app_t *app)
{
  fn_app_connection_t *connection;
  fn_result_t reason = app_result(FN_CANCELLED, FN_STAGE_SHUTDOWN);
  if (app->cancel_sent) {
    return;
  }
  app->cancel_sent = true;
  for (connection = app->connections; connection != NULL;
       connection = connection->next) {
    if (connection->handshake != NULL) {
      (void)fn_socks5_handshake_cancel(connection->handshake);
    } else if (connection->session != NULL) {
      (void)fn_session_close(connection->session, reason);
    } else if (connection->reply_operation != NULL) {
      (void)fn_op_cancel(connection->reply_operation);
    }
  }
}

static void app_begin_stop(fn_app_t *app)
{
  uint64_t now_ms;
  if (app->stopping) {
    return;
  }
  app->stopping = true;
  listeners_stop(app);
  if (fn_monotonic_now_ms(&now_ms).code == FN_OK &&
      fn_deadline_after_ms(now_ms, app->config->timeouts.drain_ms,
                           &app->stop_deadline_ms).code == FN_OK) {
    return;
  }
  app->force_stop = true;
  connections_cancel(app);
}

static void app_process_signals(fn_app_t *app)
{
  unsigned observed = (unsigned)app_signal_count;
#ifdef FN_TEST_INSTRUMENTATION
  if (app_metrics_requested != 0) {
    app_metrics_requested = 0;
    test_metrics_emit(app);
  }
#endif
  if (observed > app->handled_signals) {
    app->handled_signals = observed;
    app_begin_stop(app);
  }
  if (observed >= 2u) {
    app->force_stop = true;
    connections_cancel(app);
  }
}

static void signal_ready(fn_io_watcher_t *watcher, uint32_t events,
                         void *context)
{
  fn_app_t *app = context;
  uint8_t bytes[32];
  (void)watcher;
  if ((events & FN_IO_EVENT_READ) != 0) {
    while (read((int)fn_socket_native(app->signal_read), bytes,
                sizeof(bytes)) > 0) {
    }
  }
  app_process_signals(app);
}

static fn_result_t signal_setup(fn_app_t *app)
{
  struct sigaction action;
  int pair[2] = {-1, -1};
  bool sigint_installed = false;
  bool sigterm_installed = false;
#ifdef FN_TEST_INSTRUMENTATION
  bool sigusr1_installed = false;
#endif
  fn_result_t result;
  result = fn_budget_reserve(&app->file_descriptors, FN_BUDGET_ACTIVE, 2u);
  if (result.code != FN_OK) {
    return result;
  }
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                 0, pair) != 0) {
    int native_code = errno;
    (void)fn_budget_release(&app->file_descriptors, FN_BUDGET_ACTIVE, 2u);
    return app_posix_result(FN_STAGE_PREPARE, native_code);
  }
  (void)fn_socket_from_native((intptr_t)pair[0], &app->signal_read);
  (void)fn_socket_from_native((intptr_t)pair[1], &app->signal_write);
  result = fn_io_watcher_create(app->loop, app->signal_read, signal_ready,
                                app, &app->signal_watcher);
  if (result.code == FN_OK) {
    result = fn_io_watcher_set(app->signal_watcher, FN_IO_EVENT_READ);
  }
  if (result.code != FN_OK) {
    if (app->signal_watcher != NULL) {
      (void)fn_io_watcher_destroy(&app->signal_watcher);
    }
    (void)fn_socket_close(&app->signal_read);
    (void)fn_socket_close(&app->signal_write);
    (void)fn_budget_release(&app->file_descriptors, FN_BUDGET_ACTIVE, 2u);
    return result;
  }
  app_signal_count = 0;
  app_signal_write_fd = (sig_atomic_t)fn_socket_native(app->signal_write);
#ifdef FN_TEST_INSTRUMENTATION
  app_metrics_requested = 0;
#endif
  memset(&action, 0, sizeof(action));
  action.sa_handler = app_signal_handler;
  (void)sigemptyset(&action.sa_mask);
  if (sigaction(SIGINT, &action, &app->old_sigint) == 0) {
    sigint_installed = true;
  }
  if (sigint_installed &&
      sigaction(SIGTERM, &action, &app->old_sigterm) == 0) {
    sigterm_installed = true;
  }
#ifdef FN_TEST_INSTRUMENTATION
  if (sigterm_installed && app->test_metrics_fd >= 0 &&
      sigaction(SIGUSR1, &action, &app->old_sigusr1) == 0) {
    sigusr1_installed = true;
    app->test_metrics_signal_installed = true;
  }
#endif
  if (!sigint_installed || !sigterm_installed
#ifdef FN_TEST_INSTRUMENTATION
      || (app->test_metrics_fd >= 0 && !sigusr1_installed)
#endif
      ) {
    int native_code = errno;
    if (sigint_installed) {
      (void)sigaction(SIGINT, &app->old_sigint, NULL);
    }
#ifdef FN_TEST_INSTRUMENTATION
    if (sigusr1_installed) {
      (void)sigaction(SIGUSR1, &app->old_sigusr1, NULL);
      app->test_metrics_signal_installed = false;
    }
#endif
    app_signal_write_fd = -1;
    app_signal_count = 0;
    (void)fn_io_watcher_destroy(&app->signal_watcher);
    (void)fn_socket_close(&app->signal_read);
    (void)fn_socket_close(&app->signal_write);
    (void)fn_budget_release(&app->file_descriptors, FN_BUDGET_ACTIVE, 2u);
    return app_posix_result(FN_STAGE_PREPARE, native_code);
  }
  memset(&action, 0, sizeof(action));
  action.sa_handler = SIG_IGN;
  (void)sigemptyset(&action.sa_mask);
  if (sigaction(SIGPIPE, &action, &app->old_sigpipe) != 0) {
    int native_code = errno;
    (void)sigaction(SIGINT, &app->old_sigint, NULL);
    (void)sigaction(SIGTERM, &app->old_sigterm, NULL);
#ifdef FN_TEST_INSTRUMENTATION
    if (app->test_metrics_signal_installed) {
      (void)sigaction(SIGUSR1, &app->old_sigusr1, NULL);
      app->test_metrics_signal_installed = false;
    }
#endif
    app_signal_write_fd = -1;
    app_signal_count = 0;
    (void)fn_io_watcher_destroy(&app->signal_watcher);
    (void)fn_socket_close(&app->signal_read);
    (void)fn_socket_close(&app->signal_write);
    (void)fn_budget_release(&app->file_descriptors, FN_BUDGET_ACTIVE, 2u);
    return app_posix_result(FN_STAGE_PREPARE, native_code);
  }
  app->signal_installed = true;
  return app_result(FN_OK, FN_STAGE_NONE);
}

static void signal_teardown(fn_app_t *app)
{
  if (app->signal_installed) {
    (void)sigaction(SIGINT, &app->old_sigint, NULL);
    (void)sigaction(SIGTERM, &app->old_sigterm, NULL);
    (void)sigaction(SIGPIPE, &app->old_sigpipe, NULL);
#ifdef FN_TEST_INSTRUMENTATION
    if (app->test_metrics_signal_installed) {
      (void)sigaction(SIGUSR1, &app->old_sigusr1, NULL);
      app->test_metrics_signal_installed = false;
    }
#endif
    app->signal_installed = false;
  }
  app_signal_write_fd = -1;
  app_signal_count = 0;
#ifdef FN_TEST_INSTRUMENTATION
  app_metrics_requested = 0;
#endif
  if (app->signal_watcher != NULL) {
    (void)fn_io_watcher_destroy(&app->signal_watcher);
  }
  if (fn_socket_is_valid(app->signal_read)) {
    (void)fn_socket_close(&app->signal_read);
    (void)fn_socket_close(&app->signal_write);
    (void)fn_budget_release(&app->file_descriptors, FN_BUDGET_ACTIVE, 2u);
  }
}

static fn_result_t app_base_create(fn_app_t *app)
{
  fn_loop_options_t loop_options;
  fn_runtime_manager_options_t runtime_options;
  fn_result_t result;
  result = fn_budget_init(&app->owned_memory,
                          app->config->limits.owned_memory_limit_bytes,
                          app->config->limits.cleanup_reserve_bytes);
  if (result.code != FN_OK) return result;
  result = fn_budget_init(&app->file_descriptors,
                          app->config->limits.fd_limit, 0u);
  if (result.code != FN_OK) return result;
  result = fn_budget_init(&app->buffers,
                          app->config->limits.buffer_pool_limit_bytes, 0u);
  if (result.code != FN_OK) return result;
  memset(&loop_options, 0, sizeof(loop_options));
  loop_options.limits = &app->config->limits;
  loop_options.owned_memory = &app->owned_memory;
  loop_options.file_descriptors = &app->file_descriptors;
  loop_options.allocator = app->allocator;
  loop_options.dispatch_limit = 64u;
  result = fn_loop_create(&loop_options, &app->loop);
  if (result.code != FN_OK) return result;
  memset(&runtime_options, 0, sizeof(runtime_options));
  runtime_options.loop = app->loop;
  runtime_options.limits = &app->config->limits;
  runtime_options.owned_memory = &app->owned_memory;
  runtime_options.allocator = app->allocator;
  runtime_options.resources.context = app;
  runtime_options.resources.prepare = listener_prepare;
  runtime_options.resources.lazy_start = listener_lazy_start;
  runtime_options.resources.release = listener_release;
  result = fn_runtime_manager_create(&runtime_options,
                                     &app->runtime_manager);
  if (result.code != FN_OK) return result;
  result = fn_runtime_candidate_build(app->runtime_manager, app->config,
                                      &app->plan, &app->candidate);
  if (result.code != FN_OK) return result;
  result = fn_runtime_candidate_prepare(app->candidate);
  return result;
}

static fn_result_t app_data_plane_create(fn_app_t *app)
{
  fn_relay_buffer_pool_options_t pool_options;
  fn_direct_connector_options_t direct_options;
  fn_resolver_options_t resolver_options;
  fn_socks5_outbound_manager_options_t outbound_options;
  fn_session_manager_options_t session_options;
  size_t capacity;
  fn_result_t result;
  result = fn_runtime_candidate_commit(app->runtime_manager,
                                       &app->candidate);
  if (result.code != FN_OK) return result;
  result = fn_runtime_acquire_active(app->runtime_manager, &app->runtime);
  if (result.code != FN_OK) return result;
  memset(&pool_options, 0, sizeof(pool_options));
  capacity = app->config->limits.buffer_pool_limit_bytes /
             FN_APP_RELAY_BLOCK_SIZE;
  if (capacity == 0) capacity = 1u;
  pool_options.loop = app->loop;
  pool_options.limits = &app->config->limits;
  pool_options.owned_memory = &app->owned_memory;
  pool_options.buffer_bytes = &app->buffers;
  pool_options.allocator = app->allocator;
  pool_options.block_size = FN_APP_RELAY_BLOCK_SIZE;
  pool_options.block_capacity = capacity;
  pool_options.block_cache_limit = capacity < 8u ? capacity : 8u;
  result = fn_relay_buffer_pool_create(&pool_options, &app->relay_pool);
  if (result.code != FN_OK) return result;
  memset(&direct_options, 0, sizeof(direct_options));
  direct_options.loop = app->loop;
  direct_options.limits = &app->config->limits;
  direct_options.owned_memory = &app->owned_memory;
  direct_options.file_descriptors = &app->file_descriptors;
  direct_options.allocator = app->allocator;
  direct_options.connect_timeout_ms = app->config->timeouts.connect_ms;
  result = fn_direct_connector_create(&direct_options,
                                      &app->direct_connector);
  if (result.code != FN_OK) return result;
  if ((app->plan.reachable & FN_FEATURE_DNS_RESOLVER) != 0) {
    memset(&resolver_options, 0, sizeof(resolver_options));
    resolver_options.loop = app->loop;
    resolver_options.limits = &app->config->limits;
    resolver_options.owned_memory = &app->owned_memory;
    resolver_options.file_descriptors = &app->file_descriptors;
    resolver_options.allocator = app->allocator;
    resolver_options.config = app->config->dns;
    resolver_options.generation = fn_runtime_generation(app->runtime);
    result = fn_resolver_create(&resolver_options, &app->resolver);
    if (result.code != FN_OK) return result;
  }
  if ((app->plan.reachable & FN_FEATURE_SOCKS_OUT_TCP) != 0) {
    memset(&outbound_options, 0, sizeof(outbound_options));
    outbound_options.loop = app->loop;
    outbound_options.limits = &app->config->limits;
    outbound_options.owned_memory = &app->owned_memory;
    outbound_options.allocator = app->allocator;
    outbound_options.tcp_connector = app->direct_connector;
    outbound_options.resolver = app->resolver;
    result = fn_socks5_outbound_manager_create(&outbound_options,
                                                &app->outbound_manager);
    if (result.code != FN_OK) return result;
  }
  memset(&session_options, 0, sizeof(session_options));
  session_options.loop = app->loop;
  session_options.limits = &app->config->limits;
  session_options.owned_memory = &app->owned_memory;
  session_options.allocator = app->allocator;
  session_options.direct_connector = app->direct_connector;
  session_options.socks5_outbound_manager = app->outbound_manager;
  session_options.resolver = app->resolver;
  session_options.relay_pool = app->relay_pool;
  result = fn_session_manager_create(&session_options,
                                     &app->session_manager);
  return result;
}

static void summary_capture(fn_app_t *app, fn_app_summary_t *summary)
{
  fn_app_listener_t *listener;
  size_t index;
  memset(summary, 0, sizeof(*summary));
  if (app->runtime != NULL) {
    summary->generation = fn_runtime_generation(app->runtime);
    for (index = 0; index < fn_runtime_object_count(app->runtime); index++) {
      const fn_runtime_resource_descriptor_t *descriptor = NULL;
      fn_object_ref_t object = {
        .generation = summary->generation,
        .index = (uint32_t)index,
      };
      if (fn_runtime_object_get(app->runtime, object, &descriptor).code ==
            FN_OK && descriptor->planned_lazy) {
        summary->lazy_objects++;
      }
    }
  } else {
    for (listener = app->listeners; listener != NULL;
         listener = listener->next) {
      summary->listeners++;
    }
  }
  if (summary->listeners == 0) {
    summary->listeners = app->listener_count;
  }
  summary->accepted_connections = app->accepted_connections;
  summary->completed_sessions = app->completed_sessions;
  summary->failed_sessions = app->failed_sessions;
  summary->bytes_up = app->bytes_up;
  summary->bytes_down = app->bytes_down;
  summary->active_connections = app->active_connections;
  summary->active_handshakes = app->active_handshakes;
  summary->forced_stop = app->force_stop;
  if (app->loop != NULL) {
    (void)fn_loop_snapshot(app->loop, &summary->loop);
  }
  if (app->logger != NULL) {
    (void)fn_logger_snapshot(app->logger, &summary->logger);
  }
  (void)fn_budget_snapshot(&app->owned_memory, &summary->owned_memory);
  (void)fn_budget_snapshot(&app->file_descriptors,
                           &summary->file_descriptors);
  (void)fn_budget_snapshot(&app->buffers, &summary->buffers);
  if (app->session_manager != NULL) {
    (void)fn_session_manager_snapshot(app->session_manager,
                                      &summary->sessions);
  }
  if (app->runtime_manager != NULL) {
    (void)fn_runtime_manager_snapshot(app->runtime_manager,
                                      &summary->runtime_manager);
  }
  if (app->relay_pool != NULL) {
    (void)fn_relay_buffer_pool_snapshot(app->relay_pool,
                                        &summary->relay_pool);
  }
}

#ifdef FN_TEST_INSTRUMENTATION
static void test_metrics_emit(fn_app_t *app)
{
  fn_app_summary_t summary;
  char line[2048];
  uint64_t now_ms = 0;
  int length;
  ssize_t ignored;
  if (app->test_metrics_fd < 0) {
    return;
  }
  summary_capture(app, &summary);
  (void)fn_monotonic_now_ms(&now_ms);
  app->test_metrics_sequence++;
  length = snprintf(
    line, sizeof(line),
    "{\"schema\":\"flick.test-metrics/v1\",\"sequence\":%llu,"
    "\"monotonic_ms\":%llu,\"generation\":%llu,"
    "\"active_connections\":%zu,\"active_handshakes\":%zu,"
    "\"active_sessions\":%zu,\"owned_session_bytes\":%zu,"
    "\"owned_bytes\":%zu,"
    "\"owned_limit\":%zu,\"candidate_bytes\":%zu,"
    "\"retained_bytes\":%zu,\"buffer_bytes\":%zu,"
    "\"buffer_limit\":%zu,\"fd_budget\":%zu,\"fd_limit\":%zu,"
    "\"pool_live_blocks\":%zu,\"pool_cached_blocks\":%zu,"
    "\"resource_waiters\":%zu,\"runtime_candidates\":%zu,"
    "\"retained_runtimes\":%zu,\"async_operations\":%zu,"
    "\"lazy_waiters\":%zu,\"loop_iterations\":%llu,"
    "\"io_callbacks\":%llu,\"terminal_callbacks\":%llu,"
    "\"accepted_connections\":%llu,\"completed_sessions\":%llu,"
    "\"failed_sessions\":%llu,\"bytes_up\":%llu,"
    "\"bytes_down\":%llu}\n",
    (unsigned long long)app->test_metrics_sequence,
    (unsigned long long)now_ms,
    (unsigned long long)summary.generation,
    summary.active_connections, summary.active_handshakes,
    summary.sessions.active_sessions, summary.sessions.owned_session_bytes,
    summary.owned_memory.total,
    summary.owned_memory.limit, summary.owned_memory.candidate,
    summary.owned_memory.retained, summary.buffers.total,
    summary.buffers.limit, summary.file_descriptors.total,
    summary.file_descriptors.limit, summary.relay_pool.blocks.live_blocks,
    summary.relay_pool.blocks.cached_blocks,
    summary.relay_pool.resource_waiters,
    summary.runtime_manager.candidates,
    summary.runtime_manager.retained_runtimes,
    summary.runtime_manager.async_operations,
    summary.runtime_manager.lazy_waiters,
    (unsigned long long)summary.loop.run_iterations,
    (unsigned long long)summary.loop.io_callbacks,
    (unsigned long long)summary.loop.terminal_callbacks,
    (unsigned long long)summary.accepted_connections,
    (unsigned long long)summary.completed_sessions,
    (unsigned long long)summary.failed_sessions,
    (unsigned long long)summary.bytes_up,
    (unsigned long long)summary.bytes_down);
  if (length > 0 && (size_t)length < sizeof(line)) {
    ignored = write(app->test_metrics_fd, line, (size_t)length);
    (void)ignored;
  }
}
#endif

static fn_app_t *app_allocate(const fn_config_t *config,
                              const fn_feature_plan_t *plan,
                              fn_logger_t *logger, bool test_mode)
{
  fn_app_t *app = calloc(1u, sizeof(*app));
  if (app != NULL) {
    app->config = config;
    app->plan = *plan;
    app->allocator = fn_allocator_system();
    app->logger = logger;
    app->test_mode = test_mode;
    app->signal_read = fn_socket_invalid();
    app->signal_write = fn_socket_invalid();
#ifdef FN_TEST_INSTRUMENTATION
    {
      const char *value = getenv("FN_TEST_METRICS_FD");
      char *end = NULL;
      long descriptor = -1;
      app->test_metrics_fd = -1;
      if (value != NULL && value[0] != '\0') {
        errno = 0;
        descriptor = strtol(value, &end, 10);
        if (errno == 0 && end != value && *end == '\0' &&
            descriptor >= 0 && descriptor <= INT_MAX &&
            fcntl((int)descriptor, F_GETFD) >= 0) {
          app->test_metrics_fd = (int)descriptor;
        }
      }
    }
#endif
  }
  return app;
}

fn_result_t fn_app_test_environment(const fn_config_t *config,
                                    const fn_feature_plan_t *plan,
                                    fn_app_summary_t *summary)
{
  fn_app_t *app;
  fn_result_t result;
  fn_result_t destroy_result;
  if (config == NULL || plan == NULL || summary == NULL) {
    return app_result(FN_INVALID, FN_STAGE_PREPARE);
  }
  app = app_allocate(config, plan, NULL, true);
  if (app == NULL) {
    return app_result(FN_NO_MEMORY, FN_STAGE_RESOURCE);
  }
  result = app_base_create(app);
  summary_capture(app, summary);
  destroy_result = fn_app_destroy(&app);
  if (result.code != FN_OK) return result;
  return destroy_result;
}

fn_result_t fn_app_create(const fn_config_t *config,
                          const fn_feature_plan_t *plan,
                          fn_logger_t *logger, fn_app_t **out)
{
  fn_app_t *app;
  fn_app_listener_t *listener;
  fn_result_t result;
  if (out == NULL) {
    return app_result(FN_INVALID, FN_STAGE_PREPARE);
  }
  *out = NULL;
  if (config == NULL || plan == NULL || logger == NULL) {
    return app_result(FN_INVALID, FN_STAGE_PREPARE);
  }
  app = app_allocate(config, plan, logger, false);
  if (app == NULL) {
    return app_result(FN_NO_MEMORY, FN_STAGE_RESOURCE);
  }
  result = app_base_create(app);
  if (result.code == FN_OK) result = app_data_plane_create(app);
  if (result.code == FN_OK) result = signal_setup(app);
  for (listener = app->listeners; result.code == FN_OK && listener != NULL;
       listener = listener->next) {
    result = listener_activate(listener);
  }
  if (result.code != FN_OK) {
    fn_result_t destroy_result = fn_app_destroy(&app);
    (void)destroy_result;
    return result;
  }
  for (listener = app->listeners; listener != NULL;
       listener = listener->next) {
    if (listener->descriptor.planned_lazy) {
      app->lazy_objects++;
    }
  }
  app->entered_running = true;
  *out = app;
  return app_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_app_run(fn_app_t *app, fn_app_summary_t *summary)
{
  struct timespec pause_time = {.tv_sec = 0, .tv_nsec = 1000000L};
  fn_result_t result;
  if (app == NULL || summary == NULL || !app->entered_running) {
    return app_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  for (;;) {
    uint64_t now_ms;
    app_process_signals(app);
    if (app->runtime_error_set) {
      app_begin_stop(app);
      connections_cancel(app);
    }
    if (app->stopping && app->active_connections == 0) {
      break;
    }
    if (app->stopping && !app->force_stop &&
        fn_monotonic_now_ms(&now_ms).code == FN_OK &&
        now_ms >= app->stop_deadline_ms) {
      app->force_stop = true;
      connections_cancel(app);
    }
    result = fn_loop_run_once(
      app->loop, app->stopping ? FN_LOOP_RUN_NOWAIT : FN_LOOP_RUN_ONCE);
    if (result.code != FN_OK) {
      app->runtime_error = result;
      app->runtime_error_set = true;
      app_begin_stop(app);
      connections_cancel(app);
    }
    if (app->stopping && app->active_connections != 0) {
      (void)nanosleep(&pause_time, NULL);
    }
  }
  summary_capture(app, summary);
  if (app->force_stop) {
    return app_result(FN_TIMEOUT, FN_STAGE_SHUTDOWN);
  }
  if (app->runtime_error_set) {
    return app->runtime_error;
  }
  return app_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_app_snapshot(fn_app_t *app, fn_app_summary_t *summary)
{
  if (app == NULL || summary == NULL) {
    return app_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  summary_capture(app, summary);
  return app_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_app_destroy(fn_app_t **pointer)
{
  fn_app_t *app;
  fn_result_t first_error = app_result(FN_OK, FN_STAGE_NONE);
#define FN_APP_CLEAN(call)                                                     \
  do {                                                                         \
    fn_result_t clean_result = (call);                                         \
    if (first_error.code == FN_OK && clean_result.code != FN_OK) {             \
      first_error = clean_result;                                              \
    }                                                                          \
  } while (0)
  if (pointer == NULL) {
    return app_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  app = *pointer;
  if (app == NULL) {
    return first_error;
  }
  if (app->active_connections != 0 || app->connections != NULL) {
    return app_result(FN_INVALID, FN_STAGE_SHUTDOWN);
  }
  signal_teardown(app);
  if (app->candidate != NULL) {
    FN_APP_CLEAN(fn_runtime_candidate_destroy(&app->candidate));
  }
  if (app->runtime != NULL) {
    FN_APP_CLEAN(fn_runtime_release(&app->runtime));
  }
  if (app->session_manager != NULL) {
    FN_APP_CLEAN(fn_session_manager_destroy(&app->session_manager));
  }
  if (app->runtime_manager != NULL) {
    FN_APP_CLEAN(fn_runtime_manager_destroy(&app->runtime_manager));
  }
  if (app->outbound_manager != NULL) {
    FN_APP_CLEAN(fn_socks5_outbound_manager_destroy(&app->outbound_manager));
  }
  if (app->resolver != NULL) {
    FN_APP_CLEAN(fn_resolver_destroy(&app->resolver));
  }
  if (app->direct_connector != NULL) {
    FN_APP_CLEAN(fn_direct_connector_destroy(&app->direct_connector));
  }
  if (app->relay_pool != NULL) {
    FN_APP_CLEAN(fn_relay_buffer_pool_destroy(&app->relay_pool));
  }
  if (app->loop != NULL) {
    FN_APP_CLEAN(fn_loop_destroy(&app->loop));
  }
  free(app);
  *pointer = NULL;
#undef FN_APP_CLEAN
  return first_error;
}
