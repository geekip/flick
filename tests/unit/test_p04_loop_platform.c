#define _POSIX_C_SOURCE 200809L

#include "flicknet/clock.h"
#include "flicknet/loop.h"
#include "flicknet/platform.h"

#include "socket_policy_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

typedef struct {
  size_t calls;
  size_t frees;
  size_t live;
  size_t fail_on_call;
} test_allocator_state_t;

typedef struct {
  pthread_t owner;
  fn_loop_t *loop;
  int order[16];
  size_t order_count;
  size_t completion_count;
  fn_status_t last_status;
  bool callback_on_owner;
  fn_status_t recursive_run_status;
} callback_state_t;

typedef struct {
  fn_completion_ticket_t *ticket;
  callback_state_t *callbacks;
  fn_status_t publish_status;
} producer_context_t;

typedef struct {
  fn_socket_policy_operation_t fail_operation;
  int fail_error;
  size_t calls[4];
} policy_backend_state_t;

static void *test_allocate(void *context, size_t size)
{
  test_allocator_state_t *state = context;
  void *pointer;
  state->calls++;
  if (state->fail_on_call != 0 && state->calls == state->fail_on_call) {
    return NULL;
  }
  pointer = malloc(size);
  if (pointer != NULL) {
    state->live++;
  }
  return pointer;
}

static void test_deallocate(void *context, void *pointer)
{
  test_allocator_state_t *state = context;
  if (pointer != NULL) {
    state->frees++;
    state->live--;
    free(pointer);
  }
}

static fn_allocator_t test_allocator(test_allocator_state_t *state)
{
  const fn_allocator_t allocator = {
    .context = state,
    .allocate = test_allocate,
    .deallocate = test_deallocate,
  };
  return allocator;
}

static void record_completion(void *context, fn_result_t result)
{
  callback_state_t *state = context;
  state->completion_count++;
  state->last_status = result.code;
  state->callback_on_owner = pthread_equal(state->owner, pthread_self()) != 0;
  state->recursive_run_status = fn_loop_run_once(
    state->loop, FN_LOOP_RUN_NOWAIT).code;
  state->order[state->order_count++] = 100;
}

static void record_post_one(void *context)
{
  callback_state_t *state = context;
  state->order[state->order_count++] = 1;
}

static void record_post_two(void *context)
{
  callback_state_t *state = context;
  state->order[state->order_count++] = 2;
}

static void *delayed_producer(void *context)
{
  producer_context_t *producer = context;
  struct timespec delay = {
    .tv_sec = 0,
    .tv_nsec = 10L * 1000L * 1000L,
  };
  fn_result_t result;
  (void)nanosleep(&delay, NULL);
  result = fn_completion_publish(
    &producer->ticket,
    fn_result_make(FN_CANCELLED, FN_STAGE_SHUTDOWN,
                   FN_ERROR_ORIGIN_NONE, INT64_C(0)),
    record_completion, producer->callbacks);
  producer->publish_status = result.code;
  return NULL;
}

static int make_loop(test_allocator_state_t *allocator_state,
                     fn_budget_t *memory, fn_budget_t *fds,
                     fn_limits_t *limits, fn_loop_t **out)
{
  const fn_loop_options_t options = {
    .limits = limits,
    .owned_memory = memory,
    .file_descriptors = fds,
    .allocator = test_allocator(allocator_state),
    .dispatch_limit = 1u,
  };
  if (fn_budget_init(memory, (size_t)1024u * 1024u,
                     (size_t)128u * 1024u).code != FN_OK ||
      fn_budget_init(fds, (size_t)16u, 0).code != FN_OK) {
    return 1;
  }
  *limits = fn_limits_default();
  limits->completion_entry_limit = 2u;
  limits->completion_limit_bytes = 4096u;
  limits->loop_post_entry_limit = 2u;
  limits->loop_post_limit_bytes = 4096u;
  limits->timer_limit = 1u;
  return fn_loop_create(&options, out).code == FN_OK ? 0 : 2;
}

static int check_completion_channels(void)
{
  test_allocator_state_t allocator_state = {0};
  fn_budget_t memory;
  fn_budget_t fds;
  fn_limits_t limits;
  fn_loop_t *loop = NULL;
  fn_completion_ticket_t *first = NULL;
  fn_completion_ticket_t *second = NULL;
  fn_completion_ticket_t *extra = NULL;
  fn_loop_snapshot_t snapshot;
  callback_state_t callbacks = {
    .owner = pthread_self(),
    .loop = NULL,
    .order = {0},
    .order_count = 0,
    .completion_count = 0,
    .last_status = FN_OK,
    .callback_on_owner = false,
    .recursive_run_status = FN_OK,
  };
  producer_context_t producer;
  pthread_t thread;
  fn_budget_snapshot_t memory_snapshot;
  fn_budget_snapshot_t fd_snapshot;

  if (make_loop(&allocator_state, &memory, &fds, &limits, &loop) != 0) {
    return 1;
  }
  callbacks.loop = loop;
  if (
      fn_completion_reserve_terminal(loop, &first).code != FN_OK ||
      fn_completion_reserve_terminal(loop, &second).code != FN_OK ||
      fn_completion_reserve_terminal(loop, &extra).code != FN_LIMIT ||
      extra != NULL || fn_completion_abandon(&second).code != FN_OK ||
      second != NULL ||
      fn_loop_post(loop, record_post_one, &callbacks).code != FN_OK ||
      fn_loop_post(loop, record_post_two, &callbacks).code != FN_OK ||
      fn_loop_post(loop, record_post_two, &callbacks).code != FN_LIMIT ||
      fn_completion_publish(
        &first, fn_result_make(FN_OK, FN_STAGE_NONE, FN_ERROR_ORIGIN_NONE,
                               INT64_C(0)),
        record_completion, &callbacks).code != FN_OK || first != NULL) {
    return 1;
  }
  if (fn_loop_run_once(loop, FN_LOOP_RUN_NOWAIT).code != FN_OK ||
      fn_loop_run_once(loop, FN_LOOP_RUN_NOWAIT).code != FN_OK ||
      fn_loop_run_once(loop, FN_LOOP_RUN_NOWAIT).code != FN_OK ||
      callbacks.order_count != 3u || callbacks.order[0] != 100 ||
      callbacks.order[1] != 1 || callbacks.order[2] != 2 ||
      callbacks.completion_count != 1u ||
      callbacks.last_status != FN_OK || !callbacks.callback_on_owner ||
      callbacks.recursive_run_status != FN_INVALID) {
    return 2;
  }

  allocator_state.fail_on_call = allocator_state.calls + 1u;
  if (fn_completion_reserve_terminal(loop, &extra).code != FN_NO_MEMORY ||
      extra != NULL) {
    return 3;
  }
  allocator_state.fail_on_call = 0;
  if (fn_completion_reserve_terminal(loop, &producer.ticket).code != FN_OK) {
    return 4;
  }
  producer.callbacks = &callbacks;
  producer.publish_status = FN_INVALID;
  if (pthread_create(&thread, NULL, delayed_producer, &producer) != 0 ||
      fn_loop_run_once(loop, FN_LOOP_RUN_ONCE).code != FN_OK ||
      pthread_join(thread, NULL) != 0 || producer.publish_status != FN_OK ||
      producer.ticket != NULL || callbacks.completion_count != 2u ||
      callbacks.last_status != FN_CANCELLED || !callbacks.callback_on_owner) {
    return 5;
  }
  if (fn_loop_snapshot(loop, &snapshot).code != FN_OK ||
      snapshot.terminal_live != 0 || snapshot.terminal_queued != 0 ||
      snapshot.post_live != 0 || snapshot.post_queued != 0 ||
      snapshot.internal_fd_reservation != 3u ||
      fn_loop_destroy(&loop).code != FN_OK || loop != NULL ||
      fn_budget_snapshot(&memory, &memory_snapshot).code != FN_OK ||
      memory_snapshot.total != 0 ||
      fn_budget_snapshot(&fds, &fd_snapshot).code != FN_OK ||
      fd_snapshot.total != 0 || allocator_state.live != 0) {
    return 6;
  }
  return 0;
}

typedef struct {
  size_t timer_callbacks;
  size_t io_callbacks;
  uint32_t io_events;
} event_state_t;

static void timer_fired(fn_timer_t *timer, void *context)
{
  event_state_t *state = context;
  state->timer_callbacks++;
  if (fn_timer_cancel(timer).code != FN_OK) {
    state->timer_callbacks += 1000u;
  }
}

static void io_ready(fn_io_watcher_t *watcher, uint32_t events,
                     void *context)
{
  event_state_t *state = context;
  (void)watcher;
  state->io_callbacks++;
  state->io_events |= events;
}

static int check_timer_and_watcher(void)
{
  test_allocator_state_t allocator_state = {0};
  fn_budget_t memory;
  fn_budget_t fds;
  fn_limits_t limits;
  fn_loop_t *loop = NULL;
  fn_timer_t *timer = NULL;
  fn_timer_t *extra_timer = NULL;
  fn_io_watcher_t *watcher = NULL;
  fn_socket_t first = fn_socket_invalid();
  fn_socket_t second = fn_socket_invalid();
  fn_socket_policy_report_t report;
  fn_socket_policy_t policy = {
    .purpose = FN_SOCKET_PURPOSE_INBOUND_ACCEPTED,
    .require_nonblocking = true,
    .require_route_guard = false,
    .route_mark = 0,
    .prefer_tcp_nodelay = false,
    .prefer_keepalive = false,
  };
  event_state_t events = {0};
  uint64_t now_ms;
  int pair[2] = {-1, -1};
  uint8_t byte = UINT8_C(7);

  if (make_loop(&allocator_state, &memory, &fds, &limits, &loop) != 0 ||
      fn_monotonic_now_ms(&now_ms).code != FN_OK ||
      fn_timer_start(loop, now_ms, timer_fired, &events,
                     &timer).code != FN_OK ||
      fn_timer_start(loop, now_ms, timer_fired, &events,
                     &extra_timer).code != FN_LIMIT || extra_timer != NULL ||
      fn_loop_run_once(loop, FN_LOOP_RUN_ONCE).code != FN_OK ||
      events.timer_callbacks != 1u ||
      fn_timer_cancel(timer).code != FN_OK ||
      fn_timer_cancel(timer).code != FN_OK ||
      fn_timer_destroy(&timer).code != FN_OK || timer != NULL ||
      fn_timer_destroy(&timer).code != FN_OK) {
    return 1;
  }
  if (fn_timer_start(loop, now_ms + UINT64_C(60000), timer_fired,
                     &events, &timer).code != FN_OK ||
      fn_timer_cancel(timer).code != FN_OK ||
      fn_timer_cancel(timer).code != FN_OK ||
      fn_loop_run_once(loop, FN_LOOP_RUN_NOWAIT).code != FN_OK ||
      events.timer_callbacks != 1u ||
      fn_timer_destroy(&timer).code != FN_OK) {
    return 2;
  }
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0 ||
      fn_socket_from_native((intptr_t)pair[0], &first).code != FN_OK ||
      fn_socket_from_native((intptr_t)pair[1], &second).code != FN_OK ||
      fn_socket_policy_apply(first, &policy, &report).code != FN_OK ||
      fn_socket_policy_apply(second, &policy, &report).code != FN_OK ||
      fn_io_watcher_create(loop, first, io_ready, &events,
                           &watcher).code != FN_OK ||
      fn_io_watcher_set(watcher, FN_IO_EVENT_ERROR).code != FN_INVALID ||
      fn_io_watcher_set(watcher, FN_IO_EVENT_READ).code != FN_OK ||
      fn_socket_write(second, &byte, sizeof(byte),
                      FN_STAGE_RELAY).result.code != FN_OK ||
      fn_loop_run_once(loop, FN_LOOP_RUN_ONCE).code != FN_OK ||
      events.io_callbacks != 1u ||
      (events.io_events & FN_IO_EVENT_READ) == 0 ||
      fn_io_watcher_stop(watcher).code != FN_OK ||
      fn_io_watcher_stop(watcher).code != FN_OK ||
      fn_io_watcher_destroy(&watcher).code != FN_OK || watcher != NULL ||
      fn_io_watcher_destroy(&watcher).code != FN_OK ||
      fn_socket_close(&first).code != FN_OK ||
      fn_socket_close(&second).code != FN_OK ||
      fn_loop_destroy(&loop).code != FN_OK || allocator_state.live != 0) {
    return 3;
  }
  return 0;
}

static int policy_call(void *context, fn_socket_t socket,
                       fn_socket_policy_operation_t operation,
                       uint32_t value, int *native_error)
{
  policy_backend_state_t *state = context;
  (void)socket;
  (void)value;
  state->calls[(size_t)operation]++;
  if (operation == state->fail_operation) {
    *native_error = state->fail_error;
    return -1;
  }
  return 0;
}

static int check_socket_policy_failures(void)
{
  fn_socket_t socket;
  fn_socket_policy_report_t report;
  fn_socket_policy_t policy = {
    .purpose = FN_SOCKET_PURPOSE_DIRECT,
    .require_nonblocking = true,
    .require_route_guard = true,
    .route_mark = UINT32_C(123),
    .prefer_tcp_nodelay = true,
    .prefer_keepalive = true,
  };
  policy_backend_state_t state = {
    .fail_operation = FN_SOCKET_POLICY_OP_NONBLOCK,
    .fail_error = EACCES,
    .calls = {0},
  };
  fn_socket_policy_backend_t backend = {
    .context = &state,
    .call = policy_call,
  };
  fn_result_t result;

  if (fn_socket_from_native((intptr_t)5, &socket).code != FN_OK) {
    return 1;
  }
  result = fn_socket_policy_apply_with_backend(socket, &policy, &report,
                                                &backend);
  if (result.code != FN_IO_ERROR || result.origin != FN_ERROR_ORIGIN_POSIX ||
      result.native_code != (int64_t)EACCES || state.calls[0] != 1u ||
      state.calls[1] != 0u) {
    return 2;
  }
  memset(state.calls, 0, sizeof(state.calls));
  state.fail_operation = FN_SOCKET_POLICY_OP_ROUTE_MARK;
  state.fail_error = EPERM;
  result = fn_socket_policy_apply_with_backend(socket, &policy, &report,
                                                &backend);
  if (result.code != FN_IO_ERROR || result.native_code != (int64_t)EPERM ||
      report.applied != FN_SOCKET_OPTION_NONBLOCK ||
      state.calls[0] != 1u || state.calls[1] != 1u || state.calls[2] != 0u) {
    return 3;
  }
  memset(state.calls, 0, sizeof(state.calls));
  state.fail_operation = FN_SOCKET_POLICY_OP_TCP_NODELAY;
  state.fail_error = ENOPROTOOPT;
  result = fn_socket_policy_apply_with_backend(socket, &policy, &report,
                                                &backend);
  if (result.code != FN_OK ||
      report.applied != (FN_SOCKET_OPTION_NONBLOCK |
                         FN_SOCKET_OPTION_ROUTE_MARK |
                         FN_SOCKET_OPTION_KEEPALIVE) ||
      report.optional_failed != FN_SOCKET_OPTION_TCP_NODELAY ||
      report.optional_first_native_code != ENOPROTOOPT) {
    return 4;
  }
  memset(state.calls, 0, sizeof(state.calls));
  policy.purpose = FN_SOCKET_PURPOSE_INBOUND_LISTENER;
  result = fn_socket_policy_apply_with_backend(socket, &policy, &report,
                                                &backend);
  if (result.code != FN_INVALID || state.calls[0] != 0u) {
    return 5;
  }
  return 0;
}

static int check_partial_io_and_close(void)
{
  int pair[2] = {-1, -1};
  int eof_pair[2] = {-1, -1};
  int small_buffer = 1024;
  fn_socket_t writer = fn_socket_invalid();
  fn_socket_t reader = fn_socket_invalid();
  fn_socket_t eof_writer = fn_socket_invalid();
  fn_socket_t eof_reader = fn_socket_invalid();
  fn_socket_policy_report_t report;
  fn_socket_policy_t policy = {
    .purpose = FN_SOCKET_PURPOSE_INBOUND_ACCEPTED,
    .require_nonblocking = true,
    .require_route_guard = false,
    .route_mark = 0,
    .prefer_tcp_nodelay = true,
    .prefer_keepalive = true,
  };
  uint8_t output[8192];
  uint8_t input[17];
  size_t total = 0;
  bool saw_again = false;
  bool saw_partial = false;
  size_t iteration;

  memset(output, 0xa5, sizeof(output));
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0 ||
      setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &small_buffer,
                 (socklen_t)sizeof(small_buffer)) != 0 ||
      fn_socket_from_native((intptr_t)pair[0], &writer).code != FN_OK ||
      fn_socket_from_native((intptr_t)pair[1], &reader).code != FN_OK ||
      fn_socket_policy_apply(writer, &policy, &report).code != FN_OK ||
      fn_socket_policy_apply(reader, &policy, &report).code != FN_OK ||
      (report.applied & FN_SOCKET_OPTION_NONBLOCK) == 0) {
    return 1;
  }
  for (iteration = 0; iteration < 10000u; iteration++) {
    const fn_io_result_t written = fn_socket_write(
      writer, output, sizeof(output), FN_STAGE_RELAY);
    if (written.result.code == FN_AGAIN) {
      saw_again = true;
      break;
    }
    if (written.result.code != FN_OK || written.transferred == 0 ||
        written.transferred > sizeof(output)) {
      return 2;
    }
    if (written.transferred < sizeof(output)) {
      saw_partial = true;
    }
    total += written.transferred;
  }
  {
    const fn_io_result_t read_result = fn_socket_read(
      reader, input, sizeof(input), FN_STAGE_RELAY);
    if (!saw_again || total == 0 || read_result.result.code != FN_OK ||
        read_result.transferred == 0 ||
        read_result.transferred > sizeof(input) ||
        (!saw_partial && read_result.transferred != sizeof(input))) {
      return 3;
    }
  }
  if (fn_socket_close(&writer).code != FN_OK ||
      fn_socket_close(&writer).code != FN_OK ||
      fn_socket_close(&reader).code != FN_OK) {
    return 4;
  }

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, eof_pair) != 0 ||
      fn_socket_from_native((intptr_t)eof_pair[0], &eof_writer).code != FN_OK ||
      fn_socket_from_native((intptr_t)eof_pair[1], &eof_reader).code != FN_OK ||
      fn_socket_close(&eof_writer).code != FN_OK ||
      fn_socket_read(eof_reader, input, sizeof(input),
                     FN_STAGE_RELAY).result.code != FN_EOF ||
      fn_socket_close(&eof_reader).code != FN_OK) {
    return 5;
  }
  return 0;
}

int main(void)
{
  const int completion_check = check_completion_channels();
  const int event_check = check_timer_and_watcher();
  const int policy_check = check_socket_policy_failures();
  const int io_check = check_partial_io_and_close();

  if (completion_check != 0 || event_check != 0 || policy_check != 0 ||
      io_check != 0) {
    fprintf(stderr,
            "P04 loop/platform check failed: completion=%d event=%d policy=%d io=%d.\n",
            completion_check, event_check, policy_check, io_check);
    return 1;
  }
  puts("P04 loop, completion, timer and socket policy checks passed.");
  return 0;
}
