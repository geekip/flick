#include "flicknet/loop.h"

#include "flicknet/clock.h"

#include <ev.h>
#include <pthread.h>
#include <string.h>

#define FN_LOOP_INTERNAL_FD_RESERVATION ((size_t)3u)

typedef enum {
  FN_QUEUE_TERMINAL = 0,
  FN_QUEUE_POST
} fn_queue_kind_t;

typedef enum {
  FN_TICKET_RESERVED = 0,
  FN_TICKET_QUEUED
} fn_ticket_state_t;

struct fn_completion_ticket {
  fn_loop_t *loop;
  fn_completion_ticket_t *next;
  fn_result_t result;
  fn_completion_callback_fn completion_callback;
  fn_loop_post_callback_fn post_callback;
  void *context;
  fn_queue_kind_t kind;
  fn_ticket_state_t state;
};

struct fn_timer {
  fn_loop_t *loop;
  ev_timer watcher;
  fn_timer_callback_fn callback;
  void *context;
  bool active;
};

struct fn_io_watcher {
  fn_loop_t *loop;
  ev_io watcher;
  fn_socket_t socket;
  fn_io_watcher_callback_fn callback;
  void *context;
  uint32_t interests;
  bool active;
};

struct fn_loop {
  struct ev_loop *native_loop;
  ev_async wake;
  pthread_t owner;
  pthread_mutex_t queue_mutex;
  fn_allocator_t allocator;
  fn_budget_t *owned_memory;
  fn_budget_t *file_descriptors;
  fn_budget_t terminal_bytes;
  fn_budget_t post_bytes;
  fn_budget_t timer_entries;
  fn_completion_ticket_t *terminal_head;
  fn_completion_ticket_t *terminal_tail;
  fn_completion_ticket_t *post_head;
  fn_completion_ticket_t *post_tail;
  size_t terminal_limit;
  size_t post_limit;
  size_t terminal_live;
  size_t terminal_queued;
  size_t post_live;
  size_t post_queued;
  size_t timers;
  size_t active_timers;
  size_t io_watchers;
  size_t active_io_watchers;
  size_t dispatch_limit;
  size_t dispatch_depth;
  uint64_t run_iterations;
  uint64_t terminal_callbacks;
  uint64_t post_callbacks;
  uint64_t timer_callbacks;
  uint64_t io_callbacks;
};

/* counter_increment 让长期运行计数在极限处保持单调而不回绕。 */
static void counter_increment(uint64_t *counter)
{
  if (*counter != UINT64_MAX) {
    (*counter)++;
  }
}

static fn_result_t loop_result(fn_status_t code)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE :
                                               FN_STAGE_RESOURCE,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static fn_result_t loop_posix_result(int native_code)
{
  return fn_result_make(FN_IO_ERROR, FN_STAGE_RESOURCE,
                        FN_ERROR_ORIGIN_POSIX, (int64_t)native_code);
}

bool fn_loop_is_owner(const fn_loop_t *loop)
{
  return loop != NULL && pthread_equal(loop->owner, pthread_self()) != 0;
}

static void queue_append(fn_completion_ticket_t **head,
                         fn_completion_ticket_t **tail,
                         fn_completion_ticket_t *node)
{
  node->next = NULL;
  if (*tail == NULL) {
    *head = node;
  } else {
    (*tail)->next = node;
  }
  *tail = node;
}

static fn_completion_ticket_t *queue_pop(fn_completion_ticket_t **head,
                                         fn_completion_ticket_t **tail)
{
  fn_completion_ticket_t *node = *head;
  if (node != NULL) {
    *head = node->next;
    if (*head == NULL) {
      *tail = NULL;
    }
    node->next = NULL;
  }
  return node;
}

static bool queue_has_work(fn_loop_t *loop)
{
  bool has_work;
  (void)pthread_mutex_lock(&loop->queue_mutex);
  has_work = loop->terminal_head != NULL || loop->post_head != NULL;
  (void)pthread_mutex_unlock(&loop->queue_mutex);
  return has_work;
}

static fn_completion_ticket_t *queue_take_next(fn_loop_t *loop)
{
  fn_completion_ticket_t *node;
  (void)pthread_mutex_lock(&loop->queue_mutex);
  node = queue_pop(&loop->terminal_head, &loop->terminal_tail);
  if (node != NULL) {
    loop->terminal_queued--;
  } else {
    node = queue_pop(&loop->post_head, &loop->post_tail);
    if (node != NULL) {
      loop->post_queued--;
    }
  }
  (void)pthread_mutex_unlock(&loop->queue_mutex);
  return node;
}

static void release_queue_node(fn_completion_ticket_t *node)
{
  fn_loop_t *loop = node->loop;
  const fn_queue_kind_t kind = node->kind;
  (void)pthread_mutex_lock(&loop->queue_mutex);
  if (kind == FN_QUEUE_TERMINAL) {
    loop->terminal_live--;
  } else {
    loop->post_live--;
  }
  (void)pthread_mutex_unlock(&loop->queue_mutex);
  loop->allocator.deallocate(loop->allocator.context, node);
  if (kind == FN_QUEUE_TERMINAL) {
    (void)fn_budget_release_pair(loop->owned_memory, sizeof(*node),
                                 &loop->terminal_bytes, sizeof(*node),
                                 FN_BUDGET_CLEANUP);
  } else {
    (void)fn_budget_release_pair(loop->owned_memory, sizeof(*node),
                                 &loop->post_bytes, sizeof(*node),
                                 FN_BUDGET_ACTIVE);
  }
}

static void dispatch_pending(fn_loop_t *loop)
{
  size_t dispatched = 0;
  while (dispatched < loop->dispatch_limit) {
    fn_completion_ticket_t *node = queue_take_next(loop);
    if (node == NULL) {
      break;
    }
    loop->dispatch_depth++;
    if (node->kind == FN_QUEUE_TERMINAL) {
      counter_increment(&loop->terminal_callbacks);
      node->completion_callback(node->context, node->result);
    } else {
      counter_increment(&loop->post_callbacks);
      node->post_callback(node->context);
    }
    loop->dispatch_depth--;
    release_queue_node(node);
    dispatched++;
  }
  if (queue_has_work(loop)) {
    ev_async_send(loop->native_loop, &loop->wake);
  }
}

static void wake_callback(EV_P_ ev_async *watcher, int revents)
{
  fn_loop_t *fn_loop = watcher->data;
  (void)EV_A;
  (void)revents;
  dispatch_pending(fn_loop);
}

fn_result_t fn_loop_create(const fn_loop_options_t *options, fn_loop_t **out)
{
  fn_loop_t *loop;
  fn_result_t result;
  int mutex_result;
  if (out == NULL) {
    return loop_result(FN_INVALID);
  }
  *out = NULL;
  if (options == NULL || options->limits == NULL ||
      options->owned_memory == NULL || options->file_descriptors == NULL ||
      options->allocator.allocate == NULL ||
      options->allocator.deallocate == NULL) {
    return loop_result(FN_INVALID);
  }
  result = fn_budget_reserve(options->owned_memory, FN_BUDGET_ACTIVE,
                             sizeof(*loop));
  if (result.code != FN_OK) {
    return result;
  }
  loop = options->allocator.allocate(options->allocator.context,
                                     sizeof(*loop));
  if (loop == NULL) {
    (void)fn_budget_release(options->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*loop));
    return loop_result(FN_NO_MEMORY);
  }
  memset(loop, 0, sizeof(*loop));
  loop->allocator = options->allocator;
  loop->owned_memory = options->owned_memory;
  loop->file_descriptors = options->file_descriptors;
  loop->terminal_limit = options->limits->completion_entry_limit;
  loop->post_limit = options->limits->loop_post_entry_limit;
  loop->dispatch_limit = options->dispatch_limit == 0 ? (size_t)64u :
                                                        options->dispatch_limit;
  loop->owner = pthread_self();
  (void)fn_budget_init(&loop->terminal_bytes,
                       options->limits->completion_limit_bytes,
                       options->limits->completion_limit_bytes);
  (void)fn_budget_init(&loop->post_bytes,
                       options->limits->loop_post_limit_bytes, 0);
  (void)fn_budget_init(&loop->timer_entries,
                       options->limits->timer_limit, 0);

  mutex_result = pthread_mutex_init(&loop->queue_mutex, NULL);
  if (mutex_result != 0) {
    loop->allocator.deallocate(loop->allocator.context, loop);
    (void)fn_budget_release(options->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*loop));
    return loop_posix_result(mutex_result);
  }
  result = fn_budget_reserve(loop->file_descriptors, FN_BUDGET_ACTIVE,
                             FN_LOOP_INTERNAL_FD_RESERVATION);
  if (result.code != FN_OK) {
    (void)pthread_mutex_destroy(&loop->queue_mutex);
    loop->allocator.deallocate(loop->allocator.context, loop);
    (void)fn_budget_release(options->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*loop));
    return result;
  }
  loop->native_loop = ev_loop_new(EVFLAG_NOENV);
  if (loop->native_loop == NULL) {
    (void)fn_budget_release(loop->file_descriptors, FN_BUDGET_ACTIVE,
                            FN_LOOP_INTERNAL_FD_RESERVATION);
    (void)pthread_mutex_destroy(&loop->queue_mutex);
    loop->allocator.deallocate(loop->allocator.context, loop);
    (void)fn_budget_release(options->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*loop));
    return loop_result(FN_NO_MEMORY);
  }
  ev_async_init(&loop->wake, wake_callback);
  loop->wake.data = loop;
  ev_async_start(loop->native_loop, &loop->wake);
  *out = loop;
  return loop_result(FN_OK);
}

fn_result_t fn_loop_destroy(fn_loop_t **loop_pointer)
{
  fn_loop_t *loop;
  bool queue_busy;
  if (loop_pointer == NULL) {
    return loop_result(FN_INVALID);
  }
  loop = *loop_pointer;
  if (loop == NULL) {
    return loop_result(FN_OK);
  }
  if (!fn_loop_is_owner(loop) || loop->dispatch_depth != 0) {
    return loop_result(FN_INVALID);
  }
  (void)pthread_mutex_lock(&loop->queue_mutex);
  queue_busy = loop->terminal_live != 0 || loop->post_live != 0;
  (void)pthread_mutex_unlock(&loop->queue_mutex);
  if (queue_busy || loop->timers != 0 || loop->io_watchers != 0) {
    return loop_result(FN_INVALID);
  }
  ev_async_stop(loop->native_loop, &loop->wake);
  ev_loop_destroy(loop->native_loop);
  (void)pthread_mutex_destroy(&loop->queue_mutex);
  (void)fn_budget_release(loop->file_descriptors, FN_BUDGET_ACTIVE,
                          FN_LOOP_INTERNAL_FD_RESERVATION);
  (void)fn_budget_release(loop->owned_memory, FN_BUDGET_ACTIVE,
                          sizeof(*loop));
  loop->allocator.deallocate(loop->allocator.context, loop);
  *loop_pointer = NULL;
  return loop_result(FN_OK);
}

fn_result_t fn_loop_run_once(fn_loop_t *loop, fn_loop_run_mode_t mode)
{
  int flags;
  if (!fn_loop_is_owner(loop) || loop->dispatch_depth != 0 ||
      (mode != FN_LOOP_RUN_NOWAIT && mode != FN_LOOP_RUN_ONCE)) {
    return loop_result(FN_INVALID);
  }
  flags = mode == FN_LOOP_RUN_NOWAIT ? EVRUN_NOWAIT : EVRUN_ONCE;
  counter_increment(&loop->run_iterations);
  (void)ev_run(loop->native_loop, flags);
  return loop_result(FN_OK);
}

fn_result_t fn_loop_break(fn_loop_t *loop)
{
  if (!fn_loop_is_owner(loop)) {
    return loop_result(FN_INVALID);
  }
  ev_break(loop->native_loop, EVBREAK_ALL);
  return loop_result(FN_OK);
}

fn_result_t fn_loop_snapshot(fn_loop_t *loop, fn_loop_snapshot_t *out)
{
  if (loop == NULL || out == NULL || !fn_loop_is_owner(loop)) {
    return loop_result(FN_INVALID);
  }
  memset(out, 0, sizeof(*out));
  (void)pthread_mutex_lock(&loop->queue_mutex);
  out->terminal_live = loop->terminal_live;
  out->terminal_queued = loop->terminal_queued;
  out->post_live = loop->post_live;
  out->post_queued = loop->post_queued;
  (void)pthread_mutex_unlock(&loop->queue_mutex);
  out->timers = loop->timers;
  out->active_timers = loop->active_timers;
  out->io_watchers = loop->io_watchers;
  out->active_io_watchers = loop->active_io_watchers;
  out->internal_fd_reservation = FN_LOOP_INTERNAL_FD_RESERVATION;
  out->run_iterations = loop->run_iterations;
  out->terminal_callbacks = loop->terminal_callbacks;
  out->post_callbacks = loop->post_callbacks;
  out->timer_callbacks = loop->timer_callbacks;
  out->io_callbacks = loop->io_callbacks;
  return loop_result(FN_OK);
}

fn_result_t fn_completion_reserve_terminal(fn_loop_t *loop,
                                           fn_completion_ticket_t **out)
{
  fn_completion_ticket_t *ticket;
  fn_result_t result;
  if (out == NULL) {
    return loop_result(FN_INVALID);
  }
  *out = NULL;
  if (!fn_loop_is_owner(loop)) {
    return loop_result(FN_INVALID);
  }
  (void)pthread_mutex_lock(&loop->queue_mutex);
  if (loop->terminal_live >= loop->terminal_limit) {
    (void)pthread_mutex_unlock(&loop->queue_mutex);
    return loop_result(FN_LIMIT);
  }
  (void)pthread_mutex_unlock(&loop->queue_mutex);
  result = fn_budget_reserve_pair(loop->owned_memory, sizeof(*ticket),
                                  &loop->terminal_bytes, sizeof(*ticket),
                                  FN_BUDGET_CLEANUP);
  if (result.code != FN_OK) {
    return result;
  }
  ticket = loop->allocator.allocate(loop->allocator.context,
                                    sizeof(*ticket));
  if (ticket == NULL) {
    (void)fn_budget_release_pair(loop->owned_memory, sizeof(*ticket),
                                 &loop->terminal_bytes, sizeof(*ticket),
                                 FN_BUDGET_CLEANUP);
    return loop_result(FN_NO_MEMORY);
  }
  memset(ticket, 0, sizeof(*ticket));
  ticket->loop = loop;
  ticket->kind = FN_QUEUE_TERMINAL;
  ticket->state = FN_TICKET_RESERVED;
  (void)pthread_mutex_lock(&loop->queue_mutex);
  loop->terminal_live++;
  (void)pthread_mutex_unlock(&loop->queue_mutex);
  *out = ticket;
  return loop_result(FN_OK);
}

fn_result_t fn_completion_publish(fn_completion_ticket_t **ticket_pointer,
                                  fn_result_t result,
                                  fn_completion_callback_fn callback,
                                  void *context)
{
  fn_completion_ticket_t *ticket;
  fn_loop_t *loop;
  if (ticket_pointer == NULL || *ticket_pointer == NULL || callback == NULL) {
    return loop_result(FN_INVALID);
  }
  ticket = *ticket_pointer;
  loop = ticket->loop;
  (void)pthread_mutex_lock(&loop->queue_mutex);
  if (ticket->kind != FN_QUEUE_TERMINAL ||
      ticket->state != FN_TICKET_RESERVED) {
    (void)pthread_mutex_unlock(&loop->queue_mutex);
    return loop_result(FN_INVALID);
  }
  ticket->result = result;
  ticket->completion_callback = callback;
  ticket->context = context;
  ticket->state = FN_TICKET_QUEUED;
  queue_append(&loop->terminal_head, &loop->terminal_tail, ticket);
  loop->terminal_queued++;
  (void)pthread_mutex_unlock(&loop->queue_mutex);
  *ticket_pointer = NULL;
  ev_async_send(loop->native_loop, &loop->wake);
  return loop_result(FN_OK);
}

fn_result_t fn_completion_abandon(fn_completion_ticket_t **ticket_pointer)
{
  fn_completion_ticket_t *ticket;
  fn_loop_t *loop;
  if (ticket_pointer == NULL) {
    return loop_result(FN_INVALID);
  }
  ticket = *ticket_pointer;
  if (ticket == NULL) {
    return loop_result(FN_OK);
  }
  loop = ticket->loop;
  if (!fn_loop_is_owner(loop) || ticket->kind != FN_QUEUE_TERMINAL ||
      ticket->state != FN_TICKET_RESERVED) {
    return loop_result(FN_INVALID);
  }
  (void)pthread_mutex_lock(&loop->queue_mutex);
  loop->terminal_live--;
  (void)pthread_mutex_unlock(&loop->queue_mutex);
  loop->allocator.deallocate(loop->allocator.context, ticket);
  (void)fn_budget_release_pair(loop->owned_memory, sizeof(*ticket),
                               &loop->terminal_bytes, sizeof(*ticket),
                               FN_BUDGET_CLEANUP);
  *ticket_pointer = NULL;
  return loop_result(FN_OK);
}

fn_result_t fn_loop_post(fn_loop_t *loop, fn_loop_post_callback_fn callback,
                         void *context)
{
  fn_completion_ticket_t *node;
  fn_result_t result;
  if (!fn_loop_is_owner(loop) || callback == NULL) {
    return loop_result(FN_INVALID);
  }
  (void)pthread_mutex_lock(&loop->queue_mutex);
  if (loop->post_live >= loop->post_limit) {
    (void)pthread_mutex_unlock(&loop->queue_mutex);
    return loop_result(FN_LIMIT);
  }
  (void)pthread_mutex_unlock(&loop->queue_mutex);
  result = fn_budget_reserve_pair(loop->owned_memory, sizeof(*node),
                                  &loop->post_bytes, sizeof(*node),
                                  FN_BUDGET_ACTIVE);
  if (result.code != FN_OK) {
    return result;
  }
  node = loop->allocator.allocate(loop->allocator.context, sizeof(*node));
  if (node == NULL) {
    (void)fn_budget_release_pair(loop->owned_memory, sizeof(*node),
                                 &loop->post_bytes, sizeof(*node),
                                 FN_BUDGET_ACTIVE);
    return loop_result(FN_NO_MEMORY);
  }
  memset(node, 0, sizeof(*node));
  node->loop = loop;
  node->kind = FN_QUEUE_POST;
  node->state = FN_TICKET_QUEUED;
  node->post_callback = callback;
  node->context = context;
  (void)pthread_mutex_lock(&loop->queue_mutex);
  queue_append(&loop->post_head, &loop->post_tail, node);
  loop->post_live++;
  loop->post_queued++;
  (void)pthread_mutex_unlock(&loop->queue_mutex);
  ev_async_send(loop->native_loop, &loop->wake);
  return loop_result(FN_OK);
}

static void timer_callback(EV_P_ ev_timer *watcher, int revents)
{
  fn_timer_t *timer = watcher->data;
  fn_loop_t *fn_loop = timer->loop;
  fn_timer_callback_fn callback = timer->callback;
  void *context = timer->context;
  (void)EV_A;
  (void)revents;
  if (timer->active) {
    timer->active = false;
    fn_loop->active_timers--;
  }
  counter_increment(&fn_loop->timer_callbacks);
  fn_loop->dispatch_depth++;
  callback(timer, context);
  fn_loop->dispatch_depth--;
}

fn_result_t fn_timer_start(fn_loop_t *loop, uint64_t deadline_ms,
                           fn_timer_callback_fn callback, void *context,
                           fn_timer_t **out)
{
  fn_timer_t *timer;
  fn_result_t result;
  uint64_t now_ms;
  uint64_t remaining_ms;
  if (out == NULL) {
    return loop_result(FN_INVALID);
  }
  *out = NULL;
  if (!fn_loop_is_owner(loop) || callback == NULL) {
    return loop_result(FN_INVALID);
  }
  result = fn_monotonic_now_ms(&now_ms);
  if (result.code != FN_OK) {
    return result;
  }
  remaining_ms = fn_deadline_remaining_ms(now_ms, deadline_ms);
  result = fn_budget_reserve_pair(loop->owned_memory, sizeof(*timer),
                                  &loop->timer_entries, 1u,
                                  FN_BUDGET_ACTIVE);
  if (result.code != FN_OK) {
    return result;
  }
  timer = loop->allocator.allocate(loop->allocator.context, sizeof(*timer));
  if (timer == NULL) {
    (void)fn_budget_release_pair(loop->owned_memory, sizeof(*timer),
                                 &loop->timer_entries, 1u,
                                 FN_BUDGET_ACTIVE);
    return loop_result(FN_NO_MEMORY);
  }
  memset(timer, 0, sizeof(*timer));
  timer->loop = loop;
  timer->callback = callback;
  timer->context = context;
  timer->active = true;
  ev_timer_init(&timer->watcher, timer_callback,
                (double)remaining_ms / 1000.0, 0.0);
  timer->watcher.data = timer;
  ev_timer_start(loop->native_loop, &timer->watcher);
  loop->timers++;
  loop->active_timers++;
  *out = timer;
  return loop_result(FN_OK);
}

fn_result_t fn_timer_cancel(fn_timer_t *timer)
{
  fn_loop_t *loop;
  if (timer == NULL) {
    return loop_result(FN_OK);
  }
  loop = timer->loop;
  if (!fn_loop_is_owner(loop)) {
    return loop_result(FN_INVALID);
  }
  if (timer->active) {
    ev_timer_stop(loop->native_loop, &timer->watcher);
    timer->active = false;
    loop->active_timers--;
  }
  return loop_result(FN_OK);
}

fn_result_t fn_timer_destroy(fn_timer_t **timer_pointer)
{
  fn_timer_t *timer;
  fn_loop_t *loop;
  fn_result_t result;
  if (timer_pointer == NULL) {
    return loop_result(FN_INVALID);
  }
  timer = *timer_pointer;
  if (timer == NULL) {
    return loop_result(FN_OK);
  }
  loop = timer->loop;
  result = fn_timer_cancel(timer);
  if (result.code != FN_OK) {
    return result;
  }
  loop->timers--;
  loop->allocator.deallocate(loop->allocator.context, timer);
  (void)fn_budget_release_pair(loop->owned_memory, sizeof(*timer),
                               &loop->timer_entries, 1u,
                               FN_BUDGET_ACTIVE);
  *timer_pointer = NULL;
  return loop_result(FN_OK);
}

static void io_callback(EV_P_ ev_io *native_watcher, int revents)
{
  fn_io_watcher_t *watcher = native_watcher->data;
  fn_loop_t *fn_loop = watcher->loop;
  fn_io_watcher_callback_fn callback = watcher->callback;
  void *context = watcher->context;
  uint32_t events = 0;
  (void)EV_A;
  if ((revents & EV_READ) != 0) {
    events |= FN_IO_EVENT_READ;
  }
  if ((revents & EV_WRITE) != 0) {
    events |= FN_IO_EVENT_WRITE;
  }
  if ((revents & EV_ERROR) != 0) {
    events |= FN_IO_EVENT_ERROR;
  }
  counter_increment(&fn_loop->io_callbacks);
  fn_loop->dispatch_depth++;
  callback(watcher, events, context);
  fn_loop->dispatch_depth--;
}

fn_result_t fn_io_watcher_create(fn_loop_t *loop, fn_socket_t socket,
                                 fn_io_watcher_callback_fn callback,
                                 void *context, fn_io_watcher_t **out)
{
  fn_io_watcher_t *watcher;
  fn_result_t result;
  if (out == NULL) {
    return loop_result(FN_INVALID);
  }
  *out = NULL;
  if (!fn_loop_is_owner(loop) || !fn_socket_is_valid(socket) ||
      callback == NULL) {
    return loop_result(FN_INVALID);
  }
  result = fn_budget_reserve(loop->owned_memory, FN_BUDGET_ACTIVE,
                             sizeof(*watcher));
  if (result.code != FN_OK) {
    return result;
  }
  watcher = loop->allocator.allocate(loop->allocator.context,
                                     sizeof(*watcher));
  if (watcher == NULL) {
    (void)fn_budget_release(loop->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*watcher));
    return loop_result(FN_NO_MEMORY);
  }
  memset(watcher, 0, sizeof(*watcher));
  watcher->loop = loop;
  watcher->socket = socket;
  watcher->callback = callback;
  watcher->context = context;
  ev_io_init(&watcher->watcher, io_callback, (int)socket.value, EV_READ);
  watcher->watcher.data = watcher;
  loop->io_watchers++;
  *out = watcher;
  return loop_result(FN_OK);
}

fn_result_t fn_io_watcher_set(fn_io_watcher_t *watcher, uint32_t interests)
{
  fn_loop_t *loop;
  int native_events = 0;
  if (watcher == NULL) {
    return loop_result(FN_INVALID);
  }
  loop = watcher->loop;
  if (!fn_loop_is_owner(loop) ||
      (interests & ~(FN_IO_EVENT_READ | FN_IO_EVENT_WRITE)) != 0) {
    return loop_result(FN_INVALID);
  }
  if (interests == 0) {
    return fn_io_watcher_stop(watcher);
  }
  if (watcher->active && watcher->interests == interests) {
    return loop_result(FN_OK);
  }
  if (watcher->active) {
    ev_io_stop(loop->native_loop, &watcher->watcher);
    watcher->active = false;
    loop->active_io_watchers--;
  }
  if ((interests & FN_IO_EVENT_READ) != 0) {
    native_events |= EV_READ;
  }
  if ((interests & FN_IO_EVENT_WRITE) != 0) {
    native_events |= EV_WRITE;
  }
  ev_io_set(&watcher->watcher, (int)watcher->socket.value, native_events);
  ev_io_start(loop->native_loop, &watcher->watcher);
  watcher->interests = interests;
  watcher->active = true;
  loop->active_io_watchers++;
  return loop_result(FN_OK);
}

fn_result_t fn_io_watcher_stop(fn_io_watcher_t *watcher)
{
  fn_loop_t *loop;
  if (watcher == NULL) {
    return loop_result(FN_OK);
  }
  loop = watcher->loop;
  if (!fn_loop_is_owner(loop)) {
    return loop_result(FN_INVALID);
  }
  if (watcher->active) {
    ev_io_stop(loop->native_loop, &watcher->watcher);
    watcher->active = false;
    watcher->interests = 0;
    loop->active_io_watchers--;
  }
  return loop_result(FN_OK);
}

fn_result_t fn_io_watcher_destroy(fn_io_watcher_t **watcher_pointer)
{
  fn_io_watcher_t *watcher;
  fn_loop_t *loop;
  fn_result_t result;
  if (watcher_pointer == NULL) {
    return loop_result(FN_INVALID);
  }
  watcher = *watcher_pointer;
  if (watcher == NULL) {
    return loop_result(FN_OK);
  }
  loop = watcher->loop;
  result = fn_io_watcher_stop(watcher);
  if (result.code != FN_OK) {
    return result;
  }
  loop->io_watchers--;
  loop->allocator.deallocate(loop->allocator.context, watcher);
  (void)fn_budget_release(loop->owned_memory, FN_BUDGET_ACTIVE,
                          sizeof(*watcher));
  *watcher_pointer = NULL;
  return loop_result(FN_OK);
}
