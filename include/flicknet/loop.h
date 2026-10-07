#ifndef FLICKNET_LOOP_H
#define FLICKNET_LOOP_H

#include "flicknet/platform.h"
#include "flicknet/pool.h"
#include "flicknet/resource.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct fn_loop fn_loop_t;
typedef struct fn_completion_ticket fn_completion_ticket_t;
typedef struct fn_timer fn_timer_t;
typedef struct fn_io_watcher fn_io_watcher_t;

typedef void (*fn_completion_callback_fn)(void *context, fn_result_t result);
typedef void (*fn_loop_post_callback_fn)(void *context);
typedef void (*fn_timer_callback_fn)(fn_timer_t *timer, void *context);
typedef void (*fn_io_watcher_callback_fn)(fn_io_watcher_t *watcher,
                                          uint32_t events, void *context);

typedef enum {
  FN_LOOP_RUN_NOWAIT = 0,
  FN_LOOP_RUN_ONCE
} fn_loop_run_mode_t;

#define FN_IO_EVENT_READ  (UINT32_C(1) << 0)
#define FN_IO_EVENT_WRITE (UINT32_C(1) << 1)
#define FN_IO_EVENT_ERROR (UINT32_C(1) << 2)

typedef struct {
  const fn_limits_t *limits;
  fn_budget_t *owned_memory;
  fn_budget_t *file_descriptors;
  fn_allocator_t allocator;
  size_t dispatch_limit;
} fn_loop_options_t;

typedef struct {
  size_t terminal_live;
  size_t terminal_queued;
  size_t post_live;
  size_t post_queued;
  size_t timers;
  size_t active_timers;
  size_t io_watchers;
  size_t active_io_watchers;
  size_t internal_fd_reservation;
  uint64_t run_iterations;
  uint64_t terminal_callbacks;
  uint64_t post_callbacks;
  uint64_t timer_callbacks;
  uint64_t io_callbacks;
} fn_loop_snapshot_t;

/* fn_loop_create 固定创建线程为 owner，并保守预留 libev 内部 fd 上界。 */
fn_result_t fn_loop_create(const fn_loop_options_t *options, fn_loop_t **out);
fn_result_t fn_loop_destroy(fn_loop_t **loop);
bool fn_loop_is_owner(const fn_loop_t *loop);
fn_result_t fn_loop_run_once(fn_loop_t *loop, fn_loop_run_mode_t mode);
fn_result_t fn_loop_break(fn_loop_t *loop);
fn_result_t fn_loop_snapshot(fn_loop_t *loop, fn_loop_snapshot_t *out);

/* fn_completion_reserve_terminal 必须在异步操作对外接纳前调用。 */
fn_result_t fn_completion_reserve_terminal(fn_loop_t *loop,
                                           fn_completion_ticket_t **out);
/* fn_completion_publish 可由 worker 调用；成功消费 ticket 并唤醒 owner。 */
fn_result_t fn_completion_publish(fn_completion_ticket_t **ticket,
                                  fn_result_t result,
                                  fn_completion_callback_fn callback,
                                  void *context);
/* fn_completion_abandon 只用于尚未对外接纳时的回滚。 */
fn_result_t fn_completion_abandon(fn_completion_ticket_t **ticket);

/* fn_loop_post 是 owner-only 普通通知，不能占用 terminal reservation。 */
fn_result_t fn_loop_post(fn_loop_t *loop, fn_loop_post_callback_fn callback,
                         void *context);

/* fn_timer_start 建立单次绝对单调 deadline timer，所有操作均 owner-only。 */
fn_result_t fn_timer_start(fn_loop_t *loop, uint64_t deadline_ms,
                           fn_timer_callback_fn callback, void *context,
                           fn_timer_t **out);
fn_result_t fn_timer_cancel(fn_timer_t *timer);
fn_result_t fn_timer_destroy(fn_timer_t **timer);

/* fn_io_watcher_create 借用 socket；destroy 不关闭底层句柄。 */
fn_result_t fn_io_watcher_create(fn_loop_t *loop, fn_socket_t socket,
                                 fn_io_watcher_callback_fn callback,
                                 void *context, fn_io_watcher_t **out);
fn_result_t fn_io_watcher_set(fn_io_watcher_t *watcher, uint32_t interests);
fn_result_t fn_io_watcher_stop(fn_io_watcher_t *watcher);
fn_result_t fn_io_watcher_destroy(fn_io_watcher_t **watcher);

#endif
