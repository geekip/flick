#ifndef FLICKNET_STREAM_H
#define FLICKNET_STREAM_H

#include "flicknet/loop.h"
#include "flicknet/platform.h"
#include "flicknet/pool.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct fn_stream fn_stream_t;
typedef struct fn_relay_buffer_pool fn_relay_buffer_pool_t;
typedef struct fn_relay fn_relay_t;

typedef void (*fn_stream_ready_fn)(fn_stream_t *stream, uint32_t events,
                                   void *context);

typedef struct {
  fn_loop_t *loop;
  fn_budget_t *owned_memory;
  fn_budget_t *file_descriptors;
  fn_allocator_t allocator;
  bool owns_file_descriptor_reservation;
} fn_stream_options_t;

typedef struct {
  uint32_t interests;
  size_t references;
  size_t buffered_read_bytes;
  bool write_shutdown;
  bool aborted;
  bool owns_file_descriptor_reservation;
} fn_stream_snapshot_t;

/* fn_stream_socket_create 成功时取得 socket 所有权并使调用者句柄失效。 */
fn_result_t fn_stream_socket_create(const fn_stream_options_t *options,
                                    fn_socket_t *socket, fn_stream_t **out);
fn_result_t fn_stream_retain(fn_stream_t *stream);
fn_result_t fn_stream_release(fn_stream_t **stream);
fn_io_result_t fn_stream_read(fn_stream_t *stream, void *buffer,
                              size_t length);
fn_io_result_t fn_stream_write(fn_stream_t *stream, const void *buffer,
                               size_t length);
/* fn_stream_adopt_read_buffer 接管已完成双预算计账的前置读缓冲。 */
fn_result_t fn_stream_adopt_read_buffer(
  fn_stream_t *stream, uint8_t **owned_buffer, size_t length,
  size_t capacity, fn_budget_t *owned_memory, fn_budget_t *buffer_bytes,
  fn_allocator_t allocator);
/* events=0 会解除 callback；其余值只允许 READ/WRITE。 */
fn_result_t fn_stream_watch(fn_stream_t *stream, uint32_t events,
                            fn_stream_ready_fn callback, void *context);
fn_result_t fn_stream_shutdown_write(fn_stream_t *stream);
fn_result_t fn_stream_abort(fn_stream_t *stream);
fn_result_t fn_stream_snapshot(const fn_stream_t *stream,
                               fn_stream_snapshot_t *out);

typedef struct {
  fn_loop_t *loop;
  const fn_limits_t *limits;
  fn_budget_t *owned_memory;
  fn_budget_t *buffer_bytes;
  fn_allocator_t allocator;
  size_t block_size;
  size_t block_capacity;
  size_t block_cache_limit;
} fn_relay_buffer_pool_options_t;

typedef struct {
  fn_pool_snapshot_t blocks;
  size_t active_relays;
  size_t resource_waiters;
  size_t resource_waiter_bytes;
} fn_relay_buffer_pool_snapshot_t;

fn_result_t fn_relay_buffer_pool_create(
  const fn_relay_buffer_pool_options_t *options,
  fn_relay_buffer_pool_t **out);
fn_result_t fn_relay_buffer_pool_destroy(fn_relay_buffer_pool_t **pool);
fn_result_t fn_relay_buffer_pool_snapshot(
  const fn_relay_buffer_pool_t *pool, fn_relay_buffer_pool_snapshot_t *out);

typedef struct {
  size_t high_watermark;
  size_t low_watermark;
  size_t callback_byte_limit;
  size_t callback_io_limit;
} fn_relay_options_t;

typedef struct {
  size_t left_to_right_queued;
  size_t right_to_left_queued;
  uint64_t bytes_left_to_right;
  uint64_t bytes_right_to_left;
  size_t max_callback_bytes;
  size_t max_callback_io;
  bool left_read_eof;
  bool right_read_eof;
  bool left_write_shutdown;
  bool right_write_shutdown;
  bool left_read_paused;
  bool right_read_paused;
  bool terminal_queued;
} fn_relay_snapshot_t;

typedef void (*fn_relay_callback_fn)(fn_relay_t *relay, void *context,
                                     fn_result_t result);

fn_relay_options_t fn_relay_options_default(void);
/* fn_relay_start 借用 pool，并各持有一份 left/right Stream 引用。 */
fn_result_t fn_relay_start(fn_relay_buffer_pool_t *pool,
                           fn_stream_t *left, fn_stream_t *right,
                           const fn_relay_options_t *options,
                           fn_relay_callback_fn callback, void *context,
                           fn_relay_t **out);
/* fn_relay_begin_drain 只设置绝对排空期限，不重置已有期限。 */
fn_result_t fn_relay_begin_drain(fn_relay_t *relay, uint64_t deadline_ms);
fn_result_t fn_relay_cancel(fn_relay_t *relay);
fn_result_t fn_relay_release(fn_relay_t **relay);
fn_result_t fn_relay_snapshot(const fn_relay_t *relay,
                              fn_relay_snapshot_t *out);

#endif
