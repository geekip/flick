#include "flicknet/stream.h"

#include "flicknet/clock.h"

#include <stddef.h>
#include <string.h>

typedef struct fn_relay_buffer fn_relay_buffer_t;
typedef struct fn_relay_direction fn_relay_direction_t;

struct fn_stream {
  fn_loop_t *loop;
  fn_budget_t *owned_memory;
  fn_budget_t *file_descriptors;
  fn_allocator_t allocator;
  fn_io_watcher_t *watcher;
  fn_socket_t socket;
  fn_stream_ready_fn callback;
  void *callback_context;
  fn_budget_t *buffer_bytes;
  uint8_t *buffered_read;
  size_t buffered_read_offset;
  size_t buffered_read_length;
  size_t buffered_read_capacity;
  size_t references;
  uint32_t interests;
  bool write_shutdown;
  bool aborted;
  bool owns_file_descriptor_reservation;
};

struct fn_relay_buffer {
  fn_relay_buffer_t *next;
  size_t begin;
  size_t end;
};

struct fn_relay_direction {
  fn_relay_t *relay;
  fn_stream_t *source;
  fn_stream_t *destination;
  fn_relay_buffer_t *head;
  fn_relay_buffer_t *tail;
  fn_relay_direction_t *wait_next;
  fn_timer_t *wait_timer;
  size_t queued;
  uint64_t bytes_delivered;
  bool source_eof;
  bool write_shutdown;
  bool paused_high;
  bool waiting_resource;
};

struct fn_relay_buffer_pool {
  fn_loop_t *loop;
  fn_budget_t *owned_memory;
  fn_allocator_t allocator;
  fn_limits_t limits;
  fn_pool_t blocks;
  fn_budget_t waiter_bytes;
  fn_relay_direction_t *wait_head;
  fn_relay_direction_t *wait_tail;
  size_t waiter_count;
  size_t active_relays;
  size_t accounted_bytes;
};

struct fn_relay {
  fn_relay_buffer_pool_t *pool;
  fn_stream_t *left;
  fn_stream_t *right;
  fn_completion_ticket_t *ticket;
  fn_timer_t *drain_timer;
  fn_relay_callback_fn callback;
  void *callback_context;
  fn_relay_options_t options;
  fn_relay_direction_t directions[2];
  fn_result_t terminal_result;
  uint64_t drain_deadline_ms;
  size_t max_callback_bytes;
  size_t max_callback_io;
  bool terminal_queued;
  bool callback_started;
};

typedef struct {
  size_t bytes;
  size_t calls;
} fn_relay_callback_budget_t;

static fn_result_t stream_result(fn_status_t code)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE : FN_STAGE_RELAY,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static fn_result_t resource_timeout_result(void)
{
  return fn_result_make(FN_TIMEOUT, FN_STAGE_RESOURCE,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static fn_io_result_t stream_io_result(fn_status_t code)
{
  const fn_io_result_t result = {
    .result = stream_result(code),
    .transferred = 0,
  };
  return result;
}

static bool stream_is_owner(const fn_stream_t *stream)
{
  return stream != NULL && fn_loop_is_owner(stream->loop);
}

static void stream_release_buffered_read(fn_stream_t *stream)
{
  if (stream->buffered_read == NULL) {
    return;
  }
  stream->allocator.deallocate(stream->allocator.context,
                               stream->buffered_read);
  (void)fn_budget_release_pair(stream->owned_memory,
                               stream->buffered_read_capacity,
                               stream->buffer_bytes,
                               stream->buffered_read_capacity,
                               FN_BUDGET_ACTIVE);
  stream->buffer_bytes = NULL;
  stream->buffered_read = NULL;
  stream->buffered_read_offset = 0;
  stream->buffered_read_length = 0;
  stream->buffered_read_capacity = 0;
}

static bool relay_is_owner(const fn_relay_t *relay)
{
  return relay != NULL && relay->pool != NULL &&
         fn_loop_is_owner(relay->pool->loop);
}

static void stream_io_ready(fn_io_watcher_t *watcher, uint32_t events,
                            void *context)
{
  fn_stream_t *stream = context;
  fn_stream_ready_fn callback = stream->callback;
  void *callback_context = stream->callback_context;
  (void)watcher;
  if (!stream->aborted && callback != NULL &&
      (events & (stream->interests | FN_IO_EVENT_ERROR)) != 0) {
    callback(stream, events, callback_context);
  }
}

fn_result_t fn_stream_socket_create(const fn_stream_options_t *options,
                                    fn_socket_t *socket, fn_stream_t **out)
{
  fn_stream_t *stream;
  fn_result_t result;

  if (out == NULL) {
    return stream_result(FN_INVALID);
  }
  *out = NULL;
  if (options == NULL || options->loop == NULL ||
      options->owned_memory == NULL ||
      options->allocator.allocate == NULL ||
      options->allocator.deallocate == NULL || socket == NULL ||
      !fn_socket_is_valid(*socket) || !fn_loop_is_owner(options->loop) ||
      (options->owns_file_descriptor_reservation &&
       options->file_descriptors == NULL)) {
    return stream_result(FN_INVALID);
  }
  result = fn_budget_reserve(options->owned_memory, FN_BUDGET_ACTIVE,
                             sizeof(*stream));
  if (result.code != FN_OK) {
    return result;
  }
  stream = options->allocator.allocate(options->allocator.context,
                                       sizeof(*stream));
  if (stream == NULL) {
    (void)fn_budget_release(options->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*stream));
    return stream_result(FN_NO_MEMORY);
  }
  memset(stream, 0, sizeof(*stream));
  stream->loop = options->loop;
  stream->owned_memory = options->owned_memory;
  stream->file_descriptors = options->file_descriptors;
  stream->allocator = options->allocator;
  stream->socket = *socket;
  stream->references = 1u;
  stream->owns_file_descriptor_reservation =
    options->owns_file_descriptor_reservation;
  result = fn_io_watcher_create(options->loop, stream->socket,
                                stream_io_ready, stream, &stream->watcher);
  if (result.code != FN_OK) {
    options->allocator.deallocate(options->allocator.context, stream);
    (void)fn_budget_release(options->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*stream));
    return result;
  }
  *socket = fn_socket_invalid();
  *out = stream;
  return stream_result(FN_OK);
}

fn_result_t fn_stream_retain(fn_stream_t *stream)
{
  if (!stream_is_owner(stream) || stream->references == SIZE_MAX ||
      stream->references == 0) {
    return stream_result(FN_INVALID);
  }
  stream->references++;
  return stream_result(FN_OK);
}

fn_io_result_t fn_stream_read(fn_stream_t *stream, void *buffer,
                              size_t length)
{
  size_t remaining;
  size_t transferred;
  if (!stream_is_owner(stream) || stream->aborted || buffer == NULL ||
      length == 0) {
    return stream_io_result(FN_INVALID);
  }
  remaining = stream->buffered_read_length - stream->buffered_read_offset;
  if (remaining != 0) {
    fn_io_result_t result = stream_io_result(FN_OK);
    transferred = length < remaining ? length : remaining;
    memcpy(buffer, stream->buffered_read + stream->buffered_read_offset,
           transferred);
    stream->buffered_read_offset += transferred;
    result.transferred = transferred;
    if (stream->buffered_read_offset == stream->buffered_read_length) {
      stream_release_buffered_read(stream);
    }
    return result;
  }
  return fn_socket_read(stream->socket, buffer, length, FN_STAGE_RELAY);
}

fn_io_result_t fn_stream_write(fn_stream_t *stream, const void *buffer,
                               size_t length)
{
  if (!stream_is_owner(stream) || stream->aborted ||
      stream->write_shutdown || buffer == NULL || length == 0) {
    return stream_io_result(FN_INVALID);
  }
  return fn_socket_write(stream->socket, buffer, length, FN_STAGE_RELAY);
}

fn_result_t fn_stream_adopt_read_buffer(
  fn_stream_t *stream, uint8_t **owned_buffer, size_t length,
  size_t capacity, fn_budget_t *owned_memory, fn_budget_t *buffer_bytes,
  fn_allocator_t allocator)
{
  if (!stream_is_owner(stream) || stream->aborted || owned_buffer == NULL ||
      *owned_buffer == NULL || length == 0 || length > capacity ||
      stream->buffered_read != NULL || owned_memory != stream->owned_memory ||
      buffer_bytes == NULL || allocator.allocate != stream->allocator.allocate ||
      allocator.deallocate != stream->allocator.deallocate ||
      allocator.context != stream->allocator.context) {
    return stream_result(FN_INVALID);
  }
  stream->buffered_read = *owned_buffer;
  stream->buffered_read_length = length;
  stream->buffered_read_capacity = capacity;
  stream->buffer_bytes = buffer_bytes;
  *owned_buffer = NULL;
  return stream_result(FN_OK);
}

fn_result_t fn_stream_watch(fn_stream_t *stream, uint32_t events,
                            fn_stream_ready_fn callback, void *context)
{
  fn_result_t result;
  const uint32_t allowed = FN_IO_EVENT_READ | FN_IO_EVENT_WRITE;
  if (!stream_is_owner(stream) || stream->aborted ||
      (events & ~allowed) != 0 ||
      ((events == 0) != (callback == NULL))) {
    return stream_result(FN_INVALID);
  }
  result = fn_io_watcher_set(stream->watcher, events);
  if (result.code != FN_OK) {
    return result;
  }
  stream->interests = events;
  stream->callback = callback;
  stream->callback_context = context;
  return stream_result(FN_OK);
}

fn_result_t fn_stream_shutdown_write(fn_stream_t *stream)
{
  fn_result_t result;
  if (!stream_is_owner(stream) || stream->aborted) {
    return stream_result(FN_INVALID);
  }
  if (stream->write_shutdown) {
    return stream_result(FN_OK);
  }
  result = fn_socket_shutdown_write(stream->socket, FN_STAGE_RELAY);
  if (result.code == FN_OK) {
    stream->write_shutdown = true;
  }
  return result;
}

fn_result_t fn_stream_abort(fn_stream_t *stream)
{
  fn_result_t watch_result;
  fn_result_t close_result;
  if (!stream_is_owner(stream)) {
    return stream_result(FN_INVALID);
  }
  if (stream->aborted) {
    return stream_result(FN_OK);
  }
  watch_result = fn_io_watcher_stop(stream->watcher);
  stream->interests = 0;
  stream->callback = NULL;
  stream->callback_context = NULL;
  close_result = fn_socket_close(&stream->socket);
  stream_release_buffered_read(stream);
  if (stream->owns_file_descriptor_reservation) {
    (void)fn_budget_release(stream->file_descriptors, FN_BUDGET_ACTIVE, 1u);
    stream->owns_file_descriptor_reservation = false;
  }
  stream->aborted = true;
  if (watch_result.code != FN_OK) {
    return watch_result;
  }
  return close_result;
}

fn_result_t fn_stream_release(fn_stream_t **pointer)
{
  fn_stream_t *stream;
  fn_budget_t *owned_memory;
  fn_allocator_t allocator;
  fn_result_t abort_result;
  fn_result_t watcher_result;
  if (pointer == NULL) {
    return stream_result(FN_INVALID);
  }
  stream = *pointer;
  if (stream == NULL) {
    return stream_result(FN_OK);
  }
  if (!stream_is_owner(stream) || stream->references == 0) {
    return stream_result(FN_INVALID);
  }
  stream->references--;
  if (stream->references != 0) {
    *pointer = NULL;
    return stream_result(FN_OK);
  }
  abort_result = fn_stream_abort(stream);
  watcher_result = fn_io_watcher_destroy(&stream->watcher);
  owned_memory = stream->owned_memory;
  allocator = stream->allocator;
  allocator.deallocate(allocator.context, stream);
  (void)fn_budget_release(owned_memory, FN_BUDGET_ACTIVE, sizeof(*stream));
  *pointer = NULL;
  if (abort_result.code != FN_OK) {
    return abort_result;
  }
  return watcher_result;
}

fn_result_t fn_stream_snapshot(const fn_stream_t *stream,
                               fn_stream_snapshot_t *out)
{
  if (!stream_is_owner(stream) || out == NULL) {
    return stream_result(FN_INVALID);
  }
  out->interests = stream->interests;
  out->references = stream->references;
  out->buffered_read_bytes =
    stream->buffered_read_length - stream->buffered_read_offset;
  out->write_shutdown = stream->write_shutdown;
  out->aborted = stream->aborted;
  out->owns_file_descriptor_reservation =
    stream->owns_file_descriptor_reservation;
  return stream_result(FN_OK);
}

fn_result_t fn_relay_buffer_pool_create(
  const fn_relay_buffer_pool_options_t *options,
  fn_relay_buffer_pool_t **out)
{
  fn_relay_buffer_pool_t *pool;
  fn_result_t result;
  if (out == NULL) {
    return stream_result(FN_INVALID);
  }
  *out = NULL;
  if (options == NULL || options->loop == NULL || options->limits == NULL ||
      options->owned_memory == NULL || options->buffer_bytes == NULL ||
      options->owned_memory == options->buffer_bytes ||
      options->allocator.allocate == NULL ||
      options->allocator.deallocate == NULL ||
      options->block_size <= sizeof(fn_relay_buffer_t) ||
      options->block_cache_limit > options->block_capacity ||
      !fn_loop_is_owner(options->loop)) {
    return stream_result(FN_INVALID);
  }
  result = fn_budget_reserve(options->owned_memory, FN_BUDGET_ACTIVE,
                             sizeof(*pool));
  if (result.code != FN_OK) {
    return result;
  }
  pool = options->allocator.allocate(options->allocator.context,
                                     sizeof(*pool));
  if (pool == NULL) {
    (void)fn_budget_release(options->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*pool));
    return stream_result(FN_NO_MEMORY);
  }
  memset(pool, 0, sizeof(*pool));
  pool->loop = options->loop;
  pool->owned_memory = options->owned_memory;
  pool->allocator = options->allocator;
  pool->limits = *options->limits;
  pool->accounted_bytes = sizeof(*pool);
  result = fn_budget_init(&pool->waiter_bytes,
                          options->limits->resource_waiter_limit_bytes, 0u);
  if (result.code == FN_OK) {
    result = fn_pool_init(&pool->blocks, options->block_size,
                          options->block_capacity,
                          options->block_cache_limit,
                          options->owned_memory, options->buffer_bytes,
                          FN_BUDGET_ACTIVE, options->allocator);
  }
  if (result.code != FN_OK) {
    options->allocator.deallocate(options->allocator.context, pool);
    (void)fn_budget_release(options->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*pool));
    return result;
  }
  *out = pool;
  return stream_result(FN_OK);
}

fn_result_t fn_relay_buffer_pool_destroy(fn_relay_buffer_pool_t **pointer)
{
  fn_relay_buffer_pool_t *pool;
  fn_result_t result;
  fn_budget_t *owned_memory;
  fn_allocator_t allocator;
  size_t accounted_bytes;
  if (pointer == NULL) {
    return stream_result(FN_INVALID);
  }
  pool = *pointer;
  if (pool == NULL) {
    return stream_result(FN_OK);
  }
  if (!fn_loop_is_owner(pool->loop) || pool->active_relays != 0 ||
      pool->waiter_count != 0) {
    return stream_result(FN_INVALID);
  }
  result = fn_pool_destroy(&pool->blocks);
  if (result.code != FN_OK) {
    return result;
  }
  owned_memory = pool->owned_memory;
  allocator = pool->allocator;
  accounted_bytes = pool->accounted_bytes;
  allocator.deallocate(allocator.context, pool);
  (void)fn_budget_release(owned_memory, FN_BUDGET_ACTIVE, accounted_bytes);
  *pointer = NULL;
  return stream_result(FN_OK);
}

fn_result_t fn_relay_buffer_pool_snapshot(
  const fn_relay_buffer_pool_t *pool, fn_relay_buffer_pool_snapshot_t *out)
{
  fn_budget_snapshot_t waiter_snapshot;
  fn_result_t result;
  if (pool == NULL || out == NULL || !fn_loop_is_owner(pool->loop)) {
    return stream_result(FN_INVALID);
  }
  memset(out, 0, sizeof(*out));
  result = fn_pool_snapshot(&pool->blocks, &out->blocks);
  if (result.code != FN_OK) {
    return result;
  }
  result = fn_budget_snapshot(&pool->waiter_bytes, &waiter_snapshot);
  if (result.code != FN_OK) {
    return result;
  }
  out->active_relays = pool->active_relays;
  out->resource_waiters = pool->waiter_count;
  out->resource_waiter_bytes = waiter_snapshot.total;
  return stream_result(FN_OK);
}

fn_relay_options_t fn_relay_options_default(void)
{
  const fn_relay_options_t options = {
    .high_watermark = 32u * 1024u,
    .low_watermark = 16u * 1024u,
    .callback_byte_limit = 64u * 1024u,
    .callback_io_limit = 32u,
  };
  return options;
}

static size_t relay_buffer_capacity(const fn_relay_buffer_pool_t *pool)
{
  return pool->blocks.block_size - sizeof(fn_relay_buffer_t);
}

static unsigned char *relay_buffer_data(fn_relay_buffer_t *buffer)
{
  return (unsigned char *)buffer + sizeof(*buffer);
}

static fn_result_t relay_update_watches(fn_relay_t *relay);
static fn_result_t relay_finish(fn_relay_t *relay, fn_result_t result);
static void relay_stream_ready(fn_stream_t *stream, uint32_t events,
                               void *context);

static void pool_wait_remove(fn_relay_direction_t *direction)
{
  fn_relay_buffer_pool_t *pool = direction->relay->pool;
  fn_relay_direction_t **cursor = &pool->wait_head;
  fn_relay_direction_t *previous = NULL;
  if (!direction->waiting_resource) {
    return;
  }
  while (*cursor != NULL && *cursor != direction) {
    previous = *cursor;
    cursor = &(*cursor)->wait_next;
  }
  if (*cursor == direction) {
    *cursor = direction->wait_next;
    if (pool->wait_tail == direction) {
      pool->wait_tail = previous;
    }
    pool->waiter_count--;
    (void)fn_budget_release(&pool->waiter_bytes, FN_BUDGET_ACTIVE,
                            sizeof(*direction));
  }
  direction->wait_next = NULL;
  direction->waiting_resource = false;
  if (direction->wait_timer != NULL) {
    (void)fn_timer_destroy(&direction->wait_timer);
  }
}

static void direction_append_buffer(fn_relay_direction_t *direction,
                                    fn_relay_buffer_t *buffer)
{
  buffer->next = NULL;
  buffer->begin = 0;
  buffer->end = 0;
  if (direction->tail == NULL) {
    direction->head = buffer;
  } else {
    direction->tail->next = buffer;
  }
  direction->tail = buffer;
}

static void pool_return_buffer(fn_relay_buffer_pool_t *pool,
                               fn_relay_buffer_t *buffer)
{
  fn_relay_direction_t *waiter = pool->wait_head;
  if (waiter == NULL) {
    (void)fn_pool_release(&pool->blocks, buffer);
    return;
  }
  pool_wait_remove(waiter);
  direction_append_buffer(waiter, buffer);
  if (relay_update_watches(waiter->relay).code != FN_OK) {
    (void)relay_finish(waiter->relay, stream_result(FN_IO_ERROR));
  }
}

static void resource_wait_timeout(fn_timer_t *timer, void *context)
{
  fn_relay_direction_t *direction = context;
  fn_relay_t *relay = direction->relay;
  (void)timer;
  (void)fn_timer_destroy(&direction->wait_timer);
  pool_wait_remove(direction);
  (void)relay_finish(relay, resource_timeout_result());
}

static fn_result_t pool_wait_add(fn_relay_direction_t *direction)
{
  fn_relay_t *relay = direction->relay;
  fn_relay_buffer_pool_t *pool = relay->pool;
  fn_result_t result;
  uint64_t now_ms;
  uint64_t deadline_ms;

  if (direction->waiting_resource) {
    return stream_result(FN_AGAIN);
  }
  if (pool->waiter_count >= pool->limits.resource_waiter_limit) {
    return stream_result(FN_LIMIT);
  }
  result = fn_budget_reserve(&pool->waiter_bytes, FN_BUDGET_ACTIVE,
                             sizeof(*direction));
  if (result.code != FN_OK) {
    return result;
  }
  result = fn_monotonic_now_ms(&now_ms);
  if (result.code != FN_OK) {
    (void)fn_budget_release(&pool->waiter_bytes, FN_BUDGET_ACTIVE,
                            sizeof(*direction));
    return result;
  }
  deadline_ms = pool->limits.resource_wait_timeout_ms > UINT64_MAX - now_ms ?
    UINT64_MAX : now_ms + pool->limits.resource_wait_timeout_ms;
  if (relay->drain_deadline_ms != 0) {
    deadline_ms = fn_deadline_min(deadline_ms, relay->drain_deadline_ms);
  }
  result = fn_timer_start(pool->loop, deadline_ms, resource_wait_timeout,
                          direction, &direction->wait_timer);
  if (result.code != FN_OK) {
    (void)fn_budget_release(&pool->waiter_bytes, FN_BUDGET_ACTIVE,
                            sizeof(*direction));
    return result;
  }
  direction->waiting_resource = true;
  direction->wait_next = NULL;
  if (pool->wait_tail == NULL) {
    pool->wait_head = direction;
  } else {
    pool->wait_tail->wait_next = direction;
  }
  pool->wait_tail = direction;
  pool->waiter_count++;
  return stream_result(FN_AGAIN);
}

static fn_result_t direction_ensure_buffer(fn_relay_direction_t *direction)
{
  fn_relay_t *relay = direction->relay;
  fn_relay_buffer_t *buffer;
  fn_result_t result;
  size_t capacity = relay_buffer_capacity(relay->pool);
  if (direction->tail != NULL && direction->tail->end < capacity) {
    return stream_result(FN_OK);
  }
  result = fn_pool_acquire(&relay->pool->blocks, (void **)&buffer);
  if (result.code == FN_OK) {
    direction_append_buffer(direction, buffer);
    return result;
  }
  if (result.code == FN_LIMIT || result.code == FN_NO_MEMORY) {
    return pool_wait_add(direction);
  }
  return result;
}

static void direction_remove_empty_tail(fn_relay_direction_t *direction)
{
  fn_relay_buffer_t *buffer;
  fn_relay_buffer_t *previous = NULL;
  if (direction->tail == NULL || direction->tail->begin != 0 ||
      direction->tail->end != 0) {
    return;
  }
  buffer = direction->head;
  while (buffer != NULL && buffer != direction->tail) {
    previous = buffer;
    buffer = buffer->next;
  }
  if (buffer == NULL) {
    return;
  }
  if (previous == NULL) {
    direction->head = NULL;
  } else {
    previous->next = NULL;
  }
  direction->tail = previous;
  pool_return_buffer(direction->relay->pool, buffer);
}

static void direction_clear(fn_relay_direction_t *direction)
{
  fn_relay_buffer_t *buffer = direction->head;
  while (buffer != NULL) {
    fn_relay_buffer_t *next = buffer->next;
    pool_return_buffer(direction->relay->pool, buffer);
    buffer = next;
  }
  direction->head = NULL;
  direction->tail = NULL;
  direction->queued = 0;
}

static bool callback_budget_available(const fn_relay_t *relay,
                                      const fn_relay_callback_budget_t *budget)
{
  return budget->bytes < relay->options.callback_byte_limit &&
         budget->calls < relay->options.callback_io_limit;
}

static void add_delivered(uint64_t *total, size_t amount)
{
  if ((uint64_t)amount > UINT64_MAX - *total) {
    *total = UINT64_MAX;
  } else {
    *total += (uint64_t)amount;
  }
}

static fn_result_t direction_write(fn_relay_direction_t *direction,
                                   fn_relay_callback_budget_t *budget)
{
  fn_relay_t *relay = direction->relay;
  while (direction->head != NULL && callback_budget_available(relay, budget)) {
    fn_relay_buffer_t *buffer = direction->head;
    size_t available = buffer->end - buffer->begin;
    size_t byte_remaining = relay->options.callback_byte_limit - budget->bytes;
    size_t request = available < byte_remaining ? available : byte_remaining;
    fn_io_result_t io = fn_stream_write(
      direction->destination, relay_buffer_data(buffer) + buffer->begin,
      request);
    budget->calls++;
    if (io.result.code == FN_AGAIN) {
      return stream_result(FN_OK);
    }
    if (io.result.code != FN_OK || io.transferred == 0 ||
        io.transferred > request) {
      return io.result.code == FN_OK ? stream_result(FN_IO_ERROR) : io.result;
    }
    buffer->begin += io.transferred;
    direction->queued -= io.transferred;
    budget->bytes += io.transferred;
    add_delivered(&direction->bytes_delivered, io.transferred);
    if (buffer->begin == buffer->end) {
      direction->head = buffer->next;
      if (direction->head == NULL) {
        direction->tail = NULL;
      }
      pool_return_buffer(relay->pool, buffer);
    }
    if (direction->paused_high &&
        direction->queued <= relay->options.low_watermark) {
      direction->paused_high = false;
    }
  }
  if (direction->head == NULL && direction->source_eof &&
      !direction->write_shutdown && callback_budget_available(relay, budget)) {
    fn_result_t result = fn_stream_shutdown_write(direction->destination);
    budget->calls++;
    if (result.code != FN_OK && result.code != FN_AGAIN) {
      return result;
    }
    if (result.code == FN_OK) {
      direction->write_shutdown = true;
    }
  }
  return stream_result(FN_OK);
}

static fn_result_t direction_read(fn_relay_direction_t *direction,
                                  fn_relay_callback_budget_t *budget)
{
  fn_relay_t *relay = direction->relay;
  size_t capacity = relay_buffer_capacity(relay->pool);
  while (!direction->source_eof && !direction->paused_high &&
         !direction->waiting_resource &&
         callback_budget_available(relay, budget)) {
    fn_result_t result;
    fn_relay_buffer_t *buffer;
    size_t free_space;
    size_t high_remaining;
    size_t byte_remaining;
    size_t request;
    fn_io_result_t io;
    if (direction->queued >= relay->options.high_watermark) {
      direction->paused_high = true;
      break;
    }
    result = direction_ensure_buffer(direction);
    if (result.code == FN_AGAIN) {
      break;
    }
    if (result.code != FN_OK) {
      return result;
    }
    buffer = direction->tail;
    free_space = capacity - buffer->end;
    high_remaining = relay->options.high_watermark - direction->queued;
    byte_remaining = relay->options.callback_byte_limit - budget->bytes;
    request = free_space < high_remaining ? free_space : high_remaining;
    if (request > byte_remaining) {
      request = byte_remaining;
    }
    io = fn_stream_read(direction->source,
                        relay_buffer_data(buffer) + buffer->end, request);
    budget->calls++;
    if (io.result.code == FN_AGAIN) {
      direction_remove_empty_tail(direction);
      break;
    }
    if (io.result.code == FN_EOF) {
      direction->source_eof = true;
      direction_remove_empty_tail(direction);
      break;
    }
    if (io.result.code != FN_OK || io.transferred == 0 ||
        io.transferred > request) {
      return io.result.code == FN_OK ? stream_result(FN_IO_ERROR) : io.result;
    }
    buffer->end += io.transferred;
    direction->queued += io.transferred;
    budget->bytes += io.transferred;
    if (direction->queued >= relay->options.high_watermark) {
      direction->paused_high = true;
    }
  }
  return stream_result(FN_OK);
}

static bool relay_complete(const fn_relay_t *relay)
{
  return relay->directions[0].source_eof &&
         relay->directions[0].write_shutdown &&
         relay->directions[1].source_eof &&
         relay->directions[1].write_shutdown;
}

static fn_result_t relay_update_watches(fn_relay_t *relay)
{
  fn_relay_direction_t *up = &relay->directions[0];
  fn_relay_direction_t *down = &relay->directions[1];
  uint32_t left_events = 0;
  uint32_t right_events = 0;
  fn_result_t result;
  if (relay->terminal_queued) {
    return stream_result(FN_OK);
  }
  if (!up->source_eof && !up->paused_high && !up->waiting_resource) {
    left_events |= FN_IO_EVENT_READ;
  }
  if (down->head != NULL ||
      (down->source_eof && !down->write_shutdown)) {
    left_events |= FN_IO_EVENT_WRITE;
  }
  if (!down->source_eof && !down->paused_high && !down->waiting_resource) {
    right_events |= FN_IO_EVENT_READ;
  }
  if (up->head != NULL || (up->source_eof && !up->write_shutdown)) {
    right_events |= FN_IO_EVENT_WRITE;
  }
  result = fn_stream_watch(relay->left, left_events,
                           left_events == 0 ? NULL : relay_stream_ready,
                           left_events == 0 ? NULL : relay);
  if (result.code != FN_OK) {
    return result;
  }
  result = fn_stream_watch(relay->right, right_events,
                           right_events == 0 ? NULL : relay_stream_ready,
                           right_events == 0 ? NULL : relay);
  if (result.code != FN_OK) {
    (void)fn_stream_watch(relay->left, 0, NULL, NULL);
    return result;
  }
  return stream_result(FN_OK);
}

static void relay_stream_ready(fn_stream_t *stream, uint32_t events,
                               void *context)
{
  fn_relay_t *relay = context;
  fn_relay_callback_budget_t budget = {0};
  fn_result_t result = stream_result(FN_OK);
  if (relay->terminal_queued) {
    return;
  }
  if ((events & FN_IO_EVENT_ERROR) != 0) {
    (void)relay_finish(relay, stream_result(FN_IO_ERROR));
    return;
  }
  if (stream == relay->left) {
    if ((events & FN_IO_EVENT_WRITE) != 0) {
      result = direction_write(&relay->directions[1], &budget);
    }
    if (result.code == FN_OK && (events & FN_IO_EVENT_READ) != 0) {
      result = direction_read(&relay->directions[0], &budget);
      if (result.code == FN_OK) {
        result = direction_write(&relay->directions[0], &budget);
      }
    }
  } else if (stream == relay->right) {
    if ((events & FN_IO_EVENT_WRITE) != 0) {
      result = direction_write(&relay->directions[0], &budget);
    }
    if (result.code == FN_OK && (events & FN_IO_EVENT_READ) != 0) {
      result = direction_read(&relay->directions[1], &budget);
      if (result.code == FN_OK) {
        result = direction_write(&relay->directions[1], &budget);
      }
    }
  } else {
    result = stream_result(FN_INVALID);
  }
  if (budget.bytes > relay->max_callback_bytes) {
    relay->max_callback_bytes = budget.bytes;
  }
  if (budget.calls > relay->max_callback_io) {
    relay->max_callback_io = budget.calls;
  }
  if (result.code != FN_OK) {
    (void)relay_finish(relay, result);
  } else if (relay_complete(relay)) {
    (void)relay_finish(relay, stream_result(FN_OK));
  } else if (relay_update_watches(relay).code != FN_OK) {
    (void)relay_finish(relay, stream_result(FN_IO_ERROR));
  }
}

static void relay_completion(void *context, fn_result_t ignored)
{
  fn_relay_t *relay = context;
  fn_relay_callback_fn callback = relay->callback;
  void *callback_context = relay->callback_context;
  fn_result_t result = relay->terminal_result;
  (void)ignored;
  relay->callback_started = true;
  callback(relay, callback_context, result);
}

static fn_result_t relay_finish(fn_relay_t *relay, fn_result_t result)
{
  fn_result_t publish_result;
  if (relay->terminal_queued) {
    return stream_result(FN_OK);
  }
  relay->terminal_queued = true;
  relay->terminal_result = result;
  (void)fn_stream_watch(relay->left, 0, NULL, NULL);
  (void)fn_stream_watch(relay->right, 0, NULL, NULL);
  if (relay->drain_timer != NULL) {
    (void)fn_timer_destroy(&relay->drain_timer);
  }
  pool_wait_remove(&relay->directions[0]);
  pool_wait_remove(&relay->directions[1]);
  direction_clear(&relay->directions[0]);
  direction_clear(&relay->directions[1]);
  if (result.code != FN_OK) {
    (void)fn_stream_abort(relay->left);
    (void)fn_stream_abort(relay->right);
  }
  publish_result = fn_completion_publish(&relay->ticket, result,
                                         relay_completion, relay);
  return publish_result;
}

fn_result_t fn_relay_start(fn_relay_buffer_pool_t *pool,
                           fn_stream_t *left, fn_stream_t *right,
                           const fn_relay_options_t *options,
                           fn_relay_callback_fn callback, void *context,
                           fn_relay_t **out)
{
  fn_relay_t *relay;
  fn_completion_ticket_t *ticket = NULL;
  fn_result_t result;
  bool left_retained = false;
  bool right_retained = false;
  if (out == NULL) {
    return stream_result(FN_INVALID);
  }
  *out = NULL;
  if (pool == NULL || !fn_loop_is_owner(pool->loop) || left == NULL ||
      right == NULL || left == right || left->loop != pool->loop ||
      right->loop != pool->loop || left->aborted || right->aborted ||
      left->interests != 0 || right->interests != 0 ||
      options == NULL || callback == NULL ||
      options->low_watermark == 0 ||
      options->low_watermark >= options->high_watermark ||
      options->callback_byte_limit == 0 ||
      options->callback_io_limit == 0) {
    return stream_result(FN_INVALID);
  }
  if (pool->active_relays >= pool->limits.async_operation_limit) {
    return stream_result(FN_LIMIT);
  }
  result = fn_completion_reserve_terminal(pool->loop, &ticket);
  if (result.code != FN_OK) {
    return result;
  }
  result = fn_budget_reserve(pool->owned_memory, FN_BUDGET_ACTIVE,
                             sizeof(*relay));
  if (result.code != FN_OK) {
    (void)fn_completion_abandon(&ticket);
    return result;
  }
  relay = pool->allocator.allocate(pool->allocator.context, sizeof(*relay));
  if (relay == NULL) {
    (void)fn_budget_release(pool->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*relay));
    (void)fn_completion_abandon(&ticket);
    return stream_result(FN_NO_MEMORY);
  }
  memset(relay, 0, sizeof(*relay));
  relay->pool = pool;
  relay->left = left;
  relay->right = right;
  relay->ticket = ticket;
  relay->callback = callback;
  relay->callback_context = context;
  relay->options = *options;
  relay->directions[0].relay = relay;
  relay->directions[0].source = left;
  relay->directions[0].destination = right;
  relay->directions[1].relay = relay;
  relay->directions[1].source = right;
  relay->directions[1].destination = left;
  result = fn_stream_retain(left);
  if (result.code == FN_OK) {
    left_retained = true;
    result = fn_stream_retain(right);
    if (result.code == FN_OK) {
      right_retained = true;
    }
  }
  if (result.code == FN_OK) {
    result = relay_update_watches(relay);
  }
  if (result.code != FN_OK) {
    fn_stream_t *left_reference = relay->left;
    fn_stream_t *right_reference = relay->right;
    (void)fn_stream_watch(left, 0, NULL, NULL);
    (void)fn_stream_watch(right, 0, NULL, NULL);
    if (right_retained) {
      (void)fn_stream_release(&right_reference);
    }
    if (left_retained) {
      (void)fn_stream_release(&left_reference);
    }
    pool->allocator.deallocate(pool->allocator.context, relay);
    (void)fn_budget_release(pool->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*relay));
    (void)fn_completion_abandon(&ticket);
    return result;
  }
  pool->active_relays++;
  *out = relay;
  if (left->buffered_read != NULL || right->buffered_read != NULL) {
    fn_relay_callback_budget_t budget = {0};
    if (left->buffered_read != NULL) {
      result = direction_read(&relay->directions[0], &budget);
      if (result.code == FN_OK) {
        result = direction_write(&relay->directions[0], &budget);
      }
    }
    if (result.code == FN_OK && right->buffered_read != NULL) {
      result = direction_read(&relay->directions[1], &budget);
      if (result.code == FN_OK) {
        result = direction_write(&relay->directions[1], &budget);
      }
    }
    relay->max_callback_bytes = budget.bytes;
    relay->max_callback_io = budget.calls;
    if (result.code != FN_OK) {
      (void)relay_finish(relay, result);
    } else if (relay_complete(relay)) {
      (void)relay_finish(relay, stream_result(FN_OK));
    } else if (relay_update_watches(relay).code != FN_OK) {
      (void)relay_finish(relay, stream_result(FN_IO_ERROR));
    }
  }
  return stream_result(FN_OK);
}

static void drain_timeout(fn_timer_t *timer, void *context)
{
  fn_relay_t *relay = context;
  (void)timer;
  (void)fn_timer_destroy(&relay->drain_timer);
  (void)relay_finish(relay, stream_result(FN_TIMEOUT));
}

fn_result_t fn_relay_begin_drain(fn_relay_t *relay, uint64_t deadline_ms)
{
  fn_result_t result;
  uint64_t now_ms;
  if (!relay_is_owner(relay)) {
    return stream_result(FN_INVALID);
  }
  if (relay->terminal_queued || relay->drain_timer != NULL) {
    return stream_result(FN_OK);
  }
  result = fn_monotonic_now_ms(&now_ms);
  if (result.code != FN_OK) {
    return result;
  }
  relay->drain_deadline_ms = deadline_ms;
  if (deadline_ms <= now_ms) {
    return relay_finish(relay, stream_result(FN_TIMEOUT));
  }
  return fn_timer_start(relay->pool->loop, deadline_ms, drain_timeout, relay,
                        &relay->drain_timer);
}

fn_result_t fn_relay_cancel(fn_relay_t *relay)
{
  if (!relay_is_owner(relay)) {
    return stream_result(FN_INVALID);
  }
  if (relay->callback_started) {
    return stream_result(FN_OK);
  }
  if (relay->terminal_queued) {
    relay->terminal_result = stream_result(FN_CANCELLED);
    (void)fn_stream_abort(relay->left);
    (void)fn_stream_abort(relay->right);
    return stream_result(FN_OK);
  }
  return relay_finish(relay, stream_result(FN_CANCELLED));
}

fn_result_t fn_relay_release(fn_relay_t **pointer)
{
  fn_relay_t *relay;
  fn_relay_buffer_pool_t *pool;
  fn_stream_t *left;
  fn_stream_t *right;
  if (pointer == NULL) {
    return stream_result(FN_INVALID);
  }
  relay = *pointer;
  if (relay == NULL) {
    return stream_result(FN_OK);
  }
  if (!relay_is_owner(relay) || !relay->callback_started ||
      relay->ticket != NULL || relay->drain_timer != NULL ||
      relay->directions[0].waiting_resource ||
      relay->directions[1].waiting_resource) {
    return stream_result(FN_INVALID);
  }
  pool = relay->pool;
  left = relay->left;
  right = relay->right;
  pool->active_relays--;
  pool->allocator.deallocate(pool->allocator.context, relay);
  (void)fn_budget_release(pool->owned_memory, FN_BUDGET_ACTIVE,
                          sizeof(*relay));
  *pointer = NULL;
  (void)fn_stream_release(&left);
  return fn_stream_release(&right);
}

fn_result_t fn_relay_snapshot(const fn_relay_t *relay,
                              fn_relay_snapshot_t *out)
{
  if (!relay_is_owner(relay) || out == NULL) {
    return stream_result(FN_INVALID);
  }
  memset(out, 0, sizeof(*out));
  out->left_to_right_queued = relay->directions[0].queued;
  out->right_to_left_queued = relay->directions[1].queued;
  out->bytes_left_to_right = relay->directions[0].bytes_delivered;
  out->bytes_right_to_left = relay->directions[1].bytes_delivered;
  out->max_callback_bytes = relay->max_callback_bytes;
  out->max_callback_io = relay->max_callback_io;
  out->left_read_eof = relay->directions[0].source_eof;
  out->right_read_eof = relay->directions[1].source_eof;
  out->left_write_shutdown = relay->directions[1].write_shutdown;
  out->right_write_shutdown = relay->directions[0].write_shutdown;
  out->left_read_paused = relay->directions[0].paused_high ||
                          relay->directions[0].waiting_resource;
  out->right_read_paused = relay->directions[1].paused_high ||
                           relay->directions[1].waiting_resource;
  out->terminal_queued = relay->terminal_queued;
  return stream_result(FN_OK);
}
