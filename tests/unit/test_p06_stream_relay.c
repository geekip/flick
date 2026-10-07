#define _POSIX_C_SOURCE 200809L

#include "flicknet/clock.h"
#include "flicknet/platform.h"
#include "flicknet/stream.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures;

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__,      \
              #condition);                                                     \
      failures++;                                                              \
    }                                                                          \
  } while (0)

typedef struct {
  fn_limits_t limits;
  fn_budget_t memory;
  fn_budget_t buffers;
  fn_budget_t file_descriptors;
  fn_loop_t *loop;
  fn_relay_buffer_pool_t *pool;
} test_environment_t;

typedef struct {
  fn_stream_t *left;
  fn_stream_t *right;
  fn_socket_t left_peer;
  fn_socket_t right_peer;
} test_channel_t;

typedef struct {
  fn_relay_t **slot;
  size_t calls;
  fn_result_t result;
  fn_relay_snapshot_t snapshot;
} relay_observation_t;

static void relay_callback(fn_relay_t *relay, void *context,
                           fn_result_t result)
{
  relay_observation_t *observation = context;
  CHECK(observation->slot != NULL);
  CHECK(*observation->slot == relay);
  observation->calls++;
  observation->result = result;
  CHECK(fn_relay_snapshot(relay, &observation->snapshot).code == FN_OK);
  CHECK(fn_relay_release(observation->slot).code == FN_OK);
}

static fn_socket_policy_t nonblocking_policy(void)
{
  const fn_socket_policy_t policy = {
    .purpose = FN_SOCKET_PURPOSE_INBOUND_ACCEPTED,
    .require_nonblocking = true,
  };
  return policy;
}

static void environment_init(test_environment_t *environment,
                             size_t block_capacity,
                             uint64_t resource_wait_ms,
                             size_t async_limit)
{
  fn_loop_options_t loop_options;
  fn_relay_buffer_pool_options_t pool_options;
  memset(environment, 0, sizeof(*environment));
  environment->limits = fn_limits_default();
  environment->limits.owned_memory_limit_bytes = 16u * 1024u * 1024u;
  environment->limits.cleanup_reserve_bytes = 1024u * 1024u;
  environment->limits.buffer_pool_limit_bytes = 4u * 1024u * 1024u;
  environment->limits.resource_wait_timeout_ms = resource_wait_ms;
  environment->limits.async_operation_limit = async_limit;
  CHECK(fn_budget_init(&environment->memory,
                       environment->limits.owned_memory_limit_bytes,
                       environment->limits.cleanup_reserve_bytes).code ==
        FN_OK);
  CHECK(fn_budget_init(&environment->buffers,
                       environment->limits.buffer_pool_limit_bytes, 0u).code ==
        FN_OK);
  CHECK(fn_budget_init(&environment->file_descriptors,
                       environment->limits.fd_limit, 0u).code == FN_OK);
  memset(&loop_options, 0, sizeof(loop_options));
  loop_options.limits = &environment->limits;
  loop_options.owned_memory = &environment->memory;
  loop_options.file_descriptors = &environment->file_descriptors;
  loop_options.allocator = fn_allocator_system();
  loop_options.dispatch_limit = 16u;
  CHECK(fn_loop_create(&loop_options, &environment->loop).code == FN_OK);
  memset(&pool_options, 0, sizeof(pool_options));
  pool_options.loop = environment->loop;
  pool_options.limits = &environment->limits;
  pool_options.owned_memory = &environment->memory;
  pool_options.buffer_bytes = &environment->buffers;
  pool_options.allocator = fn_allocator_system();
  pool_options.block_size = 512u;
  pool_options.block_capacity = block_capacity;
  pool_options.block_cache_limit = block_capacity;
  CHECK(fn_relay_buffer_pool_create(&pool_options, &environment->pool).code ==
        FN_OK);
}

static void environment_destroy(test_environment_t *environment)
{
  fn_budget_snapshot_t snapshot;
  CHECK(fn_relay_buffer_pool_destroy(&environment->pool).code == FN_OK);
  CHECK(fn_loop_destroy(&environment->loop).code == FN_OK);
  CHECK(fn_budget_snapshot(&environment->memory, &snapshot).code == FN_OK);
  CHECK(snapshot.total == 0u);
  CHECK(fn_budget_snapshot(&environment->buffers, &snapshot).code == FN_OK);
  CHECK(snapshot.total == 0u);
  CHECK(fn_budget_snapshot(&environment->file_descriptors, &snapshot).code ==
        FN_OK);
  CHECK(snapshot.total == 0u);
}

static void channel_init(test_environment_t *environment,
                         test_channel_t *channel, int right_send_buffer)
{
  int left_pair[2] = {-1, -1};
  int right_pair[2] = {-1, -1};
  fn_socket_t left_internal = fn_socket_invalid();
  fn_socket_t right_internal = fn_socket_invalid();
  fn_stream_options_t options;
  fn_socket_policy_t policy = nonblocking_policy();
  fn_socket_policy_report_t report;

  memset(channel, 0, sizeof(*channel));
  channel->left_peer = fn_socket_invalid();
  channel->right_peer = fn_socket_invalid();
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, left_pair) == 0);
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, right_pair) == 0);
  if (right_send_buffer > 0) {
    CHECK(setsockopt(right_pair[1], SOL_SOCKET, SO_SNDBUF,
                     &right_send_buffer,
                     (socklen_t)sizeof(right_send_buffer)) == 0);
  }
  CHECK(fn_socket_from_native(left_pair[0], &channel->left_peer).code == FN_OK);
  CHECK(fn_socket_from_native(left_pair[1], &left_internal).code == FN_OK);
  CHECK(fn_socket_from_native(right_pair[0], &channel->right_peer).code ==
        FN_OK);
  CHECK(fn_socket_from_native(right_pair[1], &right_internal).code == FN_OK);
  CHECK(fn_socket_policy_apply(channel->left_peer, &policy, &report).code ==
        FN_OK);
  CHECK(fn_socket_policy_apply(left_internal, &policy, &report).code == FN_OK);
  CHECK(fn_socket_policy_apply(channel->right_peer, &policy, &report).code ==
        FN_OK);
  CHECK(fn_socket_policy_apply(right_internal, &policy, &report).code == FN_OK);
  memset(&options, 0, sizeof(options));
  options.loop = environment->loop;
  options.owned_memory = &environment->memory;
  options.allocator = fn_allocator_system();
  CHECK(fn_stream_socket_create(&options, &left_internal,
                                &channel->left).code == FN_OK);
  CHECK(fn_stream_socket_create(&options, &right_internal,
                                &channel->right).code == FN_OK);
  CHECK(!fn_socket_is_valid(left_internal));
  CHECK(!fn_socket_is_valid(right_internal));
}

static void channel_destroy(test_channel_t *channel)
{
  CHECK(fn_stream_release(&channel->left).code == FN_OK);
  CHECK(fn_stream_release(&channel->right).code == FN_OK);
  CHECK(fn_socket_close(&channel->left_peer).code == FN_OK);
  CHECK(fn_socket_close(&channel->right_peer).code == FN_OK);
}

static void pump_nowait(fn_loop_t *loop, size_t turns)
{
  size_t index;
  for (index = 0; index < turns; index++) {
    CHECK(fn_loop_run_once(loop, FN_LOOP_RUN_NOWAIT).code == FN_OK);
  }
}

static void write_all(test_environment_t *environment, fn_socket_t socket,
                      const unsigned char *data, size_t length)
{
  size_t offset = 0;
  size_t turns;
  for (turns = 0; turns < 20000u && offset < length; turns++) {
    fn_io_result_t io = fn_socket_write(socket, data + offset,
                                        length - offset, FN_STAGE_RELAY);
    if (io.result.code == FN_OK) {
      offset += io.transferred;
    } else {
      CHECK(io.result.code == FN_AGAIN);
    }
    pump_nowait(environment->loop, 1u);
  }
  CHECK(offset == length);
}

static void read_exact(test_environment_t *environment, fn_socket_t socket,
                       unsigned char *data, size_t length)
{
  size_t offset = 0;
  size_t turns;
  for (turns = 0; turns < 20000u && offset < length; turns++) {
    fn_io_result_t io = fn_socket_read(socket, data + offset,
                                       length - offset, FN_STAGE_RELAY);
    if (io.result.code == FN_OK) {
      offset += io.transferred;
    } else {
      CHECK(io.result.code == FN_AGAIN);
    }
    pump_nowait(environment->loop, 1u);
  }
  CHECK(offset == length);
}

static void wait_for_eof(test_environment_t *environment, fn_socket_t socket)
{
  unsigned char byte;
  size_t turns;
  bool eof = false;
  for (turns = 0; turns < 20000u && !eof; turns++) {
    fn_io_result_t io = fn_socket_read(socket, &byte, 1u, FN_STAGE_RELAY);
    if (io.result.code == FN_EOF) {
      eof = true;
    } else {
      CHECK(io.result.code == FN_AGAIN);
    }
    pump_nowait(environment->loop, 1u);
  }
  CHECK(eof);
}

static void test_bidirectional_half_close(void)
{
  static const unsigned char request[] = "request-data";
  static const unsigned char response[] = "response-after-fin";
  unsigned char received[64];
  test_environment_t environment;
  test_channel_t channel;
  fn_relay_options_t options = fn_relay_options_default();
  fn_relay_t *relay = NULL;
  relay_observation_t observation;

  environment_init(&environment, 32u, UINT64_C(50), 16u);
  channel_init(&environment, &channel, 0);
  memset(&observation, 0, sizeof(observation));
  observation.slot = &relay;
  options.callback_byte_limit = 1024u;
  options.callback_io_limit = 8u;
  CHECK(fn_relay_start(environment.pool, channel.left, channel.right,
                       &options, relay_callback, &observation,
                       &relay).code == FN_OK);
  write_all(&environment, channel.left_peer, request, sizeof(request));
  memset(received, 0, sizeof(received));
  read_exact(&environment, channel.right_peer, received, sizeof(request));
  CHECK(memcmp(received, request, sizeof(request)) == 0);

  CHECK(fn_socket_shutdown_write(channel.left_peer,
                                 FN_STAGE_RELAY).code == FN_OK);
  wait_for_eof(&environment, channel.right_peer);
  CHECK(observation.calls == 0u);
  write_all(&environment, channel.right_peer, response, sizeof(response));
  memset(received, 0, sizeof(received));
  read_exact(&environment, channel.left_peer, received, sizeof(response));
  CHECK(memcmp(received, response, sizeof(response)) == 0);
  CHECK(fn_socket_shutdown_write(channel.right_peer,
                                 FN_STAGE_RELAY).code == FN_OK);
  pump_nowait(environment.loop, 16u);
  CHECK(observation.calls == 1u);
  CHECK(observation.result.code == FN_OK);
  CHECK(observation.snapshot.bytes_left_to_right == sizeof(request));
  CHECK(observation.snapshot.bytes_right_to_left == sizeof(response));
  CHECK(observation.snapshot.max_callback_bytes <=
        options.callback_byte_limit);
  CHECK(observation.snapshot.max_callback_io <= options.callback_io_limit);
  channel_destroy(&channel);
  environment_destroy(&environment);
}

static void test_backpressure_and_fair_budget(void)
{
  unsigned char sent_data[64u * 1024u];
  unsigned char received[4096];
  test_environment_t environment;
  test_channel_t channel;
  fn_relay_options_t options = fn_relay_options_default();
  fn_relay_t *relay = NULL;
  relay_observation_t observation;
  fn_relay_snapshot_t snapshot;
  size_t sent = 0;
  size_t received_total = 0;
  size_t turns;
  bool paused = false;

  for (turns = 0; turns < sizeof(sent_data); turns++) {
    sent_data[turns] = (unsigned char)(turns % 251u);
  }
  environment_init(&environment, 64u, UINT64_C(100), 16u);
  channel_init(&environment, &channel, 1024);
  memset(&observation, 0, sizeof(observation));
  observation.slot = &relay;
  options.high_watermark = 2048u;
  options.low_watermark = 1024u;
  options.callback_byte_limit = 512u;
  options.callback_io_limit = 4u;
  CHECK(fn_relay_start(environment.pool, channel.left, channel.right,
                       &options, relay_callback, &observation,
                       &relay).code == FN_OK);

  for (turns = 0; turns < 30000u && !paused; turns++) {
    if (sent < sizeof(sent_data)) {
      fn_io_result_t io = fn_socket_write(
        channel.left_peer, sent_data + sent, sizeof(sent_data) - sent,
        FN_STAGE_RELAY);
      if (io.result.code == FN_OK) {
        sent += io.transferred;
      } else {
        CHECK(io.result.code == FN_AGAIN);
      }
    }
    pump_nowait(environment.loop, 1u);
    CHECK(fn_relay_snapshot(relay, &snapshot).code == FN_OK);
    CHECK(snapshot.left_to_right_queued <= options.high_watermark);
    paused = snapshot.left_read_paused;
  }
  CHECK(paused);
  CHECK(sent != 0u);

  for (turns = 0; turns < 60000u && received_total < sent; turns++) {
    fn_io_result_t io = fn_socket_read(channel.right_peer, received,
                                       sizeof(received), FN_STAGE_RELAY);
    if (io.result.code == FN_OK) {
      CHECK(memcmp(received, sent_data + received_total,
                   io.transferred) == 0);
      received_total += io.transferred;
    } else {
      CHECK(io.result.code == FN_AGAIN);
    }
    pump_nowait(environment.loop, 1u);
  }
  CHECK(received_total == sent);
  CHECK(fn_relay_snapshot(relay, &snapshot).code == FN_OK);
  CHECK(snapshot.left_to_right_queued == 0u);
  CHECK(!snapshot.left_read_paused);
  CHECK(snapshot.max_callback_bytes <= options.callback_byte_limit);
  CHECK(snapshot.max_callback_io <= options.callback_io_limit);

  CHECK(fn_socket_shutdown_write(channel.left_peer,
                                 FN_STAGE_RELAY).code == FN_OK);
  CHECK(fn_socket_shutdown_write(channel.right_peer,
                                 FN_STAGE_RELAY).code == FN_OK);
  pump_nowait(environment.loop, 32u);
  CHECK(observation.calls == 1u);
  CHECK(observation.result.code == FN_OK);
  channel_destroy(&channel);
  environment_destroy(&environment);
}

static void test_resource_wait_timeout(void)
{
  const unsigned char byte = 0x5au;
  test_environment_t environment;
  test_channel_t channel;
  fn_relay_options_t options = fn_relay_options_default();
  fn_relay_t *relay = NULL;
  relay_observation_t observation;
  fn_relay_buffer_pool_snapshot_t pool_snapshot;
  size_t turns;

  environment_init(&environment, 0u, UINT64_C(5), 16u);
  channel_init(&environment, &channel, 0);
  memset(&observation, 0, sizeof(observation));
  observation.slot = &relay;
  CHECK(fn_relay_start(environment.pool, channel.left, channel.right,
                       &options, relay_callback, &observation,
                       &relay).code == FN_OK);
  write_all(&environment, channel.left_peer, &byte, 1u);
  for (turns = 0; turns < 100u; turns++) {
    CHECK(fn_relay_buffer_pool_snapshot(environment.pool,
                                        &pool_snapshot).code == FN_OK);
    if (pool_snapshot.resource_waiters == 1u) {
      break;
    }
    pump_nowait(environment.loop, 1u);
  }
  CHECK(pool_snapshot.blocks.total_blocks == 0u);
  CHECK(pool_snapshot.resource_waiters == 1u);
  for (turns = 0; turns < 8u && observation.calls == 0u; turns++) {
    CHECK(fn_loop_run_once(environment.loop, FN_LOOP_RUN_ONCE).code == FN_OK);
  }
  CHECK(observation.calls == 1u);
  CHECK(observation.result.code == FN_TIMEOUT);
  CHECK(observation.result.stage == FN_STAGE_RESOURCE);
  CHECK(fn_relay_buffer_pool_snapshot(environment.pool,
                                      &pool_snapshot).code == FN_OK);
  CHECK(pool_snapshot.active_relays == 0u);
  CHECK(pool_snapshot.resource_waiters == 0u);
  channel_destroy(&channel);
  environment_destroy(&environment);
}

static void test_drain_cancel_and_admission(void)
{
  test_environment_t environment;
  test_channel_t channel;
  fn_relay_options_t options = fn_relay_options_default();
  fn_relay_t *relay = NULL;
  relay_observation_t observation;
  uint64_t now_ms;
  size_t turns;

  environment_init(&environment, 8u, UINT64_C(50), 16u);
  channel_init(&environment, &channel, 0);
  memset(&observation, 0, sizeof(observation));
  observation.slot = &relay;
  CHECK(fn_relay_start(environment.pool, channel.left, channel.right,
                       &options, relay_callback, &observation,
                       &relay).code == FN_OK);
  CHECK(fn_monotonic_now_ms(&now_ms).code == FN_OK);
  CHECK(fn_relay_begin_drain(relay, now_ms + UINT64_C(5)).code == FN_OK);
  for (turns = 0; turns < 8u && observation.calls == 0u; turns++) {
    CHECK(fn_loop_run_once(environment.loop, FN_LOOP_RUN_ONCE).code == FN_OK);
  }
  CHECK(observation.calls == 1u);
  CHECK(observation.result.code == FN_TIMEOUT);
  CHECK(observation.result.stage == FN_STAGE_RELAY);
  channel_destroy(&channel);

  channel_init(&environment, &channel, 0);
  memset(&observation, 0, sizeof(observation));
  observation.slot = &relay;
  CHECK(fn_relay_start(environment.pool, channel.left, channel.right,
                       &options, relay_callback, &observation,
                       &relay).code == FN_OK);
  CHECK(fn_relay_cancel(relay).code == FN_OK);
  CHECK(observation.calls == 0u);
  pump_nowait(environment.loop, 4u);
  CHECK(observation.calls == 1u);
  CHECK(observation.result.code == FN_CANCELLED);
  channel_destroy(&channel);
  environment_destroy(&environment);

  environment_init(&environment, 8u, UINT64_C(50), 0u);
  channel_init(&environment, &channel, 0);
  memset(&observation, 0, sizeof(observation));
  observation.slot = &relay;
  CHECK(fn_relay_start(environment.pool, channel.left, channel.right,
                       &options, relay_callback, &observation,
                       &relay).code == FN_LIMIT);
  CHECK(relay == NULL);
  CHECK(observation.calls == 0u);
  channel_destroy(&channel);
  environment_destroy(&environment);
}

int main(void)
{
  test_bidirectional_half_close();
  test_backpressure_and_fair_budget();
  test_resource_wait_timeout();
  test_drain_cancel_and_admission();
  if (failures != 0) {
    fprintf(stderr, "P06 stream/relay tests failed: %d\n", failures);
    return 1;
  }
  puts("P06 stream/relay tests passed");
  return 0;
}
