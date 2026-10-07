#define _POSIX_C_SOURCE 200809L

#include "bench_common.h"

#include "flicknet/loop.h"
#include "flicknet/platform.h"
#include "flicknet/resource.h"
#include "flicknet/stream.h"

#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum {
  RELAY_TARGET_ID = 4,
  PLAN_ITERATIONS = 1,
  PLAN_THROUGHPUT = 2,
  RELAY_CHUNK_BYTES = 16384,
};

typedef struct {
  fn_limits_t limits;
  fn_budget_t memory;
  fn_budget_t buffers;
  fn_budget_t file_descriptors;
  fn_loop_t *loop;
  fn_relay_buffer_pool_t *pool;
} relay_environment_t;

typedef struct {
  fn_stream_t *left;
  fn_stream_t *right;
  fn_socket_t left_peer;
  fn_socket_t right_peer;
} relay_channel_t;

typedef struct {
  fn_relay_t *relay;
  size_t calls;
  fn_result_t result;
} relay_completion_t;

typedef struct {
  double wall_seconds;
  double cpu_seconds;
  double owned_bytes;
  double max_buffer_bytes;
  double peer_progress_bytes;
  double fd_count;
  uint64_t verified_bytes;
  bool ok;
} sample_result_t;

static size_t process_fd_count(void)
{
  DIR *directory = opendir("/proc/self/fd");
  struct dirent *entry;
  size_t count = 0;
  if (directory == NULL) {
    return 0u;
  }
  while ((entry = readdir(directory)) != NULL) {
    if (entry->d_name[0] != '.') {
      count++;
    }
  }
  (void)closedir(directory);
  return count;
}

static int environment_init(relay_environment_t *environment)
{
  fn_loop_options_t loop_options;
  fn_relay_buffer_pool_options_t pool_options;
  memset(environment, 0, sizeof(*environment));
  environment->limits = fn_limits_default();
  environment->limits.owned_memory_limit_bytes = 128u * 1024u * 1024u;
  environment->limits.cleanup_reserve_bytes = 2u * 1024u * 1024u;
  environment->limits.buffer_pool_limit_bytes = 32u * 1024u * 1024u;
  environment->limits.async_operation_limit = 4096u;
  if (fn_budget_init(&environment->memory,
                     environment->limits.owned_memory_limit_bytes,
                     environment->limits.cleanup_reserve_bytes).code !=
      FN_OK ||
      fn_budget_init(&environment->buffers,
                     environment->limits.buffer_pool_limit_bytes, 0u).code !=
      FN_OK ||
      fn_budget_init(&environment->file_descriptors,
                     environment->limits.fd_limit, 0u).code != FN_OK) {
    return -1;
  }
  memset(&loop_options, 0, sizeof(loop_options));
  loop_options.limits = &environment->limits;
  loop_options.owned_memory = &environment->memory;
  loop_options.file_descriptors = &environment->file_descriptors;
  loop_options.allocator = fn_allocator_system();
  loop_options.dispatch_limit = 64u;
  if (fn_loop_create(&loop_options, &environment->loop).code != FN_OK) {
    return -1;
  }
  memset(&pool_options, 0, sizeof(pool_options));
  pool_options.loop = environment->loop;
  pool_options.limits = &environment->limits;
  pool_options.owned_memory = &environment->memory;
  pool_options.buffer_bytes = &environment->buffers;
  pool_options.allocator = fn_allocator_system();
  pool_options.block_size = RELAY_CHUNK_BYTES;
  pool_options.block_capacity = 2048u;
  pool_options.block_cache_limit = 8u;
  if (fn_relay_buffer_pool_create(&pool_options,
                                  &environment->pool).code != FN_OK) {
    (void)fn_loop_destroy(&environment->loop);
    return -1;
  }
  return 0;
}

static int environment_destroy(relay_environment_t *environment)
{
  fn_budget_snapshot_t memory;
  fn_budget_snapshot_t buffers;
  fn_budget_snapshot_t file_descriptors;
  if (fn_relay_buffer_pool_destroy(&environment->pool).code != FN_OK ||
      fn_loop_destroy(&environment->loop).code != FN_OK ||
      fn_budget_snapshot(&environment->memory, &memory).code != FN_OK ||
      fn_budget_snapshot(&environment->buffers, &buffers).code != FN_OK ||
      fn_budget_snapshot(&environment->file_descriptors,
                         &file_descriptors).code != FN_OK ||
      memory.total != 0u || buffers.total != 0u ||
      file_descriptors.total != 0u) {
    return -1;
  }
  return 0;
}

static fn_socket_policy_t socket_policy(void)
{
  const fn_socket_policy_t policy = {
    .purpose = FN_SOCKET_PURPOSE_INBOUND_ACCEPTED,
    .require_nonblocking = true,
  };
  return policy;
}

static int channel_init(relay_environment_t *environment,
                        relay_channel_t *channel, int send_buffer)
{
  int left_pair[2] = {-1, -1};
  int right_pair[2] = {-1, -1};
  fn_socket_t left_internal = fn_socket_invalid();
  fn_socket_t right_internal = fn_socket_invalid();
  fn_stream_options_t options;
  fn_socket_policy_t policy = socket_policy();
  fn_socket_policy_report_t report;
  memset(channel, 0, sizeof(*channel));
  channel->left_peer = fn_socket_invalid();
  channel->right_peer = fn_socket_invalid();
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, left_pair) != 0 ||
      socketpair(AF_UNIX, SOCK_STREAM, 0, right_pair) != 0) {
    return -1;
  }
  if (send_buffer > 0 &&
      setsockopt(right_pair[1], SOL_SOCKET, SO_SNDBUF, &send_buffer,
                 (socklen_t)sizeof(send_buffer)) != 0) {
    return -1;
  }
  if (fn_socket_from_native(left_pair[0], &channel->left_peer).code != FN_OK ||
      fn_socket_from_native(left_pair[1], &left_internal).code != FN_OK ||
      fn_socket_from_native(right_pair[0],
                            &channel->right_peer).code != FN_OK ||
      fn_socket_from_native(right_pair[1], &right_internal).code != FN_OK ||
      fn_socket_policy_apply(channel->left_peer,
                             &policy, &report).code != FN_OK ||
      fn_socket_policy_apply(left_internal,
                             &policy, &report).code != FN_OK ||
      fn_socket_policy_apply(channel->right_peer,
                             &policy, &report).code != FN_OK ||
      fn_socket_policy_apply(right_internal,
                             &policy, &report).code != FN_OK) {
    return -1;
  }
  memset(&options, 0, sizeof(options));
  options.loop = environment->loop;
  options.owned_memory = &environment->memory;
  options.allocator = fn_allocator_system();
  if (fn_stream_socket_create(&options, &left_internal,
                              &channel->left).code != FN_OK ||
      fn_stream_socket_create(&options, &right_internal,
                              &channel->right).code != FN_OK) {
    return -1;
  }
  return 0;
}

static int channel_destroy(relay_channel_t *channel)
{
  int status = 0;
  if (fn_stream_release(&channel->left).code != FN_OK ||
      fn_stream_release(&channel->right).code != FN_OK ||
      fn_socket_close(&channel->left_peer).code != FN_OK ||
      fn_socket_close(&channel->right_peer).code != FN_OK) {
    status = -1;
  }
  return status;
}

static void relay_done(fn_relay_t *relay, void *context,
                       fn_result_t result)
{
  relay_completion_t *completion = context;
  completion->calls++;
  completion->result = result;
  if (completion->relay != relay ||
      fn_relay_release(&completion->relay).code != FN_OK) {
    completion->result = fn_result_make(
      FN_INVALID, FN_STAGE_RELAY, FN_ERROR_ORIGIN_NONE, 0);
  }
}

static int pump(relay_environment_t *environment)
{
  return fn_loop_run_once(environment->loop,
                          FN_LOOP_RUN_NOWAIT).code == FN_OK ? 0 : -1;
}

static int socket_write_all(relay_environment_t *environment,
                            fn_socket_t socket,
                            const unsigned char *data, size_t length)
{
  size_t offset = 0;
  size_t turns = 0;
  while (offset < length && turns++ < 100000u) {
    fn_io_result_t io = fn_socket_write(
      socket, data + offset, length - offset, FN_STAGE_RELAY);
    if (io.result.code == FN_OK) {
      offset += io.transferred;
    } else if (io.result.code != FN_AGAIN) {
      return -1;
    }
    if (pump(environment) != 0) {
      return -1;
    }
  }
  return offset == length ? 0 : -1;
}

static int socket_read_exact(relay_environment_t *environment,
                             fn_socket_t socket, unsigned char *data,
                             size_t length)
{
  size_t offset = 0;
  size_t turns = 0;
  while (offset < length && turns++ < 100000u) {
    fn_io_result_t io = fn_socket_read(
      socket, data + offset, length - offset, FN_STAGE_RELAY);
    if (io.result.code == FN_OK) {
      offset += io.transferred;
    } else if (io.result.code != FN_AGAIN) {
      return -1;
    }
    if (pump(environment) != 0) {
      return -1;
    }
  }
  return offset == length ? 0 : -1;
}

static void payload_fill(unsigned char *data, size_t length,
                         uint64_t seed, uint64_t offset)
{
  size_t index;
  for (index = 0; index < length; index++) {
    data[index] = (unsigned char)(
      (seed + (offset + (uint64_t)index) * 131u) % 251u);
  }
}

static int relay_start(relay_environment_t *environment,
                       relay_channel_t *channel,
                       relay_completion_t *completion,
                       size_t high_watermark, size_t low_watermark)
{
  fn_relay_options_t options = fn_relay_options_default();
  memset(completion, 0, sizeof(*completion));
  options.high_watermark = high_watermark;
  options.low_watermark = low_watermark;
  options.callback_byte_limit = RELAY_CHUNK_BYTES * 4u;
  options.callback_io_limit = 16u;
  if (fn_relay_start(environment->pool, channel->left, channel->right,
                     &options, relay_done, completion,
                     &completion->relay).code != FN_OK) {
    return -1;
  }
  return 0;
}

static int relay_finish(relay_environment_t *environment,
                        relay_channel_t *channel,
                        relay_completion_t *completion)
{
  size_t turns;
  if (fn_socket_shutdown_write(channel->left_peer,
                               FN_STAGE_RELAY).code != FN_OK ||
      fn_socket_shutdown_write(channel->right_peer,
                               FN_STAGE_RELAY).code != FN_OK) {
    return -1;
  }
  for (turns = 0; turns < 100000u && completion->calls == 0u; turns++) {
    if (pump(environment) != 0) {
      return -1;
    }
  }
  return completion->calls == 1u && completion->result.code == FN_OK ?
    0 : -1;
}

static int transfer_direction(relay_environment_t *environment,
                              fn_socket_t input, fn_socket_t output,
                              uint64_t bytes, uint64_t seed)
{
  unsigned char sent[RELAY_CHUNK_BYTES];
  unsigned char received[RELAY_CHUNK_BYTES];
  uint64_t offset = 0;
  while (offset < bytes) {
    size_t length = (size_t)(bytes - offset);
    if (length > sizeof(sent)) {
      length = sizeof(sent);
    }
    payload_fill(sent, length, seed, offset);
    if (socket_write_all(environment, input, sent, length) != 0 ||
        socket_read_exact(environment, output, received, length) != 0 ||
        memcmp(sent, received, length) != 0) {
      return -1;
    }
    offset += length;
  }
  return 0;
}

static sample_result_t sample_native(uint64_t bytes, uint64_t directions,
                                     uint64_t seed)
{
  sample_result_t result = {0};
  int pair[2] = {-1, -1};
  unsigned char sent[RELAY_CHUNK_BYTES];
  unsigned char received[RELAY_CHUNK_BYTES];
  unsigned char read_buffer[RELAY_CHUNK_BYTES];
  uint64_t wall_start;
  uint64_t cpu_start;
  uint64_t direction;
  result.ok = socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0;
  wall_start = fn_bench_monotonic_ns();
  cpu_start = fn_bench_process_cpu_ns();
  for (direction = 0; result.ok && direction < directions; direction++) {
    int write_fd = direction == 0u ? pair[0] : pair[1];
    int read_fd = direction == 0u ? pair[1] : pair[0];
    uint64_t offset = 0;
    while (result.ok && offset < bytes) {
      size_t length = (size_t)(bytes - offset);
      size_t sent_offset = 0;
      size_t read_offset = 0;
      if (length > sizeof(sent)) {
        length = sizeof(sent);
      }
      payload_fill(sent, length, seed + direction, offset);
      while (sent_offset < length) {
        ssize_t amount = write(write_fd, sent + sent_offset,
                               length - sent_offset);
        if (amount <= 0) {
          result.ok = false;
          break;
        }
        sent_offset += (size_t)amount;
      }
      while (result.ok && read_offset < length) {
        ssize_t amount = read(read_fd, read_buffer, sizeof(read_buffer));
        if (amount <= 0 || (size_t)amount > length - read_offset) {
          result.ok = false;
          break;
        }
        memcpy(received + read_offset, read_buffer, (size_t)amount);
        read_offset += (size_t)amount;
      }
      if (result.ok && memcmp(sent, received, length) != 0) {
        result.ok = false;
      }
      offset += length;
    }
  }
  result.wall_seconds =
    (double)(fn_bench_monotonic_ns() - wall_start) / 1000000000.0;
  result.cpu_seconds =
    (double)(fn_bench_process_cpu_ns() - cpu_start) / 1000000000.0;
  result.verified_bytes = bytes * directions;
  if (pair[0] >= 0) {
    (void)close(pair[0]);
  }
  if (pair[1] >= 0) {
    (void)close(pair[1]);
  }
  return result;
}

static sample_result_t sample_in_process(relay_environment_t *environment,
                                         uint64_t bytes,
                                         uint64_t directions,
                                         uint64_t seed)
{
  sample_result_t result = {0};
  relay_channel_t channel;
  relay_completion_t completion;
  fn_budget_snapshot_t memory;
  uint64_t wall_start;
  uint64_t cpu_start;
  result.ok = channel_init(environment, &channel, 0) == 0 &&
              relay_start(environment, &channel, &completion,
                          32u * 1024u, 16u * 1024u) == 0;
  wall_start = fn_bench_monotonic_ns();
  cpu_start = fn_bench_process_cpu_ns();
  if (result.ok) {
    result.ok = transfer_direction(environment, channel.left_peer,
                                   channel.right_peer, bytes, seed) == 0;
  }
  if (result.ok && directions == 2u) {
    result.ok = transfer_direction(environment, channel.right_peer,
                                   channel.left_peer, bytes, seed + 1u) == 0;
  }
  result.wall_seconds =
    (double)(fn_bench_monotonic_ns() - wall_start) / 1000000000.0;
  result.cpu_seconds =
    (double)(fn_bench_process_cpu_ns() - cpu_start) / 1000000000.0;
  result.verified_bytes = bytes * directions;
  if (result.ok) {
    result.ok = fn_budget_snapshot(&environment->memory,
                                   &memory).code == FN_OK;
    result.owned_bytes = (double)memory.total;
  }
  if (result.ok) {
    result.ok = relay_finish(environment, &channel, &completion) == 0;
  } else if (completion.relay != NULL) {
    (void)fn_relay_cancel(completion.relay);
    while (completion.calls == 0u) {
      if (pump(environment) != 0) {
        break;
      }
    }
  }
  if (channel_destroy(&channel) != 0) {
    result.ok = false;
  }
  return result;
}

static sample_result_t sample_slow(relay_environment_t *environment,
                                   uint64_t bytes, uint64_t delay_ms,
                                   uint64_t seed)
{
  sample_result_t result = {0};
  relay_channel_t slow;
  relay_channel_t peer;
  relay_completion_t slow_completion;
  relay_completion_t peer_completion;
  fn_relay_snapshot_t snapshot;
  fn_budget_snapshot_t memory;
  unsigned char sent[RELAY_CHUNK_BYTES];
  unsigned char received[RELAY_CHUNK_BYTES];
  uint64_t wall_start;
  uint64_t offset = 0;
  uint64_t received_total = 0;
  size_t turns = 0;
  bool paused = false;
  struct timespec delay = {
    .tv_sec = (time_t)(delay_ms / 1000u),
    .tv_nsec = (long)((delay_ms % 1000u) * 1000000u),
  };
  result.ok = channel_init(environment, &slow, 1024) == 0 &&
              channel_init(environment, &peer, 0) == 0 &&
              relay_start(environment, &slow, &slow_completion,
                          32u * 1024u, 16u * 1024u) == 0 &&
              relay_start(environment, &peer, &peer_completion,
                          32u * 1024u, 16u * 1024u) == 0;
  if (!result.ok) {
    (void)fprintf(stderr, "slow receiver setup failed\n");
  }
  wall_start = fn_bench_monotonic_ns();
  while (result.ok && !paused && offset < bytes && turns++ < 100000u) {
    size_t length = (size_t)(bytes - offset);
    fn_io_result_t io;
    if (length > sizeof(sent)) {
      length = sizeof(sent);
    }
    payload_fill(sent, length, seed, offset);
    io = fn_socket_write(slow.left_peer, sent, length, FN_STAGE_RELAY);
    if (io.result.code == FN_OK) {
      offset += io.transferred;
    } else if (io.result.code != FN_AGAIN) {
      result.ok = false;
    }
    if (pump(environment) != 0 ||
        fn_relay_snapshot(slow_completion.relay,
                          &snapshot).code != FN_OK) {
      result.ok = false;
    }
    if ((double)snapshot.left_to_right_queued > result.max_buffer_bytes) {
      result.max_buffer_bytes = (double)snapshot.left_to_right_queued;
    }
    paused = snapshot.left_read_paused;
  }
  if (result.ok && paused) {
    uint64_t peer_bytes = bytes < 1048576u ? bytes : 1048576u;
    result.ok = transfer_direction(environment, peer.left_peer,
                                   peer.right_peer, peer_bytes,
                                   seed + 1u) == 0;
    result.peer_progress_bytes = (double)peer_bytes;
    if (!result.ok) {
      (void)fprintf(stderr, "slow receiver peer progress failed\n");
    }
  } else {
    (void)fprintf(stderr,
                  "slow receiver did not pause: ok=%d offset=%llu turns=%zu "
                  "max_buffer=%.0f\n",
                  result.ok ? 1 : 0, (unsigned long long)offset, turns,
                  result.max_buffer_bytes);
    result.ok = false;
  }
  while (result.ok && received_total < bytes) {
    fn_io_result_t io = fn_socket_read(
      slow.right_peer, received, sizeof(received), FN_STAGE_RELAY);
    if (io.result.code == FN_OK) {
      size_t index;
      unsigned char expected[RELAY_CHUNK_BYTES];
      payload_fill(expected, io.transferred, seed, received_total);
      for (index = 0; index < io.transferred; index++) {
        if (received[index] != expected[index]) {
          (void)fprintf(stderr,
                        "slow receiver payload mismatch at received=%llu "
                        "index=%zu actual=%u expected=%u\n",
                        (unsigned long long)received_total, index,
                        (unsigned int)received[index],
                        (unsigned int)expected[index]);
          result.ok = false;
          break;
        }
      }
      received_total += io.transferred;
      (void)nanosleep(&delay, NULL);
    } else if (io.result.code != FN_AGAIN) {
      (void)fprintf(stderr,
                    "slow receiver read failed: code=%d received=%llu\n",
                    (int)io.result.code,
                    (unsigned long long)received_total);
      result.ok = false;
    }
    if (offset < bytes) {
      size_t length = (size_t)(bytes - offset);
      fn_io_result_t write_result;
      if (length > sizeof(sent)) {
        length = sizeof(sent);
      }
      payload_fill(sent, length, seed, offset);
      write_result = fn_socket_write(
        slow.left_peer, sent, length, FN_STAGE_RELAY);
      if (write_result.result.code == FN_OK) {
        offset += write_result.transferred;
      } else if (write_result.result.code != FN_AGAIN) {
        (void)fprintf(stderr,
                      "slow receiver write failed: code=%d offset=%llu\n",
                      (int)write_result.result.code,
                      (unsigned long long)offset);
        result.ok = false;
      }
    }
    if (pump(environment) != 0 ||
        fn_relay_snapshot(slow_completion.relay,
                          &snapshot).code != FN_OK) {
      (void)fprintf(stderr,
                    "slow receiver pump/snapshot failed at received=%llu\n",
                    (unsigned long long)received_total);
      result.ok = false;
    }
    if ((double)snapshot.left_to_right_queued > result.max_buffer_bytes) {
      result.max_buffer_bytes = (double)snapshot.left_to_right_queued;
    }
  }
  result.wall_seconds =
    (double)(fn_bench_monotonic_ns() - wall_start) / 1000000000.0;
  result.verified_bytes = received_total;
  if (result.ok &&
      fn_budget_snapshot(&environment->memory, &memory).code == FN_OK) {
    result.owned_bytes = (double)memory.total;
  } else {
    (void)fprintf(stderr, "slow receiver memory snapshot failed\n");
    result.ok = false;
  }
  if (result.ok) {
    result.ok = relay_finish(environment, &slow, &slow_completion) == 0 &&
                relay_finish(environment, &peer, &peer_completion) == 0;
    if (!result.ok) {
      (void)fprintf(stderr, "slow receiver relay finish failed\n");
    }
  }
  if (channel_destroy(&slow) != 0 || channel_destroy(&peer) != 0) {
    (void)fprintf(stderr, "slow receiver channel cleanup failed\n");
    result.ok = false;
  }
  return result;
}

static sample_result_t sample_reclaim(relay_environment_t *environment,
                                      uint64_t iterations)
{
  sample_result_t result = {0};
  uint64_t wall_start = fn_bench_monotonic_ns();
  uint64_t index;
  double peak = 0.0;
  result.ok = true;
  for (index = 0; result.ok && index < iterations; index++) {
    relay_channel_t channel;
    relay_completion_t completion;
    fn_budget_snapshot_t memory;
    size_t turns;
    result.ok = channel_init(environment, &channel, 0) == 0 &&
                relay_start(environment, &channel, &completion,
                            32u * 1024u, 16u * 1024u) == 0 &&
                fn_budget_snapshot(&environment->memory,
                                   &memory).code == FN_OK;
    if (result.ok && (double)memory.total > peak) {
      peak = (double)memory.total;
    }
    if (result.ok) {
      result.ok = fn_relay_cancel(completion.relay).code == FN_OK;
    }
    for (turns = 0; result.ok && completion.calls == 0u && turns < 64u;
         turns++) {
      result.ok = pump(environment) == 0;
    }
    if (completion.calls != 1u || channel_destroy(&channel) != 0) {
      result.ok = false;
    }
  }
  result.wall_seconds =
    (double)(fn_bench_monotonic_ns() - wall_start) / 1000000000.0;
  result.owned_bytes = peak;
  result.fd_count = (double)process_fd_count();
  return result;
}

static int record_throughput(fn_bench_case_t *bench_case,
                             const sample_result_t *sample)
{
  double gib = (double)sample->verified_bytes / 1073741824.0;
  if (!sample->ok || sample->wall_seconds <= 0.0 || gib <= 0.0 ||
      fn_bench_case_add(bench_case, "bytes/s", "higher-is-better",
                        (double)sample->verified_bytes /
                        sample->wall_seconds) != 0 ||
      fn_bench_case_add(bench_case, "cpu_seconds", "lower-is-better",
                        sample->cpu_seconds) != 0 ||
      fn_bench_case_add(bench_case, "cpu_seconds/GiB", "lower-is-better",
                        sample->cpu_seconds / gib) != 0) {
    return -1;
  }
  return 0;
}

int main(int argc, char **argv)
{
  static const fn_bench_plan_expectation_t expected[] = {
    {301u, PLAN_THROUGHPUT, 1048576u, 134217728u, 2u, 2u,
     RELAY_CHUNK_BYTES, RELAY_CHUNK_BYTES},
    {302u, PLAN_THROUGHPUT, 1048576u, 134217728u, 2u, 2u,
     RELAY_CHUNK_BYTES, RELAY_CHUNK_BYTES},
    {303u, PLAN_THROUGHPUT, 1048576u, 16777216u, 1u, 1u, 1u, 100u},
    {304u, PLAN_ITERATIONS, 1u, 1000000u, 0u, 0u, 0u, 0u},
  };
  fn_bench_args_t args;
  fn_bench_plan_t plan;
  fn_bench_case_t cases[4];
  relay_environment_t environment;
  uint64_t overall_start;
  uint32_t case_index;
  memset(cases, 0, sizeof(cases));
  cases[0].name = "native_socket_bidirectional";
  cases[0].phase = "steady";
  cases[1].name = "in_process_bidirectional";
  cases[1].phase = "steady";
  cases[2].name = "slow_receiver";
  cases[2].phase = "steady";
  cases[3].name = "relay_reclaim";
  cases[3].phase = "reclaim";
  if (fn_bench_parse_args(argc, argv, &args) != 0 ||
      fn_bench_plan_load(&args, RELAY_TARGET_ID, expected,
                         sizeof(expected) / sizeof(expected[0]),
                         &plan) != 0 ||
      environment_init(&environment) != 0) {
    return 1;
  }
  overall_start = fn_bench_monotonic_ns();
  for (case_index = 0; case_index < plan.case_count; case_index++) {
    uint32_t round;
    for (round = 0; round < args.warmup_count + args.sample_count; round++) {
      sample_result_t sample;
      if (case_index == 0u) {
        sample = sample_native(plan.records[0].primary,
                               plan.records[0].secondary,
                               args.seed + round);
      } else if (case_index == 1u) {
        sample = sample_in_process(&environment, plan.records[1].primary,
                                   plan.records[1].secondary,
                                   args.seed + round);
      } else if (case_index == 2u) {
        sample = sample_slow(&environment, plan.records[2].primary,
                             plan.records[2].tertiary,
                             args.seed + round);
      } else {
        sample = sample_reclaim(&environment, plan.records[3].primary);
      }
      if (!sample.ok) {
        (void)fprintf(stderr,
                      "relay benchmark sample failed: case=%u round=%u\n",
                      case_index, round);
        goto fail;
      }
      if (round >= args.warmup_count) {
        if ((case_index < 2u &&
             record_throughput(&cases[case_index], &sample) != 0) ||
            (case_index == 2u &&
             (fn_bench_case_add(&cases[2], "bytes/s", "higher-is-better",
                                (double)sample.verified_bytes /
                                sample.wall_seconds) != 0 ||
              fn_bench_case_add(&cases[2], "max_buffer_bytes",
                                "lower-is-better",
                                sample.max_buffer_bytes) != 0 ||
              fn_bench_case_add(&cases[2], "peer_progress_bytes",
                                "higher-is-better",
                                sample.peer_progress_bytes) != 0 ||
              fn_bench_case_add(&cases[2], "owned_bytes",
                                "lower-is-better",
                                sample.owned_bytes) != 0)) ||
            (case_index == 3u &&
             (fn_bench_case_add(&cases[3], "ns/op", "lower-is-better",
                                sample.wall_seconds * 1000000000.0 /
                                (double)plan.records[3].primary) != 0 ||
              fn_bench_case_add(&cases[3], "owned_bytes",
                                "lower-is-better",
                                sample.owned_bytes) != 0 ||
              fn_bench_case_add(&cases[3], "fd_count", "lower-is-better",
                                sample.fd_count) != 0))) {
          goto fail;
        }
      }
    }
    cases[case_index].behavior_ok = true;
    cases[case_index].cleanup_ok = true;
  }
  if (environment_destroy(&environment) != 0) {
    (void)fprintf(stderr, "relay benchmark environment cleanup failed\n");
    return 1;
  }
  return fn_bench_write_target(
    &args, &plan, "relay", cases, 4u,
    fn_bench_monotonic_ns() - overall_start) == 0 ? 0 : 1;

fail:
  if (environment_destroy(&environment) != 0) {
    (void)fprintf(stderr,
                  "relay benchmark failure cleanup did not reach zero\n");
  }
  return 1;
}
