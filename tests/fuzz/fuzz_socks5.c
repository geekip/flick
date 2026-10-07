#include "flicknet/socks5.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
  fn_limits_t limits;
  fn_budget_t memory;
  fn_budget_t file_descriptors;
  fn_budget_t buffers;
  fn_loop_t *loop;
  fn_socks5_inbound_manager_t *no_auth;
  fn_socks5_inbound_manager_t *with_auth;
  fn_user_config_t user;
  bool initialized;
} fuzz_environment_t;

static fuzz_environment_t environment;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static fn_result_t fuzz_result(fn_status_t code, fn_error_stage_t stage)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE : stage,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static void fuzz_require(bool condition)
{
  if (!condition) {
    __builtin_trap();
  }
}

static int hex_value(uint8_t byte)
{
  if (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') {
    return (int)(byte - (uint8_t)'0');
  }
  if (byte >= (uint8_t)'a' && byte <= (uint8_t)'f') {
    return (int)(byte - (uint8_t)'a') + 10;
  }
  if (byte >= (uint8_t)'A' && byte <= (uint8_t)'F') {
    return (int)(byte - (uint8_t)'A') + 10;
  }
  return -1;
}

static bool decode_seed(const uint8_t *data, size_t size,
                        uint8_t *decoded, size_t capacity,
                        const uint8_t **out_data, size_t *out_size)
{
  size_t index;
  size_t length;
  if (size < 4u || memcmp(data, "hex:", 4u) != 0 ||
      ((size - 4u) & 1u) != 0) {
    *out_data = data;
    *out_size = size;
    return true;
  }
  length = (size - 4u) / 2u;
  if (length > capacity) {
    return false;
  }
  for (index = 0; index < length; index++) {
    int high = hex_value(data[4u + index * 2u]);
    int low = hex_value(data[5u + index * 2u]);
    if (high < 0 || low < 0) {
      *out_data = data;
      *out_size = size;
      return true;
    }
    decoded[index] = (uint8_t)(((unsigned)high << 4u) | (unsigned)low);
  }
  *out_data = decoded;
  *out_size = length;
  return true;
}

static void environment_init(void)
{
  fn_loop_options_t loop_options;
  fn_socks5_inbound_manager_options_t manager_options;
  if (environment.initialized) {
    return;
  }
  memset(&environment, 0, sizeof(environment));
  environment.limits = fn_limits_default();
  environment.limits.handshake_limit = 4u;
  environment.limits.owned_memory_limit_bytes = 4u * 1024u * 1024u;
  environment.limits.cleanup_reserve_bytes = 256u * 1024u;
  environment.limits.buffer_pool_limit_bytes = 2u * 1024u * 1024u;
  fuzz_require(fn_budget_init(
    &environment.memory, environment.limits.owned_memory_limit_bytes,
    environment.limits.cleanup_reserve_bytes).code == FN_OK);
  fuzz_require(fn_budget_init(&environment.file_descriptors,
                              environment.limits.fd_limit, 0u).code == FN_OK);
  fuzz_require(fn_budget_init(
    &environment.buffers, environment.limits.buffer_pool_limit_bytes,
    0u).code == FN_OK);
  memset(&loop_options, 0, sizeof(loop_options));
  loop_options.limits = &environment.limits;
  loop_options.owned_memory = &environment.memory;
  loop_options.file_descriptors = &environment.file_descriptors;
  loop_options.allocator = fn_allocator_system();
  loop_options.dispatch_limit = 8u;
  fuzz_require(fn_loop_create(&loop_options, &environment.loop).code == FN_OK);

  memset(&manager_options, 0, sizeof(manager_options));
  manager_options.loop = environment.loop;
  manager_options.limits = &environment.limits;
  manager_options.owned_memory = &environment.memory;
  manager_options.buffer_bytes = &environment.buffers;
  manager_options.allocator = fn_allocator_system();
  fuzz_require(fn_socks5_inbound_manager_create(
    &manager_options, &environment.no_auth).code == FN_OK);

  memcpy(environment.user.username, "alice", sizeof("alice") - 1u);
  environment.user.username_length = 5u;
  memcpy(environment.user.password, "secret", sizeof("secret") - 1u);
  environment.user.password_length = 6u;
  manager_options.users = &environment.user;
  manager_options.user_count = 1u;
  fuzz_require(fn_socks5_inbound_manager_create(
    &manager_options, &environment.with_auth).code == FN_OK);
  environment.initialized = true;
}

static void drain_output(fn_socks5_inbound_t *inbound)
{
  const uint8_t *output = NULL;
  size_t length = 0;
  fn_result_t result = fn_socks5_inbound_output_peek(inbound, &output,
                                                      &length);
  fuzz_require(result.code == FN_OK || result.code == FN_AGAIN);
  if (result.code == FN_AGAIN) {
    fuzz_require(output == NULL);
    fuzz_require(length == 0u);
    return;
  }
  if (length != 0u) {
    fuzz_require(output != NULL);
    fuzz_require(fn_socks5_inbound_output_consume(inbound,
                                                   length).code == FN_OK);
  }
}

static void drain_preread(fn_socks5_inbound_t *inbound)
{
  const uint8_t *input = NULL;
  size_t length = 0;
  fn_result_t result = fn_socks5_inbound_preread_peek(inbound,
                                                       &input, &length);
  if (result.code == FN_OK && length != 0u) {
    fuzz_require(input != NULL);
    fuzz_require(fn_socks5_inbound_preread_consume(inbound,
                                                    length).code == FN_OK);
  }
}

static void fuzz_one(fn_socks5_inbound_manager_t *manager,
                     const uint8_t *data, size_t size)
{
  fn_budget_snapshot_t memory_before;
  fn_budget_snapshot_t buffers_before;
  fn_budget_snapshot_t memory_after;
  fn_budget_snapshot_t buffers_after;
  fn_socks5_inbound_t *inbound = NULL;
  fn_socks5_inbound_snapshot_t snapshot;
  fn_endpoint_t bound;
  fn_addr_t bound_address;
  const uint8_t bound_bytes[4] = {127u, 0u, 0u, 1u};
  size_t offset = 0;
  size_t turns;

  fuzz_require(fn_budget_snapshot(&environment.memory,
                                  &memory_before).code == FN_OK);
  fuzz_require(fn_budget_snapshot(&environment.buffers,
                                  &buffers_before).code == FN_OK);
  fuzz_require(fn_socks5_inbound_open(manager, UINT64_MAX,
                                      &inbound).code == FN_OK);
  fuzz_require(fn_addr_from_v4(&bound_address, bound_bytes).code == FN_OK);
  fuzz_require(fn_endpoint_make(&bound, &bound_address, 12345u).code == FN_OK);

  for (turns = 0; turns < size + 32u; turns++) {
    size_t consumed = 0;
    fn_result_t result;
    drain_output(inbound);
    fuzz_require(fn_socks5_inbound_snapshot(inbound,
                                            &snapshot).code == FN_OK);
    if (snapshot.state == FN_SOCKS5_OUTBOUND_WAIT) {
      fn_result_t outcome = size != 0u && (data[size - 1u] & 1u) != 0u ?
        fuzz_result(FN_CONNECTION_REFUSED, FN_STAGE_TCP_CONNECT) :
        fuzz_result(FN_OK, FN_STAGE_NONE);
      result = fn_socks5_inbound_connect_result(
        inbound, outcome, outcome.code == FN_OK ? &bound : NULL);
      fuzz_require(result.code == FN_OK);
      continue;
    }
    if (snapshot.state == FN_SOCKS5_RELAY) {
      drain_preread(inbound);
      break;
    }
    if (snapshot.state == FN_SOCKS5_CLOSED || offset >= size) {
      break;
    }
    result = fn_socks5_inbound_feed(inbound, data + offset,
                                    size - offset, &consumed);
    offset += consumed;
    if (result.code != FN_OK || consumed == 0u) {
      drain_output(inbound);
      break;
    }
  }
  drain_output(inbound);
  drain_preread(inbound);
  (void)fn_socks5_inbound_eof(inbound);
  (void)fn_socks5_inbound_cancel(inbound);
  fuzz_require(fn_socks5_inbound_release(&inbound).code == FN_OK);
  fuzz_require(fn_budget_snapshot(&environment.memory,
                                  &memory_after).code == FN_OK);
  fuzz_require(fn_budget_snapshot(&environment.buffers,
                                  &buffers_after).code == FN_OK);
  fuzz_require(memory_after.total == memory_before.total);
  fuzz_require(buffers_after.total == buffers_before.total);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  uint8_t decoded[33024];
  const uint8_t *input;
  size_t input_size;
  environment_init();
  if (!decode_seed(data, size, decoded, sizeof(decoded),
                   &input, &input_size)) {
    return 0;
  }
  fuzz_one(environment.no_auth, input, input_size);
  fuzz_one(environment.with_auth, input, input_size);
  return 0;
}
