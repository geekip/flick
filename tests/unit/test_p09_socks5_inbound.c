#include "flicknet/clock.h"
#include "flicknet/resolver.h"
#include "flicknet/socks5.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      (void)fprintf(stderr, "check failed: %s:%d: %s\n", __FILE__,          \
                    __LINE__, #condition);                                     \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

typedef struct {
  fn_limits_t limits;
  fn_budget_t memory;
  fn_budget_t buffers;
  fn_budget_t file_descriptors;
  fn_loop_t *loop;
} test_environment_t;

typedef enum {
  CHUNK_WHOLE = 0,
  CHUNK_ONE,
  CHUNK_DECLARED
} chunk_mode_t;

static uint64_t deadline_after(uint64_t duration_ms)
{
  uint64_t now_ms;
  uint64_t deadline_ms;
  CHECK(fn_monotonic_now_ms(&now_ms).code == FN_OK);
  CHECK(fn_deadline_after_ms(now_ms, duration_ms, &deadline_ms).code == FN_OK);
  return deadline_ms;
}

static fn_result_t result_make(fn_status_t code, fn_error_stage_t stage,
                               fn_error_origin_t origin, int native_code)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE : stage,
                        origin, (int64_t)native_code);
}

static void environment_init(test_environment_t *environment,
                             size_t handshake_limit, size_t buffer_limit)
{
  fn_loop_options_t options;
  memset(environment, 0, sizeof(*environment));
  environment->limits = fn_limits_default();
  environment->limits.handshake_limit = handshake_limit;
  environment->limits.buffer_pool_limit_bytes = buffer_limit;
  CHECK(fn_budget_init(&environment->memory,
                       environment->limits.owned_memory_limit_bytes,
                       environment->limits.cleanup_reserve_bytes).code ==
        FN_OK);
  CHECK(fn_budget_init(&environment->buffers, buffer_limit, 0).code == FN_OK);
  CHECK(fn_budget_init(&environment->file_descriptors,
                       environment->limits.fd_limit, 0).code == FN_OK);
  memset(&options, 0, sizeof(options));
  options.limits = &environment->limits;
  options.owned_memory = &environment->memory;
  options.file_descriptors = &environment->file_descriptors;
  options.allocator = fn_allocator_system();
  options.dispatch_limit = 64u;
  CHECK(fn_loop_create(&options, &environment->loop).code == FN_OK);
}

static void environment_destroy(test_environment_t *environment)
{
  fn_budget_snapshot_t snapshot;
  CHECK(fn_loop_destroy(&environment->loop).code == FN_OK);
  CHECK(fn_budget_snapshot(&environment->memory, &snapshot).code == FN_OK);
  CHECK(snapshot.total == 0u);
  CHECK(fn_budget_snapshot(&environment->buffers, &snapshot).code == FN_OK);
  CHECK(snapshot.total == 0u);
  CHECK(fn_budget_snapshot(&environment->file_descriptors,
                           &snapshot).code == FN_OK);
  CHECK(snapshot.total == 0u);
}

static fn_socks5_inbound_manager_t *manager_create(
  test_environment_t *environment, const fn_user_config_t *users,
  size_t user_count)
{
  fn_socks5_inbound_manager_options_t options;
  fn_socks5_inbound_manager_t *manager = NULL;
  memset(&options, 0, sizeof(options));
  options.loop = environment->loop;
  options.limits = &environment->limits;
  options.owned_memory = &environment->memory;
  options.buffer_bytes = &environment->buffers;
  options.allocator = fn_allocator_system();
  options.users = users;
  options.user_count = user_count;
  CHECK(fn_socks5_inbound_manager_create(&options, &manager).code == FN_OK);
  return manager;
}

static fn_socks5_inbound_t *inbound_open(
  fn_socks5_inbound_manager_t *manager)
{
  fn_socks5_inbound_t *inbound = NULL;
  CHECK(fn_socks5_inbound_open(manager, deadline_after(UINT64_C(5000)),
                               &inbound).code == FN_OK);
  CHECK(inbound != NULL);
  return inbound;
}

static void capture_output(fn_socks5_inbound_t *inbound, bool one_byte,
                           uint8_t *captured, size_t capacity,
                           size_t *captured_length)
{
  const uint8_t *data;
  size_t length;
  fn_result_t result;
  for (;;) {
    result = fn_socks5_inbound_output_peek(inbound, &data, &length);
    if (result.code == FN_AGAIN) {
      return;
    }
    CHECK(result.code == FN_OK);
    if (one_byte) {
      length = 1u;
    }
    CHECK(length <= capacity - *captured_length);
    memcpy(captured + *captured_length, data, length);
    *captured_length += length;
    CHECK(fn_socks5_inbound_output_consume(inbound, length).code == FN_OK);
  }
}

static size_t next_chunk(chunk_mode_t mode, const size_t *declared,
                         size_t declared_count, size_t *declared_index,
                         size_t remaining)
{
  size_t chunk;
  if (mode == CHUNK_ONE) {
    return 1u;
  }
  if (mode == CHUNK_WHOLE) {
    return remaining;
  }
  CHECK(*declared_index < declared_count);
  chunk = declared[(*declared_index)++];
  CHECK(chunk != 0 && chunk <= remaining);
  return chunk;
}

static void check_target(const fn_endpoint_t *target,
                         const char *domain, const uint8_t v4[4],
                         uint16_t port)
{
  CHECK(target->port == port);
  if (domain != NULL) {
    CHECK(target->address.kind == FN_ADDR_DOMAIN);
    CHECK(target->address.value.domain.length == strlen(domain));
    CHECK(memcmp(target->address.value.domain.bytes, domain,
                 strlen(domain)) == 0);
  } else {
    CHECK(target->address.kind == FN_ADDR_V4);
    CHECK(memcmp(target->address.value.v4, v4, 4u) == 0);
  }
}

static void run_success_case(
  fn_socks5_inbound_manager_t *manager,
  const uint8_t *input, size_t input_length,
  chunk_mode_t mode, const size_t *declared, size_t declared_count,
  const uint8_t *expected_output, size_t expected_output_length,
  size_t output_before_connect,
  const char *domain, const uint8_t v4[4], uint16_t port,
  const uint8_t *preread, size_t preread_length)
{
  const fn_endpoint_t bound = {
    .address = {.kind = FN_ADDR_V4,
                .value.v4 = {192u, 0u, 2u, 10u}},
    .port = UINT16_C(50000),
  };
  fn_socks5_inbound_t *inbound = inbound_open(manager);
  fn_socks5_inbound_snapshot_t snapshot;
  fn_endpoint_t target;
  uint8_t output[64];
  size_t output_length = 0;
  size_t input_offset = 0;
  size_t declared_index = 0;
  bool injected = false;
  size_t guard;

  for (guard = 0; guard < 10000u; guard++) {
    size_t consumed;
    size_t chunk;
    capture_output(inbound, mode == CHUNK_ONE,
                   output, sizeof(output), &output_length);
    CHECK(fn_socks5_inbound_snapshot(inbound, &snapshot).code == FN_OK);
    if (snapshot.state == FN_SOCKS5_OUTBOUND_WAIT && !injected &&
        input_offset == input_length) {
      const uint8_t *unavailable_preread;
      size_t unavailable_length;
      CHECK(output_length == output_before_connect);
      CHECK(fn_socks5_inbound_target(inbound, &target).code == FN_OK);
      check_target(&target, domain, v4, port);
      CHECK(fn_socks5_inbound_preread_peek(
              inbound, &unavailable_preread,
              &unavailable_length).code == FN_INVALID);
      CHECK(fn_socks5_inbound_connect_result(
              inbound, result_make(FN_OK, FN_STAGE_NONE,
                                   FN_ERROR_ORIGIN_NONE, 0),
              &bound).code == FN_OK);
      injected = true;
      continue;
    }
    if (input_offset < input_length) {
      chunk = next_chunk(mode, declared, declared_count, &declared_index,
                         input_length - input_offset);
      CHECK(fn_socks5_inbound_feed(inbound, input + input_offset, chunk,
                                   &consumed).code == FN_OK);
      CHECK(consumed == chunk);
      input_offset += consumed;
      continue;
    }
    capture_output(inbound, mode == CHUNK_ONE,
                   output, sizeof(output), &output_length);
    CHECK(fn_socks5_inbound_snapshot(inbound, &snapshot).code == FN_OK);
    if (snapshot.state == FN_SOCKS5_RELAY) {
      break;
    }
  }
  CHECK(guard < 10000u);
  CHECK(injected);
  CHECK(output_length == expected_output_length);
  CHECK(memcmp(output, expected_output, expected_output_length) == 0);
  CHECK(snapshot.terminal_result.code == FN_OK);
  if (preread_length != 0) {
    const uint8_t *borrowed;
    size_t borrowed_length;
    CHECK(fn_socks5_inbound_preread_peek(
            inbound, &borrowed, &borrowed_length).code == FN_OK);
    CHECK(borrowed_length == preread_length);
    CHECK(memcmp(borrowed, preread, preread_length) == 0);
    CHECK(fn_socks5_inbound_preread_consume(
            inbound, borrowed_length).code == FN_OK);
  }
  CHECK(fn_socks5_inbound_release(&inbound).code == FN_OK);
}

static void run_failure_case(
  fn_socks5_inbound_manager_t *manager,
  const uint8_t *input, size_t input_length,
  chunk_mode_t mode, const size_t *declared, size_t declared_count,
  const uint8_t *expected_output, size_t expected_output_length,
  fn_status_t expected_status, fn_error_stage_t expected_stage)
{
  fn_socks5_inbound_t *inbound = inbound_open(manager);
  fn_socks5_inbound_snapshot_t snapshot;
  uint8_t output[32];
  size_t output_length = 0;
  size_t input_offset = 0;
  size_t declared_index = 0;
  size_t guard;

  for (guard = 0; guard < 10000u; guard++) {
    size_t chunk;
    size_t consumed;
    capture_output(inbound, mode == CHUNK_ONE,
                   output, sizeof(output), &output_length);
    CHECK(fn_socks5_inbound_snapshot(inbound, &snapshot).code == FN_OK);
    if (snapshot.state == FN_SOCKS5_CLOSED) {
      break;
    }
    if (input_offset < input_length) {
      chunk = next_chunk(mode, declared, declared_count, &declared_index,
                         input_length - input_offset);
      CHECK(fn_socks5_inbound_feed(inbound, input + input_offset, chunk,
                                   &consumed).code == FN_OK);
      CHECK(consumed == chunk);
      input_offset += consumed;
      continue;
    }
    CHECK(false);
  }
  CHECK(guard < 10000u);
  CHECK(output_length == expected_output_length);
  CHECK(memcmp(output, expected_output, expected_output_length) == 0);
  CHECK(snapshot.terminal_result.code == expected_status);
  CHECK(snapshot.terminal_result.stage == expected_stage);
  CHECK(fn_socks5_inbound_release(&inbound).code == FN_OK);
}

static void test_manifest_success_cases(void)
{
  const uint8_t no_auth_input[] = {
    0x05, 0x01, 0x00,
    0x05, 0x01, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x50,
    0x47, 0x45, 0x54,
  };
  const uint8_t no_auth_output[] = {
    0x05, 0x00,
    0x05, 0x00, 0x00, 0x01, 0xc0, 0x00, 0x02, 0x0a, 0xc3, 0x50,
  };
  const size_t no_auth_splits[] = {1u, 1u, 1u, 4u, 1u, 3u, 2u, 3u};
  const uint8_t auth_input[] = {
    0x05, 0x02, 0x00, 0x02,
    0x01, 0x05, 'a', 'l', 'i', 'c', 'e', 0x06,
    's', 'e', 'c', 'r', 'e', 't',
    0x05, 0x01, 0x00, 0x03, 0x0b,
    'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'o', 'r', 'g',
    0x01, 0xbb, 0x16, 0x03,
  };
  const uint8_t auth_output[] = {
    0x05, 0x02, 0x01, 0x00,
    0x05, 0x00, 0x00, 0x01, 0xc0, 0x00, 0x02, 0x0a, 0xc3, 0x50,
  };
  const size_t auth_splits[] = {
    2u, 2u, 1u, 1u, 5u, 1u, 6u, 4u, 1u, 11u, 2u, 2u,
  };
  const uint8_t v4[4] = {127u, 0u, 0u, 1u};
  const uint8_t preread_get[] = {0x47, 0x45, 0x54};
  const uint8_t preread_tls[] = {0x16, 0x03};
  test_environment_t environment;
  fn_socks5_inbound_manager_t *manager;
  fn_user_config_t user;
  chunk_mode_t mode;

  environment_init(&environment, 16u, 1u << 20u);
  manager = manager_create(&environment, NULL, 0);
  for (mode = CHUNK_WHOLE; mode <= CHUNK_DECLARED; mode++) {
    run_success_case(manager, no_auth_input, sizeof(no_auth_input), mode,
                     no_auth_splits,
                     sizeof(no_auth_splits) / sizeof(no_auth_splits[0]),
                     no_auth_output, sizeof(no_auth_output), 2u,
                     NULL, v4, UINT16_C(80),
                     preread_get, sizeof(preread_get));
  }
  CHECK(fn_socks5_inbound_manager_destroy(&manager).code == FN_OK);

  memset(&user, 0, sizeof(user));
  user.username_length = 5u;
  user.password_length = 6u;
  memcpy(user.username, "alice", 5u);
  memcpy(user.password, "secret", 6u);
  manager = manager_create(&environment, &user, 1u);
  for (mode = CHUNK_WHOLE; mode <= CHUNK_DECLARED; mode++) {
    run_success_case(manager, auth_input, sizeof(auth_input), mode,
                     auth_splits,
                     sizeof(auth_splits) / sizeof(auth_splits[0]),
                     auth_output, sizeof(auth_output), 4u,
                     "example.org", NULL, UINT16_C(443),
                     preread_tls, sizeof(preread_tls));
  }
  CHECK(fn_socks5_inbound_manager_destroy(&manager).code == FN_OK);
  environment_destroy(&environment);
}

static void test_manifest_failure_cases(void)
{
  const uint8_t method_input[] = {0x05, 0x01, 0x01};
  const uint8_t downgrade_input[] = {0x05, 0x01, 0x00};
  const uint8_t method_failure[] = {0x05, 0xff};
  const uint8_t auth_input[] = {
    0x05, 0x01, 0x02,
    0x01, 0x05, 'a', 'l', 'i', 'c', 'e', 0x06,
    'w', 'r', 'o', 'n', 'g', '!',
  };
  const uint8_t auth_failure[] = {0x05, 0x02, 0x01, 0x01};
  const uint8_t bind_input[] = {
    0x05, 0x01, 0x00,
    0x05, 0x02, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x50,
  };
  const uint8_t bind_output[] = {
    0x05, 0x00,
    0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  const uint8_t ipv6_input[] = {
    0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x04,
  };
  const uint8_t ipv6_output[] = {
    0x05, 0x00,
    0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  const size_t method_splits[] = {1u, 1u, 1u};
  const size_t auth_splits[] = {1u, 2u, 2u, 5u, 1u, 6u};
  const size_t bind_splits[] = {3u, 4u, 6u};
  const size_t ipv6_splits[] = {3u, 4u};
  test_environment_t environment;
  fn_socks5_inbound_manager_t *manager;
  fn_user_config_t user;
  chunk_mode_t mode;

  environment_init(&environment, 16u, 1u << 20u);
  manager = manager_create(&environment, NULL, 0);
  for (mode = CHUNK_WHOLE; mode <= CHUNK_DECLARED; mode++) {
    run_failure_case(manager, method_input, sizeof(method_input), mode,
                     method_splits, 3u, method_failure,
                     sizeof(method_failure), FN_AUTH_ERROR,
                     FN_STAGE_SOCKS_AUTH);
    run_failure_case(manager, bind_input, sizeof(bind_input), mode,
                     bind_splits, 3u, bind_output, sizeof(bind_output),
                     FN_UNSUPPORTED, FN_STAGE_INBOUND_HANDSHAKE);
    run_failure_case(manager, ipv6_input, sizeof(ipv6_input), mode,
                     ipv6_splits, 2u, ipv6_output, sizeof(ipv6_output),
                     FN_UNSUPPORTED, FN_STAGE_INBOUND_HANDSHAKE);
  }
  CHECK(fn_socks5_inbound_manager_destroy(&manager).code == FN_OK);

  memset(&user, 0, sizeof(user));
  user.username_length = 5u;
  user.password_length = 6u;
  memcpy(user.username, "alice", 5u);
  memcpy(user.password, "secret", 6u);
  manager = manager_create(&environment, &user, 1u);
  for (mode = CHUNK_WHOLE; mode <= CHUNK_DECLARED; mode++) {
    run_failure_case(manager, downgrade_input, sizeof(downgrade_input), mode,
                     method_splits, 3u, method_failure,
                     sizeof(method_failure), FN_AUTH_ERROR,
                     FN_STAGE_SOCKS_AUTH);
    run_failure_case(manager, auth_input, sizeof(auth_input), mode,
                     auth_splits, 6u, auth_failure,
                     sizeof(auth_failure), FN_AUTH_ERROR,
                     FN_STAGE_SOCKS_AUTH);
  }
  CHECK(fn_socks5_inbound_manager_destroy(&manager).code == FN_OK);
  environment_destroy(&environment);
}

static void test_maximum_fields_and_preread(void)
{
  test_environment_t environment;
  fn_socks5_inbound_manager_t *manager;
  fn_socks5_inbound_t *inbound;
  fn_user_config_t user;
  fn_socks5_inbound_snapshot_t snapshot;
  fn_endpoint_t bound;
  uint8_t input[3u + 513u + 10u];
  uint8_t payload[FN_SOCKS5_PREREAD_MAX];
  const uint8_t *output;
  size_t output_length;
  size_t consumed;
  size_t offset = 0;

  memset(&user, 0, sizeof(user));
  user.username_length = UINT8_MAX;
  user.password_length = UINT8_MAX;
  memset(user.username, 'u', UINT8_MAX);
  memset(user.password, 'p', UINT8_MAX);
  input[offset++] = 0x05;
  input[offset++] = 0x01;
  input[offset++] = 0x02;
  input[offset++] = 0x01;
  input[offset++] = 0xff;
  memset(input + offset, 'u', UINT8_MAX);
  offset += UINT8_MAX;
  input[offset++] = 0xff;
  memset(input + offset, 'p', UINT8_MAX);
  offset += UINT8_MAX;
  memcpy(input + offset,
         (const uint8_t[]){0x05, 0x01, 0x00, 0x01,
                           127u, 0u, 0u, 1u, 0x00, 0x50}, 10u);
  offset += 10u;
  CHECK(offset == sizeof(input));

  environment_init(&environment, 2u, FN_SOCKS5_PREREAD_MAX * 2u);
  manager = manager_create(&environment, &user, 1u);
  inbound = inbound_open(manager);
  CHECK(fn_socks5_inbound_feed(inbound, input, sizeof(input),
                               &consumed).code == FN_OK);
  CHECK(consumed == sizeof(input));
  CHECK(fn_socks5_inbound_output_peek(inbound, &output,
                                      &output_length).code == FN_OK);
  CHECK(output_length == 2u && output[1] == 0x02);
  CHECK(fn_socks5_inbound_output_consume(inbound, output_length).code == FN_OK);
  CHECK(fn_socks5_inbound_output_peek(inbound, &output,
                                      &output_length).code == FN_OK);
  CHECK(output_length == 2u && output[1] == 0x00);
  CHECK(fn_socks5_inbound_output_consume(inbound, output_length).code == FN_OK);
  CHECK(fn_socks5_inbound_snapshot(inbound, &snapshot).code == FN_OK);
  CHECK(snapshot.state == FN_SOCKS5_OUTBOUND_WAIT);

  memset(payload, 0xa5, sizeof(payload));
  CHECK(fn_socks5_inbound_feed(inbound, payload, sizeof(payload),
                               &consumed).code == FN_OK);
  CHECK(consumed == sizeof(payload));
  CHECK(fn_socks5_inbound_feed(inbound, payload, 1u,
                               &consumed).code == FN_AGAIN);
  CHECK(consumed == 0u);
  bound.address.kind = FN_ADDR_V4;
  memcpy(bound.address.value.v4,
         (const uint8_t[]){192u, 0u, 2u, 1u}, 4u);
  bound.port = UINT16_C(40000);
  CHECK(fn_socks5_inbound_connect_result(
          inbound, result_make(FN_OK, FN_STAGE_NONE,
                               FN_ERROR_ORIGIN_NONE, 0),
          &bound).code == FN_OK);
  CHECK(fn_socks5_inbound_snapshot(inbound, &snapshot).code == FN_OK);
  CHECK(snapshot.state == FN_SOCKS5_CONNECT_REPLY_WRITE);
  CHECK(fn_socks5_inbound_output_peek(inbound, &output,
                                      &output_length).code == FN_OK);
  CHECK(fn_socks5_inbound_output_consume(inbound, output_length).code == FN_OK);
  CHECK(fn_socks5_inbound_snapshot(inbound, &snapshot).code == FN_OK);
  CHECK(snapshot.state == FN_SOCKS5_RELAY);
  CHECK(snapshot.preread_bytes == FN_SOCKS5_PREREAD_MAX);
  CHECK(fn_socks5_inbound_release(&inbound).code == FN_OK);
  CHECK(fn_socks5_inbound_manager_destroy(&manager).code == FN_OK);
  environment_destroy(&environment);
}

static void test_domain_limit_deadline_and_resources(void)
{
  test_environment_t environment;
  fn_socks5_inbound_manager_t *manager;
  fn_socks5_inbound_t *inbound;
  fn_socks5_inbound_snapshot_t snapshot;
  fn_endpoint_t target;
  uint8_t domain[253];
  uint8_t request[260];
  const uint8_t *output;
  size_t output_length;
  size_t consumed;
  size_t index;
  size_t cursor = 0;

  for (index = 0; index < sizeof(domain); index++) {
    domain[index] = 'a';
  }
  domain[63] = '.';
  domain[127] = '.';
  domain[191] = '.';
  request[cursor++] = 0x05;
  request[cursor++] = 0x01;
  request[cursor++] = 0x00;
  request[cursor++] = 0x03;
  request[cursor++] = 0xfd;
  memcpy(request + cursor, domain, sizeof(domain));
  cursor += sizeof(domain);
  request[cursor++] = 0x01;
  request[cursor++] = 0xbb;
  CHECK(cursor == sizeof(request));

  environment_init(&environment, 1u, 4096u);
  manager = manager_create(&environment, NULL, 0);
  inbound = inbound_open(manager);
  CHECK(fn_socks5_inbound_feed(
          inbound, (const uint8_t[]){0x05, 0x01, 0x00}, 3u,
          &consumed).code == FN_OK);
  CHECK(fn_socks5_inbound_output_peek(inbound, &output,
                                      &output_length).code == FN_OK);
  CHECK(fn_socks5_inbound_output_consume(inbound, output_length).code == FN_OK);
  CHECK(fn_socks5_inbound_feed(inbound, request, sizeof(request),
                               &consumed).code == FN_OK);
  CHECK(consumed == sizeof(request));
  CHECK(fn_socks5_inbound_target(inbound, &target).code == FN_OK);
  CHECK(target.address.kind == FN_ADDR_DOMAIN);
  CHECK(target.address.value.domain.length == sizeof(domain));
  CHECK(target.port == UINT16_C(443));
  CHECK(fn_socks5_inbound_release(&inbound).code == FN_OK);

  inbound = inbound_open(manager);
  CHECK(fn_socks5_inbound_feed(inbound,
                               (const uint8_t[]){0x05}, 1u,
                               &consumed).code == FN_OK);
  CHECK(fn_socks5_inbound_eof(inbound).code == FN_OK);
  CHECK(fn_socks5_inbound_snapshot(inbound, &snapshot).code == FN_OK);
  CHECK(snapshot.state == FN_SOCKS5_CLOSED);
  CHECK(snapshot.terminal_result.code == FN_PROTOCOL_ERROR);
  CHECK(fn_socks5_inbound_release(&inbound).code == FN_OK);

  CHECK(fn_socks5_inbound_open(manager, deadline_after(UINT64_C(5000)),
                               &inbound).code == FN_OK);
  CHECK(fn_socks5_inbound_check_deadline(inbound, UINT64_MAX).code == FN_OK);
  CHECK(fn_socks5_inbound_snapshot(inbound, &snapshot).code == FN_OK);
  CHECK(snapshot.state == FN_SOCKS5_CLOSED);
  CHECK(snapshot.terminal_result.code == FN_TIMEOUT);
  CHECK(fn_socks5_inbound_release(&inbound).code == FN_OK);
  CHECK(fn_socks5_inbound_manager_destroy(&manager).code == FN_OK);
  environment_destroy(&environment);

  environment_init(&environment, 0u, 4096u);
  manager = manager_create(&environment, NULL, 0);
  CHECK(fn_socks5_inbound_open(manager, deadline_after(UINT64_C(5000)),
                               &inbound).code == FN_LIMIT);
  CHECK(inbound == NULL);
  CHECK(fn_socks5_inbound_manager_destroy(&manager).code == FN_OK);
  environment_destroy(&environment);

  environment_init(&environment, 1u, 0u);
  manager = manager_create(&environment, NULL, 0);
  inbound = inbound_open(manager);
  CHECK(fn_socks5_inbound_feed(
          inbound,
          (const uint8_t[]){0x05, 0x01, 0x00,
                            0x05, 0x01, 0x00, 0x01,
                            127u, 0u, 0u, 1u, 0x00, 0x50, 0x41},
          14u, &consumed).code == FN_OK);
  CHECK(consumed == 14u);
  CHECK(fn_socks5_inbound_output_peek(inbound, &output,
                                      &output_length).code == FN_OK);
  CHECK(fn_socks5_inbound_output_consume(inbound, output_length).code == FN_OK);
  CHECK(fn_socks5_inbound_snapshot(inbound, &snapshot).code == FN_OK);
  CHECK(snapshot.state == FN_SOCKS5_FAIL_REPLY_WRITE);
  CHECK(snapshot.terminal_result.code == FN_LIMIT);
  CHECK(fn_socks5_inbound_release(&inbound).code == FN_OK);
  CHECK(fn_socks5_inbound_manager_destroy(&manager).code == FN_OK);
  environment_destroy(&environment);
}

static void test_reply_mapping(void)
{
  CHECK(fn_socks5_reply_from_result(
          result_make(FN_REJECTED, FN_STAGE_ROUTE,
                      FN_ERROR_ORIGIN_NONE, 0)) ==
        FN_SOCKS5_REP_RULESET_DENIED);
  CHECK(fn_socks5_reply_from_result(
          result_make(FN_CONNECT_ERROR, FN_STAGE_TCP_CONNECT,
                      FN_ERROR_ORIGIN_POSIX, ENETUNREACH)) ==
        FN_SOCKS5_REP_NETWORK_UNREACHABLE);
  CHECK(fn_socks5_reply_from_result(
          result_make(FN_CONNECT_ERROR, FN_STAGE_TCP_CONNECT,
                      FN_ERROR_ORIGIN_POSIX, EHOSTUNREACH)) ==
        FN_SOCKS5_REP_HOST_UNREACHABLE);
  CHECK(fn_socks5_reply_from_result(
          result_make(FN_RESOLVE_ERROR, FN_STAGE_RESOLVE,
                      FN_ERROR_ORIGIN_DNS, 3)) ==
        FN_SOCKS5_REP_HOST_UNREACHABLE);
  CHECK(fn_socks5_reply_from_result(
          result_make(FN_TIMEOUT, FN_STAGE_TCP_CONNECT,
                      FN_ERROR_ORIGIN_NONE, 0)) ==
        FN_SOCKS5_REP_HOST_UNREACHABLE);
  CHECK(fn_socks5_reply_from_result(
          result_make(FN_CONNECTION_REFUSED, FN_STAGE_TCP_CONNECT,
                      FN_ERROR_ORIGIN_POSIX, ECONNREFUSED)) ==
        FN_SOCKS5_REP_CONNECTION_REFUSED);
  CHECK(fn_socks5_reply_from_result(
          result_make(FN_NO_MEMORY, FN_STAGE_RESOURCE,
                      FN_ERROR_ORIGIN_NONE, 0)) ==
        FN_SOCKS5_REP_GENERAL_FAILURE);
}

static void advance_to_outbound_wait(fn_socks5_inbound_t *inbound)
{
  static const uint8_t request[] = {
    0x05, 0x01, 0x00,
    0x05, 0x01, 0x00, 0x01, 127u, 0u, 0u, 1u, 0x00, 0x50,
  };
  fn_socks5_inbound_snapshot_t snapshot;
  const uint8_t *output;
  size_t output_length;
  size_t consumed;

  CHECK(fn_socks5_inbound_feed(inbound, request, sizeof(request),
                               &consumed).code == FN_OK);
  CHECK(consumed == sizeof(request));
  CHECK(fn_socks5_inbound_output_peek(inbound, &output,
                                      &output_length).code == FN_OK);
  CHECK(output_length == 2u);
  CHECK(output[0] == 0x05 && output[1] == 0x00);
  CHECK(fn_socks5_inbound_output_consume(inbound, output_length).code ==
        FN_OK);
  CHECK(fn_socks5_inbound_snapshot(inbound, &snapshot).code == FN_OK);
  CHECK(snapshot.state == FN_SOCKS5_OUTBOUND_WAIT);
}

static void test_connect_failure_cancel_and_bad_version(void)
{
  static const uint8_t refused_reply[] = {
    0x05, 0x05, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
  };
  test_environment_t environment;
  fn_socks5_inbound_manager_t *manager;
  fn_socks5_inbound_t *inbound;
  fn_socks5_inbound_snapshot_t snapshot;
  fn_endpoint_t bound;
  const uint8_t *output;
  size_t output_length;
  size_t consumed;

  environment_init(&environment, 4u, 4096u);
  manager = manager_create(&environment, NULL, 0);

  inbound = inbound_open(manager);
  advance_to_outbound_wait(inbound);
  CHECK(fn_socks5_inbound_connect_result(
          inbound,
          result_make(FN_CONNECTION_REFUSED, FN_STAGE_TCP_CONNECT,
                      FN_ERROR_ORIGIN_POSIX, ECONNREFUSED),
          NULL).code == FN_OK);
  CHECK(fn_socks5_inbound_output_peek(inbound, &output,
                                      &output_length).code == FN_OK);
  CHECK(output_length == sizeof(refused_reply));
  CHECK(memcmp(output, refused_reply, sizeof(refused_reply)) == 0);
  CHECK(fn_socks5_inbound_output_consume(inbound, 3u).code == FN_OK);
  CHECK(fn_socks5_inbound_snapshot(inbound, &snapshot).code == FN_OK);
  CHECK(snapshot.state == FN_SOCKS5_FAIL_REPLY_WRITE);
  CHECK(snapshot.output_bytes == sizeof(refused_reply) - 3u);
  CHECK(snapshot.terminal_result.code == FN_CONNECTION_REFUSED);
  CHECK(fn_socks5_inbound_output_consume(
          inbound, sizeof(refused_reply) - 3u).code == FN_OK);
  CHECK(fn_socks5_inbound_snapshot(inbound, &snapshot).code == FN_OK);
  CHECK(snapshot.state == FN_SOCKS5_CLOSED);
  CHECK(snapshot.terminal_result.code == FN_CONNECTION_REFUSED);
  CHECK(fn_socks5_inbound_release(&inbound).code == FN_OK);

  inbound = inbound_open(manager);
  advance_to_outbound_wait(inbound);
  memset(&bound, 0, sizeof(bound));
  bound.address.kind = FN_ADDR_V4;
  memcpy(bound.address.value.v4,
         (const uint8_t[]){192u, 0u, 2u, 25u}, 4u);
  bound.port = UINT16_C(41000);
  CHECK(fn_socks5_inbound_connect_result(
          inbound,
          result_make(FN_OK, FN_STAGE_NONE, FN_ERROR_ORIGIN_NONE, 0),
          &bound).code == FN_OK);
  CHECK(fn_socks5_inbound_snapshot(inbound, &snapshot).code == FN_OK);
  CHECK(snapshot.state == FN_SOCKS5_CONNECT_REPLY_WRITE);
  CHECK(snapshot.terminal_result.code == FN_OK);
  CHECK(fn_socks5_inbound_cancel(inbound).code == FN_OK);
  CHECK(fn_socks5_inbound_snapshot(inbound, &snapshot).code == FN_OK);
  CHECK(snapshot.state == FN_SOCKS5_CLOSED);
  CHECK(snapshot.output_bytes == 0u);
  CHECK(snapshot.terminal_result.code == FN_CANCELLED);
  CHECK(fn_socks5_inbound_output_peek(inbound, &output,
                                      &output_length).code == FN_AGAIN);
  CHECK(fn_socks5_inbound_release(&inbound).code == FN_OK);

  inbound = inbound_open(manager);
  CHECK(fn_socks5_inbound_feed(
          inbound, (const uint8_t[]){0x04, 0x01, 0x00}, 3u,
          &consumed).code == FN_OK);
  CHECK(consumed == 3u);
  CHECK(fn_socks5_inbound_snapshot(inbound, &snapshot).code == FN_OK);
  CHECK(snapshot.state == FN_SOCKS5_CLOSED);
  CHECK(snapshot.output_bytes == 0u);
  CHECK(snapshot.terminal_result.code == FN_PROTOCOL_ERROR);
  CHECK(snapshot.terminal_result.stage == FN_STAGE_INBOUND_HANDSHAKE);
  CHECK(fn_socks5_inbound_release(&inbound).code == FN_OK);

  CHECK(fn_socks5_inbound_manager_destroy(&manager).code == FN_OK);
  environment_destroy(&environment);
}

int main(void)
{
  test_manifest_success_cases();
  test_manifest_failure_cases();
  test_maximum_fields_and_preread();
  test_domain_limit_deadline_and_resources();
  test_reply_mapping();
  test_connect_failure_cancel_and_bad_version();
  (void)puts("p09 socks5 inbound tests passed");
  return 0;
}
