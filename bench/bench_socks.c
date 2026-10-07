#include "bench_common.h"

#include "flicknet/address.h"
#include "flicknet/clock.h"
#include "flicknet/loop.h"
#include "flicknet/resource.h"
#include "flicknet/socks5.h"

#include <stdlib.h>
#include <string.h>

enum {
  SOCKS_TARGET_ID = 2,
  PLAN_ITERATIONS = 1,
};

typedef struct {
  fn_limits_t limits;
  fn_budget_t memory;
  fn_budget_t buffers;
  fn_budget_t file_descriptors;
  fn_loop_t *loop;
  fn_socks5_inbound_manager_t *no_auth;
  fn_socks5_inbound_manager_t *with_auth;
  fn_user_config_t user;
} socks_environment_t;

typedef struct {
  unsigned char *no_auth_greeting;
  size_t no_auth_greeting_length;
  unsigned char *no_auth_request;
  size_t no_auth_request_length;
  unsigned char *auth_greeting;
  size_t auth_greeting_length;
  unsigned char *auth_credentials;
  size_t auth_credentials_length;
  unsigned char *auth_request;
  size_t auth_request_length;
} socks_fixtures_t;

typedef struct {
  double wall_per_operation;
  double cpu_per_operation;
  double owned_bytes;
  bool ok;
} sample_result_t;

static fn_addr_t v4(unsigned int a, unsigned int b,
                    unsigned int c, unsigned int d)
{
  fn_addr_t address;
  const uint8_t bytes[4] = {
    (uint8_t)a, (uint8_t)b, (uint8_t)c, (uint8_t)d,
  };
  memset(&address, 0, sizeof(address));
  if (fn_addr_from_v4(&address, bytes).code != FN_OK) {
    memset(&address, 0, sizeof(address));
  }
  return address;
}

static int fixture_read(const char *directory, const char *name,
                        unsigned char **data, size_t *length)
{
  char path[4096];
  int written = snprintf(path, sizeof(path), "%s/%s", directory, name);
  if (written < 0 || (size_t)written >= sizeof(path)) {
    return -1;
  }
  return fn_bench_read_file(path, data, length);
}

static int fixtures_load(const char *directory, socks_fixtures_t *fixtures)
{
  memset(fixtures, 0, sizeof(*fixtures));
  if (fixture_read(directory, "socks-no-auth-greeting.bin",
                   &fixtures->no_auth_greeting,
                   &fixtures->no_auth_greeting_length) != 0 ||
      fixture_read(directory, "socks-no-auth-request.bin",
                   &fixtures->no_auth_request,
                   &fixtures->no_auth_request_length) != 0 ||
      fixture_read(directory, "socks-auth-greeting.bin",
                   &fixtures->auth_greeting,
                   &fixtures->auth_greeting_length) != 0 ||
      fixture_read(directory, "socks-auth-credentials.bin",
                   &fixtures->auth_credentials,
                   &fixtures->auth_credentials_length) != 0 ||
      fixture_read(directory, "socks-auth-request.bin",
                   &fixtures->auth_request,
                   &fixtures->auth_request_length) != 0) {
    return -1;
  }
  return 0;
}

static void fixtures_destroy(socks_fixtures_t *fixtures)
{
  fn_bench_free_file(&fixtures->no_auth_greeting);
  fn_bench_free_file(&fixtures->no_auth_request);
  fn_bench_free_file(&fixtures->auth_greeting);
  fn_bench_free_file(&fixtures->auth_credentials);
  fn_bench_free_file(&fixtures->auth_request);
}

static int manager_create(socks_environment_t *environment,
                          const fn_user_config_t *users, size_t user_count,
                          fn_socks5_inbound_manager_t **out)
{
  fn_socks5_inbound_manager_options_t options;
  memset(&options, 0, sizeof(options));
  options.loop = environment->loop;
  options.limits = &environment->limits;
  options.owned_memory = &environment->memory;
  options.buffer_bytes = &environment->buffers;
  options.allocator = fn_allocator_system();
  options.users = users;
  options.user_count = user_count;
  return fn_socks5_inbound_manager_create(&options, out).code == FN_OK ?
    0 : -1;
}

static int environment_init(socks_environment_t *environment)
{
  fn_loop_options_t options;
  memset(environment, 0, sizeof(*environment));
  environment->limits = fn_limits_default();
  environment->limits.handshake_limit = 256u;
  environment->limits.buffer_pool_limit_bytes = 32u * 1024u * 1024u;
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
  memset(&options, 0, sizeof(options));
  options.limits = &environment->limits;
  options.owned_memory = &environment->memory;
  options.file_descriptors = &environment->file_descriptors;
  options.allocator = fn_allocator_system();
  options.dispatch_limit = 64u;
  if (fn_loop_create(&options, &environment->loop).code != FN_OK) {
    return -1;
  }
  memcpy(environment->user.username, "alice", sizeof("alice"));
  environment->user.username_length = 5u;
  memcpy(environment->user.password, "secret", sizeof("secret"));
  environment->user.password_length = 6u;
  if (manager_create(environment, NULL, 0u, &environment->no_auth) != 0 ||
      manager_create(environment, &environment->user, 1u,
                     &environment->with_auth) != 0) {
    return -1;
  }
  return 0;
}

static int environment_destroy(socks_environment_t *environment)
{
  fn_budget_snapshot_t memory;
  fn_budget_snapshot_t buffers;
  fn_budget_snapshot_t file_descriptors;
  int status = 0;
  if (fn_socks5_inbound_manager_destroy(&environment->no_auth).code != FN_OK ||
      fn_socks5_inbound_manager_destroy(
        &environment->with_auth).code != FN_OK ||
      fn_loop_destroy(&environment->loop).code != FN_OK) {
    status = -1;
  }
  if (fn_budget_snapshot(&environment->memory, &memory).code != FN_OK ||
      fn_budget_snapshot(&environment->buffers, &buffers).code != FN_OK ||
      fn_budget_snapshot(&environment->file_descriptors,
                         &file_descriptors).code != FN_OK ||
      memory.total != 0u || buffers.total != 0u ||
      file_descriptors.total != 0u) {
    status = -1;
  }
  return status;
}

static int drain_output(fn_socks5_inbound_t *inbound, size_t expected)
{
  size_t total = 0;
  for (;;) {
    const uint8_t *data = NULL;
    size_t length = 0;
    fn_result_t result = fn_socks5_inbound_output_peek(
      inbound, &data, &length);
    if (result.code == FN_AGAIN) {
      break;
    }
    if (result.code != FN_OK || data == NULL || length == 0u ||
        fn_socks5_inbound_output_consume(inbound, length).code != FN_OK) {
      return -1;
    }
    total += length;
  }
  return total == expected ? 0 : -1;
}

static int feed_all(fn_socks5_inbound_t *inbound,
                    const unsigned char *data, size_t length)
{
  size_t offset = 0;
  while (offset < length) {
    size_t consumed = 0;
    if (fn_socks5_inbound_feed(inbound, data + offset,
                               length - offset, &consumed).code != FN_OK ||
        consumed == 0u) {
      return -1;
    }
    offset += consumed;
  }
  return 0;
}

static int handshake_once(socks_environment_t *environment,
                          const socks_fixtures_t *fixtures, bool auth,
                          double *owned_peak)
{
  fn_socks5_inbound_manager_t *manager = auth ? environment->with_auth :
                                               environment->no_auth;
  fn_socks5_inbound_t *inbound = NULL;
  fn_endpoint_t target;
  fn_endpoint_t bound;
  fn_budget_snapshot_t memory;
  const uint8_t *preread = NULL;
  size_t preread_length = 0;
  uint64_t now_ms;
  if (fn_monotonic_now_ms(&now_ms).code != FN_OK ||
      fn_socks5_inbound_open(manager, now_ms + UINT64_C(5000),
                             &inbound).code != FN_OK) {
    return -1;
  }
  if (auth) {
    if (feed_all(inbound, fixtures->auth_greeting,
                 fixtures->auth_greeting_length) != 0 ||
        drain_output(inbound, 2u) != 0 ||
        feed_all(inbound, fixtures->auth_credentials,
                 fixtures->auth_credentials_length) != 0 ||
        drain_output(inbound, 2u) != 0 ||
        feed_all(inbound, fixtures->auth_request,
                 fixtures->auth_request_length) != 0) {
      (void)fn_socks5_inbound_release(&inbound);
      return -1;
    }
  } else if (feed_all(inbound, fixtures->no_auth_greeting,
                      fixtures->no_auth_greeting_length) != 0 ||
             drain_output(inbound, 2u) != 0 ||
             feed_all(inbound, fixtures->no_auth_request,
                      fixtures->no_auth_request_length) != 0) {
    (void)fn_socks5_inbound_release(&inbound);
    return -1;
  }
  if (fn_socks5_inbound_target(inbound, &target).code != FN_OK) {
    (void)fn_socks5_inbound_release(&inbound);
    return -1;
  }
  bound.address = auth ? v4(192u, 0u, 2u, 20u) :
                         v4(192u, 0u, 2u, 10u);
  bound.port = auth ? 49152u : 50000u;
  if (fn_socks5_inbound_connect_result(
        inbound,
        fn_result_make(FN_OK, FN_STAGE_NONE, FN_ERROR_ORIGIN_NONE, 0),
        &bound).code != FN_OK ||
      drain_output(inbound, 10u) != 0 ||
      fn_socks5_inbound_preread_peek(
        inbound, &preread, &preread_length).code != FN_OK ||
      preread == NULL || preread_length != (auth ? 2u : 3u) ||
      fn_budget_snapshot(&environment->memory, &memory).code != FN_OK) {
    (void)fn_socks5_inbound_release(&inbound);
    return -1;
  }
  if ((double)memory.total > *owned_peak) {
    *owned_peak = (double)memory.total;
  }
  if (fn_socks5_inbound_preread_consume(
        inbound, preread_length).code != FN_OK ||
      fn_socks5_inbound_release(&inbound).code != FN_OK) {
    return -1;
  }
  return 0;
}

static sample_result_t sample_handshake(socks_environment_t *environment,
                                        const socks_fixtures_t *fixtures,
                                        bool auth, uint64_t iterations)
{
  sample_result_t result = {0};
  uint64_t wall_start = fn_bench_monotonic_ns();
  uint64_t cpu_start = fn_bench_process_cpu_ns();
  uint64_t index;
  double peak = 0.0;
  result.ok = true;
  for (index = 0; result.ok && index < iterations; index++) {
    result.ok = handshake_once(environment, fixtures, auth, &peak) == 0;
  }
  result.wall_per_operation =
    (double)(fn_bench_monotonic_ns() - wall_start) / (double)iterations;
  result.cpu_per_operation =
    (double)(fn_bench_process_cpu_ns() - cpu_start) / (double)iterations;
  result.owned_bytes = peak;
  return result;
}

static sample_result_t sample_reclaim(socks_environment_t *environment,
                                      uint64_t iterations)
{
  sample_result_t result = {0};
  uint64_t wall_start = fn_bench_monotonic_ns();
  uint64_t index;
  double peak = 0.0;
  result.ok = true;
  for (index = 0; result.ok && index < iterations; index++) {
    fn_socks5_inbound_t *inbound = NULL;
    fn_budget_snapshot_t memory;
    uint64_t now_ms;
    result.ok = fn_monotonic_now_ms(&now_ms).code == FN_OK &&
                fn_socks5_inbound_open(
                  environment->no_auth, now_ms + UINT64_C(5000),
                  &inbound).code == FN_OK &&
                fn_budget_snapshot(&environment->memory,
                                   &memory).code == FN_OK;
    if (result.ok && (double)memory.total > peak) {
      peak = (double)memory.total;
    }
    if (inbound != NULL &&
        (fn_socks5_inbound_cancel(inbound).code != FN_OK ||
         fn_socks5_inbound_release(&inbound).code != FN_OK)) {
      result.ok = false;
    }
  }
  result.wall_per_operation =
    (double)(fn_bench_monotonic_ns() - wall_start) / (double)iterations;
  result.owned_bytes = peak;
  return result;
}

static int record_handshake(fn_bench_case_t *bench_case,
                            const sample_result_t *sample)
{
  return (!sample->ok ||
          fn_bench_case_add(bench_case, "ns/handshake", "lower-is-better",
                            sample->wall_per_operation) != 0 ||
          fn_bench_case_add(bench_case, "cpu_ns/handshake",
                            "lower-is-better",
                            sample->cpu_per_operation) != 0 ||
          fn_bench_case_add(bench_case, "owned_bytes", "lower-is-better",
                            sample->owned_bytes) != 0) ? -1 : 0;
}

int main(int argc, char **argv)
{
  static const fn_bench_plan_expectation_t expected[] = {
    {101u, PLAN_ITERATIONS, 1u, 1000000u, 0u, 0u, 0u, 0u},
    {102u, PLAN_ITERATIONS, 1u, 1000000u, 0u, 0u, 0u, 0u},
    {103u, PLAN_ITERATIONS, 1u, 1000000u, 0u, 0u, 0u, 0u},
  };
  fn_bench_args_t args;
  fn_bench_plan_t plan;
  fn_bench_case_t cases[3];
  socks_environment_t environment;
  socks_fixtures_t fixtures;
  uint64_t overall_start;
  uint32_t case_index;
  memset(cases, 0, sizeof(cases));
  cases[0].name = "inbound_no_auth_ipv4";
  cases[0].phase = "steady";
  cases[1].name = "inbound_userpass_domain";
  cases[1].phase = "steady";
  cases[2].name = "socks_reclaim";
  cases[2].phase = "reclaim";
  if (fn_bench_parse_args(argc, argv, &args) != 0 ||
      fn_bench_plan_load(&args, SOCKS_TARGET_ID, expected,
                         sizeof(expected) / sizeof(expected[0]),
                         &plan) != 0 ||
      fixtures_load(args.fixture_dir, &fixtures) != 0 ||
      environment_init(&environment) != 0) {
    return 1;
  }
  overall_start = fn_bench_monotonic_ns();
  for (case_index = 0; case_index < plan.case_count; case_index++) {
    uint32_t round;
    for (round = 0; round < args.warmup_count + args.sample_count; round++) {
      sample_result_t sample = case_index < 2u ?
        sample_handshake(&environment, &fixtures, case_index == 1u,
                         plan.records[case_index].primary) :
        sample_reclaim(&environment, plan.records[case_index].primary);
      if (!sample.ok) {
        goto fail;
      }
      if (round >= args.warmup_count) {
        if ((case_index < 2u &&
             record_handshake(&cases[case_index], &sample) != 0) ||
            (case_index == 2u &&
             (fn_bench_case_add(&cases[case_index], "ns/op",
                                "lower-is-better",
                                sample.wall_per_operation) != 0 ||
              fn_bench_case_add(&cases[case_index], "owned_bytes",
                                "lower-is-better",
                                sample.owned_bytes) != 0))) {
          goto fail;
        }
      }
    }
    cases[case_index].behavior_ok = true;
    cases[case_index].cleanup_ok = true;
  }
  if (environment_destroy(&environment) != 0) {
    fixtures_destroy(&fixtures);
    return 1;
  }
  fixtures_destroy(&fixtures);
  return fn_bench_write_target(
    &args, &plan, "socks", cases, 3u,
    fn_bench_monotonic_ns() - overall_start) == 0 ? 0 : 1;

fail:
  (void)environment_destroy(&environment);
  fixtures_destroy(&fixtures);
  return 1;
}
