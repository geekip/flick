#include "bench_common.h"

#include "flicknet/address.h"
#include "flicknet/loop.h"
#include "flicknet/resolver.h"
#include "flicknet/resource.h"

#include <stdlib.h>
#include <string.h>

enum {
  DNS_TARGET_ID = 3,
  PLAN_ITERATIONS = 1,
};

typedef struct {
  fn_limits_t limits;
  fn_budget_t memory;
  fn_budget_t file_descriptors;
  fn_loop_t *loop;
  fn_dns_config_t config;
  fn_dns_query_t query;
} dns_environment_t;

typedef struct {
  unsigned char *a_answer;
  size_t a_answer_length;
  unsigned char *cname_answer;
  size_t cname_answer_length;
  unsigned char *truncated;
  size_t truncated_length;
  unsigned char *nxdomain;
  size_t nxdomain_length;
} dns_fixtures_t;

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

static int fixtures_load(const char *directory, dns_fixtures_t *fixtures)
{
  memset(fixtures, 0, sizeof(*fixtures));
  return (fixture_read(directory, "dns-a-success.bin",
                       &fixtures->a_answer,
                       &fixtures->a_answer_length) == 0 &&
          fixture_read(directory, "dns-cname-then-a.bin",
                       &fixtures->cname_answer,
                       &fixtures->cname_answer_length) == 0 &&
          fixture_read(directory, "dns-udp-truncated.bin",
                       &fixtures->truncated,
                       &fixtures->truncated_length) == 0 &&
          fixture_read(directory, "dns-nxdomain.bin",
                       &fixtures->nxdomain,
                       &fixtures->nxdomain_length) == 0) ? 0 : -1;
}

static void fixtures_destroy(dns_fixtures_t *fixtures)
{
  fn_bench_free_file(&fixtures->a_answer);
  fn_bench_free_file(&fixtures->cname_answer);
  fn_bench_free_file(&fixtures->truncated);
  fn_bench_free_file(&fixtures->nxdomain);
}

static int environment_init(dns_environment_t *environment)
{
  fn_loop_options_t options;
  fn_domain_t question;
  memset(environment, 0, sizeof(*environment));
  environment->limits = fn_limits_default();
  environment->limits.resolver_pending_limit = 64u;
  if (fn_budget_init(&environment->memory,
                     environment->limits.owned_memory_limit_bytes,
                     environment->limits.cleanup_reserve_bytes).code !=
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
  environment->config.enable = true;
  environment->config.direct_present = true;
  environment->config.direct_count = 1u;
  environment->config.direct[0].transport = FN_DNS_TRANSPORT_UDP;
  environment->config.direct[0].endpoint.address = v4(127u, 0u, 0u, 1u);
  environment->config.direct[0].endpoint.port = 9u;
  environment->config.timeout_ms = 1000u;
  environment->config.attempts = 2u;
  environment->config.failure_cache_size = 64u;
  environment->config.failure_cache_ttl_ms = 1000u;
  if (fn_domain_from_bytes(&question, (const uint8_t *)"example.org",
                           strlen("example.org")).code != FN_OK ||
      fn_dns_query_build(&question, UINT16_C(0x1234),
                         &environment->query).code != FN_OK) {
    return -1;
  }
  return 0;
}

static int environment_destroy(dns_environment_t *environment)
{
  fn_budget_snapshot_t memory;
  fn_budget_snapshot_t file_descriptors;
  if (fn_loop_destroy(&environment->loop).code != FN_OK ||
      fn_budget_snapshot(&environment->memory, &memory).code != FN_OK ||
      fn_budget_snapshot(&environment->file_descriptors,
                         &file_descriptors).code != FN_OK ||
      memory.total != 0u || file_descriptors.total != 0u) {
    return -1;
  }
  return 0;
}

static int resolver_create(dns_environment_t *environment,
                           fn_resolver_t **out)
{
  fn_resolver_options_t options;
  memset(&options, 0, sizeof(options));
  options.loop = environment->loop;
  options.limits = &environment->limits;
  options.owned_memory = &environment->memory;
  options.file_descriptors = &environment->file_descriptors;
  options.allocator = fn_allocator_system();
  options.config = environment->config;
  options.generation = 1u;
  options.require_route_guard = false;
  return fn_resolver_create(&options, out).code == FN_OK ? 0 : -1;
}

static bool parse_expected(dns_environment_t *environment,
                           const unsigned char *message, size_t length,
                           fn_dns_transport_t transport,
                           fn_dns_parse_action_t action,
                           fn_status_t status)
{
  fn_dns_parse_result_t result;
  return fn_dns_response_parse(message, length, transport,
                               &environment->query, &result).code == FN_OK &&
         result.action == action && result.result.code == status;
}

static sample_result_t sample_parse(dns_environment_t *environment,
                                    const unsigned char *message,
                                    size_t length,
                                    fn_dns_parse_action_t action,
                                    fn_status_t status,
                                    uint64_t iterations)
{
  sample_result_t result = {0};
  uint64_t wall_start = fn_bench_monotonic_ns();
  uint64_t cpu_start = fn_bench_process_cpu_ns();
  uint64_t index;
  result.ok = true;
  for (index = 0; result.ok && index < iterations; index++) {
    result.ok = parse_expected(environment, message, length,
                               FN_DNS_TRANSPORT_UDP, action, status);
  }
  result.wall_per_operation =
    (double)(fn_bench_monotonic_ns() - wall_start) / (double)iterations;
  result.cpu_per_operation =
    (double)(fn_bench_process_cpu_ns() - cpu_start) / (double)iterations;
  return result;
}

static sample_result_t sample_fallback(dns_environment_t *environment,
                                       const dns_fixtures_t *fixtures,
                                       uint64_t iterations)
{
  sample_result_t result = {0};
  uint64_t wall_start = fn_bench_monotonic_ns();
  uint64_t cpu_start = fn_bench_process_cpu_ns();
  uint64_t index;
  double peak = 0.0;
  result.ok = true;
  for (index = 0; result.ok && index < iterations; index++) {
    fn_resolver_t *resolver = NULL;
    fn_budget_snapshot_t memory;
    result.ok = resolver_create(environment, &resolver) == 0 &&
                parse_expected(environment, fixtures->truncated,
                               fixtures->truncated_length,
                               FN_DNS_TRANSPORT_UDP,
                               FN_DNS_PARSE_TCP_FALLBACK, FN_OK) &&
                parse_expected(environment, fixtures->a_answer,
                               fixtures->a_answer_length,
                               FN_DNS_TRANSPORT_TCP,
                               FN_DNS_PARSE_ANSWER, FN_OK) &&
                fn_budget_snapshot(&environment->memory,
                                   &memory).code == FN_OK;
    if (result.ok && (double)memory.total > peak) {
      peak = (double)memory.total;
    }
    if (resolver != NULL && fn_resolver_destroy(&resolver).code != FN_OK) {
      result.ok = false;
    }
  }
  result.wall_per_operation =
    (double)(fn_bench_monotonic_ns() - wall_start) / (double)iterations;
  result.cpu_per_operation =
    (double)(fn_bench_process_cpu_ns() - cpu_start) / (double)iterations;
  result.owned_bytes = peak;
  return result;
}

static sample_result_t sample_reclaim(dns_environment_t *environment,
                                      uint64_t iterations)
{
  sample_result_t result = {0};
  uint64_t wall_start = fn_bench_monotonic_ns();
  uint64_t index;
  double peak = 0.0;
  result.ok = true;
  for (index = 0; result.ok && index < iterations; index++) {
    fn_resolver_t *resolver = NULL;
    fn_budget_snapshot_t memory;
    result.ok = resolver_create(environment, &resolver) == 0 &&
                fn_budget_snapshot(&environment->memory,
                                   &memory).code == FN_OK;
    if (result.ok && (double)memory.total > peak) {
      peak = (double)memory.total;
    }
    if (resolver != NULL && fn_resolver_destroy(&resolver).code != FN_OK) {
      result.ok = false;
    }
  }
  result.wall_per_operation =
    (double)(fn_bench_monotonic_ns() - wall_start) / (double)iterations;
  result.owned_bytes = peak;
  return result;
}

static int record_parse(fn_bench_case_t *bench_case,
                        const sample_result_t *sample,
                        bool owned, bool cpu)
{
  if (!sample->ok ||
      fn_bench_case_add(bench_case,
                        strcmp(bench_case->name, "resolver_reclaim") == 0 ?
                          "ns/op" : "ns/query",
                        "lower-is-better",
                        sample->wall_per_operation) != 0 ||
      (cpu && fn_bench_case_add(bench_case, "cpu_ns/query",
                                "lower-is-better",
                                sample->cpu_per_operation) != 0) ||
      (owned && fn_bench_case_add(bench_case, "owned_bytes",
                                  "lower-is-better",
                                  sample->owned_bytes) != 0)) {
    return -1;
  }
  return 0;
}

int main(int argc, char **argv)
{
  static const fn_bench_plan_expectation_t expected[] = {
    {201u, PLAN_ITERATIONS, 1u, 10000000u, 0u, 0u, 0u, 0u},
    {202u, PLAN_ITERATIONS, 1u, 10000000u, 0u, 0u, 0u, 0u},
    {203u, PLAN_ITERATIONS, 1u, 1000000u, 0u, 0u, 0u, 0u},
    {204u, PLAN_ITERATIONS, 1u, 10000000u, 0u, 0u, 0u, 0u},
    {205u, PLAN_ITERATIONS, 1u, 1000000u, 0u, 0u, 0u, 0u},
  };
  fn_bench_args_t args;
  fn_bench_plan_t plan;
  fn_bench_case_t cases[5];
  dns_environment_t environment;
  dns_fixtures_t fixtures;
  uint64_t overall_start;
  uint32_t case_index;
  memset(cases, 0, sizeof(cases));
  cases[0].name = "parse_a_answer";
  cases[0].phase = "steady";
  cases[1].name = "parse_cname_then_a";
  cases[1].phase = "steady";
  cases[2].name = "resolver_udp_tc_tcp_fallback";
  cases[2].phase = "first_lazy";
  cases[3].name = "parse_nxdomain";
  cases[3].phase = "steady";
  cases[4].name = "resolver_reclaim";
  cases[4].phase = "reclaim";
  if (fn_bench_parse_args(argc, argv, &args) != 0 ||
      fn_bench_plan_load(&args, DNS_TARGET_ID, expected,
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
      sample_result_t sample;
      if (case_index == 0u) {
        sample = sample_parse(&environment, fixtures.a_answer,
                              fixtures.a_answer_length,
                              FN_DNS_PARSE_ANSWER, FN_OK,
                              plan.records[case_index].primary);
      } else if (case_index == 1u) {
        sample = sample_parse(&environment, fixtures.cname_answer,
                              fixtures.cname_answer_length,
                              FN_DNS_PARSE_ANSWER, FN_OK,
                              plan.records[case_index].primary);
      } else if (case_index == 2u) {
        sample = sample_fallback(&environment, &fixtures,
                                 plan.records[case_index].primary);
      } else if (case_index == 3u) {
        sample = sample_parse(&environment, fixtures.nxdomain,
                              fixtures.nxdomain_length,
                              FN_DNS_PARSE_TERMINAL, FN_RESOLVE_ERROR,
                              plan.records[case_index].primary);
      } else {
        sample = sample_reclaim(&environment,
                                plan.records[case_index].primary);
      }
      if (!sample.ok ||
          (round >= args.warmup_count &&
           record_parse(&cases[case_index], &sample,
                        case_index == 2u || case_index == 4u,
                        case_index != 4u) != 0)) {
        goto fail;
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
    &args, &plan, "dns", cases, 5u,
    fn_bench_monotonic_ns() - overall_start) == 0 ? 0 : 1;

fail:
  (void)environment_destroy(&environment);
  fixtures_destroy(&fixtures);
  return 1;
}
