#include "bench_common.h"

#include "flicknet/address.h"
#include "flicknet/build.h"
#include "flicknet/clock.h"
#include "flicknet/config.h"
#include "flicknet/loop.h"
#include "flicknet/metadata.h"
#include "flicknet/resource.h"
#include "flicknet/router.h"
#include "flicknet/runtime.h"

#include <stdlib.h>
#include <string.h>

enum {
  RULE_TARGET_ID = 1,
  PLAN_ITERATIONS = 1,
};

typedef struct {
  unsigned long token;
} rule_backend_t;

typedef struct {
  fn_limits_t limits;
  fn_budget_t memory;
  fn_budget_t file_descriptors;
  fn_loop_t *loop;
  fn_runtime_manager_t *manager;
  fn_config_t config;
  fn_feature_plan_t feature_plan;
  rule_backend_t backend;
} rule_environment_t;

typedef struct {
  fn_runtime_acquire_t *operation;
  size_t calls;
  fn_result_t result;
} acquire_result_t;

typedef struct {
  double wall_per_operation;
  double cpu_per_operation;
  double owned_bytes;
  bool ok;
} sample_result_t;

static fn_result_t backend_prepare(
  void *context, const fn_runtime_resource_descriptor_t *descriptor,
  void **out_resource)
{
  rule_backend_t *backend = context;
  (void)descriptor;
  *out_resource = &backend->token;
  return fn_result_make(FN_OK, FN_STAGE_NONE, FN_ERROR_ORIGIN_NONE, 0);
}

static fn_result_t backend_lazy_start(void *context, fn_runtime_t *runtime,
                                      fn_object_ref_t object)
{
  rule_backend_t *backend = context;
  fn_result_t ok = fn_result_make(
    FN_OK, FN_STAGE_NONE, FN_ERROR_ORIGIN_NONE, 0);
  return fn_runtime_lazy_finish(runtime, object, ok, &backend->token);
}

static void backend_release(
  void *context, const fn_runtime_resource_descriptor_t *descriptor,
  void *resource)
{
  (void)context;
  (void)descriptor;
  (void)resource;
}

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

static int memory_total(fn_budget_t *budget, double *out)
{
  fn_budget_snapshot_t snapshot;
  if (fn_budget_snapshot(budget, &snapshot).code != FN_OK) {
    return -1;
  }
  *out = (double)snapshot.total;
  return 0;
}

static int environment_init(rule_environment_t *environment,
                            const char *config_path)
{
  unsigned char *config_data = NULL;
  size_t config_length = 0;
  fn_config_error_t error;
  fn_loop_options_t loop_options;
  fn_runtime_manager_options_t manager_options;
  memset(environment, 0, sizeof(*environment));
  if (fn_bench_read_file(config_path, &config_data, &config_length) != 0) {
    return -1;
  }
  memset(&error, 0, sizeof(error));
  if (fn_config_parse(config_data, config_length, fn_allocator_system(),
                      &environment->config, &error).code != FN_OK) {
    fn_bench_free_file(&config_data);
    return -1;
  }
  fn_bench_free_file(&config_data);
  if (fn_config_plan(&environment->config, fn_build_compiled_features(),
                     &environment->feature_plan, &error).code != FN_OK) {
    fn_config_destroy(&environment->config);
    return -1;
  }
  environment->limits = environment->config.limits;
  if (fn_budget_init(&environment->memory,
                     environment->limits.owned_memory_limit_bytes,
                     environment->limits.cleanup_reserve_bytes).code !=
      FN_OK ||
      fn_budget_init(&environment->file_descriptors,
                     environment->limits.fd_limit, 0u).code != FN_OK) {
    fn_config_destroy(&environment->config);
    return -1;
  }
  memset(&loop_options, 0, sizeof(loop_options));
  loop_options.limits = &environment->limits;
  loop_options.owned_memory = &environment->memory;
  loop_options.file_descriptors = &environment->file_descriptors;
  loop_options.allocator = fn_allocator_system();
  loop_options.dispatch_limit = 64u;
  if (fn_loop_create(&loop_options, &environment->loop).code != FN_OK) {
    fn_config_destroy(&environment->config);
    return -1;
  }
  memset(&manager_options, 0, sizeof(manager_options));
  manager_options.loop = environment->loop;
  manager_options.limits = &environment->limits;
  manager_options.owned_memory = &environment->memory;
  manager_options.allocator = fn_allocator_system();
  manager_options.resources.context = &environment->backend;
  manager_options.resources.prepare = backend_prepare;
  manager_options.resources.lazy_start = backend_lazy_start;
  manager_options.resources.release = backend_release;
  if (fn_runtime_manager_create(&manager_options,
                                &environment->manager).code != FN_OK) {
    (void)fn_loop_destroy(&environment->loop);
    fn_config_destroy(&environment->config);
    return -1;
  }
  return 0;
}

static int environment_destroy(rule_environment_t *environment)
{
  fn_budget_snapshot_t memory;
  fn_budget_snapshot_t file_descriptors;
  int ok = 0;
  if (fn_runtime_manager_destroy(&environment->manager).code != FN_OK) {
    ok = -1;
  }
  if (fn_loop_destroy(&environment->loop).code != FN_OK) {
    ok = -1;
  }
  if (fn_budget_snapshot(&environment->memory, &memory).code != FN_OK ||
      fn_budget_snapshot(&environment->file_descriptors,
                         &file_descriptors).code != FN_OK ||
      memory.total != 0u || file_descriptors.total != 0u) {
    ok = -1;
  }
  fn_config_destroy(&environment->config);
  return ok;
}

static int build_commit(rule_environment_t *environment,
                        fn_runtime_t **runtime)
{
  fn_runtime_candidate_t *candidate = NULL;
  if (fn_runtime_candidate_build(
        environment->manager, &environment->config,
        &environment->feature_plan, &candidate).code != FN_OK ||
      fn_runtime_candidate_prepare(candidate).code != FN_OK ||
      fn_runtime_candidate_commit(environment->manager,
                                  &candidate).code != FN_OK ||
      fn_runtime_acquire_active(environment->manager, runtime).code != FN_OK) {
    (void)fn_runtime_candidate_destroy(&candidate);
    return -1;
  }
  return 0;
}

static void acquired(fn_runtime_acquire_t *operation, void *context,
                     fn_result_t result,
                     const fn_runtime_resource_descriptor_t *descriptor,
                     void *resource)
{
  acquire_result_t *value = context;
  (void)descriptor;
  (void)resource;
  value->calls++;
  value->result = result;
  if (value->operation != operation ||
      fn_runtime_acquire_release(&value->operation).code != FN_OK) {
    value->result = fn_result_make(
      FN_INVALID, FN_STAGE_RESOURCE, FN_ERROR_ORIGIN_NONE, 0);
  }
}

static int activate_direct(rule_environment_t *environment,
                           fn_runtime_t *runtime)
{
  fn_object_ref_t direct;
  fn_runtime_acquire_t *operation = NULL;
  acquire_result_t result;
  uint64_t now_ms;
  size_t turns;
  memset(&result, 0, sizeof(result));
  if (fn_runtime_object_find(runtime, FN_RUNTIME_RESOURCE_DIRECT, "DIRECT",
                             &direct).code != FN_OK ||
      fn_monotonic_now_ms(&now_ms).code != FN_OK) {
    return -1;
  }
  result.operation = operation;
  if (fn_runtime_acquire(runtime, direct, now_ms + UINT64_C(10000),
                         acquired, &result, &operation).code != FN_OK) {
    return -1;
  }
  result.operation = operation;
  for (turns = 0; turns < 64u && result.calls == 0u; turns++) {
    if (fn_loop_run_once(environment->loop,
                         FN_LOOP_RUN_NOWAIT).code != FN_OK) {
      return -1;
    }
  }
  return result.calls == 1u && result.result.code == FN_OK ? 0 : -1;
}

static int metadata_ipv4(fn_runtime_t *runtime,
                         fn_session_metadata_t *metadata)
{
  fn_object_ref_t inbound;
  fn_session_metadata_init(metadata, FN_TCP);
  if (fn_runtime_object_find(runtime, FN_RUNTIME_RESOURCE_LISTENER,
                             "socks-in", &inbound).code != FN_OK) {
    return -1;
  }
  metadata->route.inbound = inbound;
  metadata->route.source.address = v4(198u, 51u, 100u, 2u);
  metadata->route.source.port = 40000u;
  metadata->route.original_target.address = v4(192u, 0u, 2u, 1u);
  metadata->route.original_target.port = 443u;
  return 0;
}

static int metadata_domain(fn_runtime_t *runtime,
                           fn_session_metadata_t *metadata)
{
  fn_domain_t domain;
  fn_addr_t domain_address;
  if (metadata_ipv4(runtime, metadata) != 0 ||
      fn_domain_from_bytes(&domain, (const uint8_t *)"example.org",
                           strlen("example.org")).code != FN_OK ||
      fn_addr_from_domain(&domain_address, &domain).code != FN_OK ||
      fn_endpoint_make(&metadata->route.original_target, &domain_address,
                       443u).code != FN_OK ||
      fn_session_metadata_set_domain(metadata, &domain,
                                     FN_DOMAIN_REQUEST).code != FN_OK) {
    return -1;
  }
  metadata->route.source.port = 40001u;
  metadata->dial.resolved.count = 1u;
  metadata->dial.resolved.addresses[0] = v4(192u, 0u, 2u, 1u);
  metadata->dial.resolved.ttl_seconds = 60u;
  return 0;
}

static sample_result_t sample_cold_build(rule_environment_t *environment,
                                         uint64_t iterations)
{
  sample_result_t result = {0};
  uint64_t wall_start = fn_bench_monotonic_ns();
  uint64_t cpu_start = fn_bench_process_cpu_ns();
  uint64_t index;
  double peak = 0.0;
  result.ok = wall_start != 0u && cpu_start != 0u;
  for (index = 0; result.ok && index < iterations; index++) {
    fn_runtime_candidate_t *candidate = NULL;
    double owned = 0.0;
    result.ok = fn_runtime_candidate_build(
      environment->manager, &environment->config,
      &environment->feature_plan, &candidate).code == FN_OK;
    if (result.ok) {
      result.ok = memory_total(&environment->memory, &owned) == 0;
      if (owned > peak) {
        peak = owned;
      }
    }
    if (fn_runtime_candidate_destroy(&candidate).code != FN_OK) {
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

static sample_result_t sample_route(rule_environment_t *environment,
                                    uint64_t iterations, bool domain)
{
  sample_result_t result = {0};
  fn_runtime_t *runtime = NULL;
  fn_session_metadata_t metadata;
  fn_route_result_t route;
  uint64_t wall_start;
  uint64_t cpu_start;
  uint64_t index;
  result.ok = build_commit(environment, &runtime) == 0 &&
              (domain ? metadata_domain(runtime, &metadata) :
                        metadata_ipv4(runtime, &metadata)) == 0;
  wall_start = fn_bench_monotonic_ns();
  cpu_start = fn_bench_process_cpu_ns();
  for (index = 0; result.ok && index < iterations; index++) {
    result.ok = fn_route_evaluate(runtime, &metadata, &route).code == FN_OK &&
                route.status == FN_ROUTE_READY && route.rule_index == 0u;
  }
  result.wall_per_operation =
    (double)(fn_bench_monotonic_ns() - wall_start) / (double)iterations;
  result.cpu_per_operation =
    (double)(fn_bench_process_cpu_ns() - cpu_start) / (double)iterations;
  if (fn_runtime_release(&runtime).code != FN_OK) {
    result.ok = false;
  }
  return result;
}

static sample_result_t sample_first_lazy(rule_environment_t *environment,
                                         uint64_t iterations)
{
  sample_result_t result = {0};
  uint64_t wall_start = fn_bench_monotonic_ns();
  uint64_t cpu_start = fn_bench_process_cpu_ns();
  uint64_t index;
  double peak = 0.0;
  result.ok = true;
  for (index = 0; result.ok && index < iterations; index++) {
    fn_runtime_t *runtime = NULL;
    double owned = 0.0;
    result.ok = build_commit(environment, &runtime) == 0 &&
                activate_direct(environment, runtime) == 0 &&
                memory_total(&environment->memory, &owned) == 0;
    if (owned > peak) {
      peak = owned;
    }
    if (fn_runtime_release(&runtime).code != FN_OK) {
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

static sample_result_t sample_reclaim(rule_environment_t *environment,
                                      uint64_t iterations)
{
  sample_result_t result = {0};
  fn_runtime_t *current = NULL;
  uint64_t wall_start;
  uint64_t cpu_start;
  uint64_t index;
  double peak = 0.0;
  result.ok = build_commit(environment, &current) == 0;
  wall_start = fn_bench_monotonic_ns();
  cpu_start = fn_bench_process_cpu_ns();
  for (index = 0; result.ok && index < iterations; index++) {
    fn_runtime_t *next = NULL;
    double owned = 0.0;
    result.ok = build_commit(environment, &next) == 0 &&
                memory_total(&environment->memory, &owned) == 0;
    if (owned > peak) {
      peak = owned;
    }
    if (fn_runtime_release(&current).code != FN_OK) {
      result.ok = false;
    }
    current = next;
  }
  result.wall_per_operation =
    (double)(fn_bench_monotonic_ns() - wall_start) / (double)iterations;
  result.cpu_per_operation =
    (double)(fn_bench_process_cpu_ns() - cpu_start) / (double)iterations;
  result.owned_bytes = peak;
  if (fn_runtime_release(&current).code != FN_OK) {
    result.ok = false;
  }
  return result;
}

static int record_sample(fn_bench_case_t *bench_case,
                         const sample_result_t *sample, bool owned)
{
  if (!sample->ok ||
      fn_bench_case_add(bench_case, "ns/op", "lower-is-better",
                        sample->wall_per_operation) != 0 ||
      fn_bench_case_add(bench_case, "cpu_ns/op", "lower-is-better",
                        sample->cpu_per_operation) != 0 ||
      (owned && fn_bench_case_add(
        bench_case, "owned_bytes", "lower-is-better",
        sample->owned_bytes) != 0)) {
    return -1;
  }
  return 0;
}

int main(int argc, char **argv)
{
  static const fn_bench_plan_expectation_t expected[] = {
    {1u, PLAN_ITERATIONS, 1u, 1000000u, 0u, 0u, 0u, 0u},
    {2u, PLAN_ITERATIONS, 1u, 10000000u, 0u, 0u, 0u, 0u},
    {3u, PLAN_ITERATIONS, 1u, 10000000u, 0u, 0u, 0u, 0u},
    {4u, PLAN_ITERATIONS, 1u, 1000000u, 0u, 0u, 0u, 0u},
    {5u, PLAN_ITERATIONS, 1u, 1000000u, 0u, 0u, 0u, 0u},
  };
  fn_bench_args_t args;
  fn_bench_plan_t plan;
  fn_bench_case_t cases[5];
  rule_environment_t environment;
  char config_path[4096];
  uint64_t overall_start;
  uint32_t case_index;
  int status = 1;
  memset(cases, 0, sizeof(cases));
  cases[0].name = "cold_runtime_build";
  cases[0].phase = "cold";
  cases[1].name = "steady_match_ipv4";
  cases[1].phase = "steady";
  cases[2].name = "steady_match_domain_resolved";
  cases[2].phase = "steady";
  cases[3].name = "first_lazy_activation";
  cases[3].phase = "first_lazy";
  cases[4].name = "runtime_reclaim";
  cases[4].phase = "reclaim";
  if (fn_bench_parse_args(argc, argv, &args) != 0 ||
      fn_bench_plan_load(&args, RULE_TARGET_ID, expected,
                         sizeof(expected) / sizeof(expected[0]),
                         &plan) != 0 ||
      snprintf(config_path, sizeof(config_path), "%s/rule-config.yaml",
               args.fixture_dir) < 0 ||
      environment_init(&environment, config_path) != 0) {
    return 1;
  }
  overall_start = fn_bench_monotonic_ns();
  for (case_index = 0; case_index < plan.case_count; case_index++) {
    uint32_t round;
    for (round = 0; round < args.warmup_count + args.sample_count; round++) {
      sample_result_t sample;
      bool owned = case_index == 0u || case_index >= 3u;
      if (case_index == 0u) {
        sample = sample_cold_build(&environment,
                                   plan.records[case_index].primary);
      } else if (case_index == 1u) {
        sample = sample_route(&environment,
                              plan.records[case_index].primary, false);
      } else if (case_index == 2u) {
        sample = sample_route(&environment,
                              plan.records[case_index].primary, true);
      } else if (case_index == 3u) {
        sample = sample_first_lazy(&environment,
                                   plan.records[case_index].primary);
      } else {
        sample = sample_reclaim(&environment,
                                plan.records[case_index].primary);
      }
      if (!sample.ok ||
          (round >= args.warmup_count &&
           record_sample(&cases[case_index], &sample, owned) != 0)) {
        goto cleanup;
      }
    }
    cases[case_index].behavior_ok = true;
    cases[case_index].cleanup_ok = true;
  }
  if (environment_destroy(&environment) != 0) {
    return 1;
  }
  if (fn_bench_write_target(
        &args, &plan, "rule", cases, 5u,
        fn_bench_monotonic_ns() - overall_start) != 0) {
    return 1;
  }
  return 0;

cleanup:
  (void)environment_destroy(&environment);
  return status;
}
