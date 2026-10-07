#include "flicknet/address.h"
#include "flicknet/clock.h"
#include "flicknet/config.h"
#include "flicknet/loop.h"
#include "flicknet/router.h"
#include "flicknet/runtime.h"

#include <stdio.h>
#include <string.h>

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
  size_t prepare_calls;
  size_t prepare_fail_at;
  size_t lazy_start_calls;
  size_t release_calls;
  fn_runtime_t *last_runtime;
  fn_object_ref_t last_object;
  fn_result_t next_start_result;
  unsigned long tokens[128];
} test_backend_t;

typedef struct {
  fn_runtime_acquire_t **slot;
  size_t calls;
  fn_result_t result;
  void *resource;
} acquire_observation_t;

static fn_result_t test_result(fn_status_t code, fn_error_stage_t stage)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE : stage,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static fn_result_t backend_prepare(
  void *context, const fn_runtime_resource_descriptor_t *descriptor,
  void **out_resource)
{
  test_backend_t *backend = context;
  size_t call;
  (void)descriptor;
  backend->prepare_calls++;
  call = backend->prepare_calls;
  *out_resource = NULL;
  if (backend->prepare_fail_at == call) {
    return test_result(FN_IO_ERROR, FN_STAGE_PREPARE);
  }
  *out_resource = &backend->tokens[call % 128u];
  return test_result(FN_OK, FN_STAGE_NONE);
}

static fn_result_t backend_lazy_start(void *context, fn_runtime_t *runtime,
                                      fn_object_ref_t object)
{
  test_backend_t *backend = context;
  fn_result_t result = backend->next_start_result;
  backend->lazy_start_calls++;
  backend->last_runtime = runtime;
  backend->last_object = object;
  backend->next_start_result = test_result(FN_OK, FN_STAGE_NONE);
  return result;
}

static void backend_release(
  void *context, const fn_runtime_resource_descriptor_t *descriptor,
  void *resource)
{
  test_backend_t *backend = context;
  (void)descriptor;
  CHECK(resource != NULL);
  backend->release_calls++;
}

static void acquire_callback(
  fn_runtime_acquire_t *operation, void *context, fn_result_t result,
  const fn_runtime_resource_descriptor_t *descriptor, void *resource)
{
  acquire_observation_t *observation = context;
  CHECK(descriptor != NULL);
  CHECK(observation->slot != NULL);
  CHECK(*observation->slot == operation);
  observation->calls++;
  observation->result = result;
  observation->resource = resource;
  CHECK(fn_runtime_acquire_release(observation->slot).code == FN_OK);
}

static void pump_until(fn_loop_t *loop, size_t *value, size_t expected)
{
  size_t turns;
  for (turns = 0; turns < 64u && *value < expected; turns++) {
    CHECK(fn_loop_run_once(loop, FN_LOOP_RUN_NOWAIT).code == FN_OK);
  }
  CHECK(*value == expected);
}

static fn_addr_t v4_address(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
  fn_addr_t address;
  const uint8_t bytes[4] = {a, b, c, d};
  memset(&address, 0, sizeof(address));
  CHECK(fn_addr_from_v4(&address, bytes).code == FN_OK);
  return address;
}

static fn_config_t make_config(fn_inbound_config_t *inbounds,
                               size_t inbound_count,
                               fn_proxy_config_t *proxies,
                               fn_rule_config_t *rules)
{
  fn_config_t config;
  memset(&config, 0, sizeof(config));
  config.schema_version = 1u;
  config.inbound_count = inbound_count;
  config.inbounds = inbounds;
  config.proxy_count = 1u;
  config.proxies = proxies;
  config.rule_count = 1u;
  config.rules = rules;
  config.allocator = fn_allocator_system();
  return config;
}

static fn_feature_plan_t direct_plan(void)
{
  fn_feature_plan_t plan;
  memset(&plan, 0, sizeof(plan));
  plan.reachable = FN_FEATURE_SOCKS_IN_TCP | FN_FEATURE_DIRECT_TCP |
                   FN_FEATURE_DNS_RESOLVER |
                   FN_FEATURE_DNS_FAILURE_CACHE |
                   FN_FEATURE_DNS_UPSTREAM_UDP;
  plan.prepare = FN_FEATURE_SOCKS_IN_TCP;
  plan.lazy = FN_FEATURE_DIRECT_TCP | FN_FEATURE_DNS_RESOLVER |
              FN_FEATURE_DNS_FAILURE_CACHE | FN_FEATURE_DNS_UPSTREAM_UDP;
  return plan;
}

static void set_domain_target(fn_session_metadata_t *metadata,
                              const char *domain, uint16_t port)
{
  fn_domain_t value;
  fn_addr_t address;
  CHECK(fn_domain_from_bytes(&value, (const uint8_t *)domain,
                             strlen(domain)).code == FN_OK);
  CHECK(fn_addr_from_domain(&address, &value).code == FN_OK);
  CHECK(fn_endpoint_make(&metadata->route.original_target, &address,
                         port).code == FN_OK);
  CHECK(fn_session_metadata_set_domain(metadata, &value,
                                       FN_DOMAIN_REQUEST).code == FN_OK);
}

static void test_runtime_router(void)
{
  fn_limits_t limits = fn_limits_default();
  fn_budget_t memory;
  fn_budget_t file_descriptors;
  fn_loop_options_t loop_options;
  fn_loop_t *loop = NULL;
  fn_runtime_manager_options_t manager_options;
  fn_runtime_manager_t *manager = NULL;
  fn_runtime_candidate_t *candidate = NULL;
  fn_runtime_candidate_t *candidate_b = NULL;
  fn_runtime_candidate_t *candidate_c = NULL;
  fn_runtime_candidate_t *candidate_d = NULL;
  fn_runtime_t *runtime_a = NULL;
  fn_runtime_t *runtime_b = NULL;
  fn_runtime_t *runtime_d = NULL;
  fn_runtime_manager_snapshot_t manager_snapshot;
  fn_runtime_resource_snapshot_t resource_snapshot;
  fn_budget_snapshot_t budget_snapshot;
  fn_inbound_config_t inbounds[2];
  fn_proxy_config_t proxies[1];
  fn_rule_config_t rules[1];
  fn_config_t failure_config;
  fn_config_t config;
  fn_feature_plan_t plan = direct_plan();
  test_backend_t backend;
  fn_object_ref_t inbound_a;
  fn_object_ref_t direct_a;
  fn_object_ref_t direct_b;
  fn_object_ref_t resolver_b;
  fn_object_ref_t unused;
  fn_session_metadata_t metadata;
  fn_route_result_t route;
  fn_runtime_acquire_t *operation_one = NULL;
  fn_runtime_acquire_t *operation_two = NULL;
  acquire_observation_t observation_one;
  acquire_observation_t observation_two;
  uint64_t now_ms;
  size_t releases_before;
  size_t starts_before;

  memset(&backend, 0, sizeof(backend));
  backend.next_start_result = test_result(FN_OK, FN_STAGE_NONE);
  memset(inbounds, 0, sizeof(inbounds));
  memcpy(inbounds[0].name, "socks-main", sizeof("socks-main"));
  inbounds[0].listen = v4_address(127u, 0u, 0u, 1u);
  inbounds[0].port = 1080u;
  memcpy(inbounds[1].name, "socks-alt", sizeof("socks-alt"));
  inbounds[1].listen = v4_address(127u, 0u, 0u, 1u);
  inbounds[1].port = 1081u;
  memset(proxies, 0, sizeof(proxies));
  memcpy(proxies[0].name, "unused-proxy", sizeof("unused-proxy"));
  proxies[0].server = v4_address(192u, 0u, 2u, 10u);
  proxies[0].port = 1080u;
  memset(rules, 0, sizeof(rules));
  memcpy(rules[0].target, "DIRECT", sizeof("DIRECT"));
  failure_config = make_config(inbounds, 2u, proxies, rules);
  config = make_config(inbounds, 1u, proxies, rules);

  limits.owned_memory_limit_bytes = 8u * 1024u * 1024u;
  limits.cleanup_reserve_bytes = 1024u * 1024u;
  limits.retired_runtime_limit = 1u;
  limits.resource_wait_timeout_ms = UINT64_C(5000);
  CHECK(fn_budget_init(&memory, limits.owned_memory_limit_bytes,
                       limits.cleanup_reserve_bytes).code == FN_OK);
  CHECK(fn_budget_init(&file_descriptors, limits.fd_limit, 0u).code == FN_OK);
  memset(&loop_options, 0, sizeof(loop_options));
  loop_options.limits = &limits;
  loop_options.owned_memory = &memory;
  loop_options.file_descriptors = &file_descriptors;
  loop_options.allocator = fn_allocator_system();
  loop_options.dispatch_limit = 16u;
  CHECK(fn_loop_create(&loop_options, &loop).code == FN_OK);

  memset(&manager_options, 0, sizeof(manager_options));
  manager_options.loop = loop;
  manager_options.limits = &limits;
  manager_options.owned_memory = &memory;
  manager_options.allocator = fn_allocator_system();
  manager_options.resources.context = &backend;
  manager_options.resources.prepare = backend_prepare;
  manager_options.resources.lazy_start = backend_lazy_start;
  manager_options.resources.release = backend_release;
  CHECK(fn_runtime_manager_create(&manager_options, &manager).code == FN_OK);

  backend.prepare_fail_at = 2u;
  CHECK(fn_runtime_candidate_build(manager, &failure_config, &plan,
                                   &candidate).code == FN_OK);
  CHECK(fn_runtime_candidate_prepare(candidate).code == FN_IO_ERROR);
  CHECK(backend.release_calls == 1u);
  CHECK(fn_runtime_candidate_destroy(&candidate).code == FN_OK);
  CHECK(fn_runtime_manager_snapshot(manager, &manager_snapshot).code == FN_OK);
  CHECK(manager_snapshot.candidates == 0u);

  backend.prepare_fail_at = 0u;
  CHECK(fn_runtime_candidate_build(manager, &config, &plan,
                                   &candidate).code == FN_OK);
  CHECK(fn_runtime_candidate_prepare(candidate).code == FN_OK);
  CHECK(fn_runtime_candidate_commit(manager, &candidate).code == FN_OK);
  CHECK(fn_runtime_acquire_active(manager, &runtime_a).code == FN_OK);
  CHECK(fn_runtime_object_count(runtime_a) == 3u);
  CHECK(fn_runtime_object_find(runtime_a, FN_RUNTIME_RESOURCE_LISTENER,
                               "socks-main", &inbound_a).code == FN_OK);
  CHECK(fn_runtime_object_find(runtime_a, FN_RUNTIME_RESOURCE_DIRECT,
                               "DIRECT", &direct_a).code == FN_OK);
  CHECK(fn_runtime_object_find(runtime_a, FN_RUNTIME_RESOURCE_SOCKS_PROXY,
                               "unused-proxy", &unused).code == FN_INVALID);

  fn_session_metadata_init(&metadata, FN_TCP);
  metadata.route.inbound = inbound_a;
  metadata.route.original_target.address = v4_address(203u, 0u, 113u, 8u);
  metadata.route.original_target.port = 443u;
  CHECK(fn_route_evaluate(runtime_a, &metadata, &route).code == FN_OK);
  CHECK(route.status == FN_ROUTE_READY);
  CHECK(route.outbound.index == direct_a.index);
  metadata.route.inbound.generation++;
  CHECK(fn_route_evaluate(runtime_a, &metadata, &route).code ==
        FN_STALE_GENERATION);
  metadata.route.inbound = inbound_a;
  metadata.route.inbound.index = UINT32_MAX - 1u;
  CHECK(fn_route_evaluate(runtime_a, &metadata, &route).code == FN_INVALID);
  metadata.route.inbound = inbound_a;
  set_domain_target(&metadata, "example.com", 443u);
  CHECK(fn_route_evaluate(runtime_a, &metadata, &route).code == FN_OK);
  CHECK(route.status == FN_ROUTE_NEED_RESOLVE);
  metadata.dial.resolved.count = 2u;
  metadata.dial.resolved.addresses[0] = v4_address(203u, 0u, 113u, 10u);
  metadata.dial.resolved.addresses[1] = v4_address(203u, 0u, 113u, 11u);
  CHECK(fn_route_evaluate(runtime_a, &metadata, &route).code == FN_OK);
  CHECK(route.status == FN_ROUTE_READY);
  CHECK(route.candidate_mask == UINT16_C(3));

  CHECK(fn_runtime_candidate_build(manager, &config, &plan,
                                   &candidate_b).code == FN_OK);
  CHECK(fn_runtime_candidate_build(manager, &config, &plan,
                                   &candidate_c).code == FN_OK);
  CHECK(fn_runtime_candidate_prepare(candidate_b).code == FN_OK);
  CHECK(fn_runtime_candidate_prepare(candidate_c).code == FN_OK);
  CHECK(fn_runtime_candidate_commit(manager, &candidate_b).code == FN_OK);
  CHECK(fn_runtime_manager_snapshot(manager, &manager_snapshot).code == FN_OK);
  CHECK(manager_snapshot.retained_runtimes == 1u);
  CHECK(fn_route_evaluate(runtime_a, &metadata, &route).code == FN_OK);
  CHECK(fn_runtime_candidate_commit(manager, &candidate_c).code ==
        FN_STALE_GENERATION);

  CHECK(fn_runtime_acquire_active(manager, &runtime_b).code == FN_OK);
  CHECK(fn_runtime_object_find(runtime_b, FN_RUNTIME_RESOURCE_DIRECT,
                               "DIRECT", &direct_b).code == FN_OK);
  CHECK(fn_runtime_object_find(runtime_b, FN_RUNTIME_RESOURCE_RESOLVER,
                               "$resolver", &resolver_b).code == FN_OK);
  CHECK(fn_runtime_candidate_build(manager, &config, &plan,
                                   &candidate_d).code == FN_OK);
  CHECK(fn_runtime_candidate_prepare(candidate_d).code == FN_OK);
  CHECK(fn_runtime_candidate_commit(manager, &candidate_d).code == FN_LIMIT);
  CHECK(fn_runtime_release(&runtime_a).code == FN_OK);
  CHECK(fn_runtime_manager_snapshot(manager, &manager_snapshot).code == FN_OK);
  CHECK(manager_snapshot.retained_runtimes == 0u);
  CHECK(fn_runtime_candidate_commit(manager, &candidate_d).code == FN_OK);
  CHECK(fn_runtime_manager_snapshot(manager, &manager_snapshot).code == FN_OK);
  CHECK(manager_snapshot.retained_runtimes == 1u);
  CHECK(fn_runtime_candidate_destroy(&candidate_c).code == FN_OK);
  CHECK(fn_runtime_release(&runtime_b).code == FN_OK);
  CHECK(fn_runtime_manager_snapshot(manager, &manager_snapshot).code == FN_OK);
  CHECK(manager_snapshot.retained_runtimes == 0u);

  CHECK(fn_runtime_acquire_active(manager, &runtime_d).code == FN_OK);
  CHECK(fn_runtime_object_find(runtime_d, FN_RUNTIME_RESOURCE_DIRECT,
                               "DIRECT", &direct_b).code == FN_OK);
  CHECK(fn_runtime_object_find(runtime_d, FN_RUNTIME_RESOURCE_RESOLVER,
                               "$resolver", &resolver_b).code == FN_OK);
  CHECK(fn_monotonic_now_ms(&now_ms).code == FN_OK);
  memset(&observation_one, 0, sizeof(observation_one));
  memset(&observation_two, 0, sizeof(observation_two));
  observation_one.slot = &operation_one;
  observation_two.slot = &operation_two;
  starts_before = backend.lazy_start_calls;
  CHECK(fn_runtime_acquire(runtime_d, direct_b, now_ms + UINT64_C(10000),
                           acquire_callback, &observation_one,
                           &operation_one).code == FN_OK);
  CHECK(fn_runtime_acquire(runtime_d, direct_b, now_ms + UINT64_C(10000),
                           acquire_callback, &observation_two,
                           &operation_two).code == FN_OK);
  CHECK(backend.lazy_start_calls == starts_before + 1u);
  CHECK(fn_runtime_resource_snapshot(runtime_d, direct_b,
                                     &resource_snapshot).code == FN_OK);
  CHECK(resource_snapshot.state == FN_RUNTIME_STARTING);
  CHECK(resource_snapshot.waiters == 2u);
  CHECK(fn_runtime_acquire_cancel(operation_one).code == FN_OK);
  CHECK(fn_runtime_lazy_finish(backend.last_runtime, backend.last_object,
                               test_result(FN_OK, FN_STAGE_NONE),
                               &backend.tokens[80]).code == FN_OK);
  pump_until(loop, &observation_one.calls, 1u);
  pump_until(loop, &observation_two.calls, 1u);
  CHECK(observation_one.result.code == FN_CANCELLED);
  CHECK(observation_two.result.code == FN_OK);
  CHECK(observation_two.resource == &backend.tokens[80]);

  memset(&observation_one, 0, sizeof(observation_one));
  observation_one.slot = &operation_one;
  CHECK(fn_runtime_acquire(runtime_d, resolver_b, now_ms + UINT64_C(10000),
                           acquire_callback, &observation_one,
                           &operation_one).code == FN_OK);
  CHECK(fn_runtime_acquire_cancel(operation_one).code == FN_OK);
  pump_until(loop, &observation_one.calls, 1u);
  releases_before = backend.release_calls;
  CHECK(fn_runtime_lazy_finish(backend.last_runtime, backend.last_object,
                               test_result(FN_OK, FN_STAGE_NONE),
                               &backend.tokens[81]).code == FN_OK);
  CHECK(backend.release_calls == releases_before + 1u);
  CHECK(fn_runtime_resource_snapshot(runtime_d, resolver_b,
                                     &resource_snapshot).code == FN_OK);
  CHECK(resource_snapshot.state == FN_RUNTIME_DORMANT);
  CHECK(!resource_snapshot.has_resource);

  memset(&observation_one, 0, sizeof(observation_one));
  observation_one.slot = &operation_one;
  CHECK(fn_runtime_acquire(runtime_d, resolver_b, now_ms + UINT64_C(10000),
                           acquire_callback, &observation_one,
                           &operation_one).code == FN_OK);
  releases_before = backend.release_calls;
  starts_before = backend.lazy_start_calls;
  CHECK(fn_runtime_lazy_finish(backend.last_runtime, backend.last_object,
                               test_result(FN_INVALID, FN_STAGE_PREPARE),
                               &backend.tokens[82]).code == FN_OK);
  CHECK(backend.release_calls == releases_before + 1u);
  pump_until(loop, &observation_one.calls, 1u);
  CHECK(observation_one.result.code == FN_INVALID);
  memset(&observation_two, 0, sizeof(observation_two));
  observation_two.slot = &operation_two;
  CHECK(fn_runtime_acquire(runtime_d, resolver_b, now_ms + UINT64_C(10000),
                           acquire_callback, &observation_two,
                           &operation_two).code == FN_OK);
  CHECK(backend.lazy_start_calls == starts_before);
  pump_until(loop, &observation_two.calls, 1u);
  CHECK(observation_two.result.code == FN_INVALID);

  CHECK(fn_runtime_manager_snapshot(manager, &manager_snapshot).code == FN_OK);
  CHECK(manager_snapshot.candidates == 0u);
  CHECK(manager_snapshot.retained_runtimes == 0u);
  CHECK(manager_snapshot.async_operations == 0u);
  CHECK(manager_snapshot.lazy_waiters == 0u);
  CHECK(manager_snapshot.lazy_waiter_bytes == 0u);
  CHECK(fn_runtime_release(&runtime_d).code == FN_OK);
  CHECK(fn_runtime_manager_destroy(&manager).code == FN_OK);
  CHECK(fn_loop_destroy(&loop).code == FN_OK);
  CHECK(fn_budget_snapshot(&memory, &budget_snapshot).code == FN_OK);
  CHECK(budget_snapshot.total == 0u);
  CHECK(fn_budget_snapshot(&file_descriptors, &budget_snapshot).code == FN_OK);
  CHECK(budget_snapshot.total == 0u);
}

int main(void)
{
  test_runtime_router();
  if (failures != 0) {
    fprintf(stderr, "P05 runtime/router tests failed: %d\n", failures);
    return 1;
  }
  puts("P05 runtime/router tests passed");
  return 0;
}
