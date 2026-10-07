#include "flicknet/clock.h"
#include "flicknet/config.h"
#include "flicknet/direct.h"
#include "flicknet/runtime.h"
#include "flicknet/session.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      (void)fprintf(stderr, "check failed: %s:%d: %s\n", __FILE__,          \
                    __LINE__, #condition);                                     \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

typedef struct {
  unsigned long tokens[16];
  size_t prepare_calls;
  size_t prepare_fail_at;
  size_t release_calls;
  size_t lazy_start_calls;
} runtime_backend_t;

typedef struct {
  fn_limits_t limits;
  fn_budget_t memory;
  fn_budget_t file_descriptors;
  fn_budget_t buffers;
  fn_loop_t *loop;
  fn_relay_buffer_pool_t *relay_pool;
  fn_direct_connector_t *connector;
  fn_runtime_manager_t *runtime_manager;
  fn_session_manager_t *session_manager;
  runtime_backend_t backend;
} test_environment_t;

typedef struct {
  fn_session_t *session;
  size_t calls;
  fn_session_snapshot_t snapshot;
} session_observation_t;

typedef struct {
  int listener;
  int status;
  uint64_t bytes;
} echo_server_t;

static fn_result_t test_result(fn_status_t code, fn_error_stage_t stage)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE : stage,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static fn_addr_t v4_address(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
  const uint8_t bytes[4] = {a, b, c, d};
  fn_addr_t address;
  CHECK(fn_addr_from_v4(&address, bytes).code == FN_OK);
  return address;
}

static fn_endpoint_t v4_endpoint(uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                                 uint16_t port)
{
  fn_addr_t address = v4_address(a, b, c, d);
  fn_endpoint_t endpoint;
  CHECK(fn_endpoint_make(&endpoint, &address, port).code == FN_OK);
  return endpoint;
}

static fn_result_t runtime_prepare(
  void *context, const fn_runtime_resource_descriptor_t *descriptor,
  void **out_resource)
{
  runtime_backend_t *backend = context;
  size_t call;
  (void)descriptor;
  *out_resource = NULL;
  backend->prepare_calls++;
  call = backend->prepare_calls;
  if (call == backend->prepare_fail_at) {
    return test_result(FN_IO_ERROR, FN_STAGE_PREPARE);
  }
  CHECK(call < sizeof(backend->tokens) / sizeof(backend->tokens[0]));
  backend->tokens[call] = (unsigned long)call;
  *out_resource = &backend->tokens[call];
  return test_result(FN_OK, FN_STAGE_NONE);
}

static fn_result_t runtime_lazy_start(void *context, fn_runtime_t *runtime,
                                      fn_object_ref_t object)
{
  runtime_backend_t *backend = context;
  (void)runtime;
  (void)object;
  backend->lazy_start_calls++;
  return test_result(FN_UNSUPPORTED, FN_STAGE_PREPARE);
}

static void runtime_release(
  void *context, const fn_runtime_resource_descriptor_t *descriptor,
  void *resource)
{
  runtime_backend_t *backend = context;
  size_t index;
  bool found = false;
  (void)descriptor;
  for (index = 0; index < sizeof(backend->tokens) /
                          sizeof(backend->tokens[0]); index++) {
    if (resource == &backend->tokens[index]) {
      found = true;
      break;
    }
  }
  CHECK(found);
  backend->release_calls++;
}

static void environment_init(test_environment_t *environment)
{
  fn_loop_options_t loop_options;
  fn_relay_buffer_pool_options_t pool_options;
  fn_direct_connector_options_t connector_options;
  fn_runtime_manager_options_t runtime_options;
  fn_session_manager_options_t session_options;

  memset(environment, 0, sizeof(*environment));
  environment->limits = fn_limits_default();
  environment->limits.fd_limit = 64u;
  environment->limits.session_limit = 8u;
  environment->limits.retired_runtime_limit = 2u;
  environment->limits.owned_memory_limit_bytes = 16u * 1024u * 1024u;
  environment->limits.cleanup_reserve_bytes = 1024u * 1024u;
  environment->limits.buffer_pool_limit_bytes = 4u * 1024u * 1024u;
  CHECK(fn_budget_init(&environment->memory,
                       environment->limits.owned_memory_limit_bytes,
                       environment->limits.cleanup_reserve_bytes).code ==
        FN_OK);
  CHECK(fn_budget_init(&environment->file_descriptors,
                       environment->limits.fd_limit, 0u).code == FN_OK);
  CHECK(fn_budget_init(&environment->buffers,
                       environment->limits.buffer_pool_limit_bytes,
                       0u).code == FN_OK);
  memset(&loop_options, 0, sizeof(loop_options));
  loop_options.limits = &environment->limits;
  loop_options.owned_memory = &environment->memory;
  loop_options.file_descriptors = &environment->file_descriptors;
  loop_options.allocator = fn_allocator_system();
  loop_options.dispatch_limit = 64u;
  CHECK(fn_loop_create(&loop_options, &environment->loop).code == FN_OK);

  memset(&pool_options, 0, sizeof(pool_options));
  pool_options.loop = environment->loop;
  pool_options.limits = &environment->limits;
  pool_options.owned_memory = &environment->memory;
  pool_options.buffer_bytes = &environment->buffers;
  pool_options.allocator = fn_allocator_system();
  pool_options.block_size = 1024u;
  pool_options.block_capacity = 64u;
  pool_options.block_cache_limit = 8u;
  CHECK(fn_relay_buffer_pool_create(&pool_options,
                                    &environment->relay_pool).code == FN_OK);

  memset(&connector_options, 0, sizeof(connector_options));
  connector_options.loop = environment->loop;
  connector_options.limits = &environment->limits;
  connector_options.owned_memory = &environment->memory;
  connector_options.file_descriptors = &environment->file_descriptors;
  connector_options.allocator = fn_allocator_system();
  connector_options.connect_timeout_ms = UINT64_C(500);
  CHECK(fn_direct_connector_create(&connector_options,
                                   &environment->connector).code == FN_OK);

  memset(&runtime_options, 0, sizeof(runtime_options));
  runtime_options.loop = environment->loop;
  runtime_options.limits = &environment->limits;
  runtime_options.owned_memory = &environment->memory;
  runtime_options.allocator = fn_allocator_system();
  runtime_options.resources.context = &environment->backend;
  runtime_options.resources.prepare = runtime_prepare;
  runtime_options.resources.lazy_start = runtime_lazy_start;
  runtime_options.resources.release = runtime_release;
  CHECK(fn_runtime_manager_create(&runtime_options,
                                  &environment->runtime_manager).code ==
        FN_OK);

  memset(&session_options, 0, sizeof(session_options));
  session_options.loop = environment->loop;
  session_options.limits = &environment->limits;
  session_options.owned_memory = &environment->memory;
  session_options.allocator = fn_allocator_system();
  session_options.direct_connector = environment->connector;
  session_options.relay_pool = environment->relay_pool;
  CHECK(fn_session_manager_create(&session_options,
                                  &environment->session_manager).code ==
        FN_OK);
}

static void environment_destroy(test_environment_t *environment)
{
  fn_budget_snapshot_t snapshot;
  CHECK(fn_session_manager_destroy(&environment->session_manager).code ==
        FN_OK);
  CHECK(fn_runtime_manager_destroy(&environment->runtime_manager).code ==
        FN_OK);
  CHECK(fn_direct_connector_destroy(&environment->connector).code == FN_OK);
  CHECK(fn_relay_buffer_pool_destroy(&environment->relay_pool).code == FN_OK);
  CHECK(fn_loop_destroy(&environment->loop).code == FN_OK);
  CHECK(fn_budget_snapshot(&environment->memory, &snapshot).code == FN_OK);
  CHECK(snapshot.total == 0u);
  CHECK(fn_budget_snapshot(&environment->file_descriptors,
                           &snapshot).code == FN_OK);
  CHECK(snapshot.total == 0u);
  CHECK(fn_budget_snapshot(&environment->buffers, &snapshot).code == FN_OK);
  CHECK(snapshot.total == 0u);
}

static fn_config_t make_config(fn_inbound_config_t *inbounds,
                               size_t inbound_count,
                               fn_proxy_config_t *proxies,
                               size_t proxy_count,
                               fn_rule_config_t *rules,
                               size_t rule_count)
{
  fn_config_t config;
  memset(&config, 0, sizeof(config));
  config.schema_version = UINT32_C(1);
  config.inbounds = inbounds;
  config.inbound_count = inbound_count;
  config.proxies = proxies;
  config.proxy_count = proxy_count;
  config.rules = rules;
  config.rule_count = rule_count;
  config.allocator = fn_allocator_system();
  return config;
}

static fn_feature_plan_t direct_plan(void)
{
  fn_feature_plan_t plan;
  memset(&plan, 0, sizeof(plan));
  plan.reachable = FN_FEATURE_SOCKS_IN_TCP | FN_FEATURE_DIRECT_TCP;
  plan.prepare = FN_FEATURE_SOCKS_IN_TCP;
  plan.lazy = FN_FEATURE_DIRECT_TCP;
  return plan;
}

static fn_feature_plan_t reject_plan(void)
{
  fn_feature_plan_t plan;
  memset(&plan, 0, sizeof(plan));
  plan.reachable = FN_FEATURE_SOCKS_IN_TCP;
  plan.prepare = FN_FEATURE_SOCKS_IN_TCP;
  return plan;
}

static void inbound_init(fn_inbound_config_t *inbound, const char *name,
                         uint16_t port)
{
  memset(inbound, 0, sizeof(*inbound));
  (void)snprintf(inbound->name, sizeof(inbound->name), "%s", name);
  inbound->listen = v4_address(127u, 0u, 0u, 1u);
  inbound->port = port;
}

static void rule_init(fn_rule_config_t *rule, const char *target)
{
  memset(rule, 0, sizeof(*rule));
  (void)snprintf(rule->target, sizeof(rule->target), "%s", target);
}

static void proxy_init(fn_proxy_config_t *proxy)
{
  memset(proxy, 0, sizeof(*proxy));
  memcpy(proxy->name, "unused-proxy", sizeof("unused-proxy"));
  proxy->server = v4_address(192u, 0u, 2u, 9u);
  proxy->port = 1080u;
}

static fn_runtime_t *publish_runtime(test_environment_t *environment,
                                     const fn_config_t *config,
                                     const fn_feature_plan_t *plan)
{
  fn_runtime_candidate_t *candidate = NULL;
  fn_runtime_t *runtime = NULL;
  CHECK(fn_runtime_candidate_build(environment->runtime_manager, config,
                                   plan, &candidate).code == FN_OK);
  CHECK(fn_runtime_candidate_prepare(candidate).code == FN_OK);
  CHECK(fn_runtime_candidate_commit(environment->runtime_manager,
                                    &candidate).code == FN_OK);
  CHECK(fn_runtime_acquire_active(environment->runtime_manager,
                                  &runtime).code == FN_OK);
  return runtime;
}

static int listener_create(uint16_t *port)
{
  int descriptor = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in address;
  socklen_t length = (socklen_t)sizeof(address);
  int reuse = 1;
  CHECK(descriptor >= 0);
  CHECK(setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &reuse,
                   (socklen_t)sizeof(reuse)) == 0);
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  CHECK(bind(descriptor, (const struct sockaddr *)&address,
             (socklen_t)sizeof(address)) == 0);
  CHECK(getsockname(descriptor, (struct sockaddr *)&address, &length) == 0);
  CHECK(listen(descriptor, 4) == 0);
  *port = ntohs(address.sin_port);
  return descriptor;
}

static void *echo_server_main(void *context)
{
  echo_server_t *server = context;
  uint8_t buffer[2048];
  int accepted = accept(server->listener, NULL, NULL);
  if (accepted < 0) {
    server->status = 1;
    return NULL;
  }
  for (;;) {
    ssize_t received = recv(accepted, buffer, sizeof(buffer), 0);
    size_t offset = 0;
    if (received == 0) {
      if (shutdown(accepted, SHUT_WR) != 0) {
        server->status = 2;
      }
      break;
    }
    if (received < 0) {
      server->status = 3;
      break;
    }
    while (offset < (size_t)received) {
      ssize_t sent = send(accepted, buffer + offset,
                          (size_t)received - offset, MSG_NOSIGNAL);
      if (sent <= 0) {
        server->status = 4;
        (void)close(accepted);
        return NULL;
      }
      offset += (size_t)sent;
    }
    server->bytes += (uint64_t)received;
  }
  (void)close(accepted);
  return NULL;
}

static void socketpair_stream(test_environment_t *environment,
                              fn_socket_t *peer, fn_stream_t **stream)
{
  int pair[2] = {-1, -1};
  fn_socket_t internal = fn_socket_invalid();
  fn_socket_policy_t policy;
  fn_socket_policy_report_t report;
  fn_stream_options_t options;
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
  CHECK(fn_socket_from_native(pair[0], peer).code == FN_OK);
  CHECK(fn_socket_from_native(pair[1], &internal).code == FN_OK);
  memset(&policy, 0, sizeof(policy));
  policy.purpose = FN_SOCKET_PURPOSE_INBOUND_ACCEPTED;
  policy.require_nonblocking = true;
  CHECK(fn_socket_policy_apply(*peer, &policy, &report).code == FN_OK);
  CHECK(fn_socket_policy_apply(internal, &policy, &report).code == FN_OK);
  memset(&options, 0, sizeof(options));
  options.loop = environment->loop;
  options.owned_memory = &environment->memory;
  options.allocator = fn_allocator_system();
  CHECK(fn_stream_socket_create(&options, &internal, stream).code == FN_OK);
  CHECK(!fn_socket_is_valid(internal));
}

static uint64_t deadline_after(uint64_t duration_ms)
{
  uint64_t now_ms;
  uint64_t deadline_ms;
  CHECK(fn_monotonic_now_ms(&now_ms).code == FN_OK);
  CHECK(fn_deadline_after_ms(now_ms, duration_ms, &deadline_ms).code == FN_OK);
  return deadline_ms;
}

static void session_callback(fn_session_t *session, void *context,
                             const fn_session_snapshot_t *snapshot)
{
  session_observation_t *observation = context;
  CHECK(session == observation->session);
  observation->calls++;
  observation->snapshot = *snapshot;
  CHECK(fn_session_release(&observation->session).code == FN_OK);
}

static void pump_nowait(fn_loop_t *loop, size_t turns)
{
  size_t index;
  for (index = 0; index < turns; index++) {
    CHECK(fn_loop_run_once(loop, FN_LOOP_RUN_NOWAIT).code == FN_OK);
    (void)sched_yield();
  }
}

static void wait_for_state(test_environment_t *environment,
                           session_observation_t *observation,
                           fn_session_state_t state)
{
  size_t turns;
  for (turns = 0; turns < 100000u; turns++) {
    fn_session_snapshot_t snapshot;
    CHECK(observation->session != NULL);
    CHECK(fn_session_snapshot(observation->session, &snapshot).code == FN_OK);
    if (snapshot.state == state) {
      return;
    }
    pump_nowait(environment->loop, 1u);
  }
  CHECK(false);
}

static void wait_for_terminal(test_environment_t *environment,
                              session_observation_t *observation)
{
  size_t turns;
  for (turns = 0; turns < 100000u && observation->calls == 0u; turns++) {
    pump_nowait(environment->loop, 1u);
  }
  CHECK(observation->calls == 1u);
}

static void write_all(test_environment_t *environment, fn_socket_t peer,
                      const uint8_t *data, size_t length)
{
  size_t offset = 0;
  size_t turns;
  for (turns = 0; turns < 100000u && offset < length; turns++) {
    fn_io_result_t io = fn_socket_write(peer, data + offset, length - offset,
                                        FN_STAGE_RELAY);
    if (io.result.code == FN_OK) {
      offset += io.transferred;
    } else {
      CHECK(io.result.code == FN_AGAIN);
    }
    pump_nowait(environment->loop, 1u);
  }
  CHECK(offset == length);
}

static void read_all(test_environment_t *environment, fn_socket_t peer,
                     uint8_t *data, size_t length)
{
  size_t offset = 0;
  size_t turns;
  for (turns = 0; turns < 100000u && offset < length; turns++) {
    fn_io_result_t io = fn_socket_read(peer, data + offset, length - offset,
                                       FN_STAGE_RELAY);
    if (io.result.code == FN_OK) {
      offset += io.transferred;
    } else {
      CHECK(io.result.code == FN_AGAIN);
    }
    pump_nowait(environment->loop, 1u);
  }
  CHECK(offset == length);
}

static void metadata_init(fn_session_metadata_t *metadata,
                          fn_object_ref_t inbound, uint16_t port)
{
  fn_session_metadata_init(metadata, FN_TCP);
  metadata->route.inbound = inbound;
  metadata->route.original_target = v4_endpoint(127u, 0u, 0u, 1u, port);
}

static void test_runtime_replacement(void)
{
  static const uint8_t payload[] = "p12-runtime-a";
  test_environment_t environment;
  fn_inbound_config_t inbound_a;
  fn_inbound_config_t inbound_failure[2];
  fn_inbound_config_t inbound_b;
  fn_proxy_config_t unused_proxy;
  fn_rule_config_t rule_a;
  fn_rule_config_t rule_b;
  fn_config_t config_a;
  fn_config_t config_failure;
  fn_config_t config_b;
  fn_feature_plan_t plan_a = direct_plan();
  fn_feature_plan_t plan_b = reject_plan();
  fn_runtime_candidate_t *candidate = NULL;
  fn_runtime_candidate_t *peak_candidate = NULL;
  fn_runtime_t *runtime_a;
  fn_runtime_t *runtime_b = NULL;
  fn_runtime_t *active_check = NULL;
  fn_runtime_manager_snapshot_t manager_snapshot;
  fn_budget_snapshot_t memory_snapshot;
  fn_budget_snapshot_t fd_before;
  fn_budget_snapshot_t fd_after;
  fn_object_ref_t inbound_id_a;
  fn_object_ref_t inbound_id_b;
  fn_object_ref_t unused_id;
  fn_session_metadata_t metadata;
  fn_stream_t *stream_a = NULL;
  fn_stream_t *stream_b = NULL;
  fn_socket_t peer_a = fn_socket_invalid();
  fn_socket_t peer_b = fn_socket_invalid();
  session_observation_t observation_a;
  session_observation_t observation_b;
  echo_server_t server;
  pthread_t thread;
  uint8_t received[sizeof(payload)];
  uint16_t target_port;
  uint64_t generation_a;
  uint64_t generation_b;
  size_t releases_before;

  environment_init(&environment);
  inbound_init(&inbound_a, "listener-a", 1080u);
  inbound_init(&inbound_failure[0], "listener-fail-one", 1081u);
  inbound_init(&inbound_failure[1], "listener-fail-two", 1082u);
  inbound_init(&inbound_b, "listener-b", 1083u);
  proxy_init(&unused_proxy);
  rule_init(&rule_a, "DIRECT");
  rule_init(&rule_b, "REJECT");
  config_a = make_config(&inbound_a, 1u, NULL, 0u, &rule_a, 1u);
  config_failure = make_config(inbound_failure, 2u, NULL, 0u,
                               &rule_a, 1u);
  config_b = make_config(&inbound_b, 1u, &unused_proxy, 1u, &rule_b, 1u);

  runtime_a = publish_runtime(&environment, &config_a, &plan_a);
  generation_a = fn_runtime_generation(runtime_a);
  CHECK(generation_a != 0u);
  CHECK(fn_runtime_object_find(runtime_a, FN_RUNTIME_RESOURCE_LISTENER,
                               "listener-a", &inbound_id_a).code == FN_OK);

  server.listener = listener_create(&target_port);
  server.status = 0;
  server.bytes = 0u;
  CHECK(pthread_create(&thread, NULL, echo_server_main, &server) == 0);
  socketpair_stream(&environment, &peer_a, &stream_a);
  metadata_init(&metadata, inbound_id_a, target_port);
  memset(&observation_a, 0, sizeof(observation_a));
  CHECK(fn_session_start(environment.session_manager, runtime_a, &stream_a,
                         &metadata, deadline_after(UINT64_C(3000)),
                         session_callback, &observation_a,
                         &observation_a.session).code == FN_OK);
  CHECK(stream_a == NULL);
  wait_for_state(&environment, &observation_a, FN_SESSION_RELAYING);
  CHECK(fn_runtime_release(&runtime_a).code == FN_OK);

  releases_before = environment.backend.release_calls;
  environment.backend.prepare_fail_at =
    environment.backend.prepare_calls + 2u;
  CHECK(fn_runtime_candidate_build(environment.runtime_manager,
                                   &config_failure, &plan_a,
                                   &candidate).code == FN_OK);
  CHECK(fn_budget_snapshot(&environment.memory,
                           &memory_snapshot).code == FN_OK);
  CHECK(memory_snapshot.active > 0u && memory_snapshot.candidate > 0u);
  CHECK(fn_runtime_candidate_prepare(candidate).code == FN_IO_ERROR);
  CHECK(environment.backend.release_calls == releases_before + 1u);
  CHECK(fn_runtime_manager_snapshot(environment.runtime_manager,
                                    &manager_snapshot).code == FN_OK);
  CHECK(manager_snapshot.active_generation == generation_a);
  CHECK(manager_snapshot.candidates == 1u);
  CHECK(manager_snapshot.retained_runtimes == 0u);
  CHECK(fn_runtime_acquire_active(environment.runtime_manager,
                                  &active_check).code == FN_OK);
  CHECK(fn_runtime_generation(active_check) == generation_a);
  CHECK(fn_runtime_release(&active_check).code == FN_OK);
  CHECK(fn_runtime_candidate_destroy(&candidate).code == FN_OK);
  CHECK(fn_budget_snapshot(&environment.memory,
                           &memory_snapshot).code == FN_OK);
  CHECK(memory_snapshot.candidate == 0u);

  environment.backend.prepare_fail_at = 0u;
  CHECK(fn_budget_snapshot(&environment.file_descriptors,
                           &fd_before).code == FN_OK);
  CHECK(fn_runtime_candidate_build(environment.runtime_manager,
                                   &config_b, &plan_b,
                                   &candidate).code == FN_OK);
  CHECK(fn_budget_snapshot(&environment.memory,
                           &memory_snapshot).code == FN_OK);
  CHECK(memory_snapshot.active > 0u && memory_snapshot.candidate > 0u);
  CHECK(fn_runtime_candidate_prepare(candidate).code == FN_OK);
  CHECK(fn_runtime_candidate_commit(environment.runtime_manager,
                                    &candidate).code == FN_OK);
  CHECK(fn_runtime_manager_snapshot(environment.runtime_manager,
                                    &manager_snapshot).code == FN_OK);
  generation_b = manager_snapshot.active_generation;
  CHECK(generation_b > generation_a);
  CHECK(manager_snapshot.candidates == 0u);
  CHECK(manager_snapshot.retained_runtimes == 1u);
  CHECK(fn_budget_snapshot(&environment.memory,
                           &memory_snapshot).code == FN_OK);
  CHECK(memory_snapshot.active > 0u);
  CHECK(memory_snapshot.candidate == 0u);
  CHECK(memory_snapshot.retained > 0u);
  CHECK(memory_snapshot.total <= memory_snapshot.limit);

  CHECK(fn_runtime_candidate_build(environment.runtime_manager,
                                   &config_b, &plan_b,
                                   &peak_candidate).code == FN_OK);
  CHECK(fn_budget_snapshot(&environment.memory,
                           &memory_snapshot).code == FN_OK);
  CHECK(memory_snapshot.active > 0u);
  CHECK(memory_snapshot.candidate > 0u);
  CHECK(memory_snapshot.retained > 0u);
  CHECK(memory_snapshot.total <= memory_snapshot.limit);
  CHECK(fn_runtime_candidate_destroy(&peak_candidate).code == FN_OK);
  CHECK(fn_budget_snapshot(&environment.file_descriptors,
                           &fd_after).code == FN_OK);
  CHECK(fd_after.total == fd_before.total);
  CHECK(environment.backend.lazy_start_calls == 0u);

  CHECK(fn_runtime_acquire_active(environment.runtime_manager,
                                  &runtime_b).code == FN_OK);
  CHECK(fn_runtime_generation(runtime_b) == generation_b);
  CHECK(fn_runtime_object_count(runtime_b) == 1u);
  CHECK(fn_runtime_object_find(runtime_b, FN_RUNTIME_RESOURCE_LISTENER,
                               "listener-b", &inbound_id_b).code == FN_OK);
  CHECK(fn_runtime_object_find(runtime_b, FN_RUNTIME_RESOURCE_SOCKS_PROXY,
                               "unused-proxy", &unused_id).code ==
        FN_INVALID);
  CHECK(fn_runtime_object_find(runtime_b, FN_RUNTIME_RESOURCE_DIRECT,
                               "DIRECT", &unused_id).code == FN_INVALID);
  CHECK(fn_runtime_object_find(runtime_b, FN_RUNTIME_RESOURCE_RESOLVER,
                               "$resolver", &unused_id).code == FN_INVALID);

  socketpair_stream(&environment, &peer_b, &stream_b);
  metadata_init(&metadata, inbound_id_b, 9u);
  memset(&observation_b, 0, sizeof(observation_b));
  CHECK(fn_session_start(environment.session_manager, runtime_b, &stream_b,
                         &metadata, deadline_after(UINT64_C(3000)),
                         session_callback, &observation_b,
                         &observation_b.session).code == FN_OK);
  CHECK(stream_b == NULL);
  CHECK(fn_runtime_release(&runtime_b).code == FN_OK);
  wait_for_terminal(&environment, &observation_b);
  CHECK(observation_b.snapshot.runtime_generation == generation_b);
  CHECK(observation_b.snapshot.terminal_result.code == FN_REJECTED);
  CHECK(observation_b.snapshot.state == FN_SESSION_CLOSED);
  CHECK(fn_socket_close(&peer_b).code == FN_OK);
  CHECK(fn_runtime_manager_snapshot(environment.runtime_manager,
                                    &manager_snapshot).code == FN_OK);
  CHECK(manager_snapshot.retained_runtimes == 1u);

  memset(received, 0, sizeof(received));
  write_all(&environment, peer_a, payload, sizeof(payload));
  read_all(&environment, peer_a, received, sizeof(received));
  CHECK(memcmp(received, payload, sizeof(payload)) == 0);
  CHECK(fn_socket_shutdown_write(peer_a, FN_STAGE_RELAY).code == FN_OK);
  wait_for_terminal(&environment, &observation_a);
  CHECK(observation_a.snapshot.runtime_generation == generation_a);
  CHECK(observation_a.snapshot.terminal_result.code == FN_OK);
  CHECK(observation_a.snapshot.state == FN_SESSION_CLOSED);
  CHECK(observation_a.snapshot.bytes_up == sizeof(payload));
  CHECK(observation_a.snapshot.bytes_down == sizeof(payload));
  CHECK(fn_socket_close(&peer_a).code == FN_OK);
  CHECK(pthread_join(thread, NULL) == 0);
  CHECK(server.status == 0);
  CHECK(server.bytes == sizeof(payload));
  CHECK(close(server.listener) == 0);

  CHECK(fn_runtime_manager_snapshot(environment.runtime_manager,
                                    &manager_snapshot).code == FN_OK);
  CHECK(manager_snapshot.retained_runtimes == 0u);
  CHECK(manager_snapshot.candidates == 0u);
  CHECK(manager_snapshot.async_operations == 0u);
  CHECK(fn_budget_snapshot(&environment.memory,
                           &memory_snapshot).code == FN_OK);
  CHECK(memory_snapshot.candidate == 0u);
  CHECK(memory_snapshot.retained == 0u);
  CHECK(environment.backend.lazy_start_calls == 0u);

  environment_destroy(&environment);
  CHECK(environment.backend.release_calls == 3u);
}

int main(void)
{
  test_runtime_replacement();
  (void)puts("p12 runtime replacement tests passed");
  return 0;
}
