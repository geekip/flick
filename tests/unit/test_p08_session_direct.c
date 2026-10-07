#include "flicknet/clock.h"
#include "flicknet/config.h"
#include "flicknet/direct.h"
#include "flicknet/runtime.h"
#include "flicknet/session.h"

#include <arpa/inet.h>
#include <errno.h>
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
  unsigned long token;
  size_t prepare_calls;
  size_t release_calls;
} runtime_backend_t;

typedef struct {
  fn_limits_t limits;
  fn_budget_t memory;
  fn_budget_t file_descriptors;
  fn_budget_t buffers;
  fn_loop_t *loop;
  fn_relay_buffer_pool_t *relay_pool;
  fn_direct_connector_t *connector;
} test_environment_t;

typedef struct {
  fn_session_t *session;
  size_t calls;
  fn_session_snapshot_t snapshot;
} session_observation_t;

typedef struct {
  fn_direct_connect_t *operation;
  size_t calls;
  fn_result_t result;
  fn_endpoint_t bound;
  fn_endpoint_t connected;
  bool had_stream;
} connect_observation_t;

typedef struct {
  int listener;
  int status;
  uint64_t bytes;
} echo_server_t;

typedef struct {
  int socket;
  int status;
} dns_server_t;

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

static fn_domain_t domain_make(const char *text)
{
  fn_domain_t domain;
  CHECK(fn_domain_from_bytes(&domain, (const uint8_t *)text,
                             strlen(text)).code == FN_OK);
  return domain;
}

static uint64_t deadline_after(uint64_t duration_ms)
{
  uint64_t now_ms;
  uint64_t deadline_ms;
  CHECK(fn_monotonic_now_ms(&now_ms).code == FN_OK);
  CHECK(fn_deadline_after_ms(now_ms, duration_ms, &deadline_ms).code == FN_OK);
  return deadline_ms;
}

static fn_result_t runtime_prepare(
  void *context, const fn_runtime_resource_descriptor_t *descriptor,
  void **out_resource)
{
  runtime_backend_t *backend = context;
  (void)descriptor;
  backend->prepare_calls++;
  *out_resource = &backend->token;
  return test_result(FN_OK, FN_STAGE_NONE);
}

static fn_result_t runtime_lazy_start(void *context, fn_runtime_t *runtime,
                                      fn_object_ref_t object)
{
  (void)context;
  (void)runtime;
  (void)object;
  return test_result(FN_UNSUPPORTED, FN_STAGE_PREPARE);
}

static void runtime_release(
  void *context, const fn_runtime_resource_descriptor_t *descriptor,
  void *resource)
{
  runtime_backend_t *backend = context;
  (void)descriptor;
  CHECK(resource == &backend->token);
  backend->release_calls++;
}

static void environment_init(test_environment_t *environment,
                             size_t fd_limit, size_t session_limit)
{
  fn_loop_options_t loop_options;
  fn_relay_buffer_pool_options_t pool_options;
  fn_direct_connector_options_t connector_options;

  memset(environment, 0, sizeof(*environment));
  environment->limits = fn_limits_default();
  environment->limits.fd_limit = fd_limit;
  environment->limits.session_limit = session_limit;
  environment->limits.owned_memory_limit_bytes = 16u * 1024u * 1024u;
  environment->limits.cleanup_reserve_bytes = 1024u * 1024u;
  environment->limits.buffer_pool_limit_bytes = 4u * 1024u * 1024u;
  CHECK(fn_budget_init(&environment->memory,
                       environment->limits.owned_memory_limit_bytes,
                       environment->limits.cleanup_reserve_bytes).code ==
        FN_OK);
  CHECK(fn_budget_init(&environment->file_descriptors, fd_limit, 0).code ==
        FN_OK);
  CHECK(fn_budget_init(&environment->buffers,
                       environment->limits.buffer_pool_limit_bytes, 0).code ==
        FN_OK);
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
}

static void environment_destroy(test_environment_t *environment)
{
  fn_budget_snapshot_t snapshot;
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

static fn_runtime_t *runtime_create(test_environment_t *environment,
                                    runtime_backend_t *backend,
                                    bool with_resolver,
                                    fn_runtime_manager_t **out_manager,
                                    fn_object_ref_t *out_inbound)
{
  fn_runtime_manager_options_t manager_options;
  fn_runtime_candidate_t *candidate = NULL;
  fn_runtime_t *runtime = NULL;
  fn_inbound_config_t inbound;
  fn_rule_config_t rule;
  fn_config_t config;
  fn_feature_plan_t plan;

  memset(&inbound, 0, sizeof(inbound));
  memcpy(inbound.name, "test-in", sizeof("test-in"));
  inbound.listen = v4_address(127u, 0u, 0u, 1u);
  inbound.port = 1080u;
  memset(&rule, 0, sizeof(rule));
  memcpy(rule.target, "DIRECT", sizeof("DIRECT"));
  memset(&config, 0, sizeof(config));
  config.schema_version = UINT32_C(1);
  config.inbound_count = 1u;
  config.inbounds = &inbound;
  config.rule_count = 1u;
  config.rules = &rule;
  config.allocator = fn_allocator_system();
  memset(&plan, 0, sizeof(plan));
  plan.reachable = FN_FEATURE_SOCKS_IN_TCP | FN_FEATURE_DIRECT_TCP;
  plan.prepare = FN_FEATURE_SOCKS_IN_TCP;
  plan.lazy = FN_FEATURE_DIRECT_TCP;
  if (with_resolver) {
    plan.reachable |= FN_FEATURE_DNS_RESOLVER |
                      FN_FEATURE_DNS_FAILURE_CACHE |
                      FN_FEATURE_DNS_UPSTREAM_UDP;
    plan.lazy |= FN_FEATURE_DNS_RESOLVER |
                 FN_FEATURE_DNS_FAILURE_CACHE |
                 FN_FEATURE_DNS_UPSTREAM_UDP;
  }
  memset(&manager_options, 0, sizeof(manager_options));
  manager_options.loop = environment->loop;
  manager_options.limits = &environment->limits;
  manager_options.owned_memory = &environment->memory;
  manager_options.allocator = fn_allocator_system();
  manager_options.resources.context = backend;
  manager_options.resources.prepare = runtime_prepare;
  manager_options.resources.lazy_start = runtime_lazy_start;
  manager_options.resources.release = runtime_release;
  CHECK(fn_runtime_manager_create(&manager_options, out_manager).code ==
        FN_OK);
  CHECK(fn_runtime_candidate_build(*out_manager, &config, &plan,
                                   &candidate).code == FN_OK);
  CHECK(fn_runtime_candidate_prepare(candidate).code == FN_OK);
  CHECK(fn_runtime_candidate_commit(*out_manager, &candidate).code == FN_OK);
  CHECK(fn_runtime_acquire_active(*out_manager, &runtime).code == FN_OK);
  CHECK(fn_runtime_object_find(runtime, FN_RUNTIME_RESOURCE_LISTENER,
                               "test-in", out_inbound).code == FN_OK);
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

static int socketpair_stream(test_environment_t *environment,
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
  return 0;
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

static void connect_callback(
  fn_direct_connect_t *operation, void *context, fn_result_t result,
  fn_stream_t *owned_stream, const fn_endpoint_t *bound_endpoint,
  const fn_endpoint_t *connected_endpoint)
{
  connect_observation_t *observation = context;
  CHECK(operation == observation->operation);
  observation->calls++;
  observation->result = result;
  if (owned_stream != NULL) {
    observation->had_stream = true;
    CHECK(bound_endpoint != NULL && connected_endpoint != NULL);
    observation->bound = *bound_endpoint;
    observation->connected = *connected_endpoint;
    CHECK(fn_stream_abort(owned_stream).code == FN_OK);
    CHECK(fn_stream_release(&owned_stream).code == FN_OK);
  }
  CHECK(fn_direct_connect_release(&observation->operation).code == FN_OK);
}

static void pump_nowait(fn_loop_t *loop, size_t turns)
{
  size_t index;
  for (index = 0; index < turns; index++) {
    CHECK(fn_loop_run_once(loop, FN_LOOP_RUN_NOWAIT).code == FN_OK);
    (void)sched_yield();
  }
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

static void wait_session(test_environment_t *environment,
                         session_observation_t *observation)
{
  size_t turns;
  for (turns = 0; turns < 100000u && observation->calls == 0; turns++) {
    pump_nowait(environment->loop, 1u);
  }
  CHECK(observation->calls == 1u);
}

static void run_session_payload(test_environment_t *environment,
                                fn_socket_t peer,
                                session_observation_t *observation)
{
  static const uint8_t payload[] = "p08-direct-payload";
  uint8_t received[sizeof(payload)];
  write_all(environment, peer, payload, sizeof(payload));
  memset(received, 0, sizeof(received));
  read_all(environment, peer, received, sizeof(received));
  CHECK(memcmp(received, payload, sizeof(payload)) == 0);
  CHECK(fn_socket_shutdown_write(peer, FN_STAGE_RELAY).code == FN_OK);
  wait_session(environment, observation);
  CHECK(observation->snapshot.terminal_result.code == FN_OK);
  CHECK(observation->snapshot.state == FN_SESSION_CLOSED);
  CHECK(observation->snapshot.bytes_up == sizeof(payload));
  CHECK(observation->snapshot.bytes_down == sizeof(payload));
}

static fn_session_manager_t *session_manager_create(
  test_environment_t *environment, fn_resolver_t *resolver)
{
  fn_session_manager_options_t options;
  fn_session_manager_t *manager = NULL;
  memset(&options, 0, sizeof(options));
  options.loop = environment->loop;
  options.limits = &environment->limits;
  options.owned_memory = &environment->memory;
  options.allocator = fn_allocator_system();
  options.direct_connector = environment->connector;
  options.resolver = resolver;
  options.relay_pool = environment->relay_pool;
  CHECK(fn_session_manager_create(&options, &manager).code == FN_OK);
  return manager;
}

static void set_numeric_metadata(fn_session_metadata_t *metadata,
                                 fn_object_ref_t inbound, uint16_t port)
{
  fn_session_metadata_init(metadata, FN_TCP);
  metadata->route.inbound = inbound;
  metadata->route.original_target = v4_endpoint(127u, 0u, 0u, 1u, port);
}

static void set_domain_metadata(fn_session_metadata_t *metadata,
                                fn_object_ref_t inbound, uint16_t port)
{
  fn_domain_t domain = domain_make("example.org");
  fn_addr_t address;
  fn_session_metadata_init(metadata, FN_TCP);
  metadata->route.inbound = inbound;
  CHECK(fn_addr_from_domain(&address, &domain).code == FN_OK);
  CHECK(fn_endpoint_make(&metadata->route.original_target, &address,
                         port).code == FN_OK);
  CHECK(fn_session_metadata_set_domain(metadata, &domain,
                                       FN_DOMAIN_REQUEST).code == FN_OK);
}

static void test_numeric_session_relay(void)
{
  test_environment_t environment;
  runtime_backend_t backend;
  fn_runtime_manager_t *runtime_manager = NULL;
  fn_runtime_t *runtime;
  fn_object_ref_t inbound_id;
  fn_session_manager_t *session_manager;
  fn_session_manager_snapshot_t manager_snapshot;
  fn_session_metadata_t metadata;
  fn_stream_t *inbound_stream = NULL;
  fn_socket_t peer = fn_socket_invalid();
  session_observation_t observation;
  echo_server_t server;
  pthread_t thread;
  uint16_t port;

  environment_init(&environment, 64u, 8u);
  memset(&backend, 0, sizeof(backend));
  runtime = runtime_create(&environment, &backend, false,
                           &runtime_manager, &inbound_id);
  session_manager = session_manager_create(&environment, NULL);
  server.listener = listener_create(&port);
  server.status = 0;
  server.bytes = 0;
  CHECK(pthread_create(&thread, NULL, echo_server_main, &server) == 0);
  (void)socketpair_stream(&environment, &peer, &inbound_stream);
  set_numeric_metadata(&metadata, inbound_id, port);
  memset(&observation, 0, sizeof(observation));
  CHECK(fn_session_start(session_manager, runtime, &inbound_stream, &metadata,
                         deadline_after(UINT64_C(3000)), session_callback,
                         &observation, &observation.session).code == FN_OK);
  CHECK(inbound_stream == NULL);
  run_session_payload(&environment, peer, &observation);
  CHECK(observation.snapshot.bound_endpoint.port != 0);
  CHECK(observation.snapshot.connected_endpoint.port == port);
  CHECK(fn_socket_close(&peer).code == FN_OK);
  CHECK(pthread_join(thread, NULL) == 0);
  CHECK(server.status == 0);
  CHECK(close(server.listener) == 0);
  CHECK(fn_session_manager_snapshot(session_manager,
                                    &manager_snapshot).code == FN_OK);
  CHECK(manager_snapshot.active_sessions == 0u);
  CHECK(fn_session_manager_destroy(&session_manager).code == FN_OK);
  CHECK(fn_runtime_release(&runtime).code == FN_OK);
  CHECK(fn_runtime_manager_destroy(&runtime_manager).code == FN_OK);
  CHECK(backend.release_calls == 1u);
  environment_destroy(&environment);
}

static void *dns_server_main(void *context)
{
  dns_server_t *server = context;
  struct sockaddr_in client;
  socklen_t client_length = (socklen_t)sizeof(client);
  uint8_t query[512];
  uint8_t response[544];
  ssize_t received = recvfrom(server->socket, query, sizeof(query), 0,
                              (struct sockaddr *)&client, &client_length);
  size_t length;
  size_t offset;
  size_t index;
  const uint8_t addresses[2][4] = {
    {127u, 0u, 0u, 2u}, {127u, 0u, 0u, 1u},
  };
  if (received < 12) {
    server->status = 1;
    return NULL;
  }
  length = (size_t)received;
  memcpy(response, query, length);
  fn_u16_write_be(response + 2u, UINT16_C(0x8180));
  fn_u16_write_be(response + 6u, UINT16_C(2));
  offset = length;
  for (index = 0; index < 2u; index++) {
    static const uint8_t rr[] = {
      0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x3c, 0x00, 0x04,
    };
    memcpy(response + offset, rr, sizeof(rr));
    offset += sizeof(rr);
    memcpy(response + offset, addresses[index], 4u);
    offset += 4u;
  }
  if (sendto(server->socket, response, offset, 0,
             (const struct sockaddr *)&client, client_length) !=
      (ssize_t)offset) {
    server->status = 2;
  }
  return NULL;
}

static int dns_socket_create(uint16_t *port)
{
  int descriptor = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in address;
  socklen_t length = (socklen_t)sizeof(address);
  CHECK(descriptor >= 0);
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  CHECK(bind(descriptor, (const struct sockaddr *)&address,
             (socklen_t)sizeof(address)) == 0);
  CHECK(getsockname(descriptor, (struct sockaddr *)&address, &length) == 0);
  *port = ntohs(address.sin_port);
  return descriptor;
}

static fn_resolver_t *resolver_create(test_environment_t *environment,
                                      uint16_t dns_port)
{
  fn_resolver_options_t options;
  fn_resolver_t *resolver = NULL;
  memset(&options, 0, sizeof(options));
  options.loop = environment->loop;
  options.limits = &environment->limits;
  options.owned_memory = &environment->memory;
  options.file_descriptors = &environment->file_descriptors;
  options.allocator = fn_allocator_system();
  options.config.direct_present = true;
  options.config.direct_count = 1u;
  options.config.direct[0].transport = FN_DNS_TRANSPORT_UDP;
  options.config.direct[0].endpoint =
    v4_endpoint(127u, 0u, 0u, 1u, dns_port);
  options.config.timeout_ms = UINT64_C(500);
  options.config.attempts = UINT32_C(2);
  options.config.failure_cache_size = 8u;
  options.config.failure_cache_ttl_ms = UINT64_C(5000);
  options.generation = UINT64_C(1);
  CHECK(fn_resolver_create(&options, &resolver).code == FN_OK);
  return resolver;
}

static void test_domain_session_candidates(void)
{
  test_environment_t environment;
  runtime_backend_t backend;
  fn_runtime_manager_t *runtime_manager = NULL;
  fn_runtime_t *runtime;
  fn_object_ref_t inbound_id;
  fn_resolver_t *resolver;
  fn_session_manager_t *session_manager;
  fn_session_metadata_t metadata;
  fn_stream_t *inbound_stream = NULL;
  fn_socket_t peer = fn_socket_invalid();
  fn_direct_connector_snapshot_t before;
  fn_direct_connector_snapshot_t after;
  session_observation_t observation;
  echo_server_t echo_server;
  dns_server_t dns_server;
  pthread_t echo_thread;
  pthread_t dns_thread;
  uint16_t echo_port;
  uint16_t dns_port;

  environment_init(&environment, 64u, 8u);
  memset(&backend, 0, sizeof(backend));
  runtime = runtime_create(&environment, &backend, true,
                           &runtime_manager, &inbound_id);
  dns_server.socket = dns_socket_create(&dns_port);
  dns_server.status = 0;
  CHECK(pthread_create(&dns_thread, NULL, dns_server_main, &dns_server) == 0);
  resolver = resolver_create(&environment, dns_port);
  session_manager = session_manager_create(&environment, resolver);
  echo_server.listener = listener_create(&echo_port);
  echo_server.status = 0;
  echo_server.bytes = 0;
  CHECK(pthread_create(&echo_thread, NULL, echo_server_main,
                       &echo_server) == 0);
  (void)socketpair_stream(&environment, &peer, &inbound_stream);
  set_domain_metadata(&metadata, inbound_id, echo_port);
  CHECK(fn_direct_connector_snapshot(environment.connector, &before).code ==
        FN_OK);
  memset(&observation, 0, sizeof(observation));
  CHECK(fn_session_start(session_manager, runtime, &inbound_stream, &metadata,
                         deadline_after(UINT64_C(3000)), session_callback,
                         &observation, &observation.session).code == FN_OK);
  run_session_payload(&environment, peer, &observation);
  CHECK(fn_direct_connector_snapshot(environment.connector, &after).code ==
        FN_OK);
  CHECK(after.attempts - before.attempts == 2u);
  CHECK(observation.snapshot.connected_endpoint.address.value.v4[3] == 1u);
  CHECK(fn_socket_close(&peer).code == FN_OK);
  CHECK(pthread_join(dns_thread, NULL) == 0);
  CHECK(dns_server.status == 0);
  CHECK(close(dns_server.socket) == 0);
  CHECK(pthread_join(echo_thread, NULL) == 0);
  CHECK(echo_server.status == 0);
  CHECK(close(echo_server.listener) == 0);
  CHECK(fn_session_manager_destroy(&session_manager).code == FN_OK);
  CHECK(fn_resolver_destroy(&resolver).code == FN_OK);
  CHECK(fn_runtime_release(&runtime).code == FN_OK);
  CHECK(fn_runtime_manager_destroy(&runtime_manager).code == FN_OK);
  environment_destroy(&environment);
}

static uint16_t unused_port(void)
{
  uint16_t port;
  int descriptor = listener_create(&port);
  CHECK(close(descriptor) == 0);
  return port;
}

static void test_connect_failure_cancel_and_zero_fd(void)
{
  test_environment_t environment;
  connect_observation_t observation;
  fn_endpoint_t target;
  fn_resolved_t resolved;
  fn_direct_connector_snapshot_t snapshot;
  uint16_t port;
  size_t turns;

  environment_init(&environment, 64u, 8u);
  port = unused_port();
  memset(&resolved, 0, sizeof(resolved));
  resolved.count = 2u;
  resolved.addresses[0] = v4_address(127u, 0u, 0u, 2u);
  resolved.addresses[1] = v4_address(127u, 0u, 0u, 3u);
  target.address.kind = FN_ADDR_DOMAIN;
  target.address.value.domain = domain_make("example.org");
  target.port = port;
  memset(&observation, 0, sizeof(observation));
  CHECK(fn_direct_connect_start(
          environment.connector, &target, &resolved, UINT16_C(3),
          deadline_after(UINT64_C(2000)), connect_callback, &observation,
          &observation.operation).code == FN_OK);
  for (turns = 0; turns < 10000u && observation.calls == 0; turns++) {
    pump_nowait(environment.loop, 1u);
  }
  CHECK(observation.calls == 1u);
  CHECK(observation.result.code == FN_CONNECTION_REFUSED);
  CHECK(fn_direct_connector_snapshot(environment.connector, &snapshot).code ==
        FN_OK);
  CHECK(snapshot.open_sockets == 0u);

  memset(&observation, 0, sizeof(observation));
  target = v4_endpoint(127u, 0u, 0u, 1u, port);
  CHECK(fn_direct_connect_start(
          environment.connector, &target, NULL, 0,
          deadline_after(UINT64_C(2000)), connect_callback, &observation,
          &observation.operation).code == FN_OK);
  CHECK(fn_direct_connect_cancel(observation.operation).code == FN_OK);
  pump_nowait(environment.loop, 4u);
  CHECK(observation.calls == 1u);
  CHECK(observation.result.code == FN_CANCELLED);
  environment_destroy(&environment);

  environment_init(&environment, 3u, 8u);
  memset(&observation, 0, sizeof(observation));
  CHECK(fn_direct_connect_start(
          environment.connector, &target, NULL, 0,
          deadline_after(UINT64_C(2000)), connect_callback, &observation,
          &observation.operation).code == FN_LIMIT);
  CHECK(observation.operation == NULL);
  CHECK(observation.calls == 0u);
  environment_destroy(&environment);
}

static void test_session_limit_and_close(void)
{
  test_environment_t environment;
  runtime_backend_t backend;
  fn_runtime_manager_t *runtime_manager = NULL;
  fn_runtime_t *runtime;
  fn_object_ref_t inbound_id;
  fn_session_manager_t *session_manager;
  fn_session_metadata_t metadata;
  fn_stream_t *inbound_stream = NULL;
  fn_socket_t peer = fn_socket_invalid();
  session_observation_t observation;
  uint16_t port = unused_port();

  environment_init(&environment, 64u, 0u);
  memset(&backend, 0, sizeof(backend));
  runtime = runtime_create(&environment, &backend, false,
                           &runtime_manager, &inbound_id);
  session_manager = session_manager_create(&environment, NULL);
  (void)socketpair_stream(&environment, &peer, &inbound_stream);
  set_numeric_metadata(&metadata, inbound_id, port);
  memset(&observation, 0, sizeof(observation));
  CHECK(fn_session_start(session_manager, runtime, &inbound_stream, &metadata,
                         deadline_after(UINT64_C(2000)), session_callback,
                         &observation, &observation.session).code == FN_LIMIT);
  CHECK(inbound_stream != NULL);
  CHECK(observation.calls == 0u);
  CHECK(fn_stream_release(&inbound_stream).code == FN_OK);
  CHECK(fn_socket_close(&peer).code == FN_OK);
  CHECK(fn_session_manager_destroy(&session_manager).code == FN_OK);
  CHECK(fn_runtime_release(&runtime).code == FN_OK);
  CHECK(fn_runtime_manager_destroy(&runtime_manager).code == FN_OK);
  environment_destroy(&environment);

  environment_init(&environment, 64u, 1u);
  memset(&backend, 0, sizeof(backend));
  runtime = runtime_create(&environment, &backend, false,
                           &runtime_manager, &inbound_id);
  session_manager = session_manager_create(&environment, NULL);
  (void)socketpair_stream(&environment, &peer, &inbound_stream);
  set_numeric_metadata(&metadata, inbound_id, port);
  memset(&observation, 0, sizeof(observation));
  CHECK(fn_session_start(session_manager, runtime, &inbound_stream, &metadata,
                         deadline_after(UINT64_C(2000)), session_callback,
                         &observation, &observation.session).code == FN_OK);
  CHECK(fn_session_close(
          observation.session,
          test_result(FN_CANCELLED, FN_STAGE_SHUTDOWN)).code == FN_OK);
  wait_session(&environment, &observation);
  CHECK(observation.snapshot.terminal_result.code == FN_CANCELLED);
  CHECK(fn_socket_close(&peer).code == FN_OK);
  CHECK(fn_session_manager_destroy(&session_manager).code == FN_OK);
  CHECK(fn_runtime_release(&runtime).code == FN_OK);
  CHECK(fn_runtime_manager_destroy(&runtime_manager).code == FN_OK);
  environment_destroy(&environment);
}

int main(void)
{
  test_numeric_session_relay();
  test_domain_session_candidates();
  test_connect_failure_cancel_and_zero_fd();
  test_session_limit_and_close();
  (void)puts("p08 session/direct tests passed");
  return 0;
}
