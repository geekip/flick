#define _GNU_SOURCE

#include "flicknet/clock.h"
#include "flicknet/config.h"
#include "flicknet/direct.h"
#include "flicknet/resolver.h"
#include "flicknet/runtime.h"
#include "flicknet/session.h"
#include "flicknet/socks5.h"
#include "flicknet/socks5_outbound.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      (void)fprintf(stderr, "check failed: %s:%d: %s\n", __FILE__,          \
                    __LINE__, #condition);                                     \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

static const uint8_t test_payload[] = "p10-domain-preread";
static const uint8_t test_response[] = "p10-double-chain-response";

typedef struct {
  unsigned long token;
  size_t release_calls;
} runtime_backend_t;

typedef struct {
  int descriptor;
  int status;
} dns_server_t;

typedef struct {
  int proxy_listener;
  uint16_t target_port;
  int status;
} proxy_server_t;

typedef struct {
  int target_listener;
  int status;
} target_server_t;

typedef struct {
  fn_limits_t limits;
  fn_budget_t memory;
  fn_budget_t file_descriptors;
  fn_budget_t buffers;
  fn_loop_t *loop;
  fn_relay_buffer_pool_t *relay_pool;
  fn_direct_connector_t *connector;
  fn_resolver_t *resolver;
  fn_socks5_outbound_manager_t *outbound_manager;
} test_environment_t;

typedef struct {
  fn_session_manager_t *session_manager;
  fn_socks5_handshake_t *handshake;
  fn_session_t *session;
  fn_session_snapshot_t snapshot;
  size_t handshake_calls;
  size_t session_calls;
  fn_result_t handshake_result;
  fn_result_t submit_result;
  uint64_t deadline_ms;
} chain_observation_t;

static fn_result_t test_result(fn_status_t code, fn_error_stage_t stage)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE : stage,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static uint64_t deadline_after(uint64_t duration_ms)
{
  uint64_t now_ms;
  uint64_t deadline_ms;
  CHECK(fn_monotonic_now_ms(&now_ms).code == FN_OK);
  CHECK(fn_deadline_after_ms(now_ms, duration_ms, &deadline_ms).code == FN_OK);
  return deadline_ms;
}

static fn_addr_t v4_address(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
  const uint8_t bytes[4] = {a, b, c, d};
  fn_addr_t address;
  CHECK(fn_addr_from_v4(&address, bytes).code == FN_OK);
  return address;
}

static fn_addr_t domain_address(const char *name)
{
  fn_domain_t domain;
  fn_addr_t address;
  CHECK(fn_domain_from_bytes(&domain, (const uint8_t *)name,
                             strlen(name)).code == FN_OK);
  CHECK(fn_addr_from_domain(&address, &domain).code == FN_OK);
  return address;
}

static fn_endpoint_t v4_endpoint(uint16_t port)
{
  fn_endpoint_t endpoint;
  fn_addr_t address = v4_address(127u, 0u, 0u, 1u);
  CHECK(fn_endpoint_make(&endpoint, &address, port).code == FN_OK);
  return endpoint;
}

static bool read_exact_fd(int descriptor, uint8_t *buffer, size_t length)
{
  size_t offset = 0;
  while (offset < length) {
    ssize_t count = recv(descriptor, buffer + offset, length - offset, 0);
    if (count <= 0) {
      return false;
    }
    offset += (size_t)count;
  }
  return true;
}

static bool write_exact_fd(int descriptor, const uint8_t *buffer,
                           size_t length)
{
  size_t offset = 0;
  while (offset < length) {
    ssize_t count = send(descriptor, buffer + offset, length - offset,
                         MSG_NOSIGNAL);
    if (count <= 0) {
      return false;
    }
    offset += (size_t)count;
  }
  return true;
}

static int tcp_listener_create(uint16_t *out_port)
{
  struct sockaddr_in address;
  socklen_t length = (socklen_t)sizeof(address);
  int descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  CHECK(descriptor >= 0);
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(bind(descriptor, (const struct sockaddr *)&address,
             (socklen_t)sizeof(address)) == 0);
  CHECK(listen(descriptor, 4) == 0);
  CHECK(getsockname(descriptor, (struct sockaddr *)&address, &length) == 0);
  *out_port = ntohs(address.sin_port);
  return descriptor;
}

static int udp_server_create(uint16_t *out_port)
{
  struct sockaddr_in address;
  socklen_t length = (socklen_t)sizeof(address);
  int descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  CHECK(descriptor >= 0);
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  CHECK(bind(descriptor, (const struct sockaddr *)&address,
             (socklen_t)sizeof(address)) == 0);
  CHECK(getsockname(descriptor, (struct sockaddr *)&address, &length) == 0);
  *out_port = ntohs(address.sin_port);
  return descriptor;
}

static void *dns_server_main(void *context)
{
  dns_server_t *server = context;
  struct sockaddr_in client;
  socklen_t client_length = (socklen_t)sizeof(client);
  uint8_t query[FN_DNS_MESSAGE_UDP_MAX];
  uint8_t response[FN_DNS_MESSAGE_UDP_MAX];
  ssize_t count = recvfrom(server->descriptor, query, sizeof(query), 0,
                           (struct sockaddr *)&client, &client_length);
  size_t query_length;
  size_t response_length;
  if (count < 12) {
    server->status = 1;
    return NULL;
  }
  query_length = (size_t)count;
  if (query_length + 16u > sizeof(response)) {
    server->status = 2;
    return NULL;
  }
  memcpy(response, query, query_length);
  fn_u16_write_be(response + 2u, UINT16_C(0x8180));
  fn_u16_write_be(response + 6u, UINT16_C(1));
  fn_u16_write_be(response + 8u, UINT16_C(0));
  fn_u16_write_be(response + 10u, UINT16_C(0));
  response_length = query_length;
  response[response_length++] = UINT8_C(0xc0);
  response[response_length++] = UINT8_C(0x0c);
  response[response_length++] = 0;
  response[response_length++] = 1;
  response[response_length++] = 0;
  response[response_length++] = 1;
  response[response_length++] = 0;
  response[response_length++] = 0;
  response[response_length++] = 0;
  response[response_length++] = 60;
  response[response_length++] = 0;
  response[response_length++] = 4;
  response[response_length++] = 127u;
  response[response_length++] = 0;
  response[response_length++] = 0;
  response[response_length++] = 1;
  if (sendto(server->descriptor, response, response_length, 0,
             (const struct sockaddr *)&client, client_length) !=
      (ssize_t)response_length) {
    server->status = 3;
    return NULL;
  }
  server->status = 0;
  return NULL;
}

static void *target_server_main(void *context)
{
  target_server_t *server = context;
  uint8_t payload[sizeof(test_payload)];
  int accepted = accept(server->target_listener, NULL, NULL);
  if (accepted < 0 || !read_exact_fd(accepted, payload, sizeof(payload)) ||
      memcmp(payload, test_payload, sizeof(payload)) != 0) {
    server->status = 1;
    if (accepted >= 0) {
      (void)close(accepted);
    }
    return NULL;
  }
  if (!write_exact_fd(accepted, test_response, sizeof(test_response)) ||
      shutdown(accepted, SHUT_WR) != 0) {
    server->status = 2;
    (void)close(accepted);
    return NULL;
  }
  server->status = 0;
  (void)close(accepted);
  return NULL;
}

static void *proxy_server_main(void *context)
{
  proxy_server_t *server = context;
  struct sockaddr_in target_address;
  uint8_t greeting[3];
  uint8_t auth[8];
  uint8_t request[18];
  uint8_t payload[sizeof(test_payload)];
  uint8_t response[sizeof(test_response)];
  const uint8_t method[2] = {UINT8_C(5), UINT8_C(2)};
  const uint8_t auth_success[2] = {UINT8_C(1), UINT8_C(0)};
  const uint8_t success[] = {
    UINT8_C(5), UINT8_C(0), UINT8_C(0), UINT8_C(3), UINT8_C(11),
    'b', 'o', 'u', 'n', 'd', '.', 'l', 'o', 'c', 'a', 'l',
    UINT8_C(0xc3), UINT8_C(0x50),
  };
  int client = accept(server->proxy_listener, NULL, NULL);
  int target = -1;
  if (client < 0 || !read_exact_fd(client, greeting, sizeof(greeting)) ||
      memcmp(greeting, (const uint8_t[]){5, 1, 2}, 3u) != 0 ||
      !write_exact_fd(client, method, sizeof(method)) ||
      !read_exact_fd(client, auth, sizeof(auth)) ||
      memcmp(auth, (const uint8_t[]){1, 3, 'b', 'o', 'b', 2, 'p', 'w'},
             sizeof(auth)) != 0 ||
      !write_exact_fd(client, auth_success, sizeof(auth_success)) ||
      !read_exact_fd(client, request, sizeof(request)) ||
      memcmp(request,
             (const uint8_t[]){5, 1, 0, 3, 11,
                               't', 'a', 'r', 'g', 'e', 't', '.',
                               't', 'e', 's', 't'},
             16u) != 0 ||
      fn_u16_read_be(request + 16u) != server->target_port) {
    server->status = 1;
    if (client >= 0) {
      (void)close(client);
    }
    return NULL;
  }
  target = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  memset(&target_address, 0, sizeof(target_address));
  target_address.sin_family = AF_INET;
  target_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  target_address.sin_port = htons(server->target_port);
  if (target < 0 ||
      connect(target, (const struct sockaddr *)&target_address,
              (socklen_t)sizeof(target_address)) != 0 ||
      !write_exact_fd(client, success, sizeof(success)) ||
      !read_exact_fd(client, payload, sizeof(payload)) ||
      !write_exact_fd(target, payload, sizeof(payload)) ||
      !read_exact_fd(target, response, sizeof(response)) ||
      !write_exact_fd(client, response, sizeof(response)) ||
      shutdown(client, SHUT_WR) != 0) {
    server->status = 2;
    if (target >= 0) {
      (void)close(target);
    }
    (void)close(client);
    return NULL;
  }
  server->status = 0;
  (void)close(target);
  (void)close(client);
  return NULL;
}

static void environment_init(test_environment_t *environment,
                             uint16_t dns_port)
{
  fn_loop_options_t loop_options;
  fn_relay_buffer_pool_options_t pool_options;
  fn_direct_connector_options_t connector_options;
  fn_resolver_options_t resolver_options;
  fn_socks5_outbound_manager_options_t outbound_options;
  fn_dns_config_t dns;
  memset(environment, 0, sizeof(*environment));
  environment->limits = fn_limits_default();
  environment->limits.fd_limit = 64u;
  environment->limits.session_limit = 8u;
  environment->limits.owned_memory_limit_bytes = 16u * 1024u * 1024u;
  environment->limits.cleanup_reserve_bytes = 1024u * 1024u;
  environment->limits.buffer_pool_limit_bytes = 4u * 1024u * 1024u;
  CHECK(fn_budget_init(&environment->memory,
                       environment->limits.owned_memory_limit_bytes,
                       environment->limits.cleanup_reserve_bytes).code ==
        FN_OK);
  CHECK(fn_budget_init(&environment->file_descriptors,
                       environment->limits.fd_limit, 0).code == FN_OK);
  CHECK(fn_budget_init(&environment->buffers,
                       environment->limits.buffer_pool_limit_bytes,
                       0).code == FN_OK);
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
  connector_options.connect_timeout_ms = UINT64_C(1000);
  CHECK(fn_direct_connector_create(&connector_options,
                                   &environment->connector).code == FN_OK);
  memset(&dns, 0, sizeof(dns));
  dns.bootstrap_present = true;
  dns.bootstrap_count = 1u;
  dns.bootstrap[0].transport = FN_DNS_TRANSPORT_UDP;
  dns.bootstrap[0].endpoint = v4_endpoint(dns_port);
  dns.timeout_ms = UINT64_C(1000);
  dns.attempts = UINT32_C(1);
  dns.failure_cache_size = 8u;
  dns.failure_cache_ttl_ms = UINT64_C(1000);
  memset(&resolver_options, 0, sizeof(resolver_options));
  resolver_options.loop = environment->loop;
  resolver_options.limits = &environment->limits;
  resolver_options.owned_memory = &environment->memory;
  resolver_options.file_descriptors = &environment->file_descriptors;
  resolver_options.allocator = fn_allocator_system();
  resolver_options.config = dns;
  resolver_options.generation = UINT64_C(10);
  CHECK(fn_resolver_create(&resolver_options,
                           &environment->resolver).code == FN_OK);
  memset(&outbound_options, 0, sizeof(outbound_options));
  outbound_options.loop = environment->loop;
  outbound_options.limits = &environment->limits;
  outbound_options.owned_memory = &environment->memory;
  outbound_options.allocator = fn_allocator_system();
  outbound_options.tcp_connector = environment->connector;
  outbound_options.resolver = environment->resolver;
  CHECK(fn_socks5_outbound_manager_create(
          &outbound_options, &environment->outbound_manager).code == FN_OK);
}

static void environment_destroy(test_environment_t *environment)
{
  fn_budget_snapshot_t snapshot;
  CHECK(fn_socks5_outbound_manager_destroy(
          &environment->outbound_manager).code == FN_OK);
  CHECK(fn_resolver_destroy(&environment->resolver).code == FN_OK);
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

static fn_result_t runtime_prepare(
  void *context, const fn_runtime_resource_descriptor_t *descriptor,
  void **out_resource)
{
  runtime_backend_t *backend = context;
  (void)descriptor;
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

static fn_runtime_t *runtime_create(
  test_environment_t *environment, runtime_backend_t *backend,
  uint16_t proxy_port, fn_runtime_manager_t **out_manager,
  fn_object_ref_t *out_inbound)
{
  fn_runtime_manager_options_t options;
  fn_runtime_candidate_t *candidate = NULL;
  fn_runtime_t *runtime = NULL;
  fn_inbound_config_t inbound;
  fn_proxy_config_t proxy;
  fn_rule_config_t rule;
  fn_config_t config;
  fn_feature_plan_t plan;
  memset(&inbound, 0, sizeof(inbound));
  memcpy(inbound.name, "socks-in", sizeof("socks-in"));
  inbound.listen = v4_address(127u, 0u, 0u, 1u);
  inbound.port = UINT16_C(1080);
  memset(&proxy, 0, sizeof(proxy));
  memcpy(proxy.name, "upstream", sizeof("upstream"));
  proxy.server = domain_address("proxy.test");
  proxy.port = proxy_port;
  proxy.has_credentials = true;
  memcpy(proxy.credentials.username, "bob", 3u);
  proxy.credentials.username_length = 3u;
  memcpy(proxy.credentials.password, "pw", 2u);
  proxy.credentials.password_length = 2u;
  memset(&rule, 0, sizeof(rule));
  memcpy(rule.target, "upstream", sizeof("upstream"));
  memset(&config, 0, sizeof(config));
  config.schema_version = UINT32_C(1);
  config.inbound_count = 1u;
  config.inbounds = &inbound;
  config.proxy_count = 1u;
  config.proxies = &proxy;
  config.rule_count = 1u;
  config.rules = &rule;
  config.allocator = fn_allocator_system();
  memset(&plan, 0, sizeof(plan));
  plan.reachable = FN_FEATURE_SOCKS_IN_TCP | FN_FEATURE_SOCKS_OUT_TCP |
                   FN_FEATURE_DNS_RESOLVER | FN_FEATURE_DNS_UPSTREAM_UDP |
                   FN_FEATURE_DNS_FAILURE_CACHE;
  plan.prepare = FN_FEATURE_SOCKS_IN_TCP;
  plan.lazy = plan.reachable & ~plan.prepare;
  memset(&options, 0, sizeof(options));
  options.loop = environment->loop;
  options.limits = &environment->limits;
  options.owned_memory = &environment->memory;
  options.allocator = fn_allocator_system();
  options.resources.context = backend;
  options.resources.prepare = runtime_prepare;
  options.resources.lazy_start = runtime_lazy_start;
  options.resources.release = runtime_release;
  CHECK(fn_runtime_manager_create(&options, out_manager).code == FN_OK);
  CHECK(fn_runtime_candidate_build(*out_manager, &config, &plan,
                                   &candidate).code == FN_OK);
  CHECK(fn_runtime_candidate_prepare(candidate).code == FN_OK);
  CHECK(fn_runtime_candidate_commit(*out_manager, &candidate).code == FN_OK);
  CHECK(fn_runtime_acquire_active(*out_manager, &runtime).code == FN_OK);
  CHECK(fn_runtime_object_find(runtime, FN_RUNTIME_RESOURCE_LISTENER,
                               "socks-in", out_inbound).code == FN_OK);
  return runtime;
}

static fn_session_manager_t *session_manager_create(
  test_environment_t *environment)
{
  fn_session_manager_options_t options;
  fn_session_manager_t *manager = NULL;
  memset(&options, 0, sizeof(options));
  options.loop = environment->loop;
  options.limits = &environment->limits;
  options.owned_memory = &environment->memory;
  options.allocator = fn_allocator_system();
  options.direct_connector = environment->connector;
  options.socks5_outbound_manager = environment->outbound_manager;
  options.resolver = environment->resolver;
  options.relay_pool = environment->relay_pool;
  CHECK(fn_session_manager_create(&options, &manager).code == FN_OK);
  return manager;
}

static fn_socks5_inbound_manager_t *inbound_manager_create(
  test_environment_t *environment)
{
  fn_socks5_inbound_manager_options_t options;
  fn_socks5_inbound_manager_t *manager = NULL;
  memset(&options, 0, sizeof(options));
  options.loop = environment->loop;
  options.limits = &environment->limits;
  options.owned_memory = &environment->memory;
  options.buffer_bytes = &environment->buffers;
  options.allocator = fn_allocator_system();
  CHECK(fn_socks5_inbound_manager_create(&options, &manager).code == FN_OK);
  return manager;
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
}

static void pump(test_environment_t *environment, size_t turns)
{
  size_t index;
  for (index = 0; index < turns; index++) {
    CHECK(fn_loop_run_once(environment->loop, FN_LOOP_RUN_NOWAIT).code ==
          FN_OK);
    (void)sched_yield();
  }
}

static void client_write_all(test_environment_t *environment,
                             fn_socket_t socket, const uint8_t *data,
                             size_t length)
{
  size_t offset = 0;
  size_t turns;
  for (turns = 0; turns < 200000u && offset < length; turns++) {
    fn_io_result_t io = fn_socket_write(socket, data + offset,
                                        length - offset, FN_STAGE_RELAY);
    if (io.result.code == FN_OK) {
      offset += io.transferred;
    } else {
      CHECK(io.result.code == FN_AGAIN);
    }
    pump(environment, 1u);
  }
  CHECK(offset == length);
}

static void client_read_all(test_environment_t *environment,
                            fn_socket_t socket, uint8_t *data,
                            size_t length)
{
  size_t offset = 0;
  size_t turns;
  for (turns = 0; turns < 200000u && offset < length; turns++) {
    fn_io_result_t io = fn_socket_read(socket, data + offset,
                                       length - offset, FN_STAGE_RELAY);
    if (io.result.code == FN_OK) {
      offset += io.transferred;
    } else {
      if (io.result.code != FN_AGAIN) {
        (void)fprintf(stderr,
                      "client read failed: code=%d stage=%d origin=%d native=%lld offset=%zu expected=%zu\n",
                      (int)io.result.code, (int)io.result.stage,
                      (int)io.result.origin,
                      (long long)io.result.native_code, offset, length);
      }
      CHECK(io.result.code == FN_AGAIN);
    }
    pump(environment, 1u);
  }
  CHECK(offset == length);
}

static void session_done(fn_session_t *session, void *context,
                         const fn_session_snapshot_t *snapshot)
{
  chain_observation_t *observation = context;
  CHECK(session == observation->session);
  observation->session_calls++;
  observation->snapshot = *snapshot;
  if (snapshot->terminal_result.code != FN_OK) {
    (void)fprintf(stderr,
                  "session failed: code=%d stage=%d origin=%d native=%lld\n",
                  (int)snapshot->terminal_result.code,
                  (int)snapshot->terminal_result.stage,
                  (int)snapshot->terminal_result.origin,
                  (long long)snapshot->terminal_result.native_code);
  }
  CHECK(fn_session_release(&observation->session).code == FN_OK);
}

static void handshake_done(fn_socks5_handshake_t *handshake,
                           void *context, fn_result_t result,
                           fn_inbound_request_t *request)
{
  chain_observation_t *observation = context;
  CHECK(handshake == observation->handshake);
  observation->handshake_calls++;
  observation->handshake_result = result;
  CHECK(fn_socks5_handshake_release(&observation->handshake).code == FN_OK);
  CHECK(result.code == FN_OK);
  CHECK(request != NULL);
  observation->submit_result = fn_session_submit(
    observation->session_manager, &request, observation->deadline_ms,
    session_done, observation, &observation->session);
  CHECK(observation->submit_result.code == FN_OK);
  CHECK(request == NULL);
}

static void test_double_chain_with_bootstrap(void)
{
  dns_server_t dns_server;
  proxy_server_t proxy_server;
  target_server_t target_server;
  test_environment_t environment;
  runtime_backend_t backend;
  fn_runtime_manager_t *runtime_manager = NULL;
  fn_runtime_t *runtime;
  fn_object_ref_t inbound_id;
  fn_session_manager_t *session_manager;
  fn_socks5_inbound_manager_t *inbound_manager;
  fn_stream_t *accepted_stream = NULL;
  fn_socket_t client = fn_socket_invalid();
  fn_endpoint_t source = v4_endpoint(UINT16_C(50010));
  chain_observation_t observation;
  pthread_t dns_thread;
  pthread_t proxy_thread;
  pthread_t target_thread;
  uint16_t dns_port;
  uint16_t proxy_port;
  uint16_t target_port;
  uint8_t request[21u + sizeof(test_payload)];
  uint8_t replies[20];
  uint8_t response[sizeof(test_response)];
  uint64_t accepted_at_ms;
  size_t turns;

  memset(&dns_server, 0, sizeof(dns_server));
  memset(&proxy_server, 0, sizeof(proxy_server));
  memset(&target_server, 0, sizeof(target_server));
  dns_server.descriptor = udp_server_create(&dns_port);
  proxy_server.proxy_listener = tcp_listener_create(&proxy_port);
  target_server.target_listener = tcp_listener_create(&target_port);
  proxy_server.target_port = target_port;
  CHECK(pthread_create(&dns_thread, NULL, dns_server_main, &dns_server) == 0);
  CHECK(pthread_create(&proxy_thread, NULL, proxy_server_main,
                       &proxy_server) == 0);
  CHECK(pthread_create(&target_thread, NULL, target_server_main,
                       &target_server) == 0);

  environment_init(&environment, dns_port);
  memset(&backend, 0, sizeof(backend));
  runtime = runtime_create(&environment, &backend, proxy_port,
                           &runtime_manager, &inbound_id);
  session_manager = session_manager_create(&environment);
  inbound_manager = inbound_manager_create(&environment);
  socketpair_stream(&environment, &client, &accepted_stream);
  memset(&observation, 0, sizeof(observation));
  observation.session_manager = session_manager;
  observation.deadline_ms = deadline_after(UINT64_C(5000));
  CHECK(fn_monotonic_now_ms(&accepted_at_ms).code == FN_OK);
  CHECK(fn_socks5_handshake_start(
          inbound_manager, runtime, &accepted_stream, &source, inbound_id,
          accepted_at_ms, observation.deadline_ms, handshake_done,
          &observation, &observation.handshake).code == FN_OK);
  CHECK(accepted_stream == NULL);

  memcpy(request,
         (const uint8_t[]){5, 1, 0, 5, 1, 0, 3, 11,
                           't', 'a', 'r', 'g', 'e', 't', '.',
                           't', 'e', 's', 't',
                           (uint8_t)(target_port >> 8u),
                           (uint8_t)target_port},
         21u);
  memcpy(request + 21u, test_payload, sizeof(test_payload));
  client_write_all(&environment, client, request, sizeof(request));
  client_read_all(&environment, client, replies, sizeof(replies));
  CHECK(memcmp(replies, (const uint8_t[]){5, 0, 5, 0, 0, 3, 11,
                                          'b', 'o', 'u', 'n', 'd', '.',
                                          'l', 'o', 'c', 'a', 'l',
                                          0xc3, 0x50},
               sizeof(replies)) == 0);
  client_read_all(&environment, client, response, sizeof(response));
  CHECK(memcmp(response, test_response, sizeof(response)) == 0);
  CHECK(fn_socket_shutdown_write(client, FN_STAGE_RELAY).code == FN_OK);
  for (turns = 0; turns < 200000u && observation.session_calls == 0;
       turns++) {
    pump(&environment, 1u);
  }
  CHECK(observation.handshake_calls == 1u);
  CHECK(observation.handshake_result.code == FN_OK);
  CHECK(observation.submit_result.code == FN_OK);
  CHECK(observation.session_calls == 1u);
  CHECK(observation.snapshot.terminal_result.code == FN_OK);
  CHECK(observation.snapshot.bytes_up == sizeof(test_payload));
  CHECK(observation.snapshot.bytes_down == sizeof(test_response));

  CHECK(pthread_join(dns_thread, NULL) == 0);
  CHECK(pthread_join(proxy_thread, NULL) == 0);
  CHECK(pthread_join(target_thread, NULL) == 0);
  CHECK(dns_server.status == 0);
  CHECK(proxy_server.status == 0);
  CHECK(target_server.status == 0);
  CHECK(fn_socket_close(&client).code == FN_OK);
  CHECK(fn_socks5_inbound_manager_destroy(&inbound_manager).code == FN_OK);
  CHECK(fn_session_manager_destroy(&session_manager).code == FN_OK);
  CHECK(fn_runtime_release(&runtime).code == FN_OK);
  CHECK(fn_runtime_manager_destroy(&runtime_manager).code == FN_OK);
  CHECK(backend.release_calls == 1u);
  environment_destroy(&environment);
  CHECK(close(dns_server.descriptor) == 0);
  CHECK(close(proxy_server.proxy_listener) == 0);
  CHECK(close(target_server.target_listener) == 0);
}

int main(void)
{
  test_double_chain_with_bootstrap();
  (void)puts("p10 socks5 double-chain tests passed");
  return 0;
}
