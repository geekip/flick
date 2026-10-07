#define _GNU_SOURCE

#include "flicknet/clock.h"
#include "flicknet/direct.h"
#include "flicknet/socks5_outbound.h"

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
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      (void)fprintf(stderr, "check failed: %s:%d: %s\n", __FILE__,          \
                    __LINE__, #condition);                                     \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

typedef enum {
  SERVER_SUCCESS_DOMAIN = 0,
  SERVER_AUTH_FAILURE,
  SERVER_REP_REFUSED,
  SERVER_SUCCESS_MAXIMUM,
  SERVER_WRONG_METHOD,
  SERVER_MALFORMED_REPLY,
  SERVER_EOF_METHOD,
  SERVER_STALL
} server_case_t;

typedef struct {
  int listener;
  server_case_t test_case;
  size_t chunk_mode;
  const fn_endpoint_t *target;
  const fn_user_config_t *credentials;
  bool okay;
} server_script_t;

typedef struct {
  fn_limits_t limits;
  fn_budget_t memory;
  fn_budget_t file_descriptors;
  fn_loop_t *loop;
  fn_direct_connector_t *connector;
  fn_socks5_outbound_manager_t *manager;
} test_environment_t;

typedef struct {
  fn_socks5_outbound_t *operation;
  fn_stream_t *stream;
  fn_result_t result;
  fn_endpoint_t bound;
  fn_endpoint_t connected;
  size_t calls;
  bool has_endpoints;
} observation_t;

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

static fn_endpoint_t v4_endpoint(uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                                 uint16_t port)
{
  fn_endpoint_t endpoint;
  fn_addr_t address = v4_address(a, b, c, d);
  CHECK(fn_endpoint_make(&endpoint, &address, port).code == FN_OK);
  return endpoint;
}

static fn_endpoint_t domain_endpoint(const char *name, uint16_t port)
{
  fn_domain_t domain;
  fn_addr_t address;
  fn_endpoint_t endpoint;
  CHECK(fn_domain_from_bytes(&domain, (const uint8_t *)name,
                             strlen(name)).code == FN_OK);
  CHECK(fn_addr_from_domain(&address, &domain).code == FN_OK);
  CHECK(fn_endpoint_make(&endpoint, &address, port).code == FN_OK);
  return endpoint;
}

static bool read_exact(int descriptor, uint8_t *buffer, size_t length)
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

static bool write_chunks(int descriptor, const uint8_t *buffer,
                         size_t length, size_t mode)
{
  size_t offset = 0;
  while (offset < length) {
    size_t chunk = length - offset;
    ssize_t count;
    if (mode == 1u) {
      chunk = 1u;
    } else if (mode == 2u && chunk > 3u) {
      chunk = offset == 0 ? 3u : 2u;
    }
    count = send(descriptor, buffer + offset, chunk, MSG_NOSIGNAL);
    if (count <= 0) {
      return false;
    }
    offset += (size_t)count;
    (void)sched_yield();
  }
  return true;
}

static size_t encode_request(const fn_endpoint_t *target, uint8_t *out)
{
  size_t offset = 0;
  out[offset++] = UINT8_C(5);
  out[offset++] = UINT8_C(1);
  out[offset++] = UINT8_C(0);
  if (target->address.kind == FN_ADDR_V4) {
    out[offset++] = UINT8_C(1);
    memcpy(out + offset, target->address.value.v4, 4u);
    offset += 4u;
  } else {
    const fn_domain_t *domain = &target->address.value.domain;
    out[offset++] = UINT8_C(3);
    out[offset++] = (uint8_t)domain->length;
    memcpy(out + offset, domain->bytes, domain->length);
    offset += domain->length;
  }
  fn_u16_write_be(out + offset, target->port);
  return offset + 2u;
}

static size_t encode_auth(const fn_user_config_t *credentials, uint8_t *out)
{
  size_t offset = 0;
  out[offset++] = UINT8_C(1);
  out[offset++] = credentials->username_length;
  memcpy(out + offset, credentials->username,
         credentials->username_length);
  offset += credentials->username_length;
  out[offset++] = credentials->password_length;
  memcpy(out + offset, credentials->password,
         credentials->password_length);
  return offset + credentials->password_length;
}

static void *server_main(void *context)
{
  server_script_t *script = context;
  struct timeval timeout = {.tv_sec = 3, .tv_usec = 0};
  uint8_t actual[1024];
  uint8_t expected[1024];
  const uint8_t method_no_auth[2] = {UINT8_C(5), UINT8_C(0)};
  const uint8_t method_auth[2] = {UINT8_C(5), UINT8_C(2)};
  const uint8_t auth_failure[2] = {UINT8_C(1), UINT8_C(1)};
  const uint8_t auth_success[2] = {UINT8_C(1), UINT8_C(0)};
  const uint8_t refused[10] = {
    UINT8_C(5), UINT8_C(5), UINT8_C(0), UINT8_C(1),
    0, 0, 0, 0, 0, 0,
  };
  const uint8_t domain_reply[] = {
    UINT8_C(5), UINT8_C(0), UINT8_C(0), UINT8_C(3), UINT8_C(11),
    'b', 'o', 'u', 'n', 'd', '.', 'l', 'o', 'c', 'a', 'l',
    UINT8_C(0xc3), UINT8_C(0x50),
  };
  const uint8_t v6_reply[22] = {
    UINT8_C(5), UINT8_C(0), UINT8_C(0), UINT8_C(4),
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    UINT8_C(0x30), UINT8_C(0x39),
  };
  const uint8_t *method;
  int descriptor = accept(script->listener, NULL, NULL);
  size_t expected_length;
  bool with_auth = script->test_case == SERVER_AUTH_FAILURE ||
                   script->test_case == SERVER_SUCCESS_MAXIMUM;
  if (descriptor < 0) {
    return NULL;
  }
  (void)setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO,
                   &timeout, (socklen_t)sizeof(timeout));
  method = with_auth ? method_auth : method_no_auth;
  if (!read_exact(descriptor, actual, 3u) || actual[0] != 5u ||
      actual[1] != 1u || actual[2] != method[1]) {
    (void)close(descriptor);
    return NULL;
  }
  if (script->test_case == SERVER_STALL) {
    const struct timespec delay = {.tv_sec = 0, .tv_nsec = 50000000};
    (void)nanosleep(&delay, NULL);
    script->okay = true;
    (void)close(descriptor);
    return NULL;
  }
  if (script->test_case == SERVER_EOF_METHOD) {
    script->okay = write_chunks(descriptor, method, 1u, script->chunk_mode);
    (void)close(descriptor);
    return NULL;
  }
  if (script->test_case == SERVER_WRONG_METHOD) {
    script->okay = write_chunks(descriptor, method_auth,
                                sizeof(method_auth), script->chunk_mode);
    (void)close(descriptor);
    return NULL;
  }
  if (!write_chunks(descriptor, method, 2u, script->chunk_mode)) {
    (void)close(descriptor);
    return NULL;
  }
  if (with_auth) {
    expected_length = encode_auth(script->credentials, expected);
    if (!read_exact(descriptor, actual, expected_length) ||
        memcmp(actual, expected, expected_length) != 0) {
      (void)close(descriptor);
      return NULL;
    }
    if (script->test_case == SERVER_AUTH_FAILURE) {
      script->okay = write_chunks(descriptor, auth_failure,
                                  sizeof(auth_failure), script->chunk_mode);
      (void)close(descriptor);
      return NULL;
    }
    if (!write_chunks(descriptor, auth_success, sizeof(auth_success),
                      script->chunk_mode)) {
      (void)close(descriptor);
      return NULL;
    }
  }
  expected_length = encode_request(script->target, expected);
  if (!read_exact(descriptor, actual, expected_length) ||
      memcmp(actual, expected, expected_length) != 0) {
    (void)close(descriptor);
    return NULL;
  }
  if (script->test_case == SERVER_REP_REFUSED) {
    script->okay = write_chunks(descriptor, refused, sizeof(refused),
                                script->chunk_mode);
  } else if (script->test_case == SERVER_SUCCESS_MAXIMUM) {
    script->okay = write_chunks(descriptor, v6_reply, sizeof(v6_reply),
                                script->chunk_mode);
  } else if (script->test_case == SERVER_MALFORMED_REPLY) {
    const uint8_t malformed[4] = {5u, 0u, 1u, 9u};
    script->okay = write_chunks(descriptor, malformed, sizeof(malformed),
                                script->chunk_mode);
  } else {
    script->okay = write_chunks(descriptor, domain_reply,
                                sizeof(domain_reply), script->chunk_mode);
  }
  (void)close(descriptor);
  return NULL;
}

static int listener_create(uint16_t *out_port)
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
  CHECK(listen(descriptor, 8) == 0);
  CHECK(getsockname(descriptor, (struct sockaddr *)&address, &length) == 0);
  *out_port = ntohs(address.sin_port);
  return descriptor;
}

static uint16_t unused_port(void)
{
  uint16_t port;
  int descriptor = listener_create(&port);
  CHECK(close(descriptor) == 0);
  return port;
}

static void environment_init(test_environment_t *environment,
                             size_t async_limit)
{
  fn_loop_options_t loop_options;
  fn_direct_connector_options_t connector_options;
  fn_socks5_outbound_manager_options_t manager_options;
  memset(environment, 0, sizeof(*environment));
  environment->limits = fn_limits_default();
  environment->limits.async_operation_limit = async_limit;
  environment->limits.fd_limit = 64u;
  environment->limits.owned_memory_limit_bytes = 8u * 1024u * 1024u;
  environment->limits.cleanup_reserve_bytes = 1024u * 1024u;
  CHECK(fn_budget_init(&environment->memory,
                       environment->limits.owned_memory_limit_bytes,
                       environment->limits.cleanup_reserve_bytes).code ==
        FN_OK);
  CHECK(fn_budget_init(&environment->file_descriptors,
                       environment->limits.fd_limit, 0).code == FN_OK);
  memset(&loop_options, 0, sizeof(loop_options));
  loop_options.limits = &environment->limits;
  loop_options.owned_memory = &environment->memory;
  loop_options.file_descriptors = &environment->file_descriptors;
  loop_options.allocator = fn_allocator_system();
  loop_options.dispatch_limit = 64u;
  CHECK(fn_loop_create(&loop_options, &environment->loop).code == FN_OK);
  memset(&connector_options, 0, sizeof(connector_options));
  connector_options.loop = environment->loop;
  connector_options.limits = &environment->limits;
  connector_options.owned_memory = &environment->memory;
  connector_options.file_descriptors = &environment->file_descriptors;
  connector_options.allocator = fn_allocator_system();
  connector_options.connect_timeout_ms = UINT64_C(500);
  CHECK(fn_direct_connector_create(&connector_options,
                                   &environment->connector).code == FN_OK);
  memset(&manager_options, 0, sizeof(manager_options));
  manager_options.loop = environment->loop;
  manager_options.limits = &environment->limits;
  manager_options.owned_memory = &environment->memory;
  manager_options.allocator = fn_allocator_system();
  manager_options.tcp_connector = environment->connector;
  CHECK(fn_socks5_outbound_manager_create(
          &manager_options, &environment->manager).code == FN_OK);
}

static void environment_destroy(test_environment_t *environment)
{
  fn_budget_snapshot_t snapshot;
  CHECK(fn_socks5_outbound_manager_destroy(
          &environment->manager).code == FN_OK);
  CHECK(fn_direct_connector_destroy(&environment->connector).code == FN_OK);
  CHECK(fn_loop_destroy(&environment->loop).code == FN_OK);
  CHECK(fn_budget_snapshot(&environment->memory, &snapshot).code == FN_OK);
  CHECK(snapshot.total == 0u);
  CHECK(fn_budget_snapshot(&environment->file_descriptors,
                           &snapshot).code == FN_OK);
  CHECK(snapshot.total == 0u);
}

static void outbound_done(
  fn_socks5_outbound_t *operation, void *context, fn_result_t result,
  fn_stream_t *owned_stream, const fn_endpoint_t *bound_endpoint,
  const fn_endpoint_t *connected_endpoint)
{
  observation_t *observation = context;
  CHECK(operation == observation->operation);
  observation->calls++;
  observation->result = result;
  observation->stream = owned_stream;
  if (bound_endpoint != NULL && connected_endpoint != NULL) {
    observation->bound = *bound_endpoint;
    observation->connected = *connected_endpoint;
    observation->has_endpoints = true;
  }
}

static void pump_until(test_environment_t *environment,
                       observation_t *observation)
{
  size_t turns;
  for (turns = 0; turns < 200000u && observation->calls == 0; turns++) {
    CHECK(fn_loop_run_once(environment->loop,
                           FN_LOOP_RUN_NOWAIT).code == FN_OK);
    (void)sched_yield();
  }
  CHECK(observation->calls == 1u);
}

static void run_server_case(server_case_t test_case, size_t chunk_mode,
                            const fn_endpoint_t *target,
                            const fn_user_config_t *credentials,
                            fn_status_t expected_status)
{
  test_environment_t environment;
  server_script_t script;
  observation_t observation;
  fn_endpoint_t proxy;
  pthread_t thread;
  uint16_t port;
  memset(&script, 0, sizeof(script));
  script.listener = listener_create(&port);
  script.test_case = test_case;
  script.chunk_mode = chunk_mode;
  script.target = target;
  script.credentials = credentials;
  CHECK(pthread_create(&thread, NULL, server_main, &script) == 0);
  environment_init(&environment, 64u);
  proxy = v4_endpoint(127u, 0u, 0u, 1u, port);
  memset(&observation, 0, sizeof(observation));
  CHECK(fn_socks5_outbound_start(
          environment.manager, &proxy, credentials != NULL, credentials,
          target, deadline_after(test_case == SERVER_STALL ?
                                 UINT64_C(10) : UINT64_C(3000)),
          outbound_done,
          &observation, &observation.operation).code == FN_OK);
  pump_until(&environment, &observation);
  CHECK(observation.result.code == expected_status);
  if (expected_status == FN_OK) {
    CHECK(observation.stream != NULL);
    CHECK(observation.has_endpoints);
    CHECK(observation.connected.address.kind == FN_ADDR_V4);
    if (test_case == SERVER_SUCCESS_DOMAIN) {
      CHECK(observation.bound.address.kind == FN_ADDR_DOMAIN);
      CHECK(observation.bound.port == UINT16_C(50000));
    } else {
      CHECK(observation.bound.address.kind == FN_ADDR_V6);
      CHECK(observation.bound.port == UINT16_C(12345));
    }
    CHECK(fn_stream_abort(observation.stream).code == FN_OK);
    CHECK(fn_stream_release(&observation.stream).code == FN_OK);
  } else {
    CHECK(observation.stream == NULL);
    CHECK(!observation.has_endpoints);
  }
  CHECK(fn_socks5_outbound_release(&observation.operation).code == FN_OK);
  CHECK(pthread_join(thread, NULL) == 0);
  if (!script.okay) {
    (void)fprintf(stderr, "reference server failed: case=%d chunk=%zu\n",
                  (int)test_case, chunk_mode);
  }
  CHECK(script.okay);
  CHECK(close(script.listener) == 0);
  environment_destroy(&environment);
}

static void test_manifest_chunkings(void)
{
  fn_endpoint_t domain = domain_endpoint("example.org", UINT16_C(443));
  fn_endpoint_t ipv4 = v4_endpoint(127u, 0u, 0u, 1u, UINT16_C(80));
  fn_user_config_t credentials;
  size_t mode;
  memset(&credentials, 0, sizeof(credentials));
  memcpy(credentials.username, "bob", 3u);
  credentials.username_length = 3u;
  memcpy(credentials.password, "pw", 2u);
  credentials.password_length = 2u;
  for (mode = 0; mode < 3u; mode++) {
    run_server_case(SERVER_SUCCESS_DOMAIN, mode, &domain, NULL, FN_OK);
    run_server_case(SERVER_AUTH_FAILURE, mode, &domain, &credentials,
                    FN_AUTH_ERROR);
    run_server_case(SERVER_REP_REFUSED, mode, &ipv4, NULL,
                    FN_CONNECTION_REFUSED);
  }
}

static void test_maximum_frames_and_ipv6_bound(void)
{
  char domain[254];
  fn_endpoint_t target;
  fn_user_config_t credentials;
  size_t index;
  memset(domain, 'a', sizeof(domain));
  domain[63] = '.';
  domain[127] = '.';
  domain[191] = '.';
  domain[253] = '\0';
  target = domain_endpoint(domain, UINT16_C(65535));
  memset(&credentials, 0, sizeof(credentials));
  credentials.username_length = UINT8_MAX;
  credentials.password_length = UINT8_MAX;
  for (index = 0; index < UINT8_MAX; index++) {
    credentials.username[index] = (char)('a' + (index % 26u));
    credentials.password[index] = (char)('A' + (index % 26u));
  }
  run_server_case(SERVER_SUCCESS_MAXIMUM, 1u, &target, &credentials, FN_OK);
}

static void test_protocol_faults_eof_and_deadline(void)
{
  fn_endpoint_t target = domain_endpoint("example.org", UINT16_C(443));
  run_server_case(SERVER_WRONG_METHOD, 1u, &target, NULL,
                  FN_PROTOCOL_ERROR);
  run_server_case(SERVER_MALFORMED_REPLY, 2u, &target, NULL,
                  FN_PROTOCOL_ERROR);
  run_server_case(SERVER_EOF_METHOD, 0u, &target, NULL,
                  FN_PROTOCOL_ERROR);
  run_server_case(SERVER_STALL, 0u, &target, NULL, FN_TIMEOUT);
}

static void test_unreachable_cancel_resource_and_zero_demand(void)
{
  test_environment_t environment;
  observation_t observation;
  fn_socks5_outbound_manager_snapshot_t snapshot;
  fn_endpoint_t proxy;
  fn_endpoint_t target = domain_endpoint("example.org", UINT16_C(443));
  fn_endpoint_t domain_proxy = domain_endpoint("proxy.example", 1080u);
  fn_result_t result;
  environment_init(&environment, 64u);
  CHECK(fn_socks5_outbound_manager_snapshot(
          environment.manager, &snapshot).code == FN_OK);
  CHECK(snapshot.active_operations == 0u);
  CHECK(snapshot.bootstrap_operations == 0u);
  CHECK(snapshot.protocol_operations == 0u);
  memset(&observation, 0, sizeof(observation));
  proxy = v4_endpoint(127u, 0u, 0u, 1u, unused_port());
  CHECK(fn_socks5_outbound_start(
          environment.manager, &proxy, false, NULL, &target,
          deadline_after(UINT64_C(2000)), outbound_done, &observation,
          &observation.operation).code == FN_OK);
  pump_until(&environment, &observation);
  CHECK(observation.result.code == FN_CONNECTION_REFUSED);
  CHECK(fn_socks5_outbound_release(&observation.operation).code == FN_OK);

  memset(&observation, 0, sizeof(observation));
  proxy.port = unused_port();
  CHECK(fn_socks5_outbound_start(
          environment.manager, &proxy, false, NULL, &target,
          deadline_after(UINT64_C(2000)), outbound_done, &observation,
          &observation.operation).code == FN_OK);
  CHECK(fn_socks5_outbound_cancel(observation.operation).code == FN_OK);
  pump_until(&environment, &observation);
  CHECK(observation.result.code == FN_CANCELLED);
  CHECK(fn_socks5_outbound_release(&observation.operation).code == FN_OK);

  memset(&observation, 0, sizeof(observation));
  result = fn_socks5_outbound_start(
    environment.manager, &domain_proxy, false, NULL, &target,
    deadline_after(UINT64_C(2000)), outbound_done, &observation,
    &observation.operation);
  CHECK(result.code == FN_INVALID);
  CHECK(result.stage == FN_STAGE_RESOLVE);
  CHECK(observation.operation == NULL);
  CHECK(observation.calls == 0u);
  environment_destroy(&environment);

  environment_init(&environment, 0u);
  memset(&observation, 0, sizeof(observation));
  proxy = v4_endpoint(127u, 0u, 0u, 1u, UINT16_C(1080));
  result = fn_socks5_outbound_start(
    environment.manager, &proxy, false, NULL, &target,
    deadline_after(UINT64_C(2000)), outbound_done, &observation,
    &observation.operation);
  CHECK(result.code == FN_LIMIT);
  CHECK(result.stage == FN_STAGE_RESOURCE);
  CHECK(observation.operation == NULL);
  environment_destroy(&environment);
}

int main(void)
{
  test_manifest_chunkings();
  test_maximum_frames_and_ipv6_bound();
  test_protocol_faults_eof_and_deadline();
  test_unreachable_cancel_resource_and_zero_demand();
  (void)printf("p10 socks5 outbound tests passed\n");
  return 0;
}
