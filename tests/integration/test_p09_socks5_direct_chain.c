#include "flicknet/clock.h"
#include "flicknet/config.h"
#include "flicknet/direct.h"
#include "flicknet/runtime.h"
#include "flicknet/session.h"
#include "flicknet/socks5.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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
  fn_session_manager_t *session_manager;
  fn_socks5_handshake_t *handshake;
  fn_session_t *session;
  fn_inbound_request_t *request;
  fn_op_t *reply_operation;
  fn_session_snapshot_t session_snapshot;
  size_t handshake_calls;
  size_t session_calls;
  size_t reply_calls;
  fn_result_t handshake_result;
  fn_result_t submit_result;
  fn_result_t reply_result;
  uint64_t deadline_ms;
} chain_observation_t;

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

static void environment_init(test_environment_t *environment)
{
  fn_loop_options_t loop_options;
  fn_relay_buffer_pool_options_t pool_options;
  fn_direct_connector_options_t connector_options;
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
                                    fn_runtime_manager_t **out_manager,
                                    fn_object_ref_t *out_inbound)
{
  fn_runtime_manager_options_t options;
  fn_runtime_candidate_t *candidate = NULL;
  fn_runtime_t *runtime = NULL;
  fn_inbound_config_t inbound;
  fn_rule_config_t rule;
  fn_config_t config;
  fn_feature_plan_t plan;
  memset(&inbound, 0, sizeof(inbound));
  memcpy(inbound.name, "socks-in", sizeof("socks-in"));
  inbound.listen = v4_address(127u, 0u, 0u, 1u);
  inbound.port = UINT16_C(1080);
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
  options.relay_pool = environment->relay_pool;
  CHECK(fn_session_manager_create(&options, &manager).code == FN_OK);
  return manager;
}

static fn_socks5_inbound_manager_t *socks_manager_create(
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

static int listener_create(uint16_t *port)
{
  int descriptor = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in address;
  socklen_t length = (socklen_t)sizeof(address);
  int flags;
  CHECK(descriptor >= 0);
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  CHECK(bind(descriptor, (const struct sockaddr *)&address,
             (socklen_t)sizeof(address)) == 0);
  CHECK(getsockname(descriptor, (struct sockaddr *)&address, &length) == 0);
  CHECK(listen(descriptor, 4) == 0);
  flags = fcntl(descriptor, F_GETFL, 0);
  CHECK(flags >= 0);
  CHECK(fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0);
  *port = ntohs(address.sin_port);
  return descriptor;
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

static void write_all(test_environment_t *environment, fn_socket_t socket,
                      const uint8_t *data, size_t length)
{
  size_t offset = 0;
  size_t turns;
  for (turns = 0; turns < 100000u && offset < length; turns++) {
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

static void read_all(test_environment_t *environment, fn_socket_t socket,
                     uint8_t *data, size_t length)
{
  size_t offset = 0;
  size_t turns;
  for (turns = 0; turns < 100000u && offset < length; turns++) {
    fn_io_result_t io = fn_socket_read(socket, data + offset,
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

static int accept_wait(test_environment_t *environment, int listener)
{
  size_t turns;
  for (turns = 0; turns < 100000u; turns++) {
    int accepted = accept(listener, NULL, NULL);
    if (accepted >= 0) {
      return accepted;
    }
    CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
    pump(environment, 1u);
  }
  CHECK(false);
  return -1;
}

static void session_callback(fn_session_t *session, void *context,
                             const fn_session_snapshot_t *snapshot)
{
  chain_observation_t *observation = context;
  CHECK(session == observation->session);
  observation->session_calls++;
  observation->session_snapshot = *snapshot;
  CHECK(fn_session_release(&observation->session).code == FN_OK);
}

static void request_reply_callback(fn_op_t *operation, fn_result_t result,
                                   void *context)
{
  chain_observation_t *observation = context;
  CHECK(operation == observation->reply_operation);
  observation->reply_calls++;
  observation->reply_result = result;
  CHECK(fn_op_release(&observation->reply_operation).code == FN_OK);
  CHECK(fn_inbound_request_release(&observation->request).code == FN_OK);
}

static void handshake_callback(fn_socks5_handshake_t *handshake,
                               void *context, fn_result_t result,
                               fn_inbound_request_t *request)
{
  chain_observation_t *observation = context;
  CHECK(handshake == observation->handshake);
  observation->handshake_calls++;
  observation->handshake_result = result;
  CHECK(fn_socks5_handshake_release(&observation->handshake).code == FN_OK);
  if (result.code != FN_OK) {
    if (request != NULL) {
      CHECK(fn_inbound_request_release(&request).code == FN_OK);
    }
    return;
  }
  CHECK(request != NULL);
  observation->submit_result = fn_session_submit(
    observation->session_manager, &request, observation->deadline_ms,
    session_callback, observation, &observation->session);
  if (observation->submit_result.code == FN_OK) {
    CHECK(request == NULL);
    return;
  }
  observation->request = request;
  CHECK(fn_inbound_request_reply_start(
          observation->request, observation->submit_result,
          request_reply_callback, observation,
          &observation->reply_operation).code == FN_OK);
}

static void test_socks5_direct_chain_with_preread(void)
{
  static const uint8_t payload[] = "p09-preread-payload";
  static const uint8_t response[] = "p09-direct-response";
  test_environment_t environment;
  runtime_backend_t backend;
  fn_runtime_manager_t *runtime_manager = NULL;
  fn_runtime_t *runtime;
  fn_object_ref_t inbound_id;
  fn_session_manager_t *session_manager;
  fn_socks5_inbound_manager_t *socks_manager;
  fn_stream_t *accepted_stream = NULL;
  fn_socket_t client = fn_socket_invalid();
  fn_endpoint_t source = v4_endpoint(127u, 0u, 0u, 1u, UINT16_C(50001));
  chain_observation_t observation;
  uint8_t request[13u + sizeof(payload)];
  uint8_t replies[12];
  uint8_t received[sizeof(response)];
  uint8_t server_payload[sizeof(payload)];
  uint16_t port;
  int listener;
  int server;
  size_t turns;
  ssize_t count;
  uint64_t accepted_at_ms;

  environment_init(&environment);
  memset(&backend, 0, sizeof(backend));
  runtime = runtime_create(&environment, &backend, &runtime_manager,
                           &inbound_id);
  session_manager = session_manager_create(&environment);
  socks_manager = socks_manager_create(&environment);
  listener = listener_create(&port);
  socketpair_stream(&environment, &client, &accepted_stream);
  memset(&observation, 0, sizeof(observation));
  observation.session_manager = session_manager;
  observation.deadline_ms = deadline_after(UINT64_C(3000));
  CHECK(fn_monotonic_now_ms(&accepted_at_ms).code == FN_OK);
  CHECK(fn_socks5_handshake_start(
          socks_manager, runtime, &accepted_stream, &source, inbound_id,
          accepted_at_ms,
          observation.deadline_ms, handshake_callback, &observation,
          &observation.handshake).code == FN_OK);
  CHECK(accepted_stream == NULL);

  memcpy(request,
         (const uint8_t[]){0x05, 0x01, 0x00,
                           0x05, 0x01, 0x00, 0x01,
                           127u, 0u, 0u, 1u,
                           (uint8_t)(port >> 8u), (uint8_t)port},
         13u);
  memcpy(request + 13u, payload, sizeof(payload));
  write_all(&environment, client, request, sizeof(request));
  read_all(&environment, client, replies, sizeof(replies));
  CHECK(memcmp(replies, (const uint8_t[]){0x05, 0x00}, 2u) == 0);
  CHECK(replies[2] == 0x05 && replies[3] == 0x00 && replies[4] == 0x00 &&
        replies[5] == 0x01);
  CHECK(observation.handshake_calls == 1u);
  CHECK(observation.handshake_result.code == FN_OK);
  CHECK(observation.submit_result.code == FN_OK);
  server = accept_wait(&environment, listener);

  count = recv(server, server_payload, sizeof(server_payload), MSG_DONTWAIT);
  for (turns = 0; turns < 100000u && count < 0; turns++) {
    CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
    pump(&environment, 1u);
    count = recv(server, server_payload, sizeof(server_payload), MSG_DONTWAIT);
  }
  CHECK(count == (ssize_t)sizeof(server_payload));
  CHECK(memcmp(server_payload, payload, sizeof(payload)) == 0);
  CHECK(send(server, response, sizeof(response), MSG_NOSIGNAL) ==
        (ssize_t)sizeof(response));
  memset(received, 0, sizeof(received));
  read_all(&environment, client, received, sizeof(received));
  CHECK(memcmp(received, response, sizeof(response)) == 0);

  CHECK(fn_socket_shutdown_write(client, FN_STAGE_RELAY).code == FN_OK);
  for (turns = 0; turns < 100000u; turns++) {
    count = recv(server, server_payload, sizeof(server_payload), MSG_DONTWAIT);
    if (count == 0) {
      break;
    }
    CHECK(count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    pump(&environment, 1u);
  }
  CHECK(count == 0);
  CHECK(shutdown(server, SHUT_WR) == 0);
  for (turns = 0; turns < 100000u && observation.session_calls == 0;
       turns++) {
    pump(&environment, 1u);
  }
  CHECK(observation.session_calls == 1u);
  CHECK(observation.session_snapshot.terminal_result.code == FN_OK);
  CHECK(observation.session_snapshot.bytes_up == sizeof(payload));
  CHECK(observation.session_snapshot.bytes_down == sizeof(response));

  CHECK(close(server) == 0);
  CHECK(close(listener) == 0);
  CHECK(fn_socket_close(&client).code == FN_OK);
  CHECK(fn_socks5_inbound_manager_destroy(&socks_manager).code == FN_OK);
  CHECK(fn_session_manager_destroy(&session_manager).code == FN_OK);
  CHECK(fn_runtime_release(&runtime).code == FN_OK);
  CHECK(fn_runtime_manager_destroy(&runtime_manager).code == FN_OK);
  CHECK(backend.release_calls == 1u);
  environment_destroy(&environment);
}

static void test_socks5_direct_refused_reply(void)
{
  static const uint8_t expected[] = {
    0x05, 0x00,
    0x05, 0x05, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
  };
  test_environment_t environment;
  runtime_backend_t backend;
  fn_runtime_manager_t *runtime_manager = NULL;
  fn_runtime_t *runtime;
  fn_object_ref_t inbound_id;
  fn_session_manager_t *session_manager;
  fn_socks5_inbound_manager_t *socks_manager;
  fn_stream_t *accepted_stream = NULL;
  fn_socket_t client = fn_socket_invalid();
  fn_endpoint_t source = v4_endpoint(127u, 0u, 0u, 1u, UINT16_C(50002));
  chain_observation_t observation;
  uint8_t request[13];
  uint8_t replies[sizeof(expected)];
  uint16_t port;
  int listener;
  size_t turns;
  uint64_t accepted_at_ms;

  environment_init(&environment);
  memset(&backend, 0, sizeof(backend));
  runtime = runtime_create(&environment, &backend, &runtime_manager,
                           &inbound_id);
  session_manager = session_manager_create(&environment);
  socks_manager = socks_manager_create(&environment);
  listener = listener_create(&port);
  CHECK(close(listener) == 0);
  socketpair_stream(&environment, &client, &accepted_stream);
  memset(&observation, 0, sizeof(observation));
  observation.session_manager = session_manager;
  observation.deadline_ms = deadline_after(UINT64_C(3000));
  CHECK(fn_monotonic_now_ms(&accepted_at_ms).code == FN_OK);
  CHECK(fn_socks5_handshake_start(
          socks_manager, runtime, &accepted_stream, &source, inbound_id,
          accepted_at_ms, observation.deadline_ms,
          handshake_callback, &observation,
          &observation.handshake).code == FN_OK);
  memcpy(request,
         (const uint8_t[]){0x05, 0x01, 0x00,
                           0x05, 0x01, 0x00, 0x01,
                           127u, 0u, 0u, 1u,
                           (uint8_t)(port >> 8u), (uint8_t)port},
         sizeof(request));
  write_all(&environment, client, request, sizeof(request));
  read_all(&environment, client, replies, sizeof(replies));
  CHECK(memcmp(replies, expected, sizeof(expected)) == 0);
  for (turns = 0; turns < 100000u && observation.session_calls == 0;
       turns++) {
    pump(&environment, 1u);
  }
  CHECK(observation.handshake_calls == 1u);
  CHECK(observation.session_calls == 1u);
  CHECK(observation.session_snapshot.terminal_result.code ==
        FN_CONNECTION_REFUSED);
  CHECK(observation.session_snapshot.terminal_result.stage ==
        FN_STAGE_TCP_CONNECT);
  CHECK(fn_socket_close(&client).code == FN_OK);
  CHECK(fn_socks5_inbound_manager_destroy(&socks_manager).code == FN_OK);
  CHECK(fn_session_manager_destroy(&session_manager).code == FN_OK);
  CHECK(fn_runtime_release(&runtime).code == FN_OK);
  CHECK(fn_runtime_manager_destroy(&runtime_manager).code == FN_OK);
  CHECK(backend.release_calls == 1u);
  environment_destroy(&environment);
}

static void test_handshake_cancel(void)
{
  test_environment_t environment;
  runtime_backend_t backend;
  fn_runtime_manager_t *runtime_manager = NULL;
  fn_runtime_t *runtime;
  fn_object_ref_t inbound_id;
  fn_session_manager_t *session_manager;
  fn_socks5_inbound_manager_t *socks_manager;
  fn_stream_t *accepted_stream = NULL;
  fn_socket_t client = fn_socket_invalid();
  fn_endpoint_t source = v4_endpoint(127u, 0u, 0u, 1u, UINT16_C(50003));
  chain_observation_t observation;
  fn_socks5_inbound_manager_snapshot_t manager_snapshot;
  uint64_t accepted_at_ms;
  size_t turns;

  environment_init(&environment);
  memset(&backend, 0, sizeof(backend));
  runtime = runtime_create(&environment, &backend, &runtime_manager,
                           &inbound_id);
  session_manager = session_manager_create(&environment);
  socks_manager = socks_manager_create(&environment);
  socketpair_stream(&environment, &client, &accepted_stream);
  memset(&observation, 0, sizeof(observation));
  observation.session_manager = session_manager;
  observation.deadline_ms = deadline_after(UINT64_C(3000));
  CHECK(fn_monotonic_now_ms(&accepted_at_ms).code == FN_OK);
  CHECK(fn_socks5_handshake_start(
          socks_manager, runtime, &accepted_stream, &source, inbound_id,
          accepted_at_ms, observation.deadline_ms,
          handshake_callback, &observation,
          &observation.handshake).code == FN_OK);
  CHECK(fn_socks5_handshake_cancel(observation.handshake).code == FN_OK);
  for (turns = 0; turns < 10000u && observation.handshake_calls == 0;
       turns++) {
    pump(&environment, 1u);
  }
  CHECK(observation.handshake_calls == 1u);
  CHECK(observation.handshake_result.code == FN_CANCELLED);
  CHECK(observation.session == NULL);
  CHECK(fn_socks5_inbound_manager_snapshot(
          socks_manager, &manager_snapshot).code == FN_OK);
  CHECK(manager_snapshot.active_handshakes == 0u);
  CHECK(fn_socket_close(&client).code == FN_OK);
  CHECK(fn_socks5_inbound_manager_destroy(&socks_manager).code == FN_OK);
  CHECK(fn_session_manager_destroy(&session_manager).code == FN_OK);
  CHECK(fn_runtime_release(&runtime).code == FN_OK);
  CHECK(fn_runtime_manager_destroy(&runtime_manager).code == FN_OK);
  CHECK(backend.release_calls == 1u);
  environment_destroy(&environment);
}

static void test_session_admission_failure_reply(void)
{
  static const uint8_t expected[] = {
    0x05, 0x00,
    0x05, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00,
  };
  test_environment_t environment;
  runtime_backend_t backend;
  fn_runtime_manager_t *runtime_manager = NULL;
  fn_runtime_t *runtime;
  fn_object_ref_t inbound_id;
  fn_session_manager_t *session_manager;
  fn_socks5_inbound_manager_t *socks_manager;
  fn_stream_t *accepted_stream = NULL;
  fn_socket_t client = fn_socket_invalid();
  fn_endpoint_t source = v4_endpoint(127u, 0u, 0u, 1u, UINT16_C(50004));
  chain_observation_t observation;
  uint8_t replies[sizeof(expected)];
  uint64_t accepted_at_ms;
  size_t turns;

  environment_init(&environment);
  environment.limits.session_limit = 0u;
  memset(&backend, 0, sizeof(backend));
  runtime = runtime_create(&environment, &backend, &runtime_manager,
                           &inbound_id);
  session_manager = session_manager_create(&environment);
  socks_manager = socks_manager_create(&environment);
  socketpair_stream(&environment, &client, &accepted_stream);
  memset(&observation, 0, sizeof(observation));
  observation.session_manager = session_manager;
  observation.deadline_ms = deadline_after(UINT64_C(3000));
  CHECK(fn_monotonic_now_ms(&accepted_at_ms).code == FN_OK);
  CHECK(fn_socks5_handshake_start(
          socks_manager, runtime, &accepted_stream, &source, inbound_id,
          accepted_at_ms, observation.deadline_ms,
          handshake_callback, &observation,
          &observation.handshake).code == FN_OK);
  write_all(&environment, client,
            (const uint8_t[]){0x05, 0x01, 0x00,
                              0x05, 0x01, 0x00, 0x01,
                              127u, 0u, 0u, 1u, 0x00, 0x50},
            13u);
  read_all(&environment, client, replies, sizeof(replies));
  CHECK(memcmp(replies, expected, sizeof(expected)) == 0);
  for (turns = 0; turns < 10000u && observation.reply_calls == 0;
       turns++) {
    pump(&environment, 1u);
  }
  CHECK(observation.handshake_calls == 1u);
  CHECK(observation.submit_result.code == FN_LIMIT);
  CHECK(observation.reply_calls == 1u);
  CHECK(observation.reply_result.code == FN_OK);
  CHECK(observation.session == NULL);
  CHECK(observation.request == NULL);
  CHECK(fn_socket_close(&client).code == FN_OK);
  CHECK(fn_socks5_inbound_manager_destroy(&socks_manager).code == FN_OK);
  CHECK(fn_session_manager_destroy(&session_manager).code == FN_OK);
  CHECK(fn_runtime_release(&runtime).code == FN_OK);
  CHECK(fn_runtime_manager_destroy(&runtime_manager).code == FN_OK);
  CHECK(backend.release_calls == 1u);
  environment_destroy(&environment);
}

int main(void)
{
  test_socks5_direct_chain_with_preread();
  test_socks5_direct_refused_reply();
  test_handshake_cancel();
  test_session_admission_failure_reply();
  (void)puts("p09 socks5/direct integration tests passed");
  return 0;
}
