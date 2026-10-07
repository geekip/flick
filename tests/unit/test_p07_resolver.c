#include "flicknet/clock.h"
#include "flicknet/resolver.h"

#include "resolver_internal.h"

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
  fn_limits_t limits;
  fn_budget_t memory;
  fn_budget_t file_descriptors;
  fn_loop_t *loop;
} test_environment_t;

typedef struct {
  size_t calls;
  fn_result_t result;
  fn_resolved_t resolved;
  bool has_resolved;
  fn_resolver_operation_t *operation;
} test_observation_t;

struct fn_dns_transport_operation {
  struct fake_transport *transport;
  fn_dns_transport_callback_fn callback;
  void *callback_context;
  fn_dns_transport_request_t request;
  uint8_t query[FN_DNS_MESSAGE_UDP_MAX];
  bool cancelled;
};

typedef struct fake_transport {
  fn_dns_transport_operation_t *active;
  fn_dns_transport_t sent_transport[32];
  fn_endpoint_t sent_endpoint[32];
  fn_domain_t sent_question[32];
  size_t sends;
  uint16_t next_id;
  fn_result_t start_failure;
  bool fail_start;
  bool destroyed;
} fake_transport_t;

static fn_result_t test_result(fn_status_t code)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE :
                                               FN_STAGE_RESOLVE,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static fn_result_t test_dns_result(fn_status_t code, int64_t native)
{
  return fn_result_make(code, FN_STAGE_RESOLVE, FN_ERROR_ORIGIN_DNS, native);
}

static size_t hex_decode(const char *hex, uint8_t *output, size_t capacity)
{
  size_t length = strlen(hex);
  size_t index;
  CHECK((length % 2u) == 0);
  CHECK(length / 2u <= capacity);
  for (index = 0; index < length / 2u; index++) {
    unsigned int value;
    CHECK(sscanf(hex + index * 2u, "%2x", &value) == 1);
    output[index] = (uint8_t)value;
  }
  return length / 2u;
}

static fn_domain_t domain_make(const char *text)
{
  fn_domain_t domain;
  CHECK(fn_domain_from_bytes(&domain, (const uint8_t *)text,
                             strlen(text)).code == FN_OK);
  return domain;
}

static fn_endpoint_t endpoint_make(const char *address, uint16_t port)
{
  fn_endpoint_t endpoint;
  struct in_addr parsed;
  fn_addr_t core_address;
  CHECK(inet_pton(AF_INET, address, &parsed) == 1);
  CHECK(fn_addr_from_v4(&core_address, (const uint8_t *)&parsed).code == FN_OK);
  CHECK(fn_endpoint_make(&endpoint, &core_address, port).code == FN_OK);
  return endpoint;
}

static void environment_init(test_environment_t *environment)
{
  fn_loop_options_t options;
  memset(environment, 0, sizeof(*environment));
  environment->limits = fn_limits_default();
  CHECK(fn_budget_init(&environment->memory,
                       environment->limits.owned_memory_limit_bytes,
                       environment->limits.cleanup_reserve_bytes).code ==
        FN_OK);
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
  CHECK(fn_budget_snapshot(&environment->file_descriptors,
                           &snapshot).code == FN_OK);
  CHECK(snapshot.total == 0u);
}

static void resolver_callback(fn_resolver_operation_t *operation,
                              void *context, fn_result_t result,
                              const fn_resolved_t *resolved)
{
  test_observation_t *observation = context;
  CHECK(operation == observation->operation);
  observation->calls++;
  observation->result = result;
  if (resolved != NULL) {
    observation->resolved = *resolved;
    observation->has_resolved = true;
  }
  CHECK(fn_resolver_operation_release(&observation->operation).code == FN_OK);
}

static fn_domain_t query_question(const uint8_t *query, size_t length)
{
  uint8_t text[FN_DOMAIN_MAX];
  size_t cursor = 12u;
  size_t output = 0;
  fn_domain_t domain;
  bool first = true;
  while (cursor < length && query[cursor] != 0) {
    size_t label_length = query[cursor++];
    CHECK(label_length != 0 && label_length <= FN_DOMAIN_LABEL_MAX);
    CHECK(label_length <= length - cursor);
    if (!first) {
      text[output++] = (uint8_t)'.';
    }
    CHECK(label_length <= sizeof(text) - output);
    memcpy(text + output, query + cursor, label_length);
    output += label_length;
    cursor += label_length;
    first = false;
  }
  CHECK(cursor < length && query[cursor] == 0);
  CHECK(fn_domain_from_bytes(&domain, text, output).code == FN_OK);
  return domain;
}

static fn_result_t fake_start(
  void *context, const fn_dns_transport_request_t *request,
  fn_dns_transport_callback_fn callback, void *callback_context,
  fn_dns_transport_operation_t **out)
{
  fake_transport_t *transport = context;
  fn_dns_transport_operation_t *operation;
  CHECK(out != NULL);
  *out = NULL;
  if (transport->fail_start) {
    return transport->start_failure;
  }
  CHECK(transport->active == NULL);
  CHECK(transport->sends < 32u);
  operation = calloc(1u, sizeof(*operation));
  CHECK(operation != NULL);
  operation->transport = transport;
  operation->callback = callback;
  operation->callback_context = callback_context;
  operation->request = *request;
  memcpy(operation->query, request->query, request->query_length);
  operation->request.query = operation->query;
  transport->sent_transport[transport->sends] = request->transport;
  transport->sent_endpoint[transport->sends] = request->upstream;
  transport->sent_question[transport->sends] =
    query_question(request->query, request->query_length);
  transport->sends++;
  transport->active = operation;
  *out = operation;
  return test_result(FN_OK);
}

static fn_result_t fake_cancel(fn_dns_transport_operation_t *operation)
{
  if (operation == NULL) {
    return test_result(FN_INVALID);
  }
  operation->cancelled = true;
  return test_result(FN_OK);
}

static fn_result_t fake_release(
  fn_dns_transport_operation_t **operation_pointer)
{
  fn_dns_transport_operation_t *operation;
  if (operation_pointer == NULL) {
    return test_result(FN_INVALID);
  }
  operation = *operation_pointer;
  if (operation == NULL) {
    return test_result(FN_OK);
  }
  if (operation->transport->active == operation) {
    operation->transport->active = NULL;
  }
  free(operation);
  *operation_pointer = NULL;
  return test_result(FN_OK);
}

static fn_result_t fake_random(void *context, uint16_t *out)
{
  fake_transport_t *transport = context;
  *out = transport->next_id++;
  return test_result(FN_OK);
}

static void fake_destroy(void *context)
{
  fake_transport_t *transport = context;
  CHECK(transport->active == NULL);
  transport->destroyed = true;
}

static fn_dns_transport_ops_t fake_ops(fake_transport_t *transport)
{
  fn_dns_transport_ops_t ops;
  memset(&ops, 0, sizeof(ops));
  ops.context = transport;
  ops.start = fake_start;
  ops.cancel = fake_cancel;
  ops.release = fake_release;
  ops.random_u16 = fake_random;
  ops.destroy = fake_destroy;
  return ops;
}

static void fake_deliver(fake_transport_t *transport, fn_result_t result,
                         const uint8_t *response, size_t response_length,
                         bool truncated, bool source_matched,
                         bool local_matched)
{
  fn_dns_transport_operation_t *operation = transport->active;
  bool consumed;
  CHECK(operation != NULL);
  consumed = operation->callback(operation, operation->callback_context,
                                 result, response, response_length, truncated,
                                 source_matched, local_matched);
  if (!consumed) {
    CHECK(transport->active == operation);
  }
}

static size_t response_from_query(fake_transport_t *transport, uint16_t flags,
                                  const uint8_t *answer,
                                  size_t answer_length,
                                  uint16_t answer_count, uint8_t *out)
{
  fn_dns_transport_operation_t *operation = transport->active;
  size_t length = operation->request.query_length;
  memcpy(out, operation->query, length);
  fn_u16_write_be(out + 2u, flags);
  fn_u16_write_be(out + 6u, answer_count);
  fn_u16_write_be(out + 8u, UINT16_C(0));
  fn_u16_write_be(out + 10u, UINT16_C(0));
  if (answer_length != 0) {
    memcpy(out + length, answer, answer_length);
    length += answer_length;
  }
  return length;
}

static void fake_deliver_rcode(fake_transport_t *transport, uint16_t rcode)
{
  uint8_t response[FN_DNS_MESSAGE_UDP_MAX];
  size_t length = response_from_query(
    transport, (uint16_t)(UINT16_C(0x8180) | rcode), NULL, 0,
    UINT16_C(0), response);
  fake_deliver(transport, test_result(FN_OK), response, length, false, true,
               true);
}

static void fake_deliver_a(fake_transport_t *transport,
                           const uint8_t address[4])
{
  uint8_t response[FN_DNS_MESSAGE_UDP_MAX];
  uint8_t answer[] = {
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x3c, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
  };
  size_t length;
  memcpy(answer + 12u, address, 4u);
  length = response_from_query(transport, UINT16_C(0x8180), answer,
                               sizeof(answer), UINT16_C(1), response);
  fake_deliver(transport, test_result(FN_OK), response, length, false, true,
               true);
}

static void fake_deliver_cname(fake_transport_t *transport,
                               const char *target)
{
  uint8_t response[FN_DNS_MESSAGE_UDP_MAX];
  uint8_t answer[FN_DOMAIN_MAX + 16u];
  fn_domain_t domain = domain_make(target);
  size_t input = 0;
  size_t output = 12u;
  size_t length;
  answer[0] = 0xc0;
  answer[1] = 0x0c;
  answer[2] = 0x00;
  answer[3] = 0x05;
  answer[4] = 0x00;
  answer[5] = 0x01;
  answer[6] = 0x00;
  answer[7] = 0x00;
  answer[8] = 0x00;
  answer[9] = 0x3c;
  while (input < domain.length) {
    size_t start = input;
    while (input < domain.length && domain.bytes[input] != '.') {
      input++;
    }
    answer[output++] = (uint8_t)(input - start);
    memcpy(answer + output, domain.bytes + start, input - start);
    output += input - start;
    if (input < domain.length) {
      input++;
    }
  }
  answer[output++] = 0;
  fn_u16_write_be(answer + 10u, (uint16_t)(output - 12u));
  length = response_from_query(transport, UINT16_C(0x8180), answer, output,
                               UINT16_C(1), response);
  fake_deliver(transport, test_result(FN_OK), response, length, false, true,
               true);
}

static fn_dns_config_t dns_config(size_t upstream_count, uint32_t attempts)
{
  fn_dns_config_t config;
  size_t index;
  memset(&config, 0, sizeof(config));
  config.direct_present = true;
  config.direct_count = upstream_count;
  for (index = 0; index < upstream_count; index++) {
    config.direct[index].transport = FN_DNS_TRANSPORT_UDP;
    config.direct[index].endpoint = endpoint_make(
      index == 0 ? "192.0.2.53" : "192.0.2.54", 53u);
  }
  config.timeout_ms = UINT64_C(100);
  config.attempts = attempts;
  config.failure_cache_size = 8u;
  config.failure_cache_ttl_ms = UINT64_C(5000);
  return config;
}

static fn_resolver_t *fake_resolver_create(
  test_environment_t *environment, fake_transport_t *transport,
  fn_dns_config_t config)
{
  fn_resolver_options_t options;
  fn_dns_transport_ops_t ops = fake_ops(transport);
  fn_resolver_t *resolver = NULL;
  memset(&options, 0, sizeof(options));
  options.loop = environment->loop;
  options.limits = &environment->limits;
  options.owned_memory = &environment->memory;
  options.file_descriptors = &environment->file_descriptors;
  options.allocator = fn_allocator_system();
  options.config = config;
  options.generation = UINT64_C(7);
  CHECK(fn_resolver_create_with_transport(&options, &ops,
                                          &resolver).code == FN_OK);
  return resolver;
}

static void pump_nowait(fn_loop_t *loop, size_t turns)
{
  size_t index;
  for (index = 0; index < turns; index++) {
    CHECK(fn_loop_run_once(loop, FN_LOOP_RUN_NOWAIT).code == FN_OK);
  }
}

static void parser_case(const char *response_hex,
                        fn_dns_parse_action_t action, fn_status_t status,
                        int64_t native_code)
{
  uint8_t response[2048];
  fn_dns_query_t query;
  fn_dns_parse_result_t parsed;
  fn_domain_t question = domain_make("example.org");
  size_t response_length = hex_decode(response_hex, response,
                                      sizeof(response));
  CHECK(fn_dns_query_build(&question, UINT16_C(0x1234), &query).code == FN_OK);
  CHECK(fn_dns_response_parse(response, response_length,
                              FN_DNS_TRANSPORT_UDP, &query,
                              &parsed).code == FN_OK);
  CHECK(parsed.action == action);
  CHECK(parsed.result.code == status);
  if (action == FN_DNS_PARSE_TERMINAL) {
    CHECK(parsed.result.native_code == native_code);
  }
}

static void test_parser_fixtures(void)
{
  static const char query_hex[] =
    "123401000001000000000000076578616d706c65036f72670000010001";
  static const char a_success[] =
    "123481800001000100000000076578616d706c65036f72670000010001"
    "c00c000100010000003c0004c0000201";
  static const char cname_success[] =
    "123481800001000200000000076578616d706c65036f72670000010001"
    "c00c0005000100000078001305616c696173076578616d706c65036f726700"
    "05616c696173076578616d706c65036f726700000100010000003c0004c0000202";
  static const char seventeen_a[] =
    "123481800001001100000000076578616d706c65036f72670000010001"
    "c00c000100010000003c0004c0000201c00c000100010000003c0004c0000202"
    "c00c000100010000003c0004c0000203c00c000100010000003c0004c0000204"
    "c00c000100010000003c0004c0000205c00c000100010000003c0004c0000206"
    "c00c000100010000003c0004c0000207c00c000100010000003c0004c0000208"
    "c00c000100010000003c0004c0000209c00c000100010000003c0004c000020a"
    "c00c000100010000003c0004c000020bc00c000100010000003c0004c000020c"
    "c00c000100010000003c0004c000020dc00c000100010000003c0004c000020e"
    "c00c000100010000003c0004c000020fc00c000100010000003c0004c0000210"
    "c00c000100010000003c0004c0000211";
  uint8_t query_wire[512];
  uint8_t response[2048];
  uint8_t reordered[2048];
  fn_dns_query_t query;
  fn_dns_parse_result_t parsed;
  fn_domain_t question = domain_make("example.org");
  size_t length;

  CHECK(fn_dns_query_build(&question, UINT16_C(0x1234), &query).code == FN_OK);
  length = hex_decode(query_hex, query_wire, sizeof(query_wire));
  CHECK(query.length == length);
  CHECK(memcmp(query.wire, query_wire, length) == 0);

  length = hex_decode(a_success, response, sizeof(response));
  CHECK(fn_dns_response_parse(response, length, FN_DNS_TRANSPORT_UDP, &query,
                              &parsed).code == FN_OK);
  CHECK(parsed.action == FN_DNS_PARSE_ANSWER);
  CHECK(parsed.resolved.count == 1u);
  CHECK(parsed.resolved.ttl_seconds == 60u);
  CHECK(memcmp(parsed.resolved.addresses[0].value.v4,
               (const uint8_t[]){192u, 0u, 2u, 1u}, 4u) == 0);

  length = hex_decode(cname_success, response, sizeof(response));
  CHECK(fn_dns_response_parse(response, length, FN_DNS_TRANSPORT_UDP, &query,
                              &parsed).code == FN_OK);
  CHECK(parsed.action == FN_DNS_PARSE_ANSWER);
  CHECK(parsed.cname_hops == 1u);
  CHECK(parsed.resolved.ttl_seconds == 60u);
  CHECK(memcmp(parsed.resolved.addresses[0].value.v4,
               (const uint8_t[]){192u, 0u, 2u, 2u}, 4u) == 0);
  CHECK(length == 93u);
  memcpy(reordered, response, 29u);
  memcpy(reordered + 29u, response + 60u, 33u);
  memcpy(reordered + 62u, response + 29u, 31u);
  CHECK(fn_dns_response_parse(reordered, length, FN_DNS_TRANSPORT_UDP,
                              &query, &parsed).code == FN_OK);
  CHECK(parsed.action == FN_DNS_PARSE_ANSWER);
  CHECK(parsed.cname_hops == 1u);
  CHECK(parsed.resolved.count == 1u);
  CHECK(parsed.resolved.addresses[0].value.v4[3] == 2u);

  parser_case("123481830001000000000000076578616d706c65036f72670000010001",
              FN_DNS_PARSE_TERMINAL, FN_RESOLVE_ERROR, 3);
  parser_case("123481800001000000000000076578616d706c65036f72670000010001",
              FN_DNS_PARSE_TERMINAL, FN_RESOLVE_ERROR,
              FN_DNS_NATIVE_NODATA);
  parser_case("123483800001000000000000076578616d706c65036f72670000010001",
              FN_DNS_PARSE_TCP_FALLBACK, FN_OK, 0);
  parser_case("123481800001000100000000076578616d706c65036f72670000010001"
              "c01d000100010000003c0004c0000203",
              FN_DNS_PARSE_TERMINAL, FN_PROTOCOL_ERROR,
              FN_DNS_NATIVE_MALFORMED);
  parser_case(seventeen_a, FN_DNS_PARSE_TERMINAL, FN_LIMIT,
              FN_DNS_NATIVE_RESPONSE_LIMIT);
  parser_case("123481800001000200000000076578616d706c65036f72670000010001"
              "c00c000500010000003c000f0161076578616d706c65036f726700"
              "0161076578616d706c65036f726700000500010000003c000d"
              "076578616d706c65036f726700",
              FN_DNS_PARSE_TERMINAL, FN_PROTOCOL_ERROR,
              FN_DNS_NATIVE_CNAME_LOOP);

  length = hex_decode(a_success, response, sizeof(response));
  response[0] = 0x56;
  response[1] = 0x78;
  CHECK(fn_dns_response_parse(response, length, FN_DNS_TRANSPORT_UDP, &query,
                              &parsed).code == FN_OK);
  CHECK(parsed.action == FN_DNS_PARSE_DISCARD);
  length = hex_decode(
    "123481800001000100000000076578616d706c65036e65740000010001"
    "c00c000100010000003c0004c0000201", response, sizeof(response));
  CHECK(fn_dns_response_parse(response, length, FN_DNS_TRANSPORT_UDP, &query,
                              &parsed).code == FN_OK);
  CHECK(parsed.action == FN_DNS_PARSE_DISCARD);
}

static void acquire_observed(fn_resolver_t *resolver, fn_domain_t *question,
                             uint64_t deadline, test_observation_t *observation)
{
  memset(observation, 0, sizeof(*observation));
  CHECK(fn_resolver_acquire(resolver, question, FN_RESOLVER_PURPOSE_DIRECT,
                            deadline, resolver_callback, observation,
                            &observation->operation).code == FN_OK);
}

static uint64_t deadline_after(uint64_t milliseconds)
{
  uint64_t now;
  uint64_t deadline;
  CHECK(fn_monotonic_now_ms(&now).code == FN_OK);
  CHECK(fn_deadline_after_ms(now, milliseconds, &deadline).code == FN_OK);
  return deadline;
}

static void test_retry_cache_and_caps(void)
{
  test_environment_t environment;
  fake_transport_t transport;
  fn_resolver_t *resolver;
  fn_dns_config_t config;
  fn_domain_t question = domain_make("example.org");
  test_observation_t observation;
  test_observation_t cached;
  fn_resolver_snapshot_t snapshot;

  environment_init(&environment);
  memset(&transport, 0, sizeof(transport));
  transport.next_id = UINT16_C(0x1234);
  config = dns_config(2u, UINT32_C(4));
  config.bootstrap_present = true;
  config.bootstrap_count = 1u;
  config.bootstrap[0] = config.direct[1];
  resolver = fake_resolver_create(&environment, &transport, config);
  acquire_observed(resolver, &question, deadline_after(UINT64_C(5000)),
                   &observation);
  fake_deliver(&transport,
               test_dns_result(FN_TIMEOUT, FN_DNS_NATIVE_NO_RESPONSE),
               NULL, 0, false, true, true);
  fake_deliver_rcode(&transport, UINT16_C(2));
  fake_deliver(&transport,
               test_dns_result(FN_TIMEOUT, FN_DNS_NATIVE_NO_RESPONSE),
               NULL, 0, false, true, true);
  fake_deliver_rcode(&transport, UINT16_C(2));
  pump_nowait(environment.loop, 4u);
  CHECK(observation.calls == 1u);
  CHECK(observation.result.code == FN_RESOLVE_ERROR);
  CHECK(observation.result.native_code == 2);
  CHECK(transport.sends == 4u);
  CHECK(transport.sent_endpoint[0].address.value.v4[3] == 53u);
  CHECK(transport.sent_endpoint[1].address.value.v4[3] == 54u);
  CHECK(transport.sent_endpoint[2].address.value.v4[3] == 53u);
  CHECK(transport.sent_endpoint[3].address.value.v4[3] == 54u);
  CHECK(fn_resolver_snapshot(resolver, &snapshot).code == FN_OK);
  CHECK(snapshot.failure_cache_entries == 1u);

  acquire_observed(resolver, &question, deadline_after(UINT64_C(5000)),
                   &cached);
  pump_nowait(environment.loop, 2u);
  CHECK(cached.calls == 1u);
  CHECK(cached.result.native_code == 2);
  CHECK(transport.sends == 4u);
  CHECK(fn_resolver_snapshot(resolver, &snapshot).code == FN_OK);
  CHECK(snapshot.failure_cache_hits == 1u);

  memset(&cached, 0, sizeof(cached));
  CHECK(fn_resolver_acquire(
          resolver, &question, FN_RESOLVER_PURPOSE_BOOTSTRAP,
          deadline_after(UINT64_C(5000)), resolver_callback, &cached,
          &cached.operation).code == FN_OK);
  CHECK(transport.sends == 5u);
  fake_deliver_a(&transport, (const uint8_t[]){192u, 0u, 2u, 8u});
  pump_nowait(environment.loop, 2u);
  CHECK(cached.calls == 1u);
  CHECK(cached.result.code == FN_OK);
  CHECK(fn_resolver_destroy(&resolver).code == FN_OK);
  CHECK(transport.destroyed);
  environment_destroy(&environment);

  environment_init(&environment);
  memset(&transport, 0, sizeof(transport));
  transport.next_id = UINT16_C(0x2234);
  resolver = fake_resolver_create(&environment, &transport,
                                  dns_config(1u, UINT32_C(4)));
  acquire_observed(resolver, &question, deadline_after(UINT64_C(5000)),
                   &observation);
  fake_deliver(&transport,
               test_dns_result(FN_TIMEOUT, FN_DNS_NATIVE_NO_RESPONSE),
               NULL, 0, false, true, true);
  fake_deliver(&transport,
               test_dns_result(FN_TIMEOUT, FN_DNS_NATIVE_NO_RESPONSE),
               NULL, 0, false, true, true);
  fake_deliver(&transport,
               test_dns_result(FN_TIMEOUT, FN_DNS_NATIVE_NO_RESPONSE),
               NULL, 0, false, true, true);
  pump_nowait(environment.loop, 4u);
  CHECK(observation.calls == 1u);
  CHECK(observation.result.code == FN_TIMEOUT);
  CHECK(transport.sends == 3u);
  CHECK(fn_resolver_destroy(&resolver).code == FN_OK);
  environment_destroy(&environment);
}

static void test_tc_cname_shared_and_cancel(void)
{
  const uint8_t expected_address[4] = {192u, 0u, 2u, 2u};
  test_environment_t environment;
  fake_transport_t transport;
  fn_resolver_t *resolver;
  fn_domain_t question = domain_make("example.org");
  test_observation_t first;
  test_observation_t second;
  uint8_t response[512];
  size_t length;

  environment_init(&environment);
  memset(&transport, 0, sizeof(transport));
  transport.next_id = UINT16_C(0x1234);
  resolver = fake_resolver_create(&environment, &transport,
                                  dns_config(1u, UINT32_C(2)));
  acquire_observed(resolver, &question, deadline_after(UINT64_C(5000)),
                   &first);
  length = response_from_query(&transport, UINT16_C(0x8380), NULL, 0,
                               UINT16_C(0), response);
  fake_deliver(&transport, test_result(FN_OK), response, length, false, true,
               true);
  CHECK(transport.sends == 2u);
  CHECK(transport.sent_transport[0] == FN_DNS_TRANSPORT_UDP);
  CHECK(transport.sent_transport[1] == FN_DNS_TRANSPORT_TCP);
  fake_deliver(&transport,
               test_dns_result(FN_TIMEOUT, FN_DNS_NATIVE_NO_RESPONSE),
               NULL, 0, false, true, true);
  pump_nowait(environment.loop, 4u);
  CHECK(first.calls == 1u);
  CHECK(first.result.code == FN_TIMEOUT);
  CHECK(fn_resolver_destroy(&resolver).code == FN_OK);
  environment_destroy(&environment);

  environment_init(&environment);
  memset(&transport, 0, sizeof(transport));
  transport.next_id = UINT16_C(0x3234);
  resolver = fake_resolver_create(&environment, &transport,
                                  dns_config(1u, UINT32_C(2)));
  acquire_observed(resolver, &question, deadline_after(UINT64_C(5000)),
                   &first);
  fake_deliver_cname(&transport, "alias.example.org");
  CHECK(transport.sends == 2u);
  CHECK(fn_domain_equal(&transport.sent_question[1],
                        &(fn_domain_t){.length = 17u,
                          .bytes = "alias.example.org"}));
  fake_deliver_a(&transport, expected_address);
  pump_nowait(environment.loop, 4u);
  CHECK(first.calls == 1u);
  CHECK(first.result.code == FN_OK);
  CHECK(first.resolved.count == 1u);
  CHECK(memcmp(first.resolved.addresses[0].value.v4,
               expected_address, 4u) == 0);
  CHECK(fn_resolver_destroy(&resolver).code == FN_OK);
  environment_destroy(&environment);

  environment_init(&environment);
  memset(&transport, 0, sizeof(transport));
  transport.next_id = UINT16_C(0x4234);
  resolver = fake_resolver_create(&environment, &transport,
                                  dns_config(1u, UINT32_C(2)));
  acquire_observed(resolver, &question, deadline_after(UINT64_C(5000)),
                   &first);
  acquire_observed(resolver, &question, deadline_after(UINT64_C(5000)),
                   &second);
  CHECK(transport.sends == 1u);
  CHECK(fn_resolver_operation_cancel(first.operation).code == FN_OK);
  pump_nowait(environment.loop, 2u);
  CHECK(first.calls == 1u);
  CHECK(first.result.code == FN_CANCELLED);
  CHECK(second.calls == 0u);
  fake_deliver_a(&transport, expected_address);
  pump_nowait(environment.loop, 4u);
  CHECK(second.calls == 1u);
  CHECK(second.result.code == FN_OK);
  CHECK(fn_resolver_destroy(&resolver).code == FN_OK);
  environment_destroy(&environment);

  environment_init(&environment);
  memset(&transport, 0, sizeof(transport));
  transport.next_id = UINT16_C(0x5234);
  resolver = fake_resolver_create(&environment, &transport,
                                  dns_config(1u, UINT32_C(2)));
  acquire_observed(resolver, &question, deadline_after(UINT64_C(5000)),
                   &first);
  fake_deliver_a(&transport, expected_address);
  CHECK(first.calls == 0u);
  CHECK(fn_resolver_operation_cancel(first.operation).code == FN_OK);
  pump_nowait(environment.loop, 4u);
  CHECK(first.calls == 1u);
  CHECK(first.result.code == FN_CANCELLED);
  CHECK(!first.has_resolved);
  CHECK(fn_resolver_destroy(&resolver).code == FN_OK);
  environment_destroy(&environment);
}

static void test_discard_deadline_and_waiter_limit(void)
{
  const uint8_t expected_address[4] = {192u, 0u, 2u, 7u};
  test_environment_t environment;
  fake_transport_t transport;
  fn_resolver_t *resolver;
  fn_domain_t question = domain_make("example.org");
  test_observation_t first;
  test_observation_t second;
  test_observation_t waiters[FN_DNS_WAITER_PER_KEY_MAX + 1u];
  fn_resolver_snapshot_t snapshot;
  uint8_t response[512];
  size_t length;
  size_t index;

  environment_init(&environment);
  memset(&transport, 0, sizeof(transport));
  transport.next_id = UINT16_C(0x7234);
  resolver = fake_resolver_create(&environment, &transport,
                                  dns_config(1u, UINT32_C(2)));
  acquire_observed(resolver, &question, deadline_after(UINT64_C(10)), &first);
  acquire_observed(resolver, &question, deadline_after(UINT64_C(1000)),
                   &second);
  length = response_from_query(&transport, UINT16_C(0x8180), NULL, 0,
                               UINT16_C(0), response);
  fake_deliver(&transport, test_result(FN_OK), response, length, false,
               false, true);
  CHECK(transport.active != NULL);
  response[0] ^= UINT8_C(0x5a);
  fake_deliver(&transport, test_result(FN_OK), response, length, false,
               true, true);
  CHECK(transport.active != NULL);
  for (index = 0; index < 20u && first.calls == 0u; index++) {
    CHECK(fn_loop_run_once(environment.loop, FN_LOOP_RUN_ONCE).code == FN_OK);
  }
  CHECK(first.calls == 1u);
  CHECK(first.result.code == FN_TIMEOUT);
  CHECK(second.calls == 0u);
  CHECK(transport.sends == 1u);
  fake_deliver_a(&transport, expected_address);
  pump_nowait(environment.loop, 4u);
  CHECK(second.calls == 1u);
  CHECK(second.result.code == FN_OK);
  CHECK(fn_resolver_snapshot(resolver, &snapshot).code == FN_OK);
  CHECK(snapshot.discarded_responses == 2u);
  CHECK(snapshot.failure_cache_entries == 0u);
  CHECK(fn_resolver_destroy(&resolver).code == FN_OK);
  environment_destroy(&environment);

  environment_init(&environment);
  memset(&transport, 0, sizeof(transport));
  transport.next_id = UINT16_C(0x8234);
  resolver = fake_resolver_create(&environment, &transport,
                                  dns_config(1u, UINT32_C(2)));
  for (index = 0; index < FN_DNS_WAITER_PER_KEY_MAX; index++) {
    acquire_observed(resolver, &question, deadline_after(UINT64_C(5000)),
                     &waiters[index]);
  }
  memset(&waiters[FN_DNS_WAITER_PER_KEY_MAX], 0,
         sizeof(waiters[FN_DNS_WAITER_PER_KEY_MAX]));
  CHECK(fn_resolver_acquire(
          resolver, &question, FN_RESOLVER_PURPOSE_DIRECT,
          deadline_after(UINT64_C(5000)), resolver_callback,
          &waiters[FN_DNS_WAITER_PER_KEY_MAX],
          &waiters[FN_DNS_WAITER_PER_KEY_MAX].operation).code == FN_LIMIT);
  CHECK(waiters[FN_DNS_WAITER_PER_KEY_MAX].operation == NULL);
  for (index = 0; index < FN_DNS_WAITER_PER_KEY_MAX; index++) {
    CHECK(fn_resolver_operation_cancel(waiters[index].operation).code ==
          FN_OK);
  }
  pump_nowait(environment.loop, FN_DNS_WAITER_PER_KEY_MAX + 2u);
  for (index = 0; index < FN_DNS_WAITER_PER_KEY_MAX; index++) {
    CHECK(waiters[index].calls == 1u);
    CHECK(waiters[index].result.code == FN_CANCELLED);
  }
  CHECK(fn_resolver_snapshot(resolver, &snapshot).code == FN_OK);
  CHECK(snapshot.pending == 0u);
  CHECK(snapshot.waiters == 0u);
  CHECK(snapshot.open_sockets == 0u);
  CHECK(fn_resolver_destroy(&resolver).code == FN_OK);
  environment_destroy(&environment);
}

static void test_refused_and_duplicate_upstream(void)
{
  test_environment_t environment;
  fake_transport_t transport;
  fn_resolver_t *resolver;
  fn_dns_config_t config;
  fn_domain_t question = domain_make("example.org");
  test_observation_t observation;

  environment_init(&environment);
  memset(&transport, 0, sizeof(transport));
  transport.next_id = UINT16_C(0x9234);
  resolver = fake_resolver_create(&environment, &transport,
                                  dns_config(2u, UINT32_C(4)));
  acquire_observed(resolver, &question, deadline_after(UINT64_C(5000)),
                   &observation);
  fake_deliver_rcode(&transport, UINT16_C(5));
  fake_deliver_rcode(&transport, UINT16_C(5));
  pump_nowait(environment.loop, 4u);
  CHECK(observation.calls == 1u);
  CHECK(observation.result.code == FN_RESOLVE_ERROR);
  CHECK(observation.result.native_code == 5);
  CHECK(transport.sends == 2u);
  CHECK(fn_resolver_destroy(&resolver).code == FN_OK);
  environment_destroy(&environment);

  environment_init(&environment);
  memset(&transport, 0, sizeof(transport));
  transport.next_id = UINT16_C(0xa234);
  config = dns_config(2u, UINT32_C(4));
  config.direct[1] = config.direct[0];
  resolver = fake_resolver_create(&environment, &transport, config);
  acquire_observed(resolver, &question, deadline_after(UINT64_C(5000)),
                   &observation);
  fake_deliver(&transport,
               test_dns_result(FN_TIMEOUT, FN_DNS_NATIVE_NO_RESPONSE),
               NULL, 0, false, true, true);
  fake_deliver(&transport,
               test_dns_result(FN_TIMEOUT, FN_DNS_NATIVE_NO_RESPONSE),
               NULL, 0, false, true, true);
  fake_deliver(&transport,
               test_dns_result(FN_TIMEOUT, FN_DNS_NATIVE_NO_RESPONSE),
               NULL, 0, false, true, true);
  pump_nowait(environment.loop, 4u);
  CHECK(observation.calls == 1u);
  CHECK(transport.sends == 3u);
  CHECK(fn_resolver_destroy(&resolver).code == FN_OK);
  environment_destroy(&environment);
}

typedef struct {
  int udp_socket;
  int tcp_socket;
  int status;
} real_server_t;

static bool read_all_fd(int descriptor, uint8_t *buffer, size_t length)
{
  size_t offset = 0;
  while (offset < length) {
    ssize_t received = recv(descriptor, buffer + offset, length - offset, 0);
    if (received <= 0) {
      return false;
    }
    offset += (size_t)received;
  }
  return true;
}

static void *real_server_main(void *context)
{
  real_server_t *server = context;
  struct sockaddr_in client;
  socklen_t client_length = (socklen_t)sizeof(client);
  uint8_t query[512];
  uint8_t response[530];
  uint8_t prefix[2];
  ssize_t received;
  size_t query_length;
  size_t response_length;
  int accepted;
  size_t index;

  received = recvfrom(server->udp_socket, query, sizeof(query), 0,
                      (struct sockaddr *)&client, &client_length);
  if (received < 12) {
    server->status = 1;
    return NULL;
  }
  query_length = (size_t)received;
  memcpy(response, query, query_length);
  fn_u16_write_be(response + 2u, UINT16_C(0x8380));
  fn_u16_write_be(response + 6u, UINT16_C(0));
  if (sendto(server->udp_socket, response, query_length, 0,
             (const struct sockaddr *)&client, client_length) !=
      (ssize_t)query_length) {
    server->status = 2;
    return NULL;
  }
  accepted = accept(server->tcp_socket, NULL, NULL);
  if (accepted < 0 || !read_all_fd(accepted, prefix, sizeof(prefix))) {
    server->status = 3;
    return NULL;
  }
  query_length = (size_t)fn_u16_read_be(prefix);
  if (query_length > sizeof(query) ||
      !read_all_fd(accepted, query, query_length)) {
    server->status = 4;
    (void)close(accepted);
    return NULL;
  }
  memcpy(response + 2u, query, query_length);
  fn_u16_write_be(response + 4u, UINT16_C(0x8180));
  fn_u16_write_be(response + 8u, UINT16_C(1));
  response_length = query_length + 18u;
  response[query_length + 2u] = 0xc0;
  response[query_length + 3u] = 0x0c;
  response[query_length + 4u] = 0x00;
  response[query_length + 5u] = 0x01;
  response[query_length + 6u] = 0x00;
  response[query_length + 7u] = 0x01;
  response[query_length + 8u] = 0x00;
  response[query_length + 9u] = 0x00;
  response[query_length + 10u] = 0x00;
  response[query_length + 11u] = 0x3c;
  response[query_length + 12u] = 0x00;
  response[query_length + 13u] = 0x04;
  response[query_length + 14u] = 192u;
  response[query_length + 15u] = 0u;
  response[query_length + 16u] = 2u;
  response[query_length + 17u] = 9u;
  fn_u16_write_be(response, (uint16_t)(response_length - 2u));
  for (index = 0; index < response_length; index++) {
    if (send(accepted, response + index, 1u, MSG_NOSIGNAL) != 1) {
      server->status = 5;
      (void)close(accepted);
      return NULL;
    }
    (void)sched_yield();
  }
  (void)close(accepted);
  server->status = 0;
  return NULL;
}

static void test_real_udp_tcp_fallback(void)
{
  test_environment_t environment;
  real_server_t server;
  struct sockaddr_in address;
  socklen_t address_length = (socklen_t)sizeof(address);
  int reuse = 1;
  pthread_t thread;
  fn_dns_config_t config;
  fn_resolver_options_t options;
  fn_resolver_t *resolver = NULL;
  fn_domain_t question = domain_make("example.org");
  test_observation_t observation;
  fn_resolver_snapshot_t snapshot;
  size_t turns;

  memset(&server, 0, sizeof(server));
  server.udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
  server.tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
  CHECK(server.udp_socket >= 0 && server.tcp_socket >= 0);
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  CHECK(bind(server.udp_socket, (const struct sockaddr *)&address,
             (socklen_t)sizeof(address)) == 0);
  CHECK(getsockname(server.udp_socket, (struct sockaddr *)&address,
                    &address_length) == 0);
  CHECK(setsockopt(server.tcp_socket, SOL_SOCKET, SO_REUSEADDR, &reuse,
                   (socklen_t)sizeof(reuse)) == 0);
  CHECK(bind(server.tcp_socket, (const struct sockaddr *)&address,
             (socklen_t)sizeof(address)) == 0);
  CHECK(listen(server.tcp_socket, 1) == 0);
  CHECK(pthread_create(&thread, NULL, real_server_main, &server) == 0);

  environment_init(&environment);
  config = dns_config(1u, UINT32_C(2));
  config.timeout_ms = UINT64_C(1000);
  config.direct[0].endpoint = endpoint_make("127.0.0.1",
                                            ntohs(address.sin_port));
  memset(&options, 0, sizeof(options));
  options.loop = environment.loop;
  options.limits = &environment.limits;
  options.owned_memory = &environment.memory;
  options.file_descriptors = &environment.file_descriptors;
  options.allocator = fn_allocator_system();
  options.config = config;
  options.generation = UINT64_C(11);
  CHECK(fn_resolver_create(&options, &resolver).code == FN_OK);
  acquire_observed(resolver, &question, deadline_after(UINT64_C(3000)),
                   &observation);
  for (turns = 0; turns < 1000u && observation.calls == 0u; turns++) {
    CHECK(fn_loop_run_once(environment.loop, FN_LOOP_RUN_ONCE).code == FN_OK);
  }
  CHECK(observation.calls == 1u);
  if (observation.result.code != FN_OK) {
    (void)fprintf(stderr, "real resolver result: code=%d stage=%d origin=%d native=%lld\n",
                  (int)observation.result.code,
                  (int)observation.result.stage,
                  (int)observation.result.origin,
                  (long long)observation.result.native_code);
  }
  CHECK(observation.result.code == FN_OK);
  CHECK(observation.resolved.count == 1u);
  CHECK(observation.resolved.addresses[0].value.v4[3] == 9u);
  CHECK(fn_resolver_snapshot(resolver, &snapshot).code == FN_OK);
  CHECK(snapshot.sends == 2u);
  CHECK(snapshot.open_sockets == 0u);
  CHECK(pthread_join(thread, NULL) == 0);
  CHECK(server.status == 0);
  CHECK(close(server.udp_socket) == 0);
  CHECK(close(server.tcp_socket) == 0);
  CHECK(fn_resolver_destroy(&resolver).code == FN_OK);
  environment_destroy(&environment);
}

static void test_zero_pending_and_local_failure(void)
{
  test_environment_t environment;
  fake_transport_t transport;
  fn_resolver_t *resolver;
  fn_domain_t question = domain_make("example.org");
  test_observation_t observation;
  fn_dns_config_t config;
  fn_resolver_snapshot_t snapshot;

  environment_init(&environment);
  environment.limits.resolver_pending_limit = 0;
  memset(&transport, 0, sizeof(transport));
  transport.next_id = UINT16_C(0x5234);
  config = dns_config(1u, UINT32_C(2));
  resolver = fake_resolver_create(&environment, &transport, config);
  memset(&observation, 0, sizeof(observation));
  CHECK(fn_resolver_acquire(resolver, &question, FN_RESOLVER_PURPOSE_DIRECT,
                            deadline_after(UINT64_C(1000)), resolver_callback,
                            &observation, &observation.operation).code ==
        FN_LIMIT);
  CHECK(observation.calls == 0u);
  CHECK(observation.operation == NULL);
  CHECK(fn_resolver_destroy(&resolver).code == FN_OK);
  environment_destroy(&environment);

  environment_init(&environment);
  memset(&transport, 0, sizeof(transport));
  transport.next_id = UINT16_C(0x6234);
  transport.fail_start = true;
  transport.start_failure = fn_result_make(
    FN_LIMIT, FN_STAGE_RESOURCE, FN_ERROR_ORIGIN_NONE, INT64_C(0));
  resolver = fake_resolver_create(&environment, &transport, config);
  acquire_observed(resolver, &question, deadline_after(UINT64_C(1000)),
                   &observation);
  pump_nowait(environment.loop, 2u);
  CHECK(observation.calls == 1u);
  CHECK(observation.result.code == FN_LIMIT);
  CHECK(fn_resolver_snapshot(resolver, &snapshot).code == FN_OK);
  CHECK(snapshot.failure_cache_entries == 0u);
  CHECK(fn_resolver_destroy(&resolver).code == FN_OK);
  environment_destroy(&environment);
}

int main(void)
{
  test_parser_fixtures();
  test_retry_cache_and_caps();
  test_tc_cname_shared_and_cancel();
  test_discard_deadline_and_waiter_limit();
  test_refused_and_duplicate_upstream();
  test_real_udp_tcp_fallback();
  test_zero_pending_and_local_failure();
  (void)puts("p07 resolver tests passed");
  return 0;
}
