#ifndef FLICKNET_RESOLVER_INTERNAL_H
#define FLICKNET_RESOLVER_INTERNAL_H

#include "flicknet/resolver.h"

typedef struct fn_dns_transport_operation fn_dns_transport_operation_t;

typedef struct {
  fn_endpoint_t upstream;
  fn_dns_transport_t transport;
  fn_socket_purpose_t socket_purpose;
  const uint8_t *query;
  size_t query_length;
  uint16_t query_id;
  uint64_t deadline_ms;
} fn_dns_transport_request_t;

typedef bool (*fn_dns_transport_callback_fn)(
  fn_dns_transport_operation_t *operation, void *context, fn_result_t result,
  const uint8_t *response, size_t response_length, bool truncated,
  bool source_matched, bool local_matched);

typedef struct {
  void *context;
  fn_result_t (*start)(void *context,
                       const fn_dns_transport_request_t *request,
                       fn_dns_transport_callback_fn callback,
                       void *callback_context,
                       fn_dns_transport_operation_t **out);
  fn_result_t (*cancel)(fn_dns_transport_operation_t *operation);
  fn_result_t (*release)(fn_dns_transport_operation_t **operation);
  fn_result_t (*random_u16)(void *context, uint16_t *out);
  void (*destroy)(void *context);
} fn_dns_transport_ops_t;

fn_result_t fn_resolver_create_with_transport(
  const fn_resolver_options_t *options, const fn_dns_transport_ops_t *transport,
  fn_resolver_t **out);

fn_result_t fn_dns_linux_transport_create(
  const fn_resolver_options_t *options, fn_dns_transport_ops_t *out);

#endif
