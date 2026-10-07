#include "flicknet/socks5_outbound.h"

#include "flicknet/clock.h"
#include "flicknet/socks5.h"

#include <string.h>

#define SOCKS_VERSION UINT8_C(5)
#define SOCKS_AUTH_VERSION UINT8_C(1)
#define SOCKS_COMMAND_CONNECT UINT8_C(1)
#define SOCKS_ADDRESS_V4 UINT8_C(1)
#define SOCKS_ADDRESS_DOMAIN UINT8_C(3)
#define SOCKS_ADDRESS_V6 UINT8_C(4)

struct fn_socks5_outbound_manager {
  fn_loop_t *loop;
  fn_limits_t limits;
  fn_budget_t *owned_memory;
  fn_allocator_t allocator;
  fn_direct_connector_t *tcp_connector;
  fn_resolver_t *resolver;
  size_t active_operations;
  size_t bootstrap_operations;
  size_t protocol_operations;
};

struct fn_socks5_outbound {
  fn_socks5_outbound_manager_t *manager;
  fn_socks5_outbound_callback_fn callback;
  void *callback_context;
  fn_completion_ticket_t *ticket;
  fn_resolver_operation_t *resolve_operation;
  fn_direct_connect_t *connect_operation;
  fn_stream_t *stream;
  fn_timer_t *timer;
  fn_socks5_outbound_state_t state;
  fn_endpoint_t proxy_endpoint;
  fn_endpoint_t target;
  fn_endpoint_t connected_endpoint;
  fn_endpoint_t bound_endpoint;
  fn_user_config_t credentials;
  fn_result_t terminal_result;
  uint64_t deadline_ms;
  uint8_t input[FN_SOCKS5_WORKSPACE_SIZE];
  uint8_t output[FN_SOCKS5_WORKSPACE_SIZE];
  size_t input_length;
  size_t output_length;
  size_t output_offset;
  bool has_credentials;
  bool terminal_queued;
  bool callback_started;
  bool cancel_requested;
  bool protocol_active;
};

static fn_result_t outbound_result(fn_status_t code,
                                   fn_error_stage_t stage)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE : stage,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static fn_result_t outbound_wire_result(fn_status_t code,
                                        fn_error_stage_t stage,
                                        uint8_t native_code)
{
  return fn_result_make(code, stage, FN_ERROR_ORIGIN_SOCKS,
                        (int64_t)native_code);
}

static bool manager_is_owner(const fn_socks5_outbound_manager_t *manager)
{
  return manager != NULL && fn_loop_is_owner(manager->loop);
}

static bool operation_is_owner(const fn_socks5_outbound_t *operation)
{
  return operation != NULL && manager_is_owner(operation->manager);
}

static fn_error_stage_t protocol_stage(
  const fn_socks5_outbound_t *operation)
{
  if (operation->state == FN_SOCKS5_OUT_REQUEST_WRITE ||
      operation->state == FN_SOCKS5_OUT_CONNECT_REPLY_READ) {
    return FN_STAGE_SOCKS_CONNECT;
  }
  return FN_STAGE_SOCKS_AUTH;
}

static fn_result_t transport_result(const fn_socks5_outbound_t *operation,
                                    fn_result_t result)
{
  return fn_result_make(result.code, protocol_stage(operation),
                        result.origin, result.native_code);
}

static void credentials_clear(fn_user_config_t *credentials)
{
  volatile unsigned char *bytes = (volatile unsigned char *)credentials;
  size_t index;
  for (index = 0; index < sizeof(*credentials); index++) {
    bytes[index] = 0;
  }
}

static void operation_stop_protocol(fn_socks5_outbound_t *operation)
{
  if (operation->stream != NULL) {
    (void)fn_stream_watch(operation->stream, 0, NULL, NULL);
  }
  if (operation->timer != NULL) {
    (void)fn_timer_destroy(&operation->timer);
  }
  if (operation->protocol_active) {
    operation->manager->protocol_operations--;
    operation->protocol_active = false;
  }
}

static void operation_completion(void *context, fn_result_t ignored)
{
  fn_socks5_outbound_t *operation = context;
  fn_socks5_outbound_callback_fn callback = operation->callback;
  void *callback_context = operation->callback_context;
  fn_result_t result = operation->terminal_result;
  fn_stream_t *stream = operation->stream;
  const fn_endpoint_t *bound = NULL;
  const fn_endpoint_t *connected = NULL;
  (void)ignored;
  operation->callback_started = true;
  operation->stream = NULL;
  if (operation->cancel_requested) {
    if (stream != NULL) {
      (void)fn_stream_abort(stream);
      (void)fn_stream_release(&stream);
    }
    result = outbound_result(FN_CANCELLED, FN_STAGE_SOCKS_CONNECT);
    operation->terminal_result = result;
  } else if (result.code == FN_OK) {
    bound = &operation->bound_endpoint;
    connected = &operation->connected_endpoint;
  }
  callback(operation, callback_context, result, stream, bound, connected);
}

static void operation_finish(fn_socks5_outbound_t *operation,
                             fn_result_t result)
{
  if (operation->terminal_queued) {
    return;
  }
  operation_stop_protocol(operation);
  if (result.code != FN_OK && operation->stream != NULL) {
    (void)fn_stream_abort(operation->stream);
    (void)fn_stream_release(&operation->stream);
  }
  operation->state = result.code == FN_OK ? FN_SOCKS5_OUT_READY :
                                           FN_SOCKS5_OUT_CLOSED;
  operation->terminal_result = result;
  operation->terminal_queued = true;
  (void)fn_completion_publish(&operation->ticket, result,
                              operation_completion, operation);
}

static void queue_output(fn_socks5_outbound_t *operation,
                         fn_socks5_outbound_state_t state,
                         const uint8_t *data, size_t length)
{
  memcpy(operation->output, data, length);
  operation->output_length = length;
  operation->output_offset = 0;
  operation->state = state;
}

static void queue_greeting(fn_socks5_outbound_t *operation)
{
  const uint8_t greeting[3] = {
    SOCKS_VERSION, UINT8_C(1),
    operation->has_credentials ?
      (uint8_t)FN_SOCKS5_METHOD_USERNAME_PASSWORD :
      (uint8_t)FN_SOCKS5_METHOD_NO_AUTH,
  };
  queue_output(operation, FN_SOCKS5_OUT_GREETING_WRITE,
               greeting, sizeof(greeting));
}

static void queue_auth(fn_socks5_outbound_t *operation)
{
  size_t offset = 0;
  operation->output[offset++] = SOCKS_AUTH_VERSION;
  operation->output[offset++] = operation->credentials.username_length;
  memcpy(operation->output + offset, operation->credentials.username,
         operation->credentials.username_length);
  offset += operation->credentials.username_length;
  operation->output[offset++] = operation->credentials.password_length;
  memcpy(operation->output + offset, operation->credentials.password,
         operation->credentials.password_length);
  offset += operation->credentials.password_length;
  operation->output_length = offset;
  operation->output_offset = 0;
  operation->state = FN_SOCKS5_OUT_AUTH_WRITE;
}

static fn_result_t queue_request(fn_socks5_outbound_t *operation)
{
  size_t offset = 0;
  operation->output[offset++] = SOCKS_VERSION;
  operation->output[offset++] = SOCKS_COMMAND_CONNECT;
  operation->output[offset++] = UINT8_C(0);
  if (operation->target.address.kind == FN_ADDR_V4) {
    operation->output[offset++] = SOCKS_ADDRESS_V4;
    memcpy(operation->output + offset,
           operation->target.address.value.v4, 4u);
    offset += 4u;
  } else if (operation->target.address.kind == FN_ADDR_DOMAIN) {
    const fn_domain_t *domain = &operation->target.address.value.domain;
    if (domain->length == 0 || domain->length > UINT8_MAX) {
      return outbound_result(FN_INVALID, FN_STAGE_SOCKS_CONNECT);
    }
    operation->output[offset++] = SOCKS_ADDRESS_DOMAIN;
    operation->output[offset++] = (uint8_t)domain->length;
    memcpy(operation->output + offset, domain->bytes, domain->length);
    offset += domain->length;
  } else {
    return outbound_result(FN_UNSUPPORTED, FN_STAGE_SOCKS_CONNECT);
  }
  fn_u16_write_be(operation->output + offset, operation->target.port);
  offset += 2u;
  operation->output_length = offset;
  operation->output_offset = 0;
  operation->state = FN_SOCKS5_OUT_REQUEST_WRITE;
  return outbound_result(FN_OK, FN_STAGE_NONE);
}

static fn_result_t reply_result(uint8_t reply)
{
  fn_status_t status;
  switch (reply) {
    case UINT8_C(1):
      status = FN_CONNECT_ERROR;
      break;
    case UINT8_C(2):
      status = FN_REJECTED;
      break;
    case UINT8_C(3):
    case UINT8_C(4):
    case UINT8_C(6):
      status = FN_CONNECT_ERROR;
      break;
    case UINT8_C(5):
      status = FN_CONNECTION_REFUSED;
      break;
    case UINT8_C(7):
    case UINT8_C(8):
      status = FN_UNSUPPORTED;
      break;
    default:
      return outbound_wire_result(FN_PROTOCOL_ERROR,
                                  FN_STAGE_SOCKS_CONNECT, reply);
  }
  return outbound_wire_result(status, FN_STAGE_SOCKS_CONNECT, reply);
}

static fn_result_t reply_length(const fn_socks5_outbound_t *operation,
                                size_t *out)
{
  uint8_t address_type;
  if (operation->input_length < 4u) {
    *out = 4u;
    return outbound_result(FN_AGAIN, FN_STAGE_SOCKS_CONNECT);
  }
  address_type = operation->input[3];
  if (address_type == SOCKS_ADDRESS_V4) {
    *out = 10u;
  } else if (address_type == SOCKS_ADDRESS_V6) {
    *out = 22u;
  } else if (address_type == SOCKS_ADDRESS_DOMAIN) {
    if (operation->input_length < 5u) {
      *out = 5u;
      return outbound_result(FN_AGAIN, FN_STAGE_SOCKS_CONNECT);
    }
    if (operation->input[4] == 0) {
      return outbound_wire_result(FN_PROTOCOL_ERROR,
                                  FN_STAGE_SOCKS_CONNECT, address_type);
    }
    *out = 7u + operation->input[4];
  } else {
    return outbound_wire_result(FN_PROTOCOL_ERROR,
                                FN_STAGE_SOCKS_CONNECT, address_type);
  }
  return operation->input_length < *out ?
    outbound_result(FN_AGAIN, FN_STAGE_SOCKS_CONNECT) :
    outbound_result(FN_OK, FN_STAGE_NONE);
}

static fn_result_t parse_reply(fn_socks5_outbound_t *operation)
{
  fn_addr_t address;
  fn_domain_t domain;
  fn_result_t result;
  size_t length;
  size_t port_offset;
  uint8_t reply;
  if (operation->input[0] != SOCKS_VERSION) {
    return outbound_wire_result(FN_PROTOCOL_ERROR,
                                FN_STAGE_SOCKS_CONNECT,
                                operation->input[0]);
  }
  if (operation->input[2] != 0) {
    return outbound_wire_result(FN_PROTOCOL_ERROR,
                                FN_STAGE_SOCKS_CONNECT,
                                operation->input[2]);
  }
  result = reply_length(operation, &length);
  if (result.code != FN_OK) {
    return result;
  }
  if (operation->input[3] == SOCKS_ADDRESS_V4) {
    result = fn_addr_from_v4(&address, operation->input + 4u);
    port_offset = 8u;
  } else if (operation->input[3] == SOCKS_ADDRESS_V6) {
    result = fn_addr_from_v6(&address, operation->input + 4u);
    port_offset = 20u;
  } else {
    size_t domain_length = operation->input[4];
    result = fn_domain_from_bytes(&domain, operation->input + 5u,
                                  domain_length);
    if (result.code == FN_OK) {
      result = fn_addr_from_domain(&address, &domain);
    }
    port_offset = 5u + domain_length;
  }
  if (result.code != FN_OK || port_offset + 2u != length) {
    return outbound_wire_result(FN_PROTOCOL_ERROR,
                                FN_STAGE_SOCKS_CONNECT,
                                operation->input[3]);
  }
  result = fn_endpoint_make(&operation->bound_endpoint, &address,
                            fn_u16_read_be(operation->input + port_offset));
  if (result.code != FN_OK) {
    return outbound_wire_result(FN_PROTOCOL_ERROR,
                                FN_STAGE_SOCKS_CONNECT,
                                operation->input[3]);
  }
  reply = operation->input[1];
  operation->input_length = 0;
  return reply == 0 ? outbound_result(FN_OK, FN_STAGE_NONE) :
                      reply_result(reply);
}

static fn_result_t parse_input(fn_socks5_outbound_t *operation)
{
  uint8_t expected_method;
  fn_result_t result;
  if (operation->state == FN_SOCKS5_OUT_METHOD_READ) {
    if (operation->input_length < 2u) {
      return outbound_result(FN_AGAIN, FN_STAGE_SOCKS_AUTH);
    }
    if (operation->input[0] != SOCKS_VERSION) {
      return outbound_wire_result(FN_PROTOCOL_ERROR,
                                  FN_STAGE_SOCKS_AUTH,
                                  operation->input[0]);
    }
    expected_method = operation->has_credentials ?
      (uint8_t)FN_SOCKS5_METHOD_USERNAME_PASSWORD :
      (uint8_t)FN_SOCKS5_METHOD_NO_AUTH;
    if (operation->input[1] == (uint8_t)FN_SOCKS5_METHOD_NO_ACCEPTABLE) {
      return outbound_wire_result(FN_AUTH_ERROR, FN_STAGE_SOCKS_AUTH,
                                  operation->input[1]);
    }
    if (operation->input[1] != expected_method) {
      return outbound_wire_result(FN_PROTOCOL_ERROR,
                                  FN_STAGE_SOCKS_AUTH,
                                  operation->input[1]);
    }
    operation->input_length = 0;
    if (operation->has_credentials) {
      queue_auth(operation);
      return outbound_result(FN_OK, FN_STAGE_NONE);
    }
    return queue_request(operation);
  }
  if (operation->state == FN_SOCKS5_OUT_AUTH_READ) {
    if (operation->input_length < 2u) {
      return outbound_result(FN_AGAIN, FN_STAGE_SOCKS_AUTH);
    }
    if (operation->input[0] != SOCKS_AUTH_VERSION) {
      return outbound_wire_result(FN_PROTOCOL_ERROR,
                                  FN_STAGE_SOCKS_AUTH,
                                  operation->input[0]);
    }
    if (operation->input[1] != 0) {
      return outbound_wire_result(FN_AUTH_ERROR, FN_STAGE_SOCKS_AUTH,
                                  operation->input[1]);
    }
    operation->input_length = 0;
    return queue_request(operation);
  }
  if (operation->state == FN_SOCKS5_OUT_CONNECT_REPLY_READ) {
    result = parse_reply(operation);
    if (result.code == FN_OK) {
      operation->state = FN_SOCKS5_OUT_READY;
    }
    return result;
  }
  return outbound_result(FN_INVALID, FN_STAGE_SOCKS_CONNECT);
}

static size_t read_required(const fn_socks5_outbound_t *operation)
{
  size_t required = 2u;
  size_t reply_required;
  fn_result_t result;
  if (operation->state != FN_SOCKS5_OUT_CONNECT_REPLY_READ) {
    return required;
  }
  result = reply_length(operation, &reply_required);
  if (result.code == FN_PROTOCOL_ERROR) {
    return operation->input_length;
  }
  return reply_required;
}

static fn_result_t update_watch(fn_socks5_outbound_t *operation);

static void advance(fn_socks5_outbound_t *operation)
{
  fn_result_t result;
  if (operation->state == FN_SOCKS5_OUT_READY) {
    operation_finish(operation, outbound_result(FN_OK, FN_STAGE_NONE));
    return;
  }
  result = update_watch(operation);
  if (result.code != FN_OK) {
    operation_finish(operation, result);
  }
}

static void protocol_write(fn_socks5_outbound_t *operation)
{
  size_t calls;
  for (calls = 0; calls < 32u &&
                  operation->output_offset < operation->output_length;
       calls++) {
    size_t remaining = operation->output_length - operation->output_offset;
    fn_io_result_t io = fn_stream_write(
      operation->stream, operation->output + operation->output_offset,
      remaining);
    if (io.result.code == FN_AGAIN) {
      break;
    }
    if (io.result.code != FN_OK || io.transferred == 0 ||
        io.transferred > remaining) {
      operation_finish(
        operation, io.result.code == FN_OK ?
          outbound_result(FN_IO_ERROR, protocol_stage(operation)) :
          transport_result(operation, io.result));
      return;
    }
    operation->output_offset += io.transferred;
  }
  if (operation->output_offset == operation->output_length) {
    operation->output_length = 0;
    operation->output_offset = 0;
    if (operation->state == FN_SOCKS5_OUT_GREETING_WRITE) {
      operation->state = FN_SOCKS5_OUT_METHOD_READ;
    } else if (operation->state == FN_SOCKS5_OUT_AUTH_WRITE) {
      operation->state = FN_SOCKS5_OUT_AUTH_READ;
    } else if (operation->state == FN_SOCKS5_OUT_REQUEST_WRITE) {
      operation->state = FN_SOCKS5_OUT_CONNECT_REPLY_READ;
    } else {
      operation_finish(
        operation, outbound_result(FN_INVALID, FN_STAGE_SOCKS_CONNECT));
      return;
    }
  }
  advance(operation);
}

static void protocol_read(fn_socks5_outbound_t *operation)
{
  size_t calls;
  for (calls = 0; calls < 32u; calls++) {
    size_t required = read_required(operation);
    fn_io_result_t io;
    fn_result_t result;
    if (required <= operation->input_length) {
      result = parse_input(operation);
      if (result.code == FN_AGAIN) {
        continue;
      }
      if (result.code != FN_OK) {
        operation_finish(operation, result);
        return;
      }
      if (operation->state == FN_SOCKS5_OUT_READY ||
          operation->output_length != 0) {
        break;
      }
      continue;
    }
    io = fn_stream_read(operation->stream,
                        operation->input + operation->input_length,
                        required - operation->input_length);
    if (io.result.code == FN_AGAIN) {
      break;
    }
    if (io.result.code == FN_EOF) {
      operation_finish(
        operation, outbound_wire_result(FN_PROTOCOL_ERROR,
                                        protocol_stage(operation), 0));
      return;
    }
    if (io.result.code != FN_OK || io.transferred == 0 ||
        io.transferred > required - operation->input_length) {
      operation_finish(
        operation, io.result.code == FN_OK ?
          outbound_result(FN_IO_ERROR, protocol_stage(operation)) :
          transport_result(operation, io.result));
      return;
    }
    operation->input_length += io.transferred;
  }
  advance(operation);
}

static void stream_ready(fn_stream_t *stream, uint32_t events,
                         void *context)
{
  fn_socks5_outbound_t *operation = context;
  if (stream != operation->stream || (events & FN_IO_EVENT_ERROR) != 0) {
    operation_finish(
      operation, outbound_result(FN_IO_ERROR, protocol_stage(operation)));
    return;
  }
  if ((events & FN_IO_EVENT_WRITE) != 0) {
    protocol_write(operation);
  } else if ((events & FN_IO_EVENT_READ) != 0) {
    protocol_read(operation);
  }
}

static fn_result_t update_watch(fn_socks5_outbound_t *operation)
{
  uint32_t events;
  if (operation->output_length != 0) {
    events = FN_IO_EVENT_WRITE;
  } else if (operation->state == FN_SOCKS5_OUT_METHOD_READ ||
             operation->state == FN_SOCKS5_OUT_AUTH_READ ||
             operation->state == FN_SOCKS5_OUT_CONNECT_REPLY_READ) {
    events = FN_IO_EVENT_READ;
  } else if (operation->state == FN_SOCKS5_OUT_READY) {
    events = 0;
  } else {
    return outbound_result(FN_INVALID, FN_STAGE_SOCKS_CONNECT);
  }
  return fn_stream_watch(operation->stream, events,
                         events == 0 ? NULL : stream_ready,
                         events == 0 ? NULL : operation);
}

static void protocol_timeout(fn_timer_t *timer, void *context)
{
  fn_socks5_outbound_t *operation = context;
  (void)timer;
  (void)fn_timer_destroy(&operation->timer);
  operation_finish(
    operation, outbound_result(FN_TIMEOUT, protocol_stage(operation)));
}

static void tcp_connected(
  fn_direct_connect_t *connect_operation, void *context, fn_result_t result,
  fn_stream_t *owned_stream, const fn_endpoint_t *bound_endpoint,
  const fn_endpoint_t *connected_endpoint)
{
  fn_socks5_outbound_t *operation = context;
  fn_result_t start_result;
  (void)connect_operation;
  (void)bound_endpoint;
  if (result.code == FN_OK && connected_endpoint != NULL) {
    operation->connected_endpoint = *connected_endpoint;
  }
  (void)fn_direct_connect_release(&operation->connect_operation);
  if (operation->cancel_requested) {
    if (owned_stream != NULL) {
      (void)fn_stream_abort(owned_stream);
      (void)fn_stream_release(&owned_stream);
    }
    operation_finish(
      operation, outbound_result(FN_CANCELLED, FN_STAGE_TCP_CONNECT));
    return;
  }
  if (result.code != FN_OK || owned_stream == NULL ||
      connected_endpoint == NULL) {
    if (owned_stream != NULL) {
      (void)fn_stream_abort(owned_stream);
      (void)fn_stream_release(&owned_stream);
    }
    operation_finish(
      operation, result.code == FN_OK ?
        outbound_result(FN_INVALID, FN_STAGE_TCP_CONNECT) : result);
    return;
  }
  operation->stream = owned_stream;
  operation->protocol_active = true;
  operation->manager->protocol_operations++;
  queue_greeting(operation);
  start_result = fn_timer_start(operation->manager->loop,
                                operation->deadline_ms, protocol_timeout,
                                operation, &operation->timer);
  if (start_result.code == FN_OK) {
    start_result = update_watch(operation);
  }
  if (start_result.code != FN_OK) {
    operation_finish(operation, start_result);
  }
}

static fn_result_t start_tcp(fn_socks5_outbound_t *operation,
                             const fn_resolved_t *resolved)
{
  uint16_t mask = UINT16_C(0);
  if (resolved != NULL) {
    mask = resolved->count == FN_RESOLVED_MAX ? UINT16_MAX :
      (uint16_t)((UINT32_C(1) << resolved->count) - UINT32_C(1));
  }
  return fn_direct_connect_start_for_purpose(
    operation->manager->tcp_connector, FN_SOCKET_PURPOSE_PROXY,
    &operation->proxy_endpoint, resolved, mask, operation->deadline_ms,
    tcp_connected, operation, &operation->connect_operation);
}

static void bootstrap_resolved(fn_resolver_operation_t *resolve_operation,
                               void *context, fn_result_t result,
                               const fn_resolved_t *resolved)
{
  fn_socks5_outbound_t *operation = context;
  fn_resolved_t resolved_copy;
  bool has_resolved = result.code == FN_OK && resolved != NULL &&
                      resolved->count != 0;
  (void)resolve_operation;
  if (has_resolved) {
    resolved_copy = *resolved;
  }
  (void)fn_resolver_operation_release(&operation->resolve_operation);
  operation->manager->bootstrap_operations--;
  if (operation->cancel_requested) {
    operation_finish(
      operation, outbound_result(FN_CANCELLED, FN_STAGE_RESOLVE));
    return;
  }
  if (!has_resolved) {
    operation_finish(
      operation, result.code == FN_OK ?
        outbound_result(FN_RESOLVE_ERROR, FN_STAGE_RESOLVE) : result);
    return;
  }
  result = start_tcp(operation, &resolved_copy);
  if (result.code != FN_OK) {
    operation_finish(operation, result);
  }
}

static void operation_free(fn_socks5_outbound_t *operation)
{
  fn_socks5_outbound_manager_t *manager = operation->manager;
  operation_stop_protocol(operation);
  if (operation->stream != NULL) {
    (void)fn_stream_abort(operation->stream);
    (void)fn_stream_release(&operation->stream);
  }
  credentials_clear(&operation->credentials);
  manager->active_operations--;
  manager->allocator.deallocate(manager->allocator.context, operation);
  (void)fn_budget_release(manager->owned_memory, FN_BUDGET_ACTIVE,
                          sizeof(*operation));
}

fn_result_t fn_socks5_outbound_manager_create(
  const fn_socks5_outbound_manager_options_t *options,
  fn_socks5_outbound_manager_t **out)
{
  fn_socks5_outbound_manager_t *manager;
  fn_result_t result;
  if (out == NULL) {
    return outbound_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  *out = NULL;
  if (options == NULL || options->loop == NULL || options->limits == NULL ||
      options->owned_memory == NULL || options->tcp_connector == NULL ||
      options->allocator.allocate == NULL ||
      options->allocator.deallocate == NULL ||
      !fn_loop_is_owner(options->loop)) {
    return outbound_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  result = fn_budget_reserve(options->owned_memory, FN_BUDGET_ACTIVE,
                             sizeof(*manager));
  if (result.code != FN_OK) {
    return result;
  }
  manager = options->allocator.allocate(options->allocator.context,
                                         sizeof(*manager));
  if (manager == NULL) {
    (void)fn_budget_release(options->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*manager));
    return outbound_result(FN_NO_MEMORY, FN_STAGE_RESOURCE);
  }
  memset(manager, 0, sizeof(*manager));
  manager->loop = options->loop;
  manager->limits = *options->limits;
  manager->owned_memory = options->owned_memory;
  manager->allocator = options->allocator;
  manager->tcp_connector = options->tcp_connector;
  manager->resolver = options->resolver;
  *out = manager;
  return outbound_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_outbound_manager_destroy(
  fn_socks5_outbound_manager_t **pointer)
{
  fn_socks5_outbound_manager_t *manager;
  fn_budget_t *owned_memory;
  fn_allocator_t allocator;
  if (pointer == NULL) {
    return outbound_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  manager = *pointer;
  if (manager == NULL) {
    return outbound_result(FN_OK, FN_STAGE_NONE);
  }
  if (!manager_is_owner(manager) || manager->active_operations != 0 ||
      manager->bootstrap_operations != 0 ||
      manager->protocol_operations != 0) {
    return outbound_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  owned_memory = manager->owned_memory;
  allocator = manager->allocator;
  allocator.deallocate(allocator.context, manager);
  (void)fn_budget_release(owned_memory, FN_BUDGET_ACTIVE,
                          sizeof(*manager));
  *pointer = NULL;
  return outbound_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_outbound_manager_snapshot(
  const fn_socks5_outbound_manager_t *manager,
  fn_socks5_outbound_manager_snapshot_t *out)
{
  if (!manager_is_owner(manager) || out == NULL) {
    return outbound_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  out->active_operations = manager->active_operations;
  out->bootstrap_operations = manager->bootstrap_operations;
  out->protocol_operations = manager->protocol_operations;
  return outbound_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_outbound_start(
  fn_socks5_outbound_manager_t *manager,
  const fn_endpoint_t *proxy_endpoint, bool has_credentials,
  const fn_user_config_t *credentials, const fn_endpoint_t *target,
  uint64_t deadline_ms, fn_socks5_outbound_callback_fn callback,
  void *context, fn_socks5_outbound_t **out)
{
  fn_socks5_outbound_t *operation;
  fn_result_t result;
  uint64_t now_ms;
  if (out == NULL) {
    return outbound_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  *out = NULL;
  if (!manager_is_owner(manager) || proxy_endpoint == NULL ||
      (proxy_endpoint->address.kind != FN_ADDR_V4 &&
       proxy_endpoint->address.kind != FN_ADDR_DOMAIN) ||
      proxy_endpoint->port == 0 || target == NULL ||
      (target->address.kind != FN_ADDR_V4 &&
       target->address.kind != FN_ADDR_DOMAIN) || target->port == 0 ||
      callback == NULL ||
      (has_credentials &&
       (credentials == NULL || credentials->username_length == 0 ||
        credentials->password_length == 0)) ||
      fn_monotonic_now_ms(&now_ms).code != FN_OK) {
    return outbound_result(FN_INVALID, FN_STAGE_SOCKS_CONNECT);
  }
  if (deadline_ms <= now_ms) {
    return outbound_result(FN_TIMEOUT, FN_STAGE_SOCKS_CONNECT);
  }
  if (manager->active_operations >= manager->limits.async_operation_limit) {
    return outbound_result(FN_LIMIT, FN_STAGE_RESOURCE);
  }
  result = fn_budget_reserve(manager->owned_memory, FN_BUDGET_ACTIVE,
                             sizeof(*operation));
  if (result.code != FN_OK) {
    return result;
  }
  operation = manager->allocator.allocate(manager->allocator.context,
                                           sizeof(*operation));
  if (operation == NULL) {
    (void)fn_budget_release(manager->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*operation));
    return outbound_result(FN_NO_MEMORY, FN_STAGE_RESOURCE);
  }
  memset(operation, 0, sizeof(*operation));
  operation->manager = manager;
  operation->callback = callback;
  operation->callback_context = context;
  operation->state = FN_SOCKS5_OUT_TCP_CONNECT;
  operation->proxy_endpoint = *proxy_endpoint;
  operation->target = *target;
  operation->deadline_ms = deadline_ms;
  operation->has_credentials = has_credentials;
  if (has_credentials) {
    operation->credentials = *credentials;
  }
  result = fn_completion_reserve_terminal(manager->loop,
                                           &operation->ticket);
  if (result.code != FN_OK) {
    credentials_clear(&operation->credentials);
    manager->allocator.deallocate(manager->allocator.context, operation);
    (void)fn_budget_release(manager->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*operation));
    return result;
  }
  manager->active_operations++;
  if (proxy_endpoint->address.kind == FN_ADDR_DOMAIN) {
    if (manager->resolver == NULL) {
      result = outbound_result(FN_INVALID, FN_STAGE_RESOLVE);
    } else {
      result = fn_resolver_acquire(
        manager->resolver, &proxy_endpoint->address.value.domain,
        FN_RESOLVER_PURPOSE_BOOTSTRAP, deadline_ms, bootstrap_resolved,
        operation, &operation->resolve_operation);
      if (result.code == FN_OK) {
        manager->bootstrap_operations++;
      }
    }
  } else {
    result = start_tcp(operation, NULL);
  }
  if (result.code != FN_OK) {
    (void)fn_completion_abandon(&operation->ticket);
    operation_free(operation);
    return result;
  }
  *out = operation;
  return outbound_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_outbound_cancel(fn_socks5_outbound_t *operation)
{
  if (!operation_is_owner(operation) || operation->callback_started) {
    return outbound_result(FN_INVALID, FN_STAGE_SOCKS_CONNECT);
  }
  operation->cancel_requested = true;
  if (operation->terminal_queued) {
    return outbound_result(FN_OK, FN_STAGE_NONE);
  }
  if (operation->resolve_operation != NULL) {
    (void)fn_resolver_operation_cancel(operation->resolve_operation);
  } else if (operation->connect_operation != NULL) {
    (void)fn_direct_connect_cancel(operation->connect_operation);
  } else {
    operation_finish(
      operation, outbound_result(FN_CANCELLED,
                                 protocol_stage(operation)));
  }
  return outbound_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_outbound_release(fn_socks5_outbound_t **pointer)
{
  fn_socks5_outbound_t *operation;
  if (pointer == NULL) {
    return outbound_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  operation = *pointer;
  if (operation == NULL) {
    return outbound_result(FN_OK, FN_STAGE_NONE);
  }
  if (!operation_is_owner(operation) || !operation->callback_started ||
      operation->ticket != NULL || operation->resolve_operation != NULL ||
      operation->connect_operation != NULL || operation->timer != NULL ||
      operation->stream != NULL || operation->protocol_active) {
    return outbound_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  operation_free(operation);
  *pointer = NULL;
  return outbound_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_outbound_snapshot(
  const fn_socks5_outbound_t *operation,
  fn_socks5_outbound_snapshot_t *out)
{
  if (!operation_is_owner(operation) || out == NULL) {
    return outbound_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  memset(out, 0, sizeof(*out));
  out->state = operation->state;
  out->input_bytes = operation->input_length;
  out->output_bytes = operation->output_length - operation->output_offset;
  out->terminal_result = operation->terminal_result;
  out->proxy_endpoint = operation->proxy_endpoint;
  out->connected_endpoint = operation->connected_endpoint;
  out->bound_endpoint = operation->bound_endpoint;
  return outbound_result(FN_OK, FN_STAGE_NONE);
}
