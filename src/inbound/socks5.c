#include "flicknet/socks5.h"

#include "flicknet/clock.h"
#include "flicknet/resolver.h"

#include "../core/operation_internal.h"

#include <errno.h>
#include <string.h>

#define SOCKS_VERSION UINT8_C(5)
#define SOCKS_AUTH_VERSION UINT8_C(1)
#define SOCKS_COMMAND_CONNECT UINT8_C(1)
#define SOCKS_ADDRESS_V4 UINT8_C(1)
#define SOCKS_ADDRESS_DOMAIN UINT8_C(3)
#define SOCKS_ADDRESS_V6 UINT8_C(4)

struct fn_socks5_inbound_manager {
  fn_loop_t *loop;
  fn_limits_t limits;
  fn_budget_t *owned_memory;
  fn_budget_t *buffer_bytes;
  fn_allocator_t allocator;
  fn_user_config_t *users;
  size_t user_count;
  size_t user_bytes;
  size_t active_handshakes;
};

struct fn_socks5_inbound {
  fn_socks5_inbound_manager_t *manager;
  fn_socks5_inbound_state_t state;
  fn_socks5_inbound_state_t after_output;
  fn_result_t terminal_result;
  fn_endpoint_t target;
  uint64_t deadline_ms;
  uint8_t workspace[FN_SOCKS5_WORKSPACE_SIZE];
  uint8_t output[FN_SOCKS5_WORKSPACE_SIZE];
  uint8_t *preread;
  size_t workspace_length;
  size_t output_length;
  size_t output_offset;
  size_t preread_length;
  size_t preread_offset;
  size_t preread_capacity;
  uint8_t selected_method;
  bool terminal_set;
  bool authenticated;
  bool target_ready;
};

typedef struct fn_socks5_connection fn_socks5_connection_t;
typedef struct fn_socks5_reply_operation fn_socks5_reply_operation_t;

struct fn_socks5_handshake {
  fn_socks5_inbound_manager_t *manager;
  fn_socks5_connection_t *connection;
  fn_completion_ticket_t *ticket;
  fn_socks5_handshake_callback_fn callback;
  void *callback_context;
  fn_inbound_request_t *request;
  fn_result_t terminal_result;
  bool terminal_queued;
  bool callback_started;
};

struct fn_socks5_reply_operation {
  fn_op_t base;
  fn_socks5_connection_t *connection;
  fn_completion_ticket_t *ticket;
  fn_reply_callback_fn callback;
  void *callback_context;
  fn_result_t terminal_result;
  fn_result_t outcome;
  bool terminal_queued;
  bool callback_started;
};

struct fn_socks5_connection {
  fn_socks5_inbound_manager_t *manager;
  fn_socks5_inbound_t *parser;
  fn_stream_t *stream;
  fn_timer_t *timer;
  fn_runtime_t *runtime;
  fn_socks5_handshake_t *handshake;
  fn_socks5_reply_operation_t *reply_operation;
  fn_endpoint_t source;
  fn_object_ref_t inbound;
  fn_result_t deferred_error;
  uint64_t accepted_at_ms;
  bool request_transferred;
  bool deferred_error_set;
};

static fn_result_t socks_result(fn_status_t code, fn_error_stage_t stage)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE : stage,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static fn_result_t socks_wire_result(fn_status_t code,
                                     fn_error_stage_t stage,
                                     uint8_t native_code)
{
  return fn_result_make(code, stage, FN_ERROR_ORIGIN_SOCKS,
                        (int64_t)native_code);
}

static bool manager_is_owner(const fn_socks5_inbound_manager_t *manager)
{
  return manager != NULL && fn_loop_is_owner(manager->loop);
}

static bool inbound_is_owner(const fn_socks5_inbound_t *inbound)
{
  return inbound != NULL && manager_is_owner(inbound->manager);
}

static void set_terminal(fn_socks5_inbound_t *inbound, fn_result_t result)
{
  if (!inbound->terminal_set) {
    inbound->terminal_result = result;
    inbound->terminal_set = true;
  }
}

static void workspace_discard(fn_socks5_inbound_t *inbound, size_t length)
{
  if (length < inbound->workspace_length) {
    memmove(inbound->workspace, inbound->workspace + length,
            inbound->workspace_length - length);
  }
  inbound->workspace_length -= length;
}

static void queue_output(fn_socks5_inbound_t *inbound,
                         fn_socks5_inbound_state_t state,
                         fn_socks5_inbound_state_t after,
                         const uint8_t *data, size_t length)
{
  memcpy(inbound->output, data, length);
  inbound->output_length = length;
  inbound->output_offset = 0;
  inbound->state = state;
  inbound->after_output = after;
}

static void queue_method(fn_socks5_inbound_t *inbound, uint8_t method,
                         fn_socks5_inbound_state_t after)
{
  const uint8_t output[2] = {SOCKS_VERSION, method};
  inbound->selected_method = method;
  queue_output(inbound, FN_SOCKS5_METHOD_WRITE, after,
               output, sizeof(output));
}

static void queue_auth(fn_socks5_inbound_t *inbound, bool success)
{
  const uint8_t output[2] = {
    SOCKS_AUTH_VERSION, success ? UINT8_C(0) : UINT8_C(1),
  };
  queue_output(inbound, FN_SOCKS5_AUTH_WRITE,
               success ? FN_SOCKS5_REQUEST_READ : FN_SOCKS5_CLOSED,
               output, sizeof(output));
}

static void encode_failure_reply(uint8_t output[10], uint8_t reply)
{
  memset(output, 0, 10u);
  output[0] = SOCKS_VERSION;
  output[1] = reply;
  output[3] = SOCKS_ADDRESS_V4;
}

static fn_result_t encode_success_reply(
  uint8_t output[FN_SOCKS5_WORKSPACE_SIZE],
  const fn_endpoint_t *bound, size_t *out_length)
{
  size_t offset = 4u;
  if (bound == NULL || out_length == NULL) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  output[0] = SOCKS_VERSION;
  output[1] = FN_SOCKS5_REP_SUCCEEDED;
  output[2] = UINT8_C(0);
  if (bound->address.kind == FN_ADDR_V4) {
    output[3] = SOCKS_ADDRESS_V4;
    memcpy(output + offset, bound->address.value.v4, 4u);
    offset += 4u;
  } else if (bound->address.kind == FN_ADDR_V6) {
    output[3] = SOCKS_ADDRESS_V6;
    memcpy(output + offset, bound->address.value.v6, 16u);
    offset += 16u;
  } else if (bound->address.kind == FN_ADDR_DOMAIN &&
             bound->address.value.domain.length != 0 &&
             bound->address.value.domain.length <= UINT8_MAX) {
    const fn_domain_t *domain = &bound->address.value.domain;
    output[3] = SOCKS_ADDRESS_DOMAIN;
    output[offset++] = (uint8_t)domain->length;
    memcpy(output + offset, domain->bytes, domain->length);
    offset += domain->length;
  } else {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  fn_u16_write_be(output + offset, bound->port);
  offset += 2u;
  *out_length = offset;
  return socks_result(FN_OK, FN_STAGE_NONE);
}

static void queue_failure_reply(fn_socks5_inbound_t *inbound,
                                fn_socks5_reply_t reply,
  fn_result_t result)
{
  uint8_t output[10];
  set_terminal(inbound, result);
  encode_failure_reply(output, (uint8_t)reply);
  queue_output(inbound, FN_SOCKS5_FAIL_REPLY_WRITE, FN_SOCKS5_CLOSED,
               output, sizeof(output));
}

static bool authenticate(const fn_socks5_inbound_manager_t *manager,
                         const uint8_t *username, uint8_t username_length,
                         const uint8_t *password, uint8_t password_length)
{
  uint32_t any_match = UINT32_C(0);
  size_t user_index;
  for (user_index = 0; user_index < manager->user_count; user_index++) {
    const fn_user_config_t *user = &manager->users[user_index];
    uint32_t difference =
      (uint32_t)(user->username_length ^ username_length) |
      (uint32_t)(user->password_length ^ password_length);
    size_t index;
    for (index = 0; index < 255u; index++) {
      uint8_t expected_username = index < user->username_length ?
        (uint8_t)user->username[index] : UINT8_C(0);
      uint8_t actual_username = index < username_length ?
        username[index] : UINT8_C(0);
      uint8_t expected_password = index < user->password_length ?
        (uint8_t)user->password[index] : UINT8_C(0);
      uint8_t actual_password = index < password_length ?
        password[index] : UINT8_C(0);
      difference |= (uint32_t)(expected_username ^ actual_username);
      difference |= (uint32_t)(expected_password ^ actual_password);
    }
    any_match |= (uint32_t)(difference == UINT32_C(0));
  }
  return any_match != UINT32_C(0);
}

static fn_result_t preread_reserve(fn_socks5_inbound_t *inbound,
                                   size_t required)
{
  fn_socks5_inbound_manager_t *manager = inbound->manager;
  size_t new_capacity;
  uint8_t *new_buffer;
  fn_result_t result;
  if (required <= inbound->preread_capacity) {
    return socks_result(FN_OK, FN_STAGE_NONE);
  }
  new_capacity = inbound->preread_capacity == 0 ? 1024u :
                                                inbound->preread_capacity;
  while (new_capacity < required && new_capacity < FN_SOCKS5_PREREAD_MAX) {
    new_capacity *= 2u;
  }
  if (new_capacity > FN_SOCKS5_PREREAD_MAX) {
    new_capacity = FN_SOCKS5_PREREAD_MAX;
  }
  result = fn_budget_reserve_pair(manager->owned_memory, new_capacity,
                                  manager->buffer_bytes, new_capacity,
                                  FN_BUDGET_ACTIVE);
  if (result.code != FN_OK) {
    return result;
  }
  new_buffer = manager->allocator.allocate(manager->allocator.context,
                                            new_capacity);
  if (new_buffer == NULL) {
    (void)fn_budget_release_pair(manager->owned_memory, new_capacity,
                                 manager->buffer_bytes, new_capacity,
                                 FN_BUDGET_ACTIVE);
    return socks_result(FN_NO_MEMORY, FN_STAGE_RESOURCE);
  }
  if (inbound->preread_length != 0) {
    memcpy(new_buffer, inbound->preread, inbound->preread_length);
  }
  if (inbound->preread != NULL) {
    manager->allocator.deallocate(manager->allocator.context,
                                  inbound->preread);
    (void)fn_budget_release_pair(manager->owned_memory,
                                 inbound->preread_capacity,
                                 manager->buffer_bytes,
                                 inbound->preread_capacity,
                                 FN_BUDGET_ACTIVE);
  }
  inbound->preread = new_buffer;
  inbound->preread_capacity = new_capacity;
  return socks_result(FN_OK, FN_STAGE_NONE);
}

static fn_result_t preread_append(fn_socks5_inbound_t *inbound,
                                  const uint8_t *data, size_t length)
{
  size_t required;
  fn_result_t result;
  if (!fn_size_add(inbound->preread_length, length, &required) ||
      required > FN_SOCKS5_PREREAD_MAX) {
    return socks_result(FN_LIMIT, FN_STAGE_RESOURCE);
  }
  result = preread_reserve(inbound, required);
  if (result.code != FN_OK) {
    return result;
  }
  memcpy(inbound->preread + inbound->preread_length, data, length);
  inbound->preread_length += length;
  return socks_result(FN_OK, FN_STAGE_NONE);
}

static void parse_workspace(fn_socks5_inbound_t *inbound);

static void parse_greeting(fn_socks5_inbound_t *inbound)
{
  size_t frame_length;
  size_t index;
  bool found = false;
  uint8_t method;
  if (inbound->workspace_length < 2u) {
    return;
  }
  if (inbound->workspace[0] != SOCKS_VERSION) {
    set_terminal(inbound,
                 socks_result(FN_PROTOCOL_ERROR,
                              FN_STAGE_INBOUND_HANDSHAKE));
    inbound->state = FN_SOCKS5_CLOSED;
    inbound->workspace_length = 0;
    return;
  }
  frame_length = 2u + (size_t)inbound->workspace[1];
  if (frame_length == 2u) {
    workspace_discard(inbound, frame_length);
    set_terminal(inbound,
                 socks_result(FN_AUTH_ERROR, FN_STAGE_SOCKS_AUTH));
    queue_method(inbound, FN_SOCKS5_METHOD_NO_ACCEPTABLE,
                 FN_SOCKS5_CLOSED);
    return;
  }
  if (inbound->workspace_length < frame_length) {
    return;
  }
  method = inbound->manager->user_count == 0 ?
    (uint8_t)FN_SOCKS5_METHOD_NO_AUTH :
    (uint8_t)FN_SOCKS5_METHOD_USERNAME_PASSWORD;
  for (index = 2u; index < frame_length; index++) {
    found = found || inbound->workspace[index] == method;
  }
  workspace_discard(inbound, frame_length);
  if (!found) {
    set_terminal(inbound,
                 socks_result(FN_AUTH_ERROR, FN_STAGE_SOCKS_AUTH));
    queue_method(inbound, FN_SOCKS5_METHOD_NO_ACCEPTABLE,
                 FN_SOCKS5_CLOSED);
    return;
  }
  queue_method(inbound, method,
               method == (uint8_t)FN_SOCKS5_METHOD_NO_AUTH ?
                 FN_SOCKS5_REQUEST_READ : FN_SOCKS5_AUTH_READ);
}

static void parse_auth(fn_socks5_inbound_t *inbound)
{
  uint8_t username_length;
  uint8_t password_length;
  size_t password_length_offset;
  size_t frame_length;
  bool success;
  if (inbound->workspace_length < 2u) {
    return;
  }
  username_length = inbound->workspace[1];
  if (inbound->workspace[0] != SOCKS_AUTH_VERSION ||
      username_length == 0) {
    inbound->workspace_length = 0;
    set_terminal(inbound,
                 socks_result(FN_AUTH_ERROR, FN_STAGE_SOCKS_AUTH));
    queue_auth(inbound, false);
    return;
  }
  password_length_offset = 2u + (size_t)username_length;
  if (inbound->workspace_length <= password_length_offset) {
    return;
  }
  password_length = inbound->workspace[password_length_offset];
  if (password_length == 0) {
    inbound->workspace_length = 0;
    set_terminal(inbound,
                 socks_result(FN_AUTH_ERROR, FN_STAGE_SOCKS_AUTH));
    queue_auth(inbound, false);
    return;
  }
  frame_length = password_length_offset + 1u + (size_t)password_length;
  if (inbound->workspace_length < frame_length) {
    return;
  }
  success = authenticate(inbound->manager, inbound->workspace + 2u,
                         username_length,
                         inbound->workspace + password_length_offset + 1u,
                         password_length);
  workspace_discard(inbound, frame_length);
  if (!success) {
    set_terminal(inbound,
                 socks_result(FN_AUTH_ERROR, FN_STAGE_SOCKS_AUTH));
  } else {
    inbound->authenticated = true;
  }
  queue_auth(inbound, success);
}

static void request_failure(fn_socks5_inbound_t *inbound,
                            fn_socks5_reply_t reply,
                            fn_status_t code, uint8_t native_code)
{
  inbound->workspace_length = 0;
  queue_failure_reply(
    inbound, reply,
    socks_wire_result(code, FN_STAGE_INBOUND_HANDSHAKE, native_code));
}

static void parse_request(fn_socks5_inbound_t *inbound)
{
  fn_addr_t address;
  fn_domain_t domain;
  fn_result_t result;
  size_t frame_length;
  uint16_t port;
  uint8_t address_type;
  if (inbound->workspace_length < 4u) {
    return;
  }
  if (inbound->workspace[0] != SOCKS_VERSION) {
    inbound->workspace_length = 0;
    set_terminal(inbound,
                 socks_result(FN_PROTOCOL_ERROR,
                              FN_STAGE_INBOUND_HANDSHAKE));
    inbound->state = FN_SOCKS5_CLOSED;
    return;
  }
  if (inbound->workspace[1] != SOCKS_COMMAND_CONNECT) {
    request_failure(inbound, FN_SOCKS5_REP_COMMAND_UNSUPPORTED,
                    FN_UNSUPPORTED, inbound->workspace[1]);
    return;
  }
  if (inbound->workspace[2] != UINT8_C(0)) {
    request_failure(inbound, FN_SOCKS5_REP_GENERAL_FAILURE,
                    FN_PROTOCOL_ERROR, inbound->workspace[2]);
    return;
  }
  address_type = inbound->workspace[3];
  if (address_type == SOCKS_ADDRESS_V6 ||
      (address_type != SOCKS_ADDRESS_V4 &&
       address_type != SOCKS_ADDRESS_DOMAIN)) {
    request_failure(inbound, FN_SOCKS5_REP_ADDRESS_UNSUPPORTED,
                    FN_UNSUPPORTED, address_type);
    return;
  }
  if (address_type == SOCKS_ADDRESS_V4) {
    frame_length = 10u;
    if (inbound->workspace_length < frame_length) {
      return;
    }
    result = fn_addr_from_v4(&address, inbound->workspace + 4u);
  } else {
    uint8_t domain_length;
    if (inbound->workspace_length < 5u) {
      return;
    }
    domain_length = inbound->workspace[4];
    if (domain_length == 0 || domain_length > FN_DOMAIN_MAX) {
      request_failure(inbound, FN_SOCKS5_REP_GENERAL_FAILURE,
                      FN_PROTOCOL_ERROR, address_type);
      return;
    }
    frame_length = 7u + (size_t)domain_length;
    if (inbound->workspace_length < frame_length) {
      return;
    }
    result = fn_domain_from_bytes(&domain, inbound->workspace + 5u,
                                  domain_length);
    if (result.code == FN_OK) {
      result = fn_addr_from_domain(&address, &domain);
    }
  }
  port = fn_u16_read_be(inbound->workspace + frame_length - 2u);
  if (result.code != FN_OK || port == 0) {
    request_failure(inbound, FN_SOCKS5_REP_GENERAL_FAILURE,
                    FN_PROTOCOL_ERROR, address_type);
    return;
  }
  result = fn_endpoint_make(&inbound->target, &address, port);
  if (result.code != FN_OK) {
    request_failure(inbound, FN_SOCKS5_REP_GENERAL_FAILURE,
                    FN_PROTOCOL_ERROR, address_type);
    return;
  }
  workspace_discard(inbound, frame_length);
  inbound->target_ready = true;
  inbound->state = FN_SOCKS5_OUTBOUND_WAIT;
  if (inbound->workspace_length != 0) {
    result = preread_append(inbound, inbound->workspace,
                            inbound->workspace_length);
    inbound->workspace_length = 0;
    if (result.code != FN_OK) {
      queue_failure_reply(inbound, FN_SOCKS5_REP_GENERAL_FAILURE, result);
    }
  }
}

static void parse_workspace(fn_socks5_inbound_t *inbound)
{
  switch (inbound->state) {
    case FN_SOCKS5_GREETING_READ:
      parse_greeting(inbound);
      break;
    case FN_SOCKS5_AUTH_READ:
      parse_auth(inbound);
      break;
    case FN_SOCKS5_REQUEST_READ:
      parse_request(inbound);
      break;
    default:
      break;
  }
}

fn_socks5_reply_t fn_socks5_reply_from_result(fn_result_t result)
{
  int native_code = result.origin == FN_ERROR_ORIGIN_POSIX ?
                    (int)result.native_code : 0;
  if (result.code == FN_REJECTED || native_code == EACCES ||
      native_code == EPERM) {
    return FN_SOCKS5_REP_RULESET_DENIED;
  }
  if (native_code == ENETUNREACH) {
    return FN_SOCKS5_REP_NETWORK_UNREACHABLE;
  }
  if (result.code == FN_RESOLVE_ERROR || native_code == EHOSTUNREACH ||
      (result.code == FN_TIMEOUT &&
       (result.stage == FN_STAGE_RESOLVE ||
        result.stage == FN_STAGE_TCP_CONNECT))) {
    return FN_SOCKS5_REP_HOST_UNREACHABLE;
  }
  if (result.code == FN_CONNECTION_REFUSED || native_code == ECONNREFUSED) {
    return FN_SOCKS5_REP_CONNECTION_REFUSED;
  }
  return FN_SOCKS5_REP_GENERAL_FAILURE;
}

fn_result_t fn_socks5_inbound_manager_create(
  const fn_socks5_inbound_manager_options_t *options,
  fn_socks5_inbound_manager_t **out)
{
  fn_socks5_inbound_manager_t *manager;
  size_t user_bytes = 0;
  size_t index;
  fn_result_t result;
  if (out == NULL) {
    return socks_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  *out = NULL;
  if (options == NULL || options->loop == NULL || options->limits == NULL ||
      options->owned_memory == NULL || options->buffer_bytes == NULL ||
      options->allocator.allocate == NULL ||
      options->allocator.deallocate == NULL ||
      (options->user_count != 0 && options->users == NULL) ||
      !fn_loop_is_owner(options->loop) ||
      !fn_size_multiply(options->user_count, sizeof(fn_user_config_t),
                        &user_bytes)) {
    return socks_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  for (index = 0; index < options->user_count; index++) {
    if (options->users[index].username_length == 0 ||
        options->users[index].password_length == 0) {
      return socks_result(FN_INVALID, FN_STAGE_CONFIG);
    }
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
    return socks_result(FN_NO_MEMORY, FN_STAGE_RESOURCE);
  }
  memset(manager, 0, sizeof(*manager));
  manager->loop = options->loop;
  manager->limits = *options->limits;
  manager->owned_memory = options->owned_memory;
  manager->buffer_bytes = options->buffer_bytes;
  manager->allocator = options->allocator;
  manager->user_count = options->user_count;
  manager->user_bytes = user_bytes;
  if (user_bytes != 0) {
    result = fn_budget_reserve(manager->owned_memory, FN_BUDGET_ACTIVE,
                               user_bytes);
    if (result.code != FN_OK) {
      manager->allocator.deallocate(manager->allocator.context, manager);
      (void)fn_budget_release(manager->owned_memory, FN_BUDGET_ACTIVE,
                              sizeof(*manager));
      return result;
    }
    manager->users = manager->allocator.allocate(manager->allocator.context,
                                                  user_bytes);
    if (manager->users == NULL) {
      (void)fn_budget_release(manager->owned_memory, FN_BUDGET_ACTIVE,
                              user_bytes);
      manager->allocator.deallocate(manager->allocator.context, manager);
      (void)fn_budget_release(manager->owned_memory, FN_BUDGET_ACTIVE,
                              sizeof(*manager));
      return socks_result(FN_NO_MEMORY, FN_STAGE_RESOURCE);
    }
    memset(manager->users, 0, user_bytes);
    for (index = 0; index < options->user_count; index++) {
      manager->users[index].username_length =
        options->users[index].username_length;
      manager->users[index].password_length =
        options->users[index].password_length;
      memcpy(manager->users[index].username, options->users[index].username,
             options->users[index].username_length);
      memcpy(manager->users[index].password, options->users[index].password,
             options->users[index].password_length);
    }
  }
  *out = manager;
  return socks_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_inbound_manager_destroy(
  fn_socks5_inbound_manager_t **pointer)
{
  fn_socks5_inbound_manager_t *manager;
  fn_allocator_t allocator;
  fn_budget_t *owned_memory;
  size_t user_bytes;
  if (pointer == NULL) {
    return socks_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  manager = *pointer;
  if (manager == NULL) {
    return socks_result(FN_OK, FN_STAGE_NONE);
  }
  if (!manager_is_owner(manager) || manager->active_handshakes != 0) {
    return socks_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  allocator = manager->allocator;
  owned_memory = manager->owned_memory;
  user_bytes = manager->user_bytes;
  if (manager->users != NULL) {
    memset(manager->users, 0, user_bytes);
    allocator.deallocate(allocator.context, manager->users);
    (void)fn_budget_release(owned_memory, FN_BUDGET_ACTIVE, user_bytes);
  }
  allocator.deallocate(allocator.context, manager);
  (void)fn_budget_release(owned_memory, FN_BUDGET_ACTIVE, sizeof(*manager));
  *pointer = NULL;
  return socks_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_inbound_manager_snapshot(
  const fn_socks5_inbound_manager_t *manager,
  fn_socks5_inbound_manager_snapshot_t *out)
{
  if (!manager_is_owner(manager) || out == NULL) {
    return socks_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  out->active_handshakes = manager->active_handshakes;
  out->user_count = manager->user_count;
  return socks_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_inbound_open(fn_socks5_inbound_manager_t *manager,
                                   uint64_t deadline_ms,
                                   fn_socks5_inbound_t **out)
{
  fn_socks5_inbound_t *inbound;
  fn_result_t result;
  uint64_t now_ms;
  if (out == NULL) {
    return socks_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  *out = NULL;
  if (!manager_is_owner(manager) ||
      fn_monotonic_now_ms(&now_ms).code != FN_OK) {
    return socks_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  if (manager->active_handshakes >= manager->limits.handshake_limit) {
    return socks_result(FN_LIMIT, FN_STAGE_RESOURCE);
  }
  if (deadline_ms <= now_ms) {
    return socks_result(FN_TIMEOUT, FN_STAGE_INBOUND_HANDSHAKE);
  }
  result = fn_budget_reserve(manager->owned_memory, FN_BUDGET_ACTIVE,
                             sizeof(*inbound));
  if (result.code != FN_OK) {
    return result;
  }
  inbound = manager->allocator.allocate(manager->allocator.context,
                                         sizeof(*inbound));
  if (inbound == NULL) {
    (void)fn_budget_release(manager->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*inbound));
    return socks_result(FN_NO_MEMORY, FN_STAGE_RESOURCE);
  }
  memset(inbound, 0, sizeof(*inbound));
  inbound->manager = manager;
  inbound->state = FN_SOCKS5_GREETING_READ;
  inbound->deadline_ms = deadline_ms;
  manager->active_handshakes++;
  *out = inbound;
  return socks_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_inbound_feed(fn_socks5_inbound_t *inbound,
                                   const uint8_t *data, size_t length,
                                   size_t *consumed)
{
  size_t capacity;
  size_t take;
  fn_result_t result;
  if (consumed == NULL) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  *consumed = 0;
  if (!inbound_is_owner(inbound) || data == NULL || length == 0 ||
      inbound->state == FN_SOCKS5_CLOSED ||
      inbound->state == FN_SOCKS5_RELAY) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  if (inbound->state == FN_SOCKS5_CONNECT_REPLY_WRITE ||
      inbound->state == FN_SOCKS5_FAIL_REPLY_WRITE) {
    return socks_result(FN_AGAIN, FN_STAGE_NONE);
  }
  if (inbound->state == FN_SOCKS5_OUTBOUND_WAIT) {
    capacity = FN_SOCKS5_PREREAD_MAX - inbound->preread_length;
    if (capacity == 0) {
      return socks_result(FN_AGAIN, FN_STAGE_NONE);
    }
    take = length < capacity ? length : capacity;
    result = preread_append(inbound, data, take);
    if (result.code != FN_OK) {
      queue_failure_reply(inbound, FN_SOCKS5_REP_GENERAL_FAILURE, result);
      return result;
    }
    *consumed = take;
    return socks_result(FN_OK, FN_STAGE_NONE);
  }
  if (inbound->state == FN_SOCKS5_METHOD_WRITE ||
      inbound->state == FN_SOCKS5_AUTH_WRITE) {
    return socks_result(FN_AGAIN, FN_STAGE_NONE);
  }
  capacity = FN_SOCKS5_WORKSPACE_SIZE - inbound->workspace_length;
  if (capacity == 0) {
    return socks_result(FN_AGAIN, FN_STAGE_NONE);
  }
  take = length < capacity ? length : capacity;
  memcpy(inbound->workspace + inbound->workspace_length, data, take);
  inbound->workspace_length += take;
  *consumed = take;
  parse_workspace(inbound);
  return socks_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_inbound_output_peek(
  const fn_socks5_inbound_t *inbound, const uint8_t **data, size_t *length)
{
  if (!inbound_is_owner(inbound) || data == NULL || length == NULL) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  *data = NULL;
  *length = 0;
  if (inbound->output_offset == inbound->output_length) {
    return socks_result(FN_AGAIN, FN_STAGE_NONE);
  }
  *data = inbound->output + inbound->output_offset;
  *length = inbound->output_length - inbound->output_offset;
  return socks_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_inbound_output_consume(fn_socks5_inbound_t *inbound,
                                             size_t length)
{
  size_t remaining;
  if (!inbound_is_owner(inbound) || length == 0) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  remaining = inbound->output_length - inbound->output_offset;
  if (length > remaining) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  inbound->output_offset += length;
  if (inbound->output_offset != inbound->output_length) {
    return socks_result(FN_OK, FN_STAGE_NONE);
  }
  inbound->output_offset = 0;
  inbound->output_length = 0;
  inbound->state = inbound->after_output;
  if (inbound->state == FN_SOCKS5_RELAY) {
    set_terminal(inbound, socks_result(FN_OK, FN_STAGE_NONE));
  }
  parse_workspace(inbound);
  return socks_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_inbound_target(const fn_socks5_inbound_t *inbound,
                                     fn_endpoint_t *out)
{
  if (!inbound_is_owner(inbound) || out == NULL || !inbound->target_ready) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  *out = inbound->target;
  return socks_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_inbound_connect_result(
  fn_socks5_inbound_t *inbound, fn_result_t result,
  const fn_endpoint_t *bound_endpoint)
{
  uint8_t output[FN_SOCKS5_WORKSPACE_SIZE];
  size_t output_length = 0;
  fn_result_t encode_result;
  if (!inbound_is_owner(inbound) ||
      inbound->state != FN_SOCKS5_OUTBOUND_WAIT) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  if (result.code == FN_OK) {
    encode_result = encode_success_reply(output, bound_endpoint,
                                         &output_length);
    if (encode_result.code != FN_OK) {
      return encode_result;
    }
    queue_output(inbound, FN_SOCKS5_CONNECT_REPLY_WRITE,
                 FN_SOCKS5_RELAY, output, output_length);
    return socks_result(FN_OK, FN_STAGE_NONE);
  }
  if (result.code == FN_CANCELLED || result.code == FN_EOF) {
    set_terminal(inbound, result);
    inbound->state = FN_SOCKS5_CLOSED;
    return socks_result(FN_OK, FN_STAGE_NONE);
  }
  queue_failure_reply(inbound, fn_socks5_reply_from_result(result), result);
  return socks_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_inbound_eof(fn_socks5_inbound_t *inbound)
{
  fn_result_t result;
  if (!inbound_is_owner(inbound)) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  if (inbound->state == FN_SOCKS5_CLOSED) {
    return socks_result(FN_OK, FN_STAGE_NONE);
  }
  result = inbound->state == FN_SOCKS5_OUTBOUND_WAIT ?
    socks_result(FN_CANCELLED, FN_STAGE_INBOUND_HANDSHAKE) :
    socks_result(FN_PROTOCOL_ERROR, FN_STAGE_INBOUND_HANDSHAKE);
  set_terminal(inbound, result);
  inbound->output_length = 0;
  inbound->output_offset = 0;
  inbound->state = FN_SOCKS5_CLOSED;
  return socks_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_inbound_check_deadline(fn_socks5_inbound_t *inbound,
                                             uint64_t now_ms)
{
  if (!inbound_is_owner(inbound)) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  if (inbound->state == FN_SOCKS5_CLOSED ||
      inbound->state == FN_SOCKS5_RELAY ||
      now_ms < inbound->deadline_ms) {
    return socks_result(FN_OK, FN_STAGE_NONE);
  }
  set_terminal(inbound,
               socks_result(FN_TIMEOUT, FN_STAGE_INBOUND_HANDSHAKE));
  inbound->output_length = 0;
  inbound->output_offset = 0;
  inbound->state = FN_SOCKS5_CLOSED;
  return socks_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_inbound_cancel(fn_socks5_inbound_t *inbound)
{
  if (!inbound_is_owner(inbound)) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  if (inbound->state == FN_SOCKS5_CLOSED) {
    return socks_result(FN_OK, FN_STAGE_NONE);
  }
  set_terminal(inbound,
               socks_result(FN_CANCELLED, FN_STAGE_INBOUND_HANDSHAKE));
  inbound->output_length = 0;
  inbound->output_offset = 0;
  inbound->state = FN_SOCKS5_CLOSED;
  return socks_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_inbound_preread_peek(
  const fn_socks5_inbound_t *inbound, const uint8_t **data, size_t *length)
{
  if (!inbound_is_owner(inbound) || data == NULL || length == NULL ||
      inbound->state != FN_SOCKS5_RELAY) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  *data = NULL;
  *length = inbound->preread_length - inbound->preread_offset;
  if (*length == 0) {
    return socks_result(FN_AGAIN, FN_STAGE_NONE);
  }
  *data = inbound->preread + inbound->preread_offset;
  return socks_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_inbound_preread_consume(fn_socks5_inbound_t *inbound,
                                              size_t length)
{
  size_t remaining;
  if (!inbound_is_owner(inbound) || inbound->state != FN_SOCKS5_RELAY ||
      length == 0) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  remaining = inbound->preread_length - inbound->preread_offset;
  if (length > remaining) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  inbound->preread_offset += length;
  return socks_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_inbound_snapshot(const fn_socks5_inbound_t *inbound,
                                       fn_socks5_inbound_snapshot_t *out)
{
  if (!inbound_is_owner(inbound) || out == NULL) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  memset(out, 0, sizeof(*out));
  out->state = inbound->state;
  out->terminal_result = inbound->terminal_result;
  out->target = inbound->target;
  out->workspace_bytes = inbound->workspace_length;
  out->output_bytes = inbound->output_length - inbound->output_offset;
  out->preread_bytes = inbound->preread_length - inbound->preread_offset;
  out->selected_method = inbound->selected_method;
  out->authenticated = inbound->authenticated;
  out->target_ready = inbound->target_ready;
  return socks_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_inbound_release(fn_socks5_inbound_t **pointer)
{
  fn_socks5_inbound_t *inbound;
  fn_socks5_inbound_manager_t *manager;
  if (pointer == NULL) {
    return socks_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  inbound = *pointer;
  if (inbound == NULL) {
    return socks_result(FN_OK, FN_STAGE_NONE);
  }
  if (!inbound_is_owner(inbound)) {
    return socks_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  manager = inbound->manager;
  if (inbound->preread != NULL) {
    manager->allocator.deallocate(manager->allocator.context,
                                  inbound->preread);
    (void)fn_budget_release_pair(manager->owned_memory,
                                 inbound->preread_capacity,
                                 manager->buffer_bytes,
                                 inbound->preread_capacity,
                                 FN_BUDGET_ACTIVE);
  }
  manager->active_handshakes--;
  manager->allocator.deallocate(manager->allocator.context, inbound);
  (void)fn_budget_release(manager->owned_memory, FN_BUDGET_ACTIVE,
                          sizeof(*inbound));
  *pointer = NULL;
  return socks_result(FN_OK, FN_STAGE_NONE);
}

static fn_result_t connection_update_watch(fn_socks5_connection_t *connection);
static void connection_advance(fn_socks5_connection_t *connection);
static void connection_destroy(void *state);
static void connection_stream_ready(fn_stream_t *stream, uint32_t events,
                                    void *context);
static const fn_inbound_request_ops_t adapter_ops;

static void handshake_completion(void *context, fn_result_t ignored)
{
  fn_socks5_handshake_t *handshake = context;
  fn_socks5_handshake_callback_fn callback = handshake->callback;
  fn_inbound_request_t *request = handshake->request;
  (void)ignored;
  handshake->request = NULL;
  handshake->callback_started = true;
  callback(handshake, handshake->callback_context,
           handshake->terminal_result, request);
}

static void handshake_finish(fn_socks5_handshake_t *handshake,
                             fn_result_t result,
                             fn_inbound_request_t *request)
{
  if (handshake == NULL || handshake->terminal_queued) {
    return;
  }
  handshake->terminal_result = result;
  handshake->request = request;
  handshake->terminal_queued = true;
  (void)fn_completion_publish(&handshake->ticket, result,
                              handshake_completion, handshake);
}

static void reply_completion(void *context, fn_result_t ignored)
{
  fn_socks5_reply_operation_t *operation = context;
  fn_reply_callback_fn callback = operation->callback;
  (void)ignored;
  operation->callback_started = true;
  callback(&operation->base, operation->terminal_result,
           operation->callback_context);
}

static void reply_finish(fn_socks5_reply_operation_t *operation,
                         fn_result_t result)
{
  if (operation == NULL || operation->terminal_queued) {
    return;
  }
  operation->terminal_result = result;
  operation->terminal_queued = true;
  (void)fn_completion_publish(&operation->ticket, result,
                              reply_completion, operation);
}

static void connection_stop_io(fn_socks5_connection_t *connection)
{
  if (connection->stream != NULL) {
    (void)fn_stream_watch(connection->stream, 0, NULL, NULL);
  }
  if (connection->timer != NULL) {
    (void)fn_timer_destroy(&connection->timer);
  }
}

static void connection_fail(fn_socks5_connection_t *connection,
                            fn_result_t result)
{
  fn_socks5_inbound_snapshot_t snapshot;
  if (connection->parser != NULL &&
      fn_socks5_inbound_snapshot(connection->parser, &snapshot).code ==
        FN_OK && snapshot.terminal_result.code != FN_OK) {
    result = snapshot.terminal_result;
  }
  connection_stop_io(connection);
  if (connection->stream != NULL) {
    (void)fn_stream_abort(connection->stream);
  }
  if (connection->reply_operation != NULL) {
    reply_finish(connection->reply_operation, result);
    return;
  }
  if (connection->handshake != NULL) {
    handshake_finish(connection->handshake, result, NULL);
    return;
  }
  connection->deferred_error = result;
  connection->deferred_error_set = true;
}

static fn_result_t connection_emit_request(
  fn_socks5_connection_t *connection)
{
  fn_socks5_handshake_t *handshake = connection->handshake;
  fn_session_metadata_t metadata;
  fn_endpoint_t target;
  fn_inbound_request_t *request = NULL;
  fn_result_t result;

  result = fn_socks5_inbound_target(connection->parser, &target);
  if (result.code != FN_OK) {
    return result;
  }
  fn_session_metadata_init(&metadata, FN_TCP);
  metadata.route.source = connection->source;
  metadata.route.original_target = target;
  metadata.route.inbound = connection->inbound;
  if (target.address.kind == FN_ADDR_DOMAIN) {
    result = fn_session_metadata_set_domain(
      &metadata, &target.address.value.domain, FN_DOMAIN_REQUEST);
    if (result.code != FN_OK) {
      return result;
    }
  }
  result = fn_inbound_request_create(
    connection->runtime, &metadata, connection->accepted_at_ms,
    &adapter_ops, connection, connection->manager->owned_memory,
    connection->manager->allocator, &request);
  if (result.code != FN_OK) {
    (void)fn_socks5_inbound_connect_result(connection->parser, result, NULL);
    return connection_update_watch(connection);
  }
  (void)fn_runtime_release(&connection->runtime);
  connection->request_transferred = true;
  connection->handshake = NULL;
  handshake->connection = NULL;
  handshake_finish(handshake, socks_result(FN_OK, FN_STAGE_NONE), request);
  return connection_update_watch(connection);
}

static fn_result_t connection_update_watch(fn_socks5_connection_t *connection)
{
  fn_socks5_inbound_snapshot_t snapshot;
  uint32_t interests = 0;
  fn_result_t result;
  if (connection->stream == NULL) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  result = fn_socks5_inbound_snapshot(connection->parser, &snapshot);
  if (result.code != FN_OK) {
    return result;
  }
  if (snapshot.output_bytes != 0) {
    interests = FN_IO_EVENT_WRITE;
  } else if (snapshot.state == FN_SOCKS5_GREETING_READ ||
             snapshot.state == FN_SOCKS5_AUTH_READ ||
             snapshot.state == FN_SOCKS5_REQUEST_READ ||
             (snapshot.state == FN_SOCKS5_OUTBOUND_WAIT &&
              snapshot.preread_bytes < FN_SOCKS5_PREREAD_MAX)) {
    interests = FN_IO_EVENT_READ;
  }
  return fn_stream_watch(connection->stream, interests,
                         interests == 0 ? NULL : connection_stream_ready,
                         interests == 0 ? NULL : connection);
}

static void connection_advance(fn_socks5_connection_t *connection)
{
  fn_socks5_inbound_snapshot_t snapshot;
  fn_result_t result = fn_socks5_inbound_snapshot(connection->parser,
                                                   &snapshot);
  if (result.code != FN_OK) {
    connection_fail(connection, result);
    return;
  }
  if (snapshot.state == FN_SOCKS5_OUTBOUND_WAIT &&
      !connection->request_transferred) {
    result = connection_emit_request(connection);
    if (result.code != FN_OK) {
      connection_fail(connection, result);
    }
    return;
  }
  if (snapshot.state == FN_SOCKS5_RELAY) {
    connection_stop_io(connection);
    reply_finish(connection->reply_operation,
                 socks_result(FN_OK, FN_STAGE_NONE));
    return;
  }
  if (snapshot.state == FN_SOCKS5_CLOSED) {
    connection_stop_io(connection);
    if (connection->reply_operation != NULL) {
      result = connection->reply_operation->outcome.code == FN_OK ?
        snapshot.terminal_result : socks_result(FN_OK, FN_STAGE_NONE);
      reply_finish(connection->reply_operation, result);
    } else if (connection->handshake != NULL) {
      handshake_finish(connection->handshake,
                       snapshot.terminal_result, NULL);
    } else {
      connection->deferred_error = snapshot.terminal_result;
      connection->deferred_error_set = true;
    }
    return;
  }
  result = connection_update_watch(connection);
  if (result.code != FN_OK) {
    connection_fail(connection, result);
  }
}

static void connection_write(fn_socks5_connection_t *connection)
{
  size_t calls;
  for (calls = 0; calls < 32u; calls++) {
    const uint8_t *data;
    size_t length;
    fn_result_t result = fn_socks5_inbound_output_peek(
      connection->parser, &data, &length);
    fn_io_result_t io;
    if (result.code == FN_AGAIN) {
      break;
    }
    if (result.code != FN_OK) {
      connection_fail(connection, result);
      return;
    }
    io = fn_stream_write(connection->stream, data, length);
    if (io.result.code == FN_AGAIN) {
      break;
    }
    if (io.result.code != FN_OK || io.transferred == 0 ||
        io.transferred > length) {
      connection_fail(connection,
                      io.result.code == FN_OK ?
                        socks_result(FN_IO_ERROR,
                                     FN_STAGE_INBOUND_HANDSHAKE) :
                        io.result);
      return;
    }
    result = fn_socks5_inbound_output_consume(connection->parser,
                                               io.transferred);
    if (result.code != FN_OK) {
      connection_fail(connection, result);
      return;
    }
  }
  connection_advance(connection);
}

static void connection_read(fn_socks5_connection_t *connection)
{
  uint8_t buffer[FN_SOCKS5_WORKSPACE_SIZE];
  size_t calls;
  for (calls = 0; calls < 32u; calls++) {
    fn_socks5_inbound_snapshot_t snapshot;
    fn_io_result_t io;
    fn_result_t result;
    size_t capacity;
    size_t consumed;
    result = fn_socks5_inbound_snapshot(connection->parser, &snapshot);
    if (result.code != FN_OK) {
      connection_fail(connection, result);
      return;
    }
    if (snapshot.output_bytes != 0 ||
        snapshot.state == FN_SOCKS5_CLOSED ||
        snapshot.state == FN_SOCKS5_RELAY) {
      break;
    }
    capacity = snapshot.state == FN_SOCKS5_OUTBOUND_WAIT ?
      FN_SOCKS5_PREREAD_MAX - snapshot.preread_bytes :
      FN_SOCKS5_WORKSPACE_SIZE - snapshot.workspace_bytes;
    if (capacity == 0) {
      break;
    }
    if (capacity > sizeof(buffer)) {
      capacity = sizeof(buffer);
    }
    io = fn_stream_read(connection->stream, buffer, capacity);
    if (io.result.code == FN_AGAIN) {
      break;
    }
    if (io.result.code == FN_EOF) {
      (void)fn_socks5_inbound_eof(connection->parser);
      break;
    }
    if (io.result.code != FN_OK || io.transferred == 0 ||
        io.transferred > capacity) {
      connection_fail(connection,
                      io.result.code == FN_OK ?
                        socks_result(FN_IO_ERROR,
                                     FN_STAGE_INBOUND_HANDSHAKE) :
                        io.result);
      return;
    }
    result = fn_socks5_inbound_feed(connection->parser, buffer,
                                    io.transferred, &consumed);
    if (result.code != FN_OK || consumed != io.transferred) {
      connection_fail(connection,
                      result.code == FN_OK ?
                        socks_result(FN_PROTOCOL_ERROR,
                                     FN_STAGE_INBOUND_HANDSHAKE) :
                        result);
      return;
    }
  }
  connection_advance(connection);
}

static void connection_stream_ready(fn_stream_t *stream, uint32_t events,
                                    void *context)
{
  fn_socks5_connection_t *connection = context;
  if (stream != connection->stream) {
    connection_fail(connection,
                    socks_result(FN_INVALID,
                                 FN_STAGE_INBOUND_HANDSHAKE));
    return;
  }
  if ((events & FN_IO_EVENT_ERROR) != 0) {
    connection_fail(connection,
                    socks_result(FN_IO_ERROR,
                                 FN_STAGE_INBOUND_HANDSHAKE));
    return;
  }
  if ((events & FN_IO_EVENT_WRITE) != 0) {
    connection_write(connection);
    return;
  }
  if ((events & FN_IO_EVENT_READ) != 0) {
    connection_read(connection);
  }
}

static void connection_timeout(fn_timer_t *timer, void *context)
{
  fn_socks5_connection_t *connection = context;
  (void)timer;
  (void)fn_timer_destroy(&connection->timer);
  (void)fn_socks5_inbound_check_deadline(connection->parser, UINT64_MAX);
  connection_advance(connection);
}

static fn_result_t reply_cancel(fn_op_t *base)
{
  fn_socks5_reply_operation_t *operation =
    (fn_socks5_reply_operation_t *)base;
  if (operation == NULL || operation->connection == NULL) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  if (operation->callback_started || operation->terminal_queued) {
    return socks_result(FN_OK, FN_STAGE_NONE);
  }
  (void)fn_socks5_inbound_cancel(operation->connection->parser);
  connection_advance(operation->connection);
  return socks_result(FN_OK, FN_STAGE_NONE);
}

static fn_result_t reply_release(fn_op_t **pointer)
{
  fn_socks5_reply_operation_t *operation;
  fn_socks5_connection_t *connection;
  fn_socks5_inbound_manager_t *manager;
  if (pointer == NULL) {
    return socks_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  operation = (fn_socks5_reply_operation_t *)*pointer;
  if (operation == NULL) {
    return socks_result(FN_OK, FN_STAGE_NONE);
  }
  if (!operation->callback_started || operation->ticket != NULL ||
      operation->connection == NULL) {
    return socks_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  connection = operation->connection;
  manager = connection->manager;
  if (connection->reply_operation != operation) {
    return socks_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  connection->reply_operation = NULL;
  manager->allocator.deallocate(manager->allocator.context, operation);
  (void)fn_budget_release(manager->owned_memory, FN_BUDGET_ACTIVE,
                          sizeof(*operation));
  *pointer = NULL;
  return socks_result(FN_OK, FN_STAGE_NONE);
}

static const fn_op_ops_t reply_operation_ops = {
  .cancel = reply_cancel,
  .release = reply_release,
};

static fn_result_t adapter_reply_start(
  void *state, fn_result_t outcome, const fn_endpoint_t *bound_endpoint,
  fn_reply_callback_fn callback, void *context, fn_op_t **out)
{
  fn_socks5_connection_t *connection = state;
  fn_socks5_reply_operation_t *operation;
  fn_socks5_inbound_snapshot_t snapshot;
  fn_completion_ticket_t *ticket = NULL;
  fn_result_t result;
  size_t preread_length;
  if (out == NULL) {
    return socks_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  *out = NULL;
  if (connection == NULL || callback == NULL ||
      connection->reply_operation != NULL ||
      connection->stream == NULL || connection->parser == NULL) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  if (connection->deferred_error_set) {
    return connection->deferred_error;
  }
  result = fn_socks5_inbound_snapshot(connection->parser, &snapshot);
  if (result.code != FN_OK || snapshot.state != FN_SOCKS5_OUTBOUND_WAIT) {
    return result.code == FN_OK ? snapshot.terminal_result : result;
  }
  if (outcome.code == FN_OK &&
      (bound_endpoint == NULL ||
       (bound_endpoint->address.kind != FN_ADDR_V4 &&
        bound_endpoint->address.kind != FN_ADDR_V6 &&
        bound_endpoint->address.kind != FN_ADDR_DOMAIN))) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  result = fn_completion_reserve_terminal(connection->manager->loop,
                                           &ticket);
  if (result.code != FN_OK) {
    return result;
  }
  result = fn_budget_reserve(connection->manager->owned_memory,
                             FN_BUDGET_ACTIVE, sizeof(*operation));
  if (result.code != FN_OK) {
    (void)fn_completion_abandon(&ticket);
    return result;
  }
  operation = connection->manager->allocator.allocate(
    connection->manager->allocator.context, sizeof(*operation));
  if (operation == NULL) {
    (void)fn_budget_release(connection->manager->owned_memory,
                            FN_BUDGET_ACTIVE, sizeof(*operation));
    (void)fn_completion_abandon(&ticket);
    return socks_result(FN_NO_MEMORY, FN_STAGE_RESOURCE);
  }
  memset(operation, 0, sizeof(*operation));
  fn_op_initialize(&operation->base, &reply_operation_ops);
  operation->connection = connection;
  operation->ticket = ticket;
  operation->callback = callback;
  operation->callback_context = context;
  operation->outcome = outcome;

  preread_length = connection->parser->preread_length -
                   connection->parser->preread_offset;
  if (outcome.code == FN_OK && preread_length != 0) {
    if (connection->parser->preread_offset != 0) {
      memmove(connection->parser->preread,
              connection->parser->preread +
                connection->parser->preread_offset,
              preread_length);
    }
    result = fn_stream_adopt_read_buffer(
      connection->stream, &connection->parser->preread,
      preread_length, connection->parser->preread_capacity,
      connection->manager->owned_memory,
      connection->manager->buffer_bytes,
      connection->manager->allocator);
    if (result.code != FN_OK) {
      connection->manager->allocator.deallocate(
        connection->manager->allocator.context, operation);
      (void)fn_budget_release(connection->manager->owned_memory,
                              FN_BUDGET_ACTIVE, sizeof(*operation));
      (void)fn_completion_abandon(&ticket);
      return result;
    }
    connection->parser->preread_length = 0;
    connection->parser->preread_offset = 0;
    connection->parser->preread_capacity = 0;
  }
  result = fn_socks5_inbound_connect_result(
    connection->parser, outcome,
    outcome.code == FN_OK ? bound_endpoint : NULL);
  if (result.code != FN_OK) {
    connection->manager->allocator.deallocate(
      connection->manager->allocator.context, operation);
    (void)fn_budget_release(connection->manager->owned_memory,
                            FN_BUDGET_ACTIVE, sizeof(*operation));
    (void)fn_completion_abandon(&ticket);
    return result;
  }
  connection->reply_operation = operation;
  *out = &operation->base;
  connection_advance(connection);
  return socks_result(FN_OK, FN_STAGE_NONE);
}

static fn_stream_t *adapter_take_stream(void *state)
{
  fn_socks5_connection_t *connection = state;
  fn_socks5_inbound_snapshot_t snapshot;
  fn_stream_t *stream;
  if (connection == NULL || connection->reply_operation != NULL ||
      connection->stream == NULL ||
      fn_socks5_inbound_snapshot(connection->parser, &snapshot).code !=
        FN_OK || snapshot.state != FN_SOCKS5_RELAY) {
    return NULL;
  }
  connection_stop_io(connection);
  stream = connection->stream;
  connection->stream = NULL;
  return stream;
}

static const fn_inbound_request_ops_t adapter_ops = {
  .reply_start = adapter_reply_start,
  .take_stream = adapter_take_stream,
  .destroy = connection_destroy,
};

static void connection_destroy(void *state)
{
  fn_socks5_connection_t *connection = state;
  fn_socks5_inbound_manager_t *manager;
  if (connection == NULL) {
    return;
  }
  manager = connection->manager;
  connection_stop_io(connection);
  if (connection->stream != NULL) {
    (void)fn_stream_abort(connection->stream);
    (void)fn_stream_release(&connection->stream);
  }
  if (connection->runtime != NULL) {
    (void)fn_runtime_release(&connection->runtime);
  }
  if (connection->parser != NULL) {
    (void)fn_socks5_inbound_release(&connection->parser);
  }
  manager->allocator.deallocate(manager->allocator.context, connection);
  (void)fn_budget_release(manager->owned_memory, FN_BUDGET_ACTIVE,
                          sizeof(*connection));
}

fn_result_t fn_socks5_handshake_start(
  fn_socks5_inbound_manager_t *manager, fn_runtime_t *runtime,
  fn_stream_t **accepted_stream, const fn_endpoint_t *source,
  fn_object_ref_t inbound, uint64_t accepted_at_ms, uint64_t deadline_ms,
  fn_socks5_handshake_callback_fn callback, void *context,
  fn_socks5_handshake_t **out)
{
  fn_socks5_handshake_t *handshake = NULL;
  fn_socks5_connection_t *connection = NULL;
  fn_completion_ticket_t *ticket = NULL;
  fn_result_t result;
  if (out == NULL) {
    return socks_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  *out = NULL;
  if (!manager_is_owner(manager) || runtime == NULL ||
      accepted_stream == NULL || *accepted_stream == NULL ||
      source == NULL || source->address.kind == FN_ADDR_NONE ||
      callback == NULL) {
    return socks_result(FN_INVALID, FN_STAGE_ACCEPT);
  }
  result = fn_completion_reserve_terminal(manager->loop, &ticket);
  if (result.code != FN_OK) {
    return result;
  }
  result = fn_budget_reserve(manager->owned_memory, FN_BUDGET_ACTIVE,
                             sizeof(*handshake) + sizeof(*connection));
  if (result.code != FN_OK) {
    (void)fn_completion_abandon(&ticket);
    return result;
  }
  handshake = manager->allocator.allocate(manager->allocator.context,
                                           sizeof(*handshake));
  connection = manager->allocator.allocate(manager->allocator.context,
                                            sizeof(*connection));
  if (handshake == NULL || connection == NULL) {
    if (connection != NULL) {
      manager->allocator.deallocate(manager->allocator.context, connection);
    }
    if (handshake != NULL) {
      manager->allocator.deallocate(manager->allocator.context, handshake);
    }
    (void)fn_budget_release(manager->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*handshake) + sizeof(*connection));
    (void)fn_completion_abandon(&ticket);
    return socks_result(FN_NO_MEMORY, FN_STAGE_RESOURCE);
  }
  memset(handshake, 0, sizeof(*handshake));
  memset(connection, 0, sizeof(*connection));
  handshake->manager = manager;
  handshake->connection = connection;
  handshake->ticket = ticket;
  handshake->callback = callback;
  handshake->callback_context = context;
  connection->manager = manager;
  connection->handshake = handshake;
  connection->stream = *accepted_stream;
  connection->source = *source;
  connection->inbound = inbound;
  connection->accepted_at_ms = accepted_at_ms;
  result = fn_socks5_inbound_open(manager, deadline_ms,
                                  &connection->parser);
  if (result.code == FN_OK) {
    result = fn_runtime_retain(runtime);
    if (result.code == FN_OK) {
      connection->runtime = runtime;
    }
  }
  if (result.code == FN_OK) {
    result = fn_timer_start(manager->loop, deadline_ms, connection_timeout,
                            connection, &connection->timer);
  }
  if (result.code == FN_OK) {
    result = connection_update_watch(connection);
  }
  if (result.code != FN_OK) {
    connection_stop_io(connection);
    connection->stream = NULL;
    connection_destroy(connection);
    manager->allocator.deallocate(manager->allocator.context, handshake);
    (void)fn_budget_release(manager->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*handshake));
    (void)fn_completion_abandon(&ticket);
    return result;
  }
  *accepted_stream = NULL;
  *out = handshake;
  return socks_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_handshake_cancel(fn_socks5_handshake_t *handshake)
{
  if (handshake == NULL || !manager_is_owner(handshake->manager)) {
    return socks_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  if (handshake->callback_started || handshake->terminal_queued) {
    return socks_result(FN_OK, FN_STAGE_NONE);
  }
  if (handshake->connection != NULL) {
    (void)fn_socks5_inbound_cancel(handshake->connection->parser);
    connection_stop_io(handshake->connection);
    if (handshake->connection->stream != NULL) {
      (void)fn_stream_abort(handshake->connection->stream);
    }
  }
  handshake_finish(
    handshake, socks_result(FN_CANCELLED, FN_STAGE_INBOUND_HANDSHAKE), NULL);
  return socks_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_socks5_handshake_release(fn_socks5_handshake_t **pointer)
{
  fn_socks5_handshake_t *handshake;
  fn_socks5_inbound_manager_t *manager;
  if (pointer == NULL) {
    return socks_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  handshake = *pointer;
  if (handshake == NULL) {
    return socks_result(FN_OK, FN_STAGE_NONE);
  }
  if (!manager_is_owner(handshake->manager) ||
      !handshake->callback_started || handshake->ticket != NULL ||
      handshake->request != NULL) {
    return socks_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  manager = handshake->manager;
  if (handshake->connection != NULL) {
    connection_destroy(handshake->connection);
  }
  manager->allocator.deallocate(manager->allocator.context, handshake);
  (void)fn_budget_release(manager->owned_memory, FN_BUDGET_ACTIVE,
                          sizeof(*handshake));
  *pointer = NULL;
  return socks_result(FN_OK, FN_STAGE_NONE);
}
