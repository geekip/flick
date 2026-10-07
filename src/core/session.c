#include "flicknet/session.h"

#include "flicknet/clock.h"

#include <string.h>

struct fn_session_manager {
  fn_loop_t *loop;
  fn_limits_t limits;
  fn_budget_t *owned_memory;
  fn_allocator_t allocator;
  fn_direct_connector_t *direct_connector;
  fn_socks5_outbound_manager_t *socks5_outbound_manager;
  fn_resolver_t *resolver;
  fn_relay_buffer_pool_t *relay_pool;
  uint64_t next_session_id;
  size_t active_sessions;
  bool id_exhausted;
};

struct fn_inbound_request {
  fn_runtime_t *runtime;
  fn_session_metadata_t metadata;
  const fn_inbound_request_ops_t *ops;
  void *adapter_state;
  fn_budget_t *owned_memory;
  fn_allocator_t allocator;
  uint64_t accepted_at_ms;
};

struct fn_session {
  fn_session_manager_t *manager;
  fn_runtime_t *runtime;
  fn_stream_t *inbound;
  fn_stream_t *outbound;
  fn_resolver_operation_t *resolve_operation;
  fn_direct_connect_t *connect_operation;
  fn_socks5_outbound_t *socks5_operation;
  fn_op_t *reply_operation;
  fn_relay_t *relay;
  fn_completion_ticket_t *ticket;
  fn_session_callback_fn callback;
  void *callback_context;
  fn_session_metadata_t metadata;
  fn_session_snapshot_t snapshot;
  const fn_inbound_request_ops_t *inbound_ops;
  void *inbound_state;
  fn_result_t reply_outcome;
  uint64_t deadline_ms;
  bool terminal_set;
  bool terminal_queued;
  bool callback_started;
};

static fn_result_t session_result(fn_status_t code, fn_error_stage_t stage)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE : stage,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static bool manager_is_owner(const fn_session_manager_t *manager)
{
  return manager != NULL && fn_loop_is_owner(manager->loop);
}

static bool session_is_owner(const fn_session_t *session)
{
  return session != NULL && manager_is_owner(session->manager);
}

static void session_set_terminal(fn_session_t *session, fn_result_t result)
{
  if (!session->terminal_set) {
    session->snapshot.terminal_result = result;
    session->terminal_set = true;
  }
}

static void session_completion(void *context, fn_result_t result)
{
  fn_session_t *session = context;
  fn_session_callback_fn callback = session->callback;
  void *callback_context = session->callback_context;
  (void)result;
  session->callback_started = true;
  callback(session, callback_context, &session->snapshot);
}

static void session_publish_terminal(fn_session_t *session)
{
  if (session->terminal_queued || session->resolve_operation != NULL ||
      session->connect_operation != NULL ||
      session->socks5_operation != NULL ||
      session->reply_operation != NULL || session->relay != NULL) {
    return;
  }
  if (!session->terminal_set) {
    session_set_terminal(session,
                         session_result(FN_OK, FN_STAGE_NONE));
  }
  session->snapshot.state = FN_SESSION_CLOSING;
  if (session->inbound != NULL) {
    (void)fn_stream_abort(session->inbound);
    (void)fn_stream_release(&session->inbound);
  }
  if (session->outbound != NULL) {
    (void)fn_stream_abort(session->outbound);
    (void)fn_stream_release(&session->outbound);
  }
  if (session->inbound_state != NULL) {
    session->inbound_ops->destroy(session->inbound_state);
    session->inbound_state = NULL;
    session->inbound_ops = NULL;
  }
  if (session->runtime != NULL) {
    (void)fn_runtime_release(&session->runtime);
  }
  session->snapshot.state = FN_SESSION_CLOSED;
  session->terminal_queued = true;
  (void)fn_completion_publish(&session->ticket,
                              session->snapshot.terminal_result,
                              session_completion, session);
}

static void session_close_internal(fn_session_t *session, fn_result_t result)
{
  session_set_terminal(session, result);
  session->snapshot.state = FN_SESSION_CLOSING;
  session_publish_terminal(session);
}

static void session_relay_done(fn_relay_t *relay, void *context,
                               fn_result_t result)
{
  fn_session_t *session = context;
  fn_relay_snapshot_t relay_snapshot;
  if (fn_relay_snapshot(relay, &relay_snapshot).code == FN_OK) {
    session->snapshot.bytes_up = relay_snapshot.bytes_left_to_right;
    session->snapshot.bytes_down = relay_snapshot.bytes_right_to_left;
  }
  (void)fn_relay_release(&session->relay);
  session_close_internal(session, result);
}

static void session_start_relay(fn_session_t *session)
{
  fn_relay_options_t options = fn_relay_options_default();
  fn_result_t result;
  result = fn_relay_start(session->manager->relay_pool,
                          session->inbound, session->outbound,
                          &options, session_relay_done, session,
                          &session->relay);
  if (result.code != FN_OK) {
    session_close_internal(session, result);
    return;
  }
  session->snapshot.state = FN_SESSION_RELAYING;
}

static void session_reply_done(fn_op_t *operation, fn_result_t result,
                               void *context)
{
  fn_session_t *session = context;
  fn_result_t outcome = session->reply_outcome;
  fn_stream_t *stream = NULL;
  if (session->reply_operation != operation) {
    session_close_internal(
      session, session_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE));
    return;
  }
  (void)fn_op_release(&session->reply_operation);
  if (result.code == FN_OK && outcome.code == FN_OK) {
    stream = session->inbound_ops->take_stream(session->inbound_state);
  }
  session->inbound_ops->destroy(session->inbound_state);
  session->inbound_state = NULL;
  session->inbound_ops = NULL;
  if (outcome.code != FN_OK) {
    session_close_internal(session, outcome);
    return;
  }
  if (result.code != FN_OK) {
    session_close_internal(session, result);
    return;
  }
  if (stream == NULL) {
    session_close_internal(
      session, session_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE));
    return;
  }
  session->inbound = stream;
  session_start_relay(session);
}

static void session_begin_reply(fn_session_t *session, fn_result_t outcome,
                                const fn_endpoint_t *bound_endpoint)
{
  fn_result_t result;
  if (session->terminal_set) {
    outcome = session->snapshot.terminal_result;
    bound_endpoint = NULL;
  }
  if (session->inbound_ops == NULL) {
    if (outcome.code == FN_OK) {
      session_start_relay(session);
    } else {
      session_close_internal(session, outcome);
    }
    return;
  }
  session->snapshot.state = FN_SESSION_REPLYING;
  session->reply_outcome = outcome;
  result = session->inbound_ops->reply_start(
    session->inbound_state, outcome, bound_endpoint,
    session_reply_done, session, &session->reply_operation);
  if (result.code != FN_OK) {
    session->inbound_ops->destroy(session->inbound_state);
    session->inbound_state = NULL;
    session->inbound_ops = NULL;
    session_close_internal(session,
                           outcome.code == FN_OK ? result : outcome);
  }
}

static void session_outbound_ready(
  fn_session_t *session, fn_result_t result,
  fn_stream_t *owned_stream, const fn_endpoint_t *bound_endpoint,
  const fn_endpoint_t *connected_endpoint)
{
  fn_endpoint_t bound_copy;
  fn_endpoint_t connected_copy;
  bool has_endpoints = false;
  if (result.code == FN_OK && bound_endpoint != NULL &&
      connected_endpoint != NULL) {
    bound_copy = *bound_endpoint;
    connected_copy = *connected_endpoint;
    has_endpoints = true;
  }
  if (result.code != FN_OK) {
    if (owned_stream != NULL) {
      (void)fn_stream_abort(owned_stream);
      (void)fn_stream_release(&owned_stream);
    }
    session_begin_reply(session, result, NULL);
    return;
  }
  if (owned_stream == NULL || !has_endpoints ||
      session->snapshot.state == FN_SESSION_CLOSING) {
    if (owned_stream != NULL) {
      (void)fn_stream_abort(owned_stream);
      (void)fn_stream_release(&owned_stream);
    }
    session_begin_reply(
      session, session_result(FN_CANCELLED, FN_STAGE_TCP_CONNECT), NULL);
    return;
  }
  session->outbound = owned_stream;
  session->snapshot.bound_endpoint = bound_copy;
  session->snapshot.connected_endpoint = connected_copy;
  session_begin_reply(session, session_result(FN_OK, FN_STAGE_NONE),
                      &bound_copy);
}

static void session_connected(
  fn_direct_connect_t *operation, void *context, fn_result_t result,
  fn_stream_t *owned_stream, const fn_endpoint_t *bound_endpoint,
  const fn_endpoint_t *connected_endpoint)
{
  fn_session_t *session = context;
  fn_endpoint_t bound_copy;
  fn_endpoint_t connected_copy;
  const fn_endpoint_t *bound = NULL;
  const fn_endpoint_t *connected = NULL;
  (void)operation;
  if (bound_endpoint != NULL && connected_endpoint != NULL) {
    bound_copy = *bound_endpoint;
    connected_copy = *connected_endpoint;
    bound = &bound_copy;
    connected = &connected_copy;
  }
  (void)fn_direct_connect_release(&session->connect_operation);
  session_outbound_ready(session, result, owned_stream, bound, connected);
}

static void session_socks5_connected(
  fn_socks5_outbound_t *operation, void *context, fn_result_t result,
  fn_stream_t *owned_stream, const fn_endpoint_t *bound_endpoint,
  const fn_endpoint_t *connected_endpoint)
{
  fn_session_t *session = context;
  fn_endpoint_t bound_copy;
  fn_endpoint_t connected_copy;
  const fn_endpoint_t *bound = NULL;
  const fn_endpoint_t *connected = NULL;
  (void)operation;
  if (bound_endpoint != NULL && connected_endpoint != NULL) {
    bound_copy = *bound_endpoint;
    connected_copy = *connected_endpoint;
    bound = &bound_copy;
    connected = &connected_copy;
  }
  (void)fn_socks5_outbound_release(&session->socks5_operation);
  session_outbound_ready(session, result, owned_stream, bound, connected);
}

static void session_route(fn_session_t *session);

static void session_resolved(fn_resolver_operation_t *operation,
                             void *context, fn_result_t result,
                             const fn_resolved_t *resolved)
{
  fn_session_t *session = context;
  bool has_resolved = result.code == FN_OK && resolved != NULL &&
                      resolved->count != 0;
  (void)operation;
  if (has_resolved) {
    session->metadata.dial.resolved = *resolved;
  }
  (void)fn_resolver_operation_release(&session->resolve_operation);
  if (result.code != FN_OK) {
    session_begin_reply(session, result, NULL);
    return;
  }
  if (!has_resolved || session->snapshot.state == FN_SESSION_CLOSING) {
    session_begin_reply(
      session, session_result(FN_CANCELLED, FN_STAGE_RESOLVE), NULL);
    return;
  }
  session_route(session);
}

static void session_route(fn_session_t *session)
{
  fn_route_result_t route;
  const fn_runtime_resource_descriptor_t *outbound;
  fn_result_t result;
  const fn_resolved_t *resolved = NULL;
  session->snapshot.state = FN_SESSION_ROUTING;
  result = fn_route_evaluate(session->runtime, &session->metadata, &route);
  if (result.code != FN_OK) {
    session_begin_reply(session, result, NULL);
    return;
  }
  if (route.status == FN_ROUTE_DENY) {
    session_begin_reply(session, route.denial, NULL);
    return;
  }
  if (route.status == FN_ROUTE_NEED_RESOLVE) {
    const fn_domain_t *question = &session->metadata.route.domain;
    if (session->manager->resolver == NULL || question->length == 0) {
      session_begin_reply(
        session, session_result(FN_INVALID, FN_STAGE_RESOLVE), NULL);
      return;
    }
    session->snapshot.state = FN_SESSION_RESOLVING;
    result = fn_resolver_acquire(
      session->manager->resolver, question, FN_RESOLVER_PURPOSE_DIRECT,
      session->deadline_ms, session_resolved, session,
      &session->resolve_operation);
    if (result.code != FN_OK) {
      session_begin_reply(session, result, NULL);
    }
    return;
  }
  if (route.status != FN_ROUTE_READY) {
    session_begin_reply(
      session, session_result(FN_INVALID, FN_STAGE_ROUTE), NULL);
    return;
  }
  result = fn_runtime_object_get(session->runtime, route.outbound,
                                 &outbound);
  if (result.code != FN_OK) {
    session_begin_reply(session, result, NULL);
    return;
  }
  if (outbound->kind == FN_RUNTIME_RESOURCE_SOCKS_PROXY) {
    if (session->manager->socks5_outbound_manager == NULL) {
      session_begin_reply(
        session, session_result(FN_INVALID, FN_STAGE_SOCKS_CONNECT), NULL);
      return;
    }
    session->snapshot.state = FN_SESSION_CONNECTING;
    result = fn_socks5_outbound_start(
      session->manager->socks5_outbound_manager, &outbound->endpoint,
      outbound->has_credentials, &outbound->credentials,
      &route.dial_target, session->deadline_ms, session_socks5_connected,
      session, &session->socks5_operation);
    if (result.code != FN_OK) {
      session_begin_reply(session, result, NULL);
    }
    return;
  }
  if (outbound->kind != FN_RUNTIME_RESOURCE_DIRECT) {
    session_begin_reply(
      session, session_result(FN_INVALID, FN_STAGE_ROUTE), NULL);
    return;
  }
  if (session->metadata.route.original_target.address.kind == FN_ADDR_DOMAIN) {
    resolved = &session->metadata.dial.resolved;
  }
  session->snapshot.state = FN_SESSION_CONNECTING;
  result = fn_direct_connect_start(
    session->manager->direct_connector,
    &session->metadata.route.original_target, resolved,
    route.candidate_mask, session->deadline_ms, session_connected, session,
    &session->connect_operation);
  if (result.code != FN_OK) {
    session_begin_reply(session, result, NULL);
  }
}

fn_result_t fn_session_manager_create(
  const fn_session_manager_options_t *options,
  fn_session_manager_t **out)
{
  fn_session_manager_t *manager;
  fn_result_t result;
  if (out == NULL) {
    return session_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  *out = NULL;
  if (options == NULL || options->loop == NULL || options->limits == NULL ||
      options->owned_memory == NULL || options->direct_connector == NULL ||
      options->relay_pool == NULL || options->allocator.allocate == NULL ||
      options->allocator.deallocate == NULL ||
      !fn_loop_is_owner(options->loop)) {
    return session_result(FN_INVALID, FN_STAGE_RESOURCE);
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
    return session_result(FN_NO_MEMORY, FN_STAGE_RESOURCE);
  }
  memset(manager, 0, sizeof(*manager));
  manager->loop = options->loop;
  manager->limits = *options->limits;
  manager->owned_memory = options->owned_memory;
  manager->allocator = options->allocator;
  manager->direct_connector = options->direct_connector;
  manager->socks5_outbound_manager = options->socks5_outbound_manager;
  manager->resolver = options->resolver;
  manager->relay_pool = options->relay_pool;
  manager->next_session_id = UINT64_C(1);
  *out = manager;
  return session_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_session_manager_destroy(fn_session_manager_t **pointer)
{
  fn_session_manager_t *manager;
  fn_allocator_t allocator;
  fn_budget_t *owned_memory;
  if (pointer == NULL) {
    return session_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  manager = *pointer;
  if (manager == NULL) {
    return session_result(FN_OK, FN_STAGE_NONE);
  }
  if (!manager_is_owner(manager) || manager->active_sessions != 0) {
    return session_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  allocator = manager->allocator;
  owned_memory = manager->owned_memory;
  allocator.deallocate(allocator.context, manager);
  (void)fn_budget_release(owned_memory, FN_BUDGET_ACTIVE, sizeof(*manager));
  *pointer = NULL;
  return session_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_session_manager_snapshot(
  const fn_session_manager_t *manager, fn_session_manager_snapshot_t *out)
{
  if (!manager_is_owner(manager) || out == NULL) {
    return session_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  memset(out, 0, sizeof(*out));
  out->active_sessions = manager->active_sessions;
  if (!fn_size_multiply(manager->active_sessions, sizeof(fn_session_t),
                        &out->owned_session_bytes)) {
    return session_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  out->next_session_id = manager->next_session_id;
  out->id_exhausted = manager->id_exhausted;
  return session_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_inbound_request_create(
  fn_runtime_t *runtime, const fn_session_metadata_t *metadata,
  uint64_t accepted_at_ms, const fn_inbound_request_ops_t *static_ops,
  void *adapter_state, fn_budget_t *owned_memory, fn_allocator_t allocator,
  fn_inbound_request_t **out)
{
  fn_inbound_request_t *request;
  fn_result_t result;
  if (out == NULL) {
    return session_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  *out = NULL;
  if (runtime == NULL || metadata == NULL ||
      metadata->route.network != FN_TCP || static_ops == NULL ||
      static_ops->reply_start == NULL || static_ops->take_stream == NULL ||
      static_ops->destroy == NULL || adapter_state == NULL ||
      owned_memory == NULL || allocator.allocate == NULL ||
      allocator.deallocate == NULL) {
    return session_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  result = fn_budget_reserve(owned_memory, FN_BUDGET_ACTIVE,
                             sizeof(*request));
  if (result.code != FN_OK) {
    return result;
  }
  request = allocator.allocate(allocator.context, sizeof(*request));
  if (request == NULL) {
    (void)fn_budget_release(owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*request));
    return session_result(FN_NO_MEMORY, FN_STAGE_RESOURCE);
  }
  memset(request, 0, sizeof(*request));
  result = fn_runtime_retain(runtime);
  if (result.code != FN_OK) {
    allocator.deallocate(allocator.context, request);
    (void)fn_budget_release(owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*request));
    return result;
  }
  request->runtime = runtime;
  request->metadata = *metadata;
  request->accepted_at_ms = accepted_at_ms;
  request->ops = static_ops;
  request->adapter_state = adapter_state;
  request->owned_memory = owned_memory;
  request->allocator = allocator;
  *out = request;
  return session_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_inbound_request_release(fn_inbound_request_t **pointer)
{
  fn_inbound_request_t *request;
  fn_budget_t *owned_memory;
  fn_allocator_t allocator;
  fn_result_t result;
  if (pointer == NULL) {
    return session_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  request = *pointer;
  if (request == NULL) {
    return session_result(FN_OK, FN_STAGE_NONE);
  }
  result = fn_runtime_release(&request->runtime);
  if (result.code != FN_OK) {
    return result;
  }
  request->ops->destroy(request->adapter_state);
  request->adapter_state = NULL;
  owned_memory = request->owned_memory;
  allocator = request->allocator;
  allocator.deallocate(allocator.context, request);
  (void)fn_budget_release(owned_memory, FN_BUDGET_ACTIVE, sizeof(*request));
  *pointer = NULL;
  return session_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_inbound_request_reply_start(
  fn_inbound_request_t *request, fn_result_t outcome,
  fn_reply_callback_fn callback, void *context, fn_op_t **out_operation)
{
  if (out_operation == NULL) {
    return session_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  *out_operation = NULL;
  if (request == NULL || request->ops == NULL ||
      request->adapter_state == NULL || callback == NULL ||
      outcome.code == FN_OK || outcome.code == FN_AGAIN ||
      outcome.code == FN_EOF) {
    return session_result(FN_INVALID, FN_STAGE_INBOUND_HANDSHAKE);
  }
  return request->ops->reply_start(request->adapter_state, outcome, NULL,
                                   callback, context, out_operation);
}

static fn_result_t session_allocate(fn_session_manager_t *manager,
                                    fn_runtime_t *runtime,
                                    const fn_session_metadata_t *metadata,
                                    uint64_t created_at_ms,
                                    uint64_t deadline_ms,
                                    fn_session_callback_fn callback,
                                    void *context, fn_session_t **out)
{
  fn_session_t *session;
  fn_result_t result;
  result = fn_budget_reserve(manager->owned_memory, FN_BUDGET_ACTIVE,
                             sizeof(*session));
  if (result.code != FN_OK) {
    return result;
  }
  session = manager->allocator.allocate(manager->allocator.context,
                                         sizeof(*session));
  if (session == NULL) {
    (void)fn_budget_release(manager->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*session));
    return session_result(FN_NO_MEMORY, FN_STAGE_RESOURCE);
  }
  memset(session, 0, sizeof(*session));
  session->manager = manager;
  session->runtime = runtime;
  session->callback = callback;
  session->callback_context = context;
  session->metadata = *metadata;
  session->deadline_ms = deadline_ms;
  session->snapshot.session_id = manager->next_session_id;
  session->snapshot.runtime_generation = fn_runtime_generation(runtime);
  session->snapshot.state = FN_SESSION_ACCEPTED;
  session->snapshot.created_at_ms = created_at_ms;
  result = fn_completion_reserve_terminal(manager->loop, &session->ticket);
  if (result.code != FN_OK) {
    manager->allocator.deallocate(manager->allocator.context, session);
    (void)fn_budget_release(manager->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*session));
    return result;
  }
  manager->active_sessions++;
  if (manager->next_session_id == UINT64_MAX) {
    manager->id_exhausted = true;
  } else {
    manager->next_session_id++;
  }
  *out = session;
  return session_result(FN_OK, FN_STAGE_NONE);
}

static fn_result_t session_admit(fn_session_manager_t *manager,
                                 uint64_t deadline_ms, uint64_t *now_ms)
{
  fn_result_t result;
  if (!manager_is_owner(manager) || now_ms == NULL) {
    return session_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  result = fn_monotonic_now_ms(now_ms);
  if (result.code != FN_OK) {
    return result;
  }
  if (manager->active_sessions >= manager->limits.session_limit ||
      manager->active_sessions >= manager->limits.async_operation_limit ||
      manager->id_exhausted) {
    return session_result(FN_LIMIT, FN_STAGE_RESOURCE);
  }
  if (deadline_ms <= *now_ms) {
    return session_result(FN_TIMEOUT, FN_STAGE_TCP_CONNECT);
  }
  return session_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_session_submit(fn_session_manager_t *manager,
                              fn_inbound_request_t **request_pointer,
                              uint64_t deadline_ms,
                              fn_session_callback_fn callback,
                              void *context, fn_session_t **out)
{
  fn_inbound_request_t *request;
  fn_session_t *session;
  fn_budget_t *request_memory;
  fn_allocator_t request_allocator;
  fn_result_t result;
  uint64_t now_ms;
  if (out == NULL) {
    return session_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  *out = NULL;
  if (request_pointer == NULL || *request_pointer == NULL ||
      callback == NULL) {
    return session_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  request = *request_pointer;
  result = session_admit(manager, deadline_ms, &now_ms);
  if (result.code != FN_OK) {
    return result;
  }
  result = session_allocate(manager, request->runtime, &request->metadata,
                            request->accepted_at_ms, deadline_ms,
                            callback, context, &session);
  if (result.code != FN_OK) {
    return result;
  }
  session->inbound_ops = request->ops;
  session->inbound_state = request->adapter_state;
  request->runtime = NULL;
  request->adapter_state = NULL;
  request_memory = request->owned_memory;
  request_allocator = request->allocator;
  request_allocator.deallocate(request_allocator.context, request);
  (void)fn_budget_release(request_memory, FN_BUDGET_ACTIVE,
                          sizeof(*request));
  *request_pointer = NULL;
  *out = session;
  session_route(session);
  return session_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_session_start(fn_session_manager_t *manager,
                             fn_runtime_t *runtime,
                             fn_stream_t **inbound,
                             const fn_session_metadata_t *metadata,
                             uint64_t deadline_ms,
                             fn_session_callback_fn callback,
                             void *context, fn_session_t **out)
{
  fn_session_t *session;
  fn_result_t result;
  uint64_t now_ms;
  if (out == NULL) {
    return session_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  *out = NULL;
  if (!manager_is_owner(manager) || runtime == NULL || inbound == NULL ||
      *inbound == NULL || metadata == NULL || callback == NULL ||
      metadata->route.network != FN_TCP) {
    return session_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  result = session_admit(manager, deadline_ms, &now_ms);
  if (result.code != FN_OK) {
    return result;
  }
  result = fn_runtime_retain(runtime);
  if (result.code != FN_OK) {
    return result;
  }
  result = session_allocate(manager, runtime, metadata, now_ms, deadline_ms,
                            callback, context, &session);
  if (result.code != FN_OK) {
    fn_runtime_t *retained_runtime = runtime;
    (void)fn_runtime_release(&retained_runtime);
    return result;
  }
  session->inbound = *inbound;
  *inbound = NULL;
  *out = session;
  session_route(session);
  return session_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_session_close(fn_session_t *session, fn_result_t reason)
{
  if (!session_is_owner(session) || session->callback_started ||
      reason.code == FN_AGAIN || reason.code == FN_EOF) {
    return session_result(FN_INVALID, FN_STAGE_SHUTDOWN);
  }
  session_set_terminal(session, reason);
  session->snapshot.state = FN_SESSION_CLOSING;
  if (session->resolve_operation != NULL) {
    (void)fn_resolver_operation_cancel(session->resolve_operation);
  }
  if (session->connect_operation != NULL) {
    (void)fn_direct_connect_cancel(session->connect_operation);
  }
  if (session->socks5_operation != NULL) {
    (void)fn_socks5_outbound_cancel(session->socks5_operation);
  }
  if (session->reply_operation != NULL) {
    (void)fn_op_cancel(session->reply_operation);
  }
  if (session->relay != NULL) {
    (void)fn_relay_cancel(session->relay);
  }
  session_publish_terminal(session);
  return session_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_session_snapshot(const fn_session_t *session,
                                fn_session_snapshot_t *out)
{
  if (!session_is_owner(session) || out == NULL) {
    return session_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  *out = session->snapshot;
  return session_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_session_release(fn_session_t **pointer)
{
  fn_session_t *session;
  fn_session_manager_t *manager;
  if (pointer == NULL) {
    return session_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  session = *pointer;
  if (session == NULL) {
    return session_result(FN_OK, FN_STAGE_NONE);
  }
  if (!session_is_owner(session) || !session->callback_started ||
      session->ticket != NULL || session->runtime != NULL ||
      session->inbound != NULL || session->outbound != NULL ||
      session->resolve_operation != NULL ||
      session->connect_operation != NULL ||
      session->socks5_operation != NULL ||
      session->reply_operation != NULL || session->relay != NULL ||
      session->inbound_state != NULL) {
    return session_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  manager = session->manager;
  manager->active_sessions--;
  manager->allocator.deallocate(manager->allocator.context, session);
  (void)fn_budget_release(manager->owned_memory, FN_BUDGET_ACTIVE,
                          sizeof(*session));
  *pointer = NULL;
  return session_result(FN_OK, FN_STAGE_NONE);
}
