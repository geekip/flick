#include "resolver_internal.h"

#include "flicknet/clock.h"

#include <limits.h>
#include <string.h>

#define FN_DNS_UPSTREAM_MAX 16u
#define FN_DNS_SEND_HISTORY_MAX 4u

typedef struct fn_resolver_transaction fn_resolver_transaction_t;
typedef struct fn_resolver_cache_entry fn_resolver_cache_entry_t;

typedef struct {
  fn_domain_t question;
  size_t upstream_index;
  fn_dns_transport_t transport;
} fn_dns_send_history_t;

struct fn_resolver_operation {
  fn_resolver_t *resolver;
  fn_resolver_transaction_t *transaction;
  fn_resolver_operation_t *next;
  fn_completion_ticket_t *ticket;
  fn_timer_t *timer;
  fn_resolver_callback_fn callback;
  void *callback_context;
  fn_result_t terminal_result;
  fn_resolved_t resolved;
  bool has_resolved;
  bool terminal_queued;
  bool callback_started;
  bool cancel_requested;
};

struct fn_resolver_transaction {
  fn_resolver_t *resolver;
  fn_resolver_transaction_t *next;
  fn_resolver_operation_t *waiters;
  fn_dns_transport_operation_t *attempt;
  fn_domain_t original_question;
  fn_domain_t current_question;
  fn_domain_t cname_visited[FN_DNS_CNAME_HOPS_MAX + 1u];
  fn_dns_send_history_t history[FN_DNS_SEND_HISTORY_MAX];
  fn_dns_query_t query;
  fn_result_t last_result;
  fn_resolver_purpose_t purpose;
  uint64_t policy_deadline_ms;
  uint64_t attempt_deadline_ms;
  uint32_t cname_ttl_seconds;
  size_t waiter_count;
  size_t cname_visited_count;
  size_t cname_hops_total;
  size_t history_count;
  size_t next_upstream;
  size_t active_upstream;
  size_t attempts_used;
  uint32_t incompatible_mask;
  bool has_cname_ttl;
  bool last_cacheable;
  bool force_tcp;
  bool linked;
};

struct fn_resolver_cache_entry {
  fn_resolver_cache_entry_t *next;
  fn_domain_t question;
  fn_result_t result;
  fn_resolver_purpose_t purpose;
  uint64_t generation;
  uint64_t expires_ms;
  uint64_t used_at_ms;
};

struct fn_resolver {
  fn_loop_t *loop;
  fn_limits_t limits;
  fn_budget_t *owned_memory;
  fn_budget_t *file_descriptors;
  fn_allocator_t allocator;
  fn_dns_config_t config;
  fn_dns_transport_ops_t transport;
  fn_resolver_transaction_t *transactions;
  fn_resolver_cache_entry_t *cache;
  uint64_t generation;
  size_t pending;
  size_t waiters;
  size_t live_operations;
  size_t cache_count;
  size_t cache_hits;
  size_t sends;
  size_t discarded_responses;
  size_t open_sockets;
};

static fn_result_t resolver_result(fn_status_t code)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE :
                                               FN_STAGE_RESOLVE,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static fn_result_t resolver_dns_result(fn_status_t code, int64_t native_code)
{
  return fn_result_make(code, FN_STAGE_RESOLVE, FN_ERROR_ORIGIN_DNS,
                        native_code);
}

static bool resolver_is_owner(const fn_resolver_t *resolver)
{
  return resolver != NULL && fn_loop_is_owner(resolver->loop);
}

static bool purpose_valid(fn_resolver_purpose_t purpose)
{
  return purpose == FN_RESOLVER_PURPOSE_DIRECT ||
         purpose == FN_RESOLVER_PURPOSE_BOOTSTRAP;
}

static bool endpoint_equal(const fn_endpoint_t *left,
                           const fn_endpoint_t *right)
{
  return left->address.kind == FN_ADDR_V4 &&
         right->address.kind == FN_ADDR_V4 && left->port == right->port &&
         memcmp(left->address.value.v4, right->address.value.v4, 4u) == 0;
}

static bool upstream_equal(const fn_dns_upstream_t *left,
                           const fn_dns_upstream_t *right)
{
  return left->transport == right->transport &&
         endpoint_equal(&left->endpoint, &right->endpoint);
}

static void normalize_upstreams(fn_dns_upstream_t output[FN_DNS_UPSTREAM_MAX],
                                size_t *output_count,
                                const fn_dns_upstream_t *input,
                                size_t input_count)
{
  size_t input_index;
  *output_count = 0;
  for (input_index = 0; input_index < input_count; input_index++) {
    size_t prior;
    bool duplicate = false;
    for (prior = 0; prior < *output_count; prior++) {
      if (upstream_equal(&output[prior], &input[input_index])) {
        duplicate = true;
        break;
      }
    }
    if (!duplicate && *output_count < FN_DNS_UPSTREAM_MAX) {
      output[*output_count] = input[input_index];
      (*output_count)++;
    }
  }
}

static const fn_dns_upstream_t *transaction_upstreams(
  const fn_resolver_transaction_t *transaction, size_t *count)
{
  if (transaction->purpose == FN_RESOLVER_PURPOSE_DIRECT) {
    *count = transaction->resolver->config.direct_count;
    return transaction->resolver->config.direct;
  }
  *count = transaction->resolver->config.bootstrap_count;
  return transaction->resolver->config.bootstrap;
}

static void cache_entry_free(fn_resolver_t *resolver,
                             fn_resolver_cache_entry_t *entry)
{
  resolver->allocator.deallocate(resolver->allocator.context, entry);
  (void)fn_budget_release(resolver->owned_memory, FN_BUDGET_ACTIVE,
                          sizeof(*entry));
  resolver->cache_count--;
}

static void cache_remove(fn_resolver_t *resolver,
                         fn_resolver_cache_entry_t **slot)
{
  fn_resolver_cache_entry_t *entry = *slot;
  *slot = entry->next;
  cache_entry_free(resolver, entry);
}

static fn_resolver_cache_entry_t *cache_lookup(
  fn_resolver_t *resolver, const fn_domain_t *question,
  fn_resolver_purpose_t purpose, uint64_t now_ms)
{
  fn_resolver_cache_entry_t **slot = &resolver->cache;
  while (*slot != NULL) {
    fn_resolver_cache_entry_t *entry = *slot;
    if (entry->expires_ms <= now_ms) {
      cache_remove(resolver, slot);
      continue;
    }
    if (entry->generation == resolver->generation &&
        entry->purpose == purpose &&
        fn_domain_equal(&entry->question, question)) {
      entry->used_at_ms = now_ms;
      resolver->cache_hits++;
      return entry;
    }
    slot = &entry->next;
  }
  return NULL;
}

static void cache_store(fn_resolver_t *resolver, const fn_domain_t *question,
                        fn_resolver_purpose_t purpose, fn_result_t result,
                        uint64_t now_ms)
{
  fn_resolver_cache_entry_t *entry;
  fn_resolver_cache_entry_t **slot;
  fn_resolver_cache_entry_t **oldest_slot = NULL;
  uint64_t oldest = UINT64_MAX;
  uint64_t expires;
  fn_result_t budget_result;

  if (resolver->config.failure_cache_size == 0 ||
      resolver->config.failure_cache_ttl_ms == 0 ||
      fn_deadline_after_ms(now_ms, resolver->config.failure_cache_ttl_ms,
                           &expires).code != FN_OK) {
    return;
  }
  slot = &resolver->cache;
  while (*slot != NULL) {
    entry = *slot;
    if (entry->expires_ms <= now_ms) {
      cache_remove(resolver, slot);
      continue;
    }
    if (entry->generation == resolver->generation &&
        entry->purpose == purpose &&
        fn_domain_equal(&entry->question, question)) {
      entry->result = result;
      entry->expires_ms = expires;
      entry->used_at_ms = now_ms;
      return;
    }
    if (entry->used_at_ms < oldest) {
      oldest = entry->used_at_ms;
      oldest_slot = slot;
    }
    slot = &entry->next;
  }
  if (resolver->cache_count >= resolver->config.failure_cache_size &&
      oldest_slot != NULL) {
    cache_remove(resolver, oldest_slot);
  }
  budget_result = fn_budget_reserve(resolver->owned_memory, FN_BUDGET_ACTIVE,
                                    sizeof(*entry));
  if (budget_result.code != FN_OK) {
    return;
  }
  entry = resolver->allocator.allocate(resolver->allocator.context,
                                       sizeof(*entry));
  if (entry == NULL) {
    (void)fn_budget_release(resolver->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*entry));
    return;
  }
  memset(entry, 0, sizeof(*entry));
  entry->question = *question;
  entry->purpose = purpose;
  entry->generation = resolver->generation;
  entry->result = result;
  entry->expires_ms = expires;
  entry->used_at_ms = now_ms;
  entry->next = resolver->cache;
  resolver->cache = entry;
  resolver->cache_count++;
}

static void operation_completion(void *context, fn_result_t result)
{
  fn_resolver_operation_t *operation = context;
  fn_resolver_callback_fn callback = operation->callback;
  void *callback_context = operation->callback_context;
  const fn_resolved_t *resolved = operation->has_resolved ?
                                  &operation->resolved : NULL;
  operation->callback_started = true;
  if (operation->cancel_requested) {
    result = resolver_result(FN_CANCELLED);
    resolved = NULL;
  }
  callback(operation, callback_context, result, resolved);
}

static void operation_detach(fn_resolver_operation_t *operation)
{
  fn_resolver_transaction_t *transaction = operation->transaction;
  fn_resolver_operation_t **slot;
  if (transaction == NULL) {
    return;
  }
  slot = &transaction->waiters;
  while (*slot != NULL && *slot != operation) {
    slot = &(*slot)->next;
  }
  if (*slot == operation) {
    *slot = operation->next;
    transaction->waiter_count--;
    transaction->resolver->waiters--;
  }
  operation->transaction = NULL;
  operation->next = NULL;
}

static void operation_finish(fn_resolver_operation_t *operation,
                             fn_result_t result,
                             const fn_resolved_t *resolved)
{
  operation_detach(operation);
  (void)fn_timer_destroy(&operation->timer);
  operation->terminal_result = result;
  if (resolved != NULL && result.code == FN_OK) {
    operation->resolved = *resolved;
    operation->has_resolved = true;
  }
  operation->terminal_queued = true;
  (void)fn_completion_publish(&operation->ticket, result,
                              operation_completion, operation);
}

static void transaction_unlink(fn_resolver_transaction_t *transaction)
{
  fn_resolver_t *resolver = transaction->resolver;
  fn_resolver_transaction_t **slot;
  if (!transaction->linked) {
    return;
  }
  slot = &resolver->transactions;
  while (*slot != NULL && *slot != transaction) {
    slot = &(*slot)->next;
  }
  if (*slot == transaction) {
    *slot = transaction->next;
    resolver->pending--;
  }
  transaction->linked = false;
  transaction->next = NULL;
}

static void transaction_release_attempt(
  fn_resolver_transaction_t *transaction)
{
  if (transaction->attempt != NULL) {
    (void)transaction->resolver->transport.cancel(transaction->attempt);
    (void)transaction->resolver->transport.release(&transaction->attempt);
    transaction->resolver->open_sockets--;
  }
}

static void transaction_free(fn_resolver_transaction_t *transaction)
{
  fn_resolver_t *resolver = transaction->resolver;
  transaction_release_attempt(transaction);
  transaction_unlink(transaction);
  resolver->allocator.deallocate(resolver->allocator.context, transaction);
  (void)fn_budget_release(resolver->owned_memory, FN_BUDGET_ACTIVE,
                          sizeof(*transaction));
}

static void transaction_finish(fn_resolver_transaction_t *transaction,
                               fn_result_t result,
                               const fn_resolved_t *resolved,
                               bool cache_failure)
{
  fn_resolver_t *resolver = transaction->resolver;
  uint64_t now_ms = 0;
  transaction_release_attempt(transaction);
  transaction_unlink(transaction);
  if (cache_failure && fn_monotonic_now_ms(&now_ms).code == FN_OK) {
    cache_store(resolver, &transaction->original_question,
                transaction->purpose, result, now_ms);
  }
  while (transaction->waiters != NULL) {
    operation_finish(transaction->waiters, result, resolved);
  }
  resolver->allocator.deallocate(resolver->allocator.context, transaction);
  (void)fn_budget_release(resolver->owned_memory, FN_BUDGET_ACTIVE,
                          sizeof(*transaction));
}

static bool result_is_local_failure(fn_result_t result)
{
  return result.code == FN_LIMIT || result.code == FN_NO_MEMORY ||
         result.code == FN_INVALID || result.code == FN_UNSUPPORTED ||
         result.stage == FN_STAGE_RESOURCE;
}

static size_t tuple_send_count(
  const fn_resolver_transaction_t *transaction,
  const fn_domain_t *question, size_t upstream_index,
  fn_dns_transport_t transport)
{
  size_t index;
  size_t count = 0;
  for (index = 0; index < transaction->history_count; index++) {
    const fn_dns_send_history_t *item = &transaction->history[index];
    if (item->upstream_index == upstream_index &&
        item->transport == transport &&
        fn_domain_equal(&item->question, question)) {
      count++;
    }
  }
  return count;
}

static bool select_attempt(fn_resolver_transaction_t *transaction,
                           size_t *upstream_index,
                           fn_dns_transport_t *transport)
{
  const fn_dns_upstream_t *upstreams;
  size_t upstream_count;
  size_t checked;
  upstreams = transaction_upstreams(transaction, &upstream_count);
  if (transaction->force_tcp) {
    *upstream_index = transaction->active_upstream;
    *transport = FN_DNS_TRANSPORT_TCP;
    transaction->force_tcp = false;
    return tuple_send_count(transaction, &transaction->current_question,
                            *upstream_index, *transport) < 3u;
  }
  for (checked = 0; checked < upstream_count; checked++) {
    size_t candidate = (transaction->next_upstream + checked) % upstream_count;
    fn_dns_transport_t candidate_transport = upstreams[candidate].transport;
    if ((transaction->incompatible_mask &
         (UINT32_C(1) << candidate)) != 0) {
      continue;
    }
    if (tuple_send_count(transaction, &transaction->current_question,
                         candidate, candidate_transport) >= 3u) {
      continue;
    }
    *upstream_index = candidate;
    *transport = candidate_transport;
    transaction->next_upstream = (candidate + 1u) % upstream_count;
    return true;
  }
  return false;
}

static void history_add(fn_resolver_transaction_t *transaction,
                        size_t upstream_index,
                        fn_dns_transport_t transport)
{
  if (transaction->history_count < FN_DNS_SEND_HISTORY_MAX) {
    fn_dns_send_history_t *item =
      &transaction->history[transaction->history_count++];
    item->question = transaction->current_question;
    item->upstream_index = upstream_index;
    item->transport = transport;
  }
}

static void transaction_start_attempt(
  fn_resolver_transaction_t *transaction);

static void transaction_retry(fn_resolver_transaction_t *transaction,
                              fn_result_t result, bool cacheable)
{
  transaction->last_result = result;
  transaction->last_cacheable = cacheable;
  transaction_start_attempt(transaction);
}

static bool transaction_seen_cname(
  const fn_resolver_transaction_t *transaction, const fn_domain_t *name)
{
  size_t index;
  for (index = 0; index < transaction->cname_visited_count; index++) {
    if (fn_domain_equal(&transaction->cname_visited[index], name)) {
      return true;
    }
  }
  return false;
}

static void transaction_accept_cname(
  fn_resolver_transaction_t *transaction,
  const fn_dns_parse_result_t *parsed)
{
  if (parsed->cname_hops == 0 ||
      parsed->cname_hops > FN_DNS_CNAME_HOPS_MAX -
                            transaction->cname_hops_total) {
    transaction_finish(
      transaction,
      resolver_dns_result(FN_LIMIT, FN_DNS_NATIVE_RESPONSE_LIMIT),
      NULL, false);
    return;
  }
  if (transaction_seen_cname(transaction, &parsed->cname_question)) {
    transaction_finish(
      transaction,
      resolver_dns_result(FN_PROTOCOL_ERROR, FN_DNS_NATIVE_CNAME_LOOP),
      NULL, false);
    return;
  }
  transaction->cname_hops_total += parsed->cname_hops;
  if (transaction->cname_visited_count <
      FN_DNS_CNAME_HOPS_MAX + 1u) {
    transaction->cname_visited[transaction->cname_visited_count++] =
      parsed->cname_question;
  }
  if (!transaction->has_cname_ttl ||
      parsed->cname_ttl_seconds < transaction->cname_ttl_seconds) {
    transaction->cname_ttl_seconds = parsed->cname_ttl_seconds;
    transaction->has_cname_ttl = true;
  }
  transaction->current_question = parsed->cname_question;
  transaction->next_upstream = 0;
  transaction->incompatible_mask = 0;
  transaction->force_tcp = false;
  transaction_start_attempt(transaction);
}

static bool transport_response(
  fn_dns_transport_operation_t *operation, void *context, fn_result_t result,
  const uint8_t *response, size_t response_length, bool truncated,
  bool source_matched, bool local_matched)
{
  fn_resolver_transaction_t *transaction = context;
  fn_resolver_t *resolver = transaction->resolver;
  fn_dns_parse_result_t parsed;
  (void)operation;

  if (!source_matched || !local_matched) {
    resolver->discarded_responses++;
    return false;
  }
  if (result.code == FN_OK && !truncated) {
    if (fn_dns_response_parse(response, response_length,
                              transaction->history[
                                transaction->history_count - 1u].transport,
                              &transaction->query, &parsed).code != FN_OK) {
      result = resolver_result(FN_INVALID);
    } else if (parsed.action == FN_DNS_PARSE_DISCARD) {
      resolver->discarded_responses++;
      return false;
    }
  } else if (result.code == FN_OK) {
    memset(&parsed, 0, sizeof(parsed));
    parsed.action = FN_DNS_PARSE_TERMINAL;
    parsed.result = resolver_dns_result(FN_PROTOCOL_ERROR,
                                        FN_DNS_NATIVE_TRUNCATED);
  }

  (void)resolver->transport.release(&transaction->attempt);
  resolver->open_sockets--;
  if (result.code != FN_OK) {
    if (result_is_local_failure(result)) {
      transaction_finish(transaction, result, NULL, false);
    } else {
      transaction_retry(transaction, result, true);
    }
    return true;
  }

  switch (parsed.action) {
    case FN_DNS_PARSE_TCP_FALLBACK:
      transaction->force_tcp = true;
      transaction_start_attempt(transaction);
      break;
    case FN_DNS_PARSE_CNAME_QUERY:
      transaction_accept_cname(transaction, &parsed);
      break;
    case FN_DNS_PARSE_ANSWER: {
      fn_resolved_t resolved = parsed.resolved;
      if (parsed.cname_hops >
          FN_DNS_CNAME_HOPS_MAX - transaction->cname_hops_total) {
        transaction_finish(
          transaction,
          resolver_dns_result(FN_LIMIT, FN_DNS_NATIVE_RESPONSE_LIMIT),
          NULL, false);
        break;
      }
      if (transaction->has_cname_ttl &&
          transaction->cname_ttl_seconds < resolved.ttl_seconds) {
        resolved.ttl_seconds = transaction->cname_ttl_seconds;
      }
      transaction_finish(transaction, resolver_result(FN_OK), &resolved,
                         false);
      break;
    }
    case FN_DNS_PARSE_TERMINAL:
      if (parsed.result.code == FN_RESOLVE_ERROR &&
          (parsed.result.native_code == 3 ||
           parsed.result.native_code == FN_DNS_NATIVE_NODATA)) {
        transaction_finish(transaction, parsed.result, NULL, false);
      } else if (parsed.result.code == FN_LIMIT ||
                 parsed.result.native_code == FN_DNS_NATIVE_CNAME_LOOP) {
        transaction_finish(transaction, parsed.result, NULL, false);
      } else if (parsed.result.code == FN_RESOLVE_ERROR &&
                 parsed.result.native_code != 2) {
        transaction->incompatible_mask |=
          UINT32_C(1) << transaction->active_upstream;
        transaction_retry(transaction, parsed.result, true);
      } else {
        transaction_retry(transaction, parsed.result, true);
      }
      break;
    case FN_DNS_PARSE_DISCARD:
      break;
  }
  return true;
}

static void transaction_start_attempt(
  fn_resolver_transaction_t *transaction)
{
  fn_resolver_t *resolver = transaction->resolver;
  const fn_dns_upstream_t *upstreams;
  fn_dns_transport_request_t request;
  fn_dns_transport_t transport;
  fn_socket_purpose_t socket_purpose;
  fn_result_t result;
  uint64_t now_ms;
  uint64_t timeout_deadline;
  uint16_t id;
  size_t upstream_count;
  size_t upstream_index;

  if (transaction->waiter_count == 0) {
    transaction_free(transaction);
    return;
  }
  if (fn_monotonic_now_ms(&now_ms).code != FN_OK) {
    transaction_finish(transaction, resolver_result(FN_IO_ERROR), NULL,
                       false);
    return;
  }
  if (now_ms >= transaction->policy_deadline_ms) {
    transaction_finish(
      transaction,
      resolver_dns_result(FN_TIMEOUT, FN_DNS_NATIVE_NO_RESPONSE), NULL,
      transaction->last_cacheable);
    return;
  }
  if (transaction->attempts_used >= resolver->config.attempts ||
      !select_attempt(transaction, &upstream_index, &transport)) {
    transaction_finish(transaction, transaction->last_result, NULL,
                       transaction->last_cacheable);
    return;
  }
  result = resolver->transport.random_u16(resolver->transport.context, &id);
  if (result.code != FN_OK) {
    transaction_finish(transaction, result, NULL, false);
    return;
  }
  result = fn_dns_query_build(&transaction->current_question, id,
                              &transaction->query);
  if (result.code != FN_OK) {
    transaction_finish(transaction, result, NULL, false);
    return;
  }
  if (fn_deadline_after_ms(now_ms, resolver->config.timeout_ms,
                           &timeout_deadline).code != FN_OK) {
    timeout_deadline = UINT64_MAX;
  }
  transaction->attempt_deadline_ms =
    fn_deadline_min(timeout_deadline, transaction->policy_deadline_ms);
  transaction->active_upstream = upstream_index;
  history_add(transaction, upstream_index, transport);
  transaction->attempts_used++;
  resolver->sends++;
  upstreams = transaction_upstreams(transaction, &upstream_count);
  (void)upstream_count;
  socket_purpose = transaction->purpose == FN_RESOLVER_PURPOSE_DIRECT ?
                   FN_SOCKET_PURPOSE_DNS_UPSTREAM :
                   FN_SOCKET_PURPOSE_DNS_BOOTSTRAP;
  memset(&request, 0, sizeof(request));
  request.upstream = upstreams[upstream_index].endpoint;
  request.transport = transport;
  request.socket_purpose = socket_purpose;
  request.query = transaction->query.wire;
  request.query_length = transaction->query.length;
  request.query_id = transaction->query.id;
  request.deadline_ms = transaction->attempt_deadline_ms;
  result = resolver->transport.start(
    resolver->transport.context, &request, transport_response, transaction,
    &transaction->attempt);
  if (result.code == FN_OK && transaction->attempt == NULL) {
    result = resolver_result(FN_INVALID);
  }
  if (result.code == FN_OK) {
    resolver->open_sockets++;
    return;
  }
  if (result_is_local_failure(result)) {
    transaction_finish(transaction, result, NULL, false);
  } else {
    transaction_retry(transaction, result, true);
  }
}

static void waiter_timeout(fn_timer_t *timer, void *context)
{
  fn_resolver_operation_t *operation = context;
  fn_resolver_transaction_t *transaction = operation->transaction;
  (void)timer;
  operation_finish(
    operation,
    resolver_dns_result(FN_TIMEOUT, FN_DNS_NATIVE_NO_RESPONSE), NULL);
  if (transaction != NULL && transaction->waiter_count == 0) {
    transaction_free(transaction);
  }
}

static fn_result_t operation_allocate(fn_resolver_t *resolver,
                                      fn_resolver_callback_fn callback,
                                      void *context,
                                      fn_resolver_operation_t **out)
{
  fn_resolver_operation_t *operation;
  fn_result_t result;
  *out = NULL;
  result = fn_budget_reserve(resolver->owned_memory, FN_BUDGET_ACTIVE,
                             sizeof(*operation));
  if (result.code != FN_OK) {
    return result;
  }
  operation = resolver->allocator.allocate(resolver->allocator.context,
                                            sizeof(*operation));
  if (operation == NULL) {
    (void)fn_budget_release(resolver->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*operation));
    return resolver_result(FN_NO_MEMORY);
  }
  memset(operation, 0, sizeof(*operation));
  operation->resolver = resolver;
  operation->callback = callback;
  operation->callback_context = context;
  result = fn_completion_reserve_terminal(resolver->loop,
                                           &operation->ticket);
  if (result.code != FN_OK) {
    resolver->allocator.deallocate(resolver->allocator.context, operation);
    (void)fn_budget_release(resolver->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*operation));
    return result;
  }
  resolver->live_operations++;
  *out = operation;
  return resolver_result(FN_OK);
}

static void operation_rollback(fn_resolver_operation_t **operation_pointer)
{
  fn_resolver_operation_t *operation = *operation_pointer;
  fn_resolver_t *resolver = operation->resolver;
  (void)fn_timer_destroy(&operation->timer);
  (void)fn_completion_abandon(&operation->ticket);
  resolver->live_operations--;
  resolver->allocator.deallocate(resolver->allocator.context, operation);
  (void)fn_budget_release(resolver->owned_memory, FN_BUDGET_ACTIVE,
                          sizeof(*operation));
  *operation_pointer = NULL;
}

static fn_result_t operation_attach(fn_resolver_transaction_t *transaction,
                                    uint64_t deadline_ms,
                                    fn_resolver_callback_fn callback,
                                    void *context,
                                    fn_resolver_operation_t **out)
{
  fn_resolver_t *resolver = transaction->resolver;
  fn_resolver_operation_t *operation;
  fn_result_t result = operation_allocate(resolver, callback, context,
                                          &operation);
  if (result.code != FN_OK) {
    return result;
  }
  result = fn_timer_start(resolver->loop, deadline_ms, waiter_timeout,
                          operation, &operation->timer);
  if (result.code != FN_OK) {
    operation_rollback(&operation);
    return result;
  }
  operation->transaction = transaction;
  operation->next = transaction->waiters;
  transaction->waiters = operation;
  transaction->waiter_count++;
  resolver->waiters++;
  *out = operation;
  return resolver_result(FN_OK);
}

static fn_resolver_transaction_t *transaction_find(
  fn_resolver_t *resolver, const fn_domain_t *question,
  fn_resolver_purpose_t purpose)
{
  fn_resolver_transaction_t *transaction = resolver->transactions;
  while (transaction != NULL) {
    if (transaction->purpose == purpose &&
        fn_domain_equal(&transaction->original_question, question)) {
      return transaction;
    }
    transaction = transaction->next;
  }
  return NULL;
}

static fn_result_t transaction_allocate(fn_resolver_t *resolver,
                                        const fn_domain_t *question,
                                        fn_resolver_purpose_t purpose,
                                        uint64_t now_ms,
                                        fn_resolver_transaction_t **out)
{
  fn_resolver_transaction_t *transaction;
  fn_result_t result;
  uint64_t duration;
  *out = NULL;
  result = fn_budget_reserve(resolver->owned_memory, FN_BUDGET_ACTIVE,
                             sizeof(*transaction));
  if (result.code != FN_OK) {
    return result;
  }
  transaction = resolver->allocator.allocate(resolver->allocator.context,
                                              sizeof(*transaction));
  if (transaction == NULL) {
    (void)fn_budget_release(resolver->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*transaction));
    return resolver_result(FN_NO_MEMORY);
  }
  memset(transaction, 0, sizeof(*transaction));
  transaction->resolver = resolver;
  transaction->original_question = *question;
  transaction->current_question = *question;
  transaction->cname_visited[0] = *question;
  transaction->cname_visited_count = 1u;
  transaction->purpose = purpose;
  transaction->last_result =
    resolver_dns_result(FN_TIMEOUT, FN_DNS_NATIVE_NO_RESPONSE);
  if (resolver->config.timeout_ms >
      UINT64_MAX / (uint64_t)resolver->config.attempts) {
    duration = UINT64_MAX;
  } else {
    duration = resolver->config.timeout_ms *
               (uint64_t)resolver->config.attempts;
  }
  if (fn_deadline_after_ms(now_ms, duration,
                           &transaction->policy_deadline_ms).code != FN_OK) {
    transaction->policy_deadline_ms = UINT64_MAX;
  }
  transaction->next = resolver->transactions;
  resolver->transactions = transaction;
  transaction->linked = true;
  resolver->pending++;
  *out = transaction;
  return resolver_result(FN_OK);
}

static bool upstream_list_valid(const fn_dns_upstream_t *upstreams,
                                size_t count)
{
  size_t index;
  if (count > FN_DNS_UPSTREAM_MAX) {
    return false;
  }
  for (index = 0; index < count; index++) {
    if ((upstreams[index].transport != FN_DNS_TRANSPORT_UDP &&
         upstreams[index].transport != FN_DNS_TRANSPORT_TCP) ||
        upstreams[index].endpoint.address.kind != FN_ADDR_V4 ||
        upstreams[index].endpoint.port == 0) {
      return false;
    }
  }
  return true;
}

fn_result_t fn_resolver_create_with_transport(
  const fn_resolver_options_t *options, const fn_dns_transport_ops_t *transport,
  fn_resolver_t **out)
{
  fn_resolver_t *resolver;
  fn_result_t result;
  if (out == NULL) {
    return resolver_result(FN_INVALID);
  }
  *out = NULL;
  if (options == NULL || transport == NULL || options->loop == NULL ||
      options->limits == NULL || options->owned_memory == NULL ||
      options->file_descriptors == NULL ||
      options->allocator.allocate == NULL ||
      options->allocator.deallocate == NULL || transport->start == NULL ||
      transport->cancel == NULL || transport->release == NULL ||
      transport->random_u16 == NULL || transport->destroy == NULL ||
      !fn_loop_is_owner(options->loop) ||
      options->config.timeout_ms < UINT64_C(10) ||
      options->config.timeout_ms > UINT64_C(30000) ||
      options->config.attempts == 0 || options->config.attempts > 4u ||
      options->config.failure_cache_size == 0 ||
      options->config.failure_cache_size > 65536u ||
      options->config.failure_cache_ttl_ms < UINT64_C(1000) ||
      options->config.failure_cache_ttl_ms > UINT64_C(300000) ||
      !upstream_list_valid(options->config.direct,
                           options->config.direct_count) ||
      !upstream_list_valid(options->config.bootstrap,
                           options->config.bootstrap_count)) {
    return resolver_result(FN_INVALID);
  }
  result = fn_budget_reserve(options->owned_memory, FN_BUDGET_ACTIVE,
                             sizeof(*resolver));
  if (result.code != FN_OK) {
    return result;
  }
  resolver = options->allocator.allocate(options->allocator.context,
                                          sizeof(*resolver));
  if (resolver == NULL) {
    (void)fn_budget_release(options->owned_memory, FN_BUDGET_ACTIVE,
                            sizeof(*resolver));
    return resolver_result(FN_NO_MEMORY);
  }
  memset(resolver, 0, sizeof(*resolver));
  resolver->loop = options->loop;
  resolver->limits = *options->limits;
  resolver->owned_memory = options->owned_memory;
  resolver->file_descriptors = options->file_descriptors;
  resolver->allocator = options->allocator;
  resolver->config = options->config;
  resolver->generation = options->generation;
  resolver->transport = *transport;
  normalize_upstreams(resolver->config.direct,
                      &resolver->config.direct_count,
                      options->config.direct,
                      options->config.direct_count);
  normalize_upstreams(resolver->config.bootstrap,
                      &resolver->config.bootstrap_count,
                      options->config.bootstrap,
                      options->config.bootstrap_count);
  *out = resolver;
  return resolver_result(FN_OK);
}

fn_result_t fn_resolver_create(const fn_resolver_options_t *options,
                               fn_resolver_t **out)
{
  fn_dns_transport_ops_t transport;
  fn_result_t result;
  if (out == NULL) {
    return resolver_result(FN_INVALID);
  }
  *out = NULL;
  result = fn_dns_linux_transport_create(options, &transport);
  if (result.code != FN_OK) {
    return result;
  }
  result = fn_resolver_create_with_transport(options, &transport, out);
  if (result.code != FN_OK) {
    transport.destroy(transport.context);
  }
  return result;
}

fn_result_t fn_resolver_destroy(fn_resolver_t **resolver_pointer)
{
  fn_resolver_t *resolver;
  fn_resolver_cache_entry_t *entry;
  fn_allocator_t allocator;
  fn_budget_t *owned_memory;
  if (resolver_pointer == NULL) {
    return resolver_result(FN_INVALID);
  }
  resolver = *resolver_pointer;
  if (resolver == NULL) {
    return resolver_result(FN_OK);
  }
  if (!resolver_is_owner(resolver) || resolver->pending != 0 ||
      resolver->waiters != 0 || resolver->live_operations != 0 ||
      resolver->open_sockets != 0) {
    return resolver_result(FN_INVALID);
  }
  while (resolver->cache != NULL) {
    entry = resolver->cache;
    resolver->cache = entry->next;
    cache_entry_free(resolver, entry);
  }
  allocator = resolver->allocator;
  owned_memory = resolver->owned_memory;
  resolver->transport.destroy(resolver->transport.context);
  allocator.deallocate(allocator.context, resolver);
  (void)fn_budget_release(owned_memory, FN_BUDGET_ACTIVE, sizeof(*resolver));
  *resolver_pointer = NULL;
  return resolver_result(FN_OK);
}

fn_result_t fn_resolver_snapshot(const fn_resolver_t *resolver,
                                 fn_resolver_snapshot_t *out)
{
  if (!resolver_is_owner(resolver) || out == NULL) {
    return resolver_result(FN_INVALID);
  }
  memset(out, 0, sizeof(*out));
  out->pending = resolver->pending;
  out->waiters = resolver->waiters;
  out->failure_cache_entries = resolver->cache_count;
  out->failure_cache_hits = resolver->cache_hits;
  out->sends = resolver->sends;
  out->discarded_responses = resolver->discarded_responses;
  out->open_sockets = resolver->open_sockets;
  return resolver_result(FN_OK);
}

static fn_result_t queue_immediate(fn_resolver_t *resolver,
                                   fn_result_t terminal_result,
                                   fn_resolver_callback_fn callback,
                                   void *context,
                                   fn_resolver_operation_t **out)
{
  fn_resolver_operation_t *operation;
  fn_result_t result = operation_allocate(resolver, callback, context,
                                          &operation);
  if (result.code != FN_OK) {
    return result;
  }
  operation->terminal_result = terminal_result;
  operation->terminal_queued = true;
  result = fn_completion_publish(&operation->ticket, terminal_result,
                                 operation_completion, operation);
  if (result.code != FN_OK) {
    operation_rollback(&operation);
    return result;
  }
  *out = operation;
  return resolver_result(FN_OK);
}

fn_result_t fn_resolver_acquire(fn_resolver_t *resolver,
                                const fn_domain_t *question,
                                fn_resolver_purpose_t purpose,
                                uint64_t deadline_ms,
                                fn_resolver_callback_fn callback,
                                void *context,
                                fn_resolver_operation_t **out)
{
  fn_resolver_transaction_t *transaction;
  fn_resolver_cache_entry_t *cached;
  fn_result_t result;
  uint64_t now_ms;
  size_t upstream_count;

  if (out == NULL) {
    return resolver_result(FN_INVALID);
  }
  *out = NULL;
  if (!resolver_is_owner(resolver) || question == NULL ||
      question->length == 0 || !purpose_valid(purpose) || callback == NULL) {
    return resolver_result(FN_INVALID);
  }
  upstream_count = purpose == FN_RESOLVER_PURPOSE_DIRECT ?
                   resolver->config.direct_count :
                   resolver->config.bootstrap_count;
  if (upstream_count == 0) {
    return resolver_result(FN_INVALID);
  }
  result = fn_monotonic_now_ms(&now_ms);
  if (result.code != FN_OK) {
    return result;
  }
  if (deadline_ms <= now_ms) {
    return queue_immediate(
      resolver, resolver_dns_result(FN_TIMEOUT, FN_DNS_NATIVE_NO_RESPONSE),
      callback, context, out);
  }
  cached = cache_lookup(resolver, question, purpose, now_ms);
  if (cached != NULL) {
    return queue_immediate(resolver, cached->result, callback, context, out);
  }
  transaction = transaction_find(resolver, question, purpose);
  if (transaction != NULL) {
    if (transaction->waiter_count >= FN_DNS_WAITER_PER_KEY_MAX) {
      return resolver_result(FN_LIMIT);
    }
    return operation_attach(transaction, deadline_ms, callback, context, out);
  }
  if (resolver->pending >= resolver->limits.resolver_pending_limit) {
    return resolver_result(FN_LIMIT);
  }
  result = transaction_allocate(resolver, question, purpose, now_ms,
                                &transaction);
  if (result.code != FN_OK) {
    return result;
  }
  result = operation_attach(transaction, deadline_ms, callback, context, out);
  if (result.code != FN_OK) {
    transaction_free(transaction);
    return result;
  }
  transaction_start_attempt(transaction);
  return resolver_result(FN_OK);
}

fn_result_t fn_resolver_operation_cancel(fn_resolver_operation_t *operation)
{
  fn_resolver_transaction_t *transaction;
  if (operation == NULL || !resolver_is_owner(operation->resolver) ||
      operation->callback_started) {
    return resolver_result(FN_INVALID);
  }
  if (operation->terminal_queued) {
    operation->cancel_requested = true;
    return resolver_result(FN_OK);
  }
  transaction = operation->transaction;
  operation_finish(operation, resolver_result(FN_CANCELLED), NULL);
  if (transaction != NULL && transaction->waiter_count == 0) {
    transaction_free(transaction);
  }
  return resolver_result(FN_OK);
}

fn_result_t fn_resolver_operation_release(
  fn_resolver_operation_t **operation_pointer)
{
  fn_resolver_operation_t *operation;
  fn_resolver_t *resolver;
  if (operation_pointer == NULL) {
    return resolver_result(FN_INVALID);
  }
  operation = *operation_pointer;
  if (operation == NULL) {
    return resolver_result(FN_OK);
  }
  resolver = operation->resolver;
  if (!resolver_is_owner(resolver) || !operation->callback_started ||
      operation->transaction != NULL || operation->ticket != NULL ||
      operation->timer != NULL) {
    return resolver_result(FN_INVALID);
  }
  resolver->live_operations--;
  resolver->allocator.deallocate(resolver->allocator.context, operation);
  (void)fn_budget_release(resolver->owned_memory, FN_BUDGET_ACTIVE,
                          sizeof(*operation));
  *operation_pointer = NULL;
  return resolver_result(FN_OK);
}
