#ifndef FLICKNET_RESOLVER_H
#define FLICKNET_RESOLVER_H

#include "flicknet/address.h"
#include "flicknet/config.h"
#include "flicknet/loop.h"
#include "flicknet/metadata.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FN_DNS_MESSAGE_UDP_MAX 512u
#define FN_DNS_MESSAGE_TCP_MAX 65535u
#define FN_DNS_WAITER_PER_KEY_MAX 32u
#define FN_DNS_RR_MAX 1024u
#define FN_DNS_CNAME_MAX 64u
#define FN_DNS_CNAME_HOPS_MAX 8u

#define FN_DNS_NATIVE_NODATA 256
#define FN_DNS_NATIVE_TRUNCATED 257
#define FN_DNS_NATIVE_MALFORMED 258
#define FN_DNS_NATIVE_CNAME_LOOP 259
#define FN_DNS_NATIVE_RESPONSE_LIMIT 260
#define FN_DNS_NATIVE_NO_RESPONSE 261

typedef struct fn_resolver fn_resolver_t;
typedef struct fn_resolver_operation fn_resolver_operation_t;

typedef enum {
  FN_RESOLVER_PURPOSE_DIRECT = 0,
  FN_RESOLVER_PURPOSE_BOOTSTRAP
} fn_resolver_purpose_t;

typedef struct {
  uint16_t id;
  fn_domain_t question;
  size_t length;
  uint8_t wire[FN_DNS_MESSAGE_UDP_MAX];
} fn_dns_query_t;

typedef enum {
  FN_DNS_PARSE_DISCARD = 0,
  FN_DNS_PARSE_ANSWER,
  FN_DNS_PARSE_TCP_FALLBACK,
  FN_DNS_PARSE_CNAME_QUERY,
  FN_DNS_PARSE_TERMINAL
} fn_dns_parse_action_t;

typedef struct {
  fn_dns_parse_action_t action;
  fn_result_t result;
  fn_resolved_t resolved;
  fn_domain_t cname_question;
  uint32_t cname_ttl_seconds;
  size_t cname_hops;
} fn_dns_parse_result_t;

typedef struct {
  fn_loop_t *loop;
  const fn_limits_t *limits;
  fn_budget_t *owned_memory;
  fn_budget_t *file_descriptors;
  fn_allocator_t allocator;
  fn_dns_config_t config;
  uint64_t generation;
  bool require_route_guard;
  uint32_t route_mark;
} fn_resolver_options_t;

typedef struct {
  size_t pending;
  size_t waiters;
  size_t failure_cache_entries;
  size_t failure_cache_hits;
  size_t sends;
  size_t discarded_responses;
  size_t open_sockets;
} fn_resolver_snapshot_t;

typedef void (*fn_resolver_callback_fn)(fn_resolver_operation_t *operation,
                                        void *context, fn_result_t result,
                                        const fn_resolved_t *resolved);

/* fn_dns_query_build 生成一个无 EDNS 的 A/IN 查询，不读取随机源。 */
fn_result_t fn_dns_query_build(const fn_domain_t *question, uint16_t id,
                               fn_dns_query_t *out);

/* fn_dns_response_parse 只解释已完成来源校验的单个 DNS message。 */
fn_result_t fn_dns_response_parse(const uint8_t *message,
                                  size_t message_length,
                                  fn_dns_transport_t transport,
                                  const fn_dns_query_t *query,
                                  fn_dns_parse_result_t *out);

/* fn_resolver_create 固定调用线程为 owner，并复制 DNS 配置。 */
fn_result_t fn_resolver_create(const fn_resolver_options_t *options,
                               fn_resolver_t **out);
fn_result_t fn_resolver_destroy(fn_resolver_t **resolver);
fn_result_t fn_resolver_snapshot(const fn_resolver_t *resolver,
                                 fn_resolver_snapshot_t *out);

/* fn_resolver_acquire 接纳前预留 terminal；同 key 调用共享底层事务。 */
fn_result_t fn_resolver_acquire(fn_resolver_t *resolver,
                                const fn_domain_t *question,
                                fn_resolver_purpose_t purpose,
                                uint64_t deadline_ms,
                                fn_resolver_callback_fn callback,
                                void *context,
                                fn_resolver_operation_t **out);
fn_result_t fn_resolver_operation_cancel(fn_resolver_operation_t *operation);
/* fn_resolver_operation_release 只能在 terminal callback 已开始后调用。 */
fn_result_t fn_resolver_operation_release(
  fn_resolver_operation_t **operation);

#endif
