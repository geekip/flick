#ifndef FLICKNET_METADATA_H
#define FLICKNET_METADATA_H

#include "flicknet/address.h"

#include <stdbool.h>
#include <stdint.h>

#define FN_ID_NONE UINT32_MAX

typedef enum {
  FN_TCP = 0,
  FN_UDP
} fn_network_t;

typedef enum {
  FN_DOMAIN_ABSENT = 0,
  FN_DOMAIN_REQUEST,
  FN_DOMAIN_FAKEIP,
  FN_DOMAIN_SNI,
  FN_DOMAIN_HTTP_HOST
} fn_domain_source_t;

typedef struct {
  uint64_t generation;
  uint32_t index;
} fn_object_ref_t;

typedef struct {
  uint16_t count;
  fn_addr_t addresses[FN_RESOLVED_MAX];
  uint32_t ttl_seconds;
} fn_resolved_t;

/* route 是正确性数据，不受日志或 trace 开关影响。 */
typedef struct {
  fn_network_t network;
  fn_endpoint_t source;
  fn_endpoint_t original_target;
  fn_domain_t domain;
  fn_domain_source_t domain_source;
  fn_object_ref_t inbound;
  bool original_is_fakeip;
} fn_route_metadata_t;

typedef struct {
  fn_resolved_t resolved;
  fn_endpoint_t dial_target;
  bool dial_target_set;
} fn_dial_metadata_t;

typedef struct {
  uint64_t trace_id;
  uint32_t flags;
} fn_diagnostic_metadata_t;

typedef struct {
  fn_route_metadata_t route;
  fn_dial_metadata_t dial;
  fn_diagnostic_metadata_t *diagnostics;
} fn_session_metadata_t;

void fn_session_metadata_init(fn_session_metadata_t *metadata,
                              fn_network_t network);
fn_result_t fn_session_metadata_set_domain(fn_session_metadata_t *metadata,
                                           const fn_domain_t *domain,
                                           fn_domain_source_t source);
fn_result_t fn_session_metadata_attach_diagnostics(
  fn_session_metadata_t *metadata, fn_diagnostic_metadata_t *diagnostics);
void fn_session_metadata_detach_diagnostics(fn_session_metadata_t *metadata);

#endif
