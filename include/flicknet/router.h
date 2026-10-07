#ifndef FLICKNET_ROUTER_H
#define FLICKNET_ROUTER_H

#include "flicknet/runtime.h"

#include <stddef.h>
#include <stdint.h>

typedef enum {
  FN_ROUTE_READY = 0,
  FN_ROUTE_NEED_RESOLVE,
  FN_ROUTE_DENY
} fn_route_status_t;

typedef struct {
  fn_route_status_t status;
  uint64_t generation;
  size_t rule_index;
  fn_object_ref_t outbound;
  fn_object_ref_t resolver;
  fn_endpoint_t dial_target;
  uint16_t candidate_mask;
  fn_result_t denial;
} fn_route_result_t;

/* fn_route_evaluate 是同步纯计算；策略 DENY 通过 out 返回。 */
fn_result_t fn_route_evaluate(const fn_runtime_t *runtime,
                              const fn_session_metadata_t *metadata,
                              fn_route_result_t *out);

#endif
