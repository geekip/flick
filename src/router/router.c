#include "flicknet/router.h"

#include "../core/runtime_internal.h"

#include <string.h>

static fn_result_t router_result(fn_status_t code)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE : FN_STAGE_ROUTE,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static fn_result_t validate_resolved(const fn_session_metadata_t *metadata,
                                     uint16_t *out_mask)
{
  size_t index;
  uint16_t mask = 0;
  if (metadata->dial.resolved.count > FN_RESOLVED_MAX) {
    return router_result(FN_INVALID);
  }
  for (index = 0; index < metadata->dial.resolved.count; index++) {
    fn_addr_kind_t kind = metadata->dial.resolved.addresses[index].kind;
    if (kind != FN_ADDR_V4 && kind != FN_ADDR_V6) {
      return router_result(FN_INVALID);
    }
    mask |= (uint16_t)(UINT16_C(1) << index);
  }
  *out_mask = mask;
  return router_result(FN_OK);
}

fn_result_t fn_route_evaluate(const fn_runtime_t *runtime,
                              const fn_session_metadata_t *metadata,
                              fn_route_result_t *out)
{
  fn_compiled_rule_t rule;
  fn_result_t result;
  size_t rule_count;
  size_t index;

  if (out == NULL) {
    return router_result(FN_INVALID);
  }
  memset(out, 0, sizeof(*out));
  out->outbound.index = FN_ID_NONE;
  out->resolver.index = FN_ID_NONE;
  out->denial = router_result(FN_OK);
  if (runtime == NULL || metadata == NULL ||
      metadata->route.network != FN_TCP ||
      metadata->route.original_target.address.kind == FN_ADDR_NONE ||
      metadata->route.original_target.port == 0) {
    return router_result(FN_INVALID);
  }
  result = fn_runtime_internal_validate_kind(
    runtime, metadata->route.inbound, FN_RUNTIME_RESOURCE_LISTENER);
  if (result.code != FN_OK) {
    return result;
  }
  rule_count = fn_runtime_internal_rule_count(runtime);
  if (rule_count == 0) {
    return router_result(FN_INVALID);
  }

  for (index = 0; index < rule_count; index++) {
    result = fn_runtime_internal_rule_get(runtime, index, &rule);
    if (result.code != FN_OK) {
      return result;
    }
    out->generation = fn_runtime_generation(runtime);
    out->rule_index = index;
    if (rule.kind == FN_COMPILED_REJECT) {
      out->status = FN_ROUTE_DENY;
      out->denial = router_result(FN_REJECTED);
      return router_result(FN_OK);
    }
    if (rule.kind == FN_COMPILED_PROXY) {
      result = fn_runtime_internal_validate_kind(
        runtime, rule.object, FN_RUNTIME_RESOURCE_SOCKS_PROXY);
      if (result.code != FN_OK) {
        return result;
      }
      out->status = FN_ROUTE_READY;
      out->outbound = rule.object;
      out->dial_target = metadata->route.original_target;
      return router_result(FN_OK);
    }
    if (rule.kind != FN_COMPILED_DIRECT) {
      return router_result(FN_INVALID);
    }
    result = fn_runtime_internal_validate_kind(
      runtime, rule.object, FN_RUNTIME_RESOURCE_DIRECT);
    if (result.code != FN_OK) {
      return result;
    }
    out->outbound = rule.object;
    if (metadata->route.original_target.address.kind == FN_ADDR_DOMAIN &&
        metadata->dial.resolved.count == 0) {
      result = fn_runtime_internal_find_kind(
        runtime, FN_RUNTIME_RESOURCE_RESOLVER, &out->resolver);
      if (result.code != FN_OK) {
        return result;
      }
      out->status = FN_ROUTE_NEED_RESOLVE;
      return router_result(FN_OK);
    }
    if (metadata->route.original_target.address.kind == FN_ADDR_DOMAIN) {
      result = validate_resolved(metadata, &out->candidate_mask);
      if (result.code != FN_OK || out->candidate_mask == 0) {
        return result.code == FN_OK ? router_result(FN_INVALID) : result;
      }
      out->dial_target.address = metadata->dial.resolved.addresses[0];
      out->dial_target.port = metadata->route.original_target.port;
    } else {
      out->dial_target = metadata->route.original_target;
    }
    out->status = FN_ROUTE_READY;
    return router_result(FN_OK);
  }
  return router_result(FN_INVALID);
}
