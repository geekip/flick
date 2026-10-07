#ifndef FLICKNET_RUNTIME_INTERNAL_H
#define FLICKNET_RUNTIME_INTERNAL_H

#include "flicknet/runtime.h"

#include <stddef.h>

typedef enum {
  FN_COMPILED_DIRECT = 0,
  FN_COMPILED_PROXY,
  FN_COMPILED_REJECT
} fn_compiled_target_kind_t;

typedef struct {
  fn_compiled_target_kind_t kind;
  fn_object_ref_t object;
} fn_compiled_rule_t;

size_t fn_runtime_internal_rule_count(const fn_runtime_t *runtime);
fn_result_t fn_runtime_internal_rule_get(const fn_runtime_t *runtime,
                                         size_t index,
                                         fn_compiled_rule_t *out);
fn_result_t fn_runtime_internal_validate_kind(
  const fn_runtime_t *runtime, fn_object_ref_t object,
  fn_runtime_resource_kind_t kind);
fn_result_t fn_runtime_internal_find_kind(
  const fn_runtime_t *runtime, fn_runtime_resource_kind_t kind,
  fn_object_ref_t *out);

#endif
