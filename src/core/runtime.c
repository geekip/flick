#include "flicknet/runtime.h"

#include "flicknet/clock.h"
#include "runtime_internal.h"

#include <limits.h>
#include <string.h>

typedef struct fn_runtime_service fn_runtime_service_t;

struct fn_runtime_service {
  fn_runtime_resource_state_t state;
  void *resource;
  fn_runtime_acquire_t *waiter_head;
  fn_runtime_acquire_t *waiter_tail;
  size_t waiter_count;
  fn_result_t last_result;
  uint64_t retry_after_ms;
  uint64_t failure_epoch;
  uint32_t consecutive_failures;
  bool start_holds_reference;
};

struct fn_runtime {
  fn_runtime_manager_t *manager;
  fn_runtime_t *retained_next;
  fn_runtime_resource_descriptor_t *objects;
  fn_runtime_service_t *services;
  fn_compiled_rule_t *rules;
  fn_feature_plan_t plan;
  uint64_t generation;
  size_t object_count;
  size_t rule_count;
  size_t accounted_bytes;
  size_t reference_count;
  fn_budget_class_t budget_class;
  bool retained;
};

struct fn_runtime_candidate {
  fn_runtime_manager_t *manager;
  fn_runtime_t *runtime;
  uint64_t base_generation;
  size_t accounted_bytes;
  bool prepared;
};

struct fn_runtime_acquire {
  fn_runtime_t *runtime;
  fn_runtime_acquire_t *next;
  fn_completion_ticket_t *ticket;
  fn_timer_t *timer;
  fn_runtime_acquire_callback_fn callback;
  void *context;
  void *resource;
  fn_result_t result;
  size_t object_index;
  bool waiting;
  bool queued;
  bool callback_started;
};

struct fn_runtime_manager {
  fn_loop_t *loop;
  fn_budget_t *owned_memory;
  fn_allocator_t allocator;
  fn_runtime_resource_ops_t resources;
  fn_limits_t limits;
  fn_runtime_t *active;
  fn_runtime_t *retained_head;
  uint64_t next_generation;
  size_t accounted_bytes;
  size_t candidate_count;
  size_t retained_count;
  size_t async_operation_count;
  size_t lazy_waiter_count;
  size_t lazy_waiter_bytes;
};

static fn_result_t runtime_result(fn_status_t code, fn_error_stage_t stage)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE : stage,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static bool resource_kind_valid(fn_runtime_resource_kind_t kind)
{
  return (int)kind >= (int)FN_RUNTIME_RESOURCE_LISTENER &&
         (int)kind <= (int)FN_RUNTIME_RESOURCE_RESOLVER;
}

static bool manager_is_owner(const fn_runtime_manager_t *manager)
{
  return manager != NULL && fn_loop_is_owner(manager->loop);
}

static fn_result_t manager_allocate(fn_runtime_manager_t *manager,
                                    fn_budget_class_t budget_class,
                                    size_t size, void **out)
{
  fn_result_t result;
  void *memory;

  if (out == NULL) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  *out = NULL;
  result = fn_budget_reserve(manager->owned_memory, budget_class, size);
  if (result.code != FN_OK) {
    return result;
  }
  memory = manager->allocator.allocate(manager->allocator.context, size);
  if (memory == NULL) {
    (void)fn_budget_release(manager->owned_memory, budget_class, size);
    return runtime_result(FN_NO_MEMORY, FN_STAGE_RESOURCE);
  }
  memset(memory, 0, size);
  *out = memory;
  return runtime_result(FN_OK, FN_STAGE_NONE);
}

static void manager_deallocate(fn_runtime_manager_t *manager,
                               fn_budget_class_t budget_class,
                               size_t size, void *memory)
{
  if (memory == NULL) {
    return;
  }
  manager->allocator.deallocate(manager->allocator.context, memory);
  (void)fn_budget_release(manager->owned_memory, budget_class, size);
}

static fn_result_t runtime_allocate_piece(fn_runtime_t *runtime, size_t size,
                                          void **out)
{
  fn_result_t result = manager_allocate(runtime->manager,
                                        runtime->budget_class, size, out);
  if (result.code == FN_OK) {
    runtime->accounted_bytes += size;
  }
  return result;
}

static void runtime_release_resources(fn_runtime_t *runtime)
{
  size_t index;

  if (runtime->services == NULL || runtime->objects == NULL) {
    return;
  }
  for (index = runtime->object_count; index > 0; index--) {
    fn_runtime_service_t *service = &runtime->services[index - 1u];
    if (service->resource != NULL) {
      runtime->manager->resources.release(
        runtime->manager->resources.context, &runtime->objects[index - 1u],
        service->resource);
      service->resource = NULL;
    }
  }
}

static void runtime_destroy_storage(fn_runtime_t *runtime)
{
  fn_runtime_manager_t *manager;
  fn_budget_class_t budget_class;
  size_t accounted_bytes;

  if (runtime == NULL) {
    return;
  }
  manager = runtime->manager;
  budget_class = runtime->budget_class;
  accounted_bytes = runtime->accounted_bytes;
  runtime_release_resources(runtime);
  if (runtime->rules != NULL) {
    manager->allocator.deallocate(manager->allocator.context, runtime->rules);
  }
  if (runtime->services != NULL) {
    manager->allocator.deallocate(manager->allocator.context,
                                  runtime->services);
  }
  if (runtime->objects != NULL) {
    memset(runtime->objects, 0,
           runtime->object_count * sizeof(*runtime->objects));
    manager->allocator.deallocate(manager->allocator.context,
                                  runtime->objects);
  }
  manager->allocator.deallocate(manager->allocator.context, runtime);
  (void)fn_budget_release(manager->owned_memory, budget_class,
                          accounted_bytes);
}

static const fn_proxy_config_t *config_find_proxy(const fn_config_t *config,
                                                   const char *name,
                                                   size_t *out_index)
{
  size_t index;
  for (index = 0; index < config->proxy_count; index++) {
    if (strcmp(config->proxies[index].name, name) == 0) {
      if (out_index != NULL) {
        *out_index = index;
      }
      return &config->proxies[index];
    }
  }
  return NULL;
}

static bool earlier_rule_uses_proxy(const fn_config_t *config,
                                    size_t rule_index, const char *name)
{
  size_t index;
  for (index = 0; index < rule_index; index++) {
    if (strcmp(config->rules[index].target, name) == 0) {
      return true;
    }
  }
  return false;
}

static fn_result_t count_runtime_objects(const fn_config_t *config,
                                         const fn_feature_plan_t *plan,
                                         size_t *out_count)
{
  size_t count = config->inbound_count;
  size_t index;
  bool direct = false;

  for (index = 0; index < config->rule_count; index++) {
    const char *target = config->rules[index].target;
    if (strcmp(target, "DIRECT") == 0) {
      direct = true;
    } else if (strcmp(target, "REJECT") != 0 &&
               !earlier_rule_uses_proxy(config, index, target)) {
      if (config_find_proxy(config, target, NULL) == NULL ||
          !fn_size_add(count, 1u, &count)) {
        return runtime_result(FN_INVALID, FN_STAGE_PLAN);
      }
    }
  }
  if (direct && !fn_size_add(count, 1u, &count)) {
    return runtime_result(FN_LIMIT, FN_STAGE_PLAN);
  }
  if ((plan->reachable & FN_FEATURE_DNS_RESOLVER) != 0 &&
      !fn_size_add(count, 1u, &count)) {
    return runtime_result(FN_LIMIT, FN_STAGE_PLAN);
  }
  if (count > UINT32_MAX) {
    return runtime_result(FN_LIMIT, FN_STAGE_PLAN);
  }
  *out_count = count;
  return runtime_result(FN_OK, FN_STAGE_NONE);
}

static fn_runtime_resource_descriptor_t *append_object(
  fn_runtime_t *runtime, size_t *index, fn_runtime_resource_kind_t kind,
  size_t config_index, const char *name)
{
  fn_runtime_resource_descriptor_t *descriptor = &runtime->objects[*index];
  descriptor->id.generation = runtime->generation;
  descriptor->id.index = (uint32_t)*index;
  descriptor->kind = kind;
  descriptor->config_index = config_index;
  memcpy(descriptor->name, name, strlen(name) + 1u);
  runtime->services[*index].state = FN_RUNTIME_DORMANT;
  runtime->services[*index].last_result =
    runtime_result(FN_OK, FN_STAGE_NONE);
  (*index)++;
  return descriptor;
}

static fn_result_t compile_runtime(fn_runtime_candidate_t *candidate,
                                   const fn_config_t *config,
                                   const fn_feature_plan_t *plan)
{
  fn_runtime_manager_t *manager = candidate->manager;
  fn_runtime_t *runtime = NULL;
  fn_result_t result;
  size_t object_count = 0;
  size_t object_bytes;
  size_t service_bytes;
  size_t rule_bytes;
  size_t object_index = 0;
  size_t index;
  bool direct_added = false;

  result = count_runtime_objects(config, plan, &object_count);
  if (result.code != FN_OK) {
    return result;
  }
  if (!fn_size_multiply(object_count, sizeof(*runtime->objects),
                        &object_bytes) ||
      !fn_size_multiply(object_count, sizeof(*runtime->services),
                        &service_bytes) ||
      !fn_size_multiply(config->rule_count, sizeof(*runtime->rules),
                        &rule_bytes)) {
    return runtime_result(FN_LIMIT, FN_STAGE_PLAN);
  }
  result = manager_allocate(manager, FN_BUDGET_CANDIDATE, sizeof(*runtime),
                            (void **)&runtime);
  if (result.code != FN_OK) {
    return result;
  }
  runtime->manager = manager;
  runtime->generation = manager->next_generation;
  runtime->plan = *plan;
  runtime->object_count = object_count;
  runtime->rule_count = config->rule_count;
  runtime->budget_class = FN_BUDGET_CANDIDATE;
  runtime->accounted_bytes = sizeof(*runtime);

  if (object_bytes != 0) {
    result = runtime_allocate_piece(runtime, object_bytes,
                                    (void **)&runtime->objects);
    if (result.code != FN_OK) {
      runtime_destroy_storage(runtime);
      return result;
    }
    result = runtime_allocate_piece(runtime, service_bytes,
                                    (void **)&runtime->services);
    if (result.code != FN_OK) {
      runtime_destroy_storage(runtime);
      return result;
    }
  }
  if (rule_bytes != 0) {
    result = runtime_allocate_piece(runtime, rule_bytes,
                                    (void **)&runtime->rules);
    if (result.code != FN_OK) {
      runtime_destroy_storage(runtime);
      return result;
    }
  }

  for (index = 0; index < config->inbound_count; index++) {
    fn_runtime_resource_descriptor_t *descriptor = append_object(
      runtime, &object_index, FN_RUNTIME_RESOURCE_LISTENER, index,
      config->inbounds[index].name);
    descriptor->endpoint.address = config->inbounds[index].listen;
    descriptor->endpoint.port = config->inbounds[index].port;
    descriptor->planned_prepare = true;
  }
  for (index = 0; index < config->rule_count; index++) {
    const char *target = config->rules[index].target;
    if (strcmp(target, "DIRECT") == 0 && !direct_added) {
      fn_runtime_resource_descriptor_t *descriptor = append_object(
        runtime, &object_index, FN_RUNTIME_RESOURCE_DIRECT, 0u, "DIRECT");
      descriptor->planned_lazy =
        (plan->lazy & FN_FEATURE_DIRECT_TCP) != 0;
      direct_added = true;
    } else if (strcmp(target, "DIRECT") != 0 &&
               strcmp(target, "REJECT") != 0 &&
               !earlier_rule_uses_proxy(config, index, target)) {
      size_t proxy_index;
      const fn_proxy_config_t *proxy = config_find_proxy(
        config, target, &proxy_index);
      fn_runtime_resource_descriptor_t *descriptor;
      if (proxy == NULL) {
        runtime_destroy_storage(runtime);
        return runtime_result(FN_INVALID, FN_STAGE_PLAN);
      }
      descriptor = append_object(runtime, &object_index,
                                 FN_RUNTIME_RESOURCE_SOCKS_PROXY,
                                 proxy_index, proxy->name);
      descriptor->endpoint.address = proxy->server;
      descriptor->endpoint.port = proxy->port;
      descriptor->has_credentials = proxy->has_credentials;
      if (proxy->has_credentials) {
        descriptor->credentials = proxy->credentials;
      }
      descriptor->planned_lazy =
        (plan->lazy & FN_FEATURE_SOCKS_OUT_TCP) != 0;
    }
  }
  if ((plan->reachable & FN_FEATURE_DNS_RESOLVER) != 0) {
    fn_runtime_resource_descriptor_t *descriptor = append_object(
      runtime, &object_index, FN_RUNTIME_RESOURCE_RESOLVER, 0u, "$resolver");
    descriptor->planned_lazy =
      (plan->lazy & FN_FEATURE_DNS_RESOLVER) != 0;
  }
  if (object_index != object_count) {
    runtime_destroy_storage(runtime);
    return runtime_result(FN_INVALID, FN_STAGE_PLAN);
  }

  for (index = 0; index < config->rule_count; index++) {
    const char *target = config->rules[index].target;
    if (strcmp(target, "DIRECT") == 0) {
      runtime->rules[index].kind = FN_COMPILED_DIRECT;
      result = fn_runtime_object_find(runtime, FN_RUNTIME_RESOURCE_DIRECT,
                                      "DIRECT",
                                      &runtime->rules[index].object);
    } else if (strcmp(target, "REJECT") == 0) {
      runtime->rules[index].kind = FN_COMPILED_REJECT;
      runtime->rules[index].object.generation = runtime->generation;
      runtime->rules[index].object.index = FN_ID_NONE;
      result = runtime_result(FN_OK, FN_STAGE_NONE);
    } else {
      runtime->rules[index].kind = FN_COMPILED_PROXY;
      result = fn_runtime_object_find(runtime,
                                      FN_RUNTIME_RESOURCE_SOCKS_PROXY,
                                      target,
                                      &runtime->rules[index].object);
    }
    if (result.code != FN_OK) {
      runtime_destroy_storage(runtime);
      return runtime_result(FN_INVALID, FN_STAGE_PLAN);
    }
  }
  candidate->runtime = runtime;
  return runtime_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_runtime_manager_create(
  const fn_runtime_manager_options_t *options, fn_runtime_manager_t **out)
{
  fn_runtime_manager_t *manager;
  fn_result_t result;

  if (out == NULL) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  *out = NULL;
  if (options == NULL || options->loop == NULL || options->limits == NULL ||
      options->owned_memory == NULL ||
      options->allocator.allocate == NULL ||
      options->allocator.deallocate == NULL ||
      !fn_loop_is_owner(options->loop) ||
      ((options->resources.prepare != NULL ||
        options->resources.lazy_start != NULL) &&
       options->resources.release == NULL)) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
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
    return runtime_result(FN_NO_MEMORY, FN_STAGE_RESOURCE);
  }
  memset(manager, 0, sizeof(*manager));
  manager->loop = options->loop;
  manager->owned_memory = options->owned_memory;
  manager->allocator = options->allocator;
  manager->resources = options->resources;
  manager->limits = *options->limits;
  manager->next_generation = UINT64_C(1);
  manager->accounted_bytes = sizeof(*manager);
  *out = manager;
  return runtime_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_runtime_manager_destroy(fn_runtime_manager_t **manager_pointer)
{
  fn_runtime_manager_t *manager;
  fn_budget_t *budget;
  fn_allocator_t allocator;
  size_t accounted_bytes;

  if (manager_pointer == NULL) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  manager = *manager_pointer;
  if (manager == NULL) {
    return runtime_result(FN_OK, FN_STAGE_NONE);
  }
  if (!manager_is_owner(manager) || manager->candidate_count != 0 ||
      manager->retained_count != 0 || manager->async_operation_count != 0 ||
      (manager->active != NULL && manager->active->reference_count != 1u)) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  if (manager->active != NULL) {
    runtime_destroy_storage(manager->active);
    manager->active = NULL;
  }
  budget = manager->owned_memory;
  allocator = manager->allocator;
  accounted_bytes = manager->accounted_bytes;
  allocator.deallocate(allocator.context, manager);
  (void)fn_budget_release(budget, FN_BUDGET_ACTIVE, accounted_bytes);
  *manager_pointer = NULL;
  return runtime_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_runtime_manager_snapshot(
  const fn_runtime_manager_t *manager, fn_runtime_manager_snapshot_t *out)
{
  if (!manager_is_owner(manager) || out == NULL) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  memset(out, 0, sizeof(*out));
  if (manager->active != NULL) {
    out->active_generation = manager->active->generation;
  }
  out->candidates = manager->candidate_count;
  out->retained_runtimes = manager->retained_count;
  out->async_operations = manager->async_operation_count;
  out->lazy_waiters = manager->lazy_waiter_count;
  out->lazy_waiter_bytes = manager->lazy_waiter_bytes;
  return runtime_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_runtime_candidate_build(
  fn_runtime_manager_t *manager, const fn_config_t *config,
  const fn_feature_plan_t *plan, fn_runtime_candidate_t **out)
{
  fn_runtime_candidate_t *candidate;
  fn_result_t result;
  uint64_t base_generation = 0;

  if (out == NULL) {
    return runtime_result(FN_INVALID, FN_STAGE_PLAN);
  }
  *out = NULL;
  if (!manager_is_owner(manager) || config == NULL || plan == NULL ||
      (config->inbound_count != 0 && config->inbounds == NULL) ||
      (config->proxy_count != 0 && config->proxies == NULL) ||
      (config->rule_count != 0 && config->rules == NULL) ||
      ((plan->prepare | plan->lazy) & ~plan->reachable) != 0 ||
      manager->next_generation == UINT64_MAX) {
    return runtime_result(FN_INVALID, FN_STAGE_PLAN);
  }
  result = manager_allocate(manager, FN_BUDGET_CANDIDATE,
                            sizeof(*candidate), (void **)&candidate);
  if (result.code != FN_OK) {
    return result;
  }
  candidate->manager = manager;
  candidate->accounted_bytes = sizeof(*candidate);
  if (manager->active != NULL) {
    base_generation = manager->active->generation;
  }
  candidate->base_generation = base_generation;
  result = compile_runtime(candidate, config, plan);
  if (result.code != FN_OK) {
    manager_deallocate(manager, FN_BUDGET_CANDIDATE,
                       candidate->accounted_bytes, candidate);
    return result;
  }
  manager->next_generation++;
  manager->candidate_count++;
  *out = candidate;
  return runtime_result(FN_OK, FN_STAGE_NONE);
}

static bool runtime_requires_prepare(const fn_runtime_t *runtime)
{
  size_t index;
  for (index = 0; index < runtime->object_count; index++) {
    if (runtime->objects[index].planned_prepare) {
      return true;
    }
  }
  return false;
}

fn_result_t fn_runtime_candidate_prepare(fn_runtime_candidate_t *candidate)
{
  fn_runtime_t *runtime;
  fn_runtime_manager_t *manager;
  size_t index;

  if (candidate == NULL || !manager_is_owner(candidate->manager) ||
      candidate->runtime == NULL) {
    return runtime_result(FN_INVALID, FN_STAGE_PREPARE);
  }
  if (candidate->prepared) {
    return runtime_result(FN_OK, FN_STAGE_NONE);
  }
  runtime = candidate->runtime;
  manager = candidate->manager;
  if (runtime_requires_prepare(runtime) &&
      manager->resources.prepare == NULL) {
    return runtime_result(FN_FEATURE_UNAVAILABLE, FN_STAGE_PREPARE);
  }
  for (index = 0; index < runtime->object_count; index++) {
    fn_runtime_service_t *service = &runtime->services[index];
    fn_result_t result;
    void *resource = NULL;
    if (!runtime->objects[index].planned_prepare) {
      continue;
    }
    result = manager->resources.prepare(manager->resources.context,
                                        &runtime->objects[index], &resource);
    if (result.code != FN_OK || resource == NULL) {
      if (resource != NULL) {
        manager->resources.release(manager->resources.context,
                                   &runtime->objects[index], resource);
      }
      while (index > 0) {
        index--;
        service = &runtime->services[index];
        if (service->resource != NULL) {
          manager->resources.release(manager->resources.context,
                                     &runtime->objects[index],
                                     service->resource);
          service->resource = NULL;
          service->state = FN_RUNTIME_DORMANT;
        }
      }
      return result.code == FN_OK ?
        runtime_result(FN_INVALID, FN_STAGE_PREPARE) : result;
    }
    service->resource = resource;
    service->state = FN_RUNTIME_READY;
  }
  candidate->prepared = true;
  return runtime_result(FN_OK, FN_STAGE_NONE);
}

static void retained_remove(fn_runtime_manager_t *manager,
                            fn_runtime_t *runtime)
{
  fn_runtime_t **cursor = &manager->retained_head;
  while (*cursor != NULL && *cursor != runtime) {
    cursor = &(*cursor)->retained_next;
  }
  if (*cursor == runtime) {
    *cursor = runtime->retained_next;
    runtime->retained_next = NULL;
    manager->retained_count--;
  }
}

fn_result_t fn_runtime_candidate_commit(
  fn_runtime_manager_t *manager, fn_runtime_candidate_t **candidate_pointer)
{
  fn_runtime_candidate_t *candidate;
  fn_runtime_t *runtime;
  fn_runtime_t *old;
  uint64_t active_generation = 0;
  bool retain_old;
  fn_result_t result;

  if (candidate_pointer == NULL || *candidate_pointer == NULL ||
      !manager_is_owner(manager)) {
    return runtime_result(FN_INVALID, FN_STAGE_PREPARE);
  }
  candidate = *candidate_pointer;
  if (candidate->manager != manager || candidate->runtime == NULL) {
    return runtime_result(FN_INVALID, FN_STAGE_PREPARE);
  }
  runtime = candidate->runtime;
  old = manager->active;
  if (old != NULL) {
    active_generation = old->generation;
  }
  if (candidate->base_generation != active_generation) {
    return runtime_result(FN_STALE_GENERATION, FN_STAGE_PREPARE);
  }
  if (runtime_requires_prepare(runtime) && !candidate->prepared) {
    return runtime_result(FN_INVALID, FN_STAGE_PREPARE);
  }
  retain_old = old != NULL && old->reference_count > 1u;
  if (retain_old && manager->retained_count >=
                    manager->limits.retired_runtime_limit) {
    return runtime_result(FN_LIMIT, FN_STAGE_RESOURCE);
  }

  result = fn_budget_reclassify(manager->owned_memory, FN_BUDGET_CANDIDATE,
                                FN_BUDGET_ACTIVE,
                                runtime->accounted_bytes);
  if (result.code != FN_OK) {
    return result;
  }
  if (retain_old) {
    result = fn_budget_reclassify(manager->owned_memory, FN_BUDGET_ACTIVE,
                                  FN_BUDGET_RETAINED,
                                  old->accounted_bytes);
    if (result.code != FN_OK) {
      (void)fn_budget_reclassify(manager->owned_memory, FN_BUDGET_ACTIVE,
                                 FN_BUDGET_CANDIDATE,
                                 runtime->accounted_bytes);
      return result;
    }
  }

  runtime->budget_class = FN_BUDGET_ACTIVE;
  runtime->reference_count = 1u;
  manager->active = runtime;
  candidate->runtime = NULL;
  manager->candidate_count--;
  manager_deallocate(manager, FN_BUDGET_CANDIDATE,
                     candidate->accounted_bytes, candidate);
  *candidate_pointer = NULL;

  if (retain_old) {
    old->budget_class = FN_BUDGET_RETAINED;
    old->retained = true;
    old->retained_next = manager->retained_head;
    manager->retained_head = old;
    manager->retained_count++;
  } else if (old != NULL) {
    runtime_destroy_storage(old);
  }
  return runtime_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_runtime_candidate_destroy(fn_runtime_candidate_t **pointer)
{
  fn_runtime_candidate_t *candidate;
  fn_runtime_manager_t *manager;

  if (pointer == NULL) {
    return runtime_result(FN_INVALID, FN_STAGE_PREPARE);
  }
  candidate = *pointer;
  if (candidate == NULL) {
    return runtime_result(FN_OK, FN_STAGE_NONE);
  }
  manager = candidate->manager;
  if (!manager_is_owner(manager)) {
    return runtime_result(FN_INVALID, FN_STAGE_PREPARE);
  }
  runtime_destroy_storage(candidate->runtime);
  manager->candidate_count--;
  manager_deallocate(manager, FN_BUDGET_CANDIDATE,
                     candidate->accounted_bytes, candidate);
  *pointer = NULL;
  return runtime_result(FN_OK, FN_STAGE_NONE);
}

uint64_t fn_runtime_generation(const fn_runtime_t *runtime)
{
  return runtime == NULL ? UINT64_C(0) : runtime->generation;
}

fn_feature_plan_t fn_runtime_feature_plan(const fn_runtime_t *runtime)
{
  fn_feature_plan_t plan;
  memset(&plan, 0, sizeof(plan));
  if (runtime != NULL) {
    plan = runtime->plan;
  }
  return plan;
}

size_t fn_runtime_object_count(const fn_runtime_t *runtime)
{
  return runtime == NULL ? 0u : runtime->object_count;
}

fn_result_t fn_runtime_object_get(
  const fn_runtime_t *runtime, fn_object_ref_t object,
  const fn_runtime_resource_descriptor_t **out)
{
  if (out == NULL) {
    return runtime_result(FN_INVALID, FN_STAGE_ROUTE);
  }
  *out = NULL;
  if (runtime == NULL || object.generation != runtime->generation) {
    return runtime_result(FN_STALE_GENERATION, FN_STAGE_ROUTE);
  }
  if (object.index == FN_ID_NONE || object.index >= runtime->object_count) {
    return runtime_result(FN_INVALID, FN_STAGE_ROUTE);
  }
  *out = &runtime->objects[object.index];
  return runtime_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_runtime_object_find(
  const fn_runtime_t *runtime, fn_runtime_resource_kind_t kind,
  const char *name, fn_object_ref_t *out)
{
  size_t index;
  if (out == NULL) {
    return runtime_result(FN_INVALID, FN_STAGE_ROUTE);
  }
  out->generation = 0;
  out->index = FN_ID_NONE;
  if (runtime == NULL || !resource_kind_valid(kind) || name == NULL) {
    return runtime_result(FN_INVALID, FN_STAGE_ROUTE);
  }
  for (index = 0; index < runtime->object_count; index++) {
    if (runtime->objects[index].kind == kind &&
        strcmp(runtime->objects[index].name, name) == 0) {
      *out = runtime->objects[index].id;
      return runtime_result(FN_OK, FN_STAGE_NONE);
    }
  }
  return runtime_result(FN_INVALID, FN_STAGE_ROUTE);
}

fn_result_t fn_runtime_resource_snapshot(
  const fn_runtime_t *runtime, fn_object_ref_t object,
  fn_runtime_resource_snapshot_t *out)
{
  const fn_runtime_resource_descriptor_t *descriptor;
  const fn_runtime_service_t *service;
  fn_result_t result;
  if (out == NULL || runtime == NULL ||
      !manager_is_owner(runtime->manager)) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  result = fn_runtime_object_get(runtime, object, &descriptor);
  if (result.code != FN_OK) {
    return result;
  }
  (void)descriptor;
  service = &runtime->services[object.index];
  memset(out, 0, sizeof(*out));
  out->state = service->state;
  out->waiters = service->waiter_count;
  out->last_result = service->last_result;
  out->retry_after_ms = service->retry_after_ms;
  out->consecutive_failures = service->consecutive_failures;
  out->has_resource = service->resource != NULL;
  return runtime_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_runtime_acquire_active(fn_runtime_manager_t *manager,
                                      fn_runtime_t **out)
{
  if (out == NULL) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  *out = NULL;
  if (!manager_is_owner(manager) || manager->active == NULL ||
      manager->active->reference_count == SIZE_MAX) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  manager->active->reference_count++;
  *out = manager->active;
  return runtime_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_runtime_retain(fn_runtime_t *runtime)
{
  if (runtime == NULL || !manager_is_owner(runtime->manager) ||
      runtime->reference_count == 0 || runtime->reference_count == SIZE_MAX) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  runtime->reference_count++;
  return runtime_result(FN_OK, FN_STAGE_NONE);
}

static fn_result_t runtime_drop_reference(fn_runtime_t *runtime)
{
  fn_runtime_manager_t *manager = runtime->manager;
  if (runtime->reference_count <= 1u) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  runtime->reference_count--;
  if (runtime->retained && runtime->reference_count == 1u) {
    retained_remove(manager, runtime);
    runtime_destroy_storage(runtime);
  }
  return runtime_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_runtime_release(fn_runtime_t **runtime_pointer)
{
  fn_runtime_t *runtime;
  fn_result_t result;
  if (runtime_pointer == NULL) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  runtime = *runtime_pointer;
  if (runtime == NULL) {
    return runtime_result(FN_OK, FN_STAGE_NONE);
  }
  if (!manager_is_owner(runtime->manager)) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  result = runtime_drop_reference(runtime);
  if (result.code == FN_OK) {
    *runtime_pointer = NULL;
  }
  return result;
}

static void waiter_append(fn_runtime_service_t *service,
                          fn_runtime_acquire_t *operation)
{
  operation->next = NULL;
  if (service->waiter_tail == NULL) {
    service->waiter_head = operation;
  } else {
    service->waiter_tail->next = operation;
  }
  service->waiter_tail = operation;
  service->waiter_count++;
  operation->waiting = true;
}

static bool waiter_remove(fn_runtime_service_t *service,
                          fn_runtime_acquire_t *operation)
{
  fn_runtime_acquire_t **cursor = &service->waiter_head;
  fn_runtime_acquire_t *previous = NULL;
  while (*cursor != NULL && *cursor != operation) {
    previous = *cursor;
    cursor = &(*cursor)->next;
  }
  if (*cursor == NULL) {
    return false;
  }
  *cursor = operation->next;
  if (service->waiter_tail == operation) {
    service->waiter_tail = previous;
  }
  operation->next = NULL;
  operation->waiting = false;
  service->waiter_count--;
  return true;
}

static void waiter_account_add(fn_runtime_acquire_t *operation)
{
  fn_runtime_manager_t *manager = operation->runtime->manager;
  manager->lazy_waiter_count++;
  manager->lazy_waiter_bytes += sizeof(*operation);
}

static void waiter_account_remove(fn_runtime_acquire_t *operation)
{
  fn_runtime_manager_t *manager = operation->runtime->manager;
  manager->lazy_waiter_count--;
  manager->lazy_waiter_bytes -= sizeof(*operation);
}

static void acquire_completion(void *context, fn_result_t ignored)
{
  fn_runtime_acquire_t *operation = context;
  fn_runtime_t *runtime = operation->runtime;
  const fn_runtime_resource_descriptor_t *descriptor =
    &runtime->objects[operation->object_index];
  fn_runtime_acquire_callback_fn callback = operation->callback;
  void *callback_context = operation->context;
  fn_result_t result = operation->result;
  void *resource = operation->resource;
  (void)ignored;
  operation->callback_started = true;
  callback(operation, callback_context, result, descriptor, resource);
}

static fn_result_t queue_acquire(fn_runtime_acquire_t *operation,
                                 fn_result_t result, void *resource)
{
  fn_result_t publish_result;
  if (operation->timer != NULL) {
    publish_result = fn_timer_destroy(&operation->timer);
    if (publish_result.code != FN_OK) {
      return publish_result;
    }
  }
  operation->result = result;
  operation->resource = resource;
  operation->queued = true;
  publish_result = fn_completion_publish(&operation->ticket, result,
                                         acquire_completion, operation);
  if (publish_result.code != FN_OK) {
    operation->queued = false;
  }
  return publish_result;
}

static void acquire_timeout(fn_timer_t *timer, void *context)
{
  fn_runtime_acquire_t *operation = context;
  fn_runtime_t *runtime = operation->runtime;
  fn_runtime_service_t *service =
    &runtime->services[operation->object_index];
  (void)timer;
  (void)fn_timer_destroy(&operation->timer);
  if (operation->waiting && waiter_remove(service, operation)) {
    waiter_account_remove(operation);
    (void)queue_acquire(operation,
                        runtime_result(FN_TIMEOUT, FN_STAGE_RESOURCE), NULL);
  }
}

static bool retry_allowed(fn_runtime_t *runtime,
                          fn_runtime_service_t *service, uint64_t now_ms)
{
  switch (service->last_result.code) {
    case FN_IO_ERROR:
    case FN_TIMEOUT:
    case FN_RESOLVE_ERROR:
    case FN_CONNECT_ERROR:
    case FN_CONNECTION_REFUSED:
      return now_ms >= service->retry_after_ms;
    case FN_LIMIT:
    case FN_NO_MEMORY:
      return runtime->manager->owned_memory->epoch != service->failure_epoch;
    default:
      return false;
  }
}

static fn_result_t acquire_allocate(fn_runtime_t *runtime, size_t object_index,
                                    fn_runtime_acquire_callback_fn callback,
                                    void *context,
                                    fn_runtime_acquire_t **out)
{
  fn_runtime_manager_t *manager = runtime->manager;
  fn_runtime_acquire_t *operation = NULL;
  fn_completion_ticket_t *ticket = NULL;
  fn_result_t result;

  if (manager->async_operation_count >= manager->limits.async_operation_limit) {
    return runtime_result(FN_LIMIT, FN_STAGE_RESOURCE);
  }
  result = fn_completion_reserve_terminal(manager->loop, &ticket);
  if (result.code != FN_OK) {
    return result;
  }
  result = manager_allocate(manager, FN_BUDGET_ACTIVE, sizeof(*operation),
                            (void **)&operation);
  if (result.code != FN_OK) {
    (void)fn_completion_abandon(&ticket);
    return result;
  }
  operation->runtime = runtime;
  operation->ticket = ticket;
  operation->callback = callback;
  operation->context = context;
  operation->object_index = object_index;
  runtime->reference_count++;
  manager->async_operation_count++;
  *out = operation;
  return runtime_result(FN_OK, FN_STAGE_NONE);
}

static void acquire_rollback(fn_runtime_acquire_t *operation)
{
  fn_runtime_t *runtime = operation->runtime;
  fn_runtime_manager_t *manager = runtime->manager;
  if (operation->timer != NULL) {
    (void)fn_timer_destroy(&operation->timer);
  }
  (void)fn_completion_abandon(&operation->ticket);
  manager->async_operation_count--;
  manager_deallocate(manager, FN_BUDGET_ACTIVE, sizeof(*operation), operation);
  (void)runtime_drop_reference(runtime);
}

fn_result_t fn_runtime_acquire(
  fn_runtime_t *runtime, fn_object_ref_t object, uint64_t deadline_ms,
  fn_runtime_acquire_callback_fn callback, void *context,
  fn_runtime_acquire_t **out)
{
  fn_runtime_manager_t *manager;
  fn_runtime_service_t *service;
  const fn_runtime_resource_descriptor_t *descriptor;
  fn_runtime_acquire_t *operation = NULL;
  fn_result_t result;
  uint64_t now_ms;
  uint64_t wait_deadline;
  uint64_t local_deadline;
  bool start = false;

  if (out == NULL) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  *out = NULL;
  if (runtime == NULL || callback == NULL ||
      !manager_is_owner(runtime->manager)) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  manager = runtime->manager;
  result = fn_runtime_object_get(runtime, object, &descriptor);
  if (result.code != FN_OK) {
    return result;
  }
  result = fn_monotonic_now_ms(&now_ms);
  if (result.code != FN_OK) {
    return result;
  }
  if (deadline_ms <= now_ms) {
    return runtime_result(FN_TIMEOUT, FN_STAGE_RESOURCE);
  }
  service = &runtime->services[object.index];
  if (service->state == FN_RUNTIME_DORMANT && !descriptor->planned_lazy) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  if (service->state == FN_RUNTIME_DRAINING) {
    return runtime_result(FN_STALE_GENERATION, FN_STAGE_RESOURCE);
  }
  result = acquire_allocate(runtime, object.index, callback, context,
                            &operation);
  if (result.code != FN_OK) {
    return result;
  }

  if (service->state == FN_RUNTIME_READY) {
    result = queue_acquire(operation, runtime_result(FN_OK, FN_STAGE_NONE),
                           service->resource);
    if (result.code != FN_OK) {
      acquire_rollback(operation);
      return result;
    }
    *out = operation;
    return runtime_result(FN_OK, FN_STAGE_NONE);
  }
  if (service->state == FN_RUNTIME_FAILED &&
      !retry_allowed(runtime, service, now_ms)) {
    result = queue_acquire(operation, service->last_result, NULL);
    if (result.code != FN_OK) {
      acquire_rollback(operation);
      return result;
    }
    *out = operation;
    return runtime_result(FN_OK, FN_STAGE_NONE);
  }

  if (manager->lazy_waiter_count >= manager->limits.lazy_waiter_limit ||
      service->waiter_count >= manager->limits.lazy_waiter_per_object_limit ||
      sizeof(*operation) > manager->limits.lazy_waiter_limit_bytes -
                           manager->lazy_waiter_bytes) {
    acquire_rollback(operation);
    return runtime_result(FN_LIMIT, FN_STAGE_RESOURCE);
  }
  local_deadline = now_ms;
  if (manager->limits.resource_wait_timeout_ms > UINT64_MAX - now_ms) {
    local_deadline = UINT64_MAX;
  } else {
    local_deadline += manager->limits.resource_wait_timeout_ms;
  }
  wait_deadline = fn_deadline_min(deadline_ms, local_deadline);
  result = fn_timer_start(manager->loop, wait_deadline, acquire_timeout,
                          operation, &operation->timer);
  if (result.code != FN_OK) {
    acquire_rollback(operation);
    return result;
  }
  waiter_append(service, operation);
  waiter_account_add(operation);

  if (service->state == FN_RUNTIME_DORMANT ||
      service->state == FN_RUNTIME_FAILED) {
    service->state = FN_RUNTIME_STARTING;
    service->start_holds_reference = true;
    runtime->reference_count++;
    start = true;
  }
  *out = operation;
  if (start) {
    fn_result_t start_result;
    if (manager->resources.lazy_start == NULL) {
      start_result = runtime_result(FN_FEATURE_UNAVAILABLE, FN_STAGE_PREPARE);
    } else {
      start_result = manager->resources.lazy_start(
        manager->resources.context, runtime, object);
    }
    if (start_result.code != FN_OK &&
        service->state == FN_RUNTIME_STARTING) {
      (void)fn_runtime_lazy_finish(runtime, object, start_result, NULL);
    }
  }
  return runtime_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_runtime_acquire_cancel(fn_runtime_acquire_t *operation)
{
  fn_runtime_t *runtime;
  fn_runtime_service_t *service;
  fn_result_t cancelled = runtime_result(FN_CANCELLED, FN_STAGE_RESOURCE);
  if (operation == NULL) {
    return runtime_result(FN_OK, FN_STAGE_NONE);
  }
  runtime = operation->runtime;
  if (!manager_is_owner(runtime->manager)) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  if (operation->callback_started) {
    return runtime_result(FN_OK, FN_STAGE_NONE);
  }
  if (operation->queued) {
    operation->result = cancelled;
    operation->resource = NULL;
    return runtime_result(FN_OK, FN_STAGE_NONE);
  }
  service = &runtime->services[operation->object_index];
  if (!operation->waiting || !waiter_remove(service, operation)) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  waiter_account_remove(operation);
  return queue_acquire(operation, cancelled, NULL);
}

fn_result_t fn_runtime_acquire_release(fn_runtime_acquire_t **pointer)
{
  fn_runtime_acquire_t *operation;
  fn_runtime_t *runtime;
  fn_runtime_manager_t *manager;
  if (pointer == NULL) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  operation = *pointer;
  if (operation == NULL) {
    return runtime_result(FN_OK, FN_STAGE_NONE);
  }
  runtime = operation->runtime;
  manager = runtime->manager;
  if (!manager_is_owner(manager) || !operation->callback_started ||
      operation->waiting || operation->ticket != NULL ||
      operation->timer != NULL) {
    return runtime_result(FN_INVALID, FN_STAGE_RESOURCE);
  }
  manager->async_operation_count--;
  manager_deallocate(manager, FN_BUDGET_ACTIVE, sizeof(*operation), operation);
  *pointer = NULL;
  return runtime_drop_reference(runtime);
}

static uint64_t retry_delay_ms(uint32_t failures)
{
  uint64_t delay = UINT64_C(1000);
  uint32_t index;
  for (index = 1u; index < failures && delay < UINT64_C(30000); index++) {
    delay *= UINT64_C(2);
  }
  return delay > UINT64_C(30000) ? UINT64_C(30000) : delay;
}

static void save_failure(fn_runtime_t *runtime,
                         fn_runtime_service_t *service,
                         fn_result_t result)
{
  uint64_t now_ms;
  service->last_result = result;
  service->failure_epoch = runtime->manager->owned_memory->epoch;
  service->retry_after_ms = UINT64_MAX;
  if (result.code == FN_IO_ERROR || result.code == FN_TIMEOUT ||
      result.code == FN_RESOLVE_ERROR || result.code == FN_CONNECT_ERROR ||
      result.code == FN_CONNECTION_REFUSED) {
    if (service->consecutive_failures != UINT32_MAX) {
      service->consecutive_failures++;
    }
    if (fn_monotonic_now_ms(&now_ms).code == FN_OK) {
      uint64_t delay = retry_delay_ms(service->consecutive_failures);
      service->retry_after_ms = delay > UINT64_MAX - now_ms ?
        UINT64_MAX : now_ms + delay;
    }
  }
}

fn_result_t fn_runtime_lazy_finish(fn_runtime_t *runtime,
                                   fn_object_ref_t object,
                                   fn_result_t result, void *resource)
{
  fn_runtime_manager_t *manager;
  fn_runtime_service_t *service;
  const fn_runtime_resource_descriptor_t *descriptor;
  fn_runtime_acquire_t *waiters;
  fn_runtime_acquire_t *operation;
  bool success;
  fn_result_t validation;

  if (runtime == NULL || !manager_is_owner(runtime->manager)) {
    return runtime_result(FN_INVALID, FN_STAGE_PREPARE);
  }
  manager = runtime->manager;
  validation = fn_runtime_object_get(runtime, object, &descriptor);
  if (validation.code != FN_OK) {
    return validation;
  }
  service = &runtime->services[object.index];
  if (service->state != FN_RUNTIME_STARTING ||
      !service->start_holds_reference ||
      (result.code == FN_OK && resource == NULL)) {
    return runtime_result(FN_INVALID, FN_STAGE_PREPARE);
  }
  success = result.code == FN_OK;
  if (!success && resource != NULL) {
    manager->resources.release(manager->resources.context, descriptor,
                               resource);
    resource = NULL;
  }
  waiters = service->waiter_head;
  service->waiter_head = NULL;
  service->waiter_tail = NULL;
  service->waiter_count = 0;
  for (operation = waiters; operation != NULL; operation = operation->next) {
    operation->waiting = false;
    waiter_account_remove(operation);
  }

  if (success && waiters == NULL && !descriptor->planned_prepare) {
    manager->resources.release(manager->resources.context, descriptor,
                               resource);
    resource = NULL;
    service->state = FN_RUNTIME_DORMANT;
    service->last_result = runtime_result(FN_OK, FN_STAGE_NONE);
    service->consecutive_failures = 0;
  } else if (success) {
    service->resource = resource;
    service->state = FN_RUNTIME_READY;
    service->last_result = runtime_result(FN_OK, FN_STAGE_NONE);
    service->consecutive_failures = 0;
    service->retry_after_ms = 0;
  } else if (result.code == FN_CANCELLED ||
             result.code == FN_STALE_GENERATION) {
    service->state = FN_RUNTIME_DORMANT;
    service->last_result = result;
  } else {
    service->state = FN_RUNTIME_FAILED;
    save_failure(runtime, service, result);
  }

  operation = waiters;
  while (operation != NULL) {
    fn_runtime_acquire_t *next = operation->next;
    operation->next = NULL;
    (void)queue_acquire(operation, result,
                        success ? service->resource : NULL);
    operation = next;
  }
  service->start_holds_reference = false;
  return runtime_drop_reference(runtime);
}

size_t fn_runtime_internal_rule_count(const fn_runtime_t *runtime)
{
  return runtime == NULL ? 0u : runtime->rule_count;
}

fn_result_t fn_runtime_internal_rule_get(const fn_runtime_t *runtime,
                                         size_t index,
                                         fn_compiled_rule_t *out)
{
  if (runtime == NULL || out == NULL || index >= runtime->rule_count) {
    return runtime_result(FN_INVALID, FN_STAGE_ROUTE);
  }
  *out = runtime->rules[index];
  return runtime_result(FN_OK, FN_STAGE_NONE);
}

fn_result_t fn_runtime_internal_validate_kind(
  const fn_runtime_t *runtime, fn_object_ref_t object,
  fn_runtime_resource_kind_t kind)
{
  const fn_runtime_resource_descriptor_t *descriptor;
  fn_result_t result = fn_runtime_object_get(runtime, object, &descriptor);
  if (result.code != FN_OK) {
    return result;
  }
  return descriptor->kind == kind ? runtime_result(FN_OK, FN_STAGE_NONE) :
    runtime_result(FN_INVALID, FN_STAGE_ROUTE);
}

fn_result_t fn_runtime_internal_find_kind(
  const fn_runtime_t *runtime, fn_runtime_resource_kind_t kind,
  fn_object_ref_t *out)
{
  size_t index;
  if (runtime == NULL || out == NULL || !resource_kind_valid(kind)) {
    return runtime_result(FN_INVALID, FN_STAGE_ROUTE);
  }
  out->generation = 0;
  out->index = FN_ID_NONE;
  for (index = 0; index < runtime->object_count; index++) {
    if (runtime->objects[index].kind == kind) {
      *out = runtime->objects[index].id;
      return runtime_result(FN_OK, FN_STAGE_NONE);
    }
  }
  return runtime_result(FN_INVALID, FN_STAGE_ROUTE);
}
