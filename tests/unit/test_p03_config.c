#include "flicknet/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FN_SOURCE_DIR
#error "FN_SOURCE_DIR must identify the FlickNet source tree"
#endif

typedef struct {
  size_t calls;
  size_t frees;
  size_t live;
  size_t fail_on_call;
} fault_allocator_state_t;

typedef struct {
  const char *path;
  bool valid;
  const char *error_code;
  const char *error_path;
} fixture_case_t;

static void *fault_allocate(void *context, size_t size)
{
  fault_allocator_state_t *state = context;
  void *pointer;
  state->calls++;
  if (state->fail_on_call != 0 && state->calls == state->fail_on_call) {
    return NULL;
  }
  pointer = malloc(size);
  if (pointer != NULL) {
    state->live++;
  }
  return pointer;
}

static void fault_deallocate(void *context, void *pointer)
{
  fault_allocator_state_t *state = context;
  if (pointer != NULL) {
    state->frees++;
    state->live--;
    free(pointer);
  }
}

static fn_allocator_t make_fault_allocator(fault_allocator_state_t *state)
{
  const fn_allocator_t allocator = {
    .context = state,
    .allocate = fault_allocate,
    .deallocate = fault_deallocate,
  };
  return allocator;
}

/* read_file 读取受控 fixture；返回缓冲由调用者释放。 */
static uint8_t *read_file(const char *relative_path, size_t *length)
{
  char path[1024];
  FILE *file;
  long size;
  uint8_t *data;

  *length = 0;
  (void)snprintf(path, sizeof(path), "%s/%s", FN_SOURCE_DIR, relative_path);
  file = fopen(path, "rb");
  if (file == NULL || fseek(file, 0, SEEK_END) != 0) {
    if (file != NULL) {
      (void)fclose(file);
    }
    return NULL;
  }
  size = ftell(file);
  if (size < 0 || fseek(file, 0, SEEK_SET) != 0) {
    (void)fclose(file);
    return NULL;
  }
  data = malloc((size_t)size + 1u);
  if (data == NULL) {
    (void)fclose(file);
    return NULL;
  }
  if (fread(data, 1u, (size_t)size, file) != (size_t)size ||
      fclose(file) != 0) {
    free(data);
    return NULL;
  }
  data[size] = UINT8_C(0);
  *length = (size_t)size;
  return data;
}

static fn_feature_set_t v0_1_available_features(void)
{
  return FN_FEATURE_SOCKS_IN_TCP | FN_FEATURE_SOCKS_OUT_TCP |
         FN_FEATURE_DIRECT_TCP | FN_FEATURE_DNS_RESOLVER |
         FN_FEATURE_DNS_UPSTREAM_UDP | FN_FEATURE_DNS_UPSTREAM_TCP |
         FN_FEATURE_DNS_FAILURE_CACHE;
}

static int check_plan(const char *path, const fn_config_t *config)
{
  fn_config_error_t error;
  fn_feature_plan_t plan;
  fn_feature_set_t expected_reachable;
  fn_feature_set_t expected_lazy;
  fn_result_t result = fn_config_plan(config, v0_1_available_features(),
                                      &plan, &error);
  if (result.code != FN_OK || error.code != FN_CONFIG_ERROR_NONE ||
      plan.prepare != FN_FEATURE_SOCKS_IN_TCP) {
    return 1;
  }
  if (strstr(path, "minimal-direct") != NULL) {
    expected_reachable = FN_FEATURE_SOCKS_IN_TCP | FN_FEATURE_DIRECT_TCP |
      FN_FEATURE_DNS_RESOLVER | FN_FEATURE_DNS_UPSTREAM_UDP |
      FN_FEATURE_DNS_FAILURE_CACHE;
    expected_lazy = expected_reachable & ~FN_FEATURE_SOCKS_IN_TCP;
    if (config->dns.direct_count != 1u || config->inbound_count != 1u ||
        config->limits.session_limit != 10000u ||
        config->timeouts.connect_ms != UINT64_C(10000)) {
      return 2;
    }
  } else if (strstr(path, "socks-out-domain") != NULL) {
    expected_reachable = FN_FEATURE_SOCKS_IN_TCP | FN_FEATURE_SOCKS_OUT_TCP;
    expected_lazy = FN_FEATURE_SOCKS_OUT_TCP;
  } else {
    expected_reachable = FN_FEATURE_SOCKS_IN_TCP;
    expected_lazy = 0;
  }
  return plan.reachable == expected_reachable && plan.lazy == expected_lazy ?
         0 : 3;
}

static int check_contract_fixtures(void)
{
  static const fixture_case_t cases[] = {
    {"tests/fixtures/config/v1/valid/minimal-direct.yaml", true, "", ""},
    {"tests/fixtures/config/v1/valid/socks-out-domain.yaml", true, "", ""},
    {"tests/fixtures/config/v1/valid/reject-without-resolver.yaml", true, "", ""},
    {"tests/fixtures/config/v1/invalid/null-value.yaml", false,
     "E_NULL", "log-level"},
    {"tests/fixtures/config/v1/invalid/unknown-field.yaml", false,
     "E_UNKNOWN_FIELD", "mystery"},
    {"tests/fixtures/config/v1/invalid/missing-direct-dns.yaml", false,
     "E_DNS_REQUIRED", "dns.direct"},
    {"tests/fixtures/config/v1/invalid/missing-bootstrap-dns.yaml", false,
     "E_DNS_REQUIRED", "dns.bootstrap"},
    {"tests/fixtures/config/v1/invalid/overflow-bytes.yaml", false,
     "E_OVERFLOW", "limits.memory"},
    {"tests/fixtures/config/v1/invalid/unsupported-udp.yaml", false,
     "E_UNSUPPORTED_VERSION", "inbounds[0].udp"},
    {"tests/fixtures/config/v1/invalid/empty-direct-dns.yaml", false,
     "E_RANGE", "dns.direct"},
    {"tests/fixtures/config/v1/invalid/duplicate-key.yaml", false,
     "E_DUPLICATE_KEY", "log-level"},
  };
  size_t index;

  for (index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
    size_t length;
    uint8_t *input = read_file(cases[index].path, &length);
    fn_config_t config;
    fn_config_error_t error;
    fn_result_t result;
    if (input == NULL) {
      return (int)(100u + index);
    }
    result = fn_config_parse(input, length, fn_allocator_system(),
                             &config, &error);
    free(input);
    if (cases[index].valid) {
      const int plan_result = result.code == FN_OK ?
                              check_plan(cases[index].path, &config) : 9;
      fn_config_destroy(&config);
      if (result.code != FN_OK || error.code != FN_CONFIG_ERROR_NONE ||
          plan_result != 0) {
        return (int)(200u + index * 10u + (size_t)plan_result);
      }
    } else {
      if (result.code == FN_OK ||
          strcmp(fn_config_error_code_name(error.code),
                 cases[index].error_code) != 0 ||
          strcmp(error.path, cases[index].error_path) != 0) {
        fn_config_destroy(&config);
        return (int)(400u + index);
      }
      fn_config_destroy(&config);
    }
  }
  return 0;
}

static int parse_inline(const char *input, fn_config_error_code_t expected,
                        const char *expected_path)
{
  fn_config_t config;
  fn_config_error_t error;
  fn_result_t result = fn_config_parse((const uint8_t *)input, strlen(input),
                                       fn_allocator_system(), &config,
                                       &error);
  if (result.code == FN_OK || error.code != expected ||
      strcmp(error.path, expected_path) != 0) {
    fn_config_destroy(&config);
    return 1;
  }
  fn_config_destroy(&config);
  return 0;
}

static int check_yaml_and_schema_edges(void)
{
  static const char base_tail[] =
    "inbounds:\n"
    "  - name: in\n"
    "    type: socks5\n"
    "    port: 1080\n"
    "rules:\n"
    "  - MATCH,REJECT\n";
  char input[1024];

  (void)snprintf(input, sizeof(input),
                 "schema-version: 1\nipv6: yes\n%s", base_tail);
  if (parse_inline(input, FN_CONFIG_ERROR_TYPE, "ipv6") != 0) {
    return 1;
  }
  (void)snprintf(input, sizeof(input),
                 "schema-version: 1\nlog-level: &level warn\n%s", base_tail);
  if (parse_inline(input, FN_CONFIG_ERROR_YAML_UNSUPPORTED, "") != 0) {
    return 2;
  }
  if (parse_inline("- one\n- two\n", FN_CONFIG_ERROR_TYPE, "") != 0) {
    return 3;
  }
  (void)snprintf(input, sizeof(input),
                 "schema-version: 1\n%s---\nschema-version: 1\n",
                 base_tail);
  if (parse_inline(input, FN_CONFIG_ERROR_YAML_UNSUPPORTED, "") != 0) {
    return 4;
  }
  (void)snprintf(input, sizeof(input),
                 "schema-version: 1\n"
                 "proxies:\n"
                 "  - name: unused\n"
                 "    type: socks5\n"
                 "    server: invalid_name\n"
                 "    port: 1080\n%s", base_tail);
  if (parse_inline(input, FN_CONFIG_ERROR_FORMAT,
                   "proxies[0].server") != 0) {
    return 5;
  }
  return 0;
}

static int check_unused_definition_and_feature_failure(void)
{
  static const char input[] =
    "schema-version: 1\n"
    "inbounds:\n"
    "  - name: in\n"
    "    type: socks5\n"
    "    port: 1080\n"
    "proxies:\n"
    "  - name: unused\n"
    "    type: socks5\n"
    "    server: 192.0.2.10\n"
    "    port: 1080\n"
    "rules:\n"
    "  - MATCH,REJECT\n";
  fn_config_t config;
  fn_config_error_t error;
  fn_feature_plan_t plan;
  fn_result_t result = fn_config_parse((const uint8_t *)input,
                                       sizeof(input) - 1u,
                                       fn_allocator_system(), &config,
                                       &error);
  if (result.code != FN_OK || config.proxy_count != 1u ||
      fn_config_plan(&config, v0_1_available_features(),
                     &plan, &error).code != FN_OK ||
      plan.reachable != FN_FEATURE_SOCKS_IN_TCP || plan.lazy != 0) {
    fn_config_destroy(&config);
    return 1;
  }
  plan.reachable = UINT64_MAX;
  plan.prepare = UINT64_MAX;
  plan.lazy = UINT64_MAX;
  result = fn_config_plan(&config, 0, &plan, &error);
  fn_config_destroy(&config);
  if (result.code != FN_FEATURE_UNAVAILABLE ||
      error.code != FN_CONFIG_ERROR_FEATURE_UNAVAILABLE ||
      plan.reachable != 0 || plan.prepare != 0 || plan.lazy != 0) {
    return 2;
  }
  return 0;
}

static int check_derived_limits(void)
{
  static const char input[] =
    "schema-version: 1\n"
    "limits:\n"
    "  async-operations: 32768\n"
    "inbounds:\n"
    "  - name: in\n"
    "    type: socks5\n"
    "    port: 1080\n"
    "rules:\n"
    "  - MATCH,REJECT\n";
  fn_config_t config;
  fn_config_error_t error;
  fn_result_t result = fn_config_parse(
    (const uint8_t *)input, sizeof(input) - 1u,
    fn_allocator_system(), &config, &error);
  const bool valid = result.code == FN_OK &&
    config.limits.async_operation_limit == 32768u &&
    config.limits.completion_entry_limit == 32768u &&
    config.limits.completion_limit_bytes == 32768u * 256u;
  fn_config_destroy(&config);
  return valid ? 0 : 1;
}

static int check_bounded_inputs(void)
{
  static const char prefix[] =
    "schema-version: 1\n"
    "dns:\n"
    "  direct:\n";
  static const char suffix[] =
    "inbounds:\n"
    "  - name: in\n"
    "    type: socks5\n"
    "    port: 1080\n"
    "rules:\n"
    "  - MATCH,REJECT\n";
  char input[2048];
  size_t length = 0;
  size_t index;
  uint8_t *oversized;
  fn_config_t config;
  fn_config_error_t error;
  fn_result_t result;

  memcpy(input + length, prefix, sizeof(prefix) - 1u);
  length += sizeof(prefix) - 1u;
  for (index = 0; index < 17u; index++) {
    const int written = snprintf(input + length, sizeof(input) - length,
                                 "    - udp://192.0.2.%zu:53\n", index + 1u);
    if (written < 0 || (size_t)written >= sizeof(input) - length) {
      return 1;
    }
    length += (size_t)written;
  }
  memcpy(input + length, suffix, sizeof(suffix));
  length += sizeof(suffix) - 1u;
  if (parse_inline(input, FN_CONFIG_ERROR_COLLECTION_LIMIT,
                   "dns.direct") != 0) {
    return 2;
  }

  oversized = malloc(FN_CONFIG_MAX_BYTES + 1u);
  if (oversized == NULL) {
    return 3;
  }
  memset(oversized, 'x', FN_CONFIG_MAX_BYTES + 1u);
  result = fn_config_parse(oversized, FN_CONFIG_MAX_BYTES + 1u,
                           fn_allocator_system(), &config, &error);
  free(oversized);
  fn_config_destroy(&config);
  if (result.code != FN_LIMIT || error.code != FN_CONFIG_ERROR_SIZE) {
    return 4;
  }
  return 0;
}

static int check_allocator_fault_cleanup(void)
{
  static const char input[] =
    "schema-version: 1\n"
    "inbounds:\n"
    "  - name: in\n"
    "    type: socks5\n"
    "    port: 1080\n"
    "    users:\n"
    "      alice: secret\n"
    "proxies:\n"
    "  - name: unused\n"
    "    type: socks5\n"
    "    server: 192.0.2.10\n"
    "    port: 1080\n"
    "rules:\n"
    "  - MATCH,REJECT\n";
  size_t fail_on;

  for (fail_on = 1u; fail_on < 512u; fail_on++) {
    fault_allocator_state_t state = {
      .calls = 0,
      .frees = 0,
      .live = 0,
      .fail_on_call = fail_on,
    };
    fn_config_t config;
    fn_config_error_t error;
    fn_result_t result = fn_config_parse((const uint8_t *)input,
                                         sizeof(input) - 1u,
                                         make_fault_allocator(&state),
                                         &config, &error);
    if (result.code == FN_OK) {
      fn_config_destroy(&config);
      return state.live == 0 && state.calls == state.frees ? 0 : 1;
    }
    fn_config_destroy(&config);
    if (result.code != FN_NO_MEMORY ||
        error.code != FN_CONFIG_ERROR_NO_MEMORY || state.live != 0 ||
        state.calls != state.frees + 1u) {
      return 2;
    }
  }
  return 3;
}

int main(void)
{
  const int fixture_check = check_contract_fixtures();
  const int edge_check = check_yaml_and_schema_edges();
  const int plan_check = check_unused_definition_and_feature_failure();
  const int derived_check = check_derived_limits();
  const int bound_check = check_bounded_inputs();
  const int fault_check = check_allocator_fault_cleanup();

  if (fixture_check != 0 || edge_check != 0 || plan_check != 0 ||
      derived_check != 0 ||
      bound_check != 0 || fault_check != 0) {
    fprintf(stderr,
            "P03 config check failed: fixtures=%d edges=%d plan=%d "
            "derived=%d bounds=%d fault=%d.\n",
            fixture_check, edge_check, plan_check, derived_check,
            bound_check, fault_check);
    return 1;
  }
  puts("P03 typed configuration and feature plan checks passed.");
  return 0;
}
