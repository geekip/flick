#include "flicknet/build.h"
#include "flicknet/cli.h"
#include "flicknet/loop.h"
#include "flicknet/observability.h"
#include "flicknet/pool.h"
#include "flicknet/resource.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      (void)fprintf(stderr, "check failed: %s:%d: %s\n", __FILE__,          \
                    __LINE__, #condition);                                     \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

typedef struct {
  size_t calls;
  size_t builder_calls;
  fn_log_record_t last;
} log_observation_t;

static void log_sink(void *context, const fn_log_record_t *record)
{
  log_observation_t *observation = context;
  observation->calls++;
  observation->last = *record;
}

static void log_builder(void *context, char *message, size_t capacity)
{
  log_observation_t *observation = context;
  observation->builder_calls++;
  (void)snprintf(message, capacity, "%s", "Connection failed.");
}

static void post_callback(void *context)
{
  size_t *calls = context;
  (*calls)++;
}

static void expect_cli_ok(int argc, const char *const *argv,
                          fn_cli_command_t command,
                          fn_cli_output_t output, bool features)
{
  fn_cli_options_t options;
  fn_cli_error_t error;
  CHECK(fn_cli_parse(argc, argv, &options, &error).code == FN_OK);
  CHECK(options.command == command);
  CHECK(options.output == output);
  CHECK(options.features == features);
}

static void expect_cli_error(int argc, const char *const *argv)
{
  fn_cli_options_t options;
  fn_cli_error_t error;
  CHECK(fn_cli_parse(argc, argv, &options, &error).code == FN_INVALID);
  CHECK(strcmp(error.code, "E_CLI_USAGE") == 0);
}

static void test_cli_contract(void)
{
  const char *version[] = {"flick", "--output", "json", "version",
                           "--features"};
  const char *check[] = {"flick", "-c", "config.yaml", "check"};
  const char *duplicate[] = {
    "flick", "-c", "a", "--config", "b", "check",
  };
  const char *late_global[] = {"flick", "check", "--output", "json"};
  const char *combined[] = {"flick", "-ch", "check"};
  const char *version_config[] = {"flick", "--config", "a", "version"};
  const char *version_config_help[] = {
    "flick", "--config", "a", "version", "--help",
  };
  const char *help_extra[] = {"flick", "check", "--help", "extra"};
  expect_cli_ok(5, version, FN_CLI_COMMAND_VERSION, FN_CLI_OUTPUT_JSON, true);
  expect_cli_ok(4, check, FN_CLI_COMMAND_CHECK, FN_CLI_OUTPUT_TEXT, false);
  expect_cli_error(6, duplicate);
  expect_cli_error(4, late_global);
  expect_cli_error(3, combined);
  expect_cli_error(4, version_config);
  expect_cli_error(5, version_config_help);
  expect_cli_error(4, help_extra);
}

static void test_compiled_features(void)
{
  static const char *const expected[] = {
    "direct_tcp",
    "dns_failure_cache",
    "dns_resolver",
    "dns_upstream_tcp",
    "dns_upstream_udp",
    "socks_in_tcp",
    "socks_out_tcp",
  };
  fn_feature_set_t expected_bits =
    FN_FEATURE_DIRECT_TCP | FN_FEATURE_DNS_FAILURE_CACHE |
    FN_FEATURE_DNS_RESOLVER | FN_FEATURE_DNS_UPSTREAM_TCP |
    FN_FEATURE_DNS_UPSTREAM_UDP | FN_FEATURE_SOCKS_IN_TCP |
    FN_FEATURE_SOCKS_OUT_TCP;
  size_t index;
  CHECK(fn_build_compiled_features() == expected_bits);
  CHECK(fn_build_compiled_feature_count() ==
        sizeof(expected) / sizeof(expected[0]));
  for (index = 0; index < fn_build_compiled_feature_count(); index++) {
    CHECK(strcmp(fn_build_compiled_feature_name(index), expected[index]) ==
          0);
    if (index != 0) {
      CHECK(strcmp(fn_build_compiled_feature_name(index - 1u),
                   fn_build_compiled_feature_name(index)) < 0);
    }
  }
  CHECK(fn_build_compiled_feature_name(fn_build_compiled_feature_count()) ==
        NULL);
}

static void test_log_gate(void)
{
  fn_logger_t logger;
  fn_logger_snapshot_t snapshot;
  log_observation_t observation;
  fn_result_t structured = fn_result_make(
    FN_CONNECT_ERROR, FN_STAGE_TCP_CONNECT, FN_ERROR_ORIGIN_POSIX,
    INT64_C(111));
  memset(&observation, 0, sizeof(observation));
  CHECK(fn_logger_init(&logger, false, FN_LOG_TRACE, log_sink,
                       &observation).code == FN_OK);
  CHECK(fn_logger_emit(&logger, FN_LOG_ERROR, "CONNECT_FAILED", structured,
                       log_builder, &observation).code ==
        FN_OK);
  CHECK(fn_logger_snapshot(&logger, &snapshot).code == FN_OK);
  CHECK(snapshot.attempts == 1u);
  CHECK(snapshot.records_constructed == 0u);
  CHECK(snapshot.records_emitted == 0u);
  CHECK(observation.calls == 0u);
  CHECK(observation.builder_calls == 0u);
  CHECK(structured.code == FN_CONNECT_ERROR);
  CHECK(structured.stage == FN_STAGE_TCP_CONNECT);
  CHECK(structured.origin == FN_ERROR_ORIGIN_POSIX);
  CHECK(structured.native_code == INT64_C(111));

  CHECK(fn_logger_init(&logger, true, FN_LOG_WARN, log_sink,
                       &observation).code == FN_OK);
  CHECK(fn_logger_emit(&logger, FN_LOG_INFO, "IGNORED", structured,
                       log_builder, &observation).code == FN_OK);
  CHECK(fn_logger_emit(&logger, FN_LOG_ERROR, "CONNECT_FAILED", structured,
                       log_builder, &observation).code == FN_OK);
  CHECK(fn_logger_snapshot(&logger, &snapshot).code == FN_OK);
  CHECK(snapshot.attempts == 2u);
  CHECK(snapshot.records_constructed == 1u);
  CHECK(snapshot.records_emitted == 1u);
  CHECK(observation.calls == 1u);
  CHECK(observation.builder_calls == 1u);
  CHECK(strcmp(observation.last.code, "CONNECT_FAILED") == 0);
}

static void test_loop_counters(void)
{
  fn_limits_t limits = fn_limits_default();
  fn_budget_t memory;
  fn_budget_t file_descriptors;
  fn_loop_options_t options;
  fn_loop_snapshot_t before;
  fn_loop_snapshot_t after;
  fn_loop_t *loop = NULL;
  size_t post_calls = 0;
  CHECK(fn_budget_init(&memory, limits.owned_memory_limit_bytes,
                       limits.cleanup_reserve_bytes).code == FN_OK);
  CHECK(fn_budget_init(&file_descriptors, limits.fd_limit, 0u).code == FN_OK);
  memset(&options, 0, sizeof(options));
  options.limits = &limits;
  options.owned_memory = &memory;
  options.file_descriptors = &file_descriptors;
  options.allocator = fn_allocator_system();
  options.dispatch_limit = 8u;
  CHECK(fn_loop_create(&options, &loop).code == FN_OK);
  CHECK(fn_loop_snapshot(loop, &before).code == FN_OK);
  CHECK(before.run_iterations == 0u);
  CHECK(fn_loop_post(loop, post_callback, &post_calls).code == FN_OK);
  CHECK(fn_loop_run_once(loop, FN_LOOP_RUN_NOWAIT).code == FN_OK);
  CHECK(fn_loop_snapshot(loop, &after).code == FN_OK);
  CHECK(post_calls == 1u);
  CHECK(after.run_iterations == 1u);
  CHECK(after.post_callbacks == 1u);
  CHECK(after.terminal_callbacks == 0u);
  CHECK(fn_loop_destroy(&loop).code == FN_OK);
}

int main(void)
{
  test_cli_contract();
  test_compiled_features();
  test_log_gate();
  test_loop_counters();
  (void)puts("p11 cli and observability tests passed");
  return 0;
}
