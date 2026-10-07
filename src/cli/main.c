#include "app_internal.h"

#include "flicknet/build.h"
#include "flicknet/cli.h"
#include "flicknet/config.h"
#include "flicknet/observability.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FN_DEFAULT_CONFIG_SUFFIX "/.flick/config.yaml"
#define FN_DEFAULT_PATH_MAX 4096u

typedef struct {
  char code[32];
  char path[FN_CONFIG_PATH_MAX];
  size_t line;
  size_t column;
  bool has_mark;
  char message[192];
} command_diagnostic_t;

static void diagnostic_clear(command_diagnostic_t *diagnostic)
{
  memset(diagnostic, 0, sizeof(*diagnostic));
}

static void diagnostic_set(command_diagnostic_t *diagnostic,
                           const char *code, const char *path,
                           const char *message)
{
  diagnostic_clear(diagnostic);
  (void)snprintf(diagnostic->code, sizeof(diagnostic->code), "%s", code);
  if (path != NULL) {
    (void)snprintf(diagnostic->path, sizeof(diagnostic->path), "%s", path);
  }
  (void)snprintf(diagnostic->message, sizeof(diagnostic->message), "%s",
                 message);
}

static void diagnostic_from_config(command_diagnostic_t *diagnostic,
                                   const fn_config_error_t *error)
{
  diagnostic_clear(diagnostic);
  (void)snprintf(diagnostic->code, sizeof(diagnostic->code), "%s",
                 fn_config_error_code_name(error->code));
  (void)snprintf(diagnostic->path, sizeof(diagnostic->path), "%s",
                 error->path);
  diagnostic->line = error->line;
  diagnostic->column = error->column;
  diagnostic->has_mark = error->has_mark;
  (void)snprintf(diagnostic->message, sizeof(diagnostic->message), "%s",
                 error->message);
}

static void diagnostic_from_result(command_diagnostic_t *diagnostic,
                                   const char *code, fn_result_t result,
                                   const char *message)
{
  char formatted[sizeof(diagnostic->message)];
  (void)snprintf(formatted, sizeof(formatted),
                 "%s stage=%s origin=%s native=%lld", message,
                 fn_error_stage_name(result.stage),
                 fn_error_origin_name(result.origin),
                 (long long)result.native_code);
  diagnostic_set(diagnostic, code, "", formatted);
}

static void json_string(FILE *stream, const char *value)
{
  const unsigned char *cursor = (const unsigned char *)value;
  (void)fputc('"', stream);
  while (*cursor != '\0') {
    unsigned char byte = *cursor++;
    switch (byte) {
      case '"': (void)fputs("\\\"", stream); break;
      case '\\': (void)fputs("\\\\", stream); break;
      case '\b': (void)fputs("\\b", stream); break;
      case '\f': (void)fputs("\\f", stream); break;
      case '\n': (void)fputs("\\n", stream); break;
      case '\r': (void)fputs("\\r", stream); break;
      case '\t': (void)fputs("\\t", stream); break;
      default:
        if (byte < UINT8_C(0x20)) {
          (void)fprintf(stream, "\\u%04x", (unsigned)byte);
        } else {
          (void)fputc((int)byte, stream);
        }
        break;
    }
  }
  (void)fputc('"', stream);
}

static void json_diagnostic(FILE *stream,
                            const command_diagnostic_t *diagnostic)
{
  (void)fputs("{\"code\":", stream);
  json_string(stream, diagnostic->code);
  (void)fputs(",\"path\":", stream);
  json_string(stream, diagnostic->path);
  (void)fputs(",\"line\":", stream);
  if (diagnostic->has_mark) {
    (void)fprintf(stream, "%zu", diagnostic->line);
  } else {
    (void)fputs("null", stream);
  }
  (void)fputs(",\"column\":", stream);
  if (diagnostic->has_mark) {
    (void)fprintf(stream, "%zu", diagnostic->column);
  } else {
    (void)fputs("null", stream);
  }
  (void)fputs(",\"message\":", stream);
  json_string(stream, diagnostic->message);
  (void)fputc('}', stream);
}

static void text_diagnostic(const command_diagnostic_t *diagnostic)
{
  if (diagnostic->path[0] != '\0') {
    (void)fprintf(stderr, "%s %s: %s\n", diagnostic->code,
                  diagnostic->path, diagnostic->message);
  } else {
    (void)fprintf(stderr, "%s: %s\n", diagnostic->code,
                  diagnostic->message);
  }
}

static void command_json_prefix(const char *command, const char *status,
                                int exit_code,
                                const command_diagnostic_t *diagnostic)
{
  (void)fputs("{\"format_version\":1,\"schema\":"
              "\"flick.command-result\",\"command\":", stdout);
  json_string(stdout, command);
  (void)fputs(",\"status\":", stdout);
  json_string(stdout, status);
  (void)fprintf(stdout, ",\"exit_code\":%d,\"errors\":[", exit_code);
  if (diagnostic != NULL) {
    json_diagnostic(stdout, diagnostic);
  }
  (void)fputs("],\"warnings\":[]", stdout);
}

static void emit_error(const fn_cli_options_t *options, int exit_code,
                       const command_diagnostic_t *diagnostic)
{
  if (options->output == FN_CLI_OUTPUT_JSON) {
    command_json_prefix(fn_cli_command_name(options->command), "error",
                        exit_code, diagnostic);
    (void)fputs(",\"details\":{}}\n", stdout);
  } else {
    text_diagnostic(diagnostic);
  }
}

static void print_features_json(void)
{
  size_t index;
  (void)fputc('[', stdout);
  for (index = 0; index < fn_build_compiled_feature_count(); index++) {
    if (index != 0) {
      (void)fputc(',', stdout);
    }
    json_string(stdout, fn_build_compiled_feature_name(index));
  }
  (void)fputc(']', stdout);
}

static void emit_version(const fn_cli_options_t *options)
{
  size_t index;
  if (options->output == FN_CLI_OUTPUT_JSON) {
    command_json_prefix("version", "ok", 0, NULL);
    (void)fputs(",\"details\":{\"program\":\"flick\",\"version\":",
                stdout);
    json_string(stdout, fn_build_program_version());
    (void)fputs(",\"platform\":", stdout);
    json_string(stdout, fn_build_platform());
    (void)fputs(",\"dependencies\":{\"libev\":", stdout);
    json_string(stdout, fn_build_libev_version());
    (void)fputs(",\"libyaml\":", stdout);
    json_string(stdout, fn_build_libyaml_version());
    (void)fputs("},\"tls_backend\":", stdout);
    json_string(stdout, fn_build_tls_backend());
    if (options->features) {
      (void)fputs(",\"features\":", stdout);
      print_features_json();
    }
    (void)fputs("}}\n", stdout);
    return;
  }
  (void)printf("flick %s\n", fn_build_program_version());
  (void)printf("Platform: %s\n", fn_build_platform());
  (void)printf("Dependencies: libev %s, libyaml %s\n",
               fn_build_libev_version(), fn_build_libyaml_version());
  (void)printf("TLS backend: %s\n", fn_build_tls_backend());
  if (options->features) {
    (void)fputs("Features:", stdout);
    for (index = 0; index < fn_build_compiled_feature_count(); index++) {
      (void)printf("%s%s", index == 0 ? " " : ",",
                   fn_build_compiled_feature_name(index));
    }
    (void)fputc('\n', stdout);
  }
}

static void print_help(fn_cli_command_t command)
{
  if (command == FN_CLI_COMMAND_NONE) {
    (void)fputs(
      "Usage:\n"
      "  flick [--config PATH] [--output text|json] run\n"
      "  flick [--config PATH] [--output text|json] check\n"
      "  flick [--config PATH] [--output text|json] test\n"
      "  flick [--output text|json] version [--features]\n"
      "  flick [--help]\n",
      stdout);
    return;
  }
  (void)printf("Usage: flick %s%s\n", fn_cli_command_name(command),
               command == FN_CLI_COMMAND_VERSION ? " [--features]" : "");
}

static bool default_config_path(char path[FN_DEFAULT_PATH_MAX],
                                command_diagnostic_t *diagnostic)
{
  const char *home = getenv("HOME");
  int count;
  if (home == NULL || home[0] == '\0') {
    diagnostic_set(diagnostic, "E_CONFIG_IO", "",
                   "HOME is not set; specify --config PATH.");
    return false;
  }
  count = snprintf(path, FN_DEFAULT_PATH_MAX, "%s%s", home,
                   FN_DEFAULT_CONFIG_SUFFIX);
  if (count < 0 || (size_t)count >= FN_DEFAULT_PATH_MAX) {
    diagnostic_set(diagnostic, "E_CONFIG_IO", "",
                   "The default config path is too long.");
    return false;
  }
  return true;
}

static bool read_config_file(const char *path, uint8_t **out,
                             size_t *out_length,
                             command_diagnostic_t *diagnostic)
{
  struct stat status;
  uint8_t *buffer;
  size_t length = 0;
  int descriptor;
  *out = NULL;
  *out_length = 0;
  descriptor = open(path, O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    char message[160];
    int native_code = errno;
    (void)snprintf(message, sizeof(message),
                   "Cannot open config file (posix=%d).", native_code);
    diagnostic_set(diagnostic, "E_CONFIG_IO", "", message);
    return false;
  }
  if (fstat(descriptor, &status) != 0) {
    int native_code = errno;
    char message[160];
    (void)close(descriptor);
    (void)snprintf(message, sizeof(message),
                   "Cannot inspect config file (posix=%d).", native_code);
    diagnostic_set(diagnostic, "E_CONFIG_IO", "", message);
    return false;
  }
  if (status.st_size > (off_t)FN_CONFIG_MAX_BYTES) {
    (void)close(descriptor);
    diagnostic_set(diagnostic, "E_CONFIG_SIZE", "",
                   "Config file exceeds the 1 MiB limit.");
    return false;
  }
  buffer = malloc(FN_CONFIG_MAX_BYTES + 1u);
  if (buffer == NULL) {
    (void)close(descriptor);
    diagnostic_set(diagnostic, "E_INTERNAL", "",
                   "Config file allocation failed.");
    return false;
  }
  while (length <= FN_CONFIG_MAX_BYTES) {
    ssize_t count = read(descriptor, buffer + length,
                         FN_CONFIG_MAX_BYTES + 1u - length);
    if (count > 0) {
      length += (size_t)count;
      continue;
    }
    if (count == 0) {
      break;
    }
    if (errno == EINTR) {
      continue;
    }
    {
      int native_code = errno;
      char message[160];
      free(buffer);
      (void)close(descriptor);
      (void)snprintf(message, sizeof(message),
                     "Cannot read config file (posix=%d).", native_code);
      diagnostic_set(diagnostic, "E_CONFIG_IO", "", message);
      return false;
    }
  }
  (void)close(descriptor);
  if (length > FN_CONFIG_MAX_BYTES) {
    free(buffer);
    diagnostic_set(diagnostic, "E_CONFIG_SIZE", "",
                   "Config file exceeds the 1 MiB limit.");
    return false;
  }
  buffer[length] = 0;
  *out = buffer;
  *out_length = length;
  return true;
}

static int config_failure_exit(const command_diagnostic_t *diagnostic)
{
  if (strcmp(diagnostic->code, "E_UNSUPPORTED_VERSION") == 0 ||
      strcmp(diagnostic->code, "E_FEATURE_UNAVAILABLE") == 0) {
    return 4;
  }
  if (strcmp(diagnostic->code, "E_INTERNAL") == 0) {
    return 70;
  }
  return 3;
}

static int load_and_plan(const fn_cli_options_t *options,
                         fn_config_t *config, fn_feature_plan_t *plan,
                         command_diagnostic_t *diagnostic)
{
  char default_path[FN_DEFAULT_PATH_MAX];
  const char *path = options->config_path;
  uint8_t *input = NULL;
  size_t input_length = 0;
  fn_config_error_t config_error;
  fn_result_t result;
  memset(config, 0, sizeof(*config));
  memset(plan, 0, sizeof(*plan));
  if (path == NULL) {
    if (!default_config_path(default_path, diagnostic)) {
      return 3;
    }
    path = default_path;
  }
  if (!read_config_file(path, &input, &input_length, diagnostic)) {
    return config_failure_exit(diagnostic);
  }
  memset(&config_error, 0, sizeof(config_error));
  result = fn_config_parse(input, input_length, fn_allocator_system(),
                           config, &config_error);
  free(input);
  if (result.code != FN_OK) {
    diagnostic_from_config(diagnostic, &config_error);
    return config_failure_exit(diagnostic);
  }
  memset(&config_error, 0, sizeof(config_error));
  result = fn_config_plan(config, fn_build_compiled_features(), plan,
                          &config_error);
  if (result.code != FN_OK) {
    diagnostic_from_config(diagnostic, &config_error);
    fn_config_destroy(config);
    return config_failure_exit(diagnostic);
  }
  return 0;
}

static void emit_check_success(const fn_cli_options_t *options)
{
  if (options->output == FN_CLI_OUTPUT_JSON) {
    command_json_prefix("check", "ok", 0, NULL);
    (void)fputs(",\"details\":{\"config_valid\":true,"
                "\"plan_valid\":true}}\n", stdout);
  } else {
    (void)fputs("Configuration valid.\nPlan valid.\n", stdout);
  }
}

static void emit_test_success(const fn_cli_options_t *options,
                              const fn_feature_plan_t *plan,
                              const fn_app_summary_t *summary)
{
  const char *lazy_status = plan->lazy == 0 ? "none_planned" :
                                                "not_verified";
  if (options->output == FN_CLI_OUTPUT_JSON) {
    command_json_prefix("test", "ok", 0, NULL);
    (void)fprintf(stdout,
                  ",\"details\":{\"config_valid\":true,"
                  "\"plan_valid\":true,"
                  "\"startup_resources\":\"ready\","
                  "\"lazy_external_dependencies\":\"%s\","
                  "\"listeners_tested\":%zu}}\n",
                  lazy_status, summary->listeners);
  } else {
    (void)fputs("Configuration valid.\nPlan valid.\n"
                "Startup resources ready.\n", stdout);
    if (plan->lazy == 0) {
      (void)fputs("No lazy external dependencies are planned.\n", stdout);
    } else {
      (void)fputs("Lazy external dependencies not verified.\n", stdout);
    }
  }
}

static const char *log_level_name(fn_log_level_t level)
{
  switch (level) {
    case FN_LOG_ERROR: return "error";
    case FN_LOG_WARN: return "warn";
    case FN_LOG_INFO: return "info";
    case FN_LOG_DEBUG: return "debug";
    case FN_LOG_TRACE: return "trace";
  }
  return "unknown";
}

static void stderr_log_sink(void *context, const fn_log_record_t *record)
{
  FILE *stream = context;
  (void)fprintf(stream,
                "%s %s stage=%s origin=%s native=%lld message=%s\n",
                log_level_name(record->level), record->code,
                fn_error_stage_name(record->result.stage),
                fn_error_origin_name(record->result.origin),
                (long long)record->result.native_code, record->message);
}

static void run_event(unsigned long long sequence, const char *event,
                      const char *status, uint64_t generation,
                      int exit_code,
                      const command_diagnostic_t *diagnostic,
                      const fn_app_summary_t *summary)
{
  (void)fprintf(stdout,
                "{\"format_version\":1,\"schema\":"
                "\"flick.run-event\",\"sequence\":%llu,\"event\":",
                sequence);
  json_string(stdout, event);
  (void)fputs(",\"status\":", stdout);
  json_string(stdout, status);
  if (strcmp(event, "started") == 0) {
    (void)fprintf(stdout, ",\"generation\":%llu",
                  (unsigned long long)generation);
  } else {
    (void)fprintf(stdout, ",\"exit_code\":%d", exit_code);
  }
  (void)fputs(",\"errors\":[", stdout);
  if (diagnostic != NULL) {
    json_diagnostic(stdout, diagnostic);
  }
  (void)fputs("],\"warnings\":[]", stdout);
  if (summary != NULL && strcmp(event, "started") != 0) {
    (void)fprintf(stdout,
                  ",\"counters\":{\"loop_iterations\":%llu,"
                  "\"io_callbacks\":%llu,"
                  "\"terminal_callbacks\":%llu,"
                  "\"accepted_connections\":%llu,"
                  "\"completed_sessions\":%llu,"
                  "\"failed_sessions\":%llu}",
                  (unsigned long long)summary->loop.run_iterations,
                  (unsigned long long)summary->loop.io_callbacks,
                  (unsigned long long)summary->loop.terminal_callbacks,
                  (unsigned long long)summary->accepted_connections,
                  (unsigned long long)summary->completed_sessions,
                  (unsigned long long)summary->failed_sessions);
  }
  (void)fputs("}\n", stdout);
  (void)fflush(stdout);
}

static int run_command(const fn_cli_options_t *options,
                       const fn_config_t *config,
                       const fn_feature_plan_t *plan)
{
  fn_logger_t logger;
  fn_app_t *app = NULL;
  fn_app_summary_t summary;
  fn_result_t result;
  fn_result_t destroy_result;
  command_diagnostic_t diagnostic;
  int exit_code;
  diagnostic_clear(&diagnostic);
  result = fn_logger_init(&logger, true, config->log_level,
                          stderr_log_sink, stderr);
  if (result.code == FN_OK) {
    result = fn_app_create(config, plan, &logger, &app);
  }
  if (result.code != FN_OK) {
    exit_code = result.stage == FN_STAGE_PREPARE ? 5 : 6;
    diagnostic_from_result(&diagnostic,
                           result.stage == FN_STAGE_PREPARE ?
                             "E_EXTERNAL_DEPENDENCY" : "E_STARTUP",
                           result, "Run startup failed.");
    if (options->output == FN_CLI_OUTPUT_JSON) {
      run_event(1u, "failed", "error", 0, exit_code, &diagnostic, NULL);
    } else {
      text_diagnostic(&diagnostic);
    }
    return exit_code;
  }
  memset(&summary, 0, sizeof(summary));
  (void)fn_app_snapshot(app, &summary);
  if (options->output == FN_CLI_OUTPUT_JSON) {
    run_event(1u, "started", "ok", summary.generation, 0, NULL, NULL);
  } else {
    (void)printf("FlickNet started. generation=%llu\n",
                 (unsigned long long)summary.generation);
    (void)fflush(stdout);
  }
  result = fn_app_run(app, &summary);
  destroy_result = fn_app_destroy(&app);
  if (result.code == FN_TIMEOUT && result.stage == FN_STAGE_SHUTDOWN) {
    exit_code = 8;
    diagnostic_from_result(&diagnostic, "E_SHUTDOWN_TIMEOUT", result,
                           "Run was forced to stop.");
  } else if (result.code != FN_OK) {
    exit_code = 7;
    diagnostic_from_result(&diagnostic, "E_RUNTIME", result,
                           "Run stopped after a runtime error.");
  } else if (destroy_result.code != FN_OK) {
    exit_code = 70;
    diagnostic_from_result(&diagnostic, "E_INTERNAL", destroy_result,
                           "Run cleanup failed.");
  } else {
    exit_code = 0;
  }
  if (options->output == FN_CLI_OUTPUT_JSON) {
    run_event(2u, exit_code == 0 ? "stopped" : "failed",
              exit_code == 0 ? "ok" : "error", summary.generation,
              exit_code, exit_code == 0 ? NULL : &diagnostic, &summary);
  } else if (exit_code == 0) {
    (void)printf("FlickNet stopped. sessions=%llu loop_iterations=%llu\n",
                 (unsigned long long)summary.completed_sessions,
                 (unsigned long long)summary.loop.run_iterations);
  } else {
    text_diagnostic(&diagnostic);
  }
  return exit_code;
}

int main(int argc, char **argv)
{
  const char **arguments;
  int argument_index;
  fn_cli_options_t options;
  fn_cli_error_t cli_error;
  command_diagnostic_t diagnostic;
  fn_config_t config;
  fn_feature_plan_t plan;
  fn_app_summary_t test_summary;
  fn_result_t result;
  int exit_code;
  diagnostic_clear(&diagnostic);
  arguments = malloc((size_t)(argc > 0 ? argc : 1) * sizeof(*arguments));
  if (arguments == NULL) {
    diagnostic_set(&diagnostic, "E_INTERNAL", "",
                   "CLI argument allocation failed.");
    memset(&options, 0, sizeof(options));
    emit_error(&options, 70, &diagnostic);
    return 70;
  }
  for (argument_index = 0; argument_index < argc; argument_index++) {
    arguments[argument_index] = argv[argument_index];
  }
  result = fn_cli_parse(argc, arguments, &options, &cli_error);
  free(arguments);
  if (result.code != FN_OK) {
    diagnostic_set(&diagnostic, cli_error.code, cli_error.path,
                   cli_error.message);
    emit_error(&options, 2, &diagnostic);
    return 2;
  }
  if (options.help) {
    print_help(options.command);
    return 0;
  }
  if (options.command == FN_CLI_COMMAND_VERSION) {
    emit_version(&options);
    return 0;
  }
  if (options.command == FN_CLI_COMMAND_STOP ||
      options.command == FN_CLI_COMMAND_RELOAD ||
      options.command == FN_CLI_COMMAND_STATUS) {
    diagnostic_set(&diagnostic, "E_UNSUPPORTED_VERSION", "",
                   "This command requires FlickNet V0.5.");
    emit_error(&options, 4, &diagnostic);
    return 4;
  }

  exit_code = load_and_plan(&options, &config, &plan, &diagnostic);
  if (exit_code != 0) {
    emit_error(&options, exit_code, &diagnostic);
    return exit_code;
  }
  if (options.command == FN_CLI_COMMAND_CHECK) {
    emit_check_success(&options);
    fn_config_destroy(&config);
    return 0;
  }
  if (options.command == FN_CLI_COMMAND_TEST) {
    memset(&test_summary, 0, sizeof(test_summary));
    result = fn_app_test_environment(&config, &plan, &test_summary);
    if (result.code != FN_OK) {
      diagnostic_from_result(&diagnostic, "E_EXTERNAL_DEPENDENCY", result,
                             "Startup resource validation failed.");
      emit_error(&options, 5, &diagnostic);
      fn_config_destroy(&config);
      return 5;
    }
    emit_test_success(&options, &plan, &test_summary);
    fn_config_destroy(&config);
    return 0;
  }
  exit_code = run_command(&options, &config, &plan);
  fn_config_destroy(&config);
  return exit_code;
}
