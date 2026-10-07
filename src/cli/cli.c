#include "flicknet/cli.h"

#include <stdio.h>
#include <string.h>

static fn_result_t cli_result(fn_status_t code)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE :
                                               FN_STAGE_CONFIG,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static fn_result_t cli_error(fn_cli_error_t *error, const char *message)
{
  if (error != NULL) {
    memset(error, 0, sizeof(*error));
    (void)snprintf(error->code, sizeof(error->code), "%s", "E_CLI_USAGE");
    (void)snprintf(error->message, sizeof(error->message), "%s", message);
  }
  return cli_result(FN_INVALID);
}

static fn_cli_command_t parse_command(const char *value)
{
  if (strcmp(value, "run") == 0) return FN_CLI_COMMAND_RUN;
  if (strcmp(value, "check") == 0) return FN_CLI_COMMAND_CHECK;
  if (strcmp(value, "test") == 0) return FN_CLI_COMMAND_TEST;
  if (strcmp(value, "version") == 0) return FN_CLI_COMMAND_VERSION;
  if (strcmp(value, "stop") == 0) return FN_CLI_COMMAND_STOP;
  if (strcmp(value, "reload") == 0) return FN_CLI_COMMAND_RELOAD;
  if (strcmp(value, "status") == 0) return FN_CLI_COMMAND_STATUS;
  return FN_CLI_COMMAND_NONE;
}

const char *fn_cli_command_name(fn_cli_command_t command)
{
  switch (command) {
    case FN_CLI_COMMAND_NONE: return "cli";
    case FN_CLI_COMMAND_RUN: return "run";
    case FN_CLI_COMMAND_CHECK: return "check";
    case FN_CLI_COMMAND_TEST: return "test";
    case FN_CLI_COMMAND_VERSION: return "version";
    case FN_CLI_COMMAND_STOP: return "stop";
    case FN_CLI_COMMAND_RELOAD: return "reload";
    case FN_CLI_COMMAND_STATUS: return "status";
  }
  return "cli";
}

fn_result_t fn_cli_parse(int argc, const char *const argv[],
                         fn_cli_options_t *out, fn_cli_error_t *error)
{
  int index = 1;
  bool config_seen = false;
  bool output_seen = false;
  if (out == NULL || argc < 1 || argv == NULL || argv[0] == NULL) {
    return cli_error(error, "Invalid command arguments.");
  }
  memset(out, 0, sizeof(*out));
  if (error != NULL) {
    memset(error, 0, sizeof(*error));
  }

  if (argc == 2 && (strcmp(argv[1], "--help") == 0 ||
                    strcmp(argv[1], "-h") == 0)) {
    out->help = true;
    return cli_result(FN_OK);
  }

  while (index < argc && argv[index][0] == '-') {
    const char *option = argv[index];
    if (strcmp(option, "--config") == 0 || strcmp(option, "-c") == 0) {
      if (config_seen) {
        return cli_error(error, "The config option may only appear once.");
      }
      if (index + 1 >= argc) {
        return cli_error(error, "The config option requires a path.");
      }
      config_seen = true;
      out->config_path = argv[index + 1];
      index += 2;
      continue;
    }
    if (strcmp(option, "--output") == 0) {
      if (output_seen) {
        return cli_error(error, "The output option may only appear once.");
      }
      if (index + 1 >= argc) {
        return cli_error(error, "The output option requires text or json.");
      }
      output_seen = true;
      if (strcmp(argv[index + 1], "text") == 0) {
        out->output = FN_CLI_OUTPUT_TEXT;
      } else if (strcmp(argv[index + 1], "json") == 0) {
        out->output = FN_CLI_OUTPUT_JSON;
      } else {
        return cli_error(error, "The output value must be text or json.");
      }
      index += 2;
      continue;
    }
    return cli_error(error, "Unknown global option.");
  }

  if (index >= argc) {
    return cli_error(error, "A command is required.");
  }
  out->command = parse_command(argv[index]);
  if (out->command == FN_CLI_COMMAND_NONE) {
    return cli_error(error, "Unknown command.");
  }
  index++;
  if (config_seen && out->command != FN_CLI_COMMAND_RUN &&
      out->command != FN_CLI_COMMAND_CHECK &&
      out->command != FN_CLI_COMMAND_TEST) {
    return cli_error(error,
                     "This command does not accept a config path.");
  }

  if (index < argc && (strcmp(argv[index], "--help") == 0 ||
                       strcmp(argv[index], "-h") == 0)) {
    if (index + 1 != argc) {
      return cli_error(error, "Help cannot be combined with other arguments.");
    }
    out->help = true;
    return cli_result(FN_OK);
  }
  if (out->command == FN_CLI_COMMAND_VERSION && index < argc &&
      strcmp(argv[index], "--features") == 0) {
    out->features = true;
    index++;
  }
  if (index != argc) {
    return cli_error(error, "Unexpected command argument.");
  }
  return cli_result(FN_OK);
}
