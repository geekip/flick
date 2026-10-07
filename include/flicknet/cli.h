#ifndef FLICKNET_CLI_H
#define FLICKNET_CLI_H

#include "flicknet/result.h"

#include <stdbool.h>
#include <stddef.h>

typedef enum {
  FN_CLI_COMMAND_NONE = 0,
  FN_CLI_COMMAND_RUN,
  FN_CLI_COMMAND_CHECK,
  FN_CLI_COMMAND_TEST,
  FN_CLI_COMMAND_VERSION,
  FN_CLI_COMMAND_STOP,
  FN_CLI_COMMAND_RELOAD,
  FN_CLI_COMMAND_STATUS
} fn_cli_command_t;

typedef enum {
  FN_CLI_OUTPUT_TEXT = 0,
  FN_CLI_OUTPUT_JSON
} fn_cli_output_t;

typedef struct {
  fn_cli_command_t command;
  fn_cli_output_t output;
  const char *config_path;
  bool help;
  bool features;
} fn_cli_options_t;

typedef struct {
  char code[32];
  char path[64];
  char message[160];
} fn_cli_error_t;

/* fn_cli_parse 只读取 argv，不访问环境、默认配置或文件系统。 */
fn_result_t fn_cli_parse(int argc, const char *const argv[],
                         fn_cli_options_t *out, fn_cli_error_t *error);
const char *fn_cli_command_name(fn_cli_command_t command);

#endif
