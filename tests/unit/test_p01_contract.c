#include "flicknet/build.h"
#include "flicknet/result.h"

#include <ev.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <yaml.h>

static int check_result_contract(void)
{
  const fn_result_t result = fn_result_make(
    FN_CONNECTION_REFUSED, FN_STAGE_TCP_CONNECT,
    FN_ERROR_ORIGIN_POSIX, INT64_C(111));

  if (result.code != FN_CONNECTION_REFUSED ||
      result.stage != FN_STAGE_TCP_CONNECT ||
      result.origin != FN_ERROR_ORIGIN_POSIX ||
      result.native_code != INT64_C(111)) {
    return 1;
  }
  if (!fn_result_is_error(result) ||
      !fn_result_is_error(fn_result_make(FN_CANCELLED, FN_STAGE_SHUTDOWN,
                                         FN_ERROR_ORIGIN_NONE, INT64_C(0))) ||
      fn_result_is_error(fn_result_make(FN_OK, FN_STAGE_NONE,
                                        FN_ERROR_ORIGIN_NONE, INT64_C(0))) ||
      fn_result_is_error(fn_result_make(FN_AGAIN, FN_STAGE_RELAY,
                                        FN_ERROR_ORIGIN_NONE, INT64_C(0))) ||
      fn_result_is_error(fn_result_make(FN_EOF, FN_STAGE_RELAY,
                                        FN_ERROR_ORIGIN_NONE, INT64_C(0)))) {
    return 2;
  }
  if (strcmp(fn_status_name(FN_TIMEOUT), "timeout") != 0 ||
      strcmp(fn_error_stage_name(FN_STAGE_RESOURCE), "resource") != 0 ||
      strcmp(fn_error_origin_name(FN_ERROR_ORIGIN_DNS), "dns") != 0 ||
      strcmp(fn_status_name((fn_status_t)999), "unknown") != 0 ||
      strcmp(fn_error_stage_name((fn_error_stage_t)999), "unknown") != 0 ||
      strcmp(fn_error_origin_name((fn_error_origin_t)999), "unknown") != 0) {
    return 3;
  }
  return 0;
}

static int check_dependency_contract(void)
{
  struct ev_loop *loop;
  yaml_parser_t parser;
  int yaml_major = 0;
  int yaml_minor = 0;
  int yaml_patch = 0;

  if (ev_version_major() < 4 ||
      (ev_version_major() == 4 && ev_version_minor() < 33)) {
    return 10;
  }
  loop = ev_loop_new(EVFLAG_NOENV);
  if (loop == NULL) {
    return 11;
  }
  ev_loop_destroy(loop);

  yaml_get_version(&yaml_major, &yaml_minor, &yaml_patch);
  if (yaml_major < 0 ||
      (yaml_major == 0 &&
       (yaml_minor < 2 || (yaml_minor == 2 && yaml_patch < 5)))) {
    return 12;
  }
  if (!yaml_parser_initialize(&parser)) {
    return 13;
  }
  yaml_parser_delete(&parser);
  return 0;
}

int main(void)
{
  int result_check;
  int dependency_check;

  if (fn_build_compiled_features() !=
      (FN_FEATURE_DIRECT_TCP | FN_FEATURE_DNS_FAILURE_CACHE |
       FN_FEATURE_DNS_RESOLVER | FN_FEATURE_DNS_UPSTREAM_TCP |
       FN_FEATURE_DNS_UPSTREAM_UDP | FN_FEATURE_SOCKS_IN_TCP |
       FN_FEATURE_SOCKS_OUT_TCP)) {
    fputs("Compiled capability set does not match P11.\n", stderr);
    return 20;
  }

  result_check = check_result_contract();
  if (result_check != 0) {
    fprintf(stderr, "Structured result check failed: %d.\n", result_check);
    return 21;
  }

  dependency_check = check_dependency_contract();
  if (dependency_check != 0) {
    fprintf(stderr, "Dependency lifecycle check failed: %d.\n",
            dependency_check);
    return 22;
  }

  puts("P01 contract checks passed.");
  return 0;
}
