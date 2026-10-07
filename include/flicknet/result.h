#ifndef FLICKNET_RESULT_H
#define FLICKNET_RESULT_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
  FN_OK = 0,
  FN_AGAIN,
  FN_EOF,
  FN_CANCELLED,
  FN_INVALID,
  FN_UNSUPPORTED,
  FN_LIMIT,
  FN_NO_MEMORY,
  FN_TIMEOUT,
  FN_IO_ERROR,
  FN_PROTOCOL_ERROR,
  FN_AUTH_ERROR,
  FN_RESOLVE_ERROR,
  FN_CONNECT_ERROR,
  FN_REJECTED,
  FN_RESTART_REQUIRED,
  FN_STALE_GENERATION,
  FN_CONNECTION_REFUSED,
  FN_TLS_VERIFY_ERROR,
  FN_FEATURE_UNAVAILABLE
} fn_status_t;

typedef enum {
  FN_STAGE_NONE = 0,
  FN_STAGE_CONFIG,
  FN_STAGE_PLAN,
  FN_STAGE_PREPARE,
  FN_STAGE_ACCEPT,
  FN_STAGE_INBOUND_HANDSHAKE,
  FN_STAGE_RESOLVE,
  FN_STAGE_TCP_CONNECT,
  FN_STAGE_TLS_HANDSHAKE,
  FN_STAGE_TLS_VERIFY,
  FN_STAGE_SOCKS_AUTH,
  FN_STAGE_SOCKS_CONNECT,
  FN_STAGE_ANYTLS_AUTH,
  FN_STAGE_ANYTLS_OPEN,
  FN_STAGE_ROUTE,
  FN_STAGE_RELAY,
  FN_STAGE_DRAIN,
  FN_STAGE_PERSIST,
  FN_STAGE_RESOURCE,
  FN_STAGE_CONTROL,
  FN_STAGE_SHUTDOWN
} fn_error_stage_t;

typedef enum {
  FN_ERROR_ORIGIN_NONE = 0,
  FN_ERROR_ORIGIN_POSIX,
  FN_ERROR_ORIGIN_WIN32,
  FN_ERROR_ORIGIN_WSA,
  FN_ERROR_ORIGIN_TLS,
  FN_ERROR_ORIGIN_SOCKS,
  FN_ERROR_ORIGIN_ANYTLS,
  FN_ERROR_ORIGIN_DNS
} fn_error_origin_t;

/* fn_result_t 是值对象；native_code 只有和 origin 一起才有意义。 */
typedef struct {
  fn_status_t code;
  fn_error_stage_t stage;
  fn_error_origin_t origin;
  int64_t native_code;
} fn_result_t;

/* fn_result_make 不读取 errno，调用者必须在失败点传入已捕获的原始码。 */
fn_result_t fn_result_make(fn_status_t code, fn_error_stage_t stage,
                           fn_error_origin_t origin, int64_t native_code);
bool fn_result_is_error(fn_result_t result);
const char *fn_status_name(fn_status_t status);
const char *fn_error_stage_name(fn_error_stage_t stage);
const char *fn_error_origin_name(fn_error_origin_t origin);

#endif
