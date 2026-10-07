#include "flicknet/result.h"

/* fn_result_make 只组装已捕获的字段，不读取全局错误状态或写日志。 */
fn_result_t fn_result_make(fn_status_t code, fn_error_stage_t stage,
                           fn_error_origin_t origin, int64_t native_code)
{
  fn_result_t result = {
    .code = code,
    .stage = stage,
    .origin = origin,
    .native_code = native_code,
  };
  return result;
}

/* fn_result_is_error 把 AGAIN 和 EOF 保留为控制状态。 */
bool fn_result_is_error(fn_result_t result)
{
  return result.code != FN_OK && result.code != FN_AGAIN &&
         result.code != FN_EOF;
}

const char *fn_status_name(fn_status_t status)
{
  switch (status) {
    case FN_OK: return "ok";
    case FN_AGAIN: return "again";
    case FN_EOF: return "eof";
    case FN_CANCELLED: return "cancelled";
    case FN_INVALID: return "invalid";
    case FN_UNSUPPORTED: return "unsupported";
    case FN_LIMIT: return "limit";
    case FN_NO_MEMORY: return "no_memory";
    case FN_TIMEOUT: return "timeout";
    case FN_IO_ERROR: return "io_error";
    case FN_PROTOCOL_ERROR: return "protocol_error";
    case FN_AUTH_ERROR: return "auth_error";
    case FN_RESOLVE_ERROR: return "resolve_error";
    case FN_CONNECT_ERROR: return "connect_error";
    case FN_REJECTED: return "rejected";
    case FN_RESTART_REQUIRED: return "restart_required";
    case FN_STALE_GENERATION: return "stale_generation";
    case FN_CONNECTION_REFUSED: return "connection_refused";
    case FN_TLS_VERIFY_ERROR: return "tls_verify_error";
    case FN_FEATURE_UNAVAILABLE: return "feature_unavailable";
  }
  return "unknown";
}

const char *fn_error_stage_name(fn_error_stage_t stage)
{
  switch (stage) {
    case FN_STAGE_NONE: return "none";
    case FN_STAGE_CONFIG: return "config";
    case FN_STAGE_PLAN: return "plan";
    case FN_STAGE_PREPARE: return "prepare";
    case FN_STAGE_ACCEPT: return "accept";
    case FN_STAGE_INBOUND_HANDSHAKE: return "inbound_handshake";
    case FN_STAGE_RESOLVE: return "resolve";
    case FN_STAGE_TCP_CONNECT: return "tcp_connect";
    case FN_STAGE_TLS_HANDSHAKE: return "tls_handshake";
    case FN_STAGE_TLS_VERIFY: return "tls_verify";
    case FN_STAGE_SOCKS_AUTH: return "socks_auth";
    case FN_STAGE_SOCKS_CONNECT: return "socks_connect";
    case FN_STAGE_ANYTLS_AUTH: return "anytls_auth";
    case FN_STAGE_ANYTLS_OPEN: return "anytls_open";
    case FN_STAGE_ROUTE: return "route";
    case FN_STAGE_RELAY: return "relay";
    case FN_STAGE_DRAIN: return "drain";
    case FN_STAGE_PERSIST: return "persist";
    case FN_STAGE_RESOURCE: return "resource";
    case FN_STAGE_CONTROL: return "control";
    case FN_STAGE_SHUTDOWN: return "shutdown";
  }
  return "unknown";
}

const char *fn_error_origin_name(fn_error_origin_t origin)
{
  switch (origin) {
    case FN_ERROR_ORIGIN_NONE: return "none";
    case FN_ERROR_ORIGIN_POSIX: return "posix";
    case FN_ERROR_ORIGIN_WIN32: return "win32";
    case FN_ERROR_ORIGIN_WSA: return "wsa";
    case FN_ERROR_ORIGIN_TLS: return "tls";
    case FN_ERROR_ORIGIN_SOCKS: return "socks";
    case FN_ERROR_ORIGIN_ANYTLS: return "anytls";
    case FN_ERROR_ORIGIN_DNS: return "dns";
  }
  return "unknown";
}
