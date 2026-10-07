#ifndef FLICKNET_CONFIG_H
#define FLICKNET_CONFIG_H

#include "flicknet/address.h"
#include "flicknet/build.h"
#include "flicknet/pool.h"
#include "flicknet/resource.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FN_CONFIG_MAX_BYTES ((size_t)1024u * 1024u)
#define FN_CONFIG_MAX_DEPTH 16u
#define FN_CONFIG_MAX_NODES 100000u
#define FN_CONFIG_MAX_SCALAR ((size_t)64u * 1024u)
#define FN_CONFIG_NAME_MAX 64u
#define FN_CONFIG_RULE_MAX 1024u
#define FN_CONFIG_PATH_MAX 256u

typedef enum {
  FN_CONFIG_ERROR_NONE = 0,
  FN_CONFIG_ERROR_SIZE,
  FN_CONFIG_ERROR_UTF8,
  FN_CONFIG_ERROR_YAML_SYNTAX,
  FN_CONFIG_ERROR_YAML_LIMIT,
  FN_CONFIG_ERROR_YAML_UNSUPPORTED,
  FN_CONFIG_ERROR_DUPLICATE_KEY,
  FN_CONFIG_ERROR_UNKNOWN_FIELD,
  FN_CONFIG_ERROR_REQUIRED,
  FN_CONFIG_ERROR_NULL,
  FN_CONFIG_ERROR_TYPE,
  FN_CONFIG_ERROR_FORMAT,
  FN_CONFIG_ERROR_RANGE,
  FN_CONFIG_ERROR_OVERFLOW,
  FN_CONFIG_ERROR_COLLECTION_LIMIT,
  FN_CONFIG_ERROR_UNSUPPORTED_VERSION,
  FN_CONFIG_ERROR_FEATURE_UNAVAILABLE,
  FN_CONFIG_ERROR_DUPLICATE_NAME,
  FN_CONFIG_ERROR_DUPLICATE_VALUE,
  FN_CONFIG_ERROR_REFERENCE,
  FN_CONFIG_ERROR_RULE_ORDER,
  FN_CONFIG_ERROR_LISTENER_CONFLICT,
  FN_CONFIG_ERROR_DNS_REQUIRED,
  FN_CONFIG_ERROR_RESOURCE_PLAN,
  FN_CONFIG_ERROR_NO_MEMORY
} fn_config_error_code_t;

typedef struct {
  fn_config_error_code_t code;
  char path[FN_CONFIG_PATH_MAX];
  size_t line;
  size_t column;
  bool has_mark;
  char message[128];
} fn_config_error_t;

typedef enum {
  FN_LOG_ERROR = 0,
  FN_LOG_WARN,
  FN_LOG_INFO,
  FN_LOG_DEBUG,
  FN_LOG_TRACE
} fn_log_level_t;

typedef struct {
  uint64_t handshake_ms;
  uint64_t connect_ms;
  uint64_t tcp_idle_ms;
  uint64_t drain_ms;
  uint64_t resource_wait_ms;
  uint64_t worker_task_ms;
} fn_timeouts_t;

typedef struct {
  char username[256];
  uint8_t username_length;
  char password[256];
  uint8_t password_length;
} fn_user_config_t;

typedef struct {
  char name[FN_CONFIG_NAME_MAX + 1u];
  fn_addr_t listen;
  uint16_t port;
  bool udp;
  size_t user_count;
  fn_user_config_t *users;
} fn_inbound_config_t;

typedef struct {
  char name[FN_CONFIG_NAME_MAX + 1u];
  fn_addr_t server;
  uint16_t port;
  bool udp;
  bool has_credentials;
  fn_user_config_t credentials;
} fn_proxy_config_t;

typedef struct {
  char target[FN_CONFIG_NAME_MAX + 1u];
} fn_rule_config_t;

typedef enum {
  FN_DNS_TRANSPORT_UDP = 0,
  FN_DNS_TRANSPORT_TCP
} fn_dns_transport_t;

typedef struct {
  fn_dns_transport_t transport;
  fn_endpoint_t endpoint;
} fn_dns_upstream_t;

typedef struct {
  bool enable;
  bool direct_present;
  bool bootstrap_present;
  size_t direct_count;
  fn_dns_upstream_t direct[16];
  size_t bootstrap_count;
  fn_dns_upstream_t bootstrap[16];
  uint64_t timeout_ms;
  uint32_t attempts;
  size_t failure_cache_size;
  uint64_t failure_cache_ttl_ms;
} fn_dns_config_t;

typedef struct {
  uint32_t schema_version;
  fn_log_level_t log_level;
  bool ipv6;
  fn_limits_t limits;
  fn_timeouts_t timeouts;
  size_t inbound_count;
  fn_inbound_config_t *inbounds;
  size_t proxy_count;
  fn_proxy_config_t *proxies;
  size_t rule_count;
  fn_rule_config_t *rules;
  fn_dns_config_t dns;
  fn_allocator_t allocator;
} fn_config_t;

typedef struct {
  fn_feature_set_t reachable;
  fn_feature_set_t prepare;
  fn_feature_set_t lazy;
} fn_feature_plan_t;

const char *fn_config_error_code_name(fn_config_error_code_t code);

/* fn_config_parse 只解析和校验，不读取文件、绑定端口或访问网络。 */
fn_result_t fn_config_parse(const uint8_t *input, size_t input_length,
                            fn_allocator_t allocator, fn_config_t *out,
                            fn_config_error_t *error);
/* fn_config_destroy 销毁成功结果或失败后仍可安全销毁的空结果。 */
void fn_config_destroy(fn_config_t *config);

/* fn_config_plan 从已校验 Typed Config 计算闭包并检查构建能力。 */
fn_result_t fn_config_plan(const fn_config_t *config,
                           fn_feature_set_t available_features,
                           fn_feature_plan_t *out,
                           fn_config_error_t *error);

#endif
