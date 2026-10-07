#ifndef FLICKNET_OBSERVABILITY_H
#define FLICKNET_OBSERVABILITY_H

#include "flicknet/config.h"
#include "flicknet/result.h"

#include <stdbool.h>
#include <stdint.h>

#define FN_LOG_CODE_MAX 47u
#define FN_LOG_MESSAGE_MAX 255u

typedef struct {
  fn_log_level_t level;
  char code[FN_LOG_CODE_MAX + 1u];
  fn_result_t result;
  char message[FN_LOG_MESSAGE_MAX + 1u];
} fn_log_record_t;

typedef void (*fn_log_sink_fn)(void *context,
                               const fn_log_record_t *record);
typedef void (*fn_log_message_builder_fn)(void *context, char *message,
                                          size_t capacity);

typedef struct {
  bool enabled;
  fn_log_level_t threshold;
  fn_log_sink_fn sink;
  void *sink_context;
  uint64_t attempts;
  uint64_t records_constructed;
  uint64_t records_emitted;
} fn_logger_t;

typedef struct {
  uint64_t attempts;
  uint64_t records_constructed;
  uint64_t records_emitted;
} fn_logger_snapshot_t;

/* fn_logger_init 只保存 sink；关闭时后续 emit 不构造或格式化记录。 */
fn_result_t fn_logger_init(fn_logger_t *logger, bool enabled,
                           fn_log_level_t threshold, fn_log_sink_fn sink,
                           void *sink_context);
bool fn_logger_enabled(const fn_logger_t *logger, fn_log_level_t level);
/* fn_logger_emit 在 level 门控之后才调用 builder 并构造记录。 */
fn_result_t fn_logger_emit(fn_logger_t *logger, fn_log_level_t level,
                           const char *code, fn_result_t result,
                           fn_log_message_builder_fn builder,
                           void *builder_context);
fn_result_t fn_logger_emit_message(fn_logger_t *logger,
                                   fn_log_level_t level,
                                   const char *code, fn_result_t result,
                                   const char *message);
fn_result_t fn_logger_snapshot(const fn_logger_t *logger,
                               fn_logger_snapshot_t *out);

#endif
