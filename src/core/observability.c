#include "flicknet/observability.h"

#include <stdio.h>
#include <string.h>

static fn_result_t observability_result(fn_status_t code)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE :
                                               FN_STAGE_RESOURCE,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

/* increment_counter 使诊断计数在极限处饱和，避免无符号回绕。 */
static void increment_counter(uint64_t *counter)
{
  if (*counter != UINT64_MAX) {
    (*counter)++;
  }
}

fn_result_t fn_logger_init(fn_logger_t *logger, bool enabled,
                           fn_log_level_t threshold, fn_log_sink_fn sink,
                           void *sink_context)
{
  if (logger == NULL || threshold < FN_LOG_ERROR ||
      threshold > FN_LOG_TRACE || (enabled && sink == NULL)) {
    return observability_result(FN_INVALID);
  }
  memset(logger, 0, sizeof(*logger));
  logger->enabled = enabled;
  logger->threshold = threshold;
  logger->sink = sink;
  logger->sink_context = sink_context;
  return observability_result(FN_OK);
}

bool fn_logger_enabled(const fn_logger_t *logger, fn_log_level_t level)
{
  return logger != NULL && logger->enabled && level >= FN_LOG_ERROR &&
         level <= FN_LOG_TRACE && level <= logger->threshold;
}

fn_result_t fn_logger_emit(fn_logger_t *logger, fn_log_level_t level,
                           const char *code, fn_result_t result,
                           fn_log_message_builder_fn builder,
                           void *builder_context)
{
  fn_log_record_t record;
  if (logger == NULL || code == NULL || builder == NULL ||
      level < FN_LOG_ERROR || level > FN_LOG_TRACE) {
    return observability_result(FN_INVALID);
  }
  increment_counter(&logger->attempts);
  if (!fn_logger_enabled(logger, level)) {
    return observability_result(FN_OK);
  }

  memset(&record, 0, sizeof(record));
  record.level = level;
  record.result = result;
  (void)snprintf(record.code, sizeof(record.code), "%s", code);
  builder(builder_context, record.message, sizeof(record.message));
  record.message[sizeof(record.message) - 1u] = '\0';
  increment_counter(&logger->records_constructed);
  logger->sink(logger->sink_context, &record);
  increment_counter(&logger->records_emitted);
  return observability_result(FN_OK);
}

typedef struct {
  const char *source;
} fn_message_context_t;

static void copy_message(void *context, char *message, size_t capacity)
{
  fn_message_context_t *copy = context;
  (void)snprintf(message, capacity, "%s", copy->source);
}

fn_result_t fn_logger_emit_message(fn_logger_t *logger,
                                   fn_log_level_t level,
                                   const char *code, fn_result_t result,
                                   const char *message)
{
  fn_message_context_t context;
  if (message == NULL) {
    return observability_result(FN_INVALID);
  }
  context.source = message;
  return fn_logger_emit(logger, level, code, result, copy_message,
                        &context);
}

fn_result_t fn_logger_snapshot(const fn_logger_t *logger,
                               fn_logger_snapshot_t *out)
{
  if (logger == NULL || out == NULL) {
    return observability_result(FN_INVALID);
  }
  out->attempts = logger->attempts;
  out->records_constructed = logger->records_constructed;
  out->records_emitted = logger->records_emitted;
  return observability_result(FN_OK);
}
