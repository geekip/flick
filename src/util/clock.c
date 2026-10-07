#define _POSIX_C_SOURCE 200809L

#include "flicknet/clock.h"

#include <errno.h>
#include <time.h>

static fn_result_t clock_result(fn_status_t code, fn_error_origin_t origin,
                                int64_t native_code)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE : FN_STAGE_RESOURCE,
                        origin, native_code);
}

fn_result_t fn_monotonic_parts_ms(uint64_t seconds, uint32_t nanoseconds,
                                  uint64_t *out_ms)
{
  const uint64_t nanos_per_second = UINT64_C(1000000000);
  const uint64_t millis_per_second = UINT64_C(1000);
  uint64_t millis;

  if (out_ms == NULL) {
    return clock_result(FN_INVALID, FN_ERROR_ORIGIN_NONE, INT64_C(0));
  }
  *out_ms = UINT64_C(0);
  if ((uint64_t)nanoseconds >= nanos_per_second ||
      seconds > UINT64_MAX / millis_per_second) {
    return clock_result(FN_LIMIT, FN_ERROR_ORIGIN_NONE, INT64_C(0));
  }
  millis = seconds * millis_per_second;
  if (millis > UINT64_MAX - ((uint64_t)nanoseconds / UINT64_C(1000000))) {
    return clock_result(FN_LIMIT, FN_ERROR_ORIGIN_NONE, INT64_C(0));
  }
  *out_ms = millis + ((uint64_t)nanoseconds / UINT64_C(1000000));
  return clock_result(FN_OK, FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

fn_result_t fn_monotonic_now_ms(uint64_t *out_ms)
{
  struct timespec now;
  int captured_errno;

  if (out_ms == NULL) {
    return clock_result(FN_INVALID, FN_ERROR_ORIGIN_NONE, INT64_C(0));
  }
  *out_ms = UINT64_C(0);
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    captured_errno = errno;
    return clock_result(FN_IO_ERROR, FN_ERROR_ORIGIN_POSIX,
                        (int64_t)captured_errno);
  }
  if (now.tv_sec < (time_t)0 || now.tv_nsec < 0) {
    return clock_result(FN_IO_ERROR, FN_ERROR_ORIGIN_NONE, INT64_C(0));
  }
  return fn_monotonic_parts_ms((uint64_t)now.tv_sec,
                               (uint32_t)now.tv_nsec, out_ms);
}

fn_result_t fn_deadline_after_ms(uint64_t now_ms, uint64_t duration_ms,
                                 uint64_t *out_deadline_ms)
{
  if (out_deadline_ms == NULL) {
    return clock_result(FN_INVALID, FN_ERROR_ORIGIN_NONE, INT64_C(0));
  }
  *out_deadline_ms = UINT64_C(0);
  if (duration_ms > UINT64_MAX - now_ms) {
    return clock_result(FN_LIMIT, FN_ERROR_ORIGIN_NONE, INT64_C(0));
  }
  *out_deadline_ms = now_ms + duration_ms;
  return clock_result(FN_OK, FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

uint64_t fn_deadline_remaining_ms(uint64_t now_ms, uint64_t deadline_ms)
{
  return now_ms >= deadline_ms ? UINT64_C(0) : deadline_ms - now_ms;
}

uint64_t fn_deadline_min(uint64_t left_ms, uint64_t right_ms)
{
  return left_ms < right_ms ? left_ms : right_ms;
}
