#ifndef FLICKNET_CLOCK_H
#define FLICKNET_CLOCK_H

#include "flicknet/result.h"

#include <stdint.h>

/* fn_monotonic_now_ms 不在失败时退回墙上时钟。 */
fn_result_t fn_monotonic_now_ms(uint64_t *out_ms);

/* 暴露纯转换函数，便于验证纳秒范围和整数溢出。 */
fn_result_t fn_monotonic_parts_ms(uint64_t seconds, uint32_t nanoseconds,
                                  uint64_t *out_ms);
fn_result_t fn_deadline_after_ms(uint64_t now_ms, uint64_t duration_ms,
                                 uint64_t *out_deadline_ms);
uint64_t fn_deadline_remaining_ms(uint64_t now_ms, uint64_t deadline_ms);
uint64_t fn_deadline_min(uint64_t left_ms, uint64_t right_ms);

#endif
