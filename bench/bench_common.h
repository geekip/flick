#ifndef FLICKNET_BENCH_COMMON_H
#define FLICKNET_BENCH_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define FN_BENCH_PLAN_HEADER_BYTES 72u
#define FN_BENCH_PLAN_RECORD_BYTES 32u
#define FN_BENCH_MAX_CASES 16u
#define FN_BENCH_MAX_MEASUREMENTS 8u
#define FN_BENCH_MAX_SAMPLES 64u

typedef struct {
  const char *workload_path;
  const char *workload_sha256;
  const char *plan_path;
  const char *fixture_dir;
  const char *output_path;
  uint32_t warmup_count;
  uint32_t sample_count;
  uint64_t seed;
} fn_bench_args_t;

typedef struct {
  uint32_t case_id;
  uint32_t parameter_kind;
  uint64_t primary;
  uint64_t secondary;
  uint64_t tertiary;
} fn_bench_plan_record_t;

typedef struct {
  uint32_t target_id;
  uint64_t seed;
  uint32_t warmup_count;
  uint32_t sample_count;
  uint32_t case_count;
  fn_bench_plan_record_t records[FN_BENCH_MAX_CASES];
} fn_bench_plan_t;

typedef struct {
  uint32_t case_id;
  uint32_t parameter_kind;
  uint64_t primary_min;
  uint64_t primary_max;
  uint64_t secondary_min;
  uint64_t secondary_max;
  uint64_t tertiary_min;
  uint64_t tertiary_max;
} fn_bench_plan_expectation_t;

typedef struct {
  const char *unit;
  const char *direction;
  double samples[FN_BENCH_MAX_SAMPLES];
  size_t sample_count;
} fn_bench_measurement_t;

typedef struct {
  const char *name;
  const char *phase;
  fn_bench_measurement_t measurements[FN_BENCH_MAX_MEASUREMENTS];
  size_t measurement_count;
  bool behavior_ok;
  bool cleanup_ok;
} fn_bench_case_t;

int fn_bench_parse_args(int argc, char **argv, fn_bench_args_t *out);
int fn_bench_plan_load(const fn_bench_args_t *args, uint32_t target_id,
                       const fn_bench_plan_expectation_t *expected,
                       size_t expected_count, fn_bench_plan_t *out);
uint64_t fn_bench_monotonic_ns(void);
uint64_t fn_bench_process_cpu_ns(void);
double fn_bench_nearest_rank(const double *values, size_t count,
                             double percentile);
bool fn_bench_values_finite(const double *values, size_t count);
int fn_bench_case_add(fn_bench_case_t *bench_case, const char *unit,
                      const char *direction, double value);
int fn_bench_write_target(const fn_bench_args_t *args,
                          const fn_bench_plan_t *plan,
                          const char *target,
                          const fn_bench_case_t *cases,
                          size_t case_count, uint64_t duration_ns);
int fn_bench_read_file(const char *path, unsigned char **data,
                       size_t *length);
void fn_bench_free_file(unsigned char **data);

#endif
