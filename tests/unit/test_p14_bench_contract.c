#define _POSIX_C_SOURCE 200809L

#include "bench_common.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef FN_BENCH_WORKLOAD_SHA256
#error "FN_BENCH_WORKLOAD_SHA256 is required"
#endif

static int failures;

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      (void)fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__,        \
                    __LINE__, #condition);                                     \
      failures++;                                                              \
    }                                                                          \
  } while (0)

static void write_u32_le(unsigned char *data, uint32_t value)
{
  data[0] = (unsigned char)value;
  data[1] = (unsigned char)(value >> 8u);
  data[2] = (unsigned char)(value >> 16u);
  data[3] = (unsigned char)(value >> 24u);
}

static void write_u64_le(unsigned char *data, uint64_t value)
{
  size_t index;
  for (index = 0; index < 8u; index++) {
    data[index] = (unsigned char)(value >> (index * 8u));
  }
}

static int hex_value(char value)
{
  if (value >= '0' && value <= '9') {
    return value - '0';
  }
  return value - 'a' + 10;
}

static void make_plan(unsigned char data[104])
{
  size_t index;
  memset(data, 0, 104u);
  memcpy(data, "FNBENCH1", 8u);
  write_u32_le(data + 8u, 1u);
  write_u32_le(data + 12u, 7u);
  for (index = 0; index < 32u; index++) {
    data[16u + index] = (unsigned char)(
      (hex_value(FN_BENCH_WORKLOAD_SHA256[index * 2u]) << 4) |
      hex_value(FN_BENCH_WORKLOAD_SHA256[index * 2u + 1u]));
  }
  write_u64_le(data + 48u, UINT64_C(104729));
  write_u32_le(data + 56u, 5u);
  write_u32_le(data + 60u, 30u);
  write_u32_le(data + 64u, 1u);
  write_u32_le(data + 68u, 0u);
  write_u32_le(data + 72u, 900u);
  write_u32_le(data + 76u, 1u);
  write_u64_le(data + 80u, 1000u);
}

static void save_plan(const char *path, const unsigned char *data,
                      size_t length)
{
  FILE *stream = fopen(path, "wb");
  CHECK(stream != NULL);
  if (stream != NULL) {
    CHECK(fwrite(data, 1u, length, stream) == length);
    CHECK(fclose(stream) == 0);
  }
}

static void test_plan_contract(void)
{
  char path[] = "/tmp/flick-p14-plan-XXXXXX";
  int descriptor = mkstemp(path);
  unsigned char valid[104];
  unsigned char changed[105];
  fn_bench_args_t args;
  fn_bench_plan_t plan;
  const fn_bench_plan_expectation_t expected = {
    900u, 1u, 1u, 1000u, 0u, 0u, 0u, 0u,
  };
  CHECK(descriptor >= 0);
  if (descriptor >= 0) {
    CHECK(close(descriptor) == 0);
  }
  memset(&args, 0, sizeof(args));
  args.plan_path = path;
  args.workload_sha256 = FN_BENCH_WORKLOAD_SHA256;
  args.seed = UINT64_C(104729);
  args.warmup_count = 5u;
  args.sample_count = 30u;
  make_plan(valid);
  save_plan(path, valid, sizeof(valid));
  CHECK(fn_bench_plan_load(&args, 7u, &expected, 1u, &plan) == 0);
  CHECK(plan.records[0].primary == 1000u);

  memcpy(changed, valid, sizeof(valid));
  changed[0] = 'X';
  save_plan(path, changed, sizeof(valid));
  CHECK(fn_bench_plan_load(&args, 7u, &expected, 1u, &plan) != 0);

  memcpy(changed, valid, sizeof(valid));
  write_u32_le(changed + 8u, 2u);
  save_plan(path, changed, sizeof(valid));
  CHECK(fn_bench_plan_load(&args, 7u, &expected, 1u, &plan) != 0);

  memcpy(changed, valid, sizeof(valid));
  write_u32_le(changed + 12u, 8u);
  save_plan(path, changed, sizeof(valid));
  CHECK(fn_bench_plan_load(&args, 7u, &expected, 1u, &plan) != 0);

  memcpy(changed, valid, sizeof(valid));
  changed[16] ^= 1u;
  save_plan(path, changed, sizeof(valid));
  CHECK(fn_bench_plan_load(&args, 7u, &expected, 1u, &plan) != 0);

  save_plan(path, valid, sizeof(valid) - 1u);
  CHECK(fn_bench_plan_load(&args, 7u, &expected, 1u, &plan) != 0);

  memcpy(changed, valid, sizeof(valid));
  write_u32_le(changed + 72u, 901u);
  save_plan(path, changed, sizeof(valid));
  CHECK(fn_bench_plan_load(&args, 7u, &expected, 1u, &plan) != 0);

  memcpy(changed, valid, sizeof(valid));
  write_u32_le(changed + 76u, 2u);
  save_plan(path, changed, sizeof(valid));
  CHECK(fn_bench_plan_load(&args, 7u, &expected, 1u, &plan) != 0);

  memcpy(changed, valid, sizeof(valid));
  write_u64_le(changed + 80u, 1001u);
  save_plan(path, changed, sizeof(valid));
  CHECK(fn_bench_plan_load(&args, 7u, &expected, 1u, &plan) != 0);

  memcpy(changed, valid, sizeof(valid));
  write_u32_le(changed + 68u, 1u);
  save_plan(path, changed, sizeof(valid));
  CHECK(fn_bench_plan_load(&args, 7u, &expected, 1u, &plan) != 0);

  memcpy(changed, valid, sizeof(valid));
  changed[104] = 0u;
  save_plan(path, changed, sizeof(changed));
  CHECK(fn_bench_plan_load(&args, 7u, &expected, 1u, &plan) != 0);
  CHECK(unlink(path) == 0);
}

static void test_statistics(void)
{
  const double values[] = {4.0, 1.0, 3.0, 2.0};
  const double invalid_nan[] = {1.0, NAN};
  const double invalid_infinite[] = {1.0, INFINITY};
  CHECK(fn_bench_values_finite(values, 4u));
  CHECK(!fn_bench_values_finite(values, 0u));
  CHECK(!fn_bench_values_finite(invalid_nan, 2u));
  CHECK(!fn_bench_values_finite(invalid_infinite, 2u));
  CHECK(fn_bench_nearest_rank(values, 4u, 0.50) == 2.0);
  CHECK(fn_bench_nearest_rank(values, 4u, 0.95) == 4.0);
  CHECK(fn_bench_nearest_rank(values, 4u, 0.99) == 4.0);
  CHECK(isnan(fn_bench_nearest_rank(values, 4u, 0.0)));
  CHECK(isnan(fn_bench_nearest_rank(invalid_nan, 2u, 0.5)));
}

int main(void)
{
  test_plan_contract();
  test_statistics();
  if (failures != 0) {
    (void)fprintf(stderr, "%d P14 benchmark contract checks failed\n",
                  failures);
    return 1;
  }
  (void)puts("P14 benchmark contract checks passed");
  return 0;
}
