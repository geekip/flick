#define _POSIX_C_SOURCE 200809L

#include "bench_common.h"

#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef FN_BENCH_WORKLOAD_SHA256
#error "FN_BENCH_WORKLOAD_SHA256 is required"
#endif

static uint32_t read_u32_le(const unsigned char *data)
{
  return (uint32_t)data[0] |
         ((uint32_t)data[1] << 8u) |
         ((uint32_t)data[2] << 16u) |
         ((uint32_t)data[3] << 24u);
}

static uint64_t read_u64_le(const unsigned char *data)
{
  uint64_t value = 0;
  size_t index;
  for (index = 0; index < 8u; index++) {
    value |= (uint64_t)data[index] << (index * 8u);
  }
  return value;
}

static int hex_value(char value)
{
  if (value >= '0' && value <= '9') {
    return value - '0';
  }
  if (value >= 'a' && value <= 'f') {
    return value - 'a' + 10;
  }
  return -1;
}

static int decode_sha256(const char *text, unsigned char output[32])
{
  size_t index;
  if (text == NULL || strlen(text) != 64u) {
    return -1;
  }
  for (index = 0; index < 32u; index++) {
    int high = hex_value(text[index * 2u]);
    int low = hex_value(text[index * 2u + 1u]);
    if (high < 0 || low < 0) {
      return -1;
    }
    output[index] = (unsigned char)((high << 4) | low);
  }
  return 0;
}

static int parse_u64(const char *text, uint64_t *out)
{
  char *end = NULL;
  unsigned long long value;
  if (text == NULL || *text == '\0' || *text == '-') {
    return -1;
  }
  errno = 0;
  value = strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0') {
    return -1;
  }
  *out = (uint64_t)value;
  return 0;
}

static int assign_option(const char *name, const char *value,
                         fn_bench_args_t *out, unsigned int *seen)
{
  uint64_t number;
  unsigned int bit;
  if (strcmp(name, "--workload") == 0) {
    bit = 1u << 0;
    out->workload_path = value;
  } else if (strcmp(name, "--workload-sha256") == 0) {
    bit = 1u << 1;
    out->workload_sha256 = value;
  } else if (strcmp(name, "--plan") == 0) {
    bit = 1u << 2;
    out->plan_path = value;
  } else if (strcmp(name, "--fixture-dir") == 0) {
    bit = 1u << 3;
    out->fixture_dir = value;
  } else if (strcmp(name, "--warmup") == 0) {
    bit = 1u << 4;
    if (parse_u64(value, &number) != 0 || number > UINT32_MAX) {
      return -1;
    }
    out->warmup_count = (uint32_t)number;
  } else if (strcmp(name, "--samples") == 0) {
    bit = 1u << 5;
    if (parse_u64(value, &number) != 0 || number > FN_BENCH_MAX_SAMPLES) {
      return -1;
    }
    out->sample_count = (uint32_t)number;
  } else if (strcmp(name, "--seed") == 0) {
    bit = 1u << 6;
    if (parse_u64(value, &number) != 0) {
      return -1;
    }
    out->seed = number;
  } else if (strcmp(name, "--output") == 0) {
    bit = 1u << 7;
    out->output_path = value;
  } else {
    return -1;
  }
  if ((*seen & bit) != 0u) {
    return -1;
  }
  *seen |= bit;
  return 0;
}

int fn_bench_parse_args(int argc, char **argv, fn_bench_args_t *out)
{
  unsigned int seen = 0;
  int index;
  if (out == NULL) {
    return -1;
  }
  memset(out, 0, sizeof(*out));
  if (argc != 17) {
    (void)fprintf(stderr, "benchmark requires eight option/value pairs\n");
    return -1;
  }
  for (index = 1; index < argc; index += 2) {
    if (assign_option(argv[index], argv[index + 1], out, &seen) != 0) {
      (void)fprintf(stderr, "invalid benchmark option: %s\n", argv[index]);
      return -1;
    }
  }
  if (seen != UINT32_C(0xff) || out->warmup_count == 0u ||
      out->sample_count == 0u || out->sample_count > FN_BENCH_MAX_SAMPLES ||
      strcmp(out->workload_sha256, FN_BENCH_WORKLOAD_SHA256) != 0) {
    (void)fprintf(stderr, "benchmark arguments do not match the build\n");
    return -1;
  }
  return 0;
}

int fn_bench_read_file(const char *path, unsigned char **data,
                       size_t *length)
{
  FILE *stream;
  long size;
  unsigned char *buffer;
  if (path == NULL || data == NULL || length == NULL) {
    return -1;
  }
  *data = NULL;
  *length = 0u;
  stream = fopen(path, "rb");
  if (stream == NULL || fseek(stream, 0, SEEK_END) != 0) {
    if (stream != NULL) {
      (void)fclose(stream);
    }
    return -1;
  }
  size = ftell(stream);
  if (size < 0 || fseek(stream, 0, SEEK_SET) != 0) {
    (void)fclose(stream);
    return -1;
  }
  buffer = malloc(size == 0 ? 1u : (size_t)size);
  if (buffer == NULL ||
      (size != 0 && fread(buffer, 1u, (size_t)size, stream) != (size_t)size) ||
      fclose(stream) != 0) {
    free(buffer);
    return -1;
  }
  *data = buffer;
  *length = (size_t)size;
  return 0;
}

void fn_bench_free_file(unsigned char **data)
{
  if (data != NULL) {
    free(*data);
    *data = NULL;
  }
}

int fn_bench_plan_load(const fn_bench_args_t *args, uint32_t target_id,
                       const fn_bench_plan_expectation_t *expected,
                       size_t expected_count, fn_bench_plan_t *out)
{
  unsigned char *data = NULL;
  unsigned char decoded_sha[32];
  size_t length = 0;
  size_t required;
  size_t index;
  if (args == NULL || expected == NULL || out == NULL ||
      expected_count == 0u || expected_count > FN_BENCH_MAX_CASES ||
      decode_sha256(FN_BENCH_WORKLOAD_SHA256, decoded_sha) != 0 ||
      fn_bench_read_file(args->plan_path, &data, &length) != 0) {
    return -1;
  }
  required = FN_BENCH_PLAN_HEADER_BYTES +
             expected_count * FN_BENCH_PLAN_RECORD_BYTES;
  if (length != required || memcmp(data, "FNBENCH1", 8u) != 0 ||
      read_u32_le(data + 8u) != 1u ||
      read_u32_le(data + 12u) != target_id ||
      memcmp(data + 16u, decoded_sha, sizeof(decoded_sha)) != 0 ||
      read_u64_le(data + 48u) != args->seed ||
      read_u32_le(data + 56u) != args->warmup_count ||
      read_u32_le(data + 60u) != args->sample_count ||
      read_u32_le(data + 64u) != expected_count ||
      read_u32_le(data + 68u) != 0u) {
    fn_bench_free_file(&data);
    return -1;
  }
  memset(out, 0, sizeof(*out));
  out->target_id = target_id;
  out->seed = args->seed;
  out->warmup_count = args->warmup_count;
  out->sample_count = args->sample_count;
  out->case_count = (uint32_t)expected_count;
  for (index = 0; index < expected_count; index++) {
    const unsigned char *record = data + FN_BENCH_PLAN_HEADER_BYTES +
                                  index * FN_BENCH_PLAN_RECORD_BYTES;
    fn_bench_plan_record_t *value = &out->records[index];
    const fn_bench_plan_expectation_t *limit = &expected[index];
    value->case_id = read_u32_le(record);
    value->parameter_kind = read_u32_le(record + 4u);
    value->primary = read_u64_le(record + 8u);
    value->secondary = read_u64_le(record + 16u);
    value->tertiary = read_u64_le(record + 24u);
    if (value->case_id != limit->case_id ||
        value->parameter_kind != limit->parameter_kind ||
        value->primary < limit->primary_min ||
        value->primary > limit->primary_max ||
        value->secondary < limit->secondary_min ||
        value->secondary > limit->secondary_max ||
        value->tertiary < limit->tertiary_min ||
        value->tertiary > limit->tertiary_max) {
      fn_bench_free_file(&data);
      return -1;
    }
  }
  fn_bench_free_file(&data);
  return 0;
}

uint64_t fn_bench_monotonic_ns(void)
{
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
    return 0;
  }
  return (uint64_t)value.tv_sec * UINT64_C(1000000000) +
         (uint64_t)value.tv_nsec;
}

uint64_t fn_bench_process_cpu_ns(void)
{
  struct timespec value;
  if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &value) != 0) {
    return 0;
  }
  return (uint64_t)value.tv_sec * UINT64_C(1000000000) +
         (uint64_t)value.tv_nsec;
}

static int compare_double(const void *left, const void *right)
{
  double a = *(const double *)left;
  double b = *(const double *)right;
  return (a > b) - (a < b);
}

bool fn_bench_values_finite(const double *values, size_t count)
{
  size_t index;
  if (values == NULL || count == 0u || count > FN_BENCH_MAX_SAMPLES) {
    return false;
  }
  for (index = 0; index < count; index++) {
    if (!isfinite(values[index])) {
      return false;
    }
  }
  return true;
}

double fn_bench_nearest_rank(const double *values, size_t count,
                             double percentile)
{
  double sorted[FN_BENCH_MAX_SAMPLES];
  size_t rank;
  if (!fn_bench_values_finite(values, count) || percentile <= 0.0 ||
      percentile > 1.0) {
    return NAN;
  }
  memcpy(sorted, values, count * sizeof(*values));
  qsort(sorted, count, sizeof(*sorted), compare_double);
  rank = (size_t)ceil(percentile * (double)count);
  if (rank == 0u) {
    rank = 1u;
  }
  return sorted[rank - 1u];
}

int fn_bench_case_add(fn_bench_case_t *bench_case, const char *unit,
                      const char *direction, double value)
{
  fn_bench_measurement_t *measurement;
  size_t index;
  if (bench_case == NULL || unit == NULL || direction == NULL ||
      !isfinite(value)) {
    return -1;
  }
  for (index = 0; index < bench_case->measurement_count; index++) {
    if (strcmp(bench_case->measurements[index].unit, unit) == 0) {
      measurement = &bench_case->measurements[index];
      if (strcmp(measurement->direction, direction) != 0 ||
          measurement->sample_count >= FN_BENCH_MAX_SAMPLES) {
        return -1;
      }
      measurement->samples[measurement->sample_count++] = value;
      return 0;
    }
  }
  if (bench_case->measurement_count >= FN_BENCH_MAX_MEASUREMENTS) {
    return -1;
  }
  measurement = &bench_case->measurements[bench_case->measurement_count++];
  memset(measurement, 0, sizeof(*measurement));
  measurement->unit = unit;
  measurement->direction = direction;
  measurement->samples[measurement->sample_count++] = value;
  return 0;
}

static void write_json_string(FILE *stream, const char *value)
{
  const unsigned char *cursor = (const unsigned char *)value;
  (void)fputc('"', stream);
  while (*cursor != '\0') {
    if (*cursor == '"' || *cursor == '\\') {
      (void)fputc('\\', stream);
      (void)fputc(*cursor, stream);
    } else if (*cursor >= 0x20u) {
      (void)fputc(*cursor, stream);
    } else {
      (void)fprintf(stream, "\\u%04x", (unsigned int)*cursor);
    }
    cursor++;
  }
  (void)fputc('"', stream);
}

static void iso_time(char output[32], time_t value)
{
  struct tm broken_down;
  if (gmtime_r(&value, &broken_down) == NULL ||
      strftime(output, 32u, "%Y-%m-%dT%H:%M:%SZ", &broken_down) == 0u) {
    memcpy(output, "1970-01-01T00:00:00Z", 21u);
  }
}

static int write_measurement(FILE *stream,
                             const fn_bench_measurement_t *measurement,
                             size_t expected_samples)
{
  size_t index;
  double minimum;
  double maximum;
  if (measurement->sample_count != expected_samples ||
      !fn_bench_values_finite(measurement->samples,
                              measurement->sample_count)) {
    return -1;
  }
  minimum = measurement->samples[0];
  maximum = measurement->samples[0];
  for (index = 1; index < measurement->sample_count; index++) {
    if (measurement->samples[index] < minimum) {
      minimum = measurement->samples[index];
    }
    if (measurement->samples[index] > maximum) {
      maximum = measurement->samples[index];
    }
  }
  (void)fputs("{\"unit\":", stream);
  write_json_string(stream, measurement->unit);
  (void)fputs(",\"direction\":", stream);
  write_json_string(stream, measurement->direction);
  (void)fputs(",\"samples\":[", stream);
  for (index = 0; index < measurement->sample_count; index++) {
    (void)fprintf(stream, "%s%.17g", index == 0u ? "" : ",",
                  measurement->samples[index]);
  }
  (void)fprintf(stream,
                "],\"minimum\":%.17g,\"maximum\":%.17g,"
                "\"p50\":%.17g,\"p95\":%.17g,\"p99\":%.17g}",
                minimum, maximum,
                fn_bench_nearest_rank(measurement->samples,
                                      measurement->sample_count, 0.50),
                fn_bench_nearest_rank(measurement->samples,
                                      measurement->sample_count, 0.95),
                fn_bench_nearest_rank(measurement->samples,
                                      measurement->sample_count, 0.99));
  return 0;
}

int fn_bench_write_target(const fn_bench_args_t *args,
                          const fn_bench_plan_t *plan,
                          const char *target,
                          const fn_bench_case_t *cases,
                          size_t case_count, uint64_t duration_ns)
{
  FILE *stream;
  size_t case_index;
  time_t finished = time(NULL);
  time_t started = finished - (time_t)(duration_ns / UINT64_C(1000000000));
  char started_text[32];
  char finished_text[32];
  if (args == NULL || plan == NULL || target == NULL || cases == NULL ||
      case_count != plan->case_count) {
    return -1;
  }
  for (case_index = 0; case_index < case_count; case_index++) {
    size_t metric_index;
    if (cases[case_index].measurement_count == 0u ||
        !cases[case_index].behavior_ok || !cases[case_index].cleanup_ok) {
      return -1;
    }
    for (metric_index = 0;
         metric_index < cases[case_index].measurement_count;
         metric_index++) {
      if (cases[case_index].measurements[metric_index].sample_count !=
          args->sample_count) {
        return -1;
      }
    }
  }
  stream = fopen(args->output_path, "wb");
  if (stream == NULL) {
    return -1;
  }
  iso_time(started_text, started);
  iso_time(finished_text, finished);
  (void)fputs("{\"schema\":\"flick.benchmark-target/v1\",\"target\":",
              stream);
  write_json_string(stream, target);
  (void)fprintf(stream,
                ",\"seed\":%llu,\"warmup_count\":%u,"
                "\"sample_count\":%u,\"started_at\":",
                (unsigned long long)args->seed, args->warmup_count,
                args->sample_count);
  write_json_string(stream, started_text);
  (void)fputs(",\"finished_at\":", stream);
  write_json_string(stream, finished_text);
  (void)fprintf(stream, ",\"duration_ms\":%llu,\"workload_sha256\":",
                (unsigned long long)(duration_ns / UINT64_C(1000000)));
  write_json_string(stream, args->workload_sha256);
  (void)fputs(",\"plan\":{\"path\":", stream);
  write_json_string(stream, args->plan_path);
  (void)fprintf(stream, ",\"target_id\":%u,\"case_count\":%u},",
                plan->target_id, plan->case_count);
  (void)fputs("\"fixture_inputs\":[", stream);
  write_json_string(stream, args->workload_path);
  (void)fputc(',', stream);
  write_json_string(stream, args->fixture_dir);
  (void)fputs("],\"cases\":[", stream);
  for (case_index = 0; case_index < case_count; case_index++) {
    const fn_bench_case_t *bench_case = &cases[case_index];
    size_t metric_index;
    (void)fputs(case_index == 0u ? "{\"name\":" : ",{\"name\":",
                stream);
    write_json_string(stream, bench_case->name);
    (void)fputs(",\"phase\":", stream);
    write_json_string(stream, bench_case->phase);
    (void)fputs(",\"measurements\":[", stream);
    for (metric_index = 0;
         metric_index < bench_case->measurement_count;
         metric_index++) {
      if (metric_index != 0u) {
        (void)fputc(',', stream);
      }
      if (write_measurement(stream, &bench_case->measurements[metric_index],
                            args->sample_count) != 0) {
        (void)fclose(stream);
        return -1;
      }
    }
    (void)fputs("],\"checks\":{\"behavior\":true,\"cleanup\":true}}",
                stream);
  }
  (void)fputs("],\"checks\":{\"plan_valid\":true,"
              "\"workload_hash_match\":true,"
              "\"all_samples_finite\":true,"
              "\"behavior\":true,\"cleanup\":true}}\n", stream);
  if (fclose(stream) != 0) {
    return -1;
  }
  return 0;
}
