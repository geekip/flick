#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
  double monotonic_seconds;
  double rss_bytes;
} sample_t;

static int compare_double(const void *left_pointer, const void *right_pointer)
{
  const double left = *(const double *)left_pointer;
  const double right = *(const double *)right_pointer;
  return left < right ? -1 : left > right ? 1 : 0;
}

static int fail(const char *message)
{
  (void)fprintf(stderr, "Theil-Sen calculation failed: %s\n", message);
  return 1;
}

int main(int argc, char **argv)
{
  FILE *input;
  FILE *output;
  sample_t *samples;
  double *slopes;
  long input_bytes;
  size_t sample_count;
  size_t pair_count;
  size_t first;
  size_t second;
  size_t index = 0;
  double median;
  int close_result;

  if (argc != 3) {
    return fail("expected INPUT and OUTPUT paths");
  }
  input = fopen(argv[1], "rb");
  if (input == NULL) {
    return fail("cannot open input");
  }
  if (fseek(input, 0, SEEK_END) != 0) {
    (void)fclose(input);
    return fail("cannot seek input");
  }
  input_bytes = ftell(input);
  if (input_bytes < 0 || fseek(input, 0, SEEK_SET) != 0) {
    (void)fclose(input);
    return fail("cannot measure input");
  }
  if ((size_t)input_bytes % sizeof(sample_t) != 0u) {
    (void)fclose(input);
    return fail("input size is not a complete sample array");
  }
  sample_count = (size_t)input_bytes / sizeof(sample_t);
  if (sample_count < 2u || sample_count > 10000u) {
    (void)fclose(input);
    return fail("sample count is outside 2..10000");
  }
  if (sample_count > SIZE_MAX / (sample_count - 1u)) {
    (void)fclose(input);
    return fail("pair count overflow");
  }
  pair_count = sample_count * (sample_count - 1u) / 2u;
  if (pair_count > SIZE_MAX / sizeof(*slopes)) {
    (void)fclose(input);
    return fail("slope allocation overflow");
  }
  samples = malloc(sample_count * sizeof(*samples));
  slopes = malloc(pair_count * sizeof(*slopes));
  if (samples == NULL || slopes == NULL) {
    free(samples);
    free(slopes);
    (void)fclose(input);
    return fail("allocation failed");
  }
  if (fread(samples, sizeof(*samples), sample_count, input) != sample_count) {
    free(samples);
    free(slopes);
    (void)fclose(input);
    return fail("cannot read all samples");
  }
  close_result = fclose(input);
  if (close_result != 0) {
    free(samples);
    free(slopes);
    return fail("cannot close input");
  }
  for (first = 0; first + 1u < sample_count; first++) {
    if (!isfinite(samples[first].monotonic_seconds) ||
        !isfinite(samples[first].rss_bytes)) {
      free(samples);
      free(slopes);
      return fail("input contains a non-finite value");
    }
    for (second = first + 1u; second < sample_count; second++) {
      const double elapsed = samples[second].monotonic_seconds -
                             samples[first].monotonic_seconds;
      if (!(elapsed > 0.0) || !isfinite(samples[second].rss_bytes)) {
        free(samples);
        free(slopes);
        return fail("sample times are not strictly increasing");
      }
      slopes[index++] =
        ((samples[second].rss_bytes - samples[first].rss_bytes) / elapsed) *
        3600.0 / (1024.0 * 1024.0);
    }
  }
  free(samples);
  qsort(slopes, pair_count, sizeof(*slopes), compare_double);
  if ((pair_count & 1u) != 0u) {
    median = slopes[pair_count / 2u];
  } else {
    median = (slopes[pair_count / 2u - 1u] +
              slopes[pair_count / 2u]) / 2.0;
  }
  free(slopes);
  output = fopen(argv[2], "wb");
  if (output == NULL) {
    return fail("cannot open output");
  }
  if (fprintf(output,
              "{\"schema\":\"flick.theil-sen/v1\","
              "\"samples\":%zu,\"pairs\":%zu,"
              "\"slope_mib_per_hour\":%.17g}\n",
              sample_count, pair_count, median) < 0) {
    (void)fclose(output);
    return fail("cannot write output");
  }
  if (fclose(output) != 0) {
    return fail("cannot close output");
  }
  return 0;
}
