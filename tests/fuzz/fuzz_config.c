#include "flicknet/build.h"
#include "flicknet/config.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  fn_config_t config;
  fn_config_error_t error;
  fn_feature_plan_t plan;
  fn_result_t result;

  if (size > FN_CONFIG_MAX_BYTES + 1u) {
    return 0;
  }
  result = fn_config_parse(data, size, fn_allocator_system(),
                           &config, &error);
  if (result.code == FN_OK) {
    (void)fn_config_plan(&config, fn_build_compiled_features(),
                         &plan, &error);
  }
  fn_config_destroy(&config);
  return 0;
}
