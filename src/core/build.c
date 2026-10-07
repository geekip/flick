#include "flicknet/build.h"

#ifndef FN_BUILD_PLATFORM
#define FN_BUILD_PLATFORM "unknown"
#endif

#ifndef FN_BUILD_LIBEV_VERSION
#define FN_BUILD_LIBEV_VERSION "unknown"
#endif

#ifndef FN_BUILD_LIBYAML_VERSION
#define FN_BUILD_LIBYAML_VERSION "unknown"
#endif

static const char *const compiled_feature_names[] = {
  "direct_tcp",
  "dns_failure_cache",
  "dns_resolver",
  "dns_upstream_tcp",
  "dns_upstream_udp",
  "socks_in_tcp",
  "socks_out_tcp",
};

/* fn_build_compiled_features 只公布已经接入产品进程的数据面能力。 */
fn_feature_set_t fn_build_compiled_features(void)
{
  return FN_FEATURE_DIRECT_TCP | FN_FEATURE_DNS_FAILURE_CACHE |
         FN_FEATURE_DNS_RESOLVER | FN_FEATURE_DNS_UPSTREAM_TCP |
         FN_FEATURE_DNS_UPSTREAM_UDP | FN_FEATURE_SOCKS_IN_TCP |
         FN_FEATURE_SOCKS_OUT_TCP;
}

const char *fn_build_program_version(void)
{
  return "0.1.0-dev";
}

const char *fn_build_platform(void)
{
  return FN_BUILD_PLATFORM;
}

const char *fn_build_libev_version(void)
{
  return FN_BUILD_LIBEV_VERSION;
}

const char *fn_build_libyaml_version(void)
{
  return FN_BUILD_LIBYAML_VERSION;
}

const char *fn_build_tls_backend(void)
{
  return "none";
}

size_t fn_build_compiled_feature_count(void)
{
  return sizeof(compiled_feature_names) / sizeof(compiled_feature_names[0]);
}

const char *fn_build_compiled_feature_name(size_t index)
{
  if (index >= fn_build_compiled_feature_count()) {
    return NULL;
  }
  return compiled_feature_names[index];
}
