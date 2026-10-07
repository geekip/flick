#ifndef FLICKNET_BUILD_H
#define FLICKNET_BUILD_H

#include <stdint.h>
#include <stddef.h>

typedef uint64_t fn_feature_set_t;

/* 声明 bit 只提供统一编号，不表示当前构建已经实现对应能力。 */
#define FN_FEATURE_GEOIP_DATA        (UINT64_C(1) << 0)
#define FN_FEATURE_GEOSITE_DATA      (UINT64_C(1) << 1)
#define FN_FEATURE_DNS_RESOLVER      (UINT64_C(1) << 2)
#define FN_FEATURE_DNS_LISTEN_UDP    (UINT64_C(1) << 3)
#define FN_FEATURE_DNS_LISTEN_TCP    (UINT64_C(1) << 4)
#define FN_FEATURE_FAKEIP_ALLOCATE   (UINT64_C(1) << 5)
#define FN_FEATURE_FAKEIP_RECOVER    (UINT64_C(1) << 6)
#define FN_FEATURE_TLS_CLIENT        (UINT64_C(1) << 7)
#define FN_FEATURE_TLS_SERVER        (UINT64_C(1) << 8)
#define FN_FEATURE_ANYTLS_IN         (UINT64_C(1) << 9)
#define FN_FEATURE_ANYTLS_OUT        (UINT64_C(1) << 10)
#define FN_FEATURE_UDP_RELAY_POOL    (UINT64_C(1) << 11)
#define FN_FEATURE_DNS_UPSTREAM_UDP  (UINT64_C(1) << 12)
#define FN_FEATURE_DNS_UPSTREAM_TCP  (UINT64_C(1) << 13)
#define FN_FEATURE_FAKEIP_PERSIST    (UINT64_C(1) << 14)
#define FN_FEATURE_SOCKS_IN_TCP      (UINT64_C(1) << 15)
#define FN_FEATURE_SOCKS_IN_UDP      (UINT64_C(1) << 16)
#define FN_FEATURE_SOCKS_OUT_TCP     (UINT64_C(1) << 17)
#define FN_FEATURE_SOCKS_OUT_UDP     (UINT64_C(1) << 18)
#define FN_FEATURE_MIXED_HTTP        (UINT64_C(1) << 19)
#define FN_FEATURE_TPROXY_TCP        (UINT64_C(1) << 20)
#define FN_FEATURE_TPROXY_UDP        (UINT64_C(1) << 21)
#define FN_FEATURE_SNIFF_TLS         (UINT64_C(1) << 22)
#define FN_FEATURE_SNIFF_HTTP        (UINT64_C(1) << 23)
#define FN_FEATURE_GROUP_SELECT      (UINT64_C(1) << 24)
#define FN_FEATURE_GROUP_URL_TEST    (UINT64_C(1) << 25)
#define FN_FEATURE_HEALTH            (UINT64_C(1) << 26)
#define FN_FEATURE_HTTP_CLIENT       (UINT64_C(1) << 27)
#define FN_FEATURE_ACCESS_LOG        (UINT64_C(1) << 28)
#define FN_FEATURE_TRACE             (UINT64_C(1) << 29)
#define FN_FEATURE_METRICS_DETAIL    (UINT64_C(1) << 30)
#define FN_FEATURE_GEO_UPDATE        (UINT64_C(1) << 31)
#define FN_FEATURE_CONFIG_DIFF       (UINT64_C(1) << 32)
#define FN_FEATURE_CONFIG_PATCH      (UINT64_C(1) << 33)
#define FN_FEATURE_CONTROL           (UINT64_C(1) << 34)
#define FN_FEATURE_UOT               (UINT64_C(1) << 35)
#define FN_FEATURE_DIRECT_TCP        (UINT64_C(1) << 36)
#define FN_FEATURE_DIRECT_UDP        (UINT64_C(1) << 37)
#define FN_FEATURE_DNS_RESULT_CACHE  (UINT64_C(1) << 38)
#define FN_FEATURE_DNS_FAILURE_CACHE (UINT64_C(1) << 39)

/* fn_build_compiled_features 只返回已有实现且进入当前产物的能力。 */
fn_feature_set_t fn_build_compiled_features(void);
const char *fn_build_program_version(void);
const char *fn_build_platform(void);
const char *fn_build_libev_version(void);
const char *fn_build_libyaml_version(void);
const char *fn_build_tls_backend(void);
size_t fn_build_compiled_feature_count(void);
/* fn_build_compiled_feature_name 按名称排序返回借用的静态字符串。 */
const char *fn_build_compiled_feature_name(size_t index);

#endif
