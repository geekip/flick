#include "flicknet/metadata.h"

#include <stdint.h>
#include <stdio.h>

static int make_domain(fn_domain_t *domain, const uint8_t *bytes, size_t length)
{
  return fn_domain_from_bytes(domain, bytes, length).code == FN_OK ? 0 : 1;
}

int main(void)
{
  static const uint8_t sniffed_bytes[] = "sniff.example";
  static const uint8_t requested_bytes[] = "request.example";
  static const uint8_t fake_bytes[] = "fake.example";
  fn_domain_t sniffed;
  fn_domain_t requested;
  fn_domain_t fake;
  fn_session_metadata_t metadata;
  fn_diagnostic_metadata_t diagnostics = {
    .trace_id = UINT64_C(42),
    .flags = UINT32_C(7),
  };

  if (make_domain(&sniffed, sniffed_bytes, sizeof(sniffed_bytes) - 1u) != 0 ||
      make_domain(&requested, requested_bytes,
                  sizeof(requested_bytes) - 1u) != 0 ||
      make_domain(&fake, fake_bytes, sizeof(fake_bytes) - 1u) != 0) {
    fputs("P02 metadata fixture setup failed.\n", stderr);
    return 1;
  }
  fn_session_metadata_init(&metadata, FN_TCP);
  if (metadata.route.network != FN_TCP ||
      metadata.route.inbound.index != FN_ID_NONE ||
      metadata.route.domain_source != FN_DOMAIN_ABSENT ||
      metadata.diagnostics != NULL) {
    return 2;
  }
  if (fn_session_metadata_set_domain(&metadata, &sniffed,
                                     FN_DOMAIN_SNI).code != FN_OK ||
      !fn_domain_equal(&metadata.route.domain, &sniffed) ||
      fn_session_metadata_set_domain(&metadata, &requested,
                                     FN_DOMAIN_REQUEST).code != FN_OK ||
      !fn_domain_equal(&metadata.route.domain, &requested) ||
      metadata.route.domain_source != FN_DOMAIN_REQUEST) {
    return 3;
  }
  if (fn_session_metadata_set_domain(&metadata, &sniffed,
                                     FN_DOMAIN_HTTP_HOST).code != FN_OK ||
      fn_session_metadata_set_domain(&metadata, &fake,
                                     FN_DOMAIN_FAKEIP).code != FN_OK ||
      !fn_domain_equal(&metadata.route.domain, &requested) ||
      metadata.route.domain_source != FN_DOMAIN_REQUEST) {
    return 4;
  }
  if (fn_session_metadata_attach_diagnostics(&metadata,
                                             &diagnostics).code != FN_OK ||
      metadata.diagnostics != &diagnostics ||
      fn_session_metadata_attach_diagnostics(&metadata,
                                             &diagnostics).code != FN_INVALID ||
      !fn_domain_equal(&metadata.route.domain, &requested)) {
    return 5;
  }
  fn_session_metadata_detach_diagnostics(&metadata);
  if (metadata.diagnostics != NULL ||
      !fn_domain_equal(&metadata.route.domain, &requested) ||
      fn_session_metadata_set_domain(&metadata, NULL,
                                     FN_DOMAIN_ABSENT).code != FN_OK ||
      metadata.route.domain.length != 0 ||
      metadata.route.domain_source != FN_DOMAIN_ABSENT) {
    return 6;
  }
  puts("P02 metadata separation checks passed.");
  return 0;
}
