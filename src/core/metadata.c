#include "flicknet/metadata.h"

#include <stddef.h>
#include <string.h>

static fn_result_t metadata_result(fn_status_t code)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE : FN_STAGE_ROUTE,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static int domain_priority(fn_domain_source_t source)
{
  switch (source) {
    case FN_DOMAIN_ABSENT: return 0;
    case FN_DOMAIN_SNI:
    case FN_DOMAIN_HTTP_HOST: return 1;
    case FN_DOMAIN_REQUEST:
    case FN_DOMAIN_FAKEIP: return 2;
  }
  return -1;
}

void fn_session_metadata_init(fn_session_metadata_t *metadata,
                              fn_network_t network)
{
  if (metadata == NULL) {
    return;
  }
  memset(metadata, 0, sizeof(*metadata));
  metadata->route.network = network;
  metadata->route.inbound.index = FN_ID_NONE;
}

fn_result_t fn_session_metadata_set_domain(fn_session_metadata_t *metadata,
                                           const fn_domain_t *domain,
                                           fn_domain_source_t source)
{
  int current_priority;
  int new_priority;

  if (metadata == NULL) {
    return metadata_result(FN_INVALID);
  }
  new_priority = domain_priority(source);
  current_priority = domain_priority(metadata->route.domain_source);
  if (new_priority < 0 || current_priority < 0) {
    return metadata_result(FN_INVALID);
  }
  if (source == FN_DOMAIN_ABSENT) {
    memset(&metadata->route.domain, 0, sizeof(metadata->route.domain));
    metadata->route.domain_source = FN_DOMAIN_ABSENT;
    return metadata_result(FN_OK);
  }
  if (domain == NULL || domain->length == 0 ||
      domain->length > FN_DOMAIN_MAX ||
      domain->bytes[domain->length] != '\0') {
    return metadata_result(FN_INVALID);
  }
  if (current_priority >= new_priority &&
      metadata->route.domain_source != FN_DOMAIN_ABSENT) {
    return metadata_result(FN_OK);
  }
  metadata->route.domain = *domain;
  metadata->route.domain_source = source;
  return metadata_result(FN_OK);
}

fn_result_t fn_session_metadata_attach_diagnostics(
  fn_session_metadata_t *metadata, fn_diagnostic_metadata_t *diagnostics)
{
  if (metadata == NULL || diagnostics == NULL ||
      metadata->diagnostics != NULL) {
    return metadata_result(FN_INVALID);
  }
  metadata->diagnostics = diagnostics;
  return metadata_result(FN_OK);
}

void fn_session_metadata_detach_diagnostics(fn_session_metadata_t *metadata)
{
  if (metadata != NULL) {
    metadata->diagnostics = NULL;
  }
}
