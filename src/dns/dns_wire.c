#include "flicknet/resolver.h"

#include <limits.h>
#include <string.h>

#define FN_DNS_HEADER_SIZE 12u
#define FN_DNS_NAME_STEP_MAX 8192u
#define FN_DNS_NAME_DEREFERENCE_MAX 32u

typedef struct {
  uint8_t bytes[FN_DOMAIN_MAX];
  size_t length;
  size_t consumed;
  bool host_valid;
  fn_domain_t host;
} fn_dns_name_t;

typedef struct {
  const uint8_t *message;
  size_t length;
  size_t steps;
  bool limit;
} fn_dns_decode_context_t;

typedef struct {
  fn_dns_name_t owner;
  fn_dns_name_t target;
  uint32_t ttl;
} fn_dns_cname_record_t;

typedef struct {
  fn_dns_cname_record_t records[FN_DNS_CNAME_MAX];
  size_t count;
} fn_dns_cname_index_t;

typedef struct {
  size_t offset;
  size_t end;
  uint16_t type;
  uint16_t class_code;
  uint32_t ttl;
  fn_dns_name_t owner;
} fn_dns_rr_t;

static fn_result_t dns_api_result(fn_status_t code)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE :
                                               FN_STAGE_RESOLVE,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static fn_result_t dns_native_result(fn_status_t code, int64_t native_code)
{
  return fn_result_make(code, FN_STAGE_RESOLVE, FN_ERROR_ORIGIN_DNS,
                        native_code);
}

static uint32_t read_u32_be(const uint8_t bytes[4])
{
  return ((uint32_t)bytes[0] << 24u) |
         ((uint32_t)bytes[1] << 16u) |
         ((uint32_t)bytes[2] << 8u) |
         (uint32_t)bytes[3];
}

static void parse_terminal(fn_dns_parse_result_t *out, fn_status_t code,
                           int64_t native_code)
{
  out->action = FN_DNS_PARSE_TERMINAL;
  out->result = dns_native_result(code, native_code);
}

static void parse_malformed(fn_dns_decode_context_t *context,
                            fn_dns_parse_result_t *out)
{
  parse_terminal(out, context->limit ? FN_LIMIT : FN_PROTOCOL_ERROR,
                 context->limit ? FN_DNS_NATIVE_RESPONSE_LIMIT :
                                  FN_DNS_NATIVE_MALFORMED);
}

static bool dns_name_equal(const fn_dns_name_t *left,
                           const fn_dns_name_t *right)
{
  return left->host_valid && right->host_valid &&
         fn_domain_equal(&left->host, &right->host);
}

static bool dns_name_equals_domain(const fn_dns_name_t *left,
                                   const fn_domain_t *right)
{
  return left->host_valid && fn_domain_equal(&left->host, right);
}

/* dns_decode_name 同时限制压缩跳转、展开长度和全消息解析工作量。 */
static bool dns_decode_name(fn_dns_decode_context_t *context, size_t start,
                            fn_dns_name_t *out)
{
  size_t position = start;
  size_t expanded_wire = 1u;
  size_t visited[FN_DNS_NAME_DEREFERENCE_MAX];
  size_t visited_count = 0;
  bool jumped = false;
  bool first_label = true;

  memset(out, 0, sizeof(*out));
  for (;;) {
    uint8_t length;
    if (context->steps >= FN_DNS_NAME_STEP_MAX) {
      context->limit = true;
      return false;
    }
    context->steps++;
    if (position >= context->length) {
      return false;
    }
    length = context->message[position];
    if ((length & UINT8_C(0xc0)) == UINT8_C(0xc0)) {
      size_t pointer;
      size_t index;
      if (position + 1u >= context->length ||
          visited_count >= FN_DNS_NAME_DEREFERENCE_MAX) {
        return false;
      }
      pointer = ((size_t)(length & UINT8_C(0x3f)) << 8u) |
                (size_t)context->message[position + 1u];
      if (pointer >= position || pointer >= context->length) {
        return false;
      }
      for (index = 0; index < visited_count; index++) {
        if (visited[index] == pointer) {
          return false;
        }
      }
      visited[visited_count++] = pointer;
      if (!jumped) {
        out->consumed += 2u;
      }
      position = pointer;
      jumped = true;
      continue;
    }
    if ((length & UINT8_C(0xc0)) != 0) {
      return false;
    }
    position++;
    if (!jumped) {
      out->consumed++;
    }
    if (length == 0) {
      break;
    }
    if (length > FN_DOMAIN_LABEL_MAX ||
        (size_t)length > context->length - position ||
        expanded_wire > 255u - ((size_t)length + 1u)) {
      return false;
    }
    expanded_wire += (size_t)length + 1u;
    if (!first_label) {
      if (out->length >= sizeof(out->bytes)) {
        return false;
      }
      out->bytes[out->length++] = (uint8_t)'.';
    }
    if ((size_t)length > sizeof(out->bytes) - out->length) {
      return false;
    }
    memcpy(out->bytes + out->length, context->message + position,
           (size_t)length);
    out->length += (size_t)length;
    first_label = false;
    position += (size_t)length;
    if (!jumped) {
      out->consumed += (size_t)length;
    }
  }
  if (out->length != 0 &&
      fn_domain_from_bytes(&out->host, out->bytes,
                           out->length).code == FN_OK) {
    out->host_valid = true;
  }
  return true;
}

static bool dns_parse_rr(fn_dns_decode_context_t *context, size_t *cursor,
                         fn_dns_rr_t *out)
{
  uint16_t rdlength;
  memset(out, 0, sizeof(*out));
  if (!dns_decode_name(context, *cursor, &out->owner)) {
    return false;
  }
  if (out->owner.consumed > context->length - *cursor) {
    return false;
  }
  *cursor += out->owner.consumed;
  if (context->length - *cursor < 10u) {
    return false;
  }
  out->type = fn_u16_read_be(context->message + *cursor);
  out->class_code = fn_u16_read_be(context->message + *cursor + 2u);
  out->ttl = read_u32_be(context->message + *cursor + 4u);
  rdlength = fn_u16_read_be(context->message + *cursor + 8u);
  *cursor += 10u;
  if ((size_t)rdlength > context->length - *cursor) {
    return false;
  }
  out->offset = *cursor;
  out->end = *cursor + (size_t)rdlength;
  *cursor = out->end;
  return true;
}

static bool cname_add(fn_dns_cname_index_t *index,
                      const fn_dns_rr_t *record,
                      const fn_dns_name_t *target)
{
  if (index->count >= FN_DNS_CNAME_MAX) {
    return false;
  }
  index->records[index->count].owner = record->owner;
  index->records[index->count].target = *target;
  index->records[index->count].ttl = record->ttl;
  index->count++;
  return true;
}

static bool scan_records(fn_dns_decode_context_t *context, size_t start,
                         uint16_t answer_count, uint16_t authority_count,
                         uint16_t additional_count,
                         fn_dns_cname_index_t *cnames, size_t *end)
{
  const size_t total = (size_t)answer_count + (size_t)authority_count +
                       (size_t)additional_count;
  size_t cursor = start;
  size_t index;

  for (index = 0; index < total; index++) {
    fn_dns_rr_t record;
    bool answer = index < (size_t)answer_count;
    if (!dns_parse_rr(context, &cursor, &record)) {
      return false;
    }
    if (record.type == UINT16_C(1) && record.class_code == UINT16_C(1) &&
        record.end - record.offset != 4u) {
      return false;
    }
    if (record.type == UINT16_C(5) && record.class_code == UINT16_C(1)) {
      fn_dns_name_t target;
      if (!dns_decode_name(context, record.offset, &target) ||
          target.consumed != record.end - record.offset) {
        return false;
      }
      if (answer && !cname_add(cnames, &record, &target)) {
        context->limit = true;
        return false;
      }
    }
  }
  *end = cursor;
  return true;
}

static bool chain_contains(const fn_domain_t *chain, size_t count,
                           const fn_domain_t *name)
{
  size_t index;
  for (index = 0; index < count; index++) {
    if (fn_domain_equal(&chain[index], name)) {
      return true;
    }
  }
  return false;
}

static bool resolve_cname_chain(const fn_dns_cname_index_t *index,
                                const fn_domain_t *question,
                                fn_domain_t chain[FN_DNS_CNAME_HOPS_MAX + 1u],
                                size_t *chain_count, uint32_t *ttl,
                                fn_dns_parse_result_t *out)
{
  fn_domain_t current = *question;
  size_t hops = 0;
  uint32_t minimum_ttl = UINT32_MAX;

  chain[0] = current;
  *chain_count = 1u;
  for (;;) {
    const fn_dns_cname_record_t *selected = NULL;
    size_t record_index;
    uint32_t owner_ttl = UINT32_MAX;
    for (record_index = 0; record_index < index->count; record_index++) {
      const fn_dns_cname_record_t *record = &index->records[record_index];
      if (!dns_name_equals_domain(&record->owner, &current)) {
        continue;
      }
      if (!record->target.host_valid) {
        parse_terminal(out, FN_PROTOCOL_ERROR, FN_DNS_NATIVE_MALFORMED);
        return false;
      }
      if (selected != NULL &&
          !dns_name_equal(&selected->target, &record->target)) {
        parse_terminal(out, FN_PROTOCOL_ERROR, FN_DNS_NATIVE_MALFORMED);
        return false;
      }
      selected = record;
      if (record->ttl < owner_ttl) {
        owner_ttl = record->ttl;
      }
    }
    if (selected == NULL) {
      break;
    }
    if (hops >= FN_DNS_CNAME_HOPS_MAX) {
      parse_terminal(out, FN_LIMIT, FN_DNS_NATIVE_RESPONSE_LIMIT);
      return false;
    }
    if (chain_contains(chain, *chain_count, &selected->target.host)) {
      parse_terminal(out, FN_PROTOCOL_ERROR, FN_DNS_NATIVE_CNAME_LOOP);
      return false;
    }
    if (owner_ttl < minimum_ttl) {
      minimum_ttl = owner_ttl;
    }
    current = selected->target.host;
    chain[*chain_count] = current;
    (*chain_count)++;
    hops++;
  }
  out->cname_question = current;
  out->cname_hops = hops;
  *ttl = minimum_ttl;
  return true;
}

static bool domain_is_nonterminal_chain_owner(
  const fn_domain_t *chain, size_t chain_count, const fn_dns_name_t *owner)
{
  size_t index;
  if (!owner->host_valid || chain_count < 2u) {
    return false;
  }
  for (index = 0; index + 1u < chain_count; index++) {
    if (fn_domain_equal(&chain[index], &owner->host)) {
      return true;
    }
  }
  return false;
}

static bool address_present(const fn_resolved_t *resolved,
                            const uint8_t bytes[4])
{
  size_t index;
  for (index = 0; index < resolved->count; index++) {
    if (memcmp(resolved->addresses[index].value.v4, bytes, 4u) == 0) {
      return true;
    }
  }
  return false;
}

static bool collect_addresses(fn_dns_decode_context_t *context,
                              size_t start, uint16_t answer_count,
                              uint16_t authority_count,
                              uint16_t additional_count,
                              const fn_domain_t *chain, size_t chain_count,
                              uint32_t cname_ttl,
                              fn_dns_parse_result_t *out)
{
  const size_t total = (size_t)answer_count + (size_t)authority_count +
                       (size_t)additional_count;
  const fn_domain_t *terminal = &chain[chain_count - 1u];
  size_t cursor = start;
  size_t index;
  uint32_t minimum_ttl = cname_ttl;

  memset(&out->resolved, 0, sizeof(out->resolved));
  for (index = 0; index < total; index++) {
    fn_dns_rr_t record;
    bool answer = index < (size_t)answer_count;
    if (!dns_parse_rr(context, &cursor, &record)) {
      return false;
    }
    if (!answer || record.type != UINT16_C(1) ||
        record.class_code != UINT16_C(1)) {
      continue;
    }
    if (record.end - record.offset != 4u) {
      return false;
    }
    if (domain_is_nonterminal_chain_owner(chain, chain_count,
                                           &record.owner)) {
      parse_terminal(out, FN_PROTOCOL_ERROR, FN_DNS_NATIVE_MALFORMED);
      return true;
    }
    if (!dns_name_equals_domain(&record.owner, terminal)) {
      continue;
    }
    if (address_present(&out->resolved, context->message + record.offset)) {
      if (record.ttl < minimum_ttl) {
        minimum_ttl = record.ttl;
      }
      continue;
    }
    if (out->resolved.count >= FN_RESOLVED_MAX) {
      parse_terminal(out, FN_LIMIT, FN_DNS_NATIVE_RESPONSE_LIMIT);
      return true;
    }
    if (fn_addr_from_v4(&out->resolved.addresses[out->resolved.count],
                        context->message + record.offset).code != FN_OK) {
      return false;
    }
    out->resolved.count++;
    if (record.ttl < minimum_ttl) {
      minimum_ttl = record.ttl;
    }
  }
  if (out->resolved.count != 0) {
    out->resolved.ttl_seconds = minimum_ttl;
    out->action = FN_DNS_PARSE_ANSWER;
    out->result = dns_api_result(FN_OK);
  } else if (chain_count > 1u) {
    out->action = FN_DNS_PARSE_CNAME_QUERY;
    out->result = dns_api_result(FN_OK);
    out->cname_ttl_seconds = cname_ttl;
  } else {
    parse_terminal(out, FN_RESOLVE_ERROR, FN_DNS_NATIVE_NODATA);
  }
  return true;
}

fn_result_t fn_dns_query_build(const fn_domain_t *question, uint16_t id,
                               fn_dns_query_t *out)
{
  fn_domain_t normalized;
  size_t input = 0;
  size_t output = FN_DNS_HEADER_SIZE;
  if (question == NULL || out == NULL || question->length == 0 ||
      question->length > FN_DOMAIN_MAX ||
      fn_domain_from_bytes(&normalized, (const uint8_t *)question->bytes,
                           question->length).code != FN_OK ||
      !fn_domain_equal(&normalized, question)) {
    return dns_api_result(FN_INVALID);
  }
  memset(out, 0, sizeof(*out));
  out->id = id;
  out->question = *question;
  fn_u16_write_be(out->wire, id);
  fn_u16_write_be(out->wire + 2u, UINT16_C(0x0100));
  fn_u16_write_be(out->wire + 4u, UINT16_C(1));
  while (input < question->length) {
    size_t label_start = input;
    size_t label_length;
    while (input < question->length && question->bytes[input] != '.') {
      input++;
    }
    label_length = input - label_start;
    if (label_length == 0 || label_length > FN_DOMAIN_LABEL_MAX ||
        output + 1u + label_length + 5u > sizeof(out->wire)) {
      return dns_api_result(FN_INVALID);
    }
    out->wire[output++] = (uint8_t)label_length;
    memcpy(out->wire + output, question->bytes + label_start, label_length);
    output += label_length;
    if (input < question->length) {
      input++;
    }
  }
  out->wire[output++] = 0;
  fn_u16_write_be(out->wire + output, UINT16_C(1));
  output += 2u;
  fn_u16_write_be(out->wire + output, UINT16_C(1));
  output += 2u;
  out->length = output;
  return dns_api_result(FN_OK);
}

fn_result_t fn_dns_response_parse(const uint8_t *message,
                                  size_t message_length,
                                  fn_dns_transport_t transport,
                                  const fn_dns_query_t *query,
                                  fn_dns_parse_result_t *out)
{
  fn_dns_decode_context_t context;
  fn_dns_name_t response_question;
  fn_dns_cname_index_t cnames;
  fn_domain_t normalized_question;
  fn_domain_t chain[FN_DNS_CNAME_HOPS_MAX + 1u];
  uint16_t flags;
  uint16_t answer_count;
  uint16_t authority_count;
  uint16_t additional_count;
  uint32_t cname_ttl = UINT32_MAX;
  size_t cursor;
  size_t records_end;
  size_t chain_count = 0;
  size_t total_records;
  uint16_t rcode;

  if (out == NULL) {
    return dns_api_result(FN_INVALID);
  }
  memset(out, 0, sizeof(*out));
  out->action = FN_DNS_PARSE_TERMINAL;
  out->result = dns_api_result(FN_INVALID);
  if (message == NULL || query == NULL || query->length == 0 ||
      query->length > FN_DNS_MESSAGE_UDP_MAX ||
      query->question.length == 0 ||
      query->question.length > FN_DOMAIN_MAX ||
      fn_domain_from_bytes(&normalized_question,
                           (const uint8_t *)query->question.bytes,
                           query->question.length).code != FN_OK ||
      !fn_domain_equal(&normalized_question, &query->question) ||
      (transport != FN_DNS_TRANSPORT_UDP &&
       transport != FN_DNS_TRANSPORT_TCP)) {
    return dns_api_result(FN_INVALID);
  }
  if (message_length >= 2u && fn_u16_read_be(message) != query->id) {
    out->action = FN_DNS_PARSE_DISCARD;
    out->result = dns_api_result(FN_OK);
    return dns_api_result(FN_OK);
  }
  if (message_length < FN_DNS_HEADER_SIZE ||
      (transport == FN_DNS_TRANSPORT_UDP &&
       message_length > FN_DNS_MESSAGE_UDP_MAX) ||
      message_length > FN_DNS_MESSAGE_TCP_MAX) {
    parse_terminal(out, FN_PROTOCOL_ERROR, FN_DNS_NATIVE_MALFORMED);
    return dns_api_result(FN_OK);
  }
  flags = fn_u16_read_be(message + 2u);
  answer_count = fn_u16_read_be(message + 6u);
  authority_count = fn_u16_read_be(message + 8u);
  additional_count = fn_u16_read_be(message + 10u);
  total_records = (size_t)answer_count + (size_t)authority_count +
                  (size_t)additional_count;
  if ((flags & UINT16_C(0x8000)) == 0 ||
      (flags & UINT16_C(0x7800)) != 0 ||
      (flags & UINT16_C(0x0040)) != 0 ||
      fn_u16_read_be(message + 4u) != UINT16_C(1)) {
    parse_terminal(out, FN_PROTOCOL_ERROR, FN_DNS_NATIVE_MALFORMED);
    return dns_api_result(FN_OK);
  }
  if (total_records > FN_DNS_RR_MAX) {
    parse_terminal(out, FN_LIMIT, FN_DNS_NATIVE_RESPONSE_LIMIT);
    return dns_api_result(FN_OK);
  }
  memset(&context, 0, sizeof(context));
  context.message = message;
  context.length = message_length;
  cursor = FN_DNS_HEADER_SIZE;
  if (!dns_decode_name(&context, cursor, &response_question)) {
    parse_malformed(&context, out);
    return dns_api_result(FN_OK);
  }
  cursor += response_question.consumed;
  if (message_length - cursor < 4u) {
    parse_malformed(&context, out);
    return dns_api_result(FN_OK);
  }
  if (!dns_name_equals_domain(&response_question, &query->question) ||
      fn_u16_read_be(message + cursor) != UINT16_C(1) ||
      fn_u16_read_be(message + cursor + 2u) != UINT16_C(1)) {
    out->action = FN_DNS_PARSE_DISCARD;
    out->result = dns_api_result(FN_OK);
    return dns_api_result(FN_OK);
  }
  cursor += 4u;
  if ((flags & UINT16_C(0x0200)) != 0) {
    if (transport == FN_DNS_TRANSPORT_UDP) {
      out->action = FN_DNS_PARSE_TCP_FALLBACK;
      out->result = dns_api_result(FN_OK);
    } else {
      parse_terminal(out, FN_PROTOCOL_ERROR, FN_DNS_NATIVE_TRUNCATED);
    }
    return dns_api_result(FN_OK);
  }
  memset(&cnames, 0, sizeof(cnames));
  if (!scan_records(&context, cursor, answer_count, authority_count,
                    additional_count, &cnames, &records_end) ||
      records_end != message_length) {
    parse_malformed(&context, out);
    return dns_api_result(FN_OK);
  }
  rcode = flags & UINT16_C(0x000f);
  if (rcode != 0) {
    parse_terminal(out, FN_RESOLVE_ERROR, (int64_t)rcode);
    return dns_api_result(FN_OK);
  }
  if (!resolve_cname_chain(&cnames, &query->question, chain, &chain_count,
                           &cname_ttl, out)) {
    return dns_api_result(FN_OK);
  }
  context.steps = 0;
  context.limit = false;
  if (!collect_addresses(&context, cursor, answer_count, authority_count,
                         additional_count, chain, chain_count, cname_ttl,
                         out)) {
    parse_malformed(&context, out);
  }
  return dns_api_result(FN_OK);
}
