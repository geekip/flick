#include "flicknet/resolver.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int hex_value(uint8_t byte)
{
  if (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') {
    return (int)(byte - (uint8_t)'0');
  }
  if (byte >= (uint8_t)'a' && byte <= (uint8_t)'f') {
    return (int)(byte - (uint8_t)'a') + 10;
  }
  if (byte >= (uint8_t)'A' && byte <= (uint8_t)'F') {
    return (int)(byte - (uint8_t)'A') + 10;
  }
  return -1;
}

static bool decode_seed(const uint8_t *data, size_t size,
                        uint8_t *decoded, size_t capacity,
                        const uint8_t **out_data, size_t *out_size)
{
  size_t index;
  size_t length;
  if (size < 4u || memcmp(data, "hex:", 4u) != 0 ||
      ((size - 4u) & 1u) != 0) {
    *out_data = data;
    *out_size = size;
    return true;
  }
  length = (size - 4u) / 2u;
  if (length > capacity) {
    return false;
  }
  for (index = 0; index < length; index++) {
    int high = hex_value(data[4u + index * 2u]);
    int low = hex_value(data[5u + index * 2u]);
    if (high < 0 || low < 0) {
      *out_data = data;
      *out_size = size;
      return true;
    }
    decoded[index] = (uint8_t)(((unsigned)high << 4u) | (unsigned)low);
  }
  *out_data = decoded;
  *out_size = length;
  return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  static const uint8_t question_bytes[] = "example.org";
  uint8_t decoded[FN_DNS_MESSAGE_TCP_MAX];
  const uint8_t *message;
  size_t message_size;
  fn_domain_t question;
  fn_dns_query_t query;
  fn_dns_parse_result_t parsed;
  uint16_t id;

  if (!decode_seed(data, size, decoded, sizeof(decoded),
                   &message, &message_size) ||
      message_size > FN_DNS_MESSAGE_TCP_MAX) {
    return 0;
  }
  id = message_size >= 2u ?
    (uint16_t)(((uint16_t)message[0] << 8u) | (uint16_t)message[1]) : 0u;
  if (fn_domain_from_bytes(&question, question_bytes,
                           sizeof(question_bytes) - 1u).code != FN_OK ||
      fn_dns_query_build(&question, id, &query).code != FN_OK) {
    __builtin_trap();
  }
  (void)fn_dns_response_parse(message, message_size,
                              FN_DNS_TRANSPORT_UDP, &query, &parsed);
  (void)fn_dns_response_parse(message, message_size,
                              FN_DNS_TRANSPORT_TCP, &query, &parsed);
  return 0;
}
