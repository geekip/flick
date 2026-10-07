#include "flicknet/address.h"
#include "flicknet/clock.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int check_domain_normalization(void)
{
  static const uint8_t mixed[] = "Example.COM.";
  static const uint8_t expected[] = "example.com";
  fn_domain_t domain;
  fn_domain_t copy;
  uint8_t maximum[FN_DOMAIN_MAX];
  size_t index = 0;
  size_t label;

  if (fn_domain_from_bytes(&domain, mixed, sizeof(mixed) - 1u).code != FN_OK ||
      domain.length != sizeof(expected) - 1u ||
      memcmp(domain.bytes, expected, sizeof(expected)) != 0) {
    return 1;
  }
  copy = domain;
  if (!fn_domain_equal(&domain, &copy)) {
    return 2;
  }
  for (label = 0; label < 4u; label++) {
    const size_t label_length = label < 3u ? 63u : 61u;
    size_t item;
    for (item = 0; item < label_length; item++) {
      maximum[index++] = (uint8_t)('a' + (int)label);
    }
    if (label < 3u) {
      maximum[index++] = (uint8_t)'.';
    }
  }
  if (index != FN_DOMAIN_MAX ||
      fn_domain_from_bytes(&domain, maximum, index).code != FN_OK ||
      domain.length != FN_DOMAIN_MAX) {
    return 3;
  }
  return 0;
}

static int check_domain_rejection(void)
{
  static const uint8_t empty_label[] = "a..b";
  static const uint8_t long_label[] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com";
  static const uint8_t leading_hyphen[] = "-a.example";
  static const uint8_t trailing_hyphen[] = "a-.example";
  static const uint8_t invalid_character[] = "a_b.example";
  static const uint8_t embedded_nul[] = {'a', 0, 'b'};
  static const uint8_t non_ascii[] = {'a', UINT8_C(0x80), 'b'};
  static const uint8_t root[] = ".";
  fn_domain_t domain;
  const struct {
    const uint8_t *bytes;
    size_t length;
  } cases[] = {
    {empty_label, sizeof(empty_label) - 1u},
    {long_label, sizeof(long_label) - 1u},
    {leading_hyphen, sizeof(leading_hyphen) - 1u},
    {trailing_hyphen, sizeof(trailing_hyphen) - 1u},
    {invalid_character, sizeof(invalid_character) - 1u},
    {embedded_nul, sizeof(embedded_nul)},
    {non_ascii, sizeof(non_ascii)},
    {root, sizeof(root) - 1u},
  };
  size_t index;

  for (index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
    if (fn_domain_from_bytes(&domain, cases[index].bytes,
                             cases[index].length).code != FN_INVALID ||
        domain.length != 0) {
      return (int)(10u + index);
    }
  }
  if (fn_domain_from_bytes(&domain, NULL, 0).code != FN_INVALID ||
      fn_domain_from_bytes(NULL, root, sizeof(root) - 1u).code != FN_INVALID) {
    return 20;
  }
  return 0;
}

static int check_address_and_byte_order(void)
{
  uint8_t v4[4] = {UINT8_C(192), UINT8_C(0), UINT8_C(2), UINT8_C(1)};
  uint8_t v6[16] = {0};
  uint8_t port_bytes[2] = {0};
  fn_addr_t address;
  fn_endpoint_t endpoint;

  v6[15] = UINT8_C(1);
  if (fn_addr_from_v4(&address, v4).code != FN_OK) {
    return 1;
  }
  v4[0] = UINT8_C(0);
  if (address.kind != FN_ADDR_V4 || address.value.v4[0] != UINT8_C(192) ||
      fn_endpoint_make(&endpoint, &address, UINT16_C(1080)).code != FN_OK ||
      endpoint.port != UINT16_C(1080)) {
    return 2;
  }
  if (fn_addr_from_v6(&address, v6).code != FN_OK ||
      address.value.v6[15] != UINT8_C(1)) {
    return 3;
  }
  fn_u16_write_be(port_bytes, UINT16_C(0xabcd));
  if (port_bytes[0] != UINT8_C(0xab) ||
      port_bytes[1] != UINT8_C(0xcd) ||
      fn_u16_read_be(port_bytes) != UINT16_C(0xabcd)) {
    return 4;
  }
  return 0;
}

static int check_monotonic_time(void)
{
  uint64_t converted = UINT64_MAX;
  uint64_t deadline = UINT64_MAX;
  uint64_t first;
  uint64_t second;

  if (fn_monotonic_parts_ms(UINT64_C(2), UINT32_C(123456789),
                            &converted).code != FN_OK ||
      converted != UINT64_C(2123)) {
    return 1;
  }
  if (fn_monotonic_parts_ms(UINT64_C(1), UINT32_C(1000000000),
                            &converted).code != FN_LIMIT || converted != 0) {
    return 2;
  }
  if (fn_monotonic_parts_ms(UINT64_MAX / UINT64_C(1000) + UINT64_C(1),
                            UINT32_C(0), &converted).code != FN_LIMIT ||
      converted != 0) {
    return 3;
  }
  if (fn_deadline_after_ms(UINT64_MAX - UINT64_C(5), UINT64_C(6),
                           &deadline).code != FN_LIMIT || deadline != 0 ||
      fn_deadline_after_ms(UINT64_C(100), UINT64_C(25),
                           &deadline).code != FN_OK ||
      deadline != UINT64_C(125)) {
    return 4;
  }
  if (fn_deadline_remaining_ms(UINT64_C(90), UINT64_C(125)) !=
        UINT64_C(35) ||
      fn_deadline_remaining_ms(UINT64_C(125), UINT64_C(125)) != 0 ||
      fn_deadline_remaining_ms(UINT64_C(126), UINT64_C(125)) != 0 ||
      fn_deadline_min(UINT64_C(5), UINT64_C(9)) != UINT64_C(5)) {
    return 5;
  }
  if (fn_monotonic_now_ms(&first).code != FN_OK ||
      fn_monotonic_now_ms(&second).code != FN_OK || second < first) {
    return 6;
  }
  return 0;
}

int main(void)
{
  const int domain_check = check_domain_normalization();
  const int reject_check = check_domain_rejection();
  const int address_check = check_address_and_byte_order();
  const int time_check = check_monotonic_time();

  if (domain_check != 0 || reject_check != 0 || address_check != 0 ||
      time_check != 0) {
    fprintf(stderr,
            "P02 address/clock check failed: domain=%d reject=%d address=%d time=%d.\n",
            domain_check, reject_check, address_check, time_check);
    return 1;
  }
  puts("P02 address and monotonic clock checks passed.");
  return 0;
}
