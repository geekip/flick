#include "flicknet/address.h"

#include <string.h>

static fn_result_t address_result(fn_status_t code)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE : FN_STAGE_CONFIG,
                        FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

static bool is_ascii_letter(uint8_t value)
{
  return (value >= (uint8_t)'A' && value <= (uint8_t)'Z') ||
         (value >= (uint8_t)'a' && value <= (uint8_t)'z');
}

static bool is_domain_character(uint8_t value)
{
  return is_ascii_letter(value) ||
         (value >= (uint8_t)'0' && value <= (uint8_t)'9') ||
         value == (uint8_t)'-';
}

static uint8_t ascii_lower(uint8_t value)
{
  if (value >= (uint8_t)'A' && value <= (uint8_t)'Z') {
    return (uint8_t)(value + ((uint8_t)'a' - (uint8_t)'A'));
  }
  return value;
}

fn_result_t fn_domain_from_bytes(fn_domain_t *out, const uint8_t *input,
                                 size_t input_length)
{
  size_t normalized_length;
  size_t label_start = 0;
  size_t index;

  if (out == NULL) {
    return address_result(FN_INVALID);
  }
  memset(out, 0, sizeof(*out));
  if (input == NULL || input_length == 0) {
    return address_result(FN_INVALID);
  }

  normalized_length = input_length;
  if (input[input_length - 1] == (uint8_t)'.') {
    normalized_length--;
  }
  if (normalized_length == 0 || normalized_length > (size_t)FN_DOMAIN_MAX) {
    return address_result(FN_INVALID);
  }

  for (index = 0; index <= normalized_length; index++) {
    if (index == normalized_length || input[index] == (uint8_t)'.') {
      const size_t label_length = index - label_start;
      if (label_length == 0 || label_length > (size_t)FN_DOMAIN_LABEL_MAX ||
          input[label_start] == (uint8_t)'-' ||
          input[index - 1] == (uint8_t)'-') {
        return address_result(FN_INVALID);
      }
      label_start = index + 1;
      continue;
    }
    if (!is_domain_character(input[index])) {
      return address_result(FN_INVALID);
    }
  }

  for (index = 0; index < normalized_length; index++) {
    out->bytes[index] = (char)ascii_lower(input[index]);
  }
  out->bytes[normalized_length] = '\0';
  out->length = (uint16_t)normalized_length;
  return address_result(FN_OK);
}

bool fn_domain_equal(const fn_domain_t *left, const fn_domain_t *right)
{
  if (left == NULL || right == NULL || left->length != right->length ||
      left->length > FN_DOMAIN_MAX) {
    return false;
  }
  return memcmp(left->bytes, right->bytes, left->length) == 0;
}

fn_result_t fn_addr_from_v4(fn_addr_t *out, const uint8_t bytes[4])
{
  if (out == NULL) {
    return address_result(FN_INVALID);
  }
  memset(out, 0, sizeof(*out));
  if (bytes == NULL) {
    return address_result(FN_INVALID);
  }
  out->kind = FN_ADDR_V4;
  memcpy(out->value.v4, bytes, sizeof(out->value.v4));
  return address_result(FN_OK);
}

fn_result_t fn_addr_from_v6(fn_addr_t *out, const uint8_t bytes[16])
{
  if (out == NULL) {
    return address_result(FN_INVALID);
  }
  memset(out, 0, sizeof(*out));
  if (bytes == NULL) {
    return address_result(FN_INVALID);
  }
  out->kind = FN_ADDR_V6;
  memcpy(out->value.v6, bytes, sizeof(out->value.v6));
  return address_result(FN_OK);
}

fn_result_t fn_addr_from_domain(fn_addr_t *out, const fn_domain_t *domain)
{
  if (out == NULL) {
    return address_result(FN_INVALID);
  }
  memset(out, 0, sizeof(*out));
  if (domain == NULL || domain->length == 0 ||
      domain->length > FN_DOMAIN_MAX ||
      domain->bytes[domain->length] != '\0') {
    return address_result(FN_INVALID);
  }
  out->kind = FN_ADDR_DOMAIN;
  out->value.domain = *domain;
  return address_result(FN_OK);
}

fn_result_t fn_endpoint_make(fn_endpoint_t *out, const fn_addr_t *address,
                             uint16_t port)
{
  if (out == NULL) {
    return address_result(FN_INVALID);
  }
  memset(out, 0, sizeof(*out));
  if (address == NULL || address->kind <= FN_ADDR_NONE ||
      address->kind > FN_ADDR_DOMAIN) {
    return address_result(FN_INVALID);
  }
  out->address = *address;
  out->port = port;
  return address_result(FN_OK);
}

uint16_t fn_u16_read_be(const uint8_t bytes[2])
{
  return (uint16_t)(((uint16_t)bytes[0] << 8u) | (uint16_t)bytes[1]);
}

void fn_u16_write_be(uint8_t bytes[2], uint16_t value)
{
  bytes[0] = (uint8_t)(value >> 8u);
  bytes[1] = (uint8_t)(value & UINT16_C(0x00ff));
}
