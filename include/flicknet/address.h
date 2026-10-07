#ifndef FLICKNET_ADDRESS_H
#define FLICKNET_ADDRESS_H

#include "flicknet/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FN_DOMAIN_MAX 253u
#define FN_DOMAIN_LABEL_MAX 63u
#define FN_RESOLVED_MAX 16u

typedef enum {
  FN_ADDR_NONE = 0,
  FN_ADDR_V4,
  FN_ADDR_V6,
  FN_ADDR_DOMAIN
} fn_addr_kind_t;

typedef struct {
  uint16_t length;
  char bytes[FN_DOMAIN_MAX + 1u];
} fn_domain_t;

typedef struct {
  fn_addr_kind_t kind;
  union {
    uint8_t v4[4];
    uint8_t v6[16];
    fn_domain_t domain;
  } value;
} fn_addr_t;

/* port 使用主机字节序；地址字节保持网络顺序。 */
typedef struct {
  fn_addr_t address;
  uint16_t port;
} fn_endpoint_t;

/* 输入按显式长度读取；成功后 out 持有小写、无根点的值副本。 */
fn_result_t fn_domain_from_bytes(fn_domain_t *out, const uint8_t *input,
                                 size_t input_length);
bool fn_domain_equal(const fn_domain_t *left, const fn_domain_t *right);

fn_result_t fn_addr_from_v4(fn_addr_t *out, const uint8_t bytes[4]);
fn_result_t fn_addr_from_v6(fn_addr_t *out, const uint8_t bytes[16]);
fn_result_t fn_addr_from_domain(fn_addr_t *out, const fn_domain_t *domain);
fn_result_t fn_endpoint_make(fn_endpoint_t *out, const fn_addr_t *address,
                             uint16_t port);

uint16_t fn_u16_read_be(const uint8_t bytes[2]);
void fn_u16_write_be(uint8_t bytes[2], uint16_t value);

#endif
