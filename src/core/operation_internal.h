#ifndef FLICKNET_OPERATION_INTERNAL_H
#define FLICKNET_OPERATION_INTERNAL_H

#include "flicknet/session.h"

typedef struct {
  fn_result_t (*cancel)(fn_op_t *operation);
  fn_result_t (*release)(fn_op_t **operation);
} fn_op_ops_t;

struct fn_op {
  const fn_op_ops_t *ops;
};

/* fn_op_initialize 只初始化通用分派头，不取得实现对象所有权。 */
void fn_op_initialize(fn_op_t *operation, const fn_op_ops_t *ops);

#endif
