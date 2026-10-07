#include "operation_internal.h"

static fn_result_t operation_result(fn_status_t code)
{
  return fn_result_make(code, code == FN_OK ? FN_STAGE_NONE :
                        FN_STAGE_RESOURCE, FN_ERROR_ORIGIN_NONE, INT64_C(0));
}

void fn_op_initialize(fn_op_t *operation, const fn_op_ops_t *ops)
{
  if (operation != NULL) {
    operation->ops = ops;
  }
}

fn_result_t fn_op_cancel(fn_op_t *operation)
{
  if (operation == NULL || operation->ops == NULL ||
      operation->ops->cancel == NULL) {
    return operation_result(FN_INVALID);
  }
  return operation->ops->cancel(operation);
}

fn_result_t fn_op_release(fn_op_t **pointer)
{
  fn_op_t *operation;
  if (pointer == NULL) {
    return operation_result(FN_INVALID);
  }
  operation = *pointer;
  if (operation == NULL) {
    return operation_result(FN_OK);
  }
  if (operation->ops == NULL || operation->ops->release == NULL) {
    return operation_result(FN_INVALID);
  }
  return operation->ops->release(pointer);
}
