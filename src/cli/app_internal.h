#ifndef FLICKNET_APP_INTERNAL_H
#define FLICKNET_APP_INTERNAL_H

#include "flicknet/config.h"
#include "flicknet/loop.h"
#include "flicknet/observability.h"
#include "flicknet/runtime.h"
#include "flicknet/session.h"
#include "flicknet/stream.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct fn_app fn_app_t;

typedef struct {
  uint64_t generation;
  size_t listeners;
  size_t lazy_objects;
  uint64_t accepted_connections;
  uint64_t completed_sessions;
  uint64_t failed_sessions;
  uint64_t bytes_up;
  uint64_t bytes_down;
  size_t active_connections;
  size_t active_handshakes;
  bool forced_stop;
  fn_loop_snapshot_t loop;
  fn_logger_snapshot_t logger;
  fn_budget_snapshot_t owned_memory;
  fn_budget_snapshot_t file_descriptors;
  fn_budget_snapshot_t buffers;
  fn_session_manager_snapshot_t sessions;
  fn_runtime_manager_snapshot_t runtime_manager;
  fn_relay_buffer_pool_snapshot_t relay_pool;
} fn_app_summary_t;

/* fn_app_test_environment 只短暂准备可达启动资源，不激活 lazy 对象。 */
fn_result_t fn_app_test_environment(const fn_config_t *config,
                                    const fn_feature_plan_t *plan,
                                    fn_app_summary_t *summary);
/* fn_app_create 完成 prepare/commit 后启动前台 listener。 */
fn_result_t fn_app_create(const fn_config_t *config,
                          const fn_feature_plan_t *plan,
                          fn_logger_t *logger, fn_app_t **out);
/* fn_app_run 在 owning 线程运行到信号停止或运行错误。 */
fn_result_t fn_app_run(fn_app_t *app, fn_app_summary_t *summary);
fn_result_t fn_app_snapshot(fn_app_t *app, fn_app_summary_t *summary);
fn_result_t fn_app_destroy(fn_app_t **app);

#endif
