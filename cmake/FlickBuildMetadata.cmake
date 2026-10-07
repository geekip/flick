# 将 configure 事实写入机器 Manifest；该文件本身不是产品验收证据。
function(fn_json_bool input output)
  if(${input})
    set(${output} true PARENT_SCOPE)
  else()
    set(${output} false PARENT_SCOPE)
  endif()
endfunction()

function(fn_generate_build_manifest output_path)
  fn_json_bool(FN_BUILD_TESTING FN_JSON_BUILD_TESTING)
  fn_json_bool(FN_BUILD_BENCHMARKS FN_JSON_BUILD_BENCHMARKS_REQUESTED)
  fn_json_bool(FN_BUILD_FUZZERS FN_JSON_BUILD_FUZZERS_REQUESTED)
  fn_json_bool(FN_FUZZ_TARGETS_PRESENT FN_JSON_FUZZ_TARGETS_PRESENT)
  fn_json_bool(FN_BENCHMARK_TARGETS_PRESENT FN_JSON_BENCHMARK_TARGETS_PRESENT)
  fn_json_bool(FN_ENABLE_PROFILING FN_JSON_PROFILING)
  fn_json_bool(FN_ENABLE_COVERAGE FN_JSON_COVERAGE)

  execute_process(
    COMMAND git rev-parse --verify HEAD
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    RESULT_VARIABLE _fn_git_result
    OUTPUT_VARIABLE _fn_git_revision
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
  )
  if(_fn_git_result EQUAL 0)
    set(FN_JSON_GIT_REVISION "\"${_fn_git_revision}\"")
  else()
    set(FN_JSON_GIT_REVISION null)
  endif()

  execute_process(
    COMMAND git status --porcelain
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    RESULT_VARIABLE _fn_git_status_result
    OUTPUT_VARIABLE _fn_git_status
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
  )
  if(NOT _fn_git_status_result EQUAL 0 OR NOT _fn_git_status STREQUAL "")
    set(FN_JSON_GIT_DIRTY true)
  else()
    set(FN_JSON_GIT_DIRTY false)
  endif()

  set(FN_MANIFEST_PATH "${output_path}")
  configure_file(
    "${PROJECT_SOURCE_DIR}/cmake/flick-capabilities.json.in"
    "${output_path}"
    @ONLY
  )
  message(STATUS "FlickNet capability manifest: ${output_path}")
endfunction()
