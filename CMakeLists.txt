cmake_minimum_required(VERSION 3.25)

project(FlickNet VERSION 0.0.0 LANGUAGES C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(FN_BUILD_PROFILE "custom" CACHE STRING "Supported FlickNet build profile")
set_property(CACHE FN_BUILD_PROFILE PROPERTY STRINGS
  dev release release-minimal asan ubsan coverage fuzz custom)

option(FN_BUILD_TESTING "Build FlickNet tests" ON)
option(FN_BUILD_BENCHMARKS "Build FlickNet benchmark targets when implemented" OFF)
option(FN_BUILD_FUZZERS "Instrument libraries for FlickNet fuzz targets" OFF)
option(FN_ENABLE_PROFILING "Enable FlickNet profiling hooks" OFF)
option(FN_ENABLE_COVERAGE "Enable FlickNet coverage instrumentation" OFF)
set(FN_SANITIZER "none" CACHE STRING "FlickNet sanitizer mode")
set_property(CACHE FN_SANITIZER PROPERTY STRINGS none address undefined fuzz)

include(FlickDependencies)
include(FlickProjectOptions)
find_package(Threads REQUIRED)

fn_create_project_options(fn_project_options)

add_library(flick_core STATIC
  src/config/config.c
  src/core/build.c
  src/core/metadata.c
  src/core/observability.c
  src/core/operation.c
  src/core/pool.c
  src/core/result.c
  src/core/resource.c
  src/core/runtime.c
  src/core/session.c
  src/dns/dns_wire.c
  src/dns/resolver.c
  src/dns/resolver_linux.c
  src/inbound/socks5.c
  src/net/loop.c
  src/net/stream.c
  src/outbound/direct.c
  src/outbound/socks5.c
  src/platform/linux/platform.c
  src/router/router.c
  src/util/address.c
  src/util/clock.c
  src/cli/cli.c
)
add_library(FlickNet::core ALIAS flick_core)

target_compile_features(flick_core PUBLIC c_std_11)
set_target_properties(flick_core PROPERTIES
  C_EXTENSIONS OFF
  C_STANDARD_REQUIRED ON
)
target_include_directories(flick_core
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
)
target_link_libraries(flick_core
  PUBLIC fn_project_options Threads::Threads
  PRIVATE FlickNet::libev PkgConfig::FN_YAML
)
target_compile_definitions(flick_core PRIVATE
  FN_BUILD_PLATFORM="${CMAKE_SYSTEM_NAME}/${CMAKE_SYSTEM_PROCESSOR}"
  FN_BUILD_LIBEV_VERSION="${FN_LIBEV_VERSION_MAJOR}.${FN_LIBEV_VERSION_MINOR}"
  FN_BUILD_LIBYAML_VERSION="${FN_YAML_VERSION}"
)

set(FN_FUZZ_TARGETS_PRESENT OFF)
if(FN_BUILD_FUZZERS)
  function(fn_add_fuzz_target target source)
    add_executable(${target} ${source})
    target_link_libraries(${target} PRIVATE FlickNet::core)
    target_link_options(${target} PRIVATE
      -fsanitize=fuzzer,address,undefined)
  endfunction()

  fn_add_fuzz_target(fuzz_config tests/fuzz/fuzz_config.c)
  fn_add_fuzz_target(fuzz_socks5 tests/fuzz/fuzz_socks5.c)
  fn_add_fuzz_target(fuzz_dns tests/fuzz/fuzz_dns.c)
  set(FN_FUZZ_TARGETS_PRESENT ON)
endif()

set(FN_BENCHMARK_TARGETS_PRESENT OFF)
file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/bench/workloads/v0_1.json"
  FN_BENCH_WORKLOAD_SHA256)
if(FN_BUILD_BENCHMARKS)
  function(fn_add_benchmark_target target source)
    add_executable(${target} ${source} bench/bench_common.c)
    target_include_directories(${target}
      PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/bench")
    target_compile_definitions(${target}
      PRIVATE FN_BENCH_WORKLOAD_SHA256="${FN_BENCH_WORKLOAD_SHA256}")
    target_link_libraries(${target} PRIVATE FlickNet::core m)
  endfunction()

  fn_add_benchmark_target(bench_rule bench/bench_rule.c)
  fn_add_benchmark_target(bench_socks bench/bench_socks.c)
  fn_add_benchmark_target(bench_dns bench/bench_dns.c)
  fn_add_benchmark_target(bench_relay bench/bench_relay.c)
  set(FN_BENCHMARK_TARGETS_PRESENT ON)
endif()

add_executable(flick
  src/cli/app.c
  src/cli/main.c
)
target_include_directories(flick PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/cli")
target_link_libraries(flick PRIVATE FlickNet::core)

include(FlickBuildMetadata)
fn_generate_build_manifest(
  "${CMAKE_CURRENT_BINARY_DIR}/flick-capabilities.json"
)

if(FN_BUILD_TESTING)
  target_compile_definitions(flick PRIVATE FN_TEST_INSTRUMENTATION=1)
  enable_testing()
  find_package(Python3 3.11 REQUIRED COMPONENTS Interpreter)

  add_executable(fn_p01_contract_test tests/unit/test_p01_contract.c)
  target_link_libraries(fn_p01_contract_test
    PRIVATE FlickNet::core FlickNet::libev PkgConfig::FN_YAML
  )
  add_test(NAME p01.core-contract COMMAND fn_p01_contract_test)
  set_tests_properties(p01.core-contract PROPERTIES LABELS unit)

  add_test(
    NAME p01.capability-manifest
    COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/check_capability_manifest.py"
            --path "${CMAKE_CURRENT_BINARY_DIR}/flick-capabilities.json"
            --profile "${FN_BUILD_PROFILE}"
  )
  set_tests_properties(p01.capability-manifest PROPERTIES LABELS unit)

  add_executable(fn_p02_address_clock_test
    tests/unit/test_p02_address_clock.c)
  target_link_libraries(fn_p02_address_clock_test PRIVATE FlickNet::core)
  add_test(NAME p02.address-clock COMMAND fn_p02_address_clock_test)
  set_tests_properties(p02.address-clock PROPERTIES LABELS unit)

  add_executable(fn_p02_resource_pool_test
    tests/unit/test_p02_resource_pool.c)
  target_link_libraries(fn_p02_resource_pool_test PRIVATE FlickNet::core)
  add_test(NAME p02.resource-pool COMMAND fn_p02_resource_pool_test)
  set_tests_properties(p02.resource-pool PROPERTIES
    LABELS "unit;resource;fault")

  add_executable(fn_p02_metadata_test tests/unit/test_p02_metadata.c)
  target_link_libraries(fn_p02_metadata_test PRIVATE FlickNet::core)
  add_test(NAME p02.metadata COMMAND fn_p02_metadata_test)
  set_tests_properties(p02.metadata PROPERTIES LABELS unit)

  add_executable(fn_p03_config_test tests/unit/test_p03_config.c)
  target_compile_definitions(fn_p03_config_test
    PRIVATE FN_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
  )
  target_link_libraries(fn_p03_config_test PRIVATE FlickNet::core)
  add_test(NAME p03.config COMMAND fn_p03_config_test)
  set_tests_properties(p03.config PROPERTIES LABELS "unit;config;fault")

  add_executable(fn_p04_loop_platform_test
    tests/unit/test_p04_loop_platform.c)
  target_include_directories(fn_p04_loop_platform_test
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/linux"
  )
  target_link_libraries(fn_p04_loop_platform_test PRIVATE FlickNet::core)
  add_test(NAME p04.loop-platform COMMAND fn_p04_loop_platform_test)
  set_tests_properties(p04.loop-platform PROPERTIES
    LABELS "unit;fault;resource")

  add_executable(fn_p05_runtime_router_test
    tests/unit/test_p05_runtime_router.c)
  target_link_libraries(fn_p05_runtime_router_test PRIVATE FlickNet::core)
  add_test(NAME p05.runtime-router COMMAND fn_p05_runtime_router_test)
  set_tests_properties(p05.runtime-router PROPERTIES
    LABELS "unit;fault;resource;router")

  add_executable(fn_p06_stream_relay_test
    tests/unit/test_p06_stream_relay.c)
  target_link_libraries(fn_p06_stream_relay_test PRIVATE FlickNet::core)
  add_test(NAME p06.stream-relay COMMAND fn_p06_stream_relay_test)
  set_tests_properties(p06.stream-relay PROPERTIES
    LABELS "unit;fault;resource;relay")

  add_executable(fn_p07_resolver_test tests/unit/test_p07_resolver.c)
  target_include_directories(fn_p07_resolver_test
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/dns"
  )
  target_link_libraries(fn_p07_resolver_test PRIVATE FlickNet::core)
  add_test(NAME p07.resolver COMMAND fn_p07_resolver_test)
  set_tests_properties(p07.resolver PROPERTIES
    LABELS "unit;fault;resource;dns")

  add_executable(fn_p08_session_direct_test
    tests/unit/test_p08_session_direct.c)
  target_link_libraries(fn_p08_session_direct_test PRIVATE FlickNet::core)
  add_test(NAME p08.session-direct COMMAND fn_p08_session_direct_test)
  set_tests_properties(p08.session-direct PROPERTIES
    LABELS "integration;fault;resource;session;direct")

  add_executable(fn_p09_socks5_inbound_test
    tests/unit/test_p09_socks5_inbound.c)
  target_link_libraries(fn_p09_socks5_inbound_test PRIVATE FlickNet::core)
  add_test(NAME p09.socks5-inbound COMMAND fn_p09_socks5_inbound_test)
  set_tests_properties(p09.socks5-inbound PROPERTIES
    LABELS "unit;protocol;fault;resource;socks5")

  add_executable(fn_p09_socks5_direct_chain_test
    tests/integration/test_p09_socks5_direct_chain.c)
  target_link_libraries(fn_p09_socks5_direct_chain_test
    PRIVATE FlickNet::core)
  add_test(NAME p09.socks5-direct-chain
    COMMAND fn_p09_socks5_direct_chain_test)
  set_tests_properties(p09.socks5-direct-chain PROPERTIES
    LABELS "integration;protocol;resource;socks5")

  add_executable(fn_p10_socks5_outbound_test
    tests/unit/test_p10_socks5_outbound.c)
  target_link_libraries(fn_p10_socks5_outbound_test PRIVATE FlickNet::core)
  add_test(NAME p10.socks5-outbound COMMAND fn_p10_socks5_outbound_test)
  set_tests_properties(p10.socks5-outbound PROPERTIES
    LABELS "unit;protocol;fault;resource;socks5")

  add_executable(fn_p10_socks5_double_chain_test
    tests/integration/test_p10_socks5_double_chain.c)
  target_link_libraries(fn_p10_socks5_double_chain_test
    PRIVATE FlickNet::core)
  add_test(NAME p10.socks5-double-chain
    COMMAND fn_p10_socks5_double_chain_test)
  set_tests_properties(p10.socks5-double-chain PROPERTIES
    LABELS "integration;protocol;dns;resource;socks5")

  add_executable(fn_p11_cli_observability_test
    tests/unit/test_p11_cli_observability.c)
  target_link_libraries(fn_p11_cli_observability_test PRIVATE FlickNet::core)
  add_test(NAME p11.cli-observability
    COMMAND fn_p11_cli_observability_test)
  set_tests_properties(p11.cli-observability PROPERTIES
    LABELS "unit;cli;resource;observability")

  add_test(NAME p11.cli-integration
    COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/test_p11_cli.py"
            --binary "$<TARGET_FILE:flick>"
            --root "${CMAKE_CURRENT_SOURCE_DIR}")
  set_tests_properties(p11.cli-integration PROPERTIES
    LABELS "integration;cli;protocol;fault;resource")

  add_executable(fn_p12_runtime_replacement_test
    tests/integration/test_p12_runtime_replacement.c)
  target_link_libraries(fn_p12_runtime_replacement_test
    PRIVATE FlickNet::core)
  add_test(NAME p12.runtime-replacement
    COMMAND fn_p12_runtime_replacement_test)
  set_tests_properties(p12.runtime-replacement PROPERTIES
    LABELS "integration;fault;resource;runtime")

  add_executable(fn_p13_theil_sen tests/soak/theil_sen.c)

  add_executable(fn_p14_bench_contract_test
    tests/unit/test_p14_bench_contract.c
    bench/bench_common.c)
  target_include_directories(fn_p14_bench_contract_test
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/bench")
  target_compile_definitions(fn_p14_bench_contract_test
    PRIVATE FN_BENCH_WORKLOAD_SHA256="${FN_BENCH_WORKLOAD_SHA256}")
  target_link_libraries(fn_p14_bench_contract_test PRIVATE m)
  add_test(NAME p14.bench-contract COMMAND fn_p14_bench_contract_test)
  set_tests_properties(p14.bench-contract PROPERTIES
    LABELS "unit;benchmark;fault")

  add_test(
    NAME p14.bench-driver
    COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/test_p14_bench_driver.py"
            --root "${CMAKE_CURRENT_SOURCE_DIR}")
  set_tests_properties(p14.bench-driver PROPERTIES
    LABELS "integration;benchmark;fault;resource")
endif()

if(FN_ENABLE_COVERAGE)
  find_program(FN_LCOV_EXECUTABLE NAMES lcov REQUIRED)
  find_program(FN_GENHTML_EXECUTABLE NAMES genhtml REQUIRED)
  add_custom_target(coverage
    COMMAND "${CMAKE_COMMAND}" -E make_directory
            "${CMAKE_CURRENT_BINARY_DIR}/coverage"
    COMMAND "${FN_LCOV_EXECUTABLE}" --capture
            --directory "${CMAKE_CURRENT_BINARY_DIR}"
            --output-file "${CMAKE_CURRENT_BINARY_DIR}/coverage/raw.info"
            --rc branch_coverage=1
    COMMAND "${FN_LCOV_EXECUTABLE}" --remove
            "${CMAKE_CURRENT_BINARY_DIR}/coverage/raw.info"
            "*/tests/*"
            --output-file "${CMAKE_CURRENT_BINARY_DIR}/coverage/flick.info"
            --rc branch_coverage=1
    COMMAND "${FN_GENHTML_EXECUTABLE}"
            "${CMAKE_CURRENT_BINARY_DIR}/coverage/flick.info"
            --output-directory "${CMAKE_CURRENT_BINARY_DIR}/coverage/html"
            --branch-coverage
    COMMENT "Generating FlickNet coverage report"
    VERBATIM
  )
endif()
