# fn_create_project_options 只影响项目自有目标，避免把告警策略施加给依赖。
function(fn_create_project_options target)
  add_library(${target} INTERFACE)
  target_compile_features(${target} INTERFACE c_std_11)

  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target} INTERFACE
      -Wall
      -Wextra
      -Wpedantic
      -Werror
      -Wconversion
      -Wsign-conversion
      -Wshadow
      -Wstrict-prototypes
      -Wmissing-prototypes
      -Wformat=2
      -Wundef
      -Wcast-qual
      -Wwrite-strings
    )
  else()
    message(FATAL_ERROR "Unsupported C compiler: ${CMAKE_C_COMPILER_ID}")
  endif()

  target_compile_options(${target} INTERFACE
    "$<$<CONFIG:Debug>:-O0>"
    "$<$<CONFIG:Debug>:-g3>"
    "$<$<CONFIG:Release>:-O2>"
    "$<$<CONFIG:Release>:-fstack-protector-strong>"
    "$<$<CONFIG:Release>:-fPIE>"
  )
  target_compile_definitions(${target} INTERFACE
    "$<$<CONFIG:Release>:NDEBUG>"
    "$<$<CONFIG:Release>:_FORTIFY_SOURCE=3>"
  )
  target_link_options(${target} INTERFACE
    "$<$<AND:$<CONFIG:Release>,$<PLATFORM_ID:Linux>>:-Wl,-z,relro>"
    "$<$<AND:$<CONFIG:Release>,$<PLATFORM_ID:Linux>>:-Wl,-z,now>"
    "$<$<AND:$<CONFIG:Release>,$<PLATFORM_ID:Linux>>:-pie>"
  )

  if(FN_SANITIZER STREQUAL "address")
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
      message(FATAL_ERROR "The address sanitizer preset requires Clang")
    endif()
    target_compile_options(${target} INTERFACE
      -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(${target} INTERFACE -fsanitize=address)
  elseif(FN_SANITIZER STREQUAL "undefined")
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
      message(FATAL_ERROR "The undefined sanitizer preset requires Clang")
    endif()
    target_compile_options(${target} INTERFACE
      -fsanitize=undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
    target_link_options(${target} INTERFACE
      -fsanitize=undefined -fno-sanitize-recover=all)
  elseif(FN_SANITIZER STREQUAL "fuzz")
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang" OR NOT FN_BUILD_FUZZERS)
      message(FATAL_ERROR "The fuzz sanitizer mode requires Clang and FN_BUILD_FUZZERS=ON")
    endif()
    target_compile_options(${target} INTERFACE
      -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer)
    target_link_options(${target} INTERFACE -fsanitize=address,undefined)
  elseif(NOT FN_SANITIZER STREQUAL "none")
    message(FATAL_ERROR "Unknown FN_SANITIZER value: ${FN_SANITIZER}")
  endif()

  if(FN_ENABLE_COVERAGE)
    if(NOT CMAKE_C_COMPILER_ID STREQUAL "GNU")
      message(FATAL_ERROR "Coverage requires GCC in the supported V0.1 matrix")
    endif()
    target_compile_options(${target} INTERFACE --coverage -O0 -g3)
    target_link_options(${target} INTERFACE --coverage)
  endif()

  if(FN_ENABLE_PROFILING)
    target_compile_definitions(${target} INTERFACE FN_PROFILE=1)
  endif()
endfunction()
