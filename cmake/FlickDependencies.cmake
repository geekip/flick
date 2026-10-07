# V0.1 只使用系统提供的 libev 与 libyaml，不在 configure 阶段联网或回退。
include(CheckCSourceCompiles)
include(FindPackageHandleStandardArgs)

find_path(FN_LIBEV_INCLUDE_DIR NAMES ev.h REQUIRED)
find_library(FN_LIBEV_LIBRARY NAMES ev REQUIRED)

file(STRINGS "${FN_LIBEV_INCLUDE_DIR}/ev.h" FN_LIBEV_VERSION_LINES
  REGEX "^#define EV_VERSION_(MAJOR|MINOR) [0-9]+$")
string(REGEX MATCH "EV_VERSION_MAJOR ([0-9]+)" _fn_libev_major_match
  "${FN_LIBEV_VERSION_LINES}")
set(FN_LIBEV_VERSION_MAJOR "${CMAKE_MATCH_1}")
string(REGEX MATCH "EV_VERSION_MINOR ([0-9]+)" _fn_libev_minor_match
  "${FN_LIBEV_VERSION_LINES}")
set(FN_LIBEV_VERSION_MINOR "${CMAKE_MATCH_1}")

if(FN_LIBEV_VERSION_MAJOR STREQUAL "" OR FN_LIBEV_VERSION_MINOR STREQUAL "")
  message(FATAL_ERROR "libev version macros were not found in ${FN_LIBEV_INCLUDE_DIR}/ev.h")
endif()
if(FN_LIBEV_VERSION_MAJOR LESS 4 OR
   (FN_LIBEV_VERSION_MAJOR EQUAL 4 AND FN_LIBEV_VERSION_MINOR LESS 33))
  message(FATAL_ERROR
    "libev >= 4.33 is required; found ${FN_LIBEV_VERSION_MAJOR}.${FN_LIBEV_VERSION_MINOR}")
endif()

set(CMAKE_REQUIRED_INCLUDES "${FN_LIBEV_INCLUDE_DIR}")
set(CMAKE_REQUIRED_LIBRARIES "${FN_LIBEV_LIBRARY}")
check_c_source_compiles([[#include <ev.h>
#if EV_VERSION_MAJOR < 4 || (EV_VERSION_MAJOR == 4 && EV_VERSION_MINOR < 33)
#error libev version is too old
#endif
int main(void) {
  struct ev_loop *loop = ev_loop_new(EVFLAG_NOENV);
  if (loop == 0) return 1;
  ev_loop_destroy(loop);
  return 0;
}
]] FN_LIBEV_LINK_PROBE)
unset(CMAKE_REQUIRED_INCLUDES)
unset(CMAKE_REQUIRED_LIBRARIES)
if(NOT FN_LIBEV_LINK_PROBE)
  message(FATAL_ERROR "libev header/library link probe failed")
endif()

add_library(fn_libev UNKNOWN IMPORTED GLOBAL)
add_library(FlickNet::libev ALIAS fn_libev)
set_target_properties(fn_libev PROPERTIES
  IMPORTED_LOCATION "${FN_LIBEV_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${FN_LIBEV_INCLUDE_DIR}"
)

find_package(PkgConfig 1.8 REQUIRED)
if(NOT PkgConfig_FOUND OR NOT COMMAND pkg_check_modules)
  message(FATAL_ERROR "pkg-config >= 1.8 is required for libyaml discovery")
endif()
pkg_check_modules(FN_YAML REQUIRED IMPORTED_TARGET "yaml-0.1>=0.2.5")

set(CMAKE_REQUIRED_LIBRARIES PkgConfig::FN_YAML)
check_c_source_compiles([[#include <yaml.h>
int main(void) {
  yaml_parser_t parser;
  if (!yaml_parser_initialize(&parser)) return 1;
  yaml_parser_delete(&parser);
  return 0;
}
]] FN_LIBYAML_LINK_PROBE)
unset(CMAKE_REQUIRED_LIBRARIES)
if(NOT FN_LIBYAML_LINK_PROBE)
  message(FATAL_ERROR "libyaml header/library link probe failed")
endif()

message(STATUS
  "FlickNet dependencies: libev ${FN_LIBEV_VERSION_MAJOR}.${FN_LIBEV_VERSION_MINOR}; libyaml ${FN_YAML_VERSION}")
