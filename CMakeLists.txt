cmake_minimum_required(VERSION 3.16)
project(watchtower VERSION 0.1.0 LANGUAGES C)

option(WT_CRASHPAD "Use Crashpad for crash capture (needs a Crashpad install and a crashpad_handler)" OFF)
option(WT_BUILD_TESTS "Build tests" ${PROJECT_IS_TOP_LEVEL})
option(WT_BUILD_EXAMPLES "Build the example" ${PROJECT_IS_TOP_LEVEL})

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS ON) # gnu11: gmtime_r and friends

set(WT_SOURCES src/buf.c src/core.c src/platform_posix.c src/platform_win.c)
if(WT_CRASHPAD)
  enable_language(CXX)
  set(CMAKE_CXX_STANDARD 17)
  list(APPEND WT_SOURCES src/crashpad.cc)
endif()

add_library(watchtower ${WT_SOURCES})
add_library(Watchtower::watchtower ALIAS watchtower)
target_include_directories(watchtower
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>
  PRIVATE src)
set_target_properties(watchtower PROPERTIES POSITION_INDEPENDENT_CODE ON)

set(WT_HAVE_CURL OFF)
if(WIN32)
  target_compile_definitions(watchtower PRIVATE _CRT_SECURE_NO_WARNINGS)
  target_link_libraries(watchtower PRIVATE winhttp bcrypt dbghelp)
else()
  find_package(Threads REQUIRED)
  target_link_libraries(watchtower PRIVATE Threads::Threads)
  find_package(CURL)
  if(CURL_FOUND)
    set(WT_HAVE_CURL ON)
    target_compile_definitions(watchtower PRIVATE WT_HAVE_CURL)
    target_link_libraries(watchtower PRIVATE CURL::libcurl)
  else()
    message(WARNING "libcurl not found: set wt_options.transport or no events will be delivered")
  endif()
endif()
if(WT_CRASHPAD)
  find_package(Crashpad CONFIG REQUIRED) # provides Crashpad::client (e.g. vcpkg, or your own build)
  target_compile_definitions(watchtower PRIVATE WT_CRASHPAD)
  target_link_libraries(watchtower PRIVATE Crashpad::client)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
install(TARGETS watchtower EXPORT watchtowerTargets)
install(FILES include/watchtower.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT watchtowerTargets NAMESPACE Watchtower:: FILE watchtowerTargets.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/watchtower)
configure_package_config_file(cmake/watchtowerConfig.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/watchtowerConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/watchtower)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/watchtowerConfigVersion.cmake
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/watchtowerConfig.cmake ${CMAKE_CURRENT_BINARY_DIR}/watchtowerConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/watchtower)

if(WT_BUILD_TESTS)
  enable_testing()
  add_executable(wt_test tests/test_main.c)
  target_link_libraries(wt_test PRIVATE watchtower)
  add_test(NAME wt_test COMMAND wt_test)
  set_tests_properties(wt_test PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endif()

if(WT_BUILD_EXAMPLES)
  add_executable(wt_example examples/minimal/main.c)
  target_link_libraries(wt_example PRIVATE watchtower)
endif()
