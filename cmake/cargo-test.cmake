## Copyright The OpenTelemetry Authors
## SPDX-License-Identifier: Apache-2.0

include_guard()

# add_cargo_test(SHIM_TARGET <target> LINK_LIBS <libs...> [PROJ_DIR <dir>]
#                [RUST_TEST_TARGET_DIR <dir>])
#
# Defines the `cargo-test` target: runs the whole Rust workspace test suite with
# the C++ link line of <LINK_LIBS> exported, so test binaries that need a C++
# core (through the test-only shim) can link it.
#
# This is the same mechanism add_rust_main() uses for shipped Rust binaries --
# a dummy executable makes CMake emit a link.txt, and a script turns that link
# line into the OTN_LINK_* env vars the crates' build scripts read -- pointed at
# `cargo test` instead of `cargo build`.
#
# Must be called from a directory that can see the C++ libraries the tests need;
# reducer/test does this. Tests that do not need C++ are unaffected: they simply
# ignore the extra link flags.
function(add_cargo_test)
  cmake_parse_arguments(ARG "" "SHIM_TARGET;PROJ_DIR;RUST_TEST_TARGET_DIR" "LINK_LIBS" ${ARGN})

  if(NOT DEFINED ARG_SHIM_TARGET)
    message(FATAL_ERROR "add_cargo_test: SHIM_TARGET is required (the test-only shim library)")
  endif()
  if(NOT ARG_LINK_LIBS)
    message(FATAL_ERROR "add_cargo_test: LINK_LIBS is required (C++ link libraries)")
  endif()
  if(TARGET cargo-test)
    message(FATAL_ERROR "add_cargo_test: the cargo-test target is already defined")
  endif()

  if(NOT DEFINED ARG_PROJ_DIR)
    set(ARG_PROJ_DIR "${PROJECT_SOURCE_DIR}")
  endif()
  if(NOT DEFINED ARG_RUST_TEST_TARGET_DIR)
    set(ARG_RUST_TEST_TARGET_DIR "${CMAKE_BINARY_DIR}/target")
  endif()

  # A tiny dummy executable, never built, purely so CMake emits a link.txt with
  # the resolved link line for these libraries.
  set(_dummy_target cargo-test-link-dummy)
  set(_dummy_main "${CMAKE_CURRENT_BINARY_DIR}/${_dummy_target}_main.cc")
  file(WRITE "${_dummy_main}" "int main(int, char**) { return 0; }\n")

  add_executable(${_dummy_target} EXCLUDE_FROM_ALL "${_dummy_main}")
  target_link_libraries(
    ${_dummy_target}
    PUBLIC
      ${ARG_LINK_LIBS}
      static-executable
  )

  set(_link_file "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/${_dummy_target}.dir/link.txt")

  add_custom_target(
    cargo-test
    COMMAND ${CMAKE_COMMAND}
      -DLINK_FILE=${_link_file}
      -DBIN_DIR=${CMAKE_BINARY_DIR}
      -DPROJ_DIR=${ARG_PROJ_DIR}
      -DRUST_TEST_TARGET_DIR=${ARG_RUST_TEST_TARGET_DIR}
      -DSHIM_LIB=${ARG_SHIM_TARGET}
      -P ${CMAKE_SOURCE_DIR}/cmake/cargo_test_rust.cmake
    WORKING_DIRECTORY ${ARG_PROJ_DIR}
    VERBATIM
  )

  # The libraries on the link line have to exist before cargo links them.
  add_dependencies(cargo-test ${ARG_LINK_LIBS})
endfunction()
