# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# Turns a CMake-generated link.txt into the OTN_LINK_* values that the Rust
# build scripts (crates/build/otn_link_build.rs) turn into rustc link flags.
#
# Shared by the script-mode entry points that hand a C++ link line to cargo:
#   - cargo_build_rust.cmake  (cargo build, for shipped Rust binaries)
#   - cargo_test_rust.cmake   (cargo test, for tests that link C++ cores)

cmake_minimum_required(VERSION 3.16)

# otn_compute_link_line(<link_file> <bin_dir> <out_search> <out_libs> <out_args>)
#
# <link_file>: path to a CMake-generated link.txt for a target that links the
#              C++ libraries the Rust crate needs.
# <bin_dir>:   the CMake binary directory (build root).
#
# Sets, in the caller's scope:
#   <out_search>: colon-separated library search directories
#   <out_libs>:   semicolon-separated "kind=name" library specs
#   <out_args>:   semicolon-separated extra linker args
function(otn_compute_link_line LINK_FILE BIN_DIR OUT_SEARCH OUT_LIBS OUT_ARGS)
  # Read the CMake-generated link command for the dummy/existing C++ target
  file(READ "${LINK_FILE}" LINK_CONTENT)
  get_filename_component(LINK_DIR "${LINK_FILE}" DIRECTORY)
  # Derive the target binary directory (two levels up from CMakeFiles/<target>.dir)
  get_filename_component(_cmakefiles_dir "${LINK_DIR}" DIRECTORY)
  get_filename_component(TARGET_BIN_DIR "${_cmakefiles_dir}" DIRECTORY)

  # Seed library search paths with known build output dirs and system dirs
  set(SEARCH_DIRS
    "${BIN_DIR}/collector/kernel"
    "${BIN_DIR}/collector"
    "${TARGET_BIN_DIR}"
    "${BIN_DIR}/render"
    "${BIN_DIR}/channel"
    "${BIN_DIR}/config"
    "${BIN_DIR}/platform"
    "${BIN_DIR}/scheduling"
    "${BIN_DIR}/util"
    "${BIN_DIR}/otlp"
    "${BIN_DIR}/geoip"
    "${BIN_DIR}/reducer"
    "${BIN_DIR}/reducer/util"
    "/install/lib"
    "/install/usr/lib64"
    "/usr/lib/x86_64-linux-gnu"
  )

  # Extract -L entries from link line
  string(REGEX MATCHALL "-L([^ \t\n]+)" LFLAGS "${LINK_CONTENT}")
  foreach(LF IN LISTS LFLAGS)
    string(REGEX REPLACE "^-L" "" LF_PATH "${LF}")
    list(APPEND SEARCH_DIRS "${LF_PATH}")
  endforeach()

  # Extract directories of static/shared libraries present on the link line
  # Include both absolute and relative paths; resolve relatives against LINK_DIR.
  string(REGEX MATCHALL "([^ \t\n]*lib[^ \t\n]+\\.(a|so)(\\.[0-9.]+)?)" ALL_LIB_PATHS "${LINK_CONTENT}")
  foreach(LP IN LISTS ALL_LIB_PATHS)
    set(LIB_DIR "${LP}")
    if(NOT IS_ABSOLUTE "${LIB_DIR}")
      get_filename_component(LIB_DIR "${LINK_DIR}/${LIB_DIR}" DIRECTORY)
    else()
      get_filename_component(LIB_DIR "${LIB_DIR}" DIRECTORY)
    endif()
    list(APPEND SEARCH_DIRS "${LIB_DIR}")
  endforeach()

  list(REMOVE_DUPLICATES SEARCH_DIRS)

  # Build library list specs
  set(LIB_SPECS)

  # 1) Static libs by path (.a), absolute or relative
  string(REGEX MATCHALL "([^ \t\n]*lib[^ \t\n]+\\.a)" ANY_A "${LINK_CONTENT}")
  foreach(LIB IN LISTS ANY_A)
    get_filename_component(FNAME "${LIB}" NAME)
    string(REGEX REPLACE "^lib" "" NAME_NO_PREFIX "${FNAME}")
    string(REGEX REPLACE "\\.a$" "" NAME_NO_EXT "${NAME_NO_PREFIX}")
    if(NOT NAME_NO_EXT STREQUAL "encoder_ebpf_net_all")
      list(APPEND LIB_SPECS "static=${NAME_NO_EXT}")
    endif()
  endforeach()

  # 2) Shared libs by absolute path (.so)
  string(REGEX MATCHALL "(/[^ \t\n]*/lib[^ \t\n]+\\.so(\\.[0-9.]+)?)" ABS_SO "${LINK_CONTENT}")
  foreach(LIB IN LISTS ABS_SO)
    get_filename_component(FNAME "${LIB}" NAME)
    string(REGEX REPLACE "^lib" "" NAME_NO_PREFIX "${FNAME}")
    string(REGEX REPLACE "\\.so(\\..*)?$" "" NAME_NO_EXT "${NAME_NO_PREFIX}")
    list(APPEND LIB_SPECS "dylib=${NAME_NO_EXT}")
  endforeach()

  # 3) -l flags (match standalone tokens only, not substrings like -static-libgcc or paths)
  string(REGEX MATCHALL "(^|[ \t\n])-l[A-Za-z0-9_+\-]+" LFLAG_MATCHES "${LINK_CONTENT}")
  foreach(TOK IN LISTS LFLAG_MATCHES)
    string(STRIP "${TOK}" TOK_CLEAN)
    string(REGEX REPLACE "^(-l)" "" LNAME "${TOK_CLEAN}")
    list(APPEND LIB_SPECS "dylib=${LNAME}")
  endforeach()

  # Ensure C++ runtime bits
  list(APPEND LIB_SPECS "dylib=stdc++" "dylib=gcc_s")

  # Deduplicate while preserving first occurrence
  list(REMOVE_DUPLICATES LIB_SPECS)

  # Linker args for static group ordering
  set(LINK_ARGS "-Wl,--start-group;-Wl,--end-group")

  # Compose env var strings
  string(JOIN ":" _search ${SEARCH_DIRS})
  string(JOIN ";" _libs ${LIB_SPECS})

  set(${OUT_SEARCH} "${_search}" PARENT_SCOPE)
  set(${OUT_LIBS} "${_libs}" PARENT_SCOPE)
  set(${OUT_ARGS} "${LINK_ARGS}" PARENT_SCOPE)
endfunction()
