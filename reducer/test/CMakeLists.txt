## Copyright The OpenTelemetry Authors
## SPDX-License-Identifier: Apache-2.0

# Test-only C ABI over the C++ reducer cores, linked into the `cargo test`
# binary so Rust test bodies can drive a real core. Never installed, never part
# of a shipped image: EXCLUDE_FROM_ALL keeps it off the default build, and only
# the cargo-test target depends on it.
add_library(
  core_test_shim
  STATIC
  EXCLUDE_FROM_ALL
  core_shim.cc
)
target_link_libraries(
  core_test_shim
  PUBLIC
    ${REDUCER_LINK_LIBRARIES}
)

# The shim goes first on the link line so the archives it pulls symbols from
# follow it.
add_cargo_test(
  SHIM_TARGET core_test_shim
  LINK_LIBS
    core_test_shim
    ${REDUCER_LINK_LIBRARIES}
)
