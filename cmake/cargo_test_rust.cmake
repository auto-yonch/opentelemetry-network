cmake_minimum_required(VERSION 3.16)

# Runs the Rust workspace test suite with the C++ link line exported, so tests
# that link a reducer core through the test-only shim can resolve its symbols.
# Driven by the `cargo-test` target (cmake/cargo-test.cmake).

if(NOT DEFINED LINK_FILE)
  message(FATAL_ERROR "LINK_FILE not provided to cargo_test_rust.cmake")
endif()
if(NOT DEFINED BIN_DIR)
  message(FATAL_ERROR "BIN_DIR not provided to cargo_test_rust.cmake")
endif()
if(NOT DEFINED PROJ_DIR)
  message(FATAL_ERROR "PROJ_DIR not provided to cargo_test_rust.cmake")
endif()
if(NOT DEFINED RUST_TEST_TARGET_DIR)
  message(FATAL_ERROR "RUST_TEST_TARGET_DIR not provided to cargo_test_rust.cmake")
endif()
if(NOT DEFINED SHIM_LIB)
  message(FATAL_ERROR "SHIM_LIB not provided to cargo_test_rust.cmake")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/otn_link_line.cmake")

otn_compute_link_line("${LINK_FILE}" "${BIN_DIR}" OTN_LINK_SEARCH OTN_LINK_LIBS OTN_LINK_ARGS)

message(STATUS "OTN_LINK_SEARCH=${OTN_LINK_SEARCH}")
message(STATUS "OTN_LINK_LIBS=${OTN_LINK_LIBS}")

# Escape semicolons for passing via CMake -E env
string(REPLACE ";" "\\;" OTN_LINK_LIBS_ESC "${OTN_LINK_LIBS}")
string(REPLACE ";" "\\;" OTN_LINK_ARGS_ESC "${OTN_LINK_ARGS}")

# OTN_SHIM_LIB tells the harness crate's build script that the shim is on the
# link line; without it the harness compiles without its FFI bindings, so a
# plain `cargo test` outside this target still works.
execute_process(
  COMMAND ${CMAKE_COMMAND} -E env
    CARGO_TARGET_DIR=${RUST_TEST_TARGET_DIR}
    OTN_LINK_SEARCH=${OTN_LINK_SEARCH}
    OTN_LINK_LIBS=${OTN_LINK_LIBS_ESC}
    OTN_LINK_ARGS=${OTN_LINK_ARGS_ESC}
    OTN_SHIM_LIB=${SHIM_LIB}
    cargo test --manifest-path ${PROJ_DIR}/Cargo.toml
  WORKING_DIRECTORY ${PROJ_DIR}
  RESULT_VARIABLE CARGO_RES
)

if(NOT CARGO_RES EQUAL 0)
  message(FATAL_ERROR "cargo test failed with exit code ${CARGO_RES}")
endif()
