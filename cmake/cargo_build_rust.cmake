cmake_minimum_required(VERSION 3.16)

if(NOT DEFINED LINK_FILE)
  message(FATAL_ERROR "LINK_FILE not provided to cargo_build_rust.cmake")
endif()
if(NOT DEFINED BIN_DIR)
  message(FATAL_ERROR "BIN_DIR not provided to cargo_build_rust.cmake")
endif()
if(NOT DEFINED PROJ_DIR)
  message(FATAL_ERROR "PROJ_DIR not provided to cargo_build_rust.cmake")
endif()
if(NOT DEFINED RUST_BIN_TARGET_DIR)
  message(FATAL_ERROR "RUST_BIN_TARGET_DIR not provided to cargo_build_rust.cmake")
endif()
if(NOT DEFINED RUST_PACKAGE)
  message(FATAL_ERROR "RUST_PACKAGE not provided to cargo_build_rust.cmake")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/otn_link_line.cmake")

otn_compute_link_line("${LINK_FILE}" "${BIN_DIR}" OTN_LINK_SEARCH OTN_LINK_LIBS OTN_LINK_ARGS)

message(STATUS "OTN_LINK_SEARCH=${OTN_LINK_SEARCH}")
message(STATUS "OTN_LINK_LIBS=${OTN_LINK_LIBS}")

# Escape semicolons for passing via CMake -E env
string(REPLACE ";" "\\;" OTN_LINK_LIBS_ESC "${OTN_LINK_LIBS}")
string(REPLACE ";" "\\;" OTN_LINK_ARGS_ESC "${OTN_LINK_ARGS}")

execute_process(
  COMMAND ${CMAKE_COMMAND} -E env
    CARGO_TARGET_DIR=${RUST_BIN_TARGET_DIR}
    OTN_LINK_SEARCH=${OTN_LINK_SEARCH}
    OTN_LINK_LIBS=${OTN_LINK_LIBS_ESC}
    OTN_LINK_ARGS=${OTN_LINK_ARGS_ESC}
    cargo build --release --package ${RUST_PACKAGE} --manifest-path ${PROJ_DIR}/Cargo.toml
  WORKING_DIRECTORY ${PROJ_DIR}
  RESULT_VARIABLE CARGO_RES
  OUTPUT_VARIABLE CARGO_OUT
  ERROR_VARIABLE CARGO_ERR
)

if(NOT CARGO_RES EQUAL 0)
  message(STATUS "Cargo stdout:\n${CARGO_OUT}")
  message(STATUS "Cargo stderr:\n${CARGO_ERR}")
  message(FATAL_ERROR "Cargo build failed with exit code ${CARGO_RES}")
endif()
