cmake_minimum_required(VERSION 3.22)
# Standalone additive build integration. No change to the old BUILD_GUI switch.
project(BTXAtlas NONE)
find_program(CARGO_EXECUTABLE cargo REQUIRED)
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.lock")
  message(FATAL_ERROR "Resolve, audit and commit gui/atlas/Cargo.lock before a locked native build. See BUILD.md.")
endif()
add_custom_target(btx-atlas ALL
  COMMAND "${CARGO_EXECUTABLE}" build --locked --release -p btx-atlas
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  COMMENT "Building native BTX Atlas (node and wallet implementation unchanged)"
  VERBATIM USES_TERMINAL)
