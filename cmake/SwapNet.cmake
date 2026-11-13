# SwapNet is built in, not a child daemon. Disabling the feature at runtime is
# -swapnet=0; release builds must not silently omit the registered RPC handlers.
find_package(Python3 3.11 REQUIRED COMPONENTS Interpreter Development)
execute_process(COMMAND "${Python3_EXECUTABLE}" -I -c
  "import cryptography,sqlite3; from cryptography.hazmat.primitives.ciphers.aead import AESGCM"
  RESULT_VARIABLE SWAPNET_PYTHON_DEPS)
if(NOT SWAPNET_PYTHON_DEPS EQUAL 0)
  message(FATAL_ERROR "SwapNet requires the selected Python's cryptography and sqlite3 modules")
endif()
file(GLOB SWAPNET_PYTHON_SOURCES CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/contrib/swapnet/swapnet/*.py")
set(SWAPNET_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/swapnet-generated")
set(SWAPNET_FROZEN "${SWAPNET_GENERATED_DIR}/swapnet/frozen_sources.h")
add_custom_command(OUTPUT "${SWAPNET_FROZEN}"
  COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/contrib/swapnet/generate_embedded.py"
          "${PROJECT_SOURCE_DIR}/contrib/swapnet/swapnet" "${SWAPNET_FROZEN}"
  DEPENDS ${SWAPNET_PYTHON_SOURCES} "${PROJECT_SOURCE_DIR}/contrib/swapnet/generate_embedded.py"
  VERBATIM)
add_library(btx_swapnet_engine STATIC
  "${PROJECT_SOURCE_DIR}/src/swapnet/embed.cpp"
  "${PROJECT_SOURCE_DIR}/src/swapnet/runtime.cpp"
  "${PROJECT_SOURCE_DIR}/src/swapnet/transport.cpp"
  "${SWAPNET_FROZEN}")
target_include_directories(btx_swapnet_engine PRIVATE "${PROJECT_SOURCE_DIR}/src" "${SWAPNET_GENERATED_DIR}")
target_link_libraries(btx_swapnet_engine PUBLIC Python3::Python)
target_compile_features(btx_swapnet_engine PUBLIC cxx_std_20)
set_target_properties(btx_swapnet_engine PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_sources(bitcoin_node PRIVATE
  "${PROJECT_SOURCE_DIR}/src/swapnet/node.cpp"
  "${PROJECT_SOURCE_DIR}/src/rpc/swapnet.cpp")
target_link_libraries(bitcoin_node PUBLIC btx_swapnet_engine)
# Wallet implementation is compiled into the wallet target below, avoiding a
# reverse dependency from the chain engine to private signing implementations.

if(TARGET bitcoin_wallet)
  target_compile_definitions(bitcoin_node PRIVATE SWAPNET_WITH_WALLET=1)
  target_sources(bitcoin_wallet PRIVATE "${PROJECT_SOURCE_DIR}/src/swapnet/wallet_bridge.cpp")
endif()
