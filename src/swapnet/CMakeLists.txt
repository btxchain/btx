# Included by the standalone test build, or source-listed in bitcoin_node.
add_library(btx_swapnet_transport STATIC transport.cpp)
target_compile_features(btx_swapnet_transport PUBLIC cxx_std_17)
target_include_directories(btx_swapnet_transport PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
