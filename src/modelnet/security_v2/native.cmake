# Model security is a native library shared by ModelNet and its owned guard.
# No new external daemon and no monetary/consensus changes.
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)
set(BTX_SECURITY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/security_v2")
add_library(bitcoin_model_security STATIC
  ${BTX_SECURITY_DIR}/common.cpp ${BTX_SECURITY_DIR}/database.cpp
  ${BTX_SECURITY_DIR}/trust.cpp ${BTX_SECURITY_DIR}/sandbox.cpp
  ${BTX_SECURITY_DIR}/broker.cpp ${BTX_SECURITY_DIR}/artifacts.cpp
  ${BTX_SECURITY_DIR}/evaluation.cpp ${BTX_SECURITY_DIR}/lifecycle.cpp
  ${BTX_SECURITY_DIR}/peer.cpp ${BTX_SECURITY_DIR}/mesh.cpp ${BTX_SECURITY_DIR}/work.cpp
  ${BTX_SECURITY_DIR}/service.cpp)
target_link_libraries(bitcoin_model_security PUBLIC
  core_interface bitcoin_crypto bitcoinpqc univalue SQLite::SQLite3 Threads::Threads)
target_include_directories(bitcoin_model_security PUBLIC ${PROJECT_SOURCE_DIR}/src)
if(WIN32)
  target_link_libraries(bitcoin_model_security PUBLIC bcrypt advapi32)
endif()
add_executable(btx-security ${BTX_SECURITY_DIR}/main.cpp)
target_link_libraries(btx-security PRIVATE bitcoin_model_security)
install_binary_component(btx-security)
