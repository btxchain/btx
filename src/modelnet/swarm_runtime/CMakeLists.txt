# Default-on addition under the existing WITH_MODELNET build boundary.
find_package(Python3 3.11 COMPONENTS Interpreter REQUIRED)
set(_swarm_sources "${CMAKE_CURRENT_SOURCE_DIR}")
add_library(btx_swarm_lifecycle STATIC supervisor.cpp)
target_compile_features(btx_swarm_lifecycle PUBLIC cxx_std_17)
target_link_libraries(btx_swarm_lifecycle PUBLIC Threads::Threads)
target_include_directories(btx_swarm_lifecycle PUBLIC "${PROJECT_SOURCE_DIR}/src")
target_link_libraries(btx-modeld btx_swarm_lifecycle)
foreach(_entry "btx-swarm;cli" "btx-swarmd;daemon" "btx-paynetd;paynet")
  list(GET _entry 0 _binary)
  list(GET _entry 1 _module)
  add_executable(${_binary} launcher.cpp)
  target_link_libraries(${_binary} PRIVATE btx_swarm_lifecycle)
  target_compile_definitions(${_binary} PRIVATE
    BTX_SWARM_MODULE="btxmesh.${_module}"
    BTX_SWARM_PYTHON="${Python3_EXECUTABLE}"
    BTX_SWARM_SOURCE_ROOT="${PROJECT_SOURCE_DIR}/contrib/swarm")
  install(TARGETS ${_binary} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endforeach()
install(DIRECTORY "${PROJECT_SOURCE_DIR}/contrib/swarm/btxmesh"
  DESTINATION "libexec/btx-swarm"
  PATTERN "__pycache__" EXCLUDE PATTERN "*.pyc" EXCLUDE)
install(FILES "${PROJECT_SOURCE_DIR}/contrib/swarm/pyproject.toml"
  DESTINATION "libexec/btx-swarm")
# Dependencies are installed by the offline packaging script, never at daemon start.
