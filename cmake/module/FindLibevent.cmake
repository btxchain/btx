# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

#[=======================================================================[
FindLibevent
------------

Finds the Libevent headers and libraries.

This is a wrapper around find_package()/pkg_check_modules() commands that:
 - facilitates searching in various build environments
 - prints a standard log message

On macOS, a release btxd/btx-cli must not carry Homebrew dylib load commands
(/opt/homebrew/opt/libevent/...). Prefer the static archives Homebrew already
ships (libevent_core.a / extra / pthreads). Linking the dylibs makes a
downloadable tarball fail to launch on a Mac without those kegs.
#]=======================================================================]

# Check whether evhttp_connection_get_peer expects const char**.
# See https://github.com/libevent/libevent/commit/a18301a2bb160ff7c3ffaf5b7653c39ffe27b385
function(check_evhttp_connection_get_peer target)
  include(CMakePushCheckState)
  cmake_push_check_state(RESET)
  set(CMAKE_REQUIRED_LIBRARIES ${target})
  include(CheckCXXSourceCompiles)
  check_cxx_source_compiles("
    #include <cstdint>
    #include <event2/http.h>

    int main()
    {
        evhttp_connection* conn = (evhttp_connection*)1;
        const char* host;
        uint16_t port;
        evhttp_connection_get_peer(conn, &host, &port);
    }
    " HAVE_EVHTTP_CONNECTION_GET_PEER_CONST_CHAR
  )
  cmake_pop_check_state()
  target_compile_definitions(${target} INTERFACE
    $<$<BOOL:${HAVE_EVHTTP_CONNECTION_GET_PEER_CONST_CHAR}>:HAVE_EVHTTP_CONNECTION_GET_PEER_CONST_CHAR>
  )
endfunction()

function(btx_macos_find_static_archive out_var basename search_dirs)
  set(_found "")
  foreach(_dir IN LISTS search_dirs)
    if(_dir AND EXISTS "${_dir}/${basename}")
      set(_found "${_dir}/${basename}")
      break()
    endif()
  endforeach()
  set(${out_var} "${_found}" PARENT_SCOPE)
endfunction()

function(btx_import_macos_static_libevent component archive include_dirs)
  add_library(libevent::${component} STATIC IMPORTED GLOBAL)
  set_target_properties(libevent::${component} PROPERTIES
    IMPORTED_LOCATION "${archive}"
    INTERFACE_INCLUDE_DIRECTORIES "${include_dirs}"
  )
endfunction()

set(_libevent_components core extra)
if(NOT WIN32)
  list(APPEND _libevent_components pthreads)
endif()

set(LIBEVENT_LINKAGE "" CACHE INTERNAL "How Libevent was resolved (shared vs static path)")

if(APPLE)
  set(_event_search_dirs
    /opt/homebrew/opt/libevent/lib
    /opt/homebrew/lib
    /usr/local/opt/libevent/lib
    /usr/local/lib
  )
  set(_event_include_search
    /opt/homebrew/opt/libevent/include
    /opt/homebrew/include
    /usr/local/opt/libevent/include
    /usr/local/include
  )
  btx_macos_find_static_archive(_event_core_a libevent_core.a "${_event_search_dirs}")
  btx_macos_find_static_archive(_event_extra_a libevent_extra.a "${_event_search_dirs}")
  btx_macos_find_static_archive(_event_pthreads_a libevent_pthreads.a "${_event_search_dirs}")
  set(_event_inc "")
  foreach(_inc IN LISTS _event_include_search)
    if(EXISTS "${_inc}/event2/event.h")
      set(_event_inc "${_inc}")
      break()
    endif()
  endforeach()
  if(NOT _event_core_a OR NOT _event_extra_a OR NOT _event_pthreads_a OR NOT _event_inc)
    message(FATAL_ERROR
      "macOS release builds require static libevent archives "
      "(libevent_core.a, libevent_extra.a, libevent_pthreads.a) plus event2/event.h. "
      "Homebrew: brew install libevent. Linking the dylibs puts /opt/homebrew load "
      "commands in btxd/btx-cli and the tarball will not launch on a clean Mac.")
  endif()
  btx_import_macos_static_libevent(core "${_event_core_a}" "${_event_inc}")
  btx_import_macos_static_libevent(extra "${_event_extra_a}" "${_event_inc}")
  btx_import_macos_static_libevent(pthreads "${_event_pthreads_a}" "${_event_inc}")
  set_target_properties(libevent::extra PROPERTIES
    INTERFACE_LINK_LIBRARIES "libevent::core"
  )
  set_target_properties(libevent::pthreads PROPERTIES
    INTERFACE_LINK_LIBRARIES "libevent::core"
  )
  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Libevent
    REQUIRED_VARS _event_core_a _event_extra_a _event_pthreads_a _event_inc
  )
  check_evhttp_connection_get_peer(libevent::extra)
  set(LIBEVENT_LINKAGE "static:${_event_core_a}" CACHE INTERNAL "How Libevent was resolved (shared vs static path)")
  message(STATUS "Libevent: macOS static ${_event_core_a}")
  unset(_event_search_dirs)
  unset(_event_include_search)
  unset(_event_core_a)
  unset(_event_extra_a)
  unset(_event_pthreads_a)
  unset(_event_inc)
else()
  find_package(Libevent ${Libevent_FIND_VERSION} QUIET
    NO_MODULE
  )

  include(FindPackageHandleStandardArgs)
  if(Libevent_FOUND)
    find_package(Libevent ${Libevent_FIND_VERSION} QUIET
      REQUIRED COMPONENTS ${_libevent_components}
      NO_MODULE
    )
    find_package_handle_standard_args(Libevent
      REQUIRED_VARS Libevent_DIR
      VERSION_VAR Libevent_VERSION
    )
    check_evhttp_connection_get_peer(libevent::extra)
    set(LIBEVENT_LINKAGE "shared:cmake-package" CACHE INTERNAL "How Libevent was resolved (shared vs static path)")
  else()
    find_package(PkgConfig REQUIRED)
    foreach(component IN LISTS _libevent_components)
      pkg_check_modules(libevent_${component}
        REQUIRED QUIET
        IMPORTED_TARGET GLOBAL
        libevent_${component}>=${Libevent_FIND_VERSION}
      )
      if(TARGET PkgConfig::libevent_${component} AND NOT TARGET libevent::${component})
        add_library(libevent::${component} ALIAS PkgConfig::libevent_${component})
      endif()
    endforeach()
    find_package_handle_standard_args(Libevent
      REQUIRED_VARS libevent_core_LIBRARY_DIRS
      VERSION_VAR libevent_core_VERSION
    )
    check_evhttp_connection_get_peer(PkgConfig::libevent_extra)
    set(LIBEVENT_LINKAGE "shared:pkg-config" CACHE INTERNAL "How Libevent was resolved (shared vs static path)")
  endif()
endif()

unset(_libevent_components)

mark_as_advanced(Libevent_DIR)
mark_as_advanced(_event_h)
mark_as_advanced(_event_lib)
