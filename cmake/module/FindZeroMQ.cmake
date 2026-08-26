# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/licenses/mit-license.php.
#
# FindZeroMQ
# ----------
#
# Finds the ZeroMQ headers and library.
#
# On macOS, prefer static libzmq.a (and static libsodium.a when needed) so a
# release tarball does not depend on Homebrew's libzmq dylib. Linking the
# dylib makes -zmqpub* silent on any Mac without that Homebrew keg — the
# failure shape 0.33.4.2 already hit by compiling ZMQ out entirely.

include(FindPackageHandleStandardArgs)

set(ZMQ_LINKAGE "" CACHE INTERNAL "How ZeroMQ was resolved (shared vs static path)")

function(btx_import_macos_static_zmq include_dirs zmq_static sodium_static)
  add_library(zeromq STATIC IMPORTED GLOBAL)
  set_target_properties(zeromq PROPERTIES
    IMPORTED_LOCATION "${zmq_static}"
    INTERFACE_INCLUDE_DIRECTORIES "${include_dirs}"
  )
  set(_private_libs "")
  if(sodium_static)
    list(APPEND _private_libs "${sodium_static}")
  endif()
  list(APPEND _private_libs pthread)
  set_target_properties(zeromq PROPERTIES INTERFACE_LINK_LIBRARIES "${_private_libs}")
  set(ZMQ_LINKAGE "static:${zmq_static}" CACHE INTERNAL "How ZeroMQ was resolved (shared vs static path)")
  message(STATUS "ZeroMQ: macOS static ${zmq_static}")
endfunction()

function(btx_find_macos_static_archive out_var basename search_dirs)
  set(_found "")
  foreach(_dir IN LISTS search_dirs)
    if(_dir AND EXISTS "${_dir}/${basename}")
      set(_found "${_dir}/${basename}")
      break()
    endif()
  endforeach()
  set(${out_var} "${_found}" PARENT_SCOPE)
endfunction()

if(NOT APPLE)
  find_package(ZeroMQ ${ZeroMQ_FIND_VERSION} NO_MODULE QUIET)
  if(ZeroMQ_FOUND)
    find_package_handle_standard_args(ZeroMQ
      REQUIRED_VARS ZeroMQ_DIR
      VERSION_VAR ZeroMQ_VERSION
    )
    if(TARGET libzmq)
      add_library(zeromq ALIAS libzmq)
      set(ZMQ_LINKAGE "shared:cmake-package" CACHE INTERNAL "How ZeroMQ was resolved (shared vs static path)")
    elseif(TARGET libzmq-static)
      add_library(zeromq ALIAS libzmq-static)
      set(ZMQ_LINKAGE "static:cmake-package" CACHE INTERNAL "How ZeroMQ was resolved (shared vs static path)")
    endif()
    mark_as_advanced(ZeroMQ_DIR)
  endif()
endif()

if(NOT TARGET zeromq)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(libzmq QUIET
    IMPORTED_TARGET
    libzmq>=${ZeroMQ_FIND_VERSION}
  )
  find_package_handle_standard_args(ZeroMQ
    REQUIRED_VARS libzmq_VERSION
    VERSION_VAR libzmq_VERSION
  )

  if(APPLE)
    set(_zmq_search_dirs
      ${libzmq_STATIC_LIBRARY_DIRS}
      ${libzmq_LIBRARY_DIRS}
      /opt/homebrew/lib
      /usr/local/lib
    )
    btx_find_macos_static_archive(_zmq_static libzmq.a "${_zmq_search_dirs}")
    if(NOT _zmq_static)
      message(FATAL_ERROR
        "WITH_ZMQ=ON on macOS requires static libzmq.a (Homebrew: brew install zeromq). "
        "Linking Homebrew's libzmq.dylib makes the shipped btxd fail on Macs without that keg.")
    endif()
    get_filename_component(_zmq_libdir "${_zmq_static}" DIRECTORY)
    set(_sodium_search_dirs "${_zmq_libdir}" ${_zmq_search_dirs})
    btx_find_macos_static_archive(_sodium_static libsodium.a "${_sodium_search_dirs}")
    if(NOT _sodium_static)
      message(FATAL_ERROR
        "Static libzmq.a needs static libsodium.a on macOS (Homebrew: brew install libsodium). "
        "A dylib sodium would re-introduce an /opt/homebrew load command.")
    endif()
    if(NOT libzmq_INCLUDE_DIRS AND EXISTS "/opt/homebrew/include/zmq.h")
      set(libzmq_INCLUDE_DIRS "/opt/homebrew/include")
    elseif(NOT libzmq_INCLUDE_DIRS AND EXISTS "/usr/local/include/zmq.h")
      set(libzmq_INCLUDE_DIRS "/usr/local/include")
    endif()
    btx_import_macos_static_zmq("${libzmq_INCLUDE_DIRS}" "${_zmq_static}" "${_sodium_static}")
  else()
    if(NOT TARGET PkgConfig::libzmq)
      message(FATAL_ERROR "WITH_ZMQ=ON but pkg-config did not import libzmq (install libzmq3-dev or equivalent).")
    endif()
    add_library(zeromq ALIAS PkgConfig::libzmq)
    set(ZMQ_LINKAGE "shared:pkg-config" CACHE INTERNAL "How ZeroMQ was resolved (shared vs static path)")
  endif()
endif()
