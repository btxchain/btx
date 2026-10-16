# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include_guard(GLOBAL)
include(GNUInstallDirs)

function(install_binary_component component)
  cmake_parse_arguments(PARSE_ARGV 1
    IC                # prefix
    "HAS_MANPAGE"     # options
    ""                # one_value_keywords
    ""                # multi_value_keywords
  )
  set(target_name ${component})
  set(binary_name ${target_name})
  get_target_property(target_output_name ${target_name} OUTPUT_NAME)
  if(target_output_name)
    set(binary_name ${target_output_name})
  endif()
  install(TARGETS ${target_name}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT ${component}
  )
  if(INSTALL_MAN AND IC_HAS_MANPAGE)
    install(FILES ${PROJECT_SOURCE_DIR}/doc/man/${binary_name}.1
      DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
      COMPONENT ${component}
    )
  endif()
endfunction()

# Archive layout is bin/<tool> and lib/<soname>. btx-qt already uses
# $ORIGIN/../lib (patchelf in scripts/release/bundle_qt_gui.py). The same
# relative path has to be a link-time DT_RUNPATH: patching the binary after
# codesign invalidates the signature, and Ubuntu 24.04's libssl.so.3 does
# not provide OPENSSL_3.2.0. The parent sets CMAKE_SKIP_INSTALL_RPATH, so
# SKIP_INSTALL_RPATH must be turned back off or install drops the path.
# BUILD_WITH_INSTALL_RPATH puts it on the build-tree binary the packager copies.
function(btx_set_packaged_lib_runpath target_name)
  if(NOT UNIX OR NOT TARGET ${target_name})
    return()
  endif()
  if(APPLE)
    # Mach-O has no $ORIGIN. @executable_path/../lib is the same bin/ -> lib/ hop.
    set(_btx_runpath "@executable_path/../lib")
  else()
    set(_btx_runpath "\$ORIGIN/../lib")
  endif()
  set_target_properties(${target_name} PROPERTIES
    BUILD_RPATH "${_btx_runpath}"
    INSTALL_RPATH "${_btx_runpath}"
    BUILD_WITH_INSTALL_RPATH TRUE
    SKIP_INSTALL_RPATH FALSE
  )
endfunction()
