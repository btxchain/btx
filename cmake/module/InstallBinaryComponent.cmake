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
# INSTALL_RPATH is never written; hand the path to the linker instead. The
# packager copies the build-tree binary. BUILD_WITH_INSTALL_RPATH keeps CMake
# from adding its own build-tree paths (a non-system OpenSSL prefix, say) to
# that binary. Guix configures with CMAKE_SKIP_BUILD_RPATH and check-symbols
# refuses any RUNPATH, so those binaries stay without one.
function(btx_set_packaged_lib_runpath target_name)
  if(NOT UNIX OR NOT TARGET ${target_name} OR CMAKE_SKIP_BUILD_RPATH)
    return()
  endif()
  if(APPLE)
    # Mach-O has no $ORIGIN. @executable_path/../lib is the same bin/ -> lib/ hop.
    target_link_options(${target_name} PRIVATE "LINKER:-rpath,@executable_path/../lib")
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux"
      AND (CMAKE_GENERATOR STREQUAL "Unix Makefiles" OR CMAKE_GENERATOR STREQUAL "Ninja")
      AND CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang)$")
    # CMake 3.22 over-escapes $ORIGIN in LINK_OPTIONS for both generators.
    # Pass one quoted dollar to the link script or Ninja's command shell.
    # Keep this GNU-compatible driver flag raw and shell-quote the loader
    # token. APPEND_STRING preserves flags already owned by the target.
    set_property(TARGET ${target_name} APPEND_STRING PROPERTY LINK_FLAGS
      " -Wl,--enable-new-dtags,-rpath,'$ORIGIN/../lib'")
  else()
    # Preserve the compiler-wrapper path for other generators and drivers.
    string(ASCII 36 btx_dollar)
    target_link_options(${target_name} PRIVATE "LINKER:--enable-new-dtags,-rpath,${btx_dollar}ORIGIN/../lib")
  endif()
  set_target_properties(${target_name} PROPERTIES BUILD_WITH_INSTALL_RPATH TRUE)
endfunction()
