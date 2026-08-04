# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

macro(fatal_error)
  message(FATAL_ERROR "\n"
    "Usage:\n"
    "  cmake -D BUILD_INFO_HEADER_PATH=<path> [-D SOURCE_DIR=<path>] -P ${CMAKE_CURRENT_LIST_FILE}\n"
    "All specified paths must be absolute ones.\n"
  )
endmacro()

if(DEFINED BUILD_INFO_HEADER_PATH AND IS_ABSOLUTE "${BUILD_INFO_HEADER_PATH}")
  if(EXISTS "${BUILD_INFO_HEADER_PATH}")
    file(READ "${BUILD_INFO_HEADER_PATH}" INFO)
  endif()
else()
  unset(INFO)
  set(BUILD_INFO_HEADER_PATH "/dev/stdout")
endif()

if(DEFINED SOURCE_DIR)
  if(IS_ABSOLUTE "${SOURCE_DIR}" AND IS_DIRECTORY "${SOURCE_DIR}")
    set(WORKING_DIR ${SOURCE_DIR})
  else()
    fatal_error()
  endif()
else()
  set(WORKING_DIR ${CMAKE_CURRENT_SOURCE_DIR})
endif()

set(GIT_TAG)
set(GIT_COMMIT)
set(GIT_FULL_COMMIT)
set(GIT_DIRTY)
set(GIT_SOURCE_TREE_FINGERPRINT)
if(NOT "$ENV{BITCOIN_GENBUILD_NO_GIT}" STREQUAL "1")
  find_package(Git QUIET)
  if(Git_FOUND)
    execute_process(
      COMMAND ${GIT_EXECUTABLE} rev-parse --is-inside-work-tree
      WORKING_DIRECTORY ${WORKING_DIR}
      OUTPUT_VARIABLE IS_INSIDE_WORK_TREE
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET
    )
    if(IS_INSIDE_WORK_TREE)
      # This check ensures that we are actually part of the intended git repository, and not just getting info about some unrelated git repository that the code happens to be in a directory under
      execute_process(
        COMMAND ${GIT_EXECUTABLE} status --porcelain -uall --ignored cmake/script/GenerateBuildInfo.cmake
        WORKING_DIRECTORY ${WORKING_DIR}
        RESULT_VARIABLE SCRIPT_STATUS_EXITCODE
        OUTPUT_VARIABLE SCRIPT_STATUS
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
      )
      if(SCRIPT_STATUS_EXITCODE)
        set(IS_INSIDE_WORK_TREE 0)
      elseif(SCRIPT_STATUS MATCHES "\\?")
        set(IS_INSIDE_WORK_TREE 0)
      endif()
    endif()
    if(IS_INSIDE_WORK_TREE)
      # Clean 'dirty' status of touched files that haven't been modified.
      execute_process(
        COMMAND ${GIT_EXECUTABLE} diff
        WORKING_DIRECTORY ${WORKING_DIR}
        OUTPUT_QUIET
        ERROR_QUIET
      )

      execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --abbrev=0
        WORKING_DIRECTORY ${WORKING_DIR}
        OUTPUT_VARIABLE MOST_RECENT_TAG
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
      )

      execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-list -1 ${MOST_RECENT_TAG}
        WORKING_DIRECTORY ${WORKING_DIR}
        OUTPUT_VARIABLE MOST_RECENT_TAG_COMMIT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
      )

      execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
        WORKING_DIRECTORY ${WORKING_DIR}
        OUTPUT_VARIABLE HEAD_COMMIT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
      )

      string(LENGTH "${HEAD_COMMIT}" HEAD_COMMIT_LENGTH)
      if(HEAD_COMMIT_LENGTH EQUAL 40 AND HEAD_COMMIT MATCHES "^[0-9a-fA-F]+$")
        set(GIT_FULL_COMMIT ${HEAD_COMMIT})
      endif()

      execute_process(
        COMMAND ${GIT_EXECUTABLE} diff-index --quiet HEAD --
        WORKING_DIRECTORY ${WORKING_DIR}
        RESULT_VARIABLE IS_DIRTY
      )
      # Evidence binaries are bound to the build-relevant tree. Include
      # untracked inputs, which diff-index intentionally ignores, while not
      # treating generated evidence/documents as changes to compiled code.
      execute_process(
        COMMAND ${GIT_EXECUTABLE} status --porcelain -uall -- CMakeLists.txt cmake src contrib/matmul-v4
        WORKING_DIRECTORY ${WORKING_DIR}
        RESULT_VARIABLE BUILD_RELEVANT_STATUS_EXITCODE
        OUTPUT_VARIABLE BUILD_RELEVANT_STATUS
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
      )
      if(BUILD_RELEVANT_STATUS_EXITCODE OR NOT "${BUILD_RELEVANT_STATUS}" STREQUAL "")
        set(GIT_DIRTY 1)
      else()
        set(GIT_DIRTY 0)
      endif()

      # Bind production binaries to the same implementation fingerprint used
      # by the CUDA+Metal golden corpus. Include the authoritative evidence and
      # calibration tools in contrib/matmul-v4: those programs can otherwise be
      # modified without changing the identity they emit. Only the inert
      # manifest data file is excluded to avoid a self-reference. Its bytes are
      # converted to a C++ byte array by fingerprinted CMake logic and parsed by
      # fingerprinted C++; no executable translation unit or evidence policy is
      # outside this identity.
      execute_process(
        COMMAND ${GIT_EXECUTABLE} ls-tree -r --full-tree HEAD -- CMakeLists.txt cmake src contrib/matmul-v4
        WORKING_DIRECTORY ${WORKING_DIR}
        RESULT_VARIABLE BUILD_RELEVANT_TREE_EXITCODE
        OUTPUT_VARIABLE BUILD_RELEVANT_TREE
        ERROR_QUIET
      )
      if(NOT BUILD_RELEVANT_TREE_EXITCODE AND NOT "${BUILD_RELEVANT_TREE}" STREQUAL "")
        string(REPLACE "\n" ";" BUILD_RELEVANT_TREE_LINES "${BUILD_RELEVANT_TREE}")
        set(BUILD_RELEVANT_TREE_FILTERED "")
        foreach(TREE_LINE IN LISTS BUILD_RELEVANT_TREE_LINES)
          if(NOT "${TREE_LINE}" MATCHES "src/matmul/matmul_v4_rc_production_golden_manifest\\.data$")
            if(NOT "${TREE_LINE}" STREQUAL "")
              string(APPEND BUILD_RELEVANT_TREE_FILTERED "${TREE_LINE}\n")
            endif()
          endif()
        endforeach()
        string(SHA256 GIT_SOURCE_TREE_FINGERPRINT "${BUILD_RELEVANT_TREE_FILTERED}")
      endif()

      if(HEAD_COMMIT STREQUAL MOST_RECENT_TAG_COMMIT AND NOT IS_DIRTY)
        # If latest commit is tagged and not dirty, then use the tag name.
        set(GIT_TAG ${MOST_RECENT_TAG})
      else()
        # Otherwise, generate suffix from git, i.e. string like "0e0a5173fae3-dirty".
        execute_process(
          COMMAND ${GIT_EXECUTABLE} rev-parse --short=12 HEAD
          WORKING_DIRECTORY ${WORKING_DIR}
          OUTPUT_VARIABLE GIT_COMMIT
          OUTPUT_STRIP_TRAILING_WHITESPACE
          ERROR_QUIET
        )
        if(IS_DIRTY)
          string(APPEND GIT_COMMIT "-dirty")
        endif()
      endif()
    endif()
  endif()
endif()

if(GIT_TAG)
  set(NEWINFO "#define BUILD_GIT_TAG \"${GIT_TAG}\"")
elseif(GIT_COMMIT)
  set(NEWINFO "#define BUILD_GIT_COMMIT \"${GIT_COMMIT}\"")
else()
  # NOTE: The NEWINFO line below this comment gets replaced by a string-match in contrib/guix/libexec/make_release_tarball.sh
  # If changing it, update the script too!
  set(NEWINFO [[// No build information available]])
endif()

# Keep an immutable, machine-readable source identity alongside the concise
# user-agent build suffix above. Production evidence must not be able to label
# an older harness binary with a newer operator-supplied revision. Release
# tarballs preserve these lines when make_release_tarball.sh embeds NEWINFO.
if(GIT_FULL_COMMIT)
  string(APPEND NEWINFO "\n#define BUILD_GIT_FULL_COMMIT \"${GIT_FULL_COMMIT}\"")
  string(APPEND NEWINFO "\n#define BUILD_GIT_DIRTY ${GIT_DIRTY}")
  if(GIT_SOURCE_TREE_FINGERPRINT)
    string(APPEND NEWINFO "\n#define BUILD_GIT_SOURCE_TREE_FINGERPRINT \"${GIT_SOURCE_TREE_FINGERPRINT}\"")
  endif()
endif()

# Only update the header if necessary.
set(NEWINFO_WITH_NEWLINE "${NEWINFO}\n")
if(NOT "${INFO}" STREQUAL "${NEWINFO_WITH_NEWLINE}")
  file(WRITE ${BUILD_INFO_HEADER_PATH} "${NEWINFO_WITH_NEWLINE}")
endif()
