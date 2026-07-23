# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Feature-qualified sm_120a packaging for native block-scaled MXFP4 MMA.
#
# Plain CMAKE_CUDA_ARCHITECTURES / BTX_CUDA_ARCHITECTURES must stay on
# 120 / 120-real / 120-virtual so Guix and portable fatbins keep building.
# CMake 3.22–3.28 often reject or mishandle "120a" in CUDA_ARCHITECTURES;
# architecture-accelerated PTX (mma.sync kind::mxf8f6f4.block_scale) needs
# an isolated object target with explicit nvcc -gencode flags instead.
#
# SM100 / B200 isolation (Agent E+I):
#   * SM120_MMA (this file) and SM100_CUBLASLT are SEPARATE latches.
#   * Never put 100a / 120a into BTX_CUDA_ARCHITECTURES.
#   * Never compile SM120 block_scale MMA into an sm_100 fatbin slice —
#     the MMA body is gated by __CUDA_ARCH_SPECIFIC__==1200 in
#     matmul_v4_rc_mx_ozaki_native.cu (plain sm_100 / sm_120 compile OUT).
#   * BTX_CUDA_SM100_NATIVE is an OPTIONAL fail-closed probe stub: without
#     B200 silicon evidence it MUST remain OFF / probe FALSE. It does NOT
#     replace or weaken BTX_CUDA_SM120_MXFP4_NATIVE packaging.
#
# Exact NVCC flags (verified against CUDA 13.x / NVIDIA docs; do NOT use
# bare -arch=sm_120a alone — ptxas can still target plain sm_120):
#   -gencode=arch=compute_120a,code=sm_120a
#
# Agent A TU name for linkage (when BTX_CUDA_SM120_MXFP4_NATIVE=ON):
#   src/cuda/matmul_v4_rc_mx_ozaki_native_sm120a.cu
# Object target:
#   btx_cuda_sm120a_mxfp4  (OBJECT) → linked into btx_matmul_backend

include_guard(GLOBAL)

set(BTX_CUDA_SM120A_GENCODE_FLAG "-gencode=arch=compute_120a,code=sm_120a"
    CACHE INTERNAL "NVCC gencode for feature-qualified sm_120a MXFP4 MMA")
# Comma-safe compile option for target_compile_options / SOURCE COMPILE_OPTIONS.
# Do NOT use a bare SHELL: string on SOURCE properties — CMake may pass it
# literally to nvcc ("A single input file is required...").
set(BTX_CUDA_SM120A_GENCODE_COMPILE_OPTION
    "$<$<COMPILE_LANGUAGE:CUDA>:-gencode=arch=compute_120a$<COMMA>code=sm_120a>"
    CACHE INTERNAL "Compile-option genex for sm_120a gencode (comma-safe)")

set(BTX_CUDA_SM120A_NATIVE_TU "cuda/matmul_v4_rc_mx_ozaki_native_sm120a.cu"
    CACHE INTERNAL "Dedicated sm_120a native MXFP4 TU (Agent A)")

# Reject feature-qualified arch tokens in the plain packaging list.
function(btx_cuda_reject_feature_qualified_archs arch_list)
  foreach(_arch IN LISTS ${arch_list})
    if(_arch MATCHES "^120a" OR _arch MATCHES "^121a")
      message(FATAL_ERROR
        "BTX_CUDA_ARCHITECTURES must not contain '${_arch}'. "
        "CMake may not accept feature-qualified '*a' arches in "
        "CMAKE_CUDA_ARCHITECTURES. Use plain 120 / 120-real / 120-virtual "
        "(or 121 / 121-real) for packaging, and set "
        "BTX_CUDA_SM120_MXFP4_NATIVE=ON so the dedicated object TU compiles "
        "with ${BTX_CUDA_SM120A_GENCODE_FLAG}.")
    endif()
  endforeach()
endfunction()

# Configure-time probe: compile a tiny TU that requires block_scale mxf8f6f4
# under sm_120a gencode. Sets OUT_VAR to TRUE/FALSE; on failure stores
# BTX_CUDA_SM120A_PROBE_LOG in the parent scope.
function(btx_cuda_probe_sm120a_mxfp4 OUT_VAR)
  if(NOT CMAKE_CUDA_COMPILER)
    set(${OUT_VAR} FALSE PARENT_SCOPE)
    set(BTX_CUDA_SM120A_PROBE_LOG
      "CMAKE_CUDA_COMPILER is not set; cannot probe sm_120a MXFP4."
      PARENT_SCOPE)
    return()
  endif()

  set(_probe_dir "${CMAKE_BINARY_DIR}/CMakeFiles/btx_cuda_sm120a_probe")
  file(MAKE_DIRECTORY "${_probe_dir}")
  set(_probe_src "${_probe_dir}/mxfp4_block_scale_probe.cu")
  set(_probe_obj "${_probe_dir}/mxfp4_block_scale_probe.o")

  # Minimal PTX that plain sm_120 rejects and sm_120a accepts.
  file(WRITE "${_probe_src}" [=[
// BTX configure probe: architecture-accelerated MXFP4 block_scale MMA (sm_120a).
__global__ void btx_sm120a_mxfp4_block_scale_probe()
{
  float d0 = 0.f, d1 = 0.f, d2 = 0.f, d3 = 0.f;
  unsigned a0 = 0, a1 = 0, a2 = 0, a3 = 0, b0 = 0, b1 = 0, sfa = 0, sfb = 0;
  unsigned short z = 0;
  asm volatile(
      "mma.sync.aligned.kind::mxf8f6f4.block_scale.scale_vec::1X."
      "m16n8k32.row.col.f32.e2m1.e2m1.f32.ue8m0 "
      "{%0,%1,%2,%3},{%4,%5,%6,%7},{%8,%9},{%10,%11,%12,%13},"
      "{%14},{%15,%16},{%17},{%18,%19};\n"
      : "=f"(d0), "=f"(d1), "=f"(d2), "=f"(d3)
      : "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(b0), "r"(b1), "f"(d0), "f"(d1),
        "f"(d2), "f"(d3), "r"(sfa), "h"(z), "h"(z), "r"(sfb), "h"(z), "h"(z));
}
]=])

  set(_nvcc_cmd "${CMAKE_CUDA_COMPILER}" "${BTX_CUDA_SM120A_GENCODE_FLAG}"
                -c "${_probe_src}" -o "${_probe_obj}")
  if(CMAKE_CUDA_HOST_COMPILER)
    list(APPEND _nvcc_cmd -ccbin "${CMAKE_CUDA_HOST_COMPILER}")
  endif()

  execute_process(
    COMMAND ${_nvcc_cmd}
    WORKING_DIRECTORY "${_probe_dir}"
    RESULT_VARIABLE _probe_rc
    OUTPUT_VARIABLE _probe_out
    ERROR_VARIABLE _probe_err
  )

  if(_probe_rc EQUAL 0)
    set(${OUT_VAR} TRUE PARENT_SCOPE)
    set(BTX_CUDA_SM120A_PROBE_LOG "" PARENT_SCOPE)
  else()
    set(${OUT_VAR} FALSE PARENT_SCOPE)
    set(BTX_CUDA_SM120A_PROBE_LOG
      "nvcc ${BTX_CUDA_SM120A_GENCODE_FLAG} probe failed (rc=${_probe_rc}).\n${_probe_err}${_probe_out}"
      PARENT_SCOPE)
  endif()
endfunction()

# Create OBJECT library for the dedicated sm_120a TU and link into PARENT_TARGET.
# PARENT_TARGET is typically btx_matmul_backend.
function(btx_cuda_add_sm120a_mxfp4_native_object PARENT_TARGET)
  set(_tu_rel "${BTX_CUDA_SM120A_NATIVE_TU}")
  set(_tu_abs "${CMAKE_CURRENT_SOURCE_DIR}/${_tu_rel}")
  if(NOT EXISTS "${_tu_abs}")
    message(FATAL_ERROR
      "BTX_CUDA_SM120_MXFP4_NATIVE=ON requires Agent A TU '${_tu_rel}' "
      "(absolute: ${_tu_abs}). Name the dedicated sm_120a translation unit "
      "exactly matmul_v4_rc_mx_ozaki_native_sm120a.cu. The MMA body stays in "
      "matmul_v4_rc_mx_ozaki_native.cu under __CUDA_ARCH_SPECIFIC__==1200; "
      "plain BTX_CUDA_ARCHITECTURES=120 compiles that body OUT.")
  endif()

  add_library(btx_cuda_sm120a_mxfp4 OBJECT "${_tu_rel}")
  # Isolate from CMAKE_CUDA_ARCHITECTURES / parent fatbin list.
  # Must be OFF (not ""), or CMake generate fails with "CUDA_ARCHITECTURES is empty".
  set_target_properties(btx_cuda_sm120a_mxfp4 PROPERTIES
    CUDA_ARCHITECTURES OFF
    CUDA_STANDARD 20
    CUDA_STANDARD_REQUIRED ON
    CUDA_RUNTIME_LIBRARY "${BTX_CUDA_RUNTIME_LIBRARY}"
    POSITION_INDEPENDENT_CODE ON
  )
  target_compile_options(btx_cuda_sm120a_mxfp4 PRIVATE
    ${BTX_CUDA_SM120A_GENCODE_COMPILE_OPTION}
  )
  target_compile_definitions(btx_cuda_sm120a_mxfp4 PRIVATE
    BTX_CUDA_SM120_MXFP4_NATIVE=1
  )
  target_link_libraries(btx_cuda_sm120a_mxfp4 PRIVATE core_interface)

  target_sources(${PARENT_TARGET} PRIVATE $<TARGET_OBJECTS:btx_cuda_sm120a_mxfp4>)
  add_dependencies(${PARENT_TARGET} btx_cuda_sm120a_mxfp4)
  target_compile_definitions(${PARENT_TARGET} PUBLIC BTX_CUDA_SM120_MXFP4_NATIVE=1)

  message(STATUS
    "BTX sm_120a native MXFP4: compiling ${_tu_rel} with "
    "${BTX_CUDA_SM120A_GENCODE_FLAG} (isolated from BTX_CUDA_ARCHITECTURES)")
endfunction()

# SM100 / B200 native tcgen05 packaging now lives in cmake/BTXCudaSm100.cmake
# (btx_cuda_probe_sm100_native + btx_cuda_add_sm100a_mxfp4_native_object). It is a
# SEPARATE latch on a SEPARATE ISA (async tcgen05.mma, not the sm_120 warp MMA)
# and does not touch SM120 packaging. The former fail-closed stub here has been
# replaced by a real sm_100a configure probe in that module.
