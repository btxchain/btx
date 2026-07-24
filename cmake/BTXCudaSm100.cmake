# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Feature-qualified sm_100a packaging for the native tcgen05 block-scaled MXFP4
# MMA path on datacenter Blackwell (B200 / GB200, compute capability 10.0).
#
# This mirrors cmake/BTXCudaSm120a.cmake but targets the DATACENTER ISA. The two
# are SEPARATE latches on SEPARATE tensor-core instruction families:
#   * sm_120a (consumer Blackwell): warp-synchronous mma.sync ... block_scale.
#   * sm_100a (datacenter Blackwell): async, TMEM-resident tcgen05.mma ...
#     block_scale (PTX ISA 8.6+). Consumer sm_120 CANNOT run tcgen05; datacenter
#     sm_100 CANNOT run the warp block-scale mma.sync. Never cross-compile.
#
# Rules (fail-closed):
#   * Plain CMAKE_CUDA_ARCHITECTURES / BTX_CUDA_ARCHITECTURES stay on portable
#     tokens (100 / 100-real / 100-virtual / 120 / …). CMake 3.22–3.28 often
#     reject or mishandle "100a" in CUDA_ARCHITECTURES; the architecture-
#     accelerated tcgen05 PTX needs an isolated object target with explicit
#     nvcc -gencode flags instead. Never put 100a/120a into BTX_CUDA_ARCHITECTURES.
#   * The tcgen05 MMA body is gated by __CUDA_ARCH_SPECIFIC__==1000 in
#     matmul_v4_rc_mx_ozaki_native.cu (plain sm_100 / sm_120 compile it OUT).
#   * BTX_CUDA_SM100_NATIVE is OFF by default. When ON, a REAL configure-time
#     probe must assemble the tcgen05 block-scale snippet under sm_100a or the
#     build FATAL_ERRORs (no silent success). Even with the object linked, the
#     runtime backend stays fail-closed until the bit-exact self-qual suite
#     passes on real B200 silicon (SelectedBackend==SM100_MMA).
#
# Exact NVCC gencode (verified against NVIDIA Blackwell compatibility docs; do NOT
# use bare -arch=sm_100a alone — ptxas can still target plain sm_100):
#   -gencode=arch=compute_100a,code=sm_100a
# Requires CUDA Toolkit >= 12.8 for sm_100a + tcgen05 (13.x recommended, matching
# the sm_120a rack toolchain).
#
# Agent A TU (when BTX_CUDA_SM100_NATIVE=ON):
#   src/cuda/matmul_v4_rc_mx_ozaki_native_sm100.cu   (link marker only)
# Object target:
#   btx_cuda_sm100a_mxfp4  (OBJECT) → linked into btx_matmul_backend
# The tcgen05 MMA body itself lives in matmul_v4_rc_mx_ozaki_native.cu; this module
# also attaches an sm_100a fatbin slice to that TU so the body compiles IN.

include_guard(GLOBAL)

set(BTX_CUDA_SM100A_GENCODE_FLAG "-gencode=arch=compute_100a,code=sm_100a"
    CACHE INTERNAL "NVCC gencode for feature-qualified sm_100a tcgen05 MXFP4 MMA")
# Comma-safe compile-option genex for target/SOURCE COMPILE_OPTIONS.
set(BTX_CUDA_SM100A_GENCODE_COMPILE_OPTION
    "$<$<COMPILE_LANGUAGE:CUDA>:-gencode=arch=compute_100a$<COMMA>code=sm_100a>"
    CACHE INTERNAL "Compile-option genex for sm_100a gencode (comma-safe)")

set(BTX_CUDA_SM100A_NATIVE_TU "cuda/matmul_v4_rc_mx_ozaki_native_sm100.cu"
    CACHE INTERNAL "Dedicated sm_100a native MXFP4 marker TU (Agent A)")

# Configure-time probe: compile a tiny TU that requires the tcgen05 block-scaled
# MMA pipeline under sm_100a gencode. Sets OUT_VAR TRUE/FALSE; on failure stores
# BTX_CUDA_SM100_PROBE_LOG in the parent scope. This REPLACES the old fail-closed
# stub: a real sm_100a toolkit now qualifies the packaging, while any other
# toolkit fails loudly (fail-closed) with the assembler log.
function(btx_cuda_probe_sm100_native OUT_VAR)
  if(NOT CMAKE_CUDA_COMPILER)
    set(${OUT_VAR} FALSE PARENT_SCOPE)
    set(BTX_CUDA_SM100_PROBE_LOG
      "CMAKE_CUDA_COMPILER is not set; cannot probe sm_100a tcgen05 MXFP4."
      PARENT_SCOPE)
    return()
  endif()

  set(_probe_dir "${CMAKE_BINARY_DIR}/CMakeFiles/btx_cuda_sm100a_probe")
  file(MAKE_DIRECTORY "${_probe_dir}")
  set(_probe_src "${_probe_dir}/tcgen05_block_scale_probe.cu")
  set(_probe_obj "${_probe_dir}/tcgen05_block_scale_probe.o")

  # Minimal tcgen05 block-scaled MMA pipeline that plain sm_100 rejects and
  # sm_100a accepts. Mirrors the instructions used by rc_ozaki_mxfp4_tcgen05_gemm
  # so a passing probe attests the kernel's inline PTX assembles on this toolkit.
  file(WRITE "${_probe_src}" [=[
// BTX configure probe: architecture-accelerated tcgen05 block-scaled MXFP4 (sm_100a).
#if defined(__CUDA_ARCH_SPECIFIC__) && (__CUDA_ARCH_SPECIFIC__ == 1000)
__global__ void btx_sm100a_tcgen05_block_scale_probe(unsigned* out)
{
  __shared__ unsigned slot;
  __shared__ unsigned long long mbar;
  unsigned smem_slot = (unsigned)__cvta_generic_to_shared(&slot);
  unsigned smem_mbar = (unsigned)__cvta_generic_to_shared(&mbar);
  asm volatile("tcgen05.alloc.cta_group::1.sync.aligned.shared::cta.b32 [%0], %1;\n"
               :: "r"(smem_slot), "r"(136u));
  asm volatile("tcgen05.relinquish_alloc_permit.cta_group::1.sync.aligned;\n");
  unsigned d_tmem = slot;
  unsigned long long a_desc = 0, b_desc = 0;
  unsigned idesc = 0, sfa = d_tmem + 128u, sfb = d_tmem + 132u, acc = 0;
  asm volatile(
      "{\n .reg .pred p;\n setp.ne.b32 p, %6, 0;\n"
      "tcgen05.mma.cta_group::1.kind::mxf8f6f4.block_scale.scale_vec::1X "
      "[%0], %1, %2, %3, [%4], [%5], p;\n }\n"
      :: "r"(d_tmem), "l"(a_desc), "l"(b_desc), "r"(idesc), "r"(sfa), "r"(sfb), "r"(acc));
  asm volatile("tcgen05.commit.cta_group::1.mbarrier::arrive::one.shared::cluster.b64 [%0];\n"
               :: "r"(smem_mbar));
  unsigned v = 0;
  asm volatile("tcgen05.ld.sync.aligned.32x32b.x1.b32 {%0}, [%1];\n" : "=r"(v) : "r"(d_tmem));
  asm volatile("tcgen05.wait::ld.sync.aligned;\n");
  asm volatile("tcgen05.dealloc.cta_group::1.sync.aligned.b32 %0, %1;\n" :: "r"(d_tmem), "r"(136u));
  out[threadIdx.x] = v;
}
#else
__global__ void btx_sm100a_tcgen05_block_scale_probe(unsigned* out) { out[0] = 0; }
#endif
]=])

  set(_nvcc_cmd "${CMAKE_CUDA_COMPILER}" "${BTX_CUDA_SM100A_GENCODE_FLAG}"
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
    set(BTX_CUDA_SM100_PROBE_LOG "" PARENT_SCOPE)
  else()
    set(${OUT_VAR} FALSE PARENT_SCOPE)
    set(BTX_CUDA_SM100_PROBE_LOG
      "nvcc ${BTX_CUDA_SM100A_GENCODE_FLAG} tcgen05 probe failed (rc=${_probe_rc}).\n${_probe_err}${_probe_out}"
      PARENT_SCOPE)
  endif()
endfunction()

# Create OBJECT library for the dedicated sm_100a marker TU and link into
# PARENT_TARGET (typically btx_matmul_backend). Also attaches the sm_100a gencode
# slice to matmul_v4_rc_mx_ozaki_native.cu so the tcgen05 MMA body compiles IN.
function(btx_cuda_add_sm100a_mxfp4_native_object PARENT_TARGET)
  set(_tu_rel "${BTX_CUDA_SM100A_NATIVE_TU}")
  set(_tu_abs "${CMAKE_CURRENT_SOURCE_DIR}/${_tu_rel}")
  if(NOT EXISTS "${_tu_abs}")
    message(FATAL_ERROR
      "BTX_CUDA_SM100_NATIVE=ON requires Agent A TU '${_tu_rel}' "
      "(absolute: ${_tu_abs}). Name the dedicated sm_100a translation unit "
      "exactly matmul_v4_rc_mx_ozaki_native_sm100.cu. The tcgen05 MMA body stays "
      "in matmul_v4_rc_mx_ozaki_native.cu under __CUDA_ARCH_SPECIFIC__==1000; "
      "plain BTX_CUDA_ARCHITECTURES compiles that body OUT.")
  endif()

  add_library(btx_cuda_sm100a_mxfp4 OBJECT "${_tu_rel}")
  # Isolate from CMAKE_CUDA_ARCHITECTURES / parent fatbin list.
  # Must be OFF (not ""), or CMake generate fails with "CUDA_ARCHITECTURES is empty".
  set_target_properties(btx_cuda_sm100a_mxfp4 PROPERTIES
    CUDA_ARCHITECTURES OFF
    CUDA_STANDARD 20
    CUDA_STANDARD_REQUIRED ON
    CUDA_RUNTIME_LIBRARY "${BTX_CUDA_RUNTIME_LIBRARY}"
    POSITION_INDEPENDENT_CODE ON
  )
  target_compile_options(btx_cuda_sm100a_mxfp4 PRIVATE
    ${BTX_CUDA_SM100A_GENCODE_COMPILE_OPTION}
  )
  target_compile_definitions(btx_cuda_sm100a_mxfp4 PRIVATE
    BTX_CUDA_SM100_NATIVE=1
  )
  target_link_libraries(btx_cuda_sm100a_mxfp4 PRIVATE core_interface)

  target_sources(${PARENT_TARGET} PRIVATE $<TARGET_OBJECTS:btx_cuda_sm100a_mxfp4>)
  add_dependencies(${PARENT_TARGET} btx_cuda_sm100a_mxfp4)
  target_compile_definitions(${PARENT_TARGET} PUBLIC BTX_CUDA_SM100_NATIVE=1)

  message(STATUS
    "BTX sm_100a native MXFP4: compiling ${_tu_rel} with "
    "${BTX_CUDA_SM100A_GENCODE_FLAG} (isolated from BTX_CUDA_ARCHITECTURES)")
endfunction()
