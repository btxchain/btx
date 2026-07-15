// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Apple Metal host glue for the MatMul v4 miner backend.
//
// Pipeline (mirrors matmul_v4::ComputeDigest in matmul/pow_v4.cpp exactly):
//   1. HOST  : derive sigma / operand / projector seeds and expand A, B, U, V
//              with the consensus CPU code (matmul::v4::ExpandOperand /
//              ExpandProjector). Sharing the host expansion code with the CPU
//              reference removes any possibility of oracle divergence.
//   2. GPU   : UA = U*A and BV = B*V as exact INT8 -> INT32 integer GEMMs
//              (portable integer-ALU kernel everywhere; Metal 4
//              mpp::tensor_ops::matmul2d INT8/INT32 on M5-class devices).
//   3. GPU   : Chat = (UA * BV) mod q, q = 2^61 - 1, in exact 64-bit integer
//              arithmetic (see matmul_v4_accel_kernels.metal for the proof of
//              bit-equivalence with matmul::v4::ComputeSketch).
//   4. HOST  : canonicality-check the returned words (< q), serialize with
//              matmul::v4::SerializeSketch and digest with
//              matmul::v4::ComputeSketchDigest -- the identical consensus
//              byte path used by the CPU miner.
//
// BIT-EXACTNESS GATE: on first use this backend replays a full small-n digest
// through the GPU and compares digest AND payload byte-for-byte against
// matmul_v4::ComputeDigest. The tensor-ops path is only enabled if it passes
// on this device; if even the ALU path fails, the backend reports itself
// unavailable and every call returns false (CPU fallback). No float, no
// approximation, ever (design spec §B.6).

#include <metal/matmul_v4_accel.h>

#include <matmul/int8_field.h>
#include <matmul/matmul_v4.h>
#include <matmul/pow_v4.h>
#include <primitives/block.h>
#include <logging.h>
#include <uint256.h>

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits.h>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>
#include <mach-o/dyld.h>

namespace {

// Must stay byte-identical to metal/matmul_v4_accel_kernels.metal (inline
// compile fallback when no precompiled metallib is found; same convention as
// the v3 backend in metal/matmul_accel.mm).
constexpr const char* KERNEL_SOURCE = R"METAL(
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// MatMul v4 Metal device kernels: exact INT8 -> INT32 GEMM plus the m x m
// sketch combine reduced mod q = 2^61 - 1.
//
// IMPORTANT: this file must stay byte-identical to the KERNEL_SOURCE raw
// string embedded in metal/matmul_v4_accel.mm (the inline-compile fallback
// used when no precompiled metallib is found), mirroring the v3 convention in
// metal/matmul_accel_kernels.metal / metal/matmul_accel.mm.
//
// DETERMINISM CONTRACT (design spec §B.6, matmul/pow_v4.h):
//   * Every arithmetic operation below is integer arithmetic. There is no
//     floating point anywhere in this file, and there must never be: the v4
//     compute path is exact s8 x s8 -> s32 (|C_ij| <= n*125^2 < 2^30, §B.4)
//     and the soundness field is q = 2^61 - 1 in exact 64-bit ALU math.
//   * Integer addition is associative and commutative, so any tiling or
//     accumulation order produces the same INT32 / F_q result bit-for-bit.
//     Canonical residues mod q are unique, so matching the CPU reference
//     (matmul/int8_field.cpp) reduces to computing the same exact integers.
//
// TWO GEMM PATHS:
//   * matmul_v4_s8_gemm_s32          - portable integer-ALU tiled GEMM.
//     Compiles under any Metal Shading Language version and runs bit-exactly
//     on every Metal GPU family (pre-M5 and M5). MSL `simdgroup_matrix` is
//     float/half only, so on pre-M5 hardware the scalar integer ALU is the
//     only conforming (exact) matmul engine.
//   * matmul_v4_s8_gemm_s32_tensor   - Metal 4 / M5-class path using
//     mpp::tensor_ops::matmul2d from Metal Performance Primitives, which
//     drives the per-core GPU neural accelerators with INT8 inputs and an
//     INT32 accumulator (the only accumulator type offered for INT8, i.e.
//     exact by construction). Guarded so this file still compiles with
//     pre-Metal-4 toolchains; the host additionally runs a bit-exactness
//     self-test against the CPU reference before ever trusting this path.

#include <metal_stdlib>

#if defined(__METAL_VERSION__) && (__METAL_VERSION__ >= 400) && \
    __has_include(<MetalPerformancePrimitives/MetalPerformancePrimitives.h>)
#include <MetalPerformancePrimitives/MetalPerformancePrimitives.h>
#define BTX_MATMUL_V4_HAVE_TENSOR_OPS 1
#endif

using namespace metal;

// Mersenne prime q = 2^61 - 1 (matmul::int8_field::kFieldPrime).
constant ulong FIELD_Q = 0x1fffffffffffffffUL;

// Tile edge for the portable integer GEMM (16x16 threads per threadgroup).
constant uint GEMM_TILE = 16u;

// Output tile computed by one simdgroup on the Metal 4 tensor-ops path.
#define BTX_V4_TENSOR_TILE_M 32
#define BTX_V4_TENSOR_TILE_N 32

// D (m x n, row-major s32) = X (m x k, row-major s8) * Y (k x n, row-major s8).
// Used for both stages of the sketch:
//   UA = U * A  with (m_rows, k, n_cols) = (m, n, n)
//   BV = B * V  with (m_rows, k, n_cols) = (n, n, m)
struct GemmParams {
    uint m_rows;
    uint k;
    uint n_cols;
};

// Chat (m x m, row-major u64 canonical mod q) = (UA * BV) mod q.
struct CombineParams {
    uint m;
    uint n;
};

// ---------------------------------------------------------------------------
// Portable exact INT8 -> INT32 GEMM (all Metal GPU families).
//
// Threadgroup-tiled: each 16x16 threadgroup stages 16x16 s8 tiles of X and Y
// through threadgroup memory and accumulates the exact 32-bit dot product.
// Out-of-range lanes load 0 (additive identity), so edge tiles contribute
// exactly the in-range terms; every thread reaches both barriers.
//
// Exactness: |x|,|y| <= 125 and k <= 65535, so |acc| <= k * 125^2 < 2^30
// (§B.4, CheckAccumulationBound) -- the s32 accumulator can never wrap and the
// result is the exact mathematical integer dot product, independent of order.
// ---------------------------------------------------------------------------
kernel void matmul_v4_s8_gemm_s32(
    constant GemmParams& p [[buffer(0)]],
    device const char* x [[buffer(1)]],
    device const char* y [[buffer(2)]],
    device int* d [[buffer(3)]],
    uint2 gid [[thread_position_in_grid]],
    uint2 tid [[thread_position_in_threadgroup]])
{
    threadgroup char tile_x[16][16];
    threadgroup char tile_y[16][16];

    const uint row = gid.y;
    const uint col = gid.x;

    int acc = 0;
    const uint k_tiles = (p.k + GEMM_TILE - 1u) / GEMM_TILE;
    for (uint t = 0; t < k_tiles; ++t) {
        const uint kx = t * GEMM_TILE + tid.x;
        const uint ky = t * GEMM_TILE + tid.y;
        tile_x[tid.y][tid.x] = (row < p.m_rows && kx < p.k)
            ? x[(ulong)row * p.k + kx]
            : (char)0;
        tile_y[tid.y][tid.x] = (ky < p.k && col < p.n_cols)
            ? y[(ulong)ky * p.n_cols + col]
            : (char)0;
        threadgroup_barrier(mem_flags::mem_threadgroup);

        for (uint kk = 0; kk < GEMM_TILE; ++kk) {
            acc += (int)tile_x[tid.y][kk] * (int)tile_y[kk][tid.x];
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (row < p.m_rows && col < p.n_cols) {
        d[(ulong)row * p.n_cols + col] = acc;
    }
}

// ---------------------------------------------------------------------------
// Sketch combine: Chat = (UA * BV) mod q, exact 64-bit integer arithmetic.
//
// Equivalence with the CPU reference (matmul/matmul_v4.cpp ComputeSketch):
// the CPU computes T = U*C mod q then Chat = T*V mod q with C = A*B. Over the
// integers U*(A*B)*V == (U*A)*(B*V) (matrix multiplication is associative),
// and reduction mod q is a ring homomorphism, so both sides land on the SAME
// element of F_q. Canonical representatives in [0, q) are unique, therefore
// the u64 emitted here is bit-identical to the CPU's FqAdd/FqMul chain.
//
// Per-term exactness: |UA|,|BV| <= n*125^2 < 2^30 (§B.4), so each product
// fits in a signed 64-bit value with |prod| < 2^60 < q. Its canonical residue
// is prod >= 0 ? prod : prod + q (single lift, exact). The running sum is kept
// canonical with one conditional subtract per step (acc + term < 2q < 2^62,
// so the u64 accumulator can never wrap). This reproduces
// matmul::int8_field::FqAdd / FqFromInt32 semantics exactly.
// ---------------------------------------------------------------------------
kernel void matmul_v4_combine_mod_q(
    constant CombineParams& p [[buffer(0)]],
    device const int* ua [[buffer(1)]],
    device const int* bv [[buffer(2)]],
    device ulong* chat [[buffer(3)]],
    uint2 gid [[thread_position_in_grid]])
{
    const uint a = gid.y;
    const uint c = gid.x;
    if (a >= p.m || c >= p.m) {
        return;
    }

    ulong acc = 0;
    for (uint k = 0; k < p.n; ++k) {
        const long prod = (long)ua[(ulong)a * p.n + k] * (long)bv[(ulong)k * p.m + c];
        const ulong term = prod >= 0 ? (ulong)prod : (ulong)(prod + (long)FIELD_Q);
        acc += term;
        acc = acc >= FIELD_Q ? acc - FIELD_Q : acc;
    }
    chat[(ulong)a * p.m + c] = acc;
}

#if defined(BTX_MATMUL_V4_HAVE_TENSOR_OPS)
// ---------------------------------------------------------------------------
// Metal 4 / M5-class tensor-ops GEMM (GPU neural accelerators).
//
// Uses mpp::tensor_ops::matmul2d exactly as documented in Apple's "Metal
// Performance Primitives (MPP) Programming Guide" (2026): one simdgroup per
// threadgroup computes a BTX_V4_TENSOR_TILE_M x BTX_V4_TENSOR_TILE_N output
// tile, accumulating over the full K extent of the input tensors. Inputs are
// INT8 tensors; the destination is an INT32 tensor -- INT32 is the only
// accumulator type the hardware offers for INT8 operands, so the MACs are
// exact integers and the result is order-independent and bit-identical to
// the scalar path (same |acc| < 2^30 bound as above).
//
// Tensor extents follow the MPP convention (innermost extent first):
//   X (m_rows x k, row-major):  dextents {k, m_rows},  strides {1, k}
//   Y (k x n_cols, row-major):  dextents {n_cols, k},  strides {1, n_cols}
//   D (m_rows x n_cols, s32):   dextents {n_cols, m_rows}, strides {1, n_cols}
// Edge tiles rely on the slice-derived extents: mpp bounds-checks loads and
// stores against the tensor extents, so partial tiles read/write exactly the
// in-range elements.
// ---------------------------------------------------------------------------
kernel void matmul_v4_s8_gemm_s32_tensor(
    constant GemmParams& p [[buffer(0)]],
    device const char* x [[buffer(1)]],
    device const char* y [[buffer(2)]],
    device int* d [[buffer(3)]],
    uint2 tgid [[threadgroup_position_in_grid]])
{
    using namespace mpp;
    using namespace mpp::tensor_ops;

    constexpr auto desc = matmul2d_descriptor(BTX_V4_TENSOR_TILE_M, BTX_V4_TENSOR_TILE_N);
    matmul2d<desc, execution_simdgroup> op;

    auto mX = tensor(x, dextents<int, 2>{(int)p.k, (int)p.m_rows}, array<int, 2>{1, (int)p.k});
    auto mY = tensor(y, dextents<int, 2>{(int)p.n_cols, (int)p.k}, array<int, 2>{1, (int)p.n_cols});
    auto mD = tensor(d, dextents<int, 2>{(int)p.n_cols, (int)p.m_rows}, array<int, 2>{1, (int)p.n_cols});

    const int row0 = (int)(tgid.y * BTX_V4_TENSOR_TILE_M);
    const int col0 = (int)(tgid.x * BTX_V4_TENSOR_TILE_N);

    auto tX = mX.slice(0, row0);
    auto tY = mY.slice(col0, 0);
    auto tD = mD.slice(col0, row0);

    op.run(tX, tY, tD);
}
#endif // BTX_MATMUL_V4_HAVE_TENSOR_OPS
)METAL";

struct GemmParams {
    uint32_t m_rows{0};
    uint32_t k{0};
    uint32_t n_cols{0};
};

struct CombineParams {
    uint32_t m{0};
    uint32_t n{0};
};

constexpr uint32_t kGemmTile = 16;
constexpr uint32_t kTensorTileM = 32;
constexpr uint32_t kTensorTileN = 32;
// Self-test dimensions: one shape exercising partial 16x16 / 32x32 edge tiles
// and one tensor-eligible shape (n % 32 == 0). Both satisfy ValidateDims
// (n % 8 == 0, accumulation bound).
constexpr uint32_t kSelfTestEdgeN = 40;
constexpr uint32_t kSelfTestTensorN = 64;

void AppendUniquePath(std::vector<std::string>& paths, const char* path)
{
    if (path == nullptr || path[0] == '\0') return;
    if (std::find(paths.begin(), paths.end(), path) == paths.end()) {
        paths.emplace_back(path);
    }
}

std::optional<std::string> ExecutableDirectory()
{
    uint32_t size = PATH_MAX;
    std::vector<char> buffer(size);
    if (_NSGetExecutablePath(buffer.data(), &size) != 0) {
        buffer.resize(size);
        if (_NSGetExecutablePath(buffer.data(), &size) != 0) {
            return std::nullopt;
        }
    }

    char resolved[PATH_MAX];
    const char* executable_path = realpath(buffer.data(), resolved) != nullptr ? resolved : buffer.data();
    std::string path{executable_path};
    const auto separator = path.find_last_of('/');
    if (separator == std::string::npos) {
        return std::nullopt;
    }
    return path.substr(0, separator);
}

std::vector<std::string> MatMulV4MetallibCandidatePaths()
{
    std::vector<std::string> paths;
    AppendUniquePath(paths, std::getenv("BTX_MATMUL_V4_METALLIB_PATH"));

    if (const auto executable_dir = ExecutableDirectory()) {
        const std::string packaged_path = *executable_dir + "/metal/matmul_v4_accel_kernels.metallib";
        AppendUniquePath(paths, packaged_path.c_str());
    }

#if defined(BTX_MATMUL_V4_METALLIB_PATH)
    AppendUniquePath(paths, BTX_MATMUL_V4_METALLIB_PATH);
#endif
    return paths;
}

bool EnvFlagDisabled(const char* name)
{
    const char* env = std::getenv(name);
    return env != nullptr && env[0] == '0';
}

// Singleton Metal state for the v4 backend. Command queues and pipeline state
// objects are documented thread-safe in Metal; every ComputeDigestAccel call
// uses its own buffers and command buffer, so no per-call locking is needed.
struct MetalV4Context {
    id<MTLDevice> device{nil};
    id<MTLCommandQueue> queue{nil};
    id<MTLComputePipelineState> gemm_alu_pipeline{nil};
    id<MTLComputePipelineState> combine_pipeline{nil};
    // Metal 4 / M5-class GPU-neural-accelerator GEMM; nil when the runtime
    // compiler, OS, or device does not support mpp::tensor_ops, or when the
    // path failed the bit-exactness self-test.
    id<MTLComputePipelineState> gemm_tensor_pipeline{nil};
    std::string tensor_path_reason;
    std::string error;
    std::string device_name;

    // One-time full-pipeline self-test vs the CPU reference (see SelfTest()).
    std::once_flag self_test_once;
    bool self_test_passed{false};
    std::string self_test_error;

    MetalV4Context()
    {
        @autoreleasepool {
            // MTLCreateSystemDefaultDevice() is restricted to interactive apps
            // on macOS 14+; MTLCopyAllDevices() works from CLI/daemon contexts
            // (same rationale as the v3 backend in metal/matmul_accel.mm).
            NSArray<id<MTLDevice>>* all_devices = MTLCopyAllDevices();
            if (all_devices == nil || all_devices.count == 0) {
                error = "No Metal-compatible GPU device found";
                return;
            }
            device = all_devices[0];
            device_name = device.name != nil ? std::string{[device.name UTF8String]} : "unknown";

            queue = [device newCommandQueue];
            if (queue == nil) {
                error = "Failed to create Metal command queue";
                return;
            }

            // Portable pipelines: prefer the precompiled metallib, fall back
            // to inline runtime compilation of KERNEL_SOURCE.
            NSError* library_error = nil;
            id<MTLLibrary> library = nil;
            for (const auto& candidate_path : MatMulV4MetallibCandidatePaths()) {
                NSString* precompiled_path = [NSString stringWithUTF8String:candidate_path.c_str()];
                if (![[NSFileManager defaultManager] fileExistsAtPath:precompiled_path]) {
                    continue;
                }
                library_error = nil;
                NSURL* precompiled_url = [NSURL fileURLWithPath:precompiled_path];
                library = [device newLibraryWithURL:precompiled_url error:&library_error];
                if (library != nil) {
                    break;
                }
            }
            if (library == nil) {
                library_error = nil;
                library = [device newLibraryWithSource:[NSString stringWithUTF8String:KERNEL_SOURCE]
                                               options:nil
                                                 error:&library_error];
            }
            if (library == nil) {
                error = library_error != nil ? [[library_error localizedDescription] UTF8String]
                                             : "Failed to compile Metal MatMul v4 kernel source";
                return;
            }

            gemm_alu_pipeline = MakePipeline(library, @"matmul_v4_s8_gemm_s32", error);
            if (gemm_alu_pipeline == nil) return;
            combine_pipeline = MakePipeline(library, @"matmul_v4_combine_mod_q", error);
            if (combine_pipeline == nil) return;

            InitTensorPipeline();
        }
    }

    id<MTLComputePipelineState> MakePipeline(id<MTLLibrary> library, NSString* name, std::string& out_error)
    {
        id<MTLFunction> function = [library newFunctionWithName:name];
        if (function == nil) {
            out_error = std::string{"Failed to load Metal kernel function: "} + [name UTF8String];
            return nil;
        }
        NSError* pipeline_error = nil;
        id<MTLComputePipelineState> pipeline =
            [device newComputePipelineStateWithFunction:function error:&pipeline_error];
        if (pipeline == nil) {
            out_error = pipeline_error != nil
                ? [[pipeline_error localizedDescription] UTF8String]
                : (std::string{"Failed to create pipeline: "} + [name UTF8String]);
        }
        return pipeline;
    }

    void InitTensorPipeline()
    {
        // The Metal 4 tensor-ops GEMM is always compiled at runtime with an
        // explicit metal4.0 language version so the precompiled (portable)
        // metallib never needs a Metal 4 toolchain. On pre-Metal-4 OSes,
        // toolchains, or devices this compile simply fails and we stay on the
        // (equally bit-exact) integer-ALU path. BTX_MATMUL_V4_TENSOR_OPS=0
        // forces the ALU path.
        if (EnvFlagDisabled("BTX_MATMUL_V4_TENSOR_OPS")) {
            tensor_path_reason = "disabled_by_environment";
            return;
        }

        MTLCompileOptions* options = [MTLCompileOptions new];
        // MTLLanguageVersion4_0 == (4 << 16); spelled numerically so this file
        // also builds against pre-macOS-26 SDKs, where the runtime compile
        // then fails cleanly below.
        options.languageVersion = static_cast<MTLLanguageVersion>(4 << 16);

        NSError* library_error = nil;
        id<MTLLibrary> tensor_library =
            [device newLibraryWithSource:[NSString stringWithUTF8String:KERNEL_SOURCE]
                                 options:options
                                   error:&library_error];
        if (tensor_library == nil) {
            tensor_path_reason = library_error != nil
                ? std::string{"metal4_compile_failed:"} + [[library_error localizedDescription] UTF8String]
                : "metal4_compile_failed";
            return;
        }

        std::string pipeline_error;
        id<MTLComputePipelineState> pipeline =
            MakePipeline(tensor_library, @"matmul_v4_s8_gemm_s32_tensor", pipeline_error);
        if (pipeline == nil) {
            // Function absent (BTX_MATMUL_V4_HAVE_TENSOR_OPS not defined by
            // the runtime compiler) or pipeline creation failed on this GPU
            // family: no tensor path on this device.
            tensor_path_reason = pipeline_error;
            return;
        }
        gemm_tensor_pipeline = pipeline;
        tensor_path_reason = "ok";
    }
};

MetalV4Context& GetContext()
{
    static MetalV4Context context;
    return context;
}

std::atomic_bool g_logged_unavailable{false};
std::atomic_bool g_logged_self_test{false};

void LogUnavailableOnce(const std::string& reason)
{
    bool expected{false};
    if (g_logged_unavailable.compare_exchange_strong(expected, true)) {
        LogPrintf("MATMUL v4 WARNING: Metal backend unavailable (%s); falling back to CPU\n", reason);
    }
}

bool EncodeGemm(id<MTLCommandBuffer> command,
                id<MTLComputePipelineState> pipeline,
                bool tensor_path,
                const GemmParams& params,
                id<MTLBuffer> params_buffer,
                id<MTLBuffer> x,
                id<MTLBuffer> y,
                id<MTLBuffer> d,
                std::string& error)
{
    id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
    if (encoder == nil) {
        error = "Failed to create Metal compute encoder";
        return false;
    }
    [encoder setComputePipelineState:pipeline];
    [encoder setBuffer:params_buffer offset:0 atIndex:0];
    [encoder setBuffer:x offset:0 atIndex:1];
    [encoder setBuffer:y offset:0 atIndex:2];
    [encoder setBuffer:d offset:0 atIndex:3];

    if (tensor_path) {
        // One simdgroup (32 threads) per threadgroup computes one
        // kTensorTileM x kTensorTileN output tile via mpp::tensor_ops.
        const MTLSize groups = MTLSizeMake((params.n_cols + kTensorTileN - 1) / kTensorTileN,
                                           (params.m_rows + kTensorTileM - 1) / kTensorTileM, 1);
        const MTLSize group_size = MTLSizeMake(32, 1, 1);
        [encoder dispatchThreadgroups:groups threadsPerThreadgroup:group_size];
    } else {
        const MTLSize groups = MTLSizeMake((params.n_cols + kGemmTile - 1) / kGemmTile,
                                           (params.m_rows + kGemmTile - 1) / kGemmTile, 1);
        const MTLSize group_size = MTLSizeMake(kGemmTile, kGemmTile, 1);
        [encoder dispatchThreadgroups:groups threadsPerThreadgroup:group_size];
    }
    [encoder endEncoding];
    return true;
}

// Core GPU digest computation. `use_tensor_gemm` selects the Metal 4
// tensor-ops GEMM (caller must have verified availability); the combine stage
// always runs the exact 64-bit mod-q ALU kernel. Returns false with `error`
// set on any failure -- never a wrong result.
bool ComputeDigestImpl(MetalV4Context& ctx,
                       const CBlockHeader& header,
                       uint32_t n,
                       uint32_t m,
                       bool use_tensor_gemm,
                       uint256& digest_out,
                       std::vector<unsigned char>& payload_out,
                       std::string& error)
{
    @autoreleasepool {
        // 1. Host-side consensus derivation and expansion (identical code to
        //    matmul_v4::ComputeDigest -- the same functions, not a re-impl).
        const uint256 sigma = matmul::v4::DeriveSigma(header);
        const uint256 seed_a = matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::A);
        const uint256 seed_b = matmul::v4::DeriveOperandSeed(header, matmul::v4::Operand::B);
        const auto [seed_u, seed_v] = matmul::v4::DeriveProjectorSeeds(header);

        const std::vector<int8_t> A = matmul::v4::ExpandOperand(seed_a, n);
        const std::vector<int8_t> B = matmul::v4::ExpandOperand(seed_b, n);
        const std::vector<int8_t> U = matmul::v4::ExpandProjector(seed_u, m, n);
        const std::vector<int8_t> V = matmul::v4::ExpandProjector(seed_v, n, m);

        const size_t nn = static_cast<size_t>(n) * n;
        const size_t mn = static_cast<size_t>(m) * n;
        const size_t mm = static_cast<size_t>(m) * m;

        const NSUInteger max_len = ctx.device.maxBufferLength;
        if (nn > max_len || mn * sizeof(int32_t) > max_len || mm * sizeof(uint64_t) > max_len) {
            error = "requested dimension exceeds Metal device buffer limits";
            return false;
        }

        id<MTLBuffer> buf_a = [ctx.device newBufferWithBytes:A.data() length:nn options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_b = [ctx.device newBufferWithBytes:B.data() length:nn options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_u = [ctx.device newBufferWithBytes:U.data() length:mn options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_v = [ctx.device newBufferWithBytes:V.data() length:mn options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_ua = [ctx.device newBufferWithLength:mn * sizeof(int32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_bv = [ctx.device newBufferWithLength:mn * sizeof(int32_t) options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_chat = [ctx.device newBufferWithLength:mm * sizeof(uint64_t) options:MTLResourceStorageModeShared];

        const GemmParams ua_params{.m_rows = m, .k = n, .n_cols = n};
        const GemmParams bv_params{.m_rows = n, .k = n, .n_cols = m};
        const CombineParams combine_params{.m = m, .n = n};
        id<MTLBuffer> buf_ua_params = [ctx.device newBufferWithBytes:&ua_params length:sizeof(ua_params) options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_bv_params = [ctx.device newBufferWithBytes:&bv_params length:sizeof(bv_params) options:MTLResourceStorageModeShared];
        id<MTLBuffer> buf_combine_params = [ctx.device newBufferWithBytes:&combine_params length:sizeof(combine_params) options:MTLResourceStorageModeShared];

        if (buf_a == nil || buf_b == nil || buf_u == nil || buf_v == nil ||
            buf_ua == nil || buf_bv == nil || buf_chat == nil ||
            buf_ua_params == nil || buf_bv_params == nil || buf_combine_params == nil) {
            error = "Failed to allocate Metal buffers";
            return false;
        }

        id<MTLCommandBuffer> command = [ctx.queue commandBuffer];
        if (command == nil) {
            error = "Failed to create Metal command buffer";
            return false;
        }

        id<MTLComputePipelineState> gemm_pipeline =
            use_tensor_gemm ? ctx.gemm_tensor_pipeline : ctx.gemm_alu_pipeline;

        // 2. UA = U * A (m x n s32) and BV = B * V (n x m s32). Successive
        //    encoders in one command buffer execute in order, so the combine
        //    stage observes completed UA/BV.
        if (!EncodeGemm(command, gemm_pipeline, use_tensor_gemm, ua_params, buf_ua_params, buf_u, buf_a, buf_ua, error)) return false;
        if (!EncodeGemm(command, gemm_pipeline, use_tensor_gemm, bv_params, buf_bv_params, buf_b, buf_v, buf_bv, error)) return false;

        // 3. Chat = (UA * BV) mod q -- exact 64-bit integer ALU kernel.
        {
            id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
            if (encoder == nil) {
                error = "Failed to create Metal compute encoder";
                return false;
            }
            [encoder setComputePipelineState:ctx.combine_pipeline];
            [encoder setBuffer:buf_combine_params offset:0 atIndex:0];
            [encoder setBuffer:buf_ua offset:0 atIndex:1];
            [encoder setBuffer:buf_bv offset:0 atIndex:2];
            [encoder setBuffer:buf_chat offset:0 atIndex:3];
            const MTLSize groups = MTLSizeMake((m + kGemmTile - 1) / kGemmTile,
                                               (m + kGemmTile - 1) / kGemmTile, 1);
            const MTLSize group_size = MTLSizeMake(kGemmTile, kGemmTile, 1);
            [encoder dispatchThreadgroups:groups threadsPerThreadgroup:group_size];
            [encoder endEncoding];
        }

        [command commit];
        [command waitUntilCompleted];
        if (command.status != MTLCommandBufferStatusCompleted) {
            error = command.error != nil
                ? std::string{"Metal command buffer failed: "} + [[command.error localizedDescription] UTF8String]
                : "Metal command buffer did not complete";
            return false;
        }

        // 4. Canonicality check + consensus serialization/digest on the host.
        std::vector<matmul::v4::Fq> chat(mm);
        std::memcpy(chat.data(), [buf_chat contents], mm * sizeof(uint64_t));
        for (const auto word : chat) {
            if (word >= matmul::int8_field::kFieldPrime) {
                // Defense in depth: the combine kernel proves words < q, so a
                // non-canonical word means a malfunctioning device/driver.
                error = "Metal produced a non-canonical F_q word";
                return false;
            }
        }

        payload_out = matmul::v4::SerializeSketch(chat);
        digest_out = matmul::v4::ComputeSketchDigest(sigma, payload_out);
        return true;
    }
}

// Replay one full digest through the GPU and require byte-identical digest
// AND payload vs the CPU consensus reference matmul_v4::ComputeDigest.
bool SelfTestCase(MetalV4Context& ctx, uint32_t n, bool use_tensor_gemm, std::string& error)
{
    uint32_t m = 0;
    if (!matmul::v4::ValidateDims(n, matmul_v4::kTileB, m)) {
        error = "self-test dimensions invalid";
        return false;
    }

    // Deterministic non-trivial header: all-default fields still yield
    // pseudorandom operands because seeds are SHA256 derivations of the
    // header hash. Every node runs the identical vector.
    const CBlockHeader header{};

    uint256 cpu_digest;
    std::vector<unsigned char> cpu_payload;
    if (!matmul_v4::ComputeDigest(header, n, /*rounds=*/1, cpu_digest, cpu_payload)) {
        error = "self-test CPU reference failed";
        return false;
    }

    uint256 gpu_digest;
    std::vector<unsigned char> gpu_payload;
    if (!ComputeDigestImpl(ctx, header, n, m, use_tensor_gemm, gpu_digest, gpu_payload, error)) {
        return false;
    }
    if (gpu_digest != cpu_digest || gpu_payload != cpu_payload) {
        error = "self-test digest/payload mismatch vs CPU reference";
        return false;
    }
    return true;
}

// One-time bit-exactness gate. The ALU path must pass on an edge-tile shape
// and a tensor-eligible shape or the whole backend is reported unavailable.
// The tensor path must pass on this device or it is dropped (silently falling
// back to the ALU path), satisfying the "no conforming integer path => no GPU
// path" rule without ever emitting an unverified digest.
void RunSelfTest(MetalV4Context& ctx)
{
    std::string error;
    if (!SelfTestCase(ctx, kSelfTestEdgeN, /*use_tensor_gemm=*/false, error) ||
        !SelfTestCase(ctx, kSelfTestTensorN, /*use_tensor_gemm=*/false, error)) {
        ctx.self_test_passed = false;
        ctx.self_test_error = "alu:" + error;
        ctx.gemm_tensor_pipeline = nil;
        return;
    }
    ctx.self_test_passed = true;

    if (ctx.gemm_tensor_pipeline != nil) {
        if (!SelfTestCase(ctx, kSelfTestTensorN, /*use_tensor_gemm=*/true, error)) {
            ctx.gemm_tensor_pipeline = nil;
            ctx.tensor_path_reason = "self_test_failed:" + error;
            bool expected{false};
            if (g_logged_self_test.compare_exchange_strong(expected, true)) {
                LogPrintf("MATMUL v4 WARNING: Metal tensor-ops GEMM failed bit-exactness self-test (%s); using integer-ALU kernels\n", error);
            }
        }
    }
}

bool EnsureReady(MetalV4Context& ctx, std::string& reason)
{
    if (!ctx.error.empty()) {
        reason = ctx.error;
        return false;
    }
    std::call_once(ctx.self_test_once, [&ctx] { RunSelfTest(ctx); });
    if (!ctx.self_test_passed) {
        reason = ctx.self_test_error.empty() ? "self-test failed" : ctx.self_test_error;
        return false;
    }
    return true;
}

} // namespace

namespace matmul_v4::metal {

AccelProbe ProbeAcceleration()
{
    AccelProbe probe;
    if (EnvFlagDisabled("BTX_MATMUL_V4_METAL")) {
        probe.reason = "disabled_by_environment";
        return probe;
    }
    auto& ctx = GetContext();
    std::string reason;
    if (!EnsureReady(ctx, reason)) {
        probe.reason = reason;
        return probe;
    }
    probe.available = true;
    probe.device_name = ctx.device_name;
    probe.gemm_path = ctx.gemm_tensor_pipeline != nil ? "tensor_ops" : "alu";
    probe.reason = ctx.gemm_tensor_pipeline != nil
        ? "metal4_tensor_ops_self_test_passed"
        : ("alu_self_test_passed(tensor:" + ctx.tensor_path_reason + ")");
    return probe;
}

bool ComputeDigestAccel(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                        uint256& digest_out, std::vector<unsigned char>& payload_out)
{
    if (EnvFlagDisabled("BTX_MATMUL_V4_METAL")) {
        return false;
    }

    uint32_t m = 0;
    if (!matmul::v4::ValidateDims(n, matmul_v4::kTileB, m)) {
        return false;
    }
    if (rounds == 0) {
        // API symmetry with matmul_v4::ComputeDigest (the miner runs no
        // Freivalds rounds, but rounds must be a valid parameter).
        return false;
    }

    auto& ctx = GetContext();
    std::string reason;
    if (!EnsureReady(ctx, reason)) {
        LogUnavailableOnce(reason);
        return false;
    }

    // The tensor-ops GEMM accumulates over K = n; keep it on shapes whose
    // reduction extent is 32-aligned (production shapes are), and let the
    // portable integer-ALU kernels -- equally bit-exact -- cover the rest.
    const bool use_tensor_gemm = ctx.gemm_tensor_pipeline != nil && (n % 32u) == 0u;

    std::string error;
    if (!ComputeDigestImpl(ctx, header, n, m, use_tensor_gemm, digest_out, payload_out, error)) {
        LogUnavailableOnce(error);
        return false;
    }
    return true;
}

} // namespace matmul_v4::metal
