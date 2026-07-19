// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Exact Metal 4 MPP TensorOps preference for the v4.4-LT MatExpand GEMMs.
//
// The consensus contract is integer-only.  This file uses
// mpp::tensor_ops::matmul2d with INT8 inputs and an INT32 destination; no
// floating-point value or approximate accumulator participates.  The S32xS8
// LT stage is lowered exactly to adaptive S8xS8 products with balanced
// base-256 digits:
//
//     L = L0 + 256*L1 + 65536*L2,  Li in [-128,127].
//
// The third product is omitted for the normal LT distribution when L2 is all
// zero, but makes the route total over LT's current |G*W| <= 36*n envelope.
// Inputs outside that exact three-limb envelope, dimensions whose conservative
// accumulator bound can exceed INT32, a Metal/MPP error, or any self-test
// mismatch return false.  The caller then runs the canonical CPU/integer-ALU
// ExactGemm implementation.  Availability means that both LT operations have
// passed deterministic bit-exact tests on this process's actual device; it
// does not claim that a particular Apple GPU executes MPP on a neural core.

#include <cuda/matmul_v4_lt_tensor_gemm.h>

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <vector>

namespace matmul_v4::metal {
namespace {

constexpr uint32_t kTensorTileM = 32;
constexpr uint32_t kTensorTileN = 32;

// Runtime-compiled with MSL 4.0.  Keeping this isolated from the portable
// metallib means an older SDK/device simply declines the optional lane.
static NSString* const kLtTensorSource = @R"MSL(
#include <metal_stdlib>
#include <MetalPerformancePrimitives/MetalPerformancePrimitives.h>
using namespace metal;

#define BTX_LT_TENSOR_TILE_M 32
#define BTX_LT_TENSOR_TILE_N 32

struct GemmParams {
    uint m_rows;
    uint k;
    uint n_cols;
};

kernel void matmul_v4_lt_s8_gemm_s32_tensor(
    constant GemmParams& p [[buffer(0)]],
    // The current MPP INT8 specialization requires mutable int8_t tensor
    // element types even though matmul2d only reads these two tensors.
    device int8_t* x [[buffer(1)]],
    device int8_t* y [[buffer(2)]],
    device int32_t* d [[buffer(3)]],
    uint2 tgid [[threadgroup_position_in_grid]])
{
    using namespace mpp;
    using namespace mpp::tensor_ops;

    constexpr auto desc = matmul2d_descriptor(BTX_LT_TENSOR_TILE_M,
                                               BTX_LT_TENSOR_TILE_N);
    matmul2d<desc, execution_simdgroup> op;

    auto mX = tensor(x, dextents<int, 2>{(int)p.k, (int)p.m_rows},
                     array<int, 2>{1, (int)p.k});
    auto mY = tensor(y, dextents<int, 2>{(int)p.n_cols, (int)p.k},
                     array<int, 2>{1, (int)p.n_cols});
    auto mD = tensor(d, dextents<int, 2>{(int)p.n_cols, (int)p.m_rows},
                     array<int, 2>{1, (int)p.n_cols});

    const int row0 = (int)(tgid.y * BTX_LT_TENSOR_TILE_M);
    const int col0 = (int)(tgid.x * BTX_LT_TENSOR_TILE_N);
    auto tX = mX.slice(0, row0);
    auto tY = mY.slice(col0, 0);
    auto tD = mD.slice(col0, row0);
    op.run(tX, tY, tD);
}
)MSL";

struct GemmParams {
    uint32_t m_rows{0};
    uint32_t k{0};
    uint32_t n_cols{0};
};

bool EnvDisabled()
{
    const char* value = std::getenv("BTX_MATMUL_V4_LT_TENSOR_OPS");
    return value != nullptr && value[0] == '0';
}

bool CheckedElements(uint32_t a, uint32_t b, size_t element_size, size_t& bytes)
{
    const uint64_t elements = static_cast<uint64_t>(a) * b;
    if (elements > std::numeric_limits<size_t>::max() / element_size) return false;
    bytes = static_cast<size_t>(elements) * element_size;
    return true;
}

template <typename T>
uint64_t MaxAbs(const std::vector<T>& values)
{
    uint64_t maximum = 0;
    for (const T value : values) {
        const int64_t wide = static_cast<int64_t>(value);
        const uint64_t magnitude = wide < 0 ? static_cast<uint64_t>(-wide)
                                            : static_cast<uint64_t>(wide);
        maximum = std::max(maximum, magnitude);
    }
    return maximum;
}

bool AccumulatorFitsInt32(uint64_t max_left, uint64_t max_right, uint32_t inner)
{
    const __uint128_t bound = static_cast<__uint128_t>(max_left) * max_right * inner;
    return bound <= static_cast<uint64_t>(std::numeric_limits<int32_t>::max());
}

struct MetalLtTensorContext {
    id<MTLDevice> device{nil};
    id<MTLCommandQueue> queue{nil};
    id<MTLComputePipelineState> pipeline{nil};
    std::mutex launch_mutex;

    // Shared grow-only scratch is serialized by launch_mutex.  S32xS8 needs
    // up to three input/output planes; S8xS8 uses plane zero only.
    id<MTLBuffer> a0{nil};
    id<MTLBuffer> a1{nil};
    id<MTLBuffer> a2{nil};
    id<MTLBuffer> b{nil};
    id<MTLBuffer> d0{nil};
    id<MTLBuffer> d1{nil};
    id<MTLBuffer> d2{nil};
    size_t a0_bytes{0};
    size_t a1_bytes{0};
    size_t a2_bytes{0};
    size_t b_bytes{0};
    size_t d0_bytes{0};
    size_t d1_bytes{0};
    size_t d2_bytes{0};

    bool initialized{false};
    const char* reason{"not_initialized"};

    MetalLtTensorContext()
    {
        @autoreleasepool {
            if (EnvDisabled()) { reason = "disabled_by_environment"; return; }

            // MTLCopyAllDevices also works from CLI/daemon contexts where the
            // system-default-device API can be restricted.
            NSArray<id<MTLDevice>>* devices = MTLCopyAllDevices();
            if (devices == nil || devices.count == 0) { reason = "no_metal_device"; return; }
            device = devices[0];
            queue = [device newCommandQueue];
            if (queue == nil) { reason = "command_queue_failed"; return; }

            MTLCompileOptions* options = [MTLCompileOptions new];
            // MTLLanguageVersion4_0, numeric so this host TU still compiles
            // with SDK headers that predate the symbolic enum.
            options.languageVersion = static_cast<MTLLanguageVersion>(4 << 16);
            NSError* error = nil;
            id<MTLLibrary> library =
                [device newLibraryWithSource:kLtTensorSource options:options error:&error];
            if (library == nil) {
                reason = "metal4_mpp_compile_failed";
                if (std::getenv("BTX_MATMUL_V4_LT_TENSOR_DIAGNOSTIC") != nullptr && error != nil) {
                    std::fprintf(stderr, "LT TensorOps: %s\n", [[error localizedDescription] UTF8String]);
                }
                return;
            }
            id<MTLFunction> function =
                [library newFunctionWithName:@"matmul_v4_lt_s8_gemm_s32_tensor"];
            if (function == nil) { reason = "tensor_function_missing"; return; }
            pipeline = [device newComputePipelineStateWithFunction:function error:&error];
            initialized = pipeline != nil;
            reason = initialized ? "initialized" : "tensor_pipeline_failed";
            if (!initialized && std::getenv("BTX_MATMUL_V4_LT_TENSOR_DIAGNOSTIC") != nullptr && error != nil) {
                std::fprintf(stderr, "LT TensorOps: %s\n", [[error localizedDescription] UTF8String]);
            }
        }
    }

    bool Grow(id<MTLBuffer> __strong& buffer, size_t& have, size_t need)
    {
        if (buffer != nil && have >= need) return true;
        buffer = [device newBufferWithLength:need options:MTLResourceStorageModeShared];
        have = buffer != nil ? need : 0;
        return buffer != nil;
    }

    bool Ensure(size_t a_bytes, size_t rhs_bytes, size_t out_bytes, uint32_t planes)
    {
        if (!Grow(a0, a0_bytes, a_bytes) ||
            !Grow(b, b_bytes, rhs_bytes) ||
            !Grow(d0, d0_bytes, out_bytes)) {
            return false;
        }
        if (planes >= 2 &&
            (!Grow(a1, a1_bytes, a_bytes) || !Grow(d1, d1_bytes, out_bytes))) {
            return false;
        }
        return planes < 3 ||
               (Grow(a2, a2_bytes, a_bytes) && Grow(d2, d2_bytes, out_bytes));
    }
};

MetalLtTensorContext& Context()
{
    static MetalLtTensorContext context;
    return context;
}

bool EncodeGemm(MetalLtTensorContext& ctx, id<MTLCommandBuffer> command,
                const GemmParams& params, id<MTLBuffer> left,
                id<MTLBuffer> right, id<MTLBuffer> output)
{
    id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
    if (encoder == nil) return false;
    [encoder setComputePipelineState:ctx.pipeline];
    [encoder setBytes:&params length:sizeof(params) atIndex:0];
    [encoder setBuffer:left offset:0 atIndex:1];
    [encoder setBuffer:right offset:0 atIndex:2];
    [encoder setBuffer:output offset:0 atIndex:3];

    const MTLSize groups = MTLSizeMake(
        (params.n_cols + kTensorTileN - 1) / kTensorTileN,
        (params.m_rows + kTensorTileM - 1) / kTensorTileM, 1);
    [encoder dispatchThreadgroups:groups threadsPerThreadgroup:MTLSizeMake(32, 1, 1)];
    [encoder endEncoding];
    return true;
}

bool LaunchS8S8Raw(const std::vector<int8_t>& left,
                   const std::vector<int8_t>& right,
                   uint32_t rows, uint32_t inner, uint32_t cols,
                   std::vector<int32_t>& out)
{
    auto& ctx = Context();
    if (!ctx.initialized) return false;
    if (rows == 0 || cols == 0) {
        out.clear();
        return true;
    }
    if (inner == 0) {
        out.assign(static_cast<size_t>(rows) * cols, 0);
        return true;
    }

    size_t left_bytes = 0, right_bytes = 0, out_bytes = 0;
    if (!CheckedElements(rows, inner, sizeof(int8_t), left_bytes) ||
        !CheckedElements(inner, cols, sizeof(int8_t), right_bytes) ||
        !CheckedElements(rows, cols, sizeof(int32_t), out_bytes) ||
        left.size() != left_bytes || right.size() != right_bytes ||
        !AccumulatorFitsInt32(MaxAbs(left), MaxAbs(right), inner)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(ctx.launch_mutex);
    if (!ctx.Ensure(left_bytes, right_bytes, out_bytes, /*planes=*/1)) return false;
    std::memcpy([ctx.a0 contents], left.data(), left_bytes);
    std::memcpy([ctx.b contents], right.data(), right_bytes);

    id<MTLCommandBuffer> command = [ctx.queue commandBuffer];
    if (command == nil) return false;
    const GemmParams params{rows, inner, cols};
    if (!EncodeGemm(ctx, command, params, ctx.a0, ctx.b, ctx.d0)) return false;
    [command commit];
    [command waitUntilCompleted];
    if (command.status != MTLCommandBufferStatusCompleted) return false;

    out.resize(static_cast<size_t>(rows) * cols);
    std::memcpy(out.data(), [ctx.d0 contents], out_bytes);
    return true;
}

bool DecomposeBalancedBase256(const std::vector<int32_t>& input,
                              std::vector<int8_t>& limb0,
                              std::vector<int8_t>& limb1,
                              std::vector<int8_t>& limb2,
                              uint32_t& active_limbs)
{
    limb0.resize(input.size());
    limb1.resize(input.size());
    limb2.resize(input.size());
    active_limbs = 1;
    for (size_t i = 0; i < input.size(); ++i) {
        int64_t value = input[i];
        auto take_digit = [](int64_t& remaining) {
            int64_t digit = remaining % 256;
            if (digit > 127) digit -= 256;
            if (digit < -128) digit += 256;
            remaining = (remaining - digit) / 256;
            return digit;
        };
        limb0[i] = static_cast<int8_t>(take_digit(value));
        limb1[i] = static_cast<int8_t>(take_digit(value));
        if (value < -128 || value > 127) return false;
        limb2[i] = static_cast<int8_t>(value);
        if (limb2[i] != 0) active_limbs = 3;
        else if (limb1[i] != 0 && active_limbs < 2) active_limbs = 2;
    }
    return true;
}

bool LaunchS32S8Raw(const std::vector<int32_t>& left,
                    const std::vector<int8_t>& right,
                    uint32_t rows, uint32_t inner, uint32_t cols,
                    std::vector<int32_t>& out)
{
    auto& ctx = Context();
    if (!ctx.initialized) return false;
    if (rows == 0 || cols == 0) {
        out.clear();
        return true;
    }
    if (inner == 0) {
        out.assign(static_cast<size_t>(rows) * cols, 0);
        return true;
    }

    size_t left_count_bytes = 0, right_bytes = 0, out_bytes = 0;
    if (!CheckedElements(rows, inner, sizeof(int32_t), left_count_bytes) ||
        !CheckedElements(inner, cols, sizeof(int8_t), right_bytes) ||
        !CheckedElements(rows, cols, sizeof(int32_t), out_bytes) ||
        left.size() != left_count_bytes / sizeof(int32_t) ||
        right.size() != right_bytes ||
        !AccumulatorFitsInt32(MaxAbs(left), MaxAbs(right), inner)) {
        return false;
    }

    std::vector<int8_t> limb0, limb1, limb2;
    uint32_t active_limbs = 1;
    if (!DecomposeBalancedBase256(left, limb0, limb1, limb2, active_limbs)) return false;
    const size_t limb_bytes = limb0.size();

    std::lock_guard<std::mutex> lock(ctx.launch_mutex);
    if (!ctx.Ensure(limb_bytes, right_bytes, out_bytes, active_limbs)) return false;
    std::memcpy([ctx.a0 contents], limb0.data(), limb_bytes);
    std::memcpy([ctx.b contents], right.data(), right_bytes);
    if (active_limbs >= 2) std::memcpy([ctx.a1 contents], limb1.data(), limb_bytes);
    if (active_limbs >= 3) std::memcpy([ctx.a2 contents], limb2.data(), limb_bytes);

    id<MTLCommandBuffer> command = [ctx.queue commandBuffer];
    if (command == nil) return false;
    const GemmParams params{rows, inner, cols};
    if (!EncodeGemm(ctx, command, params, ctx.a0, ctx.b, ctx.d0) ||
        (active_limbs >= 2 && !EncodeGemm(ctx, command, params, ctx.a1, ctx.b, ctx.d1)) ||
        (active_limbs >= 3 && !EncodeGemm(ctx, command, params, ctx.a2, ctx.b, ctx.d2))) {
        return false;
    }
    [command commit];
    [command waitUntilCompleted];
    if (command.status != MTLCommandBufferStatusCompleted) return false;

    const int32_t* product0 = static_cast<const int32_t*>([ctx.d0 contents]);
    const int32_t* product1 = active_limbs >= 2
        ? static_cast<const int32_t*>([ctx.d1 contents]) : nullptr;
    const int32_t* product2 = active_limbs >= 3
        ? static_cast<const int32_t*>([ctx.d2 contents]) : nullptr;
    const size_t output_count = static_cast<size_t>(rows) * cols;
    out.resize(output_count);
    for (size_t i = 0; i < output_count; ++i) {
        const int64_t exact = static_cast<int64_t>(product0[i]) +
            (product1 != nullptr ? 256LL * product1[i] : 0LL) +
            (product2 != nullptr ? 65536LL * product2[i] : 0LL);
        if (exact < std::numeric_limits<int32_t>::min() ||
            exact > std::numeric_limits<int32_t>::max()) {
            out.clear();
            return false;
        }
        out[i] = static_cast<int32_t>(exact);
    }
    return true;
}

std::vector<int32_t> ReferenceS8S8(const std::vector<int8_t>& left,
                                   const std::vector<int8_t>& right,
                                   uint32_t rows, uint32_t inner, uint32_t cols)
{
    std::vector<int32_t> out(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t row = 0; row < rows; ++row) {
        for (uint32_t col = 0; col < cols; ++col) {
            int64_t sum = 0;
            for (uint32_t k = 0; k < inner; ++k) {
                sum += static_cast<int32_t>(left[static_cast<size_t>(row) * inner + k]) *
                       static_cast<int32_t>(right[static_cast<size_t>(k) * cols + col]);
            }
            out[static_cast<size_t>(row) * cols + col] = static_cast<int32_t>(sum);
        }
    }
    return out;
}

std::vector<int32_t> ReferenceS32S8(const std::vector<int32_t>& left,
                                    const std::vector<int8_t>& right,
                                    uint32_t rows, uint32_t inner, uint32_t cols)
{
    std::vector<int32_t> out(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t row = 0; row < rows; ++row) {
        for (uint32_t col = 0; col < cols; ++col) {
            int64_t sum = 0;
            for (uint32_t k = 0; k < inner; ++k) {
                sum += static_cast<int64_t>(left[static_cast<size_t>(row) * inner + k]) *
                       static_cast<int32_t>(right[static_cast<size_t>(k) * cols + col]);
            }
            out[static_cast<size_t>(row) * cols + col] = static_cast<int32_t>(sum);
        }
    }
    return out;
}

bool RunSelfTest()
{
    if (!Context().initialized) return false;

    // Exercise partial M/N tiles, multiple output tiles/threadgroups, a
    // non-tile-aligned K, all signed-byte edge values, and the actual LT
    // reduction extent (128). Qualification must cover the multi-tile behavior
    // used by production matrices, not merely one output tile.
    for (const GemmParams p : {GemmParams{4, 4, 4}, GemmParams{17, 33, 19},
                               GemmParams{32, 128, 32}, GemmParams{65, 128, 67}}) {
        std::vector<int8_t> left(static_cast<size_t>(p.m_rows) * p.k);
        std::vector<int8_t> right(static_cast<size_t>(p.k) * p.n_cols);
        for (size_t i = 0; i < left.size(); ++i) {
            left[i] = static_cast<int8_t>((i * 73 + 19) % 256 - 128);
        }
        for (size_t i = 0; i < right.size(); ++i) {
            right[i] = static_cast<int8_t>((i * 151 + 7) % 256 - 128);
        }
        std::vector<int32_t> device;
        if (!LaunchS8S8Raw(left, right, p.m_rows, p.k, p.n_cols, device) ||
            device != ReferenceS8S8(left, right, p.m_rows, p.k, p.n_cols)) {
            return false;
        }
    }

    const GemmParams p{65, 128, 67};
    std::vector<int32_t> left(static_cast<size_t>(p.m_rows) * p.k);
    std::vector<int8_t> right(static_cast<size_t>(p.k) * p.n_cols);
    for (size_t i = 0; i < left.size(); ++i) {
        // Exercises the common two-limb range.
        left[i] = static_cast<int32_t>((i * 8191 + 97) % 9217) - 4608;
    }
    for (size_t i = 0; i < right.size(); ++i) {
        right[i] = static_cast<int8_t>((i * 11 + 5) % 13 - 6);
    }
    std::vector<int32_t> device;
    if (!LaunchS32S8Raw(left, right, p.m_rows, p.k, p.n_cols, device) ||
        device != ReferenceS32S8(left, right, p.m_rows, p.k, p.n_cols)) {
        return false;
    }

    // Force the third balanced-base256 limb while keeping the exact result in
    // INT32.  Current consensus dimensions satisfy |G*W| <= 36*n < 310k.
    constexpr GemmParams p3{65, 8, 67};
    std::vector<int32_t> left3(static_cast<size_t>(p3.m_rows) * p3.k);
    std::vector<int8_t> right3(static_cast<size_t>(p3.k) * p3.n_cols);
    for (size_t i = 0; i < left3.size(); ++i) {
        left3[i] = (i & 1) != 0 ? 300'000 : -300'000;
    }
    for (size_t i = 0; i < right3.size(); ++i) {
        right3[i] = static_cast<int8_t>((i % 3) - 1);
    }
    return LaunchS32S8Raw(left3, right3, p3.m_rows, p3.k, p3.n_cols, device) &&
           device == ReferenceS32S8(left3, right3, p3.m_rows, p3.k, p3.n_cols);
}

bool Qualified()
{
    static std::once_flag once;
    static bool passed = false;
    std::call_once(once, [] {
        passed = RunSelfTest();
        if (!passed && std::getenv("BTX_MATMUL_V4_LT_TENSOR_DIAGNOSTIC") != nullptr) {
            std::fprintf(stderr, "LT TensorOps qualification failed: %s\n", Context().reason);
        }
    });
    return passed;
}

} // namespace

bool IsLtTensorOpsGemmAvailable()
{
    return Qualified();
}

bool TryLaunchLtTensorOpsGemmS8S8(const std::vector<int8_t>& left,
                                  const std::vector<int8_t>& right,
                                  uint32_t rows, uint32_t inner, uint32_t cols,
                                  std::vector<int32_t>& out)
{
    out.clear();
    if (!Qualified()) return false;
    return LaunchS8S8Raw(left, right, rows, inner, cols, out);
}

bool TryLaunchLtTensorOpsGemmS32S8(const std::vector<int32_t>& left,
                                   const std::vector<int8_t>& right,
                                   uint32_t rows, uint32_t inner, uint32_t cols,
                                   std::vector<int32_t>& out)
{
    out.clear();
    if (!Qualified()) return false;
    return LaunchS32S8Raw(left, right, rows, inner, cols, out);
}

} // namespace matmul_v4::metal
