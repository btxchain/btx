// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <ascend/matmul_v4_lt_accel.h>

#include <matmul/matmul_v4_lt.h>

#include <arith_uint256.h>
#include <primitives/block.h>

#include <cstdint>
#include <mutex>
#include <vector>

// Real Ascend ExactGemm host path. Linked only when BTX_ENABLE_ASCEND=ON and
// CANN was detected (BTX_HAVE_CANN).
//
// Grounded in CANN ≥ 9.1 / Ascend 950PR·DT (dav-3510) ops-nn / ops-math samples:
//   - aclnnMm / aclnnMatmul two-phase (GetWorkspaceSize → execute)
//   - INT8 weight affinity: aclnnCalculateMatmulWeightSize(+V2) +
//     aclnnTransMatmulWeight (optional MatmulWeightNz when headers exist)
//   - cubeMathType = 0 KEEP_DTYPE only (never HF32 / FP down-precision)
//
// Official aclnnMm/Matmul dtype tables list BF16/FP16/FP32; INT8×INT8→INT32
// is attempted and admitted ONLY after process-local ExactGemmS8S8 self-qual.
// used_cube_path is set only when Cube/aclnn ran after that gate.

#if defined(BTX_HAVE_CANN)

#include <acl/acl.h>
#include <aclnn/aclnn_base.h>

#if __has_include(<aclnnop/aclnn_mm.h>)
#include <aclnnop/aclnn_mm.h>
#define BTX_ASCEND_HAVE_ACLN_MM 1
#endif
#if __has_include(<aclnnop/aclnn_matmul.h>)
#include <aclnnop/aclnn_matmul.h>
#define BTX_ASCEND_HAVE_ACLN_MATMUL 1
#endif
#if __has_include(<aclnnop/aclnn_matmul_weight_nz.h>)
#include <aclnnop/aclnn_matmul_weight_nz.h>
#define BTX_ASCEND_HAVE_MATMUL_WEIGHT_NZ 1
#endif
#if __has_include(<aclnnop/aclnn_trans_matmul_weight.h>)
#include <aclnnop/aclnn_trans_matmul_weight.h>
#define BTX_ASCEND_HAVE_TRANS_WEIGHT 1
#endif
#if __has_include(<aclnnop/aclnn_calculate_matmul_weight_size.h>)
#include <aclnnop/aclnn_calculate_matmul_weight_size.h>
#define BTX_ASCEND_HAVE_CALC_WEIGHT_SIZE 1
#elif __has_include(<aclnnop/aclnn_calculate_matmul_weight_size_v2.h>)
#include <aclnnop/aclnn_calculate_matmul_weight_size_v2.h>
#define BTX_ASCEND_HAVE_CALC_WEIGHT_SIZE_V2 1
#endif

#endif // BTX_HAVE_CANN

namespace matmul_v4::ascend {
namespace {

#if defined(BTX_HAVE_CANN)

// cubeMathType: 0=KEEP_DTYPE, 1=ALLOW_FP32_DOWN_PRECISION, 2=USE_FP16,
// 3=USE_HF32, 4=USE_FP32_ADD. ExactGemm forbids down-precision / HF32.
constexpr int8_t kCubeMathKeepDtype = 0;

struct AclTensorBundle {
    void* device{nullptr};
    aclTensor* tensor{nullptr};
    size_t bytes{0};

    void Reset()
    {
        if (tensor) {
            aclDestroyTensor(tensor);
            tensor = nullptr;
        }
        if (device) {
            aclrtFree(device);
            device = nullptr;
        }
        bytes = 0;
    }

    ~AclTensorBundle() { Reset(); }
};

struct AscendRuntime {
    std::mutex mu;
    bool ok{false};
    aclrtStream stream{nullptr};
};

AscendRuntime& Runtime()
{
    static AscendRuntime rt;
    return rt;
}

[[nodiscard]] bool EnsureAclRuntimeLocked(aclrtStream* stream_out)
{
    auto& rt = Runtime();
    if (rt.ok && rt.stream) {
        *stream_out = rt.stream;
        return true;
    }
    if (aclInit(nullptr) != ACL_SUCCESS) return false;
    if (aclrtSetDevice(0) != ACL_SUCCESS) return false;
    if (aclrtCreateStream(&rt.stream) != ACL_SUCCESS) {
        rt.stream = nullptr;
        return false;
    }
    rt.ok = true;
    *stream_out = rt.stream;
    return true;
}

[[nodiscard]] bool CreateNdTensor(const void* host, size_t elem_bytes, aclDataType dtype,
                                  const std::vector<int64_t>& shape, AclTensorBundle& out,
                                  size_t alloc_elems_override = 0)
{
    out.Reset();
    int64_t n_elem = 1;
    for (int64_t d : shape) n_elem *= d;
    const size_t logical_elems = static_cast<size_t>(n_elem);
    const size_t alloc_elems =
        alloc_elems_override > logical_elems ? alloc_elems_override : logical_elems;
    out.bytes = alloc_elems * elem_bytes;
    if (aclrtMalloc(&out.device, out.bytes, ACL_MEM_MALLOC_HUGE_FIRST) != ACL_SUCCESS) {
        return false;
    }
    if (host != nullptr) {
        const size_t host_bytes = logical_elems * elem_bytes;
        if (aclrtMemcpy(out.device, out.bytes, host, host_bytes, ACL_MEMCPY_HOST_TO_DEVICE) !=
            ACL_SUCCESS) {
            out.Reset();
            return false;
        }
        if (out.bytes > host_bytes) {
            if (aclrtMemset(static_cast<char*>(out.device) + host_bytes, out.bytes - host_bytes, 0,
                            out.bytes - host_bytes) != ACL_SUCCESS) {
                out.Reset();
                return false;
            }
        }
    } else if (aclrtMemset(out.device, out.bytes, 0, out.bytes) != ACL_SUCCESS) {
        out.Reset();
        return false;
    }
    std::vector<int64_t> strides(shape.size(), 1);
    for (int64_t i = static_cast<int64_t>(shape.size()) - 2; i >= 0; --i) {
        strides[static_cast<size_t>(i)] =
            shape[static_cast<size_t>(i) + 1] * strides[static_cast<size_t>(i) + 1];
    }
    // Weight-affinity buffers use a 1-D storage shape (CANN TransMatmulWeight sample).
    if (alloc_elems_override > logical_elems) {
        const int64_t storage = static_cast<int64_t>(alloc_elems);
        out.tensor = aclCreateTensor(shape.data(), shape.size(), dtype, strides.data(), 0,
                                     ACL_FORMAT_ND, &storage, 1, out.device);
    } else {
        out.tensor = aclCreateTensor(shape.data(), shape.size(), dtype, strides.data(), 0,
                                     ACL_FORMAT_ND, shape.data(), shape.size(), out.device);
    }
    if (!out.tensor) {
        out.Reset();
        return false;
    }
    return true;
}

[[nodiscard]] bool RunAclnnTwoPhase(uint64_t workspace_size, aclOpExecutor* executor,
                                    aclrtStream stream,
                                    aclError (*execute)(void*, uint64_t, aclOpExecutor*, aclrtStream))
{
    void* workspace = nullptr;
    if (workspace_size > 0) {
        if (aclrtMalloc(&workspace, workspace_size, ACL_MEM_MALLOC_HUGE_FIRST) != ACL_SUCCESS) {
            return false;
        }
    }
    const aclError er = execute(workspace, workspace_size, executor, stream);
    if (workspace) aclrtFree(workspace);
    if (er != ACL_SUCCESS) return false;
    return aclrtSynchronizeStream(stream) == ACL_SUCCESS;
}

[[nodiscard]] bool TryCalculateWeightElems(const std::vector<int64_t>& shape, size_t* elems_out)
{
    *elems_out = 1;
    for (int64_t d : shape) *elems_out *= static_cast<size_t>(d);

#if defined(BTX_ASCEND_HAVE_CALC_WEIGHT_SIZE) || defined(BTX_ASCEND_HAVE_CALC_WEIGHT_SIZE_V2)
    const aclIntArray* arr = aclCreateIntArray(shape.data(), shape.size());
    if (!arr) return false;
    uint64_t size = static_cast<uint64_t>(*elems_out);
    aclError st = ACL_ERROR_FAILURE;
#if defined(BTX_ASCEND_HAVE_CALC_WEIGHT_SIZE_V2)
    st = aclnnCalculateMatmulWeightSizeV2(arr, ACL_INT8, &size);
#elif defined(BTX_ASCEND_HAVE_CALC_WEIGHT_SIZE)
    st = aclnnCalculateMatmulWeightSize(arr, &size);
#endif
    aclDestroyIntArray(arr);
    if (st != ACL_SUCCESS || size == 0) return false;
    *elems_out = static_cast<size_t>(size);
    return true;
#else
    return true; // no calculator — ND size is fine for the plain Mm path
#endif
}

[[nodiscard]] bool TryTransMatmulWeight(aclTensor* weight, aclrtStream stream)
{
#if defined(BTX_ASCEND_HAVE_TRANS_WEIGHT)
    uint64_t ws = 0;
    aclOpExecutor* ex = nullptr;
    if (aclnnTransMatmulWeightGetWorkspaceSize(weight, &ws, &ex) != ACL_SUCCESS || !ex) {
        return false;
    }
    return RunAclnnTwoPhase(ws, ex, stream, aclnnTransMatmulWeight);
#else
    (void)weight;
    (void)stream;
    return false;
#endif
}

[[nodiscard]] bool TryLaunchMmFamily(aclTensor* a, aclTensor* b, aclTensor* c, aclrtStream stream)
{
    uint64_t workspace_size = 0;
    aclOpExecutor* executor = nullptr;

#if defined(BTX_ASCEND_HAVE_ACLN_MM)
    workspace_size = 0;
    executor = nullptr;
    if (aclnnMmGetWorkspaceSize(a, b, c, kCubeMathKeepDtype, &workspace_size, &executor) ==
            ACL_SUCCESS &&
        executor != nullptr) {
        if (RunAclnnTwoPhase(workspace_size, executor, stream, aclnnMm)) return true;
    }
#endif

#if defined(BTX_ASCEND_HAVE_ACLN_MATMUL)
    workspace_size = 0;
    executor = nullptr;
    if (aclnnMatmulGetWorkspaceSize(a, b, c, kCubeMathKeepDtype, &workspace_size, &executor) ==
            ACL_SUCCESS &&
        executor != nullptr) {
        if (RunAclnnTwoPhase(workspace_size, executor, stream, aclnnMatmul)) return true;
    }
#endif

#if defined(BTX_ASCEND_HAVE_MATMUL_WEIGHT_NZ)
    // Prefer after TransMatmulWeight (Atlas A2/A3). Ascend 950 docs prefer
    // NpuFormatCast for NZ; if GetWorkspaceSize rejects INT8, this is a no-op.
    workspace_size = 0;
    executor = nullptr;
    if (aclnnMatmulWeightNzGetWorkspaceSize(a, b, c, kCubeMathKeepDtype, &workspace_size,
                                            &executor) == ACL_SUCCESS &&
        executor != nullptr) {
        if (RunAclnnTwoPhase(workspace_size, executor, stream, aclnnMatmulWeightNz)) return true;
    }
#endif

    return false;
}

[[nodiscard]] bool LaunchCubeS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                                  uint32_t rows, uint32_t k, uint32_t cols, std::vector<int32_t>& out)
{
    std::lock_guard<std::mutex> lock(Runtime().mu);
    aclrtStream stream = nullptr;
    if (!EnsureAclRuntimeLocked(&stream)) return false;
    if (rows == 0 || k == 0 || cols == 0) {
        out.clear();
        return true;
    }
    if (left.size() != static_cast<size_t>(rows) * k ||
        right.size() != static_cast<size_t>(k) * cols) {
        return false;
    }

    const std::vector<int64_t> a_shape{static_cast<int64_t>(rows), static_cast<int64_t>(k)};
    const std::vector<int64_t> b_shape{static_cast<int64_t>(k), static_cast<int64_t>(cols)};
    const std::vector<int64_t> c_shape{static_cast<int64_t>(rows), static_cast<int64_t>(cols)};

    // Path 1: plain ND INT8×INT8→INT32 (KEEP_DTYPE). Works if the toolkit
    // accepts INT8 on Mm/Matmul despite FP-centric public dtype tables.
    {
        AclTensorBundle a, b, c;
        if (CreateNdTensor(left.data(), sizeof(int8_t), ACL_INT8, a_shape, a) &&
            CreateNdTensor(right.data(), sizeof(int8_t), ACL_INT8, b_shape, b) &&
            CreateNdTensor(nullptr, sizeof(int32_t), ACL_INT32, c_shape, c) &&
            TryLaunchMmFamily(a.tensor, b.tensor, c.tensor, stream)) {
            out.assign(static_cast<size_t>(rows) * cols, 0);
            if (aclrtMemcpy(out.data(), out.size() * sizeof(int32_t), c.device, c.bytes,
                            ACL_MEMCPY_DEVICE_TO_HOST) == ACL_SUCCESS) {
                return true;
            }
            out.clear();
        }
    }

    // Path 2: Cube-affinity weight buffer (CalculateMatmulWeightSize +
    // TransMatmulWeight) then Mm / Matmul / MatmulWeightNz. Matches ops-math
    // INT8 weight samples for Ascend 950 / Atlas A2·A3.
    {
        size_t weight_elems = 0;
        if (!TryCalculateWeightElems(b_shape, &weight_elems)) return false;

        AclTensorBundle a, b, c;
        if (!CreateNdTensor(left.data(), sizeof(int8_t), ACL_INT8, a_shape, a)) return false;
        if (!CreateNdTensor(right.data(), sizeof(int8_t), ACL_INT8, b_shape, b, weight_elems)) {
            return false;
        }
        if (!CreateNdTensor(nullptr, sizeof(int32_t), ACL_INT32, c_shape, c)) return false;

        // TransWeight is best-effort: if it fails, still try Mm on the oversized ND buffer.
        (void)TryTransMatmulWeight(b.tensor, stream);

        if (!TryLaunchMmFamily(a.tensor, b.tensor, c.tensor, stream)) return false;

        out.assign(static_cast<size_t>(rows) * cols, 0);
        if (aclrtMemcpy(out.data(), out.size() * sizeof(int32_t), c.device, c.bytes,
                        ACL_MEMCPY_DEVICE_TO_HOST) != ACL_SUCCESS) {
            out.clear();
            return false;
        }
        return true;
    }
}

void FillSelfTestOperands(uint32_t rows, uint32_t inner, uint32_t cols, int32_t scale_a,
                          int32_t scale_b, int32_t bias_a, int32_t bias_b,
                          std::vector<int8_t>& left, std::vector<int8_t>& right)
{
    // FoldInt32ToEmax48 here is GEMM self-qual filler only — NOT Lever-B MX Extract.
    left.resize(static_cast<size_t>(rows) * inner);
    right.resize(static_cast<size_t>(inner) * cols);
    for (uint32_t i = 0; i < rows * inner; ++i) {
        left[i] = matmul::v4::lt::FoldInt32ToEmax48(static_cast<int32_t>(i) * scale_a + bias_a);
    }
    for (uint32_t i = 0; i < inner * cols; ++i) {
        right[i] = matmul::v4::lt::FoldInt32ToEmax48(static_cast<int32_t>(i) * scale_b + bias_b);
    }
}

void FillCornerOperands(uint32_t dim, std::vector<int8_t>& left, std::vector<int8_t>& right)
{
    // Max-|entry| corners: ±127 on diagonal / anti-diagonal; stresses Cube
    // accumulate order vs ExactGemmS8S8.
    left.assign(static_cast<size_t>(dim) * dim, 0);
    right.assign(static_cast<size_t>(dim) * dim, 0);
    for (uint32_t i = 0; i < dim; ++i) {
        left[static_cast<size_t>(i) * dim + i] = 127;
        right[static_cast<size_t>(i) * dim + i] = -127;
        left[static_cast<size_t>(i) * dim + (dim - 1 - i)] = -127;
        right[static_cast<size_t>((dim - 1 - i)) * dim + i] = 127;
    }
}

[[nodiscard]] bool MatchCubeVsCpu(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                                  uint32_t rows, uint32_t inner, uint32_t cols)
{
    const auto cpu = matmul::v4::lt::ExactGemmS8S8(left, right, rows, inner, cols);
    std::vector<int32_t> npu;
    if (!LaunchCubeS8S8(left, right, rows, inner, cols, npu)) return false;
    return npu == cpu;
}

[[nodiscard]] bool SelfQualifyCubeOnce()
{
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        struct Case {
            uint32_t rows, inner, cols;
            int32_t sa, sb, ba, bb;
        };
        // Odd inner (odd accumulator length) + MatExpand-like rectangular panels.
        const Case cases[] = {
            {24, 24, 24, 7, 11, -101, 53},
            {17, 17, 17, 13, -9, 127, -128}, // odd square
            {19, 19, 19, 3, 5, -127, 126},   // odd square, large |entry|
            {16, 17, 16, 11, -7, 64, -63},   // odd K rectangular
            {32, 24, 32, 31, 29, -127, 126}, // MatExpand-ish panel
        };
        for (const Case& c : cases) {
            std::vector<int8_t> left, right;
            FillSelfTestOperands(c.rows, c.inner, c.cols, c.sa, c.sb, c.ba, c.bb, left, right);
            if (!MatchCubeVsCpu(left, right, c.rows, c.inner, c.cols)) return;
        }
        // Explicit max-|entry| corner matrices (odd + even).
        for (const uint32_t dim : {17u, 32u}) {
            std::vector<int8_t> left, right;
            FillCornerOperands(dim, left, right);
            if (!MatchCubeVsCpu(left, right, dim, dim, dim)) return;
        }
        ok = true;
    });
    return ok;
}

[[nodiscard]] bool DevicePresent()
{
    std::lock_guard<std::mutex> lock(Runtime().mu);
    aclrtStream stream = nullptr;
    return EnsureAclRuntimeLocked(&stream);
}

#endif // BTX_HAVE_CANN

} // namespace

bool IsAscendExactGemmAvailable()
{
#if defined(BTX_HAVE_CANN)
    if (!DevicePresent()) return false;
    return SelfQualifyCubeOnce();
#else
    return false;
#endif
}

bool ExactGemmS8S8Ascend(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                         uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out,
                         bool* used_cube_path)
{
    if (used_cube_path) *used_cube_path = false;
#if defined(BTX_HAVE_CANN)
    // Hard gate: never set used_cube_path without process-local ExactGemm match.
    if (!IsAscendExactGemmAvailable()) {
        out.clear();
        return false;
    }
    std::vector<int32_t> npu;
    if (!LaunchCubeS8S8(left, right, rows, inner, cols, npu)) {
        out.clear();
        return false;
    }
    out = std::move(npu);
    if (used_cube_path) *used_cube_path = true;
    return true;
#else
    (void)left;
    (void)right;
    (void)rows;
    (void)inner;
    (void)cols;
    out.clear();
    return false;
#endif
}

bool ExactGemmS32S8Ascend(const std::vector<int32_t>& /*left*/, const std::vector<int8_t>& /*right*/,
                          uint32_t /*rows*/, uint32_t /*inner*/, uint32_t /*cols*/,
                          std::vector<int32_t>& out, bool* used_cube_path)
{
    // No proven Cube INT32×INT8→INT32 aclnn path yet (same stance as CUDA IMMA
    // for S32S8). Callers must use CPU ExactGemmS32S8; never set used_cube_path.
    out.clear();
    if (used_cube_path) *used_cube_path = false;
    return false;
}

bool TryLaunchLtCubeGemmS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                             uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    bool used_cube = false;
    return ExactGemmS8S8Ascend(left, right, rows, inner, cols, out, &used_cube) && used_cube;
}

bool TryLaunchLtCubeGemmS32S8(const std::vector<int32_t>& left, const std::vector<int8_t>& right,
                              uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    bool used_cube = false;
    return ExactGemmS32S8Ascend(left, right, rows, inner, cols, out, &used_cube) && used_cube;
}

bool ComputeDigestsOnlyLTAscend(const CBlockHeader& tmpl, uint32_t n, const uint64_t* nonces,
                                size_t count, std::vector<matmul::v4::lt::DigestOnlyResultLT>& out)
{
    out.clear();
    if (!IsAscendExactGemmAvailable() || nonces == nullptr || count == 0) {
        return false;
    }

    matmul::v4::lt::ExactGemmBackend backend;
    backend.gemm_s8s8 = &TryLaunchLtCubeGemmS8S8;
    // S32S8 stays null → MatExpand falls back to CPU ExactGemmS32S8.

    const matmul::v4::lt::WindowSketchMinerLT miner{tmpl, n, backend};
    if (!miner.Valid()) return false;

    std::vector<uint64_t> nonce_vec(nonces, nonces + count);
    const uint256 kNoTarget = ArithToUint256(~arith_uint256{});
    if (!miner.Mine(nonce_vec, kNoTarget, out) || out.size() != count) {
        out.clear();
        return false;
    }
    return true;
}

} // namespace matmul_v4::ascend
