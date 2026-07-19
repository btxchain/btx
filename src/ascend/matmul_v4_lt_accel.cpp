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
// CANN was detected (BTX_HAVE_CANN). aclnn two-phase INT8 matmul with
// cubeMathType=KEEP_DTYPE; self-qualify vs ExactGemmS8S8; used_cube_path only
// after Cube ran + matched.

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
#if __has_include(<aclnnop/aclnn_trans_matmul_weight.h>)
#include <aclnnop/aclnn_trans_matmul_weight.h>
#define BTX_ASCEND_HAVE_TRANS_WEIGHT 1
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

[[nodiscard]] bool EnsureAclRuntime(aclrtStream* stream_out)
{
    static std::once_flag once;
    static bool ok = false;
    static aclrtStream stream = nullptr;
    std::call_once(once, [] {
        if (aclInit(nullptr) != ACL_SUCCESS) return;
        if (aclrtSetDevice(0) != ACL_SUCCESS) return;
        if (aclrtCreateStream(&stream) != ACL_SUCCESS) return;
        ok = true;
    });
    if (!ok || !stream) return false;
    *stream_out = stream;
    return true;
}

[[nodiscard]] bool CreateNdTensor(const void* host, size_t elem_bytes, aclDataType dtype,
                                  const std::vector<int64_t>& shape, AclTensorBundle& out)
{
    out.Reset();
    int64_t n_elem = 1;
    for (int64_t d : shape) n_elem *= d;
    out.bytes = static_cast<size_t>(n_elem) * elem_bytes;
    if (aclrtMalloc(&out.device, out.bytes, ACL_MEM_MALLOC_HUGE_FIRST) != ACL_SUCCESS) {
        return false;
    }
    if (host != nullptr) {
        if (aclrtMemcpy(out.device, out.bytes, host, out.bytes, ACL_MEMCPY_HOST_TO_DEVICE) !=
            ACL_SUCCESS) {
            out.Reset();
            return false;
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
    out.tensor = aclCreateTensor(shape.data(), shape.size(), dtype, strides.data(), 0,
                                 ACL_FORMAT_ND, shape.data(), shape.size(), out.device);
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

[[nodiscard]] bool LaunchCubeS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                                  uint32_t rows, uint32_t k, uint32_t cols, std::vector<int32_t>& out)
{
    aclrtStream stream = nullptr;
    if (!EnsureAclRuntime(&stream)) return false;
    if (rows == 0 || k == 0 || cols == 0) {
        out.clear();
        return true;
    }

    const std::vector<int64_t> a_shape{static_cast<int64_t>(rows), static_cast<int64_t>(k)};
    const std::vector<int64_t> b_shape{static_cast<int64_t>(k), static_cast<int64_t>(cols)};
    const std::vector<int64_t> c_shape{static_cast<int64_t>(rows), static_cast<int64_t>(cols)};

    AclTensorBundle a, b, c;
    if (!CreateNdTensor(left.data(), sizeof(int8_t), ACL_INT8, a_shape, a)) return false;
    if (!CreateNdTensor(right.data(), sizeof(int8_t), ACL_INT8, b_shape, b)) return false;
    if (!CreateNdTensor(nullptr, sizeof(int32_t), ACL_INT32, c_shape, c)) return false;

#if defined(BTX_ASCEND_HAVE_TRANS_WEIGHT)
    {
        uint64_t ws = 0;
        aclOpExecutor* ex = nullptr;
        if (aclnnTransMatmulWeightGetWorkspaceSize(b.tensor, &ws, &ex) == ACL_SUCCESS && ex) {
            (void)RunAclnnTwoPhase(ws, ex, stream, aclnnTransMatmulWeight);
        }
    }
#endif

    uint64_t workspace_size = 0;
    aclOpExecutor* executor = nullptr;
    bool launched = false;

#if defined(BTX_ASCEND_HAVE_ACLN_MM)
    if (aclnnMmGetWorkspaceSize(a.tensor, b.tensor, c.tensor, kCubeMathKeepDtype, &workspace_size,
                                &executor) == ACL_SUCCESS &&
        executor != nullptr) {
        launched = RunAclnnTwoPhase(workspace_size, executor, stream, aclnnMm);
    }
#endif

#if defined(BTX_ASCEND_HAVE_ACLN_MATMUL)
    if (!launched) {
        workspace_size = 0;
        executor = nullptr;
        if (aclnnMatmulGetWorkspaceSize(a.tensor, b.tensor, c.tensor, kCubeMathKeepDtype,
                                        &workspace_size, &executor) == ACL_SUCCESS &&
            executor != nullptr) {
            launched = RunAclnnTwoPhase(workspace_size, executor, stream, aclnnMatmul);
        }
    }
#endif

    if (!launched) return false;

    out.assign(static_cast<size_t>(rows) * cols, 0);
    if (aclrtMemcpy(out.data(), out.size() * sizeof(int32_t), c.device, c.bytes,
                    ACL_MEMCPY_DEVICE_TO_HOST) != ACL_SUCCESS) {
        out.clear();
        return false;
    }
    return true;
}

[[nodiscard]] bool FillSelfTestOperands(uint32_t dim, int32_t scale_a, int32_t scale_b,
                                        int32_t bias_a, int32_t bias_b,
                                        std::vector<int8_t>& left, std::vector<int8_t>& right)
{
    left.resize(static_cast<size_t>(dim) * dim);
    right.resize(static_cast<size_t>(dim) * dim);
    for (uint32_t i = 0; i < dim * dim; ++i) {
        left[i] = matmul::v4::lt::FoldInt32ToEmax48(static_cast<int32_t>(i) * scale_a + bias_a);
        right[i] = matmul::v4::lt::FoldInt32ToEmax48(static_cast<int32_t>(i) * scale_b + bias_b);
    }
    return true;
}

[[nodiscard]] bool SelfQualifyCubeOnce()
{
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        struct Case {
            uint32_t dim;
            int32_t sa, sb, ba, bb;
        };
        const Case cases[] = {
            {24, 7, 11, -101, 53},
            {17, 13, -9, 127, -128}, // odd inner
            {32, 31, 29, -127, 126}, // max-|entry|-ish
        };
        for (const Case& c : cases) {
            std::vector<int8_t> left, right;
            FillSelfTestOperands(c.dim, c.sa, c.sb, c.ba, c.bb, left, right);
            const auto cpu = matmul::v4::lt::ExactGemmS8S8(left, right, c.dim, c.dim, c.dim);
            std::vector<int32_t> npu;
            if (!LaunchCubeS8S8(left, right, c.dim, c.dim, c.dim, npu) || npu != cpu) {
                return;
            }
        }
        ok = true;
    });
    return ok;
}

[[nodiscard]] bool DevicePresent()
{
    aclrtStream stream = nullptr;
    return EnsureAclRuntime(&stream);
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
