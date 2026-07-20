// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <ascend/matmul_v4_lt_accel.h>

#include <matmul/exact_gemm_radix.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_lt_mx_exact.h>

#include <primitives/block.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <vector>

// Real Ascend ExactGemm host path. Linked only when BTX_ENABLE_ASCEND=ON and
// CANN was detected (BTX_HAVE_CANN).
//
// CANN 9.1 documents the exact integer mode used here:
//   aclnnQuantMatmulV5(INT8, INT8, x2Scale=FLOAT32(1), out=INT32, bias=null)
// has semantics out = x1 @ x2 and all scale inputs are ignored. Supplying the
// scale tensor satisfies the operator's documented dtype table. This is a
// materially stronger contract than attempting INT8 through aclnnMm/Matmul,
// whose public dtype contract is floating-point on released toolkits.
//
// Device and page-locked host allocations, the stream, and the largest
// workspace are retained process-wide. H2D, zero-fill, the Cube operator, and
// D2H are ordered on one stream and require only one terminal synchronization.
// Shape-specific aclOpExecutor objects are intentionally not retained here:
// CANN requires explicit repeatability admission, and an NZ-transforming plan
// is not unconditionally repeatable. CANN's opbase cache may still cache the
// phase-1 plan/tiling internally (controlled by ACLNN_CACHE_LIMIT).

#if defined(BTX_HAVE_CANN)

#include <acl/acl.h>
#include <aclnn/aclnn_base.h>

#if __has_include(<aclnnop/aclnn_quant_matmul_v5.h>)
#include <aclnnop/aclnn_quant_matmul_v5.h>
#define BTX_ASCEND_HAVE_QUANT_MATMUL_V5 1
#endif

// Require the documented AI-processor-affine NZ conversion as part of the
// native-path proof. An ND-only launch may be arithmetically exact but is not
// admitted as a proven Cube path by this backend.
#if __has_include(<aclnnop/aclnn_trans_matmul_weight.h>)
#include <aclnnop/aclnn_trans_matmul_weight.h>
#define BTX_ASCEND_HAVE_TRANS_WEIGHT 1
#endif
#if __has_include(<aclnnop/aclnn_calculate_matmul_weight_size_v2.h>)
#include <aclnnop/aclnn_calculate_matmul_weight_size_v2.h>
#define BTX_ASCEND_HAVE_CALC_WEIGHT_SIZE_V2 1
#endif

#endif // BTX_HAVE_CANN

namespace matmul_v4::ascend {
namespace {

#if defined(BTX_HAVE_CANN)

constexpr uint32_t kMaxDocumentedMatrixAxis = 65535;

[[nodiscard]] bool CheckedMul(size_t a, size_t b, size_t* out)
{
    if (a != 0 && b > std::numeric_limits<size_t>::max() / a) return false;
    *out = a * b;
    return true;
}

struct DeviceBuffer {
    void* data{nullptr};
    size_t capacity{0};

    [[nodiscard]] bool Ensure(size_t bytes)
    {
        if (bytes <= capacity) return true;
        void* replacement = nullptr;
        if (aclrtMalloc(&replacement, bytes, ACL_MEM_MALLOC_HUGE_FIRST) != ACL_SUCCESS) {
            return false;
        }
        if (data) aclrtFree(data);
        data = replacement;
        capacity = bytes;
        return true;
    }

    void Reset()
    {
        if (data) aclrtFree(data);
        data = nullptr;
        capacity = 0;
    }
};

struct PinnedHostBuffer {
    void* data{nullptr};
    size_t capacity{0};

    [[nodiscard]] bool Ensure(size_t bytes)
    {
        if (bytes <= capacity) return true;
        void* replacement = nullptr;
        if (aclrtMallocHost(&replacement, bytes) != ACL_SUCCESS) return false;
        if (data) aclrtFreeHost(data);
        data = replacement;
        capacity = bytes;
        return true;
    }

    void Reset()
    {
        if (data) aclrtFreeHost(data);
        data = nullptr;
        capacity = 0;
    }
};

struct AscendRuntime {
    std::mutex mu;
    bool init_attempted{false};
    bool acl_initialized{false};
    bool ok{false};
    aclrtStream stream{nullptr};
    DeviceBuffer a;
    DeviceBuffer b;
    DeviceBuffer c;
    DeviceBuffer scale;
    DeviceBuffer workspace;
    PinnedHostBuffer host_a;
    PinnedHostBuffer host_b;
    PinnedHostBuffer host_c;
    PinnedHostBuffer host_scale;

    ~AscendRuntime()
    {
        if (!ok) return;
        if (stream) aclrtSynchronizeStream(stream);
        workspace.Reset();
        scale.Reset();
        c.Reset();
        b.Reset();
        a.Reset();
        host_c.Reset();
        host_scale.Reset();
        host_b.Reset();
        host_a.Reset();
        if (stream) aclrtDestroyStream(stream);
    }
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
    if (!rt.init_attempted) {
        rt.init_attempted = true;
        rt.acl_initialized = aclInit(nullptr) == ACL_SUCCESS;
    }
    if (!rt.acl_initialized) return false;
    uint32_t device_count = 0;
    if (aclrtGetDeviceCount(&device_count) != ACL_SUCCESS || device_count == 0) return false;
    if (aclrtSetDevice(0) != ACL_SUCCESS) return false;
    if (aclrtCreateStream(&rt.stream) != ACL_SUCCESS) {
        rt.stream = nullptr;
        return false;
    }
    rt.ok = true;
    *stream_out = rt.stream;
    return true;
}

struct AclTensorView {
    aclTensor* tensor{nullptr};

    AclTensorView() = default;
    AclTensorView(const AclTensorView&) = delete;
    AclTensorView& operator=(const AclTensorView&) = delete;
    ~AclTensorView()
    {
        if (tensor) aclDestroyTensor(tensor);
    }
};

[[nodiscard]] bool CreateTensorView(void* device, aclDataType dtype,
                                    const std::vector<int64_t>& shape, AclTensorView& out,
                                    size_t storage_elems = 0)
{
    if (shape.empty() || !device) return false;
    size_t logical_elems = 1;
    for (const int64_t d : shape) {
        if (d <= 0 || !CheckedMul(logical_elems, static_cast<size_t>(d), &logical_elems)) {
            return false;
        }
    }
    if (storage_elems < logical_elems) storage_elems = logical_elems;

    std::vector<int64_t> strides(shape.size(), 1);
    for (size_t i = shape.size(); i-- > 1;) {
        strides[i - 1] = shape[i] * strides[i];
    }
    const int64_t storage = static_cast<int64_t>(storage_elems);
    if (storage_elems > logical_elems) {
        out.tensor = aclCreateTensor(shape.data(), shape.size(), dtype, strides.data(), 0,
                                     ACL_FORMAT_ND, &storage, 1, device);
    } else {
        out.tensor = aclCreateTensor(shape.data(), shape.size(), dtype, strides.data(), 0,
                                     ACL_FORMAT_ND, shape.data(), shape.size(), device);
    }
    return out.tensor != nullptr;
}

[[nodiscard]] bool CalculateWeightElements(const std::vector<int64_t>& shape,
                                           size_t logical_elems, size_t* storage_elems)
{
    *storage_elems = logical_elems;
#if defined(BTX_ASCEND_HAVE_CALC_WEIGHT_SIZE_V2)
    const aclIntArray* arr = aclCreateIntArray(shape.data(), shape.size());
    if (!arr) return false;
    uint64_t elements = 0;
    const aclError status = aclnnCalculateMatmulWeightSizeV2(arr, ACL_INT8, &elements);
    aclDestroyIntArray(arr);
    if (status != ACL_SUCCESS || elements < logical_elems ||
        elements > std::numeric_limits<size_t>::max()) {
        return false;
    }
    *storage_elems = static_cast<size_t>(elements);
#endif
    return true;
}

[[nodiscard]] bool EnsureLaunchBuffersLocked(size_t a_bytes, size_t b_bytes,
                                             size_t c_bytes, size_t workspace_bytes)
{
    auto& rt = Runtime();
    return rt.a.Ensure(a_bytes) && rt.b.Ensure(b_bytes) && rt.c.Ensure(c_bytes) &&
           rt.scale.Ensure(sizeof(float)) &&
           rt.host_a.Ensure(a_bytes) && rt.host_b.Ensure(b_bytes) &&
           rt.host_c.Ensure(c_bytes) && rt.host_scale.Ensure(sizeof(float)) &&
           (workspace_bytes == 0 || rt.workspace.Ensure(workspace_bytes));
}

[[nodiscard]] bool EnqueueInputsLocked(const void* left, size_t left_bytes,
                                       const void* right, size_t right_bytes,
                                       size_t right_storage_bytes, aclrtStream stream)
{
    auto& rt = Runtime();
    std::memcpy(rt.host_a.data, left, left_bytes);
    std::memcpy(rt.host_b.data, right, right_bytes);
    const float unit_scale = 1.0F;
    std::memcpy(rt.host_scale.data, &unit_scale, sizeof(unit_scale));

    // The weight transform consumes padded storage. Clear it before copying
    // the logical matrix so stale bytes from a prior launch cannot affect NZ.
    if (aclrtMemsetAsync(rt.b.data, rt.b.capacity, 0, right_storage_bytes, stream) != ACL_SUCCESS) {
        return false;
    }
    return aclrtMemcpyAsync(rt.a.data, rt.a.capacity, rt.host_a.data, left_bytes,
                            ACL_MEMCPY_HOST_TO_DEVICE, stream) == ACL_SUCCESS &&
           aclrtMemcpyAsync(rt.b.data, rt.b.capacity, rt.host_b.data, right_bytes,
                            ACL_MEMCPY_HOST_TO_DEVICE, stream) == ACL_SUCCESS &&
           aclrtMemcpyAsync(rt.scale.data, rt.scale.capacity, rt.host_scale.data,
                            sizeof(unit_scale), ACL_MEMCPY_HOST_TO_DEVICE, stream) == ACL_SUCCESS;
}

[[nodiscard]] bool GetTransformPlan(aclTensor* weight, uint64_t* workspace_size,
                                    aclOpExecutor** executor)
{
#if defined(BTX_ASCEND_HAVE_TRANS_WEIGHT) && defined(BTX_ASCEND_HAVE_CALC_WEIGHT_SIZE_V2)
    return aclnnTransMatmulWeightGetWorkspaceSize(weight, workspace_size, executor) == ACL_SUCCESS &&
           *executor != nullptr;
#else
    (void)weight;
    (void)workspace_size;
    (void)executor;
    return false;
#endif
}

[[nodiscard]] bool ExecuteTransform(void* workspace, uint64_t workspace_size,
                                    aclOpExecutor* executor, aclrtStream stream)
{
#if defined(BTX_ASCEND_HAVE_TRANS_WEIGHT) && defined(BTX_ASCEND_HAVE_CALC_WEIGHT_SIZE_V2)
    return aclnnTransMatmulWeight(workspace, workspace_size, executor, stream) == ACL_SUCCESS;
#else
    (void)workspace;
    (void)workspace_size;
    (void)executor;
    (void)stream;
    return false;
#endif
}

[[nodiscard]] bool GetExactQuantMatmulPlan(aclTensor* a, aclTensor* b,
                                           aclTensor* x2_scale, aclTensor* c,
                                           uint64_t* workspace_size,
                                           aclOpExecutor** executor)
{
#if defined(BTX_ASCEND_HAVE_QUANT_MATMUL_V5)
    // CANN 9.1 exact raw mode: with INT8 x1/x2 and INT32 output, scales do not
    // participate and nullptr bias gives out = x1 @ x2. The documented dtype
    // table still requires x2Scale for this combination, so supply a stable
    // FLOAT32 scalar with value 1 rather than relying on a rejected nullptr.
    return aclnnQuantMatmulV5GetWorkspaceSize(
               a, b,
               /*x1Scale=*/nullptr, x2_scale, /*yScale=*/nullptr,
               /*x1Offset=*/nullptr, /*x2Offset=*/nullptr, /*yOffset=*/nullptr,
               /*bias=*/nullptr, /*transposeX1=*/false, /*transposeX2=*/false,
               /*groupSize=*/0, c, workspace_size, executor) == ACL_SUCCESS &&
           *executor != nullptr;
#else
    (void)a;
    (void)b;
    (void)x2_scale;
    (void)c;
    (void)workspace_size;
    (void)executor;
    return false;
#endif
}

[[nodiscard]] bool ExecuteExactQuantMatmul(void* workspace, uint64_t workspace_size,
                                           aclOpExecutor* executor, aclrtStream stream)
{
#if defined(BTX_ASCEND_HAVE_QUANT_MATMUL_V5)
    return aclnnQuantMatmulV5(workspace, workspace_size, executor, stream) == ACL_SUCCESS;
#else
    (void)workspace;
    (void)workspace_size;
    (void)executor;
    (void)stream;
    return false;
#endif
}

[[nodiscard]] bool LaunchCubeS8S8(const std::vector<int8_t>& left,
                                  const std::vector<int8_t>& right,
                                  uint32_t rows, uint32_t inner, uint32_t cols,
                                  std::vector<int32_t>& out)
{
#if !defined(BTX_ASCEND_HAVE_QUANT_MATMUL_V5) || \
    !defined(BTX_ASCEND_HAVE_TRANS_WEIGHT) || \
    !defined(BTX_ASCEND_HAVE_CALC_WEIGHT_SIZE_V2)
    (void)left;
    (void)right;
    (void)rows;
    (void)inner;
    (void)cols;
    out.clear();
    return false;
#else
    out.clear();
    if (rows == 0 || inner == 0 || cols == 0 ||
        rows > kMaxDocumentedMatrixAxis || inner > kMaxDocumentedMatrixAxis ||
        cols > kMaxDocumentedMatrixAxis) {
        return false;
    }

    size_t a_elems = 0, b_elems = 0, c_elems = 0, c_bytes = 0;
    if (!CheckedMul(rows, inner, &a_elems) || !CheckedMul(inner, cols, &b_elems) ||
        !CheckedMul(rows, cols, &c_elems) ||
        !CheckedMul(c_elems, sizeof(int32_t), &c_bytes) ||
        left.size() != a_elems || right.size() != b_elems) {
        return false;
    }

    std::lock_guard<std::mutex> lock(Runtime().mu);
    aclrtStream stream = nullptr;
    if (!EnsureAclRuntimeLocked(&stream)) return false;

    const std::vector<int64_t> a_shape{static_cast<int64_t>(rows),
                                        static_cast<int64_t>(inner)};
    const std::vector<int64_t> b_shape{static_cast<int64_t>(inner),
                                        static_cast<int64_t>(cols)};
    const std::vector<int64_t> c_shape{static_cast<int64_t>(rows),
                                        static_cast<int64_t>(cols)};

    size_t b_storage_elems = b_elems;
    if (!CalculateWeightElements(b_shape, b_elems, &b_storage_elems)) return false;

    if (!EnsureLaunchBuffersLocked(a_elems, b_storage_elems, c_bytes, 0)) return false;

    AclTensorView a;
    AclTensorView b;
    AclTensorView c;
    AclTensorView scale;
    if (!CreateTensorView(Runtime().a.data, ACL_INT8, a_shape, a) ||
        !CreateTensorView(Runtime().b.data, ACL_INT8, b_shape, b, b_storage_elems) ||
        !CreateTensorView(Runtime().c.data, ACL_INT32, c_shape, c) ||
        !CreateTensorView(Runtime().scale.data, ACL_FLOAT, {1}, scale)) {
        return false;
    }

    // NZ is required because it is the documented AI-processor-affine weight
    // path. Do not advertise an ND-only launch as proven native Cube work.
    uint64_t transform_workspace = 0;
    aclOpExecutor* transform_executor = nullptr;
    if (!GetTransformPlan(b.tensor, &transform_workspace, &transform_executor)) return false;

    uint64_t gemm_workspace = 0;
    aclOpExecutor* gemm_executor = nullptr;
    if (!GetExactQuantMatmulPlan(a.tensor, b.tensor, scale.tensor, c.tensor,
                                 &gemm_workspace, &gemm_executor)) {
        return false;
    }

    const uint64_t required_workspace = std::max(transform_workspace, gemm_workspace);
    if (required_workspace > std::numeric_limits<size_t>::max() ||
        !EnsureLaunchBuffersLocked(a_elems, b_storage_elems, c_bytes,
                                   static_cast<size_t>(required_workspace))) {
        return false;
    }
    void* workspace = required_workspace == 0 ? nullptr : Runtime().workspace.data;

    if (!EnqueueInputsLocked(left.data(), a_elems, right.data(), b_elems,
                             b_storage_elems, stream)) {
        (void)aclrtSynchronizeStream(stream);
        return false;
    }
    if (!ExecuteTransform(workspace, transform_workspace, transform_executor, stream)) {
        (void)aclrtSynchronizeStream(stream);
        return false;
    }
    if (!ExecuteExactQuantMatmul(workspace, gemm_workspace, gemm_executor, stream)) {
        (void)aclrtSynchronizeStream(stream);
        return false;
    }
    if (aclrtMemcpyAsync(Runtime().host_c.data, Runtime().host_c.capacity,
                         Runtime().c.data, c_bytes, ACL_MEMCPY_DEVICE_TO_HOST, stream) != ACL_SUCCESS ||
        aclrtSynchronizeStream(stream) != ACL_SUCCESS) {
        return false;
    }

    out.resize(c_elems);
    std::memcpy(out.data(), Runtime().host_c.data, c_bytes);
    return true;
#endif
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

void FillCornerOperands(uint32_t rows, uint32_t inner, uint32_t cols,
                        std::vector<int8_t>& left, std::vector<int8_t>& right)
{
    left.resize(static_cast<size_t>(rows) * inner);
    right.resize(static_cast<size_t>(inner) * cols);
    for (size_t i = 0; i < left.size(); ++i) {
        left[i] = (i & 1U) ? int8_t{-128} : int8_t{127};
    }
    for (size_t i = 0; i < right.size(); ++i) {
        right[i] = (i & 2U) ? int8_t{-128} : int8_t{127};
    }
}

[[nodiscard]] bool MatchCubeVsCpu(const std::vector<int8_t>& left,
                                  const std::vector<int8_t>& right,
                                  uint32_t rows, uint32_t inner, uint32_t cols)
{
    const auto cpu = matmul::v4::lt::ExactGemmS8S8(left, right, rows, inner, cols);
    std::vector<int32_t> npu;
    return LaunchCubeS8S8(left, right, rows, inner, cols, npu) && npu == cpu;
}

[[nodiscard]] bool SelfQualifyCubeOnce()
{
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
#if !defined(BTX_ASCEND_HAVE_QUANT_MATMUL_V5) || \
    !defined(BTX_ASCEND_HAVE_TRANS_WEIGHT) || \
    !defined(BTX_ASCEND_HAVE_CALC_WEIGHT_SIZE_V2)
        return;
#else
        struct Case {
            uint32_t rows, inner, cols;
            int32_t sa, sb, ba, bb;
        };
        // Include odd axes (padding/cropping), rectangular panels, and aligned
        // Cube shapes. Exactness is assessed byte-for-byte against CPU.
        const Case cases[] = {
            {24, 24, 24, 7, 11, -101, 53},
            {17, 17, 17, 13, -9, 127, -128},
            {16, 17, 16, 11, -7, 64, -63},
            {31, 33, 29, 3, 5, -127, 126},
            {32, 64, 48, 31, 29, -127, 126},
        };
        for (const Case& c : cases) {
            std::vector<int8_t> left, right;
            FillSelfTestOperands(c.rows, c.inner, c.cols, c.sa, c.sb, c.ba, c.bb, left, right);
            if (!MatchCubeVsCpu(left, right, c.rows, c.inner, c.cols)) return;
        }

        // Dense max-|entry| operands exercise long positive/negative sums and
        // would expose saturation or narrowing before the INT32 output.
        for (const Case& c : {Case{17, 65, 19, 0, 0, 0, 0},
                              Case{32, 256, 32, 0, 0, 0, 0}}) {
            std::vector<int8_t> left, right;
            FillCornerOperands(c.rows, c.inner, c.cols, left, right);
            if (!MatchCubeVsCpu(left, right, c.rows, c.inner, c.cols)) return;
        }
        ok = true;
#endif
    });
    return ok;
}

[[nodiscard]] bool DevicePresent()
{
    std::lock_guard<std::mutex> lock(Runtime().mu);
    aclrtStream stream = nullptr;
    return EnsureAclRuntimeLocked(&stream);
}

// ---------------------------------------------------------------------------
// Exact MX scale-partitioned B̂·V: four Cube ExactGemm passes via the shared
// ComputeProjectedRightMxScalePartitionedGemmLT helper (e∈{0..3}, shift, sum).
// Bit-identical to ComputeProjectedRightMxBlockScaleLT under Lever-B.
// ---------------------------------------------------------------------------

[[nodiscard]] bool LaunchCubeMxScalePartitioned(const std::vector<int8_t>& mu,
                                                const std::vector<uint8_t>& scales,
                                                const std::vector<int8_t>& V, uint32_t n,
                                                uint32_t m, std::vector<int32_t>& out)
{
    out.clear();
    if (n == 0 || m == 0 || (n % matmul::v4::lt::kMatExpandMxBlockLen) != 0) return false;

    matmul::v4::lt::ExactGemmBackend gemm;
    // Direct Cube launch: caller has already gated ExactGemm + MX self-qual.
    gemm.gemm_s8s8 = [](const std::vector<int8_t>& L, const std::vector<int8_t>& R,
                        uint32_t rows, uint32_t inner, uint32_t cols,
                        std::vector<int32_t>& product) -> bool {
        return LaunchCubeS8S8(L, R, rows, inner, cols, product);
    };

    out = matmul::v4::lt::ComputeProjectedRightMxScalePartitionedGemmLT(mu, scales, V, n, m,
                                                                        gemm);
    if (out.size() != static_cast<size_t>(n) * m) {
        out.clear();
        return false;
    }
    return true;
}

void FillMxSelfTestOperands(uint32_t n, uint32_t m, std::vector<int8_t>& mu,
                            std::vector<uint8_t>& scales, std::vector<int8_t>& V)
{
    const uint32_t nblk = n / matmul::v4::lt::kMatExpandMxBlockLen;
    mu.resize(static_cast<size_t>(n) * n);
    scales.resize(static_cast<size_t>(n) * nblk);
    V.resize(static_cast<size_t>(n) * m);
    // M11-ish mantissas in [-6,6] and e∈{0..3} — Lever-B alphabet shape only.
    for (size_t i = 0; i < mu.size(); ++i) {
        mu[i] = static_cast<int8_t>((static_cast<int32_t>(i) % 13) - 6);
    }
    for (size_t i = 0; i < scales.size(); ++i) {
        scales[i] = static_cast<uint8_t>(i & 0x3U);
    }
    for (size_t i = 0; i < V.size(); ++i) {
        V[i] = static_cast<int8_t>((static_cast<int32_t>(i) % 11) - 5);
    }
}

[[nodiscard]] bool MatchMxCubeVsCpu(const std::vector<int8_t>& mu,
                                    const std::vector<uint8_t>& scales,
                                    const std::vector<int8_t>& V, uint32_t n, uint32_t m)
{
    const auto cpu =
        matmul::v4::lt::ComputeProjectedRightMxBlockScaleLT(mu, scales, V, n, m);
    std::vector<int32_t> npu;
    return LaunchCubeMxScalePartitioned(mu, scales, V, n, m, npu) && npu == cpu;
}

[[nodiscard]] bool SelfQualifyMxProjectionOnce()
{
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        if (!SelfQualifyCubeOnce()) return;
        // Cover one MX-block axis, a rectangular deep-m panel, and a denser
        // 64×32 case. Exactness is byte-for-byte vs the CPU oracle.
        const struct {
            uint32_t n, m;
        } cases[] = {{32, 16}, {32, 32}, {64, 32}};
        for (const auto& c : cases) {
            std::vector<int8_t> mu, V;
            std::vector<uint8_t> scales;
            FillMxSelfTestOperands(c.n, c.m, mu, scales, V);
            if (!MatchMxCubeVsCpu(mu, scales, V, c.n, c.m)) return;
        }
        ok = true;
    });
    return ok;
}

// Attempt to detect a native CANN FP8/MX matmul header. Presence alone does
// NOT qualify — native_mx_qualified stays false until an ExactGemm/oracle
// self-qual path is wired. This probe only documents that we looked.
[[nodiscard]] bool CannNativeMxHeadersPresent()
{
#if __has_include(<aclnnop/aclnn_quant_matmul_v5.h>)
    // No released public CANN API is admitted here as OCP-MX / committed-E8M0
    // ExactGemm for Lever-B. Keep the probe compile-clean and fail-closed.
    return false;
#else
    return false;
#endif
}

[[nodiscard]] bool TryNativeMxProjection()
{
    // Optional FP8/MX CANN ops: refused until a documented raw-integer contract
    // plus CPU-oracle self-qual exists. Never label a float path as native MX.
    (void)CannNativeMxHeadersPresent();
    return false;
}

#endif // BTX_HAVE_CANN

LtAscendDigestProvenance g_last_provenance{};

} // namespace

bool GetAscendRuntimeSocName(std::string& out)
{
    out.clear();
#if defined(BTX_HAVE_CANN)
    std::lock_guard<std::mutex> lock(Runtime().mu);
    aclrtStream stream = nullptr;
    if (!EnsureAclRuntimeLocked(&stream)) return false;
    const char* soc = aclrtGetSocName();
    if (soc == nullptr || soc[0] == '\0') return false;
    out = soc;
    return true;
#else
    return false;
#endif
}

bool IsAscendExactGemmAvailable()
{
#if defined(BTX_HAVE_CANN)
    return DevicePresent() && SelfQualifyCubeOnce();
#else
    return false;
#endif
}

bool ExactGemmS8S8Ascend(const std::vector<int8_t>& left,
                         const std::vector<int8_t>& right,
                         uint32_t rows, uint32_t inner, uint32_t cols,
                         std::vector<int32_t>& out, bool* used_cube_path)
{
    if (used_cube_path) *used_cube_path = false;
#if defined(BTX_HAVE_CANN)
    // Hard gate: never advertise the native path before the process-local
    // exact raw INT8->INT32 V5 qualification has passed.
    if (!IsAscendExactGemmAvailable() ||
        !LaunchCubeS8S8(left, right, rows, inner, cols, out)) {
        out.clear();
        return false;
    }
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

bool ExactGemmS32S8Ascend(const std::vector<int32_t>& left,
                          const std::vector<int8_t>& right,
                          uint32_t rows, uint32_t inner, uint32_t cols,
                          std::vector<int32_t>& out, bool* used_cube_path)
{
    out.clear();
    if (used_cube_path) *used_cube_path = false;
#if defined(BTX_HAVE_CANN)
    if (!IsAscendExactGemmAvailable()) return false;
    const bool ok = matmul::v4::lt::ExactGemmS32S8ViaRadix256(
        left, right, rows, inner, cols, out,
        [](const std::vector<int8_t>& plane,
           const std::vector<int8_t>& rhs,
           uint32_t m, uint32_t k, uint32_t n,
           std::vector<int32_t>& product) {
            // Availability and whole-device exactness were gated above. Calling
            // the launch primitive directly avoids four redundant self-qual checks.
            return LaunchCubeS8S8(plane, rhs, m, k, n, product);
        });
    if (!ok) return false;
    if (used_cube_path) *used_cube_path = true;
    return true;
#else
    (void)left;
    (void)right;
    (void)rows;
    (void)inner;
    (void)cols;
    return false;
#endif
}

bool TryLaunchLtCubeGemmS8S8(const std::vector<int8_t>& left,
                             const std::vector<int8_t>& right,
                             uint32_t rows, uint32_t inner, uint32_t cols,
                             std::vector<int32_t>& out)
{
    bool used_cube = false;
    return ExactGemmS8S8Ascend(left, right, rows, inner, cols, out, &used_cube) && used_cube;
}

bool TryLaunchLtCubeGemmS32S8(const std::vector<int32_t>& left,
                              const std::vector<int8_t>& right,
                              uint32_t rows, uint32_t inner, uint32_t cols,
                              std::vector<int32_t>& out)
{
    bool used_cube = false;
    return ExactGemmS32S8Ascend(left, right, rows, inner, cols, out, &used_cube) && used_cube;
}

bool IsAscendExactMxProjectionAvailable()
{
#if defined(BTX_HAVE_CANN)
    return IsAscendExactGemmAvailable() && SelfQualifyMxProjectionOnce();
#else
    return false;
#endif
}

bool ComputeProjectedRightMxBlockScaleLTAscend(
    const std::vector<int8_t>& mu, const std::vector<uint8_t>& scales,
    const std::vector<int8_t>& V, uint32_t n, uint32_t m, std::vector<int32_t>& out,
    LtAscendDigestProvenance* provenance)
{
    out.clear();
    if (provenance) *provenance = {};
    g_last_provenance = {};
#if defined(BTX_HAVE_CANN)
    // Prefer a proven native MX/FP8 CANN op only after ExactGemm+oracle qual.
    // None is admitted today — TryNativeMxProjection always returns false.
    if (TryNativeMxProjection()) {
        // Unreachable until a native lane is wired and self-qualified.
        return false;
    }
    if (!IsAscendExactMxProjectionAvailable() ||
        !LaunchCubeMxScalePartitioned(mu, scales, V, n, m, out)) {
        out.clear();
        return false;
    }
    LtAscendDigestProvenance p;
    p.used_cube_path = true;
    p.exact_mx_scale_partitioned = true;
    p.native_mx_qualified = false;
    g_last_provenance = p;
    if (provenance) *provenance = p;
    return true;
#else
    (void)mu;
    (void)scales;
    (void)V;
    (void)n;
    (void)m;
    return false;
#endif
}

bool TryLaunchLtCubeMxProjectRight(const std::vector<int8_t>& mu,
                                   const std::vector<uint8_t>& scales,
                                   const std::vector<int8_t>& V, uint32_t n, uint32_t m,
                                   std::vector<int32_t>& out,
                                   matmul::v4::lt::MxLaneProvenance* provenance)
{
    out.clear();
    if (provenance) *provenance = {};
    LtAscendDigestProvenance ascend_prov;
    if (!ComputeProjectedRightMxBlockScaleLTAscend(mu, scales, V, n, m, out, &ascend_prov)) {
        return false;
    }
    if (provenance) {
        provenance->exact_mx_scale_partitioned = ascend_prov.exact_mx_scale_partitioned;
        provenance->native_mxfp4_attempted = false;
        provenance->native_mxfp4_qualified = false;
        provenance->native_fp8_attempted = false;
        provenance->native_fp8_qualified = false;
    }
    return true;
}

LtAscendDigestProvenance LastAscendDigestProvenance()
{
    return g_last_provenance;
}

bool ComputeDigestsOnlyLTAscend(const CBlockHeader& tmpl, uint32_t n,
                                const uint64_t* nonces, size_t count,
                                std::vector<matmul::v4::lt::DigestOnlyResultLT>& out,
                                LtAscendDigestProvenance* provenance)
{
    out.clear();
    if (provenance) *provenance = {};
    g_last_provenance = {};
    if (!IsAscendExactMxProjectionAvailable() || nonces == nullptr || count == 0) {
        return false;
    }

#if defined(BTX_HAVE_CANN)
    uint32_t m = 0;
    if (!matmul::v4::lt::ValidateDimsBMX4CLT(n, m)) return false;

    matmul::v4::lt::ExactGemmBackend backend;
    backend.gemm_s8s8 = &TryLaunchLtCubeGemmS8S8;
    backend.gemm_s32s8 = &TryLaunchLtCubeGemmS32S8;

    // Template-scoped A/U/V/P once (same structure as WindowSketchMinerLT),
    // with Cube ExactGemm inject for MatExpand G*W / (G*W)*H.
    const std::vector<int8_t> A =
        matmul::v4::lt::ExpandOperandAMatExpand(tmpl, n, backend);
    if (A.size() != static_cast<size_t>(n) * n) return false;
    const auto [seed_u, seed_v] = matmul::v4::lt::DeriveProjectorSeedsBMX4CLT(tmpl);
    const std::vector<int8_t> U = matmul::v4::bmx4::ExpandProjectorBMX4C(seed_u, m, n);
    const std::vector<int8_t> V = matmul::v4::bmx4::ExpandProjectorBMX4C(seed_v, n, m);
    const std::vector<int32_t> P = matmul::v4::ComputeProjectedLeft(U, A, n, m);

    out.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        CBlockHeader header = tmpl;
        header.nNonce64 = nonces[i];
        header.nNonce = static_cast<uint32_t>(nonces[i]);

        std::vector<int8_t> mu;
        std::vector<uint8_t> scales;
        matmul::v4::lt::ExpandOperandBMatExpandMxComponents(header, n, backend, mu, scales);

        std::vector<int32_t> Q;
        if (!LaunchCubeMxScalePartitioned(mu, scales, V, n, m, Q)) {
            out.clear();
            g_last_provenance = {};
            if (provenance) *provenance = {};
            return false;
        }

        const uint256 sigma = matmul::v4::DeriveSigma(header);
        const auto Chat = matmul::v4::ComputeCombineModQ(P, Q, n, m);
        matmul::v4::lt::DigestOnlyResultLT res;
        res.nonce = nonces[i];
        res.digest = matmul::v4::ComputeSketchDigestFromFq(sigma, Chat);
        res.target_match = false;
        res.backend_status = matmul::v4::bmx4::DigestOnlyBackendStatus::Ok;
        out.push_back(std::move(res));
    }

    LtAscendDigestProvenance p;
    p.used_cube_path = true;
    p.exact_mx_scale_partitioned = true;
    p.native_mx_qualified = false; // no CANN FP8/MX ExactGemm admitted
    g_last_provenance = p;
    if (provenance) *provenance = p;
    return out.size() == count;
#else
    (void)tmpl;
    (void)n;
    return false;
#endif
}

} // namespace matmul_v4::ascend
