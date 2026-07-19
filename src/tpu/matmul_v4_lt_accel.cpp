// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <tpu/matmul_v4_lt_accel.h>

#include <matmul/matmul_v4_lt.h>

#include <algorithm>
#include <limits>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace matmul_v4::tpu {
namespace {

enum class Qualification { UNTESTED, PASSED, FAILED };

struct ProviderState {
    std::mutex mutex;
    std::mutex qualification_mutex;
    TpuPjrtExactGemmProviderV1 provider{};
    std::string provider_name;
    bool registered{false};
    uint64_t generation{0};
    Qualification qualification{Qualification::UNTESTED};
};

ProviderState& State()
{
    static ProviderState state;
    return state;
}

#if defined(BTX_HAVE_TPU_PJRT)

[[nodiscard]] bool CheckedProduct(size_t a, size_t b, size_t& product)
{
    if (a != 0 && b > std::numeric_limits<size_t>::max() / a) return false;
    product = a * b;
    return true;
}

[[nodiscard]] bool ValidShape(const std::vector<int8_t>& left,
                              const std::vector<int8_t>& right,
                              uint32_t rows, uint32_t inner, uint32_t cols,
                              size_t& out_elems)
{
    size_t left_elems{0};
    size_t right_elems{0};
    if (!CheckedProduct(rows, inner, left_elems) ||
        !CheckedProduct(inner, cols, right_elems) ||
        !CheckedProduct(rows, cols, out_elems)) {
        return false;
    }
    return left.size() == left_elems && right.size() == right_elems;
}

[[nodiscard]] bool IsBf16Fp32ExactlyBounded(const std::vector<int8_t>& left,
                                            const std::vector<int8_t>& right,
                                            uint32_t inner)
{
    uint32_t max_left{0};
    uint32_t max_right{0};
    for (const int8_t value : left) {
        const int32_t wide = value;
        max_left = std::max(max_left, static_cast<uint32_t>(wide < 0 ? -wide : wide));
    }
    for (const int8_t value : right) {
        const int32_t wide = value;
        max_right = std::max(max_right, static_cast<uint32_t>(wide < 0 ? -wide : wide));
    }
    // BF16 represents every S8 integer exactly. Its product is exact in FP32,
    // and this conservative absolute-sum bound makes every possible reduction
    // order an exactly representable integer as well.
    constexpr uint64_t kMaxConsecutiveIntegerFp32 = uint64_t{1} << 24;
    return static_cast<uint64_t>(inner) * max_left * max_right <=
           kMaxConsecutiveIntegerFp32;
}

[[nodiscard]] bool LaunchProvider(const TpuPjrtExactGemmProviderV1& provider,
                                  const std::vector<int8_t>& left,
                                  const std::vector<int8_t>& right,
                                  uint32_t rows, uint32_t inner, uint32_t cols,
                                  std::vector<int32_t>& out)
{
    out.clear();
    if (provider.gemm_s8s8 == nullptr || rows == 0 || inner == 0 || cols == 0) return false;

    size_t out_elems{0};
    if (!ValidShape(left, right, rows, inner, cols, out_elems) ||
        !IsBf16Fp32ExactlyBounded(left, right, inner)) {
        return false;
    }

    std::vector<int32_t> candidate;
    try {
        candidate.assign(out_elems, 0);
    } catch (...) {
        return false;
    }

    bool used_exact_mxu{false};
    bool ok{false};
    try {
        ok = provider.gemm_s8s8(provider.context,
                                left.data(), left.size(), right.data(), right.size(),
                                rows, inner, cols, candidate.data(), candidate.size(),
                                &used_exact_mxu);
    } catch (...) {
        // Provider callbacks are forbidden from throwing, but contain an
        // accidental ABI violation rather than allowing it into mining code.
        return false;
    }
    if (!ok || !used_exact_mxu) return false;
    out = std::move(candidate);
    return true;
}

void FillPattern(uint32_t rows, uint32_t inner, uint32_t cols,
                 int32_t left_mul, int32_t right_mul,
                 std::vector<int8_t>& left, std::vector<int8_t>& right)
{
    left.resize(static_cast<size_t>(rows) * inner);
    right.resize(static_cast<size_t>(inner) * cols);
    for (size_t i = 0; i < left.size(); ++i) {
        // Production MatExpand operands are bounded by 48.  This deterministic
        // sequence covers the full signed interval without implementation-
        // defined narrowing.
        const int32_t v = (static_cast<int32_t>(i % 97) * left_mul + 41) % 97;
        left[i] = static_cast<int8_t>(v - 48);
    }
    for (size_t i = 0; i < right.size(); ++i) {
        const int32_t v = (static_cast<int32_t>(i % 97) * right_mul + 73) % 97;
        right[i] = static_cast<int8_t>(v - 48);
    }
}

[[nodiscard]] bool MatchCpu(const TpuPjrtExactGemmProviderV1& provider,
                            const std::vector<int8_t>& left,
                            const std::vector<int8_t>& right,
                            uint32_t rows, uint32_t inner, uint32_t cols)
{
    const auto cpu = matmul::v4::lt::ExactGemmS8S8(left, right, rows, inner, cols);
    std::vector<int32_t> device;
    return LaunchProvider(provider, left, right, rows, inner, cols, device) && device == cpu;
}

[[nodiscard]] bool SelfQualify(const TpuPjrtExactGemmProviderV1& provider)
{
    struct Shape { uint32_t rows, inner, cols; int32_t lm, rm; };
    // Includes odd contraction lengths, TPU-friendly multiples, and the thin
    // MatExpand panel orientation.  Providers should cache compiled PJRT
    // executables per shape; these probes run only once per process.
    constexpr Shape kShapes[] = {
        {17, 19, 23, 7, 11},
        {32, 32, 32, 13, 29},
        {64, 128, 128, 31, 47},
        {128, 128, 32, 53, 59},
    };
    for (const Shape& shape : kShapes) {
        std::vector<int8_t> left;
        std::vector<int8_t> right;
        FillPattern(shape.rows, shape.inner, shape.cols, shape.lm, shape.rm, left, right);
        if (!MatchCpu(provider, left, right, shape.rows, shape.inner, shape.cols)) return false;
    }

    // Max-magnitude and cancellation probes catch unsigned reinterpretation,
    // saturating accumulation, FP fallback, and incorrect zero-point handling.
    constexpr uint32_t kRows = 7;
    constexpr uint32_t kInner = 257;
    constexpr uint32_t kCols = 9;
    std::vector<int8_t> left(static_cast<size_t>(kRows) * kInner);
    std::vector<int8_t> right(static_cast<size_t>(kInner) * kCols);
    for (size_t i = 0; i < left.size(); ++i) {
        left[i] = (i % 3 == 0) ? int8_t{-127} : ((i % 3 == 1) ? int8_t{127} : int8_t{0});
    }
    for (size_t i = 0; i < right.size(); ++i) {
        right[i] = (i % 4 < 2) ? int8_t{127} : int8_t{-127};
    }
    if (!MatchCpu(provider, left, right, kRows, kInner, kCols)) return false;

    // Production-length contraction close to the FP32 consecutive-integer
    // bound. Values remain in the LT operand range, so BF16 input and FP32
    // accumulation are exact for every reduction order.
    constexpr uint32_t kLongInner = 4096;
    left.assign(kLongInner, int8_t{48});
    right.assign(static_cast<size_t>(kLongInner) * 3, int8_t{48});
    right[(static_cast<size_t>(kLongInner) - 1) * 3] = int8_t{47};
    for (uint32_t k = 0; k < kLongInner; ++k) {
        right[static_cast<size_t>(k) * 3 + 1] = int8_t{-48};
        right[static_cast<size_t>(k) * 3 + 2] = (k & 1) ? int8_t{-48} : int8_t{48};
    }
    if (!MatchCpu(provider, left, right, 1, kLongInner, 3)) return false;

    // Inclusive proof frontier: 1024 * |-128| * |-128| == 2^24.
    // A BF16/FP32 bridge that narrows or saturates here must not qualify.
    left.assign(1024, int8_t{-128});
    right.assign(1024, int8_t{-128});
    return MatchCpu(provider, left, right, 1, 1024, 1);
}

#endif // BTX_HAVE_TPU_PJRT

} // namespace

bool RegisterTpuPjrtExactGemmProvider(const TpuPjrtExactGemmProviderV1& provider)
{
#if defined(BTX_HAVE_TPU_PJRT)
    if (provider.abi_version != kTpuPjrtExactGemmProviderAbiV1 ||
        provider.struct_size < sizeof(TpuPjrtExactGemmProviderV1) ||
        provider.gemm_s8s8 == nullptr) {
        return false;
    }
    auto& state = State();
    std::lock_guard<std::mutex> lock(state.mutex);
    if (state.registered) return false;
    state.provider = provider;
    state.provider_name = provider.provider_name ? provider.provider_name : "unnamed-pjrt-provider";
    state.provider.provider_name = state.provider_name.c_str();
    state.registered = true;
    ++state.generation;
    state.qualification = Qualification::UNTESTED;
    return true;
#else
    (void)provider;
    return false;
#endif
}

void ResetTpuPjrtExactGemmProviderForTesting()
{
    auto& state = State();
    std::lock_guard<std::mutex> qualification_lock(state.qualification_mutex);
    std::lock_guard<std::mutex> lock(state.mutex);
    state.provider = {};
    state.provider_name.clear();
    state.registered = false;
    ++state.generation;
    state.qualification = Qualification::UNTESTED;
}

bool IsTpuPjrtExactGemmAvailable()
{
#if defined(BTX_HAVE_TPU_PJRT)
    auto& state = State();
    std::lock_guard<std::mutex> qualification_lock(state.qualification_mutex);

    TpuPjrtExactGemmProviderV1 provider;
    uint64_t generation{0};
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        if (!state.registered) return false;
        if (state.qualification == Qualification::PASSED) return true;
        if (state.qualification == Qualification::FAILED) return false;
        provider = state.provider;
        generation = state.generation;
    }

    const bool passed = SelfQualify(provider);
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        if (!state.registered || state.generation != generation) return false;
        state.qualification = passed ? Qualification::PASSED : Qualification::FAILED;
    }
    return passed;
#else
    return false;
#endif
}

bool TryLaunchLtTpuGemmS8S8(const std::vector<int8_t>& left,
                            const std::vector<int8_t>& right,
                            uint32_t rows, uint32_t inner, uint32_t cols,
                            std::vector<int32_t>& out)
{
    out.clear();
#if defined(BTX_HAVE_TPU_PJRT)
    if (!IsTpuPjrtExactGemmAvailable()) return false;
    TpuPjrtExactGemmProviderV1 provider;
    {
        auto& state = State();
        std::lock_guard<std::mutex> lock(state.mutex);
        if (!state.registered || state.qualification != Qualification::PASSED) return false;
        provider = state.provider;
    }
    return LaunchProvider(provider, left, right, rows, inner, cols, out);
#else
    (void)left;
    (void)right;
    (void)rows;
    (void)inner;
    (void)cols;
    return false;
#endif
}

bool TryLaunchLtTpuGemmS32S8(const std::vector<int32_t>& left,
                             const std::vector<int8_t>& right,
                             uint32_t rows, uint32_t inner, uint32_t cols,
                             std::vector<int32_t>& out)
{
    (void)left;
    (void)right;
    (void)rows;
    (void)inner;
    (void)cols;
    out.clear();
    return false;
}

} // namespace matmul_v4::tpu
