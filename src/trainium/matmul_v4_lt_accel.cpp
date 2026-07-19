// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <trainium/matmul_v4_lt_accel.h>

#include <matmul/matmul_v4_lt.h>

#include <algorithm>
#include <array>
#include <limits>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace matmul_v4::trainium {
namespace {

enum class Qualification { UNTESTED, PASSED, FAILED };

struct ProviderState {
    std::mutex mutex;
    std::mutex qualification_mutex;
    TrainiumNeuronExactGemmProviderV1 provider{};
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

#if defined(BTX_HAVE_NEURON_NRT)

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
    constexpr uint64_t kMaxConsecutiveIntegerFp32 = uint64_t{1} << 24;
    return static_cast<uint64_t>(inner) * max_left * max_right <=
           kMaxConsecutiveIntegerFp32;
}

[[nodiscard]] bool LaunchProvider(const TrainiumNeuronExactGemmProviderV1& provider,
                                  const std::vector<int8_t>& left,
                                  const std::vector<int8_t>& right,
                                  uint32_t rows, uint32_t inner, uint32_t cols,
                                  std::vector<int32_t>& out)
{
    out.clear();
    if (provider.gemm_s8s8_bf16 == nullptr || rows == 0 || inner == 0 || cols == 0) return false;
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

    bool used_bf16_tensor_engine{false};
    bool ok{false};
    try {
        ok = provider.gemm_s8s8_bf16(
            provider.context, left.data(), left.size(), right.data(), right.size(),
            rows, inner, cols, candidate.data(), candidate.size(),
            &used_bf16_tensor_engine);
    } catch (...) {
        return false;
    }
    if (!ok || !used_bf16_tensor_engine) return false;
    out = std::move(candidate);
    return true;
}

void FillPattern(uint32_t rows, uint32_t inner, uint32_t cols,
                 std::vector<int8_t>& left, std::vector<int8_t>& right)
{
    left.resize(static_cast<size_t>(rows) * inner);
    right.resize(static_cast<size_t>(inner) * cols);
    for (size_t i = 0; i < left.size(); ++i) {
        left[i] = static_cast<int8_t>(static_cast<int32_t>((i * 31 + 17) % 97) - 48);
    }
    for (size_t i = 0; i < right.size(); ++i) {
        right[i] = static_cast<int8_t>(static_cast<int32_t>((i * 47 + 29) % 97) - 48);
    }
}

[[nodiscard]] bool MatchCpu(const TrainiumNeuronExactGemmProviderV1& provider,
                            const std::vector<int8_t>& left,
                            const std::vector<int8_t>& right,
                            uint32_t rows, uint32_t inner, uint32_t cols)
{
    const auto cpu = matmul::v4::lt::ExactGemmS8S8(left, right, rows, inner, cols);
    std::vector<int32_t> device;
    return LaunchProvider(provider, left, right, rows, inner, cols, device) && device == cpu;
}

[[nodiscard]] bool SelfQualify(const TrainiumNeuronExactGemmProviderV1& provider)
{
    for (const auto& shape : {
             std::array<uint32_t, 3>{17, 19, 23},
             std::array<uint32_t, 3>{64, 128, 128},
             std::array<uint32_t, 3>{128, 128, 32},
         }) {
        std::vector<int8_t> left;
        std::vector<int8_t> right;
        FillPattern(shape[0], shape[1], shape[2], left, right);
        if (!MatchCpu(provider, left, right, shape[0], shape[1], shape[2])) return false;
    }

    // Production K, near worst-case LT magnitude, cancellation, and an odd
    // integer result. The absolute-sum bound is 4096*48*48 < 2^24.
    constexpr uint32_t kInner = 4096;
    std::vector<int8_t> left(kInner, int8_t{48});
    std::vector<int8_t> right(static_cast<size_t>(kInner) * 3, int8_t{48});
    right[(static_cast<size_t>(kInner) - 1) * 3] = int8_t{47};
    for (uint32_t k = 0; k < kInner; ++k) {
        right[static_cast<size_t>(k) * 3 + 1] = int8_t{-48};
        right[static_cast<size_t>(k) * 3 + 2] = (k & 1) ? int8_t{-48} : int8_t{48};
    }
    if (!MatchCpu(provider, left, right, 1, kInner, 3)) return false;

    // Inclusive proof frontier: 1024 * |-128| * |-128| == 2^24.
    left.assign(1024, int8_t{-128});
    right.assign(1024, int8_t{-128});
    return MatchCpu(provider, left, right, 1, 1024, 1);
}

#endif // BTX_HAVE_NEURON_NRT

} // namespace

bool RegisterTrainiumNeuronExactGemmProvider(
    const TrainiumNeuronExactGemmProviderV1& provider)
{
#if defined(BTX_HAVE_NEURON_NRT)
    if (provider.abi_version != kTrainiumNeuronExactGemmProviderAbiV1 ||
        provider.struct_size < sizeof(TrainiumNeuronExactGemmProviderV1) ||
        provider.gemm_s8s8_bf16 == nullptr) {
        return false;
    }
    auto& state = State();
    std::lock_guard<std::mutex> lock(state.mutex);
    if (state.registered) return false;
    state.provider = provider;
    state.provider_name = provider.provider_name ? provider.provider_name : "unnamed-neuron-provider";
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

void ResetTrainiumNeuronExactGemmProviderForTesting()
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

bool IsTrainiumExactGemmAvailable()
{
#if defined(BTX_HAVE_NEURON_NRT)
    auto& state = State();
    std::lock_guard<std::mutex> qualification_lock(state.qualification_mutex);
    TrainiumNeuronExactGemmProviderV1 provider;
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

bool TryLaunchLtTrainiumGemmS8S8(const std::vector<int8_t>& left,
                                 const std::vector<int8_t>& right,
                                 uint32_t rows, uint32_t inner, uint32_t cols,
                                 std::vector<int32_t>& out)
{
    out.clear();
#if defined(BTX_HAVE_NEURON_NRT)
    if (!IsTrainiumExactGemmAvailable()) return false;
    TrainiumNeuronExactGemmProviderV1 provider;
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

bool TryLaunchLtTrainiumGemmS32S8(const std::vector<int32_t>& left,
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

} // namespace matmul_v4::trainium
