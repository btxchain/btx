// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <tpu/matmul_v4_lt_accel.h>

#include <matmul/exact_gemm_resolve.h>
#include <matmul/matmul_v4_lt.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>

namespace {

enum class FakeMode { EXACT_MXU, WRONG_RESULT, HOST_ONLY };

struct FakeContext {
    FakeMode mode;
    uint32_t calls{0};
};

bool FakePjrtGemm(void* opaque, const int8_t* left, size_t left_elems,
                  const int8_t* right, size_t right_elems,
                  uint32_t rows, uint32_t inner, uint32_t cols,
                  int32_t* out, size_t out_elems, bool* used_exact_mxu)
{
    auto* context = static_cast<FakeContext*>(opaque);
    if (!context || !out || !used_exact_mxu ||
        left_elems != static_cast<size_t>(rows) * inner ||
        right_elems != static_cast<size_t>(inner) * cols ||
        out_elems != static_cast<size_t>(rows) * cols) {
        return false;
    }
    ++context->calls;
    std::fill(out, out + out_elems, int32_t{0});
    for (uint32_t row = 0; row < rows; ++row) {
        for (uint32_t k = 0; k < inner; ++k) {
            const int32_t a = left[static_cast<size_t>(row) * inner + k];
            for (uint32_t col = 0; col < cols; ++col) {
                out[static_cast<size_t>(row) * cols + col] +=
                    a * static_cast<int32_t>(right[static_cast<size_t>(k) * cols + col]);
            }
        }
    }
    if (context->mode == FakeMode::WRONG_RESULT && out_elems != 0) ++out[0];
    *used_exact_mxu = context->mode != FakeMode::HOST_ONLY;
    return true;
}

matmul_v4::tpu::TpuPjrtExactGemmProviderV1 Provider(FakeContext& context)
{
    matmul_v4::tpu::TpuPjrtExactGemmProviderV1 provider;
    provider.provider_name = "fake-pjrt";
    provider.context = &context;
    provider.gemm_s8s8 = &FakePjrtGemm;
    return provider;
}

} // namespace

BOOST_AUTO_TEST_SUITE(matmul_v4_lt_tpu_tests)

BOOST_AUTO_TEST_CASE(tpu_provider_is_compile_time_closed)
{
    matmul_v4::tpu::ResetTpuPjrtExactGemmProviderForTesting();
#if !defined(BTX_HAVE_TPU_PJRT)
    FakeContext context{FakeMode::EXACT_MXU};
    BOOST_CHECK(!matmul_v4::tpu::RegisterTpuPjrtExactGemmProvider(Provider(context)));
    BOOST_CHECK(!matmul_v4::tpu::IsTpuPjrtExactGemmAvailable());
#else
    BOOST_CHECK(!matmul_v4::tpu::IsTpuPjrtExactGemmAvailable());
#endif
}

#if defined(BTX_HAVE_TPU_PJRT)
BOOST_AUTO_TEST_CASE(tpu_provider_qualifies_and_launches_exactly)
{
    matmul_v4::tpu::ResetTpuPjrtExactGemmProviderForTesting();
    FakeContext context{FakeMode::EXACT_MXU};
    BOOST_REQUIRE(matmul_v4::tpu::RegisterTpuPjrtExactGemmProvider(Provider(context)));
    BOOST_REQUIRE(matmul_v4::tpu::IsTpuPjrtExactGemmAvailable());

    constexpr uint32_t rows{5}, inner{7}, cols{3};
    std::vector<int8_t> left(static_cast<size_t>(rows) * inner);
    std::vector<int8_t> right(static_cast<size_t>(inner) * cols);
    for (size_t i = 0; i < left.size(); ++i) {
        left[i] = static_cast<int8_t>(static_cast<int32_t>(i % 17) - 8);
    }
    for (size_t i = 0; i < right.size(); ++i) {
        right[i] = static_cast<int8_t>(static_cast<int32_t>(i % 13) - 6);
    }

    std::vector<int32_t> device;
    BOOST_REQUIRE(matmul_v4::tpu::TryLaunchLtTpuGemmS8S8(
        left, right, rows, inner, cols, device));
    BOOST_CHECK(device == matmul::v4::lt::ExactGemmS8S8(
        left, right, rows, inner, cols));

#if !defined(_WIN32)
    BOOST_REQUIRE_EQUAL(setenv("BTX_MATMUL_LT_EXACT_BACKEND", "tpu", 1), 0);
    const auto resolved = matmul_v4::accel::MakeResolvedExactGemmBackend();
    unsetenv("BTX_MATMUL_LT_EXACT_BACKEND");
    BOOST_CHECK(resolved.gemm_s8s8 == &matmul_v4::tpu::TryLaunchLtTpuGemmS8S8);
    BOOST_CHECK(resolved.gemm_s32s8 == nullptr);
#endif
}

BOOST_AUTO_TEST_CASE(tpu_provider_rejects_wrong_or_host_only_results)
{
    for (const FakeMode mode : {FakeMode::WRONG_RESULT, FakeMode::HOST_ONLY}) {
        matmul_v4::tpu::ResetTpuPjrtExactGemmProviderForTesting();
        FakeContext context{mode};
        BOOST_REQUIRE(matmul_v4::tpu::RegisterTpuPjrtExactGemmProvider(Provider(context)));
        BOOST_CHECK(!matmul_v4::tpu::IsTpuPjrtExactGemmAvailable());
    }
}

BOOST_AUTO_TEST_CASE(tpu_bf16_fp32_proof_accepts_boundary_and_rejects_above)
{
    matmul_v4::tpu::ResetTpuPjrtExactGemmProviderForTesting();
    FakeContext context{FakeMode::EXACT_MXU};
    BOOST_REQUIRE(matmul_v4::tpu::RegisterTpuPjrtExactGemmProvider(Provider(context)));
    BOOST_REQUIRE(matmul_v4::tpu::IsTpuPjrtExactGemmAvailable());

    // 1024 * 128 * 128 == 2^24: inclusive because every integer in
    // [-2^24, 2^24] is exactly representable in IEEE FP32.
    std::vector<int8_t> left(1024, int8_t{-128});
    std::vector<int8_t> right(1024, int8_t{-128});
    std::vector<int32_t> out;
    BOOST_REQUIRE(matmul_v4::tpu::TryLaunchLtTpuGemmS8S8(
        left, right, 1, 1024, 1, out));
    BOOST_REQUIRE_EQUAL(out.size(), 1U);
    BOOST_CHECK_EQUAL(out[0], int32_t{1} << 24);

    const uint32_t calls_before_reject = context.calls;
    left.assign(1025, int8_t{-128});
    right.assign(1025, int8_t{-128});
    out.assign(1, 42);
    BOOST_CHECK(!matmul_v4::tpu::TryLaunchLtTpuGemmS8S8(
        left, right, 1, 1025, 1, out));
    BOOST_CHECK(out.empty());
    BOOST_CHECK_EQUAL(context.calls, calls_before_reject); // rejected before provider
}
#endif

BOOST_AUTO_TEST_CASE(tpu_s32s8_always_declines)
{
    std::vector<int32_t> left(4, 1);
    std::vector<int8_t> right(4, 1);
    std::vector<int32_t> out{42};
    BOOST_CHECK(!matmul_v4::tpu::TryLaunchLtTpuGemmS32S8(left, right, 2, 2, 2, out));
    BOOST_CHECK(out.empty());
}

BOOST_AUTO_TEST_SUITE_END()
