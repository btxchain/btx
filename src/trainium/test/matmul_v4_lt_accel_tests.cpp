// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <trainium/matmul_v4_lt_accel.h>

#include <matmul/exact_gemm_resolve.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>

namespace {

enum class FakeMode { EXACT_ENGINE, WRONG_RESULT, HOST_ONLY };
struct FakeContext { FakeMode mode; uint32_t calls{0}; };

bool FakeNeuronGemm(void* opaque, const int8_t* left, size_t left_elems,
                    const int8_t* right, size_t right_elems,
                    uint32_t rows, uint32_t inner, uint32_t cols,
                    int32_t* out, size_t out_elems, bool* used_engine)
{
    auto* context = static_cast<FakeContext*>(opaque);
    if (!context || !out || !used_engine ||
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
    *used_engine = context->mode != FakeMode::HOST_ONLY;
    return true;
}

matmul_v4::trainium::TrainiumNeuronExactGemmProviderV1 Provider(FakeContext& context)
{
    matmul_v4::trainium::TrainiumNeuronExactGemmProviderV1 provider;
    provider.provider_name = "fake-neuron";
    provider.context = &context;
    provider.gemm_s8s8_bf16 = &FakeNeuronGemm;
    return provider;
}

} // namespace

BOOST_AUTO_TEST_SUITE(matmul_v4_lt_trainium_tests)

BOOST_AUTO_TEST_CASE(trainium_provider_is_compile_time_closed)
{
    matmul_v4::trainium::ResetTrainiumNeuronExactGemmProviderForTesting();
#if !defined(BTX_HAVE_NEURON_NRT)
    FakeContext context{FakeMode::EXACT_ENGINE};
    BOOST_CHECK(!matmul_v4::trainium::RegisterTrainiumNeuronExactGemmProvider(
        Provider(context)));
#endif
    BOOST_CHECK(!matmul_v4::trainium::IsTrainiumExactGemmAvailable());
}

#if defined(BTX_HAVE_NEURON_NRT)
BOOST_AUTO_TEST_CASE(trainium_provider_qualifies_and_bound_is_exact)
{
    matmul_v4::trainium::ResetTrainiumNeuronExactGemmProviderForTesting();
    FakeContext context{FakeMode::EXACT_ENGINE};
    BOOST_REQUIRE(matmul_v4::trainium::RegisterTrainiumNeuronExactGemmProvider(
        Provider(context)));
    BOOST_REQUIRE(matmul_v4::trainium::IsTrainiumExactGemmAvailable());

    std::vector<int8_t> left(1024, int8_t{-128});
    std::vector<int8_t> right(1024, int8_t{-128});
    std::vector<int32_t> out;
    BOOST_REQUIRE(matmul_v4::trainium::TryLaunchLtTrainiumGemmS8S8(
        left, right, 1, 1024, 1, out));
    BOOST_CHECK_EQUAL(out.at(0), int32_t{1} << 24);

#if !defined(_WIN32)
    BOOST_REQUIRE_EQUAL(setenv("BTX_MATMUL_LT_EXACT_BACKEND", "trainium", 1), 0);
    const auto resolved = matmul_v4::accel::MakeResolvedExactGemmBackend();
    unsetenv("BTX_MATMUL_LT_EXACT_BACKEND");
    BOOST_CHECK(resolved.gemm_s8s8 ==
                &matmul_v4::trainium::TryLaunchLtTrainiumGemmS8S8);
    BOOST_CHECK(resolved.gemm_s32s8 == nullptr);
#endif

    const uint32_t calls_before_reject = context.calls;
    left.assign(1025, int8_t{-128});
    right.assign(1025, int8_t{-128});
    BOOST_CHECK(!matmul_v4::trainium::TryLaunchLtTrainiumGemmS8S8(
        left, right, 1, 1025, 1, out));
    BOOST_CHECK(out.empty());
    BOOST_CHECK_EQUAL(context.calls, calls_before_reject);
}

BOOST_AUTO_TEST_CASE(trainium_provider_rejects_wrong_or_host_only_results)
{
    for (const FakeMode mode : {FakeMode::WRONG_RESULT, FakeMode::HOST_ONLY}) {
        matmul_v4::trainium::ResetTrainiumNeuronExactGemmProviderForTesting();
        FakeContext context{mode};
        BOOST_REQUIRE(matmul_v4::trainium::RegisterTrainiumNeuronExactGemmProvider(
            Provider(context)));
        BOOST_CHECK(!matmul_v4::trainium::IsTrainiumExactGemmAvailable());
    }
}
#endif

BOOST_AUTO_TEST_CASE(trainium_s32s8_always_declines)
{
    std::vector<int32_t> left(4, 1);
    std::vector<int8_t> right(4, 1);
    std::vector<int32_t> out{42};
    BOOST_CHECK(!matmul_v4::trainium::TryLaunchLtTrainiumGemmS32S8(
        left, right, 2, 2, 2, out));
    BOOST_CHECK(out.empty());
}

BOOST_AUTO_TEST_SUITE_END()
