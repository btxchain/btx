// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_pow.h>

#include <arith_uint256.h>
#include <hash.h>
#include <matmul/transcript.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <util/time.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <limits>
#include <string_view>
#include <thread>
#include <vector>

namespace {

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

arith_uint256 MaxTarget()
{
    return UintToArith256(ParseUint256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
}

matmul::PowConfig BaseConfig()
{
    return {
        .n = 4,
        .b = 2,
        .r = 2,
        .target = MaxTarget(),
    };
}

matmul::PowState BaseState()
{
    return {
        .version = 0x20000000,
        .previous_block_hash = ParseUint256("1111111111111111111111111111111111111111111111111111111111111111"),
        .merkle_root = ParseUint256("2222222222222222222222222222222222222222222222222222222222222222"),
        .time = 1'710'000'090,
        .bits = 0x207fffff,
        .seed_a = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000"),
        .seed_b = ParseUint256("4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150"),
        .nonce = 0,
        .matmul_dim = 4,
        .digest = uint256{},
    };
}

CBlockHeader HeaderFromState(const matmul::PowState& state)
{
    CBlockHeader header;
    header.nVersion = state.version;
    header.hashPrevBlock = state.previous_block_hash;
    header.hashMerkleRoot = state.merkle_root;
    header.nTime = state.time;
    header.nBits = state.bits;
    header.nNonce64 = state.nonce;
    header.nNonce = static_cast<uint32_t>(state.nonce);
    header.matmul_dim = state.matmul_dim;
    header.seed_a = state.seed_a;
    header.seed_b = state.seed_b;
    return header;
}

uint256 DeterministicTestHash(uint32_t block_index, uint32_t tag)
{
    HashWriter hw;
    hw << block_index << tag;
    return hw.GetSHA256();
}

uint256 ComputeDigestForState(const matmul::PowState& state, const matmul::PowConfig& config)
{
    const matmul::Matrix A = matmul::FromSeed(state.seed_a, config.n);
    const matmul::Matrix B = matmul::FromSeed(state.seed_b, config.n);
    const uint256 sigma = matmul::DeriveSigma(state);
    const matmul::noise::NoisePair np = matmul::noise::Generate(sigma, config.n, config.r);
    const matmul::Matrix A_prime = A + (np.E_L * np.E_R);
    const matmul::Matrix B_prime = B + (np.F_L * np.F_R);
    return matmul::transcript::CanonicalMatMul(A_prime, B_prime, config.b, sigma).transcript_hash;
}

std::array<int, 3> SimulateWinsForWorkerShares(
    const std::array<int, 3>& worker_shares,
    int block_count,
    const matmul::PowConfig& config)
{
    const int total_workers = worker_shares[0] + worker_shares[1] + worker_shares[2];
    BOOST_REQUIRE(total_workers > 0);

    std::vector<int> worker_to_miner;
    worker_to_miner.reserve(total_workers);
    for (int miner = 0; miner < static_cast<int>(worker_shares.size()); ++miner) {
        for (int worker = 0; worker < worker_shares[miner]; ++worker) {
            worker_to_miner.push_back(miner);
        }
    }

    std::array<int, 3> wins{0, 0, 0};
    for (int block_index = 0; block_index < block_count; ++block_index) {
        auto base = BaseState();
        base.previous_block_hash = DeterministicTestHash(static_cast<uint32_t>(block_index), 1);
        base.merkle_root = DeterministicTestHash(static_cast<uint32_t>(block_index), 2);
        base.seed_a = DeterministicTestHash(static_cast<uint32_t>(block_index), 3);
        base.seed_b = DeterministicTestHash(static_cast<uint32_t>(block_index), 4);
        base.time += static_cast<uint32_t>(block_index);

        bool solved{false};
        for (uint64_t round = 0; round < 2048 && !solved; ++round) {
            for (int worker = 0; worker < total_workers; ++worker) {
                auto candidate = base;
                candidate.nonce = round * static_cast<uint64_t>(total_workers) + static_cast<uint64_t>(worker);
                candidate.digest = ComputeDigestForState(candidate, config);
                if (UintToArith256(candidate.digest) <= config.target) {
                    ++wins[worker_to_miner[worker]];
                    solved = true;
                    break;
                }
            }
        }

        BOOST_REQUIRE_MESSAGE(solved, "simulation failed to find a valid nonce within the capped search window");
    }
    return wins;
}

class ScopedAmxEnv
{
public:
    explicit ScopedAmxEnv(const char* value)
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_AMX_EXPERIMENT", value != nullptr ? value : "");
#else
        if (value != nullptr) {
            setenv("BTX_MATMUL_AMX_EXPERIMENT", value, 1);
        } else {
            unsetenv("BTX_MATMUL_AMX_EXPERIMENT");
        }
#endif
    }

    ~ScopedAmxEnv()
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_AMX_EXPERIMENT", "");
#else
        unsetenv("BTX_MATMUL_AMX_EXPERIMENT");
#endif
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_pow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(solve_finds_proof_regtest)
{
    auto config = BaseConfig();
    auto state = BaseState();
    uint64_t max_tries = 1;

    BOOST_CHECK(matmul::Solve(state, config, max_tries));
    BOOST_CHECK_EQUAL(max_tries, 0U);
    BOOST_CHECK(state.digest != uint256{});
}

BOOST_AUTO_TEST_CASE(solve_proof_verifies)
{
    auto config = BaseConfig();
    auto state = BaseState();
    uint64_t max_tries = 2;

    BOOST_REQUIRE(matmul::Solve(state, config, max_tries));
    BOOST_CHECK(matmul::Verify(state, config));
}

BOOST_AUTO_TEST_CASE(solve_runtime_clamps_worker_threads)
{
    BOOST_CHECK_EQUAL(matmul::ClampSolveWorkerThreads(4), 4U);
    {
        const matmul::ScopedSolveRuntime runtime{
            {.time_budget_ms = 0, .max_worker_threads = 2}};
        BOOST_CHECK_EQUAL(matmul::ClampSolveWorkerThreads(4), 2U);
        BOOST_CHECK_EQUAL(matmul::ClampSolveWorkerThreads(1), 1U);
    }
    BOOST_CHECK_EQUAL(matmul::ClampSolveWorkerThreads(4), 4U);
}

BOOST_AUTO_TEST_CASE(solve_runtime_budget_expiry_tracks_mock_time)
{
    SetMockTime(1'710'000'000);
    {
        const matmul::ScopedSolveRuntime runtime{
            {.time_budget_ms = 1000, .max_worker_threads = 0}};
        BOOST_CHECK(!matmul::SolveTimeBudgetExpired());
        SetMockTime(1'710'000'002);
        BOOST_CHECK(matmul::SolveTimeBudgetExpired());
    }
    BOOST_CHECK(!matmul::SolveTimeBudgetExpired());
    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(solve_stops_when_time_budget_expires)
{
    SetMockTime(1'710'000'000);

    auto config = BaseConfig();
    config.n = 64;
    config.b = 8;
    config.r = 4;
    config.target = arith_uint256{};

    auto state = BaseState();
    state.matmul_dim = static_cast<uint16_t>(config.n);
    uint64_t max_tries = 100'000;

    std::thread advance_time([] {
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
        SetMockTime(1'710'000'002);
    });

    const bool solved = matmul::Solve(
        state,
        config,
        max_tries,
        {.time_budget_ms = 1000, .max_worker_threads = 1});
    advance_time.join();

    BOOST_CHECK(!solved);
    BOOST_CHECK_GT(max_tries, 0U);
    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(pow_state_sigma_matches_header_sigma)
{
    const auto state = BaseState();
    const auto header = HeaderFromState(state);

    BOOST_CHECK_EQUAL(matmul::DeriveSigma(state), matmul::DeriveSigma(header));
}

BOOST_AUTO_TEST_CASE(verify_rejects_wrong_seed_a)
{
    auto config = BaseConfig();
    auto state = BaseState();
    uint64_t max_tries = 2;

    BOOST_REQUIRE(matmul::Solve(state, config, max_tries));

    auto tampered = state;
    tampered.seed_a = ParseUint256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    BOOST_CHECK(!matmul::Verify(tampered, config));
}

BOOST_AUTO_TEST_CASE(verify_rejects_wrong_seed_b)
{
    auto config = BaseConfig();
    auto state = BaseState();
    uint64_t max_tries = 2;

    BOOST_REQUIRE(matmul::Solve(state, config, max_tries));

    auto tampered = state;
    tampered.seed_b = ParseUint256("c6a811f7f75fe4e64be106a50351aed9c04403a74bfe7b4bbe59f7311722b735");
    BOOST_CHECK(!matmul::Verify(tampered, config));
}

BOOST_AUTO_TEST_CASE(verify_rejects_tampered_digest)
{
    auto config = BaseConfig();
    auto state = BaseState();
    uint64_t max_tries = 2;

    BOOST_REQUIRE(matmul::Solve(state, config, max_tries));

    auto tampered = state;
    tampered.digest = ParseUint256("0100000000000000000000000000000000000000000000000000000000000000");
    BOOST_CHECK(!matmul::Verify(tampered, config));
}

BOOST_AUTO_TEST_CASE(verify_rejects_changed_previous_block_hash)
{
    auto config = BaseConfig();
    auto state = BaseState();
    uint64_t max_tries = 2;

    BOOST_REQUIRE(matmul::Solve(state, config, max_tries));

    auto tampered = state;
    tampered.previous_block_hash = ParseUint256("3333333333333333333333333333333333333333333333333333333333333333");
    BOOST_CHECK(!matmul::Verify(tampered, config));
}

BOOST_AUTO_TEST_CASE(verify_rejects_changed_bits)
{
    auto config = BaseConfig();
    auto state = BaseState();
    uint64_t max_tries = 2;

    BOOST_REQUIRE(matmul::Solve(state, config, max_tries));

    auto tampered = state;
    tampered.bits = 0x1d00ffff;
    BOOST_CHECK(!matmul::Verify(tampered, config));
}

BOOST_AUTO_TEST_CASE(verify_rejects_bad_dimension)
{
    auto state = BaseState();
    state.digest = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");

    auto bad = BaseConfig();
    bad.n = 5;
    bad.b = 2;

    BOOST_CHECK(!matmul::Verify(state, bad));
}

BOOST_AUTO_TEST_CASE(verify_commitment_only)
{
    auto config = BaseConfig();
    auto state = BaseState();
    uint64_t max_tries = 2;

    BOOST_REQUIRE(matmul::Solve(state, config, max_tries));
    BOOST_CHECK(matmul::VerifyCommitment(state, config));

    auto strict = config;
    strict.target = arith_uint256{};
    BOOST_CHECK(!matmul::VerifyCommitment(state, strict));
}

BOOST_AUTO_TEST_CASE(solve_max_tries_zero)
{
    auto config = BaseConfig();
    auto before = BaseState();
    auto state = before;

    uint64_t max_tries = 0;
    BOOST_CHECK(!matmul::Solve(state, config, max_tries));

    BOOST_CHECK_EQUAL(state.seed_a, before.seed_a);
    BOOST_CHECK_EQUAL(state.seed_b, before.seed_b);
    BOOST_CHECK_EQUAL(state.nonce, before.nonce);
    BOOST_CHECK_EQUAL(state.digest, before.digest);
}

BOOST_AUTO_TEST_CASE(solve_increments_nonce)
{
    auto config = BaseConfig();
    config.target = arith_uint256{};

    auto state = BaseState();
    state.nonce = 7;

    uint64_t max_tries = 3;
    BOOST_CHECK(!matmul::Solve(state, config, max_tries));

    BOOST_CHECK_EQUAL(state.nonce, 10U);
    BOOST_CHECK_EQUAL(max_tries, 0U);
}

BOOST_AUTO_TEST_CASE(simulated_miners_with_equal_workers_have_balanced_win_share)
{
    auto config = BaseConfig();
    config.target >>= 5;

    const auto wins = SimulateWinsForWorkerShares({1, 1, 1}, 360, config);
    const int total_wins = wins[0] + wins[1] + wins[2];
    BOOST_REQUIRE_EQUAL(total_wins, 360);

    for (const int miner_wins : wins) {
        const double share = static_cast<double>(miner_wins) / static_cast<double>(total_wins);
        BOOST_CHECK_CLOSE_FRACTION(share, 1.0 / 3.0, 0.15);
    }
}

BOOST_AUTO_TEST_CASE(simulated_miners_win_in_proportion_to_worker_share)
{
    auto config = BaseConfig();
    config.target >>= 5;

    const auto wins = SimulateWinsForWorkerShares({4, 1, 1}, 360, config);
    const int total_wins = wins[0] + wins[1] + wins[2];
    BOOST_REQUIRE_EQUAL(total_wins, 360);

    BOOST_CHECK_CLOSE_FRACTION(static_cast<double>(wins[0]) / static_cast<double>(total_wins), 4.0 / 6.0, 0.10);
    BOOST_CHECK_CLOSE_FRACTION(static_cast<double>(wins[1]) / static_cast<double>(total_wins), 1.0 / 6.0, 0.10);
    BOOST_CHECK_CLOSE_FRACTION(static_cast<double>(wins[2]) / static_cast<double>(total_wins), 1.0 / 6.0, 0.10);
}

BOOST_AUTO_TEST_CASE(denoise_recovers_product)
{
    const uint256 seed_a = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    const uint256 seed_b = ParseUint256("4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150");
    const uint256 sigma = ParseUint256("ffc381ccd5e78ab52348ec8ba82f51d5feb0e857d7969ab0df9a5891c68cdf15");

    const matmul::Matrix a = matmul::FromSeed(seed_a, 4);
    const matmul::Matrix b = matmul::FromSeed(seed_b, 4);
    const matmul::Matrix clean = a * b;

    const auto np = matmul::noise::Generate(sigma, 4, 2);
    const matmul::Matrix e = np.E_L * np.E_R;
    const matmul::Matrix f = np.F_L * np.F_R;
    const matmul::Matrix noisy = (a + e) * (b + f);

    BOOST_CHECK(matmul::Denoise(noisy, a, b, np) == clean);
}

BOOST_AUTO_TEST_CASE(denoise_zero_noise_identity)
{
    const uint256 seed_a = ParseUint256("0000000000000000000000000000000000000000000000000000000000000000");
    const uint256 seed_b = ParseUint256("4504d44d861b69197db1d95e473442346c4f2bc1f5869996bdccd63cfbdbd150");

    const matmul::Matrix clean = matmul::FromSeed(seed_a, 4) * matmul::FromSeed(seed_b, 4);

    matmul::noise::NoisePair np{
        .E_L = matmul::Matrix(4, 2),
        .E_R = matmul::Matrix(2, 4),
        .F_L = matmul::Matrix(4, 2),
        .F_R = matmul::Matrix(2, 4),
    };

    BOOST_CHECK(matmul::Denoise(clean, matmul::FromSeed(seed_a, 4), matmul::FromSeed(seed_b, 4), np) == clean);
}

BOOST_AUTO_TEST_CASE(denoise_cost_quadratic_r)
{
    constexpr uint32_t n = 64;
    constexpr uint32_t r = 4;

    const matmul::Matrix noisy(n, n);
    const matmul::Matrix a(n, n);
    const matmul::Matrix b(n, n);
    matmul::noise::NoisePair np{
        .E_L = matmul::Matrix(n, r),
        .E_R = matmul::Matrix(r, n),
        .F_L = matmul::Matrix(n, r),
        .F_R = matmul::Matrix(r, n),
    };

    const uint64_t ops = matmul::DenoiseOpsForTest(noisy, a, b, np);
    BOOST_CHECK_EQUAL(ops, 5ULL * n * n * r + 2ULL * n * r * r);
    BOOST_CHECK(ops < static_cast<uint64_t>(n) * n * n);
}

BOOST_AUTO_TEST_CASE(low_rank_kernel_profile_reports_amx_experiment_gate)
{
    ScopedAmxEnv amx_env(nullptr);
    const auto profile = matmul::ProbeLowRankProductProfile(64, 8, 64);

#if defined(__APPLE__)
    BOOST_CHECK(profile.accelerate_compiled);
    BOOST_CHECK(profile.accelerate_active);
#else
    BOOST_CHECK(!profile.accelerate_compiled);
    BOOST_CHECK(!profile.accelerate_active);
#endif
    BOOST_CHECK(!profile.reason.empty());
}

BOOST_AUTO_TEST_CASE(solve_digest_parity_with_amx_experiment_toggle)
{
    auto config = BaseConfig();
    auto state_scalar = BaseState();
    auto state_amx = BaseState();
    uint64_t tries_scalar = 1;
    uint64_t tries_amx = 1;

    {
        ScopedAmxEnv amx_env("0");
        BOOST_REQUIRE(matmul::Solve(state_scalar, config, tries_scalar));
    }
    {
        ScopedAmxEnv amx_env("1");
        BOOST_REQUIRE(matmul::Solve(state_amx, config, tries_amx));
    }

    BOOST_CHECK_EQUAL(state_scalar.digest, state_amx.digest);
}

BOOST_AUTO_TEST_CASE(low_rank_kernel_profile_can_force_disable_amx)
{
    ScopedAmxEnv amx_env("0");
    const auto profile = matmul::ProbeLowRankProductProfile(64, 8, 64);

#if defined(__APPLE__)
    BOOST_CHECK(profile.accelerate_compiled);
    BOOST_CHECK(!profile.accelerate_active);
#else
    BOOST_CHECK(!profile.accelerate_compiled);
    BOOST_CHECK(!profile.accelerate_active);
#endif
    BOOST_CHECK(!profile.reason.empty());
}

BOOST_AUTO_TEST_SUITE_END()
