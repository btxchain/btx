// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/accelerated_solver.h>

#include <matmul/matmul_pow.h>
#include <matmul/noise.h>
#include <matmul/transcript.h>
#include <metal/oracle_accel.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <string_view>
#include <vector>

namespace {

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

CBlockHeader MakeCandidateHeader()
{
    CBlockHeader header;
    header.nVersion = 2;
    header.hashPrevBlock = ParseUint256("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    header.hashMerkleRoot = ParseUint256("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
    header.nTime = 1'700'000'000U;
    header.nBits = 0x207fffffU;
    header.nNonce64 = 42;
    header.nNonce = static_cast<uint32_t>(header.nNonce64);
    header.matmul_dim = 8;
    header.seed_a = ParseUint256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    header.seed_b = ParseUint256("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");
    header.matmul_digest.SetNull();
    return header;
}

uint256 ComputeReferenceProductDigest(const CBlockHeader& header,
                                      const matmul::Matrix& A,
                                      const matmul::Matrix& B,
                                      uint32_t transcript_block_size,
                                      uint32_t noise_rank)
{
    const uint256 sigma = matmul::DeriveSigma(header);
    const auto np = matmul::noise::Generate(sigma, header.matmul_dim, noise_rank);
    const auto A_prime = A + (np.E_L * np.E_R);
    const auto B_prime = B + (np.F_L * np.F_R);
    return matmul::transcript::ComputeProductCommittedDigestFromPerturbed(
        A_prime,
        B_prime,
        transcript_block_size,
        sigma);
}

class ScopedGpuInputEnv
{
public:
    explicit ScopedGpuInputEnv(const char* value)
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_GPU_INPUTS", value != nullptr ? value : "");
#else
        if (value != nullptr) {
            setenv("BTX_MATMUL_GPU_INPUTS", value, 1);
        } else {
            unsetenv("BTX_MATMUL_GPU_INPUTS");
        }
#endif
    }

    ~ScopedGpuInputEnv()
    {
#if defined(WIN32)
        _putenv_s("BTX_MATMUL_GPU_INPUTS", "");
#else
        unsetenv("BTX_MATMUL_GPU_INPUTS");
#endif
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_accelerated_solver_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cpu_digest_matches_canonical_reference)
{
    constexpr uint32_t kTranscriptBlockSize = 4;
    constexpr uint32_t kNoiseRank = 2;

    const CBlockHeader header = MakeCandidateHeader();
    const matmul::Matrix A = matmul::FromSeed(header.seed_a, header.matmul_dim);
    const matmul::Matrix B = matmul::FromSeed(header.seed_b, header.matmul_dim);

    const uint256 cpu_digest = matmul::accelerated::ComputeMatMulDigestCPU(
        header,
        A,
        B,
        kTranscriptBlockSize,
        kNoiseRank);

    const uint256 sigma = matmul::DeriveSigma(header);
    const auto np = matmul::noise::Generate(sigma, header.matmul_dim, kNoiseRank);
    const auto A_prime = A + (np.E_L * np.E_R);
    const auto B_prime = B + (np.F_L * np.F_R);
    const auto canonical = matmul::transcript::CanonicalMatMul(A_prime, B_prime, kTranscriptBlockSize, sigma);

    BOOST_CHECK_EQUAL(cpu_digest, canonical.transcript_hash);
}

BOOST_AUTO_TEST_CASE(cpu_product_digest_matches_canonical_reference)
{
    constexpr uint32_t kTranscriptBlockSize = 4;
    constexpr uint32_t kNoiseRank = 2;

    const CBlockHeader header = MakeCandidateHeader();
    const matmul::Matrix A = matmul::FromSeed(header.seed_a, header.matmul_dim);
    const matmul::Matrix B = matmul::FromSeed(header.seed_b, header.matmul_dim);

    const uint256 cpu_digest = matmul::accelerated::ComputeMatMulDigestCPU(
        header,
        A,
        B,
        kTranscriptBlockSize,
        kNoiseRank,
        matmul::accelerated::DigestScheme::PRODUCT_COMMITTED);

    BOOST_CHECK_EQUAL(
        cpu_digest,
        ComputeReferenceProductDigest(header, A, B, kTranscriptBlockSize, kNoiseRank));
}

BOOST_AUTO_TEST_CASE(metal_digest_matches_cpu_or_cleanly_falls_back)
{
    constexpr uint32_t kTranscriptBlockSize = 4;
    constexpr uint32_t kNoiseRank = 2;

    const CBlockHeader header = MakeCandidateHeader();
    const matmul::Matrix A = matmul::FromSeed(header.seed_a, header.matmul_dim);
    const matmul::Matrix B = matmul::FromSeed(header.seed_b, header.matmul_dim);

    const uint256 cpu_digest = matmul::accelerated::ComputeMatMulDigestCPU(
        header,
        A,
        B,
        kTranscriptBlockSize,
        kNoiseRank);

    const auto digest_result = matmul::accelerated::ComputeMatMulDigest(
        header,
        A,
        B,
        kTranscriptBlockSize,
        kNoiseRank,
        matmul::backend::Kind::METAL);

    BOOST_CHECK(digest_result.ok);
    BOOST_CHECK_EQUAL(digest_result.digest, cpu_digest);

    if (digest_result.backend == matmul::backend::Kind::METAL) {
        BOOST_CHECK(digest_result.accelerated);
    } else {
        BOOST_CHECK_EQUAL(digest_result.backend, matmul::backend::Kind::CPU);
    }
}

BOOST_AUTO_TEST_CASE(prepared_digest_inputs_match_direct_path)
{
    constexpr uint32_t kTranscriptBlockSize = 4;
    constexpr uint32_t kNoiseRank = 2;

    const CBlockHeader header = MakeCandidateHeader();
    const matmul::Matrix A = matmul::FromSeed(header.seed_a, header.matmul_dim);
    const matmul::Matrix B = matmul::FromSeed(header.seed_b, header.matmul_dim);

    const auto prepared = matmul::accelerated::PrepareMatMulDigestInputs(
        header,
        kTranscriptBlockSize,
        kNoiseRank);
    const auto prepared_cpu = matmul::accelerated::ComputeMatMulDigestPrepared(
        header,
        A,
        B,
        kTranscriptBlockSize,
        kNoiseRank,
        prepared,
        matmul::backend::Kind::CPU);
    const auto direct_cpu = matmul::accelerated::ComputeMatMulDigest(
        header,
        A,
        B,
        kTranscriptBlockSize,
        kNoiseRank,
        matmul::backend::Kind::CPU);

    BOOST_REQUIRE(prepared_cpu.ok);
    BOOST_REQUIRE(direct_cpu.ok);
    BOOST_CHECK_EQUAL(prepared_cpu.digest, direct_cpu.digest);
}

BOOST_AUTO_TEST_CASE(prepared_product_digest_inputs_match_direct_path)
{
    constexpr uint32_t kTranscriptBlockSize = 4;
    constexpr uint32_t kNoiseRank = 2;

    const CBlockHeader header = MakeCandidateHeader();
    const matmul::Matrix A = matmul::FromSeed(header.seed_a, header.matmul_dim);
    const matmul::Matrix B = matmul::FromSeed(header.seed_b, header.matmul_dim);

    const auto prepared = matmul::accelerated::PrepareMatMulDigestInputs(
        header,
        kTranscriptBlockSize,
        kNoiseRank);
    const auto prepared_cpu = matmul::accelerated::ComputeMatMulDigestPrepared(
        header,
        A,
        B,
        kTranscriptBlockSize,
        kNoiseRank,
        prepared,
        matmul::backend::Kind::CPU,
        matmul::accelerated::DigestScheme::PRODUCT_COMMITTED);
    const auto direct_cpu = matmul::accelerated::ComputeMatMulDigest(
        header,
        A,
        B,
        kTranscriptBlockSize,
        kNoiseRank,
        matmul::backend::Kind::CPU,
        matmul::accelerated::DigestScheme::PRODUCT_COMMITTED);

    BOOST_REQUIRE(prepared_cpu.ok);
    BOOST_REQUIRE(direct_cpu.ok);
    BOOST_CHECK_EQUAL(prepared_cpu.digest, direct_cpu.digest);
}

BOOST_AUTO_TEST_CASE(prepared_batch_digest_matches_direct_cpu_sequence)
{
    constexpr uint32_t kTranscriptBlockSize = 4;
    constexpr uint32_t kNoiseRank = 2;
    constexpr uint32_t kBatchSize = 3;

    const CBlockHeader base_header = MakeCandidateHeader();
    const matmul::Matrix A = matmul::FromSeed(base_header.seed_a, base_header.matmul_dim);
    const matmul::Matrix B = matmul::FromSeed(base_header.seed_b, base_header.matmul_dim);

    std::vector<CBlockHeader> headers;
    std::vector<matmul::accelerated::PreparedDigestInputs> prepared_inputs;
    headers.reserve(kBatchSize);
    prepared_inputs.reserve(kBatchSize);

    for (uint32_t i = 0; i < kBatchSize; ++i) {
        CBlockHeader header = base_header;
        header.nNonce64 += i;
        header.nNonce = static_cast<uint32_t>(header.nNonce64);
        headers.push_back(header);
        prepared_inputs.push_back(matmul::accelerated::PrepareMatMulDigestInputs(
            header,
            kTranscriptBlockSize,
            kNoiseRank));
    }

    const auto batch = matmul::accelerated::ComputeMatMulDigestPreparedBatch(
        headers,
        A,
        B,
        kTranscriptBlockSize,
        kNoiseRank,
        prepared_inputs,
        matmul::backend::Kind::CPU);
    BOOST_REQUIRE_EQUAL(batch.size(), kBatchSize);

    for (uint32_t i = 0; i < kBatchSize; ++i) {
        const auto single = matmul::accelerated::ComputeMatMulDigestPrepared(
            headers[i],
            A,
            B,
            kTranscriptBlockSize,
            kNoiseRank,
            prepared_inputs[i],
            matmul::backend::Kind::CPU);
        BOOST_REQUIRE(single.ok);
        BOOST_REQUIRE(batch[i].ok);
        BOOST_CHECK_EQUAL(batch[i].digest, single.digest);
        BOOST_CHECK_EQUAL(batch[i].backend, single.backend);
    }
}

BOOST_AUTO_TEST_CASE(prepared_batch_product_digest_matches_direct_cpu_sequence)
{
    constexpr uint32_t kTranscriptBlockSize = 4;
    constexpr uint32_t kNoiseRank = 2;
    constexpr uint32_t kBatchSize = 3;

    const CBlockHeader base_header = MakeCandidateHeader();
    const matmul::Matrix A = matmul::FromSeed(base_header.seed_a, base_header.matmul_dim);
    const matmul::Matrix B = matmul::FromSeed(base_header.seed_b, base_header.matmul_dim);

    std::vector<CBlockHeader> headers;
    std::vector<matmul::accelerated::PreparedDigestInputs> prepared_inputs;
    headers.reserve(kBatchSize);
    prepared_inputs.reserve(kBatchSize);

    for (uint32_t i = 0; i < kBatchSize; ++i) {
        CBlockHeader header = base_header;
        header.nNonce64 += i;
        header.nNonce = static_cast<uint32_t>(header.nNonce64);
        headers.push_back(header);
        prepared_inputs.push_back(matmul::accelerated::PrepareMatMulDigestInputs(
            header,
            kTranscriptBlockSize,
            kNoiseRank));
    }

    const auto batch = matmul::accelerated::ComputeMatMulDigestPreparedBatch(
        headers,
        A,
        B,
        kTranscriptBlockSize,
        kNoiseRank,
        prepared_inputs,
        matmul::backend::Kind::CPU,
        matmul::accelerated::DigestScheme::PRODUCT_COMMITTED);
    BOOST_REQUIRE_EQUAL(batch.size(), kBatchSize);

    for (uint32_t i = 0; i < kBatchSize; ++i) {
        const auto single = matmul::accelerated::ComputeMatMulDigestPrepared(
            headers[i],
            A,
            B,
            kTranscriptBlockSize,
            kNoiseRank,
            prepared_inputs[i],
            matmul::backend::Kind::CPU,
            matmul::accelerated::DigestScheme::PRODUCT_COMMITTED);
        BOOST_REQUIRE(single.ok);
        BOOST_REQUIRE(batch[i].ok);
        BOOST_CHECK_EQUAL(batch[i].digest, single.digest);
        BOOST_CHECK_EQUAL(batch[i].backend, single.backend);
    }
}

BOOST_AUTO_TEST_CASE(backend_prepared_inputs_gpu_generation_path_preserves_digest)
{
    ScopedGpuInputEnv gpu_env("1");
    constexpr uint32_t kTranscriptBlockSize = 4;
    constexpr uint32_t kNoiseRank = 2;

    const CBlockHeader header = MakeCandidateHeader();
    const matmul::Matrix A = matmul::FromSeed(header.seed_a, header.matmul_dim);
    const matmul::Matrix B = matmul::FromSeed(header.seed_b, header.matmul_dim);

    const auto prepared = matmul::accelerated::PrepareMatMulDigestInputsForBackend(
        header,
        kTranscriptBlockSize,
        kNoiseRank,
        matmul::backend::Kind::METAL);
    const auto prepared_cpu = matmul::accelerated::ComputeMatMulDigestPrepared(
        header,
        A,
        B,
        kTranscriptBlockSize,
        kNoiseRank,
        prepared,
        matmul::backend::Kind::CPU);
    const auto direct_cpu = matmul::accelerated::ComputeMatMulDigest(
        header,
        A,
        B,
        kTranscriptBlockSize,
        kNoiseRank,
        matmul::backend::Kind::CPU);

    BOOST_REQUIRE(prepared_cpu.ok);
    BOOST_REQUIRE(direct_cpu.ok);
    BOOST_CHECK_EQUAL(prepared_cpu.digest, direct_cpu.digest);
}

BOOST_AUTO_TEST_CASE(backend_prepared_inputs_gpu_generation_auto_mode_records_profile_samples)
{
    ScopedGpuInputEnv gpu_env(nullptr);
    constexpr uint32_t kTranscriptBlockSize = 4;
    constexpr uint32_t kNoiseRank = 2;

    const CBlockHeader header = MakeCandidateHeader();
    const auto profile_before = btx::metal::ProbeMatMulInputGenerationProfile();
    const auto prepared = matmul::accelerated::PrepareMatMulDigestInputsForBackend(
        header,
        kTranscriptBlockSize,
        kNoiseRank,
        matmul::backend::Kind::METAL);
    const auto profile_after = btx::metal::ProbeMatMulInputGenerationProfile();

    if (!profile_after.available) {
        BOOST_CHECK(!profile_after.reason.empty());
        return;
    }

    const bool expect_gpu_generation = matmul::accelerated::ShouldUseGpuGeneratedInputsForShape(
        matmul::backend::Kind::METAL,
        header.matmul_dim,
        kTranscriptBlockSize,
        kNoiseRank);
    if (expect_gpu_generation) {
        BOOST_CHECK_GT(profile_after.samples, profile_before.samples);
    } else {
        BOOST_CHECK_EQUAL(profile_after.samples, profile_before.samples);
    }
    BOOST_CHECK(!profile_after.reason.empty());
    BOOST_CHECK(!prepared.compress_vec.empty());
}

BOOST_AUTO_TEST_CASE(backend_runtime_stats_track_cpu_digest_requests)
{
    matmul::accelerated::ResetMatMulBackendRuntimeStats();

    constexpr uint32_t kTranscriptBlockSize = 4;
    constexpr uint32_t kNoiseRank = 2;

    const CBlockHeader header = MakeCandidateHeader();
    const matmul::Matrix A = matmul::FromSeed(header.seed_a, header.matmul_dim);
    const matmul::Matrix B = matmul::FromSeed(header.seed_b, header.matmul_dim);

    const auto digest_result = matmul::accelerated::ComputeMatMulDigest(
        header,
        A,
        B,
        kTranscriptBlockSize,
        kNoiseRank,
        matmul::backend::Kind::CPU);
    BOOST_REQUIRE(digest_result.ok);

    const auto stats = matmul::accelerated::ProbeMatMulBackendRuntimeStats();
    BOOST_CHECK_EQUAL(stats.digest_requests, 1U);
    BOOST_CHECK_EQUAL(stats.requested_cpu, 1U);
    BOOST_CHECK_EQUAL(stats.requested_metal, 0U);
    BOOST_CHECK_EQUAL(stats.requested_cuda, 0U);
    BOOST_CHECK_EQUAL(stats.metal_successes, 0U);
    BOOST_CHECK_EQUAL(stats.metal_fallbacks_to_cpu, 0U);
}

BOOST_AUTO_TEST_CASE(gpu_input_auto_mode_disables_after_hard_failure)
{
    ScopedGpuInputEnv gpu_env(nullptr);
    matmul::accelerated::ResetMatMulBackendRuntimeStats();

    const CBlockHeader header = MakeCandidateHeader();
    constexpr uint32_t kTranscriptBlockSize = 4;
    constexpr uint32_t kInvalidNoiseRank = 16;

    (void)matmul::accelerated::PrepareMatMulDigestInputsForBackend(
        header,
        kTranscriptBlockSize,
        kInvalidNoiseRank,
        matmul::backend::Kind::METAL);
    const auto after_failure = matmul::accelerated::ProbeMatMulBackendRuntimeStats();

#if defined(__APPLE__)
    constexpr uint32_t kValidNoiseRank = 2;
    BOOST_CHECK_GE(after_failure.gpu_input_generation_attempts, 0U);
    BOOST_CHECK_GE(after_failure.gpu_input_generation_failures, 0U);
    const uint64_t attempts_after_failure = after_failure.gpu_input_generation_attempts;

    (void)matmul::accelerated::PrepareMatMulDigestInputsForBackend(
        header,
        kTranscriptBlockSize,
        kValidNoiseRank,
        matmul::backend::Kind::METAL);
    const auto after_second = matmul::accelerated::ProbeMatMulBackendRuntimeStats();
    if (after_failure.gpu_input_auto_disabled) {
        BOOST_CHECK(after_second.gpu_input_auto_disabled);
        BOOST_CHECK_EQUAL(after_second.gpu_input_generation_attempts, attempts_after_failure);
        BOOST_CHECK_GE(after_second.gpu_input_auto_disabled_skips, 1U);
    } else {
        BOOST_CHECK_GE(after_second.gpu_input_generation_attempts, attempts_after_failure);
    }
#else
    BOOST_CHECK_EQUAL(after_failure.gpu_input_generation_attempts, 0U);
    BOOST_CHECK_EQUAL(after_failure.gpu_input_generation_failures, 0U);
    BOOST_CHECK(!after_failure.gpu_input_auto_disabled);
#endif
}

BOOST_AUTO_TEST_CASE(gpu_input_forced_mode_keeps_attempting_after_failures)
{
    ScopedGpuInputEnv gpu_env("1");
    matmul::accelerated::ResetMatMulBackendRuntimeStats();

    const CBlockHeader header = MakeCandidateHeader();
    constexpr uint32_t kTranscriptBlockSize = 4;
    constexpr uint32_t kInvalidNoiseRank = 16;

    (void)matmul::accelerated::PrepareMatMulDigestInputsForBackend(
        header,
        kTranscriptBlockSize,
        kInvalidNoiseRank,
        matmul::backend::Kind::METAL);
    (void)matmul::accelerated::PrepareMatMulDigestInputsForBackend(
        header,
        kTranscriptBlockSize,
        kInvalidNoiseRank,
        matmul::backend::Kind::METAL);

    const auto stats = matmul::accelerated::ProbeMatMulBackendRuntimeStats();
    BOOST_CHECK_EQUAL(stats.gpu_input_generation_attempts, 2U);
    BOOST_CHECK_EQUAL(stats.gpu_input_generation_failures, 2U);
    BOOST_CHECK(!stats.gpu_input_auto_disabled);
    BOOST_CHECK_EQUAL(stats.gpu_input_auto_disabled_skips, 0U);
}

BOOST_AUTO_TEST_CASE(gpu_input_auto_disable_policy_distinguishes_hard_and_transient_failures)
{
    BOOST_CHECK(matmul::accelerated::ShouldDisableGpuInputAutoModeForError("invalid dimensions for GPU input generation"));
    BOOST_CHECK(matmul::accelerated::ShouldDisableGpuInputAutoModeForError("noise rank exceeds matrix dimension"));
    BOOST_CHECK(matmul::accelerated::ShouldDisableGpuInputAutoModeForError("matrix dimension must be divisible by transcript block size"));
    BOOST_CHECK(matmul::accelerated::ShouldDisableGpuInputAutoModeForError("input generation dimensions exceed supported bounds"));
    BOOST_CHECK(matmul::accelerated::ShouldDisableGpuInputAutoModeForError("Metal context initialization failed"));

    BOOST_CHECK(!matmul::accelerated::ShouldDisableGpuInputAutoModeForError("Failed to create Metal command buffer"));
    BOOST_CHECK(!matmul::accelerated::ShouldDisableGpuInputAutoModeForError("unknown Metal command failure"));
}

BOOST_AUTO_TEST_CASE(gpu_input_auto_policy_disabled_on_all_platforms)
{
    // AUTO mode now always returns false to avoid GPU/CPU input divergence
    // that caused cpu_confirm_candidates to reject Metal solutions.
    ScopedGpuInputEnv gpu_env(nullptr);

    BOOST_CHECK(!matmul::accelerated::ShouldUseGpuGeneratedInputsForShape(
        matmul::backend::Kind::METAL,
        /*n=*/512,
        /*b=*/16,
        /*r=*/8));
    BOOST_CHECK(!matmul::accelerated::ShouldUseGpuGeneratedInputsForShape(
        matmul::backend::Kind::METAL,
        /*n=*/256,
        /*b=*/8,
        /*r=*/4));
    BOOST_CHECK(!matmul::accelerated::ShouldUseGpuGeneratedInputsForShape(
        matmul::backend::Kind::METAL,
        /*n=*/64,
        /*b=*/8,
        /*r=*/4));
}

BOOST_AUTO_TEST_CASE(metal_retry_policy_only_retries_uploaded_base_stale_errors)
{
    BOOST_CHECK(matmul::accelerated::ShouldRetryMetalDigestWithoutUploadedBase(
        "uploaded base matrices are unavailable or stale for requested dimension"));

    BOOST_CHECK(!matmul::accelerated::ShouldRetryMetalDigestWithoutUploadedBase(
        "Failed to create Metal command buffer"));
    BOOST_CHECK(!matmul::accelerated::ShouldRetryMetalDigestWithoutUploadedBase(
        "invalid MatMul request dimensions"));
}

BOOST_AUTO_TEST_CASE(cuda_digest_is_scaffolded_and_falls_back_to_cpu)
{
    constexpr uint32_t kTranscriptBlockSize = 4;
    constexpr uint32_t kNoiseRank = 2;

    const CBlockHeader header = MakeCandidateHeader();
    const matmul::Matrix A = matmul::FromSeed(header.seed_a, header.matmul_dim);
    const matmul::Matrix B = matmul::FromSeed(header.seed_b, header.matmul_dim);

    const uint256 cpu_digest = matmul::accelerated::ComputeMatMulDigestCPU(
        header,
        A,
        B,
        kTranscriptBlockSize,
        kNoiseRank);

    const auto digest_result = matmul::accelerated::ComputeMatMulDigest(
        header,
        A,
        B,
        kTranscriptBlockSize,
        kNoiseRank,
        matmul::backend::Kind::CUDA);

    BOOST_CHECK(digest_result.ok);
    BOOST_CHECK_EQUAL(digest_result.backend, matmul::backend::Kind::CPU);
    BOOST_CHECK(!digest_result.accelerated);
    BOOST_CHECK_EQUAL(digest_result.digest, cpu_digest);
    BOOST_CHECK(!digest_result.error.empty());
}

BOOST_AUTO_TEST_SUITE_END()
