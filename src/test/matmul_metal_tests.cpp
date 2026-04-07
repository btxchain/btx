// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/accelerated_solver.h>
#include <matmul/backend_capabilities.h>
#include <matmul/matmul_pow.h>
#include <matmul/noise.h>
#include <matmul/transcript.h>
#include <metal/matmul_accel.h>
#include <metal/nonce_accel.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <condition_variable>
#include <cstdlib>
#include <mutex>
#include <string>
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

CBlockHeader BuildHeader(uint32_t n, uint64_t nonce64)
{
    CBlockHeader header{};
    header.nVersion = 1;
    header.hashPrevBlock = ParseUint256("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    header.hashMerkleRoot = ParseUint256("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
    header.nTime = 1'700'000'000U;
    header.nBits = 0x207fffffU;
    header.nNonce64 = nonce64;
    header.nNonce = static_cast<uint32_t>(nonce64);
    header.matmul_dim = static_cast<uint16_t>(n);
    header.seed_a = ParseUint256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    header.seed_b = ParseUint256("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");
    return header;
}

uint256 ComputeReferenceProductDigest(const CBlockHeader& header,
                                      const matmul::Matrix& matrix_a,
                                      const matmul::Matrix& matrix_b,
                                      uint32_t transcript_block_size,
                                      uint32_t noise_rank)
{
    const uint256 sigma = matmul::DeriveSigma(header);
    const auto noise = matmul::noise::Generate(sigma, header.matmul_dim, noise_rank);
    const auto a_prime = matrix_a + (noise.E_L * noise.E_R);
    const auto b_prime = matrix_b + (noise.F_L * noise.F_R);
    return matmul::transcript::ComputeProductCommittedDigestFromPerturbed(
        a_prime,
        b_prime,
        transcript_block_size,
        sigma);
}

class ScopedEnvVar
{
public:
    ScopedEnvVar(const char* name, const char* value) : m_name(name)
    {
        const char* current = std::getenv(name);
        if (current != nullptr) {
            m_had_original = true;
            m_original = current;
        }
#if defined(WIN32)
        _putenv_s(name, value != nullptr ? value : "");
#else
        if (value != nullptr) {
            setenv(name, value, 1);
        } else {
            unsetenv(name);
        }
#endif
    }

    ~ScopedEnvVar()
    {
#if defined(WIN32)
        _putenv_s(m_name, m_had_original ? m_original.c_str() : "");
#else
        if (m_had_original) {
            setenv(m_name, m_original.c_str(), 1);
        } else {
            unsetenv(m_name);
        }
#endif
    }

private:
    const char* m_name;
    bool m_had_original{false};
    std::string m_original;
};

class ThreadGate
{
public:
    explicit ThreadGate(size_t participants) : m_participants(participants)
    {
    }

    void ArriveAndWait()
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        const size_t generation = m_generation;
        ++m_arrived;
        if (m_arrived == m_participants) {
            m_arrived = 0;
            ++m_generation;
            lock.unlock();
            m_cv.notify_all();
            return;
        }
        m_cv.wait(lock, [&] {
            return generation != m_generation;
        });
    }

private:
    const size_t m_participants;
    size_t m_arrived{0};
    size_t m_generation{0};
    std::mutex m_mutex;
    std::condition_variable m_cv;
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_metal_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(metal_digest_matches_cpu_across_supported_dimensions)
{
    constexpr std::array<uint32_t, 2> kDims{8, 16};
    const auto capability = matmul::backend::CapabilityFor(matmul::backend::Kind::METAL);

    for (const uint32_t n : kDims) {
        const uint32_t b = n / 2;
        const uint32_t r = n / 4;
        const CBlockHeader header = BuildHeader(n, 1000 + n);
        const matmul::Matrix matrix_a = matmul::FromSeed(header.seed_a, n);
        const matmul::Matrix matrix_b = matmul::FromSeed(header.seed_b, n);

        const uint256 cpu_digest = matmul::accelerated::ComputeMatMulDigestCPU(
            header,
            matrix_a,
            matrix_b,
            b,
            r);

        const auto digest_result = matmul::accelerated::ComputeMatMulDigest(
            header,
            matrix_a,
            matrix_b,
            b,
            r,
            matmul::backend::Kind::METAL);

        BOOST_REQUIRE(digest_result.ok);
        BOOST_CHECK_EQUAL(digest_result.digest, cpu_digest);
        if (capability.available) {
            BOOST_CHECK_EQUAL(digest_result.backend, matmul::backend::Kind::METAL);
        } else {
            BOOST_CHECK_EQUAL(digest_result.backend, matmul::backend::Kind::CPU);
        }
    }
}

BOOST_AUTO_TEST_CASE(metal_product_digest_matches_cpu_across_supported_dimensions)
{
    constexpr std::array<uint32_t, 2> kDims{8, 16};
    const auto capability = matmul::backend::CapabilityFor(matmul::backend::Kind::METAL);

    for (const uint32_t n : kDims) {
        const uint32_t b = n / 2;
        const uint32_t r = n / 4;
        const CBlockHeader header = BuildHeader(n, 10'000 + n);
        const matmul::Matrix matrix_a = matmul::FromSeed(header.seed_a, n);
        const matmul::Matrix matrix_b = matmul::FromSeed(header.seed_b, n);

        const uint256 cpu_digest = matmul::accelerated::ComputeMatMulDigestCPU(
            header,
            matrix_a,
            matrix_b,
            b,
            r,
            matmul::accelerated::DigestScheme::PRODUCT_COMMITTED);

        const auto digest_result = matmul::accelerated::ComputeMatMulDigest(
            header,
            matrix_a,
            matrix_b,
            b,
            r,
            matmul::backend::Kind::METAL,
            matmul::accelerated::DigestScheme::PRODUCT_COMMITTED);

        BOOST_REQUIRE(digest_result.ok);
        BOOST_CHECK_EQUAL(
            digest_result.digest,
            ComputeReferenceProductDigest(header, matrix_a, matrix_b, b, r));
        BOOST_CHECK_EQUAL(digest_result.digest, cpu_digest);
        if (capability.available) {
            BOOST_CHECK_EQUAL(digest_result.backend, matmul::backend::Kind::METAL);
        } else {
            BOOST_CHECK_EQUAL(digest_result.backend, matmul::backend::Kind::CPU);
        }
    }
}

BOOST_AUTO_TEST_CASE(metal_buffer_pool_reuses_for_repeated_dimension_digest_requests)
{
    const auto probe = btx::metal::ProbeMatMulDigestAcceleration();
    if (!probe.available) {
        const auto pool = btx::metal::ProbeMatMulBufferPool();
        BOOST_CHECK(!pool.available);
        return;
    }

    constexpr uint32_t kN = 16;
    constexpr uint32_t kB = 8;
    constexpr uint32_t kR = 4;
    const matmul::Matrix matrix_a(kN, kN);
    const matmul::Matrix matrix_b(kN, kN);
    const uint256 sigma = ParseUint256("0f0e0d0c0b0a09080706050403020100000102030405060708090a0b0c0d0e0f");
    const auto noise = matmul::noise::Generate(sigma, kN, kR);
    const auto compress_vec = matmul::transcript::DeriveCompressionVector(sigma, kB);

    const auto before = btx::metal::ProbeMatMulBufferPool();
    const uint32_t requests = std::max<uint32_t>(2U, before.slot_count + 1U);
    for (uint32_t i = 0; i < requests; ++i) {
        const auto digest = btx::metal::ComputeCanonicalTranscriptDigest({
            .n = kN,
            .b = kB,
            .r = kR,
            .matrix_a = matrix_a.data(),
            .matrix_b = matrix_b.data(),
            .noise_e_l = noise.E_L.data(),
            .noise_e_r = noise.E_R.data(),
            .noise_f_l = noise.F_L.data(),
            .noise_f_r = noise.F_R.data(),
            .compress_vec = compress_vec.data(),
        });
        BOOST_REQUIRE(digest.success);
    }

    const auto after = btx::metal::ProbeMatMulBufferPool();
    BOOST_CHECK(after.initialized);
    BOOST_CHECK_GE(after.allocation_events + after.reuse_events,
                   before.allocation_events + before.reuse_events + requests);
    BOOST_CHECK_LE(after.allocation_events, before.allocation_events + after.slot_count);
    BOOST_CHECK_GT(after.reuse_events, before.reuse_events);
}

BOOST_AUTO_TEST_CASE(metal_kernel_profile_and_profiling_report_runtime_values)
{
    const auto probe = btx::metal::ProbeMatMulDigestAcceleration();
    const auto kernel = btx::metal::ProbeMatMulKernelProfile();
    const auto profiling = btx::metal::ProbeMatMulProfilingStats();

    BOOST_CHECK_EQUAL(kernel.available, probe.available);
    BOOST_CHECK_EQUAL(profiling.available, probe.available);
    if (!probe.available) {
        BOOST_CHECK(!kernel.reason.empty());
        BOOST_CHECK(!profiling.reason.empty());
        return;
    }

    BOOST_CHECK(kernel.tiled_build_prefix);
    BOOST_CHECK(kernel.fused_prefix_compress);
    BOOST_CHECK(kernel.gpu_transcript_hash);
    BOOST_CHECK(kernel.function_constant_specialization);
    BOOST_CHECK_GT(kernel.specialized_shape_count, 0U);
    BOOST_CHECK_GT(kernel.fused_prefix_threadgroup_threads, 0U);
    BOOST_CHECK(!kernel.specialization_reason.empty());
    BOOST_CHECK(!kernel.library_source.empty());
    BOOST_CHECK(!profiling.reason.empty());
}

BOOST_AUTO_TEST_CASE(metal_function_constant_policy_prefers_mainnet_legacy_path_in_auto_mode)
{
    ScopedEnvVar pipeline_env("BTX_MATMUL_METAL_PIPELINE", "auto");
    ScopedEnvVar specialization_env("BTX_MATMUL_METAL_FUNCTION_CONSTANTS", "auto");

    const auto capability = matmul::backend::CapabilityFor(matmul::backend::Kind::METAL);
    if (!capability.compiled) {
        BOOST_CHECK(!btx::metal::ShouldUseFunctionConstantSpecializationPolicy(/*n=*/512, /*use_legacy_pipeline=*/true));
        BOOST_CHECK(!btx::metal::ShouldUseFunctionConstantSpecializationPolicy(/*n=*/512, /*use_legacy_pipeline=*/false));
        BOOST_CHECK(!btx::metal::ShouldUseFunctionConstantSpecializationPolicy(/*n=*/256, /*use_legacy_pipeline=*/true));
        BOOST_CHECK(!btx::metal::ShouldUseFunctionConstantSpecializationPolicy(/*n=*/256, /*use_legacy_pipeline=*/false));
        return;
    }

    BOOST_CHECK(btx::metal::ShouldUseFunctionConstantSpecializationPolicy(/*n=*/512, /*use_legacy_pipeline=*/true));
    BOOST_CHECK(!btx::metal::ShouldUseFunctionConstantSpecializationPolicy(/*n=*/512, /*use_legacy_pipeline=*/false));
    BOOST_CHECK(btx::metal::ShouldUseFunctionConstantSpecializationPolicy(/*n=*/256, /*use_legacy_pipeline=*/true));
    BOOST_CHECK(btx::metal::ShouldUseFunctionConstantSpecializationPolicy(/*n=*/256, /*use_legacy_pipeline=*/false));
}

BOOST_AUTO_TEST_CASE(metal_mainnet_shape_digest_matches_cpu_under_auto_policy)
{
    const auto capability = matmul::backend::CapabilityFor(matmul::backend::Kind::METAL);
    if (!capability.available) {
        return;
    }

    ScopedEnvVar pipeline_env("BTX_MATMUL_METAL_PIPELINE", "auto");
    ScopedEnvVar specialization_env("BTX_MATMUL_METAL_FUNCTION_CONSTANTS", "auto");

    constexpr uint32_t kN = 512;
    constexpr uint32_t kB = 16;
    constexpr uint32_t kR = 8;

    for (uint64_t nonce64 = 1000; nonce64 < 1004; ++nonce64) {
        const CBlockHeader header = BuildHeader(kN, nonce64);
        const matmul::Matrix matrix_a = matmul::FromSeed(header.seed_a, kN);
        const matmul::Matrix matrix_b = matmul::FromSeed(header.seed_b, kN);

        const uint256 cpu_digest = matmul::accelerated::ComputeMatMulDigestCPU(
            header,
            matrix_a,
            matrix_b,
            kB,
            kR);

        const auto digest_result = matmul::accelerated::ComputeMatMulDigest(
            header,
            matrix_a,
            matrix_b,
            kB,
            kR,
            matmul::backend::Kind::METAL);

        BOOST_REQUIRE(digest_result.ok);
        BOOST_CHECK_EQUAL(digest_result.digest, cpu_digest);
    }
}

BOOST_AUTO_TEST_CASE(metal_batch_digest_matches_single_digest_sequence)
{
    const auto probe = btx::metal::ProbeMatMulDigestAcceleration();
    if (!probe.available) {
        const auto batch = btx::metal::ComputeCanonicalTranscriptDigestBatch({});
        BOOST_CHECK(!batch.available);
        BOOST_CHECK(!batch.success);
        return;
    }

    constexpr uint32_t kN = 16;
    constexpr uint32_t kB = 8;
    constexpr uint32_t kR = 4;
    constexpr uint32_t kBatchSize = 3;

    const matmul::Matrix matrix_a = matmul::FromSeed(
        ParseUint256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        kN);
    const matmul::Matrix matrix_b = matmul::FromSeed(
        ParseUint256("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        kN);

    const auto uploaded = btx::metal::UploadBaseMatrices({
        .n = kN,
        .matrix_a = matrix_a.data(),
        .matrix_b = matrix_b.data(),
    });
    BOOST_REQUIRE(uploaded.success);

    std::vector<matmul::noise::NoisePair> noises;
    std::vector<std::vector<matmul::field::Element>> compress_vectors;
    std::vector<const matmul::field::Element*> noise_e_l_ptrs;
    std::vector<const matmul::field::Element*> noise_e_r_ptrs;
    std::vector<const matmul::field::Element*> noise_f_l_ptrs;
    std::vector<const matmul::field::Element*> noise_f_r_ptrs;
    std::vector<const matmul::field::Element*> compress_ptrs;
    std::vector<uint256> single_hashes;

    noises.reserve(kBatchSize);
    compress_vectors.reserve(kBatchSize);
    noise_e_l_ptrs.reserve(kBatchSize);
    noise_e_r_ptrs.reserve(kBatchSize);
    noise_f_l_ptrs.reserve(kBatchSize);
    noise_f_r_ptrs.reserve(kBatchSize);
    compress_ptrs.reserve(kBatchSize);
    single_hashes.reserve(kBatchSize);

    for (uint32_t i = 0; i < kBatchSize; ++i) {
        const CBlockHeader header = BuildHeader(kN, 9'000 + i);
        const uint256 sigma = matmul::DeriveSigma(header);
        noises.push_back(matmul::noise::Generate(sigma, kN, kR));
        compress_vectors.push_back(matmul::transcript::DeriveCompressionVector(sigma, kB));

        const auto& noise = noises.back();
        const auto& compress = compress_vectors.back();
        noise_e_l_ptrs.push_back(noise.E_L.data());
        noise_e_r_ptrs.push_back(noise.E_R.data());
        noise_f_l_ptrs.push_back(noise.F_L.data());
        noise_f_r_ptrs.push_back(noise.F_R.data());
        compress_ptrs.push_back(compress.data());

        const auto single = btx::metal::ComputeCanonicalTranscriptDigest({
            .n = kN,
            .b = kB,
            .r = kR,
            .use_uploaded_base_matrices = true,
            .noise_e_l = noise.E_L.data(),
            .noise_e_r = noise.E_R.data(),
            .noise_f_l = noise.F_L.data(),
            .noise_f_r = noise.F_R.data(),
            .compress_vec = compress.data(),
        });
        BOOST_REQUIRE(single.success);
        single_hashes.push_back(single.digest);
    }

    const auto batch = btx::metal::ComputeCanonicalTranscriptDigestBatch({
        .n = kN,
        .b = kB,
        .r = kR,
        .batch_size = kBatchSize,
        .use_uploaded_base_matrices = true,
        .noise_e_l = noise_e_l_ptrs.data(),
        .noise_e_r = noise_e_r_ptrs.data(),
        .noise_f_l = noise_f_l_ptrs.data(),
        .noise_f_r = noise_f_r_ptrs.data(),
        .compress_vec = compress_ptrs.data(),
    });
    BOOST_REQUIRE(batch.success);
    BOOST_REQUIRE_EQUAL(batch.digests.size(), kBatchSize);
    for (uint32_t i = 0; i < kBatchSize; ++i) {
        BOOST_CHECK(batch.digests[i] == single_hashes[i]);
    }
}

BOOST_AUTO_TEST_CASE(metal_product_digest_batch_matches_single_digest_sequence)
{
    constexpr uint32_t kN = 16;
    constexpr uint32_t kB = 8;
    constexpr uint32_t kR = 4;
    constexpr uint32_t kBatchSize = 3;

    const matmul::Matrix matrix_a = matmul::FromSeed(
        ParseUint256("abababababababababababababababababababababababababababababababab"),
        kN);
    const matmul::Matrix matrix_b = matmul::FromSeed(
        ParseUint256("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
        kN);

    std::vector<CBlockHeader> headers;
    std::vector<matmul::accelerated::PreparedDigestInputs> prepared_inputs;
    std::vector<uint256> single_digests;
    headers.reserve(kBatchSize);
    prepared_inputs.reserve(kBatchSize);
    single_digests.reserve(kBatchSize);

    for (uint32_t i = 0; i < kBatchSize; ++i) {
        const CBlockHeader header = BuildHeader(kN, 20'000 + i);
        headers.push_back(header);
        prepared_inputs.push_back(matmul::accelerated::PrepareMatMulDigestInputs(
            header,
            kB,
            kR));
        single_digests.push_back(ComputeReferenceProductDigest(header, matrix_a, matrix_b, kB, kR));
    }

    const auto batch = matmul::accelerated::ComputeMatMulDigestPreparedBatch(
        headers,
        matrix_a,
        matrix_b,
        kB,
        kR,
        prepared_inputs,
        matmul::backend::Kind::METAL,
        matmul::accelerated::DigestScheme::PRODUCT_COMMITTED);
    BOOST_REQUIRE_EQUAL(batch.size(), kBatchSize);

    const auto capability = matmul::backend::CapabilityFor(matmul::backend::Kind::METAL);
    for (uint32_t i = 0; i < kBatchSize; ++i) {
        BOOST_REQUIRE(batch[i].ok);
        BOOST_CHECK_EQUAL(batch[i].digest, single_digests[i]);
        if (capability.available) {
            BOOST_CHECK_EQUAL(batch[i].backend, matmul::backend::Kind::METAL);
        } else {
            BOOST_CHECK_EQUAL(batch[i].backend, matmul::backend::Kind::CPU);
        }
    }
}

BOOST_AUTO_TEST_CASE(metal_batch_digest_reuses_staging_pool_for_repeated_requests)
{
    const auto probe = btx::metal::ProbeMatMulDigestAcceleration();
    if (!probe.available) {
        return;
    }

    constexpr uint32_t kN = 16;
    constexpr uint32_t kB = 8;
    constexpr uint32_t kR = 4;
    constexpr uint32_t kBatchSize = 4;

    const matmul::Matrix matrix_a = matmul::FromSeed(
        ParseUint256("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        kN);
    const matmul::Matrix matrix_b = matmul::FromSeed(
        ParseUint256("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
        kN);

    const auto uploaded = btx::metal::UploadBaseMatrices({
        .n = kN,
        .matrix_a = matrix_a.data(),
        .matrix_b = matrix_b.data(),
    });
    BOOST_REQUIRE(uploaded.success);

    std::vector<matmul::noise::NoisePair> noises;
    std::vector<std::vector<matmul::field::Element>> compress_vectors;
    std::vector<const matmul::field::Element*> noise_e_l_ptrs;
    std::vector<const matmul::field::Element*> noise_e_r_ptrs;
    std::vector<const matmul::field::Element*> noise_f_l_ptrs;
    std::vector<const matmul::field::Element*> noise_f_r_ptrs;
    std::vector<const matmul::field::Element*> compress_ptrs;

    noises.reserve(kBatchSize);
    compress_vectors.reserve(kBatchSize);
    noise_e_l_ptrs.reserve(kBatchSize);
    noise_e_r_ptrs.reserve(kBatchSize);
    noise_f_l_ptrs.reserve(kBatchSize);
    noise_f_r_ptrs.reserve(kBatchSize);
    compress_ptrs.reserve(kBatchSize);

    for (uint32_t i = 0; i < kBatchSize; ++i) {
        const CBlockHeader header = BuildHeader(kN, 12'000 + i);
        const uint256 sigma = matmul::DeriveSigma(header);
        noises.push_back(matmul::noise::Generate(sigma, kN, kR));
        compress_vectors.push_back(matmul::transcript::DeriveCompressionVector(sigma, kB));
        noise_e_l_ptrs.push_back(noises.back().E_L.data());
        noise_e_r_ptrs.push_back(noises.back().E_R.data());
        noise_f_l_ptrs.push_back(noises.back().F_L.data());
        noise_f_r_ptrs.push_back(noises.back().F_R.data());
        compress_ptrs.push_back(compress_vectors.back().data());
    }

    const auto before = btx::metal::ProbeMatMulBufferPool();
    const uint32_t requests = std::max<uint32_t>(2U, before.slot_count + 1U);
    for (uint32_t i = 0; i < requests; ++i) {
        const auto batch = btx::metal::ComputeCanonicalTranscriptDigestBatch({
            .n = kN,
            .b = kB,
            .r = kR,
            .batch_size = kBatchSize,
            .use_uploaded_base_matrices = true,
            .noise_e_l = noise_e_l_ptrs.data(),
            .noise_e_r = noise_e_r_ptrs.data(),
            .noise_f_l = noise_f_l_ptrs.data(),
            .noise_f_r = noise_f_r_ptrs.data(),
            .compress_vec = compress_ptrs.data(),
        });
        BOOST_REQUIRE(batch.success);
    }

    const auto after = btx::metal::ProbeMatMulBufferPool();
    BOOST_CHECK(after.initialized);
    BOOST_CHECK_GE(after.allocation_events + after.reuse_events,
                   before.allocation_events + before.reuse_events + requests);
    BOOST_CHECK_LE(after.allocation_events, before.allocation_events + after.slot_count);
    BOOST_CHECK_GT(after.reuse_events, before.reuse_events);
}

BOOST_AUTO_TEST_CASE(metal_concurrent_digest_requests_match_cpu_and_report_pool_contention)
{
    const auto probe = btx::metal::ProbeMatMulDigestAcceleration();
    if (!probe.available) {
        return;
    }

    constexpr uint32_t kN = 512;
    constexpr uint32_t kB = 16;
    constexpr uint32_t kR = 8;
    constexpr size_t kThreads = 2;

    const matmul::Matrix matrix_a = matmul::FromSeed(
        ParseUint256("1111111111111111111111111111111111111111111111111111111111111111"),
        kN);
    const matmul::Matrix matrix_b = matmul::FromSeed(
        ParseUint256("2222222222222222222222222222222222222222222222222222222222222222"),
        kN);

    const auto uploaded = btx::metal::UploadBaseMatrices({
        .n = kN,
        .matrix_a = matrix_a.data(),
        .matrix_b = matrix_b.data(),
    });
    BOOST_REQUIRE(uploaded.success);

    struct WorkerResult {
        bool success{false};
        uint256 digest;
        uint256 expected;
        std::string error;
    };

    std::array<CBlockHeader, kThreads> headers{
        BuildHeader(kN, 52'000),
        BuildHeader(kN, 52'001),
    };
    std::array<WorkerResult, kThreads> results;
    for (size_t i = 0; i < kThreads; ++i) {
        results[i].expected = matmul::accelerated::ComputeMatMulDigestCPU(headers[i], matrix_a, matrix_b, kB, kR);
    }

    const auto before = btx::metal::ProbeMatMulBufferPool();
    ThreadGate gate(kThreads);
    std::vector<std::thread> workers;
    workers.reserve(kThreads);

    for (size_t i = 0; i < kThreads; ++i) {
        workers.emplace_back([&, i] {
            const uint256 sigma = matmul::DeriveSigma(headers[i]);
            const auto noise = matmul::noise::Generate(sigma, kN, kR);
            const auto compress_vec = matmul::transcript::DeriveCompressionVector(sigma, kB);
            gate.ArriveAndWait();

            const auto digest = btx::metal::ComputeCanonicalTranscriptDigest({
                .n = kN,
                .b = kB,
                .r = kR,
                .use_uploaded_base_matrices = true,
                .noise_e_l = noise.E_L.data(),
                .noise_e_r = noise.E_R.data(),
                .noise_f_l = noise.F_L.data(),
                .noise_f_r = noise.F_R.data(),
                .compress_vec = compress_vec.data(),
            });

            results[i].success = digest.success;
            results[i].digest = digest.digest;
            results[i].error = digest.error;
        });
    }

    for (auto& worker : workers) {
        worker.join();
    }

    const auto after = btx::metal::ProbeMatMulBufferPool();
    for (const auto& result : results) {
        BOOST_REQUIRE_MESSAGE(result.success, result.error);
        BOOST_CHECK_EQUAL(result.digest, result.expected);
    }
    BOOST_CHECK(after.initialized);
    BOOST_CHECK_GE(after.slot_count, 1U);
    BOOST_CHECK_EQUAL(after.active_slots, 0U);
    BOOST_CHECK_GE(after.reuse_events + after.allocation_events, before.reuse_events + before.allocation_events + 2);
    BOOST_CHECK_GE(after.high_water_slots, 1U);
    if (after.slot_count >= kThreads) {
        BOOST_CHECK_GE(after.high_water_slots, static_cast<uint32_t>(kThreads));
        BOOST_CHECK_EQUAL(after.wait_events, before.wait_events);
    } else {
        BOOST_CHECK_GT(after.wait_events, before.wait_events);
    }
}

BOOST_AUTO_TEST_CASE(metal_nonce_threshold_tuner_holds_when_pass_rate_in_target_window)
{
    const auto tuned = btx::metal::TuneNoncePrefilterThreshold({
        .current_threshold = 4'000'000'000'000'000'000ULL,
        .batch_size = 1024,
        .observed_candidates = 64,
        .target_min_candidates = 48,
        .target_max_candidates = 80,
    });

    BOOST_CHECK(!tuned.adjusted);
    BOOST_CHECK_EQUAL(tuned.threshold, 4'000'000'000'000'000'000ULL);
}

BOOST_AUTO_TEST_CASE(metal_nonce_threshold_tuner_increases_when_pass_rate_too_low)
{
    const auto tuned = btx::metal::TuneNoncePrefilterThreshold({
        .current_threshold = 1'000'000'000'000'000'000ULL,
        .batch_size = 4096,
        .observed_candidates = 8,
        .target_min_candidates = 128,
        .target_max_candidates = 256,
    });

    BOOST_CHECK(tuned.adjusted);
    BOOST_CHECK_GT(tuned.threshold, 1'000'000'000'000'000'000ULL);
}

BOOST_AUTO_TEST_CASE(metal_nonce_threshold_tuner_decreases_when_pass_rate_too_high)
{
    const auto tuned = btx::metal::TuneNoncePrefilterThreshold({
        .current_threshold = 8'000'000'000'000'000'000ULL,
        .batch_size = 4096,
        .observed_candidates = 2048,
        .target_min_candidates = 128,
        .target_max_candidates = 256,
    });

    BOOST_CHECK(tuned.adjusted);
    BOOST_CHECK_LT(tuned.threshold, 8'000'000'000'000'000'000ULL);
}

BOOST_AUTO_TEST_CASE(metal_nonce_threshold_tuner_handles_zero_candidates_without_overflow)
{
    const auto tuned = btx::metal::TuneNoncePrefilterThreshold({
        .current_threshold = 0,
        .batch_size = 1024,
        .observed_candidates = 0,
        .target_min_candidates = 16,
        .target_max_candidates = 32,
    });

    BOOST_CHECK(tuned.adjusted);
    BOOST_CHECK_GT(tuned.threshold, 0U);
}

BOOST_AUTO_TEST_SUITE_END()
