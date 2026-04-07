// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/backend_capabilities.h>
#include <matmul/noise.h>
#include <matmul/matrix.h>
#include <matmul/transcript.h>
#include <metal/matmul_accel.h>
#include <metal/oracle_accel.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <unistd.h>

namespace {

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

} // namespace

BOOST_AUTO_TEST_SUITE(matmul_backend_capabilities_tests)

BOOST_AUTO_TEST_CASE(cpu_backend_always_available)
{
    const auto capability = matmul::backend::CapabilityFor(matmul::backend::Kind::CPU);
    BOOST_CHECK(capability.compiled);
    BOOST_CHECK(capability.available);
    BOOST_CHECK_EQUAL(capability.reason, "always_available");
}

BOOST_AUTO_TEST_CASE(unknown_backend_falls_back_to_cpu)
{
    const auto selection = matmul::backend::ResolveRequestedBackend("not-a-backend");
    BOOST_CHECK(!selection.requested_known);
    BOOST_CHECK_EQUAL(matmul::backend::ToString(selection.requested), "cpu");
    BOOST_CHECK_EQUAL(matmul::backend::ToString(selection.active), "cpu");
    BOOST_CHECK_EQUAL(selection.reason, "unknown_backend_fallback_to_cpu");
}

BOOST_AUTO_TEST_CASE(cuda_backend_is_disabled_by_default)
{
    const auto capability = matmul::backend::CapabilityFor(matmul::backend::Kind::CUDA);
    if (!capability.compiled) {
        BOOST_CHECK(!capability.available);
        BOOST_CHECK_EQUAL(capability.reason, "disabled_by_build");
    } else {
        BOOST_CHECK(!capability.available);
        BOOST_CHECK_EQUAL(capability.reason, "runtime_probe_not_implemented");
    }
}

BOOST_AUTO_TEST_CASE(metal_or_mlx_request_uses_same_backend)
{
    const auto capability = matmul::backend::CapabilityFor(matmul::backend::Kind::METAL);
    const auto metal_selection = matmul::backend::ResolveRequestedBackend("metal");
    const auto mlx_selection = matmul::backend::ResolveRequestedBackend("mlx");

    BOOST_CHECK(metal_selection.requested_known);
    BOOST_CHECK(mlx_selection.requested_known);
    BOOST_CHECK_EQUAL(matmul::backend::ToString(metal_selection.requested), "metal");
    BOOST_CHECK_EQUAL(matmul::backend::ToString(mlx_selection.requested), "metal");

    if (capability.available) {
        BOOST_CHECK_EQUAL(matmul::backend::ToString(metal_selection.active), "metal");
        BOOST_CHECK_EQUAL(matmul::backend::ToString(mlx_selection.active), "metal");
        BOOST_CHECK_EQUAL(metal_selection.reason, "requested_backend_available");
        BOOST_CHECK_EQUAL(mlx_selection.reason, "requested_backend_available");
    } else {
        BOOST_CHECK_EQUAL(matmul::backend::ToString(metal_selection.active), "cpu");
        BOOST_CHECK_EQUAL(matmul::backend::ToString(mlx_selection.active), "cpu");
        BOOST_CHECK(metal_selection.reason.find("metal_unavailable_fallback_to_cpu") == 0);
        BOOST_CHECK(mlx_selection.reason.find("metal_unavailable_fallback_to_cpu") == 0);
    }
}

BOOST_AUTO_TEST_CASE(metal_base_matrix_upload_api_matches_probe_state)
{
    constexpr uint32_t kN = 8;

    const auto probe = btx::metal::ProbeMatMulDigestAcceleration();

    const auto invalid = btx::metal::UploadBaseMatrices({
        .n = kN,
        .matrix_a = nullptr,
        .matrix_b = nullptr,
    });
    BOOST_CHECK_EQUAL(invalid.available, probe.available);
    BOOST_CHECK(!invalid.success);
    BOOST_CHECK(!invalid.error.empty());

    const matmul::Matrix matrix_a(kN, kN);
    const matmul::Matrix matrix_b(kN, kN);
    const auto valid = btx::metal::UploadBaseMatrices({
        .n = kN,
        .matrix_a = matrix_a.data(),
        .matrix_b = matrix_b.data(),
    });
    BOOST_CHECK_EQUAL(valid.available, probe.available);
    if (probe.available) {
        BOOST_CHECK(valid.success);
    } else {
        BOOST_CHECK(!valid.success);
    }
}

BOOST_AUTO_TEST_CASE(metal_async_digest_submission_api_matches_probe_state)
{
    constexpr uint32_t kN = 8;
    constexpr uint32_t kB = 4;
    constexpr uint32_t kR = 2;

    const auto probe = btx::metal::ProbeMatMulDigestAcceleration();
    const matmul::Matrix matrix_a(kN, kN);
    const matmul::Matrix matrix_b(kN, kN);
    const uint256 sigma = ParseUint256("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    const auto noise = matmul::noise::Generate(sigma, kN, kR);
    const auto compress_vec = matmul::transcript::DeriveCompressionVector(sigma, kB);

    const auto submission = btx::metal::SubmitCanonicalTranscriptDigest({
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

    BOOST_CHECK_EQUAL(submission.available, probe.available);
    if (!probe.available) {
        BOOST_CHECK(!submission.submitted);
        BOOST_CHECK(!btx::metal::IsCanonicalTranscriptDigestSubmissionReady(submission));
        const auto result = btx::metal::WaitForCanonicalTranscriptDigestSubmission(
            btx::metal::SubmitCanonicalTranscriptDigest({}));
        BOOST_CHECK(!result.success);
        BOOST_CHECK(!result.error.empty());
        return;
    }

    BOOST_REQUIRE(submission.submitted);
    const auto result = btx::metal::WaitForCanonicalTranscriptDigestSubmission(
        btx::metal::SubmitCanonicalTranscriptDigest({
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
        }));
    BOOST_CHECK(result.success);
}

BOOST_AUTO_TEST_CASE(metal_async_batch_digest_submission_api_matches_probe_state)
{
    constexpr uint32_t kN = 8;
    constexpr uint32_t kB = 4;
    constexpr uint32_t kR = 2;

    const auto probe = btx::metal::ProbeMatMulDigestAcceleration();
    const matmul::Matrix matrix_a(kN, kN);
    const matmul::Matrix matrix_b(kN, kN);
    const uint256 sigma0 = ParseUint256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const uint256 sigma1 = ParseUint256("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    const auto noise0 = matmul::noise::Generate(sigma0, kN, kR);
    const auto noise1 = matmul::noise::Generate(sigma1, kN, kR);
    const auto compress0 = matmul::transcript::DeriveCompressionVector(sigma0, kB);
    const auto compress1 = matmul::transcript::DeriveCompressionVector(sigma1, kB);
    const matmul::field::Element* noise_e_l[] = {noise0.E_L.data(), noise1.E_L.data()};
    const matmul::field::Element* noise_e_r[] = {noise0.E_R.data(), noise1.E_R.data()};
    const matmul::field::Element* noise_f_l[] = {noise0.F_L.data(), noise1.F_L.data()};
    const matmul::field::Element* noise_f_r[] = {noise0.F_R.data(), noise1.F_R.data()};
    const matmul::field::Element* compress_vec[] = {compress0.data(), compress1.data()};

    const auto submission = btx::metal::SubmitCanonicalTranscriptDigestBatch({
        .n = kN,
        .b = kB,
        .r = kR,
        .batch_size = 2,
        .matrix_a = matrix_a.data(),
        .matrix_b = matrix_b.data(),
        .noise_e_l = noise_e_l,
        .noise_e_r = noise_e_r,
        .noise_f_l = noise_f_l,
        .noise_f_r = noise_f_r,
        .compress_vec = compress_vec,
    });

    BOOST_CHECK_EQUAL(submission.available, probe.available);
    if (!probe.available) {
        BOOST_CHECK(!submission.submitted);
        BOOST_CHECK(!btx::metal::IsCanonicalTranscriptDigestBatchSubmissionReady(submission));
        const auto result = btx::metal::WaitForCanonicalTranscriptDigestBatchSubmission(
            btx::metal::SubmitCanonicalTranscriptDigestBatch({}));
        BOOST_CHECK(!result.success);
        BOOST_CHECK(!result.error.empty());
        return;
    }

    BOOST_REQUIRE(submission.submitted);
    const auto result = btx::metal::WaitForCanonicalTranscriptDigestBatchSubmission(
        btx::metal::SubmitCanonicalTranscriptDigestBatch({
            .n = kN,
            .b = kB,
            .r = kR,
            .batch_size = 2,
            .matrix_a = matrix_a.data(),
            .matrix_b = matrix_b.data(),
            .noise_e_l = noise_e_l,
            .noise_e_r = noise_e_r,
            .noise_f_l = noise_f_l,
            .noise_f_r = noise_f_r,
            .compress_vec = compress_vec,
        }));
    BOOST_CHECK(result.success);
    BOOST_CHECK_EQUAL(result.digests.size(), 2U);
}

BOOST_AUTO_TEST_CASE(metal_digest_accepts_uploaded_base_matrices_and_reuses_buffer_pool)
{
    constexpr uint32_t kN = 8;
    constexpr uint32_t kB = 4;
    constexpr uint32_t kR = 2;

    const auto probe = btx::metal::ProbeMatMulDigestAcceleration();
    const auto pool_before = btx::metal::ProbeMatMulBufferPool();
    BOOST_CHECK_EQUAL(pool_before.available, probe.available);

    const matmul::Matrix matrix_a(kN, kN);
    const matmul::Matrix matrix_b(kN, kN);
    const uint256 sigma = ParseUint256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    const auto noise = matmul::noise::Generate(sigma, kN, kR);
    const auto compress_vec = matmul::transcript::DeriveCompressionVector(sigma, kB);

    const auto explicit_result = btx::metal::ComputeCanonicalTranscriptDigest({
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
    BOOST_CHECK_EQUAL(explicit_result.available, probe.available);
    if (!probe.available) {
        BOOST_CHECK(!explicit_result.success);
        return;
    }
    BOOST_REQUIRE(explicit_result.success);

    const auto upload = btx::metal::UploadBaseMatrices({
        .n = kN,
        .matrix_a = matrix_a.data(),
        .matrix_b = matrix_b.data(),
    });
    BOOST_REQUIRE(upload.success);

    const auto uploaded_result = btx::metal::ComputeCanonicalTranscriptDigest({
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
    BOOST_REQUIRE(uploaded_result.success);
    BOOST_CHECK(uploaded_result.digest == explicit_result.digest);

    const auto pool_after_first = btx::metal::ProbeMatMulBufferPool();
    const uint64_t total_before = pool_before.allocation_events + pool_before.reuse_events;
    const uint64_t total_after_first = pool_after_first.allocation_events + pool_after_first.reuse_events;
    BOOST_CHECK(pool_after_first.initialized);
    BOOST_CHECK_GT(total_after_first, total_before);

    const auto uploaded_result_second = btx::metal::ComputeCanonicalTranscriptDigest({
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
    BOOST_REQUIRE(uploaded_result_second.success);
    BOOST_CHECK(uploaded_result_second.digest == explicit_result.digest);

    const auto pool_after_second = btx::metal::ProbeMatMulBufferPool();
    const uint64_t total_after_second = pool_after_second.allocation_events + pool_after_second.reuse_events;
    BOOST_CHECK_GT(total_after_second, total_after_first);
    BOOST_CHECK_GT(pool_after_second.reuse_events, pool_after_first.reuse_events);
}

BOOST_AUTO_TEST_CASE(metal_dispatch_probe_matches_runtime_availability)
{
    const auto probe = btx::metal::ProbeMatMulDigestAcceleration();
    const auto dispatch = btx::metal::ProbeMatMulDispatchConfig();

    BOOST_CHECK_EQUAL(dispatch.available, probe.available);
    if (!probe.available) {
        BOOST_CHECK(!dispatch.reason.empty());
        return;
    }

    BOOST_CHECK_GT(dispatch.build_perturbed_threads, 0U);
    BOOST_CHECK_GT(dispatch.build_prefix_threads, 0U);
    BOOST_CHECK_GT(dispatch.compress_prefix_threads, 0U);
    BOOST_CHECK_GE(dispatch.build_perturbed_threads, dispatch.build_prefix_threads);
}

BOOST_AUTO_TEST_CASE(metal_kernel_profile_reports_tiled_fused_pipeline)
{
    const auto probe = btx::metal::ProbeMatMulDigestAcceleration();
    const auto profile = btx::metal::ProbeMatMulKernelProfile();

    BOOST_CHECK_EQUAL(profile.available, probe.available);
    if (!probe.available) {
        BOOST_CHECK(!profile.reason.empty());
        return;
    }

    BOOST_CHECK(profile.tiled_build_prefix);
    BOOST_CHECK(profile.fused_prefix_compress);
    BOOST_CHECK(profile.gpu_transcript_hash);
    BOOST_CHECK(profile.function_constant_specialization);
    BOOST_CHECK(!profile.uses_prefix_buffer);
    BOOST_CHECK_GT(profile.specialized_shape_count, 0U);
    BOOST_CHECK_GT(profile.build_prefix_threadgroup_width, 1U);
    BOOST_CHECK_GT(profile.build_prefix_threadgroup_height, 1U);
    BOOST_CHECK_GT(profile.fused_prefix_threadgroup_threads, 0U);
    BOOST_CHECK(!profile.specialization_reason.empty());
    BOOST_CHECK(profile.cooperative_tensor_prepared);
    BOOST_CHECK(!profile.cooperative_tensor_active);
    BOOST_CHECK(!profile.cooperative_tensor_reason.empty());
    BOOST_CHECK(!profile.library_source.empty());
}

BOOST_AUTO_TEST_CASE(metal_profiling_probe_matches_runtime_availability)
{
    const auto probe = btx::metal::ProbeMatMulDigestAcceleration();
    const auto profiling = btx::metal::ProbeMatMulProfilingStats();

    BOOST_CHECK_EQUAL(profiling.available, probe.available);
    if (!probe.available) {
        BOOST_CHECK(!profiling.reason.empty());
        return;
    }

    BOOST_CHECK_GE(profiling.samples, 0U);
    BOOST_CHECK(!profiling.reason.empty());
}

BOOST_AUTO_TEST_CASE(metal_profiling_samples_increment_after_digest)
{
    constexpr uint32_t kN = 8;
    constexpr uint32_t kB = 4;
    constexpr uint32_t kR = 2;

    const auto probe = btx::metal::ProbeMatMulDigestAcceleration();
    if (!probe.available) {
        const auto profiling = btx::metal::ProbeMatMulProfilingStats();
        BOOST_CHECK(!profiling.available);
        return;
    }

    const auto before = btx::metal::ProbeMatMulProfilingStats();

    const matmul::Matrix matrix_a(kN, kN);
    const matmul::Matrix matrix_b(kN, kN);
    const uint256 sigma = ParseUint256("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    const auto noise = matmul::noise::Generate(sigma, kN, kR);
    const auto compress_vec = matmul::transcript::DeriveCompressionVector(sigma, kB);

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

    const auto after = btx::metal::ProbeMatMulProfilingStats();
    BOOST_CHECK_GT(after.samples, before.samples);
    BOOST_CHECK_GT(after.last_encode_build_perturbed_us, 0.0);
    BOOST_CHECK_GT(after.last_encode_fused_prefix_compress_us, 0.0);
    BOOST_CHECK_GT(after.last_encode_transcript_sha256_us, 0.0);
    BOOST_CHECK_GT(after.last_submit_wait_us, 0.0);
}

BOOST_AUTO_TEST_CASE(metal_zero_copy_profile_reports_aligned_input_wrap)
{
    // Use n=128 so matrix buffers (128*128*4 = 65536 bytes) exceed the system
    // page size, satisfying WrapSharedNoCopyBuffer's minimum-length guard.
    constexpr uint32_t kN = 128;
    constexpr uint32_t kB = 4;
    constexpr uint32_t kR = 2;

    const auto probe = btx::metal::ProbeMatMulDigestAcceleration();
    if (!probe.available) {
        return;
    }

    const matmul::Matrix matrix_a(kN, kN);
    const matmul::Matrix matrix_b(kN, kN);
    const uint256 sigma = ParseUint256("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    const auto noise = matmul::noise::Generate(sigma, kN, kR);
    const auto compress_vec = matmul::transcript::DeriveCompressionVector(sigma, kB);

    const size_t sys_page = static_cast<size_t>(sysconf(_SC_PAGE_SIZE));
    const auto aligned_alloc = [sys_page](size_t bytes) {
        // Round up to page boundary so Metal's zero-copy view stays within
        // the actual allocation.
        const size_t alloc_bytes = ((bytes + sys_page - 1) / sys_page) * sys_page;
        void* raw{nullptr};
        if (posix_memalign(&raw, sys_page, alloc_bytes) != 0) {
            return std::unique_ptr<matmul::field::Element, decltype(&std::free)>(nullptr, &std::free);
        }
        return std::unique_ptr<matmul::field::Element, decltype(&std::free)>(
            static_cast<matmul::field::Element*>(raw), &std::free);
    };

    const size_t matrix_bytes = static_cast<size_t>(kN) * kN * sizeof(matmul::field::Element);
    const size_t noise_bytes = static_cast<size_t>(kN) * kR * sizeof(matmul::field::Element);
    const size_t compress_bytes = static_cast<size_t>(kB) * kB * sizeof(matmul::field::Element);

    auto matrix_a_aligned = aligned_alloc(matrix_bytes);
    auto matrix_b_aligned = aligned_alloc(matrix_bytes);
    auto e_l_aligned = aligned_alloc(noise_bytes);
    auto e_r_aligned = aligned_alloc(noise_bytes);
    auto f_l_aligned = aligned_alloc(noise_bytes);
    auto f_r_aligned = aligned_alloc(noise_bytes);
    auto compress_aligned = aligned_alloc(compress_bytes);

    BOOST_REQUIRE(matrix_a_aligned);
    BOOST_REQUIRE(matrix_b_aligned);
    BOOST_REQUIRE(e_l_aligned);
    BOOST_REQUIRE(e_r_aligned);
    BOOST_REQUIRE(f_l_aligned);
    BOOST_REQUIRE(f_r_aligned);
    BOOST_REQUIRE(compress_aligned);

    std::memcpy(matrix_a_aligned.get(), matrix_a.data(), matrix_bytes);
    std::memcpy(matrix_b_aligned.get(), matrix_b.data(), matrix_bytes);
    std::memcpy(e_l_aligned.get(), noise.E_L.data(), noise_bytes);
    std::memcpy(e_r_aligned.get(), noise.E_R.data(), noise_bytes);
    std::memcpy(f_l_aligned.get(), noise.F_L.data(), noise_bytes);
    std::memcpy(f_r_aligned.get(), noise.F_R.data(), noise_bytes);
    std::memcpy(compress_aligned.get(), compress_vec.data(), compress_bytes);

    const auto digest = btx::metal::ComputeCanonicalTranscriptDigest({
        .n = kN,
        .b = kB,
        .r = kR,
        .matrix_a = matrix_a_aligned.get(),
        .matrix_b = matrix_b_aligned.get(),
        .noise_e_l = e_l_aligned.get(),
        .noise_e_r = e_r_aligned.get(),
        .noise_f_l = f_l_aligned.get(),
        .noise_f_r = f_r_aligned.get(),
        .compress_vec = compress_aligned.get(),
    });
    BOOST_REQUIRE(digest.success);

    const auto profiling = btx::metal::ProbeMatMulProfilingStats();
    BOOST_CHECK(profiling.last_zero_copy_inputs);
}

BOOST_AUTO_TEST_CASE(metal_gpu_generated_inputs_match_cpu_oracle_generation)
{
    constexpr uint32_t kN = 8;
    constexpr uint32_t kB = 4;
    constexpr uint32_t kR = 2;

    const auto profile = btx::metal::ProbeMatMulInputGenerationProfile();
    const uint256 sigma = ParseUint256("89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567");
    const auto generated = btx::metal::GenerateMatMulInputsGPU({
        .n = kN,
        .b = kB,
        .r = kR,
        .sigma = sigma,
    });

    if (generated.available != profile.available || (!generated.success && profile.available)) {
        BOOST_TEST_MESSAGE("oracle accel error: " << generated.error);
    }

    BOOST_CHECK_EQUAL(generated.available, profile.available);
    if (!profile.available) {
        BOOST_CHECK(!generated.success);
        return;
    }

    BOOST_REQUIRE(generated.success);
    const auto cpu_noise = matmul::noise::Generate(sigma, kN, kR);
    const auto cpu_compress = matmul::transcript::DeriveCompressionVector(sigma, kB);

    BOOST_CHECK_EQUAL_COLLECTIONS(
        generated.noise_e_l.begin(), generated.noise_e_l.end(),
        cpu_noise.E_L.data(), cpu_noise.E_L.data() + generated.noise_e_l.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        generated.noise_e_r.begin(), generated.noise_e_r.end(),
        cpu_noise.E_R.data(), cpu_noise.E_R.data() + generated.noise_e_r.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        generated.noise_f_l.begin(), generated.noise_f_l.end(),
        cpu_noise.F_L.data(), cpu_noise.F_L.data() + generated.noise_f_l.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        generated.noise_f_r.begin(), generated.noise_f_r.end(),
        cpu_noise.F_R.data(), cpu_noise.F_R.data() + generated.noise_f_r.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        generated.compress_vec.begin(), generated.compress_vec.end(),
        cpu_compress.begin(), cpu_compress.end());
}

BOOST_AUTO_TEST_CASE(metal_gpu_generated_inputs_profile_tracks_samples_and_pool_reuse)
{
    constexpr uint32_t kN = 8;
    constexpr uint32_t kB = 4;
    constexpr uint32_t kR = 2;
    const uint256 sigma = ParseUint256("0123012301230123012301230123012301230123012301230123012301230123");

    const auto profile_before = btx::metal::ProbeMatMulInputGenerationProfile();
    const auto first = btx::metal::GenerateMatMulInputsGPU({
        .n = kN,
        .b = kB,
        .r = kR,
        .sigma = sigma,
    });
    const auto profile_mid = btx::metal::ProbeMatMulInputGenerationProfile();
    const auto second = btx::metal::GenerateMatMulInputsGPU({
        .n = kN,
        .b = kB,
        .r = kR,
        .sigma = sigma,
    });
    const auto profile_after = btx::metal::ProbeMatMulInputGenerationProfile();

    BOOST_CHECK_EQUAL(profile_after.available, first.available);
    BOOST_CHECK_EQUAL(profile_after.available, second.available);
    if (!profile_after.available) {
        BOOST_CHECK(!profile_after.library_source.empty());
        BOOST_CHECK(!profile_after.reason.empty());
        BOOST_CHECK(!first.success);
        BOOST_CHECK(!second.success);
        return;
    }

    BOOST_REQUIRE(first.success);
    BOOST_REQUIRE(second.success);
    BOOST_CHECK(!profile_after.library_source.empty());
    BOOST_CHECK(profile_mid.pool_initialized);
    BOOST_CHECK(profile_after.pool_initialized);
    BOOST_CHECK_GT(profile_mid.samples, profile_before.samples);
    BOOST_CHECK_GT(profile_after.samples, profile_mid.samples);
    BOOST_CHECK_GE(profile_after.reuse_events, profile_mid.reuse_events);
    BOOST_CHECK_GE(profile_after.allocation_events, profile_mid.allocation_events);
    BOOST_CHECK(!profile_after.reason.empty());
}

BOOST_AUTO_TEST_CASE(metal_gpu_generated_inputs_match_cpu_oracle_generation_for_mainnet_shape)
{
    constexpr uint32_t kN = 512;
    constexpr uint32_t kB = 16;
    constexpr uint32_t kR = 8;

    const auto profile = btx::metal::ProbeMatMulInputGenerationProfile();
    const uint256 sigma = ParseUint256("0123456789abcdef00112233445566778899aabbccddeefffedcba9876543210");
    const auto generated = btx::metal::GenerateMatMulInputsGPU({
        .n = kN,
        .b = kB,
        .r = kR,
        .sigma = sigma,
    });

    BOOST_CHECK_EQUAL(generated.available, profile.available);
    if (!profile.available) {
        BOOST_CHECK(!generated.success);
        return;
    }

    BOOST_REQUIRE(generated.success);
    const auto cpu_noise = matmul::noise::Generate(sigma, kN, kR);
    const auto cpu_compress = matmul::transcript::DeriveCompressionVector(sigma, kB);

    BOOST_CHECK_EQUAL_COLLECTIONS(
        generated.noise_e_l.begin(), generated.noise_e_l.end(),
        cpu_noise.E_L.data(), cpu_noise.E_L.data() + generated.noise_e_l.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        generated.noise_e_r.begin(), generated.noise_e_r.end(),
        cpu_noise.E_R.data(), cpu_noise.E_R.data() + generated.noise_e_r.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        generated.noise_f_l.begin(), generated.noise_f_l.end(),
        cpu_noise.F_L.data(), cpu_noise.F_L.data() + generated.noise_f_l.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        generated.noise_f_r.begin(), generated.noise_f_r.end(),
        cpu_noise.F_R.data(), cpu_noise.F_R.data() + generated.noise_f_r.size());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        generated.compress_vec.begin(), generated.compress_vec.end(),
        cpu_compress.begin(), cpu_compress.end());
}

BOOST_AUTO_TEST_SUITE_END()
