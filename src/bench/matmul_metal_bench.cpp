// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bench/bench.h>

#include <matmul/matmul_pow.h>
#include <matmul/noise.h>
#include <matmul/transcript.h>
#include <metal/matmul_accel.h>
#include <metal/oracle_accel.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <stdexcept>
#include <string_view>

namespace {

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    if (!parsed.has_value()) {
        throw std::runtime_error("invalid uint256 literal in matmul metal benchmark");
    }
    return *parsed;
}

CBlockHeader BuildTemplateHeader(uint32_t n)
{
    CBlockHeader header{};
    header.nVersion = 1;
    header.nTime = 1'738'800'000;
    header.nBits = 0x2100ffffU;
    header.nNonce = 1;
    header.nNonce64 = 1;
    header.hashPrevBlock = ParseUint256("0000000000000000000000000000000000000000000000000000000000000001");
    header.hashMerkleRoot = ParseUint256("0000000000000000000000000000000000000000000000000000000000000002");
    header.matmul_dim = static_cast<uint16_t>(n);
    header.seed_a = ParseUint256("0000000000000000000000000000000000000000000000000000000000000011");
    header.seed_b = ParseUint256("0000000000000000000000000000000000000000000000000000000000000022");
    return header;
}

void RunMatMulMetalDigestBenchmark(benchmark::Bench& bench, uint32_t n, uint32_t b, uint32_t r)
{
    const auto acceleration_probe = btx::metal::ProbeMatMulDigestAcceleration();
    if (!acceleration_probe.available) {
        std::cout << "MatMulMetalDigestBenchmark skipped"
                  << " n=" << n
                  << " b=" << b
                  << " r=" << r
                  << " reason=" << acceleration_probe.reason << '\n';
        bench.epochs(1).epochIterations(1).run([&] {});
        return;
    }

    const CBlockHeader template_header = BuildTemplateHeader(n);
    const matmul::Matrix matrix_a = matmul::FromSeed(template_header.seed_a, n);
    const matmul::Matrix matrix_b = matmul::FromSeed(template_header.seed_b, n);

    const auto uploaded = btx::metal::UploadBaseMatrices({
        .n = n,
        .matrix_a = matrix_a.data(),
        .matrix_b = matrix_b.data(),
    });
    if (!uploaded.success) {
        std::cout << "MatMulMetalDigestBenchmark skipped"
                  << " n=" << n
                  << " b=" << b
                  << " r=" << r
                  << " reason=" << uploaded.error << '\n';
        bench.epochs(1).epochIterations(1).run([&] {});
        return;
    }

    CBlockHeader nonce_header{template_header};

    bench.batch(1).unit("digest").run([&] {
        nonce_header.nNonce64 += 1;
        nonce_header.nNonce = static_cast<uint32_t>(nonce_header.nNonce64);
        const uint256 sigma = matmul::DeriveSigma(nonce_header);
        const auto noise = matmul::noise::Generate(sigma, n, r);
        const auto compress_vec = matmul::transcript::DeriveCompressionVector(sigma, b);

        const auto result = btx::metal::ComputeCanonicalTranscriptDigest({
            .n = n,
            .b = b,
            .r = r,
            .use_uploaded_base_matrices = true,
            .noise_e_l = noise.E_L.data(),
            .noise_e_r = noise.E_R.data(),
            .noise_f_l = noise.F_L.data(),
            .noise_f_r = noise.F_R.data(),
            .compress_vec = compress_vec.data(),
        });
        if (!result.success) {
            throw std::runtime_error("Metal digest benchmark failed: " + result.error);
        }
    });
}

void RunMatMulMetalBatchDigestBenchmark(benchmark::Bench& bench,
                                        uint32_t n,
                                        uint32_t b,
                                        uint32_t r,
                                        uint32_t batch_size)
{
    const auto acceleration_probe = btx::metal::ProbeMatMulDigestAcceleration();
    if (!acceleration_probe.available || batch_size == 0) {
        std::cout << "MatMulMetalBatchDigestBenchmark skipped"
                  << " n=" << n
                  << " b=" << b
                  << " r=" << r
                  << " batch_size=" << batch_size
                  << " reason=" << (batch_size == 0 ? "invalid_batch_size" : acceleration_probe.reason) << '\n';
        bench.epochs(1).epochIterations(1).run([&] {});
        return;
    }

    const CBlockHeader template_header = BuildTemplateHeader(n);
    const matmul::Matrix matrix_a = matmul::FromSeed(template_header.seed_a, n);
    const matmul::Matrix matrix_b = matmul::FromSeed(template_header.seed_b, n);

    const auto uploaded = btx::metal::UploadBaseMatrices({
        .n = n,
        .matrix_a = matrix_a.data(),
        .matrix_b = matrix_b.data(),
    });
    if (!uploaded.success) {
        std::cout << "MatMulMetalBatchDigestBenchmark skipped"
                  << " n=" << n
                  << " b=" << b
                  << " r=" << r
                  << " batch_size=" << batch_size
                  << " reason=" << uploaded.error << '\n';
        bench.epochs(1).epochIterations(1).run([&] {});
        return;
    }

    CBlockHeader nonce_header{template_header};
    std::vector<matmul::noise::NoisePair> noises;
    std::vector<std::vector<matmul::field::Element>> compress_vectors;
    std::vector<const matmul::field::Element*> noise_e_l_ptrs(batch_size);
    std::vector<const matmul::field::Element*> noise_e_r_ptrs(batch_size);
    std::vector<const matmul::field::Element*> noise_f_l_ptrs(batch_size);
    std::vector<const matmul::field::Element*> noise_f_r_ptrs(batch_size);
    std::vector<const matmul::field::Element*> compress_ptrs(batch_size);
    noises.reserve(batch_size);
    compress_vectors.reserve(batch_size);

    bench.batch(batch_size).unit("digest").run([&] {
        noises.clear();
        compress_vectors.clear();
        for (uint32_t i = 0; i < batch_size; ++i) {
            nonce_header.nNonce64 += 1;
            nonce_header.nNonce = static_cast<uint32_t>(nonce_header.nNonce64);
            const uint256 sigma = matmul::DeriveSigma(nonce_header);
            noises.push_back(matmul::noise::Generate(sigma, n, r));
            compress_vectors.push_back(matmul::transcript::DeriveCompressionVector(sigma, b));
            noise_e_l_ptrs[i] = noises[i].E_L.data();
            noise_e_r_ptrs[i] = noises[i].E_R.data();
            noise_f_l_ptrs[i] = noises[i].F_L.data();
            noise_f_r_ptrs[i] = noises[i].F_R.data();
            compress_ptrs[i] = compress_vectors[i].data();
        }

        const auto result = btx::metal::ComputeCanonicalTranscriptDigestBatch({
            .n = n,
            .b = b,
            .r = r,
            .batch_size = batch_size,
            .use_uploaded_base_matrices = true,
            .noise_e_l = noise_e_l_ptrs.data(),
            .noise_e_r = noise_e_r_ptrs.data(),
            .noise_f_l = noise_f_l_ptrs.data(),
            .noise_f_r = noise_f_r_ptrs.data(),
            .compress_vec = compress_ptrs.data(),
        });
        if (!result.success) {
            throw std::runtime_error("Metal batch digest benchmark failed: " + result.error);
        }
    });
}

void MatMulMetalDigestMainnetDimensions(benchmark::Bench& bench)
{
    RunMatMulMetalDigestBenchmark(bench, /*n=*/512, /*b=*/16, /*r=*/8);
}

void MatMulMetalDigestTestnetDimensions(benchmark::Bench& bench)
{
    RunMatMulMetalDigestBenchmark(bench, /*n=*/256, /*b=*/8, /*r=*/4);
}

void MatMulMetalBatchDigestMainnetBatch2(benchmark::Bench& bench)
{
    RunMatMulMetalBatchDigestBenchmark(bench, /*n=*/512, /*b=*/16, /*r=*/8, /*batch_size=*/2);
}

void MatMulMetalBatchDigestMainnetBatch4(benchmark::Bench& bench)
{
    RunMatMulMetalBatchDigestBenchmark(bench, /*n=*/512, /*b=*/16, /*r=*/8, /*batch_size=*/4);
}

void RunMatMulCpuInputPreparationBenchmark(benchmark::Bench& bench, uint32_t n, uint32_t b, uint32_t r)
{
    const CBlockHeader template_header = BuildTemplateHeader(n);
    CBlockHeader nonce_header{template_header};

    bench.batch(1).unit("prepare").run([&] {
        nonce_header.nNonce64 += 1;
        nonce_header.nNonce = static_cast<uint32_t>(nonce_header.nNonce64);
        const uint256 sigma = matmul::DeriveSigma(nonce_header);
        const auto noise = matmul::noise::Generate(sigma, n, r);
        const auto compress_vec = matmul::transcript::DeriveCompressionVector(sigma, b);
        (void)noise;
        (void)compress_vec;
    });
}

void RunMatMulGpuInputPreparationBenchmark(benchmark::Bench& bench, uint32_t n, uint32_t b, uint32_t r)
{
    const auto input_probe = btx::metal::ProbeMatMulInputGenerationProfile();
    if (!input_probe.available) {
        std::cout << "MatMulGpuInputPreparationBenchmark skipped"
                  << " n=" << n
                  << " b=" << b
                  << " r=" << r
                  << " reason=" << input_probe.reason << '\n';
        bench.epochs(1).epochIterations(1).run([&] {});
        return;
    }

    const CBlockHeader template_header = BuildTemplateHeader(n);
    CBlockHeader nonce_header{template_header};

    bench.batch(1).unit("prepare").run([&] {
        nonce_header.nNonce64 += 1;
        nonce_header.nNonce = static_cast<uint32_t>(nonce_header.nNonce64);
        const uint256 sigma = matmul::DeriveSigma(nonce_header);
        const auto result = btx::metal::GenerateMatMulInputsGPU({
            .n = n,
            .b = b,
            .r = r,
            .sigma = sigma,
        });
        if (!result.success) {
            throw std::runtime_error("Metal GPU input generation benchmark failed: " + result.error);
        }
        (void)result;
    });
}

void MatMulCpuInputPreparationMainnetDimensions(benchmark::Bench& bench)
{
    RunMatMulCpuInputPreparationBenchmark(bench, /*n=*/512, /*b=*/16, /*r=*/8);
}

void MatMulGpuInputPreparationMainnetDimensions(benchmark::Bench& bench)
{
    RunMatMulGpuInputPreparationBenchmark(bench, /*n=*/512, /*b=*/16, /*r=*/8);
}

} // namespace

BENCHMARK(MatMulMetalDigestMainnetDimensions, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulMetalDigestTestnetDimensions, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulMetalBatchDigestMainnetBatch2, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulMetalBatchDigestMainnetBatch4, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulCpuInputPreparationMainnetDimensions, benchmark::PriorityLevel::HIGH);
BENCHMARK(MatMulGpuInputPreparationMainnetDimensions, benchmark::PriorityLevel::HIGH);
