// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bench/bench.h>
#include <hash.h>
#include <key.h>
#include <pqkey.h>
#include <pubkey.h>
#include <script/script.h>

#include <cassert>
#include <cstddef>
#include <vector>

namespace {

uint256 BenchmarkMessageHash()
{
    static const std::vector<unsigned char> msg{
        0x62, 0x74, 0x78, 0x2d, 0x70, 0x71, 0x2d, 0x62,
        0x65, 0x6e, 0x63, 0x68, 0x2d, 0x76, 0x31,
    };
    return Hash(msg);
}

void bench_schnorr_verify(benchmark::Bench& bench)
{
    ECC_Context ecc_context{};
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    const XOnlyPubKey pubkey{key.GetPubKey()};
    const uint256 hash = BenchmarkMessageHash();

    std::vector<unsigned char> sig(64);
    const bool signed_ok = key.SignSchnorr(hash, sig, /*merkle_root=*/nullptr, uint256{});
    assert(signed_ok);
    assert(pubkey.VerifySchnorr(hash, sig));

    bench.minEpochIterations(50).run([&] {
        assert(pubkey.VerifySchnorr(hash, sig));
    });
}

void bench_mldsa_verify(benchmark::Bench& bench)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    assert(key.IsValid());

    const uint256 hash = BenchmarkMessageHash();
    std::vector<unsigned char> sig;
    const bool signed_ok = key.Sign(hash, sig);
    assert(signed_ok);

    const CPQPubKey pubkey{PQAlgorithm::ML_DSA_44, key.GetPubKey()};
    assert(pubkey.Verify(hash, sig));

    bench.minEpochIterations(20).run([&] {
        assert(pubkey.Verify(hash, sig));
    });
}

void bench_slhdsa_verify(benchmark::Bench& bench)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    assert(key.IsValid());

    const uint256 hash = BenchmarkMessageHash();
    std::vector<unsigned char> sig;
    const bool signed_ok = key.Sign(hash, sig);
    assert(signed_ok);

    const CPQPubKey pubkey{PQAlgorithm::SLH_DSA_128S, key.GetPubKey()};
    assert(pubkey.Verify(hash, sig));

    bench.minEpochIterations(5).run([&] {
        assert(pubkey.Verify(hash, sig));
    });
}

void bench_worst_case_p2mr_block(benchmark::Bench& bench)
{
    CPQKey mldsa_key;
    mldsa_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    assert(mldsa_key.IsValid());
    CPQKey slhdsa_key;
    slhdsa_key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    assert(slhdsa_key.IsValid());

    const uint256 hash = BenchmarkMessageHash();

    std::vector<unsigned char> mldsa_sig;
    std::vector<unsigned char> slhdsa_sig;
    assert(mldsa_key.Sign(hash, mldsa_sig));
    assert(slhdsa_key.Sign(hash, slhdsa_sig));

    const CPQPubKey mldsa_pub{PQAlgorithm::ML_DSA_44, mldsa_key.GetPubKey()};
    const CPQPubKey slhdsa_pub{PQAlgorithm::SLH_DSA_128S, slhdsa_key.GetPubKey()};
    assert(mldsa_pub.Verify(hash, mldsa_sig));
    assert(slhdsa_pub.Verify(hash, slhdsa_sig));

    static constexpr size_t kInputsPerBlockSample = 8;
    static constexpr size_t kMldsaChecksPerInput = 100; // 100 * 500 = 50k validation weight
    static constexpr size_t kSlhdsaChecksPerInput = 10; // 10 * 5000 = 50k validation weight
    const size_t total_verifies =
        kInputsPerBlockSample * (kMldsaChecksPerInput + kSlhdsaChecksPerInput);

    bench.batch(total_verifies).run([&] {
        for (size_t in = 0; in < kInputsPerBlockSample; ++in) {
            for (size_t i = 0; i < kMldsaChecksPerInput; ++i) {
                assert(mldsa_pub.Verify(hash, mldsa_sig));
            }
            for (size_t i = 0; i < kSlhdsaChecksPerInput; ++i) {
                assert(slhdsa_pub.Verify(hash, slhdsa_sig));
            }
        }
    });
}

void bench_worst_case_tapscript_block(benchmark::Bench& bench)
{
    ECC_Context ecc_context{};
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    const XOnlyPubKey pubkey{key.GetPubKey()};
    const uint256 hash = BenchmarkMessageHash();

    std::vector<unsigned char> sig(64);
    const bool signed_ok = key.SignSchnorr(hash, sig, /*merkle_root=*/nullptr, uint256{});
    assert(signed_ok);
    assert(pubkey.VerifySchnorr(hash, sig));

    static constexpr size_t kInputsPerBlockSample = 8;
    static constexpr size_t kChecksPerInput = 1000; // 1000 * 50 = 50k validation weight

    bench.batch(kInputsPerBlockSample * kChecksPerInput).run([&] {
        for (size_t in = 0; in < kInputsPerBlockSample; ++in) {
            for (size_t i = 0; i < kChecksPerInput; ++i) {
                assert(pubkey.VerifySchnorr(hash, sig));
            }
        }
    });
}

} // namespace

BENCHMARK(bench_schnorr_verify, benchmark::PriorityLevel::HIGH);
BENCHMARK(bench_mldsa_verify, benchmark::PriorityLevel::HIGH);
BENCHMARK(bench_slhdsa_verify, benchmark::PriorityLevel::HIGH);
BENCHMARK(bench_worst_case_p2mr_block, benchmark::PriorityLevel::LOW);
BENCHMARK(bench_worst_case_tapscript_block, benchmark::PriorityLevel::LOW);
