// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <hash.h>
#include <random.h>
#include <shielded/lattice/sampling.h>
#include <shielded/ringct/ring_signature.h>

#include <cassert>
#include <string>
#include <vector>

using namespace shielded::ringct;
namespace lattice = shielded::lattice;

namespace {

std::vector<std::vector<uint256>> BuildBenchRingMembers(size_t input_count)
{
    std::vector<std::vector<uint256>> ring_members(input_count, std::vector<uint256>(lattice::RING_SIZE));
    for (auto& ring : ring_members) {
        for (auto& member : ring) member = GetRandHash();
    }
    return ring_members;
}

std::vector<lattice::PolyVec> BuildBenchInputSecrets(const std::vector<std::vector<uint256>>& ring_members,
                                                     const std::vector<size_t>& real_indices,
                                                     Span<const unsigned char> spending_key)
{
    if (ring_members.size() != real_indices.size()) return {};
    std::vector<lattice::PolyVec> input_secrets;
    input_secrets.reserve(ring_members.size());
    for (size_t input_idx = 0; input_idx < ring_members.size(); ++input_idx) {
        if (real_indices[input_idx] >= ring_members[input_idx].size()) return {};
        HashWriter hw;
        hw << std::string{"BTX_MatRiCT_RingSig_BenchSecret_V1"};
        hw.write(AsBytes(spending_key));
        hw << ring_members[input_idx][real_indices[input_idx]];
        hw << static_cast<uint32_t>(input_idx);
        const uint256 seed = hw.GetSHA256();
        FastRandomContext rng(seed);
        input_secrets.push_back(lattice::SampleSmallVec(rng, lattice::MODULE_RANK, /*eta=*/2));
    }
    return input_secrets;
}

void RingSignatureCreateBench(benchmark::Bench& bench)
{
    const std::vector<std::vector<uint256>> ring_members = BuildBenchRingMembers(/*input_count=*/2);
    const std::vector<size_t> real_indices{3, 11};
    const std::vector<unsigned char> spending_key(32, 0x9A);
    const std::vector<lattice::PolyVec> input_secrets = BuildBenchInputSecrets(ring_members, real_indices, spending_key);
    assert(input_secrets.size() == ring_members.size());
    const uint256 message_hash = GetRandHash();

    bench.minEpochIterations(5).run([&] {
        RingSignature signature;
        const bool ok = CreateRingSignature(signature, ring_members, real_indices, input_secrets, message_hash);
        ankerl::nanobench::doNotOptimizeAway(ok);
        ankerl::nanobench::doNotOptimizeAway(signature.challenge_seed);
    });
}

void RingSignatureVerifyBench(benchmark::Bench& bench)
{
    const std::vector<std::vector<uint256>> ring_members = BuildBenchRingMembers(/*input_count=*/2);
    const std::vector<size_t> real_indices{4, 12};
    const std::vector<unsigned char> spending_key(32, 0x71);
    const std::vector<lattice::PolyVec> input_secrets = BuildBenchInputSecrets(ring_members, real_indices, spending_key);
    assert(input_secrets.size() == ring_members.size());
    const uint256 message_hash = GetRandHash();

    RingSignature signature;
    const bool created = CreateRingSignature(signature, ring_members, real_indices, input_secrets, message_hash);
    assert(created);

    bench.minEpochIterations(20).run([&] {
        const bool ok = VerifyRingSignature(signature, ring_members, message_hash);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
}

} // namespace

BENCHMARK(RingSignatureCreateBench, benchmark::PriorityLevel::HIGH);
BENCHMARK(RingSignatureVerifyBench, benchmark::PriorityLevel::HIGH);
