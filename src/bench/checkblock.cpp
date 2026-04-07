// Copyright (c) 2016-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <bench/data/block413567.raw.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/validation.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <validation.h>

#include <cassert>
#include <cstddef>
#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>

// These are the two major time-sinks which happen after we have fully received
// a block off the wire, but before we can relay the block on to peers using
// compact block relay.

namespace {
const std::vector<unsigned char>& Fixture413567BtxEncoded()
{
    static const std::vector<unsigned char> fixture = [] {
        std::vector<unsigned char> raw;
        raw.reserve(benchmark::data::block413567.size());
        for (const std::byte b : benchmark::data::block413567) {
            raw.push_back(static_cast<unsigned char>(b));
        }

        CBlock block;
        if (!DecodeHexBlkCompat(block, HexStr(raw))) {
            throw std::runtime_error("Unable to decode benchmark fixture block413567");
        }

        DataStream encoded;
        encoded << TX_WITH_WITNESS(block);
        std::vector<unsigned char> bytes;
        bytes.reserve(encoded.size());
        for (const std::byte b : encoded) {
            bytes.push_back(static_cast<unsigned char>(b));
        }
        return bytes;
    }();
    return fixture;
}
} // namespace

static void DeserializeBlockTest(benchmark::Bench& bench)
{
    const auto& fixture = Fixture413567BtxEncoded();

    bench.unit("block").run([&] {
        DataStream stream(fixture);
        CBlock block;
        stream >> TX_WITH_WITNESS(block);
    });
}

static void DeserializeAndCheckBlockTest(benchmark::Bench& bench)
{
    const auto& fixture = Fixture413567BtxEncoded();

    ArgsManager bench_args;
    // The fixture comes from historical Bitcoin mainnet and contains legacy output templates.
    // BTX main/test chains enforce P2MR-only outputs at consensus, so use regtest params for
    // this context-free benchmark sanity check.
    const auto chainParams = CreateChainParams(bench_args, ChainType::REGTEST);

    bench.unit("block").run([&] {
        DataStream stream(fixture);
        CBlock block; // Note that CBlock caches its checked state, so we need to recreate it here
        stream >> TX_WITH_WITNESS(block);

        // The benchmark fixture is sourced from historical Bitcoin mainnet blocks. BTX uses
        // MatMul PoW which requires additional header fields to be present and non-null, so
        // populate them with deterministic values that satisfy Phase1 PoW checks.
        const auto& consensus = chainParams->GetConsensus();
        block.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
        if (block.seed_a.IsNull()) block.seed_a = uint256{"0000000000000000000000000000000000000000000000000000000000000001"};
        if (block.seed_b.IsNull()) block.seed_b = uint256{"0000000000000000000000000000000000000000000000000000000000000002"};

        BlockValidationState validationState;
        bool checked = CheckBlock(block, validationState, consensus);
        assert(checked);
    });
}

BENCHMARK(DeserializeBlockTest, benchmark::PriorityLevel::HIGH);
BENCHMARK(DeserializeAndCheckBlockTest, benchmark::PriorityLevel::HIGH);
