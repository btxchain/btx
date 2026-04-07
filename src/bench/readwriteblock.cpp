// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <bench/data/block413567.raw.h>
#include <flatfile.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <validation.h>

#include <cassert>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

static CBlock CreateTestBlock()
{
    CBlock block;
    std::vector<unsigned char> raw_block;
    raw_block.reserve(benchmark::data::block413567.size());
    for (const std::byte b : benchmark::data::block413567) {
        raw_block.push_back(static_cast<unsigned char>(b));
    }
    if (!DecodeHexBlkCompat(block, HexStr(raw_block))) {
        throw std::runtime_error("Unable to decode benchmark fixture block413567");
    }
    return block;
}

static void SaveBlockBench(benchmark::Bench& bench)
{
    const auto testing_setup{MakeNoLogFileContext<const TestingSetup>(ChainType::MAIN)};
    auto& blockman{testing_setup->m_node.chainman->m_blockman};
    CBlock block{CreateTestBlock()};
    // The benchmark fixture is sourced from historical Bitcoin mainnet blocks. BTX uses
    // MatMul PoW which requires additional header fields to be present and non-null, so
    // populate them with deterministic values that satisfy Phase1 PoW checks.
    const auto& consensus = testing_setup->m_node.chainman->GetConsensus();
    block.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    if (block.seed_a.IsNull()) block.seed_a = uint256{"0000000000000000000000000000000000000000000000000000000000000001"};
    if (block.seed_b.IsNull()) block.seed_b = uint256{"0000000000000000000000000000000000000000000000000000000000000002"};
    bench.run([&] {
        const auto pos{blockman.WriteBlock(block, 413'567)};
        assert(!pos.IsNull());
    });
}

static void ReadBlockBench(benchmark::Bench& bench)
{
    const auto testing_setup{MakeNoLogFileContext<const TestingSetup>(ChainType::MAIN)};
    auto& blockman{testing_setup->m_node.chainman->m_blockman};
    CBlock fixture{CreateTestBlock()};
    const auto& consensus = testing_setup->m_node.chainman->GetConsensus();
    fixture.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    if (fixture.seed_a.IsNull()) fixture.seed_a = uint256{"0000000000000000000000000000000000000000000000000000000000000001"};
    if (fixture.seed_b.IsNull()) fixture.seed_b = uint256{"0000000000000000000000000000000000000000000000000000000000000002"};
    const auto pos{blockman.WriteBlock(fixture, 413'567)};
    CBlock block;
    bench.run([&] {
        const auto success{blockman.ReadBlock(block, pos)};
        assert(success);
    });
}

static void ReadRawBlockBench(benchmark::Bench& bench)
{
    const auto testing_setup{MakeNoLogFileContext<const TestingSetup>(ChainType::MAIN)};
    auto& blockman{testing_setup->m_node.chainman->m_blockman};
    CBlock fixture{CreateTestBlock()};
    const auto& consensus = testing_setup->m_node.chainman->GetConsensus();
    fixture.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    if (fixture.seed_a.IsNull()) fixture.seed_a = uint256{"0000000000000000000000000000000000000000000000000000000000000001"};
    if (fixture.seed_b.IsNull()) fixture.seed_b = uint256{"0000000000000000000000000000000000000000000000000000000000000002"};
    const auto pos{blockman.WriteBlock(fixture, 413'567)};
    std::vector<uint8_t> block_data;
    blockman.ReadRawBlock(block_data, pos); // warmup
    bench.run([&] {
        const auto success{blockman.ReadRawBlock(block_data, pos)};
        assert(success);
    });
}

BENCHMARK(SaveBlockBench, benchmark::PriorityLevel::HIGH);
BENCHMARK(ReadBlockBench, benchmark::PriorityLevel::HIGH);
BENCHMARK(ReadRawBlockBench, benchmark::PriorityLevel::HIGH);
