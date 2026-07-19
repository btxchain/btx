// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/mining.h>

#include <chainparams.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <key_io.h>
#include <node/context.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <random.h>
#include <test/util/script.h>
#include <util/check.h>
#include <validation.h>
#include <validationinterface.h>
#include <versionbits.h>

#include <cassert>
#include <limits>

using node::BlockAssembler;
using node::NodeContext;

COutPoint generatetoaddress(const NodeContext& node, const std::string& address)
{
    const auto dest = DecodeDestination(address);
    assert(IsValidDestination(dest));
    BlockAssembler::Options assembler_options;
    assembler_options.coinbase_output_script = GetScriptForDestination(dest);

    return MineBlock(node, assembler_options);
}

bool MineHeaderForConsensus(CBlockHeader& header,
                            uint32_t block_height,
                            const Consensus::Params& consensus,
                            uint64_t max_tries,
                            std::optional<int64_t> parent_median_time_past,
                            std::vector<uint32_t>* v4_payload_out)
{
    if (consensus.fMatMulPOW) {
        if (header.matmul_dim == 0) {
            // Mirror BlockAssembler (src/node/miner.cpp): at product-committed
            // (v4) heights the header commits to the v4 dimension, otherwise the
            // legacy v3 dimension. A bare synthetic header (matmul_dim == 0) mined
            // at a v4 height would otherwise carry the wrong dimension and fail
            // Phase1 (bad matmul_dim) / solve against the wrong operand size.
            header.matmul_dim = consensus.IsMatMulV4Active(static_cast<int32_t>(block_height))
                ? static_cast<uint16_t>(consensus.nMatMulV4Dimension)
                : static_cast<uint16_t>(consensus.nMatMulDimension);
        }
        if (!SetDeterministicMatMulSeeds(
                header,
                consensus,
                static_cast<int32_t>(block_height),
                parent_median_time_past)) {
            return false;
        }
        header.mix_hash.SetNull();
        return SolveMatMul(
            header,
            consensus,
            max_tries,
            static_cast<int32_t>(block_height),
            nullptr,
            v4_payload_out,
            nullptr,
            parent_median_time_past) &&
               GrindMatMulHeaderSpamNonce(header, consensus, max_tries);
    }

    const bool kawpow_active{consensus.fKAWPOW && consensus.nKAWPOWHeight <= static_cast<int>(block_height)};
    if (kawpow_active) {
        if (consensus.fSkipKAWPOWValidation) {
            // Regtest defaults to skipping KAWPOW validation; keep tests deterministic and fast.
            header.nNonce64 = 0;
            header.mix_hash.SetNull();
            return true;
        }

        if constexpr (G_FUZZING) {
            while (max_tries > 0) {
                if (CheckKAWPOWProofOfWork(header, block_height, consensus)) return true;
                if (header.nNonce64 == std::numeric_limits<uint64_t>::max()) return false;
                ++header.nNonce64;
                --max_tries;
            }
            return CheckKAWPOWProofOfWork(header, block_height, consensus);
        }

        return SolveKAWPOW(header, block_height, consensus, max_tries);
    }

    while (max_tries > 0) {
        if (CheckProofOfWork(header.GetHash(), header.nBits, consensus)) return true;
        if (header.nNonce == std::numeric_limits<uint32_t>::max()) return false;
        ++header.nNonce;
        --max_tries;
    }
    return CheckProofOfWork(header.GetHash(), header.nBits, consensus);
}

bool MineHeaderForConsensus(CBlock& block,
                            uint32_t block_height,
                            const Consensus::Params& consensus,
                            uint64_t max_tries,
                            std::optional<int64_t> parent_median_time_past)
{
    // At product-committed-digest (v4) heights the block payload must carry the
    // exact product sketch C' the solver committed to. Capture it directly from
    // the solver rather than recomputing it with the v3-only
    // PopulateFreivaldsPayload helper.
    const bool v4_active{consensus.fMatMulPOW &&
                         consensus.IsMatMulProductDigestActive(static_cast<int32_t>(block_height))};
    std::vector<uint32_t> v4_payload;

    if (!MineHeaderForConsensus(
            static_cast<CBlockHeader&>(block),
            block_height,
            consensus,
            max_tries,
            parent_median_time_past,
            v4_active ? &v4_payload : nullptr)) {
        return false;
    }

    if (v4_active) {
        // v4: attach the solver's product sketch and drop the v3 A'/B' payload.
        block.matrix_a_data.clear();
        block.matrix_b_data.clear();
        block.matrix_c_data = std::move(v4_payload);
        // Some solver backends (e.g. share-scan fast paths) may not surface the
        // sketch; fall back to recomputation so the payload is never empty.
        if (block.matrix_c_data.empty() && consensus.fMatMulFreivaldsEnabled) {
            PopulateFreivaldsPayload(block, consensus);
        }
        // WP-1 / C3: at ENC-DR (DIGEST_RECOMPUTE) heights the block body MUST be
        // empty (validation rejects a non-empty body at DIGEST_RECOMPUTE), so
        // route the freshly-committed sketch through the central producer
        // finalizer, which offloads it to the local cache and clears
        // matrix_c_data. Without this the helper produces self-rejecting ENC-DR
        // blocks that break validation_block_tests / mempool_locks_reorg. Under
        // FLAT_SKETCH_INBLOCK (regtest replay only) the inline sketch is retained.
        const int height = static_cast<int>(block_height);
        const bool enc_dr =
            consensus.IsMatMulV4Active(height) &&
            consensus.GetMatMulProfileParams(height).commitment ==
                Consensus::MatMulCommitmentScheme::DIGEST_RECOMPUTE;
        FinalizeMatMulSolvedBlock(block, consensus, height);
        // The ENC-DR block body is now empty; the sketch lives in the cache.
        assert(!enc_dr || block.matrix_c_data.empty());
    } else if (consensus.fMatMulPOW && consensus.fMatMulFreivaldsEnabled) {
        // v3 (pre-product-digest) path: unchanged.
        PopulateFreivaldsPayload(block, consensus);
    }

    return true;
}

std::vector<std::shared_ptr<CBlock>> CreateBlockChain(size_t total_height, const CChainParams& params)
{
    std::vector<std::shared_ptr<CBlock>> ret{total_height};
    auto time{params.GenesisBlock().nTime};
    for (size_t height{0}; height < total_height; ++height) {
        CBlock& block{*(ret.at(height) = std::make_shared<CBlock>())};

        CMutableTransaction coinbase_tx;
        coinbase_tx.vin.resize(1);
        coinbase_tx.vin[0].prevout.SetNull();
        coinbase_tx.vout.resize(1);
        coinbase_tx.vout[0].scriptPubKey = P2WSH_OP_TRUE;
        coinbase_tx.vout[0].nValue = GetBlockSubsidy(height + 1, params.GetConsensus());
        coinbase_tx.vin[0].scriptSig = CScript() << (height + 1) << OP_0;
        block.vtx = {MakeTransactionRef(std::move(coinbase_tx))};

        block.nVersion = VERSIONBITS_LAST_OLD_BLOCK_VERSION;
        block.hashPrevBlock = (height >= 1 ? *ret.at(height - 1) : params.GenesisBlock()).GetHash();
        block.hashMerkleRoot = BlockMerkleRoot(block);
        block.nTime = ++time;
        block.nBits = params.GenesisBlock().nBits;
        block.nNonce = 0;
        const auto block_height{static_cast<uint32_t>(height + 1)};
        assert(MineHeaderForConsensus(block, block_height, params.GetConsensus()));
    }
    return ret;
}

COutPoint MineBlock(const NodeContext& node, const node::BlockAssembler::Options& assembler_options)
{
    auto block = PrepareBlock(node, assembler_options);
    auto valid = MineBlock(node, block);
    assert(!valid.IsNull());
    return valid;
}

struct BlockValidationStateCatcher : public CValidationInterface {
    const uint256 m_hash;
    std::optional<BlockValidationState> m_state;

    BlockValidationStateCatcher(const uint256& hash)
        : m_hash{hash},
          m_state{} {}

protected:
    void BlockChecked(const CBlock& block, const BlockValidationState& state) override
    {
        if (block.GetHash() != m_hash) return;
        m_state = state;
    }
};

COutPoint MineBlock(const NodeContext& node, std::shared_ptr<CBlock>& block)
{
    auto& chainman{*Assert(node.chainman)};
    const CBlockIndex* prev_index{WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(block->hashPrevBlock))};
    const uint32_t block_height{prev_index ? static_cast<uint32_t>(prev_index->nHeight + 1) : 0};
    assert(MineHeaderForConsensus(
        *block,
        block_height,
        Params().GetConsensus(),
        5'000'000,
        prev_index ? std::optional<int64_t>{prev_index->GetMedianTimePast()} : std::nullopt));
    // Populate Freivalds' product matrix payload for O(n^2) verification.
    PopulateFreivaldsPayload(*block, Params().GetConsensus());

    const auto old_height = WITH_LOCK(chainman.GetMutex(), return chainman.ActiveHeight());
    bool new_block;
    BlockValidationStateCatcher bvsc{block->GetHash()};
    node.validation_signals->RegisterValidationInterface(&bvsc);
    const bool processed{chainman.ProcessNewBlock(block, true, true, &new_block)};
    const bool duplicate{!new_block && processed};
    assert(!duplicate);
    node.validation_signals->UnregisterValidationInterface(&bvsc);
    node.validation_signals->SyncWithValidationInterfaceQueue();
    const bool was_valid{bvsc.m_state && bvsc.m_state->IsValid()};
    assert(old_height + was_valid == WITH_LOCK(chainman.GetMutex(), return chainman.ActiveHeight()));

    if (was_valid) return {block->vtx[0]->GetHash(), 0};
    return {};
}

std::shared_ptr<CBlock> PrepareBlock(const NodeContext& node,
                                     const BlockAssembler::Options& assembler_options)
{
    auto block = std::make_shared<CBlock>(
        BlockAssembler{Assert(node.chainman)->ActiveChainstate(), Assert(node.mempool.get()), assembler_options, node}
            .CreateNewBlock()
            ->block);

    LOCK(cs_main);
    block->nTime = Assert(node.chainman)->ActiveChain().Tip()->GetMedianTimePast() + 1;
    block->hashMerkleRoot = BlockMerkleRoot(*block);

    return block;
}
std::shared_ptr<CBlock> PrepareBlock(const NodeContext& node, const CScript& coinbase_scriptPubKey)
{
    BlockAssembler::Options assembler_options;
    assembler_options.coinbase_output_script = coinbase_scriptPubKey;
    ApplyArgsManOptions(*node.args, assembler_options);
    return PrepareBlock(node, assembler_options);
}
