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
                            uint64_t max_tries)
{
    if (consensus.fMatMulPOW) {
        if (header.matmul_dim == 0) {
            header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
        }
        if (header.seed_a.IsNull()) header.seed_a = DeterministicMatMulSeed(header.hashPrevBlock, block_height, 0);
        if (header.seed_b.IsNull()) header.seed_b = DeterministicMatMulSeed(header.hashPrevBlock, block_height, 1);
        header.mix_hash.SetNull();
        return SolveMatMul(header, consensus, max_tries, static_cast<int32_t>(block_height));
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
                            uint64_t max_tries)
{
    if (!MineHeaderForConsensus(static_cast<CBlockHeader&>(block), block_height, consensus, max_tries)) {
        return false;
    }

    if (consensus.fMatMulPOW && consensus.fMatMulFreivaldsEnabled) {
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
    assert(MineHeaderForConsensus(*block, block_height, Params().GetConsensus()));
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
