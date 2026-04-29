// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/miner.h>

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <deploymentstatus.h>
#include <logging.h>
#include <matmul/matrix.h>
#include <node/context.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <random.h>
#include <shielded/bundle.h>
#include <shielded/validation.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <algorithm>
#include <array>
#include <limits>
#include <type_traits>
#include <utility>
#include <vector>

namespace node {

namespace {
bool TryGetNextBlockHeight(int current_height, int& next_height)
{
    if (current_height == std::numeric_limits<int>::max()) return false;
    next_height = current_height + 1;
    return true;
}

bool IsP2MROutputScript(const CScript& script_pub_key)
{
    int witness_version{-1};
    std::vector<unsigned char> witness_program;
    if (!script_pub_key.IsWitnessProgram(witness_version, witness_program)) return false;
    return witness_version == 2 && witness_program.size() == 32;
}

[[nodiscard]] std::vector<uint256> CollectReferencedShieldedNettingManifests(const CTransaction& tx)
{
    std::vector<uint256> out;
    if (!tx.HasShieldedBundle()) return out;
    const auto* bundle = tx.GetShieldedBundle().GetV2Bundle();
    if (bundle == nullptr ||
        !shielded::v2::BundleHasSemanticFamily(*bundle, shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR)) {
        return out;
    }

    const auto& payload = std::get<shielded::v2::SettlementAnchorPayload>(bundle->payload);
    if (!payload.anchored_netting_manifest_id.IsNull()) {
        out.push_back(payload.anchored_netting_manifest_id);
    }
    return out;
}

[[nodiscard]] bool AddCreatedShieldedRefs(const CTransaction& tx,
                                          std::set<uint256>& settlement_anchors,
                                          std::set<uint256>& netting_manifests)
{
    if (!tx.HasShieldedBundle()) return true;
    const auto family = tx.GetShieldedBundle().GetTransactionFamily();
    if (!family.has_value()) return true;

    std::string reject_reason;
    switch (*family) {
    case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR: {
        auto created = ExtractCreatedShieldedSettlementAnchors(tx, reject_reason);
        if (!created.has_value()) return false;
        settlement_anchors.insert(created->begin(), created->end());
        return true;
    }
    case shielded::v2::TransactionFamily::V2_REBALANCE: {
        auto created = ExtractCreatedShieldedNettingManifests(tx, reject_reason);
        if (!created.has_value()) return false;
        netting_manifests.insert(created->begin(), created->end());
        return true;
    }
    case shielded::v2::TransactionFamily::V2_SEND:
    case shielded::v2::TransactionFamily::V2_SPEND_PATH_RECOVERY:
    case shielded::v2::TransactionFamily::V2_INGRESS_BATCH:
    case shielded::v2::TransactionFamily::V2_EGRESS_BATCH:
    case shielded::v2::TransactionFamily::V2_LIFECYCLE:
    case shielded::v2::TransactionFamily::V2_GENERIC:
        return true;
    }
    return true;
}

[[nodiscard]] bool AreShieldedRefsReadyForBlock(const CTransaction& tx,
                                                const ChainstateManager& chainman,
                                                const std::set<uint256>& settlement_anchors,
                                                const std::set<uint256>& netting_manifests)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    if (!tx.HasShieldedBundle()) return true;

    for (const auto& anchor : CollectShieldedSettlementAnchorRefs(tx.GetShieldedBundle())) {
        if (anchor.IsNull()) continue;
        if (!chainman.IsShieldedSettlementAnchorValid(anchor) &&
            settlement_anchors.count(anchor) == 0) {
            return false;
        }
    }

    for (const auto& account_registry_anchor :
         CollectShieldedAccountRegistryRefs(tx.GetShieldedBundle())) {
        if (account_registry_anchor.IsNull()) continue;
        if (!chainman.IsShieldedAccountRegistryRootValid(account_registry_anchor)) {
            return false;
        }
    }

    for (const auto& manifest_id : CollectReferencedShieldedNettingManifests(tx)) {
        if (manifest_id.IsNull()) continue;
        if (!chainman.IsShieldedNettingManifestValid(manifest_id) &&
            netting_manifests.count(manifest_id) == 0) {
            return false;
        }
    }

    return true;
}

[[nodiscard]] bool IsShieldedPackageReadyForBlock(const std::vector<CTxMemPool::txiter>& sorted_entries,
                                                  const CTxMemPool::setEntries& in_block,
                                                  const ChainstateManager& chainman)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    std::set<uint256> settlement_anchors;
    std::set<uint256> netting_manifests;
    for (const auto& entry : in_block) {
        if (!AddCreatedShieldedRefs(entry->GetTx(), settlement_anchors, netting_manifests)) {
            return false;
        }
    }

    for (const auto& entry : sorted_entries) {
        if (!AreShieldedRefsReadyForBlock(entry->GetTx(), chainman, settlement_anchors, netting_manifests)) {
            return false;
        }
        if (!AddCreatedShieldedRefs(entry->GetTx(), settlement_anchors, netting_manifests)) {
            return false;
        }
    }
    return true;
}

template <typename TCurrent, typename TLimit, typename TDelta>
bool IsNearLimit(TCurrent current, TLimit limit, TDelta delta)
{
    using CommonT = std::common_type_t<TCurrent, TLimit, TDelta>;
    static_assert(std::is_unsigned_v<CommonT>);
    const CommonT current_u{static_cast<CommonT>(current)};
    const CommonT limit_u{static_cast<CommonT>(limit)};
    const CommonT delta_u{static_cast<CommonT>(delta)};
    if (current_u >= limit_u) return true;
    if (delta_u >= limit_u) return true;
    return current_u > (limit_u - delta_u);
}

bool CoinbaseOutputScriptSatisfiesReducedDataLimits(const Consensus::Params& consensus_params, const CScript& script_pub_key)
{
    // Consensus only enforces output types when reduced-data limits are enabled.
    if (!(consensus_params.fReducedDataLimits && consensus_params.fEnforceP2MROnlyOutputs)) return true;

    if (!script_pub_key.empty() && script_pub_key[0] == OP_RETURN) {
        // Match consensus semantics: allow OP_RETURN, but enforce the size limit.
        return script_pub_key.size() <= consensus_params.nMaxOpReturnBytes;
    }

    return IsP2MROutputScript(script_pub_key);
}

[[maybe_unused]] std::vector<uint32_t> FlattenMatrixWords(const matmul::Matrix& matrix)
{
    std::vector<uint32_t> out;
    out.reserve(static_cast<size_t>(matrix.rows()) * matrix.cols());
    for (uint32_t row = 0; row < matrix.rows(); ++row) {
        for (uint32_t col = 0; col < matrix.cols(); ++col) {
            out.push_back(matrix.at(row, col));
        }
    }
    return out;
}

// NOTE: This function is reserved for v2 (arbitrary matrices) where miners
// choose A/B and must embed them in the block body for validators. In v1
// (seed-derived matrices), validators regenerate A/B from header seeds, so
// storing the full matrices wastes ~2MB per block. See spec §12.5.1.
[[maybe_unused]] void PopulateMatMulPayloadFromSeeds(CBlock& block)
{
    if (block.matmul_dim == 0 || block.seed_a.IsNull() || block.seed_b.IsNull()) {
        block.matrix_a_data.clear();
        block.matrix_b_data.clear();
        return;
    }
    const uint32_t n = block.matmul_dim;
    const matmul::Matrix A = matmul::FromSeed(block.seed_a, n);
    const matmul::Matrix B = matmul::FromSeed(block.seed_b, n);
    block.matrix_a_data = FlattenMatrixWords(A);
    block.matrix_b_data = FlattenMatrixWords(B);
}

constexpr size_t PACKAGE_SELECTION_CANDIDATE_WINDOW{8};
constexpr uint64_t SCARCITY_PPM_SCALE{1'000'000};

enum class PackageResourceDimension : size_t {
    SERIALIZED_SIZE = 0,
    VERIFY_UNITS = 1,
    SCAN_UNITS = 2,
    TREE_UPDATE_UNITS = 3,
};

struct RemainingBlockResources {
    uint64_t serialized_bytes{0};
    uint64_t verify_units{0};
    uint64_t scan_units{0};
    uint64_t tree_update_units{0};
    uint64_t max_serialized_bytes{0};
    uint64_t max_verify_units{0};
    uint64_t max_scan_units{0};
    uint64_t max_tree_update_units{0};
};

struct PackageSelectionCandidate {
    CTxMemPool::txiter iter;
    bool from_modified{false};
    CTxMemPool::setEntries entries;
    CAmount selection_fees{0};
    uint64_t selection_size{0};
    CAmount total_fees{0};
    uint64_t total_policy_size{0};
    uint64_t total_serialized_size{0};
    uint64_t total_weight{0};
    int64_t total_sigops_cost{0};
    uint64_t total_shielded_verify_units{0};
    uint64_t total_shielded_scan_units{0};
    uint64_t total_shielded_tree_update_units{0};
};

[[nodiscard]] bool UseAccountRegistryAppendRateLimit(const Consensus::Params& consensus, int32_t height)
{
    return consensus.IsShieldedMatRiCTDisabled(height);
}

[[nodiscard]] bool UseAccountRegistryEntryCountLimit(const Consensus::Params& consensus, int32_t height)
{
    return consensus.IsShieldedMatRiCTDisabled(height);
}

[[nodiscard]] bool WouldExceedAccountRegistryEntryCountLimit(const Consensus::Params& consensus,
                                                             uint64_t current_entries,
                                                             uint64_t new_entries)
{
    return current_entries > consensus.nMaxShieldedAccountRegistryEntries ||
           new_entries > consensus.nMaxShieldedAccountRegistryEntries - current_entries;
}

[[nodiscard]] bool UseNoncedShieldedBridgeTags(const Consensus::Params& consensus, int32_t height)
{
    return consensus.IsShieldedBridgeTagUpgradeActive(height);
}

[[nodiscard]] uint64_t ScaleResourcePressurePpm(uint64_t used, uint64_t remaining)
{
    if (used == 0) return 0;
    if (remaining == 0) return std::numeric_limits<uint64_t>::max();
    const __int128 scaled = static_cast<__int128>(used) * SCARCITY_PPM_SCALE + remaining - 1;
    return static_cast<uint64_t>(scaled / remaining);
}

[[nodiscard]] uint64_t GetRemainingResource(const RemainingBlockResources& remaining, PackageResourceDimension dim)
{
    switch (dim) {
    case PackageResourceDimension::SERIALIZED_SIZE:
        return remaining.serialized_bytes;
    case PackageResourceDimension::VERIFY_UNITS:
        return remaining.verify_units;
    case PackageResourceDimension::SCAN_UNITS:
        return remaining.scan_units;
    case PackageResourceDimension::TREE_UPDATE_UNITS:
        return remaining.tree_update_units;
    }
    return 0;
}

[[nodiscard]] uint64_t GetMaxResource(const RemainingBlockResources& remaining, PackageResourceDimension dim)
{
    switch (dim) {
    case PackageResourceDimension::SERIALIZED_SIZE:
        return remaining.max_serialized_bytes;
    case PackageResourceDimension::VERIFY_UNITS:
        return remaining.max_verify_units;
    case PackageResourceDimension::SCAN_UNITS:
        return remaining.max_scan_units;
    case PackageResourceDimension::TREE_UPDATE_UNITS:
        return remaining.max_tree_update_units;
    }
    return 0;
}

[[nodiscard]] std::array<uint64_t, 4> ComputeCandidatePressurePpm(const PackageSelectionCandidate& candidate,
                                                                  const RemainingBlockResources& remaining)
{
    return {
        ScaleResourcePressurePpm(candidate.total_serialized_size, remaining.serialized_bytes),
        ScaleResourcePressurePpm(candidate.total_shielded_verify_units, remaining.verify_units),
        ScaleResourcePressurePpm(candidate.total_shielded_scan_units, remaining.scan_units),
        ScaleResourcePressurePpm(candidate.total_shielded_tree_update_units, remaining.tree_update_units),
    };
}

template <typename T>
void SetLegacySelectionScore(const T& source, PackageSelectionCandidate& candidate)
{
    const __int128 tx_score = static_cast<__int128>(source.GetModifiedFee()) * source.GetSizeWithAncestors();
    const __int128 ancestor_score = static_cast<__int128>(source.GetModFeesWithAncestors()) * source.GetTxSize();
    if (tx_score > ancestor_score) {
        candidate.selection_fees = source.GetModFeesWithAncestors();
        candidate.selection_size = source.GetSizeWithAncestors();
    } else {
        candidate.selection_fees = source.GetModifiedFee();
        candidate.selection_size = source.GetTxSize();
    }
}

[[nodiscard]] uint64_t GetDominantShieldedPressurePpm(const std::array<uint64_t, 4>& pressures)
{
    return std::max({pressures[static_cast<size_t>(PackageResourceDimension::VERIFY_UNITS)],
                     pressures[static_cast<size_t>(PackageResourceDimension::SCAN_UNITS)],
                     pressures[static_cast<size_t>(PackageResourceDimension::TREE_UPDATE_UNITS)]});
}

[[nodiscard]] bool IsShieldedScarcityActive(const RemainingBlockResources& remaining)
{
    constexpr uint64_t SHIELDED_SCARCITY_TRIGGER_PPM{600'000};
    const auto below_threshold = [&](uint64_t available, uint64_t maximum) {
        if (maximum == 0) return false;
        return available * SCARCITY_PPM_SCALE <= maximum * SHIELDED_SCARCITY_TRIGGER_PPM;
    };
    return below_threshold(remaining.verify_units, remaining.max_verify_units) ||
           below_threshold(remaining.scan_units, remaining.max_scan_units) ||
           below_threshold(remaining.tree_update_units, remaining.max_tree_update_units);
}

PackageSelectionCandidate BuildPackageSelectionCandidate(const CTxMemPool& mempool,
                                                         const CTxMemPool::setEntries& in_block,
                                                         CTxMemPool::txiter candidate_iter,
                                                         bool from_modified,
                                                         CAmount selection_fees,
                                                         uint64_t selection_size) EXCLUSIVE_LOCKS_REQUIRED(mempool.cs)
{
    PackageSelectionCandidate candidate;
    candidate.iter = candidate_iter;
    candidate.from_modified = from_modified;
    candidate.selection_fees = selection_fees;
    candidate.selection_size = selection_size;
    candidate.entries = mempool.AssumeCalculateMemPoolAncestors(__func__, *candidate_iter, CTxMemPool::Limits::NoLimits(), /*fSearchForParents=*/false);
    for (auto it = candidate.entries.begin(); it != candidate.entries.end();) {
        if (in_block.count(*it)) {
            candidate.entries.erase(it++);
        } else {
            ++it;
        }
    }
    candidate.entries.insert(candidate_iter);

    for (CTxMemPool::txiter entry : candidate.entries) {
        candidate.total_fees += entry->GetModifiedFee();
        candidate.total_policy_size += entry->GetTxSize();
        candidate.total_serialized_size += ::GetSerializeSize(TX_WITH_WITNESS(entry->GetTx()));
        candidate.total_weight += entry->GetTxWeight();
        candidate.total_sigops_cost += entry->GetSigOpCost();
        const auto shielded_usage = entry->GetTx().HasShieldedBundle()
            ? ::GetShieldedResourceUsage(entry->GetTx().GetShieldedBundle())
            : ShieldedResourceUsage{};
        candidate.total_shielded_verify_units += shielded_usage.verify_units;
        candidate.total_shielded_scan_units += shielded_usage.scan_units;
        candidate.total_shielded_tree_update_units += shielded_usage.tree_update_units;
    }

    return candidate;
}

[[nodiscard]] std::array<PackageResourceDimension, 4> GetScarcityPriority(const RemainingBlockResources& remaining)
{
    std::array<PackageResourceDimension, 4> order{
        PackageResourceDimension::SERIALIZED_SIZE,
        PackageResourceDimension::VERIFY_UNITS,
        PackageResourceDimension::SCAN_UNITS,
        PackageResourceDimension::TREE_UPDATE_UNITS,
    };
    std::sort(order.begin(), order.end(), [&](PackageResourceDimension lhs, PackageResourceDimension rhs) {
        const __int128 lhs_remaining = GetRemainingResource(remaining, lhs);
        const __int128 rhs_remaining = GetRemainingResource(remaining, rhs);
        const __int128 lhs_max = GetMaxResource(remaining, lhs);
        const __int128 rhs_max = GetMaxResource(remaining, rhs);
        const __int128 lhs_ratio = lhs_remaining * rhs_max;
        const __int128 rhs_ratio = rhs_remaining * lhs_max;
        if (lhs_ratio != rhs_ratio) return lhs_ratio < rhs_ratio;
        return static_cast<size_t>(lhs) < static_cast<size_t>(rhs);
    });
    return order;
}

[[nodiscard]] bool IsCandidateScoreBetter(const PackageSelectionCandidate& lhs,
                                          const PackageSelectionCandidate& rhs,
                                          const RemainingBlockResources& remaining)
{
    const __int128 lhs_base = static_cast<__int128>(lhs.selection_fees) * rhs.selection_size;
    const __int128 rhs_base = static_cast<__int128>(rhs.selection_fees) * lhs.selection_size;

    if (!IsShieldedScarcityActive(remaining) || lhs_base == rhs_base) {
        if (lhs_base != rhs_base) return lhs_base > rhs_base;
        const auto lhs_pressures = ComputeCandidatePressurePpm(lhs, remaining);
        const auto rhs_pressures = ComputeCandidatePressurePpm(rhs, remaining);
        const auto scarcity_order = GetScarcityPriority(remaining);
        for (const PackageResourceDimension dim : scarcity_order) {
            const size_t index = static_cast<size_t>(dim);
            if (lhs_pressures[index] != rhs_pressures[index]) {
                return lhs_pressures[index] < rhs_pressures[index];
            }
        }
        if (lhs.total_fees != rhs.total_fees) return lhs.total_fees > rhs.total_fees;
        if (lhs.total_policy_size != rhs.total_policy_size) return lhs.total_policy_size < rhs.total_policy_size;
        return lhs.iter->GetTx().GetHash() < rhs.iter->GetTx().GetHash();
    }

    const auto lhs_pressures = ComputeCandidatePressurePpm(lhs, remaining);
    const auto rhs_pressures = ComputeCandidatePressurePpm(rhs, remaining);
    const uint64_t lhs_dominant = std::max<uint64_t>(1, GetDominantShieldedPressurePpm(lhs_pressures));
    const uint64_t rhs_dominant = std::max<uint64_t>(1, GetDominantShieldedPressurePpm(rhs_pressures));

    const __int128 lhs_score =
        static_cast<__int128>(lhs.selection_fees) * rhs.selection_size * rhs_dominant;
    const __int128 rhs_score =
        static_cast<__int128>(rhs.selection_fees) * lhs.selection_size * lhs_dominant;
    if (lhs_score != rhs_score) return lhs_score > rhs_score;

    const auto scarcity_order = GetScarcityPriority(remaining);
    for (const PackageResourceDimension dim : scarcity_order) {
        const size_t index = static_cast<size_t>(dim);
        if (lhs_pressures[index] != rhs_pressures[index]) {
            return lhs_pressures[index] < rhs_pressures[index];
        }
    }

    if (lhs.total_fees != rhs.total_fees) return lhs.total_fees > rhs.total_fees;
    if (lhs.total_policy_size != rhs.total_policy_size) return lhs.total_policy_size < rhs.total_policy_size;
    return lhs.iter->GetTx().GetHash() < rhs.iter->GetTx().GetHash();
}
} // namespace

int64_t GetMinimumTime(const CBlockIndex* pindexPrev, const Consensus::Params& consensus_params)
{
    int64_t min_time{pindexPrev->GetMedianTimePast() + 1};
    // Height of block to be mined.
    int height{0};
    if (!TryGetNextBlockHeight(pindexPrev->nHeight, height)) return min_time;
    if (EnforceTimewarpProtectionAtHeight(consensus_params, height)) {
        min_time = std::max<int64_t>(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }
    return min_time;
}

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime{std::max<int64_t>(GetMinimumTime(pindexPrev, consensusParams),
                                       TicksSinceEpoch<std::chrono::seconds>(NodeClock::now()))};

    if (nOldTime < nNewTime) {
        pblock->nTime = nNewTime;
    }

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks) {
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
    }

    return nNewTime - nOldTime;
}

void RegenerateCommitments(CBlock& block, ChainstateManager& chainman)
{
    CMutableTransaction tx{*block.vtx.at(0)};
    tx.vout.erase(tx.vout.begin() + GetWitnessCommitmentIndex(block));
    block.vtx.at(0) = MakeTransactionRef(tx);

    const CBlockIndex* prev_block = WITH_LOCK(::cs_main, return chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock));
    chainman.GenerateCoinbaseCommitment(block, prev_block);

    block.hashMerkleRoot = BlockMerkleRoot(block);
}

BlockCreateOptions BlockCreateOptions::Clamped() const
{
    BlockAssembler::Options options = *this;
    CHECK_NONFATAL(options.block_reserved_size <= MAX_BLOCK_SERIALIZED_SIZE);
    CHECK_NONFATAL(options.block_reserved_weight <= MAX_BLOCK_WEIGHT);
    CHECK_NONFATAL(options.block_reserved_weight >= MINIMUM_BLOCK_RESERVED_WEIGHT);
    CHECK_NONFATAL(options.coinbase_output_max_additional_sigops <= MAX_BLOCK_SIGOPS_COST);
    // Limit size to between block_reserved_size and MAX_BLOCK_SERIALIZED_SIZE-1K for sanity:
    options.nBlockMaxSize = std::clamp<size_t>(options.nBlockMaxSize, options.block_reserved_size, MAX_BLOCK_SERIALIZED_SIZE);
    // Limit weight to between block_reserved_weight and MAX_BLOCK_WEIGHT for sanity:
    // block_reserved_weight can safely exceed -blockmaxweight, but the rest of the block template will be empty.
    options.nBlockMaxWeight = std::clamp<size_t>(options.nBlockMaxWeight, options.block_reserved_weight, MAX_BLOCK_WEIGHT);
    return options;
}

BlockAssembler::BlockAssembler(Chainstate& chainstate, const CTxMemPool* mempool, const Options& options, const NodeContext& node)
    : chainparams{chainstate.m_chainman.GetParams()},
      m_mempool{options.use_mempool ? mempool : nullptr},
      m_chainstate{chainstate},
      m_node{node},
      m_options{options.Clamped()}
{
    // Always account for serialized bytes: nBlockMaxSize is a consensus ceiling.
    fNeedSizeAccounting = true;
}

void ApplyArgsManOptions(const ArgsManager& args, BlockAssembler::Options& options)
{
    // Block resource limits
    // If neither -blockmaxsize or -blockmaxweight is given, limit to DEFAULT_BLOCK_MAX_*
    // If only one is given, only restrict the specified resource.
    // If both are given, restrict both.
    bool fWeightSet = false;
    if (args.IsArgSet("-blockmaxweight")) {
        options.nBlockMaxWeight = args.GetIntArg("-blockmaxweight", DEFAULT_BLOCK_MAX_WEIGHT);
        options.nBlockMaxSize = MAX_BLOCK_SERIALIZED_SIZE;
        fWeightSet = true;
    }
    if (args.IsArgSet("-blockmaxsize")) {
        options.nBlockMaxSize = args.GetIntArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);
        if (!fWeightSet) {
            options.nBlockMaxWeight = MAX_BLOCK_WEIGHT;
        }
    }
    if (const auto blockmintxfee{args.GetArg("-blockmintxfee")}) {
        if (const auto parsed{ParseMoney(*blockmintxfee)}) options.blockMinFeeRate = CFeeRate{*parsed};
    }
    options.print_modified_fee = args.GetBoolArg("-printpriority", options.print_modified_fee);
    options.block_reserved_weight = args.GetIntArg("-blockreservedweight", options.block_reserved_weight);
}

void BlockAssembler::resetBlock()
{
    inBlock.clear();

    // Reserve space for fixed-size block header, txs count, and coinbase tx.
    nBlockSize = m_options.block_reserved_size;
    nBlockWeight = m_options.block_reserved_weight;
    nBlockSigOpsCost = m_options.coinbase_output_max_additional_sigops;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
    nBlockShieldedVerifyCost = 0;
    nBlockShieldedScanUnits = 0;
    nBlockShieldedTreeUpdateUnits = 0;
    nBlockShieldedAccountRegistryAppends = 0;
    m_baseShieldedAccountRegistryEntries = 0;

    lastFewTxs = 0;
    blockFinished = false;
}

std::shared_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock()
{
    const auto time_start{SteadyClock::now()};

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());
    CBlock* const pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end
    if (m_options.print_modified_fee) {
        pblocktemplate->vTxPriorities.push_back(-1);  // n/a
    }

    LOCK(::cs_main);
    CBlockIndex* pindexPrev = m_chainstate.m_chain.Tip();
    if (!pindexPrev) {
        LogWarning("CreateNewBlock(): chain tip is null; chain may not be fully initialized\n");
        throw std::runtime_error("CreateNewBlock(): chain tip is null; chain may not be fully initialized");
    }
    if (!TryGetNextBlockHeight(pindexPrev->nHeight, nHeight)) {
        LogWarning("CreateNewBlock(): block height overflow at prev height %d\n", pindexPrev->nHeight);
        throw std::runtime_error("CreateNewBlock(): block height overflow");
    }
    m_baseShieldedAccountRegistryEntries = m_chainstate.m_chainman.GetShieldedAccountRegistryEntryCount();
    LogDebug(BCLog::MINING, "CreateNewBlock(): building on tip height=%d hash=%s\n",
             pindexPrev->nHeight, pindexPrev->GetBlockHash().GetHex());

    pblock->nVersion = m_chainstate.m_chainman.m_versionbitscache.ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand()) {
        pblock->nVersion = gArgs.GetIntArg("-blockversion", pblock->nVersion);
    }

    pblock->nTime = TicksSinceEpoch<std::chrono::seconds>(NodeClock::now());
    m_lock_time_cutoff = pindexPrev->GetMedianTimePast();

    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    if (m_mempool) {
        CTxMemPool& mutable_mempool{*const_cast<CTxMemPool*>(m_mempool)};
        LOCK(mutable_mempool.cs);
        RemoveStaleShieldedAnchorMempoolTransactions(mutable_mempool, m_chainstate.m_chain, m_chainstate.m_chainman);
        addPriorityTxs(mutable_mempool, nPackagesSelected);
        addPackageTxs(mutable_mempool, nPackagesSelected, nDescendantsUpdated);
    }

    const auto time_1{SteadyClock::now()};

    m_last_block_num_txs = nBlockTx;
    m_last_block_weight = nBlockWeight;
    if (fNeedSizeAccounting) {
        m_last_block_size = nBlockSize;
    } else {
        m_last_block_size = std::nullopt;
    }
    m_last_block_shielded_verify_units = static_cast<int64_t>(nBlockShieldedVerifyCost);
    m_last_block_shielded_scan_units = static_cast<int64_t>(nBlockShieldedScanUnits);
    m_last_block_shielded_tree_update_units = static_cast<int64_t>(nBlockShieldedTreeUpdateUnits);
    pblocktemplate->nShieldedVerifyUnits = nBlockShieldedVerifyCost;
    pblocktemplate->nShieldedScanUnits = nBlockShieldedScanUnits;
    pblocktemplate->nShieldedTreeUpdateUnits = nBlockShieldedTreeUpdateUnits;

    // Create coinbase transaction.
    if (!CoinbaseOutputScriptSatisfiesReducedDataLimits(chainparams.GetConsensus(), m_options.coinbase_output_script)) {
        throw std::runtime_error("CreateNewBlock(): coinbase output must be witness v2 P2MR (32-byte program) or OP_RETURN under reduced-data limits");
    }
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = m_options.coinbase_output_script;
    coinbaseTx.vout[0].nValue = nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    pblocktemplate->vchCoinbaseCommitment = m_chainstate.m_chainman.GenerateCoinbaseCommitment(*pblock, pindexPrev);
    pblocktemplate->vTxFees[0] = -nFees;

    uint64_t nSerializeSize = GetSerializeSize(TX_WITH_WITNESS(*pblock));
    LogPrintf("CreateNewBlock(): total size: %u block weight: %u txs: %u fees: %ld sigops %d\n", nSerializeSize, GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
    pblock->nNonce         = 0;
    pblock->nNonce64       = 0;
    pblock->mix_hash.SetNull();
    if (chainparams.GetConsensus().fMatMulPOW) {
        pblock->matmul_dim = static_cast<uint16_t>(chainparams.GetConsensus().nMatMulDimension);
        pblock->seed_a = DeterministicMatMulSeed(pblock->hashPrevBlock, nHeight, 0);
        pblock->seed_b = DeterministicMatMulSeed(pblock->hashPrevBlock, nHeight, 1);
        pblock->matmul_digest.SetNull();
        // v1 uses seed-derived matrices; do not store full matrices in block body.
        // Validators regenerate A and B from seed_a/seed_b on demand.
        pblock->matrix_a_data.clear();
        pblock->matrix_b_data.clear();
        // C' payload is populated after mining solves the block (see PopulateFreivaldsPayload)
        pblock->matrix_c_data.clear();
    } else {
        pblock->matmul_dim = 0;
        pblock->seed_a.SetNull();
        pblock->seed_b.SetNull();
        pblock->matmul_digest.SetNull();
        pblock->matrix_a_data.clear();
        pblock->matrix_b_data.clear();
        pblock->matrix_c_data.clear();
    }
    pblocktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx[0]);

    const auto& consensus_params = chainparams.GetConsensus();
    const bool skip_pow_template_check =
        consensus_params.fMatMulPOW ||
        (consensus_params.fKAWPOW && !consensus_params.fSkipKAWPOWValidation &&
            nHeight >= consensus_params.nKAWPOWHeight);
    BlockValidationState state;
    if (m_options.test_block_validity && !skip_pow_template_check) {
        LogDebug(BCLog::MINING, "CreateNewBlock(): running TestBlockValidity for height %d\n", nHeight);
        if (!TestBlockValidity(state, chainparams, m_chainstate, *pblock, pindexPrev,
                               /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false)) {
            LogWarning("CreateNewBlock(): TestBlockValidity failed at height %d: %s\n", nHeight, state.ToString());
            throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, state.ToString()));
        }
        LogDebug(BCLog::MINING, "CreateNewBlock(): TestBlockValidity passed for height %d\n", nHeight);
    } else {
        LogDebug(BCLog::MINING, "CreateNewBlock(): skipping TestBlockValidity (skip_pow=%s, test_validity=%s) for height %d\n",
                 skip_pow_template_check ? "true" : "false",
                 m_options.test_block_validity ? "true" : "false", nHeight);
    }
    const auto time_2{SteadyClock::now()};

    LogDebug(BCLog::BENCH, "CreateNewBlock() packages: %.2fms (%d packages, %d updated descendants), validity: %.2fms (total %.2fms)\n",
             Ticks<MillisecondsDouble>(time_1 - time_start), nPackagesSelected, nDescendantsUpdated,
             Ticks<MillisecondsDouble>(time_2 - time_1),
             Ticks<MillisecondsDouble>(time_2 - time_start));

    if (m_node.validation_signals) m_node.validation_signals->NewBlockTemplate(pblocktemplate);

    return std::move(pblocktemplate);
}

void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        // Only test txs not already in the block
        if (inBlock.count(*iit)) {
            testSet.erase(iit++);
        } else {
            iit++;
        }
    }
}

bool BlockAssembler::TestPackage(uint64_t packageWeight, int64_t packageSigOpsCost) const
{
    if (nBlockWeight + packageWeight >= m_options.nBlockMaxWeight) {
        return false;
    }
    if (nBlockSigOpsCost + packageSigOpsCost >= MAX_BLOCK_SIGOPS_COST) {
        return false;
    }
    return true;
}

static ShieldedResourceUsage GetTransactionShieldedResourceUsage(const CTransaction& tx)
{
    if (!tx.HasShieldedBundle()) return {};
    return ::GetShieldedResourceUsage(tx.GetShieldedBundle());
}

static bool TryCountTransactionShieldedAccountRegistryAppends(const CTransaction& tx,
                                                              const Consensus::Params& consensus,
                                                              int32_t height,
                                                              uint64_t& out_count)
{
    out_count = 0;
    if (!tx.HasShieldedBundle()) return true;
    const auto account_leaf_commitments =
        CollectShieldedOutputAccountLeafCommitments(tx.GetShieldedBundle(),
                                                    UseNoncedShieldedBridgeTags(consensus, height));
    if (!account_leaf_commitments.has_value()) return false;
    out_count = static_cast<uint64_t>(account_leaf_commitments->size());
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
// - serialized size limit (consensus nBlockMaxSize ceiling)
// - shielded verification cost budget
bool BlockAssembler::TestPackageTransactions(const CTxMemPool::setEntries& package) const
{
    uint64_t nPotentialBlockSize = nBlockSize; // only used with fNeedSizeAccounting
    uint64_t nPotentialShieldedCost = nBlockShieldedVerifyCost;
    uint64_t nPotentialShieldedScanUnits = nBlockShieldedScanUnits;
    uint64_t nPotentialShieldedTreeUpdateUnits = nBlockShieldedTreeUpdateUnits;
    uint64_t nPotentialShieldedAccountRegistryAppends = nBlockShieldedAccountRegistryAppends;
    for (CTxMemPool::txiter it : package) {
        if (it->GetTx().HasShieldedBundle() &&
            UseAccountRegistryEntryCountLimit(chainparams.GetConsensus(), nHeight) &&
            m_baseShieldedAccountRegistryEntries >
                chainparams.GetConsensus().nMaxShieldedAccountRegistryEntries) {
            return false;
        }
        if (!IsFinalTx(it->GetTx(), nHeight, m_lock_time_cutoff)) {
            return false;
        }
        if (fNeedSizeAccounting) {
            uint64_t nTxSize = ::GetSerializeSize(TX_WITH_WITNESS(it->GetTx()));
            if (nPotentialBlockSize + nTxSize >= m_options.nBlockMaxSize) {
                return false;
            }
            nPotentialBlockSize += nTxSize;
        }
        const auto shielded_usage = GetTransactionShieldedResourceUsage(it->GetTx());
        nPotentialShieldedCost += shielded_usage.verify_units;
        if (nPotentialShieldedCost > chainparams.GetConsensus().nMaxBlockShieldedVerifyCost) {
            return false;
        }
        nPotentialShieldedScanUnits += shielded_usage.scan_units;
        if (nPotentialShieldedScanUnits > chainparams.GetConsensus().nMaxBlockShieldedScanUnits) {
            return false;
        }
        nPotentialShieldedTreeUpdateUnits += shielded_usage.tree_update_units;
        if (nPotentialShieldedTreeUpdateUnits > chainparams.GetConsensus().nMaxBlockShieldedTreeUpdateUnits) {
            return false;
        }
        if (UseAccountRegistryAppendRateLimit(chainparams.GetConsensus(), nHeight)) {
            uint64_t bundle_account_registry_appends{0};
            if (!TryCountTransactionShieldedAccountRegistryAppends(
                    it->GetTx(), chainparams.GetConsensus(), nHeight, bundle_account_registry_appends)) {
                return false;
            }
            if (bundle_account_registry_appends >
                    chainparams.GetConsensus().nMaxBlockShieldedAccountRegistryAppends ||
                nPotentialShieldedAccountRegistryAppends >
                chainparams.GetConsensus().nMaxBlockShieldedAccountRegistryAppends -
                    bundle_account_registry_appends) {
                return false;
            }
            nPotentialShieldedAccountRegistryAppends += bundle_account_registry_appends;
            if (nPotentialShieldedAccountRegistryAppends >
                chainparams.GetConsensus().nMaxBlockShieldedAccountRegistryAppends) {
                return false;
            }
        }
        if (UseAccountRegistryEntryCountLimit(chainparams.GetConsensus(), nHeight) &&
            WouldExceedAccountRegistryEntryCountLimit(chainparams.GetConsensus(),
                                                     m_baseShieldedAccountRegistryEntries,
                                                     nPotentialShieldedAccountRegistryAppends)) {
            return false;
        }
    }
    return true;
}

void BlockAssembler::AddToBlock(const CTxMemPool& mempool, CTxMemPool::txiter iter)
{
    pblocktemplate->block.vtx.emplace_back(iter->GetSharedTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());
    if (fNeedSizeAccounting) {
        nBlockSize += ::GetSerializeSize(TX_WITH_WITNESS(iter->GetTx()));
    }
    nBlockWeight += iter->GetTxWeight();
    ++nBlockTx;
    nBlockSigOpsCost += iter->GetSigOpCost();
    nFees += iter->GetFee();
    const auto shielded_usage = GetTransactionShieldedResourceUsage(iter->GetTx());
    uint64_t shielded_account_registry_appends{0};
    const bool counted_account_registry_appends = TryCountTransactionShieldedAccountRegistryAppends(
        iter->GetTx(), chainparams.GetConsensus(), nHeight, shielded_account_registry_appends);
    Assume(counted_account_registry_appends);
    nBlockShieldedVerifyCost += shielded_usage.verify_units;
    nBlockShieldedScanUnits += shielded_usage.scan_units;
    nBlockShieldedTreeUpdateUnits += shielded_usage.tree_update_units;
    nBlockShieldedAccountRegistryAppends += shielded_account_registry_appends;
    inBlock.insert(iter);

    if (m_options.print_modified_fee) {
        double dPriority = iter->GetPriority(nHeight);
        CAmount dummy;
        mempool.ApplyDeltas(iter->GetTx().GetHash(), dPriority, dummy);
        LogPrintf("priority %.1f fee rate %s txid %s\n",
                  dPriority,
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
        pblocktemplate->vTxPriorities.push_back(dPriority);
    }
}

/** Add descendants of given transactions to mapModifiedTx with ancestor
 * state updated assuming given transactions are inBlock. Returns number
 * of updated descendants. */
static int UpdatePackagesForAdded(const CTxMemPool& mempool,
                                  const CTxMemPool::setEntries& alreadyAdded,
                                  indexed_modified_transaction_set& mapModifiedTx) EXCLUSIVE_LOCKS_REQUIRED(mempool.cs)
{
    AssertLockHeld(mempool.cs);

    int nDescendantsUpdated = 0;
    for (CTxMemPool::txiter it : alreadyAdded) {
        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(it, descendants);
        // Insert all descendants (not yet in block) into the modified set
        for (CTxMemPool::txiter desc : descendants) {
            if (alreadyAdded.count(desc)) {
                continue;
            }
            ++nDescendantsUpdated;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                mit = mapModifiedTx.insert(modEntry).first;
            }
            mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
        }
    }
    return nDescendantsUpdated;
}

void BlockAssembler::SortForBlock(const CTxMemPool::setEntries& package, std::vector<CTxMemPool::txiter>& sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for block inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void BlockAssembler::addPackageTxs(const CTxMemPool& mempool, int& nPackagesSelected, int& nDescendantsUpdated)
{
    AssertLockHeld(mempool.cs);

    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the block
    indexed_modified_transaction_set mapModifiedTx;
    // Keep track of entries that failed inclusion, to avoid duplicate work
    CTxMemPool::setEntries failedTx;

    // Start by adding all descendants of previously added txs to mapModifiedTx
    // and modifying them for their already included ancestors
    nDescendantsUpdated += UpdatePackagesForAdded(mempool, inBlock, mapModifiedTx);
    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    CTxMemPool::txiter iter;

    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    constexpr int32_t BLOCK_FULL_ENOUGH_SIZE_DELTA = 1000;
    constexpr int32_t BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000;
    int64_t nConsecutiveFailed = 0;

    while (mi != mempool.mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty()) {
        while (mi != mempool.mapTx.get<ancestor_score>().end()) {
            auto it = mempool.mapTx.project<0>(mi);
            assert(it != mempool.mapTx.end());
            if (mapModifiedTx.count(it) || inBlock.count(it) || failedTx.count(it)) {
                ++mi;
                continue;
            }
            break;
        }

        std::vector<PackageSelectionCandidate> candidate_window;
        candidate_window.reserve(PACKAGE_SELECTION_CANDIDATE_WINDOW * 2);

        auto map_scan = mi;
        size_t map_candidates = 0;
        while (map_scan != mempool.mapTx.get<ancestor_score>().end() &&
               map_candidates < PACKAGE_SELECTION_CANDIDATE_WINDOW) {
            auto candidate_iter = mempool.mapTx.project<0>(map_scan);
            assert(candidate_iter != mempool.mapTx.end());
            if (!mapModifiedTx.count(candidate_iter) && !inBlock.count(candidate_iter) && !failedTx.count(candidate_iter)) {
                CAmount selection_fees{0};
                uint64_t selection_size{0};
                {
                    PackageSelectionCandidate score_source;
                    SetLegacySelectionScore(*candidate_iter, score_source);
                    selection_fees = score_source.selection_fees;
                    selection_size = score_source.selection_size;
                }
                candidate_window.emplace_back(BuildPackageSelectionCandidate(
                    mempool, inBlock, candidate_iter, /*from_modified=*/false, selection_fees, selection_size));
                ++map_candidates;
            }
            ++map_scan;
        }

        auto mod_scan = mapModifiedTx.get<ancestor_score>().begin();
        size_t modified_candidates = 0;
        while (mod_scan != mapModifiedTx.get<ancestor_score>().end() &&
               modified_candidates < PACKAGE_SELECTION_CANDIDATE_WINDOW) {
            const auto& modified_entry = *mod_scan;
            if (!inBlock.count(modified_entry.iter) && !failedTx.count(modified_entry.iter)) {
                CAmount selection_fees{0};
                uint64_t selection_size{0};
                {
                    PackageSelectionCandidate score_source;
                    SetLegacySelectionScore(modified_entry, score_source);
                    selection_fees = score_source.selection_fees;
                    selection_size = score_source.selection_size;
                }
                candidate_window.emplace_back(BuildPackageSelectionCandidate(
                    mempool, inBlock, modified_entry.iter, /*from_modified=*/true, selection_fees, selection_size));
                ++modified_candidates;
            }
            ++mod_scan;
        }

        if (candidate_window.empty()) {
            return;
        }

        RemainingBlockResources remaining_resources;
        remaining_resources.serialized_bytes =
            nBlockSize < m_options.nBlockMaxSize ? m_options.nBlockMaxSize - nBlockSize : 0;
        remaining_resources.verify_units =
            nBlockShieldedVerifyCost < chainparams.GetConsensus().nMaxBlockShieldedVerifyCost ?
                chainparams.GetConsensus().nMaxBlockShieldedVerifyCost - nBlockShieldedVerifyCost : 0;
        remaining_resources.scan_units =
            nBlockShieldedScanUnits < chainparams.GetConsensus().nMaxBlockShieldedScanUnits ?
                chainparams.GetConsensus().nMaxBlockShieldedScanUnits - nBlockShieldedScanUnits : 0;
        remaining_resources.tree_update_units =
            nBlockShieldedTreeUpdateUnits < chainparams.GetConsensus().nMaxBlockShieldedTreeUpdateUnits ?
                chainparams.GetConsensus().nMaxBlockShieldedTreeUpdateUnits - nBlockShieldedTreeUpdateUnits : 0;
        remaining_resources.max_serialized_bytes = m_options.nBlockMaxSize;
        remaining_resources.max_verify_units = chainparams.GetConsensus().nMaxBlockShieldedVerifyCost;
        remaining_resources.max_scan_units = chainparams.GetConsensus().nMaxBlockShieldedScanUnits;
        remaining_resources.max_tree_update_units = chainparams.GetConsensus().nMaxBlockShieldedTreeUpdateUnits;

        std::optional<size_t> best_candidate_index;
        for (size_t i = 0; i < candidate_window.size(); ++i) {
            const auto& candidate = candidate_window[i];
            if (candidate.total_fees < m_options.blockMinFeeRate.GetFee(candidate.total_policy_size)) {
                continue;
            }
            std::vector<CTxMemPool::txiter> sorted_entries;
            SortForBlock(candidate.entries, sorted_entries);
            if (!IsShieldedPackageReadyForBlock(sorted_entries, inBlock, m_chainstate.m_chainman)) {
                continue;
            }
            if (!best_candidate_index.has_value() ||
                IsCandidateScoreBetter(candidate, candidate_window[*best_candidate_index], remaining_resources)) {
                best_candidate_index = i;
            }
        }

        if (!best_candidate_index.has_value()) {
            return;
        }

        auto candidate = std::move(candidate_window[*best_candidate_index]);
        iter = candidate.iter;

        assert(!inBlock.count(iter));

        if (!TestPackage(candidate.total_weight, candidate.total_sigops_cost)) {
            if (candidate.from_modified) {
                mapModifiedTx.erase(iter);
            }
            failedTx.insert(iter);

            ++nConsecutiveFailed;

            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES &&
                IsNearLimit(nBlockWeight, m_options.nBlockMaxWeight,
                            static_cast<uint64_t>(BLOCK_FULL_ENOUGH_WEIGHT_DELTA))) {
                // Give up if we're close to full and haven't succeeded in a while
                break;
            }
            continue;
        }

        // Test if all tx's are Final
        if (!TestPackageTransactions(candidate.entries)) {
            if (candidate.from_modified) {
                mapModifiedTx.erase(iter);
            }
            failedTx.insert(iter);

            if (fNeedSizeAccounting) {
                ++nConsecutiveFailed;

                if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES &&
                    IsNearLimit(nBlockSize, m_options.nBlockMaxSize,
                                static_cast<uint64_t>(BLOCK_FULL_ENOUGH_SIZE_DELTA))) {
                    // Give up if we're close to full and haven't succeeded in a while
                    break;
                }
            }
            continue;
        }

        // This transaction will make it in; reset the failed counter.
        nConsecutiveFailed = 0;

        // Package can be added. Sort the entries in a valid order.
        std::vector<CTxMemPool::txiter> sortedEntries;
        SortForBlock(candidate.entries, sortedEntries);

        for (size_t i = 0; i < sortedEntries.size(); ++i) {
            AddToBlock(mempool, sortedEntries[i]);
            // Erase from the modified set, if present
            mapModifiedTx.erase(sortedEntries[i]);
        }

        ++nPackagesSelected;
        pblocktemplate->m_package_feerates.emplace_back(candidate.total_fees, static_cast<int32_t>(candidate.total_policy_size));

        // Update transactions that depend on each of these
        nDescendantsUpdated += UpdatePackagesForAdded(mempool, candidate.entries, mapModifiedTx);
    }
}
} // namespace node
