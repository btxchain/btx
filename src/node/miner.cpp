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
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <deploymentstatus.h>
#include <matmul/matmul_v4.h>
#include <logging.h>
#include <matmul/matrix.h>
#include <node/context.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <random.h>
#include <shielded/bundle.h>
#include <shielded/unshield_velocity.h>
#include <shielded/validation.h>
#include <util/check.h>
#include <util/moneystr.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <algorithm>
#include <array>
#include <limits>
#include <set>
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

[[nodiscard]] bool PassesReducedDataOutputLimits(const CTransaction& tx,
                                                 const Consensus::Params& consensus)
{
    if (!consensus.fReducedDataLimits) return true;

    for (const auto& txout : tx.vout) {
        const size_t script_size{txout.scriptPubKey.size()};
        const bool is_op_return{script_size > 0 && txout.scriptPubKey[0] == OP_RETURN};
        if (is_op_return) {
            if (script_size > consensus.nMaxOpReturnBytes) {
                return false;
            }
            continue;
        }
        if (script_size > consensus.nMaxTxoutScriptPubKeyBytes) {
            return false;
        }
        if (consensus.fEnforceP2MROnlyOutputs && !IsP2MROutputScript(txout.scriptPubKey)) {
            return false;
        }
    }
    return true;
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
                                          int64_t validation_height,
                                          std::set<uint256>& settlement_anchors,
                                          std::set<uint256>& netting_manifests)
{
    if (!tx.HasShieldedBundle()) return true;
    const auto family = tx.GetShieldedBundle().GetTransactionFamily();
    if (!family.has_value()) return true;

    std::string reject_reason;
    switch (*family) {
    case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR: {
        auto created = ExtractCreatedShieldedSettlementAnchors(tx, validation_height, reject_reason);
        if (!created.has_value()) return false;
        for (const auto& anchor : *created) {
            if (!settlement_anchors.insert(anchor).second) return false;
        }
        return true;
    }
    case shielded::v2::TransactionFamily::V2_REBALANCE: {
        auto created = ExtractCreatedShieldedNettingManifests(tx, reject_reason);
        if (!created.has_value()) return false;
        for (const auto& manifest_id : *created) {
            if (!netting_manifests.insert(manifest_id).second) return false;
        }
        return true;
    }
    case shielded::v2::TransactionFamily::V2_SEND:
    case shielded::v2::TransactionFamily::V2_SPEND_PATH_RECOVERY:
    case shielded::v2::TransactionFamily::V2_RECOVERY_EXIT:
    case shielded::v2::TransactionFamily::V2_INGRESS_BATCH:
    case shielded::v2::TransactionFamily::V2_EGRESS_BATCH:
    case shielded::v2::TransactionFamily::V2_LIFECYCLE:
    case shielded::v2::TransactionFamily::V2_GENERIC:
        return true;
    }
    return true;
}

[[nodiscard]] bool IsSettlementAnchorMatureForTemplate(const ConfirmedSettlementAnchorState& anchor_state,
                                                       const Consensus::Params& consensus,
                                                       int32_t validation_height)
{
    const uint32_t maturity_depth = consensus.GetShieldedSettlementAnchorMaturityDepth(validation_height);
    if (maturity_depth == 0) return true;
    if (!anchor_state.IsValid() || validation_height <= anchor_state.created_height) return false;
    const auto depth = static_cast<uint32_t>(validation_height - anchor_state.created_height);
    return depth >= maturity_depth;
}

[[nodiscard]] bool GetCachedShieldedRetirementsForTemplateTx(
    const CTransaction& tx,
    const CTxMemPool& pool,
    std::set<Txid>& retirement_cache_complete,
    std::map<Txid, std::vector<Nullifier>>& nullifier_cache,
    std::map<Txid, std::vector<uint256>>& commitment_cache,
    std::vector<Nullifier>& out_nullifiers,
    std::vector<uint256>& out_recovery_commitments);

[[nodiscard]] bool AreShieldedRefsReadyForBlock(const CTransaction& tx,
                                                const ChainstateManager& chainman,
                                                const std::set<uint256>& settlement_anchors,
                                                const std::set<uint256>& netting_manifests,
                                                const std::set<uint256>& shielded_nullifiers,
                                                const std::set<uint256>& recovery_exit_commitments,
                                                const CTxMemPool& pool,
                                                std::set<Txid>& retirement_cache_complete,
                                                std::map<Txid, std::vector<Nullifier>>& nullifier_cache,
                                                std::map<Txid, std::vector<uint256>>& commitment_cache)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main, pool.cs)
{
    if (!tx.HasShieldedBundle()) return true;

    std::vector<Nullifier> tx_nullifiers;
    std::vector<uint256> tx_recovery_exit_commitments;
    if (!GetCachedShieldedRetirementsForTemplateTx(tx,
                                                   pool,
                                                   retirement_cache_complete,
                                                   nullifier_cache,
                                                   commitment_cache,
                                                   tx_nullifiers,
                                                   tx_recovery_exit_commitments)) {
        return false;
    }
    for (const auto& nullifier : tx_nullifiers) {
        if (chainman.IsShieldedNullifierSpent(nullifier) ||
            shielded_nullifiers.count(nullifier) != 0) {
            return false;
        }
    }
    for (const auto& commitment : tx_recovery_exit_commitments) {
        if (chainman.IsShieldedRecoveryExitCommitmentRetired(commitment) ||
            recovery_exit_commitments.count(commitment) != 0) {
            return false;
        }
    }

    for (const auto& anchor : CollectShieldedSettlementAnchorRefs(tx.GetShieldedBundle())) {
        if (anchor.IsNull()) continue;
        if (!chainman.IsShieldedSettlementAnchorValid(anchor) &&
            settlement_anchors.count(anchor) == 0) {
            return false;
        }
    }

    const auto* v2_bundle = tx.GetShieldedBundle().GetV2Bundle();
    if (v2_bundle != nullptr &&
        shielded::v2::BundleHasSemanticFamily(*v2_bundle,
                                              shielded::v2::TransactionFamily::V2_EGRESS_BATCH)) {
        const auto& payload = std::get<shielded::v2::EgressBatchPayload>(v2_bundle->payload);
        const int32_t validation_height = chainman.ActiveChain().Height() + 1;
        const uint32_t maturity_depth =
            chainman.GetConsensus().GetShieldedSettlementAnchorMaturityDepth(validation_height);
        const auto anchor_state = chainman.GetShieldedSettlementAnchorState(payload.settlement_anchor);
        if (maturity_depth > 0) {
            if (!anchor_state.has_value() ||
                !IsSettlementAnchorMatureForTemplate(*anchor_state,
                                                     chainman.GetConsensus(),
                                                     validation_height)) {
                return false;
            }
        } else if (!anchor_state.has_value() &&
                   settlement_anchors.count(payload.settlement_anchor) == 0) {
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

[[nodiscard]] bool GetCachedShieldedRetirementsForTemplateTx(
    const CTransaction& tx,
    const CTxMemPool& pool,
    std::set<Txid>& retirement_cache_complete,
    std::map<Txid, std::vector<Nullifier>>& nullifier_cache,
    std::map<Txid, std::vector<uint256>>& commitment_cache,
    std::vector<Nullifier>& out_nullifiers,
    std::vector<uint256>& out_recovery_commitments)
    EXCLUSIVE_LOCKS_REQUIRED(pool.cs)
{
    out_nullifiers.clear();
    out_recovery_commitments.clear();
    if (!tx.HasShieldedBundle()) return true;

    const Txid txid = tx.GetHash();
    if (retirement_cache_complete.count(txid) != 0) {
        if (const auto it = nullifier_cache.find(txid); it != nullifier_cache.end()) {
            out_nullifiers = it->second;
        }
        if (const auto it = commitment_cache.find(txid); it != commitment_cache.end()) {
            out_recovery_commitments = it->second;
        }
        return true;
    }

    if (!pool.GetShieldedRetirementsForMempoolTx(tx, out_nullifiers, out_recovery_commitments)) {
        return false;
    }
    if (!out_nullifiers.empty()) {
        nullifier_cache.emplace(txid, out_nullifiers);
    }
    if (!out_recovery_commitments.empty()) {
        commitment_cache.emplace(txid, out_recovery_commitments);
    }
    retirement_cache_complete.insert(txid);
    return true;
}

[[nodiscard]] bool AddShieldedRetirementsForTemplateTx(
    const CTransaction& tx,
    const CTxMemPool& pool,
    std::set<uint256>& shielded_nullifiers,
    std::set<uint256>& recovery_exit_commitments,
    std::set<Txid>& retirement_cache_complete,
    std::map<Txid, std::vector<Nullifier>>& nullifier_cache,
    std::map<Txid, std::vector<uint256>>& commitment_cache)
    EXCLUSIVE_LOCKS_REQUIRED(pool.cs)
{
    std::vector<Nullifier> tx_nullifiers;
    std::vector<uint256> tx_recovery_exit_commitments;
    if (!GetCachedShieldedRetirementsForTemplateTx(tx,
                                                   pool,
                                                   retirement_cache_complete,
                                                   nullifier_cache,
                                                   commitment_cache,
                                                   tx_nullifiers,
                                                   tx_recovery_exit_commitments)) {
        return false;
    }
    for (const auto& nullifier : tx_nullifiers) {
        if (!shielded_nullifiers.insert(nullifier).second) {
            return false;
        }
    }
    for (const auto& commitment : tx_recovery_exit_commitments) {
        if (!recovery_exit_commitments.insert(commitment).second) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool IsShieldedPackageReadyForBlock(const std::vector<CTxMemPool::txiter>& sorted_entries,
                                                  const ChainstateManager& chainman,
                                                  const CTxMemPool& pool,
                                                  const std::set<uint256>& template_settlement_anchors,
                                                  const std::set<uint256>& template_netting_manifests,
                                                  const std::set<uint256>& template_shielded_nullifiers,
                                                  const std::set<uint256>& template_recovery_exit_commitments,
                                                  std::set<Txid>& retirement_cache_complete,
                                                  std::map<Txid, std::vector<Nullifier>>& nullifier_cache,
                                                  std::map<Txid, std::vector<uint256>>& commitment_cache)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main, pool.cs)
{
    std::set<uint256> settlement_anchors{template_settlement_anchors};
    std::set<uint256> netting_manifests{template_netting_manifests};
    std::set<uint256> shielded_nullifiers{template_shielded_nullifiers};
    std::set<uint256> recovery_exit_commitments{template_recovery_exit_commitments};
    // The package is being assembled for the next block; bridge-OUT attestor receipts must verify
    // under the scheme fixed by that height (FIPS-205 at/after C-002).
    const int64_t validation_height = chainman.ActiveChain().Height() + 1;

    for (const auto& entry : sorted_entries) {
        if (!AreShieldedRefsReadyForBlock(entry->GetTx(),
                                          chainman,
                                          settlement_anchors,
                                          netting_manifests,
                                          shielded_nullifiers,
                                          recovery_exit_commitments,
                                          pool,
                                          retirement_cache_complete,
                                          nullifier_cache,
                                          commitment_cache)) {
            return false;
        }
        if (!AddShieldedRetirementsForTemplateTx(entry->GetTx(),
                                                 pool,
                                                 shielded_nullifiers,
                                                 recovery_exit_commitments,
                                                 retirement_cache_complete,
                                                 nullifier_cache,
                                                 commitment_cache)) {
            return false;
        }
        if (!AddCreatedShieldedRefs(entry->GetTx(), validation_height, settlement_anchors, netting_manifests)) {
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
// Recovery-exit bundles are consensus-valid without a shielded proof envelope,
// so their consensus shielded verify usage is zero. They still trigger
// expensive ownership/nullifier/commitment checks in TestBlockValidity. Bound
// that policy-only CPU work so getblocktemplate cannot pack an entire recovery
// wave and hold cs_main for tens of seconds per new block.
constexpr uint64_t RECOVERY_EXIT_TEMPLATE_POLICY_VERIFY_UNITS{100};
constexpr uint64_t MAX_TEMPLATE_POLICY_VERIFY_UNITS{1'600};
constexpr uint64_t MAX_TEMPLATE_RECOVERY_EXIT_TXS{16};
constexpr uint64_t MAX_TEMPLATE_POLICY_CANDIDATE_EVALUATIONS{128};

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
    uint64_t total_template_policy_verify_units{0};
    uint64_t total_recovery_exit_txs{0};
    CAmount total_positive_shielded_egress{0};
    bool has_positive_shielded_egress{false};
    bool has_unusable_shielded_egress{false};
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

[[nodiscard]] bool IsRecoveryExitTemplateTransaction(const CTransaction& tx)
{
    if (!tx.HasShieldedBundle()) return false;
    const auto family = tx.GetShieldedBundle().GetTransactionFamily();
    return family.has_value() && *family == shielded::v2::TransactionFamily::V2_RECOVERY_EXIT;
}

[[nodiscard]] bool IsPostSunsetShieldedExitVelocityFilterActive(const Consensus::Params& consensus,
                                                                int32_t height)
{
    return consensus.IsShieldedSunsetActive(height) &&
           consensus.IsShieldedUnshieldVelocityCapActive(height);
}

[[nodiscard]] std::optional<CAmount> GetPositiveShieldedEgressValue(const CTransaction& tx)
{
    if (!tx.HasShieldedBundle()) return CAmount{0};
    std::string reject_reason;
    const auto state_value_balance =
        TryGetShieldedStateValueBalance(tx.GetShieldedBundle(), reject_reason);
    if (!state_value_balance.has_value()) return std::nullopt;
    return *state_value_balance > 0 ? *state_value_balance : CAmount{0};
}

[[nodiscard]] bool TryAddMoneyRange(CAmount& total, CAmount value)
{
    if (value < 0 || value > MAX_MONEY - total) return false;
    total += value;
    return true;
}

[[nodiscard]] std::optional<CAmount> ComputePendingMempoolShieldedEgress(const CTxMemPool& mempool)
    EXCLUSIVE_LOCKS_REQUIRED(mempool.cs)
{
    CAmount pending{0};
    for (auto it = mempool.mapTx.begin(); it != mempool.mapTx.end(); ++it) {
        const auto egress = GetPositiveShieldedEgressValue(it->GetTx());
        if (!egress.has_value()) return std::nullopt;
        if (!TryAddMoneyRange(pending, *egress)) return std::nullopt;
    }
    return pending;
}

[[nodiscard]] CAmount ComputeRemainingShieldedExitCapacity(const ChainstateManager& chainman,
                                                           const Consensus::Params& consensus,
                                                           int32_t height,
                                                           CAmount pool_balance)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    const CAmount window_egress = chainman.GetShieldedUnshieldVelocityWindowTotal(
        height, consensus.nShieldedUnshieldVelocityWindowBlocks);
    const CAmount min_cap = consensus.ShieldedUnshieldVelocityMinCapForHeight(height);
    const CAmount cap_amount = ShieldedUnshieldVelocity::WindowCap(
        pool_balance, consensus.nShieldedUnshieldVelocityCapBps, min_cap);
    return cap_amount > window_egress ? cap_amount - window_egress : 0;
}

[[nodiscard]] uint64_t GetTransactionTemplatePolicyVerifyUnits(const CTransaction& tx)
{
    if (!tx.HasShieldedBundle()) return 0;
    uint64_t units = ::GetShieldedResourceUsage(tx.GetShieldedBundle()).verify_units;
    if (IsRecoveryExitTemplateTransaction(tx)) {
        units += RECOVERY_EXIT_TEMPLATE_POLICY_VERIFY_UNITS;
    }
    return units;
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

    bool has_shielded_entry{false};
    for (CTxMemPool::txiter entry : candidate.entries) {
        candidate.total_fees += entry->GetModifiedFee();
        const bool entry_has_shielded_bundle = entry->GetTx().HasShieldedBundle();
        has_shielded_entry = has_shielded_entry || entry_has_shielded_bundle;
        candidate.total_policy_size += entry_has_shielded_bundle
            ? static_cast<uint64_t>(GetShieldedRelayVirtualSize(entry->GetTx()))
            : static_cast<uint64_t>(entry->GetTxSize());
        candidate.total_serialized_size += ::GetSerializeSize(TX_WITH_WITNESS(entry->GetTx()));
        candidate.total_weight += entry->GetTxWeight();
        candidate.total_sigops_cost += entry->GetSigOpCost();
        const auto shielded_usage = entry_has_shielded_bundle
            ? ::GetShieldedResourceUsage(entry->GetTx().GetShieldedBundle())
            : ShieldedResourceUsage{};
        candidate.total_shielded_verify_units += shielded_usage.verify_units;
        candidate.total_shielded_scan_units += shielded_usage.scan_units;
        candidate.total_shielded_tree_update_units += shielded_usage.tree_update_units;
        candidate.total_template_policy_verify_units += GetTransactionTemplatePolicyVerifyUnits(entry->GetTx());
        if (entry_has_shielded_bundle) {
            const auto egress = GetPositiveShieldedEgressValue(entry->GetTx());
            if (!egress.has_value() || !TryAddMoneyRange(candidate.total_positive_shielded_egress, *egress)) {
                candidate.has_unusable_shielded_egress = true;
            } else if (*egress > 0) {
                candidate.has_positive_shielded_egress = true;
            }
        }
        if (IsRecoveryExitTemplateTransaction(entry->GetTx())) {
            ++candidate.total_recovery_exit_txs;
        }
    }
    if (has_shielded_entry) {
        candidate.selection_size = std::max(candidate.selection_size, candidate.total_policy_size);
    }

    return candidate;
}

[[nodiscard]] bool TemplatePolicyFits(uint64_t current_policy_verify_units,
                                      uint64_t current_recovery_exit_txs,
                                      uint64_t additional_policy_verify_units,
                                      uint64_t additional_recovery_exit_txs)
{
    if (additional_policy_verify_units >
        MAX_TEMPLATE_POLICY_VERIFY_UNITS - std::min(current_policy_verify_units, MAX_TEMPLATE_POLICY_VERIFY_UNITS)) {
        return false;
    }
    if (additional_recovery_exit_txs >
        MAX_TEMPLATE_RECOVERY_EXIT_TXS - std::min(current_recovery_exit_txs, MAX_TEMPLATE_RECOVERY_EXIT_TXS)) {
        return false;
    }
    return true;
}

[[nodiscard]] bool TemplatePolicyFits(uint64_t current_policy_verify_units,
                                      uint64_t current_recovery_exit_txs,
                                      const PackageSelectionCandidate& candidate)
{
    return TemplatePolicyFits(current_policy_verify_units,
                              current_recovery_exit_txs,
                              candidate.total_template_policy_verify_units,
                              candidate.total_recovery_exit_txs);
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

std::optional<int64_t> GetMaximumTime(const CBlockIndex* pindexPrev, const Consensus::Params& consensus_params)
{
    auto max_time{consensus_params.MatMulFutureBlockTimeLimit(pindexPrev->GetMedianTimePast())};
    if (!max_time.has_value()) return max_time;
    // a5 fix: keep the miner's upper bound consistent with the reconciled consensus rule -- never
    // below the BIP94 timewarp floor -- so an honest miner can always produce a valid timestamp at
    // a drift-cap activation boundary instead of self-rejecting (UpdateTime would otherwise emit a
    // min_time above the raw cap). Mirrors the gated reconciliation in ContextualCheckBlockHeader.
    int height{0};
    if (TryGetNextBlockHeight(pindexPrev->nHeight, height) &&
        consensus_params.IsMatMulTimewarpReconcileActive(height) &&
        EnforceTimewarpProtectionAtHeight(consensus_params, height)) {
        max_time = std::max<int64_t>(*max_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }
    return max_time;
}

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    const int64_t min_time{GetMinimumTime(pindexPrev, consensusParams)};
    int64_t nNewTime{std::max<int64_t>(min_time,
                                       TicksSinceEpoch<std::chrono::seconds>(NodeClock::now()))};
    const auto max_time{GetMaximumTime(pindexPrev, consensusParams)};
    if (max_time.has_value() && nNewTime > *max_time) {
        nNewTime = std::max(min_time, *max_time);
    }

    if (nOldTime < nNewTime || (max_time.has_value() && nOldTime > *max_time)) {
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
    if (args.IsArgSet("-blockmaxtemplatetxs")) {
        options.nBlockMaxTemplateTxs = static_cast<size_t>(
            std::max<int64_t>(0, args.GetIntArg("-blockmaxtemplatetxs", DEFAULT_BLOCK_MAX_TEMPLATE_TXS)));
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
    nBlockTemplatePolicyVerifyCost = 0;
    nBlockTemplateRecoveryExitTxs = 0;
    nBlockTemplatePolicySkippedTxs = 0;
    nBlockTemplatePolicyCandidateEvaluations = 0;
    nBlockShieldedAccountRegistryAppends = 0;
    m_blockShieldedPoolBalance = ShieldedPoolBalance{};
    m_pendingMempoolShieldedEgress = 0;
    m_remainingShieldedExitCapacity = 0;
    m_filterShieldedExitTxsForVelocity = false;
    m_baseShieldedAccountRegistryEntries = 0;
    m_blockShieldedNullifiers.clear();
    m_blockShieldedRecoveryExitCommitments.clear();
    m_blockShieldedSettlementAnchors.clear();
    m_blockShieldedNettingManifests.clear();
    m_templateShieldedRetirementCacheComplete.clear();
    m_templateShieldedNullifierCache.clear();
    m_templateShieldedRecoveryCommitmentCache.clear();

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
    const CAmount base_shielded_pool_balance{m_chainstate.m_chainman.GetShieldedPoolBalance()};
    if (!m_blockShieldedPoolBalance.SetBalance(base_shielded_pool_balance)) {
        LogWarning("CreateNewBlock(): invalid shielded pool balance at tip height %d\n", pindexPrev->nHeight);
        throw std::runtime_error("CreateNewBlock(): invalid shielded pool balance");
    }
    m_baseShieldedAccountRegistryEntries = m_chainstate.m_chainman.GetShieldedAccountRegistryEntryCount();
    LogDebug(BCLog::MINING, "CreateNewBlock(): building on tip height=%d hash=%s\n",
             pindexPrev->nHeight, pindexPrev->GetBlockHash().GetHex());

    // Audit P1: at legacy in-block v4 heights the solved block carries a MANDATORY
    // product-sketch payload (matrix_c_data, ~8 MiB at n=4096) that is attached
    // AFTER transaction selection but still counts toward the consensus block
    // size/weight limits (WITNESS_SCALE_FACTOR == 1, so the payload is in
    // GetBlockWeight and the serialized size). Reserve its EXACT serialized size
    // up front so the assembler cannot pack transactions that, once the payload is
    // appended, push the block over nMaxBlockSerializedSize / nMaxBlockWeight --
    // which would make the miner's OWN solved block invalid (a self-DoS / mining
    // halt under a full mempool).
    // v4.4 ENC-DR (DIGEST_RECOMPUTE, the production carriage): the sketch is NOT
    // carried in-block (the miner offloads it to the non-consensus sketch cache
    // and emits a digest-only body, see rpc/mining.cpp GenerateBlock), so there is
    // nothing to reserve. Reserve ONLY on the regtest FLAT_SKETCH_INBLOCK replay
    // path.
    if (chainparams.GetConsensus().IsMatMulV4Active(nHeight) &&
        chainparams.GetConsensus().GetMatMulProfileParams(nHeight).commitment ==
            Consensus::MatMulCommitmentScheme::FLAT_SKETCH_INBLOCK) {
        const uint64_t m{static_cast<uint64_t>(chainparams.GetConsensus().nMatMulV4Dimension) / matmul::v4::kTileB};
        const uint64_t words{2 * m * m};  // 2 uint32 words per F_q sketch element, m*m elements
        const size_t payload_bytes{GetSizeOfCompactSize(words) + static_cast<size_t>(words) * sizeof(uint32_t)};
        nBlockSize += payload_bytes;
        nBlockWeight += payload_bytes * WITNESS_SCALE_FACTOR;
    }

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
        if (IsPostSunsetShieldedExitVelocityFilterActive(chainparams.GetConsensus(), nHeight)) {
            m_remainingShieldedExitCapacity = ComputeRemainingShieldedExitCapacity(
                m_chainstate.m_chainman, chainparams.GetConsensus(), nHeight, base_shielded_pool_balance);
            if (m_options.exclude_shielded_exit_txs_for_velocity) {
                m_filterShieldedExitTxsForVelocity = true;
            } else {
                const auto pending = ComputePendingMempoolShieldedEgress(mutable_mempool);
                if (pending.has_value()) {
                    m_pendingMempoolShieldedEgress = *pending;
                    m_filterShieldedExitTxsForVelocity =
                        m_pendingMempoolShieldedEgress > m_remainingShieldedExitCapacity;
                } else {
                    m_pendingMempoolShieldedEgress = MAX_MONEY;
                    m_filterShieldedExitTxsForVelocity = true;
                    LogWarning("CreateNewBlock(): unable to compute pending mempool shielded egress; "
                               "excluding shielded exit transactions from this template\n");
                }
            }
            if (m_filterShieldedExitTxsForVelocity) {
                LogDebug(BCLog::MINING,
                         "CreateNewBlock(): excluding shielded exit transactions at height %d "
                         "(pending_egress=%s remaining_capacity=%s forced=%d)\n",
                         nHeight,
                         FormatMoney(m_pendingMempoolShieldedEgress),
                         FormatMoney(m_remainingShieldedExitCapacity),
                         m_options.exclude_shielded_exit_txs_for_velocity);
            }
        }
        // Do not run the full shielded stale-mempool scan from getblocktemplate.
        // ConnectTip removes exact nullifier/commitment conflicts for connected
        // blocks, reorg handling keeps the safety fallback, and package
        // selection below checks each candidate against current shielded state.
        // Running the full scan here lets a recovery-exit wave stall mining/RPC
        // once per block while holding the mempool lock.
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
    m_last_block_template_policy_verify_units = static_cast<int64_t>(nBlockTemplatePolicyVerifyCost);
    m_last_block_template_recovery_exit_txs = static_cast<int64_t>(nBlockTemplateRecoveryExitTxs);
    m_last_block_template_policy_skipped_txs = static_cast<int64_t>(nBlockTemplatePolicySkippedTxs);
    m_last_block_template_policy_candidate_evaluations = static_cast<int64_t>(nBlockTemplatePolicyCandidateEvaluations);
    pblocktemplate->nShieldedVerifyUnits = nBlockShieldedVerifyCost;
    pblocktemplate->nShieldedScanUnits = nBlockShieldedScanUnits;
    pblocktemplate->nShieldedTreeUpdateUnits = nBlockShieldedTreeUpdateUnits;
    pblocktemplate->nTemplatePolicyVerifyUnits = nBlockTemplatePolicyVerifyCost;
    pblocktemplate->nTemplateRecoveryExitTxs = nBlockTemplateRecoveryExitTxs;
    pblocktemplate->nTemplatePolicySkippedTxs = nBlockTemplatePolicySkippedTxs;
    pblocktemplate->nTemplatePolicyCandidateEvaluations = nBlockTemplatePolicyCandidateEvaluations;

    // Create coinbase transaction.
    if (!CoinbaseOutputScriptSatisfiesReducedDataLimits(chainparams.GetConsensus(), m_options.coinbase_output_script)) {
        throw std::runtime_error("CreateNewBlock(): coinbase output must be witness v2 P2MR (32-byte program) or OP_RETURN under reduced-data limits");
    }
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = m_options.coinbase_output_script;
    coinbaseTx.vout[0].nValue = nFees + GetBlockSubsidyForBlock(nHeight, *pblock, pindexPrev, chainparams.GetConsensus());
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
        // MatMul v4 (spec §I.3, §J#9): at and above nMatMulV4Height the
        // template carries the v4 dimension; SetDeterministicMatMulSeeds
        // below already dispatches to the v4 (unconditionally nonce/parent-
        // MTP-bound) seed derivation internally via IsMatMulV4Active.
        pblock->matmul_dim = chainparams.GetConsensus().IsMatMulV4Active(nHeight)
            ? static_cast<uint16_t>(chainparams.GetConsensus().nMatMulV4Dimension)
            : static_cast<uint16_t>(chainparams.GetConsensus().nMatMulDimension);
        if (!SetDeterministicMatMulSeeds(
                *pblock,
                chainparams.GetConsensus(),
                nHeight,
                pindexPrev->GetMedianTimePast())) {
            throw std::runtime_error("CreateNewBlock(): unable to derive deterministic MatMul seeds");
        }
        pblock->matmul_digest.SetNull();
        // v1 uses seed-derived matrices; do not store full matrices in block body.
        // Validators regenerate A and B from seed_a/seed_b on demand. v4 blocks
        // are likewise seed-derived only (spec §H.2: A/B payload forbidden).
        pblock->matrix_a_data.clear();
        pblock->matrix_b_data.clear();
        // C' / sketch payload is populated after mining solves the block (see
        // PopulateFreivaldsPayload for v3, SolveMatMul's v4 dispatch for v4).
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

    BlockValidationState state;
    if (m_options.test_block_validity) {
        LogDebug(BCLog::MINING, "CreateNewBlock(): running TestBlockValidity for height %d\n", nHeight);
        if (!TestBlockValidity(state, chainparams, m_chainstate, *pblock, pindexPrev,
                               /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false)) {
            LogWarning("CreateNewBlock(): TestBlockValidity failed at height %d: %s\n", nHeight, state.ToString());
            if (m_mempool != nullptr && nBlockTx > 0) {
                if (IsPostSunsetShieldedExitVelocityFilterActive(chainparams.GetConsensus(), nHeight) &&
                    !m_options.exclude_shielded_exit_txs_for_velocity &&
                    state.GetRejectReason() == "shielded-unshield-velocity-exceeded") {
                    LogWarning("CreateNewBlock(): retrying template with shielded exit transactions excluded "
                               "after unshield velocity cap validation failure\n");
                    Options retry_options = m_options;
                    retry_options.exclude_shielded_exit_txs_for_velocity = true;
                    auto fallback_template = BlockAssembler{m_chainstate, m_mempool, retry_options, m_node}.CreateNewBlock();
                    fallback_template->m_mempool_validation_fallback = true;
                    return fallback_template;
                }
                if (m_options.include_recovery_exit_txs && nBlockTemplateRecoveryExitTxs > 0) {
                    LogWarning("CreateNewBlock(): retrying without recovery-exit transactions after mempool-selected recovery exits failed block validation\n");
                    Options retry_options = m_options;
                    retry_options.include_recovery_exit_txs = false;
                    auto fallback_template = BlockAssembler{m_chainstate, m_mempool, retry_options, m_node}.CreateNewBlock();
                    fallback_template->m_mempool_validation_fallback = true;
                    return fallback_template;
                }
                LogWarning("CreateNewBlock(): retrying with an empty template after mempool-selected transactions failed block validation\n");
                Options retry_options = m_options;
                retry_options.use_mempool = false;
                auto fallback_template = BlockAssembler{m_chainstate, m_mempool, retry_options, m_node}.CreateNewBlock();
                fallback_template->m_mempool_validation_fallback = true;
                return fallback_template;
            }
            throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, state.ToString()));
        }
        LogDebug(BCLog::MINING, "CreateNewBlock(): TestBlockValidity passed for height %d\n", nHeight);
    } else {
        LogDebug(BCLog::MINING, "CreateNewBlock(): skipping TestBlockValidity (test_validity=false) for height %d\n",
                 nHeight);
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

bool BlockAssembler::TestTemplatePolicy(const CTransaction& tx) const
{
    const bool is_recovery_exit = IsRecoveryExitTemplateTransaction(tx);
    if (!m_options.include_recovery_exit_txs && is_recovery_exit) {
        return false;
    }
    if (m_filterShieldedExitTxsForVelocity) {
        const auto positive_shielded_egress = GetPositiveShieldedEgressValue(tx);
        if (!positive_shielded_egress.has_value() || *positive_shielded_egress > 0) {
            return false;
        }
    }
    return TemplatePolicyFits(nBlockTemplatePolicyVerifyCost,
                              nBlockTemplateRecoveryExitTxs,
                              GetTransactionTemplatePolicyVerifyUnits(tx),
                              is_recovery_exit ? 1 : 0);
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
bool BlockAssembler::TestPackageTransactions(const CTxMemPool& mempool,
                                             const CTxMemPool::setEntries& package) const
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    uint64_t nPotentialBlockSize = nBlockSize; // only used with fNeedSizeAccounting
    uint64_t nPotentialShieldedCost = nBlockShieldedVerifyCost;
    uint64_t nPotentialShieldedScanUnits = nBlockShieldedScanUnits;
    uint64_t nPotentialShieldedTreeUpdateUnits = nBlockShieldedTreeUpdateUnits;
    uint64_t nPotentialShieldedAccountRegistryAppends = nBlockShieldedAccountRegistryAppends;
    ShieldedPoolBalance nPotentialShieldedPoolBalance = m_blockShieldedPoolBalance;
    CBlockIndex* const tip = m_chainstate.m_chain.Tip();
    if (tip == nullptr) return false;
    CCoinsViewMemPool view_mempool{&m_chainstate.CoinsTip(), mempool};
    std::set<COutPoint> spent_outpoints;
    for (CTxMemPool::txiter it : inBlock) {
        for (const auto& txin : it->GetTx().vin) {
            if (!txin.prevout.IsNull()) {
                spent_outpoints.insert(txin.prevout);
            }
        }
    }
    for (CTxMemPool::txiter it : package) {
        if (it->GetTx().IsCoinBase()) {
            return false;
        }
        TxValidationState tx_state;
        if (!CheckTransaction(it->GetTx(), tx_state)) {
            return false;
        }
        if (!PassesReducedDataOutputLimits(it->GetTx(), chainparams.GetConsensus())) {
            return false;
        }
        for (const auto& txin : it->GetTx().vin) {
            if (txin.prevout.IsNull() || !spent_outpoints.insert(txin.prevout).second) {
                return false;
            }
        }
        if (it->GetTx().HasShieldedBundle() &&
            UseAccountRegistryEntryCountLimit(chainparams.GetConsensus(), nHeight) &&
            m_baseShieldedAccountRegistryEntries >
                chainparams.GetConsensus().nMaxShieldedAccountRegistryEntries) {
            return false;
        }
        if (!IsFinalTx(it->GetTx(), nHeight, m_lock_time_cutoff)) {
            return false;
        }
        const std::optional<LockPoints> lock_points{
            CalculateLockPointsAtTip(tip, view_mempool, it->GetTx())};
        if (!lock_points.has_value() ||
            !CheckSequenceLocksAtTip(tip, *lock_points)) {
            return false;
        }
        it->UpdateLockPoints(*lock_points);
        if (it->GetSpendsCoinbase()) {
            for (const CTxIn& txin : it->GetTx().vin) {
                if (mempool.exists(GenTxid::Txid(txin.prevout.hash))) continue;
                const Coin& coin{m_chainstate.CoinsTip().AccessCoin(txin.prevout)};
                if (coin.IsSpent()) return false;
                const int64_t coinbase_depth{static_cast<int64_t>(nHeight) - coin.nHeight};
                if (coin.IsCoinBase() && coinbase_depth < COINBASE_MATURITY) {
                    return false;
                }
            }
        }
        if (fNeedSizeAccounting) {
            uint64_t nTxSize = ::GetSerializeSize(TX_WITH_WITNESS(it->GetTx()));
            if (nPotentialBlockSize + nTxSize >= m_options.nBlockMaxSize) {
                return false;
            }
            nPotentialBlockSize += nTxSize;
        }
        const auto shielded_usage = GetTransactionShieldedResourceUsage(it->GetTx());
        if (it->GetTx().HasShieldedBundle()) {
            std::string pool_balance_reject;
            const auto state_value_balance =
                TryGetShieldedStateValueBalance(it->GetTx().GetShieldedBundle(), pool_balance_reject);
            if (!state_value_balance.has_value() ||
                !nPotentialShieldedPoolBalance.ApplyValueBalance(*state_value_balance)) {
                return false;
            }
        }
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
    nBlockTemplatePolicyVerifyCost += GetTransactionTemplatePolicyVerifyUnits(iter->GetTx());
    if (IsRecoveryExitTemplateTransaction(iter->GetTx())) {
        ++nBlockTemplateRecoveryExitTxs;
    }
    nBlockShieldedAccountRegistryAppends += shielded_account_registry_appends;
    if (iter->GetTx().HasShieldedBundle()) {
        std::string pool_balance_reject;
        const auto state_value_balance =
            TryGetShieldedStateValueBalance(iter->GetTx().GetShieldedBundle(), pool_balance_reject);
        Assume(state_value_balance.has_value());
        Assume(m_blockShieldedPoolBalance.ApplyValueBalance(*state_value_balance));
    }
    Assume(AddShieldedRetirementsForTemplateTx(iter->GetTx(),
                                               mempool,
                                               m_blockShieldedNullifiers,
                                               m_blockShieldedRecoveryExitCommitments,
                                               m_templateShieldedRetirementCacheComplete,
                                               m_templateShieldedNullifierCache,
                                               m_templateShieldedRecoveryCommitmentCache));
    Assume(AddCreatedShieldedRefs(iter->GetTx(),
                                  nHeight,
                                  m_blockShieldedSettlementAnchors,
                                  m_blockShieldedNettingManifests));
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
        if (m_options.nBlockMaxTemplateTxs > 0 && nBlockTx >= m_options.nBlockMaxTemplateTxs) {
            break;
        }

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

        size_t package_invalid_candidates{0};
        for (auto candidate_it = candidate_window.begin(); candidate_it != candidate_window.end();) {
            if (!TestPackageTransactions(mempool, candidate_it->entries)) {
                if (candidate_it->from_modified) {
                    mapModifiedTx.erase(candidate_it->iter);
                }
                failedTx.insert(candidate_it->iter);
                candidate_it = candidate_window.erase(candidate_it);
                ++package_invalid_candidates;
                continue;
            }
            ++candidate_it;
        }

        if (candidate_window.empty()) {
            if (package_invalid_candidates > 0) {
                if (fNeedSizeAccounting) {
                    nConsecutiveFailed += static_cast<int64_t>(package_invalid_candidates);
                    if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES &&
                        IsNearLimit(nBlockSize, m_options.nBlockMaxSize,
                                    static_cast<uint64_t>(BLOCK_FULL_ENOUGH_SIZE_DELTA))) {
                        break;
                    }
                }
                continue;
            }
            return;
        }

        const uint64_t policy_candidate_evaluations = std::count_if(
            candidate_window.begin(), candidate_window.end(), [](const PackageSelectionCandidate& candidate) {
                return candidate.total_template_policy_verify_units > 0;
            });
        nBlockTemplatePolicyCandidateEvaluations += policy_candidate_evaluations;
        if (nBlockTemplatePolicyCandidateEvaluations > MAX_TEMPLATE_POLICY_CANDIDATE_EVALUATIONS) {
            LogDebug(BCLog::MINING,
                     "CreateNewBlock(): stopping package selection after %llu candidate evaluations "
                     "(policy_verify_units=%llu/%llu recovery_exit_txs=%llu/%llu skipped=%llu)\n",
                     static_cast<unsigned long long>(nBlockTemplatePolicyCandidateEvaluations),
                     static_cast<unsigned long long>(nBlockTemplatePolicyVerifyCost),
                     static_cast<unsigned long long>(MAX_TEMPLATE_POLICY_VERIFY_UNITS),
                     static_cast<unsigned long long>(nBlockTemplateRecoveryExitTxs),
                     static_cast<unsigned long long>(MAX_TEMPLATE_RECOVERY_EXIT_TXS),
                     static_cast<unsigned long long>(nBlockTemplatePolicySkippedTxs));
            break;
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
        bool skipped_not_ready_shielded_candidate{false};
        bool skipped_unusable_candidate{false};
        bool skipped_template_policy_candidate{false};
        bool skipped_shielded_exit_velocity_candidate{false};
        for (size_t i = 0; i < candidate_window.size(); ++i) {
            const auto& candidate = candidate_window[i];
            if (candidate.total_fees < m_options.blockMinFeeRate.GetFee(candidate.total_policy_size)) {
                continue;
            }
            if (candidate.has_unusable_shielded_egress) {
                skipped_unusable_candidate = true;
                continue;
            }
            if (m_filterShieldedExitTxsForVelocity && candidate.has_positive_shielded_egress) {
                skipped_shielded_exit_velocity_candidate = true;
                continue;
            }
            if (!TestPackage(candidate.total_weight, candidate.total_sigops_cost)) {
                skipped_unusable_candidate = true;
                continue;
            }
            if (m_options.nBlockMaxTemplateTxs > 0 &&
                candidate.entries.size() > m_options.nBlockMaxTemplateTxs - nBlockTx) {
                skipped_unusable_candidate = true;
                continue;
            }
            if (!TemplatePolicyFits(nBlockTemplatePolicyVerifyCost,
                                    nBlockTemplateRecoveryExitTxs,
                                    candidate)) {
                skipped_template_policy_candidate = true;
                nBlockTemplatePolicySkippedTxs += static_cast<uint64_t>(candidate.entries.size());
                continue;
            }
            if (!m_options.include_recovery_exit_txs && candidate.total_recovery_exit_txs > 0) {
                skipped_template_policy_candidate = true;
                nBlockTemplatePolicySkippedTxs += static_cast<uint64_t>(candidate.entries.size());
                continue;
            }
            std::vector<CTxMemPool::txiter> sorted_entries;
            SortForBlock(candidate.entries, sorted_entries);
            if (!IsShieldedPackageReadyForBlock(sorted_entries,
                                                m_chainstate.m_chainman,
                                                mempool,
                                                m_blockShieldedSettlementAnchors,
                                                m_blockShieldedNettingManifests,
                                                m_blockShieldedNullifiers,
                                                m_blockShieldedRecoveryExitCommitments,
                                                m_templateShieldedRetirementCacheComplete,
                                                m_templateShieldedNullifierCache,
                                                m_templateShieldedRecoveryCommitmentCache)) {
                skipped_not_ready_shielded_candidate = true;
                continue;
            }
            if (!best_candidate_index.has_value() ||
                IsCandidateScoreBetter(candidate, candidate_window[*best_candidate_index], remaining_resources)) {
                best_candidate_index = i;
            }
        }

        if (!best_candidate_index.has_value()) {
            if (skipped_not_ready_shielded_candidate ||
                skipped_unusable_candidate ||
                skipped_template_policy_candidate ||
                skipped_shielded_exit_velocity_candidate) {
                for (const auto& candidate : candidate_window) {
                    if (candidate.from_modified) {
                        mapModifiedTx.erase(candidate.iter);
                    }
                    failedTx.insert(candidate.iter);
                }
                nConsecutiveFailed += static_cast<int64_t>(candidate_window.size());
                if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES &&
                    IsNearLimit(nBlockWeight, m_options.nBlockMaxWeight,
                                static_cast<uint64_t>(BLOCK_FULL_ENOUGH_WEIGHT_DELTA))) {
                    break;
                }
                continue;
            }
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
        if (!TestPackageTransactions(mempool, candidate.entries)) {
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
