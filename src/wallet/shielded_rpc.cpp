// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <coins.h>
#include <consensus/tx_verify.h>
#include <core_io.h>
#include <common/messages.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <hash.h>
#include <key_io.h>
#include <node/context.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <rpc/util.h>
#include <addresstype.h>
#include <script/pqm.h>
#include <univalue.h>
#include <util/moneystr.h>
#include <util/overflow.h>
#include <util/strencodings.h>
#include <validation.h>
#include <wallet/bridge_wallet.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/receive.h>
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/shielded_privacy.h>
#include <wallet/shielded_fees.h>
#include <wallet/shielded_wallet.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>
#include <shielded/smile2/params.h>
#include <shielded/v2_egress.h>
#include <shielded/v2_ingress.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <limits>
#include <set>
#include <string>
#include <tuple>
#include <vector>

namespace wallet {
namespace {

static constexpr int64_t DEFAULT_SHIELD_SWEEP_SOFT_TARGET_WEIGHT{400'000};
static constexpr size_t DEFAULT_SHIELD_SWEEP_MAX_INPUTS_PER_CHUNK{64};
static constexpr size_t MIN_SHIELD_SWEEP_MAX_INPUTS_PER_CHUNK{4};
static constexpr int MAX_SHIELD_SWEEP_REBUILD_ATTEMPTS{8};
static constexpr int MAX_SHIELDED_FEE_CONVERGENCE_ATTEMPTS{8};
static constexpr int MAX_SHIELDED_STALE_ANCHOR_REBUILD_ATTEMPTS{3};
static constexpr uint64_t DEFAULT_BRIDGE_PROVER_BLOCK_INTERVAL_MILLIS{90'000};
static constexpr uint32_t DEFAULT_V2_REBALANCE_SETTLEMENT_WINDOW{144};
static constexpr int64_t BRIDGE_FEE_HEADROOM_SCALE{1000};
static constexpr int64_t DEFAULT_BRIDGE_FEE_HEADROOM_MULTIPLIER_MILLI{2000};
static constexpr const char* TAG_REBALANCE_MANIFEST_GROSS_FLOW{"BTX_RPC_Rebalance_Manifest_Gross_Flow_V1"};
static constexpr const char* TAG_REBALANCE_MANIFEST_AUTH{"BTX_RPC_Rebalance_Manifest_Authorization_V1"};

[[nodiscard]] constexpr CAmount GetShieldingChunkSmileValueLimit()
{
    return static_cast<CAmount>(smile2::Q) - 1;
}

[[nodiscard]] CAmount RequiredMempoolFee(const CWallet& wallet, size_t relay_vsize, bool has_shielded_bundle);
[[nodiscard]] CAmount RequiredMempoolFee(const CWallet& wallet, const CTransaction& tx);

[[nodiscard]] uint256 HashBytes(Span<const unsigned char> bytes)
{
    uint256 out;
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(out.begin());
    return out;
}

[[nodiscard]] int32_t NextBridgeLeafBuildHeight(const CWallet& wallet)
{
    const auto tip_height = wallet.chain().getHeight();
    if (!tip_height.has_value() ||
        *tip_height < 0 ||
        *tip_height >= std::numeric_limits<int32_t>::max() - 1) {
        return std::numeric_limits<int32_t>::max();
    }
    return *tip_height + 1;
}

[[nodiscard]] int32_t CurrentShieldedRpcPrivacyHeight(const CWallet& wallet)
{
    const auto tip_height = wallet.chain().getHeight();
    if (!tip_height.has_value() ||
        *tip_height < 0 ||
        *tip_height >= std::numeric_limits<int32_t>::max()) {
        return std::numeric_limits<int32_t>::max();
    }
    return *tip_height;
}

[[nodiscard]] int32_t NextShieldingRpcBuildHeight(const CWallet& wallet)
{
    return NextBridgeLeafBuildHeight(wallet);
}

[[nodiscard]] bool UseCoinbaseOnlyShieldingCompatibility(const CWallet& wallet)
{
    return wallet::UseShieldedPrivacyRedesignAtHeight(NextShieldingRpcBuildHeight(wallet));
}

[[nodiscard]] CAmount CanonicalizeShieldingFee(const CWallet& wallet, CAmount fee)
{
    return shielded::RoundShieldedFeeToCanonicalBucket(
        fee,
        Params().GetConsensus(),
        NextShieldingRpcBuildHeight(wallet));
}

[[nodiscard]] bool RedactSensitiveShieldedRpcFields(const CWallet& wallet, bool include_sensitive)
{
    return wallet::RedactSensitiveShieldedRpcFieldsAtHeight(
        CurrentShieldedRpcPrivacyHeight(wallet),
        include_sensitive);
}

[[nodiscard]] bool DisableRawShieldedViewingKeySharing(const CWallet& wallet)
{
    return Params().GetConsensus().IsShieldedMatRiCTDisabled(CurrentShieldedRpcPrivacyHeight(wallet));
}

void RequireRawViewingKeySharingAllowedOrThrow(const CWallet& wallet, std::string_view rpc_name)
{
    if (!DisableRawShieldedViewingKeySharing(wallet)) {
        return;
    }

    throw JSONRPCError(
        RPC_WALLET_ERROR,
        strprintf("%s is disabled after block %d; use structured audit grants or full wallet backup instead",
                  rpc_name,
                  Params().GetConsensus().nShieldedMatRiCTDisableHeight));
}

void RequireSensitiveShieldedRpcOptInOrThrow(const CWallet& wallet,
                                             bool allow_sensitive,
                                             std::string_view rpc_name)
{
    if (!wallet::RequireSensitiveShieldedRpcOptInAtHeight(CurrentShieldedRpcPrivacyHeight(wallet)) ||
        allow_sensitive) {
        return;
    }

    throw JSONRPCError(
        RPC_INVALID_PARAMETER,
        strprintf("%s requires explicit allow_sensitive=true after block %d",
                  rpc_name,
                  Params().GetConsensus().nShieldedMatRiCTDisableHeight));
}

void PushRedactedShieldedNoteIdentity(UniValue& entry)
{
    entry.pushKV("nullifier_redacted", true);
    entry.pushKV("tree_position_redacted", true);
    entry.pushKV("commitment_redacted", true);
    entry.pushKV("block_hash_redacted", true);
}

void PushRedactedShieldedSpend(UniValue& entry)
{
    entry.pushKV("nullifier_redacted", true);
}

void PushShieldedValueBalance(UniValue& out, CAmount value_balance, bool redact_sensitive)
{
    if (redact_sensitive) {
        out.pushKV("value_balance_redacted", true);
        return;
    }
    out.pushKV("value_balance", ValueFromAmount(value_balance));
}

struct TransparentShieldingUTXO
{
    COutPoint outpoint;
    CAmount value{0};
    bool is_coinbase{false};
};

struct ShieldingPolicySnapshot
{
    int64_t max_standard_tx_weight{MAX_STANDARD_TX_WEIGHT};
    int64_t soft_target_tx_weight{DEFAULT_SHIELD_SWEEP_SOFT_TARGET_WEIGHT};
    size_t recommended_max_inputs_per_chunk{DEFAULT_SHIELD_SWEEP_MAX_INPUTS_PER_CHUNK};
    size_t applied_max_inputs_per_chunk{DEFAULT_SHIELD_SWEEP_MAX_INPUTS_PER_CHUNK};
    size_t min_inputs_per_chunk{MIN_SHIELD_SWEEP_MAX_INPUTS_PER_CHUNK};
    CAmount relay_fee_floor{0};
    CAmount mempool_fee_floor{0};
    CAmount shielded_fee_premium{MIN_SHIELDED_RELAY_FEE_PREMIUM};
    std::string selection_strategy{"largest-first"};
};

struct ShieldingChunkPreview
{
    std::vector<TransparentShieldingUTXO> selected;
    CTransactionRef tx;
    CAmount gross_amount{0};
    CAmount fee{0};
    CAmount shielded_amount{0};
    int64_t tx_weight{0};
};

struct ShieldingPlanPreview
{
    ShieldingPolicySnapshot policy;
    std::vector<ShieldingChunkPreview> chunks;
    CAmount requested_amount{0};
    CAmount spendable_amount{0};
    size_t spendable_utxos{0};
    CAmount estimated_total_fee{0};
    CAmount estimated_total_shielded{0};
};

struct BridgePsbtRelayFeeAnalysis
{
    bool available{false};
    std::string error;
    CAmount transparent_input_value{0};
    CAmount transparent_output_value{0};
    CAmount shielded_value_balance{0};
    CAmount estimated_fee{0};
    size_t estimated_vsize{0};
    int64_t estimated_sigop_cost{0};
    CFeeRate estimated_feerate{};
    CAmount relay_fee_floor{0};
    CAmount mempool_fee_floor{0};
    CAmount required_base_fee{0};
    CAmount required_shielded_fee_premium{0};
    CAmount required_total_fee{0};
    bool fee_sufficient{false};
};

struct BridgeFeeHeadroomPolicy
{
    int64_t min_multiplier_milli{DEFAULT_BRIDGE_FEE_HEADROOM_MULTIPLIER_MILLI};
    bool enforce{false};
};

struct BridgeFeeHeadroomAssessment
{
    bool available{false};
    std::string error;
    int64_t multiplier_milli{DEFAULT_BRIDGE_FEE_HEADROOM_MULTIPLIER_MILLI};
    CAmount required_fee{0};
    bool sufficient{false};
};

struct PQDescriptorIntegrityReport
{
    int total{0};
    int with_seed{0};
    int seed_capable{0};
    int seed_capable_with_seed{0};
    int public_only{0};
    int missing_local_seed{0};
};

struct WalletBridgeSigningKey
{
    shielded::BridgeKeySpec spec;
    CPQKey key;
    std::string address;
};

struct ParsedBridgeBatchEntries
{
    std::vector<shielded::BridgeBatchLeaf> leaves;
    std::vector<shielded::BridgeBatchAuthorization> authorizations;
};

struct BridgeBatchReceiptPolicy
{
    size_t min_receipts{1};
    std::vector<shielded::BridgeKeySpec> required_attestors;
    std::vector<shielded::BridgeKeySpec> revealed_attestors;
    std::vector<shielded::BridgeVerifierSetProof> attestor_proofs;
};

struct BridgeProofReceiptPolicy
{
    size_t min_receipts{1};
    std::vector<uint256> required_proof_system_ids;
    std::vector<uint256> required_verifier_key_hashes;
    std::vector<shielded::BridgeProofDescriptor> revealed_descriptors;
    std::vector<shielded::BridgeProofPolicyProof> descriptor_proofs;
};

struct BridgeHybridAnchorPolicies
{
    BridgeBatchReceiptPolicy receipt_policy;
    BridgeProofReceiptPolicy proof_receipt_policy;
};

struct BridgeBatchReceiptValidationSummary
{
    size_t distinct_attestor_count{0};
};

struct BridgeProofReceiptValidationSummary
{
    size_t distinct_receipt_count{0};
};

struct IngressSettlementWitnessSummary
{
    std::vector<shielded::BridgeBatchReceipt> receipts;
    std::vector<shielded::BridgeVerifierSetProof> signed_receipt_proofs;
    std::vector<shielded::BridgeProofReceipt> proof_receipts;
    std::vector<shielded::BridgeProofPolicyProof> proof_receipt_descriptor_proofs;
    std::optional<BridgeBatchReceiptValidationSummary> receipt_summary;
    std::optional<BridgeProofReceiptValidationSummary> proof_summary;
    std::optional<shielded::BridgeVerificationBundle> verification_bundle;
    std::optional<shielded::BridgeExternalAnchor> external_anchor;
};

[[nodiscard]] shielded::BridgeProofSystemProfile DecodeBridgeProofSystemProfileOrThrow(const UniValue& value);

[[nodiscard]] shielded::BridgeBatchCommitment BuildBridgeBatchCommitmentOrThrow(shielded::BridgeDirection direction,
                                                                                Span<const shielded::BridgeBatchLeaf> leaves,
                                                                                const shielded::BridgePlanIds& ids,
                                                                                std::optional<shielded::BridgeExternalAnchor> external_anchor);

[[nodiscard]] std::shared_ptr<CWallet> EnsureWalletForShielded(const JSONRPCRequest& request)
{
    const auto pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
    }
    if (!pwallet->m_shielded_wallet) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Shielded wallet is not initialized");
    }
    return pwallet;
}

void EnsureEncryptedShieldedWritesOrThrow(const CWallet& wallet)
{
    if (!wallet.IsCrypted()) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            "Shielded keys require an encrypted wallet; encrypt this wallet before using shielded features");
    }
}

void EnsureUnlockedShieldedSecretPersistenceOrThrow(const CWallet& wallet)
{
    EnsureEncryptedShieldedWritesOrThrow(wallet);
    if (wallet.IsLocked()) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Shielded key import requires an unlocked encrypted wallet");
    }
}

void EnsureShieldedViewingKeyWalletOrThrow(const CWallet& wallet)
{
    if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            "Shielded viewing keys require an encrypted blank wallet with private keys enabled; disable_private_keys wallets cannot persist shielded viewing keys");
    }
}

[[nodiscard]] std::optional<ShieldedAddress> ParseShieldedAddr(const std::string& addr)
{
    auto parsed = ShieldedAddress::Decode(addr);
    if (!parsed || !parsed->IsValid()) return std::nullopt;
    return parsed;
}

[[nodiscard]] std::string DescribeShieldedBundleFamily(const CShieldedBundle& bundle, bool redact_sensitive)
{
    if (redact_sensitive) {
        return bundle.HasV2Bundle() ? "shielded_v2" : "legacy_shielded";
    }
    if (const auto family = bundle.GetTransactionFamily()) {
        switch (*family) {
        case shielded::v2::TransactionFamily::V2_SEND:
            return "v2_send";
        case shielded::v2::TransactionFamily::V2_LIFECYCLE:
            return "v2_lifecycle";
        case shielded::v2::TransactionFamily::V2_INGRESS_BATCH:
            return "v2_ingress_batch";
        case shielded::v2::TransactionFamily::V2_EGRESS_BATCH:
            return "v2_egress_batch";
        case shielded::v2::TransactionFamily::V2_REBALANCE:
            return "v2_rebalance";
        case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
            return "v2_settlement_anchor";
        case shielded::v2::TransactionFamily::V2_GENERIC:
            return "shielded_v2";
        }
    }
    if (bundle.IsShieldOnly()) return "legacy_shield";
    if (bundle.IsUnshieldOnly()) return "legacy_unshield";
    if (bundle.IsFullyShielded()) return "legacy_direct";
    return "legacy_mixed";
}

void PushShieldedBundleFamily(UniValue& out, const CShieldedBundle& bundle, bool redact_sensitive)
{
    out.pushKV("family", DescribeShieldedBundleFamily(bundle, redact_sensitive));
    if (redact_sensitive) {
        out.pushKV("family_redacted", true);
    }
}

template <typename EncryptedNote>
void AppendShieldedOutputView(const std::shared_ptr<CWallet>& pwallet,
                              const uint256& commitment,
                              const EncryptedNote& encrypted_note,
                              std::vector<ShieldedTxViewOutput>& output_views)
{
    ShieldedTxViewOutput output_view;
    output_view.commitment = commitment;
    auto dec = WITH_LOCK(pwallet->m_shielded_wallet->cs_shielded, return pwallet->m_shielded_wallet->TryDecryptNote(encrypted_note));
    if (dec.has_value()) {
        output_view.amount = dec->value;
        output_view.is_ours = true;
    }
    output_views.push_back(std::move(output_view));
}

bool BuildOutputChunkViews(std::vector<ShieldedTxViewOutputChunk>& chunk_views,
                           Span<const shielded::v2::OutputChunkDescriptor> output_chunks,
                           Span<const ShieldedTxViewOutput> output_views)
{
    for (const auto& chunk : output_chunks) {
        const size_t first = chunk.first_output_index;
        const size_t count = chunk.output_count;
        if (first > output_views.size() || count > output_views.size() - first) {
            return false;
        }

        ShieldedTxViewOutputChunk chunk_view;
        chunk_view.scan_domain = shielded::v2::GetScanDomainName(chunk.scan_domain);
        chunk_view.first_output_index = chunk.first_output_index;
        chunk_view.output_count = chunk.output_count;
        chunk_view.ciphertext_bytes = chunk.ciphertext_bytes;
        chunk_view.scan_hint_commitment = chunk.scan_hint_commitment;
        chunk_view.ciphertext_commitment = chunk.ciphertext_commitment;
        for (size_t i = first; i < first + count; ++i) {
            const auto& output = output_views[i];
            if (!output.is_ours) continue;
            ++chunk_view.owned_output_count;
            const auto next_amount = CheckedAdd(chunk_view.owned_amount, output.amount);
            if (!next_amount || !MoneyRange(*next_amount)) {
                return false;
            }
            chunk_view.owned_amount = *next_amount;
        }
        chunk_views.push_back(std::move(chunk_view));
    }
    return true;
}

UniValue ShieldedTxViewOutputToJSON(const ShieldedTxViewOutput& output, bool redact_sensitive = false)
{
    UniValue out(UniValue::VOBJ);
    if (redact_sensitive) {
        out.pushKV("commitment_redacted", true);
    } else {
        out.pushKV("commitment", output.commitment.GetHex());
    }
    out.pushKV("amount", ValueFromAmount(output.amount));
    out.pushKV("is_ours", output.is_ours);
    return out;
}

UniValue ShieldedTxViewOutputChunkToJSON(const ShieldedTxViewOutputChunk& chunk, bool redact_sensitive = false)
{
    UniValue out(UniValue::VOBJ);
    if (redact_sensitive) {
        out.pushKV("chunk_metadata_redacted", true);
        out.pushKV("owned_output_count", static_cast<uint64_t>(chunk.owned_output_count));
        out.pushKV("owned_amount", ValueFromAmount(chunk.owned_amount));
        return out;
    }
    out.pushKV("scan_domain", chunk.scan_domain);
    out.pushKV("first_output_index", static_cast<uint64_t>(chunk.first_output_index));
    out.pushKV("output_count", static_cast<uint64_t>(chunk.output_count));
    out.pushKV("ciphertext_bytes", static_cast<uint64_t>(chunk.ciphertext_bytes));
    out.pushKV("scan_hint_commitment", chunk.scan_hint_commitment.GetHex());
    out.pushKV("ciphertext_commitment", chunk.ciphertext_commitment.GetHex());
    out.pushKV("owned_output_count", static_cast<uint64_t>(chunk.owned_output_count));
    out.pushKV("owned_amount", ValueFromAmount(chunk.owned_amount));
    return out;
}

[[nodiscard]] const UniValue& FindValue(const UniValue& obj, std::string_view key)
{
    return obj.find_value(std::string{key});
}

[[nodiscard]] size_t ShieldedRelayVirtualSize(const CTransaction& tx)
{
    return GetVirtualTransactionSize(GetShieldedPolicyWeight(tx), 0, 0);
}

void SetShieldedFeeEstimateMode(const CWallet& wallet,
                                CCoinControl& coin_control,
                                const UniValue& conf_target,
                                const UniValue& estimate_mode)
{
    // Shielded RPCs do not yet expose replaceability, so default to
    // conservative estimation unless the caller explicitly overrides it.
    coin_control.m_signal_bip125_rbf = false;

    if (!estimate_mode.isNull() &&
        !common::FeeModeFromString(estimate_mode.get_str(), coin_control.m_fee_mode)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, common::InvalidEstimateModeErrorMessage());
    }
    if (!conf_target.isNull()) {
        coin_control.m_confirm_target = ParseConfirmTarget(
            conf_target,
            wallet.chain().estimateMaxBlocks());
    }
}

[[nodiscard]] CAmount ComputeShieldedAutoFee(const CWallet& wallet,
                                             const CCoinControl& coin_control,
                                             const size_t relay_vsize,
                                             const bool has_shielded_bundle)
{
    if (relay_vsize == std::numeric_limits<size_t>::max()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Estimated shielded transaction size overflow");
    }

    CAmount fee = GetMinimumFeeRate(wallet, coin_control, /*feeCalc=*/nullptr).GetFee(relay_vsize);
    fee = std::max(fee, RequiredMempoolFee(wallet, relay_vsize, has_shielded_bundle));
    fee = BucketShieldedAutoFee(fee);
    if (fee <= 0 || !MoneyRange(fee)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Estimated shielded fee out of range");
    }
    return fee;
}

[[nodiscard]] std::set<int> InterpretShieldedSubtractFeeInstructions(
    const UniValue& instructions,
    const std::vector<std::string>& destinations)
{
    std::set<int> subtract_set;
    if (instructions.isNull()) return subtract_set;

    for (const auto& value : instructions.getValues()) {
        int position{-1};
        if (value.isStr()) {
            const auto it = std::find(destinations.begin(), destinations.end(), value.get_str());
            if (it == destinations.end()) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    strprintf("Invalid parameter 'subtractfeefromamount', destination %s not found in tx outputs",
                              value.get_str()));
            }
            position = it - destinations.begin();
        } else if (value.isNum()) {
            position = value.getInt<int>();
        } else {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("Invalid parameter 'subtractfeefromamount', invalid value type: %s",
                          uvTypeName(value.type())));
        }

        if (subtract_set.contains(position)) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("Invalid parameter 'subtractfeefromamount', duplicated position: %d", position));
        }
        if (position < 0) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("Invalid parameter 'subtractfeefromamount', negative position: %d", position));
        }
        if (position >= static_cast<int>(destinations.size())) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("Invalid parameter 'subtractfeefromamount', position too large: %d", position));
        }
        subtract_set.insert(position);
    }
    return subtract_set;
}

[[nodiscard]] size_t EstimateTransparentShieldingInputVirtualSize(const CWallet& wallet,
                                                                 Span<const COutPoint> utxos)
{
    size_t total_vsize{0};
    LOCK(wallet.cs_wallet);
    for (const auto& outpoint : utxos) {
        const CWalletTx* wtx = wallet.GetWalletTx(outpoint.hash);
        if (wtx == nullptr || outpoint.n >= wtx->tx->vout.size()) {
            return std::numeric_limits<size_t>::max();
        }

        int input_vsize = CalculateMaximumSignedInputSize(
            wtx->tx->vout[outpoint.n],
            &wallet,
            /*coin_control=*/nullptr);
        if (input_vsize < 0) {
            input_vsize = GetVirtualTransactionSize(GetTransactionInputWeight(CTxIn()), 0, 0);
        }
        if (input_vsize < 0 ||
            static_cast<size_t>(input_vsize) > std::numeric_limits<size_t>::max() - total_vsize) {
            return std::numeric_limits<size_t>::max();
        }
        total_vsize += static_cast<size_t>(input_vsize);
    }
    return total_vsize;
}

[[nodiscard]] CTxDestination ParseDestinationOrThrow(const UniValue& value, std::string_view field_name);

[[nodiscard]] std::shared_ptr<CWallet> EnsureWalletForBridge(const JSONRPCRequest& request)
{
    const auto pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
    }
    return pwallet;
}

[[nodiscard]] bool IsP2MROutputScript(const CScript& script_pub_key)
{
    int witness_version{-1};
    std::vector<unsigned char> witness_program;
    if (!script_pub_key.IsWitnessProgram(witness_version, witness_program)) return false;
    return witness_version == 2 && witness_program.size() == 32;
}

[[nodiscard]] std::string BridgeTemplateKindToString(shielded::BridgeTemplateKind kind)
{
    switch (kind) {
    case shielded::BridgeTemplateKind::SHIELD:
        return "shield";
    case shielded::BridgeTemplateKind::UNSHIELD:
        return "unshield";
    }
    return "unknown";
}

[[nodiscard]] std::string BridgeDirectionToString(shielded::BridgeDirection direction)
{
    switch (direction) {
    case shielded::BridgeDirection::BRIDGE_IN:
        return "bridge_in";
    case shielded::BridgeDirection::BRIDGE_OUT:
        return "bridge_out";
    }
    return "unknown";
}

[[nodiscard]] shielded::BridgeDirection ParseBridgeDirectionOrThrow(const UniValue& value, std::string_view field_name)
{
    const std::string direction = value.get_str();
    if (direction == "bridge_in") return shielded::BridgeDirection::BRIDGE_IN;
    if (direction == "bridge_out") return shielded::BridgeDirection::BRIDGE_OUT;
    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be bridge_in or bridge_out", field_name));
}

[[nodiscard]] std::string BridgeProofClaimKindToString(shielded::BridgeProofClaimKind kind)
{
    switch (kind) {
    case shielded::BridgeProofClaimKind::BATCH_TUPLE:
        return "batch_tuple_v1";
    case shielded::BridgeProofClaimKind::SETTLEMENT_METADATA:
        return "settlement_metadata_v1";
    case shielded::BridgeProofClaimKind::DATA_ROOT_TUPLE:
        return "data_root_tuple_v1";
    }
    return "unknown";
}

[[nodiscard]] shielded::BridgeProofClaimKind ParseBridgeProofClaimKindOrThrow(const UniValue& value,
                                                                              std::string_view field_name)
{
    if (!value.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a string", field_name));
    }
    const std::string kind = value.get_str();
    if (kind == "batch_tuple_v1") return shielded::BridgeProofClaimKind::BATCH_TUPLE;
    if (kind == "settlement_metadata_v1") return shielded::BridgeProofClaimKind::SETTLEMENT_METADATA;
    if (kind == "data_root_tuple_v1") return shielded::BridgeProofClaimKind::DATA_ROOT_TUPLE;
    throw JSONRPCError(RPC_INVALID_PARAMETER,
                       strprintf("%s must be batch_tuple_v1, settlement_metadata_v1, or data_root_tuple_v1",
                                 field_name));
}

[[nodiscard]] std::string BridgeDataArtifactKindToString(shielded::BridgeDataArtifactKind kind)
{
    switch (kind) {
    case shielded::BridgeDataArtifactKind::STATE_DIFF:
        return "state_diff_v1";
    case shielded::BridgeDataArtifactKind::SNAPSHOT_APPENDIX:
        return "snapshot_appendix_v1";
    case shielded::BridgeDataArtifactKind::DATA_ROOT_QUERY:
        return "data_root_query_v1";
    }
    return "unknown";
}

[[nodiscard]] shielded::BridgeDataArtifactKind ParseBridgeDataArtifactKindOrThrow(const UniValue& value,
                                                                                  std::string_view field_name)
{
    if (!value.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a string", field_name));
    }
    const std::string kind = value.get_str();
    if (kind == "state_diff_v1") return shielded::BridgeDataArtifactKind::STATE_DIFF;
    if (kind == "snapshot_appendix_v1") return shielded::BridgeDataArtifactKind::SNAPSHOT_APPENDIX;
    if (kind == "data_root_query_v1") return shielded::BridgeDataArtifactKind::DATA_ROOT_QUERY;
    throw JSONRPCError(RPC_INVALID_PARAMETER,
                       strprintf("%s must be state_diff_v1, snapshot_appendix_v1, or data_root_query_v1",
                                 field_name));
}

[[nodiscard]] std::string BridgeBatchLeafKindToString(shielded::BridgeBatchLeafKind kind)
{
    switch (kind) {
    case shielded::BridgeBatchLeafKind::SHIELD_CREDIT:
        return "shield_credit";
    case shielded::BridgeBatchLeafKind::TRANSPARENT_PAYOUT:
        return "transparent_payout";
    case shielded::BridgeBatchLeafKind::SHIELDED_PAYOUT:
        return "shielded_payout";
    }
    return "unknown";
}

[[nodiscard]] PQAlgorithm ParseBridgeAlgoOrThrow(const UniValue& value, std::string_view field_name)
{
    const std::string algo_name = value.get_str();
    if (algo_name == "ml-dsa-44") return PQAlgorithm::ML_DSA_44;
    if (algo_name == "slh-dsa-shake-128s") return PQAlgorithm::SLH_DSA_128S;
    throw JSONRPCError(RPC_INVALID_PARAMETER,
                       strprintf("%s must be ml-dsa-44 or slh-dsa-shake-128s", field_name));
}

[[nodiscard]] std::string BridgeAlgoToString(PQAlgorithm algo)
{
    switch (algo) {
    case PQAlgorithm::ML_DSA_44:
        return "ml-dsa-44";
    case PQAlgorithm::SLH_DSA_128S:
        return "slh-dsa-shake-128s";
    }
    return "unknown";
}

[[nodiscard]] UniValue BridgeKeyToUniValue(const shielded::BridgeKeySpec& key)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("algo", BridgeAlgoToString(key.algo));
    out.pushKV("pubkey", HexStr(key.pubkey));
    return out;
}

[[nodiscard]] UniValue BridgePlanIdsToUniValue(const shielded::BridgePlanIds& ids)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("bridge_id", ids.bridge_id.GetHex());
    out.pushKV("operation_id", ids.operation_id.GetHex());
    return out;
}

[[nodiscard]] UniValue BridgeExternalAnchorToUniValue(const shielded::BridgeExternalAnchor& anchor)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", anchor.version);
    out.pushKV("domain_id", anchor.domain_id.GetHex());
    out.pushKV("source_epoch", static_cast<int64_t>(anchor.source_epoch));
    if (!anchor.data_root.IsNull()) {
        out.pushKV("data_root", anchor.data_root.GetHex());
    }
    if (!anchor.verification_root.IsNull()) {
        out.pushKV("verification_root", anchor.verification_root.GetHex());
    }
    return out;
}

[[nodiscard]] UniValue BridgeVerifierSetCommitmentToUniValue(const shielded::BridgeVerifierSetCommitment& verifier_set)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", verifier_set.version);
    out.pushKV("attestor_count", static_cast<int64_t>(verifier_set.attestor_count));
    out.pushKV("required_signers", static_cast<int64_t>(verifier_set.required_signers));
    out.pushKV("attestor_root", verifier_set.attestor_root.GetHex());
    return out;
}

[[nodiscard]] UniValue BridgeVerifierSetProofToUniValue(const shielded::BridgeVerifierSetProof& proof)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", proof.version);
    out.pushKV("leaf_index", static_cast<int64_t>(proof.leaf_index));
    UniValue siblings(UniValue::VARR);
    for (const auto& sibling : proof.siblings) {
        siblings.push_back(sibling.GetHex());
    }
    out.pushKV("siblings", std::move(siblings));
    return out;
}

[[nodiscard]] UniValue BridgeProofSystemProfileToUniValue(const shielded::BridgeProofSystemProfile& profile)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", profile.version);
    out.pushKV("family_id", profile.family_id.GetHex());
    out.pushKV("proof_type_id", profile.proof_type_id.GetHex());
    out.pushKV("claim_system_id", profile.claim_system_id.GetHex());
    return out;
}

[[nodiscard]] UniValue BridgeProofClaimToUniValue(const shielded::BridgeProofClaim& claim)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", claim.version);
    out.pushKV("kind", BridgeProofClaimKindToString(claim.kind));
    out.pushKV("statement_hash", claim.statement_hash.GetHex());
    if (claim.kind == shielded::BridgeProofClaimKind::BATCH_TUPLE ||
        claim.kind == shielded::BridgeProofClaimKind::SETTLEMENT_METADATA) {
        out.pushKV("direction", BridgeDirectionToString(claim.direction));
        out.pushKV("ids", BridgePlanIdsToUniValue(claim.ids));
        out.pushKV("entry_count", static_cast<int64_t>(claim.entry_count));
        out.pushKV("total_amount", ValueFromAmount(claim.total_amount));
        out.pushKV("batch_root", claim.batch_root.GetHex());
    }
    if (claim.kind == shielded::BridgeProofClaimKind::SETTLEMENT_METADATA ||
        claim.kind == shielded::BridgeProofClaimKind::DATA_ROOT_TUPLE) {
        out.pushKV("domain_id", claim.domain_id.GetHex());
        out.pushKV("source_epoch", static_cast<int64_t>(claim.source_epoch));
        out.pushKV("data_root", claim.data_root.GetHex());
    }
    return out;
}

[[nodiscard]] UniValue BridgeProofAdapterToUniValue(const shielded::BridgeProofAdapter& adapter)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", adapter.version);
    out.pushKV("profile", BridgeProofSystemProfileToUniValue(adapter.profile));
    out.pushKV("claim_kind", BridgeProofClaimKindToString(adapter.claim_kind));
    return out;
}

[[nodiscard]] UniValue BridgeProofArtifactToUniValue(const shielded::BridgeProofArtifact& artifact)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", artifact.version);
    out.pushKV("proof_adapter", BridgeProofAdapterToUniValue(artifact.adapter));
    out.pushKV("statement_hash", artifact.statement_hash.GetHex());
    out.pushKV("verifier_key_hash", artifact.verifier_key_hash.GetHex());
    out.pushKV("public_values_hash", artifact.public_values_hash.GetHex());
    out.pushKV("proof_commitment", artifact.proof_commitment.GetHex());
    out.pushKV("artifact_commitment", artifact.artifact_commitment.GetHex());
    out.pushKV("proof_size_bytes", static_cast<int64_t>(artifact.proof_size_bytes));
    out.pushKV("public_values_size_bytes", static_cast<int64_t>(artifact.public_values_size_bytes));
    out.pushKV("auxiliary_data_size_bytes", static_cast<int64_t>(artifact.auxiliary_data_size_bytes));
    out.pushKV("storage_bytes", static_cast<int64_t>(shielded::GetBridgeProofArtifactStorageBytes(artifact)));
    return out;
}

[[nodiscard]] UniValue BridgeDataArtifactToUniValue(const shielded::BridgeDataArtifact& artifact)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", artifact.version);
    out.pushKV("kind", BridgeDataArtifactKindToString(artifact.kind));
    out.pushKV("statement_hash", artifact.statement_hash.GetHex());
    out.pushKV("data_root", artifact.data_root.GetHex());
    out.pushKV("payload_commitment", artifact.payload_commitment.GetHex());
    out.pushKV("artifact_commitment", artifact.artifact_commitment.GetHex());
    out.pushKV("payload_size_bytes", static_cast<int64_t>(artifact.payload_size_bytes));
    out.pushKV("auxiliary_data_size_bytes", static_cast<int64_t>(artifact.auxiliary_data_size_bytes));
    out.pushKV("storage_bytes", static_cast<int64_t>(shielded::GetBridgeDataArtifactStorageBytes(artifact)));
    return out;
}

[[nodiscard]] UniValue BridgeAggregateArtifactBundleToUniValue(const shielded::BridgeAggregateArtifactBundle& bundle)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", bundle.version);
    out.pushKV("statement_hash", bundle.statement_hash.GetHex());
    out.pushKV("proof_artifact_root", bundle.proof_artifact_root.GetHex());
    out.pushKV("data_artifact_root", bundle.data_artifact_root.GetHex());
    out.pushKV("proof_artifact_count", static_cast<int64_t>(bundle.proof_artifact_count));
    out.pushKV("data_artifact_count", static_cast<int64_t>(bundle.data_artifact_count));
    out.pushKV("proof_payload_bytes", static_cast<int64_t>(bundle.proof_payload_bytes));
    out.pushKV("proof_auxiliary_bytes", static_cast<int64_t>(bundle.proof_auxiliary_bytes));
    out.pushKV("data_availability_payload_bytes", static_cast<int64_t>(bundle.data_availability_payload_bytes));
    out.pushKV("data_auxiliary_bytes", static_cast<int64_t>(bundle.data_auxiliary_bytes));
    out.pushKV("storage_bytes", static_cast<int64_t>(shielded::GetBridgeAggregateArtifactBundleStorageBytes(bundle)));
    return out;
}

[[nodiscard]] std::string BridgeAggregatePayloadLocationToString(shielded::BridgeAggregatePayloadLocation location)
{
    switch (location) {
    case shielded::BridgeAggregatePayloadLocation::INLINE_NON_WITNESS:
        return "non_witness";
    case shielded::BridgeAggregatePayloadLocation::INLINE_WITNESS:
        return "witness";
    case shielded::BridgeAggregatePayloadLocation::L1_DATA_AVAILABILITY:
        return "data_availability";
    case shielded::BridgeAggregatePayloadLocation::OFFCHAIN:
        return "offchain";
    }
    return "unknown";
}

[[nodiscard]] UniValue BridgeAggregateSettlementToUniValue(const shielded::BridgeAggregateSettlement& settlement)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", settlement.version);
    out.pushKV("statement_hash", settlement.statement_hash.GetHex());
    out.pushKV("batched_user_count", static_cast<int64_t>(settlement.batched_user_count));
    out.pushKV("new_wallet_count", static_cast<int64_t>(settlement.new_wallet_count));
    out.pushKV("input_count", static_cast<int64_t>(settlement.input_count));
    out.pushKV("output_count", static_cast<int64_t>(settlement.output_count));
    out.pushKV("base_non_witness_bytes", static_cast<int64_t>(settlement.base_non_witness_bytes));
    out.pushKV("base_witness_bytes", static_cast<int64_t>(settlement.base_witness_bytes));
    out.pushKV("state_commitment_bytes", static_cast<int64_t>(settlement.state_commitment_bytes));
    out.pushKV("proof_payload_bytes", static_cast<int64_t>(settlement.proof_payload_bytes));
    out.pushKV("data_availability_payload_bytes", static_cast<int64_t>(settlement.data_availability_payload_bytes));
    out.pushKV("control_plane_bytes", static_cast<int64_t>(settlement.control_plane_bytes));
    out.pushKV("auxiliary_offchain_bytes", static_cast<int64_t>(settlement.auxiliary_offchain_bytes));
    out.pushKV("proof_payload_location", BridgeAggregatePayloadLocationToString(settlement.proof_payload_location));
    out.pushKV("data_availability_location", BridgeAggregatePayloadLocationToString(settlement.data_availability_location));
    return out;
}

[[nodiscard]] UniValue BridgeShieldedStateProfileToUniValue(const shielded::BridgeShieldedStateProfile& profile)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", profile.version);
    out.pushKV("commitment_index_key_bytes", static_cast<int64_t>(profile.commitment_index_key_bytes));
    out.pushKV("commitment_index_value_bytes", static_cast<int64_t>(profile.commitment_index_value_bytes));
    out.pushKV("snapshot_commitment_bytes", static_cast<int64_t>(profile.snapshot_commitment_bytes));
    out.pushKV("nullifier_index_key_bytes", static_cast<int64_t>(profile.nullifier_index_key_bytes));
    out.pushKV("nullifier_index_value_bytes", static_cast<int64_t>(profile.nullifier_index_value_bytes));
    out.pushKV("snapshot_nullifier_bytes", static_cast<int64_t>(profile.snapshot_nullifier_bytes));
    out.pushKV("nullifier_cache_bytes", static_cast<int64_t>(profile.nullifier_cache_bytes));
    out.pushKV("wallet_materialization_bytes", static_cast<int64_t>(profile.wallet_materialization_bytes));
    out.pushKV("bounded_anchor_history_bytes", static_cast<int64_t>(profile.bounded_anchor_history_bytes));
    return out;
}

[[nodiscard]] UniValue BridgeShieldedStateRetentionPolicyToUniValue(const shielded::BridgeShieldedStateRetentionPolicy& policy)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", policy.version);
    out.pushKV("retain_commitment_index", policy.retain_commitment_index);
    out.pushKV("retain_nullifier_index", policy.retain_nullifier_index);
    out.pushKV("snapshot_include_commitments", policy.snapshot_include_commitments);
    out.pushKV("snapshot_include_nullifiers", policy.snapshot_include_nullifiers);
    out.pushKV("wallet_l1_materialization_bps", static_cast<int64_t>(policy.wallet_l1_materialization_bps));
    out.pushKV("snapshot_target_bytes", static_cast<int64_t>(policy.snapshot_target_bytes));
    return out;
}

[[nodiscard]] UniValue BridgeProverSampleToUniValue(const shielded::BridgeProverSample& sample)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", sample.version);
    out.pushKV("statement_hash", sample.statement_hash.GetHex());
    out.pushKV("proof_artifact_id", sample.proof_artifact_id.GetHex());
    out.pushKV("proof_system_id", sample.proof_system_id.GetHex());
    out.pushKV("verifier_key_hash", sample.verifier_key_hash.GetHex());
    out.pushKV("artifact_storage_bytes", static_cast<int64_t>(sample.artifact_storage_bytes));
    out.pushKV("native_millis", static_cast<int64_t>(sample.native_millis));
    out.pushKV("cpu_millis", static_cast<int64_t>(sample.cpu_millis));
    out.pushKV("gpu_millis", static_cast<int64_t>(sample.gpu_millis));
    out.pushKV("network_millis", static_cast<int64_t>(sample.network_millis));
    out.pushKV("peak_memory_bytes", static_cast<int64_t>(sample.peak_memory_bytes));
    return out;
}

[[nodiscard]] UniValue BridgeProverProfileToUniValue(const shielded::BridgeProverProfile& profile)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", profile.version);
    out.pushKV("statement_hash", profile.statement_hash.GetHex());
    out.pushKV("sample_count", static_cast<int64_t>(profile.sample_count));
    out.pushKV("sample_root", profile.sample_root.GetHex());
    out.pushKV("total_artifact_storage_bytes", static_cast<int64_t>(profile.total_artifact_storage_bytes));
    out.pushKV("total_peak_memory_bytes", static_cast<int64_t>(profile.total_peak_memory_bytes));
    out.pushKV("max_peak_memory_bytes", static_cast<int64_t>(profile.max_peak_memory_bytes));
    out.pushKV("native_millis_per_settlement", static_cast<int64_t>(profile.native_millis_per_settlement));
    out.pushKV("cpu_millis_per_settlement", static_cast<int64_t>(profile.cpu_millis_per_settlement));
    out.pushKV("gpu_millis_per_settlement", static_cast<int64_t>(profile.gpu_millis_per_settlement));
    out.pushKV("network_millis_per_settlement", static_cast<int64_t>(profile.network_millis_per_settlement));
    return out;
}

[[nodiscard]] UniValue BridgeProverMetricSummaryToUniValue(const shielded::BridgeProverMetricSummary& summary)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("min", static_cast<int64_t>(summary.min));
    out.pushKV("p50", static_cast<int64_t>(summary.p50));
    out.pushKV("p90", static_cast<int64_t>(summary.p90));
    out.pushKV("max", static_cast<int64_t>(summary.max));
    return out;
}

[[nodiscard]] UniValue BridgeProverBenchmarkToUniValue(const shielded::BridgeProverBenchmark& benchmark)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", benchmark.version);
    out.pushKV("statement_hash", benchmark.statement_hash.GetHex());
    out.pushKV("profile_count", static_cast<int64_t>(benchmark.profile_count));
    out.pushKV("sample_count_per_profile", static_cast<int64_t>(benchmark.sample_count_per_profile));
    out.pushKV("profile_root", benchmark.profile_root.GetHex());
    out.pushKV("artifact_storage_bytes_per_profile", static_cast<int64_t>(benchmark.artifact_storage_bytes_per_profile));
    out.pushKV("total_peak_memory_bytes", BridgeProverMetricSummaryToUniValue(benchmark.total_peak_memory_bytes));
    out.pushKV("max_peak_memory_bytes", BridgeProverMetricSummaryToUniValue(benchmark.max_peak_memory_bytes));
    out.pushKV("native_millis_per_settlement", BridgeProverMetricSummaryToUniValue(benchmark.native_millis_per_settlement));
    out.pushKV("cpu_millis_per_settlement", BridgeProverMetricSummaryToUniValue(benchmark.cpu_millis_per_settlement));
    out.pushKV("gpu_millis_per_settlement", BridgeProverMetricSummaryToUniValue(benchmark.gpu_millis_per_settlement));
    out.pushKV("network_millis_per_settlement", BridgeProverMetricSummaryToUniValue(benchmark.network_millis_per_settlement));
    return out;
}

[[nodiscard]] std::string BridgeCapacityBindingToString(shielded::BridgeCapacityBinding binding)
{
    switch (binding) {
    case shielded::BridgeCapacityBinding::SERIALIZED_SIZE:
        return "serialized_size";
    case shielded::BridgeCapacityBinding::WEIGHT:
        return "weight";
    case shielded::BridgeCapacityBinding::DATA_AVAILABILITY:
        return "data_availability";
    case shielded::BridgeCapacityBinding::TIED:
        return "tied";
    }
    return "unknown";
}

[[nodiscard]] std::string BridgeProverBenchmarkStatisticToString(shielded::BridgeProverBenchmarkStatistic statistic)
{
    switch (statistic) {
    case shielded::BridgeProverBenchmarkStatistic::MIN:
        return "min";
    case shielded::BridgeProverBenchmarkStatistic::P50:
        return "p50";
    case shielded::BridgeProverBenchmarkStatistic::P90:
        return "p90";
    case shielded::BridgeProverBenchmarkStatistic::MAX:
        return "max";
    }
    return "unknown";
}

[[nodiscard]] shielded::BridgeProverBenchmarkStatistic ParseBridgeProverBenchmarkStatisticOrThrow(const UniValue& value,
                                                                                                  std::string_view field_name)
{
    const std::string name = value.get_str();
    if (name == "min") return shielded::BridgeProverBenchmarkStatistic::MIN;
    if (name == "p50") return shielded::BridgeProverBenchmarkStatistic::P50;
    if (name == "p90") return shielded::BridgeProverBenchmarkStatistic::P90;
    if (name == "max") return shielded::BridgeProverBenchmarkStatistic::MAX;
    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be one of min, p50, p90, or max", field_name));
}

[[nodiscard]] shielded::BridgeAggregatePayloadLocation ParseBridgeAggregatePayloadLocationOrThrow(const UniValue& value,
                                                                                                  std::string_view field_name)
{
    const std::string name = value.get_str();
    if (name == "non_witness") return shielded::BridgeAggregatePayloadLocation::INLINE_NON_WITNESS;
    if (name == "witness") return shielded::BridgeAggregatePayloadLocation::INLINE_WITNESS;
    if (name == "data_availability") return shielded::BridgeAggregatePayloadLocation::L1_DATA_AVAILABILITY;
    if (name == "offchain") return shielded::BridgeAggregatePayloadLocation::OFFCHAIN;
    throw JSONRPCError(RPC_INVALID_PARAMETER,
                       strprintf("%s must be one of non_witness, witness, data_availability, or offchain", field_name));
}

[[nodiscard]] std::optional<shielded::BridgeAggregateArtifactBundle> ParseBridgeAggregateArtifactBundleSelectorOrThrow(
    const UniValue& value,
    std::string_view field_name);

[[nodiscard]] std::string BridgeThroughputBindingToString(shielded::BridgeThroughputBinding binding)
{
    switch (binding) {
    case shielded::BridgeThroughputBinding::L1:
        return "l1";
    case shielded::BridgeThroughputBinding::PROVER:
        return "prover";
    case shielded::BridgeThroughputBinding::TIED:
        return "tied";
    }
    return "unknown";
}

[[nodiscard]] UniValue BridgeCapacityFootprintToUniValue(const shielded::BridgeCapacityFootprint& footprint)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("l1_serialized_bytes", static_cast<int64_t>(footprint.l1_serialized_bytes));
    out.pushKV("l1_weight", static_cast<int64_t>(footprint.l1_weight));
    out.pushKV("l1_data_availability_bytes", static_cast<int64_t>(footprint.l1_data_availability_bytes));
    out.pushKV("control_plane_bytes", static_cast<int64_t>(footprint.control_plane_bytes));
    out.pushKV("offchain_storage_bytes", static_cast<int64_t>(footprint.offchain_storage_bytes));
    out.pushKV("batched_user_count", static_cast<int64_t>(footprint.batched_user_count));
    return out;
}

[[nodiscard]] UniValue BridgeCapacityEstimateToUniValue(const shielded::BridgeCapacityEstimate& estimate)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("footprint", BridgeCapacityFootprintToUniValue(estimate.footprint));

    UniValue block_limits(UniValue::VOBJ);
    block_limits.pushKV("serialized_size", static_cast<int64_t>(estimate.block_serialized_limit));
    block_limits.pushKV("weight", static_cast<int64_t>(estimate.block_weight_limit));
    if (estimate.block_data_availability_limit.has_value()) {
        block_limits.pushKV("data_availability", static_cast<int64_t>(*estimate.block_data_availability_limit));
    }
    out.pushKV("block_limits", std::move(block_limits));

    out.pushKV("fit_by_serialized_size", static_cast<int64_t>(estimate.fit_by_serialized_size));
    out.pushKV("fit_by_weight", static_cast<int64_t>(estimate.fit_by_weight));
    if (estimate.fit_by_data_availability.has_value()) {
        out.pushKV("fit_by_data_availability", static_cast<int64_t>(*estimate.fit_by_data_availability));
    }
    out.pushKV("binding_limit", BridgeCapacityBindingToString(estimate.binding_limit));
    out.pushKV("max_settlements_per_block", static_cast<int64_t>(estimate.max_settlements_per_block));
    out.pushKV("users_per_block", static_cast<int64_t>(estimate.users_per_block));

    UniValue per_user(UniValue::VOBJ);
    per_user.pushKV("l1_serialized_bytes", static_cast<double>(estimate.footprint.l1_serialized_bytes) /
                                               static_cast<double>(estimate.footprint.batched_user_count));
    per_user.pushKV("l1_weight", static_cast<double>(estimate.footprint.l1_weight) /
                                        static_cast<double>(estimate.footprint.batched_user_count));
    per_user.pushKV("l1_data_availability_bytes", static_cast<double>(estimate.footprint.l1_data_availability_bytes) /
                                                     static_cast<double>(estimate.footprint.batched_user_count));
    per_user.pushKV("control_plane_bytes", static_cast<double>(estimate.footprint.control_plane_bytes) /
                                                   static_cast<double>(estimate.footprint.batched_user_count));
    per_user.pushKV("offchain_storage_bytes", static_cast<double>(estimate.footprint.offchain_storage_bytes) /
                                                     static_cast<double>(estimate.footprint.batched_user_count));
    out.pushKV("per_user", std::move(per_user));

    UniValue block_totals(UniValue::VOBJ);
    block_totals.pushKV("l1_serialized_bytes", static_cast<int64_t>(estimate.total_l1_serialized_bytes));
    block_totals.pushKV("l1_weight", static_cast<int64_t>(estimate.total_l1_weight));
    block_totals.pushKV("l1_data_availability_bytes", static_cast<int64_t>(estimate.total_l1_data_availability_bytes));
    block_totals.pushKV("control_plane_bytes", static_cast<int64_t>(estimate.total_control_plane_bytes));
    block_totals.pushKV("offchain_storage_bytes", static_cast<int64_t>(estimate.total_offchain_storage_bytes));
    out.pushKV("block_totals", std::move(block_totals));
    return out;
}

[[nodiscard]] UniValue BridgeProofCompressionTargetToUniValue(const shielded::BridgeProofCompressionTarget& target)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", target.version);
    out.pushKV("settlement_id", target.settlement_id.GetHex());
    out.pushKV("statement_hash", target.statement_hash.GetHex());
    out.pushKV("block_serialized_limit", static_cast<int64_t>(target.block_serialized_limit));
    out.pushKV("block_weight_limit", static_cast<int64_t>(target.block_weight_limit));
    if (target.block_data_availability_limit > 0) {
        out.pushKV("block_data_availability_limit", static_cast<int64_t>(target.block_data_availability_limit));
    }
    out.pushKV("target_users_per_block", static_cast<int64_t>(target.target_users_per_block));
    out.pushKV("target_settlements_per_block", static_cast<int64_t>(target.target_settlements_per_block));
    out.pushKV("target_represented_users_per_block",
               static_cast<int64_t>(target.target_settlements_per_block) *
                   static_cast<int64_t>(target.batched_user_count));
    out.pushKV("batched_user_count", static_cast<int64_t>(target.batched_user_count));
    out.pushKV("proof_artifact_count", static_cast<int64_t>(target.proof_artifact_count));
    out.pushKV("current_proof_payload_bytes", static_cast<int64_t>(target.current_proof_payload_bytes));
    out.pushKV("current_proof_auxiliary_bytes", static_cast<int64_t>(target.current_proof_auxiliary_bytes));
    out.pushKV("current_proof_artifact_total_bytes",
               static_cast<int64_t>(target.current_proof_payload_bytes + target.current_proof_auxiliary_bytes));
    out.pushKV("fixed_l1_serialized_bytes", static_cast<int64_t>(target.fixed_l1_serialized_bytes));
    out.pushKV("fixed_l1_weight", static_cast<int64_t>(target.fixed_l1_weight));
    out.pushKV("fixed_l1_data_availability_bytes", static_cast<int64_t>(target.fixed_l1_data_availability_bytes));
    out.pushKV("fixed_control_plane_bytes", static_cast<int64_t>(target.fixed_control_plane_bytes));
    out.pushKV("fixed_offchain_storage_bytes", static_cast<int64_t>(target.fixed_offchain_storage_bytes));
    out.pushKV("proof_payload_location", BridgeAggregatePayloadLocationToString(target.proof_payload_location));
    return out;
}

[[nodiscard]] UniValue BridgeProofCompressionEstimateToUniValue(const shielded::BridgeProofCompressionEstimate& estimate)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("target", BridgeProofCompressionTargetToUniValue(estimate.target));
    out.pushKV("current_capacity", BridgeCapacityEstimateToUniValue(estimate.current_capacity));
    out.pushKV("zero_proof_capacity", BridgeCapacityEstimateToUniValue(estimate.zero_proof_capacity));
    out.pushKV("achievable", estimate.achievable);

    if (estimate.max_proof_payload_bytes_by_serialized_size.has_value()) {
        out.pushKV("max_proof_payload_bytes_by_serialized_size",
                   static_cast<int64_t>(*estimate.max_proof_payload_bytes_by_serialized_size));
    }
    if (estimate.max_proof_payload_bytes_by_weight.has_value()) {
        out.pushKV("max_proof_payload_bytes_by_weight",
                   static_cast<int64_t>(*estimate.max_proof_payload_bytes_by_weight));
    }
    if (estimate.max_proof_payload_bytes_by_data_availability.has_value()) {
        out.pushKV("max_proof_payload_bytes_by_data_availability",
                   static_cast<int64_t>(*estimate.max_proof_payload_bytes_by_data_availability));
    }
    if (estimate.required_max_proof_payload_bytes.has_value()) {
        out.pushKV("required_max_proof_payload_bytes",
                   static_cast<int64_t>(*estimate.required_max_proof_payload_bytes));
        if (estimate.target.current_proof_payload_bytes > 0) {
            out.pushKV("required_proof_payload_remaining_ratio",
                       static_cast<double>(*estimate.required_max_proof_payload_bytes) /
                           static_cast<double>(estimate.target.current_proof_payload_bytes));
        }
        if (estimate.target.current_proof_payload_bytes + estimate.target.current_proof_auxiliary_bytes > 0) {
            out.pushKV("required_proof_payload_remaining_ratio_vs_artifact_total",
                       static_cast<double>(*estimate.required_max_proof_payload_bytes) /
                           static_cast<double>(estimate.target.current_proof_payload_bytes +
                                               estimate.target.current_proof_auxiliary_bytes));
        }
    }
    if (estimate.required_proof_payload_reduction_bytes.has_value()) {
        out.pushKV("required_proof_payload_reduction_bytes",
                   static_cast<int64_t>(*estimate.required_proof_payload_reduction_bytes));
        if (estimate.target.current_proof_payload_bytes > 0) {
            out.pushKV("required_proof_payload_reduction_ratio",
                       static_cast<double>(*estimate.required_proof_payload_reduction_bytes) /
                           static_cast<double>(estimate.target.current_proof_payload_bytes));
        }
    }
    if (estimate.modeled_target_capacity.has_value()) {
        out.pushKV("target_binding_limit", BridgeCapacityBindingToString(estimate.target_binding_limit));
        out.pushKV("modeled_target_capacity", BridgeCapacityEstimateToUniValue(*estimate.modeled_target_capacity));
    }
    return out;
}

[[nodiscard]] UniValue BridgeShieldedStateEstimateToUniValue(const shielded::BridgeShieldedStateEstimate& estimate)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("aggregate_settlement", BridgeAggregateSettlementToUniValue(estimate.settlement));
    out.pushKV("state_profile", BridgeShieldedStateProfileToUniValue(estimate.profile));
    out.pushKV("capacity_estimate", BridgeCapacityEstimateToUniValue(estimate.capacity));
    out.pushKV("block_interval_millis", static_cast<int64_t>(estimate.block_interval_millis));

    UniValue per_settlement(UniValue::VOBJ);
    per_settlement.pushKV("note_commitments", static_cast<int64_t>(estimate.note_commitments_per_settlement));
    per_settlement.pushKV("nullifiers", static_cast<int64_t>(estimate.nullifiers_per_settlement));
    per_settlement.pushKV("new_wallets", static_cast<int64_t>(estimate.new_wallets_per_settlement));
    per_settlement.pushKV("commitment_index_bytes", static_cast<int64_t>(estimate.commitment_index_bytes_per_settlement));
    per_settlement.pushKV("nullifier_index_bytes", static_cast<int64_t>(estimate.nullifier_index_bytes_per_settlement));
    per_settlement.pushKV("snapshot_appendix_bytes", static_cast<int64_t>(estimate.snapshot_appendix_bytes_per_settlement));
    per_settlement.pushKV("wallet_materialization_bytes",
                          static_cast<int64_t>(estimate.wallet_materialization_bytes_per_settlement));
    per_settlement.pushKV("persistent_state_bytes", static_cast<int64_t>(estimate.persistent_state_bytes_per_settlement));
    per_settlement.pushKV("hot_cache_bytes", static_cast<int64_t>(estimate.hot_cache_bytes_per_settlement));
    per_settlement.pushKV("bounded_state_bytes", static_cast<int64_t>(estimate.bounded_state_bytes));
    out.pushKV("per_settlement", std::move(per_settlement));

    UniValue per_block(UniValue::VOBJ);
    per_block.pushKV("note_commitments", static_cast<int64_t>(estimate.note_commitments_per_block));
    per_block.pushKV("nullifiers", static_cast<int64_t>(estimate.nullifiers_per_block));
    per_block.pushKV("new_wallets", static_cast<int64_t>(estimate.new_wallets_per_block));
    per_block.pushKV("persistent_state_bytes", static_cast<int64_t>(estimate.persistent_state_bytes_per_block));
    per_block.pushKV("snapshot_appendix_bytes", static_cast<int64_t>(estimate.snapshot_appendix_bytes_per_block));
    per_block.pushKV("hot_cache_bytes", static_cast<int64_t>(estimate.hot_cache_bytes_per_block));
    out.pushKV("per_block", std::move(per_block));

    UniValue per_hour(UniValue::VOBJ);
    per_hour.pushKV("note_commitments", static_cast<int64_t>(estimate.note_commitments_per_hour));
    per_hour.pushKV("nullifiers", static_cast<int64_t>(estimate.nullifiers_per_hour));
    per_hour.pushKV("new_wallets", static_cast<int64_t>(estimate.new_wallets_per_hour));
    per_hour.pushKV("persistent_state_bytes", static_cast<int64_t>(estimate.persistent_state_bytes_per_hour));
    per_hour.pushKV("snapshot_appendix_bytes", static_cast<int64_t>(estimate.snapshot_appendix_bytes_per_hour));
    per_hour.pushKV("hot_cache_bytes", static_cast<int64_t>(estimate.hot_cache_bytes_per_hour));
    out.pushKV("per_hour", std::move(per_hour));

    UniValue per_day(UniValue::VOBJ);
    per_day.pushKV("persistent_state_bytes", static_cast<int64_t>(estimate.persistent_state_bytes_per_day));
    per_day.pushKV("snapshot_appendix_bytes", static_cast<int64_t>(estimate.snapshot_appendix_bytes_per_day));
    per_day.pushKV("hot_cache_bytes", static_cast<int64_t>(estimate.hot_cache_bytes_per_day));
    out.pushKV("per_day", std::move(per_day));
    return out;
}

[[nodiscard]] UniValue BridgeShieldedStateRetentionEstimateToUniValue(const shielded::BridgeShieldedStateRetentionEstimate& estimate)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("snapshot_target_bytes", static_cast<int64_t>(estimate.policy.snapshot_target_bytes));

    UniValue per_settlement(UniValue::VOBJ);
    per_settlement.pushKV("materialized_wallets", static_cast<int64_t>(estimate.materialized_wallets_per_settlement));
    per_settlement.pushKV("deferred_wallets", static_cast<int64_t>(estimate.deferred_wallets_per_settlement));
    per_settlement.pushKV("retained_persistent_state_bytes",
                          static_cast<int64_t>(estimate.retained_persistent_state_bytes_per_settlement));
    per_settlement.pushKV("externalized_persistent_state_bytes",
                          static_cast<int64_t>(estimate.externalized_persistent_state_bytes_per_settlement));
    per_settlement.pushKV("deferred_wallet_materialization_bytes",
                          static_cast<int64_t>(estimate.deferred_wallet_materialization_bytes_per_settlement));
    per_settlement.pushKV("snapshot_export_bytes", static_cast<int64_t>(estimate.snapshot_export_bytes_per_settlement));
    per_settlement.pushKV("externalized_snapshot_bytes",
                          static_cast<int64_t>(estimate.externalized_snapshot_bytes_per_settlement));
    per_settlement.pushKV("runtime_hot_cache_bytes",
                          static_cast<int64_t>(estimate.runtime_hot_cache_bytes_per_settlement));
    per_settlement.pushKV("bounded_snapshot_bytes", static_cast<int64_t>(estimate.bounded_snapshot_bytes));
    out.pushKV("per_settlement", std::move(per_settlement));

    UniValue per_block(UniValue::VOBJ);
    per_block.pushKV("retained_persistent_state_bytes",
                     static_cast<int64_t>(estimate.retained_persistent_state_bytes_per_block));
    per_block.pushKV("externalized_persistent_state_bytes",
                     static_cast<int64_t>(estimate.externalized_persistent_state_bytes_per_block));
    per_block.pushKV("deferred_wallet_materialization_bytes",
                     static_cast<int64_t>(estimate.deferred_wallet_materialization_bytes_per_block));
    per_block.pushKV("snapshot_export_bytes", static_cast<int64_t>(estimate.snapshot_export_bytes_per_block));
    per_block.pushKV("externalized_snapshot_bytes",
                     static_cast<int64_t>(estimate.externalized_snapshot_bytes_per_block));
    per_block.pushKV("runtime_hot_cache_bytes",
                     static_cast<int64_t>(estimate.runtime_hot_cache_bytes_per_block));
    out.pushKV("per_block", std::move(per_block));

    UniValue per_hour(UniValue::VOBJ);
    per_hour.pushKV("retained_persistent_state_bytes",
                    static_cast<int64_t>(estimate.retained_persistent_state_bytes_per_hour));
    per_hour.pushKV("externalized_persistent_state_bytes",
                    static_cast<int64_t>(estimate.externalized_persistent_state_bytes_per_hour));
    per_hour.pushKV("deferred_wallet_materialization_bytes",
                    static_cast<int64_t>(estimate.deferred_wallet_materialization_bytes_per_hour));
    per_hour.pushKV("snapshot_export_bytes", static_cast<int64_t>(estimate.snapshot_export_bytes_per_hour));
    per_hour.pushKV("externalized_snapshot_bytes",
                    static_cast<int64_t>(estimate.externalized_snapshot_bytes_per_hour));
    per_hour.pushKV("runtime_hot_cache_bytes",
                    static_cast<int64_t>(estimate.runtime_hot_cache_bytes_per_hour));
    out.pushKV("per_hour", std::move(per_hour));

    UniValue per_day(UniValue::VOBJ);
    per_day.pushKV("retained_persistent_state_bytes",
                   static_cast<int64_t>(estimate.retained_persistent_state_bytes_per_day));
    per_day.pushKV("externalized_persistent_state_bytes",
                   static_cast<int64_t>(estimate.externalized_persistent_state_bytes_per_day));
    per_day.pushKV("deferred_wallet_materialization_bytes",
                   static_cast<int64_t>(estimate.deferred_wallet_materialization_bytes_per_day));
    per_day.pushKV("snapshot_export_bytes", static_cast<int64_t>(estimate.snapshot_export_bytes_per_day));
    per_day.pushKV("externalized_snapshot_bytes",
                   static_cast<int64_t>(estimate.externalized_snapshot_bytes_per_day));
    per_day.pushKV("runtime_hot_cache_bytes",
                   static_cast<int64_t>(estimate.runtime_hot_cache_bytes_per_day));
    out.pushKV("per_day", std::move(per_day));

    if (estimate.blocks_to_snapshot_target.has_value()) {
        UniValue snapshot_target(UniValue::VOBJ);
        snapshot_target.pushKV("blocks", static_cast<int64_t>(*estimate.blocks_to_snapshot_target));
        if (estimate.hours_to_snapshot_target.has_value()) {
            snapshot_target.pushKV("hours", static_cast<int64_t>(*estimate.hours_to_snapshot_target));
        }
        if (estimate.days_to_snapshot_target.has_value()) {
            snapshot_target.pushKV("days", static_cast<int64_t>(*estimate.days_to_snapshot_target));
        }
        if (estimate.users_to_snapshot_target.has_value()) {
            snapshot_target.pushKV("represented_users", static_cast<int64_t>(*estimate.users_to_snapshot_target));
        }
        out.pushKV("time_to_snapshot_target", std::move(snapshot_target));
    }
    return out;
}

[[nodiscard]] UniValue BridgeProverLaneToUniValue(const shielded::BridgeProverLane& lane)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("millis_per_settlement", static_cast<int64_t>(lane.millis_per_settlement));
    out.pushKV("workers", static_cast<int64_t>(lane.workers));
    out.pushKV("parallel_jobs_per_worker", static_cast<int64_t>(lane.parallel_jobs_per_worker));
    out.pushKV("hourly_cost_cents", static_cast<int64_t>(lane.hourly_cost_cents));
    out.pushKV("hourly_cost_usd", static_cast<double>(lane.hourly_cost_cents) / 100.0);
    return out;
}

[[nodiscard]] UniValue BridgeProverLaneEstimateToUniValue(const shielded::BridgeProverLaneEstimate& estimate,
                                                          const shielded::BridgeProverCapacityEstimate& prover_estimate)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("lane", BridgeProverLaneToUniValue(estimate.lane));
    out.pushKV("effective_parallel_jobs", static_cast<int64_t>(estimate.effective_parallel_jobs));
    out.pushKV("settlements_per_block_interval", static_cast<int64_t>(estimate.settlements_per_block_interval));
    out.pushKV("settlements_per_hour", static_cast<int64_t>(estimate.settlements_per_hour));
    out.pushKV("users_per_block_interval", static_cast<int64_t>(estimate.users_per_block_interval));
    out.pushKV("users_per_hour", static_cast<int64_t>(estimate.users_per_hour));
    out.pushKV("sustainable_settlements_per_block", static_cast<int64_t>(estimate.sustainable_settlements_per_block));
    out.pushKV("sustainable_settlements_per_hour", static_cast<int64_t>(estimate.sustainable_settlements_per_hour));
    out.pushKV("sustainable_users_per_block", static_cast<int64_t>(estimate.sustainable_users_per_block));
    out.pushKV("sustainable_users_per_hour", static_cast<int64_t>(estimate.sustainable_users_per_hour));
    out.pushKV("binding_limit", BridgeThroughputBindingToString(estimate.binding_limit));

    const double l1_fill_ratio = prover_estimate.l1_capacity.max_settlements_per_block == 0
        ? 0.0
        : static_cast<double>(estimate.sustainable_settlements_per_block) /
              static_cast<double>(prover_estimate.l1_capacity.max_settlements_per_block);
    out.pushKV("coverage_of_l1_capacity", l1_fill_ratio);

    out.pushKV("required_parallel_jobs_to_fill_l1_capacity",
               static_cast<int64_t>(estimate.required_parallel_jobs_to_fill_l1_capacity));
    out.pushKV("required_workers_to_fill_l1_capacity",
               static_cast<int64_t>(estimate.required_workers_to_fill_l1_capacity));
    out.pushKV("worker_gap_to_fill_l1_capacity",
               static_cast<int64_t>(estimate.worker_gap_to_fill_l1_capacity));
    out.pushKV("millis_to_fill_l1_capacity", static_cast<int64_t>(estimate.millis_to_fill_l1_capacity));

    UniValue hourly_cost(UniValue::VOBJ);
    hourly_cost.pushKV("current_cents", static_cast<int64_t>(estimate.current_hourly_cost_cents));
    hourly_cost.pushKV("current_usd", static_cast<double>(estimate.current_hourly_cost_cents) / 100.0);
    hourly_cost.pushKV("required_cents", static_cast<int64_t>(estimate.required_hourly_cost_cents));
    hourly_cost.pushKV("required_usd", static_cast<double>(estimate.required_hourly_cost_cents) / 100.0);
    out.pushKV("hourly_cost", std::move(hourly_cost));
    return out;
}

[[nodiscard]] UniValue BridgeProverCapacityEstimateToUniValue(const shielded::BridgeProverCapacityEstimate& estimate)
{
    UniValue out(UniValue::VOBJ);

    UniValue footprint(UniValue::VOBJ);
    footprint.pushKV("block_interval_millis", static_cast<int64_t>(estimate.footprint.block_interval_millis));
    if (estimate.footprint.native.has_value()) footprint.pushKV("native", BridgeProverLaneToUniValue(*estimate.footprint.native));
    if (estimate.footprint.cpu.has_value()) footprint.pushKV("cpu", BridgeProverLaneToUniValue(*estimate.footprint.cpu));
    if (estimate.footprint.gpu.has_value()) footprint.pushKV("gpu", BridgeProverLaneToUniValue(*estimate.footprint.gpu));
    if (estimate.footprint.network.has_value()) footprint.pushKV("network", BridgeProverLaneToUniValue(*estimate.footprint.network));
    out.pushKV("footprint", std::move(footprint));

    UniValue l1_limits(UniValue::VOBJ);
    l1_limits.pushKV("block_interval_millis", static_cast<int64_t>(estimate.footprint.block_interval_millis));
    l1_limits.pushKV("blocks_per_hour", 3'600'000.0 / static_cast<double>(estimate.footprint.block_interval_millis));
    l1_limits.pushKV("max_settlements_per_block", static_cast<int64_t>(estimate.l1_capacity.max_settlements_per_block));
    l1_limits.pushKV("users_per_block", static_cast<int64_t>(estimate.l1_capacity.users_per_block));
    l1_limits.pushKV("settlements_per_hour", static_cast<int64_t>(estimate.l1_settlements_per_hour_limit));
    l1_limits.pushKV("users_per_hour", static_cast<int64_t>(estimate.l1_users_per_hour_limit));
    out.pushKV("l1_limits", std::move(l1_limits));

    if (estimate.native.has_value()) out.pushKV("native", BridgeProverLaneEstimateToUniValue(*estimate.native, estimate));
    if (estimate.cpu.has_value()) out.pushKV("cpu", BridgeProverLaneEstimateToUniValue(*estimate.cpu, estimate));
    if (estimate.gpu.has_value()) out.pushKV("gpu", BridgeProverLaneEstimateToUniValue(*estimate.gpu, estimate));
    if (estimate.network.has_value()) out.pushKV("network", BridgeProverLaneEstimateToUniValue(*estimate.network, estimate));
    return out;
}

[[nodiscard]] UniValue BridgeProofDescriptorToUniValue(const shielded::BridgeProofDescriptor& descriptor)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("proof_system_id", descriptor.proof_system_id.GetHex());
    out.pushKV("verifier_key_hash", descriptor.verifier_key_hash.GetHex());
    return out;
}

[[nodiscard]] UniValue BridgeProofPolicyCommitmentToUniValue(const shielded::BridgeProofPolicyCommitment& proof_policy)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", proof_policy.version);
    out.pushKV("descriptor_count", static_cast<int64_t>(proof_policy.descriptor_count));
    out.pushKV("required_receipts", static_cast<int64_t>(proof_policy.required_receipts));
    out.pushKV("descriptor_root", proof_policy.descriptor_root.GetHex());
    return out;
}

[[nodiscard]] UniValue BridgeBatchAggregateCommitmentToUniValue(
    const shielded::BridgeBatchAggregateCommitment& commitment)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", commitment.version);
    out.pushKV("action_root", commitment.action_root.GetHex());
    out.pushKV("data_availability_root", commitment.data_availability_root.GetHex());
    if (!commitment.recovery_or_exit_root.IsNull()) {
        out.pushKV("recovery_or_exit_root", commitment.recovery_or_exit_root.GetHex());
    }
    out.pushKV("extension_flags", static_cast<int64_t>(commitment.extension_flags));
    if (!commitment.policy_commitment.IsNull()) {
        out.pushKV("policy_commitment", commitment.policy_commitment.GetHex());
    }
    return out;
}

[[nodiscard]] UniValue BridgeProofPolicyProofToUniValue(const shielded::BridgeProofPolicyProof& proof)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", proof.version);
    out.pushKV("leaf_index", static_cast<int64_t>(proof.leaf_index));
    UniValue siblings(UniValue::VARR);
    for (const auto& sibling : proof.siblings) {
        siblings.push_back(sibling.GetHex());
    }
    out.pushKV("siblings", std::move(siblings));
    return out;
}

[[nodiscard]] UniValue BridgeVerificationBundleToUniValue(const shielded::BridgeVerificationBundle& bundle)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", bundle.version);
    out.pushKV("signed_receipt_root", bundle.signed_receipt_root.GetHex());
    out.pushKV("proof_receipt_root", bundle.proof_receipt_root.GetHex());
    return out;
}

[[nodiscard]] UniValue BridgeAttestationBodyToUniValue(const shielded::BridgeAttestationMessage& message)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", message.version);
    out.pushKV("direction", BridgeDirectionToString(message.direction));
    out.pushKV("genesis_hash", message.genesis_hash.GetHex());
    out.pushKV("ctv_hash", message.ctv_hash.GetHex());
    out.pushKV("refund_lock_height", static_cast<int64_t>(message.refund_lock_height));
    out.pushKV("ids", BridgePlanIdsToUniValue(message.ids));
    if (message.version >= 2) {
        out.pushKV("batch_entry_count", static_cast<int64_t>(message.batch_entry_count));
        out.pushKV("batch_total_amount", ValueFromAmount(message.batch_total_amount));
        out.pushKV("batch_root", message.batch_root.GetHex());
    }
    if (message.version >= 3) {
        out.pushKV("external_anchor", BridgeExternalAnchorToUniValue(message.external_anchor));
    }
    return out;
}

[[nodiscard]] UniValue BridgeBatchLeafToUniValue(const shielded::BridgeBatchLeaf& leaf)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("kind", BridgeBatchLeafKindToString(leaf.kind));
    out.pushKV("wallet_id", leaf.wallet_id.GetHex());
    out.pushKV("destination_id", leaf.destination_id.GetHex());
    out.pushKV("amount", ValueFromAmount(leaf.amount));
    out.pushKV("authorization_hash", leaf.authorization_hash.GetHex());
    return out;
}

[[nodiscard]] UniValue BridgeBatchAuthorizationToUniValue(const shielded::BridgeBatchAuthorization& authorization)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", authorization.version);
    out.pushKV("direction", BridgeDirectionToString(authorization.direction));
    out.pushKV("ids", BridgePlanIdsToUniValue(authorization.ids));
    out.pushKV("kind", BridgeBatchLeafKindToString(authorization.kind));
    out.pushKV("wallet_id", authorization.wallet_id.GetHex());
    out.pushKV("destination_id", authorization.destination_id.GetHex());
    out.pushKV("amount", ValueFromAmount(authorization.amount));
    out.pushKV("authorization_nonce", authorization.authorization_nonce.GetHex());
    out.pushKV("authorizer", BridgeKeyToUniValue(authorization.authorizer));
    out.pushKV("signature", HexStr(authorization.signature));
    return out;
}

[[nodiscard]] UniValue BridgeBatchStatementToUniValue(const shielded::BridgeBatchStatement& statement)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", statement.version);
    out.pushKV("direction", BridgeDirectionToString(statement.direction));
    out.pushKV("ids", BridgePlanIdsToUniValue(statement.ids));
    out.pushKV("entry_count", static_cast<int64_t>(statement.entry_count));
    out.pushKV("total_amount", ValueFromAmount(statement.total_amount));
    out.pushKV("batch_root", statement.batch_root.GetHex());
    out.pushKV("domain_id", statement.domain_id.GetHex());
    out.pushKV("source_epoch", static_cast<int64_t>(statement.source_epoch));
    out.pushKV("data_root", statement.data_root.GetHex());
    if (statement.version >= 2 && statement.verifier_set.IsValid()) {
        out.pushKV("verifier_set", BridgeVerifierSetCommitmentToUniValue(statement.verifier_set));
    }
    if (statement.version >= 3 && statement.proof_policy.IsValid()) {
        out.pushKV("proof_policy", BridgeProofPolicyCommitmentToUniValue(statement.proof_policy));
    }
    if (statement.version >= 5 && statement.aggregate_commitment.IsValid()) {
        out.pushKV("aggregate_commitment", BridgeBatchAggregateCommitmentToUniValue(statement.aggregate_commitment));
    }
    return out;
}

[[nodiscard]] UniValue BridgeBatchReceiptToUniValue(const shielded::BridgeBatchReceipt& receipt)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", receipt.version);
    out.pushKV("statement", BridgeBatchStatementToUniValue(receipt.statement));
    out.pushKV("attestor", BridgeKeyToUniValue(receipt.attestor));
    out.pushKV("signature", HexStr(receipt.signature));
    return out;
}

[[nodiscard]] UniValue BridgeProofReceiptToUniValue(const shielded::BridgeProofReceipt& receipt)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", receipt.version);
    out.pushKV("statement_hash", receipt.statement_hash.GetHex());
    out.pushKV("proof_system_id", receipt.proof_system_id.GetHex());
    out.pushKV("verifier_key_hash", receipt.verifier_key_hash.GetHex());
    out.pushKV("public_values_hash", receipt.public_values_hash.GetHex());
    out.pushKV("proof_commitment", receipt.proof_commitment.GetHex());
    return out;
}

[[nodiscard]] UniValue BridgeBatchCommitmentToUniValue(const shielded::BridgeBatchCommitment& commitment)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", commitment.version);
    out.pushKV("direction", BridgeDirectionToString(commitment.direction));
    out.pushKV("ids", BridgePlanIdsToUniValue(commitment.ids));
    out.pushKV("entry_count", static_cast<int64_t>(commitment.entry_count));
    out.pushKV("total_amount", ValueFromAmount(commitment.total_amount));
    out.pushKV("batch_root", commitment.batch_root.GetHex());
    if (commitment.version >= 2) {
        out.pushKV("external_anchor", BridgeExternalAnchorToUniValue(commitment.external_anchor));
    }
    if (commitment.version >= 3 && commitment.aggregate_commitment.IsValid()) {
        out.pushKV("aggregate_commitment", BridgeBatchAggregateCommitmentToUniValue(commitment.aggregate_commitment));
    }
    return out;
}

[[nodiscard]] std::string BridgeViewGrantFormatToString(BridgeViewGrantFormat format)
{
    switch (format) {
    case BridgeViewGrantFormat::LEGACY_AUDIT:
        return "legacy_audit";
    case BridgeViewGrantFormat::STRUCTURED_DISCLOSURE:
        return "structured_disclosure";
    }
    return "unknown";
}

[[nodiscard]] UniValue BridgeViewGrantRequestToUniValue(const BridgeViewGrantRequest& request)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("format", BridgeViewGrantFormatToString(request.format));
    out.pushKV("recipient_pubkey", HexStr(request.recipient_pubkey));
    if (request.format == BridgeViewGrantFormat::STRUCTURED_DISCLOSURE) {
        UniValue fields(UniValue::VARR);
        for (const auto& field_name : shielded::viewgrants::GetDisclosureFieldNames(request.disclosure_flags)) {
            fields.push_back(field_name);
        }
        out.pushKV("disclosure_fields", std::move(fields));
    }
    return out;
}

[[nodiscard]] UniValue BridgeDisclosurePolicyToUniValue(const BridgeDisclosurePolicy& policy)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", policy.version);
    out.pushKV("threshold_amount", ValueFromAmount(policy.threshold_amount));
    UniValue grants(UniValue::VARR);
    for (const auto& grant : policy.required_grants) {
        grants.push_back(BridgeViewGrantRequestToUniValue(grant));
    }
    out.pushKV("required_grants", std::move(grants));
    return out;
}

[[nodiscard]] UniValue BridgeViewGrantToUniValue(const CViewGrant& grant, const BridgeViewGrantRequest* request = nullptr)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("kem_ciphertext", HexStr(grant.kem_ct));
    out.pushKV("nonce", HexStr(grant.nonce));
    out.pushKV("encrypted_data", HexStr(grant.encrypted_data));
    if (request != nullptr) {
        out.pushKV("format", BridgeViewGrantFormatToString(request->format));
        out.pushKV("recipient_pubkey", HexStr(request->recipient_pubkey));
        if (request->format == BridgeViewGrantFormat::STRUCTURED_DISCLOSURE) {
            UniValue fields(UniValue::VARR);
            for (const auto& field_name : shielded::viewgrants::GetDisclosureFieldNames(request->disclosure_flags)) {
                fields.push_back(field_name);
            }
            out.pushKV("disclosure_fields", std::move(fields));
        }
    }
    return out;
}

[[nodiscard]] UniValue BridgeScriptTreeToUniValue(const shielded::BridgeScriptTree& tree)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("kind", BridgeTemplateKindToString(tree.kind));
    out.pushKV("refund_lock_height", static_cast<int64_t>(tree.refund_lock_height));
    out.pushKV("merkle_root", tree.merkle_root.GetHex());
    out.pushKV("normal_key", BridgeKeyToUniValue(tree.normal_key));
    out.pushKV("refund_key", BridgeKeyToUniValue(tree.refund_key));
    out.pushKV("normal_leaf_hash", tree.normal_leaf_hash.GetHex());
    out.pushKV("refund_leaf_hash", tree.refund_leaf_hash.GetHex());
    out.pushKV("normal_leaf_script", HexStr(tree.normal_leaf_script));
    out.pushKV("normal_control_block", HexStr(tree.normal_control_block));
    out.pushKV("refund_leaf_script", HexStr(tree.refund_leaf_script));
    out.pushKV("refund_control_block", HexStr(tree.refund_control_block));
    return out;
}

[[nodiscard]] UniValue BridgeBundleToUniValue(const CShieldedBundle& bundle,
                                              Span<const BridgeViewGrantRequest> grant_requests = {})
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("shielded_output_count", static_cast<int64_t>(bundle.shielded_outputs.size()));
    out.pushKV("view_grant_count", static_cast<int64_t>(bundle.view_grants.size()));
    out.pushKV("value_balance", ValueFromAmount(bundle.value_balance));

    UniValue outputs(UniValue::VARR);
    for (const auto& output : bundle.shielded_outputs) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("note_commitment", output.note_commitment.GetHex());
        entry.pushKV("merkle_anchor", output.merkle_anchor.GetHex());
        outputs.push_back(std::move(entry));
    }
    out.pushKV("shielded_outputs", std::move(outputs));

    UniValue grants(UniValue::VARR);
    for (size_t i = 0; i < bundle.view_grants.size(); ++i) {
        const BridgeViewGrantRequest* request =
            i < grant_requests.size() ? &grant_requests[i] : nullptr;
        grants.push_back(BridgeViewGrantToUniValue(bundle.view_grants[i], request));
    }
    out.pushKV("view_grants", std::move(grants));
    return out;
}

[[nodiscard]] UniValue BridgeOutputsToUniValue(const std::vector<CTxOut>& outputs)
{
    UniValue out(UniValue::VARR);
    for (const auto& txout : outputs) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("amount", ValueFromAmount(txout.nValue));
        UniValue script_obj(UniValue::VOBJ);
        ScriptToUniv(txout.scriptPubKey, script_obj, /*include_hex=*/true, /*include_address=*/true);
        entry.pushKV("scriptPubKey", std::move(script_obj));
        out.push_back(std::move(entry));
    }
    return out;
}

[[nodiscard]] std::string EncodeBridgePlanHex(const BridgePlan& plan)
{
    DataStream ss{};
    ss << plan;
    return HexStr(ss.str());
}

[[nodiscard]] std::string EncodeBridgeBatchCommitmentHex(const shielded::BridgeBatchCommitment& commitment)
{
    return HexStr(shielded::SerializeBridgeBatchCommitment(commitment));
}

[[nodiscard]] std::string EncodeBridgeBatchStatementHex(const shielded::BridgeBatchStatement& statement)
{
    return HexStr(shielded::SerializeBridgeBatchStatement(statement));
}

[[nodiscard]] std::string EncodeBridgeProofSystemProfileHex(const shielded::BridgeProofSystemProfile& profile)
{
    return HexStr(shielded::SerializeBridgeProofSystemProfile(profile));
}

[[nodiscard]] std::string EncodeBridgeProofClaimHex(const shielded::BridgeProofClaim& claim)
{
    return HexStr(shielded::SerializeBridgeProofClaim(claim));
}

[[nodiscard]] std::string EncodeBridgeProofAdapterHex(const shielded::BridgeProofAdapter& adapter)
{
    return HexStr(shielded::SerializeBridgeProofAdapter(adapter));
}

[[nodiscard]] std::string EncodeBridgeProofArtifactHex(const shielded::BridgeProofArtifact& artifact)
{
    return HexStr(shielded::SerializeBridgeProofArtifact(artifact));
}

[[nodiscard]] std::string EncodeBridgeDataArtifactHex(const shielded::BridgeDataArtifact& artifact)
{
    return HexStr(shielded::SerializeBridgeDataArtifact(artifact));
}

[[nodiscard]] std::string EncodeBridgeAggregateArtifactBundleHex(const shielded::BridgeAggregateArtifactBundle& bundle)
{
    return HexStr(shielded::SerializeBridgeAggregateArtifactBundle(bundle));
}

[[nodiscard]] std::string EncodeBridgeAggregateSettlementHex(const shielded::BridgeAggregateSettlement& settlement)
{
    return HexStr(shielded::SerializeBridgeAggregateSettlement(settlement));
}

[[nodiscard]] std::string EncodeBridgeProofCompressionTargetHex(const shielded::BridgeProofCompressionTarget& target)
{
    return HexStr(shielded::SerializeBridgeProofCompressionTarget(target));
}

[[nodiscard]] std::string EncodeBridgeShieldedStateProfileHex(const shielded::BridgeShieldedStateProfile& profile)
{
    return HexStr(shielded::SerializeBridgeShieldedStateProfile(profile));
}

[[nodiscard]] std::string EncodeBridgeShieldedStateRetentionPolicyHex(const shielded::BridgeShieldedStateRetentionPolicy& policy)
{
    return HexStr(shielded::SerializeBridgeShieldedStateRetentionPolicy(policy));
}

[[nodiscard]] std::string EncodeBridgeProverSampleHex(const shielded::BridgeProverSample& sample)
{
    return HexStr(shielded::SerializeBridgeProverSample(sample));
}

[[nodiscard]] std::string EncodeBridgeProverProfileHex(const shielded::BridgeProverProfile& profile)
{
    return HexStr(shielded::SerializeBridgeProverProfile(profile));
}

[[nodiscard]] std::string EncodeBridgeProverBenchmarkHex(const shielded::BridgeProverBenchmark& benchmark)
{
    return HexStr(shielded::SerializeBridgeProverBenchmark(benchmark));
}

[[nodiscard]] std::string EncodeBridgeVerifierSetProofHex(const shielded::BridgeVerifierSetProof& proof)
{
    return HexStr(shielded::SerializeBridgeVerifierSetProof(proof));
}

[[nodiscard]] std::string EncodeBridgeProofPolicyProofHex(const shielded::BridgeProofPolicyProof& proof)
{
    return HexStr(shielded::SerializeBridgeProofPolicyProof(proof));
}

[[nodiscard]] std::string EncodeBridgeBatchReceiptHex(const shielded::BridgeBatchReceipt& receipt)
{
    return HexStr(shielded::SerializeBridgeBatchReceipt(receipt));
}

[[nodiscard]] std::string EncodeBridgeProofReceiptHex(const shielded::BridgeProofReceipt& receipt)
{
    return HexStr(shielded::SerializeBridgeProofReceipt(receipt));
}

[[nodiscard]] std::string EncodeBridgeBatchAuthorizationHex(const shielded::BridgeBatchAuthorization& authorization)
{
    return HexStr(shielded::SerializeBridgeBatchAuthorization(authorization));
}

[[nodiscard]] shielded::BridgeBatchStatement DecodeBridgeBatchStatementOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "statement_hex");
    const auto statement = shielded::DeserializeBridgeBatchStatement(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!statement.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "statement_hex is not a valid bridge batch statement");
    }
    return *statement;
}

[[nodiscard]] shielded::BridgeProofSystemProfile DecodeBridgeProofSystemProfileOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "proof_profile_hex");
    const auto profile = shielded::DeserializeBridgeProofSystemProfile(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!profile.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "proof_profile_hex is not a valid bridge proof profile");
    }
    return *profile;
}

[[nodiscard]] shielded::BridgeAggregateSettlement DecodeBridgeAggregateSettlementOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "aggregate_settlement_hex");
    const auto settlement = shielded::DeserializeBridgeAggregateSettlement(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!settlement.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "aggregate_settlement_hex is not a valid bridge aggregate settlement");
    }
    return *settlement;
}

[[nodiscard]] shielded::BridgeProofCompressionTarget DecodeBridgeProofCompressionTargetOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "proof_compression_target_hex");
    const auto target = shielded::DeserializeBridgeProofCompressionTarget(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!target.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "proof_compression_target_hex is not a valid bridge proof compression target");
    }
    return *target;
}

[[nodiscard]] shielded::BridgeShieldedStateProfile DecodeBridgeShieldedStateProfileOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "state_profile_hex");
    const auto profile = shielded::DeserializeBridgeShieldedStateProfile(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!profile.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "state_profile_hex is not a valid bridge shielded state profile");
    }
    return *profile;
}

[[nodiscard]] shielded::BridgeShieldedStateRetentionPolicy DecodeBridgeShieldedStateRetentionPolicyOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "retention_policy_hex");
    const auto policy = shielded::DeserializeBridgeShieldedStateRetentionPolicy(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!policy.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "retention_policy_hex is not a valid bridge shielded state retention policy");
    }
    return *policy;
}

[[nodiscard]] shielded::BridgeProofClaim DecodeBridgeProofClaimOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "claim_hex");
    const auto claim = shielded::DeserializeBridgeProofClaim(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!claim.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "claim_hex is not a valid bridge proof claim");
    }
    return *claim;
}

[[nodiscard]] shielded::BridgeProofAdapter DecodeBridgeProofAdapterOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "proof_adapter_hex");
    const auto adapter = shielded::DeserializeBridgeProofAdapter(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!adapter.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "proof_adapter_hex is not a valid bridge proof adapter");
    }
    return *adapter;
}

[[nodiscard]] shielded::BridgeProofArtifact DecodeBridgeProofArtifactOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "proof_artifact_hex");
    const auto artifact = shielded::DeserializeBridgeProofArtifact(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!artifact.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "proof_artifact_hex is not a valid bridge proof artifact");
    }
    return *artifact;
}

[[nodiscard]] shielded::BridgeDataArtifact DecodeBridgeDataArtifactOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "data_artifact_hex");
    const auto artifact = shielded::DeserializeBridgeDataArtifact(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!artifact.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "data_artifact_hex is not a valid bridge data artifact");
    }
    return *artifact;
}

[[nodiscard]] shielded::BridgeAggregateArtifactBundle DecodeBridgeAggregateArtifactBundleOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "artifact_bundle_hex");
    const auto bundle = shielded::DeserializeBridgeAggregateArtifactBundle(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!bundle.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "artifact_bundle_hex is not a valid bridge aggregate artifact bundle");
    }
    return *bundle;
}

[[nodiscard]] shielded::BridgeProverSample DecodeBridgeProverSampleOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "prover_sample_hex");
    const auto sample = shielded::DeserializeBridgeProverSample(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!sample.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "prover_sample_hex is not a valid bridge prover sample");
    }
    return *sample;
}

[[nodiscard]] shielded::BridgeProverProfile DecodeBridgeProverProfileOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "prover_profile_hex");
    const auto profile = shielded::DeserializeBridgeProverProfile(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!profile.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "prover_profile_hex is not a valid bridge prover profile");
    }
    return *profile;
}

[[nodiscard]] shielded::BridgeProverBenchmark DecodeBridgeProverBenchmarkOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "prover_benchmark_hex");
    const auto benchmark = shielded::DeserializeBridgeProverBenchmark(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!benchmark.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "prover_benchmark_hex is not a valid bridge prover benchmark");
    }
    return *benchmark;
}

[[nodiscard]] shielded::BridgeBatchReceipt DecodeBridgeBatchReceiptOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "receipt_hex");
    const auto receipt = shielded::DeserializeBridgeBatchReceipt(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!receipt.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "receipt_hex is not a valid bridge batch receipt");
    }
    return *receipt;
}

[[nodiscard]] shielded::BridgeProofReceipt DecodeBridgeProofReceiptOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "proof_receipt_hex");
    const auto receipt = shielded::DeserializeBridgeProofReceipt(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!receipt.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "proof_receipt_hex is not a valid bridge proof receipt");
    }
    return *receipt;
}

[[nodiscard]] shielded::BridgeVerifierSetProof DecodeBridgeVerifierSetProofOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "proof_hex");
    const auto proof = shielded::DeserializeBridgeVerifierSetProof(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!proof.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "proof_hex is not a valid bridge verifier-set proof");
    }
    return *proof;
}

[[nodiscard]] shielded::BridgeProofPolicyProof DecodeBridgeProofPolicyProofOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "proof_hex");
    const auto proof = shielded::DeserializeBridgeProofPolicyProof(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!proof.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "proof_hex is not a valid bridge proof-policy proof");
    }
    return *proof;
}

[[nodiscard]] shielded::BridgeBatchAuthorization DecodeBridgeBatchAuthorizationOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "authorization_hex");
    const auto authorization = shielded::DeserializeBridgeBatchAuthorization(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!authorization.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "authorization_hex is not a valid bridge batch authorization");
    }
    return *authorization;
}

[[nodiscard]] shielded::BridgeBatchCommitment DecodeBridgeBatchCommitmentOrThrow(const UniValue& value)
{
    const auto bytes = ParseHexV(value, "batch_commitment_hex");
    const auto commitment = shielded::DeserializeBridgeBatchCommitment(Span<const uint8_t>{bytes.data(), bytes.size()});
    if (!commitment.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "batch_commitment_hex is not a valid bridge batch commitment");
    }
    return *commitment;
}

[[nodiscard]] BridgePlan DecodeBridgePlanOrThrow(const UniValue& value)
{
    const std::string plan_hex = value.get_str();
    if (!IsHex(plan_hex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "plan_hex must be hex");
    }

    const auto plan_bytes = ParseHex(plan_hex);
    DataStream ss{Span<const uint8_t>{plan_bytes.data(), plan_bytes.size()}};
    BridgePlan plan;
    try {
        ss >> plan;
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Failed to decode plan_hex: %s", e.what()));
    }
    if (!ss.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "plan_hex has trailing bytes");
    }
    if (!plan.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "plan_hex decoded to an invalid bridge plan");
    }
    return plan;
}

[[nodiscard]] std::string EncodePSBTBase64(const PartiallySignedTransaction& psbt)
{
    DataStream ss{};
    ss << psbt;
    return EncodeBase64(ss.str());
}

[[nodiscard]] UniValue BridgePsbtMetadataToUniValue(const PartiallySignedTransaction& psbt)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("psbt", EncodePSBTBase64(psbt));
    out.pushKV("txid", psbt.tx->GetHash().GetHex());
    out.pushKV("locktime", static_cast<int64_t>(psbt.tx->nLockTime));

    if (psbt.inputs.empty()) return out;

    const auto& input = psbt.inputs[0];
    out.pushKV("p2mr_merkle_root", input.m_p2mr_merkle_root.GetHex());
    out.pushKV("p2mr_leaf_script", HexStr(input.m_p2mr_leaf_script));
    out.pushKV("p2mr_leaf_version", static_cast<int64_t>(input.m_p2mr_leaf_version));
    out.pushKV("p2mr_control_block", HexStr(input.m_p2mr_control_block));
    if (!input.m_p2mr_leaf_script.empty()) {
        out.pushKV("p2mr_leaf_hash", ComputeP2MRLeafHash(P2MR_LEAF_VERSION, input.m_p2mr_leaf_script).GetHex());
    }

    UniValue csfs_messages(UniValue::VARR);
    for (const auto& [leaf_pubkey, msg] : input.m_p2mr_csfs_msgs) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("leaf_hash", leaf_pubkey.first.GetHex());
        entry.pushKV("pubkey", HexStr(leaf_pubkey.second));
        entry.pushKV("message", HexStr(msg));
        csfs_messages.push_back(std::move(entry));
    }
    out.pushKV("p2mr_csfs_messages", std::move(csfs_messages));

    UniValue csfs_sigs(UniValue::VARR);
    for (const auto& [leaf_pubkey, sig] : input.m_p2mr_csfs_sigs) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("leaf_hash", leaf_pubkey.first.GetHex());
        entry.pushKV("pubkey", HexStr(leaf_pubkey.second));
        entry.pushKV("signature", HexStr(sig));
        csfs_sigs.push_back(std::move(entry));
    }
    out.pushKV("p2mr_csfs_signatures", std::move(csfs_sigs));

    UniValue pq_sigs(UniValue::VARR);
    for (const auto& [leaf_pubkey, sig] : input.m_p2mr_pq_sigs) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("leaf_hash", leaf_pubkey.first.GetHex());
        entry.pushKV("pubkey", HexStr(leaf_pubkey.second));
        entry.pushKV("signature", HexStr(sig));
        pq_sigs.push_back(std::move(entry));
    }
    out.pushKV("p2mr_partial_signatures", std::move(pq_sigs));

    return out;
}

[[nodiscard]] CTransactionRef FinalizeBridgePsbtWithWalletOrThrow(const std::shared_ptr<CWallet>& pwallet,
                                                                  PartiallySignedTransaction psbt,
                                                                  const std::string& context)
{
    EnsureWalletIsUnlocked(*pwallet);

    bool complete{false};
    const auto update_err{pwallet->FillPSBT(psbt,
                                            complete,
                                            SIGHASH_DEFAULT,
                                            /*sign=*/false,
                                            /*bip32derivs=*/true)};
    if (update_err) {
        throw JSONRPCPSBTError(*update_err);
    }

    const auto sign_err{pwallet->FillPSBT(psbt,
                                          complete,
                                          SIGHASH_DEFAULT,
                                          /*sign=*/true,
                                          /*bip32derivs=*/false)};
    if (sign_err) {
        throw JSONRPCPSBTError(*sign_err);
    }

    if (!complete) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to sign %s with wallet keys", context));
    }

    CMutableTransaction mtx;
    if (!FinalizeAndExtractPSBT(psbt, mtx)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Failed to finalize %s", context));
    }

    return MakeTransactionRef(std::move(mtx));
}

[[nodiscard]] UniValue BridgeSubmittedResultToUniValue(const CTransactionRef& tx,
                                                       const BridgePlan& plan,
                                                       const std::string& selected_path)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("txid", tx->GetHash().GetHex());
    out.pushKV("locktime", static_cast<int64_t>(tx->nLockTime));
    out.pushKV("selected_path", selected_path);
    out.pushKV("bridge_root", plan.script_tree.merkle_root.GetHex());
    out.pushKV("ctv_hash", plan.ctv_hash.GetHex());
    return out;
}

[[nodiscard]] UniValue BridgePlanToUniValue(const BridgePlan& plan,
                                            Span<const BridgeViewGrantRequest> grant_requests = {},
                                            const BridgeDisclosurePolicy* disclosure_policy = nullptr)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("version", plan.version);
    out.pushKV("kind", BridgeTemplateKindToString(plan.kind));
    out.pushKV("plan_hex", EncodeBridgePlanHex(plan));
    out.pushKV("bridge_address", EncodeDestination(WitnessV2P2MR(plan.script_tree.merkle_root)));
    out.pushKV("bridge_root", plan.script_tree.merkle_root.GetHex());
    out.pushKV("ctv_hash", plan.ctv_hash.GetHex());
    out.pushKV("refund_lock_height", static_cast<int64_t>(plan.refund_lock_height));
    out.pushKV("ids", BridgePlanIdsToUniValue(plan.ids));
    out.pushKV("script_tree", BridgeScriptTreeToUniValue(plan.script_tree));

    if (plan.kind == shielded::BridgeTemplateKind::SHIELD) {
        out.pushKV("bundle", BridgeBundleToUniValue(plan.shielded_bundle, grant_requests));
        if (!grant_requests.empty()) {
            UniValue grants(UniValue::VARR);
            for (const auto& grant : grant_requests) {
                grants.push_back(BridgeViewGrantRequestToUniValue(grant));
            }
            out.pushKV("operator_view_grants", std::move(grants));
        }
        if (disclosure_policy != nullptr) {
            out.pushKV("disclosure_policy", BridgeDisclosurePolicyToUniValue(*disclosure_policy));
        }
    } else {
        out.pushKV("outputs", BridgeOutputsToUniValue(plan.transparent_outputs));
        const auto attestation_bytes = shielded::SerializeBridgeAttestationMessage(plan.attestation);
        UniValue attestation(UniValue::VOBJ);
        attestation.pushKV("message", BridgeAttestationBodyToUniValue(plan.attestation));
        attestation.pushKV("bytes", HexStr(attestation_bytes));
        attestation.pushKV("hash", shielded::ComputeBridgeAttestationHash(plan.attestation).GetHex());
        out.pushKV("attestation", std::move(attestation));
    }
    return out;
}

[[nodiscard]] shielded::BridgeKeySpec ParseBridgeKeySpec(const UniValue& value, std::string_view field_name)
{
    std::optional<PQAlgorithm> algo;
    std::vector<unsigned char> pubkey;
    if (value.isObject()) {
        const UniValue& algo_value = FindValue(value, "algo");
        if (!algo_value.isNull()) {
            algo = ParseBridgeAlgoOrThrow(algo_value, strprintf("%s.algo", field_name));
        }
        const UniValue& pubkey_value = FindValue(value, "pubkey");
        if (pubkey_value.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.pubkey is required", field_name));
        }
        pubkey = ParseHexV(pubkey_value, strprintf("%s.pubkey", field_name));
    } else {
        pubkey = ParseHexV(value, field_name);
    }

    if (!algo.has_value()) {
        if (pubkey.size() == MLDSA44_PUBKEY_SIZE) {
            algo = PQAlgorithm::ML_DSA_44;
        } else if (pubkey.size() == SLHDSA128S_PUBKEY_SIZE) {
            algo = PQAlgorithm::SLH_DSA_128S;
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s has an unsupported pubkey length", field_name));
        }
    }

    shielded::BridgeKeySpec key{*algo, std::move(pubkey)};
    if (!key.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not valid PQ bridge key material", field_name));
    }
    return key;
}

[[nodiscard]] WalletBridgeSigningKey GetWalletBridgeSigningKeyOrThrow(const std::shared_ptr<CWallet>& pwallet,
                                                                      const std::string& address,
                                                                      PQAlgorithm algo)
{
    const CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid BTX address");
    }

    LOCK(pwallet->cs_wallet);

    if (!(pwallet->IsMine(dest) & ISMINE_SPENDABLE)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "authorizer_address is not a spendable wallet address");
    }

    const CScript script_pub_key = GetScriptForDestination(dest);
    if (!IsP2MROutputScript(script_pub_key)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "authorizer_address must be a P2MR destination");
    }

    EnsureWalletIsUnlocked(*pwallet);

    std::set<ScriptPubKeyMan*> spk_mans = pwallet->GetScriptPubKeyMans(script_pub_key);
    if (spk_mans.empty()) {
        spk_mans = pwallet->GetAllScriptPubKeyMans();
    }

    for (ScriptPubKeyMan* spk_man : spk_mans) {
        auto* desc_spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
        if (desc_spk_man == nullptr) continue;

        std::unique_ptr<FlatSigningProvider> provider = desc_spk_man->GetSigningProvider(script_pub_key, /*include_private=*/true);
        if (!provider) continue;

        for (const auto& [pubkey, pq_key] : provider->pq_keys) {
            if (!pq_key.IsValid() || pq_key.GetAlgorithm() != algo) continue;
            return WalletBridgeSigningKey{{algo, pubkey}, pq_key, EncodeDestination(dest)};
        }
    }

    throw JSONRPCError(RPC_WALLET_ERROR, "No matching PQ signing key found for authorizer_address and algorithm");
}

[[nodiscard]] shielded::BridgePlanIds ParseBridgePlanIdsOrThrow(const UniValue& options)
{
    const UniValue& bridge_id_value = FindValue(options, "bridge_id");
    const UniValue& operation_id_value = FindValue(options, "operation_id");
    if (bridge_id_value.isNull() || operation_id_value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "bridge_id and operation_id are required");
    }
    shielded::BridgePlanIds ids;
    ids.bridge_id = ParseHashV(bridge_id_value, "bridge_id");
    ids.operation_id = ParseHashV(operation_id_value, "operation_id");
    if (!ids.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "bridge_id and operation_id must be non-zero hashes");
    }
    return ids;
}

[[nodiscard]] std::optional<shielded::BridgeExternalAnchor> ParseBridgeExternalAnchorOrThrow(const UniValue& options)
{
    const UniValue& value = FindValue(options, "external_anchor");
    if (value.isNull()) return std::nullopt;
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "external_anchor must be an object");
    }

    shielded::BridgeExternalAnchor anchor;
    anchor.domain_id = ParseHashV(FindValue(value, "domain_id"), "external_anchor.domain_id");

    const UniValue& source_epoch_value = FindValue(value, "source_epoch");
    if (source_epoch_value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "external_anchor.source_epoch is required");
    }
    const int64_t source_epoch = source_epoch_value.getInt<int64_t>();
    if (source_epoch <= 0 || source_epoch > std::numeric_limits<uint32_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "external_anchor.source_epoch must be a positive integer");
    }
    anchor.source_epoch = static_cast<uint32_t>(source_epoch);

    const UniValue& data_root_value = FindValue(value, "data_root");
    if (!data_root_value.isNull()) {
        anchor.data_root = ParseHashV(data_root_value, "external_anchor.data_root");
    }

    const UniValue& verification_root_value = FindValue(value, "verification_root");
    if (!verification_root_value.isNull()) {
        anchor.verification_root = ParseHashV(verification_root_value, "external_anchor.verification_root");
    }

    if (!anchor.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "external_anchor must include domain_id, source_epoch, and at least one of data_root or verification_root");
    }
    return anchor;
}

[[nodiscard]] shielded::BridgeVerifierSetCommitment ParseBridgeVerifierSetCommitmentOrThrow(const UniValue& value,
                                                                                            std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    shielded::BridgeVerifierSetCommitment verifier_set;
    const UniValue& version_value = FindValue(value, "version");
    if (!version_value.isNull()) {
        const int64_t version = version_value.getInt<int64_t>();
        if (version != 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.version must be 1", field_name));
        }
        verifier_set.version = static_cast<uint8_t>(version);
    }

    const UniValue& attestor_count_value = FindValue(value, "attestor_count");
    if (attestor_count_value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.attestor_count is required", field_name));
    }
    const int64_t attestor_count = attestor_count_value.getInt<int64_t>();
    if (attestor_count <= 0 || attestor_count > std::numeric_limits<uint32_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.attestor_count must be a positive integer", field_name));
    }
    verifier_set.attestor_count = static_cast<uint32_t>(attestor_count);

    const UniValue& required_signers_value = FindValue(value, "required_signers");
    if (required_signers_value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.required_signers is required", field_name));
    }
    const int64_t required_signers = required_signers_value.getInt<int64_t>();
    if (required_signers <= 0 || required_signers > std::numeric_limits<uint32_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.required_signers must be a positive integer", field_name));
    }
    verifier_set.required_signers = static_cast<uint32_t>(required_signers);
    verifier_set.attestor_root = ParseHashV(FindValue(value, "attestor_root"), strprintf("%s.attestor_root", field_name));

    if (!verifier_set.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must include a non-zero attestor_root and a valid required_signers/attestor_count pair",
                                     field_name));
    }
    return verifier_set;
}

[[nodiscard]] bool IsValidBridgeProofProfileLabel(std::string_view label)
{
    if (label.empty()) return false;
    return std::all_of(label.begin(), label.end(), [](char ch) {
        return (ch >= 'a' && ch <= 'z') ||
               (ch >= 'A' && ch <= 'Z') ||
               (ch >= '0' && ch <= '9') ||
               ch == '-' || ch == '_' || ch == '.' || ch == '/';
    });
}

[[nodiscard]] std::string NormalizeBridgeProofProfileLabelOrThrow(std::string_view field_name, const UniValue& value)
{
    if (!value.isStr()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a string", field_name));
    }
    const std::string normalized = ToLower(value.get_str());
    if (!IsValidBridgeProofProfileLabel(normalized)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must be a non-empty ASCII label using only [a-z0-9._/-]", field_name));
    }
    return normalized;
}

[[nodiscard]] uint256 HashBridgeProofProfileLabelId(std::string_view label_domain, std::string_view normalized_label)
{
    if (!IsValidBridgeProofProfileLabel(normalized_label)) return uint256{};
    HashWriter hw;
    hw << std::string{"BTX_Bridge_Proof_Profile_Label_V1"};
    hw << std::string{label_domain};
    hw << std::string{normalized_label};
    return hw.GetSHA256();
}

[[nodiscard]] uint256 HashBridgeProofProfileLabel(std::string_view field_name,
                                                  std::string_view label_domain,
                                                  const UniValue& value)
{
    return HashBridgeProofProfileLabelId(label_domain, NormalizeBridgeProofProfileLabelOrThrow(field_name, value));
}

struct BridgeProofAdapterTemplate
{
    std::string_view name;
    std::string_view family;
    std::string_view proof_type;
    std::string_view claim_system;
    shielded::BridgeProofClaimKind claim_kind;
};

struct BridgeProverTemplate
{
    std::string_view name;
    std::string_view proof_adapter_name;
    uint64_t native_millis;
    uint64_t cpu_millis;
    uint64_t gpu_millis;
    uint64_t network_millis;
    uint64_t peak_memory_bytes;
};

[[nodiscard]] const BridgeProofAdapterTemplate* FindBridgeProofAdapterTemplate(std::string_view name);
[[nodiscard]] shielded::BridgeProofAdapter BuildBridgeProofAdapterFromTemplateOrThrow(const BridgeProofAdapterTemplate& adapter_template);
[[nodiscard]] std::optional<shielded::BridgeProofArtifact> ParseBridgeProofArtifactSelectorOrThrow(const UniValue& value,
                                                                                                    std::string_view field_name);

constexpr std::array<BridgeProofAdapterTemplate, 14> BRIDGE_PROOF_ADAPTER_TEMPLATES{{
    {"sp1-compressed-settlement-metadata-v1", "sp1", "compressed", "settlement-metadata-v1", shielded::BridgeProofClaimKind::SETTLEMENT_METADATA},
    {"sp1-compressed-batch-tuple-v1", "sp1", "compressed", "batch-tuple-v1", shielded::BridgeProofClaimKind::BATCH_TUPLE},
    {"sp1-plonk-settlement-metadata-v1", "sp1", "plonk", "settlement-metadata-v1", shielded::BridgeProofClaimKind::SETTLEMENT_METADATA},
    {"sp1-plonk-batch-tuple-v1", "sp1", "plonk", "batch-tuple-v1", shielded::BridgeProofClaimKind::BATCH_TUPLE},
    {"sp1-groth16-settlement-metadata-v1", "sp1", "groth16", "settlement-metadata-v1", shielded::BridgeProofClaimKind::SETTLEMENT_METADATA},
    {"sp1-groth16-batch-tuple-v1", "sp1", "groth16", "batch-tuple-v1", shielded::BridgeProofClaimKind::BATCH_TUPLE},
    {"risc0-zkvm-composite-settlement-metadata-v1", "risc0-zkvm", "composite", "settlement-metadata-v1", shielded::BridgeProofClaimKind::SETTLEMENT_METADATA},
    {"risc0-zkvm-composite-batch-tuple-v1", "risc0-zkvm", "composite", "batch-tuple-v1", shielded::BridgeProofClaimKind::BATCH_TUPLE},
    {"risc0-zkvm-succinct-settlement-metadata-v1", "risc0-zkvm", "succinct", "settlement-metadata-v1", shielded::BridgeProofClaimKind::SETTLEMENT_METADATA},
    {"risc0-zkvm-succinct-batch-tuple-v1", "risc0-zkvm", "succinct", "batch-tuple-v1", shielded::BridgeProofClaimKind::BATCH_TUPLE},
    {"risc0-zkvm-groth16-settlement-metadata-v1", "risc0-zkvm", "groth16", "settlement-metadata-v1", shielded::BridgeProofClaimKind::SETTLEMENT_METADATA},
    {"risc0-zkvm-groth16-batch-tuple-v1", "risc0-zkvm", "groth16", "batch-tuple-v1", shielded::BridgeProofClaimKind::BATCH_TUPLE},
    {"blobstream-sp1-data-root-tuple-v1", "blobstream", "sp1", "data-root-tuple-v1", shielded::BridgeProofClaimKind::DATA_ROOT_TUPLE},
    {"blobstream-risc0-data-root-tuple-v1", "blobstream", "risc0", "data-root-tuple-v1", shielded::BridgeProofClaimKind::DATA_ROOT_TUPLE},
}};

constexpr std::array<BridgeProverTemplate, 8> BRIDGE_PROVER_TEMPLATES{{
    {"sp1-compressed-reference-v1", "sp1-compressed-settlement-metadata-v1", 260, 90000, 6500, 1800, 1342177280ULL},
    {"sp1-plonk-reference-v1", "sp1-plonk-settlement-metadata-v1", 240, 75000, 5200, 1600, 1207959552ULL},
    {"sp1-groth16-reference-v1", "sp1-groth16-settlement-metadata-v1", 220, 60000, 4500, 1500, 1073741824ULL},
    {"risc0-composite-reference-v1", "risc0-zkvm-composite-batch-tuple-v1", 210, 96000, 7000, 2000, 2147483648ULL},
    {"risc0-succinct-reference-v1", "risc0-zkvm-succinct-batch-tuple-v1", 180, 72000, 4200, 1200, 1610612736ULL},
    {"risc0-groth16-reference-v1", "risc0-zkvm-groth16-batch-tuple-v1", 170, 68000, 3800, 1150, 1342177280ULL},
    {"blobstream-sp1-reference-v1", "blobstream-sp1-data-root-tuple-v1", 250, 48000, 3300, 1300, 805306368ULL},
    {"blobstream-risc0-reference-v1", "blobstream-risc0-data-root-tuple-v1", 270, 62000, 3900, 1400, 1073741824ULL},
}};

[[nodiscard]] UniValue BridgeProofAdapterLabelsToUniValue(const BridgeProofAdapterTemplate& adapter_template)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("family", std::string{adapter_template.family});
    out.pushKV("proof_type", std::string{adapter_template.proof_type});
    out.pushKV("claim_system", std::string{adapter_template.claim_system});
    return out;
}

[[nodiscard]] UniValue BridgeProverTemplateToUniValue(const BridgeProverTemplate& prover_template)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("template_name", std::string{prover_template.name});
    out.pushKV("proof_adapter_name", std::string{prover_template.proof_adapter_name});
    if (const auto* adapter_template = FindBridgeProofAdapterTemplate(prover_template.proof_adapter_name)) {
        const auto adapter = BuildBridgeProofAdapterFromTemplateOrThrow(*adapter_template);
        out.pushKV("labels", BridgeProofAdapterLabelsToUniValue(*adapter_template));
        out.pushKV("claim_kind", BridgeProofClaimKindToString(adapter_template->claim_kind));
        out.pushKV("proof_adapter", BridgeProofAdapterToUniValue(adapter));
        out.pushKV("proof_adapter_hex", EncodeBridgeProofAdapterHex(adapter));
        out.pushKV("proof_adapter_id", shielded::ComputeBridgeProofAdapterId(adapter).GetHex());
        out.pushKV("proof_system_id", shielded::ComputeBridgeProofSystemId(adapter.profile).GetHex());
    }
    out.pushKV("timing_basis", "modeled_reference_input");
    out.pushKV("native_millis", static_cast<int64_t>(prover_template.native_millis));
    out.pushKV("cpu_millis", static_cast<int64_t>(prover_template.cpu_millis));
    out.pushKV("gpu_millis", static_cast<int64_t>(prover_template.gpu_millis));
    out.pushKV("network_millis", static_cast<int64_t>(prover_template.network_millis));
    out.pushKV("peak_memory_bytes", static_cast<int64_t>(prover_template.peak_memory_bytes));
    return out;
}

[[nodiscard]] const BridgeProofAdapterTemplate* FindBridgeProofAdapterTemplate(std::string_view name)
{
    const auto it = std::find_if(BRIDGE_PROOF_ADAPTER_TEMPLATES.begin(),
                                 BRIDGE_PROOF_ADAPTER_TEMPLATES.end(),
                                 [&](const auto& adapter) { return adapter.name == name; });
    return it == BRIDGE_PROOF_ADAPTER_TEMPLATES.end() ? nullptr : &*it;
}

[[nodiscard]] const BridgeProverTemplate* FindBridgeProverTemplate(std::string_view name)
{
    const auto it = std::find_if(BRIDGE_PROVER_TEMPLATES.begin(),
                                 BRIDGE_PROVER_TEMPLATES.end(),
                                 [&](const auto& prover_template) { return prover_template.name == name; });
    return it == BRIDGE_PROVER_TEMPLATES.end() ? nullptr : &*it;
}

[[nodiscard]] shielded::BridgeProofSystemProfile BuildBridgeProofSystemProfileOrThrow(const UniValue& value,
                                                                                      std::string_view field_name);

[[nodiscard]] const BridgeProofAdapterTemplate* FindBridgeProofAdapterTemplate(const shielded::BridgeProofAdapter& adapter)
{
    const uint256 adapter_id = shielded::ComputeBridgeProofAdapterId(adapter);
    if (adapter_id.IsNull()) return nullptr;
    for (const auto& adapter_template : BRIDGE_PROOF_ADAPTER_TEMPLATES) {
        const auto candidate = BuildBridgeProofAdapterFromTemplateOrThrow(adapter_template);
        if (shielded::ComputeBridgeProofAdapterId(candidate) == adapter_id) {
            return &adapter_template;
        }
    }
    return nullptr;
}

[[nodiscard]] shielded::BridgeProofAdapter BuildBridgeProofAdapterFromTemplateOrThrow(const BridgeProofAdapterTemplate& adapter_template)
{
    shielded::BridgeProofAdapter adapter;
    adapter.profile.family_id = HashBridgeProofProfileLabelId("family", adapter_template.family);
    adapter.profile.proof_type_id = HashBridgeProofProfileLabelId("proof_type", adapter_template.proof_type);
    adapter.profile.claim_system_id = HashBridgeProofProfileLabelId("claim_system", adapter_template.claim_system);
    adapter.claim_kind = adapter_template.claim_kind;
    if (!adapter.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("failed to build a valid bridge proof adapter from template %s", adapter_template.name));
    }
    return adapter;
}

[[nodiscard]] shielded::BridgeProofSystemProfile ParseCanonicalBridgeProofSystemProfileOrThrow(const UniValue& value,
                                                                                               std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    shielded::BridgeProofSystemProfile profile;
    const UniValue& version_value = FindValue(value, "version");
    if (!version_value.isNull()) {
        const int64_t version = version_value.getInt<int64_t>();
        if (version != 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.version must be 1", field_name));
        }
        profile.version = static_cast<uint8_t>(version);
    }
    profile.family_id = ParseHashV(FindValue(value, "family_id"), strprintf("%s.family_id", field_name));
    profile.proof_type_id = ParseHashV(FindValue(value, "proof_type_id"), strprintf("%s.proof_type_id", field_name));
    profile.claim_system_id = ParseHashV(FindValue(value, "claim_system_id"), strprintf("%s.claim_system_id", field_name));
    if (!profile.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not a valid canonical bridge proof profile", field_name));
    }
    return profile;
}

[[nodiscard]] shielded::BridgeProofAdapter BuildBridgeProofAdapterOrThrow(const UniValue& value,
                                                                          std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    const UniValue& adapter_name_value = FindValue(value, "adapter_name");
    const UniValue& proof_profile_hex_value = FindValue(value, "proof_profile_hex");
    const UniValue& proof_profile_value = FindValue(value, "proof_profile");
    const UniValue& canonical_profile_value = FindValue(value, "profile");
    const size_t selector_count = (!adapter_name_value.isNull() ? 1U : 0U) +
                                  (!proof_profile_hex_value.isNull() ? 1U : 0U) +
                                  (!proof_profile_value.isNull() ? 1U : 0U) +
                                  (!canonical_profile_value.isNull() ? 1U : 0U);
    if (selector_count != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must include exactly one of adapter_name, proof_profile_hex, proof_profile, or profile",
                                     field_name));
    }

    if (!adapter_name_value.isNull()) {
        const std::string name = NormalizeBridgeProofProfileLabelOrThrow(strprintf("%s.adapter_name", field_name), adapter_name_value);
        const auto* adapter_template = FindBridgeProofAdapterTemplate(name);
        if (adapter_template == nullptr) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s.adapter_name is not a supported built-in proof adapter", field_name));
        }
        return BuildBridgeProofAdapterFromTemplateOrThrow(*adapter_template);
    }

    shielded::BridgeProofAdapter adapter;
    const UniValue& version_value = FindValue(value, "version");
    if (!version_value.isNull()) {
        const int64_t version = version_value.getInt<int64_t>();
        if (version != 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.version must be 1", field_name));
        }
        adapter.version = static_cast<uint8_t>(version);
    }
    adapter.claim_kind = ParseBridgeProofClaimKindOrThrow(FindValue(value, "claim_kind"),
                                                          strprintf("%s.claim_kind", field_name));
    adapter.profile = !proof_profile_hex_value.isNull()
        ? DecodeBridgeProofSystemProfileOrThrow(proof_profile_hex_value)
        : (!canonical_profile_value.isNull()
            ? ParseCanonicalBridgeProofSystemProfileOrThrow(canonical_profile_value, strprintf("%s.profile", field_name))
            : BuildBridgeProofSystemProfileOrThrow(proof_profile_value, strprintf("%s.proof_profile", field_name)));
    if (!adapter.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not a valid bridge proof adapter", field_name));
    }
    return adapter;
}

[[nodiscard]] std::optional<shielded::BridgeProofAdapter> ParseBridgeProofAdapterSelectorOrThrow(const UniValue& value,
                                                                                                  std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    const UniValue& adapter_name_value = FindValue(value, "proof_adapter_name");
    const UniValue& adapter_hex_value = FindValue(value, "proof_adapter_hex");
    const UniValue& adapter_value = FindValue(value, "proof_adapter");
    const size_t selector_count = (!adapter_name_value.isNull() ? 1U : 0U) +
                                  (!adapter_hex_value.isNull() ? 1U : 0U) +
                                  (!adapter_value.isNull() ? 1U : 0U);
    if (selector_count == 0) return std::nullopt;
    if (selector_count != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must include exactly one of proof_adapter_name, proof_adapter_hex, or proof_adapter",
                                     field_name));
    }

    if (!adapter_name_value.isNull()) {
        if (!adapter_name_value.isStr()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.proof_adapter_name must be a string", field_name));
        }
        UniValue adapter_value(UniValue::VOBJ);
        adapter_value.pushKV("adapter_name", adapter_name_value.get_str());
        return BuildBridgeProofAdapterOrThrow(adapter_value, strprintf("%s.proof_adapter", field_name));
    }
    if (!adapter_hex_value.isNull()) {
        return DecodeBridgeProofAdapterOrThrow(adapter_hex_value);
    }

    if (!adapter_value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.proof_adapter must be an object", field_name));
    }
    return BuildBridgeProofAdapterOrThrow(adapter_value, strprintf("%s.proof_adapter", field_name));
}

[[nodiscard]] shielded::BridgeProofSystemProfile BuildBridgeProofSystemProfileOrThrow(const UniValue& value,
                                                                                      std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    shielded::BridgeProofSystemProfile profile;
    const UniValue& version_value = FindValue(value, "version");
    if (!version_value.isNull()) {
        const int64_t version = version_value.getInt<int64_t>();
        if (version != 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.version must be 1", field_name));
        }
        profile.version = static_cast<uint8_t>(version);
    }

    profile.family_id = HashBridgeProofProfileLabel(strprintf("%s.family", field_name), "family", FindValue(value, "family"));
    profile.proof_type_id = HashBridgeProofProfileLabel(strprintf("%s.proof_type", field_name), "proof_type", FindValue(value, "proof_type"));
    profile.claim_system_id = HashBridgeProofProfileLabel(strprintf("%s.claim_system", field_name), "claim_system", FindValue(value, "claim_system"));
    if (!profile.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not a valid bridge proof profile", field_name));
    }
    return profile;
}

[[nodiscard]] uint256 ParseBridgeProofSystemIdOrThrow(const UniValue& value, std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    const UniValue& proof_system_id_value = FindValue(value, "proof_system_id");
    const UniValue& proof_profile_hex_value = FindValue(value, "proof_profile_hex");
    const UniValue& proof_profile_value = FindValue(value, "proof_profile");
    const size_t selector_count = (!proof_system_id_value.isNull() ? 1U : 0U) +
                                  (!proof_profile_hex_value.isNull() ? 1U : 0U) +
                                  (!proof_profile_value.isNull() ? 1U : 0U);
    if (selector_count != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must include exactly one of proof_system_id, proof_profile_hex, or proof_profile", field_name));
    }

    if (!proof_system_id_value.isNull()) {
        return ParseHashV(proof_system_id_value, strprintf("%s.proof_system_id", field_name));
    }
    if (!proof_profile_hex_value.isNull()) {
        const auto profile = DecodeBridgeProofSystemProfileOrThrow(proof_profile_hex_value);
        return shielded::ComputeBridgeProofSystemId(profile);
    }
    const auto profile = BuildBridgeProofSystemProfileOrThrow(proof_profile_value, strprintf("%s.proof_profile", field_name));
    return shielded::ComputeBridgeProofSystemId(profile);
}

[[nodiscard]] shielded::BridgeProofClaim ParseBridgeProofClaimOrThrow(const UniValue& value, std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    shielded::BridgeProofClaim claim;
    const UniValue& version_value = FindValue(value, "version");
    if (!version_value.isNull()) {
        const int64_t version = version_value.getInt<int64_t>();
        if (version != 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.version must be 1", field_name));
        }
        claim.version = static_cast<uint8_t>(version);
    }

    claim.kind = ParseBridgeProofClaimKindOrThrow(FindValue(value, "kind"), strprintf("%s.kind", field_name));
    claim.statement_hash = ParseHashV(FindValue(value, "statement_hash"), strprintf("%s.statement_hash", field_name));

    if (claim.kind == shielded::BridgeProofClaimKind::BATCH_TUPLE ||
        claim.kind == shielded::BridgeProofClaimKind::SETTLEMENT_METADATA) {
        claim.direction = ParseBridgeDirectionOrThrow(FindValue(value, "direction"), strprintf("%s.direction", field_name));
        const UniValue& ids_value = FindValue(value, "ids");
        if (ids_value.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.ids is required", field_name));
        }
        if (!ids_value.isObject()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.ids must be an object", field_name));
        }
        claim.ids = ParseBridgePlanIdsOrThrow(ids_value);

        const UniValue& entry_count_value = FindValue(value, "entry_count");
        if (entry_count_value.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.entry_count is required", field_name));
        }
        const int64_t entry_count = entry_count_value.getInt<int64_t>();
        if (entry_count <= 0 || entry_count > std::numeric_limits<uint32_t>::max()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.entry_count must be a positive integer", field_name));
        }
        claim.entry_count = static_cast<uint32_t>(entry_count);
        claim.total_amount = AmountFromValue(FindValue(value, "total_amount"));
        claim.batch_root = ParseHashV(FindValue(value, "batch_root"), strprintf("%s.batch_root", field_name));
    }

    if (claim.kind == shielded::BridgeProofClaimKind::SETTLEMENT_METADATA ||
        claim.kind == shielded::BridgeProofClaimKind::DATA_ROOT_TUPLE) {
        claim.domain_id = ParseHashV(FindValue(value, "domain_id"), strprintf("%s.domain_id", field_name));
        const UniValue& source_epoch_value = FindValue(value, "source_epoch");
        if (source_epoch_value.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.source_epoch is required", field_name));
        }
        const int64_t source_epoch = source_epoch_value.getInt<int64_t>();
        if (source_epoch <= 0 || source_epoch > std::numeric_limits<uint32_t>::max()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.source_epoch must be a positive integer", field_name));
        }
        claim.source_epoch = static_cast<uint32_t>(source_epoch);
        claim.data_root = ParseHashV(FindValue(value, "data_root"), strprintf("%s.data_root", field_name));
    }

    if (!claim.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not a valid bridge proof claim", field_name));
    }
    return claim;
}

[[nodiscard]] uint256 ParseBridgePublicValuesHashOrThrow(const UniValue& value,
                                                         const shielded::BridgeBatchStatement& statement)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "proof_receipt must be an object");
    }

    const UniValue& public_values_hash_value = FindValue(value, "public_values_hash");
    const UniValue& claim_hex_value = FindValue(value, "claim_hex");
    const UniValue& claim_value = FindValue(value, "claim");
    const size_t selector_count = (!public_values_hash_value.isNull() ? 1U : 0U) +
                                  (!claim_hex_value.isNull() ? 1U : 0U) +
                                  (!claim_value.isNull() ? 1U : 0U);
    if (selector_count != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "proof_receipt must include exactly one of public_values_hash, claim_hex, or claim");
    }

    if (!public_values_hash_value.isNull()) {
        return ParseHashV(public_values_hash_value, "proof_receipt.public_values_hash");
    }

    const shielded::BridgeProofClaim claim = !claim_hex_value.isNull()
        ? DecodeBridgeProofClaimOrThrow(claim_hex_value)
        : ParseBridgeProofClaimOrThrow(claim_value, "proof_receipt.claim");
    if (!shielded::DoesBridgeProofClaimMatchStatement(claim, statement)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "proof_receipt claim does not match statement_hex");
    }
    return shielded::ComputeBridgeProofClaimHash(claim);
}

[[nodiscard]] uint32_t ParsePositiveUint32OrThrow(const UniValue& value, std::string_view field_name)
{
    if (value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is required", field_name));
    }
    const int64_t parsed = value.getInt<int64_t>();
    if (parsed <= 0 || parsed > std::numeric_limits<uint32_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a positive integer", field_name));
    }
    return static_cast<uint32_t>(parsed);
}

[[nodiscard]] uint64_t ParsePositiveUint64OrThrow(const UniValue& value, std::string_view field_name)
{
    if (value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is required", field_name));
    }
    const int64_t parsed = value.getInt<int64_t>();
    if (parsed <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a positive integer", field_name));
    }
    return static_cast<uint64_t>(parsed);
}

[[nodiscard]] uint32_t ParseNonNegativeUint32OrThrow(const UniValue& value, std::string_view field_name)
{
    if (value.isNull()) return 0;
    const int64_t parsed = value.getInt<int64_t>();
    if (parsed < 0 || parsed > std::numeric_limits<uint32_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a non-negative integer", field_name));
    }
    return static_cast<uint32_t>(parsed);
}

[[nodiscard]] uint64_t ParseNonNegativeUint64OrThrow(const UniValue& value, std::string_view field_name)
{
    if (value.isNull()) return 0;
    const int64_t parsed = value.getInt<int64_t>();
    if (parsed < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a non-negative integer", field_name));
    }
    return static_cast<uint64_t>(parsed);
}

[[nodiscard]] shielded::BridgeAggregateSettlement ParseBridgeAggregateSettlementOrThrow(const shielded::BridgeBatchStatement& statement,
                                                                                        const UniValue& value,
                                                                                        std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    shielded::BridgeAggregateSettlement settlement;
    settlement.statement_hash = shielded::ComputeBridgeBatchStatementHash(statement);

    const UniValue& version_value = FindValue(value, "version");
    if (!version_value.isNull()) {
        const int64_t version = version_value.getInt<int64_t>();
        if (version != 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.version must be 1", field_name));
        }
        settlement.version = static_cast<uint8_t>(version);
    }

    settlement.batched_user_count = ParsePositiveUint32OrThrow(FindValue(value, "batched_user_count"),
                                                               strprintf("%s.batched_user_count", field_name));
    settlement.new_wallet_count = ParseNonNegativeUint32OrThrow(FindValue(value, "new_wallet_count"),
                                                                strprintf("%s.new_wallet_count", field_name));
    settlement.input_count = ParseNonNegativeUint32OrThrow(FindValue(value, "input_count"),
                                                           strprintf("%s.input_count", field_name));
    settlement.output_count = ParseNonNegativeUint32OrThrow(FindValue(value, "output_count"),
                                                            strprintf("%s.output_count", field_name));
    settlement.base_non_witness_bytes = ParsePositiveUint64OrThrow(FindValue(value, "base_non_witness_bytes"),
                                                                   strprintf("%s.base_non_witness_bytes", field_name));
    settlement.base_witness_bytes = ParseNonNegativeUint64OrThrow(FindValue(value, "base_witness_bytes"),
                                                                  strprintf("%s.base_witness_bytes", field_name));
    settlement.state_commitment_bytes = ParsePositiveUint64OrThrow(FindValue(value, "state_commitment_bytes"),
                                                                   strprintf("%s.state_commitment_bytes", field_name));
    settlement.control_plane_bytes = ParseNonNegativeUint64OrThrow(FindValue(value, "control_plane_bytes"),
                                                                   strprintf("%s.control_plane_bytes", field_name));

    const auto artifact_bundle = ParseBridgeAggregateArtifactBundleSelectorOrThrow(value, field_name);
    const auto artifact = ParseBridgeProofArtifactSelectorOrThrow(value, field_name);
    const UniValue& proof_payload_bytes_value = FindValue(value, "proof_payload_bytes");
    const UniValue& data_payload_bytes_value = FindValue(value, "data_availability_payload_bytes");
    const UniValue& auxiliary_offchain_bytes_value = FindValue(value, "auxiliary_offchain_bytes");
    if (artifact_bundle.has_value()) {
        if (artifact.has_value() ||
            !proof_payload_bytes_value.isNull() ||
            !data_payload_bytes_value.isNull() ||
            !auxiliary_offchain_bytes_value.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s must not mix artifact_bundle_* with proof_artifact_*, proof_payload_bytes, data_availability_payload_bytes, or auxiliary_offchain_bytes",
                                         field_name));
        }
        if (artifact_bundle->statement_hash != settlement.statement_hash) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s artifact bundle does not match statement_hex", field_name));
        }
        settlement.proof_payload_bytes = artifact_bundle->proof_payload_bytes;
        settlement.data_availability_payload_bytes = artifact_bundle->data_availability_payload_bytes;
        const auto aux_total = shielded::GetBridgeAggregateArtifactBundleStorageBytes(*artifact_bundle);
        const auto payload_total = artifact_bundle->proof_payload_bytes >
                std::numeric_limits<uint64_t>::max() - artifact_bundle->data_availability_payload_bytes
            ? std::optional<uint64_t>{}
            : std::optional<uint64_t>{artifact_bundle->proof_payload_bytes +
                                      artifact_bundle->data_availability_payload_bytes};
        if (!payload_total.has_value() || aux_total < *payload_total) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s artifact bundle storage accounting is invalid", field_name));
        }
        settlement.auxiliary_offchain_bytes = aux_total - *payload_total;
    } else if (artifact.has_value() && !proof_payload_bytes_value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must not include proof_payload_bytes when proof_artifact_* is supplied", field_name));
    } else if (artifact.has_value()) {
        if (artifact->statement_hash != settlement.statement_hash) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s proof artifact does not match statement_hex", field_name));
        }
        settlement.proof_payload_bytes = static_cast<uint64_t>(artifact->proof_size_bytes) +
                                         static_cast<uint64_t>(artifact->public_values_size_bytes);
        settlement.data_availability_payload_bytes = ParseNonNegativeUint64OrThrow(data_payload_bytes_value,
                                                                                   strprintf("%s.data_availability_payload_bytes", field_name));
        settlement.auxiliary_offchain_bytes = ParseNonNegativeUint64OrThrow(auxiliary_offchain_bytes_value,
                                                                            strprintf("%s.auxiliary_offchain_bytes", field_name));
        if (settlement.auxiliary_offchain_bytes >
            std::numeric_limits<uint64_t>::max() - static_cast<uint64_t>(artifact->auxiliary_data_size_bytes)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s auxiliary_offchain_bytes overflows when proof artifact bytes are added", field_name));
        }
        settlement.auxiliary_offchain_bytes += static_cast<uint64_t>(artifact->auxiliary_data_size_bytes);
    } else {
        settlement.proof_payload_bytes = ParseNonNegativeUint64OrThrow(proof_payload_bytes_value,
                                                                       strprintf("%s.proof_payload_bytes", field_name));
        settlement.data_availability_payload_bytes = ParseNonNegativeUint64OrThrow(data_payload_bytes_value,
                                                                                   strprintf("%s.data_availability_payload_bytes", field_name));
        settlement.auxiliary_offchain_bytes = ParseNonNegativeUint64OrThrow(auxiliary_offchain_bytes_value,
                                                                            strprintf("%s.auxiliary_offchain_bytes", field_name));
    }

    const UniValue& proof_location_value = FindValue(value, "proof_payload_location");
    if (!proof_location_value.isNull()) {
        if (!proof_location_value.isStr()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.proof_payload_location must be a string", field_name));
        }
        settlement.proof_payload_location = ParseBridgeAggregatePayloadLocationOrThrow(proof_location_value,
                                                                                       strprintf("%s.proof_payload_location", field_name));
    }

    const UniValue& data_location_value = FindValue(value, "data_availability_location");
    if (!data_location_value.isNull()) {
        if (!data_location_value.isStr()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.data_availability_location must be a string", field_name));
        }
        settlement.data_availability_location = ParseBridgeAggregatePayloadLocationOrThrow(data_location_value,
                                                                                           strprintf("%s.data_availability_location", field_name));
    }

    if (!settlement.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not a valid bridge aggregate settlement", field_name));
    }
    return settlement;
}

[[nodiscard]] shielded::BridgeCapacityFootprint ParseBridgeCapacityFootprintOrThrow(const UniValue& value,
                                                                                    std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    shielded::BridgeCapacityFootprint footprint;
    footprint.l1_serialized_bytes = ParsePositiveUint64OrThrow(FindValue(value, "l1_serialized_bytes"),
                                                               strprintf("%s.l1_serialized_bytes", field_name));
    footprint.l1_weight = ParsePositiveUint64OrThrow(FindValue(value, "l1_weight"),
                                                     strprintf("%s.l1_weight", field_name));
    footprint.l1_data_availability_bytes = ParseNonNegativeUint64OrThrow(FindValue(value, "l1_data_availability_bytes"),
                                                                         strprintf("%s.l1_data_availability_bytes", field_name));
    footprint.control_plane_bytes = ParseNonNegativeUint64OrThrow(FindValue(value, "control_plane_bytes"),
                                                                  strprintf("%s.control_plane_bytes", field_name));
    footprint.offchain_storage_bytes = ParseNonNegativeUint64OrThrow(FindValue(value, "offchain_storage_bytes"),
                                                                     strprintf("%s.offchain_storage_bytes", field_name));
    footprint.batched_user_count = ParsePositiveUint32OrThrow(FindValue(value, "batched_user_count"),
                                                              strprintf("%s.batched_user_count", field_name));
    if (!footprint.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not a valid bridge capacity footprint", field_name));
    }
    return footprint;
}

[[nodiscard]] shielded::BridgeShieldedStateProfile ParseBridgeShieldedStateProfileOrThrow(const UniValue& value,
                                                                                          std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    shielded::BridgeShieldedStateProfile profile;
    const UniValue& version_value = FindValue(value, "version");
    if (!version_value.isNull()) {
        const int64_t version = version_value.getInt<int64_t>();
        if (version != 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.version must be 1", field_name));
        }
        profile.version = static_cast<uint8_t>(version);
    }

    const auto parse_positive = [&](const char* key, uint64_t& out_value) {
        const UniValue& field = FindValue(value, key);
        if (!field.isNull()) {
            out_value = ParsePositiveUint64OrThrow(field, strprintf("%s.%s", field_name, key));
        }
    };
    const auto parse_non_negative = [&](const char* key, uint64_t& out_value) {
        const UniValue& field = FindValue(value, key);
        if (!field.isNull()) {
            out_value = ParseNonNegativeUint64OrThrow(field, strprintf("%s.%s", field_name, key));
        }
    };

    parse_positive("commitment_index_key_bytes", profile.commitment_index_key_bytes);
    parse_positive("commitment_index_value_bytes", profile.commitment_index_value_bytes);
    parse_positive("snapshot_commitment_bytes", profile.snapshot_commitment_bytes);
    parse_positive("nullifier_index_key_bytes", profile.nullifier_index_key_bytes);
    parse_positive("nullifier_index_value_bytes", profile.nullifier_index_value_bytes);
    parse_positive("snapshot_nullifier_bytes", profile.snapshot_nullifier_bytes);
    parse_positive("nullifier_cache_bytes", profile.nullifier_cache_bytes);
    parse_non_negative("wallet_materialization_bytes", profile.wallet_materialization_bytes);
    parse_non_negative("bounded_anchor_history_bytes", profile.bounded_anchor_history_bytes);
    if (!profile.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not a valid bridge shielded state profile", field_name));
    }
    return profile;
}

[[nodiscard]] std::optional<shielded::BridgeShieldedStateProfile> ParseBridgeShieldedStateProfileSelectorOrThrow(const UniValue& value,
                                                                                                                   std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    const UniValue& profile_hex_value = FindValue(value, "state_profile_hex");
    const UniValue& profile_value = FindValue(value, "state_profile");
    const size_t selector_count = (!profile_hex_value.isNull() ? 1U : 0U) +
                                  (!profile_value.isNull() ? 1U : 0U);
    if (selector_count == 0) return std::nullopt;
    if (selector_count != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must include at most one of state_profile_hex or state_profile", field_name));
    }
    if (!profile_hex_value.isNull()) {
        return DecodeBridgeShieldedStateProfileOrThrow(profile_hex_value);
    }
    return ParseBridgeShieldedStateProfileOrThrow(profile_value, strprintf("%s.state_profile", field_name));
}

[[nodiscard]] shielded::BridgeShieldedStateRetentionPolicy ParseBridgeShieldedStateRetentionPolicyOrThrow(const UniValue& value,
                                                                                                            std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    shielded::BridgeShieldedStateRetentionPolicy policy;
    const UniValue& version_value = FindValue(value, "version");
    if (!version_value.isNull()) {
        const int64_t version = version_value.getInt<int64_t>();
        if (version != 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.version must be 1", field_name));
        }
        policy.version = static_cast<uint8_t>(version);
    }

    const auto parse_bool_field = [&](const char* key, bool& out_value) {
        const UniValue& field = FindValue(value, key);
        if (!field.isNull()) {
            if (!field.isBool()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.%s must be a boolean", field_name, key));
            }
            out_value = field.get_bool();
        }
    };
    parse_bool_field("retain_commitment_index", policy.retain_commitment_index);
    parse_bool_field("retain_nullifier_index", policy.retain_nullifier_index);
    parse_bool_field("snapshot_include_commitments", policy.snapshot_include_commitments);
    parse_bool_field("snapshot_include_nullifiers", policy.snapshot_include_nullifiers);

    const UniValue& wallet_bps_value = FindValue(value, "wallet_l1_materialization_bps");
    if (!wallet_bps_value.isNull()) {
        const int64_t parsed = wallet_bps_value.getInt<int64_t>();
        if (parsed < 0 || parsed > 10'000) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s.wallet_l1_materialization_bps must be between 0 and 10000", field_name));
        }
        policy.wallet_l1_materialization_bps = static_cast<uint32_t>(parsed);
    }

    const UniValue& snapshot_target_bytes_value = FindValue(value, "snapshot_target_bytes");
    if (!snapshot_target_bytes_value.isNull()) {
        policy.snapshot_target_bytes = ParsePositiveUint64OrThrow(snapshot_target_bytes_value,
                                                                  strprintf("%s.snapshot_target_bytes", field_name));
    }

    if (!policy.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s is not a valid bridge shielded state retention policy", field_name));
    }
    return policy;
}

[[nodiscard]] std::optional<shielded::BridgeShieldedStateRetentionPolicy> ParseBridgeShieldedStateRetentionPolicySelectorOrThrow(
    const UniValue& value,
    std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    const UniValue& policy_hex_value = FindValue(value, "retention_policy_hex");
    const UniValue& policy_value = FindValue(value, "retention_policy");
    const size_t selector_count = (!policy_hex_value.isNull() ? 1U : 0U) +
                                  (!policy_value.isNull() ? 1U : 0U);
    if (selector_count == 0) return std::nullopt;
    if (selector_count != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must include at most one of retention_policy_hex or retention_policy", field_name));
    }
    if (!policy_hex_value.isNull()) {
        return DecodeBridgeShieldedStateRetentionPolicyOrThrow(policy_hex_value);
    }
    return ParseBridgeShieldedStateRetentionPolicyOrThrow(policy_value, strprintf("%s.retention_policy", field_name));
}

[[nodiscard]] std::optional<shielded::BridgeProverLane> ParseBridgeProverLaneOrThrow(const UniValue& value,
                                                                                      std::string_view field_name,
                                                                                      std::optional<uint64_t> default_millis_per_settlement = std::nullopt)
{
    if (value.isNull()) return std::nullopt;
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    shielded::BridgeProverLane lane;
    const UniValue& millis_value = FindValue(value, "millis_per_settlement");
    if (!millis_value.isNull()) {
        if (default_millis_per_settlement.has_value()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s.millis_per_settlement must be omitted when prover profile or benchmark timings are provided",
                                         field_name));
        }
        lane.millis_per_settlement = ParsePositiveUint64OrThrow(millis_value,
                                                                strprintf("%s.millis_per_settlement", field_name));
    } else if (default_millis_per_settlement.has_value()) {
        lane.millis_per_settlement = *default_millis_per_settlement;
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.millis_per_settlement is required", field_name));
    }
    lane.workers = ParsePositiveUint32OrThrow(FindValue(value, "workers"),
                                              strprintf("%s.workers", field_name));
    const UniValue& parallel_jobs_value = FindValue(value, "parallel_jobs_per_worker");
    lane.parallel_jobs_per_worker = parallel_jobs_value.isNull()
        ? 1
        : ParsePositiveUint32OrThrow(parallel_jobs_value,
                                     strprintf("%s.parallel_jobs_per_worker", field_name));
    lane.hourly_cost_cents = ParseNonNegativeUint64OrThrow(FindValue(value, "hourly_cost_cents"),
                                                           strprintf("%s.hourly_cost_cents", field_name));
    if (!lane.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not a valid bridge prover lane", field_name));
    }
    return lane;
}

[[nodiscard]] shielded::BridgeProverFootprint ParseBridgeProverFootprintOrThrow(const UniValue& value,
                                                                                 std::string_view field_name,
                                                                                 std::optional<shielded::BridgeProverProfile> profile = std::nullopt,
                                                                                 std::optional<shielded::BridgeProverBenchmark> benchmark = std::nullopt,
                                                                                 shielded::BridgeProverBenchmarkStatistic benchmark_statistic = shielded::BridgeProverBenchmarkStatistic::P50)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    shielded::BridgeProverFootprint footprint;
    const UniValue& block_interval_value = FindValue(value, "block_interval_millis");
    footprint.block_interval_millis = block_interval_value.isNull()
        ? DEFAULT_BRIDGE_PROVER_BLOCK_INTERVAL_MILLIS
        : ParsePositiveUint64OrThrow(block_interval_value,
                                     strprintf("%s.block_interval_millis", field_name));
    const auto default_lane_millis = [&](uint64_t shielded::BridgeProverProfile::*profile_member,
                                         const shielded::BridgeProverMetricSummary shielded::BridgeProverBenchmark::*benchmark_member)
        -> std::optional<uint64_t> {
        if (profile.has_value() && (*profile).*profile_member > 0) {
            return (*profile).*profile_member;
        }
        if (benchmark.has_value()) {
            const uint64_t value = shielded::SelectBridgeProverMetric((*benchmark).*benchmark_member, benchmark_statistic);
            if (value > 0) return value;
        }
        return std::nullopt;
    };
    footprint.native = ParseBridgeProverLaneOrThrow(FindValue(value, "native"),
                                                    strprintf("%s.native", field_name),
                                                    default_lane_millis(&shielded::BridgeProverProfile::native_millis_per_settlement,
                                                                        &shielded::BridgeProverBenchmark::native_millis_per_settlement));
    footprint.cpu = ParseBridgeProverLaneOrThrow(FindValue(value, "cpu"),
                                                 strprintf("%s.cpu", field_name),
                                                 default_lane_millis(&shielded::BridgeProverProfile::cpu_millis_per_settlement,
                                                                     &shielded::BridgeProverBenchmark::cpu_millis_per_settlement));
    footprint.gpu = ParseBridgeProverLaneOrThrow(FindValue(value, "gpu"),
                                                 strprintf("%s.gpu", field_name),
                                                 default_lane_millis(&shielded::BridgeProverProfile::gpu_millis_per_settlement,
                                                                     &shielded::BridgeProverBenchmark::gpu_millis_per_settlement));
    footprint.network = ParseBridgeProverLaneOrThrow(FindValue(value, "network"),
                                                     strprintf("%s.network", field_name),
                                                     default_lane_millis(&shielded::BridgeProverProfile::network_millis_per_settlement,
                                                                         &shielded::BridgeProverBenchmark::network_millis_per_settlement));
    if (!footprint.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not a valid bridge prover footprint", field_name));
    }
    return footprint;
}

[[nodiscard]] uint256 ParseBridgeProofArtifactCommitmentOrThrow(const UniValue& value, std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    const UniValue& artifact_commitment_value = FindValue(value, "artifact_commitment");
    const UniValue& artifact_hex_value = FindValue(value, "artifact_hex");
    const size_t selector_count = (!artifact_commitment_value.isNull() ? 1U : 0U) +
                                  (!artifact_hex_value.isNull() ? 1U : 0U);
    if (selector_count != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must include exactly one of artifact_commitment or artifact_hex", field_name));
    }
    if (!artifact_commitment_value.isNull()) {
        return ParseHashV(artifact_commitment_value, strprintf("%s.artifact_commitment", field_name));
    }
    const auto artifact_bytes = ParseHexV(artifact_hex_value, strprintf("%s.artifact_hex", field_name));
    const uint256 artifact_commitment = shielded::ComputeBridgeProofArtifactCommitment(
        Span<const uint8_t>{artifact_bytes.data(), artifact_bytes.size()});
    if (artifact_commitment.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.artifact_hex does not produce a valid artifact commitment", field_name));
    }
    return artifact_commitment;
}

[[nodiscard]] uint256 ParseBridgeArtifactCommitmentOrThrow(const UniValue& value,
                                                           std::string_view field_name,
                                                           std::string_view commitment_key,
                                                           std::string_view hex_key)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    const UniValue& commitment_value = FindValue(value, std::string(commitment_key));
    const UniValue& hex_value = FindValue(value, std::string(hex_key));
    const size_t selector_count = (!commitment_value.isNull() ? 1U : 0U) +
                                  (!hex_value.isNull() ? 1U : 0U);
    if (selector_count != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must include exactly one of %s or %s",
                                     field_name,
                                     commitment_key,
                                     hex_key));
    }
    if (!commitment_value.isNull()) {
        return ParseHashV(commitment_value, strprintf("%s.%s", field_name, commitment_key));
    }
    const auto artifact_bytes = ParseHexV(hex_value, strprintf("%s.%s", field_name, hex_key));
    const uint256 commitment = shielded::ComputeBridgeProofArtifactCommitment(
        Span<const uint8_t>{artifact_bytes.data(), artifact_bytes.size()});
    if (commitment.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s.%s does not produce a valid commitment", field_name, hex_key));
    }
    return commitment;
}

[[nodiscard]] shielded::BridgeProofArtifact ParseBridgeProofArtifactOrThrow(const UniValue& value,
                                                                            std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    const UniValue& version_value = FindValue(value, "version");
    shielded::BridgeProofArtifact artifact;
    if (!version_value.isNull()) {
        const int64_t version = version_value.getInt<int64_t>();
        if (version != 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.version must be 1", field_name));
        }
        artifact.version = static_cast<uint8_t>(version);
    }

    const auto adapter = ParseBridgeProofAdapterSelectorOrThrow(value, field_name);
    if (!adapter.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must include exactly one of proof_adapter_name, proof_adapter_hex, or proof_adapter",
                                     field_name));
    }
    artifact.adapter = *adapter;
    artifact.statement_hash = ParseHashV(FindValue(value, "statement_hash"), strprintf("%s.statement_hash", field_name));
    artifact.verifier_key_hash = ParseHashV(FindValue(value, "verifier_key_hash"), strprintf("%s.verifier_key_hash", field_name));
    artifact.public_values_hash = ParseHashV(FindValue(value, "public_values_hash"), strprintf("%s.public_values_hash", field_name));
    artifact.proof_commitment = ParseHashV(FindValue(value, "proof_commitment"), strprintf("%s.proof_commitment", field_name));
    artifact.artifact_commitment = ParseHashV(FindValue(value, "artifact_commitment"), strprintf("%s.artifact_commitment", field_name));
    artifact.proof_size_bytes = ParsePositiveUint32OrThrow(FindValue(value, "proof_size_bytes"),
                                                           strprintf("%s.proof_size_bytes", field_name));
    artifact.public_values_size_bytes = ParsePositiveUint32OrThrow(FindValue(value, "public_values_size_bytes"),
                                                                   strprintf("%s.public_values_size_bytes", field_name));
    const UniValue& auxiliary_size_value = FindValue(value, "auxiliary_data_size_bytes");
    if (!auxiliary_size_value.isNull()) {
        const int64_t auxiliary_size = auxiliary_size_value.getInt<int64_t>();
        if (auxiliary_size < 0 || auxiliary_size > std::numeric_limits<uint32_t>::max()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s.auxiliary_data_size_bytes must be a non-negative integer", field_name));
        }
        artifact.auxiliary_data_size_bytes = static_cast<uint32_t>(auxiliary_size);
    }
    if (!artifact.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not a valid bridge proof artifact", field_name));
    }
    return artifact;
}

[[nodiscard]] std::optional<shielded::BridgeProofArtifact> ParseBridgeProofArtifactSelectorOrThrow(const UniValue& value,
                                                                                                    std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    const UniValue& artifact_hex_value = FindValue(value, "proof_artifact_hex");
    const UniValue& artifact_value = FindValue(value, "proof_artifact");
    const size_t selector_count = (!artifact_hex_value.isNull() ? 1U : 0U) +
                                  (!artifact_value.isNull() ? 1U : 0U);
    if (selector_count == 0) return std::nullopt;
    if (selector_count != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must include exactly one of proof_artifact_hex or proof_artifact", field_name));
    }
    if (!artifact_hex_value.isNull()) {
        return DecodeBridgeProofArtifactOrThrow(artifact_hex_value);
    }
    if (!artifact_value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.proof_artifact must be an object", field_name));
    }
    return ParseBridgeProofArtifactOrThrow(artifact_value, strprintf("%s.proof_artifact", field_name));
}

[[nodiscard]] shielded::BridgeProofArtifact BuildBridgeProofArtifactOrThrow(const shielded::BridgeBatchStatement& statement,
                                                                            const UniValue& value,
                                                                            std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    const auto adapter = ParseBridgeProofAdapterSelectorOrThrow(value, field_name);
    if (!adapter.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must include exactly one of proof_adapter_name, proof_adapter_hex, or proof_adapter",
                                     field_name));
    }
    const uint256 verifier_key_hash = ParseHashV(FindValue(value, "verifier_key_hash"), strprintf("%s.verifier_key_hash", field_name));
    const uint256 proof_commitment = ParseHashV(FindValue(value, "proof_commitment"), strprintf("%s.proof_commitment", field_name));
    const uint256 artifact_commitment = ParseBridgeProofArtifactCommitmentOrThrow(value, field_name);
    const uint32_t proof_size_bytes = ParsePositiveUint32OrThrow(FindValue(value, "proof_size_bytes"),
                                                                 strprintf("%s.proof_size_bytes", field_name));
    const uint32_t public_values_size_bytes = ParsePositiveUint32OrThrow(FindValue(value, "public_values_size_bytes"),
                                                                         strprintf("%s.public_values_size_bytes", field_name));
    uint32_t auxiliary_data_size_bytes{0};
    const UniValue& auxiliary_size_value = FindValue(value, "auxiliary_data_size_bytes");
    if (!auxiliary_size_value.isNull()) {
        const int64_t auxiliary_size = auxiliary_size_value.getInt<int64_t>();
        if (auxiliary_size < 0 || auxiliary_size > std::numeric_limits<uint32_t>::max()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s.auxiliary_data_size_bytes must be a non-negative integer", field_name));
        }
        auxiliary_data_size_bytes = static_cast<uint32_t>(auxiliary_size);
    }
    const auto artifact = shielded::BuildBridgeProofArtifact(statement,
                                                             *adapter,
                                                             verifier_key_hash,
                                                             proof_commitment,
                                                             artifact_commitment,
                                                             proof_size_bytes,
                                                             public_values_size_bytes,
                                                             auxiliary_data_size_bytes);
    if (!artifact.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("failed to build a valid bridge proof artifact from %s", field_name));
    }
    return *artifact;
}

[[nodiscard]] shielded::BridgeDataArtifact ParseBridgeDataArtifactOrThrow(const UniValue& value,
                                                                          std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    shielded::BridgeDataArtifact artifact;
    const UniValue& version_value = FindValue(value, "version");
    if (!version_value.isNull()) {
        const int64_t version = version_value.getInt<int64_t>();
        if (version != 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.version must be 1", field_name));
        }
        artifact.version = static_cast<uint8_t>(version);
    }

    artifact.kind = ParseBridgeDataArtifactKindOrThrow(FindValue(value, "kind"), strprintf("%s.kind", field_name));
    artifact.statement_hash = ParseHashV(FindValue(value, "statement_hash"), strprintf("%s.statement_hash", field_name));
    artifact.data_root = ParseHashV(FindValue(value, "data_root"), strprintf("%s.data_root", field_name));
    artifact.payload_commitment = ParseHashV(FindValue(value, "payload_commitment"), strprintf("%s.payload_commitment", field_name));
    artifact.artifact_commitment = ParseHashV(FindValue(value, "artifact_commitment"), strprintf("%s.artifact_commitment", field_name));
    artifact.payload_size_bytes = ParsePositiveUint32OrThrow(FindValue(value, "payload_size_bytes"),
                                                             strprintf("%s.payload_size_bytes", field_name));
    const UniValue& auxiliary_size_value = FindValue(value, "auxiliary_data_size_bytes");
    if (!auxiliary_size_value.isNull()) {
        const int64_t auxiliary_size = auxiliary_size_value.getInt<int64_t>();
        if (auxiliary_size < 0 || auxiliary_size > std::numeric_limits<uint32_t>::max()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s.auxiliary_data_size_bytes must be a non-negative integer", field_name));
        }
        artifact.auxiliary_data_size_bytes = static_cast<uint32_t>(auxiliary_size);
    }
    if (!artifact.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not a valid bridge data artifact", field_name));
    }
    return artifact;
}

[[nodiscard]] std::optional<shielded::BridgeDataArtifact> ParseBridgeDataArtifactSelectorOrThrow(const UniValue& value,
                                                                                                  std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    const UniValue& artifact_hex_value = FindValue(value, "data_artifact_hex");
    const UniValue& artifact_value = FindValue(value, "data_artifact");
    const size_t selector_count = (!artifact_hex_value.isNull() ? 1U : 0U) +
                                  (!artifact_value.isNull() ? 1U : 0U);
    if (selector_count == 0) return std::nullopt;
    if (selector_count != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must include exactly one of data_artifact_hex or data_artifact", field_name));
    }
    if (!artifact_hex_value.isNull()) {
        return DecodeBridgeDataArtifactOrThrow(artifact_hex_value);
    }
    if (!artifact_value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.data_artifact must be an object", field_name));
    }
    return ParseBridgeDataArtifactOrThrow(artifact_value, strprintf("%s.data_artifact", field_name));
}

[[nodiscard]] shielded::BridgeDataArtifact BuildBridgeDataArtifactOrThrow(const shielded::BridgeBatchStatement& statement,
                                                                          const UniValue& value,
                                                                          std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    const auto kind = ParseBridgeDataArtifactKindOrThrow(FindValue(value, "kind"), strprintf("%s.kind", field_name));
    const uint256 payload_commitment = ParseBridgeArtifactCommitmentOrThrow(value, field_name, "payload_commitment", "payload_hex");
    const uint256 artifact_commitment = ParseBridgeArtifactCommitmentOrThrow(value, field_name, "artifact_commitment", "artifact_hex");
    const uint32_t payload_size_bytes = ParsePositiveUint32OrThrow(FindValue(value, "payload_size_bytes"),
                                                                   strprintf("%s.payload_size_bytes", field_name));
    uint32_t auxiliary_data_size_bytes{0};
    const UniValue& auxiliary_size_value = FindValue(value, "auxiliary_data_size_bytes");
    if (!auxiliary_size_value.isNull()) {
        const int64_t auxiliary_size = auxiliary_size_value.getInt<int64_t>();
        if (auxiliary_size < 0 || auxiliary_size > std::numeric_limits<uint32_t>::max()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s.auxiliary_data_size_bytes must be a non-negative integer", field_name));
        }
        auxiliary_data_size_bytes = static_cast<uint32_t>(auxiliary_size);
    }
    const auto artifact = shielded::BuildBridgeDataArtifact(statement,
                                                            kind,
                                                            payload_commitment,
                                                            artifact_commitment,
                                                            payload_size_bytes,
                                                            auxiliary_data_size_bytes);
    if (!artifact.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("failed to build a valid bridge data artifact from %s", field_name));
    }
    return *artifact;
}

[[nodiscard]] std::vector<shielded::BridgeProofArtifact> ParseBridgeProofArtifactArrayOrThrow(const UniValue& value,
                                                                                               std::string_view field_name)
{
    if (value.isNull()) return {};
    if (!value.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an array", field_name));
    }

    std::vector<shielded::BridgeProofArtifact> artifacts;
    artifacts.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        const UniValue& entry = value[i];
        if (!entry.isObject()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s[%d] must be an object", field_name, i));
        }
        const auto artifact = ParseBridgeProofArtifactSelectorOrThrow(entry, strprintf("%s[%d]", field_name, i));
        if (!artifact.has_value()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s[%d] must include exactly one of proof_artifact_hex or proof_artifact", field_name, i));
        }
        artifacts.push_back(*artifact);
    }
    return artifacts;
}

[[nodiscard]] std::vector<shielded::BridgeDataArtifact> ParseBridgeDataArtifactArrayOrThrow(const UniValue& value,
                                                                                             std::string_view field_name)
{
    if (value.isNull()) return {};
    if (!value.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an array", field_name));
    }

    std::vector<shielded::BridgeDataArtifact> artifacts;
    artifacts.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        const UniValue& entry = value[i];
        if (!entry.isObject()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s[%d] must be an object", field_name, i));
        }
        const auto artifact = ParseBridgeDataArtifactSelectorOrThrow(entry, strprintf("%s[%d]", field_name, i));
        if (!artifact.has_value()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s[%d] must include exactly one of data_artifact_hex or data_artifact", field_name, i));
        }
        artifacts.push_back(*artifact);
    }
    return artifacts;
}

[[nodiscard]] shielded::BridgeAggregateArtifactBundle ParseBridgeAggregateArtifactBundleOrThrow(const UniValue& value,
                                                                                                std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    shielded::BridgeAggregateArtifactBundle bundle;
    const UniValue& version_value = FindValue(value, "version");
    if (!version_value.isNull()) {
        const int64_t version = version_value.getInt<int64_t>();
        if (version != 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.version must be 1", field_name));
        }
        bundle.version = static_cast<uint8_t>(version);
    }

    bundle.statement_hash = ParseHashV(FindValue(value, "statement_hash"), strprintf("%s.statement_hash", field_name));
    bundle.proof_artifact_root = ParseHashV(FindValue(value, "proof_artifact_root"), strprintf("%s.proof_artifact_root", field_name));
    bundle.data_artifact_root = ParseHashV(FindValue(value, "data_artifact_root"), strprintf("%s.data_artifact_root", field_name));
    bundle.proof_artifact_count = ParseNonNegativeUint32OrThrow(FindValue(value, "proof_artifact_count"),
                                                                strprintf("%s.proof_artifact_count", field_name));
    bundle.data_artifact_count = ParseNonNegativeUint32OrThrow(FindValue(value, "data_artifact_count"),
                                                               strprintf("%s.data_artifact_count", field_name));
    bundle.proof_payload_bytes = ParseNonNegativeUint64OrThrow(FindValue(value, "proof_payload_bytes"),
                                                               strprintf("%s.proof_payload_bytes", field_name));
    bundle.proof_auxiliary_bytes = ParseNonNegativeUint64OrThrow(FindValue(value, "proof_auxiliary_bytes"),
                                                                 strprintf("%s.proof_auxiliary_bytes", field_name));
    bundle.data_availability_payload_bytes = ParseNonNegativeUint64OrThrow(FindValue(value, "data_availability_payload_bytes"),
                                                                           strprintf("%s.data_availability_payload_bytes", field_name));
    bundle.data_auxiliary_bytes = ParseNonNegativeUint64OrThrow(FindValue(value, "data_auxiliary_bytes"),
                                                                strprintf("%s.data_auxiliary_bytes", field_name));
    if (!bundle.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not a valid bridge aggregate artifact bundle", field_name));
    }
    return bundle;
}

[[nodiscard]] std::optional<shielded::BridgeAggregateArtifactBundle> ParseBridgeAggregateArtifactBundleSelectorOrThrow(
    const UniValue& value,
    std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    const UniValue& bundle_hex_value = FindValue(value, "artifact_bundle_hex");
    const UniValue& bundle_value = FindValue(value, "artifact_bundle");
    const size_t selector_count = (!bundle_hex_value.isNull() ? 1U : 0U) +
                                  (!bundle_value.isNull() ? 1U : 0U);
    if (selector_count == 0) return std::nullopt;
    if (selector_count != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must include exactly one of artifact_bundle_hex or artifact_bundle", field_name));
    }
    if (!bundle_hex_value.isNull()) {
        return DecodeBridgeAggregateArtifactBundleOrThrow(bundle_hex_value);
    }
    if (!bundle_value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.artifact_bundle must be an object", field_name));
    }
    return ParseBridgeAggregateArtifactBundleOrThrow(bundle_value, strprintf("%s.artifact_bundle", field_name));
}

[[nodiscard]] shielded::BridgeAggregateArtifactBundle BuildBridgeAggregateArtifactBundleOrThrow(
    const shielded::BridgeBatchStatement& statement,
    const UniValue& value,
    std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    const auto proof_artifacts = ParseBridgeProofArtifactArrayOrThrow(FindValue(value, "proof_artifacts"),
                                                                      strprintf("%s.proof_artifacts", field_name));
    const auto data_artifacts = ParseBridgeDataArtifactArrayOrThrow(FindValue(value, "data_artifacts"),
                                                                    strprintf("%s.data_artifacts", field_name));
    const auto bundle = shielded::BuildBridgeAggregateArtifactBundle(statement,
                                                                     Span<const shielded::BridgeProofArtifact>{proof_artifacts.data(), proof_artifacts.size()},
                                                                     Span<const shielded::BridgeDataArtifact>{data_artifacts.data(), data_artifacts.size()});
    if (!bundle.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("failed to build a valid bridge aggregate artifact bundle from %s", field_name));
    }
    return *bundle;
}

[[nodiscard]] shielded::BridgeProverSample ParseBridgeProverSampleOrThrow(const UniValue& value,
                                                                          std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    shielded::BridgeProverSample sample;
    const UniValue& version_value = FindValue(value, "version");
    if (!version_value.isNull()) {
        const int64_t version = version_value.getInt<int64_t>();
        if (version != 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.version must be 1", field_name));
        }
        sample.version = static_cast<uint8_t>(version);
    }

    sample.statement_hash = ParseHashV(FindValue(value, "statement_hash"), strprintf("%s.statement_hash", field_name));
    sample.proof_artifact_id = ParseHashV(FindValue(value, "proof_artifact_id"), strprintf("%s.proof_artifact_id", field_name));
    sample.proof_system_id = ParseHashV(FindValue(value, "proof_system_id"), strprintf("%s.proof_system_id", field_name));
    sample.verifier_key_hash = ParseHashV(FindValue(value, "verifier_key_hash"), strprintf("%s.verifier_key_hash", field_name));
    sample.artifact_storage_bytes = ParsePositiveUint64OrThrow(FindValue(value, "artifact_storage_bytes"),
                                                               strprintf("%s.artifact_storage_bytes", field_name));
    sample.native_millis = ParseNonNegativeUint64OrThrow(FindValue(value, "native_millis"), strprintf("%s.native_millis", field_name));
    sample.cpu_millis = ParseNonNegativeUint64OrThrow(FindValue(value, "cpu_millis"), strprintf("%s.cpu_millis", field_name));
    sample.gpu_millis = ParseNonNegativeUint64OrThrow(FindValue(value, "gpu_millis"), strprintf("%s.gpu_millis", field_name));
    sample.network_millis = ParseNonNegativeUint64OrThrow(FindValue(value, "network_millis"), strprintf("%s.network_millis", field_name));
    sample.peak_memory_bytes = ParseNonNegativeUint64OrThrow(FindValue(value, "peak_memory_bytes"),
                                                             strprintf("%s.peak_memory_bytes", field_name));
    if (!sample.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not a valid bridge prover sample", field_name));
    }
    return sample;
}

[[nodiscard]] std::optional<shielded::BridgeProverSample> ParseBridgeProverSampleSelectorOrThrow(const UniValue& value,
                                                                                                  std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    const UniValue& sample_hex_value = FindValue(value, "prover_sample_hex");
    const UniValue& sample_value = FindValue(value, "prover_sample");
    const size_t selector_count = (!sample_hex_value.isNull() ? 1U : 0U) +
                                  (!sample_value.isNull() ? 1U : 0U);
    if (selector_count == 0) return std::nullopt;
    if (selector_count != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must include exactly one of prover_sample_hex or prover_sample", field_name));
    }
    if (!sample_hex_value.isNull()) {
        return DecodeBridgeProverSampleOrThrow(sample_hex_value);
    }
    if (!sample_value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.prover_sample must be an object", field_name));
    }
    return ParseBridgeProverSampleOrThrow(sample_value, strprintf("%s.prover_sample", field_name));
}

[[nodiscard]] shielded::BridgeProverSample BuildBridgeProverSampleOrThrow(const UniValue& value,
                                                                          std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    const auto artifact = ParseBridgeProofArtifactSelectorOrThrow(value, field_name);
    if (!artifact.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must include exactly one of proof_artifact_hex or proof_artifact", field_name));
    }

    uint64_t native_millis = ParseNonNegativeUint64OrThrow(FindValue(value, "native_millis"),
                                                           strprintf("%s.native_millis", field_name));
    uint64_t cpu_millis = ParseNonNegativeUint64OrThrow(FindValue(value, "cpu_millis"),
                                                        strprintf("%s.cpu_millis", field_name));
    uint64_t gpu_millis = ParseNonNegativeUint64OrThrow(FindValue(value, "gpu_millis"),
                                                        strprintf("%s.gpu_millis", field_name));
    uint64_t network_millis = ParseNonNegativeUint64OrThrow(FindValue(value, "network_millis"),
                                                            strprintf("%s.network_millis", field_name));
    uint64_t peak_memory_bytes = ParseNonNegativeUint64OrThrow(FindValue(value, "peak_memory_bytes"),
                                                               strprintf("%s.peak_memory_bytes", field_name));

    const UniValue& prover_template_name_value = FindValue(value, "prover_template_name");
    if (!prover_template_name_value.isNull()) {
        if (!prover_template_name_value.isStr()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s.prover_template_name must be a string", field_name));
        }
        const auto* prover_template = FindBridgeProverTemplate(prover_template_name_value.get_str());
        if (prover_template == nullptr) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s.prover_template_name is not a supported built-in prover template", field_name));
        }
        const auto* adapter_template = FindBridgeProofAdapterTemplate(prover_template->proof_adapter_name);
        if (adapter_template == nullptr) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s.prover_template_name references an unknown proof adapter", field_name));
        }
        const auto expected_adapter = BuildBridgeProofAdapterFromTemplateOrThrow(*adapter_template);
        if (shielded::ComputeBridgeProofAdapterId(expected_adapter) != shielded::ComputeBridgeProofAdapterId(artifact->adapter)) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("%s.prover_template_name expects proof_adapter_name %s but the selected artifact uses a different proof adapter",
                          field_name,
                          prover_template->proof_adapter_name));
        }

        native_millis = prover_template->native_millis;
        cpu_millis = prover_template->cpu_millis;
        gpu_millis = prover_template->gpu_millis;
        network_millis = prover_template->network_millis;
        peak_memory_bytes = prover_template->peak_memory_bytes;

        const UniValue& native_millis_value = FindValue(value, "native_millis");
        if (!native_millis_value.isNull()) {
            native_millis = ParseNonNegativeUint64OrThrow(native_millis_value, strprintf("%s.native_millis", field_name));
        }
        const UniValue& cpu_millis_value = FindValue(value, "cpu_millis");
        if (!cpu_millis_value.isNull()) {
            cpu_millis = ParseNonNegativeUint64OrThrow(cpu_millis_value, strprintf("%s.cpu_millis", field_name));
        }
        const UniValue& gpu_millis_value = FindValue(value, "gpu_millis");
        if (!gpu_millis_value.isNull()) {
            gpu_millis = ParseNonNegativeUint64OrThrow(gpu_millis_value, strprintf("%s.gpu_millis", field_name));
        }
        const UniValue& network_millis_value = FindValue(value, "network_millis");
        if (!network_millis_value.isNull()) {
            network_millis = ParseNonNegativeUint64OrThrow(network_millis_value, strprintf("%s.network_millis", field_name));
        }
        const UniValue& peak_memory_bytes_value = FindValue(value, "peak_memory_bytes");
        if (!peak_memory_bytes_value.isNull()) {
            peak_memory_bytes = ParseNonNegativeUint64OrThrow(peak_memory_bytes_value,
                                                              strprintf("%s.peak_memory_bytes", field_name));
        }
    }

    const auto sample = shielded::BuildBridgeProverSample(*artifact,
                                                          native_millis,
                                                          cpu_millis,
                                                          gpu_millis,
                                                          network_millis,
                                                          peak_memory_bytes);
    if (!sample.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("failed to build a valid bridge prover sample from %s", field_name));
    }
    return *sample;
}

[[maybe_unused]] [[nodiscard]] std::vector<shielded::BridgeProverSample> ParseBridgeProverSamplesOrThrow(const UniValue& value,
                                                                                         std::string_view field_name)
{
    if (!value.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an array", field_name));
    }
    std::vector<shielded::BridgeProverSample> samples;
    samples.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        const auto sample = ParseBridgeProverSampleSelectorOrThrow(value[i], strprintf("%s[%d]", field_name, i));
        if (!sample.has_value()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s[%d] must include exactly one of prover_sample_hex or prover_sample",
                                         field_name,
                                         i));
        }
        samples.push_back(*sample);
    }
    return samples;
}

[[nodiscard]] shielded::BridgeProverProfile ParseBridgeProverProfileOrThrow(const UniValue& value,
                                                                            std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    shielded::BridgeProverProfile profile;
    const UniValue& version_value = FindValue(value, "version");
    if (!version_value.isNull()) {
        const int64_t version = version_value.getInt<int64_t>();
        if (version != 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.version must be 1", field_name));
        }
        profile.version = static_cast<uint8_t>(version);
    }

    profile.statement_hash = ParseHashV(FindValue(value, "statement_hash"), strprintf("%s.statement_hash", field_name));
    profile.sample_count = ParsePositiveUint32OrThrow(FindValue(value, "sample_count"), strprintf("%s.sample_count", field_name));
    profile.sample_root = ParseHashV(FindValue(value, "sample_root"), strprintf("%s.sample_root", field_name));
    profile.total_artifact_storage_bytes = ParsePositiveUint64OrThrow(FindValue(value, "total_artifact_storage_bytes"),
                                                                      strprintf("%s.total_artifact_storage_bytes", field_name));
    profile.total_peak_memory_bytes = ParseNonNegativeUint64OrThrow(FindValue(value, "total_peak_memory_bytes"),
                                                                    strprintf("%s.total_peak_memory_bytes", field_name));
    profile.max_peak_memory_bytes = ParseNonNegativeUint64OrThrow(FindValue(value, "max_peak_memory_bytes"),
                                                                  strprintf("%s.max_peak_memory_bytes", field_name));
    profile.native_millis_per_settlement = ParseNonNegativeUint64OrThrow(FindValue(value, "native_millis_per_settlement"),
                                                                         strprintf("%s.native_millis_per_settlement", field_name));
    profile.cpu_millis_per_settlement = ParseNonNegativeUint64OrThrow(FindValue(value, "cpu_millis_per_settlement"),
                                                                      strprintf("%s.cpu_millis_per_settlement", field_name));
    profile.gpu_millis_per_settlement = ParseNonNegativeUint64OrThrow(FindValue(value, "gpu_millis_per_settlement"),
                                                                      strprintf("%s.gpu_millis_per_settlement", field_name));
    profile.network_millis_per_settlement = ParseNonNegativeUint64OrThrow(FindValue(value, "network_millis_per_settlement"),
                                                                          strprintf("%s.network_millis_per_settlement", field_name));
    if (!profile.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not a valid bridge prover profile", field_name));
    }
    return profile;
}

[[nodiscard]] std::optional<shielded::BridgeProverProfile> ParseBridgeProverProfileSelectorOrThrow(const UniValue& value,
                                                                                                    std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    const UniValue& profile_hex_value = FindValue(value, "prover_profile_hex");
    const UniValue& profile_value = FindValue(value, "prover_profile");
    const size_t selector_count = (!profile_hex_value.isNull() ? 1U : 0U) +
                                  (!profile_value.isNull() ? 1U : 0U);
    if (selector_count == 0) return std::nullopt;
    if (selector_count != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must include exactly one of prover_profile_hex or prover_profile", field_name));
    }
    if (!profile_hex_value.isNull()) {
        return DecodeBridgeProverProfileOrThrow(profile_hex_value);
    }
    if (!profile_value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.prover_profile must be an object", field_name));
    }
    return ParseBridgeProverProfileOrThrow(profile_value, strprintf("%s.prover_profile", field_name));
}

[[maybe_unused]] [[nodiscard]] shielded::BridgeProverProfile BuildBridgeProverProfileOrThrow(const UniValue& value,
                                                                            std::string_view field_name)
{
    if (!value.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an array", field_name));
    }
    std::vector<shielded::BridgeProverSample> samples;
    samples.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        const std::string item_name = strprintf("%s[%d]", field_name, i);
        const auto sample = ParseBridgeProverSampleSelectorOrThrow(value[i], item_name);
        if (sample.has_value()) {
            samples.push_back(*sample);
            continue;
        }
        samples.push_back(BuildBridgeProverSampleOrThrow(value[i], item_name));
    }
    const auto profile = shielded::BuildBridgeProverProfile(samples);
    if (!profile.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("failed to build a valid bridge prover profile from %s", field_name));
    }
    return *profile;
}

[[nodiscard]] shielded::BridgeProverMetricSummary ParseBridgeProverMetricSummaryOrThrow(const UniValue& value,
                                                                                        std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    shielded::BridgeProverMetricSummary summary;
    summary.min = ParseNonNegativeUint64OrThrow(FindValue(value, "min"), strprintf("%s.min", field_name));
    summary.p50 = ParseNonNegativeUint64OrThrow(FindValue(value, "p50"), strprintf("%s.p50", field_name));
    summary.p90 = ParseNonNegativeUint64OrThrow(FindValue(value, "p90"), strprintf("%s.p90", field_name));
    summary.max = ParseNonNegativeUint64OrThrow(FindValue(value, "max"), strprintf("%s.max", field_name));
    if (!summary.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not a valid bridge prover metric summary", field_name));
    }
    return summary;
}

[[nodiscard]] shielded::BridgeProverBenchmark ParseBridgeProverBenchmarkOrThrow(const UniValue& value,
                                                                                std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    shielded::BridgeProverBenchmark benchmark;
    const UniValue& version_value = FindValue(value, "version");
    if (!version_value.isNull()) {
        const int64_t version = version_value.getInt<int64_t>();
        if (version != 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.version must be 1", field_name));
        }
        benchmark.version = static_cast<uint8_t>(version);
    }

    benchmark.statement_hash = ParseHashV(FindValue(value, "statement_hash"), strprintf("%s.statement_hash", field_name));
    benchmark.profile_count = ParsePositiveUint32OrThrow(FindValue(value, "profile_count"), strprintf("%s.profile_count", field_name));
    benchmark.sample_count_per_profile = ParsePositiveUint32OrThrow(FindValue(value, "sample_count_per_profile"),
                                                                    strprintf("%s.sample_count_per_profile", field_name));
    benchmark.profile_root = ParseHashV(FindValue(value, "profile_root"), strprintf("%s.profile_root", field_name));
    benchmark.artifact_storage_bytes_per_profile = ParsePositiveUint64OrThrow(FindValue(value, "artifact_storage_bytes_per_profile"),
                                                                              strprintf("%s.artifact_storage_bytes_per_profile", field_name));
    benchmark.total_peak_memory_bytes = ParseBridgeProverMetricSummaryOrThrow(FindValue(value, "total_peak_memory_bytes"),
                                                                              strprintf("%s.total_peak_memory_bytes", field_name));
    benchmark.max_peak_memory_bytes = ParseBridgeProverMetricSummaryOrThrow(FindValue(value, "max_peak_memory_bytes"),
                                                                            strprintf("%s.max_peak_memory_bytes", field_name));
    benchmark.native_millis_per_settlement = ParseBridgeProverMetricSummaryOrThrow(FindValue(value, "native_millis_per_settlement"),
                                                                                   strprintf("%s.native_millis_per_settlement", field_name));
    benchmark.cpu_millis_per_settlement = ParseBridgeProverMetricSummaryOrThrow(FindValue(value, "cpu_millis_per_settlement"),
                                                                                strprintf("%s.cpu_millis_per_settlement", field_name));
    benchmark.gpu_millis_per_settlement = ParseBridgeProverMetricSummaryOrThrow(FindValue(value, "gpu_millis_per_settlement"),
                                                                                strprintf("%s.gpu_millis_per_settlement", field_name));
    benchmark.network_millis_per_settlement = ParseBridgeProverMetricSummaryOrThrow(FindValue(value, "network_millis_per_settlement"),
                                                                                    strprintf("%s.network_millis_per_settlement", field_name));
    if (!benchmark.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not a valid bridge prover benchmark", field_name));
    }
    return benchmark;
}

[[nodiscard]] std::optional<shielded::BridgeProverBenchmark> ParseBridgeProverBenchmarkSelectorOrThrow(const UniValue& value,
                                                                                                        std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    const UniValue& benchmark_hex_value = FindValue(value, "prover_benchmark_hex");
    const UniValue& benchmark_value = FindValue(value, "prover_benchmark");
    const size_t selector_count = (!benchmark_hex_value.isNull() ? 1U : 0U) +
                                  (!benchmark_value.isNull() ? 1U : 0U);
    if (selector_count == 0) return std::nullopt;
    if (selector_count != 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must include exactly one of prover_benchmark_hex or prover_benchmark", field_name));
    }
    if (!benchmark_hex_value.isNull()) {
        return DecodeBridgeProverBenchmarkOrThrow(benchmark_hex_value);
    }
    if (!benchmark_value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.prover_benchmark must be an object", field_name));
    }
    return ParseBridgeProverBenchmarkOrThrow(benchmark_value, strprintf("%s.prover_benchmark", field_name));
}

[[nodiscard]] shielded::BridgeProverBenchmark BuildBridgeProverBenchmarkOrThrow(const UniValue& value,
                                                                                std::string_view field_name)
{
    if (!value.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an array", field_name));
    }
    std::vector<shielded::BridgeProverProfile> profiles;
    profiles.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        const std::string item_name = strprintf("%s[%d]", field_name, i);
        const auto profile = ParseBridgeProverProfileSelectorOrThrow(value[i], item_name);
        if (profile.has_value()) {
            profiles.push_back(*profile);
            continue;
        }
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s[%d] must include exactly one of prover_profile_hex or prover_profile",
                                     field_name,
                                     i));
    }
    const auto benchmark = shielded::BuildBridgeProverBenchmark(profiles);
    if (!benchmark.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("failed to build a valid bridge prover benchmark from %s", field_name));
    }
    return *benchmark;
}

[[nodiscard]] shielded::BridgeProofDescriptor ParseBridgeProofDescriptorOrThrow(const UniValue& value,
                                                                                std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    const auto artifact = ParseBridgeProofArtifactSelectorOrThrow(value, field_name);
    const auto adapter = ParseBridgeProofAdapterSelectorOrThrow(value, field_name);
    const UniValue& proof_system_id_value = FindValue(value, "proof_system_id");
    const UniValue& proof_profile_hex_value = FindValue(value, "proof_profile_hex");
    const UniValue& proof_profile_value = FindValue(value, "proof_profile");
    const UniValue& verifier_key_hash_value = FindValue(value, "verifier_key_hash");
    const bool has_proof_system_selector = !proof_system_id_value.isNull() ||
                                           !proof_profile_hex_value.isNull() ||
                                           !proof_profile_value.isNull();
    if (artifact.has_value()) {
        if (adapter.has_value() || has_proof_system_selector || !verifier_key_hash_value.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s cannot mix proof_artifact_* selectors with verifier_key_hash, proof_adapter_*, proof_system_id, proof_profile_hex, or proof_profile",
                                         field_name));
        }
        const auto descriptor = shielded::BuildBridgeProofDescriptorFromArtifact(*artifact);
        if (!descriptor.has_value()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s does not produce a valid proof descriptor", field_name));
        }
        return *descriptor;
    }
    if (adapter.has_value() && has_proof_system_selector) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s cannot mix proof_adapter_* selectors with proof_system_id, proof_profile_hex, or proof_profile",
                                     field_name));
    }

    const uint256 verifier_key_hash = ParseHashV(verifier_key_hash_value, strprintf("%s.verifier_key_hash", field_name));
    if (adapter.has_value()) {
        const auto descriptor = shielded::BuildBridgeProofDescriptorFromAdapter(*adapter, verifier_key_hash);
        if (!descriptor.has_value()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s does not produce a valid proof descriptor", field_name));
        }
        return *descriptor;
    }

    shielded::BridgeProofDescriptor parsed_descriptor;
    parsed_descriptor.proof_system_id = ParseBridgeProofSystemIdOrThrow(value, field_name);
    parsed_descriptor.verifier_key_hash = verifier_key_hash;
    if (!parsed_descriptor.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must contain non-zero proof_system_id and verifier_key_hash", field_name));
    }
    return parsed_descriptor;
}

[[nodiscard]] std::vector<shielded::BridgeProofDescriptor> ParseBridgeProofDescriptorArrayOrThrow(const UniValue& value,
                                                                                                   std::string_view field_name)
{
    if (!value.isArray() || value.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a non-empty array", field_name));
    }

    std::set<std::pair<uint256, uint256>> seen_descriptors;
    std::vector<shielded::BridgeProofDescriptor> descriptors;
    descriptors.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        const auto descriptor = ParseBridgeProofDescriptorOrThrow(value[i], strprintf("%s[%u]", field_name, i));
        const auto [it, inserted] = seen_descriptors.emplace(descriptor.proof_system_id, descriptor.verifier_key_hash);
        if (!inserted) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s[%u] duplicates a prior descriptor", field_name, i));
        }
        descriptors.push_back(descriptor);
    }
    return descriptors;
}

[[nodiscard]] shielded::BridgeProofPolicyCommitment ParseBridgeProofPolicyCommitmentOrThrow(const UniValue& value,
                                                                                            std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    shielded::BridgeProofPolicyCommitment proof_policy;
    const UniValue& version_value = FindValue(value, "version");
    if (!version_value.isNull()) {
        const int64_t version = version_value.getInt<int64_t>();
        if (version != 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.version must be 1", field_name));
        }
        proof_policy.version = static_cast<uint8_t>(version);
    }

    const UniValue& descriptor_count_value = FindValue(value, "descriptor_count");
    if (descriptor_count_value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.descriptor_count is required", field_name));
    }
    const int64_t descriptor_count = descriptor_count_value.getInt<int64_t>();
    if (descriptor_count <= 0 || descriptor_count > std::numeric_limits<uint32_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.descriptor_count must be a positive integer", field_name));
    }
    proof_policy.descriptor_count = static_cast<uint32_t>(descriptor_count);

    const UniValue& required_receipts_value = FindValue(value, "required_receipts");
    if (required_receipts_value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.required_receipts is required", field_name));
    }
    const int64_t required_receipts = required_receipts_value.getInt<int64_t>();
    if (required_receipts <= 0 || required_receipts > std::numeric_limits<uint32_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.required_receipts must be a positive integer", field_name));
    }
    proof_policy.required_receipts = static_cast<uint32_t>(required_receipts);
    proof_policy.descriptor_root = ParseHashV(FindValue(value, "descriptor_root"), strprintf("%s.descriptor_root", field_name));

    if (!proof_policy.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must include a non-zero descriptor_root and a valid required_receipts/descriptor_count pair",
                                     field_name));
    }
    return proof_policy;
}

[[nodiscard]] shielded::BridgeBatchAggregateCommitment ParseBridgeBatchAggregateCommitmentOrThrow(
    const UniValue& value,
    const uint256& default_action_root,
    const uint256& default_data_availability_root,
    const shielded::BridgeProofPolicyCommitment& default_proof_policy,
    std::string_view field_name)
{
    const auto default_commitment = shielded::BuildDefaultBridgeBatchAggregateCommitment(default_action_root,
                                                                                         default_data_availability_root,
                                                                                         default_proof_policy);
    if (!default_commitment.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("failed to build a default aggregate commitment for %s", field_name));
    }
    if (value.isNull()) {
        return *default_commitment;
    }
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    auto aggregate = *default_commitment;
    const UniValue& version_value = FindValue(value, "version");
    if (!version_value.isNull()) {
        const int64_t version = version_value.getInt<int64_t>();
        if (version != 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.version must be 1", field_name));
        }
        aggregate.version = static_cast<uint8_t>(version);
    }

    const UniValue& action_root_value = FindValue(value, "action_root");
    if (!action_root_value.isNull()) {
        aggregate.action_root = ParseHashV(action_root_value, strprintf("%s.action_root", field_name));
    }

    const UniValue& data_root_value = FindValue(value, "data_availability_root");
    if (!data_root_value.isNull()) {
        aggregate.data_availability_root = ParseHashV(data_root_value, strprintf("%s.data_availability_root", field_name));
    }

    const UniValue& recovery_root_value = FindValue(value, "recovery_or_exit_root");
    if (!recovery_root_value.isNull()) {
        aggregate.recovery_or_exit_root = ParseHashV(recovery_root_value, strprintf("%s.recovery_or_exit_root", field_name));
    }

    const UniValue& policy_commitment_value = FindValue(value, "policy_commitment");
    if (!policy_commitment_value.isNull()) {
        aggregate.policy_commitment = ParseHashV(policy_commitment_value, strprintf("%s.policy_commitment", field_name));
    }

    const UniValue& extension_flags_value = FindValue(value, "extension_flags");
    if (!extension_flags_value.isNull()) {
        const int64_t extension_flags = extension_flags_value.getInt<int64_t>();
        if (extension_flags < 0 || extension_flags > std::numeric_limits<uint32_t>::max()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s.extension_flags must be an unsigned 32-bit integer", field_name));
        }
        aggregate.extension_flags = static_cast<uint32_t>(extension_flags);
    } else {
        aggregate.extension_flags = 0;
        if (!aggregate.recovery_or_exit_root.IsNull()) {
            aggregate.extension_flags |= shielded::BridgeBatchAggregateCommitment::FLAG_HAS_RECOVERY_OR_EXIT_ROOT;
        }
        if (!aggregate.policy_commitment.IsNull()) {
            aggregate.extension_flags |= shielded::BridgeBatchAggregateCommitment::FLAG_HAS_POLICY_COMMITMENT;
        }
        if (aggregate.action_root != default_action_root) {
            aggregate.extension_flags |= shielded::BridgeBatchAggregateCommitment::FLAG_CUSTOM_ACTION_ROOT;
        }
        if (aggregate.data_availability_root != default_data_availability_root) {
            aggregate.extension_flags |=
                shielded::BridgeBatchAggregateCommitment::FLAG_CUSTOM_DATA_AVAILABILITY_ROOT;
        }
    }

    if (!aggregate.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s does not produce a valid aggregate commitment", field_name));
    }
    return aggregate;
}

[[nodiscard]] shielded::BridgeBatchStatement BuildBridgeBatchStatementOrThrow(shielded::BridgeDirection direction,
                                                                              Span<const shielded::BridgeBatchLeaf> leaves,
                                                                              const shielded::BridgePlanIds& ids,
                                                                              const UniValue& options)
{
    const UniValue& value = FindValue(options, "external_statement");
    if (value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "external_statement is required");
    }
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "external_statement must be an object");
    }

    const auto commitment = BuildBridgeBatchCommitmentOrThrow(direction, leaves, ids, std::nullopt);

    shielded::BridgeBatchStatement statement;
    statement.direction = direction;
    statement.ids = ids;
    statement.entry_count = commitment.entry_count;
    statement.total_amount = commitment.total_amount;
    statement.batch_root = commitment.batch_root;
    statement.domain_id = ParseHashV(FindValue(value, "domain_id"), "external_statement.domain_id");

    const UniValue& source_epoch_value = FindValue(value, "source_epoch");
    if (source_epoch_value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "external_statement.source_epoch is required");
    }
    const int64_t source_epoch = source_epoch_value.getInt<int64_t>();
    if (source_epoch <= 0 || source_epoch > std::numeric_limits<uint32_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "external_statement.source_epoch must be a positive integer");
    }
    statement.source_epoch = static_cast<uint32_t>(source_epoch);
    statement.data_root = ParseHashV(FindValue(value, "data_root"), "external_statement.data_root");

    const UniValue& verifier_set_value = FindValue(value, "verifier_set");
    const UniValue& proof_policy_value = FindValue(value, "proof_policy");
    if (!verifier_set_value.isNull()) {
        statement.version = 2;
        statement.verifier_set = ParseBridgeVerifierSetCommitmentOrThrow(verifier_set_value, "external_statement.verifier_set");
    }
    if (!proof_policy_value.isNull()) {
        statement.version = statement.verifier_set.IsValid() ? 4 : 3;
        statement.proof_policy = ParseBridgeProofPolicyCommitmentOrThrow(proof_policy_value, "external_statement.proof_policy");
    }

    statement.aggregate_commitment = ParseBridgeBatchAggregateCommitmentOrThrow(
        FindValue(value, "aggregate_commitment"),
        statement.batch_root,
        statement.data_root,
        statement.proof_policy,
        "external_statement.aggregate_commitment");
    statement.version = 5;

    if (!statement.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to build a valid bridge batch statement");
    }
    return statement;
}

[[nodiscard]] std::vector<std::pair<ShieldedAddress, CAmount>> ParseShieldedRecipientAmountsOrThrow(
    const std::shared_ptr<CWallet>& pwallet,
    const UniValue& value,
    std::string_view field_name,
    size_t max_outputs,
    std::string_view limit_name)
{
    if (!value.isArray() || value.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a non-empty array", field_name));
    }
    if (value.size() > max_outputs) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s exceeds the %s output limit (%u > %u)",
                                     field_name,
                                     limit_name,
                                     static_cast<unsigned int>(value.size()),
                                     static_cast<unsigned int>(max_outputs)));
    }

    std::vector<std::pair<ShieldedAddress, CAmount>> recipients;
    recipients.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        const UniValue& entry = value[i];
        if (!entry.isObject()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s[%u] must be an object", field_name, i));
        }
        const UniValue& address_value = FindValue(entry, "address");
        if (!address_value.isStr()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s[%u].address must be a string", field_name, i));
        }
        auto recipient = ParseShieldedAddr(address_value.get_str());
        if (!recipient.has_value()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                               strprintf("%s[%u].address must be a valid shielded address", field_name, i));
        }
        if (!recipient->HasKEMPublicKey()) {
            LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
            mlkem::PublicKey kem_pk{};
            if (pwallet->m_shielded_wallet->GetKEMPublicKey(*recipient, kem_pk)) {
                std::copy(kem_pk.begin(), kem_pk.end(), recipient->kem_pk.begin());
            }
        }
        if (!recipient->HasKEMPublicKey()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s[%u].address must include a KEM public key or belong to this wallet",
                                         field_name,
                                         i));
        }

        const UniValue& amount_value = FindValue(entry, "amount");
        if (amount_value.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s[%u].amount is required", field_name, i));
        }
        const CAmount amount = AmountFromValue(amount_value);
        if (amount <= 0 || !MoneyRange(amount)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s[%u].amount must be a positive valid amount", field_name, i));
        }
        recipients.emplace_back(*recipient, amount);
    }
    return recipients;
}

[[nodiscard]] std::vector<std::pair<ShieldedAddress, CAmount>> ParseV2EgressRecipientsOrThrow(
    const std::shared_ptr<CWallet>& pwallet,
    const UniValue& value,
    std::string_view field_name)
{
    return ParseShieldedRecipientAmountsOrThrow(pwallet,
                                                value,
                                                field_name,
                                                shielded::v2::MAX_EGRESS_OUTPUTS,
                                                "v2_egress_batch");
}

[[nodiscard]] std::vector<std::pair<ShieldedAddress, CAmount>> ParseV2IngressReserveOutputsOrThrow(
    const std::shared_ptr<CWallet>& pwallet,
    const UniValue& value,
    std::string_view field_name)
{
    return ParseShieldedRecipientAmountsOrThrow(pwallet,
                                                value,
                                                field_name,
                                                shielded::v2::MAX_BATCH_RESERVE_OUTPUTS,
                                                "v2_ingress_batch reserve");
}

[[nodiscard]] std::vector<std::pair<ShieldedAddress, CAmount>> ParseV2RebalanceReserveOutputsOrThrow(
    const std::shared_ptr<CWallet>& pwallet,
    const UniValue& value,
    std::string_view field_name)
{
    if (!value.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an array", field_name));
    }
    if (value.empty()) {
        return {};
    }
    return ParseShieldedRecipientAmountsOrThrow(pwallet,
                                                value,
                                                field_name,
                                                shielded::v2::MAX_BATCH_RESERVE_OUTPUTS,
                                                "v2_rebalance reserve");
}

[[nodiscard]] CAmount SignedAmountFromValueOrThrow(const UniValue& value)
{
    if (!value.isNum() && !value.isStr()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount is not a number or string");
    }

    CAmount amount;
    if (!ParseFixedPoint(value.getValStr(), 8, &amount)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    }
    if (!MoneyRangeSigned(amount)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount out of range");
    }
    return amount;
}

[[nodiscard]] std::vector<shielded::v2::ReserveDelta> ParseV2RebalanceReserveDeltasOrThrow(
    const UniValue& value,
    std::string_view field_name)
{
    if (!value.isArray() || value.size() < 2) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must be an array with at least two reserve deltas", field_name));
    }
    if (value.size() > shielded::v2::MAX_REBALANCE_DOMAINS) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s exceeds the v2_rebalance domain limit (%u > %u)",
                                     field_name,
                                     value.size(),
                                     shielded::v2::MAX_REBALANCE_DOMAINS));
    }

    std::vector<shielded::v2::ReserveDelta> reserve_deltas;
    reserve_deltas.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        if (!value[i].isObject()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s[%u] must be an object", field_name, i));
        }
        const UniValue& l2_id_value = FindValue(value[i], "l2_id");
        const UniValue& reserve_delta_value = FindValue(value[i], "reserve_delta");
        if (l2_id_value.isNull() || reserve_delta_value.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s[%u] requires l2_id and reserve_delta", field_name, i));
        }

        shielded::v2::ReserveDelta reserve_delta;
        reserve_delta.l2_id = ParseHashV(l2_id_value, strprintf("%s[%u].l2_id", field_name, i));
        reserve_delta.reserve_delta = SignedAmountFromValueOrThrow(reserve_delta_value);
        if (!reserve_delta.IsValid()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s[%u] is not a valid reserve delta", field_name, i));
        }
        reserve_deltas.push_back(std::move(reserve_delta));
    }

    std::sort(reserve_deltas.begin(), reserve_deltas.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.l2_id < rhs.l2_id;
    });
    if (!shielded::v2::ReserveDeltaSetIsCanonical(
            Span<const shielded::v2::ReserveDelta>{reserve_deltas.data(), reserve_deltas.size()})) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must be canonical, unique, and zero-sum", field_name));
    }
    return reserve_deltas;
}

[[nodiscard]] uint256 ComputeV2RebalanceReserveOutputRequestDigest(
    const std::vector<std::pair<ShieldedAddress, CAmount>>& reserve_outputs)
{
    HashWriter hw;
    hw << std::string{"BTX_RPC_Rebalance_Reserve_Output_Request_V1"};
    for (const auto& [address, amount] : reserve_outputs) {
        hw << address.pk_hash
           << address.kem_pk_hash
           << amount;
    }
    return hw.GetSHA256();
}

[[nodiscard]] uint256 DeriveDefaultV2RebalanceManifestDigest(
    std::string_view tag,
    Span<const shielded::v2::ReserveDelta> reserve_deltas,
    const std::vector<std::pair<ShieldedAddress, CAmount>>& reserve_outputs,
    uint32_t settlement_window)
{
    HashWriter hw;
    hw << std::string{tag}
       << settlement_window
       << shielded::v2::ComputeReserveDeltaRoot(reserve_deltas)
       << ComputeV2RebalanceReserveOutputRequestDigest(reserve_outputs);
    return hw.GetSHA256();
}

[[nodiscard]] shielded::v2::NettingManifest BuildV2RebalanceNettingManifestOrThrow(
    const std::vector<shielded::v2::ReserveDelta>& reserve_deltas,
    const std::vector<std::pair<ShieldedAddress, CAmount>>& reserve_outputs,
    const UniValue& options)
{
    uint32_t settlement_window = DEFAULT_V2_REBALANCE_SETTLEMENT_WINDOW;
    const UniValue& settlement_window_value = FindValue(options, "settlement_window");
    if (!settlement_window_value.isNull()) {
        const int raw = settlement_window_value.getInt<int>();
        if (raw <= 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "settlement_window must be positive");
        }
        settlement_window = static_cast<uint32_t>(raw);
    }

    const uint256 default_gross_flow_commitment = DeriveDefaultV2RebalanceManifestDigest(
        TAG_REBALANCE_MANIFEST_GROSS_FLOW,
        Span<const shielded::v2::ReserveDelta>{reserve_deltas.data(), reserve_deltas.size()},
        reserve_outputs,
        settlement_window);
    const uint256 default_authorization_digest = DeriveDefaultV2RebalanceManifestDigest(
        TAG_REBALANCE_MANIFEST_AUTH,
        Span<const shielded::v2::ReserveDelta>{reserve_deltas.data(), reserve_deltas.size()},
        reserve_outputs,
        settlement_window);

    shielded::v2::NettingManifest manifest;
    manifest.settlement_window = settlement_window;
    manifest.binding_kind = shielded::v2::SettlementBindingKind::NETTING_MANIFEST;
    manifest.gross_flow_commitment = FindValue(options, "gross_flow_commitment").isNull()
        ? default_gross_flow_commitment
        : ParseHashV(FindValue(options, "gross_flow_commitment"), "gross_flow_commitment");
    manifest.authorization_digest = FindValue(options, "authorization_digest").isNull()
        ? default_authorization_digest
        : ParseHashV(FindValue(options, "authorization_digest"), "authorization_digest");
    manifest.aggregate_net_delta = 0;
    manifest.domains.reserve(reserve_deltas.size());
    for (const auto& reserve_delta : reserve_deltas) {
        manifest.domains.push_back({reserve_delta.l2_id, reserve_delta.reserve_delta});
    }
    if (!manifest.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "options do not produce a valid netting manifest");
    }
    return manifest;
}

[[nodiscard]] std::vector<shielded::v2::V2EgressRecipient> BuildV2EgressRecipients(
    const std::vector<std::pair<ShieldedAddress, CAmount>>& shielded_recipients)
{
    std::vector<shielded::v2::V2EgressRecipient> recipients;
    recipients.reserve(shielded_recipients.size());
    for (const auto& [addr, amount] : shielded_recipients) {
        shielded::v2::V2EgressRecipient recipient;
        recipient.recipient_pk_hash = addr.pk_hash;
        recipient.recipient_kem_pk = addr.kem_pk;
        recipient.amount = amount;
        recipients.push_back(std::move(recipient));
    }
    return recipients;
}

[[nodiscard]] UniValue V2IngressLeafInputToUniValue(const shielded::v2::V2IngressLeafInput& leaf)
{
    UniValue out = BridgeBatchLeafToUniValue(leaf.bridge_leaf);
    out.pushKV("l2_id", leaf.l2_id.GetHex());
    out.pushKV("fee", ValueFromAmount(leaf.fee));
    return out;
}

[[nodiscard]] std::vector<shielded::v2::V2IngressLeafInput> ParseV2IngressLeafInputsOrThrow(
    const UniValue& value,
    std::string_view field_name)
{
    if (!value.isArray() || value.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a non-empty array", field_name));
    }
    if (value.size() > shielded::v2::MAX_BATCH_LEAVES) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s exceeds the v2_ingress_batch intent limit (%u > %u)",
                                     field_name,
                                     static_cast<unsigned int>(value.size()),
                                     static_cast<unsigned int>(shielded::v2::MAX_BATCH_LEAVES)));
    }

    std::vector<shielded::v2::V2IngressLeafInput> leaves;
    leaves.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        const UniValue& entry = value[i];
        if (!entry.isObject()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s[%u] must be an object", field_name, i));
        }

        shielded::v2::V2IngressLeafInput leaf;
        leaf.bridge_leaf.kind = shielded::BridgeBatchLeafKind::SHIELD_CREDIT;
        leaf.bridge_leaf.wallet_id = ParseHashV(FindValue(entry, "wallet_id"),
                                                strprintf("%s[%u].wallet_id", field_name, i));
        leaf.bridge_leaf.destination_id = ParseHashV(FindValue(entry, "destination_id"),
                                                     strprintf("%s[%u].destination_id", field_name, i));

        const UniValue& amount_value = FindValue(entry, "amount");
        if (amount_value.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s[%u].amount is required", field_name, i));
        }
        leaf.bridge_leaf.amount = AmountFromValue(amount_value);
        leaf.bridge_leaf.authorization_hash = ParseHashV(FindValue(entry, "authorization_hash"),
                                                         strprintf("%s[%u].authorization_hash", field_name, i));
        leaf.l2_id = ParseHashV(FindValue(entry, "l2_id"), strprintf("%s[%u].l2_id", field_name, i));

        const UniValue& fee_value = FindValue(entry, "fee");
        if (fee_value.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s[%u].fee is required", field_name, i));
        }
        leaf.fee = AmountFromValue(fee_value);
        if (!leaf.IsValid()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s[%u] is not a valid shield_credit ingress intent", field_name, i));
        }
        leaves.push_back(std::move(leaf));
    }
    return leaves;
}

[[nodiscard]] shielded::BridgeBatchStatement BuildV2EgressStatementOrThrow(
    const std::vector<std::pair<ShieldedAddress, CAmount>>& shielded_recipients,
    const UniValue& options)
{
    const UniValue& value = FindValue(options, "external_statement");
    if (value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "external_statement is required");
    }
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "external_statement must be an object");
    }

    shielded::v2::V2EgressStatementTemplate statement_template;
    statement_template.ids = ParseBridgePlanIdsOrThrow(options);
    statement_template.domain_id = ParseHashV(FindValue(value, "domain_id"), "external_statement.domain_id");

    const UniValue& source_epoch_value = FindValue(value, "source_epoch");
    if (source_epoch_value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "external_statement.source_epoch is required");
    }
    const int64_t source_epoch = source_epoch_value.getInt<int64_t>();
    if (source_epoch <= 0 || source_epoch > std::numeric_limits<uint32_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "external_statement.source_epoch must be a positive integer");
    }
    statement_template.source_epoch = static_cast<uint32_t>(source_epoch);
    statement_template.data_root = ParseHashV(FindValue(value, "data_root"), "external_statement.data_root");

    const UniValue& verifier_set_value = FindValue(value, "verifier_set");
    if (!verifier_set_value.isNull()) {
        statement_template.verifier_set = ParseBridgeVerifierSetCommitmentOrThrow(verifier_set_value,
                                                                                  "external_statement.verifier_set");
    }

    const UniValue& proof_policy_value = FindValue(value, "proof_policy");
    if (!proof_policy_value.isNull()) {
        statement_template.proof_policy = ParseBridgeProofPolicyCommitmentOrThrow(proof_policy_value,
                                                                                  "external_statement.proof_policy");
    }

    const auto recipients = BuildV2EgressRecipients(shielded_recipients);
    std::string reject_reason;
    auto statement = shielded::v2::BuildV2EgressStatement(
        statement_template,
        Span<const shielded::v2::V2EgressRecipient>{recipients.data(), recipients.size()},
        reject_reason);
    if (!statement.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("failed to build a valid v2_egress_batch statement: %s", reject_reason));
    }
    statement->aggregate_commitment = ParseBridgeBatchAggregateCommitmentOrThrow(
        FindValue(value, "aggregate_commitment"),
        statement->batch_root,
        statement->data_root,
        statement->proof_policy,
        "external_statement.aggregate_commitment");
    return *statement;
}

[[nodiscard]] shielded::BridgeBatchStatement BuildV2IngressStatementOrThrow(
    const std::vector<shielded::v2::V2IngressLeafInput>& ingress_leaves,
    const UniValue& options)
{
    const UniValue& value = FindValue(options, "external_statement");
    if (value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "external_statement is required");
    }
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "external_statement must be an object");
    }

    shielded::v2::V2IngressStatementTemplate statement_template;
    statement_template.ids = ParseBridgePlanIdsOrThrow(options);
    statement_template.domain_id = ParseHashV(FindValue(value, "domain_id"), "external_statement.domain_id");

    const UniValue& source_epoch_value = FindValue(value, "source_epoch");
    if (source_epoch_value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "external_statement.source_epoch is required");
    }
    const int64_t source_epoch = source_epoch_value.getInt<int64_t>();
    if (source_epoch <= 0 || source_epoch > std::numeric_limits<uint32_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "external_statement.source_epoch must be a positive integer");
    }
    statement_template.source_epoch = static_cast<uint32_t>(source_epoch);
    statement_template.data_root = ParseHashV(FindValue(value, "data_root"), "external_statement.data_root");

    const UniValue& verifier_set_value = FindValue(value, "verifier_set");
    if (!verifier_set_value.isNull()) {
        statement_template.verifier_set = ParseBridgeVerifierSetCommitmentOrThrow(verifier_set_value,
                                                                                  "external_statement.verifier_set");
    }

    const UniValue& proof_policy_value = FindValue(value, "proof_policy");
    if (!proof_policy_value.isNull()) {
        statement_template.proof_policy = ParseBridgeProofPolicyCommitmentOrThrow(proof_policy_value,
                                                                                  "external_statement.proof_policy");
    }

    std::string reject_reason;
    auto statement = shielded::v2::BuildV2IngressStatement(
        statement_template,
        Span<const shielded::v2::V2IngressLeafInput>{ingress_leaves.data(), ingress_leaves.size()},
        reject_reason);
    if (!statement.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("failed to build a valid v2_ingress_batch statement: %s", reject_reason));
    }
    statement->aggregate_commitment = ParseBridgeBatchAggregateCommitmentOrThrow(
        FindValue(value, "aggregate_commitment"),
        statement->batch_root,
        statement->data_root,
        statement->proof_policy,
        "external_statement.aggregate_commitment");
    return *statement;
}

[[nodiscard]] std::vector<uint32_t> ParseV2EgressOutputChunkSizesOrThrow(const UniValue& value,
                                                                         size_t expected_outputs,
                                                                         std::string_view field_name)
{
    if (value.isNull()) return {};
    if (!value.isArray() || value.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a non-empty array", field_name));
    }
    if (value.size() > shielded::v2::MAX_OUTPUT_CHUNKS) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s exceeds the output-chunk limit (%u > %u)",
                                     field_name,
                                     static_cast<unsigned int>(value.size()),
                                     static_cast<unsigned int>(shielded::v2::MAX_OUTPUT_CHUNKS)));
    }

    uint64_t total_outputs{0};
    std::vector<uint32_t> chunk_sizes;
    chunk_sizes.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        const int64_t chunk_size = value[i].getInt<int64_t>();
        if (chunk_size <= 0 || chunk_size > std::numeric_limits<uint32_t>::max()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s[%u] must be a positive integer", field_name, i));
        }
        total_outputs += static_cast<uint32_t>(chunk_size);
        if (total_outputs > expected_outputs) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s covers more outputs than recipients", field_name));
        }
        chunk_sizes.push_back(static_cast<uint32_t>(chunk_size));
    }
    if (total_outputs != expected_outputs) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must sum to the recipient count", field_name));
    }
    return chunk_sizes;
}

[[nodiscard]] std::vector<shielded::BridgeBatchReceipt> ParseBridgeBatchReceiptsOrThrow(const UniValue& value,
                                                                                         const shielded::BridgeBatchStatement& statement)
{
    if (!value.isArray() || value.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "receipts must be a non-empty array");
    }

    std::vector<shielded::BridgeBatchReceipt> receipts;
    receipts.reserve(value.size());
    const uint256 expected_statement_hash = shielded::ComputeBridgeBatchStatementHash(statement);
    if (expected_statement_hash.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "statement_hex does not produce a valid statement hash");
    }

    for (size_t i = 0; i < value.size(); ++i) {
        const auto receipt = DecodeBridgeBatchReceiptOrThrow(value[i]);
        const uint256 receipt_statement_hash = shielded::ComputeBridgeBatchStatementHash(receipt.statement);
        if (receipt_statement_hash != expected_statement_hash) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("receipts[%u] does not match statement_hex", i));
        }
        receipts.push_back(receipt);
    }
    return receipts;
}

[[nodiscard]] shielded::BridgeProofReceipt BuildBridgeProofReceiptOrThrow(const shielded::BridgeBatchStatement& statement,
                                                                          const UniValue& value)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "proof_receipt must be an object");
    }

    const uint256 statement_hash = shielded::ComputeBridgeBatchStatementHash(statement);
    if (statement_hash.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "statement_hex does not produce a valid statement hash");
    }

    const auto artifact = ParseBridgeProofArtifactSelectorOrThrow(value, "proof_receipt");
    const auto adapter = ParseBridgeProofAdapterSelectorOrThrow(value, "proof_receipt");
    const UniValue& proof_system_id_value = FindValue(value, "proof_system_id");
    const UniValue& proof_profile_hex_value = FindValue(value, "proof_profile_hex");
    const UniValue& proof_profile_value = FindValue(value, "proof_profile");
    const bool has_proof_system_selector = !proof_system_id_value.isNull() ||
                                           !proof_profile_hex_value.isNull() ||
                                           !proof_profile_value.isNull();
    const UniValue& public_values_hash_value = FindValue(value, "public_values_hash");
    const UniValue& claim_hex_value = FindValue(value, "claim_hex");
    const UniValue& claim_value = FindValue(value, "claim");
    const bool has_public_values_selector = !public_values_hash_value.isNull() ||
                                            !claim_hex_value.isNull() ||
                                            !claim_value.isNull();
    const UniValue& verifier_key_hash_value = FindValue(value, "verifier_key_hash");
    const UniValue& proof_commitment_value = FindValue(value, "proof_commitment");
    if (artifact.has_value()) {
        if (adapter.has_value() || has_proof_system_selector || has_public_values_selector ||
            !verifier_key_hash_value.isNull() || !proof_commitment_value.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "proof_receipt cannot mix proof_artifact_* selectors with verifier_key_hash, proof_commitment, proof_adapter_*, proof_system_id, proof_profile_hex, proof_profile, public_values_hash, claim_hex, or claim");
        }
        if (artifact->statement_hash != statement_hash) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "proof_artifact does not match statement_hex");
        }
        if (!shielded::DoesBridgeProofArtifactMatchStatement(*artifact, statement)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "proof_artifact public values do not match statement_hex");
        }
        const auto built = shielded::BuildBridgeProofReceiptFromArtifact(*artifact);
        if (!built.has_value()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to build a valid bridge proof receipt from proof_artifact");
        }
        return *built;
    }

    shielded::BridgeProofReceipt receipt;
    receipt.statement_hash = statement_hash;
    receipt.verifier_key_hash = ParseHashV(verifier_key_hash_value, "proof_receipt.verifier_key_hash");
    receipt.proof_commitment = ParseHashV(proof_commitment_value, "proof_receipt.proof_commitment");
    if (adapter.has_value()) {
        if (has_proof_system_selector) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "proof_receipt cannot mix proof_adapter_* selectors with proof_system_id, proof_profile_hex, or proof_profile");
        }
        if (has_public_values_selector) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "proof_receipt cannot mix proof_adapter_* selectors with public_values_hash, claim_hex, or claim");
        }
        const auto adapted = shielded::BuildBridgeProofReceiptFromAdapter(statement,
                                                                          *adapter,
                                                                          receipt.verifier_key_hash,
                                                                          receipt.proof_commitment);
        if (!adapted.has_value()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to build a valid bridge proof receipt from proof_adapter");
        }
        return *adapted;
    }

    receipt.proof_system_id = ParseBridgeProofSystemIdOrThrow(value, "proof_receipt");
    receipt.public_values_hash = ParseBridgePublicValuesHashOrThrow(value, statement);
    if (!receipt.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to build a valid bridge proof receipt");
    }
    return receipt;
}

[[nodiscard]] std::vector<shielded::BridgeProofReceipt> ParseBridgeProofReceiptsOrThrow(const UniValue& value,
                                                                                         const shielded::BridgeBatchStatement& statement)
{
    if (!value.isArray() || value.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "proof_receipts must be a non-empty array");
    }

    std::vector<shielded::BridgeProofReceipt> receipts;
    receipts.reserve(value.size());
    const uint256 expected_statement_hash = shielded::ComputeBridgeBatchStatementHash(statement);
    if (expected_statement_hash.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "statement_hex does not produce a valid statement hash");
    }

    for (size_t i = 0; i < value.size(); ++i) {
        const auto receipt = DecodeBridgeProofReceiptOrThrow(value[i]);
        if (receipt.statement_hash != expected_statement_hash) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("proof_receipts[%u] does not match statement_hex", i));
        }
        receipts.push_back(receipt);
    }
    return receipts;
}

[[nodiscard]] BridgeBatchReceiptPolicy ParseBridgeBatchReceiptPolicyOrThrow(const UniValue& value)
{
    BridgeBatchReceiptPolicy policy;
    if (value.isNull()) return policy;
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
    }

    const UniValue& min_receipts_value = FindValue(value, "min_receipts");
    if (!min_receipts_value.isNull()) {
        const int64_t min_receipts = min_receipts_value.getInt<int64_t>();
        if (min_receipts <= 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "options.min_receipts must be a positive integer");
        }
        policy.min_receipts = static_cast<size_t>(min_receipts);
    }

    const UniValue& required_attestors_value = FindValue(value, "required_attestors");
    if (!required_attestors_value.isNull()) {
        if (!required_attestors_value.isArray() || required_attestors_value.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "options.required_attestors must be a non-empty array");
        }

        std::set<std::pair<uint8_t, std::vector<unsigned char>>> seen_attestors;
        policy.required_attestors.reserve(required_attestors_value.size());
        for (size_t i = 0; i < required_attestors_value.size(); ++i) {
            const auto attestor = ParseBridgeKeySpec(required_attestors_value[i],
                                                     strprintf("options.required_attestors[%u]", i));
            const auto [it, inserted] = seen_attestors.emplace(static_cast<uint8_t>(attestor.algo), attestor.pubkey);
            if (!inserted) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   strprintf("options.required_attestors[%u] duplicates a prior attestor", i));
            }
            policy.required_attestors.push_back(attestor);
        }
    }

    const UniValue& revealed_attestors_value = FindValue(value, "revealed_attestors");
    if (!revealed_attestors_value.isNull()) {
        if (!revealed_attestors_value.isArray() || revealed_attestors_value.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "options.revealed_attestors must be a non-empty array");
        }

        std::set<std::pair<uint8_t, std::vector<unsigned char>>> seen_attestors;
        policy.revealed_attestors.reserve(revealed_attestors_value.size());
        for (size_t i = 0; i < revealed_attestors_value.size(); ++i) {
            const auto attestor = ParseBridgeKeySpec(revealed_attestors_value[i],
                                                     strprintf("options.revealed_attestors[%u]", i));
            const auto [it, inserted] = seen_attestors.emplace(static_cast<uint8_t>(attestor.algo), attestor.pubkey);
            if (!inserted) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   strprintf("options.revealed_attestors[%u] duplicates a prior attestor", i));
            }
            policy.revealed_attestors.push_back(attestor);
        }
    }

    const UniValue& attestor_proofs_value = FindValue(value, "attestor_proofs");
    if (!attestor_proofs_value.isNull()) {
        if (!attestor_proofs_value.isArray() || attestor_proofs_value.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "options.attestor_proofs must be a non-empty array");
        }

        policy.attestor_proofs.reserve(attestor_proofs_value.size());
        for (size_t i = 0; i < attestor_proofs_value.size(); ++i) {
            policy.attestor_proofs.push_back(DecodeBridgeVerifierSetProofOrThrow(attestor_proofs_value[i]));
        }
    }
    return policy;
}

[[nodiscard]] BridgeProofReceiptPolicy ParseBridgeProofReceiptPolicyOrThrow(const UniValue& value)
{
    BridgeProofReceiptPolicy policy;
    if (value.isNull()) return policy;
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
    }

    const UniValue& min_receipts_value = FindValue(value, "min_receipts");
    if (!min_receipts_value.isNull()) {
        const int64_t min_receipts = min_receipts_value.getInt<int64_t>();
        if (min_receipts <= 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "options.min_receipts must be a positive integer");
        }
        policy.min_receipts = static_cast<size_t>(min_receipts);
    }

    const auto parse_hash_array = [&](std::string_view field_name, std::vector<uint256>& out) {
        const std::string field_name_str{field_name};
        const UniValue& array_value = FindValue(value, field_name);
        if (array_value.isNull()) return;
        if (!array_value.isArray() || array_value.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("options.%s must be a non-empty array", field_name_str));
        }

        std::set<uint256> seen;
        out.reserve(array_value.size());
        for (size_t i = 0; i < array_value.size(); ++i) {
            const uint256 hash = ParseHashV(array_value[i], strprintf("options.%s[%u]", field_name_str, i));
            if (!seen.emplace(hash).second) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   strprintf("options.%s[%u] duplicates a prior hash", field_name_str, i));
            }
            out.push_back(hash);
        }
    };

    parse_hash_array("required_proof_system_ids", policy.required_proof_system_ids);
    parse_hash_array("required_verifier_key_hashes", policy.required_verifier_key_hashes);

    const UniValue& revealed_descriptors_value = FindValue(value, "revealed_descriptors");
    if (!revealed_descriptors_value.isNull()) {
        policy.revealed_descriptors = ParseBridgeProofDescriptorArrayOrThrow(revealed_descriptors_value,
                                                                             "options.revealed_descriptors");
    }

    const UniValue& descriptor_proofs_value = FindValue(value, "descriptor_proofs");
    if (!descriptor_proofs_value.isNull()) {
        if (!descriptor_proofs_value.isArray() || descriptor_proofs_value.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "options.descriptor_proofs must be a non-empty array");
        }

        policy.descriptor_proofs.reserve(descriptor_proofs_value.size());
        for (size_t i = 0; i < descriptor_proofs_value.size(); ++i) {
            policy.descriptor_proofs.push_back(DecodeBridgeProofPolicyProofOrThrow(descriptor_proofs_value[i]));
        }
    }
    return policy;
}

[[nodiscard]] BridgeHybridAnchorPolicies ParseBridgeHybridAnchorPoliciesOrThrow(const UniValue& value)
{
    BridgeHybridAnchorPolicies policies;
    if (value.isNull()) return policies;
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
    }

    const UniValue& receipt_policy_value = FindValue(value, "receipt_policy");
    const UniValue& proof_receipt_policy_value = FindValue(value, "proof_receipt_policy");
    policies.receipt_policy = ParseBridgeBatchReceiptPolicyOrThrow(receipt_policy_value);
    policies.proof_receipt_policy = ParseBridgeProofReceiptPolicyOrThrow(proof_receipt_policy_value);
    return policies;
}

[[nodiscard]] BridgeBatchReceiptValidationSummary ValidateBridgeBatchReceiptSetOrThrow(const shielded::BridgeBatchStatement& statement,
                                                                                       Span<const shielded::BridgeBatchReceipt> receipts,
                                                                                       const BridgeBatchReceiptPolicy& policy)
{
    if (receipts.size() < policy.min_receipts) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("receipt set does not satisfy min_receipts: have %u, need %u",
                                     receipts.size(), policy.min_receipts));
    }

    BridgeBatchReceiptValidationSummary summary;
    summary.distinct_attestor_count = shielded::CountDistinctBridgeBatchReceiptAttestors(receipts);
    if (summary.distinct_attestor_count != receipts.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "receipts contain duplicate attestors");
    }

    std::set<std::pair<uint8_t, std::vector<unsigned char>>> attestors;
    for (const auto& receipt : receipts) {
        attestors.emplace(static_cast<uint8_t>(receipt.attestor.algo), receipt.attestor.pubkey);
    }

    if (statement.verifier_set.IsValid()) {
        if (policy.attestor_proofs.empty() && policy.revealed_attestors.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "statement requires options.attestor_proofs or options.revealed_attestors to validate verifier_set membership");
        }
        if (summary.distinct_attestor_count < statement.verifier_set.required_signers) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("receipt set does not satisfy statement verifier_set: have %u distinct attestors, need %u",
                                         summary.distinct_attestor_count, statement.verifier_set.required_signers));
        }

        if (!policy.attestor_proofs.empty()) {
            if (policy.attestor_proofs.size() != receipts.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   strprintf("options.attestor_proofs must contain one proof per receipt: have %u, need %u",
                                             policy.attestor_proofs.size(), receipts.size()));
            }
            for (size_t i = 0; i < receipts.size(); ++i) {
                if (!shielded::VerifyBridgeVerifierSetProof(statement.verifier_set, receipts[i].attestor, policy.attestor_proofs[i])) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                                       strprintf("options.attestor_proofs[%u] does not verify for receipts[%u].attestor", i, i));
                }
            }
        } else {
            const auto verifier_set = shielded::BuildBridgeVerifierSetCommitment(policy.revealed_attestors,
                                                                                 statement.verifier_set.required_signers);
            if (!verifier_set.has_value() ||
                verifier_set->attestor_count != statement.verifier_set.attestor_count ||
                verifier_set->required_signers != statement.verifier_set.required_signers ||
                verifier_set->attestor_root != statement.verifier_set.attestor_root) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "options.revealed_attestors do not match statement verifier_set");
            }
            std::set<std::pair<uint8_t, std::vector<unsigned char>>> revealed_attestors;
            for (const auto& attestor : policy.revealed_attestors) {
                revealed_attestors.emplace(static_cast<uint8_t>(attestor.algo), attestor.pubkey);
            }
            for (size_t i = 0; i < receipts.size(); ++i) {
                const auto& receipt = receipts[i];
                if (revealed_attestors.count({static_cast<uint8_t>(receipt.attestor.algo), receipt.attestor.pubkey}) == 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                                       strprintf("receipts[%u] attestor is not in options.revealed_attestors", i));
                }
            }
        }
    } else if (!policy.attestor_proofs.empty() || !policy.revealed_attestors.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "options.attestor_proofs and options.revealed_attestors require a statement-bound verifier_set");
    }

    for (size_t i = 0; i < policy.required_attestors.size(); ++i) {
        const auto& attestor = policy.required_attestors[i];
        if (attestors.count({static_cast<uint8_t>(attestor.algo), attestor.pubkey}) == 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("required_attestors[%u] is missing from the receipt set", i));
        }
    }
    return summary;
}

[[nodiscard]] BridgeProofReceiptValidationSummary ValidateBridgeProofReceiptSetOrThrow(const shielded::BridgeBatchStatement& statement,
                                                                                       Span<const shielded::BridgeProofReceipt> receipts,
                                                                                       const BridgeProofReceiptPolicy& policy)
{
    if (receipts.size() < policy.min_receipts) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("proof receipt set does not satisfy min_receipts: have %u, need %u",
                                     receipts.size(), policy.min_receipts));
    }

    BridgeProofReceiptValidationSummary summary;
    summary.distinct_receipt_count = shielded::CountDistinctBridgeProofReceipts(receipts);
    if (summary.distinct_receipt_count != receipts.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "proof_receipts contain duplicates");
    }

    if (statement.proof_policy.IsValid()) {
        if (policy.descriptor_proofs.empty() && policy.revealed_descriptors.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "statement requires options.descriptor_proofs or options.revealed_descriptors to validate proof_policy membership");
        }
        if (summary.distinct_receipt_count < statement.proof_policy.required_receipts) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("proof receipt set does not satisfy statement proof_policy: have %u distinct receipts, need %u",
                                         summary.distinct_receipt_count, statement.proof_policy.required_receipts));
        }

        if (!policy.descriptor_proofs.empty()) {
            if (policy.descriptor_proofs.size() != receipts.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   strprintf("options.descriptor_proofs must contain one proof per receipt: have %u, need %u",
                                             policy.descriptor_proofs.size(), receipts.size()));
            }
            for (size_t i = 0; i < receipts.size(); ++i) {
                const shielded::BridgeProofDescriptor descriptor{receipts[i].proof_system_id, receipts[i].verifier_key_hash};
                if (!shielded::VerifyBridgeProofPolicyProof(statement.proof_policy, descriptor, policy.descriptor_proofs[i])) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                                       strprintf("options.descriptor_proofs[%u] does not verify for proof_receipts[%u] descriptor", i, i));
                }
            }
        } else {
            const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(policy.revealed_descriptors,
                                                                                 statement.proof_policy.required_receipts);
            if (!proof_policy.has_value() ||
                proof_policy->descriptor_count != statement.proof_policy.descriptor_count ||
                proof_policy->required_receipts != statement.proof_policy.required_receipts ||
                proof_policy->descriptor_root != statement.proof_policy.descriptor_root) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "options.revealed_descriptors do not match statement proof_policy");
            }
            std::set<std::pair<uint256, uint256>> revealed_descriptors;
            for (const auto& descriptor : policy.revealed_descriptors) {
                revealed_descriptors.emplace(descriptor.proof_system_id, descriptor.verifier_key_hash);
            }
            for (size_t i = 0; i < receipts.size(); ++i) {
                const auto& receipt = receipts[i];
                if (revealed_descriptors.count({receipt.proof_system_id, receipt.verifier_key_hash}) == 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                                       strprintf("proof_receipts[%u] descriptor is not in options.revealed_descriptors", i));
                }
            }
        }
    } else if (!policy.descriptor_proofs.empty() || !policy.revealed_descriptors.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "options.descriptor_proofs and options.revealed_descriptors require a statement-bound proof_policy");
    }

    std::set<uint256> proof_system_ids;
    std::set<uint256> verifier_key_hashes;
    for (const auto& receipt : receipts) {
        proof_system_ids.emplace(receipt.proof_system_id);
        verifier_key_hashes.emplace(receipt.verifier_key_hash);
    }

    for (size_t i = 0; i < policy.required_proof_system_ids.size(); ++i) {
        if (proof_system_ids.count(policy.required_proof_system_ids[i]) == 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("required_proof_system_ids[%u] is missing from the proof receipt set", i));
        }
    }
    for (size_t i = 0; i < policy.required_verifier_key_hashes.size(); ++i) {
        if (verifier_key_hashes.count(policy.required_verifier_key_hashes[i]) == 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("required_verifier_key_hashes[%u] is missing from the proof receipt set", i));
        }
    }
    return summary;
}

[[nodiscard]] IngressSettlementWitnessSummary BuildIngressSettlementWitnessSummaryOrThrow(
    const shielded::BridgeBatchStatement& statement,
    const UniValue& options)
{
    IngressSettlementWitnessSummary summary;
    std::optional<BridgeBatchReceiptPolicy> receipt_policy;
    std::optional<BridgeProofReceiptPolicy> proof_receipt_policy;
    if (options.isNull()) {
        if (statement.verifier_set.IsValid()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "statement commits to verifier_set; options.receipts are required");
        }
        if (statement.proof_policy.IsValid()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "statement commits to proof_policy; options.proof_receipts are required");
        }
        return summary;
    }
    if (!options.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
    }

    const UniValue& receipts_value = FindValue(options, "receipts");
    const UniValue& proof_receipts_value = FindValue(options, "proof_receipts");
    const UniValue& receipt_policy_value = FindValue(options, "receipt_policy");
    const UniValue& proof_receipt_policy_value = FindValue(options, "proof_receipt_policy");

    if (!receipts_value.isNull()) {
        summary.receipts = ParseBridgeBatchReceiptsOrThrow(receipts_value, statement);
        receipt_policy = ParseBridgeBatchReceiptPolicyOrThrow(receipt_policy_value);
        summary.receipt_summary = ValidateBridgeBatchReceiptSetOrThrow(
            statement,
            Span<const shielded::BridgeBatchReceipt>{summary.receipts.data(), summary.receipts.size()},
            *receipt_policy);
        if (statement.verifier_set.IsValid()) {
            if (!receipt_policy->attestor_proofs.empty()) {
                summary.signed_receipt_proofs = receipt_policy->attestor_proofs;
            } else {
                summary.signed_receipt_proofs.reserve(summary.receipts.size());
                for (size_t i = 0; i < summary.receipts.size(); ++i) {
                    auto proof = shielded::BuildBridgeVerifierSetProof(
                        receipt_policy->revealed_attestors,
                        summary.receipts[i].attestor);
                    if (!proof.has_value()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                                           strprintf("failed to derive attestor proof for receipts[%u]", i));
                    }
                    summary.signed_receipt_proofs.push_back(std::move(*proof));
                }
            }
        }
    } else if (!receipt_policy_value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "options.receipt_policy requires options.receipts");
    } else if (statement.verifier_set.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "statement commits to verifier_set; options.receipts are required");
    }

    if (!proof_receipts_value.isNull()) {
        summary.proof_receipts = ParseBridgeProofReceiptsOrThrow(proof_receipts_value, statement);
        proof_receipt_policy = ParseBridgeProofReceiptPolicyOrThrow(proof_receipt_policy_value);
        summary.proof_summary = ValidateBridgeProofReceiptSetOrThrow(
            statement,
            Span<const shielded::BridgeProofReceipt>{summary.proof_receipts.data(), summary.proof_receipts.size()},
            *proof_receipt_policy);
        if (statement.proof_policy.IsValid()) {
            if (!proof_receipt_policy->descriptor_proofs.empty()) {
                summary.proof_receipt_descriptor_proofs = proof_receipt_policy->descriptor_proofs;
            } else {
                summary.proof_receipt_descriptor_proofs.reserve(summary.proof_receipts.size());
                for (size_t i = 0; i < summary.proof_receipts.size(); ++i) {
                    const shielded::BridgeProofDescriptor descriptor{
                        summary.proof_receipts[i].proof_system_id,
                        summary.proof_receipts[i].verifier_key_hash};
                    auto proof = shielded::BuildBridgeProofPolicyProof(
                        proof_receipt_policy->revealed_descriptors,
                        descriptor);
                    if (!proof.has_value()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                                           strprintf("failed to derive descriptor proof for proof_receipts[%u]", i));
                    }
                    summary.proof_receipt_descriptor_proofs.push_back(std::move(*proof));
                }
            }
        }
    } else if (!proof_receipt_policy_value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "options.proof_receipt_policy requires options.proof_receipts");
    } else if (statement.proof_policy.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "statement commits to proof_policy; options.proof_receipts are required");
    }

    if (summary.receipts.empty() && summary.proof_receipts.empty()) return summary;

    if (!summary.receipts.empty() && !summary.proof_receipts.empty()) {
        shielded::BridgeVerificationBundle bundle;
        bundle.signed_receipt_root = shielded::ComputeBridgeBatchReceiptRoot(summary.receipts);
        bundle.proof_receipt_root = shielded::ComputeBridgeProofReceiptRoot(summary.proof_receipts);
        if (!bundle.IsValid()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "receipt witness sets do not produce a valid verification bundle");
        }
        summary.verification_bundle = bundle;
        summary.external_anchor = shielded::BuildBridgeExternalAnchorFromHybridWitness(
            statement,
            Span<const shielded::BridgeBatchReceipt>{summary.receipts.data(), summary.receipts.size()},
            Span<const shielded::BridgeProofReceipt>{summary.proof_receipts.data(), summary.proof_receipts.size()});
        if (!summary.external_anchor.has_value()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "receipt witness sets do not produce a valid external anchor");
        }
        return summary;
    }

    if (!summary.receipts.empty()) {
        summary.external_anchor = shielded::BuildBridgeExternalAnchorFromStatement(
            statement,
            Span<const shielded::BridgeBatchReceipt>{summary.receipts.data(), summary.receipts.size()});
        if (!summary.external_anchor.has_value()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "receipts do not produce a valid external anchor");
        }
        return summary;
    }

    summary.external_anchor = shielded::BuildBridgeExternalAnchorFromProofReceipts(
        statement,
        Span<const shielded::BridgeProofReceipt>{summary.proof_receipts.data(), summary.proof_receipts.size()});
    if (!summary.external_anchor.has_value()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "proof_receipts do not produce a valid external anchor");
    }
    return summary;
}

[[nodiscard]] std::vector<shielded::BridgeKeySpec> ParseBridgeKeyArrayOrThrow(const UniValue& value,
                                                                               std::string_view field_name)
{
    if (!value.isArray() || value.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a non-empty array", field_name));
    }

    std::set<std::pair<uint8_t, std::vector<unsigned char>>> seen_attestors;
    std::vector<shielded::BridgeKeySpec> attestors;
    attestors.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        const auto attestor = ParseBridgeKeySpec(value[i], strprintf("%s[%u]", field_name, i));
        const auto [it, inserted] = seen_attestors.emplace(static_cast<uint8_t>(attestor.algo), attestor.pubkey);
        if (!inserted) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s[%u] duplicates a prior attestor", field_name, i));
        }
        attestors.push_back(attestor);
    }
    return attestors;
}

[[nodiscard]] shielded::BridgeBatchLeafKind ParseBridgeBatchLeafKindOrThrow(const UniValue& value,
                                                                            std::string_view field_name)
{
    const std::string kind = value.get_str();
    if (kind == "shield_credit") return shielded::BridgeBatchLeafKind::SHIELD_CREDIT;
    if (kind == "transparent_payout") return shielded::BridgeBatchLeafKind::TRANSPARENT_PAYOUT;
    if (kind == "shielded_payout") return shielded::BridgeBatchLeafKind::SHIELDED_PAYOUT;
    throw JSONRPCError(RPC_INVALID_PARAMETER,
                       strprintf("%s must be shield_credit, transparent_payout, or shielded_payout",
                                 field_name));
}

[[nodiscard]] shielded::BridgeBatchLeaf ParseBridgeBatchLeafOrThrow(const UniValue& value,
                                                                    std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    shielded::BridgeBatchLeaf leaf;
    leaf.kind = ParseBridgeBatchLeafKindOrThrow(FindValue(value, "kind"),
                                                strprintf("%s.kind", field_name));
    leaf.wallet_id = ParseHashV(FindValue(value, "wallet_id"), strprintf("%s.wallet_id", field_name));
    leaf.destination_id = ParseHashV(FindValue(value, "destination_id"), strprintf("%s.destination_id", field_name));
    leaf.amount = AmountFromValue(FindValue(value, "amount"));
    leaf.authorization_hash = ParseHashV(FindValue(value, "authorization_hash"),
                                         strprintf("%s.authorization_hash", field_name));
    if (!leaf.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is not a valid bridge batch leaf", field_name));
    }
    return leaf;
}

[[nodiscard]] shielded::BridgeBatchAuthorization ParseBridgeBatchAuthorizationBodyOrThrow(
    const UniValue& value,
    shielded::BridgeDirection direction,
    const shielded::BridgePlanIds& ids,
    const shielded::BridgeKeySpec& authorizer)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "authorization must be an object");
    }

    shielded::BridgeBatchAuthorization authorization;
    authorization.direction = direction;
    authorization.ids = ids;
    authorization.kind = ParseBridgeBatchLeafKindOrThrow(FindValue(value, "kind"), "authorization.kind");
    authorization.wallet_id = ParseHashV(FindValue(value, "wallet_id"), "authorization.wallet_id");
    authorization.destination_id = ParseHashV(FindValue(value, "destination_id"), "authorization.destination_id");
    authorization.amount = AmountFromValue(FindValue(value, "amount"));
    authorization.authorization_nonce = ParseHashV(FindValue(value, "authorization_nonce"), "authorization.authorization_nonce");
    authorization.authorizer = authorizer;
    if (!authorization.IsMessageValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "authorization is not a valid bridge batch authorization message");
    }
    return authorization;
}

[[nodiscard]] ParsedBridgeBatchEntries ParseBridgeBatchEntriesOrThrow(const UniValue& value,
                                                                     int32_t build_height,
                                                                     std::optional<shielded::BridgeDirection> expected_direction = std::nullopt,
                                                                     std::optional<shielded::BridgePlanIds> expected_ids = std::nullopt)
{
    if (!value.isArray() || value.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "leaves must be a non-empty array");
    }

    ParsedBridgeBatchEntries parsed;
    parsed.leaves.reserve(value.size());
    parsed.authorizations.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        if (!value[i].isObject()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("leaves[%u] must be an object", i));
        }

        const UniValue& authorization_hex_value = FindValue(value[i], "authorization_hex");
        if (!authorization_hex_value.isNull()) {
            shielded::BridgeBatchAuthorization authorization = DecodeBridgeBatchAuthorizationOrThrow(authorization_hex_value);
            if (expected_direction.has_value() && authorization.direction != *expected_direction) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("leaves[%u].authorization_hex direction does not match requested direction", i));
            }
            if (expected_ids.has_value() &&
                (authorization.ids.bridge_id != expected_ids->bridge_id ||
                 authorization.ids.operation_id != expected_ids->operation_id)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("leaves[%u].authorization_hex ids do not match bridge_id/operation_id", i));
            }
            const auto leaf = shielded::BuildBridgeBatchLeafFromAuthorization(authorization, build_height);
            if (!leaf.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("leaves[%u].authorization_hex does not derive a valid bridge batch leaf", i));
            }
            parsed.authorizations.push_back(std::move(authorization));
            parsed.leaves.push_back(*leaf);
            continue;
        }

        parsed.leaves.push_back(ParseBridgeBatchLeafOrThrow(value[i], strprintf("leaves[%u]", i)));
    }
    return parsed;
}

[[nodiscard]] shielded::BridgeBatchCommitment BuildBridgeBatchCommitmentOrThrow(shielded::BridgeDirection direction,
                                                                                Span<const shielded::BridgeBatchLeaf> leaves,
                                                                                const shielded::BridgePlanIds& ids,
                                                                                std::optional<shielded::BridgeExternalAnchor> external_anchor = std::nullopt)
{
    if (leaves.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "at least one bridge batch leaf is required");
    }

    CAmount total_amount{0};
    for (const auto& leaf : leaves) {
        const auto next = CheckedAdd(total_amount, leaf.amount);
        if (!next.has_value() || !MoneyRange(*next)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "batch leaf total exceeds valid money range");
        }
        total_amount = *next;
    }

    shielded::BridgeBatchCommitment commitment;
    commitment.direction = direction;
    commitment.ids = ids;
    commitment.entry_count = leaves.size();
    commitment.total_amount = total_amount;
    commitment.batch_root = shielded::ComputeBridgeBatchRoot(leaves);
    if (external_anchor.has_value()) {
        commitment.external_anchor = *external_anchor;
        const auto aggregate_commitment = shielded::BuildDefaultBridgeBatchAggregateCommitment(commitment.batch_root,
                                                                                               external_anchor->data_root,
                                                                                               shielded::BridgeProofPolicyCommitment{});
        if (!aggregate_commitment.has_value()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to build a future-proofed bridge batch commitment");
        }
        commitment.aggregate_commitment = *aggregate_commitment;
        commitment.version = 3;
    }
    if (!commitment.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to build a valid bridge batch commitment");
    }
    return commitment;
}

[[nodiscard]] std::optional<shielded::BridgeBatchCommitment> ParseBridgeBatchCommitmentOrThrow(
    const UniValue& options,
    shielded::BridgeDirection expected_direction,
    const shielded::BridgePlanIds& ids)
{
    const UniValue& value = FindValue(options, "batch_commitment_hex");
    if (value.isNull()) return std::nullopt;

    shielded::BridgeBatchCommitment commitment = DecodeBridgeBatchCommitmentOrThrow(value);
    if (commitment.direction != expected_direction) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "batch_commitment_hex direction does not match the requested bridge flow");
    }
    if (commitment.ids.bridge_id != ids.bridge_id || commitment.ids.operation_id != ids.operation_id) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "batch_commitment_hex ids do not match bridge_id/operation_id");
    }
    return commitment;
}

[[nodiscard]] uint32_t ParseRefundLockHeightOrThrow(const UniValue& options)
{
    const UniValue& value = FindValue(options, "refund_lock_height");
    if (value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "refund_lock_height is required");
    }
    const int64_t height = value.getInt<int64_t>();
    if (height <= 0 || height > std::numeric_limits<uint32_t>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "refund_lock_height must be a positive absolute height");
    }
    const uint32_t refund_lock_height = static_cast<uint32_t>(height);
    if (!shielded::IsValidRefundLockHeight(refund_lock_height)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "refund_lock_height is outside the valid range");
    }
    return refund_lock_height;
}

[[nodiscard]] std::vector<unsigned char> ParseBridgeMemoOrThrow(const UniValue& options)
{
    const UniValue& memo_value = FindValue(options, "memo");
    const UniValue& memo_hex_value = FindValue(options, "memo_hex");
    if (!memo_value.isNull() && !memo_hex_value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Specify either memo or memo_hex, not both");
    }

    std::vector<unsigned char> memo;
    if (!memo_value.isNull()) {
        const std::string memo_str = memo_value.get_str();
        memo.assign(memo_str.begin(), memo_str.end());
    } else if (!memo_hex_value.isNull()) {
        memo = ParseHexV(memo_hex_value, "memo_hex");
    }

    if (memo.size() > MAX_SHIELDED_MEMO_SIZE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("memo exceeds %u bytes", MAX_SHIELDED_MEMO_SIZE));
    }
    return memo;
}

[[nodiscard]] mlkem::PublicKey ParseBridgeViewGrantPubkeyOrThrow(const UniValue& value, std::string_view field_name)
{
    const auto bytes = ParseHexV(value, std::string{field_name});
    if (bytes.size() != mlkem::PUBLICKEYBYTES) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an ML-KEM public key", field_name));
    }
    mlkem::PublicKey pk{};
    std::copy(bytes.begin(), bytes.end(), pk.begin());
    return pk;
}

[[nodiscard]] BridgeViewGrantFormat ParseBridgeViewGrantFormatOrThrow(const UniValue& value, std::string_view field_name)
{
    const std::string format = value.get_str();
    if (format == "legacy_audit") return BridgeViewGrantFormat::LEGACY_AUDIT;
    if (format == "structured_disclosure") return BridgeViewGrantFormat::STRUCTURED_DISCLOSURE;
    throw JSONRPCError(
        RPC_INVALID_PARAMETER,
        strprintf("%s must be legacy_audit or structured_disclosure", field_name));
}

[[nodiscard]] uint8_t ParseBridgeDisclosureFlagsOrThrow(const UniValue& value, std::string_view field_name)
{
    if (!value.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an array", field_name));
    }

    uint8_t disclosure_flags{0};
    for (size_t i = 0; i < value.size(); ++i) {
        if (!value[i].isStr()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s[%u] must be a string", field_name, i));
        }
        const std::string item = value[i].get_str();
        if (const auto flag = shielded::viewgrants::ParseDisclosureField(item); flag.has_value()) {
            disclosure_flags |= *flag;
            continue;
        }
        if (item == "recipient_pk_hash") {
            disclosure_flags |= shielded::viewgrants::DISCLOSE_RECIPIENT;
            continue;
        }
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("%s[%u] must be one of amount, recipient, memo, sender", field_name, i));
    }

    if (!shielded::viewgrants::IsValidDisclosureFlags(disclosure_flags)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must not be empty", field_name));
    }
    return disclosure_flags;
}

[[nodiscard]] BridgeViewGrantRequest ParseBridgeViewGrantRequestOrThrow(const UniValue& value,
                                                                        std::string_view field_name)
{
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be an object", field_name));
    }

    BridgeViewGrantRequest request;
    const UniValue& pubkey_value = FindValue(value, "pubkey");
    if (pubkey_value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s.pubkey is required", field_name));
    }
    request.recipient_pubkey = ParseBridgeViewGrantPubkeyOrThrow(pubkey_value, strprintf("%s.pubkey", field_name));

    const UniValue& format_value = FindValue(value, "format");
    const UniValue& disclosure_fields_value = FindValue(value, "disclosure_fields");
    const UniValue& legacy_fields_value = FindValue(value, "fields");
    if (!disclosure_fields_value.isNull() && !legacy_fields_value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s must not specify both disclosure_fields and fields", field_name));
    }
    const UniValue& fields_value = disclosure_fields_value.isNull() ? legacy_fields_value : disclosure_fields_value;
    request.format = format_value.isNull()
        ? (fields_value.isNull() ? BridgeViewGrantFormat::LEGACY_AUDIT
                                 : BridgeViewGrantFormat::STRUCTURED_DISCLOSURE)
        : ParseBridgeViewGrantFormatOrThrow(format_value, strprintf("%s.format", field_name));

    if (request.format == BridgeViewGrantFormat::STRUCTURED_DISCLOSURE) {
        if (fields_value.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("%s.disclosure_fields is required for structured_disclosure", field_name));
        }
        const std::string fields_name = disclosure_fields_value.isNull()
            ? strprintf("%s.fields", field_name)
            : strprintf("%s.disclosure_fields", field_name);
        request.disclosure_flags = ParseBridgeDisclosureFlagsOrThrow(fields_value, fields_name);
    } else if (!fields_value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s.disclosure_fields is only valid for structured_disclosure", field_name));
    }

    if (!request.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s is invalid", field_name));
    }
    return request;
}

[[nodiscard]] std::vector<BridgeViewGrantRequest> ParseBridgeViewGrantsOrThrow(const UniValue& options,
                                                                               int32_t build_height)
{
    std::vector<BridgeViewGrantRequest> result;

    const UniValue& legacy_value = FindValue(options, "operator_view_pubkeys");
    if (!legacy_value.isNull()) {
        if (!legacy_value.isArray()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "operator_view_pubkeys must be an array");
        }
        const bool postfork = wallet::UseShieldedPrivacyRedesignAtHeight(build_height);
        for (size_t i = 0; i < legacy_value.size(); ++i) {
            BridgeViewGrantRequest request;
            request.format = postfork
                ? BridgeViewGrantFormat::STRUCTURED_DISCLOSURE
                : BridgeViewGrantFormat::LEGACY_AUDIT;
            request.recipient_pubkey = ParseBridgeViewGrantPubkeyOrThrow(
                legacy_value[i], strprintf("operator_view_pubkeys[%u]", i));
            if (request.format == BridgeViewGrantFormat::STRUCTURED_DISCLOSURE) {
                request.disclosure_flags = static_cast<uint8_t>(
                    shielded::viewgrants::DISCLOSE_AMOUNT |
                    shielded::viewgrants::DISCLOSE_RECIPIENT |
                    shielded::viewgrants::DISCLOSE_SENDER);
            }
            result.push_back(std::move(request));
        }
    }

    const UniValue& grants_value = FindValue(options, "operator_view_grants");
    if (!grants_value.isNull()) {
        if (!grants_value.isArray()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "operator_view_grants must be an array");
        }
        for (size_t i = 0; i < grants_value.size(); ++i) {
            result.push_back(ParseBridgeViewGrantRequestOrThrow(
                grants_value[i], strprintf("operator_view_grants[%u]", i)));
        }
    }

    if (result.size() > MAX_VIEW_GRANTS_PER_TX) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("total bridge view grants exceeds %u entries", MAX_VIEW_GRANTS_PER_TX));
    }

    return result;
}

[[nodiscard]] std::optional<BridgeDisclosurePolicy> ParseBridgeDisclosurePolicyOrThrow(const UniValue& options)
{
    const UniValue& value = FindValue(options, "disclosure_policy");
    if (value.isNull()) return std::nullopt;
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "disclosure_policy must be an object");
    }

    BridgeDisclosurePolicy policy;
    const UniValue& version_value = FindValue(value, "version");
    if (!version_value.isNull()) {
        const int version = version_value.getInt<int>();
        if (version < 0 || version > std::numeric_limits<uint8_t>::max()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "disclosure_policy.version is out of range");
        }
        policy.version = static_cast<uint8_t>(version);
    }

    const UniValue& threshold_value = FindValue(value, "threshold_amount");
    if (threshold_value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "disclosure_policy.threshold_amount is required");
    }
    policy.threshold_amount = AmountFromValue(threshold_value);

    const UniValue& grants_value = FindValue(value, "required_grants");
    if (grants_value.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "disclosure_policy.required_grants is required");
    }
    if (!grants_value.isArray()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "disclosure_policy.required_grants must be an array");
    }
    for (size_t i = 0; i < grants_value.size(); ++i) {
        policy.required_grants.push_back(ParseBridgeViewGrantRequestOrThrow(
            grants_value[i], strprintf("disclosure_policy.required_grants[%u]", i)));
    }

    if (!policy.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "disclosure_policy is invalid");
    }
    return policy;
}

[[nodiscard]] ShieldedAddress ResolveBridgeRecipientOrThrow(const std::shared_ptr<CWallet>& pwallet,
                                                            const UniValue& options,
                                                            bool& generated)
{
    generated = false;
    const UniValue& recipient_value = FindValue(options, "recipient");
    if (recipient_value.isNull()) {
        EnsureEncryptedShieldedWritesOrThrow(*pwallet);
        EnsureWalletIsUnlocked(*pwallet);
        LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
        generated = true;
        return pwallet->m_shielded_wallet->GenerateNewAddress();
    }

    auto recipient = ParseShieldedAddr(recipient_value.get_str());
    if (!recipient.has_value()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "recipient must be a valid shielded address");
    }
    if (!recipient->HasKEMPublicKey()) {
        LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
        mlkem::PublicKey kem_pk{};
        if (pwallet->m_shielded_wallet->GetKEMPublicKey(*recipient, kem_pk)) {
            std::copy(kem_pk.begin(), kem_pk.end(), recipient->kem_pk.begin());
        }
    }
    if (!recipient->HasKEMPublicKey()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "recipient must include a KEM public key");
    }
    return *recipient;
}

[[nodiscard]] uint256 ResolveBridgeAnchorOrThrow(const std::shared_ptr<CWallet>& pwallet, const UniValue& options)
{
    const UniValue& value = FindValue(options, "shielded_anchor");
    if (!value.isNull()) {
        const uint256 anchor = ParseHashV(value, "shielded_anchor");
        if (anchor.IsNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "shielded_anchor must be non-zero");
        }
        return anchor;
    }

    LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
    const uint256 anchor = pwallet->m_shielded_wallet->GetCurrentAnchor();
    if (anchor.IsNull()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Shielded wallet has no current anchor");
    }
    return anchor;
}

[[nodiscard]] uint256 ResolveBridgeGenesisHashOrThrow(const std::shared_ptr<CWallet>& pwallet, const UniValue& options)
{
    const UniValue& value = FindValue(options, "genesis_hash");
    if (!value.isNull()) {
        const uint256 genesis_hash = ParseHashV(value, "genesis_hash");
        if (genesis_hash.IsNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "genesis_hash must be non-zero");
        }
        return genesis_hash;
    }
    return pwallet->chain().getBlockHash(0);
}

[[nodiscard]] CTxDestination ParseDestinationOrThrow(const UniValue& value, std::string_view field_name)
{
    std::string error;
    CTxDestination destination = DecodeDestination(value.get_str(), error);
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error.empty() ? strprintf("Invalid %s", field_name) : error);
    }
    return destination;
}

[[nodiscard]] bool ParseEnforceTimeoutFlag(const UniValue& value)
{
    return value.isNull() ? true : value.get_bool();
}

[[nodiscard]] BridgeFeeHeadroomPolicy ParseBridgeFeeHeadroomPolicy(const UniValue& value, bool default_enforce)
{
    BridgeFeeHeadroomPolicy policy;
    policy.enforce = default_enforce;

    if (value.isNull()) return policy;
    if (!value.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
    }

    const UniValue& multiplier_value = FindValue(value, "min_fee_headroom_multiplier");
    if (!multiplier_value.isNull()) {
        const double multiplier = multiplier_value.get_real();
        if (!std::isfinite(multiplier) || multiplier < 1.0 || multiplier > 1000.0) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "options.min_fee_headroom_multiplier must be between 1.0 and 1000.0");
        }
        policy.min_multiplier_milli =
            static_cast<int64_t>(std::llround(multiplier * static_cast<double>(BRIDGE_FEE_HEADROOM_SCALE)));
        if (policy.min_multiplier_milli < BRIDGE_FEE_HEADROOM_SCALE) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "options.min_fee_headroom_multiplier must be at least 1.0");
        }
    }

    const UniValue& enforce_value = FindValue(value, "enforce_fee_headroom");
    if (!enforce_value.isNull()) {
        policy.enforce = enforce_value.get_bool();
    }
    return policy;
}

[[nodiscard]] BridgeFeeHeadroomAssessment EvaluateBridgeFeeHeadroom(
    const BridgePsbtRelayFeeAnalysis& analysis,
    const BridgeFeeHeadroomPolicy& policy)
{
    BridgeFeeHeadroomAssessment assessment;
    assessment.multiplier_milli = policy.min_multiplier_milli;
    if (!analysis.available) {
        assessment.error = analysis.error;
        return assessment;
    }
    if (policy.min_multiplier_milli < BRIDGE_FEE_HEADROOM_SCALE) {
        assessment.error = "fee headroom multiplier is below 1.0x";
        return assessment;
    }
    if (analysis.required_total_fee >
        (std::numeric_limits<CAmount>::max() - (BRIDGE_FEE_HEADROOM_SCALE - 1)) / policy.min_multiplier_milli) {
        assessment.error = "fee headroom requirement overflow";
        return assessment;
    }

    const CAmount scaled_required = analysis.required_total_fee * policy.min_multiplier_milli;
    assessment.required_fee =
        (scaled_required + BRIDGE_FEE_HEADROOM_SCALE - 1) / BRIDGE_FEE_HEADROOM_SCALE;
    assessment.sufficient = analysis.estimated_fee >= assessment.required_fee;
    assessment.available = true;
    return assessment;
}

void EnsureBridgeFeeHeadroomOrThrow(const BridgeFeeHeadroomAssessment& assessment,
                                    const BridgeFeeHeadroomPolicy& policy,
                                    std::string_view context)
{
    if (!policy.enforce) return;
    if (!assessment.available) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            strprintf("Unable to verify bridge fee headroom for %s: %s", context, assessment.error));
    }
    if (!assessment.sufficient) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            strprintf("Bridge fee headroom too low for %s. Required at least %s at %.3fx current mempool floor",
                      context,
                      FormatMoney(assessment.required_fee),
                      static_cast<double>(assessment.multiplier_milli) / static_cast<double>(BRIDGE_FEE_HEADROOM_SCALE)));
    }
}

[[nodiscard]] std::optional<uint256> ParseOptionalConflictTxid(const UniValue& value)
{
    if (value.isNull()) return std::nullopt;
    const uint256 txid = ParseHashV(value, "conflict_txid");
    if (txid.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "conflict_txid must be non-zero");
    }
    return txid;
}

[[nodiscard]] std::vector<CTxOut> ParseBridgePayoutsOrThrow(const UniValue& value)
{
    if (!value.isArray() || value.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "payouts must be a non-empty array");
    }

    std::vector<CTxOut> payouts;
    payouts.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        if (!value[i].isObject()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("payouts[%u] must be an object", i));
        }
        const UniValue& address_value = FindValue(value[i], "address");
        const UniValue& amount_value = FindValue(value[i], "amount");
        if (address_value.isNull() || amount_value.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("payouts[%u] requires address and amount", i));
        }
        const CTxDestination dest = ParseDestinationOrThrow(address_value, strprintf("payouts[%u].address", i));
        const CAmount amount = AmountFromValue(amount_value);
        if (amount <= 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("payouts[%u].amount must be positive", i));
        }
        payouts.emplace_back(amount, GetScriptForDestination(dest));
    }
    return payouts;
}

[[nodiscard]] bool ValidateMLKEMImportMaterial(const std::vector<unsigned char>& kem_sk,
                                               const std::vector<unsigned char>& kem_pk)
{
    if (kem_sk.size() != mlkem::SECRETKEYBYTES || kem_pk.size() != mlkem::PUBLICKEYBYTES) {
        return false;
    }

    mlkem::KeyPair keypair;
    std::copy(kem_pk.begin(), kem_pk.end(), keypair.pk.begin());
    keypair.sk.assign(kem_sk.begin(), kem_sk.end());
    const auto enc = mlkem::Encaps(keypair.pk);
    const auto dec = mlkem::Decaps(enc.ct, keypair.sk);
    return dec == enc.ss;
}

[[nodiscard]] bool CommitShieldedTransaction(const std::shared_ptr<CWallet>& pwallet,
                                             const CTransactionRef& tx,
                                             std::string& error,
                                             bool* mempool_rejected = nullptr,
                                             mapValue_t map_value = {})
{
    if (mempool_rejected != nullptr) {
        *mempool_rejected = false;
    }
    LOCK(pwallet->cs_wallet);
    std::string broadcast_error;
    try {
        pwallet->CommitTransaction(
            tx,
            std::move(map_value),
            {},
            /*bypass_maxtxfee=*/false,
            &broadcast_error);
    } catch (const std::exception& e) {
        error = e.what();
    }

    if (!error.empty()) {
        if (pwallet->GetWalletTx(tx->GetHash()) != nullptr) {
            pwallet->AbandonTransaction(tx->GetHash());
        }
        return false;
    }

    if (!pwallet->GetBroadcastTransactions()) return true;

    const CWalletTx* wtx = pwallet->GetWalletTx(tx->GetHash());
    if (wtx == nullptr) {
        error = "Committed shielded transaction was not found in wallet state";
        return false;
    }

    if (!wtx->InMempool() && pwallet->GetTxDepthInMainChain(*wtx) <= 0) {
        pwallet->AbandonTransaction(tx->GetHash());
        if (mempool_rejected != nullptr) {
            *mempool_rejected = true;
        }
        error = broadcast_error.empty()
            ? "Shielded transaction created but rejected from mempool (policy or consensus)"
            : broadcast_error;
        return false;
    }
    return true;
}

[[nodiscard]] bool IsBadShieldedAnchorReject(const std::string& error)
{
    return error.find("bad-shielded-anchor") != std::string::npos;
}

struct ShieldedCommitResult
{
    bool committed{false};
    bool mempool_rejected{false};
    bool stale_anchor{false};
    std::string error;
};

[[nodiscard]] ShieldedCommitResult CommitShieldedTransactionResult(const std::shared_ptr<CWallet>& pwallet,
                                                                  const CTransactionRef& tx,
                                                                  mapValue_t map_value = {})
{
    ShieldedCommitResult result;
    result.committed = CommitShieldedTransaction(
        pwallet,
        tx,
        result.error,
        &result.mempool_rejected,
        std::move(map_value));
    result.stale_anchor = result.mempool_rejected && IsBadShieldedAnchorReject(result.error);
    return result;
}

[[noreturn]] void ThrowShieldedCommitError(const ShieldedCommitResult& result)
{
    const auto code = result.mempool_rejected ? RPC_VERIFY_REJECTED : RPC_WALLET_ERROR;
    throw JSONRPCError(code, result.error.empty() ? "Shielded transaction commit failed" : result.error);
}

template <typename BuildFunc, typename CleanupFunc>
CTransactionRef BuildAndCommitShieldedTransactionWithAnchorRetry(const std::shared_ptr<CWallet>& pwallet,
                                                                 const char* rpc_name,
                                                                 const mapValue_t& map_value,
                                                                 BuildFunc&& build_tx,
                                                                 CleanupFunc&& cleanup)
{
    for (int anchor_attempt = 0; anchor_attempt < MAX_SHIELDED_STALE_ANCHOR_REBUILD_ATTEMPTS; ++anchor_attempt) {
        const CTransactionRef tx = build_tx();
        const auto result = CommitShieldedTransactionResult(pwallet, tx, mapValue_t{map_value});
        if (result.committed) {
            return tx;
        }

        cleanup();
        if (result.stale_anchor &&
            anchor_attempt + 1 < MAX_SHIELDED_STALE_ANCHOR_REBUILD_ATTEMPTS) {
            LogPrintf("%s: retrying shielded transaction after stale anchor reject attempt=%u/%u (%s)\n",
                      rpc_name,
                      static_cast<unsigned int>(anchor_attempt + 2),
                      static_cast<unsigned int>(MAX_SHIELDED_STALE_ANCHOR_REBUILD_ATTEMPTS),
                      result.error);
            pwallet->BlockUntilSyncedToCurrentChain();
            continue;
        }

        ThrowShieldedCommitError(result);
    }

    throw JSONRPCError(
        RPC_WALLET_ERROR,
        strprintf("%s exhausted stale-anchor rebuild attempts", rpc_name));
}

void CommitShieldedTransactionOrThrow(const std::shared_ptr<CWallet>& pwallet,
                                      const CTransactionRef& tx,
                                      mapValue_t map_value = {})
{
    const auto result = CommitShieldedTransactionResult(pwallet, tx, std::move(map_value));
    if (result.committed) return;
    ThrowShieldedCommitError(result);
}

void AbandonReplacedShieldedTransactionIfStale(const std::shared_ptr<CWallet>& pwallet, const uint256& conflict_txid)
{
    LOCK(pwallet->cs_wallet);
    const CWalletTx* wtx = pwallet->GetWalletTx(conflict_txid);
    if (wtx == nullptr) return;
    if (wtx->InMempool()) return;
    if (pwallet->GetTxDepthInMainChain(*wtx) > 0) return;
    pwallet->AbandonTransaction(conflict_txid);
}

[[nodiscard]] bool CommitBridgeTransaction(const std::shared_ptr<CWallet>& pwallet,
                                           const CTransactionRef& tx,
                                           std::string& error,
                                           mapValue_t map_value = {})
{
    LOCK(pwallet->cs_wallet);
    try {
        pwallet->CommitTransaction(tx, std::move(map_value), {}, /*bypass_maxtxfee=*/false);
    } catch (const std::exception& e) {
        error = e.what();
    }

    if (!error.empty()) {
        if (pwallet->GetWalletTx(tx->GetHash()) != nullptr) {
            pwallet->AbandonTransaction(tx->GetHash());
        }
        return false;
    }

    if (!pwallet->GetBroadcastTransactions()) return true;

    const CWalletTx* wtx = pwallet->GetWalletTx(tx->GetHash());
    if (wtx == nullptr) {
        error = "Committed bridge settlement transaction was not found in wallet state";
        return false;
    }

    if (!wtx->InMempool() && pwallet->GetTxDepthInMainChain(*wtx) <= 0) {
        pwallet->AbandonTransaction(tx->GetHash());
        error = "Bridge settlement transaction created but rejected from mempool (policy or consensus)";
        return false;
    }
    return true;
}

void CommitBridgeTransactionOrThrow(const std::shared_ptr<CWallet>& pwallet,
                                    const CTransactionRef& tx,
                                    mapValue_t map_value = {})
{
    std::string error;
    if (CommitBridgeTransaction(pwallet, tx, error, std::move(map_value))) return;

    const RPCErrorCode code = error == "Bridge settlement transaction created but rejected from mempool (policy or consensus)"
        ? RPC_VERIFY_REJECTED
        : RPC_WALLET_ERROR;
    throw JSONRPCError(code, error);
}

[[nodiscard]] UniValue ShieldedSendResultToUniValue(const CTransactionRef& tx,
                                                    const CAmount fee,
                                                    const bool verbose,
                                                    const bool redact_sensitive)
{
    if (!verbose) {
        return tx->GetHash().GetHex();
    }

    UniValue out(UniValue::VOBJ);
    out.pushKV("txid", tx->GetHash().GetHex());
    PushShieldedBundleFamily(out, tx->GetShieldedBundle(), redact_sensitive);
    if (redact_sensitive) {
        out.pushKV("io_counts_redacted", true);
    } else {
        out.pushKV("spends", static_cast<int64_t>(tx->GetShieldedBundle().GetShieldedInputCount()));
        out.pushKV("outputs", static_cast<int64_t>(tx->GetShieldedBundle().GetShieldedOutputCount()));
    }
    out.pushKV("fee", ValueFromAmount(fee));
    return out;
}

[[nodiscard]] UniValue RebalanceSubmitResultToUniValue(const CTransactionRef& tx,
                                                       const CAmount fee,
                                                       const bool redact_sensitive)
{
    const auto* bundle = tx->GetShieldedBundle().GetV2Bundle();
    CHECK_NONFATAL(bundle != nullptr);
    CHECK_NONFATAL(shielded::v2::BundleHasSemanticFamily(*bundle,
                                                         shielded::v2::TransactionFamily::V2_REBALANCE));

    const auto& payload = std::get<shielded::v2::RebalancePayload>(bundle->payload);
    UniValue out(UniValue::VOBJ);
    out.pushKV("txid", tx->GetHash().GetHex());
    PushShieldedBundleFamily(out, tx->GetShieldedBundle(), redact_sensitive);
    out.pushKV("fee", ValueFromAmount(fee));
    if (redact_sensitive) {
        out.pushKV("bundle_metadata_redacted", true);
    } else {
        out.pushKV("reserve_domain_count", static_cast<int64_t>(payload.reserve_deltas.size()));
        out.pushKV("reserve_output_count", static_cast<int64_t>(payload.reserve_outputs.size()));
        out.pushKV("output_chunk_count", static_cast<int64_t>(bundle->output_chunks.size()));
        out.pushKV("netting_manifest_id", shielded::v2::ComputeNettingManifestId(payload.netting_manifest).GetHex());
        out.pushKV("settlement_binding_digest", payload.settlement_binding_digest.GetHex());
        out.pushKV("batch_statement_digest", payload.batch_statement_digest.GetHex());
    }
    return out;
}

[[nodiscard]] CAmount RequiredMempoolFee(const CWallet& wallet, size_t relay_vsize, bool has_shielded_bundle)
{
    CFeeRate floor_rate = wallet.chain().relayMinFee();
    const CFeeRate mempool_floor = wallet.chain().mempoolMinFee();
    if (mempool_floor > floor_rate) floor_rate = mempool_floor;

    CAmount required = floor_rate.GetFee(relay_vsize);
    if (has_shielded_bundle) {
        if (required >= std::numeric_limits<CAmount>::max() - MIN_SHIELDED_RELAY_FEE_PREMIUM) {
            return std::numeric_limits<CAmount>::max();
        }
        required += MIN_SHIELDED_RELAY_FEE_PREMIUM;
    }
    return required;
}

[[nodiscard]] CAmount RequiredMempoolFee(const CWallet& wallet, const CTransaction& tx)
{
    return RequiredMempoolFee(wallet, ShieldedRelayVirtualSize(tx), tx.HasShieldedBundle());
}

struct P2MRMultisigLeaf
{
    uint8_t threshold{0};
    std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>> pubkeys;
};

[[nodiscard]] size_t ExpectedP2MRSignatureSize(PQAlgorithm algo)
{
    if (algo == PQAlgorithm::ML_DSA_44) return MLDSA44_SIGNATURE_SIZE;
    if (algo == PQAlgorithm::SLH_DSA_128S) return SLHDSA128S_SIGNATURE_SIZE;
    return 0;
}

[[nodiscard]] size_t ExpectedP2MRSignatureSize(size_t pubkey_size)
{
    if (pubkey_size == MLDSA44_PUBKEY_SIZE) return MLDSA44_SIGNATURE_SIZE;
    if (pubkey_size == SLHDSA128S_PUBKEY_SIZE) return SLHDSA128S_SIGNATURE_SIZE;
    return 0;
}

[[nodiscard]] std::optional<PQAlgorithm> ParseP2MRChecksigAlgo(Span<const unsigned char> leaf_script)
{
    if (!leaf_script.empty() && leaf_script.back() == OP_CHECKSIG_MLDSA) {
        if (leaf_script.size() >= 1 + 3 + MLDSA44_PUBKEY_SIZE) {
            const size_t offset = leaf_script.size() - (1 + 3 + MLDSA44_PUBKEY_SIZE);
            if (leaf_script[offset] == OP_PUSHDATA2 &&
                leaf_script[offset + 1] == static_cast<unsigned char>(MLDSA44_PUBKEY_SIZE & 0xFF) &&
                leaf_script[offset + 2] == static_cast<unsigned char>((MLDSA44_PUBKEY_SIZE >> 8) & 0xFF)) {
                return PQAlgorithm::ML_DSA_44;
            }
        }
    }

    if (!leaf_script.empty() && leaf_script.back() == OP_CHECKSIG_SLHDSA) {
        if (leaf_script.size() >= 1 + 1 + SLHDSA128S_PUBKEY_SIZE) {
            const size_t offset = leaf_script.size() - (1 + 1 + SLHDSA128S_PUBKEY_SIZE);
            if (leaf_script[offset] == static_cast<unsigned char>(SLHDSA128S_PUBKEY_SIZE)) {
                return PQAlgorithm::SLH_DSA_128S;
            }
        }
    }

    return std::nullopt;
}

[[nodiscard]] std::optional<P2MRMultisigLeaf> ParseP2MRMultisigLeaf(Span<const unsigned char> script)
{
    size_t offset{0};
    std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>> keys;
    std::set<std::pair<PQAlgorithm, std::vector<unsigned char>>> unique_keys;

    while (offset < script.size()) {
        Span<const unsigned char> pubkey;
        PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
        size_t push_consumed{0};
        if (!ParseP2MRAnyPubkeyPush(script, offset, algo, pubkey, push_consumed)) break;

        offset += push_consumed;
        if (offset >= script.size()) return std::nullopt;
        const opcodetype observed = static_cast<opcodetype>(script[offset]);
        const opcodetype expected = keys.empty() ? GetP2MRChecksigOpcode(algo) : GetP2MRChecksigAddOpcode(algo);
        if (observed != expected) return std::nullopt;
        ++offset;

        std::vector<unsigned char> key_bytes(pubkey.begin(), pubkey.end());
        if (!unique_keys.emplace(algo, key_bytes).second) return std::nullopt;
        keys.emplace_back(algo, std::move(key_bytes));
    }

    if (keys.size() < 2) return std::nullopt;
    if (offset + 2 != script.size()) return std::nullopt;

    const opcodetype threshold_opcode = static_cast<opcodetype>(script[offset]);
    if (threshold_opcode < OP_1 || threshold_opcode > OP_16) return std::nullopt;
    const uint8_t threshold = static_cast<uint8_t>(CScript::DecodeOP_N(threshold_opcode));
    if (threshold == 0 || threshold > keys.size()) return std::nullopt;
    if (static_cast<opcodetype>(script[offset + 1]) != OP_NUMEQUAL) return std::nullopt;

    return P2MRMultisigLeaf{threshold, std::move(keys)};
}

[[nodiscard]] bool IsWellFormedPlaceholderP2MRSig(Span<const unsigned char> sig, size_t expected_sig_size)
{
    return sig.size() == expected_sig_size || sig.size() == expected_sig_size + 1;
}

[[nodiscard]] bool HasExactP2MRMultisigWitnessSize(const P2MRMultisigLeaf& multisig)
{
    if (multisig.threshold == multisig.pubkeys.size()) return true;
    if (multisig.pubkeys.empty()) return false;

    const size_t reference_sig_size = ExpectedP2MRSignatureSize(multisig.pubkeys.front().first);
    if (reference_sig_size == 0) return false;

    for (const auto& [algo, _pubkey] : multisig.pubkeys) {
        if (ExpectedP2MRSignatureSize(algo) != reference_sig_size) return false;
    }
    return true;
}

[[nodiscard]] std::optional<CScriptWitness> BuildP2MRPlaceholderWitness(const PSBTInput& input)
{
    if (input.m_p2mr_leaf_script.empty() || input.m_p2mr_control_block.empty()) return std::nullopt;

    CScriptWitness witness;
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, input.m_p2mr_leaf_script);

    if (!input.m_p2mr_csfs_msgs.empty()) {
        for (const auto& [leaf_pubkey, msg] : input.m_p2mr_csfs_msgs) {
            if (leaf_pubkey.first != leaf_hash) continue;
            const size_t sig_size = ExpectedP2MRSignatureSize(leaf_pubkey.second.size());
            if (sig_size == 0) return std::nullopt;
            witness.stack.emplace_back(sig_size, 0);
            witness.stack.push_back(msg);
            witness.stack.push_back(input.m_p2mr_leaf_script);
            witness.stack.push_back(input.m_p2mr_control_block);
            return witness;
        }
        return std::nullopt;
    }

    if (const auto multisig = ParseP2MRMultisigLeaf(
            Span<const unsigned char>{input.m_p2mr_leaf_script.data(), input.m_p2mr_leaf_script.size()});
        multisig.has_value()) {
        if (!HasExactP2MRMultisigWitnessSize(*multisig)) return std::nullopt;

        std::vector<std::vector<unsigned char>> selected_sigs(multisig->pubkeys.size());
        size_t selected_count{0};
        for (PQAlgorithm algo_preference : {PQAlgorithm::ML_DSA_44, PQAlgorithm::SLH_DSA_128S}) {
            for (size_t i = 0; i < multisig->pubkeys.size() && selected_count < multisig->threshold; ++i) {
                if (!selected_sigs[i].empty()) continue;
                const auto& [algo, pubkey] = multisig->pubkeys[i];
                if (algo != algo_preference) continue;

                const auto existing_sig = input.m_p2mr_pq_sigs.find({leaf_hash, pubkey});
                const size_t expected_sig_size = ExpectedP2MRSignatureSize(algo);
                if (expected_sig_size == 0) return std::nullopt;

                if (existing_sig != input.m_p2mr_pq_sigs.end() &&
                    IsWellFormedPlaceholderP2MRSig(existing_sig->second, expected_sig_size)) {
                    selected_sigs[i] = existing_sig->second;
                } else {
                    selected_sigs[i] = std::vector<unsigned char>(expected_sig_size, 0);
                }
                ++selected_count;
            }
        }
        if (selected_count != multisig->threshold) return std::nullopt;

        witness.stack.reserve(selected_sigs.size() + 2);
        for (size_t i = selected_sigs.size(); i > 0; --i) {
            witness.stack.push_back(std::move(selected_sigs[i - 1]));
        }
        witness.stack.push_back(input.m_p2mr_leaf_script);
        witness.stack.push_back(input.m_p2mr_control_block);
        return witness;
    }

    const auto algo = ParseP2MRChecksigAlgo(Span<const unsigned char>{input.m_p2mr_leaf_script.data(),
                                                                      input.m_p2mr_leaf_script.size()});
    if (!algo.has_value()) return std::nullopt;

    const size_t sig_size = ExpectedP2MRSignatureSize(*algo);
    if (sig_size == 0) return std::nullopt;
    witness.stack.emplace_back(sig_size, 0);
    witness.stack.push_back(input.m_p2mr_leaf_script);
    witness.stack.push_back(input.m_p2mr_control_block);
    return witness;
}

[[nodiscard]] BridgePsbtRelayFeeAnalysis AnalyzeBridgePsbtRelayFee(const CWallet& wallet,
                                                                   const PartiallySignedTransaction& psbt)
{
    BridgePsbtRelayFeeAnalysis result;

    if (psbt.tx->vin.size() != psbt.inputs.size()) {
        result.error = "PSBT input metadata does not match transaction input count";
        return result;
    }

    CAmount transparent_input_value{0};
    for (unsigned int i = 0; i < psbt.tx->vin.size(); ++i) {
        CTxOut utxo;
        if (!psbt.GetInputUTXO(utxo, i)) {
            result.error = strprintf("Missing input UTXO for input %u", i);
            return result;
        }
        if (!MoneyRange(utxo.nValue)) {
            result.error = strprintf("Input %u has invalid value", i);
            return result;
        }
        const auto next = CheckedAdd(transparent_input_value, utxo.nValue);
        if (!next.has_value() || !MoneyRange(*next)) {
            result.error = "Transparent input value overflow";
            return result;
        }
        transparent_input_value = *next;
    }

    CAmount transparent_output_value{0};
    for (const auto& txout : psbt.tx->vout) {
        if (!MoneyRange(txout.nValue)) {
            result.error = "Transaction output value is out of range";
            return result;
        }
        const auto next = CheckedAdd(transparent_output_value, txout.nValue);
        if (!next.has_value() || !MoneyRange(*next)) {
            result.error = "Transparent output value overflow";
            return result;
        }
        transparent_output_value = *next;
    }

    const CAmount shielded_value_balance = psbt.tx->HasShieldedBundle() ? psbt.tx->GetShieldedBundle().value_balance : 0;
    if (!MoneyRangeSigned(shielded_value_balance)) {
        result.error = "Shielded value balance is out of range";
        return result;
    }

    const auto adjusted_input = CheckedAdd(transparent_input_value, shielded_value_balance);
    if (!adjusted_input.has_value() || !MoneyRange(*adjusted_input)) {
        result.error = "Adjusted input value overflow";
        return result;
    }
    if (*adjusted_input < transparent_output_value) {
        result.error = "Adjusted input value is below transaction outputs";
        return result;
    }

    const CAmount estimated_fee = *adjusted_input - transparent_output_value;
    if (!MoneyRange(estimated_fee)) {
        result.error = "Estimated fee is out of range";
        return result;
    }

    CMutableTransaction mtx(*psbt.tx);
    CCoinsView view_dummy;
    CCoinsViewCache view(&view_dummy);

    for (unsigned int i = 0; i < psbt.tx->vin.size(); ++i) {
        const PSBTInput& input = psbt.inputs[i];
        const auto witness = BuildP2MRPlaceholderWitness(input);
        if (!witness.has_value()) {
            result.error = strprintf("Unable to derive exact witness template for input %u", i);
            return result;
        }
        mtx.vin[i].scriptWitness = *witness;

        CTxOut utxo;
        if (!psbt.GetInputUTXO(utxo, i)) {
            result.error = strprintf("Missing input UTXO for input %u", i);
            return result;
        }
        Coin coin;
        coin.out = utxo;
        coin.nHeight = 1;
        view.AddCoin(psbt.tx->vin[i].prevout, std::move(coin), true);
    }

    const CTransaction finalized_tx(mtx);
    const int64_t estimated_sigop_cost = GetTransactionSigOpCost(finalized_tx, view, STANDARD_SCRIPT_VERIFY_FLAGS);
    const int32_t extra_weight = CalculateExtraTxWeight(finalized_tx, view, ::g_weight_per_data_byte);
    const size_t estimated_vsize = GetVirtualTransactionSize(
        GetTransactionWeight(finalized_tx) + extra_weight,
        estimated_sigop_cost,
        ::nBytesPerSigOp);
    if (estimated_vsize == 0) {
        result.error = "Estimated virtual size is zero";
        return result;
    }

    const CFeeRate relay_floor = wallet.chain().relayMinFee();
    const CFeeRate mempool_floor = wallet.chain().mempoolMinFee();
    const CAmount relay_fee_floor = relay_floor.GetFee(estimated_vsize);
    const CAmount mempool_fee_floor = mempool_floor.GetFee(estimated_vsize);
    const CAmount required_base_fee = std::max(relay_fee_floor, mempool_fee_floor);
    const CAmount required_shielded_fee_premium = finalized_tx.HasShieldedBundle() ? MIN_SHIELDED_RELAY_FEE_PREMIUM : 0;
    const auto required_total_fee = CheckedAdd(required_base_fee, required_shielded_fee_premium);
    if (!required_total_fee.has_value() || !MoneyRange(*required_total_fee)) {
        result.error = "Required total fee overflow";
        return result;
    }

    result.available = true;
    result.transparent_input_value = transparent_input_value;
    result.transparent_output_value = transparent_output_value;
    result.shielded_value_balance = shielded_value_balance;
    result.estimated_fee = estimated_fee;
    result.estimated_vsize = estimated_vsize;
    result.estimated_sigop_cost = estimated_sigop_cost;
    result.estimated_feerate = CFeeRate(estimated_fee, estimated_vsize);
    result.relay_fee_floor = relay_fee_floor;
    result.mempool_fee_floor = mempool_fee_floor;
    result.required_base_fee = required_base_fee;
    result.required_shielded_fee_premium = required_shielded_fee_premium;
    result.required_total_fee = *required_total_fee;
    result.fee_sufficient = estimated_fee >= *required_total_fee;
    return result;
}

[[nodiscard]] CAmount RedactedBridgeFeeAmount(CAmount amount, int32_t build_height)
{
    if (amount <= 0) return amount;
    return shielded::RoundShieldedFeeToCanonicalBucket(amount, Params().GetConsensus(), build_height);
}

void AppendBridgePsbtRelayFeeAnalysis(UniValue& out,
                                      const BridgePsbtRelayFeeAnalysis& analysis,
                                      int32_t build_height,
                                      const BridgeFeeHeadroomPolicy& headroom_policy = {})
{
    const BridgeFeeHeadroomAssessment headroom = EvaluateBridgeFeeHeadroom(analysis, headroom_policy);
    const bool redact_sensitive =
        wallet::RedactSensitiveShieldedRpcFieldsAtHeight(build_height, /*include_sensitive=*/false);

    out.pushKV("fee_authoritative", analysis.available);
    out.pushKV("relay_fee_sufficient", analysis.available && analysis.fee_sufficient);
    out.pushKV("relay_fee_analysis_available", analysis.available);
    out.pushKV("fee_headroom_enforced", headroom_policy.enforce);
    out.pushKV("fee_headroom_multiplier",
               static_cast<double>(headroom.multiplier_milli) / static_cast<double>(BRIDGE_FEE_HEADROOM_SCALE));
    out.pushKV("fee_headroom_sufficient", headroom.available && headroom.sufficient);
    if (!headroom.available) {
        out.pushKV("fee_headroom_error", headroom.error);
    } else if (redact_sensitive) {
        out.pushKV("required_fee_headroom_redacted", true);
        out.pushKV("required_fee_headroom_bucket",
                   ValueFromAmount(RedactedBridgeFeeAmount(headroom.required_fee, build_height)));
        if (!headroom.sufficient) {
            out.pushKV("fee_headroom_warning", "Estimated fee is below the requested bridge headroom target");
        }
    } else {
        out.pushKV("required_fee_headroom", ValueFromAmount(headroom.required_fee));
        if (!headroom.sufficient) {
            out.pushKV("fee_headroom_warning",
                       strprintf("Estimated fee %s is below the requested %.3fx bridge headroom target of %s",
                                 FormatMoney(analysis.estimated_fee),
                                 static_cast<double>(headroom.multiplier_milli) /
                                     static_cast<double>(BRIDGE_FEE_HEADROOM_SCALE),
                                 FormatMoney(headroom.required_fee)));
        }
    }

    if (!analysis.available) {
        out.pushKV("fee_authoritative_error", analysis.error);
        out.pushKV("relay_fee_analysis_error", analysis.error);
        return;
    }

    const CAmount required_fee_out = redact_sensitive
        ? RedactedBridgeFeeAmount(analysis.required_total_fee, build_height)
        : analysis.required_total_fee;

    out.pushKV("estimated_vsize", static_cast<int64_t>(analysis.estimated_vsize));
    out.pushKV("estimated_sigop_cost", analysis.estimated_sigop_cost);
    out.pushKV("required_mempool_fee", ValueFromAmount(required_fee_out));

    UniValue fee_analysis(UniValue::VOBJ);
    fee_analysis.pushKV("estimated_vsize", static_cast<int64_t>(analysis.estimated_vsize));
    fee_analysis.pushKV("estimated_sigop_cost", analysis.estimated_sigop_cost);
    fee_analysis.pushKV("fee_sufficient", analysis.fee_sufficient);
    fee_analysis.pushKV("fee_headroom_multiplier",
                        static_cast<double>(headroom.multiplier_milli) / static_cast<double>(BRIDGE_FEE_HEADROOM_SCALE));
    fee_analysis.pushKV("fee_headroom_enforced", headroom_policy.enforce);
    fee_analysis.pushKV("fee_headroom_sufficient", headroom.available && headroom.sufficient);
    if (!headroom.available) {
        fee_analysis.pushKV("fee_headroom_error", headroom.error);
    } else if (redact_sensitive) {
        fee_analysis.pushKV("required_fee_headroom_redacted", true);
        fee_analysis.pushKV("required_fee_headroom_bucket",
                            ValueFromAmount(RedactedBridgeFeeAmount(headroom.required_fee, build_height)));
        if (!headroom.sufficient) {
            fee_analysis.pushKV("fee_headroom_warning",
                                "Estimated fee is below the requested bridge headroom target");
        }
    } else {
        fee_analysis.pushKV("required_fee_headroom", ValueFromAmount(headroom.required_fee));
        if (!headroom.sufficient) {
            fee_analysis.pushKV("fee_headroom_warning",
                                strprintf("Estimated fee %s is below the requested %.3fx bridge headroom target of %s",
                                          FormatMoney(analysis.estimated_fee),
                                          static_cast<double>(headroom.multiplier_milli) /
                                              static_cast<double>(BRIDGE_FEE_HEADROOM_SCALE),
                                          FormatMoney(headroom.required_fee)));
        }
    }

    if (redact_sensitive) {
        fee_analysis.pushKV("transparent_input_value_redacted", true);
        fee_analysis.pushKV("transparent_output_value_redacted", true);
        fee_analysis.pushKV("shielded_value_balance_redacted", true);
        fee_analysis.pushKV("estimated_fee_redacted", true);
        fee_analysis.pushKV("estimated_feerate_redacted", true);
        fee_analysis.pushKV("relay_fee_floor_redacted", true);
        fee_analysis.pushKV("mempool_fee_floor_redacted", true);
        fee_analysis.pushKV("required_base_fee_redacted", true);
        fee_analysis.pushKV("required_shielded_fee_premium_redacted", true);
        fee_analysis.pushKV("required_total_fee_redacted", true);
        fee_analysis.pushKV("required_mempool_fee_redacted", true);
        fee_analysis.pushKV("estimated_fee_bucket",
                            ValueFromAmount(RedactedBridgeFeeAmount(analysis.estimated_fee, build_height)));
        fee_analysis.pushKV("relay_fee_floor_bucket",
                            ValueFromAmount(RedactedBridgeFeeAmount(analysis.relay_fee_floor, build_height)));
        fee_analysis.pushKV("mempool_fee_floor_bucket",
                            ValueFromAmount(RedactedBridgeFeeAmount(analysis.mempool_fee_floor, build_height)));
        fee_analysis.pushKV("required_base_fee_bucket",
                            ValueFromAmount(RedactedBridgeFeeAmount(analysis.required_base_fee, build_height)));
        fee_analysis.pushKV("required_shielded_fee_premium_bucket",
                            ValueFromAmount(RedactedBridgeFeeAmount(analysis.required_shielded_fee_premium, build_height)));
        fee_analysis.pushKV("required_total_fee_bucket", ValueFromAmount(required_fee_out));
        fee_analysis.pushKV("required_mempool_fee_bucket", ValueFromAmount(required_fee_out));
    } else {
        fee_analysis.pushKV("transparent_input_value", ValueFromAmount(analysis.transparent_input_value));
        fee_analysis.pushKV("transparent_output_value", ValueFromAmount(analysis.transparent_output_value));
        fee_analysis.pushKV("shielded_value_balance", ValueFromAmount(analysis.shielded_value_balance));
        fee_analysis.pushKV("estimated_fee", ValueFromAmount(analysis.estimated_fee));
        fee_analysis.pushKV("estimated_feerate", analysis.estimated_feerate.ToString(FeeEstimateMode::SAT_VB));
        fee_analysis.pushKV("relay_fee_floor", ValueFromAmount(analysis.relay_fee_floor));
        fee_analysis.pushKV("mempool_fee_floor", ValueFromAmount(analysis.mempool_fee_floor));
        fee_analysis.pushKV("required_base_fee", ValueFromAmount(analysis.required_base_fee));
        fee_analysis.pushKV("required_shielded_fee_premium", ValueFromAmount(analysis.required_shielded_fee_premium));
        fee_analysis.pushKV("required_total_fee", ValueFromAmount(analysis.required_total_fee));
        fee_analysis.pushKV("required_mempool_fee", ValueFromAmount(analysis.required_total_fee));
    }
    out.pushKV("relay_fee_analysis", std::move(fee_analysis));
}

[[nodiscard]] ShieldingPolicySnapshot GetShieldingPolicySnapshot(const CWallet& wallet,
                                                                std::optional<size_t> override_max_inputs)
{
    ShieldingPolicySnapshot policy;
    policy.soft_target_tx_weight = std::min<int64_t>(DEFAULT_SHIELD_SWEEP_SOFT_TARGET_WEIGHT, MAX_STANDARD_TX_WEIGHT);
    policy.recommended_max_inputs_per_chunk = DEFAULT_SHIELD_SWEEP_MAX_INPUTS_PER_CHUNK;
    policy.applied_max_inputs_per_chunk = override_max_inputs.value_or(policy.recommended_max_inputs_per_chunk);
    if (policy.applied_max_inputs_per_chunk < policy.min_inputs_per_chunk) {
        policy.applied_max_inputs_per_chunk = policy.min_inputs_per_chunk;
    }
    policy.relay_fee_floor = wallet.chain().relayMinFee().GetFee(1000);
    policy.mempool_fee_floor = wallet.chain().mempoolMinFee().GetFee(1000);
    if (UseCoinbaseOnlyShieldingCompatibility(wallet)) {
        policy.selection_strategy = "coinbase-largest-first";
    }
    return policy;
}

[[nodiscard]] std::vector<TransparentShieldingUTXO> CollectSpendableTransparentShieldingUTXOs(
    const CWallet& wallet,
    bool coinbase_only = false)
{
    std::vector<TransparentShieldingUTXO> coins;
    LOCK(wallet.cs_wallet);
    for (const auto& [txid, wtx] : wallet.mapWallet) {
        if (wtx.IsCoinBase() && wallet.GetTxBlocksToMaturity(wtx) > 0) continue;
        if (coinbase_only && !wtx.IsCoinBase()) continue;
        for (uint32_t n = 0; n < wtx.tx->vout.size(); ++n) {
            if (!(wallet.IsMine(wtx.tx->vout[n]) & ISMINE_SPENDABLE)) continue;
            const COutPoint outpoint{Txid::FromUint256(txid), n};
            if (wallet.IsSpent(outpoint)) continue;
            if (wallet.IsLockedCoin(outpoint)) continue;
            coins.push_back({outpoint, wtx.tx->vout[n].nValue, wtx.IsCoinBase()});
        }
    }

    std::sort(coins.begin(), coins.end(), [](const auto& a, const auto& b) {
        return std::tie(a.value, a.outpoint.hash, a.outpoint.n) >
               std::tie(b.value, b.outpoint.hash, b.outpoint.n);
    });
    return coins;
}

[[nodiscard]] std::optional<CAmount> SumTransparentShieldingUTXOValues(
    Span<const TransparentShieldingUTXO> coins)
{
    CAmount total{0};
    for (const auto& coin : coins) {
        const auto next = CheckedAdd(total, coin.value);
        if (!next || !MoneyRange(*next)) {
            return std::nullopt;
        }
        total = *next;
    }
    return total;
}

[[nodiscard]] std::optional<ShieldedAddress> ResolveShieldingDestination(const std::shared_ptr<CWallet>& pwallet,
                                                                         std::optional<ShieldedAddress> requested_dest,
                                                                         bool allow_generate,
                                                                         std::string& error)
{
    LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
    if (requested_dest.has_value()) {
        return requested_dest;
    }

    auto preferred = pwallet->m_shielded_wallet->GetPreferredReceiveAddress();
    if (preferred.has_value()) {
        return preferred;
    }

    if (!allow_generate) {
        error = "No shielded destination available; provide one explicitly or create a shielded address first";
        return std::nullopt;
    }

    if (!pwallet->IsCrypted()) {
        error = "Shielded keys require an encrypted wallet; encrypt this wallet before using shielded features";
        return std::nullopt;
    }

    return pwallet->m_shielded_wallet->GenerateNewAddress();
}

[[nodiscard]] size_t ReduceShieldingInputLimit(size_t current_limit, size_t minimum_limit)
{
    if (current_limit <= minimum_limit) return minimum_limit;
    return std::max(minimum_limit, current_limit / 2);
}

[[nodiscard]] UniValue PolicyToUniValue(const ShieldingPolicySnapshot& policy)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("selection_strategy", policy.selection_strategy);
    out.pushKV("max_standard_tx_weight", policy.max_standard_tx_weight);
    out.pushKV("soft_target_tx_weight", policy.soft_target_tx_weight);
    out.pushKV("recommended_max_inputs_per_chunk", static_cast<int64_t>(policy.recommended_max_inputs_per_chunk));
    out.pushKV("applied_max_inputs_per_chunk", static_cast<int64_t>(policy.applied_max_inputs_per_chunk));
    out.pushKV("min_inputs_per_chunk", static_cast<int64_t>(policy.min_inputs_per_chunk));
    out.pushKV("relay_fee_floor_per_kb", ValueFromAmount(policy.relay_fee_floor));
    out.pushKV("mempool_fee_floor_per_kb", ValueFromAmount(policy.mempool_fee_floor));
    out.pushKV("shielded_fee_premium", ValueFromAmount(policy.shielded_fee_premium));
    return out;
}

[[nodiscard]] UniValue ChunkToUniValue(const ShieldingChunkPreview& chunk)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("txid", chunk.tx ? chunk.tx->GetHash().GetHex() : "");
    out.pushKV("gross_amount", ValueFromAmount(chunk.gross_amount));
    out.pushKV("amount", ValueFromAmount(chunk.shielded_amount));
    out.pushKV("fee", ValueFromAmount(chunk.fee));
    out.pushKV("transparent_inputs", static_cast<int64_t>(chunk.selected.size()));
    out.pushKV("tx_weight", chunk.tx_weight);
    return out;
}

[[nodiscard]] std::optional<ShieldingChunkPreview> BuildShieldingChunkPreview(
    const std::shared_ptr<CWallet>& pwallet,
    const std::vector<TransparentShieldingUTXO>& available_coins,
    const ShieldedAddress& dest,
    const CAmount remaining_requested,
    const bool explicit_fee,
    const CAmount initial_fee,
    size_t input_limit,
    const ShieldingPolicySnapshot& policy,
    std::string& error)
{
    if (available_coins.empty()) {
        error = "Insufficient transparent funds";
        return std::nullopt;
    }

    input_limit = std::max(policy.min_inputs_per_chunk, input_limit);
    const CAmount chunk_requested = std::min(remaining_requested, GetShieldingChunkSmileValueLimit());
    for (int rebuild = 0; rebuild < MAX_SHIELD_SWEEP_REBUILD_ATTEMPTS; ++rebuild) {
        std::vector<TransparentShieldingUTXO> selected;
        selected.reserve(std::min(input_limit, available_coins.size()));
        CAmount gross_amount{0};
        CAmount fee{CanonicalizeShieldingFee(*pwallet, initial_fee)};
        const auto desired_total = CheckedAdd(chunk_requested, fee);
        if (!desired_total || !MoneyRange(*desired_total)) {
            error = "Requested amount + fee overflows";
            return std::nullopt;
        }

        for (const auto& coin : available_coins) {
            selected.push_back(coin);
            const auto next = CheckedAdd(gross_amount, coin.value);
            if (!next || !MoneyRange(*next)) {
                error = "Input value overflow";
                return std::nullopt;
            }
            gross_amount = *next;
            if (selected.size() >= input_limit || gross_amount >= *desired_total) break;
        }

        if (selected.empty() || gross_amount <= fee) {
            error = "Insufficient transparent funds";
            return std::nullopt;
        }

        CTransactionRef tx;
        for (int attempt = 0; attempt < MAX_SHIELDED_FEE_CONVERGENCE_ATTEMPTS; ++attempt) {
            std::optional<CMutableTransaction> mtx;
            std::string create_error;
            {
                LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
                std::vector<COutPoint> outpoints;
                outpoints.reserve(selected.size());
                for (const auto& coin : selected) {
                    outpoints.push_back(coin.outpoint);
                }
                mtx = pwallet->m_shielded_wallet->ShieldFunds(
                    outpoints,
                    fee,
                    dest,
                    chunk_requested,
                    &create_error);
            }
            if (!mtx.has_value()) {
                error = create_error.empty() ? "Failed to create shielding transaction" : create_error;
                return std::nullopt;
            }

            CTransactionRef candidate = MakeTransactionRef(std::move(*mtx));
            const CAmount required_fee = RequiredMempoolFee(*pwallet, *candidate);
            if (fee >= required_fee) {
                tx = std::move(candidate);
                break;
            }

            if (explicit_fee) {
                error = strprintf("Fee too low for transaction size. Required at least %s", FormatMoney(required_fee));
                return std::nullopt;
            }

            fee = CanonicalizeShieldingFee(*pwallet, required_fee);
        }

        if (!tx) {
            error = "Failed to create fee-compliant shielding transaction";
            return std::nullopt;
        }

        const int64_t tx_weight = GetTransactionWeight(*tx);
        if (tx_weight > policy.soft_target_tx_weight && input_limit > policy.min_inputs_per_chunk) {
            const size_t next_limit = ReduceShieldingInputLimit(std::min(input_limit, selected.size()), policy.min_inputs_per_chunk);
            if (next_limit == input_limit) break;
            input_limit = next_limit;
            continue;
        }

        ShieldingChunkPreview preview;
        preview.selected = std::move(selected);
        preview.tx = std::move(tx);
        preview.gross_amount = gross_amount;
        preview.fee = fee;
        preview.shielded_amount = std::min(chunk_requested, gross_amount - fee);
        preview.tx_weight = tx_weight;
        return preview;
    }

    error = "Failed to build shielding chunk within policy limits";
    return std::nullopt;
}

[[nodiscard]] std::optional<ShieldingPlanPreview> BuildShieldingPlanPreview(
    const std::shared_ptr<CWallet>& pwallet,
    const CAmount requested,
    const ShieldedAddress& dest,
    const bool explicit_fee,
    const CAmount fee,
    ShieldingPolicySnapshot policy,
    std::string& error)
{
    ShieldingPlanPreview plan;
    plan.policy = policy;
    plan.requested_amount = requested;
    const bool coinbase_only_compatibility = UseCoinbaseOnlyShieldingCompatibility(*pwallet);
    const auto all_available = CollectSpendableTransparentShieldingUTXOs(*pwallet);
    auto total_spendable = SumTransparentShieldingUTXOValues(
        Span<const TransparentShieldingUTXO>{all_available.data(), all_available.size()});
    if (!total_spendable.has_value()) {
        error = "Input value overflow";
        return std::nullopt;
    }

    std::vector<TransparentShieldingUTXO> available =
        coinbase_only_compatibility
            ? CollectSpendableTransparentShieldingUTXOs(*pwallet, /*coinbase_only=*/true)
            : all_available;
    auto compatible_spendable = SumTransparentShieldingUTXOValues(
        Span<const TransparentShieldingUTXO>{available.data(), available.size()});
    if (!compatible_spendable.has_value()) {
        error = "Input value overflow";
        return std::nullopt;
    }

    plan.spendable_utxos = available.size();
    plan.spendable_amount = *compatible_spendable;
    if (plan.spendable_amount <= 0) {
        error = coinbase_only_compatibility && !all_available.empty()
            ? GetPostForkCoinbaseShieldingCompatibilityMessage()
            : "Insufficient transparent funds";
        return std::nullopt;
    }
    if (plan.spendable_amount < requested) {
        if (coinbase_only_compatibility && *total_spendable >= requested) {
            error = GetPostForkCoinbaseShieldingCompatibilityMessage();
            return std::nullopt;
        }
        error = "Insufficient transparent funds";
        return std::nullopt;
    }

    CAmount remaining_requested = requested;
    while (remaining_requested > 0) {
        auto preview = BuildShieldingChunkPreview(
            pwallet,
            available,
            dest,
            remaining_requested,
            explicit_fee,
            fee,
            plan.policy.applied_max_inputs_per_chunk,
            plan.policy,
            error);
        if (!preview.has_value()) {
            return std::nullopt;
        }

        plan.estimated_total_fee += preview->fee;
        plan.estimated_total_shielded += preview->shielded_amount;
        remaining_requested -= preview->shielded_amount;
        plan.chunks.push_back(*preview);
        available.erase(available.begin(), available.begin() + preview->selected.size());
        if (available.empty() && remaining_requested > 0) {
            error = "Insufficient transparent funds under current shielding policy";
            return std::nullopt;
        }
    }

    return plan;
}

void ParseShieldingPolicyOptions(const UniValue& options,
                                 std::optional<size_t>& max_inputs_per_chunk)
{
    if (options.isNull()) return;
    const UniValue& opts = options.get_obj();
    if (opts.exists("max_inputs_per_chunk")) {
        const int raw = opts["max_inputs_per_chunk"].getInt<int>();
        if (raw < static_cast<int>(MIN_SHIELD_SWEEP_MAX_INPUTS_PER_CHUNK)) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                strprintf("max_inputs_per_chunk must be at least %u",
                          static_cast<unsigned int>(MIN_SHIELD_SWEEP_MAX_INPUTS_PER_CHUNK)));
        }
        max_inputs_per_chunk = static_cast<size_t>(raw);
    }
}

} // namespace

RPCHelpMan z_getnewaddress()
{
    return RPCHelpMan{
        "z_getnewaddress",
        "\nGenerate and return a new shielded address.\n",
        {
            {"account", RPCArg::Type::NUM, RPCArg::Default{0}, "Account index"},
        },
        RPCResult{RPCResult::Type::STR, "address", "Shielded address"},
        RPCExamples{
            HelpExampleCli("z_getnewaddress", "") +
            HelpExampleCli("z_getnewaddress", "0")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();
            EnsureEncryptedShieldedWritesOrThrow(*pwallet);
            EnsureWalletIsUnlocked(*pwallet);

            uint32_t account{0};
            if (!request.params[0].isNull()) {
                account = request.params[0].getInt<uint32_t>();
            }

            LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
            return pwallet->m_shielded_wallet->GenerateNewAddress(account).Encode();
        }};
}

RPCHelpMan z_getbalance()
{
    return RPCHelpMan{
        "z_getbalance",
        "\nReturn shielded balance split between spendable and watch-only notes.\n",
        {
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "Minimum confirmations"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_AMOUNT, "balance", "Spendable shielded balance"},
                {RPCResult::Type::NUM, "note_count", "Spendable unspent shielded note count"},
                {RPCResult::Type::STR_AMOUNT, "watchonly_balance", /*optional=*/true, "Watch-only shielded balance"},
                {RPCResult::Type::NUM, "watchonly_note_count", /*optional=*/true, "Watch-only unspent shielded note count"},
                {RPCResult::Type::STR_AMOUNT, "total_balance", "Spendable plus watch-only shielded balance"},
                {RPCResult::Type::NUM, "total_note_count", "Total unspent shielded note count"},
                {RPCResult::Type::BOOL, "scan_incomplete", /*optional=*/true, "True if the shielded scan could not complete (e.g. pruned blocks). Balance may be underreported."},
                {RPCResult::Type::BOOL, "locked_state_incomplete", /*optional=*/true, "True if the wallet was loaded locked from tree-only fallback state and full shielded accounting requires an unlock refresh."},
            }},
        RPCExamples{
            HelpExampleCli("z_getbalance", "") +
            HelpExampleCli("z_getbalance", "6")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();
            int minconf = 1;
            if (!request.params[0].isNull()) {
                minconf = request.params[0].getInt<int>();
            }
            // R5-510: Reject negative minconf.
            if (minconf < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "minconf must be non-negative");

            UniValue out(UniValue::VOBJ);
            const bool locked_state_incomplete = WalletNeedsLockedShieldedAccountingRefresh(*pwallet);
            LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
            const ShieldedBalanceSummary summary = pwallet->m_shielded_wallet->GetShieldedBalanceSummary(minconf);
            out.pushKV("balance", ValueFromAmount(summary.spendable));
            out.pushKV("note_count", summary.spendable_note_count);
            if (summary.watchonly_note_count > 0 || summary.watchonly != 0) {
                out.pushKV("watchonly_balance", ValueFromAmount(summary.watchonly));
                out.pushKV("watchonly_note_count", summary.watchonly_note_count);
            }
            const auto total_balance = CheckedAdd(summary.spendable, summary.watchonly);
            if (!total_balance || !MoneyRange(*total_balance)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Balance overflow");
            }
            out.pushKV("total_balance", ValueFromAmount(*total_balance));
            out.pushKV("total_note_count", summary.spendable_note_count + summary.watchonly_note_count);
            if (pwallet->m_shielded_wallet->IsScanIncomplete()) {
                out.pushKV("scan_incomplete", true);
            }
            if (locked_state_incomplete) {
                out.pushKV("locked_state_incomplete", true);
            }
            return out;
        }};
}

RPCHelpMan z_sendtoaddress()
{
    return RPCHelpMan{
        "z_sendtoaddress",
        "\nSend value from the shielded pool to one shielded address using a v2 private send transaction.\n"
        "Unlike z_sendmany, this RPC does not fall back to transparent-input shielding when shielded funds are insufficient.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Shielded recipient address"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount to send"},
            {"comment", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Optional wallet-only comment"},
            {"comment_to", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Optional wallet-only recipient label"},
            {"subtractfeefromamount", RPCArg::Type::BOOL, RPCArg::Default{false}, "Deduct the fee from the recipient amount"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"wallet shielded fee estimation"}, "Fee"},
            {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, return spend/output counts and fee"},
            {"conf_target", RPCArg::Type::NUM, RPCArg::DefaultHint{"wallet -txconfirmtarget"}, "Confirmation target in blocks for automatic fee estimation"},
            {"estimate_mode", RPCArg::Type::STR, RPCArg::Default{"unset"}, "The fee estimate mode, must be one of (case insensitive):\n"
                + common::FeeModesDetail(std::string("conservative mode is used by default for shielded sends"))},
            {"conflict_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional in-mempool wallet shielded send to replace by respending the same notes"},
        },
        {
            RPCResult{"if verbose is not set or set to false",
                RPCResult::Type::STR_HEX, "txid", "The transaction id."},
            RPCResult{"if verbose is set to true",
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
                    {RPCResult::Type::STR, "family", "The shielded transaction family."},
                    {RPCResult::Type::BOOL, "family_redacted", /*optional=*/true, "True when only the generic post-fork shielded family class is exposed"},
                    {RPCResult::Type::NUM, "spends", /*optional=*/true, "Shielded input count"},
                    {RPCResult::Type::NUM, "outputs", /*optional=*/true, "Shielded output count"},
                    {RPCResult::Type::BOOL, "io_counts_redacted", /*optional=*/true, "True when input/output counts are redacted by default after the post-fork privacy redesign"},
                    {RPCResult::Type::STR_AMOUNT, "fee", "Applied fee"},
                }},
        },
        RPCExamples{
            HelpExampleCli("z_sendtoaddress", "\"btxs1...\" 0.5") +
            HelpExampleCli("z_sendtoaddress", "\"btxs1...\" 0.5 \"rent\" \"ops\" true 0.0001 true 6 economical") +
            HelpExampleCli("-named z_sendtoaddress", "address=\"btxs1...\" amount=0.5 conf_target=6 estimate_mode=\"economical\"") +
            HelpExampleCli("-named z_sendtoaddress", "address=\"btxs1...\" amount=0.5 fee=0.0015 conflict_txid=\"<txid>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();
            EnsureWalletIsUnlocked(*pwallet);

            const auto dest = ParseShieldedAddr(request.params[0].get_str());
            if (!dest.has_value()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid shielded destination");
            }

            const CAmount requested_amount = AmountFromValue(request.params[1]);
            if (requested_amount <= 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount must be positive");
            }

            mapValue_t map_value;
            if (!request.params[2].isNull() && !request.params[2].get_str().empty()) {
                map_value["comment"] = request.params[2].get_str();
            }
            if (!request.params[3].isNull() && !request.params[3].get_str().empty()) {
                map_value["to"] = request.params[3].get_str();
            }

            const bool subtract_fee{!request.params[4].isNull() && request.params[4].get_bool()};

            bool explicit_fee{false};
            CAmount fee{10000};
            if (!request.params[5].isNull()) {
                explicit_fee = true;
                fee = AmountFromValue(request.params[5]);
                if (fee <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee must be positive");
            }

            const bool verbose{!request.params[6].isNull() && request.params[6].get_bool()};
            if (explicit_fee && (!request.params[7].isNull() || !request.params[8].isNull())) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "Cannot specify conf_target or estimate_mode together with an explicit fee");
            }
            const auto conflict_txid = ParseOptionalConflictTxid(
                request.params.size() > 9 ? request.params[9] : UniValue());

            CCoinControl coin_control;
            SetShieldedFeeEstimateMode(*pwallet, coin_control, request.params[7], request.params[8]);

            std::optional<std::vector<ShieldedCoin>> conflict_selection;
            if (conflict_txid.has_value()) {
                std::string conflict_error;
                conflict_selection = WITH_LOCK(
                    pwallet->m_shielded_wallet->cs_shielded,
                    return pwallet->m_shielded_wallet->GetConflictSpendSelection(*conflict_txid, &conflict_error));
                if (!conflict_selection.has_value()) {
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        conflict_error.empty() ? "Unable to resolve conflict_txid spend set" : conflict_error);
                }
            }

            std::vector<Nullifier> reserved_nullifiers;

            // Helper: release any pending-spend reservations still held.
            // Safe to call with an empty vector or while not holding the lock
            // (acquires cs_shielded internally).
            const auto release_reservations = [&]() {
                if (reserved_nullifiers.empty()) return;
                LOCK(pwallet->m_shielded_wallet->cs_shielded);
                pwallet->m_shielded_wallet->ReleasePendingSpends(reserved_nullifiers);
                reserved_nullifiers.clear();
            };

            if (!explicit_fee) {
                CAmount estimated_fee{0};
                for (int attempt = 0; attempt < MAX_SHIELDED_FEE_CONVERGENCE_ATTEMPTS; ++attempt) {
                    if (subtract_fee && requested_amount <= estimated_fee) {
                        throw JSONRPCError(
                            RPC_INVALID_PARAMETER,
                            "Amount must be greater than fee when subtractfeefromamount is true");
                    }

                    const CAmount recipient_amount =
                        subtract_fee ? requested_amount - estimated_fee : requested_amount;
                    std::string selection_error;
                    const auto selection = WITH_LOCK(
                        pwallet->m_shielded_wallet->cs_shielded,
                        return pwallet->m_shielded_wallet->EstimateDirectSpendSelection(
                            {{*dest, recipient_amount}},
                            /*transparent_recipients=*/{},
                            estimated_fee,
                            &selection_error,
                            conflict_selection.has_value() ? &*conflict_selection : nullptr));
                    if (!selection.has_value()) break;

                    const CAmount next_fee = ComputeShieldedAutoFee(
                        *pwallet,
                        coin_control,
                        EstimateDirectShieldedSendVirtualSize(
                            selection->selected.size(),
                            selection->shielded_output_count,
                            selection->transparent_output_bytes),
                        /*has_shielded_bundle=*/true);
                    if (next_fee == estimated_fee) break;
                    estimated_fee = next_fee;
                }
                fee = estimated_fee > 0
                    ? estimated_fee
                    : ComputeShieldedAutoFee(
                        *pwallet,
                        coin_control,
                        EstimateDirectShieldedSendVirtualSize(/*spend_count=*/1, /*shielded_output_count=*/2),
                        /*has_shielded_bundle=*/true);
            }

            const auto tx = BuildAndCommitShieldedTransactionWithAnchorRetry(
                pwallet,
                "z_sendtoaddress",
                map_value,
                [&]() -> CTransactionRef {
                    CTransactionRef built_tx;
                    try {
                        for (int attempt = 0; attempt < MAX_SHIELDED_FEE_CONVERGENCE_ATTEMPTS; ++attempt) {
                            // Release nullifier reservations from any prior iteration so
                            // that the notes become eligible for selection again.
                            release_reservations();

                            if (subtract_fee && requested_amount <= fee) {
                                throw JSONRPCError(
                                    RPC_INVALID_PARAMETER,
                                    "Amount must be greater than fee when subtractfeefromamount is true");
                            }

                            const CAmount recipient_amount = subtract_fee ? requested_amount - fee : requested_amount;
                            const std::optional<CAmount> required_total = subtract_fee
                                ? std::make_optional(requested_amount)
                                : CheckedAdd(requested_amount, fee);
                            if (!required_total.has_value() || !MoneyRange(*required_total)) {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount + fee overflows");
                            }

                            std::optional<CMutableTransaction> mtx;
                            std::string create_error;
                            {
                                LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
                                AssertLockHeld(pwallet->m_shielded_wallet->cs_shielded);

                                const CAmount shielded_balance = pwallet->m_shielded_wallet->GetShieldedBalance(/*min_depth=*/1);
                                if (shielded_balance < *required_total) {
                                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient shielded funds");
                                }

                                mtx = pwallet->m_shielded_wallet->CreateShieldedSpend(
                                    {{*dest, recipient_amount}},
                                    /*transparent_recipients=*/{},
                                    fee,
                                    /*allow_transparent_fallback=*/false,
                                    &create_error,
                                    conflict_selection.has_value() ? &*conflict_selection : nullptr);
                                if (mtx.has_value()) {
                                    reserved_nullifiers = CollectShieldedNullifiers(mtx->shielded_bundle);
                                    pwallet->m_shielded_wallet->ReservePendingSpends(reserved_nullifiers);
                                }
                            }

                            if (!mtx.has_value()) {
                                throw JSONRPCError(
                                    RPC_WALLET_ERROR,
                                    create_error.empty() ? "Failed to create shielded v2 send transaction" : create_error);
                            }

                            CTransactionRef candidate = MakeTransactionRef(std::move(*mtx));
                            const CAmount required_fee = RequiredMempoolFee(*pwallet, *candidate);
                            if (explicit_fee) {
                                if (fee >= required_fee) {
                                    built_tx = std::move(candidate);
                                    break;
                                }
                                throw JSONRPCError(
                                    RPC_WALLET_ERROR,
                                    strprintf("Fee too low for transaction size. Required at least %s", FormatMoney(required_fee)));
                            }

                            const CAmount desired_fee = ComputeShieldedAutoFee(
                                *pwallet,
                                coin_control,
                                ShieldedRelayVirtualSize(*candidate),
                                candidate->HasShieldedBundle());
                            if (fee >= desired_fee) {
                                built_tx = std::move(candidate);
                                break;
                            }

                            fee = desired_fee;
                        }

                        if (!built_tx) {
                            throw JSONRPCError(
                                RPC_WALLET_ERROR,
                                "Failed to build fee-compliant shielded v2 send transaction");
                        }
                    } catch (...) {
                        // Any throw from the loop or the !built_tx check above must
                        // release reservations so that the notes are not permanently locked.
                        release_reservations();
                        throw;
                    }
                    return built_tx;
                },
                [&]() {
                    release_reservations();
                });
            if (conflict_txid.has_value()) {
                AbandonReplacedShieldedTransactionIfStale(pwallet, *conflict_txid);
            }

            return ShieldedSendResultToUniValue(
                tx,
                fee,
                verbose,
                RedactSensitiveShieldedRpcFields(*pwallet, /*include_sensitive=*/false));
        }};
}

RPCHelpMan z_listunspent()
{
    return RPCHelpMan{
        "z_listunspent",
        "\nList unspent shielded notes.\n",
        {
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "Minimum confirmations"},
            {"maxconf", RPCArg::Type::NUM, RPCArg::Default{9999999}, "Maximum confirmations"},
            {"include_watchonly", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include view-only notes"},
            {"include_sensitive", RPCArg::Type::BOOL, RPCArg::Default{false},
                "Include nullifier and tree-position identifiers after the post-61000 privacy fork"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "summary_redacted", /*optional=*/true, "True when the entry is a privacy-preserving aggregate summary"},
                        {RPCResult::Type::NUM, "note_count", /*optional=*/true, "Number of wallet notes covered by a redacted summary entry"},
                        {RPCResult::Type::STR_AMOUNT, "total_amount", /*optional=*/true, "Total value across notes covered by a redacted summary entry"},
                        {RPCResult::Type::STR_HEX, "nullifier", /*optional=*/true, "Note nullifier"},
                        {RPCResult::Type::BOOL, "nullifier_redacted", /*optional=*/true, "True when nullifier disclosure is redacted"},
                        {RPCResult::Type::STR_HEX, "commitment", /*optional=*/true, "Note commitment"},
                        {RPCResult::Type::BOOL, "commitment_redacted", /*optional=*/true, "True when note commitment disclosure is redacted"},
                        {RPCResult::Type::STR_AMOUNT, "amount", /*optional=*/true, "Note value"},
                        {RPCResult::Type::NUM, "confirmations", /*optional=*/true, "Confirmation depth"},
                        {RPCResult::Type::BOOL, "spendable", "True if wallet has spending key"},
                        {RPCResult::Type::NUM, "tree_position", /*optional=*/true, "Commitment position"},
                        {RPCResult::Type::BOOL, "tree_position_redacted", /*optional=*/true, "True when tree-position disclosure is redacted"},
                        {RPCResult::Type::STR_HEX, "block_hash", /*optional=*/true, "Containing block hash"},
                        {RPCResult::Type::BOOL, "block_hash_redacted", /*optional=*/true, "True when containing block hash disclosure is redacted"},
                    }},
            }},
        RPCExamples{HelpExampleCli("z_listunspent", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            int minconf{1};
            int maxconf{9999999};
            bool include_watchonly{false};
            bool include_sensitive{false};
            if (!request.params[0].isNull()) minconf = request.params[0].getInt<int>();
            if (!request.params[1].isNull()) maxconf = request.params[1].getInt<int>();
            if (!request.params[2].isNull()) include_watchonly = request.params[2].get_bool();
            if (request.params.size() > 3 && !request.params[3].isNull()) {
                include_sensitive = request.params[3].get_bool();
            }
            // R5-510: Reject negative minconf/maxconf.
            if (minconf < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "minconf must be non-negative");
            if (maxconf < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "maxconf must be non-negative");
            if (minconf > maxconf) throw JSONRPCError(RPC_INVALID_PARAMETER, "minconf must be less than or equal to maxconf");

            UniValue out(UniValue::VARR);
            LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
            const int tip_height = pwallet->chain().getHeight().value_or(0);
            const bool redact_sensitive = RedactSensitiveShieldedRpcFields(*pwallet, include_sensitive);
            const auto notes = pwallet->m_shielded_wallet->GetUnspentNotes(/*min_depth=*/0);
            CAmount redacted_spendable_amount{0};
            int64_t redacted_spendable_count{0};
            CAmount redacted_watchonly_amount{0};
            int64_t redacted_watchonly_count{0};
            for (const auto& coin : notes) {
                const int depth = coin.GetDepth(tip_height);
                if (depth < minconf || depth > maxconf) continue;
                if (!include_watchonly && !coin.is_mine_spend) continue;

                if (redact_sensitive) {
                    CAmount& bucket_amount = coin.is_mine_spend ? redacted_spendable_amount : redacted_watchonly_amount;
                    int64_t& bucket_count = coin.is_mine_spend ? redacted_spendable_count : redacted_watchonly_count;
                    const auto next_amount = CheckedAdd(bucket_amount, coin.note.value);
                    if (!next_amount || !MoneyRange(*next_amount)) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "Redacted note summary overflow");
                    }
                    bucket_amount = *next_amount;
                    ++bucket_count;
                    continue;
                }

                UniValue entry(UniValue::VOBJ);
                entry.pushKV("nullifier", coin.nullifier.GetHex());
                entry.pushKV("tree_position", static_cast<int64_t>(coin.tree_position));
                entry.pushKV("commitment", coin.commitment.GetHex());
                entry.pushKV("amount", ValueFromAmount(coin.note.value));
                entry.pushKV("confirmations", depth);
                entry.pushKV("spendable", coin.is_mine_spend);
                entry.pushKV("block_hash", coin.block_hash.GetHex());
                out.push_back(std::move(entry));
            }
            if (redact_sensitive) {
                const auto push_bucket = [&](bool spendable, int64_t note_count, CAmount total_amount) {
                    if (note_count <= 0) return;
                    UniValue entry(UniValue::VOBJ);
                    entry.pushKV("summary_redacted", true);
                    entry.pushKV("note_count", note_count);
                    entry.pushKV("total_amount", ValueFromAmount(total_amount));
                    entry.pushKV("spendable", spendable);
                    PushRedactedShieldedNoteIdentity(entry);
                    out.push_back(std::move(entry));
                };
                push_bucket(/*spendable=*/true, redacted_spendable_count, redacted_spendable_amount);
                push_bucket(/*spendable=*/false, redacted_watchonly_count, redacted_watchonly_amount);
            }
            return out;
        }};
}

RPCHelpMan z_sendmany()
{
    return RPCHelpMan{
        "z_sendmany",
        "\nSend value from shielded pool to shielded and/or transparent recipients.\n"
        "Before the post-61000 privacy fork, if only shielded recipients are specified and\n"
        "spendable shielded funds are insufficient, the wallet can fall back to a transparent-input\n"
        "direct deposit path.\n"
        "After the post-61000 privacy fork, mixed direct sends to transparent recipients are disabled;\n"
        "use the bridge unshield flow for transparent settlement instead. Transparent-input fallback\n"
        "is also disabled on this RPC after the fork.\n",
        {
            {"amounts", RPCArg::Type::ARR, RPCArg::Optional::NO, "Recipients",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Recipient address"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount"},
                        }},
                }},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"wallet shielded fee estimation"}, "Fee"},
            {"subtractfeefromamount", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "The outputs to subtract the fee from.\n"
                "Each entry can be a destination address or a zero-based position in the amounts array.\n"
                "The fee is split equally across the selected outputs; the first selected output pays any remainder.",
                {
                    {"output", RPCArg::Type::STR, RPCArg::Optional::OMITTED,
                        "Destination address or zero-based output index"},
                }},
            {"conf_target", RPCArg::Type::NUM, RPCArg::DefaultHint{"wallet -txconfirmtarget"}, "Confirmation target in blocks for automatic fee estimation"},
            {"estimate_mode", RPCArg::Type::STR, RPCArg::Default{"unset"}, "The fee estimate mode, must be one of (case insensitive):\n"
                + common::FeeModesDetail(std::string("conservative mode is used by default for shielded sends"))},
            {"conflict_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional in-mempool wallet shielded send to replace by respending the same notes"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "Transaction id"},
                {RPCResult::Type::STR, "family", "The shielded transaction family."},
                {RPCResult::Type::BOOL, "family_redacted", /*optional=*/true, "True when only the generic post-fork shielded family class is exposed"},
                {RPCResult::Type::NUM, "spends", /*optional=*/true, "Shielded input count"},
                {RPCResult::Type::NUM, "outputs", /*optional=*/true, "Shielded output count"},
                {RPCResult::Type::BOOL, "io_counts_redacted", /*optional=*/true, "True when input/output counts are redacted by default after the post-fork privacy redesign"},
                {RPCResult::Type::STR_AMOUNT, "fee", "Applied fee"},
            }},
        RPCExamples{
            HelpExampleCli("z_sendmany", "'[{\"address\":\"btxs1...\",\"amount\":1.0}]'") +
            HelpExampleCli("z_sendmany", "'[{\"address\":\"btxs1...\",\"amount\":1.0},{\"address\":\"btx1...\",\"amount\":0.5}]' 0.0002 '[0]' 6 economical") +
            HelpExampleCli("-named z_sendmany", "amounts='[{\"address\":\"btxs1...\",\"amount\":1.0}]' fee=0.0015 conflict_txid=\"<txid>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();
            EnsureWalletIsUnlocked(*pwallet);

            const UniValue& recipients_param = request.params[0].get_array();
            if (recipients_param.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "amounts must contain at least one recipient");
            }

            struct ParsedRecipient {
                std::string address;
                CAmount amount{0};
                std::optional<ShieldedAddress> shielded_destination;
                std::optional<CTxDestination> transparent_destination;
            };

            std::vector<ParsedRecipient> parsed_recipients;
            parsed_recipients.reserve(recipients_param.size());
            std::vector<std::string> destinations;
            destinations.reserve(recipients_param.size());
            size_t shielded_recipient_count{0};
            size_t transparent_output_bytes{0};
            for (size_t i = 0; i < recipients_param.size(); ++i) {
                const UniValue& rec = recipients_param[i].get_obj();
                const std::string addr_str = rec["address"].get_str();
                const CAmount amount = AmountFromValue(rec["amount"]);
                destinations.push_back(addr_str);

                auto shielded_addr = ParseShieldedAddr(addr_str);
                if (shielded_addr.has_value()) {
                    parsed_recipients.push_back(ParsedRecipient{
                        addr_str,
                        amount,
                        *shielded_addr,
                        std::nullopt,
                    });
                    ++shielded_recipient_count;
                    continue;
                }

                const CTxDestination dest = DecodeDestination(addr_str);
                if (!IsValidDestination(dest)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid address: %s", addr_str));
                }
                parsed_recipients.push_back(ParsedRecipient{
                    addr_str,
                    amount,
                    std::nullopt,
                    dest,
                });
                const size_t output_bytes = ::GetSerializeSize(CTxOut(amount, GetScriptForDestination(dest)));
                if (output_bytes > std::numeric_limits<size_t>::max() - transparent_output_bytes) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Transparent output size overflow");
                }
                transparent_output_bytes += output_bytes;
            }
            if (shielded_recipient_count > MAX_SHIELDED_OUTPUTS_PER_TX) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    strprintf("Too many shielded recipients (%u > %u)",
                              static_cast<unsigned int>(shielded_recipient_count),
                              static_cast<unsigned int>(MAX_SHIELDED_OUTPUTS_PER_TX)));
            }

            bool explicit_fee{false};
            CAmount fee{10000};
            if (!request.params[1].isNull()) {
                explicit_fee = true;
                fee = AmountFromValue(request.params[1]);
                if (fee <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee must be positive");
            }

            const std::set<int> subtract_fee_from_outputs = InterpretShieldedSubtractFeeInstructions(
                request.params[2],
                destinations);
            if (explicit_fee && (!request.params[3].isNull() || !request.params[4].isNull())) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "Cannot specify conf_target or estimate_mode together with an explicit fee");
            }
            const auto conflict_txid = ParseOptionalConflictTxid(
                request.params.size() > 5 ? request.params[5] : UniValue());

            CCoinControl coin_control;
            SetShieldedFeeEstimateMode(*pwallet, coin_control, request.params[3], request.params[4]);

            std::optional<std::vector<ShieldedCoin>> conflict_selection;
            if (conflict_txid.has_value()) {
                std::string conflict_error;
                conflict_selection = WITH_LOCK(
                    pwallet->m_shielded_wallet->cs_shielded,
                    return pwallet->m_shielded_wallet->GetConflictSpendSelection(*conflict_txid, &conflict_error));
                if (!conflict_selection.has_value()) {
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        conflict_error.empty() ? "Unable to resolve conflict_txid spend set" : conflict_error);
                }
            }

            const auto materialize_recipients = [&](const CAmount current_fee) {
                std::vector<CAmount> adjusted_amounts;
                adjusted_amounts.reserve(parsed_recipients.size());
                for (const auto& recipient : parsed_recipients) {
                    adjusted_amounts.push_back(recipient.amount);
                }

                if (!subtract_fee_from_outputs.empty()) {
                    const CAmount per_output_fee = current_fee / static_cast<CAmount>(subtract_fee_from_outputs.size());
                    const CAmount remainder = current_fee % static_cast<CAmount>(subtract_fee_from_outputs.size());
                    bool first{true};
                    for (const int index : subtract_fee_from_outputs) {
                        const CAmount deduction = per_output_fee + (first ? remainder : 0);
                        first = false;
                        if (adjusted_amounts[index] <= deduction) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "The transaction amount is too small to pay the fee");
                        }
                        adjusted_amounts[index] -= deduction;
                    }
                }

                std::vector<std::pair<ShieldedAddress, CAmount>> shielded_recipients;
                std::vector<std::pair<CTxDestination, CAmount>> transparent_recipients;
                shielded_recipients.reserve(shielded_recipient_count);
                transparent_recipients.reserve(parsed_recipients.size() - shielded_recipient_count);
                for (size_t i = 0; i < parsed_recipients.size(); ++i) {
                    if (parsed_recipients[i].shielded_destination.has_value()) {
                        shielded_recipients.emplace_back(
                            *parsed_recipients[i].shielded_destination,
                            adjusted_amounts[i]);
                    } else {
                        transparent_recipients.emplace_back(
                            *parsed_recipients[i].transparent_destination,
                            adjusted_amounts[i]);
                    }
                }
                return std::make_pair(std::move(shielded_recipients), std::move(transparent_recipients));
            };

            std::vector<Nullifier> reserved_nullifiers;
            const auto release_reservations = [&]() {
                if (reserved_nullifiers.empty()) return;
                LOCK(pwallet->m_shielded_wallet->cs_shielded);
                pwallet->m_shielded_wallet->ReleasePendingSpends(reserved_nullifiers);
                reserved_nullifiers.clear();
            };

            if (!explicit_fee) {
                CAmount estimated_fee{0};
                for (int attempt = 0; attempt < MAX_SHIELDED_FEE_CONVERGENCE_ATTEMPTS; ++attempt) {
                    const auto [shielded_recipients, transparent_recipients] = materialize_recipients(estimated_fee);
                    std::string selection_error;
                    const auto selection = WITH_LOCK(
                        pwallet->m_shielded_wallet->cs_shielded,
                        return pwallet->m_shielded_wallet->EstimateDirectSpendSelection(
                            shielded_recipients,
                            transparent_recipients,
                            estimated_fee,
                            &selection_error,
                            conflict_selection.has_value() ? &*conflict_selection : nullptr));
                    if (!selection.has_value()) break;

                    const CAmount next_fee = ComputeShieldedAutoFee(
                        *pwallet,
                        coin_control,
                        EstimateDirectShieldedSendVirtualSize(
                            selection->selected.size(),
                            selection->shielded_output_count,
                            selection->transparent_output_bytes),
                        /*has_shielded_bundle=*/true);
                    if (next_fee == estimated_fee) break;
                    estimated_fee = next_fee;
                }
                const size_t fallback_spend_count =
                    shielded_recipient_count > 0 && shielded_recipient_count == parsed_recipients.size() ? 0 : 1;
                const size_t fallback_shielded_outputs =
                    shielded_recipient_count == 0 ? 1 : shielded_recipient_count + 1;
                fee = estimated_fee > 0
                    ? estimated_fee
                    : ComputeShieldedAutoFee(
                        *pwallet,
                        coin_control,
                        EstimateDirectShieldedSendVirtualSize(
                            fallback_spend_count,
                            fallback_shielded_outputs,
                            transparent_output_bytes),
                        /*has_shielded_bundle=*/true);
            }

            const auto tx = BuildAndCommitShieldedTransactionWithAnchorRetry(
                pwallet,
                "z_sendmany",
                /*map_value=*/{},
                [&]() -> CTransactionRef {
                    CTransactionRef built_tx;
                    try {
                        for (int attempt = 0; attempt < MAX_SHIELDED_FEE_CONVERGENCE_ATTEMPTS; ++attempt) {
                            release_reservations();
                            const auto [shielded_recipients, transparent_recipients] = materialize_recipients(fee);

                            std::optional<CMutableTransaction> mtx;
                            std::string create_error;
                            {
                                LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
                                mtx = pwallet->m_shielded_wallet->CreateShieldedSpend(
                                    shielded_recipients,
                                    transparent_recipients,
                                    fee,
                                    /*allow_transparent_fallback=*/true,
                                    &create_error,
                                    conflict_selection.has_value() ? &*conflict_selection : nullptr);
                                if (mtx.has_value()) {
                                    reserved_nullifiers = CollectShieldedNullifiers(mtx->shielded_bundle);
                                    pwallet->m_shielded_wallet->ReservePendingSpends(reserved_nullifiers);
                                }
                            }
                            if (!mtx.has_value()) {
                                throw JSONRPCError(
                                    RPC_WALLET_ERROR,
                                    create_error.empty() ? "Failed to create shielded transaction" : create_error);
                            }

                            CTransactionRef candidate = MakeTransactionRef(std::move(*mtx));
                            const CAmount required_fee = RequiredMempoolFee(*pwallet, *candidate);
                            if (explicit_fee) {
                                if (fee >= required_fee) {
                                    built_tx = std::move(candidate);
                                    break;
                                }
                                throw JSONRPCError(
                                    RPC_WALLET_ERROR,
                                    strprintf("Fee too low for transaction size. Required at least %s", FormatMoney(required_fee)));
                            }

                            const CAmount desired_fee = ComputeShieldedAutoFee(
                                *pwallet,
                                coin_control,
                                ShieldedRelayVirtualSize(*candidate),
                                candidate->HasShieldedBundle());
                            if (fee >= desired_fee) {
                                built_tx = std::move(candidate);
                                break;
                            }

                            fee = desired_fee;
                        }
                        if (!built_tx) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to build fee-compliant shielded transaction");
                        }
                    } catch (...) {
                        release_reservations();
                        throw;
                    }
                    return built_tx;
                },
                [&]() {
                    release_reservations();
                });
            if (conflict_txid.has_value()) {
                AbandonReplacedShieldedTransactionIfStale(pwallet, *conflict_txid);
            }

            return ShieldedSendResultToUniValue(
                tx,
                fee,
                /*verbose=*/true,
                RedactSensitiveShieldedRpcFields(*pwallet, /*include_sensitive=*/false));
        }};
}

RPCHelpMan z_shieldcoinbase()
{
    return RPCHelpMan{
        "z_shieldcoinbase",
        "\nShield mature coinbase outputs into one shielded note.\n"
        "This remains the supported wallet-compatible transparent deposit path after the post-61000\n"
        "privacy fork.\n",
        {
            {"destination", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Destination shielded address"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"wallet shielded fee estimation"}, "Fee"},
            {"limit", RPCArg::Type::NUM, RPCArg::Default{50}, "Maximum coinbase inputs"},
            {"conf_target", RPCArg::Type::NUM, RPCArg::DefaultHint{"wallet -txconfirmtarget"}, "Confirmation target in blocks for automatic fee estimation"},
            {"estimate_mode", RPCArg::Type::STR, RPCArg::Default{"unset"}, "The fee estimate mode, must be one of (case insensitive):\n"
                + common::FeeModesDetail(std::string("conservative mode is used by default for shielded wallet transactions"))},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "Transaction id"},
                {RPCResult::Type::STR_AMOUNT, "amount", "Shielded amount"},
                {RPCResult::Type::NUM, "shielding_inputs", "Input count"},
            }},
        RPCExamples{
            HelpExampleCli("z_shieldcoinbase", "") +
            HelpExampleCli("z_shieldcoinbase", "\"btxs1...\" null 25 6 economical")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();
            EnsureWalletIsUnlocked(*pwallet);

            std::optional<ShieldedAddress> dest;
            if (!request.params[0].isNull()) {
                dest = ParseShieldedAddr(request.params[0].get_str());
                if (!dest.has_value()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid shielded destination");
            }

            bool explicit_fee{false};
            CAmount fee{10000};
            if (!request.params[1].isNull()) {
                explicit_fee = true;
                fee = AmountFromValue(request.params[1]);
                if (fee <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee must be positive");
            }
            int limit{50};
            if (!request.params[2].isNull()) limit = request.params[2].getInt<int>();
            if (limit <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "limit must be positive");
            if (explicit_fee && (!request.params[3].isNull() || !request.params[4].isNull())) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "Cannot specify conf_target or estimate_mode together with an explicit fee");
            }

            CCoinControl coin_control;
            SetShieldedFeeEstimateMode(*pwallet, coin_control, request.params[3], request.params[4]);

            std::vector<COutPoint> utxos;
            CAmount total_in{0};
            {
                LOCK(pwallet->cs_wallet);
                for (const auto& [txid, wtx] : pwallet->mapWallet) {
                    if (!wtx.IsCoinBase()) continue;
                    if (pwallet->GetTxBlocksToMaturity(wtx) > 0) continue;
                    for (uint32_t n = 0; n < wtx.tx->vout.size(); ++n) {
                        if (!(pwallet->IsMine(wtx.tx->vout[n]) & ISMINE_SPENDABLE)) continue;
                        const COutPoint outpoint{Txid::FromUint256(txid), n};
                        if (pwallet->IsSpent(outpoint)) continue;
                        if (pwallet->IsLockedCoin(outpoint)) continue;
                        // R5-506: Checked accumulation to prevent overflow.
                        const auto next = CheckedAdd(total_in, wtx.tx->vout[n].nValue);
                        if (!next || !MoneyRange(*next)) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Input value overflow");
                        }
                        const CAmount fee_floor = explicit_fee ? fee : CAmount{10000};
                        if (*next - fee_floor > GetShieldingChunkSmileValueLimit()) {
                            break;
                        }
                        utxos.push_back(outpoint);
                        total_in = *next;
                        if (static_cast<int>(utxos.size()) >= limit) break;
                    }
                    if (static_cast<int>(utxos.size()) >= limit) break;
                }
            }
            if (utxos.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "No mature coinbase outputs available");
            }

            if (!explicit_fee) {
                const size_t input_vsize = EstimateTransparentShieldingInputVirtualSize(
                    *pwallet,
                    Span<const COutPoint>{utxos.data(), utxos.size()});
                const size_t base_vsize = EstimateDirectShieldedSendVirtualSize(
                    /*spend_count=*/0,
                    /*shielded_output_count=*/1);
                if (input_vsize == std::numeric_limits<size_t>::max() ||
                    base_vsize > std::numeric_limits<size_t>::max() - input_vsize) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Estimated shielding transaction size overflow");
                }
                fee = ComputeShieldedAutoFee(
                    *pwallet,
                    coin_control,
                    base_vsize + input_vsize,
                    /*has_shielded_bundle=*/true);
            }
            fee = CanonicalizeShieldingFee(*pwallet, fee);

            CTransactionRef tx;
            for (int attempt = 0; attempt < MAX_SHIELDED_FEE_CONVERGENCE_ATTEMPTS; ++attempt) {
                std::optional<CMutableTransaction> mtx;
                std::string create_error;
                {
                    LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
                    mtx = pwallet->m_shielded_wallet->ShieldFunds(utxos, fee, dest, /*requested_amount=*/0, &create_error);
                }
                if (!mtx.has_value()) {
                    throw JSONRPCError(
                        RPC_WALLET_ERROR,
                        create_error.empty() ? "Failed to build shielding transaction" : create_error);
                }

                CTransactionRef candidate = MakeTransactionRef(std::move(*mtx));
                const CAmount required_fee = RequiredMempoolFee(*pwallet, *candidate);
                if (explicit_fee) {
                    if (fee >= required_fee) {
                        tx = std::move(candidate);
                        break;
                    }
                    throw JSONRPCError(
                        RPC_WALLET_ERROR,
                        strprintf("Fee too low for transaction size. Required at least %s", FormatMoney(required_fee)));
                }

                const CAmount desired_fee = ComputeShieldedAutoFee(
                    *pwallet,
                    coin_control,
                    ShieldedRelayVirtualSize(*candidate),
                    candidate->HasShieldedBundle());
                if (fee >= desired_fee) {
                    tx = std::move(candidate);
                    break;
                }
                fee = CanonicalizeShieldingFee(*pwallet, desired_fee);
            }
            if (!tx) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to build fee-compliant shielding transaction");
            }

            CommitShieldedTransactionOrThrow(pwallet, tx);

            UniValue out(UniValue::VOBJ);
            out.pushKV("txid", tx->GetHash().GetHex());
            out.pushKV("amount", ValueFromAmount(total_in - fee));
            out.pushKV("shielding_inputs", static_cast<int64_t>(utxos.size()));
            return out;
        }};
}

RPCHelpMan z_shieldfunds()
{
    return RPCHelpMan{
        "z_shieldfunds",
        "\nShield transparent wallet funds into one or more shielded notes using policy-aware chunking.\n"
        "After the post-61000 privacy fork, this RPC is limited to mature coinbase outputs; use\n"
        "bridge ingress for general transparent deposits. The examples below assume the wallet's\n"
        "compatible transparent set consists of mature coinbase outputs.\n",
        {
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Requested minimum amount"},
            {"destination", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Destination shielded address"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(10000)}, "Fee"},
            {"options", RPCArg::Type::OBJ, RPCArg::DefaultHint{"{}"}, "Optional chunking policy overrides",
                {
                    {"max_inputs_per_chunk", RPCArg::Type::NUM, RPCArg::Optional::OMITTED,
                        "Override the daemon's recommended transparent-input batch size"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "First chunk transaction id (for backward compatibility)"},
                {RPCResult::Type::ARR, "txids", "", {
                    {RPCResult::Type::STR_HEX, "", "Committed chunk transaction id"},
                }},
                {RPCResult::Type::STR_AMOUNT, "amount", "Total shielded amount across all chunks"},
                {RPCResult::Type::NUM, "transparent_inputs", "Total transparent input count across all chunks"},
                {RPCResult::Type::NUM, "chunk_count", "Committed chunk count"},
                {RPCResult::Type::ARR, "chunks", "", {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR_HEX, "txid", "Chunk transaction id"},
                        {RPCResult::Type::STR_AMOUNT, "gross_amount", "Chunk input value before fee"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "Shielded amount for this chunk"},
                        {RPCResult::Type::STR_AMOUNT, "fee", "Applied fee for this chunk"},
                        {RPCResult::Type::NUM, "transparent_inputs", "Transparent inputs in this chunk"},
                        {RPCResult::Type::NUM, "tx_weight", "Transaction weight for this chunk"},
                    }},
                }},
                {RPCResult::Type::OBJ, "policy", "Applied chunking policy", {
                    {RPCResult::Type::STR, "selection_strategy", "Transparent UTXO ordering strategy"},
                    {RPCResult::Type::NUM, "max_standard_tx_weight", "Network standard transaction weight ceiling"},
                    {RPCResult::Type::NUM, "soft_target_tx_weight", "Daemon soft target used for chunk sizing"},
                    {RPCResult::Type::NUM, "recommended_max_inputs_per_chunk", "Default recommended input cap per chunk"},
                    {RPCResult::Type::NUM, "applied_max_inputs_per_chunk", "Input cap used for this request"},
                    {RPCResult::Type::NUM, "min_inputs_per_chunk", "Minimum retry chunk size"},
                    {RPCResult::Type::STR_AMOUNT, "relay_fee_floor_per_kb", "Current relay fee floor per kvB"},
                    {RPCResult::Type::STR_AMOUNT, "mempool_fee_floor_per_kb", "Current mempool fee floor per kvB"},
                    {RPCResult::Type::STR_AMOUNT, "shielded_fee_premium", "Fixed shielded relay premium"},
                }},
            }},
        RPCExamples{
            HelpExampleCli("z_shieldfunds", "1.0") +
            HelpExampleCli("z_shieldfunds", "1.0 \"btxs1...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();
            EnsureWalletIsUnlocked(*pwallet);

            const CAmount requested = AmountFromValue(request.params[0]);
            if (requested <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount must be positive");

            std::optional<ShieldedAddress> dest;
            if (!request.params[1].isNull()) {
                dest = ParseShieldedAddr(request.params[1].get_str());
                if (!dest.has_value()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid shielded destination");
            }

            bool explicit_fee{false};
            CAmount fee{10000};
            if (!request.params[2].isNull()) {
                explicit_fee = true;
                fee = AmountFromValue(request.params[2]);
                if (fee <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee must be positive");
            }

            std::optional<size_t> max_inputs_override;
            if (request.params.size() > 3) {
                ParseShieldingPolicyOptions(request.params[3], max_inputs_override);
            }

            std::string destination_error;
            auto effective_dest = ResolveShieldingDestination(pwallet, dest, /*allow_generate=*/true, destination_error);
            if (!effective_dest.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, destination_error);
            }

            ShieldingPolicySnapshot policy = GetShieldingPolicySnapshot(*pwallet, max_inputs_override);
            const bool coinbase_only_compatibility = UseCoinbaseOnlyShieldingCompatibility(*pwallet);
            const auto all_available = CollectSpendableTransparentShieldingUTXOs(*pwallet);
            auto total_spendable = SumTransparentShieldingUTXOValues(
                Span<const TransparentShieldingUTXO>{all_available.data(), all_available.size()});
            if (!total_spendable.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Input value overflow");
            }

            std::vector<TransparentShieldingUTXO> available =
                coinbase_only_compatibility
                    ? CollectSpendableTransparentShieldingUTXOs(*pwallet, /*coinbase_only=*/true)
                    : all_available;
            auto compatible_spendable = SumTransparentShieldingUTXOValues(
                Span<const TransparentShieldingUTXO>{available.data(), available.size()});
            if (!compatible_spendable.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Input value overflow");
            }
            const CAmount spendable_amount = *compatible_spendable;
            if (spendable_amount <= 0) {
                if (coinbase_only_compatibility && !all_available.empty()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, GetPostForkCoinbaseShieldingCompatibilityMessage());
                }
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient transparent funds");
            }
            if (spendable_amount < requested) {
                if (coinbase_only_compatibility && *total_spendable >= requested) {
                    throw JSONRPCError(RPC_WALLET_ERROR, GetPostForkCoinbaseShieldingCompatibilityMessage());
                }
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient transparent funds");
            }

            CAmount remaining_requested = requested;
            CAmount total_shielded{0};
            size_t total_inputs{0};
            UniValue txids(UniValue::VARR);
            UniValue chunks(UniValue::VARR);
            std::string first_txid;

            while (remaining_requested > 0) {
                std::string build_error;
                auto preview = BuildShieldingChunkPreview(
                    pwallet,
                    available,
                    *effective_dest,
                    remaining_requested,
                    explicit_fee,
                    fee,
                    policy.applied_max_inputs_per_chunk,
                    policy,
                    build_error);
                if (!preview.has_value()) {
                    const RPCErrorCode code = build_error.find("Insufficient transparent funds") != std::string::npos
                        ? RPC_WALLET_INSUFFICIENT_FUNDS
                        : RPC_WALLET_ERROR;
                    throw JSONRPCError(code, build_error);
                }

                std::string commit_error;
                size_t current_limit = policy.applied_max_inputs_per_chunk;
                while (!CommitShieldedTransaction(pwallet, preview->tx, commit_error)) {
                    if (current_limit <= policy.min_inputs_per_chunk) {
                        throw JSONRPCError(
                            commit_error == "Shielded transaction created but rejected from mempool (policy or consensus)"
                                ? RPC_VERIFY_REJECTED
                                : RPC_WALLET_ERROR,
                            commit_error);
                    }
                    current_limit = ReduceShieldingInputLimit(current_limit, policy.min_inputs_per_chunk);
                    policy.applied_max_inputs_per_chunk = current_limit;
                    preview = BuildShieldingChunkPreview(
                        pwallet,
                        available,
                        *effective_dest,
                        remaining_requested,
                        explicit_fee,
                        fee,
                        current_limit,
                        policy,
                        build_error);
                    if (!preview.has_value()) {
                        throw JSONRPCError(RPC_WALLET_ERROR, build_error);
                    }
                }

                if (first_txid.empty()) {
                    first_txid = preview->tx->GetHash().GetHex();
                }
                txids.push_back(preview->tx->GetHash().GetHex());
                chunks.push_back(ChunkToUniValue(*preview));
                total_inputs += preview->selected.size();
                total_shielded += preview->shielded_amount;
                remaining_requested -= preview->shielded_amount;
                available.erase(available.begin(), available.begin() + preview->selected.size());
                if (available.empty() && remaining_requested > 0) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient transparent funds under current shielding policy");
                }
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("txid", first_txid);
            out.pushKV("txids", std::move(txids));
            out.pushKV("amount", ValueFromAmount(total_shielded));
            out.pushKV("transparent_inputs", static_cast<int64_t>(total_inputs));
            out.pushKV("chunk_count", chunks.size());
            out.pushKV("chunks", std::move(chunks));
            out.pushKV("policy", PolicyToUniValue(policy));
            return out;
        }};
}

RPCHelpMan z_fundpsbt()
{
    return RPCHelpMan{
        "z_fundpsbt",
        "\nCreate an unsigned PSBT that shields transparent funds into shielded notes.\n"
        "Use walletprocesspsbt to add signatures (repeat for each multisig signer),\n"
        "then z_finalizepsbt to finalize and broadcast.\n"
        "After the post-61000 privacy fork, this RPC is limited to mature coinbase inputs;\n"
        "use bridge ingress tooling for general transparent deposits. The examples below assume\n"
        "the wallet's compatible transparent set consists of mature coinbase outputs.\n",
        {
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount to shield"},
            {"destination", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Destination shielded address (default: wallet's own)"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(10000)}, "Fee"},
            {"options", RPCArg::Type::OBJ, RPCArg::DefaultHint{"{}"}, "Options",
                {
                    {"max_inputs_per_chunk", RPCArg::Type::NUM, RPCArg::Optional::OMITTED,
                        "Override transparent-input batch size"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "psbt", "Base64-encoded unsigned PSBT with shielded bundle"},
                {RPCResult::Type::STR_AMOUNT, "fee", "Applied fee"},
                {RPCResult::Type::NUM, "transparent_inputs", "Number of transparent inputs requiring signatures"},
                {RPCResult::Type::NUM, "shielded_outputs", "Number of shielded outputs in the bundle"},
                {RPCResult::Type::STR_AMOUNT, "shielded_amount", "Total amount being shielded"},
                {RPCResult::Type::BOOL, "fee_authoritative", "Whether the fee quote below is exact for the constructed PSBT under current local mempool policy"},
                {RPCResult::Type::STR, "fee_authoritative_error", /*optional=*/true, "Error string when fee_authoritative is false"},
                {RPCResult::Type::NUM, "estimated_vsize", /*optional=*/true, "Estimated mempool virtual size (present when fee_authoritative is true)"},
                {RPCResult::Type::NUM, "estimated_sigop_cost", /*optional=*/true, "Estimated sigop cost (present when fee_authoritative is true)"},
                {RPCResult::Type::STR_AMOUNT, "required_mempool_fee", /*optional=*/true, "Current-node minimum fee required for mempool acceptance (present when fee_authoritative is true)"},
                {RPCResult::Type::BOOL, "relay_fee_analysis_available", "Whether detailed relay-fee analysis is available"},
                {RPCResult::Type::BOOL, "relay_fee_sufficient", "Whether the supplied fee meets the current local mempool floor"},
                {RPCResult::Type::BOOL, "fee_headroom_enforced", "Whether a bridge fee-headroom policy is being enforced for this RPC result"},
                {RPCResult::Type::NUM, "fee_headroom_multiplier", "Requested fee-headroom multiplier"},
                {RPCResult::Type::BOOL, "fee_headroom_sufficient", "Whether the implied fee satisfies the requested fee-headroom target"},
                {RPCResult::Type::STR, "fee_headroom_error", /*optional=*/true, "Fee-headroom analysis error when fee_headroom_sufficient cannot be assessed"},
                {RPCResult::Type::STR_AMOUNT, "required_fee_headroom", /*optional=*/true, "Required fee to satisfy the requested fee-headroom target when not redacted"},
                {RPCResult::Type::BOOL, "required_fee_headroom_redacted", /*optional=*/true, "Whether required_fee_headroom is redacted"},
                {RPCResult::Type::STR_AMOUNT, "required_fee_headroom_bucket", /*optional=*/true, "Redacted bucketed required fee to satisfy the requested fee-headroom target"},
                {RPCResult::Type::STR, "fee_headroom_warning", /*optional=*/true, "Warning when the implied fee is below the requested fee-headroom target"},
                {RPCResult::Type::STR, "relay_fee_analysis_error", /*optional=*/true, "Detailed analysis error when relay_fee_analysis_available is false"},
                {RPCResult::Type::OBJ, "relay_fee_analysis", /*optional=*/true, "Detailed relay-fee analysis (present when relay_fee_analysis_available is true)",
                    {
                        {RPCResult::Type::STR_AMOUNT, "transparent_input_value", "Sum of transparent input values"},
                        {RPCResult::Type::STR_AMOUNT, "transparent_output_value", "Sum of transparent output values"},
                        {RPCResult::Type::STR_AMOUNT, "shielded_value_balance", "Signed shielded value balance"},
                        {RPCResult::Type::STR_AMOUNT, "estimated_fee", "Fee implied by inputs, outputs, and shielded value balance"},
                        {RPCResult::Type::NUM, "estimated_vsize", "Estimated mempool virtual size"},
                        {RPCResult::Type::NUM, "estimated_sigop_cost", "Estimated sigop cost"},
                        {RPCResult::Type::STR, "estimated_feerate", "Estimated fee rate"},
                        {RPCResult::Type::STR_AMOUNT, "relay_fee_floor", "Current relay fee floor for the estimated vsize"},
                        {RPCResult::Type::STR_AMOUNT, "mempool_fee_floor", "Current mempool fee floor for the estimated vsize"},
                        {RPCResult::Type::STR_AMOUNT, "required_base_fee", "Maximum of relay and mempool fee floors"},
                        {RPCResult::Type::STR_AMOUNT, "required_shielded_fee_premium", "Additional shielded relay premium"},
                        {RPCResult::Type::STR_AMOUNT, "required_total_fee", "Total fee required for mempool acceptance"},
                        {RPCResult::Type::STR_AMOUNT, "required_mempool_fee", "Alias for required_total_fee"},
                        {RPCResult::Type::BOOL, "fee_sufficient", "Whether the implied fee satisfies the current local mempool floor"},
                        {RPCResult::Type::NUM, "fee_headroom_multiplier", "Requested fee-headroom multiplier"},
                        {RPCResult::Type::BOOL, "fee_headroom_enforced", "Whether a bridge fee-headroom policy is being enforced"},
                        {RPCResult::Type::BOOL, "fee_headroom_sufficient", "Whether the implied fee satisfies the requested fee-headroom target"},
                        {RPCResult::Type::STR, "fee_headroom_error", /*optional=*/true, "Fee-headroom analysis error when fee_headroom_sufficient cannot be assessed"},
                        {RPCResult::Type::STR_AMOUNT, "required_fee_headroom", /*optional=*/true, "Required fee to satisfy the requested fee-headroom target when not redacted"},
                        {RPCResult::Type::BOOL, "required_fee_headroom_redacted", /*optional=*/true, "Whether required_fee_headroom is redacted"},
                        {RPCResult::Type::STR_AMOUNT, "required_fee_headroom_bucket", /*optional=*/true, "Redacted bucketed required fee to satisfy the requested fee-headroom target"},
                        {RPCResult::Type::STR, "fee_headroom_warning", /*optional=*/true, "Warning when the implied fee is below the requested fee-headroom target"},
                    }},
            }},
        RPCExamples{
            HelpExampleCli("z_fundpsbt", "1.0") +
            HelpExampleCli("z_fundpsbt", "1.0 \"btxs1...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();
            EnsureWalletIsUnlocked(*pwallet);

            const CAmount requested = AmountFromValue(request.params[0]);
            if (requested <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount must be positive");

            std::optional<ShieldedAddress> dest;
            if (!request.params[1].isNull()) {
                dest = ParseShieldedAddr(request.params[1].get_str());
                if (!dest.has_value()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid shielded destination");
            }

            CAmount fee{10000};
            if (!request.params[2].isNull()) {
                fee = AmountFromValue(request.params[2]);
                if (fee <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee must be positive");
            }
            fee = CanonicalizeShieldingFee(*pwallet, fee);

            std::optional<size_t> max_inputs_override;
            if (request.params.size() > 3) {
                ParseShieldingPolicyOptions(request.params[3], max_inputs_override);
            }

            std::string destination_error;
            auto effective_dest = ResolveShieldingDestination(pwallet, dest, /*allow_generate=*/true, destination_error);
            if (!effective_dest.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, destination_error);
            }

            // Collect UTXOs and select up to the requested amount + fee
            const bool coinbase_only_compatibility = UseCoinbaseOnlyShieldingCompatibility(*pwallet);
            const auto all_available = CollectSpendableTransparentShieldingUTXOs(*pwallet);
            auto total_spendable = SumTransparentShieldingUTXOValues(
                Span<const TransparentShieldingUTXO>{all_available.data(), all_available.size()});
            if (!total_spendable.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Input value overflow");
            }
            std::vector<TransparentShieldingUTXO> available =
                coinbase_only_compatibility
                    ? CollectSpendableTransparentShieldingUTXOs(*pwallet, /*coinbase_only=*/true)
                    : all_available;
            auto spendable = SumTransparentShieldingUTXOValues(
                Span<const TransparentShieldingUTXO>{available.data(), available.size()});
            if (!spendable.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Input value overflow");
            }
            if (*spendable <= 0) {
                if (coinbase_only_compatibility && !all_available.empty()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, GetPostForkCoinbaseShieldingCompatibilityMessage());
                }
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient transparent funds");
            }

            const ShieldingPolicySnapshot policy = GetShieldingPolicySnapshot(*pwallet, max_inputs_override);
            const auto desired_total = CheckedAdd(requested, fee);
            if (!desired_total || !MoneyRange(*desired_total)) throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount + fee overflows");
            if (*spendable < *desired_total) {
                if (coinbase_only_compatibility && *total_spendable >= *desired_total) {
                    throw JSONRPCError(RPC_WALLET_ERROR, GetPostForkCoinbaseShieldingCompatibilityMessage());
                }
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient transparent funds for requested amount plus fee");
            }

            // Select inputs (largest-first, respecting chunk limit)
            std::vector<COutPoint> outpoints;
            CAmount gross_amount{0};
            size_t limit = policy.applied_max_inputs_per_chunk;
            for (const auto& coin : available) {
                outpoints.push_back(coin.outpoint);
                const auto next = CheckedAdd(gross_amount, coin.value);
                if (!next || !MoneyRange(*next)) throw JSONRPCError(RPC_WALLET_ERROR, "Input accumulation overflow");
                gross_amount = *next;
                if (outpoints.size() >= limit || gross_amount >= *desired_total) break;
            }

            if (gross_amount < *desired_total) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient transparent funds for requested amount plus fee");
            }

            std::optional<PartiallySignedTransaction> psbt;
            std::string create_error;
            {
                LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
                psbt = pwallet->m_shielded_wallet->ShieldFundsPSBT(
                    outpoints,
                    fee,
                    *effective_dest,
                    requested,
                    &create_error);
            }
            if (!psbt.has_value()) {
                throw JSONRPCError(
                    RPC_WALLET_ERROR,
                    create_error.empty() ? "Failed to create shielded PSBT" : create_error);
            }

            // Populate BIP32 derivation paths for signers
            bool complete{false};
            const auto fill_err = pwallet->FillPSBT(*psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true);
            if (fill_err) {
                throw JSONRPCPSBTError(*fill_err);
            }

            // Count shielded outputs from the bundle
            size_t shielded_output_count{0};
            CAmount shielded_amount{0};
            if (!psbt->tx->shielded_bundle.IsEmpty()) {
                shielded_output_count = psbt->tx->shielded_bundle.GetShieldedOutputCount();
                // value_balance is negative for net deposits into shielded pool
                shielded_amount = -GetShieldedTxValueBalance(psbt->tx->shielded_bundle);
            }

            // Serialize PSBT to base64
            UniValue out(UniValue::VOBJ);
            out.pushKV("psbt", EncodePSBTBase64(*psbt));
            out.pushKV("fee", ValueFromAmount(fee));
            out.pushKV("transparent_inputs", static_cast<int64_t>(outpoints.size()));
            out.pushKV("shielded_outputs", static_cast<int64_t>(shielded_output_count));
            out.pushKV("shielded_amount", ValueFromAmount(shielded_amount));
            AppendBridgePsbtRelayFeeAnalysis(out,
                                             AnalyzeBridgePsbtRelayFee(*pwallet, *psbt),
                                             NextBridgeLeafBuildHeight(*pwallet));
            return out;
        }};
}

RPCHelpMan z_finalizepsbt()
{
    return RPCHelpMan{
        "z_finalizepsbt",
        "\nFinalize a fully-signed shielded PSBT and broadcast the transaction.\n"
        "The PSBT must have been created by z_fundpsbt and signed by all required\n"
        "signers via walletprocesspsbt.\n",
        {
            {"psbt", RPCArg::Type::STR, RPCArg::Optional::NO, "Base64-encoded PSBT"},
            {"broadcast", RPCArg::Type::BOOL, RPCArg::Default{true}, "Broadcast the transaction after finalizing"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", /*optional=*/true, "Transaction id (if broadcast)"},
                {RPCResult::Type::STR_HEX, "hex", "Finalized raw transaction hex"},
                {RPCResult::Type::BOOL, "complete", "Whether all transparent inputs are fully signed"},
            }},
        RPCExamples{HelpExampleCli("z_finalizepsbt", "\"cHNidP8B...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            // Decode PSBT
            PartiallySignedTransaction psbtx;
            std::string parse_error;
            if (!DecodeBase64PSBT(psbtx, request.params[0].get_str(), parse_error)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed %s", parse_error));
            }

            // Verify that this PSBT carries a shielded bundle
            if (psbtx.tx->shielded_bundle.IsEmpty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "PSBT does not contain a shielded bundle");
            }

            bool broadcast = request.params[1].isNull() || request.params[1].get_bool();

            // Try to finalize
            CMutableTransaction mtx;
            bool complete = FinalizeAndExtractPSBT(psbtx, mtx);

            UniValue out(UniValue::VOBJ);

            // Always serialize a best-effort transaction view for inspection.
            CMutableTransaction inspect_tx = complete ? mtx : *psbtx.tx;
            for (size_t i = 0; i < inspect_tx.vin.size() && i < psbtx.inputs.size(); ++i) {
                inspect_tx.vin[i].scriptSig = psbtx.inputs[i].final_script_sig;
                inspect_tx.vin[i].scriptWitness = psbtx.inputs[i].final_script_witness;
            }
            DataStream ssTx;
            ssTx << TX_WITH_WITNESS(inspect_tx);
            out.pushKV("hex", HexStr(ssTx));

            if (complete && broadcast) {
                pwallet->BlockUntilSyncedToCurrentChain();
                const CTransactionRef tx = MakeTransactionRef(mtx);
                node::NodeContext* node_context = pwallet->chain().context();
                if (node_context == nullptr || node_context->chainman == nullptr) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Node context not available for mempool preflight");
                }
                const auto accept_result = WITH_LOCK(::cs_main, return node_context->chainman->ProcessTransaction(
                    tx,
                    /*test_accept=*/true,
                    empty_ignore_rejects));
                if (accept_result.m_result_type != MempoolAcceptResult::ResultType::VALID) {
                    throw JSONRPCError(RPC_VERIFY_REJECTED, accept_result.m_state.ToString());
                }
                CommitShieldedTransactionOrThrow(pwallet, tx);
                out.pushKV("txid", tx->GetHash().GetHex());
            }

            out.pushKV("complete", complete);
            return out;
        }};
}

RPCHelpMan z_planshieldfunds()
{
    return RPCHelpMan{
        "z_planshieldfunds",
        "\nPlan a policy-aware transparent-to-shielded sweep without broadcasting it.\n"
        "After the post-61000 privacy fork, this planner only covers mature-coinbase compatibility\n"
        "sweeps; use bridge ingress for general transparent deposits. The examples below assume\n"
        "the wallet's compatible transparent set consists of mature coinbase outputs.\n",
        {
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Requested minimum shielded amount"},
            {"destination", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Destination shielded address"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(10000)}, "Fee"},
            {"options", RPCArg::Type::OBJ, RPCArg::DefaultHint{"{}"}, "Optional chunking policy overrides",
                {
                    {"max_inputs_per_chunk", RPCArg::Type::NUM, RPCArg::Optional::OMITTED,
                        "Override the daemon's recommended transparent-input batch size"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_AMOUNT, "requested_amount", "Requested minimum shielded amount"},
                {RPCResult::Type::STR_AMOUNT, "spendable_amount", "Current spendable transparent amount"},
                {RPCResult::Type::NUM, "spendable_utxos", "Current spendable transparent UTXO count"},
                {RPCResult::Type::STR_AMOUNT, "estimated_total_shielded", "Estimated total shielded amount"},
                {RPCResult::Type::STR_AMOUNT, "estimated_total_fee", "Estimated total fee across chunks"},
                {RPCResult::Type::NUM, "estimated_chunk_count", "Estimated chunk count"},
                {RPCResult::Type::OBJ, "policy", "Applied chunking policy", {
                    {RPCResult::Type::STR, "selection_strategy", "Transparent UTXO ordering strategy"},
                    {RPCResult::Type::NUM, "max_standard_tx_weight", "Network standard transaction weight ceiling"},
                    {RPCResult::Type::NUM, "soft_target_tx_weight", "Daemon soft target used for chunk sizing"},
                    {RPCResult::Type::NUM, "recommended_max_inputs_per_chunk", "Default recommended input cap per chunk"},
                    {RPCResult::Type::NUM, "applied_max_inputs_per_chunk", "Input cap used for this plan"},
                    {RPCResult::Type::NUM, "min_inputs_per_chunk", "Minimum retry chunk size"},
                    {RPCResult::Type::STR_AMOUNT, "relay_fee_floor_per_kb", "Current relay fee floor per kvB"},
                    {RPCResult::Type::STR_AMOUNT, "mempool_fee_floor_per_kb", "Current mempool fee floor per kvB"},
                    {RPCResult::Type::STR_AMOUNT, "shielded_fee_premium", "Fixed shielded relay premium"},
                }},
                {RPCResult::Type::ARR, "chunks", "", {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR_HEX, "txid", "Unsigned preview uses the deterministic candidate txid"},
                        {RPCResult::Type::STR_AMOUNT, "gross_amount", "Chunk input value before fee"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "Estimated shielded amount for this chunk"},
                        {RPCResult::Type::STR_AMOUNT, "fee", "Estimated fee for this chunk"},
                        {RPCResult::Type::NUM, "transparent_inputs", "Estimated transparent inputs in this chunk"},
                        {RPCResult::Type::NUM, "tx_weight", "Estimated transaction weight for this chunk"},
                    }},
                }},
            }},
        RPCExamples{
            HelpExampleCli("z_planshieldfunds", "10.0") +
            HelpExampleCli("z_planshieldfunds", "10.0 \"btxs1...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const CAmount requested = AmountFromValue(request.params[0]);
            if (requested <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount must be positive");

            std::optional<ShieldedAddress> dest;
            if (!request.params[1].isNull()) {
                dest = ParseShieldedAddr(request.params[1].get_str());
                if (!dest.has_value()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid shielded destination");
            }

            bool explicit_fee{false};
            CAmount fee{10000};
            if (!request.params[2].isNull()) {
                explicit_fee = true;
                fee = AmountFromValue(request.params[2]);
                if (fee <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee must be positive");
            }

            std::optional<size_t> max_inputs_override;
            if (request.params.size() > 3) {
                ParseShieldingPolicyOptions(request.params[3], max_inputs_override);
            }

            std::string destination_error;
            auto effective_dest = ResolveShieldingDestination(pwallet, dest, /*allow_generate=*/false, destination_error);
            if (!effective_dest.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, destination_error);
            }

            ShieldingPolicySnapshot policy = GetShieldingPolicySnapshot(*pwallet, max_inputs_override);
            std::string plan_error;
            auto preview = BuildShieldingPlanPreview(pwallet, requested, *effective_dest, explicit_fee, fee, policy, plan_error);
            if (!preview.has_value()) {
                const RPCErrorCode code = plan_error.find("Insufficient transparent funds") != std::string::npos
                    ? RPC_WALLET_INSUFFICIENT_FUNDS
                    : RPC_WALLET_ERROR;
                throw JSONRPCError(code, plan_error);
            }

            UniValue chunks(UniValue::VARR);
            for (const auto& chunk : preview->chunks) {
                chunks.push_back(ChunkToUniValue(chunk));
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("requested_amount", ValueFromAmount(preview->requested_amount));
            out.pushKV("spendable_amount", ValueFromAmount(preview->spendable_amount));
            out.pushKV("spendable_utxos", static_cast<int64_t>(preview->spendable_utxos));
            out.pushKV("estimated_total_shielded", ValueFromAmount(preview->estimated_total_shielded));
            out.pushKV("estimated_total_fee", ValueFromAmount(preview->estimated_total_fee));
            out.pushKV("estimated_chunk_count", static_cast<int64_t>(preview->chunks.size()));
            out.pushKV("policy", PolicyToUniValue(preview->policy));
            out.pushKV("chunks", std::move(chunks));
            return out;
        }};
}

RPCHelpMan z_mergenotes()
{
    return RPCHelpMan{
        "z_mergenotes",
        "\nMerge several small shielded notes into one.\n"
        "The merge path stays inside the live direct-spend envelope,\n"
        "so repeated calls may still be required when a wallet holds many small notes.\n"
        "This is the supported wallet-level consolidation path for high-note-count miner wallets.\n",
        {
            {"max_notes", RPCArg::Type::NUM, RPCArg::Default{10}, "Maximum notes requested for merge (the current live merge path uses up to 8 notes per tx)"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(10000)}, "Fee"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "Transaction id"},
                {RPCResult::Type::NUM, "merged_notes", "Merged note count"},
                {RPCResult::Type::NUM, "remaining_spendable_notes", "Remaining confirmed spendable note count after reserving the merge inputs"},
            }},
        RPCExamples{HelpExampleCli("z_mergenotes", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();
            EnsureWalletIsUnlocked(*pwallet);

            size_t max_notes{10};
            if (!request.params[0].isNull()) {
                // R5-511: Validate before signed-to-unsigned conversion.
                const int raw = request.params[0].getInt<int>();
                if (raw < 2) throw JSONRPCError(RPC_INVALID_PARAMETER, "max_notes must be at least 2");
                max_notes = static_cast<size_t>(raw);
            }

            bool explicit_fee{false};
            CAmount fee{10000};
            if (!request.params[1].isNull()) {
                explicit_fee = true;
                fee = AmountFromValue(request.params[1]);
                if (fee <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee must be positive");
            }

            size_t merged_count{0};
            // R5-520: Track reserved nullifiers for merge notes.
            std::vector<Nullifier> reserved_nullifiers;
            const auto release_reservations = [&]() {
                if (reserved_nullifiers.empty()) return;
                LOCK(pwallet->m_shielded_wallet->cs_shielded);
                pwallet->m_shielded_wallet->ReleasePendingSpends(reserved_nullifiers);
                reserved_nullifiers.clear();
            };
            const auto tx = BuildAndCommitShieldedTransactionWithAnchorRetry(
                pwallet,
                "z_mergenotes",
                /*map_value=*/{},
                [&]() -> CTransactionRef {
                    CTransactionRef built_tx;
                    try {
                        for (int attempt = 0; attempt < MAX_SHIELDED_FEE_CONVERGENCE_ATTEMPTS; ++attempt) {
                            std::optional<CMutableTransaction> mtx;
                            std::string create_error;
                            {
                                LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
                                if (!reserved_nullifiers.empty()) {
                                    pwallet->m_shielded_wallet->ReleasePendingSpends(reserved_nullifiers);
                                    reserved_nullifiers.clear();
                                }
                                merged_count = std::min({max_notes,
                                                         pwallet->m_shielded_wallet->GetSpendableNotes(1).size(),
                                                         static_cast<size_t>(shielded::v2::MAX_LIVE_DIRECT_SMILE_SPENDS)});
                                mtx = pwallet->m_shielded_wallet->MergeNotes(max_notes, fee, &create_error);
                                if (mtx.has_value()) {
                                    merged_count = mtx->shielded_bundle.GetShieldedInputCount();
                                    reserved_nullifiers = CollectShieldedNullifiers(mtx->shielded_bundle);
                                    pwallet->m_shielded_wallet->ReservePendingSpends(reserved_nullifiers);
                                }
                            }
                            if (!mtx.has_value()) {
                                throw JSONRPCError(
                                    RPC_WALLET_ERROR,
                                    create_error.empty() ? "No merge candidate notes found" : create_error);
                            }

                            CTransactionRef candidate = MakeTransactionRef(std::move(*mtx));
                            const CAmount required_fee = RequiredMempoolFee(*pwallet, *candidate);
                            if (fee >= required_fee) {
                                built_tx = std::move(candidate);
                                break;
                            }

                            if (explicit_fee) {
                                release_reservations();
                                throw JSONRPCError(
                                    RPC_WALLET_ERROR,
                                    strprintf("Fee too low for transaction size. Required at least %s", FormatMoney(required_fee)));
                            }
                            fee = required_fee;
                        }
                        if (!built_tx) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to create fee-compliant merge transaction");
                        }
                    } catch (...) {
                        release_reservations();
                        throw;
                    }
                    return built_tx;
                },
                [&]() {
                    release_reservations();
                });

            UniValue out(UniValue::VOBJ);
            out.pushKV("txid", tx->GetHash().GetHex());
            out.pushKV("merged_notes", static_cast<int64_t>(merged_count));
            const auto remaining_spendable_notes = WITH_LOCK(
                pwallet->m_shielded_wallet->cs_shielded,
                return pwallet->m_shielded_wallet->GetSpendableNotes(1).size());
            out.pushKV("remaining_spendable_notes", static_cast<int64_t>(remaining_spendable_notes));
            return out;
        }};
}

RPCHelpMan z_viewtransaction()
{
    return RPCHelpMan{
        "z_viewtransaction",
        "\nView shielded details for a wallet transaction.\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Transaction id"},
            {"include_sensitive", RPCArg::Type::BOOL, RPCArg::Default{false},
                "Include nullifiers and value-balance details after the post-61000 privacy fork"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "Transaction id"},
                {RPCResult::Type::STR, "family", "Shielded bundle family"},
                {RPCResult::Type::BOOL, "family_redacted", /*optional=*/true, "True when only the generic post-fork shielded family class is exposed"},
                {RPCResult::Type::ARR, "spends", "", {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR_HEX, "nullifier", /*optional=*/true, "Nullifier"},
                        {RPCResult::Type::BOOL, "nullifier_redacted", /*optional=*/true, "True when spend nullifier disclosure is redacted"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "Amount if owned"},
                        {RPCResult::Type::BOOL, "is_ours", "Ownership"},
                    }},
                }},
                {RPCResult::Type::ARR, "outputs", "", {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR_HEX, "commitment", /*optional=*/true, "Commitment"},
                        {RPCResult::Type::BOOL, "commitment_redacted", /*optional=*/true, "True when output commitment disclosure is redacted"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "Amount if decryptable"},
                        {RPCResult::Type::BOOL, "is_ours", "Ownership"},
                    }},
                }},
                {RPCResult::Type::ARR, "output_chunks", "", {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR, "scan_domain", /*optional=*/true, "Canonical chunk scan domain"},
                        {RPCResult::Type::NUM, "first_output_index", /*optional=*/true, "First covered output index"},
                        {RPCResult::Type::NUM, "output_count", /*optional=*/true, "Number of outputs covered by this chunk"},
                        {RPCResult::Type::NUM, "ciphertext_bytes", /*optional=*/true, "Covered ciphertext byte total"},
                        {RPCResult::Type::STR_HEX, "scan_hint_commitment", /*optional=*/true, "Chunk scan-hint commitment"},
                        {RPCResult::Type::STR_HEX, "ciphertext_commitment", /*optional=*/true, "Chunk ciphertext commitment"},
                        {RPCResult::Type::NUM, "owned_output_count", /*optional=*/true, "Number of decryptable outputs in this chunk"},
                        {RPCResult::Type::STR_AMOUNT, "owned_amount", /*optional=*/true, "Total decryptable amount in this chunk"},
                        {RPCResult::Type::BOOL, "chunk_metadata_redacted", /*optional=*/true, "True when chunk metadata is redacted"},
                    }},
                }},
                {RPCResult::Type::BOOL, "output_chunks_redacted", /*optional=*/true, "True when chunk metadata is redacted by default after the post-fork privacy redesign"},
                {RPCResult::Type::STR_AMOUNT, "value_balance", /*optional=*/true, "Shielded-state balance delta (legacy transparent value flow, or v2 fee)"},
                {RPCResult::Type::BOOL, "value_balance_redacted", /*optional=*/true, "True when value-balance disclosure is redacted"},
            }},
        RPCExamples{HelpExampleCli("z_viewtransaction", "\"<txid>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();
            const uint256 txid = ParseHashV(request.params[0], "txid");
            bool include_sensitive{false};
            if (request.params.size() > 1 && !request.params[1].isNull()) {
                include_sensitive = request.params[1].get_bool();
            }

            LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
            const bool redact_sensitive = RedactSensitiveShieldedRpcFields(*pwallet, include_sensitive);
            const CWalletTx* wtx = pwallet->GetWalletTx(txid);
            if (wtx && wtx->tx->HasShieldedBundle()) {
                const CShieldedBundle& bundle = wtx->tx->GetShieldedBundle();
                UniValue out(UniValue::VOBJ);
                out.pushKV("txid", txid.GetHex());
                PushShieldedBundleFamily(out, bundle, redact_sensitive);

                UniValue spends(UniValue::VARR);
                for (const Nullifier& nullifier : CollectShieldedNullifiers(bundle)) {
                    UniValue e(UniValue::VOBJ);
                    if (redact_sensitive) {
                        PushRedactedShieldedSpend(e);
                    } else {
                        e.pushKV("nullifier", nullifier.GetHex());
                    }
                    const auto owned = pwallet->m_shielded_wallet->GetCoinByNullifier(nullifier);
                    if (owned.has_value()) {
                        e.pushKV("amount", ValueFromAmount(owned->note.value));
                        e.pushKV("is_ours", true);
                    } else {
                        e.pushKV("amount", ValueFromAmount(0));
                        e.pushKV("is_ours", false);
                    }
                    spends.push_back(std::move(e));
                }
                out.pushKV("spends", std::move(spends));

                std::vector<ShieldedTxViewOutput> output_views;
                std::vector<ShieldedTxViewOutputChunk> output_chunk_views;
                if (bundle.HasV2Bundle()) {
                    const auto* v2_bundle = bundle.GetV2Bundle();
                    if (v2_bundle != nullptr) {
                        switch (shielded::v2::GetBundleSemanticFamily(*v2_bundle)) {
                        case shielded::v2::TransactionFamily::V2_SEND: {
                            const auto& payload = std::get<shielded::v2::SendPayload>(v2_bundle->payload);
                            for (const auto& output : payload.outputs) {
                                AppendShieldedOutputView(pwallet,
                                                         output.note_commitment,
                                                         output.encrypted_note,
                                                         output_views);
                            }
                            break;
                        }
                        case shielded::v2::TransactionFamily::V2_LIFECYCLE:
                            break;
                        case shielded::v2::TransactionFamily::V2_INGRESS_BATCH: {
                            const auto& payload = std::get<shielded::v2::IngressBatchPayload>(v2_bundle->payload);
                            for (const auto& output : payload.reserve_outputs) {
                                AppendShieldedOutputView(pwallet,
                                                         output.note_commitment,
                                                         output.encrypted_note,
                                                         output_views);
                            }
                            break;
                        }
                        case shielded::v2::TransactionFamily::V2_EGRESS_BATCH: {
                            const auto& payload = std::get<shielded::v2::EgressBatchPayload>(v2_bundle->payload);
                            for (const auto& output : payload.outputs) {
                                AppendShieldedOutputView(pwallet,
                                                         output.note_commitment,
                                                         output.encrypted_note,
                                                         output_views);
                            }
                            if (shielded::v2::TransactionBundleOutputChunksAreCanonical(*v2_bundle)) {
                                BuildOutputChunkViews(output_chunk_views,
                                                      {v2_bundle->output_chunks.data(), v2_bundle->output_chunks.size()},
                                                      {output_views.data(), output_views.size()});
                            }
                            break;
                        }
                        case shielded::v2::TransactionFamily::V2_REBALANCE: {
                            const auto& payload = std::get<shielded::v2::RebalancePayload>(v2_bundle->payload);
                            for (const auto& output : payload.reserve_outputs) {
                                AppendShieldedOutputView(pwallet,
                                                         output.note_commitment,
                                                         output.encrypted_note,
                                                         output_views);
                            }
                            if (!v2_bundle->output_chunks.empty() &&
                                shielded::v2::TransactionBundleOutputChunksAreCanonical(*v2_bundle)) {
                                BuildOutputChunkViews(output_chunk_views,
                                                      {v2_bundle->output_chunks.data(), v2_bundle->output_chunks.size()},
                                                      {output_views.data(), output_views.size()});
                            }
                            break;
                        }
                        case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
                        case shielded::v2::TransactionFamily::V2_GENERIC:
                            break;
                        }
                    }
                } else {
                    for (const auto& output : bundle.shielded_outputs) {
                        AppendShieldedOutputView(pwallet,
                                                 output.note_commitment,
                                                 output.encrypted_note,
                                                 output_views);
                    }
                }
                UniValue outputs(UniValue::VARR);
                for (const auto& output : output_views) {
                    outputs.push_back(ShieldedTxViewOutputToJSON(output, redact_sensitive));
                }
                out.pushKV("outputs", std::move(outputs));
                UniValue output_chunks(UniValue::VARR);
                for (const auto& chunk : output_chunk_views) {
                    output_chunks.push_back(ShieldedTxViewOutputChunkToJSON(chunk, redact_sensitive));
                }
                out.pushKV("output_chunks", std::move(output_chunks));
                if (redact_sensitive) {
                    out.pushKV("output_chunks_redacted", true);
                }
                PushShieldedValueBalance(out, GetShieldedStateValueBalance(bundle), redact_sensitive);
                return out;
            }

            auto cached_view = pwallet->m_shielded_wallet->GetCachedTransactionView(txid);
            if (!cached_view.has_value()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not found or no shielded bundle");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("txid", txid.GetHex());
            const bool redact_family = redact_sensitive && cached_view->family.rfind("v2_", 0) == 0;
            out.pushKV("family", redact_family ? "shielded_v2" : cached_view->family);
            if (redact_family) {
                out.pushKV("family_redacted", true);
            }

            UniValue spends(UniValue::VARR);
            for (const auto& spend : cached_view->spends) {
                UniValue e(UniValue::VOBJ);
                if (redact_sensitive) {
                    PushRedactedShieldedSpend(e);
                } else {
                    e.pushKV("nullifier", spend.nullifier.GetHex());
                }
                e.pushKV("amount", ValueFromAmount(spend.amount));
                e.pushKV("is_ours", spend.is_ours);
                spends.push_back(std::move(e));
            }
            out.pushKV("spends", std::move(spends));

            UniValue outputs(UniValue::VARR);
            for (const auto& output : cached_view->outputs) {
                outputs.push_back(ShieldedTxViewOutputToJSON(output, redact_sensitive));
            }
            out.pushKV("outputs", std::move(outputs));
            UniValue output_chunks(UniValue::VARR);
            for (const auto& chunk : cached_view->output_chunks) {
                output_chunks.push_back(ShieldedTxViewOutputChunkToJSON(chunk, redact_sensitive));
            }
            out.pushKV("output_chunks", std::move(output_chunks));
            if (redact_sensitive) {
                out.pushKV("output_chunks_redacted", true);
            }
            PushShieldedValueBalance(out, cached_view->value_balance, redact_sensitive);
            return out;
        }};
}

RPCHelpMan z_exportviewingkey()
{
    return RPCHelpMan{
        "z_exportviewingkey",
        "\nExport viewing key material for a shielded address.\n"
        "Disabled after the post-61000 privacy fork; use structured audit grants or a full encrypted wallet backup instead.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Shielded address"},
            {"allow_sensitive", RPCArg::Type::BOOL, RPCArg::Default{false},
                "Explicitly allow sensitive disclosure before the post-61000 privacy fork"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "Shielded address"},
                {RPCResult::Type::STR_HEX, "viewing_key", "KEM secret key"},
                {RPCResult::Type::STR_HEX, "kem_public_key", "KEM public key"},
            }},
        RPCExamples{HelpExampleCli("z_exportviewingkey", "\"btxs1...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();
            EnsureWalletIsUnlocked(*pwallet);
            bool allow_sensitive{false};
            if (request.params.size() > 1 && !request.params[1].isNull()) {
                allow_sensitive = request.params[1].get_bool();
            }
            RequireRawViewingKeySharingAllowedOrThrow(*pwallet, "z_exportviewingkey");
            RequireSensitiveShieldedRpcOptInOrThrow(*pwallet, allow_sensitive, "z_exportviewingkey");

            auto addr = ParseShieldedAddr(request.params[0].get_str());
            if (!addr.has_value()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid shielded address");

            LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
            auto vk = pwallet->m_shielded_wallet->ExportViewingKey(*addr);
            if (!vk.has_value()) throw JSONRPCError(RPC_WALLET_ERROR, "Address not found");

            mlkem::PublicKey kem_pk;
            if (!pwallet->m_shielded_wallet->GetKEMPublicKey(*addr, kem_pk)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Address key material unavailable");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("address", addr->Encode());
            out.pushKV("viewing_key", HexStr(*vk));
            out.pushKV("kem_public_key", HexStr(kem_pk));
            return out;
        }};
}

RPCHelpMan z_importviewingkey()
{
    return RPCHelpMan{
        "z_importviewingkey",
        "\nImport a viewing key for watch-only shielded scanning.\n"
        "Disabled after the post-61000 privacy fork; use structured audit grants or restore the encrypted wallet instead.\n",
        {
            {"viewing_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "KEM secret key"},
            {"kem_public_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "KEM public key"},
            {"address_or_spending_pk_hash",
             RPCArg::Type::STR,
             RPCArg::Optional::NO,
             "Shielded address (preferred) or legacy spending public key hash"},
            {"rescan", RPCArg::Type::BOOL, RPCArg::Default{true}, "Reset local shielded scan cache"},
            {"start_height", RPCArg::Type::NUM, RPCArg::Default{0}, "Scan start height marker"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "Imported shielded address"},
                {RPCResult::Type::BOOL, "success", "Import result"},
            }},
        RPCExamples{HelpExampleCli("z_importviewingkey", "\"<kem_sk>\" \"<kem_pk>\" \"btxs1...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();
            RequireRawViewingKeySharingAllowedOrThrow(*pwallet, "z_importviewingkey");
            EnsureShieldedViewingKeyWalletOrThrow(*pwallet);
            EnsureUnlockedShieldedSecretPersistenceOrThrow(*pwallet);

            const std::string kem_sk_hex = request.params[0].get_str();
            const std::string kem_pk_hex = request.params[1].get_str();
            if (!IsHex(kem_sk_hex) || kem_sk_hex.size() != mlkem::SECRETKEYBYTES * 2) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid viewing_key: expected ML-KEM secret key hex");
            }
            if (!IsHex(kem_pk_hex) || kem_pk_hex.size() != mlkem::PUBLICKEYBYTES * 2) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid kem_public_key: expected ML-KEM public key hex");
            }

            const auto kem_sk = ParseHex(kem_sk_hex);
            const auto kem_pk = ParseHex(kem_pk_hex);
            if (!ValidateMLKEMImportMaterial(kem_sk, kem_pk)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid viewing key material");
            }
            const std::string address_or_hash = request.params[2].get_str();
            std::optional<ShieldedAddress> imported_addr_hint = ParseShieldedAddr(address_or_hash);
            uint256 spending_pk_hash;
            if (imported_addr_hint.has_value()) {
                spending_pk_hash = imported_addr_hint->pk_hash;
                if (imported_addr_hint->kem_pk_hash != HashBytes(Span<const unsigned char>{kem_pk.data(), kem_pk.size()})) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Shielded address does not match kem_public_key");
                }
                if (imported_addr_hint->HasKEMPublicKey() &&
                    !std::equal(imported_addr_hint->kem_pk.begin(),
                                imported_addr_hint->kem_pk.end(),
                                kem_pk.begin(),
                                kem_pk.end())) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Shielded address does not match kem_public_key");
                }
            } else {
                spending_pk_hash = ParseHashV(request.params[2], "address_or_spending_pk_hash");
            }
            bool rescan = true;
            int start_height = 0;
            if (!request.params[3].isNull()) rescan = request.params[3].get_bool();
            if (!request.params[4].isNull()) start_height = request.params[4].getInt<int>();

            WalletRescanReserver reserver(*pwallet);
            if (rescan && !reserver.reserve()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
            }

            bool imported{false};
            ShieldedAddress imported_addr;
            uint256 start_block;
            int64_t import_birth_time{GetTime()};
            {
                LOCK(pwallet->cs_wallet);
                const int tip_height = pwallet->GetLastBlockHeight();
                if (start_height < 0 || start_height > tip_height) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid start_height");
                }
                if (rescan && !pwallet->chain().hasBlocks(pwallet->GetLastBlockHash(), start_height, {})) {
                    if (pwallet->chain().havePruned() && pwallet->chain().getPruneHeight() >= start_height) {
                        throw JSONRPCError(RPC_MISC_ERROR, "Can't rescan beyond pruned data. Use RPC call getblockchaininfo to determine your pruned height.");
                    }
                    if (pwallet->chain().hasAssumedValidChain()) {
                        throw JSONRPCError(RPC_MISC_ERROR, "Failed to rescan unavailable blocks likely due to an in-progress assumeutxo background sync. Check logs or getchainstates RPC for assumeutxo background sync progress and try again later.");
                    }
                    throw JSONRPCError(RPC_MISC_ERROR, "Failed to rescan unavailable blocks, potentially caused by data corruption. If the issue persists you may want to reindex (see -reindex option).");
                }
                if (rescan) {
                    EnsureNoHistoricalShieldedPartialRescan(*pwallet, start_height);
                    CHECK_NONFATAL(pwallet->chain().findAncestorByHeight(pwallet->GetLastBlockHash(), start_height, interfaces::FoundBlock().hash(start_block)));
                    CHECK_NONFATAL(pwallet->chain().findBlock(start_block, interfaces::FoundBlock().maxTime(import_birth_time)));
                }

                LOCK(pwallet->m_shielded_wallet->cs_shielded);
                imported = pwallet->m_shielded_wallet->ImportViewingKey(kem_sk, kem_pk, spending_pk_hash);
                if (!imported) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to import viewing key");
                }

                bool resolved{false};
                if (imported_addr_hint.has_value()) {
                    imported_addr = *imported_addr_hint;
                    resolved = true;
                } else {
                    const auto addrs = pwallet->m_shielded_wallet->GetAddresses();
                    for (const auto& addr : addrs) {
                        if (addr.pk_hash != spending_pk_hash) continue;
                        mlkem::PublicKey local_kem_pk{};
                        if (!pwallet->m_shielded_wallet->GetKEMPublicKey(addr, local_kem_pk)) continue;
                        if (std::equal(local_kem_pk.begin(), local_kem_pk.end(), kem_pk.begin(), kem_pk.end())) {
                            imported_addr = addr;
                            resolved = true;
                            break;
                        }
                    }
                }
                if (!resolved) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Imported key material could not be resolved to shielded address");
                }
                if (rescan) {
                    pwallet->MaybeUpdateBirthTime(import_birth_time);
                    pwallet->m_shielded_wallet->Rescan(start_height);
                }
            }

            if (imported && rescan) {
                const CWallet::ScanResult result = pwallet->ScanForWalletTransactions(start_block, start_height, /*max_height=*/{}, reserver, /*fUpdate=*/true, /*save_progress=*/false, /*scan_shielded=*/true);
                switch (result.status) {
                case CWallet::ScanResult::SUCCESS:
                    break;
                case CWallet::ScanResult::FAILURE:
                    throw JSONRPCError(RPC_MISC_ERROR, "Rescan failed. Potentially corrupted data files.");
                case CWallet::ScanResult::USER_ABORT:
                    throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted.");
                }
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("address", imported ? imported_addr.Encode() : "");
            out.pushKV("success", imported);
            return out;
        }};
}

RPCHelpMan z_validateaddress()
{
    return RPCHelpMan{
        "z_validateaddress",
        "\nValidate a shielded address string.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Shielded address"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "isvalid", "True if valid shielded address"},
                {RPCResult::Type::STR, "address", "Normalized address (if valid)"},
                {RPCResult::Type::NUM, "version", "Address version"},
                {RPCResult::Type::STR_HEX, "pk_hash", "Spending key hash"},
                {RPCResult::Type::STR_HEX, "kem_pk_hash", "KEM key hash"},
                {RPCResult::Type::STR_HEX, "kem_public_key", /*optional=*/true, "KEM public key when derivable from the address or known to the local wallet"},
                {RPCResult::Type::BOOL, "ismine", "Wallet has spending key"},
                {RPCResult::Type::BOOL, "iswatchonly", "Wallet has viewing key only"},
                {RPCResult::Type::STR, "lifecycle_state", /*optional=*/true, "Wallet-local lifecycle state if the address belongs to this wallet"},
                {RPCResult::Type::BOOL, "has_successor", /*optional=*/true, "Whether the wallet-local address lifecycle points to a successor"},
                {RPCResult::Type::STR, "successor", /*optional=*/true, "Successor address when lifecycle_state is rotated"},
                {RPCResult::Type::BOOL, "has_predecessor", /*optional=*/true, "Whether the wallet-local address lifecycle points to a predecessor"},
                {RPCResult::Type::STR, "predecessor", /*optional=*/true, "Previous address when this address replaced an older one"},
                {RPCResult::Type::NUM, "transition_height", /*optional=*/true, "Height where the wallet-local lifecycle last changed"},
            }},
        RPCExamples{HelpExampleCli("z_validateaddress", "\"btxs1...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            UniValue out(UniValue::VOBJ);
            auto addr = ParseShieldedAddr(request.params[0].get_str());
            if (!addr.has_value()) {
                out.pushKV("isvalid", false);
                return out;
            }

            out.pushKV("isvalid", true);
            out.pushKV("address", addr->Encode());
            out.pushKV("version", static_cast<int>(addr->version));
            out.pushKV("pk_hash", addr->pk_hash.GetHex());
            out.pushKV("kem_pk_hash", addr->kem_pk_hash.GetHex());
            if (addr->HasKEMPublicKey()) {
                out.pushKV("kem_public_key", HexStr(addr->kem_pk));
            }

            bool is_mine{false};
            bool is_watchonly{false};
            std::optional<ShieldedAddressLifecycle> lifecycle;
            if (const auto pwallet = GetWalletForJSONRPCRequest(request); pwallet && pwallet->m_shielded_wallet) {
                pwallet->BlockUntilSyncedToCurrentChain();
                LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
                const bool have_spending = pwallet->m_shielded_wallet->HaveSpendingKey(*addr);
                const bool have_view = pwallet->m_shielded_wallet->ExportViewingKey(*addr).has_value();
                mlkem::PublicKey kem_pk{};
                if (!addr->HasKEMPublicKey() && pwallet->m_shielded_wallet->GetKEMPublicKey(*addr, kem_pk)) {
                    out.pushKV("kem_public_key", HexStr(kem_pk));
                }
                is_mine = have_spending;
                is_watchonly = have_view && !have_spending;
                lifecycle = pwallet->m_shielded_wallet->GetAddressLifecycle(*addr);
            }
            out.pushKV("ismine", is_mine);
            out.pushKV("iswatchonly", is_watchonly);
            if (lifecycle.has_value() && lifecycle->IsValid()) {
                out.pushKV("lifecycle_state", GetShieldedAddressLifecycleStateName(lifecycle->state));
                out.pushKV("has_successor", lifecycle->has_successor);
                if (lifecycle->has_successor) {
                    out.pushKV("successor", lifecycle->successor.Encode());
                }
                out.pushKV("has_predecessor", lifecycle->has_predecessor);
                if (lifecycle->has_predecessor) {
                    out.pushKV("predecessor", lifecycle->predecessor.Encode());
                }
                if (lifecycle->transition_height >= 0) {
                    out.pushKV("transition_height", lifecycle->transition_height);
                }
            }
            return out;
        }};
}

// R4-603: List all local shielded addresses.
RPCHelpMan z_listaddresses()
{
    return RPCHelpMan{
        "z_listaddresses",
        "\nList all shielded addresses in the wallet.\n",
        {},
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                 {
                     {RPCResult::Type::STR, "address", "Shielded address"},
                     {RPCResult::Type::BOOL, "ismine", "True if spending key is available"},
                     {RPCResult::Type::BOOL, "iswatchonly", "True if only viewing key is available"},
                     {RPCResult::Type::STR, "lifecycle_state", /*optional=*/true, "Wallet-local lifecycle state"},
                     {RPCResult::Type::BOOL, "preferred_receive", /*optional=*/true, "True when this is the current preferred local receive address"},
                 }},
            }},
        RPCExamples{HelpExampleCli("z_listaddresses", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
            const auto addrs = pwallet->m_shielded_wallet->GetAddresses();
            const auto preferred = pwallet->m_shielded_wallet->GetPreferredReceiveAddress();

            UniValue result(UniValue::VARR);
            for (const auto& addr : addrs) {
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("address", addr.Encode());
                const bool have_spending = pwallet->m_shielded_wallet->HaveSpendingKey(addr);
                const bool have_view = pwallet->m_shielded_wallet->ExportViewingKey(addr).has_value();
                entry.pushKV("ismine", have_spending);
                entry.pushKV("iswatchonly", have_view && !have_spending);
                if (const auto lifecycle = pwallet->m_shielded_wallet->GetAddressLifecycle(addr);
                    lifecycle.has_value() && lifecycle->IsValid()) {
                    entry.pushKV("lifecycle_state", GetShieldedAddressLifecycleStateName(lifecycle->state));
                }
                entry.pushKV("preferred_receive", preferred.has_value() && *preferred == addr);
                result.push_back(std::move(entry));
            }
            return result;
        }};
}

RPCHelpMan z_rotateaddress()
{
    return RPCHelpMan{
        "z_rotateaddress",
        "\nRotate a local shielded address to a fresh successor after the post-fork privacy boundary.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Local shielded address to rotate"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(10000)}, "Lifecycle-control transaction fee"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "Lifecycle-control transaction id"},
                {RPCResult::Type::STR, "address", "Original shielded address"},
                {RPCResult::Type::STR, "successor", "Fresh successor shielded address"},
                {RPCResult::Type::STR, "lifecycle_state", "Lifecycle state of the original address"},
            }},
        RPCExamples{HelpExampleCli("z_rotateaddress", "\"btxs1...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();
            EnsureWalletIsUnlocked(*pwallet);

            const auto addr = ParseShieldedAddr(request.params[0].get_str());
            if (!addr.has_value()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid shielded address");
            }

            int32_t validation_height{0};
            {
                LOCK(pwallet->cs_wallet);
                validation_height = pwallet->GetLastBlockHeight() + 1;
            }
            if (!UseShieldedPrivacyRedesignAtHeight(validation_height)) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                                   strprintf("z_rotateaddress is disabled before block %d",
                                             Params().GetConsensus().nShieldedMatRiCTDisableHeight));
            }

            CAmount fee{10000};
            if (request.params.size() > 1 && !request.params[1].isNull()) {
                fee = AmountFromValue(request.params[1]);
                if (fee <= 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee must be positive");
                }
            }

            std::string error;
            std::optional<ShieldedAddressLifecycleBuildResult> built;
            {
                LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
                built = pwallet->m_shielded_wallet->BuildAddressRotationTransaction(*addr, fee, &error);
            }
            if (!built.has_value() || !built->successor.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                                   error.empty() ? "Failed to build shielded address rotation" : error);
            }

            const CTransactionRef tx = MakeTransactionRef(std::move(built->tx));
            CommitShieldedTransactionOrThrow(pwallet, tx);

            {
                LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
                if (!pwallet->m_shielded_wallet->ApplyCommittedAddressRotation(*addr,
                                                                               *built->successor,
                                                                               &error)) {
                    throw JSONRPCError(RPC_WALLET_ERROR,
                                       error.empty() ? "Failed to persist rotated shielded address lifecycle"
                                                     : error);
                }
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("txid", tx->GetHash().GetHex());
            out.pushKV("address", addr->Encode());
            out.pushKV("successor", built->successor->Encode());
            out.pushKV("lifecycle_state", GetShieldedAddressLifecycleStateName(ShieldedAddressLifecycleState::ROTATED));
            return out;
        }};
}

RPCHelpMan z_revokeaddress()
{
    return RPCHelpMan{
        "z_revokeaddress",
        "\nRevoke a local shielded address after the post-fork privacy boundary.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Local shielded address to revoke"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(10000)}, "Lifecycle-control transaction fee"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "Lifecycle-control transaction id"},
                {RPCResult::Type::STR, "address", "Revoked shielded address"},
                {RPCResult::Type::STR, "lifecycle_state", "Lifecycle state of the revoked address"},
            }},
        RPCExamples{HelpExampleCli("z_revokeaddress", "\"btxs1...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();
            EnsureWalletIsUnlocked(*pwallet);

            const auto addr = ParseShieldedAddr(request.params[0].get_str());
            if (!addr.has_value()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid shielded address");
            }

            int32_t validation_height{0};
            {
                LOCK(pwallet->cs_wallet);
                validation_height = pwallet->GetLastBlockHeight() + 1;
            }
            if (!UseShieldedPrivacyRedesignAtHeight(validation_height)) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                                   strprintf("z_revokeaddress is disabled before block %d",
                                             Params().GetConsensus().nShieldedMatRiCTDisableHeight));
            }

            CAmount fee{10000};
            if (request.params.size() > 1 && !request.params[1].isNull()) {
                fee = AmountFromValue(request.params[1]);
                if (fee <= 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee must be positive");
                }
            }

            std::string error;
            std::optional<ShieldedAddressLifecycleBuildResult> built;
            {
                LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
                built = pwallet->m_shielded_wallet->BuildAddressRevocationTransaction(*addr, fee, &error);
            }
            if (!built.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                                   error.empty() ? "Failed to build shielded address revocation" : error);
            }

            const CTransactionRef tx = MakeTransactionRef(std::move(built->tx));
            CommitShieldedTransactionOrThrow(pwallet, tx);

            {
                LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
                if (!pwallet->m_shielded_wallet->ApplyCommittedAddressRevocation(*addr, &error)) {
                    throw JSONRPCError(RPC_WALLET_ERROR,
                                       error.empty() ? "Failed to persist revoked shielded address lifecycle"
                                                     : error);
                }
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("txid", tx->GetHash().GetHex());
            out.pushKV("address", addr->Encode());
            out.pushKV("lifecycle_state", GetShieldedAddressLifecycleStateName(ShieldedAddressLifecycleState::REVOKED));
            return out;
        }};
}

RPCHelpMan z_gettotalbalance()
{
    return RPCHelpMan{
        "z_gettotalbalance",
        "\nReturn the combined transparent and shielded wallet balance.\n",
        {
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "Minimum confirmations"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_AMOUNT, "transparent", "Spendable transparent balance"},
                {RPCResult::Type::STR_AMOUNT, "shielded", "Spendable shielded balance"},
                {RPCResult::Type::STR_AMOUNT, "total", "Combined spendable balance"},
                {RPCResult::Type::STR_AMOUNT, "transparent_watchonly", /*optional=*/true, "Watch-only transparent balance"},
                {RPCResult::Type::STR_AMOUNT, "shielded_watchonly", /*optional=*/true, "Watch-only shielded balance"},
                {RPCResult::Type::STR_AMOUNT, "watchonly_total", /*optional=*/true, "Combined watch-only balance"},
                {RPCResult::Type::STR_AMOUNT, "total_including_watchonly", /*optional=*/true, "Combined spendable plus watch-only balance"},
                {RPCResult::Type::BOOL, "scan_incomplete", /*optional=*/true, "True if shielded scan could not complete due to pruned blocks"},
                {RPCResult::Type::BOOL, "locked_state_incomplete", /*optional=*/true, "True if the wallet was loaded locked from tree-only fallback state and full shielded accounting requires an unlock refresh."},
            }},
        RPCExamples{
            HelpExampleCli("z_gettotalbalance", "") +
            HelpExampleCli("z_gettotalbalance", "6")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            int minconf = 1;
            if (!request.params[0].isNull()) {
                minconf = request.params[0].getInt<int>();
            }
            if (minconf < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "minconf must be non-negative");

            const Balance transparent_bal = GetBalance(*pwallet, minconf);
            const CAmount transparent = transparent_bal.m_mine_trusted;

            ShieldedBalanceSummary shielded_summary;
            bool scan_incomplete;
            bool locked_state_incomplete;
            {
                LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
                shielded_summary = pwallet->m_shielded_wallet->GetShieldedBalanceSummary(minconf);
                scan_incomplete = pwallet->m_shielded_wallet->IsScanIncomplete();
                locked_state_incomplete = false;
            }
            locked_state_incomplete = WalletNeedsLockedShieldedAccountingRefresh(*pwallet);

            const auto total = CheckedAdd(transparent, shielded_summary.spendable);
            if (!total || !MoneyRange(*total)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Balance overflow");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("transparent", ValueFromAmount(transparent));
            out.pushKV("shielded", ValueFromAmount(shielded_summary.spendable));
            out.pushKV("total", ValueFromAmount(*total));
            const CAmount transparent_watchonly = transparent_bal.m_watchonly_trusted;
            if (transparent_watchonly != 0 || shielded_summary.watchonly != 0) {
                const auto watchonly_total = CheckedAdd(transparent_watchonly, shielded_summary.watchonly);
                if (!watchonly_total || !MoneyRange(*watchonly_total)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Balance overflow");
                }
                const auto total_with_watchonly = CheckedAdd(*total, *watchonly_total);
                if (!total_with_watchonly || !MoneyRange(*total_with_watchonly)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Balance overflow");
                }
                out.pushKV("transparent_watchonly", ValueFromAmount(transparent_watchonly));
                out.pushKV("shielded_watchonly", ValueFromAmount(shielded_summary.watchonly));
                out.pushKV("watchonly_total", ValueFromAmount(*watchonly_total));
                out.pushKV("total_including_watchonly", ValueFromAmount(*total_with_watchonly));
            }
            if (scan_incomplete) {
                out.pushKV("scan_incomplete", true);
            }
            if (locked_state_incomplete) {
                out.pushKV("locked_state_incomplete", true);
            }
            return out;
        }};
}

RPCHelpMan z_listreceivedbyaddress()
{
    return RPCHelpMan{
        "z_listreceivedbyaddress",
        "\nList shielded notes received by each address.\n",
        {
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "Minimum confirmations"},
            {"include_watchonly", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include view-only addresses"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", "Shielded address"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "Total received"},
                        {RPCResult::Type::NUM, "note_count", "Note count"},
                    }},
            }},
        RPCExamples{HelpExampleCli("z_listreceivedbyaddress", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            int minconf = 1;
            bool include_watchonly = false;
            if (!request.params[0].isNull()) minconf = request.params[0].getInt<int>();
            if (!request.params[1].isNull()) include_watchonly = request.params[1].get_bool();
            if (minconf < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "minconf must be non-negative");

            LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
            const auto notes = pwallet->m_shielded_wallet->GetUnspentNotes(minconf);
            const auto addrs = pwallet->m_shielded_wallet->GetAddresses();

            // Accumulate per-address totals.
            std::map<std::string, std::pair<CAmount, int>> addr_totals;
            for (const auto& addr : addrs) {
                const bool have_spending = pwallet->m_shielded_wallet->HaveSpendingKey(addr);
                if (!include_watchonly && !have_spending) continue;
                addr_totals[addr.Encode()] = {0, 0};
            }
            for (const auto& coin : notes) {
                if (!include_watchonly && !coin.is_mine_spend) continue;
                // Find the address for this note via its spending key hash.
                for (const auto& addr : addrs) {
                    if (addr.pk_hash == coin.note.recipient_pk_hash) {
                        auto& [total, count] = addr_totals[addr.Encode()];
                        const auto sum = CheckedAdd(total, coin.note.value);
                        if (!sum || !MoneyRange(*sum)) {
                            throw JSONRPCError(RPC_WALLET_ERROR, "Balance overflow");
                        }
                        total = *sum;
                        ++count;
                        break;
                    }
                }
            }

            UniValue result(UniValue::VARR);
            for (const auto& [addr_str, totals] : addr_totals) {
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("address", addr_str);
                entry.pushKV("amount", ValueFromAmount(totals.first));
                entry.pushKV("note_count", totals.second);
                result.push_back(std::move(entry));
            }
            return result;
        }};
}

RPCHelpMan z_verifywalletintegrity()
{
    return RPCHelpMan{
        "z_verifywalletintegrity",
        "\nVerify that all shielded and PQ key material is present, derivable, and "
        "properly persisted. Run this before backupwallet to confirm the backup "
        "will contain complete key material.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "integrity_ok", "True if all key material is present and consistent"},
                {RPCResult::Type::NUM, "shielded_keys_total", "Total shielded key sets"},
                {RPCResult::Type::NUM, "spending_keys_loaded", "Spending keys available (can sign)"},
                {RPCResult::Type::NUM, "viewing_keys_loaded", "Viewing keys available (can decrypt)"},
                {RPCResult::Type::NUM, "spending_keys_missing", "Spending keys not yet derived (wallet may be locked)"},
                {RPCResult::Type::BOOL, "master_seed_available", "True if master seed is accessible for key derivation"},
                {RPCResult::Type::NUM, "shielded_notes_total", "Total tracked shielded notes"},
                {RPCResult::Type::NUM, "shielded_notes_unspent", "Unspent shielded notes"},
                {RPCResult::Type::NUM, "tree_size", "Shielded Merkle tree commitment count"},
                {RPCResult::Type::NUM, "scan_height", "Last scanned block height"},
                {RPCResult::Type::BOOL, "scan_incomplete", "True if scan could not complete (e.g. pruned blocks)"},
                {RPCResult::Type::NUM, "pq_descriptors", "Number of PQ descriptors in wallet"},
                {RPCResult::Type::NUM, "pq_descriptors_with_seed", "PQ descriptors that have their seed stored"},
                {RPCResult::Type::NUM, "pq_seed_capable_descriptors", "PQ descriptors that include pqhd() and can carry a local seed"},
                {RPCResult::Type::NUM, "pq_seed_capable_with_seed", "Seed-capable PQ descriptors that have their local seed stored"},
                {RPCResult::Type::NUM, "pq_public_only_descriptors", "PQ descriptors that only contain public key material and do not require a local seed"},
                {RPCResult::Type::ARR, "warnings", "List of issues found",
                    {{RPCResult::Type::STR, "", "Warning message"}}},
                {RPCResult::Type::ARR, "notes", "Informational notes that do not affect integrity",
                    {{RPCResult::Type::STR, "", "Informational note"}}},
            }},
        RPCExamples{HelpExampleCli("z_verifywalletintegrity", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            UniValue warnings(UniValue::VARR);
            UniValue notes(UniValue::VARR);
            UniValue out(UniValue::VOBJ);

            // Shielded wallet integrity
            CShieldedWallet::KeyIntegrityReport report;
            {
                LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
                report = pwallet->m_shielded_wallet->VerifyKeyIntegrity();
            }

            out.pushKV("shielded_keys_total", report.total_keys);
            out.pushKV("spending_keys_loaded", report.spending_keys_loaded);
            out.pushKV("viewing_keys_loaded", report.viewing_keys_loaded);
            out.pushKV("spending_keys_missing", report.spending_keys_missing);
            out.pushKV("master_seed_available", report.master_seed_available);
            out.pushKV("shielded_notes_total", report.notes_total);
            out.pushKV("shielded_notes_unspent", report.notes_unspent);
            out.pushKV("tree_size", report.tree_size);
            out.pushKV("scan_height", report.scan_height);
            out.pushKV("scan_incomplete", report.scan_incomplete);

            if (!report.master_seed_available) {
                warnings.push_back("Master seed is not available — spending keys cannot be derived. "
                                   "Wallet may be locked or seed was not persisted.");
            }
            if (report.spending_keys_missing > 0) {
                warnings.push_back(strprintf("%d spending key(s) could not be loaded. "
                                             "Unlock the wallet and retry.", report.spending_keys_missing));
            }
            if (report.scan_incomplete) {
                warnings.push_back("Shielded chain scan is incomplete — some blocks were pruned. "
                                   "Shielded balances may be underreported. Disable pruning and reindex.");
            }

            // PQ descriptor integrity
            const bool private_keys_disabled = pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
            PQDescriptorIntegrityReport pq_report;
            {
                LOCK(pwallet->cs_wallet);
                WalletBatch batch(pwallet->GetDatabase());
                for (const auto& spkm : pwallet->GetAllScriptPubKeyMans()) {
                    const auto* desc_spkm = dynamic_cast<const DescriptorScriptPubKeyMan*>(spkm);
                    if (!desc_spkm) continue;

                    std::string desc_str;
                    if (!desc_spkm->GetDescriptorString(desc_str, false)) continue;
                    if (desc_str.find("pqhd(") == std::string::npos &&
                        desc_str.find("mr(") == std::string::npos) continue;

                    ++pq_report.total;
                    const bool seed_capable = desc_str.find("pqhd(") != std::string::npos;
                    if (seed_capable) {
                        ++pq_report.seed_capable;
                    } else {
                        ++pq_report.public_only;
                    }

                    std::vector<unsigned char> seed;
                    if (batch.ReadPQDescriptorSeed(desc_spkm->GetID(), seed) && seed.size() == 32) {
                        ++pq_report.with_seed;
                        if (seed_capable) {
                            ++pq_report.seed_capable_with_seed;
                        }
                        memory_cleanse(seed.data(), seed.size());
                    } else if (seed_capable) {
                        ++pq_report.missing_local_seed;
                    }
                }
            }

            out.pushKV("pq_descriptors", pq_report.total);
            out.pushKV("pq_descriptors_with_seed", pq_report.with_seed);
            out.pushKV("pq_seed_capable_descriptors", pq_report.seed_capable);
            out.pushKV("pq_seed_capable_with_seed", pq_report.seed_capable_with_seed);
            out.pushKV("pq_public_only_descriptors", pq_report.public_only);

            if (pq_report.public_only > 0) {
                notes.push_back(strprintf("%d PQ descriptor(s) are public-only and do not require a local seed. "
                                          "This is expected for imported multisig cosigner descriptors.",
                                          pq_report.public_only));
            }
            if (pq_report.missing_local_seed > 0) {
                if (private_keys_disabled) {
                    notes.push_back(strprintf("%d seed-capable PQ descriptor(s) are missing a local seed because "
                                              "this wallet has private keys disabled.",
                                              pq_report.missing_local_seed));
                } else {
                    warnings.push_back(strprintf("%d of %d seed-capable PQ descriptor(s) are missing their local seed. "
                                                 "These descriptors cannot derive keys and the wallet backup will be incomplete. "
                                                 "Use importdescriptors to restore from a private listdescriptors export.",
                                                 pq_report.missing_local_seed, pq_report.seed_capable));
                }
            }

            bool integrity_ok = (report.spending_keys_missing == 0 &&
                                 report.master_seed_available &&
                                 !report.scan_incomplete &&
                                 (private_keys_disabled || pq_report.missing_local_seed == 0));
            out.pushKV("integrity_ok", integrity_ok);
            out.pushKV("warnings", std::move(warnings));
            out.pushKV("notes", std::move(notes));
            return out;
        }};
}

RPCHelpMan bridge_planin()
{
    return RPCHelpMan{
        "bridge_planin",
        "\nBuild a deterministic bridge-in plan for funding a P2MR bridge output and settling it into the shielded pool.\n",
        {
            {"operator_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Operator PQ pubkey hex (ML-DSA-44 or SLH-DSA-128s)"},
            {"refund_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Refund PQ pubkey hex (ML-DSA-44 or SLH-DSA-128s)"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Shielded bridge amount"},
            {"options", RPCArg::Type::OBJ, RPCArg::DefaultHint{"{}"}, "Bridge planning options",
                {
                    {"bridge_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge instance id"},
                    {"operation_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge operation id"},
                    {"refund_lock_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Absolute refund lock height"},
                    {"recipient", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Shielded recipient address; if omitted a new local shielded address is generated"},
                    {"shielded_anchor", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Shielded anchor override"},
                    {"memo", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "UTF-8 memo"},
                    {"memo_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex memo bytes"},
                    {"batch_commitment_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Canonical bridge batch commitment bytes; if set, memo/memo_hex must be omitted and the batch total must equal amount"},
                    {"operator_view_pubkeys", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Legacy shorthand for operator_view_grants; before the post-61000 fork this emits the legacy full-plaintext audit payload, while after the fork it emits the structured minimal disclosure payload",
                        {
                            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "ML-KEM public key"},
                        }},
                    {"operator_view_grants", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Optional structured or legacy view grants to include in the bridge settlement",
                        {
                            {"grant", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One grant request",
                                {
                                    {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "ML-KEM public key"},
                                    {"format", RPCArg::Type::STR, RPCArg::DefaultHint{"legacy_audit or structured_disclosure"}, "Grant payload format"},
                                    {"disclosure_fields", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Selected fields for structured_disclosure grants",
                                        {
                                            {"field", RPCArg::Type::STR, RPCArg::Optional::NO, "One of amount, recipient, memo, sender"},
                                        }},
                                }},
                        }},
                    {"disclosure_policy", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional bridge-side policy that auto-adds required grants when amount crosses a threshold",
                        {
                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Policy version"},
                            {"threshold_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount threshold that triggers the policy"},
                            {"required_grants", RPCArg::Type::ARR, RPCArg::Optional::NO, "Grant requests that must be included when the policy triggers",
                                {
                                    {"grant", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One grant request",
                                        {
                                            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "ML-KEM public key"},
                                            {"format", RPCArg::Type::STR, RPCArg::DefaultHint{"legacy_audit or structured_disclosure"}, "Grant payload format"},
                                            {"disclosure_fields", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Selected fields for structured_disclosure grants",
                                                {
                                                    {"field", RPCArg::Type::STR, RPCArg::Optional::NO, "One of amount, recipient, memo, sender"},
                                                }},
                                        }},
                                }},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Bridge plan and chain-side artifacts",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_planin",
                           "\"<operator_pubkey>\" \"<refund_pubkey>\" 5 "
                           "'{\"bridge_id\":\"01\",\"operation_id\":\"02\",\"refund_lock_height\":200,\"recipient\":\"btxs1...\"}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const UniValue& options = request.params[3];
            BridgeInPlanRequest plan_request;
            plan_request.operator_key = ParseBridgeKeySpec(request.params[0], "operator_key");
            plan_request.refund_key = ParseBridgeKeySpec(request.params[1], "refund_key");
            plan_request.amount = AmountFromValue(request.params[2]);
            if (plan_request.amount <= 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "amount must be positive");
            }
            plan_request.build_height = NextBridgeLeafBuildHeight(*pwallet);
            plan_request.ids = ParseBridgePlanIdsOrThrow(options);
            plan_request.refund_lock_height = ParseRefundLockHeightOrThrow(options);
            bool generated_recipient{false};
            plan_request.recipient = ResolveBridgeRecipientOrThrow(pwallet, options, generated_recipient);
            plan_request.shielded_anchor = ResolveBridgeAnchorOrThrow(pwallet, options);
            plan_request.memo = ParseBridgeMemoOrThrow(options);
            plan_request.batch_commitment = ParseBridgeBatchCommitmentOrThrow(options,
                                                                             shielded::BridgeDirection::BRIDGE_IN,
                                                                             plan_request.ids);
            if (plan_request.batch_commitment.has_value() && !plan_request.memo.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "batch_commitment_hex cannot be combined with memo or memo_hex");
            }
            plan_request.operator_view_grants = ParseBridgeViewGrantsOrThrow(options, plan_request.build_height);
            plan_request.disclosure_policy = ParseBridgeDisclosurePolicyOrThrow(options);
            if (auto error = ValidateAndApplyBridgeDisclosurePolicy(plan_request); error.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, *error);
            }

            auto plan = BuildBridgeInPlan(plan_request);
            if (!plan.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to construct bridge-in plan");
            }

            UniValue out = BridgePlanToUniValue(
                *plan,
                Span<const BridgeViewGrantRequest>{plan_request.operator_view_grants.data(), plan_request.operator_view_grants.size()},
                plan_request.disclosure_policy ? &*plan_request.disclosure_policy : nullptr);
            out.pushKV("recipient", plan_request.recipient.Encode());
            out.pushKV("recipient_generated", generated_recipient);
            out.pushKV("shielded_anchor", plan_request.shielded_anchor.GetHex());
            if (plan_request.batch_commitment.has_value()) {
                out.pushKV("batch_commitment", BridgeBatchCommitmentToUniValue(*plan_request.batch_commitment));
                out.pushKV("batch_commitment_hex", EncodeBridgeBatchCommitmentHex(*plan_request.batch_commitment));
                out.pushKV("batch_commitment_hash",
                           shielded::ComputeBridgeBatchCommitmentHash(*plan_request.batch_commitment).GetHex());
            }
            return out;
        }};
}

RPCHelpMan bridge_planbatchin()
{
    return RPCHelpMan{
        "bridge_planbatchin",
        "\nBuild a deterministic bridge-in plan that aggregates many off-chain credits into one shielded settlement note.\n",
        {
            {"operator_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Operator PQ pubkey hex (ML-DSA-44 or SLH-DSA-128s)"},
            {"refund_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Refund PQ pubkey hex (ML-DSA-44 or SLH-DSA-128s)"},
            {"leaves", RPCArg::Type::ARR, RPCArg::Optional::NO, "Canonical batch leaves or signed authorizations",
                {
                    {"leaf", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One batch entry",
                        {
                            {"kind", RPCArg::Type::STR, RPCArg::Optional::NO, "shield_credit, transparent_payout, or shielded_payout"},
                            {"wallet_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Source wallet/account identifier hash"},
                            {"destination_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Destination identifier hash"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Leaf amount"},
                            {"authorization_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the off-chain user authorization bundle"},
                            {"authorization_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Signed bridge batch authorization; if set, the leaf fields are ignored and derived from the signed authorization"},
                        }},
                }},
            {"options", RPCArg::Type::OBJ, RPCArg::DefaultHint{"{}"}, "Bridge planning options",
                {
                    {"bridge_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge instance id"},
                    {"operation_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge operation id"},
                    {"refund_lock_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Absolute refund lock height"},
                    {"recipient", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Shielded recipient address; if omitted a new local shielded address is generated"},
                    {"shielded_anchor", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Shielded anchor override"},
                    {"external_anchor", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional external DA/proof anchor for the aggregated batch",
                        {
                            {"domain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed identifier for the external domain, namespace, bridge cluster, or proving domain"},
                            {"source_epoch", RPCArg::Type::NUM, RPCArg::Optional::NO, "Positive external batch / epoch / blob sequence number"},
                            {"data_root", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "External data-availability or batch-log root"},
                            {"verification_root", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "External proof receipt root, committee transcript root, or verification digest"},
                        }},
                    {"operator_view_pubkeys", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Legacy shorthand for operator_view_grants; before the post-61000 fork this emits the legacy full-plaintext audit payload, while after the fork it emits the structured minimal disclosure payload",
                        {
                            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "ML-KEM public key"},
                        }},
                    {"operator_view_grants", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Optional structured or legacy view grants to include in the bridge settlement",
                        {
                            {"grant", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One grant request",
                                {
                                    {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "ML-KEM public key"},
                                    {"format", RPCArg::Type::STR, RPCArg::DefaultHint{"legacy_audit or structured_disclosure"}, "Grant payload format"},
                                    {"disclosure_fields", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Selected fields for structured_disclosure grants",
                                        {
                                            {"field", RPCArg::Type::STR, RPCArg::Optional::NO, "One of amount, recipient, memo, sender"},
                                        }},
                                }},
                        }},
                    {"disclosure_policy", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional bridge-side policy that auto-adds required grants when amount crosses a threshold",
                        {
                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Policy version"},
                            {"threshold_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount threshold that triggers the policy"},
                            {"required_grants", RPCArg::Type::ARR, RPCArg::Optional::NO, "Grant requests that must be included when the policy triggers",
                                {
                                    {"grant", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One grant request",
                                        {
                                            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "ML-KEM public key"},
                                            {"format", RPCArg::Type::STR, RPCArg::DefaultHint{"legacy_audit or structured_disclosure"}, "Grant payload format"},
                                            {"disclosure_fields", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Selected fields for structured_disclosure grants",
                                                {
                                                    {"field", RPCArg::Type::STR, RPCArg::Optional::NO, "One of amount, recipient, memo, sender"},
                                                }},
                                        }},
                                }},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Bridge batch-in plan and canonical commitment",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_planbatchin",
                           "\"<operator_pubkey>\" \"<refund_pubkey>\" "
                           "'[{\"authorization_hex\":\"<authorization_hex>\"}]' "
                           "'{\"bridge_id\":\"01\",\"operation_id\":\"02\",\"refund_lock_height\":200,\"recipient\":\"btxs1...\"}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const UniValue& options = request.params[3];
            const auto ids = ParseBridgePlanIdsOrThrow(options);
            const auto entries = ParseBridgeBatchEntriesOrThrow(request.params[2],
                                                                NextBridgeLeafBuildHeight(*pwallet),
                                                                shielded::BridgeDirection::BRIDGE_IN,
                                                                ids);
            const auto external_anchor = ParseBridgeExternalAnchorOrThrow(options);
            const auto commitment = BuildBridgeBatchCommitmentOrThrow(shielded::BridgeDirection::BRIDGE_IN,
                                                                      entries.leaves,
                                                                      ids,
                                                                      external_anchor);

            BridgeInPlanRequest plan_request;
            plan_request.operator_key = ParseBridgeKeySpec(request.params[0], "operator_key");
            plan_request.refund_key = ParseBridgeKeySpec(request.params[1], "refund_key");
            plan_request.ids = ids;
            plan_request.amount = commitment.total_amount;
            plan_request.refund_lock_height = ParseRefundLockHeightOrThrow(options);
            plan_request.build_height = NextBridgeLeafBuildHeight(*pwallet);
            bool generated_recipient{false};
            plan_request.recipient = ResolveBridgeRecipientOrThrow(pwallet, options, generated_recipient);
            plan_request.shielded_anchor = ResolveBridgeAnchorOrThrow(pwallet, options);
            plan_request.batch_commitment = commitment;
            plan_request.operator_view_grants = ParseBridgeViewGrantsOrThrow(options, plan_request.build_height);
            plan_request.disclosure_policy = ParseBridgeDisclosurePolicyOrThrow(options);
            if (auto error = ValidateAndApplyBridgeDisclosurePolicy(plan_request); error.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, *error);
            }

            auto plan = BuildBridgeInPlan(plan_request);
            if (!plan.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to construct batch bridge-in plan");
            }

            UniValue out = BridgePlanToUniValue(
                *plan,
                Span<const BridgeViewGrantRequest>{plan_request.operator_view_grants.data(), plan_request.operator_view_grants.size()},
                plan_request.disclosure_policy ? &*plan_request.disclosure_policy : nullptr);
            out.pushKV("recipient", plan_request.recipient.Encode());
            out.pushKV("recipient_generated", generated_recipient);
            out.pushKV("shielded_anchor", plan_request.shielded_anchor.GetHex());
            out.pushKV("batch_commitment", BridgeBatchCommitmentToUniValue(commitment));
            out.pushKV("batch_commitment_hex", EncodeBridgeBatchCommitmentHex(commitment));
            out.pushKV("batch_commitment_hash", shielded::ComputeBridgeBatchCommitmentHash(commitment).GetHex());

            UniValue leaf_array(UniValue::VARR);
            for (const auto& leaf : entries.leaves) {
                leaf_array.push_back(BridgeBatchLeafToUniValue(leaf));
            }
            out.pushKV("leaves", std::move(leaf_array));

            if (!entries.authorizations.empty()) {
                UniValue authorization_array(UniValue::VARR);
                for (const auto& authorization : entries.authorizations) {
                    UniValue entry(UniValue::VOBJ);
                    entry.pushKV("authorization", BridgeBatchAuthorizationToUniValue(authorization));
                    entry.pushKV("authorization_hex", EncodeBridgeBatchAuthorizationHex(authorization));
                    entry.pushKV("authorization_hash", shielded::ComputeBridgeBatchAuthorizationHash(authorization).GetHex());
                    authorization_array.push_back(std::move(entry));
                }
                out.pushKV("authorizations", std::move(authorization_array));
            }
            return out;
        }};
}

RPCHelpMan bridge_planout()
{
    return RPCHelpMan{
        "bridge_planout",
        "\nBuild a deterministic bridge-out plan for settling a bridge output to a transparent payout template.\n",
        {
            {"operator_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Operator PQ pubkey hex (ML-DSA-44 or SLH-DSA-128s)"},
            {"refund_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Refund PQ pubkey hex (ML-DSA-44 or SLH-DSA-128s)"},
            {"payout_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Transparent payout address"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Payout amount"},
            {"options", RPCArg::Type::OBJ, RPCArg::DefaultHint{"{}"}, "Bridge planning options",
                {
                    {"bridge_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge instance id"},
                    {"operation_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge operation id"},
                    {"refund_lock_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Absolute refund lock height"},
                    {"genesis_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Genesis hash override; defaults to the active chain genesis hash"},
                    {"batch_commitment_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Canonical bridge batch commitment bytes; if set, the batch total must equal amount"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Bridge plan and canonical attestation",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_planout",
                           "\"<operator_pubkey>\" \"<refund_pubkey>\" \"btxrt1...\" 4 "
                           "'{\"bridge_id\":\"03\",\"operation_id\":\"04\",\"refund_lock_height\":250}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForBridge(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const UniValue& options = request.params[4];
            const CTxDestination payout_dest = ParseDestinationOrThrow(request.params[2], "payout_address");

            BridgeOutPlanRequest plan_request;
            plan_request.operator_key = ParseBridgeKeySpec(request.params[0], "operator_key");
            plan_request.refund_key = ParseBridgeKeySpec(request.params[1], "refund_key");
            plan_request.payout = CTxOut{AmountFromValue(request.params[3]), GetScriptForDestination(payout_dest)};
            if (plan_request.payout.nValue <= 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "amount must be positive");
            }
            plan_request.ids = ParseBridgePlanIdsOrThrow(options);
            plan_request.refund_lock_height = ParseRefundLockHeightOrThrow(options);
            plan_request.genesis_hash = ResolveBridgeGenesisHashOrThrow(pwallet, options);
            plan_request.batch_commitment = ParseBridgeBatchCommitmentOrThrow(options,
                                                                              shielded::BridgeDirection::BRIDGE_OUT,
                                                                              plan_request.ids);

            auto plan = BuildBridgeOutPlan(plan_request);
            if (!plan.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to construct bridge-out plan");
            }

            UniValue out = BridgePlanToUniValue(*plan);
            out.pushKV("payout_address", EncodeDestination(payout_dest));
            if (plan_request.batch_commitment.has_value()) {
                out.pushKV("batch_commitment", BridgeBatchCommitmentToUniValue(*plan_request.batch_commitment));
                out.pushKV("batch_commitment_hex", EncodeBridgeBatchCommitmentHex(*plan_request.batch_commitment));
                out.pushKV("batch_commitment_hash",
                           shielded::ComputeBridgeBatchCommitmentHash(*plan_request.batch_commitment).GetHex());
            }
            return out;
        }};
}

RPCHelpMan bridge_planbatchout()
{
    return RPCHelpMan{
        "bridge_planbatchout",
        "\nBuild a deterministic bridge-out plan for settling one bridge output to many transparent payouts.\n",
        {
            {"operator_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Operator PQ pubkey hex (ML-DSA-44 or SLH-DSA-128s)"},
            {"refund_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Refund PQ pubkey hex (ML-DSA-44 or SLH-DSA-128s)"},
            {"payouts", RPCArg::Type::ARR, RPCArg::Optional::NO, "Transparent payout templates",
                {
                    {"payout", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One payout",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Transparent payout address"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Payout amount"},
                        }},
                }},
            {"options", RPCArg::Type::OBJ, RPCArg::DefaultHint{"{}"}, "Bridge planning options",
                {
                    {"bridge_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge instance id"},
                    {"operation_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge operation id"},
                    {"refund_lock_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Absolute refund lock height"},
                    {"genesis_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Genesis hash override; defaults to the active chain genesis hash"},
                    {"batch_commitment_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Canonical bridge batch commitment bytes; if set, the batch total must equal the sum of payouts"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Bridge plan and canonical attestation",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_planbatchout",
                           "\"<operator_pubkey>\" \"<refund_pubkey>\" "
                           "'[{\"address\":\"btxrt1...\",\"amount\":2},{\"address\":\"btxrt1...\",\"amount\":3}]' "
                           "'{\"bridge_id\":\"03\",\"operation_id\":\"04\",\"refund_lock_height\":250}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForBridge(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const UniValue& options = request.params[3];
            BridgeOutPlanRequest plan_request;
            plan_request.operator_key = ParseBridgeKeySpec(request.params[0], "operator_key");
            plan_request.refund_key = ParseBridgeKeySpec(request.params[1], "refund_key");
            plan_request.payouts = ParseBridgePayoutsOrThrow(request.params[2]);
            plan_request.ids = ParseBridgePlanIdsOrThrow(options);
            plan_request.refund_lock_height = ParseRefundLockHeightOrThrow(options);
            plan_request.genesis_hash = ResolveBridgeGenesisHashOrThrow(pwallet, options);
            plan_request.batch_commitment = ParseBridgeBatchCommitmentOrThrow(options,
                                                                              shielded::BridgeDirection::BRIDGE_OUT,
                                                                              plan_request.ids);

            auto plan = BuildBridgeOutPlan(plan_request);
            if (!plan.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to construct batch bridge-out plan");
            }

            UniValue out = BridgePlanToUniValue(*plan);
            out.pushKV("payout_count", static_cast<int64_t>(plan->transparent_outputs.size()));
            if (plan_request.batch_commitment.has_value()) {
                out.pushKV("batch_commitment", BridgeBatchCommitmentToUniValue(*plan_request.batch_commitment));
                out.pushKV("batch_commitment_hex", EncodeBridgeBatchCommitmentHex(*plan_request.batch_commitment));
                out.pushKV("batch_commitment_hash",
                           shielded::ComputeBridgeBatchCommitmentHash(*plan_request.batch_commitment).GetHex());
            }
            return out;
        }};
}

RPCHelpMan bridge_buildverifierset()
{
    return RPCHelpMan{
        "bridge_buildverifierset",
        "\nBuild a canonical verifier-set commitment for committee-backed bridge batch statements.\n",
        {
            {"attestors", RPCArg::Type::ARR, RPCArg::Optional::NO, "Verifier or committee public keys",
                {
                    {"attestor", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One attestor key",
                        {
                            {"algo", RPCArg::Type::STR, RPCArg::Optional::NO, "ml-dsa-44 or slh-dsa-shake-128s"},
                            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "PQ public key bytes"},
                        }},
                }},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Verifier-set policy",
                {
                    {"required_signers", RPCArg::Type::NUM, RPCArg::Optional::NO, "Minimum distinct attestors required for the batch statement"},
                    {"targets", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Optional subset of attestors for which membership proofs should be built",
                        {
                            {"attestor", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One attestor key",
                                {
                                    {"algo", RPCArg::Type::STR, RPCArg::Optional::NO, "ml-dsa-44 or slh-dsa-shake-128s"},
                                    {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "PQ public key bytes"},
                                }},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical verifier-set commitment",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildverifierset",
                           "'[{\"algo\":\"ml-dsa-44\",\"pubkey\":\"<pubkey>\"}]' "
                           "'{\"required_signers\":1,\"targets\":[{\"algo\":\"ml-dsa-44\",\"pubkey\":\"<pubkey>\"}]}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto attestors = ParseBridgeKeyArrayOrThrow(request.params[0], "attestors");
            const UniValue& options = request.params[1];
            const UniValue& required_signers_value = FindValue(options, "required_signers");
            if (required_signers_value.isNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "options.required_signers is required");
            }
            const int64_t required_signers = required_signers_value.getInt<int64_t>();
            if (required_signers <= 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "options.required_signers must be a positive integer");
            }

            const auto verifier_set = shielded::BuildBridgeVerifierSetCommitment(attestors, static_cast<size_t>(required_signers));
            if (!verifier_set.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "failed to build verifier_set commitment from the supplied attestors and required_signers");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("verifier_set", BridgeVerifierSetCommitmentToUniValue(*verifier_set));
            UniValue attestor_array(UniValue::VARR);
            for (const auto& attestor : attestors) {
                attestor_array.push_back(BridgeKeyToUniValue(attestor));
            }
            out.pushKV("attestors", std::move(attestor_array));

            const UniValue& targets_value = FindValue(options, "targets");
            if (!targets_value.isNull()) {
                const auto targets = ParseBridgeKeyArrayOrThrow(targets_value, "options.targets");
                UniValue proof_array(UniValue::VARR);
                for (size_t i = 0; i < targets.size(); ++i) {
                    const auto proof = shielded::BuildBridgeVerifierSetProof(attestors, targets[i]);
                    if (!proof.has_value() || !shielded::VerifyBridgeVerifierSetProof(*verifier_set, targets[i], *proof)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                                           strprintf("failed to build verifier-set proof for options.targets[%u]", i));
                    }
                    UniValue entry(UniValue::VOBJ);
                    entry.pushKV("attestor", BridgeKeyToUniValue(targets[i]));
                    entry.pushKV("proof", BridgeVerifierSetProofToUniValue(*proof));
                    entry.pushKV("proof_hex", EncodeBridgeVerifierSetProofHex(*proof));
                    proof_array.push_back(std::move(entry));
                }
                out.pushKV("proofs", std::move(proof_array));
            }
            return out;
        }};
}

RPCHelpMan bridge_buildproofprofile()
{
    return RPCHelpMan{
        "bridge_buildproofprofile",
        "\nBuild a canonical imported-proof profile whose hash becomes the proof_system_id used by bridge proof descriptors and proof receipts.\n",
        {
            {"profile", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Proof-profile labels",
                {
                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Profile version"},
                    {"family", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof family label such as sp1, risc0-zkvm, or blobstream"},
                    {"proof_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof or receipt type such as groth16, succinct, composite, or sp1"},
                    {"claim_system", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII public-output or claim-schema label such as public-values-v1, journal-digest-v1, or data-root-tuple-v1"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical bridge proof profile",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildproofprofile",
                           "'{\"family\":\"sp1\",\"proof_type\":\"groth16\",\"claim_system\":\"public-values-v1\"}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto profile = BuildBridgeProofSystemProfileOrThrow(request.params[0], "profile");
            UniValue labels(UniValue::VOBJ);
            labels.pushKV("family", ToLower(FindValue(request.params[0], "family").get_str()));
            labels.pushKV("proof_type", ToLower(FindValue(request.params[0], "proof_type").get_str()));
            labels.pushKV("claim_system", ToLower(FindValue(request.params[0], "claim_system").get_str()));

            UniValue out(UniValue::VOBJ);
            out.pushKV("profile", BridgeProofSystemProfileToUniValue(profile));
            out.pushKV("profile_hex", EncodeBridgeProofSystemProfileHex(profile));
            out.pushKV("proof_system_id", shielded::ComputeBridgeProofSystemId(profile).GetHex());
            out.pushKV("labels", std::move(labels));
            return out;
        }};
}

RPCHelpMan bridge_decodeproofprofile()
{
    return RPCHelpMan{
        "bridge_decodeproofprofile",
        "\nDecode a canonical bridge proof profile and return the derived proof_system_id.\n",
        {
            {"proof_profile_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge proof profile"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Decoded bridge proof profile",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_decodeproofprofile", "\"<proof_profile_hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto profile = DecodeBridgeProofSystemProfileOrThrow(request.params[0]);
            UniValue out(UniValue::VOBJ);
            out.pushKV("profile", BridgeProofSystemProfileToUniValue(profile));
            out.pushKV("profile_hex", EncodeBridgeProofSystemProfileHex(profile));
            out.pushKV("proof_system_id", shielded::ComputeBridgeProofSystemId(profile).GetHex());
            return out;
        }};
}

RPCHelpMan bridge_buildproofclaim()
{
    return RPCHelpMan{
        "bridge_buildproofclaim",
        "\nBuild a canonical BTX proof claim from a batch statement so imported receipts can commit to explicit settlement metadata instead of an opaque public_values_hash.\n",
        {
            {"statement_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded canonical bridge batch statement"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Proof-claim options",
                {
                    {"kind", RPCArg::Type::STR, RPCArg::Optional::NO, "batch_tuple_v1, settlement_metadata_v1, or data_root_tuple_v1"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical bridge proof claim",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildproofclaim",
                           "\"<statement_hex>\" '{\"kind\":\"settlement_metadata_v1\"}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto statement = DecodeBridgeBatchStatementOrThrow(request.params[0]);
            if (!request.params[1].isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
            }
            const auto kind = ParseBridgeProofClaimKindOrThrow(FindValue(request.params[1], "kind"), "options.kind");
            const auto claim = shielded::BuildBridgeProofClaimFromStatement(statement, kind);
            if (!claim.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to build a valid bridge proof claim from statement_hex");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("statement", BridgeBatchStatementToUniValue(statement));
            out.pushKV("statement_hex", EncodeBridgeBatchStatementHex(statement));
            out.pushKV("statement_hash", shielded::ComputeBridgeBatchStatementHash(statement).GetHex());
            out.pushKV("claim", BridgeProofClaimToUniValue(*claim));
            out.pushKV("claim_hex", EncodeBridgeProofClaimHex(*claim));
            out.pushKV("public_values_hash", shielded::ComputeBridgeProofClaimHash(*claim).GetHex());
            return out;
        }};
}

RPCHelpMan bridge_decodeproofclaim()
{
    return RPCHelpMan{
        "bridge_decodeproofclaim",
        "\nDecode a canonical bridge proof claim and return the derived public_values_hash.\n",
        {
            {"claim_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge proof claim"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Decoded bridge proof claim",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_decodeproofclaim", "\"<claim_hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto claim = DecodeBridgeProofClaimOrThrow(request.params[0]);
            UniValue out(UniValue::VOBJ);
            out.pushKV("claim", BridgeProofClaimToUniValue(claim));
            out.pushKV("claim_hex", EncodeBridgeProofClaimHex(claim));
            out.pushKV("public_values_hash", shielded::ComputeBridgeProofClaimHash(claim).GetHex());
            return out;
        }};
}

RPCHelpMan bridge_listproofadapters()
{
    return RPCHelpMan{
        "bridge_listproofadapters",
        "\nList the built-in proof adapters that bind proof-family profiles to canonical BTX proof-claim kinds.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "Built-in bridge proof adapters",
            {
                {RPCResult::Type::ARR, "adapters", "", {{RPCResult::Type::ELISION, "", ""}}},
            }},
        RPCExamples{HelpExampleCli("bridge_listproofadapters", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            UniValue adapters(UniValue::VARR);
            for (const auto& adapter_template : BRIDGE_PROOF_ADAPTER_TEMPLATES) {
                const auto adapter = BuildBridgeProofAdapterFromTemplateOrThrow(adapter_template);
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("adapter_name", std::string{adapter_template.name});
                entry.pushKV("labels", BridgeProofAdapterLabelsToUniValue(adapter_template));
                entry.pushKV("claim_kind", BridgeProofClaimKindToString(adapter_template.claim_kind));
                entry.pushKV("proof_adapter", BridgeProofAdapterToUniValue(adapter));
                entry.pushKV("proof_adapter_hex", EncodeBridgeProofAdapterHex(adapter));
                entry.pushKV("proof_adapter_id", shielded::ComputeBridgeProofAdapterId(adapter).GetHex());
                entry.pushKV("proof_system_id", shielded::ComputeBridgeProofSystemId(adapter.profile).GetHex());
                adapters.push_back(std::move(entry));
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("adapters", std::move(adapters));
            return out;
        }};
}

RPCHelpMan bridge_listprovertemplates()
{
    return RPCHelpMan{
        "bridge_listprovertemplates",
        "\nList the built-in modeled prover templates that attach reference native / CPU / GPU / network timings to named bridge proof adapters.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "Built-in bridge prover templates",
            {
                {RPCResult::Type::ARR, "templates", "", {{RPCResult::Type::ELISION, "", ""}}},
            }},
        RPCExamples{HelpExampleCli("bridge_listprovertemplates", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            UniValue templates(UniValue::VARR);
            for (const auto& prover_template : BRIDGE_PROVER_TEMPLATES) {
                templates.push_back(BridgeProverTemplateToUniValue(prover_template));
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("templates", std::move(templates));
            return out;
        }};
}

RPCHelpMan bridge_buildproofadapter()
{
    return RPCHelpMan{
        "bridge_buildproofadapter",
        "\nBuild a canonical proof adapter that binds a proof-family profile to one BTX proof-claim kind.\n",
        {
            {"adapter", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Proof adapter selector",
                {
                    {"adapter_name", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Built-in adapter name such as sp1-groth16-settlement-metadata-v1"},
                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Adapter version used for explicit adapters"},
                    {"proof_profile_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof profile used for explicit adapters"},
                    {"proof_profile", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline bridge proof profile used for explicit adapters",
                        {
                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Profile version"},
                            {"family", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof family label"},
                            {"proof_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof or receipt type label"},
                            {"claim_system", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII public-output or claim-schema label"},
                        }},
                    {"claim_kind", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "batch_tuple_v1, settlement_metadata_v1, or data_root_tuple_v1; required for explicit adapters"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical bridge proof adapter",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildproofadapter",
                           "'{\"adapter_name\":\"sp1-groth16-settlement-metadata-v1\"}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto adapter = BuildBridgeProofAdapterOrThrow(request.params[0], "adapter");
            const auto* adapter_template = FindBridgeProofAdapterTemplate(adapter);

            UniValue out(UniValue::VOBJ);
            out.pushKV("proof_adapter", BridgeProofAdapterToUniValue(adapter));
            out.pushKV("proof_adapter_hex", EncodeBridgeProofAdapterHex(adapter));
            out.pushKV("proof_adapter_id", shielded::ComputeBridgeProofAdapterId(adapter).GetHex());
            out.pushKV("proof_system_id", shielded::ComputeBridgeProofSystemId(adapter.profile).GetHex());
            if (adapter_template != nullptr) {
                out.pushKV("adapter_name", std::string{adapter_template->name});
                out.pushKV("labels", BridgeProofAdapterLabelsToUniValue(*adapter_template));
            }
            return out;
        }};
}

RPCHelpMan bridge_decodeproofadapter()
{
    return RPCHelpMan{
        "bridge_decodeproofadapter",
        "\nDecode a canonical bridge proof adapter and return the derived proof_system_id plus claim binding.\n",
        {
            {"proof_adapter_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge proof adapter"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Decoded bridge proof adapter",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_decodeproofadapter", "\"<proof_adapter_hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto adapter = DecodeBridgeProofAdapterOrThrow(request.params[0]);
            const auto* adapter_template = FindBridgeProofAdapterTemplate(adapter);

            UniValue out(UniValue::VOBJ);
            out.pushKV("proof_adapter", BridgeProofAdapterToUniValue(adapter));
            out.pushKV("proof_adapter_hex", EncodeBridgeProofAdapterHex(adapter));
            out.pushKV("proof_adapter_id", shielded::ComputeBridgeProofAdapterId(adapter).GetHex());
            out.pushKV("proof_system_id", shielded::ComputeBridgeProofSystemId(adapter.profile).GetHex());
            if (adapter_template != nullptr) {
                out.pushKV("adapter_name", std::string{adapter_template->name});
                out.pushKV("labels", BridgeProofAdapterLabelsToUniValue(*adapter_template));
            }
            return out;
        }};
}

RPCHelpMan bridge_buildproofartifact()
{
    return RPCHelpMan{
        "bridge_buildproofartifact",
        "\nBuild a self-contained imported-proof artifact summary that can regenerate the canonical proof descriptor and proof receipt while tracking off-chain byte counts.\n",
        {
            {"statement_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded canonical bridge batch statement"},
            {"artifact", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Imported proof artifact summary",
                {
                    {"proof_adapter_name", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Built-in proof adapter name"},
                    {"proof_adapter_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof adapter"},
                    {"proof_adapter", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline bridge proof adapter",
                        {
                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Adapter version"},
                            {"proof_profile_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof profile for the adapter"},
                            {"proof_profile", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline bridge proof profile for the adapter",
                                {
                                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Profile version"},
                                    {"family", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof family label"},
                                    {"proof_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof or receipt type label"},
                                    {"claim_system", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII public-output or claim-schema label"},
                                }},
                            {"claim_kind", RPCArg::Type::STR, RPCArg::Optional::NO, "batch_tuple_v1, settlement_metadata_v1, or data_root_tuple_v1"},
                        }},
                    {"verifier_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the verifier key, image ID, or program identifier"},
                    {"proof_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Commitment to the proof/seal/receipt payload"},
                    {"artifact_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Commitment to the full imported artifact bundle"},
                    {"artifact_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Raw imported artifact bytes used to derive artifact_commitment"},
                    {"proof_size_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Proof or seal payload size in bytes"},
                    {"public_values_size_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Public-values, journal, or tuple payload size in bytes"},
                    {"auxiliary_data_size_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Additional sidecar or proof-query metadata bytes kept off-chain"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical bridge proof artifact",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildproofartifact",
                           "\"<statement_hex>\" "
                           "'{\"proof_adapter_name\":\"sp1-groth16-settlement-metadata-v1\",\"verifier_key_hash\":\"0b\",\"proof_commitment\":\"0d\",\"artifact_hex\":\"0011\",\"proof_size_bytes\":4096,\"public_values_size_bytes\":96,\"auxiliary_data_size_bytes\":512}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto statement = DecodeBridgeBatchStatementOrThrow(request.params[0]);
            const auto artifact = BuildBridgeProofArtifactOrThrow(statement, request.params[1], "artifact");
            const auto descriptor = shielded::BuildBridgeProofDescriptorFromArtifact(artifact);
            const auto receipt = shielded::BuildBridgeProofReceiptFromArtifact(artifact);
            if (!descriptor.has_value() || !receipt.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to derive proof descriptor or proof receipt from artifact");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("statement", BridgeBatchStatementToUniValue(statement));
            out.pushKV("statement_hex", EncodeBridgeBatchStatementHex(statement));
            out.pushKV("statement_hash", shielded::ComputeBridgeBatchStatementHash(statement).GetHex());
            out.pushKV("proof_artifact", BridgeProofArtifactToUniValue(artifact));
            out.pushKV("proof_artifact_hex", EncodeBridgeProofArtifactHex(artifact));
            out.pushKV("proof_artifact_id", shielded::ComputeBridgeProofArtifactId(artifact).GetHex());
            out.pushKV("proof_descriptor", BridgeProofDescriptorToUniValue(*descriptor));
            out.pushKV("proof_receipt", BridgeProofReceiptToUniValue(*receipt));
            out.pushKV("proof_receipt_hex", EncodeBridgeProofReceiptHex(*receipt));
            return out;
        }};
}

RPCHelpMan bridge_decodeproofartifact()
{
    return RPCHelpMan{
        "bridge_decodeproofartifact",
        "\nDecode a canonical bridge proof artifact and return the derived descriptor, receipt, and storage summary.\n",
        {
            {"proof_artifact_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge proof artifact"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Decoded bridge proof artifact",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_decodeproofartifact", "\"<proof_artifact_hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto artifact = DecodeBridgeProofArtifactOrThrow(request.params[0]);
            const auto descriptor = shielded::BuildBridgeProofDescriptorFromArtifact(artifact);
            const auto receipt = shielded::BuildBridgeProofReceiptFromArtifact(artifact);
            if (!descriptor.has_value() || !receipt.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to derive proof descriptor or proof receipt from proof_artifact_hex");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("proof_artifact", BridgeProofArtifactToUniValue(artifact));
            out.pushKV("proof_artifact_hex", EncodeBridgeProofArtifactHex(artifact));
            out.pushKV("proof_artifact_id", shielded::ComputeBridgeProofArtifactId(artifact).GetHex());
            out.pushKV("proof_descriptor", BridgeProofDescriptorToUniValue(*descriptor));
            out.pushKV("proof_receipt", BridgeProofReceiptToUniValue(*receipt));
            out.pushKV("proof_receipt_hex", EncodeBridgeProofReceiptHex(*receipt));
            return out;
        }};
}

RPCHelpMan bridge_builddataartifact()
{
    return RPCHelpMan{
        "bridge_builddataartifact",
        "\nBuild a canonical data-availability or replay artifact summary tied to one bridge batch statement.\n",
        {
            {"statement_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded canonical bridge batch statement"},
            {"artifact", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Imported DA/state artifact summary",
                {
                    {"kind", RPCArg::Type::STR, RPCArg::Optional::NO, "state_diff_v1, snapshot_appendix_v1, or data_root_query_v1"},
                    {"payload_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Commitment to the published payload"},
                    {"payload_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Payload bytes used to derive payload_commitment"},
                    {"artifact_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Commitment to the full imported artifact bundle"},
                    {"artifact_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Raw imported artifact bytes used to derive artifact_commitment"},
                    {"payload_size_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Published payload size in bytes"},
                    {"auxiliary_data_size_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Additional replay, audit, or proof-query bytes kept off-chain"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical bridge data artifact",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_builddataartifact",
                           "\"<statement_hex>\" "
                           "'{\"kind\":\"state_diff_v1\",\"payload_hex\":\"0011\",\"artifact_hex\":\"2233\",\"payload_size_bytes\":2048,\"auxiliary_data_size_bytes\":256}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto statement = DecodeBridgeBatchStatementOrThrow(request.params[0]);
            const auto artifact = BuildBridgeDataArtifactOrThrow(statement, request.params[1], "artifact");

            UniValue out(UniValue::VOBJ);
            out.pushKV("statement", BridgeBatchStatementToUniValue(statement));
            out.pushKV("statement_hex", EncodeBridgeBatchStatementHex(statement));
            out.pushKV("statement_hash", shielded::ComputeBridgeBatchStatementHash(statement).GetHex());
            out.pushKV("data_artifact", BridgeDataArtifactToUniValue(artifact));
            out.pushKV("data_artifact_hex", EncodeBridgeDataArtifactHex(artifact));
            out.pushKV("data_artifact_id", shielded::ComputeBridgeDataArtifactId(artifact).GetHex());
            return out;
        }};
}

RPCHelpMan bridge_decodedataartifact()
{
    return RPCHelpMan{
        "bridge_decodedataartifact",
        "\nDecode a canonical bridge data artifact and return its storage summary.\n",
        {
            {"data_artifact_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge data artifact"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Decoded bridge data artifact",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_decodedataartifact", "\"<data_artifact_hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto artifact = DecodeBridgeDataArtifactOrThrow(request.params[0]);

            UniValue out(UniValue::VOBJ);
            out.pushKV("data_artifact", BridgeDataArtifactToUniValue(artifact));
            out.pushKV("data_artifact_hex", EncodeBridgeDataArtifactHex(artifact));
            out.pushKV("data_artifact_id", shielded::ComputeBridgeDataArtifactId(artifact).GetHex());
            return out;
        }};
}

RPCHelpMan bridge_buildaggregateartifactbundle()
{
    return RPCHelpMan{
        "bridge_buildaggregateartifactbundle",
        "\nBuild a canonical aggregate artifact bundle from proof artifacts and DA/state artifacts so a hard-fork settlement can reuse measured artifact bytes instead of manual payload estimates.\n",
        {
            {"statement_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded canonical bridge batch statement"},
            {"bundle", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Aggregate artifact bundle builder",
                {
                    {"proof_artifacts", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Proof artifacts contributing aggregate proof payload bytes",
                        {
                            {"artifact", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Proof artifact selector",
                                {
                                    {"proof_artifact_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof artifact"},
                                }},
                        }},
                    {"data_artifacts", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "DA or replay artifacts contributing published payload bytes",
                        {
                            {"artifact", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Data artifact selector",
                                {
                                    {"data_artifact_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge data artifact"},
                                }},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical aggregate artifact bundle",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildaggregateartifactbundle",
                           "\"<statement_hex>\" "
                           "'{\"proof_artifacts\":[{\"proof_artifact_hex\":\"<proof_hex>\"}],\"data_artifacts\":[{\"data_artifact_hex\":\"<data_hex>\"}]}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto statement = DecodeBridgeBatchStatementOrThrow(request.params[0]);
            const auto bundle = BuildBridgeAggregateArtifactBundleOrThrow(statement, request.params[1], "bundle");

            UniValue out(UniValue::VOBJ);
            out.pushKV("statement", BridgeBatchStatementToUniValue(statement));
            out.pushKV("statement_hex", EncodeBridgeBatchStatementHex(statement));
            out.pushKV("statement_hash", shielded::ComputeBridgeBatchStatementHash(statement).GetHex());
            out.pushKV("artifact_bundle", BridgeAggregateArtifactBundleToUniValue(bundle));
            out.pushKV("artifact_bundle_hex", EncodeBridgeAggregateArtifactBundleHex(bundle));
            out.pushKV("artifact_bundle_id", shielded::ComputeBridgeAggregateArtifactBundleId(bundle).GetHex());
            return out;
        }};
}

RPCHelpMan bridge_decodeaggregateartifactbundle()
{
    return RPCHelpMan{
        "bridge_decodeaggregateartifactbundle",
        "\nDecode a canonical aggregate artifact bundle and return its derived proof/data byte summary.\n",
        {
            {"artifact_bundle_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge aggregate artifact bundle"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Decoded aggregate artifact bundle",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_decodeaggregateartifactbundle", "\"<artifact_bundle_hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto bundle = DecodeBridgeAggregateArtifactBundleOrThrow(request.params[0]);

            UniValue out(UniValue::VOBJ);
            out.pushKV("artifact_bundle", BridgeAggregateArtifactBundleToUniValue(bundle));
            out.pushKV("artifact_bundle_hex", EncodeBridgeAggregateArtifactBundleHex(bundle));
            out.pushKV("artifact_bundle_id", shielded::ComputeBridgeAggregateArtifactBundleId(bundle).GetHex());
            return out;
        }};
}

RPCHelpMan bridge_buildaggregatesettlement()
{
    return RPCHelpMan{
        "bridge_buildaggregatesettlement",
        "\nBuild a canonical hard-fork aggregate-settlement prototype from one bridge batch statement, explicitly placing proof and data payloads in non-witness bytes, witness bytes, a separate L1 data-availability lane, or off-chain storage.\n",
        {
            {"statement_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded canonical bridge batch statement"},
            {"aggregate", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Aggregate settlement prototype",
                {
                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Aggregate settlement version"},
                    {"batched_user_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "How many user actions this one consensus settlement represents"},
                    {"new_wallet_count", RPCArg::Type::NUM, RPCArg::Default{0}, "How many represented users or wallets are first-touch accounts not previously materialized on L1"},
                    {"input_count", RPCArg::Type::NUM, RPCArg::Default{0}, "Number of shielded or aggregate inputs consumed by the settlement"},
                    {"output_count", RPCArg::Type::NUM, RPCArg::Default{0}, "Number of settlement outputs or note commitments created"},
                    {"base_non_witness_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Transaction-shell bytes that remain in non-witness serialization under the hard fork"},
                    {"base_witness_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Witness bytes outside the aggregate proof or DA payload"},
                    {"state_commitment_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Consensus roots / commitments / policy ids that must remain on-chain non-witness bytes"},
                    {"artifact_bundle_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded aggregate artifact bundle used to derive proof_payload_bytes, data_availability_payload_bytes, and auxiliary_offchain_bytes"},
                    {"artifact_bundle", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline aggregate artifact bundle",
                        {
                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Bundle version"},
                            {"statement_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the committed bridge batch statement"},
                            {"proof_artifact_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Merkle root over included proof artifacts"},
                            {"data_artifact_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Merkle root over included data artifacts"},
                            {"proof_artifact_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "Number of proof artifacts included in the bundle"},
                            {"data_artifact_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "Number of data artifacts included in the bundle"},
                            {"proof_payload_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Aggregate proof plus public-values payload bytes"},
                            {"proof_auxiliary_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Auxiliary off-chain proof bytes"},
                            {"data_availability_payload_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Aggregate DA or replay payload bytes"},
                            {"data_auxiliary_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Auxiliary off-chain DA or replay bytes"},
                        }},
                    {"proof_payload_bytes", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Manual proof plus public-values payload bytes; omit when proof_artifact_* is supplied"},
                    {"proof_artifact_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded proof artifact used to derive proof_payload_bytes from proof_size_bytes + public_values_size_bytes"},
                    {"proof_artifact", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline proof artifact used to derive proof_payload_bytes",
                        {
                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Artifact version"},
                            {"proof_adapter_name", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Built-in proof adapter name"},
                            {"proof_adapter_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof adapter"},
                            {"proof_adapter", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline bridge proof adapter",
                                {
                                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Adapter version"},
                                    {"proof_profile_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof profile"},
                                    {"proof_profile", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline bridge proof profile",
                                        {
                                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Profile version"},
                                            {"family", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof family label"},
                                            {"proof_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof or receipt type label"},
                                            {"claim_system", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII public-output or claim-schema label"},
                                        }},
                                    {"claim_kind", RPCArg::Type::STR, RPCArg::Optional::NO, "batch_tuple_v1, settlement_metadata_v1, or data_root_tuple_v1"},
                                }},
                            {"statement_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the committed bridge batch statement"},
                            {"verifier_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the verifier key, image ID, or program identifier"},
                            {"public_values_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the canonical public values or claim digest"},
                            {"proof_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Commitment to the proof/seal/receipt payload"},
                            {"artifact_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Commitment to the imported artifact bundle"},
                            {"proof_size_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Proof or seal payload size in bytes"},
                            {"public_values_size_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Public-values, journal, or tuple payload size in bytes"},
                            {"auxiliary_data_size_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Additional sidecar or proof-query metadata bytes kept off-chain"},
                        }},
                    {"proof_payload_location", RPCArg::Type::STR, RPCArg::Default{"witness"}, "Where the aggregate proof payload lives: non_witness, witness, data_availability, or offchain"},
                    {"data_availability_payload_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "DA payload bytes such as note diffs, nullifier sets, or public batch data"},
                    {"data_availability_location", RPCArg::Type::STR, RPCArg::Default{"offchain"}, "Where the DA payload lives: non_witness, witness, data_availability, or offchain"},
                    {"control_plane_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Additional per-settlement coordination bytes kept outside the transaction footprint"},
                    {"auxiliary_offchain_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Off-chain bytes retained alongside the settlement even after proof/data placement is chosen"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical aggregate settlement prototype plus derived capacity footprint",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildaggregatesettlement",
                           "\"<statement_hex>\" "
                           "'{\"batched_user_count\":64,\"new_wallet_count\":24,\"input_count\":64,\"output_count\":64,"
                           "\"base_non_witness_bytes\":900,\"base_witness_bytes\":2600,\"state_commitment_bytes\":192,"
                           "\"proof_payload_bytes\":16384,\"proof_payload_location\":\"witness\","
                           "\"data_availability_payload_bytes\":4096,\"data_availability_location\":\"data_availability\"}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto statement = DecodeBridgeBatchStatementOrThrow(request.params[0]);
            const auto artifact_bundle = ParseBridgeAggregateArtifactBundleSelectorOrThrow(request.params[1], "aggregate");
            const auto settlement = ParseBridgeAggregateSettlementOrThrow(statement, request.params[1], "aggregate");
            const auto footprint = shielded::BuildBridgeAggregateSettlementFootprint(settlement);
            if (!footprint.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to derive a valid bridge capacity footprint from aggregate");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("statement", BridgeBatchStatementToUniValue(statement));
            out.pushKV("statement_hex", EncodeBridgeBatchStatementHex(statement));
            out.pushKV("statement_hash", shielded::ComputeBridgeBatchStatementHash(statement).GetHex());
            if (artifact_bundle.has_value()) {
                out.pushKV("artifact_bundle", BridgeAggregateArtifactBundleToUniValue(*artifact_bundle));
                out.pushKV("artifact_bundle_hex", EncodeBridgeAggregateArtifactBundleHex(*artifact_bundle));
                out.pushKV("artifact_bundle_id", shielded::ComputeBridgeAggregateArtifactBundleId(*artifact_bundle).GetHex());
            }
            out.pushKV("aggregate_settlement", BridgeAggregateSettlementToUniValue(settlement));
            out.pushKV("aggregate_settlement_hex", EncodeBridgeAggregateSettlementHex(settlement));
            out.pushKV("aggregate_settlement_id", shielded::ComputeBridgeAggregateSettlementId(settlement).GetHex());
            out.pushKV("footprint", BridgeCapacityFootprintToUniValue(*footprint));
            return out;
        }};
}

RPCHelpMan bridge_decodeaggregatesettlement()
{
    return RPCHelpMan{
        "bridge_decodeaggregatesettlement",
        "\nDecode a canonical hard-fork aggregate-settlement prototype and return its derived capacity footprint.\n",
        {
            {"aggregate_settlement_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge aggregate settlement"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Decoded aggregate settlement prototype",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_decodeaggregatesettlement", "\"<aggregate_settlement_hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto settlement = DecodeBridgeAggregateSettlementOrThrow(request.params[0]);
            const auto footprint = shielded::BuildBridgeAggregateSettlementFootprint(settlement);
            if (!footprint.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to derive a valid bridge capacity footprint from aggregate_settlement_hex");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("aggregate_settlement", BridgeAggregateSettlementToUniValue(settlement));
            out.pushKV("aggregate_settlement_hex", EncodeBridgeAggregateSettlementHex(settlement));
            out.pushKV("aggregate_settlement_id", shielded::ComputeBridgeAggregateSettlementId(settlement).GetHex());
            out.pushKV("footprint", BridgeCapacityFootprintToUniValue(*footprint));
            return out;
        }};
}

RPCHelpMan bridge_buildproofcompressiontarget()
{
    return RPCHelpMan{
        "bridge_buildproofcompressiontarget",
        "\nBuild a canonical proof-compression target from one aggregate settlement so BTX can quantify the final proof envelope required to hit a chosen throughput, or prove that fixed DA or shell bytes make the target impossible even with a zero-byte proof.\n",
        {
            {"aggregate_settlement_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge aggregate settlement"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Target throughput and optional artifact context",
                {
                    {"target_users_per_block", RPCArg::Type::NUM, RPCArg::Optional::NO, "Minimum represented users per block the compressed proof path should sustain"},
                    {"block_serialized_limit", RPCArg::Type::NUM, RPCArg::Default{MAX_BLOCK_SERIALIZED_SIZE}, "Serialized block-size limit used for the target"},
                    {"block_weight_limit", RPCArg::Type::NUM, RPCArg::Default{MAX_BLOCK_WEIGHT}, "Block-weight limit used for the target"},
                    {"block_data_availability_limit", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Separate L1 data-availability cap; required when the settlement or its fixed payloads consume that lane"},
                    {"artifact_bundle_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional artifact-backed bundle used to bind current proof auxiliary bytes and artifact counts"},
                    {"artifact_bundle", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline aggregate artifact bundle",
                        {
                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Bundle version"},
                            {"statement_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the committed bridge batch statement"},
                            {"proof_artifact_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Merkle root over included proof artifacts"},
                            {"data_artifact_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Merkle root over included data artifacts"},
                            {"proof_artifact_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "Number of proof artifacts included in the bundle"},
                            {"data_artifact_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "Number of data artifacts included in the bundle"},
                            {"proof_payload_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Aggregate proof plus public-values payload bytes"},
                            {"proof_auxiliary_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Auxiliary off-chain proof bytes"},
                            {"data_availability_payload_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Aggregate DA or replay payload bytes"},
                            {"data_auxiliary_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Auxiliary off-chain DA or replay bytes"},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical proof-compression target plus derived estimate",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildproofcompressiontarget",
                           "\"<aggregate_settlement_hex>\" "
                           "'{\"target_users_per_block\":12288,\"artifact_bundle_hex\":\"<artifact_bundle_hex>\"}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto settlement = DecodeBridgeAggregateSettlementOrThrow(request.params[0]);
            if (!request.params[1].isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
            }

            const UniValue& options = request.params[1];
            uint64_t block_serialized_limit = MAX_BLOCK_SERIALIZED_SIZE;
            uint64_t block_weight_limit = MAX_BLOCK_WEIGHT;
            std::optional<uint64_t> block_data_availability_limit;

            const UniValue& target_users_value = FindValue(options, "target_users_per_block");
            const uint64_t target_users_per_block = ParsePositiveUint64OrThrow(target_users_value,
                                                                               "options.target_users_per_block");
            const UniValue& block_serialized_limit_value = FindValue(options, "block_serialized_limit");
            const UniValue& block_weight_limit_value = FindValue(options, "block_weight_limit");
            const UniValue& block_data_availability_limit_value = FindValue(options, "block_data_availability_limit");
            if (!block_serialized_limit_value.isNull()) {
                block_serialized_limit = ParsePositiveUint64OrThrow(block_serialized_limit_value,
                                                                    "options.block_serialized_limit");
            }
            if (!block_weight_limit_value.isNull()) {
                block_weight_limit = ParsePositiveUint64OrThrow(block_weight_limit_value,
                                                                "options.block_weight_limit");
            }
            if (!block_data_availability_limit_value.isNull()) {
                block_data_availability_limit = ParsePositiveUint64OrThrow(block_data_availability_limit_value,
                                                                          "options.block_data_availability_limit");
            }

            const auto artifact_bundle = ParseBridgeAggregateArtifactBundleSelectorOrThrow(options, "options");
            const auto target = shielded::BuildBridgeProofCompressionTarget(settlement,
                                                                            artifact_bundle,
                                                                            block_serialized_limit,
                                                                            block_weight_limit,
                                                                            block_data_availability_limit,
                                                                            target_users_per_block);
            if (!target.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "failed to build a valid proof compression target from aggregate_settlement_hex");
            }
            const auto estimate = shielded::EstimateBridgeProofCompression(*target);
            if (!estimate.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "failed to estimate proof compression requirements from aggregate_settlement_hex");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("aggregate_settlement", BridgeAggregateSettlementToUniValue(settlement));
            out.pushKV("aggregate_settlement_hex", EncodeBridgeAggregateSettlementHex(settlement));
            out.pushKV("aggregate_settlement_id", shielded::ComputeBridgeAggregateSettlementId(settlement).GetHex());
            if (artifact_bundle.has_value()) {
                out.pushKV("artifact_bundle", BridgeAggregateArtifactBundleToUniValue(*artifact_bundle));
                out.pushKV("artifact_bundle_hex", EncodeBridgeAggregateArtifactBundleHex(*artifact_bundle));
                out.pushKV("artifact_bundle_id", shielded::ComputeBridgeAggregateArtifactBundleId(*artifact_bundle).GetHex());
            }
            out.pushKV("proof_compression_target", BridgeProofCompressionTargetToUniValue(*target));
            out.pushKV("proof_compression_target_hex", EncodeBridgeProofCompressionTargetHex(*target));
            out.pushKV("proof_compression_target_id", shielded::ComputeBridgeProofCompressionTargetId(*target).GetHex());
            out.pushKV("proof_compression_estimate", BridgeProofCompressionEstimateToUniValue(*estimate));
            return out;
        }};
}

RPCHelpMan bridge_decodeproofcompressiontarget()
{
    return RPCHelpMan{
        "bridge_decodeproofcompressiontarget",
        "\nDecode a canonical proof-compression target and re-run the derived compression estimate.\n",
        {
            {"proof_compression_target_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge proof compression target"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Decoded proof-compression target plus derived estimate",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_decodeproofcompressiontarget", "\"<proof_compression_target_hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto target = DecodeBridgeProofCompressionTargetOrThrow(request.params[0]);
            const auto estimate = shielded::EstimateBridgeProofCompression(target);
            if (!estimate.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "failed to estimate proof compression requirements from proof_compression_target_hex");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("proof_compression_target", BridgeProofCompressionTargetToUniValue(target));
            out.pushKV("proof_compression_target_hex", EncodeBridgeProofCompressionTargetHex(target));
            out.pushKV("proof_compression_target_id", shielded::ComputeBridgeProofCompressionTargetId(target).GetHex());
            out.pushKV("proof_compression_estimate", BridgeProofCompressionEstimateToUniValue(*estimate));
            return out;
        }};
}

RPCHelpMan bridge_buildshieldedstateprofile()
{
    return RPCHelpMan{
        "bridge_buildshieldedstateprofile",
        "\nBuild a canonical shielded-state profile so BTX can model the long-lived nullifier, commitment, snapshot, and first-touch wallet growth caused by one aggregate settlement.\n",
        {
            {"state_profile", RPCArg::Type::OBJ, RPCArg::DefaultHint{"{}"}, "Shielded-state byte model; omitted fields use BTX's current code-derived defaults",
                {
                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Shielded-state profile version"},
                    {"commitment_index_key_bytes", RPCArg::Type::NUM, RPCArg::Default{9}, "Persistent bytes for one commitment-index key"},
                    {"commitment_index_value_bytes", RPCArg::Type::NUM, RPCArg::Default{32}, "Persistent bytes for one commitment-index value"},
                    {"snapshot_commitment_bytes", RPCArg::Type::NUM, RPCArg::Default{32}, "Snapshot appendix bytes retained per new commitment"},
                    {"nullifier_index_key_bytes", RPCArg::Type::NUM, RPCArg::Default{33}, "Persistent bytes for one nullifier-index key"},
                    {"nullifier_index_value_bytes", RPCArg::Type::NUM, RPCArg::Default{1}, "Persistent bytes for one nullifier-index value"},
                    {"snapshot_nullifier_bytes", RPCArg::Type::NUM, RPCArg::Default{32}, "Snapshot appendix bytes retained per nullifier"},
                    {"nullifier_cache_bytes", RPCArg::Type::NUM, RPCArg::Default{96}, "Hot-cache bytes retained per nullifier entry"},
                    {"wallet_materialization_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Additional persistent bytes charged per first-touch wallet or account materialization"},
                    {"bounded_anchor_history_bytes", RPCArg::Type::NUM, RPCArg::Default{800}, "Bounded bytes retained for recent anchor/output-count history"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical bridge shielded-state profile",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildshieldedstateprofile",
                           "'{\"wallet_materialization_bytes\":96}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const shielded::BridgeShieldedStateProfile profile = request.params[0].isNull()
                ? shielded::BridgeShieldedStateProfile{}
                : ParseBridgeShieldedStateProfileOrThrow(request.params[0], "state_profile");

            UniValue out(UniValue::VOBJ);
            out.pushKV("state_profile", BridgeShieldedStateProfileToUniValue(profile));
            out.pushKV("state_profile_hex", EncodeBridgeShieldedStateProfileHex(profile));
            out.pushKV("state_profile_id", shielded::ComputeBridgeShieldedStateProfileId(profile).GetHex());
            return out;
        }};
}

RPCHelpMan bridge_decodeshieldedstateprofile()
{
    return RPCHelpMan{
        "bridge_decodeshieldedstateprofile",
        "\nDecode a canonical shielded-state profile.\n",
        {
            {"state_profile_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge shielded-state profile"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Decoded bridge shielded-state profile",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_decodeshieldedstateprofile", "\"<state_profile_hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto profile = DecodeBridgeShieldedStateProfileOrThrow(request.params[0]);
            UniValue out(UniValue::VOBJ);
            out.pushKV("state_profile", BridgeShieldedStateProfileToUniValue(profile));
            out.pushKV("state_profile_hex", EncodeBridgeShieldedStateProfileHex(profile));
            out.pushKV("state_profile_id", shielded::ComputeBridgeShieldedStateProfileId(profile).GetHex());
            return out;
        }};
}

RPCHelpMan bridge_buildstateretentionpolicy()
{
    return RPCHelpMan{
        "bridge_buildstateretentionpolicy",
        "\nBuild a canonical shielded-state retention policy so BTX can model which aggregate-settlement state remains permanent on L1, which state is externalized to proofs or DA artifacts, and how quickly snapshots hit a target size.\n",
        {
            {"retention_policy", RPCArg::Type::OBJ, RPCArg::DefaultHint{"{}"}, "Shielded-state retention policy; omitted fields use the production externalized weekly-snapshot default, while full retention remains an explicit dev/audit override",
                {
                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Retention policy version"},
                    {"retain_commitment_index", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether the commitment index remains permanent local state"},
                    {"retain_nullifier_index", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether the nullifier index remains permanent local state"},
                    {"snapshot_include_commitments", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether snapshots serialize commitment entries"},
                    {"snapshot_include_nullifiers", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether snapshots serialize nullifier entries"},
                    {"wallet_l1_materialization_bps", RPCArg::Type::NUM, RPCArg::Default{2500}, "How many first-touch wallets are materialized on L1 immediately, in basis points"},
                    {"snapshot_target_bytes", RPCArg::Type::NUM, RPCArg::Default{2642412320}, "Target snapshot size used to estimate checkpoint cadence"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical bridge shielded-state retention policy",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildstateretentionpolicy",
                           "'{\"retain_commitment_index\":false,\"snapshot_include_commitments\":false,\"wallet_l1_materialization_bps\":2500}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const shielded::BridgeShieldedStateRetentionPolicy policy = request.params[0].isNull()
                ? shielded::BridgeShieldedStateRetentionPolicy{}
                : ParseBridgeShieldedStateRetentionPolicyOrThrow(request.params[0], "retention_policy");

            UniValue out(UniValue::VOBJ);
            out.pushKV("retention_policy", BridgeShieldedStateRetentionPolicyToUniValue(policy));
            out.pushKV("retention_policy_hex", EncodeBridgeShieldedStateRetentionPolicyHex(policy));
            out.pushKV("retention_policy_id", shielded::ComputeBridgeShieldedStateRetentionPolicyId(policy).GetHex());
            return out;
        }};
}

RPCHelpMan bridge_decodestateretentionpolicy()
{
    return RPCHelpMan{
        "bridge_decodestateretentionpolicy",
        "\nDecode a canonical shielded-state retention policy.\n",
        {
            {"retention_policy_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge shielded-state retention policy"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Decoded bridge shielded-state retention policy",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_decodestateretentionpolicy", "\"<retention_policy_hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto policy = DecodeBridgeShieldedStateRetentionPolicyOrThrow(request.params[0]);
            UniValue out(UniValue::VOBJ);
            out.pushKV("retention_policy", BridgeShieldedStateRetentionPolicyToUniValue(policy));
            out.pushKV("retention_policy_hex", EncodeBridgeShieldedStateRetentionPolicyHex(policy));
            out.pushKV("retention_policy_id", shielded::ComputeBridgeShieldedStateRetentionPolicyId(policy).GetHex());
            return out;
        }};
}

RPCHelpMan bridge_buildproversample()
{
    return RPCHelpMan{
        "bridge_buildproversample",
        "\nBuild a canonical prover sample linked to one imported proof artifact so BTX can reuse artifact-backed timing data across settlement-capacity scenarios.\n",
        {
            {"sample", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Artifact-linked prover timing sample",
                {
                    {"proof_artifact_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof artifact"},
                    {"proof_artifact", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline bridge proof artifact",
                        {
                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Artifact version"},
                            {"proof_adapter_name", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Built-in proof adapter name"},
                            {"proof_adapter_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof adapter"},
                            {"statement_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the committed bridge batch statement"},
                            {"verifier_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the verifier key, image ID, or program identifier"},
                            {"public_values_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the canonical public values or claim digest"},
                            {"proof_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Commitment to the proof/seal/receipt payload"},
                            {"artifact_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Commitment to the imported artifact bundle"},
                            {"proof_size_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Proof or seal payload size in bytes"},
                            {"public_values_size_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Public-values, journal, or tuple payload size in bytes"},
                            {"auxiliary_data_size_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Additional sidecar or proof-query metadata bytes kept off-chain"},
                        }},
                    {"prover_template_name", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Built-in modeled reference template name such as sp1-groth16-reference-v1; explicit timing fields may override the template defaults"},
                    {"native_millis", RPCArg::Type::NUM, RPCArg::Default{0}, "Measured or modeled native pre-proof wall time for this artifact in milliseconds"},
                    {"cpu_millis", RPCArg::Type::NUM, RPCArg::Default{0}, "Measured or modeled CPU proving wall time for this artifact in milliseconds"},
                    {"gpu_millis", RPCArg::Type::NUM, RPCArg::Default{0}, "Measured or modeled GPU proving wall time for this artifact in milliseconds"},
                    {"network_millis", RPCArg::Type::NUM, RPCArg::Default{0}, "Measured or modeled remote prover or proving-network wall time for this artifact in milliseconds"},
                    {"peak_memory_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Measured or modeled peak memory usage observed while producing this artifact"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical bridge prover sample",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildproversample",
                           "'{\"proof_artifact_hex\":\"<proof_artifact_hex>\",\"prover_template_name\":\"sp1-groth16-reference-v1\"}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto sample = BuildBridgeProverSampleOrThrow(request.params[0], "sample");
            UniValue out(UniValue::VOBJ);
            out.pushKV("prover_sample", BridgeProverSampleToUniValue(sample));
            out.pushKV("prover_sample_hex", EncodeBridgeProverSampleHex(sample));
            out.pushKV("prover_sample_id", shielded::ComputeBridgeProverSampleId(sample).GetHex());
            const UniValue& prover_template_name_value = FindValue(request.params[0], "prover_template_name");
            if (!prover_template_name_value.isNull()) {
                if (const auto* prover_template = FindBridgeProverTemplate(prover_template_name_value.get_str())) {
                    out.pushKV("prover_template", BridgeProverTemplateToUniValue(*prover_template));
                }
            }
            return out;
        }};
}

RPCHelpMan bridge_decodeproversample()
{
    return RPCHelpMan{
        "bridge_decodeproversample",
        "\nDecode a canonical bridge prover sample.\n",
        {
            {"prover_sample_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge prover sample"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Decoded bridge prover sample",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_decodeproversample", "\"<prover_sample_hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto sample = DecodeBridgeProverSampleOrThrow(request.params[0]);
            UniValue out(UniValue::VOBJ);
            out.pushKV("prover_sample", BridgeProverSampleToUniValue(sample));
            out.pushKV("prover_sample_hex", EncodeBridgeProverSampleHex(sample));
            out.pushKV("prover_sample_id", shielded::ComputeBridgeProverSampleId(sample).GetHex());
            return out;
        }};
}

RPCHelpMan bridge_buildproverprofile()
{
    return RPCHelpMan{
        "bridge_buildproverprofile",
        "\nBuild a canonical prover profile that aggregates artifact-linked timing samples for one bridge batch statement.\n",
        {
            {"samples", RPCArg::Type::ARR, RPCArg::Optional::NO, "Prover samples or inline sample builders",
                {
                    {"sample", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One prover sample selector or builder",
                        {
                            {"prover_sample_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge prover sample"},
                            {"prover_sample", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline canonical bridge prover sample",
                                {
                                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Sample version"},
                                    {"statement_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the committed bridge batch statement"},
                                    {"proof_artifact_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the canonical proof artifact"},
                                    {"proof_system_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed proof-system identifier"},
                                    {"verifier_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the verifier key, image ID, or program identifier"},
                                    {"artifact_storage_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Artifact storage bytes contributed by this sample"},
                                    {"native_millis", RPCArg::Type::NUM, RPCArg::Default{0}, "Measured native pre-proof wall time"},
                                    {"cpu_millis", RPCArg::Type::NUM, RPCArg::Default{0}, "Measured CPU proving wall time"},
                                    {"gpu_millis", RPCArg::Type::NUM, RPCArg::Default{0}, "Measured GPU proving wall time"},
                                    {"network_millis", RPCArg::Type::NUM, RPCArg::Default{0}, "Measured remote proving wall time"},
                                    {"peak_memory_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Peak memory usage observed while producing this artifact"},
                                }},
                            {"proof_artifact_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof artifact to build a sample from"},
                            {"proof_artifact", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline bridge proof artifact to build a sample from",
                                {
                                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Artifact version"},
                                    {"proof_adapter_name", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Built-in proof adapter name"},
                                    {"proof_adapter_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof adapter"},
                                    {"statement_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the committed bridge batch statement"},
                                    {"verifier_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the verifier key, image ID, or program identifier"},
                                    {"public_values_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the canonical public values or claim digest"},
                                    {"proof_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Commitment to the proof/seal/receipt payload"},
                                    {"artifact_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Commitment to the imported artifact bundle"},
                                    {"proof_size_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Proof or seal payload size in bytes"},
                                    {"public_values_size_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Public-values, journal, or tuple payload size in bytes"},
                                    {"auxiliary_data_size_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Additional sidecar or proof-query metadata bytes kept off-chain"},
                                }},
                            {"prover_template_name", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Built-in modeled reference template name for artifact-backed sample builders"},
                            {"native_millis", RPCArg::Type::NUM, RPCArg::Default{0}, "Measured or modeled native pre-proof wall time when building from an artifact"},
                            {"cpu_millis", RPCArg::Type::NUM, RPCArg::Default{0}, "Measured or modeled CPU proving wall time when building from an artifact"},
                            {"gpu_millis", RPCArg::Type::NUM, RPCArg::Default{0}, "Measured or modeled GPU proving wall time when building from an artifact"},
                            {"network_millis", RPCArg::Type::NUM, RPCArg::Default{0}, "Measured or modeled remote proving wall time when building from an artifact"},
                            {"peak_memory_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Measured or modeled peak memory usage observed while producing this artifact"},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical bridge prover profile",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildproverprofile",
                           "'[{\"prover_sample_hex\":\"<sample_a_hex>\"},{\"prover_sample_hex\":\"<sample_b_hex>\"}]'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            if (!request.params[0].isArray()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "samples must be an array");
            }
            std::vector<shielded::BridgeProverSample> samples;
            samples.reserve(request.params[0].size());
            for (size_t i = 0; i < request.params[0].size(); ++i) {
                const std::string item_name = strprintf("samples[%d]", i);
                const auto sample = ParseBridgeProverSampleSelectorOrThrow(request.params[0][i], item_name);
                if (sample.has_value()) {
                    samples.push_back(*sample);
                } else {
                    samples.push_back(BuildBridgeProverSampleOrThrow(request.params[0][i], item_name));
                }
            }
            const auto profile = shielded::BuildBridgeProverProfile(samples);
            if (!profile.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to build a valid bridge prover profile from samples");
            }

            UniValue sample_ids(UniValue::VARR);
            for (const auto& sample : samples) {
                sample_ids.push_back(shielded::ComputeBridgeProverSampleId(sample).GetHex());
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("prover_profile", BridgeProverProfileToUniValue(*profile));
            out.pushKV("prover_profile_hex", EncodeBridgeProverProfileHex(*profile));
            out.pushKV("prover_profile_id", shielded::ComputeBridgeProverProfileId(*profile).GetHex());
            out.pushKV("prover_sample_ids", std::move(sample_ids));
            return out;
        }};
}

RPCHelpMan bridge_decodeproverprofile()
{
    return RPCHelpMan{
        "bridge_decodeproverprofile",
        "\nDecode a canonical bridge prover profile.\n",
        {
            {"prover_profile_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge prover profile"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Decoded bridge prover profile",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_decodeproverprofile", "\"<prover_profile_hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto profile = DecodeBridgeProverProfileOrThrow(request.params[0]);
            UniValue out(UniValue::VOBJ);
            out.pushKV("prover_profile", BridgeProverProfileToUniValue(profile));
            out.pushKV("prover_profile_hex", EncodeBridgeProverProfileHex(profile));
            out.pushKV("prover_profile_id", shielded::ComputeBridgeProverProfileId(profile).GetHex());
            return out;
        }};
}

RPCHelpMan bridge_buildproverbenchmark()
{
    return RPCHelpMan{
        "bridge_buildproverbenchmark",
        "\nBuild a canonical prover benchmark from repeated prover profiles over the same bridge batch statement, capturing min / p50 / p90 / max for each lane.\n",
        {
            {"profiles", RPCArg::Type::ARR, RPCArg::Optional::NO, "Canonical prover profiles to aggregate into one benchmark",
                {
                    {"profile", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One prover profile selector",
                        {
                            {"prover_profile_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge prover profile"},
                            {"prover_profile", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline canonical bridge prover profile",
                                {
                                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Profile version"},
                                    {"statement_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the committed bridge batch statement"},
                                    {"sample_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "Number of prover samples in the profile"},
                                    {"sample_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical root over the prover sample ids"},
                                    {"total_artifact_storage_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Total artifact storage bytes represented by the profile"},
                                    {"total_peak_memory_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Sum of peak memory usage across the samples"},
                                    {"max_peak_memory_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Largest peak memory usage among the samples"},
                                    {"native_millis_per_settlement", RPCArg::Type::NUM, RPCArg::Default{0}, "Native pre-proof wall time contributed by the profile"},
                                    {"cpu_millis_per_settlement", RPCArg::Type::NUM, RPCArg::Default{0}, "CPU proving wall time contributed by the profile"},
                                    {"gpu_millis_per_settlement", RPCArg::Type::NUM, RPCArg::Default{0}, "GPU proving wall time contributed by the profile"},
                                    {"network_millis_per_settlement", RPCArg::Type::NUM, RPCArg::Default{0}, "Remote proving wall time contributed by the profile"},
                                }},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical bridge prover benchmark",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildproverbenchmark",
                           "'[{\"prover_profile_hex\":\"<profile_a_hex>\"},{\"prover_profile_hex\":\"<profile_b_hex>\"}]'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto benchmark = BuildBridgeProverBenchmarkOrThrow(request.params[0], "profiles");
            UniValue out(UniValue::VOBJ);
            out.pushKV("prover_benchmark", BridgeProverBenchmarkToUniValue(benchmark));
            out.pushKV("prover_benchmark_hex", EncodeBridgeProverBenchmarkHex(benchmark));
            out.pushKV("prover_benchmark_id", shielded::ComputeBridgeProverBenchmarkId(benchmark).GetHex());
            return out;
        }};
}

RPCHelpMan bridge_decodeproverbenchmark()
{
    return RPCHelpMan{
        "bridge_decodeproverbenchmark",
        "\nDecode a canonical bridge prover benchmark.\n",
        {
            {"prover_benchmark_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge prover benchmark"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Decoded bridge prover benchmark",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_decodeproverbenchmark", "\"<prover_benchmark_hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto benchmark = DecodeBridgeProverBenchmarkOrThrow(request.params[0]);
            UniValue out(UniValue::VOBJ);
            out.pushKV("prover_benchmark", BridgeProverBenchmarkToUniValue(benchmark));
            out.pushKV("prover_benchmark_hex", EncodeBridgeProverBenchmarkHex(benchmark));
            out.pushKV("prover_benchmark_id", shielded::ComputeBridgeProverBenchmarkId(benchmark).GetHex());
            return out;
        }};
}

RPCHelpMan bridge_estimatestategrowth()
{
    return RPCHelpMan{
        "bridge_estimatestategrowth",
        "\nEstimate the persistent shielded-state growth implied by one hard-fork aggregate settlement, including commitment/nullifier index growth, snapshot appendix growth, hot-cache pressure, and optional first-touch wallet materialization costs.\n",
        {
            {"aggregate_settlement_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded canonical bridge aggregate settlement"},
            {"options", RPCArg::Type::OBJ, RPCArg::DefaultHint{"{}"}, "Optional block-fit limits and state-profile overrides",
                {
                    {"block_serialized_limit", RPCArg::Type::NUM, RPCArg::Default{MAX_BLOCK_SERIALIZED_SIZE}, "Serialized block-size limit used to convert one settlement into settlements per block"},
                    {"block_weight_limit", RPCArg::Type::NUM, RPCArg::Default{MAX_BLOCK_WEIGHT}, "Block-weight limit used to convert one settlement into settlements per block"},
                    {"block_data_availability_limit", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Optional separate L1 data-availability cap; required when the aggregate settlement consumes that lane"},
                    {"block_interval_millis", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_BRIDGE_PROVER_BLOCK_INTERVAL_MILLIS}, "Consensus block interval used to project per-hour and per-day growth"},
                    {"state_profile_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge shielded-state profile"},
                    {"state_profile", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline shielded-state profile",
                        {
                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Shielded-state profile version"},
                            {"commitment_index_key_bytes", RPCArg::Type::NUM, RPCArg::Default{9}, "Persistent bytes for one commitment-index key"},
                            {"commitment_index_value_bytes", RPCArg::Type::NUM, RPCArg::Default{32}, "Persistent bytes for one commitment-index value"},
                            {"snapshot_commitment_bytes", RPCArg::Type::NUM, RPCArg::Default{32}, "Snapshot appendix bytes retained per new commitment"},
                            {"nullifier_index_key_bytes", RPCArg::Type::NUM, RPCArg::Default{33}, "Persistent bytes for one nullifier-index key"},
                            {"nullifier_index_value_bytes", RPCArg::Type::NUM, RPCArg::Default{1}, "Persistent bytes for one nullifier-index value"},
                            {"snapshot_nullifier_bytes", RPCArg::Type::NUM, RPCArg::Default{32}, "Snapshot appendix bytes retained per nullifier"},
                            {"nullifier_cache_bytes", RPCArg::Type::NUM, RPCArg::Default{96}, "Hot-cache bytes retained per nullifier entry"},
                            {"wallet_materialization_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Additional persistent bytes charged per first-touch wallet/account"},
                            {"bounded_anchor_history_bytes", RPCArg::Type::NUM, RPCArg::Default{800}, "Bounded bytes retained for recent anchor/output-count history"},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Shielded-state growth estimate",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_estimatestategrowth",
                           "\"<aggregate_settlement_hex>\" "
                           "'{\"block_data_availability_limit\":786432,\"state_profile\":{\"wallet_materialization_bytes\":96}}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto settlement = DecodeBridgeAggregateSettlementOrThrow(request.params[0]);
            const auto footprint = shielded::BuildBridgeAggregateSettlementFootprint(settlement);
            if (!footprint.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "failed to derive a valid bridge capacity footprint from aggregate_settlement_hex");
            }

            uint64_t block_serialized_limit = MAX_BLOCK_SERIALIZED_SIZE;
            uint64_t block_weight_limit = MAX_BLOCK_WEIGHT;
            std::optional<uint64_t> block_data_availability_limit;
            uint64_t block_interval_millis = DEFAULT_BRIDGE_PROVER_BLOCK_INTERVAL_MILLIS;
            shielded::BridgeShieldedStateProfile profile;

            if (!request.params[1].isNull()) {
                const UniValue& options = request.params[1];
                if (!options.isObject()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
                }
                const UniValue& block_serialized_limit_value = FindValue(options, "block_serialized_limit");
                const UniValue& block_weight_limit_value = FindValue(options, "block_weight_limit");
                const UniValue& block_data_availability_limit_value = FindValue(options, "block_data_availability_limit");
                const UniValue& block_interval_value = FindValue(options, "block_interval_millis");
                if (!block_serialized_limit_value.isNull()) {
                    block_serialized_limit = ParsePositiveUint64OrThrow(block_serialized_limit_value, "options.block_serialized_limit");
                }
                if (!block_weight_limit_value.isNull()) {
                    block_weight_limit = ParsePositiveUint64OrThrow(block_weight_limit_value, "options.block_weight_limit");
                }
                if (!block_data_availability_limit_value.isNull()) {
                    block_data_availability_limit = ParsePositiveUint64OrThrow(block_data_availability_limit_value,
                                                                              "options.block_data_availability_limit");
                }
                if (!block_interval_value.isNull()) {
                    block_interval_millis = ParsePositiveUint64OrThrow(block_interval_value, "options.block_interval_millis");
                }
                if (const auto selected_profile = ParseBridgeShieldedStateProfileSelectorOrThrow(options, "options")) {
                    profile = *selected_profile;
                }
            }

            const auto capacity = shielded::EstimateBridgeCapacity(*footprint,
                                                                   block_serialized_limit,
                                                                   block_weight_limit,
                                                                   block_data_availability_limit);
            if (!capacity.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to estimate block-fit capacity from aggregate_settlement_hex");
            }
            const auto estimate = shielded::EstimateBridgeShieldedStateGrowth(settlement, profile, *capacity, block_interval_millis);
            if (!estimate.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to estimate shielded state growth from aggregate_settlement_hex");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("aggregate_settlement", BridgeAggregateSettlementToUniValue(settlement));
            out.pushKV("aggregate_settlement_hex", EncodeBridgeAggregateSettlementHex(settlement));
            out.pushKV("aggregate_settlement_id", shielded::ComputeBridgeAggregateSettlementId(settlement).GetHex());
            out.pushKV("footprint", BridgeCapacityFootprintToUniValue(*footprint));
            out.pushKV("capacity_estimate", BridgeCapacityEstimateToUniValue(*capacity));
            out.pushKV("state_profile", BridgeShieldedStateProfileToUniValue(profile));
            out.pushKV("state_profile_hex", EncodeBridgeShieldedStateProfileHex(profile));
            out.pushKV("state_profile_id", shielded::ComputeBridgeShieldedStateProfileId(profile).GetHex());
            out.pushKV("state_estimate", BridgeShieldedStateEstimateToUniValue(*estimate));
            return out;
        }};
}

RPCHelpMan bridge_estimatestateretention()
{
    return RPCHelpMan{
        "bridge_estimatestateretention",
        "\nEstimate how much aggregate-settlement shielded state BTX keeps permanently, how much state is externalized to proof or DA artifacts, and how quickly snapshots reach a target size under a chosen retention policy.\n",
        {
            {"aggregate_settlement_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded canonical bridge aggregate settlement"},
            {"options", RPCArg::Type::OBJ, RPCArg::DefaultHint{"{}"}, "Optional block-fit limits, state-profile overrides, and retention policy",
                {
                    {"block_serialized_limit", RPCArg::Type::NUM, RPCArg::Default{MAX_BLOCK_SERIALIZED_SIZE}, "Serialized block-size limit used to convert one settlement into settlements per block"},
                    {"block_weight_limit", RPCArg::Type::NUM, RPCArg::Default{MAX_BLOCK_WEIGHT}, "Block-weight limit used to convert one settlement into settlements per block"},
                    {"block_data_availability_limit", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Optional separate L1 data-availability cap; required when the aggregate settlement consumes that lane"},
                    {"block_interval_millis", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_BRIDGE_PROVER_BLOCK_INTERVAL_MILLIS}, "Consensus block interval used to project hourly/daily retention"},
                    {"state_profile_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge shielded-state profile"},
                    {"state_profile", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline shielded-state profile",
                        {
                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Shielded-state profile version"},
                            {"commitment_index_key_bytes", RPCArg::Type::NUM, RPCArg::Default{9}, "Persistent bytes for one commitment-index key"},
                            {"commitment_index_value_bytes", RPCArg::Type::NUM, RPCArg::Default{32}, "Persistent bytes for one commitment-index value"},
                            {"snapshot_commitment_bytes", RPCArg::Type::NUM, RPCArg::Default{32}, "Snapshot appendix bytes retained per new commitment"},
                            {"nullifier_index_key_bytes", RPCArg::Type::NUM, RPCArg::Default{33}, "Persistent bytes for one nullifier-index key"},
                            {"nullifier_index_value_bytes", RPCArg::Type::NUM, RPCArg::Default{1}, "Persistent bytes for one nullifier-index value"},
                            {"snapshot_nullifier_bytes", RPCArg::Type::NUM, RPCArg::Default{32}, "Snapshot appendix bytes retained per nullifier"},
                            {"nullifier_cache_bytes", RPCArg::Type::NUM, RPCArg::Default{96}, "Hot-cache bytes retained per nullifier entry"},
                            {"wallet_materialization_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Additional persistent bytes charged per first-touch wallet/account"},
                            {"bounded_anchor_history_bytes", RPCArg::Type::NUM, RPCArg::Default{800}, "Bounded bytes retained for recent anchor/output-count history"},
                        }},
                    {"retention_policy_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge shielded-state retention policy"},
                    {"retention_policy", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline shielded-state retention policy",
                        {
                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Retention policy version"},
                            {"retain_commitment_index", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether the commitment index remains permanent local state"},
                            {"retain_nullifier_index", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether the nullifier index remains permanent local state"},
                            {"snapshot_include_commitments", RPCArg::Type::BOOL, RPCArg::Default{false}, "Whether snapshots serialize commitment entries"},
                            {"snapshot_include_nullifiers", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether snapshots serialize nullifier entries"},
                            {"wallet_l1_materialization_bps", RPCArg::Type::NUM, RPCArg::Default{2500}, "How many first-touch wallets are materialized on L1 immediately, in basis points"},
                            {"snapshot_target_bytes", RPCArg::Type::NUM, RPCArg::Default{2642412320}, "Target snapshot size used to estimate checkpoint cadence"},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Shielded-state retention estimate",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_estimatestateretention",
                           "\"<aggregate_settlement_hex>\" "
                           "'{\"block_data_availability_limit\":786432,\"state_profile\":{\"wallet_materialization_bytes\":96},"
                           "\"retention_policy\":{\"retain_commitment_index\":false,\"snapshot_include_commitments\":false,\"wallet_l1_materialization_bps\":2500}}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto settlement = DecodeBridgeAggregateSettlementOrThrow(request.params[0]);
            const auto footprint = shielded::BuildBridgeAggregateSettlementFootprint(settlement);
            if (!footprint.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "failed to derive a valid bridge capacity footprint from aggregate_settlement_hex");
            }

            uint64_t block_serialized_limit = MAX_BLOCK_SERIALIZED_SIZE;
            uint64_t block_weight_limit = MAX_BLOCK_WEIGHT;
            std::optional<uint64_t> block_data_availability_limit;
            uint64_t block_interval_millis = DEFAULT_BRIDGE_PROVER_BLOCK_INTERVAL_MILLIS;
            shielded::BridgeShieldedStateProfile profile;
            shielded::BridgeShieldedStateRetentionPolicy retention_policy;

            if (!request.params[1].isNull()) {
                const UniValue& options = request.params[1];
                if (!options.isObject()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
                }
                const UniValue& block_serialized_limit_value = FindValue(options, "block_serialized_limit");
                const UniValue& block_weight_limit_value = FindValue(options, "block_weight_limit");
                const UniValue& block_data_availability_limit_value = FindValue(options, "block_data_availability_limit");
                const UniValue& block_interval_value = FindValue(options, "block_interval_millis");
                if (!block_serialized_limit_value.isNull()) {
                    block_serialized_limit = ParsePositiveUint64OrThrow(block_serialized_limit_value, "options.block_serialized_limit");
                }
                if (!block_weight_limit_value.isNull()) {
                    block_weight_limit = ParsePositiveUint64OrThrow(block_weight_limit_value, "options.block_weight_limit");
                }
                if (!block_data_availability_limit_value.isNull()) {
                    block_data_availability_limit = ParsePositiveUint64OrThrow(block_data_availability_limit_value,
                                                                              "options.block_data_availability_limit");
                }
                if (!block_interval_value.isNull()) {
                    block_interval_millis = ParsePositiveUint64OrThrow(block_interval_value, "options.block_interval_millis");
                }
                if (const auto selected_profile = ParseBridgeShieldedStateProfileSelectorOrThrow(options, "options")) {
                    profile = *selected_profile;
                }
                if (const auto selected_policy = ParseBridgeShieldedStateRetentionPolicySelectorOrThrow(options, "options")) {
                    retention_policy = *selected_policy;
                }
            }

            const auto capacity = shielded::EstimateBridgeCapacity(*footprint,
                                                                   block_serialized_limit,
                                                                   block_weight_limit,
                                                                   block_data_availability_limit);
            if (!capacity.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to estimate block-fit capacity from aggregate_settlement_hex");
            }
            const auto state_estimate = shielded::EstimateBridgeShieldedStateGrowth(settlement, profile, *capacity, block_interval_millis);
            if (!state_estimate.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to estimate shielded state growth from aggregate_settlement_hex");
            }
            const auto retention_estimate = shielded::EstimateBridgeShieldedStateRetention(*state_estimate, retention_policy);
            if (!retention_estimate.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "failed to estimate shielded state retention from aggregate_settlement_hex");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("aggregate_settlement", BridgeAggregateSettlementToUniValue(settlement));
            out.pushKV("aggregate_settlement_hex", EncodeBridgeAggregateSettlementHex(settlement));
            out.pushKV("aggregate_settlement_id", shielded::ComputeBridgeAggregateSettlementId(settlement).GetHex());
            out.pushKV("footprint", BridgeCapacityFootprintToUniValue(*footprint));
            out.pushKV("capacity_estimate", BridgeCapacityEstimateToUniValue(*capacity));
            out.pushKV("state_profile", BridgeShieldedStateProfileToUniValue(profile));
            out.pushKV("state_profile_hex", EncodeBridgeShieldedStateProfileHex(profile));
            out.pushKV("state_profile_id", shielded::ComputeBridgeShieldedStateProfileId(profile).GetHex());
            out.pushKV("state_estimate", BridgeShieldedStateEstimateToUniValue(*state_estimate));
            out.pushKV("retention_policy", BridgeShieldedStateRetentionPolicyToUniValue(retention_policy));
            out.pushKV("retention_policy_hex", EncodeBridgeShieldedStateRetentionPolicyHex(retention_policy));
            out.pushKV("retention_policy_id", shielded::ComputeBridgeShieldedStateRetentionPolicyId(retention_policy).GetHex());
            out.pushKV("retention_estimate", BridgeShieldedStateRetentionEstimateToUniValue(*retention_estimate));
            return out;
        }};
}

RPCHelpMan bridge_estimatecapacity()
{
    return RPCHelpMan{
        "bridge_estimatecapacity",
        "\nEstimate how many settlement transactions of one measured bridge or shielded footprint fit in a BTX block, plus the implied users-per-block, off-chain storage growth, and optional prover-side throughput required to sustain that footprint.\n",
        {
            {"footprint", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Measured settlement footprint",
                {
                    {"l1_serialized_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Finalized transaction or settlement envelope bytes that reach L1"},
                    {"l1_weight", RPCArg::Type::NUM, RPCArg::Optional::NO, "Finalized transaction or settlement envelope weight charged by BTX"},
                    {"l1_data_availability_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Bytes consumed on a separate L1 data-availability lane such as a blob-style hard-fork path"},
                    {"control_plane_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Additional per-settlement control bytes kept off-chain or between operators"},
                    {"offchain_storage_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Off-chain proof / artifact bytes retained per settlement"},
                    {"batched_user_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "How many user actions or payouts one L1 settlement represents"},
                }},
            {"options", RPCArg::Type::OBJ, RPCArg::DefaultHint{"{}"}, "Optional limits and comparison baseline",
                {
                    {"block_serialized_limit", RPCArg::Type::NUM, RPCArg::Default{MAX_BLOCK_SERIALIZED_SIZE}, "Serialized block-size limit to use in the estimate"},
                    {"block_weight_limit", RPCArg::Type::NUM, RPCArg::Default{MAX_BLOCK_WEIGHT}, "Block-weight limit to use in the estimate"},
                    {"block_data_availability_limit", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Optional cap for a separate L1 data-availability lane; required when l1_data_availability_bytes is non-zero"},
                    {"baseline", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional comparison baseline using the same footprint schema",
                        {
                            {"l1_serialized_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Baseline L1 serialized bytes"},
                            {"l1_weight", RPCArg::Type::NUM, RPCArg::Optional::NO, "Baseline L1 weight"},
                            {"l1_data_availability_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Baseline L1 data-availability bytes"},
                            {"control_plane_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Baseline control-plane bytes"},
                            {"offchain_storage_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Baseline off-chain storage bytes"},
                            {"batched_user_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "Baseline user count represented by one settlement"},
                        }},
                    {"prover", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional prover-side throughput model evaluated against the L1 block-fit result",
                        {
                            {"block_interval_millis", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_BRIDGE_PROVER_BLOCK_INTERVAL_MILLIS}, "Settlement cadence to sustain; defaults to BTX's current 90 second target spacing"},
                            {"prover_profile_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded canonical prover profile used to supply per-lane millis_per_settlement"},
                            {"prover_profile", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline canonical prover profile used to supply per-lane millis_per_settlement",
                                {
                                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Profile version"},
                                    {"statement_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the committed bridge batch statement"},
                                    {"sample_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "Number of prover samples in the profile"},
                                    {"sample_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical root over the prover sample ids"},
                                    {"total_artifact_storage_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Total artifact storage bytes represented by the profile"},
                                    {"total_peak_memory_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Sum of peak memory usage across the samples"},
                                    {"max_peak_memory_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Largest peak memory usage among the samples"},
                                    {"native_millis_per_settlement", RPCArg::Type::NUM, RPCArg::Default{0}, "Native pre-proof wall time contributed by the profile"},
                                    {"cpu_millis_per_settlement", RPCArg::Type::NUM, RPCArg::Default{0}, "CPU proving wall time contributed by the profile"},
                                    {"gpu_millis_per_settlement", RPCArg::Type::NUM, RPCArg::Default{0}, "GPU proving wall time contributed by the profile"},
                                    {"network_millis_per_settlement", RPCArg::Type::NUM, RPCArg::Default{0}, "Remote proving wall time contributed by the profile"},
                                }},
                            {"prover_benchmark_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded canonical prover benchmark used to supply per-lane millis_per_settlement from min, p50, p90, or max"},
                            {"prover_benchmark", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline canonical prover benchmark used to supply per-lane millis_per_settlement from min, p50, p90, or max",
                                {
                                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Benchmark version"},
                                    {"statement_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the committed bridge batch statement"},
                                    {"profile_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "Number of prover profiles represented by the benchmark"},
                                    {"sample_count_per_profile", RPCArg::Type::NUM, RPCArg::Optional::NO, "Number of prover samples represented by each profile"},
                                    {"profile_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical root over the prover profile ids"},
                                    {"artifact_storage_bytes_per_profile", RPCArg::Type::NUM, RPCArg::Optional::NO, "Artifact storage bytes represented by each benchmarked profile"},
                                    {"total_peak_memory_bytes", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Summary for summed peak memory bytes across repeated profiles",
                                        {
                                            {"min", RPCArg::Type::NUM, RPCArg::Optional::NO, "Minimum observed value"},
                                            {"p50", RPCArg::Type::NUM, RPCArg::Optional::NO, "Nearest-rank p50 value"},
                                            {"p90", RPCArg::Type::NUM, RPCArg::Optional::NO, "Nearest-rank p90 value"},
                                            {"max", RPCArg::Type::NUM, RPCArg::Optional::NO, "Maximum observed value"},
                                        }},
                                    {"max_peak_memory_bytes", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Summary for per-profile max peak memory bytes",
                                        {
                                            {"min", RPCArg::Type::NUM, RPCArg::Optional::NO, "Minimum observed value"},
                                            {"p50", RPCArg::Type::NUM, RPCArg::Optional::NO, "Nearest-rank p50 value"},
                                            {"p90", RPCArg::Type::NUM, RPCArg::Optional::NO, "Nearest-rank p90 value"},
                                            {"max", RPCArg::Type::NUM, RPCArg::Optional::NO, "Maximum observed value"},
                                        }},
                                    {"native_millis_per_settlement", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Summary for native pre-proof wall time",
                                        {
                                            {"min", RPCArg::Type::NUM, RPCArg::Optional::NO, "Minimum observed value"},
                                            {"p50", RPCArg::Type::NUM, RPCArg::Optional::NO, "Nearest-rank p50 value"},
                                            {"p90", RPCArg::Type::NUM, RPCArg::Optional::NO, "Nearest-rank p90 value"},
                                            {"max", RPCArg::Type::NUM, RPCArg::Optional::NO, "Maximum observed value"},
                                        }},
                                    {"cpu_millis_per_settlement", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Summary for CPU proving wall time",
                                        {
                                            {"min", RPCArg::Type::NUM, RPCArg::Optional::NO, "Minimum observed value"},
                                            {"p50", RPCArg::Type::NUM, RPCArg::Optional::NO, "Nearest-rank p50 value"},
                                            {"p90", RPCArg::Type::NUM, RPCArg::Optional::NO, "Nearest-rank p90 value"},
                                            {"max", RPCArg::Type::NUM, RPCArg::Optional::NO, "Maximum observed value"},
                                        }},
                                    {"gpu_millis_per_settlement", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Summary for GPU proving wall time",
                                        {
                                            {"min", RPCArg::Type::NUM, RPCArg::Optional::NO, "Minimum observed value"},
                                            {"p50", RPCArg::Type::NUM, RPCArg::Optional::NO, "Nearest-rank p50 value"},
                                            {"p90", RPCArg::Type::NUM, RPCArg::Optional::NO, "Nearest-rank p90 value"},
                                            {"max", RPCArg::Type::NUM, RPCArg::Optional::NO, "Maximum observed value"},
                                        }},
                                    {"network_millis_per_settlement", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Summary for remote proving wall time",
                                        {
                                            {"min", RPCArg::Type::NUM, RPCArg::Optional::NO, "Minimum observed value"},
                                            {"p50", RPCArg::Type::NUM, RPCArg::Optional::NO, "Nearest-rank p50 value"},
                                            {"p90", RPCArg::Type::NUM, RPCArg::Optional::NO, "Nearest-rank p90 value"},
                                            {"max", RPCArg::Type::NUM, RPCArg::Optional::NO, "Maximum observed value"},
                                        }},
                                }},
                            {"benchmark_statistic", RPCArg::Type::STR, RPCArg::Default{"p50"}, "Which benchmark statistic to use when prover_benchmark_* supplies per-lane millis_per_settlement: min, p50, p90, or max"},
                            {"native", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Modeled native pre-proof stage such as hashing or witness construction",
                                {
                                    {"millis_per_settlement", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Wall-clock milliseconds to process one settlement on one worker; omit when prover_profile or prover_benchmark supplies it"},
                                    {"workers", RPCArg::Type::NUM, RPCArg::Optional::NO, "How many workers or hosts are assigned to this lane"},
                                    {"parallel_jobs_per_worker", RPCArg::Type::NUM, RPCArg::Default{1}, "Concurrent jobs each worker can sustain"},
                                    {"hourly_cost_cents", RPCArg::Type::NUM, RPCArg::Default{0}, "Modeled hourly cost per worker in cents"},
                                }},
                            {"cpu", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Modeled CPU proving lane",
                                {
                                    {"millis_per_settlement", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Wall-clock milliseconds to prove one settlement on one worker; omit when prover_profile or prover_benchmark supplies it"},
                                    {"workers", RPCArg::Type::NUM, RPCArg::Optional::NO, "How many CPU workers or hosts are assigned"},
                                    {"parallel_jobs_per_worker", RPCArg::Type::NUM, RPCArg::Default{1}, "Concurrent jobs each worker can sustain"},
                                    {"hourly_cost_cents", RPCArg::Type::NUM, RPCArg::Default{0}, "Modeled hourly cost per worker in cents"},
                                }},
                            {"gpu", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Modeled GPU proving lane",
                                {
                                    {"millis_per_settlement", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Wall-clock milliseconds to prove one settlement on one GPU worker; omit when prover_profile or prover_benchmark supplies it"},
                                    {"workers", RPCArg::Type::NUM, RPCArg::Optional::NO, "How many GPU workers or hosts are assigned"},
                                    {"parallel_jobs_per_worker", RPCArg::Type::NUM, RPCArg::Default{1}, "Concurrent jobs each GPU worker can sustain"},
                                    {"hourly_cost_cents", RPCArg::Type::NUM, RPCArg::Default{0}, "Modeled hourly cost per worker in cents"},
                                }},
                            {"network", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Modeled remote prover or proving-network lane",
                                {
                                    {"millis_per_settlement", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Wall-clock milliseconds to return one settlement proof from one remote slot; omit when prover_profile or prover_benchmark supplies it"},
                                    {"workers", RPCArg::Type::NUM, RPCArg::Optional::NO, "How many remote slots or workers are assigned"},
                                    {"parallel_jobs_per_worker", RPCArg::Type::NUM, RPCArg::Default{1}, "Concurrent jobs each remote worker can sustain"},
                                    {"hourly_cost_cents", RPCArg::Type::NUM, RPCArg::Default{0}, "Modeled hourly cost per worker in cents"},
                                }},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Capacity estimate",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_estimatecapacity",
                           "'{\"l1_serialized_bytes\":3191,\"l1_weight\":12764,\"control_plane_bytes\":178,\"batched_user_count\":3}' "
                           "'{\"baseline\":{\"l1_serialized_bytes\":586196,\"l1_weight\":2344784,\"batched_user_count\":1},"
                           "\"prover\":{\"gpu\":{\"millis_per_settlement\":12000,\"workers\":8,\"hourly_cost_cents\":1800}}}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto footprint = ParseBridgeCapacityFootprintOrThrow(request.params[0], "footprint");
            uint64_t block_serialized_limit = MAX_BLOCK_SERIALIZED_SIZE;
            uint64_t block_weight_limit = MAX_BLOCK_WEIGHT;
            std::optional<uint64_t> block_data_availability_limit;
            std::optional<shielded::BridgeCapacityFootprint> baseline;
            std::optional<shielded::BridgeProverFootprint> prover;
            std::optional<shielded::BridgeProverProfile> prover_profile;
            std::optional<shielded::BridgeProverBenchmark> prover_benchmark;
            shielded::BridgeProverBenchmarkStatistic benchmark_statistic = shielded::BridgeProverBenchmarkStatistic::P50;

            if (!request.params[1].isNull()) {
                const UniValue& options = request.params[1];
                if (!options.isObject()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
                }
                const UniValue& block_serialized_limit_value = FindValue(options, "block_serialized_limit");
                const UniValue& block_weight_limit_value = FindValue(options, "block_weight_limit");
                const UniValue& block_data_availability_limit_value = FindValue(options, "block_data_availability_limit");
                const UniValue& baseline_value = FindValue(options, "baseline");
                const UniValue& prover_value = FindValue(options, "prover");
                if (!block_serialized_limit_value.isNull()) {
                    block_serialized_limit = ParsePositiveUint64OrThrow(block_serialized_limit_value, "options.block_serialized_limit");
                }
                if (!block_weight_limit_value.isNull()) {
                    block_weight_limit = ParsePositiveUint64OrThrow(block_weight_limit_value, "options.block_weight_limit");
                }
                if (!block_data_availability_limit_value.isNull()) {
                    block_data_availability_limit = ParsePositiveUint64OrThrow(block_data_availability_limit_value,
                                                                              "options.block_data_availability_limit");
                }
                if (!baseline_value.isNull()) {
                    baseline = ParseBridgeCapacityFootprintOrThrow(baseline_value, "options.baseline");
                }
                if (!prover_value.isNull()) {
                    prover_profile = ParseBridgeProverProfileSelectorOrThrow(prover_value, "options.prover");
                    prover_benchmark = ParseBridgeProverBenchmarkSelectorOrThrow(prover_value, "options.prover");
                    if (prover_profile.has_value() && prover_benchmark.has_value()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                                           "options.prover cannot include both prover_profile_* and prover_benchmark_* selectors");
                    }
                    const UniValue& benchmark_statistic_value = FindValue(prover_value, "benchmark_statistic");
                    if (!benchmark_statistic_value.isNull()) {
                        if (!benchmark_statistic_value.isStr()) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                               "options.prover.benchmark_statistic must be a string");
                        }
                        benchmark_statistic = ParseBridgeProverBenchmarkStatisticOrThrow(benchmark_statistic_value,
                                                                                         "options.prover.benchmark_statistic");
                    }
                    prover = ParseBridgeProverFootprintOrThrow(prover_value,
                                                               "options.prover",
                                                               prover_profile,
                                                               prover_benchmark,
                                                               benchmark_statistic);
                }
            }

            const auto estimate = shielded::EstimateBridgeCapacity(footprint,
                                                                   block_serialized_limit,
                                                                   block_weight_limit,
                                                                   block_data_availability_limit);
            if (!estimate.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to estimate bridge capacity from footprint");
            }

            UniValue out = BridgeCapacityEstimateToUniValue(*estimate);
            if (prover.has_value()) {
                const auto prover_estimate = shielded::EstimateBridgeProverCapacity(*estimate, *prover);
                if (!prover_estimate.has_value()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to estimate prover throughput from options.prover");
                }
                UniValue prover_out = BridgeProverCapacityEstimateToUniValue(*prover_estimate);
                if (prover_profile.has_value()) {
                    prover_out.pushKV("profile", BridgeProverProfileToUniValue(*prover_profile));
                    prover_out.pushKV("prover_profile_hex", EncodeBridgeProverProfileHex(*prover_profile));
                    prover_out.pushKV("prover_profile_id", shielded::ComputeBridgeProverProfileId(*prover_profile).GetHex());
                    prover_out.pushKV("artifact_storage_bytes_delta_vs_footprint",
                                      static_cast<int64_t>(prover_profile->total_artifact_storage_bytes) -
                                          static_cast<int64_t>(estimate->footprint.offchain_storage_bytes));
                }
                if (prover_benchmark.has_value()) {
                    prover_out.pushKV("benchmark", BridgeProverBenchmarkToUniValue(*prover_benchmark));
                    prover_out.pushKV("prover_benchmark_hex", EncodeBridgeProverBenchmarkHex(*prover_benchmark));
                    prover_out.pushKV("prover_benchmark_id", shielded::ComputeBridgeProverBenchmarkId(*prover_benchmark).GetHex());
                    prover_out.pushKV("benchmark_statistic", BridgeProverBenchmarkStatisticToString(benchmark_statistic));
                    prover_out.pushKV("artifact_storage_bytes_delta_vs_footprint",
                                      static_cast<int64_t>(prover_benchmark->artifact_storage_bytes_per_profile) -
                                          static_cast<int64_t>(estimate->footprint.offchain_storage_bytes));
                }
                out.pushKV("prover", std::move(prover_out));
            }
            if (baseline.has_value()) {
                const auto baseline_estimate = shielded::EstimateBridgeCapacity(*baseline,
                                                                                block_serialized_limit,
                                                                                block_weight_limit,
                                                                                block_data_availability_limit);
                if (!baseline_estimate.has_value()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to estimate bridge capacity from options.baseline");
                }
                out.pushKV("baseline_estimate", BridgeCapacityEstimateToUniValue(*baseline_estimate));

                const double candidate_l1_serialized_per_user = static_cast<double>(estimate->footprint.l1_serialized_bytes) /
                    static_cast<double>(estimate->footprint.batched_user_count);
                const double candidate_l1_weight_per_user = static_cast<double>(estimate->footprint.l1_weight) /
                    static_cast<double>(estimate->footprint.batched_user_count);
                const double baseline_l1_serialized_per_user = static_cast<double>(baseline_estimate->footprint.l1_serialized_bytes) /
                    static_cast<double>(baseline_estimate->footprint.batched_user_count);
                const double baseline_l1_weight_per_user = static_cast<double>(baseline_estimate->footprint.l1_weight) /
                    static_cast<double>(baseline_estimate->footprint.batched_user_count);

                UniValue comparison(UniValue::VOBJ);
                comparison.pushKV("l1_serialized_bytes_ratio_per_user", candidate_l1_serialized_per_user / baseline_l1_serialized_per_user);
                comparison.pushKV("l1_weight_ratio_per_user", candidate_l1_weight_per_user / baseline_l1_weight_per_user);
                comparison.pushKV("settlement_count_gain",
                                  static_cast<double>(estimate->max_settlements_per_block) /
                                      static_cast<double>(baseline_estimate->max_settlements_per_block));
                comparison.pushKV("users_per_block_gain",
                                  static_cast<double>(estimate->users_per_block) /
                                      static_cast<double>(baseline_estimate->users_per_block));
                comparison.pushKV("control_plane_bytes_delta_per_settlement",
                                  static_cast<int64_t>(estimate->footprint.control_plane_bytes) -
                                      static_cast<int64_t>(baseline_estimate->footprint.control_plane_bytes));
                comparison.pushKV("offchain_storage_bytes_delta_per_settlement",
                                  static_cast<int64_t>(estimate->footprint.offchain_storage_bytes) -
                                      static_cast<int64_t>(baseline_estimate->footprint.offchain_storage_bytes));
                out.pushKV("comparison", std::move(comparison));
            }
            return out;
        }};
}

RPCHelpMan bridge_buildproofpolicy()
{
    return RPCHelpMan{
        "bridge_buildproofpolicy",
        "\nBuild a canonical proof-policy commitment for imported proof receipts over a bridge batch statement.\n",
        {
            {"descriptors", RPCArg::Type::ARR, RPCArg::Optional::NO, "Allowed proof-system/verifier-key descriptors",
                {
                    {"descriptor", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One proof descriptor",
                        {
                            {"proof_system_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hashed proof-system identifier"},
                            {"proof_profile_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof profile used to derive proof_system_id"},
                            {"proof_profile", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline bridge proof profile used to derive proof_system_id",
                                {
                                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Profile version"},
                                    {"family", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof family label"},
                                    {"proof_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof or receipt type label"},
                                    {"claim_system", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII public-output or claim-schema label"},
                                }},
                            {"proof_adapter_name", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Built-in proof adapter name used to derive proof_system_id"},
                            {"proof_adapter_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof adapter used to derive proof_system_id"},
                            {"proof_adapter", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline bridge proof adapter used to derive proof_system_id",
                                {
                                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Adapter version"},
                                    {"proof_profile_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof profile for the adapter"},
                                    {"proof_profile", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline bridge proof profile for the adapter",
                                        {
                                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Profile version"},
                                            {"family", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof family label"},
                                            {"proof_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof or receipt type label"},
                                            {"claim_system", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII public-output or claim-schema label"},
                                        }},
                                    {"claim_kind", RPCArg::Type::STR, RPCArg::Optional::NO, "batch_tuple_v1, settlement_metadata_v1, or data_root_tuple_v1"},
                                }},
                            {"proof_artifact_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof artifact used to derive proof_system_id and verifier_key_hash"},
                            {"proof_artifact", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline bridge proof artifact used to derive proof_system_id and verifier_key_hash",
                                {
                                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Artifact version"},
                                    {"proof_adapter_name", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Built-in proof adapter name"},
                                    {"proof_adapter_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof adapter"},
                                    {"statement_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the committed bridge batch statement"},
                                    {"verifier_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the verifier key, image ID, or program identifier"},
                                    {"public_values_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the canonical public values or claim digest"},
                                    {"proof_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Commitment to the proof/seal payload"},
                                    {"artifact_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Commitment to the full imported artifact bundle"},
                                    {"proof_size_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Proof or seal payload size in bytes"},
                                    {"public_values_size_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Public-values, journal, or tuple payload size in bytes"},
                                    {"auxiliary_data_size_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Additional sidecar or proof-query metadata bytes kept off-chain"},
                                }},
                            {"verifier_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hashed verifier key, program id, or image id; omitted when proof_artifact_* is provided"},
                        }},
                }},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Proof-policy parameters",
                {
                    {"required_receipts", RPCArg::Type::NUM, RPCArg::Optional::NO, "Minimum number of distinct receipts required from the committed descriptor set"},
                    {"targets", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Optional subset of descriptors for which membership proofs should be built",
                        {
                            {"descriptor", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One proof descriptor",
                                {
                                    {"proof_system_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hashed proof-system identifier"},
                                    {"proof_profile_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof profile used to derive proof_system_id"},
                                    {"proof_profile", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline bridge proof profile used to derive proof_system_id",
                                        {
                                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Profile version"},
                                            {"family", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof family label"},
                                            {"proof_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof or receipt type label"},
                                            {"claim_system", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII public-output or claim-schema label"},
                                        }},
                                    {"proof_adapter_name", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Built-in proof adapter name used to derive proof_system_id"},
                                    {"proof_adapter_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof adapter used to derive proof_system_id"},
                                    {"proof_adapter", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline bridge proof adapter used to derive proof_system_id",
                                        {
                                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Adapter version"},
                                            {"proof_profile_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof profile for the adapter"},
                                            {"proof_profile", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline bridge proof profile for the adapter",
                                                {
                                                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Profile version"},
                                                    {"family", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof family label"},
                                                    {"proof_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof or receipt type label"},
                                                    {"claim_system", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII public-output or claim-schema label"},
                                                }},
                                            {"claim_kind", RPCArg::Type::STR, RPCArg::Optional::NO, "batch_tuple_v1, settlement_metadata_v1, or data_root_tuple_v1"},
                                        }},
                                    {"proof_artifact_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof artifact used to derive proof_system_id and verifier_key_hash"},
                                    {"proof_artifact", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline bridge proof artifact used to derive proof_system_id and verifier_key_hash",
                                        {
                                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Artifact version"},
                                            {"proof_adapter_name", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Built-in proof adapter name"},
                                            {"proof_adapter_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof adapter"},
                                            {"statement_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the committed bridge batch statement"},
                                            {"verifier_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the verifier key, image ID, or program identifier"},
                                            {"public_values_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the canonical public values or claim digest"},
                                            {"proof_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Commitment to the proof/seal payload"},
                                            {"artifact_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Commitment to the full imported artifact bundle"},
                                            {"proof_size_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Proof or seal payload size in bytes"},
                                            {"public_values_size_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Public-values, journal, or tuple payload size in bytes"},
                                            {"auxiliary_data_size_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Additional sidecar or proof-query metadata bytes kept off-chain"},
                                        }},
                                    {"verifier_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hashed verifier key, program id, or image id; omitted when proof_artifact_* is provided"},
                                }},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical proof-policy commitment",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildproofpolicy",
                           "'[{\"proof_adapter_name\":\"sp1-groth16-settlement-metadata-v1\",\"verifier_key_hash\":\"0b\"}]' "
                           "'{\"required_receipts\":1,\"targets\":[{\"proof_adapter_name\":\"sp1-groth16-settlement-metadata-v1\",\"verifier_key_hash\":\"0b\"}]}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto descriptors = ParseBridgeProofDescriptorArrayOrThrow(request.params[0], "descriptors");
            const UniValue& options = request.params[1];
            const UniValue& required_receipts_value = FindValue(options, "required_receipts");
            if (required_receipts_value.isNull()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "options.required_receipts is required");
            }
            const int64_t required_receipts = required_receipts_value.getInt<int64_t>();
            if (required_receipts <= 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "options.required_receipts must be a positive integer");
            }

            const auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(descriptors, static_cast<size_t>(required_receipts));
            if (!proof_policy.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "failed to build proof_policy commitment from the supplied descriptors and required_receipts");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("proof_policy", BridgeProofPolicyCommitmentToUniValue(*proof_policy));
            UniValue descriptor_array(UniValue::VARR);
            for (const auto& descriptor : descriptors) {
                descriptor_array.push_back(BridgeProofDescriptorToUniValue(descriptor));
            }
            out.pushKV("descriptors", std::move(descriptor_array));

            const UniValue& targets_value = FindValue(options, "targets");
            if (!targets_value.isNull()) {
                const auto targets = ParseBridgeProofDescriptorArrayOrThrow(targets_value, "options.targets");
                UniValue proof_array(UniValue::VARR);
                for (size_t i = 0; i < targets.size(); ++i) {
                    const auto proof = shielded::BuildBridgeProofPolicyProof(descriptors, targets[i]);
                    if (!proof.has_value() || !shielded::VerifyBridgeProofPolicyProof(*proof_policy, targets[i], *proof)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                                           strprintf("failed to build proof-policy proof for options.targets[%u]", i));
                    }
                    UniValue entry(UniValue::VOBJ);
                    entry.pushKV("descriptor", BridgeProofDescriptorToUniValue(targets[i]));
                    entry.pushKV("proof", BridgeProofPolicyProofToUniValue(*proof));
                    entry.pushKV("proof_hex", EncodeBridgeProofPolicyProofHex(*proof));
                    proof_array.push_back(std::move(entry));
                }
                out.pushKV("proofs", std::move(proof_array));
            }
            return out;
        }};
}

RPCHelpMan bridge_buildbatchstatement()
{
    return RPCHelpMan{
        "bridge_buildbatchstatement",
        "\nBuild a canonical pre-anchor batch statement for committee/prover receipts over an aggregated batch.\n",
        {
            {"direction", RPCArg::Type::STR, RPCArg::Optional::NO, "bridge_in or bridge_out"},
            {"leaves", RPCArg::Type::ARR, RPCArg::Optional::NO, "Canonical batch leaves or signed authorizations",
                {
                    {"leaf", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One batch entry",
                        {
                            {"kind", RPCArg::Type::STR, RPCArg::Optional::NO, "shield_credit, transparent_payout, or shielded_payout"},
                            {"wallet_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Source wallet/account identifier hash"},
                            {"destination_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Destination identifier hash"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Leaf amount"},
                            {"authorization_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the off-chain user authorization bundle"},
                            {"authorization_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Signed bridge batch authorization; if set, the leaf fields are ignored and derived from the signed authorization"},
                        }},
                }},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Batch statement metadata",
                {
                    {"bridge_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge instance id"},
                    {"operation_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge operation id"},
                    {"external_statement", RPCArg::Type::OBJ, RPCArg::Optional::NO, "External DA/proof preimage bound by the statement",
                        {
                            {"domain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed identifier for the external domain, namespace, bridge cluster, or proving domain"},
                            {"source_epoch", RPCArg::Type::NUM, RPCArg::Optional::NO, "Positive external batch / epoch / blob sequence number"},
                            {"data_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "External data-availability or batch-log root"},
                            {"verifier_set", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional committed verifier-set policy for committee-backed receipt sets",
                                {
                                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Commitment version"},
                                    {"attestor_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "Total number of attestors in the committed verifier set"},
                                    {"required_signers", RPCArg::Type::NUM, RPCArg::Optional::NO, "Minimum distinct attestors required"},
                                    {"attestor_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical Merkle root of the verifier-set public keys"},
                                }},
                            {"proof_policy", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional committed imported-proof policy for proof-backed receipt sets",
                                {
                                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Commitment version"},
                                    {"descriptor_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "Total number of allowed proof descriptors"},
                                    {"required_receipts", RPCArg::Type::NUM, RPCArg::Optional::NO, "Minimum number of distinct receipts required"},
                                    {"descriptor_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical Merkle root of the allowed proof descriptors"},
                                }},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical bridge batch statement",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildbatchstatement",
                           "\"bridge_out\" "
                           "'[{\"authorization_hex\":\"<authorization_hex>\"}]' "
                           "'{\"bridge_id\":\"0a\",\"operation_id\":\"0b\",\"external_statement\":{\"domain_id\":\"0c\",\"source_epoch\":7,\"data_root\":\"0d\",\"proof_policy\":{\"descriptor_count\":2,\"required_receipts\":1,\"descriptor_root\":\"0e\"}}}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForBridge(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const shielded::BridgeDirection direction = ParseBridgeDirectionOrThrow(request.params[0], "direction");
            const auto ids = ParseBridgePlanIdsOrThrow(request.params[2]);
            const auto entries = ParseBridgeBatchEntriesOrThrow(request.params[1],
                                                                NextBridgeLeafBuildHeight(*pwallet),
                                                                direction,
                                                                ids);
            const auto statement = BuildBridgeBatchStatementOrThrow(direction, entries.leaves, ids, request.params[2]);

            UniValue out(UniValue::VOBJ);
            out.pushKV("statement", BridgeBatchStatementToUniValue(statement));
            out.pushKV("statement_hex", EncodeBridgeBatchStatementHex(statement));
            out.pushKV("statement_hash", shielded::ComputeBridgeBatchStatementHash(statement).GetHex());
            UniValue leaf_array(UniValue::VARR);
            for (const auto& leaf : entries.leaves) {
                leaf_array.push_back(BridgeBatchLeafToUniValue(leaf));
            }
            out.pushKV("leaves", std::move(leaf_array));
            if (!entries.authorizations.empty()) {
                UniValue authorization_array(UniValue::VARR);
                for (const auto& authorization : entries.authorizations) {
                    UniValue entry(UniValue::VOBJ);
                    entry.pushKV("authorization", BridgeBatchAuthorizationToUniValue(authorization));
                    entry.pushKV("authorization_hex", EncodeBridgeBatchAuthorizationHex(authorization));
                    entry.pushKV("authorization_hash", shielded::ComputeBridgeBatchAuthorizationHash(authorization).GetHex());
                    authorization_array.push_back(std::move(entry));
                }
                out.pushKV("authorizations", std::move(authorization_array));
            }
            return out;
        }};
}

RPCHelpMan bridge_signbatchreceipt()
{
    return RPCHelpMan{
        "bridge_signbatchreceipt",
        "\nSign a canonical bridge batch statement with a wallet-owned P2MR PQ key to produce a committee/prover receipt.\n",
        {
            {"attestor_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Wallet-owned P2MR address whose PQ key should sign the batch statement"},
            {"statement_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded canonical bridge batch statement"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Signing options",
                {
                    {"algorithm", RPCArg::Type::STR, RPCArg::Default{"ml-dsa-44"}, "PQ algorithm to use for attestor_address"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Signed bridge batch receipt",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_signbatchreceipt",
                           "\"btx1...\" \"<statement_hex>\" '{\"algorithm\":\"ml-dsa-44\"}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForBridge(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const UniValue& options = request.params[2];
            const PQAlgorithm algo = FindValue(options, "algorithm").isNull()
                ? PQAlgorithm::ML_DSA_44
                : ParseBridgeAlgoOrThrow(FindValue(options, "algorithm"), "options.algorithm");
            const auto signing_key = GetWalletBridgeSigningKeyOrThrow(pwallet, request.params[0].get_str(), algo);
            const auto statement = DecodeBridgeBatchStatementOrThrow(request.params[1]);

            shielded::BridgeBatchReceipt receipt;
            receipt.statement = statement;
            receipt.attestor = signing_key.spec;
            const uint256 receipt_hash = shielded::ComputeBridgeBatchReceiptHash(receipt);
            if (receipt_hash.IsNull()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to compute bridge batch receipt hash");
            }
            if (!signing_key.key.Sign(receipt_hash, receipt.signature) || !receipt.IsValid()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign bridge batch receipt");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("attestor_address", signing_key.address);
            out.pushKV("statement", BridgeBatchStatementToUniValue(statement));
            out.pushKV("statement_hex", EncodeBridgeBatchStatementHex(statement));
            out.pushKV("statement_hash", shielded::ComputeBridgeBatchStatementHash(statement).GetHex());
            out.pushKV("receipt", BridgeBatchReceiptToUniValue(receipt));
            out.pushKV("receipt_hex", EncodeBridgeBatchReceiptHex(receipt));
            out.pushKV("receipt_message_hex", HexStr(shielded::SerializeBridgeBatchReceiptMessage(receipt)));
            out.pushKV("receipt_hash", receipt_hash.GetHex());
            out.pushKV("verified", true);
            return out;
        }};
}

RPCHelpMan bridge_decodebatchreceipt()
{
    return RPCHelpMan{
        "bridge_decodebatchreceipt",
        "\nDecode a signed bridge batch receipt and return the canonical statement hash plus attestor envelope.\n",
        {
            {"receipt_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded signed bridge batch receipt"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Decoded bridge batch receipt",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_decodebatchreceipt", "\"<receipt_hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto receipt = DecodeBridgeBatchReceiptOrThrow(request.params[0]);
            UniValue out(UniValue::VOBJ);
            out.pushKV("statement", BridgeBatchStatementToUniValue(receipt.statement));
            out.pushKV("statement_hex", EncodeBridgeBatchStatementHex(receipt.statement));
            out.pushKV("statement_hash", shielded::ComputeBridgeBatchStatementHash(receipt.statement).GetHex());
            out.pushKV("receipt", BridgeBatchReceiptToUniValue(receipt));
            out.pushKV("receipt_hex", EncodeBridgeBatchReceiptHex(receipt));
            out.pushKV("receipt_message_hex", HexStr(shielded::SerializeBridgeBatchReceiptMessage(receipt)));
            out.pushKV("receipt_hash", shielded::ComputeBridgeBatchReceiptHash(receipt).GetHex());
            out.pushKV("verified", true);
            return out;
        }};
}

RPCHelpMan bridge_buildproofreceipt()
{
    return RPCHelpMan{
        "bridge_buildproofreceipt",
        "\nBuild a canonical imported-proof receipt summary for a bridge batch statement.\n",
        {
            {"statement_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded canonical bridge batch statement"},
            {"proof_receipt", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Imported proof receipt summary",
                {
                    {"proof_system_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hashed proof-system or receipt-family identifier"},
                    {"proof_profile_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof profile used to derive proof_system_id"},
                    {"proof_profile", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline bridge proof profile used to derive proof_system_id",
                        {
                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Profile version"},
                            {"family", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof family label"},
                            {"proof_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof or receipt type label"},
                            {"claim_system", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII public-output or claim-schema label"},
                        }},
                    {"proof_adapter_name", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Built-in proof adapter name; if set, proof_system_id and public_values_hash are both derived from the adapter and statement"},
                    {"proof_adapter_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof adapter; if set, proof_system_id and public_values_hash are both derived from the adapter and statement"},
                    {"proof_adapter", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline bridge proof adapter; if set, proof_system_id and public_values_hash are both derived from the adapter and statement",
                        {
                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Adapter version"},
                            {"proof_profile_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof profile for the adapter"},
                            {"proof_profile", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline bridge proof profile for the adapter",
                                {
                                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Profile version"},
                                    {"family", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof family label"},
                                    {"proof_type", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII proof or receipt type label"},
                                    {"claim_system", RPCArg::Type::STR, RPCArg::Optional::NO, "Lowercase ASCII public-output or claim-schema label"},
                                }},
                            {"claim_kind", RPCArg::Type::STR, RPCArg::Optional::NO, "batch_tuple_v1, settlement_metadata_v1, or data_root_tuple_v1"},
                        }},
                    {"proof_artifact_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof artifact; if set, the descriptor and receipt fields are derived from the artifact"},
                    {"proof_artifact", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline bridge proof artifact; if set, the descriptor and receipt fields are derived from the artifact",
                        {
                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Artifact version"},
                            {"proof_adapter_name", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Built-in proof adapter name"},
                            {"proof_adapter_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded bridge proof adapter"},
                            {"statement_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the committed bridge batch statement"},
                            {"verifier_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the verifier key, image ID, or program identifier"},
                            {"public_values_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the canonical public values or claim digest"},
                            {"proof_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Commitment to the proof/seal payload"},
                            {"artifact_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Commitment to the full imported artifact bundle"},
                            {"proof_size_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Proof or seal payload size in bytes"},
                            {"public_values_size_bytes", RPCArg::Type::NUM, RPCArg::Optional::NO, "Public-values, journal, or tuple payload size in bytes"},
                            {"auxiliary_data_size_bytes", RPCArg::Type::NUM, RPCArg::Default{0}, "Additional sidecar or proof-query metadata bytes kept off-chain"},
                        }},
                    {"verifier_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hash of the verifier key, image ID, or program identifier; omitted when proof_artifact_* is provided"},
                    {"public_values_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Low-level hash of public values, journal output, or claim digest"},
                    {"claim_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Hex-encoded canonical bridge proof claim used to derive public_values_hash"},
                    {"claim", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Inline canonical bridge proof claim used to derive public_values_hash",
                        {
                            {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Claim version"},
                            {"kind", RPCArg::Type::STR, RPCArg::Optional::NO, "batch_tuple_v1, settlement_metadata_v1, or data_root_tuple_v1"},
                            {"statement_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the committed bridge batch statement"},
                            {"direction", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "bridge_in or bridge_out; required for batch_tuple_v1 and settlement_metadata_v1"},
                            {"ids", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Bridge batch ids; required for batch_tuple_v1 and settlement_metadata_v1",
                                {
                                    {"bridge_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge instance id"},
                                    {"operation_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge operation id"},
                                }},
                            {"entry_count", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Batch entry count; required for batch_tuple_v1 and settlement_metadata_v1"},
                            {"total_amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "Batch total amount; required for batch_tuple_v1 and settlement_metadata_v1"},
                            {"batch_root", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Canonical batch root; required for batch_tuple_v1 and settlement_metadata_v1"},
                            {"domain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "External domain id; required for settlement_metadata_v1 and data_root_tuple_v1"},
                            {"source_epoch", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "External source epoch; required for settlement_metadata_v1 and data_root_tuple_v1"},
                            {"data_root", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "External data root; required for settlement_metadata_v1 and data_root_tuple_v1"},
                        }},
                    {"proof_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Commitment to the proof/seal/receipt artifact or recursive bundle; omitted when proof_artifact_* is provided"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical bridge proof receipt",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildproofreceipt",
                           "\"<statement_hex>\" "
                           "'{\"proof_artifact_hex\":\"<proof_artifact_hex>\"}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto statement = DecodeBridgeBatchStatementOrThrow(request.params[0]);
            const auto receipt = BuildBridgeProofReceiptOrThrow(statement, request.params[1]);

            UniValue out(UniValue::VOBJ);
            out.pushKV("statement", BridgeBatchStatementToUniValue(statement));
            out.pushKV("statement_hex", EncodeBridgeBatchStatementHex(statement));
            out.pushKV("statement_hash", shielded::ComputeBridgeBatchStatementHash(statement).GetHex());
            out.pushKV("proof_receipt", BridgeProofReceiptToUniValue(receipt));
            out.pushKV("proof_receipt_hex", EncodeBridgeProofReceiptHex(receipt));
            out.pushKV("proof_receipt_hash", shielded::ComputeBridgeProofReceiptHash(receipt).GetHex());
            out.pushKV("proof_receipt_leaf_hash", shielded::ComputeBridgeProofReceiptLeafHash(receipt).GetHex());
            return out;
        }};
}

RPCHelpMan bridge_buildingressstatement()
{
    return RPCHelpMan{
        "bridge_buildingressstatement",
        "\nBuild a canonical `v2_ingress_batch` bridge batch statement from shield-credit ingress intents.\n",
        {
            {"intents", RPCArg::Type::ARR, RPCArg::Optional::NO, "Ingress intents",
                {
                    {"intent", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One shield-credit ingress intent",
                        {
                            {"wallet_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge wallet/account identifier"},
                            {"destination_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "External destination identifier"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Shield-credit amount"},
                            {"authorization_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Authorization or admission hash"},
                            {"l2_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "External L2 or rollup identifier"},
                            {"fee", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Per-intent batch fee charged inside the native batch proof"},
                        }},
                }},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Ingress statement metadata",
                {
                    {"bridge_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge instance id"},
                    {"operation_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge operation id"},
                    {"external_statement", RPCArg::Type::OBJ, RPCArg::Optional::NO, "External DA/proof preimage bound by the statement",
                        {
                            {"domain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed identifier for the external domain, namespace, bridge cluster, or proving domain"},
                            {"source_epoch", RPCArg::Type::NUM, RPCArg::Optional::NO, "Positive external batch / epoch / blob sequence number"},
                            {"data_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "External data-availability or batch-log root"},
                            {"verifier_set", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional committed verifier-set policy",
                                {
                                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Commitment version"},
                                    {"attestor_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "Total number of attestors in the committed verifier set"},
                                    {"required_signers", RPCArg::Type::NUM, RPCArg::Optional::NO, "Minimum distinct attestors required"},
                                    {"attestor_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical Merkle root of the verifier-set public keys"},
                                }},
                            {"proof_policy", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional committed imported-proof policy",
                                {
                                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Commitment version"},
                                    {"descriptor_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "Total number of allowed proof descriptors"},
                                    {"required_receipts", RPCArg::Type::NUM, RPCArg::Optional::NO, "Minimum number of distinct receipts required"},
                                    {"descriptor_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical Merkle root of the allowed proof descriptors"},
                                }},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical ingress statement",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildingressstatement",
                           "'[{\"wallet_id\":\"0a\",\"destination_id\":\"0b\",\"amount\":1.0,\"authorization_hash\":\"0c\",\"l2_id\":\"0d\",\"fee\":0.01}]' "
                           "'{\"bridge_id\":\"0e\",\"operation_id\":\"0f\",\"external_statement\":{\"domain_id\":\"10\",\"source_epoch\":7,\"data_root\":\"11\",\"proof_policy\":{\"descriptor_count\":1,\"required_receipts\":1,\"descriptor_root\":\"12\"}}}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const auto intents = ParseV2IngressLeafInputsOrThrow(request.params[0], "intents");
            const auto statement = BuildV2IngressStatementOrThrow(intents, request.params[1]);

            UniValue out(UniValue::VOBJ);
            out.pushKV("statement", BridgeBatchStatementToUniValue(statement));
            out.pushKV("statement_hex", EncodeBridgeBatchStatementHex(statement));
            out.pushKV("statement_hash", shielded::ComputeBridgeBatchStatementHash(statement).GetHex());

            UniValue intent_array(UniValue::VARR);
            for (const auto& intent : intents) {
                intent_array.push_back(V2IngressLeafInputToUniValue(intent));
            }
            out.pushKV("intents", std::move(intent_array));
            return out;
        }};
}

RPCHelpMan bridge_buildingressbatchtx()
{
    return RPCHelpMan{
        "bridge_buildingressbatchtx",
        "\nBuild a deterministic wallet-side `v2_ingress_batch` transaction from shield-credit intents plus reserve outputs.\n",
        {
            {"statement_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded canonical bridge batch statement"},
            {"intents", RPCArg::Type::ARR, RPCArg::Optional::NO, "Ingress intents",
                {
                    {"intent", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One shield-credit ingress intent",
                        {
                            {"wallet_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge wallet/account identifier"},
                            {"destination_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "External destination identifier"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Shield-credit amount"},
                            {"authorization_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Authorization or admission hash"},
                            {"l2_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "External L2 or rollup identifier"},
                            {"fee", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Per-intent batch fee charged inside the native batch proof"},
                        }},
                }},
            {"reserve_outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Wallet-built reserve outputs",
                {
                    {"reserve_output", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One reserve note output",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Shielded reserve destination"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Reserve note amount"},
                        }},
                }},
            {"options", RPCArg::Type::OBJ, RPCArg::DefaultHint{"{}"}, "Optional settlement-witness validation overrides",
                {
                    {"receipts", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Signed bridge batch receipts used to validate a statement-bound verifier_set",
                        {
                            {"receipt_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded signed bridge batch receipt"},
                        }},
                    {"proof_receipts", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Imported proof receipts used to validate a statement-bound proof_policy",
                        {
                            {"proof_receipt_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge proof receipt"},
                        }},
                    {"receipt_policy", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional receipt-policy overrides",
                        {
                            {"min_receipts", RPCArg::Type::NUM, RPCArg::Default{1}, "Minimum number of signed receipts required"},
                            {"required_attestors", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Expected committee attestors that must appear in the receipt set",
                                {
                                    {"attestor", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Required attestor key",
                                        {
                                            {"algo", RPCArg::Type::STR, RPCArg::Optional::NO, "ml-dsa-44 or slh-dsa-shake-128s"},
                                            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "PQ public key bytes"},
                                        }},
                                }},
                            {"revealed_attestors", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Full verifier-set disclosure fallback",
                                {
                                    {"attestor", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One attestor key",
                                        {
                                            {"algo", RPCArg::Type::STR, RPCArg::Optional::NO, "ml-dsa-44 or slh-dsa-shake-128s"},
                                            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "PQ public key bytes"},
                                        }},
                                }},
                            {"attestor_proofs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Per-receipt verifier-set membership proofs",
                                {
                                    {"proof_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded verifier-set proof for the corresponding receipt attestor"},
                                }},
                        }},
                    {"proof_receipt_policy", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional imported-proof policy overrides",
                        {
                            {"min_receipts", RPCArg::Type::NUM, RPCArg::Default{1}, "Minimum number of proof receipts required"},
                            {"required_proof_system_ids", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Proof-system ids that must appear in the proof receipt set",
                                {
                                    {"proof_system_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed proof-system identifier"},
                                }},
                            {"required_verifier_key_hashes", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Verifier/program hashes that must appear in the proof receipt set",
                                {
                                    {"verifier_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed verifier key or image ID"},
                                }},
                            {"revealed_descriptors", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Full proof-policy disclosure fallback",
                                {
                                    {"descriptor", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One proof descriptor",
                                        {
                                            {"proof_system_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed proof-system identifier"},
                                            {"verifier_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed verifier key, program id, or image id"},
                                        }},
                                }},
                            {"descriptor_proofs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Per-receipt proof-policy membership proofs",
                                {
                                    {"proof_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded proof-policy proof for the corresponding receipt descriptor"},
                                }},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Built ingress transaction plus reserve-output preview metadata",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildingressbatchtx",
                           "\"<statement_hex>\" "
                           "'[{\"wallet_id\":\"0a\",\"destination_id\":\"0b\",\"amount\":1.0,\"authorization_hash\":\"0c\",\"l2_id\":\"0d\",\"fee\":0.01}]' "
                           "'[{\"address\":\"btxs1...\",\"amount\":0.5}]' "
                           "'{\"proof_receipts\":[\"<proof_receipt_hex>\"],\"proof_receipt_policy\":{\"min_receipts\":1}}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const auto statement = DecodeBridgeBatchStatementOrThrow(request.params[0]);
            if (statement.direction != shielded::BridgeDirection::BRIDGE_IN) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "statement_hex is not a bridge_in statement");
            }
            const auto intents = ParseV2IngressLeafInputsOrThrow(request.params[1], "intents");
            const auto reserve_outputs = ParseV2IngressReserveOutputsOrThrow(pwallet, request.params[2], "reserve_outputs");
            const UniValue& options = request.params[3];

            shielded::v2::V2IngressStatementTemplate statement_template;
            statement_template.ids = statement.ids;
            statement_template.domain_id = statement.domain_id;
            statement_template.source_epoch = statement.source_epoch;
            statement_template.data_root = statement.data_root;
            statement_template.verifier_set = statement.verifier_set;
            statement_template.proof_policy = statement.proof_policy;

            std::string reject_reason;
            const auto canonical_statement = shielded::v2::BuildV2IngressStatement(
                statement_template,
                Span<const shielded::v2::V2IngressLeafInput>{intents.data(), intents.size()},
                reject_reason);
            if (!canonical_statement.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   strprintf("statement/intents mismatch: %s", reject_reason));
            }
            if (shielded::ComputeBridgeBatchStatementHash(*canonical_statement) !=
                shielded::ComputeBridgeBatchStatementHash(statement)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "statement_hex does not match intents");
            }

            const auto settlement_summary = BuildIngressSettlementWitnessSummaryOrThrow(statement, options);
            std::optional<shielded::v2::V2IngressSettlementWitness> settlement_witness;
            if ((statement.verifier_set.IsValid() || statement.proof_policy.IsValid()) &&
                (!settlement_summary.receipts.empty() || !settlement_summary.proof_receipts.empty())) {
                shielded::v2::V2IngressSettlementWitness witness;
                witness.signed_receipts = settlement_summary.receipts;
                witness.signed_receipt_proofs = settlement_summary.signed_receipt_proofs;
                witness.proof_receipts = settlement_summary.proof_receipts;
                witness.proof_receipt_descriptor_proofs =
                    settlement_summary.proof_receipt_descriptor_proofs;
                if (!witness.IsValid()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Canonical ingress settlement witness is invalid");
                }
                settlement_witness = std::move(witness);
            }

            std::optional<CMutableTransaction> tx;
            std::string create_error;
            {
                LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
                tx = pwallet->m_shielded_wallet->CreateV2IngressBatch(
                    statement,
                    intents,
                    reserve_outputs,
                    std::move(settlement_witness),
                    &create_error);
            }
            if (!tx.has_value()) {
                throw JSONRPCError(
                    RPC_WALLET_ERROR,
                    create_error.empty() ? "Failed to construct v2_ingress_batch transaction" : create_error);
            }

            const CTransaction immutable_tx{*tx};
            const auto* v2_bundle = immutable_tx.GetShieldedBundle().GetV2Bundle();
            if (v2_bundle == nullptr ||
                !shielded::v2::BundleHasSemanticFamily(*v2_bundle,
                                                       shielded::v2::TransactionFamily::V2_INGRESS_BATCH)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Constructed transaction is missing a valid v2_ingress_batch bundle");
            }

            const auto& payload = std::get<shielded::v2::IngressBatchPayload>(v2_bundle->payload);
            std::vector<ShieldedTxViewOutput> output_views;
            output_views.reserve(payload.reserve_outputs.size());
            for (const auto& output : payload.reserve_outputs) {
                AppendShieldedOutputView(pwallet,
                                         output.note_commitment,
                                         output.encrypted_note,
                                         output_views);
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("txid", immutable_tx.GetHash().GetHex());
            PushShieldedBundleFamily(out, immutable_tx.GetShieldedBundle(), RedactSensitiveShieldedRpcFields(*pwallet, /*include_sensitive=*/false));
            out.pushKV("tx_hex", EncodeHexTx(immutable_tx));
            out.pushKV("statement", BridgeBatchStatementToUniValue(statement));
            out.pushKV("statement_hex", EncodeBridgeBatchStatementHex(statement));
            out.pushKV("statement_hash", shielded::ComputeBridgeBatchStatementHash(statement).GetHex());

            UniValue intent_array(UniValue::VARR);
            for (const auto& intent : intents) {
                intent_array.push_back(V2IngressLeafInputToUniValue(intent));
            }
            out.pushKV("intents", std::move(intent_array));

            UniValue reserve_array(UniValue::VARR);
            for (const auto& [addr, amount] : reserve_outputs) {
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("address", addr.Encode());
                entry.pushKV("amount", ValueFromAmount(amount));
                reserve_array.push_back(std::move(entry));
            }
            out.pushKV("reserve_outputs", std::move(reserve_array));

            if (settlement_summary.external_anchor.has_value()) {
                out.pushKV("external_anchor", BridgeExternalAnchorToUniValue(*settlement_summary.external_anchor));
            }
            if (settlement_summary.verification_bundle.has_value()) {
                out.pushKV("verification_bundle", BridgeVerificationBundleToUniValue(*settlement_summary.verification_bundle));
                out.pushKV("verification_bundle_hash",
                           shielded::ComputeBridgeVerificationBundleHash(*settlement_summary.verification_bundle).GetHex());
            }
            if (settlement_summary.receipt_summary.has_value()) {
                out.pushKV("receipt_count", static_cast<uint64_t>(settlement_summary.receipts.size()));
                out.pushKV("distinct_attestor_count",
                           static_cast<uint64_t>(settlement_summary.receipt_summary->distinct_attestor_count));
            }
            if (settlement_summary.proof_summary.has_value()) {
                out.pushKV("proof_receipt_count", static_cast<uint64_t>(settlement_summary.proof_receipts.size()));
                out.pushKV("distinct_proof_receipt_count",
                           static_cast<uint64_t>(settlement_summary.proof_summary->distinct_receipt_count));
            }

            UniValue outputs(UniValue::VARR);
            for (const auto& output : output_views) {
                outputs.push_back(ShieldedTxViewOutputToJSON(output));
            }
            out.pushKV("outputs", std::move(outputs));
            out.pushKV("output_chunks", UniValue(UniValue::VARR));
            out.pushKV("value_balance", ValueFromAmount(GetShieldedStateValueBalance(immutable_tx.GetShieldedBundle())));
            return out;
        }};
}

RPCHelpMan bridge_buildegressstatement()
{
    return RPCHelpMan{
        "bridge_buildegressstatement",
        "\nBuild a canonical `v2_egress_batch` bridge batch statement from deterministic shielded recipients.\n",
        {
            {"recipients", RPCArg::Type::ARR, RPCArg::Optional::NO, "Shielded batch recipients",
                {
                    {"recipient", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One shielded output",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Shielded recipient address"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Shielded recipient amount"},
                        }},
                }},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Egress statement metadata",
                {
                    {"bridge_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge instance id"},
                    {"operation_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge operation id"},
                    {"external_statement", RPCArg::Type::OBJ, RPCArg::Optional::NO, "External DA/proof preimage bound by the statement",
                        {
                            {"domain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed identifier for the external domain, namespace, bridge cluster, or proving domain"},
                            {"source_epoch", RPCArg::Type::NUM, RPCArg::Optional::NO, "Positive external batch / epoch / blob sequence number"},
                            {"data_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "External data-availability or batch-log root"},
                            {"verifier_set", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional committed verifier-set policy",
                                {
                                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Commitment version"},
                                    {"attestor_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "Total number of attestors in the committed verifier set"},
                                    {"required_signers", RPCArg::Type::NUM, RPCArg::Optional::NO, "Minimum distinct attestors required"},
                                    {"attestor_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical Merkle root of the verifier-set public keys"},
                                }},
                            {"proof_policy", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional committed imported-proof policy",
                                {
                                    {"version", RPCArg::Type::NUM, RPCArg::Default{1}, "Commitment version"},
                                    {"descriptor_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "Total number of allowed proof descriptors"},
                                    {"required_receipts", RPCArg::Type::NUM, RPCArg::Optional::NO, "Minimum number of distinct receipts required"},
                                    {"descriptor_root", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Canonical Merkle root of the allowed proof descriptors"},
                                }},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical egress statement",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildegressstatement",
                           "'[{\"address\":\"btxs1...\",\"amount\":1.0}]' "
                           "'{\"bridge_id\":\"0a\",\"operation_id\":\"0b\",\"external_statement\":{\"domain_id\":\"0c\",\"source_epoch\":7,\"data_root\":\"0d\",\"proof_policy\":{\"descriptor_count\":1,\"required_receipts\":1,\"descriptor_root\":\"0e\"}}}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const auto recipients = ParseV2EgressRecipientsOrThrow(pwallet, request.params[0], "recipients");
            const auto statement = BuildV2EgressStatementOrThrow(recipients, request.params[1]);

            UniValue out(UniValue::VOBJ);
            out.pushKV("statement", BridgeBatchStatementToUniValue(statement));
            out.pushKV("statement_hex", EncodeBridgeBatchStatementHex(statement));
            out.pushKV("statement_hash", shielded::ComputeBridgeBatchStatementHash(statement).GetHex());

            UniValue recipient_array(UniValue::VARR);
            for (const auto& [addr, amount] : recipients) {
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("address", addr.Encode());
                entry.pushKV("amount", ValueFromAmount(amount));
                entry.pushKV("recipient_pk_hash", addr.pk_hash.GetHex());
                entry.pushKV("recipient_kem_pk_hash", addr.kem_pk_hash.GetHex());
                recipient_array.push_back(std::move(entry));
            }
            out.pushKV("recipients", std::move(recipient_array));
            return out;
        }};
}

RPCHelpMan bridge_buildegressbatchtx()
{
    return RPCHelpMan{
        "bridge_buildegressbatchtx",
        "\nBuild a deterministic wallet-side `v2_egress_batch` transaction from a receipt-backed statement.\n",
        {
            {"statement_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded canonical bridge batch statement"},
            {"descriptors", RPCArg::Type::ARR, RPCArg::Optional::NO, "Allowed proof descriptors",
                {
                    {"descriptor", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One proof descriptor",
                        {
                            {"proof_system_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed proof-system identifier"},
                            {"verifier_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed verifier key, program id, or image id"},
                        }},
                }},
            {"proof_receipts", RPCArg::Type::ARR, RPCArg::Optional::NO, "Imported proof receipts",
                {
                    {"proof_receipt_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge proof receipt"},
                }},
            {"recipients", RPCArg::Type::ARR, RPCArg::Optional::NO, "Shielded batch recipients",
                {
                    {"recipient", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One shielded output",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Shielded recipient address"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Shielded recipient amount"},
                        }},
                }},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Builder overrides",
                {
                    {"imported_descriptor_index", RPCArg::Type::NUM, RPCArg::Default{0}, "Descriptor index to bind into the imported settlement witness"},
                    {"imported_receipt_index", RPCArg::Type::NUM, RPCArg::Default{0}, "Proof-receipt index to bind into the imported settlement witness"},
                    {"output_chunk_sizes", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Optional canonical output chunk sizes",
                        {
                            {"output_count", RPCArg::Type::NUM, RPCArg::Optional::NO, "One positive chunk output count"},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Built egress transaction plus preview metadata",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildegressbatchtx",
                           "\"<statement_hex>\" "
                           "'[{\"proof_system_id\":\"0a\",\"verifier_key_hash\":\"0b\"}]' "
                           "'[\"<proof_receipt_hex>\"]' "
                           "'[{\"address\":\"btxs1...\",\"amount\":1.0}]' "
                           "'{\"output_chunk_sizes\":[1]}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForShielded(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const auto statement = DecodeBridgeBatchStatementOrThrow(request.params[0]);
            if (statement.direction != shielded::BridgeDirection::BRIDGE_OUT) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "statement_hex is not a bridge_out statement");
            }
            if (statement.verifier_set.IsValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "v2_egress_batch wallet construction currently supports proof-policy receipts only");
            }

            const auto descriptors = ParseBridgeProofDescriptorArrayOrThrow(request.params[1], "descriptors");
            const auto proof_receipts = ParseBridgeProofReceiptsOrThrow(request.params[2], statement);
            const auto recipients = ParseV2EgressRecipientsOrThrow(pwallet, request.params[3], "recipients");
            const UniValue& options = request.params[4];

            const UniValue& imported_descriptor_index_value = FindValue(options, "imported_descriptor_index");
            const UniValue& imported_receipt_index_value = FindValue(options, "imported_receipt_index");
            const int64_t imported_descriptor_index_raw = imported_descriptor_index_value.isNull()
                ? 0
                : imported_descriptor_index_value.getInt<int64_t>();
            const int64_t imported_receipt_index_raw = imported_receipt_index_value.isNull()
                ? 0
                : imported_receipt_index_value.getInt<int64_t>();
            if (imported_descriptor_index_raw < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "options.imported_descriptor_index must be non-negative");
            }
            if (imported_receipt_index_raw < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "options.imported_receipt_index must be non-negative");
            }
            const size_t imported_descriptor_index = static_cast<size_t>(imported_descriptor_index_raw);
            const size_t imported_receipt_index = static_cast<size_t>(imported_receipt_index_raw);
            if (imported_descriptor_index >= descriptors.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "options.imported_descriptor_index is out of range");
            }
            if (imported_receipt_index >= proof_receipts.size()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "options.imported_receipt_index is out of range");
            }

            const auto output_chunk_sizes = ParseV2EgressOutputChunkSizesOrThrow(
                FindValue(options, "output_chunk_sizes"),
                recipients.size(),
                "options.output_chunk_sizes");

            std::optional<CMutableTransaction> tx;
            std::string create_error;
            {
                LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
                tx = pwallet->m_shielded_wallet->CreateV2EgressBatch(statement,
                                                                     descriptors,
                                                                     descriptors[imported_descriptor_index],
                                                                     proof_receipts,
                                                                     proof_receipts[imported_receipt_index],
                                                                     recipients,
                                                                     output_chunk_sizes,
                                                                     &create_error);
            }
            if (!tx.has_value()) {
                throw JSONRPCError(
                    RPC_WALLET_ERROR,
                    create_error.empty() ? "Failed to construct v2_egress_batch transaction" : create_error);
            }

            const CTransaction immutable_tx{*tx};
            const auto* v2_bundle = immutable_tx.GetShieldedBundle().GetV2Bundle();
            if (v2_bundle == nullptr ||
                !shielded::v2::BundleHasSemanticFamily(*v2_bundle,
                                                       shielded::v2::TransactionFamily::V2_EGRESS_BATCH)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Constructed transaction is missing a valid v2_egress_batch bundle");
            }

            const auto& payload = std::get<shielded::v2::EgressBatchPayload>(v2_bundle->payload);
            std::vector<ShieldedTxViewOutput> output_views;
            output_views.reserve(payload.outputs.size());
            for (const auto& output : payload.outputs) {
                AppendShieldedOutputView(pwallet,
                                         output.note_commitment,
                                         output.encrypted_note,
                                         output_views);
            }

            std::vector<ShieldedTxViewOutputChunk> output_chunk_views;
            if (shielded::v2::TransactionBundleOutputChunksAreCanonical(*v2_bundle)) {
                if (!BuildOutputChunkViews(output_chunk_views,
                                           {v2_bundle->output_chunks.data(), v2_bundle->output_chunks.size()},
                                           {output_views.data(), output_views.size()})) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "Failed to summarize canonical output chunks");
                }
            } else {
                throw JSONRPCError(RPC_WALLET_ERROR, "Constructed transaction does not have canonical output chunks");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("txid", immutable_tx.GetHash().GetHex());
            PushShieldedBundleFamily(out, immutable_tx.GetShieldedBundle(), RedactSensitiveShieldedRpcFields(*pwallet, /*include_sensitive=*/false));
            out.pushKV("tx_hex", EncodeHexTx(immutable_tx));
            out.pushKV("statement", BridgeBatchStatementToUniValue(statement));
            out.pushKV("statement_hex", EncodeBridgeBatchStatementHex(statement));
            out.pushKV("statement_hash", shielded::ComputeBridgeBatchStatementHash(statement).GetHex());
            out.pushKV("descriptor_count", static_cast<uint64_t>(descriptors.size()));
            out.pushKV("proof_receipt_count", static_cast<uint64_t>(proof_receipts.size()));
            out.pushKV("imported_descriptor_index", static_cast<uint64_t>(imported_descriptor_index));
            out.pushKV("imported_receipt_index", static_cast<uint64_t>(imported_receipt_index));
            out.pushKV("imported_descriptor", BridgeProofDescriptorToUniValue(descriptors[imported_descriptor_index]));
            out.pushKV("imported_receipt", BridgeProofReceiptToUniValue(proof_receipts[imported_receipt_index]));
            out.pushKV("imported_receipt_hex", EncodeBridgeProofReceiptHex(proof_receipts[imported_receipt_index]));
            out.pushKV("imported_receipt_hash",
                       shielded::ComputeBridgeProofReceiptHash(proof_receipts[imported_receipt_index]).GetHex());

            UniValue recipient_array(UniValue::VARR);
            for (const auto& [addr, amount] : recipients) {
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("address", addr.Encode());
                entry.pushKV("amount", ValueFromAmount(amount));
                recipient_array.push_back(std::move(entry));
            }
            out.pushKV("recipients", std::move(recipient_array));

            UniValue outputs(UniValue::VARR);
            for (const auto& output : output_views) {
                outputs.push_back(ShieldedTxViewOutputToJSON(output));
            }
            out.pushKV("outputs", std::move(outputs));

            UniValue output_chunks(UniValue::VARR);
            for (const auto& chunk : output_chunk_views) {
                output_chunks.push_back(ShieldedTxViewOutputChunkToJSON(chunk));
            }
            out.pushKV("output_chunks", std::move(output_chunks));
            out.pushKV("value_balance", ValueFromAmount(GetShieldedStateValueBalance(immutable_tx.GetShieldedBundle())));
            return out;
        }};
}

RPCHelpMan bridge_decodeproofreceipt()
{
    return RPCHelpMan{
        "bridge_decodeproofreceipt",
        "\nDecode a canonical imported bridge proof receipt summary.\n",
        {
            {"proof_receipt_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge proof receipt"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Decoded bridge proof receipt",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_decodeproofreceipt", "\"<proof_receipt_hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto receipt = DecodeBridgeProofReceiptOrThrow(request.params[0]);
            UniValue out(UniValue::VOBJ);
            out.pushKV("proof_receipt", BridgeProofReceiptToUniValue(receipt));
            out.pushKV("proof_receipt_hex", EncodeBridgeProofReceiptHex(receipt));
            out.pushKV("proof_receipt_hash", shielded::ComputeBridgeProofReceiptHash(receipt).GetHex());
            out.pushKV("proof_receipt_leaf_hash", shielded::ComputeBridgeProofReceiptLeafHash(receipt).GetHex());
            out.pushKV("statement_hash", receipt.statement_hash.GetHex());
            return out;
        }};
}

RPCHelpMan bridge_buildproofanchor()
{
    return RPCHelpMan{
        "bridge_buildproofanchor",
        "\nVerify a set of imported proof receipts and derive the external anchor whose verification_root commits to them.\n",
        {
            {"statement_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded canonical bridge batch statement"},
            {"proof_receipts", RPCArg::Type::ARR, RPCArg::Optional::NO, "Imported bridge proof receipts",
                {
                    {"proof_receipt_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge proof receipt"},
                }},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Proof-receipt policy",
                {
                    {"min_receipts", RPCArg::Type::NUM, RPCArg::Default{1}, "Minimum number of proof receipts required"},
                    {"required_proof_system_ids", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Proof-system ids that must appear in the receipt set",
                        {
                            {"proof_system_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed proof-system identifier"},
                        }},
                    {"required_verifier_key_hashes", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Verifier-key or program hashes that must appear in the receipt set",
                        {
                            {"verifier_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed verifier key or image ID"},
                        }},
                    {"revealed_descriptors", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Full descriptor-set disclosure used to validate a statement-bound proof_policy commitment",
                        {
                            {"descriptor", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One proof descriptor",
                                {
                                    {"proof_system_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed proof-system identifier"},
                                    {"verifier_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed verifier key, program id, or image id"},
                                }},
                        }},
                    {"descriptor_proofs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Per-receipt proof-policy membership proofs in receipt order",
                        {
                            {"proof_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded proof-policy proof for the corresponding receipt descriptor"},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Derived external anchor and decoded proof receipts",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildproofanchor",
                           "\"<statement_hex>\" '[\"<proof_receipt_hex>\",\"<proof_receipt_hex>\"]' "
                           "'{\"min_receipts\":1}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto statement = DecodeBridgeBatchStatementOrThrow(request.params[0]);
            if (statement.verifier_set.IsValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "statement also commits to verifier_set; use bridge_buildhybridanchor");
            }
            const auto receipts = ParseBridgeProofReceiptsOrThrow(request.params[1], statement);
            const auto policy = ParseBridgeProofReceiptPolicyOrThrow(request.params[2]);
            const auto summary = ValidateBridgeProofReceiptSetOrThrow(statement, receipts, policy);

            const auto anchor = shielded::BuildBridgeExternalAnchorFromProofReceipts(statement, receipts);
            if (!anchor.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "proof_receipts do not produce a valid external anchor");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("statement", BridgeBatchStatementToUniValue(statement));
            out.pushKV("statement_hex", EncodeBridgeBatchStatementHex(statement));
            out.pushKV("statement_hash", shielded::ComputeBridgeBatchStatementHash(statement).GetHex());
            out.pushKV("external_anchor", BridgeExternalAnchorToUniValue(*anchor));
            out.pushKV("receipt_count", static_cast<int64_t>(receipts.size()));
            out.pushKV("distinct_receipt_count", static_cast<int64_t>(summary.distinct_receipt_count));
            if (statement.proof_policy.IsValid()) {
                out.pushKV("proof_policy", BridgeProofPolicyCommitmentToUniValue(statement.proof_policy));
            }
            UniValue receipt_array(UniValue::VARR);
            for (const auto& receipt : receipts) {
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("proof_receipt", BridgeProofReceiptToUniValue(receipt));
                entry.pushKV("proof_receipt_hex", EncodeBridgeProofReceiptHex(receipt));
                entry.pushKV("proof_receipt_hash", shielded::ComputeBridgeProofReceiptHash(receipt).GetHex());
                receipt_array.push_back(std::move(entry));
            }
            out.pushKV("proof_receipts", std::move(receipt_array));
            if (!policy.required_proof_system_ids.empty()) {
                UniValue ids(UniValue::VARR);
                for (const auto& proof_system_id : policy.required_proof_system_ids) {
                    ids.push_back(proof_system_id.GetHex());
                }
                out.pushKV("required_proof_system_ids", std::move(ids));
            }
            if (!policy.required_verifier_key_hashes.empty()) {
                UniValue verifier_keys(UniValue::VARR);
                for (const auto& verifier_key_hash : policy.required_verifier_key_hashes) {
                    verifier_keys.push_back(verifier_key_hash.GetHex());
                }
                out.pushKV("required_verifier_key_hashes", std::move(verifier_keys));
            }
            return out;
        }};
}

RPCHelpMan bridge_buildhybridanchor()
{
    return RPCHelpMan{
        "bridge_buildhybridanchor",
        "\nVerify both signed bridge batch receipts and imported proof receipts, then derive one external anchor whose verification_root commits to both witness sets.\n",
        {
            {"statement_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded canonical bridge batch statement"},
            {"receipts", RPCArg::Type::ARR, RPCArg::Optional::NO, "Signed bridge batch receipts",
                {
                    {"receipt_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded signed bridge batch receipt"},
                }},
            {"proof_receipts", RPCArg::Type::ARR, RPCArg::Optional::NO, "Imported bridge proof receipts",
                {
                    {"proof_receipt_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge proof receipt"},
                }},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Hybrid witness policy",
                {
                    {"receipt_policy", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional receipt-policy overrides",
                        {
                            {"min_receipts", RPCArg::Type::NUM, RPCArg::Default{1}, "Minimum number of signed receipts required"},
                            {"required_attestors", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Expected committee attestors that must appear in the receipt set",
                                {
                                    {"attestor", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Required attestor key",
                                        {
                                            {"algo", RPCArg::Type::STR, RPCArg::Optional::NO, "ml-dsa-44 or slh-dsa-shake-128s"},
                                            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "PQ public key bytes"},
                                        }},
                                }},
                            {"revealed_attestors", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Full verifier-set disclosure fallback",
                                {
                                    {"attestor", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One attestor key",
                                        {
                                            {"algo", RPCArg::Type::STR, RPCArg::Optional::NO, "ml-dsa-44 or slh-dsa-shake-128s"},
                                            {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "PQ public key bytes"},
                                        }},
                                }},
                            {"attestor_proofs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Per-receipt verifier-set membership proofs",
                                {
                                    {"proof_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded verifier-set proof for the corresponding receipt attestor"},
                                }},
                        }},
                    {"proof_receipt_policy", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional imported-proof policy overrides",
                        {
                            {"min_receipts", RPCArg::Type::NUM, RPCArg::Default{1}, "Minimum number of proof receipts required"},
                            {"required_proof_system_ids", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Proof-system ids that must appear in the proof receipt set",
                                {
                                    {"proof_system_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed proof-system identifier"},
                                }},
                            {"required_verifier_key_hashes", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Verifier/program hashes that must appear in the proof receipt set",
                                {
                                    {"verifier_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed verifier key or image ID"},
                                }},
                            {"revealed_descriptors", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Full proof-policy disclosure fallback",
                                {
                                    {"descriptor", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One proof descriptor",
                                        {
                                            {"proof_system_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed proof-system identifier"},
                                            {"verifier_key_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed verifier key, program id, or image id"},
                                        }},
                                }},
                            {"descriptor_proofs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Per-receipt proof-policy membership proofs",
                                {
                                    {"proof_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded proof-policy proof for the corresponding receipt descriptor"},
                                }},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Derived hybrid external anchor and decoded witness sets",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildhybridanchor",
                           "\"<statement_hex>\" '[\"<receipt_hex>\"]' '[\"<proof_receipt_hex>\"]' "
                           "'{\"receipt_policy\":{\"min_receipts\":1},\"proof_receipt_policy\":{\"min_receipts\":1}}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto statement = DecodeBridgeBatchStatementOrThrow(request.params[0]);
            if (!statement.verifier_set.IsValid() || !statement.proof_policy.IsValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "statement must commit to both verifier_set and proof_policy for hybrid anchoring");
            }

            const auto receipts = ParseBridgeBatchReceiptsOrThrow(request.params[1], statement);
            const auto proof_receipts = ParseBridgeProofReceiptsOrThrow(request.params[2], statement);
            const auto policies = ParseBridgeHybridAnchorPoliciesOrThrow(request.params[3]);
            const auto receipt_summary = ValidateBridgeBatchReceiptSetOrThrow(statement, receipts, policies.receipt_policy);
            const auto proof_summary = ValidateBridgeProofReceiptSetOrThrow(statement, proof_receipts, policies.proof_receipt_policy);

            const auto anchor = shielded::BuildBridgeExternalAnchorFromHybridWitness(statement, receipts, proof_receipts);
            if (!anchor.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "hybrid witness sets do not produce a valid external anchor");
            }

            shielded::BridgeVerificationBundle bundle;
            bundle.signed_receipt_root = shielded::ComputeBridgeBatchReceiptRoot(receipts);
            bundle.proof_receipt_root = shielded::ComputeBridgeProofReceiptRoot(proof_receipts);
            if (!bundle.IsValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "hybrid witness sets do not produce a valid verification bundle");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("statement", BridgeBatchStatementToUniValue(statement));
            out.pushKV("statement_hex", EncodeBridgeBatchStatementHex(statement));
            out.pushKV("statement_hash", shielded::ComputeBridgeBatchStatementHash(statement).GetHex());
            out.pushKV("external_anchor", BridgeExternalAnchorToUniValue(*anchor));
            out.pushKV("verification_bundle", BridgeVerificationBundleToUniValue(bundle));
            out.pushKV("verification_bundle_hash", shielded::ComputeBridgeVerificationBundleHash(bundle).GetHex());
            out.pushKV("receipt_count", static_cast<int64_t>(receipts.size()));
            out.pushKV("distinct_attestor_count", static_cast<int64_t>(receipt_summary.distinct_attestor_count));
            out.pushKV("proof_receipt_count", static_cast<int64_t>(proof_receipts.size()));
            out.pushKV("distinct_proof_receipt_count", static_cast<int64_t>(proof_summary.distinct_receipt_count));
            out.pushKV("verifier_set", BridgeVerifierSetCommitmentToUniValue(statement.verifier_set));
            out.pushKV("proof_policy", BridgeProofPolicyCommitmentToUniValue(statement.proof_policy));

            UniValue receipt_array(UniValue::VARR);
            for (const auto& receipt : receipts) {
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("receipt", BridgeBatchReceiptToUniValue(receipt));
                entry.pushKV("receipt_hex", EncodeBridgeBatchReceiptHex(receipt));
                entry.pushKV("receipt_hash", shielded::ComputeBridgeBatchReceiptHash(receipt).GetHex());
                receipt_array.push_back(std::move(entry));
            }
            out.pushKV("receipts", std::move(receipt_array));

            UniValue proof_receipt_array(UniValue::VARR);
            for (const auto& receipt : proof_receipts) {
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("proof_receipt", BridgeProofReceiptToUniValue(receipt));
                entry.pushKV("proof_receipt_hex", EncodeBridgeProofReceiptHex(receipt));
                entry.pushKV("proof_receipt_hash", shielded::ComputeBridgeProofReceiptHash(receipt).GetHex());
                proof_receipt_array.push_back(std::move(entry));
            }
            out.pushKV("proof_receipts", std::move(proof_receipt_array));
            return out;
        }};
}

RPCHelpMan bridge_buildexternalanchor()
{
    return RPCHelpMan{
        "bridge_buildexternalanchor",
        "\nVerify a set of signed bridge batch receipts and derive the external anchor whose verification_root commits to them.\n",
        {
            {"statement_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded canonical bridge batch statement"},
            {"receipts", RPCArg::Type::ARR, RPCArg::Optional::NO, "Signed bridge batch receipts",
                {
                    {"receipt_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded signed bridge batch receipt"},
                }},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Receipt-set policy",
                {
                    {"min_receipts", RPCArg::Type::NUM, RPCArg::Default{1}, "Minimum number of signed receipts required"},
                    {"required_attestors", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Expected committee/prover attestors that must appear in the receipt set",
                        {
                            {"attestor", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Required attestor key",
                                {
                                    {"algo", RPCArg::Type::STR, RPCArg::Optional::NO, "ml-dsa-44 or slh-dsa-shake-128s"},
                                    {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "PQ public key bytes"},
                                }},
                        }},
                    {"revealed_attestors", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Full verifier-set disclosure used to validate a statement-bound verifier_set commitment",
                        {
                            {"attestor", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One attestor key",
                                {
                                    {"algo", RPCArg::Type::STR, RPCArg::Optional::NO, "ml-dsa-44 or slh-dsa-shake-128s"},
                                    {"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "PQ public key bytes"},
                                }},
                        }},
                    {"attestor_proofs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Per-receipt verifier-set membership proofs in receipt order",
                        {
                            {"proof_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded verifier-set proof for the corresponding receipt attestor"},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Derived external anchor and decoded receipts",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildexternalanchor",
                           "\"<statement_hex>\" '[\"<receipt_hex>\",\"<receipt_hex>\"]' "
                           "'{\"min_receipts\":2}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto statement = DecodeBridgeBatchStatementOrThrow(request.params[0]);
            if (statement.proof_policy.IsValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "statement also commits to proof_policy; use bridge_buildhybridanchor");
            }
            const auto receipts = ParseBridgeBatchReceiptsOrThrow(request.params[1], statement);
            const auto policy = ParseBridgeBatchReceiptPolicyOrThrow(request.params[2]);
            const auto summary = ValidateBridgeBatchReceiptSetOrThrow(statement, receipts, policy);

            const auto anchor = shielded::BuildBridgeExternalAnchorFromStatement(statement, receipts);
            if (!anchor.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "receipts do not produce a valid external anchor");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("statement", BridgeBatchStatementToUniValue(statement));
            out.pushKV("statement_hex", EncodeBridgeBatchStatementHex(statement));
            out.pushKV("statement_hash", shielded::ComputeBridgeBatchStatementHash(statement).GetHex());
            out.pushKV("external_anchor", BridgeExternalAnchorToUniValue(*anchor));
            out.pushKV("receipt_count", static_cast<int64_t>(receipts.size()));
            out.pushKV("distinct_attestor_count", static_cast<int64_t>(summary.distinct_attestor_count));
            out.pushKV("required_attestor_count", static_cast<int64_t>(policy.required_attestors.size()));
            if (statement.verifier_set.IsValid()) {
                out.pushKV("verifier_set", BridgeVerifierSetCommitmentToUniValue(statement.verifier_set));
            }
            UniValue receipt_array(UniValue::VARR);
            for (const auto& receipt : receipts) {
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("receipt", BridgeBatchReceiptToUniValue(receipt));
                entry.pushKV("receipt_hex", EncodeBridgeBatchReceiptHex(receipt));
                entry.pushKV("receipt_hash", shielded::ComputeBridgeBatchReceiptHash(receipt).GetHex());
                receipt_array.push_back(std::move(entry));
            }
            out.pushKV("receipts", std::move(receipt_array));
            if (!policy.required_attestors.empty()) {
                UniValue required_attestors(UniValue::VARR);
                for (const auto& attestor : policy.required_attestors) {
                    required_attestors.push_back(BridgeKeyToUniValue(attestor));
                }
                out.pushKV("required_attestors", std::move(required_attestors));
            }
            return out;
        }};
}

RPCHelpMan bridge_signbatchauthorization()
{
    return RPCHelpMan{
        "bridge_signbatchauthorization",
        "\nSign a canonical bridge batch authorization with a wallet-owned P2MR PQ key.\n",
        {
            {"authorizer_address", RPCArg::Type::STR, RPCArg::Optional::NO, "Wallet-owned P2MR address whose PQ key should sign the authorization"},
            {"direction", RPCArg::Type::STR, RPCArg::Optional::NO, "bridge_in or bridge_out"},
            {"authorization", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Authorization body to sign",
                {
                    {"kind", RPCArg::Type::STR, RPCArg::Optional::NO, "shield_credit, transparent_payout, or shielded_payout"},
                    {"wallet_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Source wallet/account identifier hash"},
                    {"destination_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Destination identifier hash"},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Authorized amount"},
                    {"authorization_nonce", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Per-authorization nonce to distinguish repeated intents"},
                }},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Authorization domain options",
                {
                    {"bridge_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge instance id"},
                    {"operation_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge operation id"},
                    {"algorithm", RPCArg::Type::STR, RPCArg::Default{"ml-dsa-44"}, "PQ algorithm to use for authorizer_address"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Signed canonical bridge batch authorization",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_signbatchauthorization",
                           "\"btx1...\" \"bridge_out\" "
                           "'{\"kind\":\"transparent_payout\",\"wallet_id\":\"01\",\"destination_id\":\"02\",\"amount\":2,\"authorization_nonce\":\"03\"}' "
                           "'{\"bridge_id\":\"0a\",\"operation_id\":\"0b\"}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForBridge(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const UniValue& options = request.params[3];
            const PQAlgorithm algo = FindValue(options, "algorithm").isNull()
                ? PQAlgorithm::ML_DSA_44
                : ParseBridgeAlgoOrThrow(FindValue(options, "algorithm"), "options.algorithm");
            const auto signing_key = GetWalletBridgeSigningKeyOrThrow(pwallet, request.params[0].get_str(), algo);
            const shielded::BridgeDirection direction = ParseBridgeDirectionOrThrow(request.params[1], "direction");
            const shielded::BridgePlanIds ids = ParseBridgePlanIdsOrThrow(options);

            auto authorization = ParseBridgeBatchAuthorizationBodyOrThrow(request.params[2], direction, ids, signing_key.spec);
            const uint256 authorization_hash = shielded::ComputeBridgeBatchAuthorizationHash(authorization);
            if (authorization_hash.IsNull()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to compute bridge batch authorization hash");
            }
            if (!signing_key.key.Sign(authorization_hash, authorization.signature) || !authorization.IsValid()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign bridge batch authorization");
            }
            const auto leaf = shielded::BuildBridgeBatchLeafFromAuthorization(
                authorization,
                NextBridgeLeafBuildHeight(*pwallet));
            if (!leaf.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive bridge batch leaf from signed authorization");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("authorizer_address", signing_key.address);
            out.pushKV("authorization", BridgeBatchAuthorizationToUniValue(authorization));
            out.pushKV("authorization_hex", EncodeBridgeBatchAuthorizationHex(authorization));
            out.pushKV("authorization_message_hex", HexStr(shielded::SerializeBridgeBatchAuthorizationMessage(authorization)));
            out.pushKV("authorization_hash", authorization_hash.GetHex());
            out.pushKV("verified", true);
            out.pushKV("leaf", BridgeBatchLeafToUniValue(*leaf));
            return out;
        }};
}

RPCHelpMan bridge_decodebatchauthorization()
{
    return RPCHelpMan{
        "bridge_decodebatchauthorization",
        "\nDecode a signed bridge batch authorization and return the canonical authorization hash plus derived leaf.\n",
        {
            {"authorization_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded signed bridge batch authorization"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Decoded bridge batch authorization",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_decodebatchauthorization", "\"<authorization_hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForBridge(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const auto authorization = DecodeBridgeBatchAuthorizationOrThrow(request.params[0]);
            const auto leaf = shielded::BuildBridgeBatchLeafFromAuthorization(
                authorization,
                NextBridgeLeafBuildHeight(*pwallet));
            if (!leaf.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "authorization_hex does not derive a valid bridge batch leaf");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("authorization", BridgeBatchAuthorizationToUniValue(authorization));
            out.pushKV("authorization_hex", EncodeBridgeBatchAuthorizationHex(authorization));
            out.pushKV("authorization_message_hex", HexStr(shielded::SerializeBridgeBatchAuthorizationMessage(authorization)));
            out.pushKV("authorization_hash", shielded::ComputeBridgeBatchAuthorizationHash(authorization).GetHex());
            out.pushKV("verified", true);
            out.pushKV("leaf", BridgeBatchLeafToUniValue(*leaf));
            return out;
        }};
}

RPCHelpMan bridge_buildbatchcommitment()
{
    return RPCHelpMan{
        "bridge_buildbatchcommitment",
        "\nBuild a canonical bridge batch commitment from raw leaves and/or signed user authorizations.\n",
        {
            {"direction", RPCArg::Type::STR, RPCArg::Optional::NO, "bridge_in or bridge_out"},
            {"leaves", RPCArg::Type::ARR, RPCArg::Optional::NO, "Canonical batch leaves or signed authorizations",
                {
                    {"leaf", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One batch entry",
                        {
                            {"kind", RPCArg::Type::STR, RPCArg::Optional::NO, "shield_credit, transparent_payout, or shielded_payout"},
                            {"wallet_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Source wallet/account identifier hash"},
                            {"destination_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Destination identifier hash"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Leaf amount"},
                            {"authorization_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hash of the off-chain user authorization bundle"},
                            {"authorization_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Signed bridge batch authorization; if set, the leaf fields are ignored and derived from the signed authorization"},
                        }},
                }},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Batch commitment metadata",
                {
                    {"bridge_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge instance id"},
                    {"operation_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Bridge operation id"},
                    {"external_anchor", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional external DA/proof anchor for the aggregated batch",
                        {
                            {"domain_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hashed identifier for the external domain, namespace, bridge cluster, or proving domain"},
                            {"source_epoch", RPCArg::Type::NUM, RPCArg::Optional::NO, "Positive external batch / epoch / blob sequence number"},
                            {"data_root", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "External data-availability or batch-log root"},
                            {"verification_root", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "External proof receipt root, committee transcript root, or verification digest"},
                        }},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Canonical bridge batch commitment",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{
            HelpExampleCli("bridge_buildbatchcommitment",
                           "\"bridge_out\" "
                           "'[{\"kind\":\"transparent_payout\",\"wallet_id\":\"01\",\"destination_id\":\"02\",\"amount\":2,\"authorization_hash\":\"03\"}]' "
                           "'{\"bridge_id\":\"0a\",\"operation_id\":\"0b\"}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForBridge(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const shielded::BridgeDirection direction = ParseBridgeDirectionOrThrow(request.params[0], "direction");
            const auto ids = ParseBridgePlanIdsOrThrow(request.params[2]);
            const auto entries = ParseBridgeBatchEntriesOrThrow(request.params[1],
                                                                NextBridgeLeafBuildHeight(*pwallet),
                                                                direction,
                                                                ids);
            const auto& leaves = entries.leaves;
            const auto external_anchor = ParseBridgeExternalAnchorOrThrow(request.params[2]);
            const auto commitment = BuildBridgeBatchCommitmentOrThrow(direction, leaves, ids, external_anchor);

            UniValue out(UniValue::VOBJ);
            out.pushKV("commitment", BridgeBatchCommitmentToUniValue(commitment));
            out.pushKV("commitment_hex", EncodeBridgeBatchCommitmentHex(commitment));
            out.pushKV("commitment_hash", shielded::ComputeBridgeBatchCommitmentHash(commitment).GetHex());
            UniValue leaf_array(UniValue::VARR);
            for (const auto& leaf : leaves) {
                leaf_array.push_back(BridgeBatchLeafToUniValue(leaf));
            }
            out.pushKV("leaves", std::move(leaf_array));
            if (!entries.authorizations.empty()) {
                UniValue authorization_array(UniValue::VARR);
                for (const auto& authorization : entries.authorizations) {
                    UniValue entry(UniValue::VOBJ);
                    entry.pushKV("authorization", BridgeBatchAuthorizationToUniValue(authorization));
                    entry.pushKV("authorization_hex", EncodeBridgeBatchAuthorizationHex(authorization));
                    entry.pushKV("authorization_hash", shielded::ComputeBridgeBatchAuthorizationHash(authorization).GetHex());
                    authorization_array.push_back(std::move(entry));
                }
                out.pushKV("authorizations", std::move(authorization_array));
            }
            return out;
        }};
}

RPCHelpMan bridge_decodebatchcommitment()
{
    return RPCHelpMan{
        "bridge_decodebatchcommitment",
        "\nDecode canonical bridge batch commitment bytes and return the message body plus the CSFS-domain hash.\n",
        {
            {"batch_commitment_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded canonical bridge batch commitment"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Decoded bridge batch commitment",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_decodebatchcommitment", "\"<batch_commitment_hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            EnsureWalletForBridge(request)->BlockUntilSyncedToCurrentChain();

            const auto commitment = DecodeBridgeBatchCommitmentOrThrow(request.params[0]);
            UniValue out(UniValue::VOBJ);
            out.pushKV("commitment", BridgeBatchCommitmentToUniValue(commitment));
            out.pushKV("commitment_hex", EncodeBridgeBatchCommitmentHex(commitment));
            out.pushKV("commitment_hash", shielded::ComputeBridgeBatchCommitmentHash(commitment).GetHex());
            return out;
        }};
}

RPCHelpMan bridge_buildshieldtx()
{
    return RPCHelpMan{
        "bridge_buildshieldtx",
        "\nBuild a PSBT that settles a funded bridge-in output into the shielded pool using the plan's normal path.\n",
        {
            {"plan_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge plan"},
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Funding txid"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Funding output index"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Funding output amount"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional fee-headroom policy",
                {
                    {"min_fee_headroom_multiplier", RPCArg::Type::NUM, RPCArg::Default{2.0}, "Require or report at least this multiple of the current local mempool floor"},
                    {"enforce_fee_headroom", RPCArg::Type::BOOL, RPCArg::Default{false}, "Reject the PSBT if it does not meet min_fee_headroom_multiplier"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "PSBT plus selected bridge metadata",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_buildshieldtx", "\"<plan_hex>\" \"<txid>\" 0 5")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForBridge(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const BridgePlan plan = DecodeBridgePlanOrThrow(request.params[0]);
            if (plan.kind != shielded::BridgeTemplateKind::SHIELD) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "plan_hex is not a bridge-in shield plan");
            }

            const uint256 txid = ParseHashV(request.params[1], "txid");
            const int vout = request.params[2].getInt<int>();
            if (vout < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "vout must be non-negative");
            }
            const CAmount amount = AmountFromValue(request.params[3]);
            const int32_t build_height = NextBridgeLeafBuildHeight(*pwallet);
            const BridgeFeeHeadroomPolicy headroom_policy =
                ParseBridgeFeeHeadroomPolicy(request.params[4], /*default_enforce=*/false);
            const auto psbt = CreateBridgeShieldSettlementTransaction(plan,
                                                                      COutPoint{Txid::FromUint256(txid), static_cast<uint32_t>(vout)},
                                                                      amount,
                                                                      &Params().GetConsensus(),
                                                                      build_height);
            if (!psbt.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to construct bridge shield settlement PSBT");
            }

            const BridgePsbtRelayFeeAnalysis analysis = AnalyzeBridgePsbtRelayFee(*pwallet, *psbt);
            const BridgeFeeHeadroomAssessment headroom = EvaluateBridgeFeeHeadroom(analysis, headroom_policy);
            EnsureBridgeFeeHeadroomOrThrow(headroom, headroom_policy, "bridge_buildshieldtx");

            UniValue out = BridgePsbtMetadataToUniValue(*psbt);
            AppendBridgePsbtRelayFeeAnalysis(out, analysis, build_height, headroom_policy);
            out.pushKV("selected_path", "normal");
            out.pushKV("bridge_root", plan.script_tree.merkle_root.GetHex());
            out.pushKV("ctv_hash", plan.ctv_hash.GetHex());
            return out;
        }};
}

RPCHelpMan bridge_buildunshieldtx()
{
    return RPCHelpMan{
        "bridge_buildunshieldtx",
        "\nBuild a PSBT that settles a funded bridge-out output to the plan's transparent payout template using the normal path.\n",
        {
            {"plan_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge plan"},
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Funding txid"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Funding output index"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Funding output amount"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "PSBT plus selected bridge metadata",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_buildunshieldtx", "\"<plan_hex>\" \"<txid>\" 0 5")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForBridge(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const BridgePlan plan = DecodeBridgePlanOrThrow(request.params[0]);
            if (plan.kind != shielded::BridgeTemplateKind::UNSHIELD) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "plan_hex is not a bridge-out unshield plan");
            }

            const uint256 txid = ParseHashV(request.params[1], "txid");
            const int vout = request.params[2].getInt<int>();
            if (vout < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "vout must be non-negative");
            }
            const CAmount amount = AmountFromValue(request.params[3]);
            const int32_t build_height = NextBridgeLeafBuildHeight(*pwallet);
            const auto psbt = CreateBridgeUnshieldSettlementTransaction(plan,
                                                                        COutPoint{Txid::FromUint256(txid), static_cast<uint32_t>(vout)},
                                                                        amount,
                                                                        &Params().GetConsensus(),
                                                                        build_height);
            if (!psbt.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to construct bridge unshield settlement PSBT");
            }

            UniValue out = BridgePsbtMetadataToUniValue(*psbt);
            AppendBridgePsbtRelayFeeAnalysis(out,
                                             AnalyzeBridgePsbtRelayFee(*pwallet, *psbt),
                                             build_height);
            out.pushKV("selected_path", "normal");
            out.pushKV("bridge_root", plan.script_tree.merkle_root.GetHex());
            out.pushKV("ctv_hash", plan.ctv_hash.GetHex());
            return out;
        }};
}

RPCHelpMan bridge_submitrebalancetx()
{
    return RPCHelpMan{
        "bridge_submitrebalancetx",
        "\nBuild, sign, and broadcast a wallet-funded `v2_rebalance` transaction from canonical reserve deltas plus reserve note outputs.\n",
        {
            {"reserve_deltas", RPCArg::Type::ARR, RPCArg::Optional::NO, "Canonical reserve deltas; the set is sorted by l2_id and must sum to zero",
                {
                    {"reserve_delta", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One domain delta",
                        {
                            {"l2_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Settlement-domain identifier"},
                            {"reserve_delta", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Signed reserve delta for that domain"},
                        }},
                }},
            {"reserve_outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "Reserve note outputs to create (may be empty)",
                {
                    {"reserve_output", RPCArg::Type::OBJ, RPCArg::Optional::NO, "One reserve note output",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Shielded reserve destination"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Reserve note amount"},
                        }},
                }},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Rebalance manifest and fee overrides",
                {
                    {"settlement_window", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_V2_REBALANCE_SETTLEMENT_WINDOW}, "Positive settlement-window id to commit into the manifest"},
                    {"gross_flow_commitment", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional explicit gross-flow commitment; omitted values are derived deterministically from the request"},
                    {"authorization_digest", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional explicit operator authorization digest; omitted values are derived deterministically from the request"},
                    {"fee", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(10000)}, "Requested transparent fee carrier fee"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Submitted rebalance transaction metadata",
            {
                {RPCResult::Type::STR_HEX, "txid", "Submitted transaction id"},
                {RPCResult::Type::STR, "family", "The shielded transaction family"},
                {RPCResult::Type::STR_AMOUNT, "fee", "Applied fee"},
                {RPCResult::Type::NUM, "reserve_domain_count", "Committed reserve-domain count"},
                {RPCResult::Type::NUM, "reserve_output_count", "Committed reserve-output count"},
                {RPCResult::Type::NUM, "output_chunk_count", "Committed reserve-output chunk count"},
                {RPCResult::Type::STR_HEX, "netting_manifest_id", "Canonical netting-manifest id"},
                {RPCResult::Type::STR_HEX, "settlement_binding_digest", "Committed settlement binding digest"},
                {RPCResult::Type::STR_HEX, "batch_statement_digest", "Committed deterministic batch statement digest"},
            }},
        RPCExamples{
            HelpExampleCli("bridge_submitrebalancetx",
                           "'[{\"l2_id\":\"01\",\"reserve_delta\":7},{\"l2_id\":\"02\",\"reserve_delta\":-4},{\"l2_id\":\"03\",\"reserve_delta\":-3}]' "
                           "'[{\"address\":\"btxs1...\",\"amount\":3},{\"address\":\"btxs1...\",\"amount\":4}]' "
                           "'{\"settlement_window\":288}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForBridge(request);
            pwallet->BlockUntilSyncedToCurrentChain();
            EnsureWalletIsUnlocked(*pwallet);

            const auto reserve_deltas =
                ParseV2RebalanceReserveDeltasOrThrow(request.params[0], "reserve_deltas");
            const auto reserve_outputs =
                ParseV2RebalanceReserveOutputsOrThrow(pwallet, request.params[1], "reserve_outputs");
            const UniValue options = request.params[2].isNull() ? UniValue(UniValue::VOBJ) : request.params[2];
            if (!options.isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "options must be an object");
            }
            const auto netting_manifest =
                BuildV2RebalanceNettingManifestOrThrow(reserve_deltas, reserve_outputs, options);

            bool explicit_fee{false};
            CAmount fee{10000};
            const UniValue& fee_value = FindValue(options, "fee");
            if (!fee_value.isNull()) {
                explicit_fee = true;
                fee = AmountFromValue(fee_value);
                if (fee <= 0) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "options.fee must be positive");
                }
            }

            CAmount applied_fee{0};
            CTransactionRef tx;
            for (int attempt = 0; attempt < MAX_SHIELDED_FEE_CONVERGENCE_ATTEMPTS; ++attempt) {
                CAmount actual_fee_paid{0};
                std::optional<CMutableTransaction> mtx;
                std::string create_error;
                {
                    LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
                    mtx = pwallet->m_shielded_wallet->CreateV2Rebalance(reserve_deltas,
                                                                        reserve_outputs,
                                                                        netting_manifest,
                                                                        fee,
                                                                        actual_fee_paid,
                                                                        &create_error);
                }
                if (!mtx.has_value()) {
                    throw JSONRPCError(
                        RPC_WALLET_ERROR,
                        create_error.empty() ? "Failed to construct v2_rebalance transaction" : create_error);
                }

                CTransactionRef candidate = MakeTransactionRef(std::move(*mtx));
                const CAmount required_fee = RequiredMempoolFee(*pwallet, *candidate);
                if (actual_fee_paid >= required_fee) {
                    tx = std::move(candidate);
                    applied_fee = actual_fee_paid;
                    break;
                }

                if (explicit_fee) {
                    throw JSONRPCError(
                        RPC_WALLET_ERROR,
                        strprintf("Fee too low for transaction size. Required at least %s", FormatMoney(required_fee)));
                }

                fee = required_fee;
            }

            if (!tx) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to build fee-compliant v2_rebalance transaction");
            }

            CommitShieldedTransactionOrThrow(pwallet, tx);
            return RebalanceSubmitResultToUniValue(
                tx,
                applied_fee,
                RedactSensitiveShieldedRpcFields(*pwallet, /*include_sensitive=*/false));
        }};
}

RPCHelpMan bridge_submitshieldtx()
{
    return RPCHelpMan{
        "bridge_submitshieldtx",
        "\nSign, finalize, and broadcast a funded bridge-in settlement using the plan's normal path.\n"
        "Use bridge_buildshieldtx instead when an external signer or manual PSBT review is required.\n",
        {
            {"plan_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge plan"},
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Funding txid"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Funding output index"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Funding output amount"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Optional fee-headroom policy",
                {
                    {"min_fee_headroom_multiplier", RPCArg::Type::NUM, RPCArg::Default{2.0}, "Require at least this multiple of the current local mempool floor before broadcast"},
                    {"enforce_fee_headroom", RPCArg::Type::BOOL, RPCArg::Default{true}, "Reject broadcast if the settlement does not meet min_fee_headroom_multiplier"},
                }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Submitted bridge settlement metadata",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_submitshieldtx", "\"<plan_hex>\" \"<txid>\" 0 5")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForBridge(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const BridgePlan plan = DecodeBridgePlanOrThrow(request.params[0]);
            if (plan.kind != shielded::BridgeTemplateKind::SHIELD) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "plan_hex is not a bridge-in shield plan");
            }

            const uint256 txid = ParseHashV(request.params[1], "txid");
            const int vout = request.params[2].getInt<int>();
            if (vout < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "vout must be non-negative");
            }
            const CAmount amount = AmountFromValue(request.params[3]);
            const BridgeFeeHeadroomPolicy headroom_policy =
                ParseBridgeFeeHeadroomPolicy(request.params[4], /*default_enforce=*/true);
            const int32_t build_height = NextBridgeLeafBuildHeight(*pwallet);
            const auto psbt = CreateBridgeShieldSettlementTransaction(plan,
                                                                      COutPoint{Txid::FromUint256(txid), static_cast<uint32_t>(vout)},
                                                                      amount,
                                                                      &Params().GetConsensus(),
                                                                      build_height);
            if (!psbt.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to construct bridge shield settlement PSBT");
            }

            const BridgePsbtRelayFeeAnalysis analysis = AnalyzeBridgePsbtRelayFee(*pwallet, *psbt);
            const BridgeFeeHeadroomAssessment headroom = EvaluateBridgeFeeHeadroom(analysis, headroom_policy);
            EnsureBridgeFeeHeadroomOrThrow(headroom, headroom_policy, "bridge_submitshieldtx");

            const auto tx = FinalizeBridgePsbtWithWalletOrThrow(pwallet,
                                                                *psbt,
                                                                "bridge shield settlement PSBT");
            CommitShieldedTransactionOrThrow(pwallet, tx);
            UniValue out = BridgeSubmittedResultToUniValue(tx, plan, "normal");
            AppendBridgePsbtRelayFeeAnalysis(out, analysis, build_height, headroom_policy);
            return out;
        }};
}

RPCHelpMan bridge_submitunshieldtx()
{
    return RPCHelpMan{
        "bridge_submitunshieldtx",
        "\nSign, finalize, and broadcast a funded bridge-out settlement using the plan's normal path.\n"
        "Use bridge_buildunshieldtx instead when an external signer or manual PSBT review is required.\n",
        {
            {"plan_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge plan"},
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Funding txid"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Funding output index"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Funding output amount"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Submitted bridge settlement metadata",
            {
                {RPCResult::Type::STR_HEX, "txid", "Submitted transaction id"},
                {RPCResult::Type::NUM, "locktime", "Transaction locktime"},
                {RPCResult::Type::STR, "selected_path", "Bridge settlement path"},
                {RPCResult::Type::STR_HEX, "bridge_root", "Bridge P2MR merkle root"},
                {RPCResult::Type::STR_HEX, "ctv_hash", "Bridge template hash"},
            }},
        RPCExamples{HelpExampleCli("bridge_submitunshieldtx", "\"<plan_hex>\" \"<txid>\" 0 5")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForBridge(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const BridgePlan plan = DecodeBridgePlanOrThrow(request.params[0]);
            if (plan.kind != shielded::BridgeTemplateKind::UNSHIELD) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "plan_hex is not a bridge-out unshield plan");
            }

            const uint256 txid = ParseHashV(request.params[1], "txid");
            const int vout = request.params[2].getInt<int>();
            if (vout < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "vout must be non-negative");
            }
            const CAmount amount = AmountFromValue(request.params[3]);
            const auto psbt = CreateBridgeUnshieldSettlementTransaction(plan,
                                                                        COutPoint{Txid::FromUint256(txid), static_cast<uint32_t>(vout)},
                                                                        amount,
                                                                        &Params().GetConsensus(),
                                                                        NextBridgeLeafBuildHeight(*pwallet));
            if (!psbt.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to construct bridge unshield settlement PSBT");
            }

            const auto tx = FinalizeBridgePsbtWithWalletOrThrow(pwallet,
                                                                *psbt,
                                                                "bridge unshield settlement PSBT");
            CommitBridgeTransactionOrThrow(pwallet, tx);
            return BridgeSubmittedResultToUniValue(tx, plan, "normal");
        }};
}

RPCHelpMan bridge_buildrefund()
{
    return RPCHelpMan{
        "bridge_buildrefund",
        "\nBuild a refund-path PSBT for a bridge plan once the refund lock height is eligible.\n",
        {
            {"plan_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded bridge plan"},
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Funding txid"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "Funding output index"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Funding output amount"},
            {"destination", RPCArg::Type::STR, RPCArg::Optional::NO, "Refund destination address"},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Refund fee"},
            {"enforce_timeout", RPCArg::Type::BOOL, RPCArg::Default{true}, "Reject construction before the active chain reaches refund_lock_height"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Refund PSBT plus selected bridge metadata",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_buildrefund", "\"<plan_hex>\" \"<txid>\" 0 5 \"btxrt1...\" 0.0001")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForBridge(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const BridgePlan plan = DecodeBridgePlanOrThrow(request.params[0]);
            const bool enforce_timeout = ParseEnforceTimeoutFlag(request.params[6]);
            int current_height{0};
            {
                LOCK(pwallet->cs_wallet);
                current_height = pwallet->GetLastBlockHeight();
            }
            if (enforce_timeout && current_height < static_cast<int>(plan.refund_lock_height)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   strprintf("Refund path not yet eligible: current height %d, refund_lock_height %u",
                                             current_height,
                                             plan.refund_lock_height));
            }

            const uint256 txid = ParseHashV(request.params[1], "txid");
            const int vout = request.params[2].getInt<int>();
            if (vout < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "vout must be non-negative");
            }
            const CAmount amount = AmountFromValue(request.params[3]);
            const CTxDestination destination = ParseDestinationOrThrow(request.params[4], "destination");
            const CAmount fee = AmountFromValue(request.params[5]);

            const int32_t build_height = NextBridgeLeafBuildHeight(*pwallet);
            const auto psbt = CreateBridgeRefundTransaction(plan,
                                                            COutPoint{Txid::FromUint256(txid), static_cast<uint32_t>(vout)},
                                                            amount,
                                                            destination,
                                                            fee,
                                                            &Params().GetConsensus(),
                                                            build_height);
            if (!psbt.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to construct bridge refund PSBT");
            }

            UniValue out = BridgePsbtMetadataToUniValue(*psbt);
            AppendBridgePsbtRelayFeeAnalysis(out,
                                             AnalyzeBridgePsbtRelayFee(*pwallet, *psbt),
                                             build_height);
            out.pushKV("selected_path", "refund");
            out.pushKV("bridge_root", plan.script_tree.merkle_root.GetHex());
            out.pushKV("ctv_hash", plan.ctv_hash.GetHex());
            out.pushKV("refund_lock_height", static_cast<int64_t>(plan.refund_lock_height));
            out.pushKV("current_height", current_height);
            return out;
        }};
}

RPCHelpMan bridge_decodeattestation()
{
    return RPCHelpMan{
        "bridge_decodeattestation",
        "\nDecode canonical bridge attestation bytes and return the message body plus the CSFS-domain hash.\n",
        {
            {"attestation_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex-encoded canonical attestation bytes"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "Decoded bridge attestation",
            {
                {RPCResult::Type::ELISION, "", ""},
            }},
        RPCExamples{HelpExampleCli("bridge_decodeattestation", "\"<attestation_hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            auto pwallet = EnsureWalletForBridge(request);
            pwallet->BlockUntilSyncedToCurrentChain();

            const auto bytes = ParseHexV(request.params[0], "attestation_hex");
            const auto attestation = shielded::DeserializeBridgeAttestationMessage(Span<const uint8_t>{bytes.data(), bytes.size()});
            if (!attestation.has_value()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "attestation_hex is not a valid canonical bridge attestation");
            }

            UniValue out(UniValue::VOBJ);
            out.pushKV("message", BridgeAttestationBodyToUniValue(*attestation));
            out.pushKV("bytes", HexStr(bytes));
            out.pushKV("hash", shielded::ComputeBridgeAttestationHash(*attestation).GetHex());
            out.pushKV("matches_active_genesis",
                       shielded::DoesBridgeAttestationMatchGenesis(*attestation, pwallet->chain().getBlockHash(0)));
            return out;
        }};
}

} // namespace wallet
