// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_WALLET_BRIDGE_WALLET_H
#define BTX_WALLET_BRIDGE_WALLET_H

#include <consensus/params.h>
#include <consensus/amount.h>
#include <crypto/ml_kem.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <shielded/bridge.h>
#include <shielded/view_grant.h>
#include <wallet/shielded_wallet.h>

#include <optional>
#include <utility>
#include <vector>

namespace wallet {

enum class BridgeViewGrantFormat : uint8_t {
    LEGACY_AUDIT = 1,
    STRUCTURED_DISCLOSURE = 2,
};

struct BridgeViewGrantRequest
{
    BridgeViewGrantFormat format{BridgeViewGrantFormat::LEGACY_AUDIT};
    mlkem::PublicKey recipient_pubkey{};
    uint8_t disclosure_flags{0};

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint8_t format_u8 = static_cast<uint8_t>(format);
        ::Serialize(s, format_u8);
        ::Serialize(s, recipient_pubkey);
        ::Serialize(s, disclosure_flags);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint8_t format_u8{0};
        ::Unserialize(s, format_u8);
        format = static_cast<BridgeViewGrantFormat>(format_u8);
        ::Unserialize(s, recipient_pubkey);
        ::Unserialize(s, disclosure_flags);
    }
};

struct BridgeDisclosurePolicy
{
    uint8_t version{1};
    CAmount threshold_amount{0};
    std::vector<BridgeViewGrantRequest> required_grants;

    [[nodiscard]] bool IsValid() const;
    [[nodiscard]] bool RequiresDisclosure(CAmount amount) const;

    SERIALIZE_METHODS(BridgeDisclosurePolicy, obj)
    {
        READWRITE(obj.version, obj.threshold_amount, obj.required_grants);
    }
};

struct BridgeInPlanRequest
{
    shielded::BridgePlanIds ids;
    shielded::BridgeKeySpec operator_key;
    shielded::BridgeKeySpec refund_key;
    ShieldedAddress recipient;
    uint256 shielded_anchor;
    CAmount amount{0};
    uint32_t refund_lock_height{0};
    int32_t build_height{0};
    std::vector<unsigned char> memo;
    std::vector<BridgeViewGrantRequest> operator_view_grants;
    bool allow_legacy_audit_view_grants{false};
    std::optional<BridgeDisclosurePolicy> disclosure_policy;
    std::optional<shielded::BridgeBatchCommitment> batch_commitment;
};

struct BridgeOutPlanRequest
{
    shielded::BridgePlanIds ids;
    shielded::BridgeKeySpec operator_key;
    shielded::BridgeKeySpec refund_key;
    uint256 genesis_hash;
    CTxOut payout;
    std::vector<CTxOut> payouts;
    uint32_t refund_lock_height{0};
    std::optional<shielded::BridgeBatchCommitment> batch_commitment;
};

struct BridgePlan
{
    static constexpr uint8_t LEGACY_VERSION{1};
    static constexpr uint8_t VIEW_GRANT_POLICY_VERSION{2};
    static constexpr uint8_t CURRENT_VERSION{VIEW_GRANT_POLICY_VERSION};

    uint8_t version{CURRENT_VERSION};
    shielded::BridgeTemplateKind kind{shielded::BridgeTemplateKind::SHIELD};
    shielded::BridgePlanIds ids;
    uint32_t refund_lock_height{0};
    uint256 ctv_hash;
    shielded::BridgeScriptTree script_tree;
    CShieldedBundle shielded_bundle;
    std::vector<CTxOut> transparent_outputs;
    std::vector<BridgeViewGrantRequest> view_grant_metadata;
    bool allow_legacy_audit_view_grants{false};
    std::optional<BridgeDisclosurePolicy> disclosure_policy;
    bool has_attestation{false};
    shielded::BridgeAttestationMessage attestation;

    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint8_t kind_u8 = static_cast<uint8_t>(kind);
        ::Serialize(s, version);
        ::Serialize(s, kind_u8);
        ::Serialize(s, ids);
        ::Serialize(s, refund_lock_height);
        ::Serialize(s, ctv_hash);
        ::Serialize(s, script_tree);
        ::Serialize(s, shielded_bundle);
        ::Serialize(s, transparent_outputs);
        ::Serialize(s, has_attestation);
        if (has_attestation) {
            const std::vector<uint8_t> attestation_bytes = shielded::SerializeBridgeAttestationMessage(attestation);
            ::Serialize(s, attestation_bytes);
        }
        if (version >= VIEW_GRANT_POLICY_VERSION) {
            ::Serialize(s, view_grant_metadata);
            ::Serialize(s, allow_legacy_audit_view_grants);
            ::Serialize(s, disclosure_policy.has_value());
            if (disclosure_policy.has_value()) {
                ::Serialize(s, *disclosure_policy);
            }
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint8_t kind_u8{0};
        ::Unserialize(s, version);
        ::Unserialize(s, kind_u8);
        kind = static_cast<shielded::BridgeTemplateKind>(kind_u8);
        ::Unserialize(s, ids);
        ::Unserialize(s, refund_lock_height);
        ::Unserialize(s, ctv_hash);
        ::Unserialize(s, script_tree);
        ::Unserialize(s, shielded_bundle);
        ::Unserialize(s, transparent_outputs);
        ::Unserialize(s, has_attestation);
        if (has_attestation) {
            std::vector<uint8_t> attestation_bytes;
            ::Unserialize(s, attestation_bytes);
            auto parsed = shielded::DeserializeBridgeAttestationMessage(attestation_bytes);
            if (!parsed.has_value()) {
                throw std::ios_base::failure("BridgePlan::Unserialize invalid attestation");
            }
            attestation = *parsed;
        }
        if (version >= VIEW_GRANT_POLICY_VERSION) {
            ::Unserialize(s, view_grant_metadata);
            ::Unserialize(s, allow_legacy_audit_view_grants);
            bool has_disclosure_policy{false};
            ::Unserialize(s, has_disclosure_policy);
            if (has_disclosure_policy) {
                BridgeDisclosurePolicy parsed_policy;
                ::Unserialize(s, parsed_policy);
                disclosure_policy = std::move(parsed_policy);
            } else {
                disclosure_policy.reset();
            }
        } else {
            view_grant_metadata.clear();
            allow_legacy_audit_view_grants = false;
            disclosure_policy.reset();
        }
    }
};

[[nodiscard]] std::optional<BridgePlan> BuildBridgeInPlan(const BridgeInPlanRequest& request);
[[nodiscard]] std::optional<BridgePlan> BuildBridgeOutPlan(const BridgeOutPlanRequest& request);
[[nodiscard]] std::optional<std::string> ValidateAndApplyBridgeDisclosurePolicy(BridgeInPlanRequest& request);
[[nodiscard]] std::optional<std::string> ValidateBridgePlanViewGrantPolicy(const BridgePlan& plan,
                                                                           int32_t validation_height,
                                                                           bool allow_legacy_audit_view_grants = false);
[[nodiscard]] std::vector<uint8_t> SerializeBridgeViewGrantMetadataAad(const BridgeViewGrantRequest& request);
[[nodiscard]] std::optional<PartiallySignedTransaction> CreateBridgeShieldSettlementTransaction(const BridgePlan& plan,
                                                                                                const COutPoint& prevout,
                                                                                                CAmount prev_value,
                                                                                                const Consensus::Params* consensus = nullptr,
                                                                                                int32_t validation_height = 0,
                                                                                                bool allow_legacy_audit_view_grants = false);
[[nodiscard]] std::optional<PartiallySignedTransaction> CreateBridgeUnshieldSettlementTransaction(const BridgePlan& plan,
                                                                                                  const COutPoint& prevout,
                                                                                                  CAmount prev_value,
                                                                                                  const Consensus::Params* consensus = nullptr,
                                                                                                  int32_t validation_height = 0);
[[nodiscard]] std::optional<PartiallySignedTransaction> CreateBridgeRefundTransaction(const BridgePlan& plan,
                                                                                      const COutPoint& prevout,
                                                                                      CAmount prev_value,
                                                                                      const CTxDestination& destination,
                                                                                      CAmount fee,
                                                                                      const Consensus::Params* consensus = nullptr,
                                                                                      int32_t validation_height = 0);

} // namespace wallet

#endif // BTX_WALLET_BRIDGE_WALLET_H
