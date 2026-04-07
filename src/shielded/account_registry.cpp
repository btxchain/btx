// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <shielded/account_registry.h>

#include <dbwrapper.h>
#include <hash.h>
#include <logging.h>
#include <shielded/smile2/wallet_bridge.h>
#include <streams.h>

#include <algorithm>
#include <array>
#include <iterator>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <utility>

namespace shielded::registry {
namespace {

constexpr std::string_view TAG_PUBLIC_KEY_COMMIT{"BTX_SMILE_ACCOUNT_PUBLIC_KEY_COMMIT_V1"};
constexpr std::string_view TAG_PUBLIC_COIN_T0_COMMIT{"BTX_SMILE_ACCOUNT_PUBLIC_COIN_T0_COMMIT_V1"};
constexpr std::string_view TAG_PUBLIC_COIN_MSG_COMMIT{"BTX_SMILE_ACCOUNT_PUBLIC_COIN_MSG_COMMIT_V1"};
constexpr std::string_view TAG_ACCOUNT_PAYLOAD_COMMIT{"BTX_SMILE_ACCOUNT_PAYLOAD_COMMIT_V1"};
constexpr std::string_view TAG_SPEND_TAG_COMMIT{"BTX_SMILE_ACCOUNT_SPEND_TAG_COMMIT_V1"};
constexpr std::string_view TAG_INGRESS_BRIDGE_TAG{"BTX_SMILE_ACCOUNT_INGRESS_BRIDGE_TAG_V1"};
constexpr std::string_view TAG_EGRESS_BRIDGE_TAG{"BTX_SMILE_ACCOUNT_EGRESS_BRIDGE_TAG_V1"};
constexpr std::string_view TAG_REBALANCE_BRIDGE_TAG{"BTX_SMILE_ACCOUNT_REBALANCE_BRIDGE_TAG_V1"};
constexpr std::string_view TAG_INGRESS_BRIDGE_TAG_V2{"BTX_SMILE_ACCOUNT_INGRESS_BRIDGE_TAG_V2"};
constexpr std::string_view TAG_EGRESS_BRIDGE_TAG_V2{"BTX_SMILE_ACCOUNT_EGRESS_BRIDGE_TAG_V2"};
constexpr std::string_view TAG_REBALANCE_BRIDGE_TAG_V2{"BTX_SMILE_ACCOUNT_REBALANCE_BRIDGE_TAG_V2"};
constexpr std::string_view TAG_ACCOUNT_LEAF{"BTX_SMILE_ACCOUNT_LEAF_V1"};
constexpr std::string_view TAG_REGISTRY_ENTRY{"BTX_SMILE_ACCOUNT_REGISTRY_ENTRY_V1"};
constexpr std::string_view TAG_REGISTRY_NODE{"BTX_SMILE_ACCOUNT_REGISTRY_NODE_V1"};
constexpr std::string_view TAG_REGISTRY_EMPTY{"BTX_SMILE_ACCOUNT_REGISTRY_EMPTY_V1"};
constexpr std::string_view TAG_NULLIFIER_SET{"BTX_SMILE_ACCOUNT_NULLIFIER_SET_V1"};
constexpr std::string_view TAG_NULLIFIER_LEAF{"BTX_SMILE_ACCOUNT_NULLIFIER_LEAF_V1"};
constexpr std::string_view TAG_NULLIFIER_NODE{"BTX_SMILE_ACCOUNT_NULLIFIER_NODE_V1"};
constexpr std::string_view TAG_STATE_COMMITMENT{"BTX_SMILE_ACCOUNT_BLOCK_STATE_COMMITMENT_V1"};
constexpr uint8_t DB_ACCOUNT_REGISTRY_PAYLOAD{'P'};

std::mutex g_registry_payload_store_mutex;
std::shared_ptr<PayloadStore> g_registry_payload_store;

template <typename T>
[[nodiscard]] uint256 HashTaggedObject(std::string_view tag, const T& obj)
{
    HashWriter hw;
    hw << std::string{tag} << obj;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 HashTaggedPair(std::string_view tag,
                                     const uint256& left,
                                     const uint256& right)
{
    HashWriter hw;
    hw << std::string{tag} << left << right;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 HashTaggedString(std::string_view tag)
{
    HashWriter hw;
    hw << std::string{tag};
    return hw.GetSHA256();
}

[[nodiscard]] uint256 ComputeMerkleRoot(std::vector<uint256> level,
                                        std::string_view node_tag,
                                        std::string_view empty_tag)
{
    if (level.empty()) {
        return HashTaggedString(empty_tag);
    }

    while (level.size() > 1) {
        if ((level.size() & 1U) != 0U) {
            level.push_back(level.back());
        }

        std::vector<uint256> next_level;
        next_level.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            next_level.push_back(HashTaggedPair(node_tag, level[i], level[i + 1]));
        }
        level = std::move(next_level);
    }

    return level.front();
}

[[nodiscard]] bool HasUniqueRegistryCommitments(Span<const ShieldedAccountRegistryEntry> entries)
{
    std::set<uint256> seen_commitments;
    for (const auto& entry : entries) {
        if (!seen_commitments.insert(entry.account_leaf_commitment).second) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool HasUniqueRegistryPersistedCommitments(
    Span<const ShieldedAccountRegistryPersistedEntry> entries)
{
    std::set<uint256> seen_commitments;
    for (const auto& entry : entries) {
        if (!seen_commitments.insert(entry.account_leaf_commitment).second) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::optional<MinimalOutputRecord> BuildMinimalOutput(
    const shielded::v2::OutputDescription& output,
    const std::optional<ShieldedAccountLeaf>& account_leaf,
    AccountDomain domain)
{
    if (!account_leaf.has_value() || !output.IsValid()) {
        return std::nullopt;
    }

    MinimalOutputRecord minimal_output;
    minimal_output.note_commitment = output.note_commitment;
    minimal_output.account_leaf_commitment = ComputeShieldedAccountLeafCommitment(*account_leaf);
    minimal_output.account_domain = domain;
    minimal_output.encrypted_note = output.encrypted_note;
    if (!minimal_output.IsValid()) {
        return std::nullopt;
    }
    return minimal_output;
}

template <typename Stream>
void SerializeMinimalOutput(Stream& s,
                            const MinimalOutputRecord& output,
                            std::optional<AccountDomain> implied_account_domain,
                            std::optional<shielded::v2::ScanDomain> implied_scan_domain)
{
    if (!output.IsValid()) {
        throw std::ios_base::failure("SerializeMinimalOutput invalid output");
    }

    ::Serialize(s, output.version);
    ::Serialize(s, output.note_commitment);
    ::Serialize(s, output.account_leaf_commitment);
    if (implied_account_domain.has_value()) {
        if (*implied_account_domain != output.account_domain) {
            throw std::ios_base::failure("SerializeMinimalOutput mismatched implied account_domain");
        }
    } else {
        shielded::v2::detail::SerializeEnum(s, static_cast<uint8_t>(output.account_domain));
    }

    if (implied_scan_domain.has_value()) {
        output.encrypted_note.SerializeWithSharedScanDomain(s, *implied_scan_domain);
    } else {
        output.encrypted_note.Serialize(s);
    }
}

template <typename Stream>
void UnserializeMinimalOutput(Stream& s,
                              MinimalOutputRecord& output,
                              std::optional<AccountDomain> implied_account_domain,
                              std::optional<shielded::v2::ScanDomain> implied_scan_domain)
{
    output = {};
    ::Unserialize(s, output.version);
    if (output.version != REGISTRY_WIRE_VERSION) {
        throw std::ios_base::failure("UnserializeMinimalOutput invalid version");
    }
    ::Unserialize(s, output.note_commitment);
    ::Unserialize(s, output.account_leaf_commitment);
    if (implied_account_domain.has_value()) {
        output.account_domain = *implied_account_domain;
    } else {
        shielded::v2::detail::UnserializeEnum(s,
                                              output.account_domain,
                                              IsValidAccountDomain,
                                              "UnserializeMinimalOutput invalid account_domain");
    }

    if (implied_scan_domain.has_value()) {
        output.encrypted_note.UnserializeWithSharedScanDomain(s, *implied_scan_domain);
    } else {
        output.encrypted_note.Unserialize(s);
    }

    if (!output.IsValid()) {
        throw std::ios_base::failure("UnserializeMinimalOutput invalid output");
    }
}

} // namespace

bool IsValidAccountDomain(AccountDomain domain)
{
    switch (domain) {
    case AccountDomain::DIRECT_SEND:
    case AccountDomain::INGRESS:
    case AccountDomain::EGRESS:
    case AccountDomain::REBALANCE:
        return true;
    }
    return false;
}

bool AccountLeafHint::IsValid() const
{
    if (version != REGISTRY_WIRE_VERSION || !IsValidAccountDomain(domain)) {
        return false;
    }
    switch (domain) {
    case AccountDomain::DIRECT_SEND:
        return settlement_binding_digest.IsNull() && output_binding_digest.IsNull();
    case AccountDomain::INGRESS:
        return !settlement_binding_digest.IsNull() && output_binding_digest.IsNull();
    case AccountDomain::EGRESS:
        return !settlement_binding_digest.IsNull() && !output_binding_digest.IsNull();
    case AccountDomain::REBALANCE:
        return !settlement_binding_digest.IsNull() && output_binding_digest.IsNull();
    }
    return false;
}

AccountLeafHint MakeDirectSendAccountLeafHint()
{
    AccountLeafHint hint;
    hint.domain = AccountDomain::DIRECT_SEND;
    return hint;
}

std::optional<AccountLeafHint> MakeIngressAccountLeafHint(const uint256& settlement_binding_digest)
{
    AccountLeafHint hint;
    hint.domain = AccountDomain::INGRESS;
    hint.settlement_binding_digest = settlement_binding_digest;
    if (!hint.IsValid()) return std::nullopt;
    return hint;
}

std::optional<AccountLeafHint> MakeEgressAccountLeafHint(const uint256& settlement_binding_digest,
                                                         const uint256& output_binding_digest)
{
    AccountLeafHint hint;
    hint.domain = AccountDomain::EGRESS;
    hint.settlement_binding_digest = settlement_binding_digest;
    hint.output_binding_digest = output_binding_digest;
    if (!hint.IsValid()) return std::nullopt;
    return hint;
}

std::optional<AccountLeafHint> MakeRebalanceAccountLeafHint(const uint256& settlement_binding_digest)
{
    AccountLeafHint hint;
    hint.domain = AccountDomain::REBALANCE;
    hint.settlement_binding_digest = settlement_binding_digest;
    if (!hint.IsValid()) return std::nullopt;
    return hint;
}

const char* GetAccountDomainName(AccountDomain domain)
{
    switch (domain) {
    case AccountDomain::DIRECT_SEND:
        return "direct_send";
    case AccountDomain::INGRESS:
        return "ingress";
    case AccountDomain::EGRESS:
        return "egress";
    case AccountDomain::REBALANCE:
        return "rebalance";
    }
    return "invalid";
}

std::optional<ShieldedAccountLeaf> BuildAccountLeafFromNote(const ShieldedNote& note,
                                                            const uint256& note_commitment,
                                                            const AccountLeafHint& hint,
                                                            bool use_nonced_bridge_tag)
{
    if (!note.IsValid() || !hint.IsValid()) return std::nullopt;

    const auto account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        note);
    if (!account.has_value()) return std::nullopt;
    const uint256 effective_note_commitment =
        note_commitment.IsNull() ? smile2::ComputeCompactPublicAccountHash(*account) : note_commitment;

    switch (hint.domain) {
    case AccountDomain::DIRECT_SEND:
        return BuildShieldedAccountLeaf(*account, effective_note_commitment, AccountDomain::DIRECT_SEND);
    case AccountDomain::INGRESS:
        return BuildShieldedAccountLeaf(*account,
                                        effective_note_commitment,
                                        AccountDomain::INGRESS,
                                        use_nonced_bridge_tag
                                            ? ComputeIngressBridgeTag(hint.settlement_binding_digest,
                                                                      effective_note_commitment)
                                            : ComputeIngressBridgeTag(hint.settlement_binding_digest));
    case AccountDomain::EGRESS:
        return BuildShieldedAccountLeaf(*account,
                                        effective_note_commitment,
                                        AccountDomain::EGRESS,
                                        use_nonced_bridge_tag
                                            ? ComputeEgressBridgeTag(hint.settlement_binding_digest,
                                                                     hint.output_binding_digest,
                                                                     effective_note_commitment)
                                            : ComputeEgressBridgeTag(hint.settlement_binding_digest,
                                                                     hint.output_binding_digest));
    case AccountDomain::REBALANCE:
        return BuildShieldedAccountLeaf(*account,
                                        effective_note_commitment,
                                        AccountDomain::REBALANCE,
                                        use_nonced_bridge_tag
                                            ? ComputeRebalanceBridgeTag(hint.settlement_binding_digest,
                                                                        effective_note_commitment)
                                            : ComputeRebalanceBridgeTag(hint.settlement_binding_digest));
    }
    return std::nullopt;
}

std::optional<uint256> ComputeAccountLeafCommitmentFromNote(const ShieldedNote& note,
                                                            const uint256& note_commitment,
                                                            const AccountLeafHint& hint,
                                                            bool use_nonced_bridge_tag)
{
    const auto leaf = BuildAccountLeafFromNote(note, note_commitment, hint, use_nonced_bridge_tag);
    if (!leaf.has_value()) return std::nullopt;
    const uint256 commitment = ComputeShieldedAccountLeafCommitment(*leaf);
    if (commitment.IsNull()) return std::nullopt;
    return commitment;
}

std::vector<uint256> CollectAccountLeafCommitmentCandidatesFromNote(const ShieldedNote& note,
                                                                    const uint256& note_commitment,
                                                                    const AccountLeafHint& hint)
{
    std::vector<uint256> commitments;
    const auto append_commitment = [&](bool use_nonced_bridge_tag) {
        const auto commitment =
            ComputeAccountLeafCommitmentFromNote(note, note_commitment, hint, use_nonced_bridge_tag);
        if (!commitment.has_value() || commitment->IsNull()) return;
        if (std::find(commitments.begin(), commitments.end(), *commitment) == commitments.end()) {
            commitments.push_back(*commitment);
        }
    };

    append_commitment(false);
    if (hint.IsValid() && hint.domain != AccountDomain::DIRECT_SEND) {
        append_commitment(true);
    }
    return commitments;
}

uint256 ComputeCompactPublicKeyCommitment(const smile2::CompactPublicAccount& account)
{
    if (!account.IsValid()) return uint256{};
    DataStream stream;
    for (const auto& row : account.public_key) {
        smile2::SerializePoly(row, stream);
    }
    return HashTaggedObject(TAG_PUBLIC_KEY_COMMIT, Span<const uint8_t>{
                                                       reinterpret_cast<const uint8_t*>(stream.data()),
                                                       stream.size()});
}

uint256 ComputeCompactPublicCoinT0Commitment(const smile2::CompactPublicAccount& account)
{
    if (!account.IsValid()) return uint256{};
    DataStream stream;
    for (const auto& poly : account.public_coin.t0) {
        smile2::SerializePoly(poly, stream);
    }
    return HashTaggedObject(TAG_PUBLIC_COIN_T0_COMMIT, Span<const uint8_t>{
                                                            reinterpret_cast<const uint8_t*>(stream.data()),
                                                            stream.size()});
}

uint256 ComputeCompactPublicCoinMessageCommitment(const smile2::CompactPublicAccount& account)
{
    if (!account.IsValid()) return uint256{};
    DataStream stream;
    for (const auto& poly : account.public_coin.t_msg) {
        smile2::SerializePoly(poly, stream);
    }
    return HashTaggedObject(TAG_PUBLIC_COIN_MSG_COMMIT, Span<const uint8_t>{
                                                             reinterpret_cast<const uint8_t*>(stream.data()),
                                                             stream.size()});
}

uint256 ComputeAccountPayloadCommitment(const smile2::CompactPublicAccount& account)
{
    if (!account.IsValid()) return uint256{};
    const uint256 key_commitment = ComputeCompactPublicKeyCommitment(account);
    const uint256 coin_t0_commitment = ComputeCompactPublicCoinT0Commitment(account);
    const uint256 coin_msg_commitment = ComputeCompactPublicCoinMessageCommitment(account);
    if (key_commitment.IsNull() || coin_t0_commitment.IsNull() || coin_msg_commitment.IsNull()) {
        return uint256{};
    }
    HashWriter hw;
    hw << std::string{TAG_ACCOUNT_PAYLOAD_COMMIT}
       << key_commitment
       << coin_t0_commitment
       << coin_msg_commitment;
    return hw.GetSHA256();
}

uint256 ComputeSpendTagCommitment(const smile2::CompactPublicAccount& account,
                                  const uint256& note_commitment)
{
    if (!account.IsValid() || note_commitment.IsNull()) return uint256{};
    const uint256 key_commitment = ComputeCompactPublicKeyCommitment(account);
    const uint256 coin_msg_commitment = ComputeCompactPublicCoinMessageCommitment(account);
    if (key_commitment.IsNull() || coin_msg_commitment.IsNull()) {
        return uint256{};
    }

    HashWriter hw;
    hw << std::string{TAG_SPEND_TAG_COMMIT}
       << note_commitment
       << key_commitment
       << coin_msg_commitment;
    return hw.GetSHA256();
}

std::optional<smile2::CompactPublicAccount> BuildCompactPublicAccountFromAccountLeaf(
    const ShieldedAccountLeaf& leaf)
{
    if (!leaf.compact_public_key.IsValid()) return std::nullopt;
    return smile2::BuildCompactPublicAccountFromPublicParts(leaf.compact_public_key,
                                                            leaf.compact_public_coin);
}

uint256 ComputeIngressBridgeTag(const uint256& settlement_binding_digest)
{
    if (settlement_binding_digest.IsNull()) return uint256{};
    return HashTaggedObject(TAG_INGRESS_BRIDGE_TAG, settlement_binding_digest);
}

uint256 ComputeEgressBridgeTag(const uint256& settlement_binding_digest,
                               const uint256& output_binding_digest)
{
    if (settlement_binding_digest.IsNull() || output_binding_digest.IsNull()) return uint256{};
    HashWriter hw;
    hw << std::string{TAG_EGRESS_BRIDGE_TAG}
       << settlement_binding_digest
       << output_binding_digest;
    return hw.GetSHA256();
}

uint256 ComputeRebalanceBridgeTag(const uint256& settlement_binding_digest)
{
    if (settlement_binding_digest.IsNull()) return uint256{};
    return HashTaggedObject(TAG_REBALANCE_BRIDGE_TAG, settlement_binding_digest);
}

uint256 ComputeIngressBridgeTag(const uint256& settlement_binding_digest,
                                const uint256& note_commitment)
{
    if (settlement_binding_digest.IsNull() || note_commitment.IsNull()) return uint256{};
    HashWriter hw;
    hw << std::string{TAG_INGRESS_BRIDGE_TAG_V2}
       << settlement_binding_digest
       << note_commitment;
    return hw.GetSHA256();
}

uint256 ComputeEgressBridgeTag(const uint256& settlement_binding_digest,
                               const uint256& output_binding_digest,
                               const uint256& note_commitment)
{
    if (settlement_binding_digest.IsNull() || output_binding_digest.IsNull() || note_commitment.IsNull()) {
        return uint256{};
    }
    HashWriter hw;
    hw << std::string{TAG_EGRESS_BRIDGE_TAG_V2}
       << settlement_binding_digest
       << output_binding_digest
       << note_commitment;
    return hw.GetSHA256();
}

uint256 ComputeRebalanceBridgeTag(const uint256& settlement_binding_digest,
                                  const uint256& note_commitment)
{
    if (settlement_binding_digest.IsNull() || note_commitment.IsNull()) return uint256{};
    HashWriter hw;
    hw << std::string{TAG_REBALANCE_BRIDGE_TAG_V2}
       << settlement_binding_digest
       << note_commitment;
    return hw.GetSHA256();
}

bool ShieldedAccountLeaf::IsValid() const
{
    if (version != REGISTRY_WIRE_VERSION ||
        !IsValidAccountDomain(domain) ||
        note_commitment.IsNull() ||
        account_payload_commitment.IsNull() ||
        spend_tag_commitment.IsNull() ||
        !compact_public_key.IsValid()) {
        return false;
    }

    const auto account = BuildCompactPublicAccountFromAccountLeaf(*this);
    if (!account.has_value() ||
        ComputeAccountPayloadCommitment(*account) != account_payload_commitment ||
        ComputeSpendTagCommitment(*account, note_commitment) != spend_tag_commitment) {
        return false;
    }

    if (domain == AccountDomain::DIRECT_SEND) {
        return !bridge_tag.has_value();
    }
    return bridge_tag.has_value() && !bridge_tag->IsNull();
}

uint256 ComputeShieldedAccountLeafCommitment(const ShieldedAccountLeaf& leaf)
{
    if (!leaf.IsValid()) return uint256{};
    HashWriter hw;
    hw << std::string{TAG_ACCOUNT_LEAF}
       << leaf.note_commitment
       << static_cast<uint8_t>(leaf.domain)
       << leaf.account_payload_commitment
       << leaf.spend_tag_commitment;
    if (leaf.bridge_tag.has_value()) {
        hw << uint8_t{1} << *leaf.bridge_tag;
    } else {
        hw << uint8_t{0};
    }
    return hw.GetSHA256();
}

std::vector<uint8_t> SerializeShieldedAccountLeafPayload(const ShieldedAccountLeaf& leaf)
{
    if (!leaf.IsValid()) return {};
    DataStream stream;
    stream << leaf;
    const auto* begin = reinterpret_cast<const uint8_t*>(stream.data());
    return std::vector<uint8_t>{begin, begin + stream.size()};
}

std::optional<ShieldedAccountLeaf> DeserializeShieldedAccountLeafPayload(Span<const uint8_t> bytes)
{
    if (bytes.empty()) return std::nullopt;
    try {
        DataStream stream{bytes};
        ShieldedAccountLeaf leaf;
        stream >> leaf;
        if (!leaf.IsValid() || !stream.empty()) {
            return std::nullopt;
        }
        return leaf;
    } catch (const std::ios_base::failure&) {
        return std::nullopt;
    }
}

std::optional<ShieldedAccountLeaf> BuildShieldedAccountLeaf(const smile2::CompactPublicAccount& account,
                                                            const uint256& note_commitment,
                                                            AccountDomain domain,
                                                            std::optional<uint256> bridge_tag)
{
    if (!account.IsValid()) return std::nullopt;

    const uint256 effective_note_commitment =
        note_commitment.IsNull() ? smile2::ComputeCompactPublicAccountHash(account) : note_commitment;
    const uint256 account_payload_commitment = ComputeAccountPayloadCommitment(account);
    const uint256 spend_tag_commitment = ComputeSpendTagCommitment(account, effective_note_commitment);
    if (effective_note_commitment.IsNull() ||
        account_payload_commitment.IsNull() ||
        spend_tag_commitment.IsNull()) {
        return std::nullopt;
    }

    ShieldedAccountLeaf leaf;
    leaf.note_commitment = effective_note_commitment;
    leaf.domain = domain;
    leaf.account_payload_commitment = account_payload_commitment;
    leaf.spend_tag_commitment = spend_tag_commitment;
    leaf.compact_public_key = smile2::ExtractCompactPublicKeyData(account);
    leaf.compact_public_coin = account.public_coin;
    leaf.bridge_tag = std::move(bridge_tag);
    if (!leaf.IsValid()) {
        return std::nullopt;
    }
    return leaf;
}

std::optional<ShieldedAccountLeaf> BuildDirectSendAccountLeaf(
    const shielded::v2::OutputDescription& output)
{
    if (!output.smile_account.has_value()) return std::nullopt;
    return BuildShieldedAccountLeaf(*output.smile_account,
                                    output.note_commitment,
                                    AccountDomain::DIRECT_SEND);
}

std::optional<ShieldedAccountLeaf> BuildIngressAccountLeaf(
    const shielded::v2::OutputDescription& output,
    const uint256& settlement_binding_digest,
    bool use_nonced_bridge_tag)
{
    if (!output.smile_account.has_value()) return std::nullopt;
    return BuildShieldedAccountLeaf(*output.smile_account,
                                    output.note_commitment,
                                    AccountDomain::INGRESS,
                                    use_nonced_bridge_tag
                                        ? ComputeIngressBridgeTag(settlement_binding_digest,
                                                                  output.note_commitment)
                                        : ComputeIngressBridgeTag(settlement_binding_digest));
}

std::optional<ShieldedAccountLeaf> BuildEgressAccountLeaf(
    const shielded::v2::OutputDescription& output,
    const uint256& settlement_binding_digest,
    const uint256& output_binding_digest,
    bool use_nonced_bridge_tag)
{
    if (!output.smile_account.has_value()) return std::nullopt;
    return BuildShieldedAccountLeaf(*output.smile_account,
                                    output.note_commitment,
                                    AccountDomain::EGRESS,
                                    use_nonced_bridge_tag
                                        ? ComputeEgressBridgeTag(settlement_binding_digest,
                                                                 output_binding_digest,
                                                                 output.note_commitment)
                                        : ComputeEgressBridgeTag(settlement_binding_digest,
                                                                 output_binding_digest));
}

std::optional<ShieldedAccountLeaf> BuildRebalanceAccountLeaf(
    const shielded::v2::OutputDescription& output,
    const uint256& settlement_binding_digest,
    bool use_nonced_bridge_tag)
{
    if (!output.smile_account.has_value()) return std::nullopt;
    return BuildShieldedAccountLeaf(*output.smile_account,
                                    output.note_commitment,
                                    AccountDomain::REBALANCE,
                                    use_nonced_bridge_tag
                                        ? ComputeRebalanceBridgeTag(settlement_binding_digest,
                                                                    output.note_commitment)
                                        : ComputeRebalanceBridgeTag(settlement_binding_digest));
}

bool MinimalOutputRecord::IsValid() const
{
    return version == REGISTRY_WIRE_VERSION &&
           !note_commitment.IsNull() &&
           !account_leaf_commitment.IsNull() &&
           IsValidAccountDomain(account_domain) &&
           encrypted_note.IsValid();
}

std::vector<uint8_t> SerializeMinimalOutputRecord(
    const MinimalOutputRecord& output,
    std::optional<AccountDomain> implied_account_domain,
    std::optional<shielded::v2::ScanDomain> implied_scan_domain)
{
    DataStream stream;
    SerializeMinimalOutput(stream, output, implied_account_domain, implied_scan_domain);
    const auto* begin = reinterpret_cast<const uint8_t*>(stream.data());
    return {begin, begin + stream.size()};
}

std::optional<MinimalOutputRecord> DeserializeMinimalOutputRecord(
    Span<const uint8_t> bytes,
    std::optional<AccountDomain> implied_account_domain,
    std::optional<shielded::v2::ScanDomain> implied_scan_domain)
{
    DataStream stream{std::vector<uint8_t>{bytes.begin(), bytes.end()}};
    MinimalOutputRecord output;
    try {
        UnserializeMinimalOutput(stream, output, implied_account_domain, implied_scan_domain);
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (!stream.empty()) return std::nullopt;
    return output;
}

std::optional<MinimalOutputRecord> BuildDirectSendMinimalOutput(
    const shielded::v2::OutputDescription& output)
{
    return BuildMinimalOutput(output,
                              BuildDirectSendAccountLeaf(output),
                              AccountDomain::DIRECT_SEND);
}

std::optional<MinimalOutputRecord> BuildIngressMinimalOutput(
    const shielded::v2::OutputDescription& output,
    const uint256& settlement_binding_digest)
{
    return BuildMinimalOutput(output,
                              BuildIngressAccountLeaf(output, settlement_binding_digest),
                              AccountDomain::INGRESS);
}

std::optional<MinimalOutputRecord> BuildEgressMinimalOutput(
    const shielded::v2::OutputDescription& output,
    const uint256& settlement_binding_digest,
    const uint256& output_binding_digest)
{
    return BuildMinimalOutput(output,
                              BuildEgressAccountLeaf(output,
                                                     settlement_binding_digest,
                                                     output_binding_digest),
                              AccountDomain::EGRESS);
}

std::optional<MinimalOutputRecord> BuildRebalanceMinimalOutput(
    const shielded::v2::OutputDescription& output,
    const uint256& settlement_binding_digest)
{
    return BuildMinimalOutput(output,
                              BuildRebalanceAccountLeaf(output, settlement_binding_digest),
                              AccountDomain::REBALANCE);
}

bool MinimalOutputRecordMatchesOutput(const MinimalOutputRecord& minimal_output,
                                      const shielded::v2::OutputDescription& output,
                                      const ShieldedAccountLeaf& account_leaf)
{
    return minimal_output.IsValid() &&
           output.IsValid() &&
           account_leaf.IsValid() &&
           minimal_output.note_commitment == output.note_commitment &&
           minimal_output.account_leaf_commitment == ComputeShieldedAccountLeafCommitment(account_leaf) &&
           minimal_output.encrypted_note.scan_domain == output.encrypted_note.scan_domain &&
           minimal_output.encrypted_note.scan_hint == output.encrypted_note.scan_hint &&
           minimal_output.encrypted_note.ciphertext == output.encrypted_note.ciphertext &&
           minimal_output.encrypted_note.ephemeral_key == output.encrypted_note.ephemeral_key;
}

bool ShieldedAccountRegistryEntry::IsValid() const
{
    return version == REGISTRY_WIRE_VERSION &&
           !spent &&
           !account_leaf_commitment.IsNull() &&
           !account_leaf_payload.empty() &&
           [&]() {
               const auto account_leaf = DeserializeShieldedAccountLeafPayload(
                   Span<const uint8_t>{account_leaf_payload.data(), account_leaf_payload.size()});
               return account_leaf.has_value() &&
                      ComputeShieldedAccountLeafCommitment(*account_leaf) == account_leaf_commitment;
           }();
}

uint256 ComputeShieldedAccountRegistryEntryCommitment(const ShieldedAccountRegistryEntry& entry)
{
    if (!entry.IsValid()) return uint256{};
    HashWriter hw;
    hw << std::string{TAG_REGISTRY_ENTRY}
       << entry.leaf_index
       << entry.account_leaf_commitment
       << entry.account_leaf_payload
       << entry.spent;
    return hw.GetSHA256();
}

bool ShieldedAccountRegistryProof::IsValid() const
{
    return version == REGISTRY_WIRE_VERSION &&
           entry.IsValid() &&
           sibling_path.size() <= MAX_REGISTRY_PROOF_SIBLINGS &&
           std::all_of(sibling_path.begin(), sibling_path.end(), [](const uint256& sibling) {
               return !sibling.IsNull();
           });
}

bool ShieldedAccountRegistrySpendWitness::IsValid() const
{
    return version == REGISTRY_WIRE_VERSION &&
           !account_leaf_commitment.IsNull() &&
           sibling_path.size() <= MAX_REGISTRY_PROOF_SIBLINGS &&
           std::all_of(sibling_path.begin(), sibling_path.end(), [](const uint256& sibling) {
               return !sibling.IsNull();
           });
}

namespace {

uint256 ComputeShieldedAccountRegistryPathRoot(uint256 hash,
                                               uint64_t node_index,
                                               Span<const uint256> sibling_path)
{
    if (hash.IsNull()) {
        return uint256{};
    }
    for (const uint256& sibling : sibling_path) {
        if (sibling.IsNull()) {
            return uint256{};
        }
        if ((node_index & 1U) == 0U) {
            hash = HashTaggedPair(TAG_REGISTRY_NODE, hash, sibling);
        } else {
            hash = HashTaggedPair(TAG_REGISTRY_NODE, sibling, hash);
        }
        node_index >>= 1;
    }
    return hash;
}

} // namespace

bool VerifyShieldedAccountRegistryProof(const ShieldedAccountRegistryProof& proof,
                                        const uint256& expected_root)
{
    if (!proof.IsValid() || expected_root.IsNull()) {
        return false;
    }

    return ComputeShieldedAccountRegistryPathRoot(
               ComputeShieldedAccountRegistryEntryCommitment(proof.entry),
               proof.entry.leaf_index,
               Span<const uint256>{proof.sibling_path.data(), proof.sibling_path.size()}) == expected_root;
}

std::optional<ShieldedAccountRegistrySpendWitness> BuildShieldedAccountRegistrySpendWitness(
    const ShieldedAccountRegistryProof& proof)
{
    if (!proof.IsValid()) {
        return std::nullopt;
    }
    ShieldedAccountRegistrySpendWitness witness;
    witness.leaf_index = proof.entry.leaf_index;
    witness.account_leaf_commitment = proof.entry.account_leaf_commitment;
    witness.sibling_path = proof.sibling_path;
    if (!witness.IsValid()) {
        return std::nullopt;
    }
    return witness;
}

bool ShieldedAccountRegistrySnapshot::IsValid() const
{
    if (version != REGISTRY_WIRE_VERSION || entries.size() > MAX_REGISTRY_ENTRIES) {
        return false;
    }
    for (size_t i = 0; i < entries.size(); ++i) {
        if (!entries[i].IsValid() || entries[i].leaf_index != i) {
            return false;
        }
    }
    return HasUniqueRegistryCommitments(Span<const ShieldedAccountRegistryEntry>{
        entries.data(),
        entries.size()});
}

bool ShieldedAccountRegistryPersistedEntry::IsValid() const
{
    return version == REGISTRY_WIRE_VERSION &&
           !spent &&
           !account_leaf_commitment.IsNull() &&
           !entry_commitment.IsNull();
}

bool ShieldedAccountRegistryPersistedSnapshot::IsValid() const
{
    if (version != REGISTRY_WIRE_VERSION || entries.size() > MAX_REGISTRY_ENTRIES) {
        return false;
    }
    for (size_t i = 0; i < entries.size(); ++i) {
        if (!entries[i].IsValid() || entries[i].leaf_index != i) {
            return false;
        }
    }
    return HasUniqueRegistryPersistedCommitments(
        Span<const ShieldedAccountRegistryPersistedEntry>{entries.data(), entries.size()});
}

struct PayloadStore
{
    explicit PayloadStore(const fs::path& db_path,
                          size_t cache_bytes,
                          bool memory_only,
                          bool wipe_data,
                          DBOptions options) :
        db(std::make_unique<CDBWrapper>(DBParams{
            .path = db_path,
            .cache_bytes = cache_bytes,
            .memory_only = memory_only,
            .wipe_data = wipe_data,
            .obfuscate = true,
            .options = options}))
    {
    }

    [[nodiscard]] bool WritePayloadBatch(
        const std::vector<std::pair<uint64_t, std::vector<uint8_t>>>& payloads)
    {
        std::lock_guard<std::mutex> lock(mutex);
        CDBBatch batch(*db);
        for (const auto& [leaf_index, payload] : payloads) {
            batch.Write(std::make_pair(DB_ACCOUNT_REGISTRY_PAYLOAD, leaf_index), payload);
        }
        return db->WriteBatch(batch, /*fSync=*/true);
    }

    [[nodiscard]] bool ErasePayloadRange(uint64_t start, uint64_t end)
    {
        if (start >= end) return true;
        std::lock_guard<std::mutex> lock(mutex);
        CDBBatch batch(*db);
        for (uint64_t leaf_index = start; leaf_index < end; ++leaf_index) {
            batch.Erase(std::make_pair(DB_ACCOUNT_REGISTRY_PAYLOAD, leaf_index));
        }
        if (!db->WriteBatch(batch, /*fSync=*/true)) {
            return false;
        }
        db->Compact();
        return true;
    }

    [[nodiscard]] bool PruneToSize(uint64_t size)
    {
        std::vector<std::pair<uint8_t, uint64_t>> stale_keys;
        std::lock_guard<std::mutex> lock(mutex);
        std::unique_ptr<CDBIterator> cursor{db->NewIterator()};
        cursor->Seek(std::make_pair(DB_ACCOUNT_REGISTRY_PAYLOAD, uint64_t{0}));
        while (cursor->Valid()) {
            std::pair<uint8_t, uint64_t> key;
            if (!cursor->GetKey(key) || key.first != DB_ACCOUNT_REGISTRY_PAYLOAD) {
                break;
            }
            if (key.second >= size) {
                stale_keys.push_back(key);
            }
            cursor->Next();
        }
        if (stale_keys.empty()) {
            return true;
        }
        CDBBatch batch(*db);
        for (const auto& key : stale_keys) {
            batch.Erase(key);
        }
        if (!db->WriteBatch(batch, /*fSync=*/true)) {
            return false;
        }
        db->Compact();
        return true;
    }

    [[nodiscard]] std::optional<std::vector<uint8_t>> ReadPayload(uint64_t leaf_index) const
    {
        std::lock_guard<std::mutex> lock(mutex);
        std::vector<uint8_t> payload;
        if (!db->Read(std::make_pair(DB_ACCOUNT_REGISTRY_PAYLOAD, leaf_index), payload)) {
            return std::nullopt;
        }
        return payload;
    }

    std::unique_ptr<CDBWrapper> db;
    mutable std::mutex mutex;
};

ShieldedAccountRegistryState::ShieldedAccountRegistryState() = default;

ShieldedAccountRegistryState ShieldedAccountRegistryState::WithConfiguredPayloadStore()
{
    ShieldedAccountRegistryState state;
    state.AttachConfiguredPayloadStore();
    return state;
}

bool ShieldedAccountRegistryState::ConfigurePayloadStore(const fs::path& db_path,
                                                         size_t cache_bytes,
                                                         bool memory_only,
                                                         bool wipe_data,
                                                         DBOptions options)
{
    try {
        auto store = std::make_shared<PayloadStore>(
            db_path,
            cache_bytes,
            memory_only,
            wipe_data,
            options);
        std::lock_guard<std::mutex> lock(g_registry_payload_store_mutex);
        g_registry_payload_store = std::move(store);
        return true;
    } catch (const std::exception& e) {
        LogPrintf("ShieldedAccountRegistryState::ConfigurePayloadStore failed: %s\n", e.what());
        return false;
    }
}

void ShieldedAccountRegistryState::ResetPayloadStore()
{
    std::lock_guard<std::mutex> lock(g_registry_payload_store_mutex);
    g_registry_payload_store.reset();
}

bool ShieldedAccountRegistryState::HasPayloadStore()
{
    std::lock_guard<std::mutex> lock(g_registry_payload_store_mutex);
    return g_registry_payload_store != nullptr;
}

void ShieldedAccountRegistryState::AttachConfiguredPayloadStore()
{
    std::lock_guard<std::mutex> lock(g_registry_payload_store_mutex);
    m_payload_store = g_registry_payload_store;
}

std::optional<std::vector<uint8_t>> ShieldedAccountRegistryState::LoadPayloadBytes(
    uint64_t leaf_index) const
{
    if (leaf_index >= m_entries.size()) {
        return std::nullopt;
    }
    const auto& entry = m_entries[leaf_index];
    if (!entry.inline_payload.empty()) {
        return entry.inline_payload;
    }
    if (!m_payload_store) {
        return std::nullopt;
    }
    return m_payload_store->ReadPayload(entry.leaf_index);
}

bool ShieldedAccountRegistryState::LoadFromSnapshot(const ShieldedAccountRegistrySnapshot& snapshot)
{
    if (!snapshot.IsValid()) return false;

    std::vector<StoredEntry> restored_entries;
    restored_entries.reserve(snapshot.entries.size());
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> payload_batch;
    if (m_payload_store) {
        payload_batch.reserve(snapshot.entries.size());
    }

    for (const auto& entry : snapshot.entries) {
        if (!entry.IsValid()) {
            return false;
        }
        if (m_payload_store) {
            payload_batch.emplace_back(entry.leaf_index, entry.account_leaf_payload);
        }
        restored_entries.push_back(StoredEntry{
            .leaf_index = entry.leaf_index,
            .account_leaf_commitment = entry.account_leaf_commitment,
            .entry_commitment = ComputeShieldedAccountRegistryEntryCommitment(entry),
            .spent = entry.spent,
            .inline_payload = m_payload_store ? std::vector<uint8_t>{} : entry.account_leaf_payload,
        });
    }

    if (m_payload_store && !m_payload_store->WritePayloadBatch(payload_batch)) {
        return false;
    }
    if (m_payload_store && !m_payload_store->PruneToSize(restored_entries.size())) {
        return false;
    }

    m_entries = std::move(restored_entries);
    return true;
}

bool ShieldedAccountRegistryState::LoadFromPersistedSnapshot(
    const ShieldedAccountRegistryPersistedSnapshot& snapshot)
{
    if (!snapshot.IsValid()) return false;
    if (!snapshot.entries.empty() && !m_payload_store) {
        return false;
    }

    std::vector<StoredEntry> restored_entries;
    restored_entries.reserve(snapshot.entries.size());
    for (const auto& entry : snapshot.entries) {
        restored_entries.push_back(StoredEntry{
            .leaf_index = entry.leaf_index,
            .account_leaf_commitment = entry.account_leaf_commitment,
            .entry_commitment = entry.entry_commitment,
            .spent = entry.spent,
            .inline_payload = {},
        });
    }
    if (m_payload_store && !m_payload_store->PruneToSize(restored_entries.size())) {
        return false;
    }
    m_entries = std::move(restored_entries);
    return true;
}

bool ShieldedAccountRegistryState::Append(Span<const ShieldedAccountLeaf> account_leaves,
                                          std::vector<uint64_t>* inserted_indices)
{
    if (account_leaves.empty()) return true;
    if (m_entries.size() + account_leaves.size() > MAX_REGISTRY_ENTRIES) {
        return false;
    }
    if (std::any_of(account_leaves.begin(),
                    account_leaves.end(),
                    [](const ShieldedAccountLeaf& leaf) { return !leaf.IsValid(); })) {
        return false;
    }

    std::set<uint256> seen_commitments;
    for (const auto& entry : m_entries) {
        seen_commitments.insert(entry.account_leaf_commitment);
    }

    std::vector<StoredEntry> new_entries;
    new_entries.reserve(account_leaves.size());
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> payload_batch;
    if (m_payload_store) {
        payload_batch.reserve(account_leaves.size());
    }
    std::vector<uint64_t> new_indices;
    if (inserted_indices != nullptr) {
        new_indices.reserve(account_leaves.size());
    }

    const uint64_t base_index = m_entries.size();
    for (size_t offset = 0; offset < account_leaves.size(); ++offset) {
        const ShieldedAccountLeaf& leaf = account_leaves[offset];
        ShieldedAccountRegistryEntry entry;
        entry.leaf_index = base_index + offset;
        entry.account_leaf_commitment = ComputeShieldedAccountLeafCommitment(leaf);
        if (!seen_commitments.insert(entry.account_leaf_commitment).second) {
            return false;
        }
        entry.account_leaf_payload = SerializeShieldedAccountLeafPayload(leaf);
        if (!entry.IsValid()) return false;
        if (m_payload_store) {
            payload_batch.emplace_back(entry.leaf_index, entry.account_leaf_payload);
        }
        if (inserted_indices != nullptr) {
            new_indices.push_back(entry.leaf_index);
        }
        new_entries.push_back(StoredEntry{
            .leaf_index = entry.leaf_index,
            .account_leaf_commitment = entry.account_leaf_commitment,
            .entry_commitment = ComputeShieldedAccountRegistryEntryCommitment(entry),
            .spent = entry.spent,
            .inline_payload = m_payload_store ? std::vector<uint8_t>{}
                                              : std::move(entry.account_leaf_payload),
        });
    }

    if (m_payload_store && !m_payload_store->WritePayloadBatch(payload_batch)) {
        return false;
    }

    if (inserted_indices != nullptr) {
        *inserted_indices = std::move(new_indices);
    }
    m_entries.insert(m_entries.end(),
                     std::make_move_iterator(new_entries.begin()),
                     std::make_move_iterator(new_entries.end()));
    return true;
}

bool ShieldedAccountRegistryState::Truncate(size_t size, PayloadPruneMode prune_mode)
{
    if (size > m_entries.size()) return false;
    if (prune_mode == PayloadPruneMode::PRUNE &&
        m_payload_store &&
        !m_payload_store->PruneToSize(size)) {
        return false;
    }
    m_entries.resize(size);
    return true;
}

std::optional<uint64_t> ShieldedAccountRegistryState::FindLeafIndexByCommitment(
    const uint256& account_leaf_commitment) const
{
    if (account_leaf_commitment.IsNull()) return std::nullopt;

    std::optional<uint64_t> match;
    for (const auto& entry : m_entries) {
        if (entry.account_leaf_commitment != account_leaf_commitment) {
            continue;
        }
        if (match.has_value()) {
            return std::nullopt;
        }
        match = entry.leaf_index;
    }
    return match;
}

std::optional<ShieldedAccountRegistryProof> ShieldedAccountRegistryState::BuildProof(
    uint64_t leaf_index) const
{
    if (leaf_index >= m_entries.size()) return std::nullopt;

    std::vector<uint256> level;
    level.reserve(m_entries.size());
    for (const auto& entry : m_entries) {
        level.push_back(entry.entry_commitment);
    }
    if (level.empty()) return std::nullopt;

    ShieldedAccountRegistryProof proof;
    const auto entry = MaterializeEntry(leaf_index);
    if (!entry.has_value()) {
        return std::nullopt;
    }
    proof.entry = *entry;
    uint64_t node_index = leaf_index;

    while (level.size() > 1) {
        if ((level.size() & 1U) != 0U) {
            level.push_back(level.back());
        }

        const size_t sibling_index = (node_index & 1U) == 0U ? node_index + 1U : node_index - 1U;
        proof.sibling_path.push_back(level[sibling_index]);

        std::vector<uint256> next_level;
        next_level.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            next_level.push_back(HashTaggedPair(TAG_REGISTRY_NODE, level[i], level[i + 1]));
        }
        level = std::move(next_level);
        node_index >>= 1;
    }

    if (!proof.IsValid()) return std::nullopt;
    return proof;
}

std::optional<ShieldedAccountRegistrySpendWitness> ShieldedAccountRegistryState::BuildSpendWitness(
    uint64_t leaf_index) const
{
    if (leaf_index >= m_entries.size()) {
        return std::nullopt;
    }

    std::vector<uint256> level;
    level.reserve(m_entries.size());
    for (const auto& entry : m_entries) {
        level.push_back(entry.entry_commitment);
    }
    if (level.empty()) {
        return std::nullopt;
    }

    const auto& entry = m_entries[leaf_index];
    if (entry.spent || entry.account_leaf_commitment.IsNull() || entry.entry_commitment.IsNull()) {
        return std::nullopt;
    }

    ShieldedAccountRegistrySpendWitness witness;
    witness.leaf_index = leaf_index;
    witness.account_leaf_commitment = entry.account_leaf_commitment;
    uint64_t node_index = leaf_index;

    while (level.size() > 1) {
        if ((level.size() & 1U) != 0U) {
            level.push_back(level.back());
        }

        const size_t sibling_index = (node_index & 1U) == 0U ? node_index + 1U : node_index - 1U;
        witness.sibling_path.push_back(level[sibling_index]);

        std::vector<uint256> next_level;
        next_level.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            next_level.push_back(HashTaggedPair(TAG_REGISTRY_NODE, level[i], level[i + 1]));
        }
        level = std::move(next_level);
        node_index >>= 1;
    }

    if (!witness.IsValid()) {
        return std::nullopt;
    }
    return witness;
}

std::optional<ShieldedAccountRegistryProof> ShieldedAccountRegistryState::BuildProofByCommitment(
    const uint256& account_leaf_commitment) const
{
    const auto leaf_index = FindLeafIndexByCommitment(account_leaf_commitment);
    if (!leaf_index.has_value()) return std::nullopt;
    return BuildProof(*leaf_index);
}

std::optional<ShieldedAccountRegistrySpendWitness>
ShieldedAccountRegistryState::BuildSpendWitnessByCommitment(
    const uint256& account_leaf_commitment) const
{
    const auto leaf_index = FindLeafIndexByCommitment(account_leaf_commitment);
    if (!leaf_index.has_value()) {
        return std::nullopt;
    }
    return BuildSpendWitness(*leaf_index);
}

std::optional<ShieldedAccountRegistryEntry> ShieldedAccountRegistryState::MaterializeEntry(
    uint64_t leaf_index) const
{
    if (leaf_index >= m_entries.size()) {
        return std::nullopt;
    }
    const auto& stored = m_entries[leaf_index];
    auto payload = LoadPayloadBytes(leaf_index);
    if (!payload.has_value()) {
        return std::nullopt;
    }

    ShieldedAccountRegistryEntry entry;
    entry.leaf_index = stored.leaf_index;
    entry.account_leaf_commitment = stored.account_leaf_commitment;
    entry.account_leaf_payload = std::move(*payload);
    entry.spent = stored.spent;
    if (!entry.IsValid()) {
        return std::nullopt;
    }
    if (ComputeShieldedAccountRegistryEntryCommitment(entry) != stored.entry_commitment) {
        return std::nullopt;
    }
    return entry;
}

bool ShieldedAccountRegistryState::CanMaterializeAllEntries() const
{
    for (uint64_t leaf_index = 0; leaf_index < m_entries.size(); ++leaf_index) {
        if (!MaterializeEntry(leaf_index).has_value()) {
            return false;
        }
    }
    return true;
}

uint256 ShieldedAccountRegistryState::Root() const
{
    std::vector<uint256> level;
    level.reserve(m_entries.size());
    for (const auto& entry : m_entries) {
        level.push_back(entry.entry_commitment);
    }
    return ComputeMerkleRoot(std::move(level), TAG_REGISTRY_NODE, TAG_REGISTRY_EMPTY);
}

ShieldedAccountRegistrySnapshot ShieldedAccountRegistryState::ExportSnapshot() const
{
    ShieldedAccountRegistrySnapshot snapshot;
    snapshot.entries.reserve(m_entries.size());
    for (uint64_t leaf_index = 0; leaf_index < m_entries.size(); ++leaf_index) {
        auto entry = MaterializeEntry(leaf_index);
        if (!entry.has_value()) {
            snapshot.version = 0;
            snapshot.entries.clear();
            return snapshot;
        }
        snapshot.entries.push_back(std::move(*entry));
    }
    return snapshot;
}

ShieldedAccountRegistryPersistedSnapshot ShieldedAccountRegistryState::ExportPersistedSnapshot() const
{
    ShieldedAccountRegistryPersistedSnapshot snapshot;
    snapshot.entries.reserve(m_entries.size());
    for (const auto& entry : m_entries) {
        if (entry.account_leaf_commitment.IsNull() || entry.entry_commitment.IsNull() || entry.spent) {
            snapshot.version = 0;
            snapshot.entries.clear();
            return snapshot;
        }
        snapshot.entries.push_back(ShieldedAccountRegistryPersistedEntry{
            .leaf_index = entry.leaf_index,
            .account_leaf_commitment = entry.account_leaf_commitment,
            .entry_commitment = entry.entry_commitment,
            .spent = entry.spent,
        });
    }
    return snapshot;
}

std::optional<ShieldedAccountRegistryState> ShieldedAccountRegistryState::Restore(
    const ShieldedAccountRegistrySnapshot& snapshot)
{
    ShieldedAccountRegistryState state = ShieldedAccountRegistryState::WithConfiguredPayloadStore();
    if (!state.LoadFromSnapshot(snapshot)) {
        return std::nullopt;
    }
    return state;
}

std::optional<ShieldedAccountRegistryState> ShieldedAccountRegistryState::RestorePersisted(
    const ShieldedAccountRegistryPersistedSnapshot& snapshot)
{
    ShieldedAccountRegistryState state = ShieldedAccountRegistryState::WithConfiguredPayloadStore();
    if (!state.LoadFromPersistedSnapshot(snapshot)) {
        return std::nullopt;
    }
    return state;
}

bool BuildRegistryAccountState(const ShieldedAccountRegistryState& registry,
                               std::map<uint256, smile2::CompactPublicAccount>& public_accounts,
                               std::map<uint256, uint256>& account_leaf_commitments)
{
    public_accounts.clear();
    account_leaf_commitments.clear();

    if (!registry.ForEachEntry([&](const ShieldedAccountRegistryEntry& entry) {
        if (!entry.IsValid()) {
            return false;
        }
        const auto leaf = DeserializeShieldedAccountLeafPayload(
            Span<const uint8_t>{entry.account_leaf_payload.data(), entry.account_leaf_payload.size()});
        if (!leaf.has_value()) {
            return false;
        }
        const auto account = BuildCompactPublicAccountFromAccountLeaf(*leaf);
        if (!account.has_value()) {
            return false;
        }
        public_accounts[leaf->note_commitment] = *account;
        account_leaf_commitments[leaf->note_commitment] = entry.account_leaf_commitment;
        return true;
    })) {
        return false;
    }
    return true;
}

bool VerifyShieldedAccountRegistrySpendWitness(const ShieldedAccountRegistrySpendWitness& witness,
                                               const ShieldedAccountRegistryState& registry,
                                               const uint256& expected_root)
{
    if (!witness.IsValid() || expected_root.IsNull() || witness.leaf_index >= registry.Size()) {
        return false;
    }
    const auto& entry = registry.m_entries[witness.leaf_index];
    if (entry.spent || entry.entry_commitment.IsNull() ||
        entry.account_leaf_commitment != witness.account_leaf_commitment) {
        return false;
    }
    return ComputeShieldedAccountRegistryPathRoot(
               entry.entry_commitment,
               witness.leaf_index,
               Span<const uint256>{witness.sibling_path.data(), witness.sibling_path.size()}) == expected_root;
}

uint256 ComputeNullifierSetCommitment(Span<const uint256> nullifiers)
{
    if (nullifiers.empty()) {
        return HashTaggedObject(TAG_NULLIFIER_SET, uint8_t{0});
    }

    std::vector<uint256> sorted{nullifiers.begin(), nullifiers.end()};
    if (std::any_of(sorted.begin(), sorted.end(), [](const uint256& nullifier) { return nullifier.IsNull(); })) {
        return uint256{};
    }
    std::sort(sorted.begin(), sorted.end());
    sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());

    std::vector<uint256> leaves;
    leaves.reserve(sorted.size());
    for (const uint256& nullifier : sorted) {
        leaves.push_back(HashTaggedObject(TAG_NULLIFIER_LEAF, nullifier));
    }

    return ComputeMerkleRoot(std::move(leaves), TAG_NULLIFIER_NODE, TAG_NULLIFIER_SET);
}

bool ShieldedStateCommitment::IsValid() const
{
    return version == REGISTRY_WIRE_VERSION &&
           !account_registry_root.IsNull() &&
           !nullifier_root.IsNull();
}

uint256 ComputeShieldedStateCommitmentHash(const ShieldedStateCommitment& commitment)
{
    if (!commitment.IsValid()) return uint256{};
    HashWriter hw;
    hw << std::string{TAG_STATE_COMMITMENT}
       << commitment.note_commitment_root
       << commitment.account_registry_root
       << commitment.nullifier_root
       << commitment.bridge_settlement_root;
    return hw.GetSHA256();
}

bool VerifyShieldedStateInclusion(const ShieldedStateCommitment& commitment,
                                  const ShieldedAccountRegistryProof& proof)
{
    return commitment.IsValid() &&
           VerifyShieldedAccountRegistryProof(proof, commitment.account_registry_root);
}

} // namespace shielded::registry
