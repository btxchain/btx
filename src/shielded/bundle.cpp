// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/bundle.h>

#include <consensus/amount.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/common.h>
#include <crypto/hkdf_sha256_32.h>
#include <hash.h>
#include <random.h>
#include <shielded/account_registry.h>
#include <shielded/lattice/params.h>
#include <shielded/v2_ingress.h>
#include <shielded/v2_proof.h>
#include <support/cleanse.h>
#include <util/overflow.h>

#include <algorithm>
#include <set>
#include <limits>
#include <string>
#include <stdexcept>

namespace {
constexpr const char* VIEW_GRANT_SALT{"BTX-Shielded-ViewGrant"};
constexpr const char* VIEW_GRANT_INFO{"BTX-ViewGrant-V1"};
constexpr const char* CTV_V2_BUNDLE_TAG{"BTX-CTV-Shielded-Bundle-V2"};
// Verify cost units calibrated for SMILE v2 lattice proofs.
// SMILE amortizes membership + balance + range across all inputs in a single
// BDLOP commitment with one z vector. Measured: ~23ms for 2-in-2-out on 4-core.
// Previous MatRiCT+ values (760/102) artificially capped throughput to ~88 txns/block.
constexpr uint64_t SHIELDED_VERIFY_UNITS_PER_DIRECT_SPEND{100};
constexpr uint64_t SHIELDED_VERIFY_UNITS_PER_DIRECT_OUTPUT{15};
constexpr uint64_t SHIELDED_VERIFY_UNITS_PER_SETTLEMENT_PROOF{100};

[[nodiscard]] std::optional<CAmount> CheckedSumPositiveReserveDeltas(
    Span<const shielded::v2::ReserveDelta> deltas,
    std::string& reject_reason)
{
    CAmount total_positive{0};
    for (const auto& delta : deltas) {
        if (!MoneyRangeSigned(delta.reserve_delta)) {
            reject_reason = "bad-shielded-v2-rebalance-deltas";
            return std::nullopt;
        }
        if (delta.reserve_delta <= 0) continue;

        const auto next_total = CheckedAdd(total_positive, delta.reserve_delta);
        if (!next_total || !MoneyRange(*next_total)) {
            reject_reason = "bad-shielded-v2-rebalance-deltas";
            return std::nullopt;
        }
        total_positive = *next_total;
    }
    return total_positive;
}

[[nodiscard]] size_t GetV2ShieldedInputCount(const shielded::v2::TransactionBundle& bundle)
{
    switch (shielded::v2::GetBundleSemanticFamily(bundle)) {
    case shielded::v2::TransactionFamily::V2_SEND:
        return std::get<shielded::v2::SendPayload>(bundle.payload).spends.size();
    case shielded::v2::TransactionFamily::V2_LIFECYCLE:
        return 0;
    case shielded::v2::TransactionFamily::V2_INGRESS_BATCH:
        return std::get<shielded::v2::IngressBatchPayload>(bundle.payload).consumed_spends.size();
    case shielded::v2::TransactionFamily::V2_EGRESS_BATCH:
    case shielded::v2::TransactionFamily::V2_REBALANCE:
    case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
    case shielded::v2::TransactionFamily::V2_GENERIC:
        return 0;
    }
    return 0;
}

[[nodiscard]] size_t GetV2ShieldedOutputCount(const shielded::v2::TransactionBundle& bundle)
{
    switch (shielded::v2::GetBundleSemanticFamily(bundle)) {
    case shielded::v2::TransactionFamily::V2_SEND:
        return std::get<shielded::v2::SendPayload>(bundle.payload).outputs.size();
    case shielded::v2::TransactionFamily::V2_LIFECYCLE:
        return 0;
    case shielded::v2::TransactionFamily::V2_INGRESS_BATCH:
        return std::get<shielded::v2::IngressBatchPayload>(bundle.payload).reserve_outputs.size();
    case shielded::v2::TransactionFamily::V2_EGRESS_BATCH:
        return std::get<shielded::v2::EgressBatchPayload>(bundle.payload).outputs.size();
    case shielded::v2::TransactionFamily::V2_REBALANCE:
        return std::get<shielded::v2::RebalancePayload>(bundle.payload).reserve_outputs.size();
    case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
    case shielded::v2::TransactionFamily::V2_GENERIC:
        return 0;
    }
    return 0;
}

[[nodiscard]] uint64_t GetProofEnvelopeVerifyUnits(const shielded::v2::ProofEnvelope& envelope)
{
    switch (envelope.proof_kind) {
    case shielded::v2::ProofKind::DIRECT_MATRICT:
    case shielded::v2::ProofKind::DIRECT_SMILE:
    case shielded::v2::ProofKind::GENERIC_SMILE:
    case shielded::v2::ProofKind::GENERIC_OPAQUE:
        return SHIELDED_VERIFY_UNITS_PER_SETTLEMENT_PROOF;
    case shielded::v2::ProofKind::BATCH_MATRICT:
    case shielded::v2::ProofKind::BATCH_SMILE:
    case shielded::v2::ProofKind::IMPORTED_RECEIPT:
    case shielded::v2::ProofKind::IMPORTED_CLAIM:
    case shielded::v2::ProofKind::GENERIC_BRIDGE:
        return SHIELDED_VERIFY_UNITS_PER_SETTLEMENT_PROOF;
    case shielded::v2::ProofKind::NONE:
        return 0;
    }
    return 0;
}

[[nodiscard]] uint64_t GetProofEnvelopeVerifyUnits(const shielded::v2::ProofEnvelope& envelope,
                                                   size_t proof_shard_count)
{
    switch (envelope.proof_kind) {
    case shielded::v2::ProofKind::BATCH_MATRICT:
    case shielded::v2::ProofKind::BATCH_SMILE:
    case shielded::v2::ProofKind::IMPORTED_RECEIPT:
    case shielded::v2::ProofKind::IMPORTED_CLAIM:
    case shielded::v2::ProofKind::GENERIC_BRIDGE:
    case shielded::v2::ProofKind::GENERIC_OPAQUE: {
        const uint64_t shard_count = std::max<uint64_t>(1, proof_shard_count);
        if (shard_count > std::numeric_limits<uint64_t>::max() / SHIELDED_VERIFY_UNITS_PER_SETTLEMENT_PROOF) {
            return std::numeric_limits<uint64_t>::max();
        }
        return SHIELDED_VERIFY_UNITS_PER_SETTLEMENT_PROOF * shard_count;
    }
    case shielded::v2::ProofKind::DIRECT_MATRICT:
    case shielded::v2::ProofKind::DIRECT_SMILE:
    case shielded::v2::ProofKind::GENERIC_SMILE:
    case shielded::v2::ProofKind::NONE:
        return GetProofEnvelopeVerifyUnits(envelope);
    }
    return 0;
}

[[nodiscard]] uint64_t GetDirectShieldedSpendVerifyUnits(const shielded::v2::TransactionBundle& bundle)
{
    size_t ring_size = shielded::lattice::DEFAULT_RING_SIZE;
    if (bundle.header.proof_envelope.proof_kind != shielded::v2::ProofKind::NONE) {
        std::string reject_reason;
        const auto witness = shielded::v2::proof::ParseV2SendWitness(bundle, reject_reason);
        if (witness.has_value() && !witness->spends.empty()) {
            ring_size = witness->spends.front().ring_positions.size();
        }
    }
    if (!shielded::lattice::IsSupportedRingSize(ring_size)) {
        ring_size = shielded::lattice::DEFAULT_RING_SIZE;
    }
    return (SHIELDED_VERIFY_UNITS_PER_DIRECT_SPEND * static_cast<uint64_t>(ring_size)) /
           static_cast<uint64_t>(shielded::lattice::DEFAULT_RING_SIZE);
}
} // namespace

CViewGrant CViewGrant::Create(Span<const uint8_t> view_key, const mlkem::PublicKey& operator_pk)
{
    std::array<uint8_t, mlkem::ENCAPS_SEEDBYTES> kem_seed;
    std::array<uint8_t, 12> nonce;
    GetStrongRandBytes(Span<unsigned char>{kem_seed.data(), kem_seed.size()});
    GetStrongRandBytes(Span<unsigned char>{nonce.data(), nonce.size()});

    auto result = CreateDeterministic(view_key, operator_pk, kem_seed, nonce);
    memory_cleanse(kem_seed.data(), kem_seed.size());
    memory_cleanse(nonce.data(), nonce.size());
    return result;
}

CViewGrant CViewGrant::CreateDeterministic(Span<const uint8_t> view_key,
                                           const mlkem::PublicKey& operator_pk,
                                           Span<const uint8_t> kem_seed,
                                           Span<const uint8_t> nonce)
{
    const size_t max_view_key_size = MAX_VIEW_GRANT_ENCRYPTED_DATA_SIZE - AEADChaCha20Poly1305::EXPANSION;
    if (view_key.size() > max_view_key_size) {
        throw std::invalid_argument("CViewGrant::Create oversized view_key");
    }
    if (kem_seed.size() != mlkem::ENCAPS_SEEDBYTES) {
        throw std::invalid_argument("CViewGrant::CreateDeterministic kem_seed size mismatch");
    }
    if (nonce.size() != 12) {
        throw std::invalid_argument("CViewGrant::CreateDeterministic nonce must be 12 bytes");
    }

    auto kem = mlkem::EncapsDerand(operator_pk, kem_seed);

    std::vector<uint8_t, secure_allocator<uint8_t>> aead_key(32, 0);
    CHKDF_HMAC_SHA256_L32 hkdf(kem.ss.data(), kem.ss.size(), VIEW_GRANT_SALT);
    hkdf.Expand32(VIEW_GRANT_INFO, aead_key.data());

    CViewGrant out;
    out.kem_ct = kem.ct;
    std::copy(nonce.begin(), nonce.end(), out.nonce.begin());
    out.encrypted_data.resize(view_key.size() + AEADChaCha20Poly1305::EXPANSION);

    {
        AEADChaCha20Poly1305 aead(MakeByteSpan(aead_key));
        const uint32_t nonce_prefix = ReadLE32(out.nonce.data());
        const uint64_t nonce_suffix = ReadLE64(out.nonce.data() + 4);
        const AEADChaCha20Poly1305::Nonce96 nonce96{nonce_prefix, nonce_suffix};
        aead.Encrypt(AsBytes(view_key),
                     MakeByteSpan(out.kem_ct),
                     nonce96,
                     MakeWritableByteSpan(out.encrypted_data));
    }

    memory_cleanse(kem.ss.data(), kem.ss.size());
    memory_cleanse(aead_key.data(), aead_key.size());
    return out;
}

std::optional<CViewGrant::SecureBytes> CViewGrant::Decrypt(const mlkem::SecretKey& operator_sk) const
{
    if (encrypted_data.size() > MAX_VIEW_GRANT_ENCRYPTED_DATA_SIZE) {
        return std::nullopt;
    }
    if (encrypted_data.size() < AEADChaCha20Poly1305::EXPANSION) {
        return std::nullopt;
    }

    auto ss = mlkem::Decaps(kem_ct, operator_sk);

    std::vector<uint8_t, secure_allocator<uint8_t>> aead_key(32, 0);
    CHKDF_HMAC_SHA256_L32 hkdf(ss.data(), ss.size(), VIEW_GRANT_SALT);
    hkdf.Expand32(VIEW_GRANT_INFO, aead_key.data());

    // R5-212: Use secure_allocator to prevent plaintext from being paged to swap.
    std::vector<uint8_t, secure_allocator<uint8_t>> plaintext_secure(encrypted_data.size() - AEADChaCha20Poly1305::EXPANSION);
    bool ok{false};
    {
        AEADChaCha20Poly1305 aead(MakeByteSpan(aead_key));
        const uint32_t nonce_prefix = ReadLE32(nonce.data());
        const uint64_t nonce_suffix = ReadLE64(nonce.data() + 4);
        const AEADChaCha20Poly1305::Nonce96 nonce96{nonce_prefix, nonce_suffix};
        ok = aead.Decrypt(MakeByteSpan(encrypted_data),
                          MakeByteSpan(kem_ct),
                          nonce96,
                          MakeWritableByteSpan(plaintext_secure));
    }

    memory_cleanse(ss.data(), ss.size());
    memory_cleanse(aead_key.data(), aead_key.size());

    if (!ok) {
        memory_cleanse(plaintext_secure.data(), plaintext_secure.size());
        return std::nullopt;
    }
    CViewGrant::SecureBytes result(plaintext_secure.begin(), plaintext_secure.end());
    memory_cleanse(plaintext_secure.data(), plaintext_secure.size());
    return result;
}

bool CShieldedBundle::IsEmpty() const
{
    return !HasV2Bundle() &&
           shielded_inputs.empty() &&
           shielded_outputs.empty() &&
           view_grants.empty() &&
           proof.empty() &&
           value_balance == 0;
}

bool CShieldedBundle::HasLegacyDirectSpendData() const
{
    return !shielded_inputs.empty() ||
           !shielded_outputs.empty() ||
           !view_grants.empty() ||
           !proof.empty() ||
           value_balance != 0;
}

bool CShieldedBundle::HasShieldedInputs() const
{
    return GetShieldedInputCount() != 0;
}

bool CShieldedBundle::HasShieldedOutputs() const
{
    return GetShieldedOutputCount() != 0;
}

size_t CShieldedBundle::GetShieldedInputCount() const
{
    if (v2_bundle) {
        return GetV2ShieldedInputCount(*v2_bundle);
    }
    return shielded_inputs.size();
}

size_t CShieldedBundle::GetShieldedOutputCount() const
{
    if (v2_bundle) {
        return GetV2ShieldedOutputCount(*v2_bundle);
    }
    return shielded_outputs.size();
}

size_t CShieldedBundle::GetProofSize() const
{
    if (v2_bundle) {
        return v2_bundle->proof_payload.size();
    }
    return proof.size();
}

bool CShieldedBundle::IsShieldOnly() const
{
    if (HasV2Bundle()) return false;
    return shielded_inputs.empty() &&
           !shielded_outputs.empty() &&
           value_balance < 0;
}

bool CShieldedBundle::IsUnshieldOnly() const
{
    if (HasV2Bundle()) return false;
    return !shielded_inputs.empty() &&
           shielded_outputs.empty() &&
           value_balance > 0;
}

bool CShieldedBundle::IsFullyShielded() const
{
    if (HasV2Bundle()) return false;
    return !shielded_inputs.empty() &&
           !shielded_outputs.empty() &&
           value_balance == 0;
}

bool CShieldedBundle::CheckStructure() const
{
    if (IsEmpty()) return false;
    if (HasV2Bundle()) {
        return !HasLegacyDirectSpendData() && v2_bundle->IsValid();
    }
    if (shielded_inputs.size() > MAX_SHIELDED_SPENDS_PER_TX) return false;
    if (shielded_outputs.size() > MAX_SHIELDED_OUTPUTS_PER_TX) return false;
    if (view_grants.size() > MAX_VIEW_GRANTS_PER_TX) return false;
    if (proof.size() > MAX_SHIELDED_PROOF_BYTES) return false;
    if (!MoneyRangeSigned(value_balance)) return false;

    // Enforce turnstile directionality at bundle-structure level:
    // positive value balance (unshielding) must consume shielded notes,
    // and negative value balance (shielding) must create shielded notes.
    if (value_balance > 0 && shielded_inputs.empty()) return false;
    if (value_balance < 0 && shielded_outputs.empty()) return false;
    // A zero-balance one-sided bundle is nonsensical and weakens invariants.
    if (value_balance == 0 && (shielded_inputs.empty() != shielded_outputs.empty())) return false;

    std::set<uint256> input_nullifiers;
    for (const auto& in : shielded_inputs) {
        if (in.nullifier.IsNull()) return false;
        if (!shielded::lattice::IsSupportedRingSize(in.ring_positions.size())) return false;
        if (!input_nullifiers.insert(in.nullifier).second) return false;
    }

    std::set<uint256> output_commitments;
    for (const auto& out : shielded_outputs) {
        if (out.note_commitment.IsNull()) return false;
        if (!output_commitments.insert(out.note_commitment).second) return false;
        if (out.merkle_anchor.IsNull()) return false;
        if (out.encrypted_note.aead_ciphertext.size() > shielded::EncryptedNote::MAX_AEAD_CIPHERTEXT_SIZE) {
            return false;
        }
        if (out.encrypted_note.aead_ciphertext.size() < AEADChaCha20Poly1305::EXPANSION) {
            return false;
        }
        // Per-output range proof bytes are deprecated; MatRiCT proof carries range statements.
        if (!out.range_proof.empty()) return false;
    }

    for (const auto& view_grant : view_grants) {
        if (view_grant.encrypted_data.size() > MAX_VIEW_GRANT_ENCRYPTED_DATA_SIZE) return false;
        if (view_grant.encrypted_data.size() < AEADChaCha20Poly1305::EXPANSION) return false;
    }

    if (shielded_inputs.empty()) {
        if (!proof.empty()) return false;
    } else {
        if (proof.empty()) return false;
    }

    return true;
}

uint256 ComputeShieldedBundleCtvHash(const CShieldedBundle& bundle)
{
    HashWriter hw{};
    if (bundle.HasV2Bundle()) {
        hw << std::string{CTV_V2_BUNDLE_TAG};
        hw << *bundle.GetV2Bundle();
        return hw.GetSHA256();
    }

    hw << bundle.value_balance;
    hw << bundle.shielded_inputs;
    hw << bundle.shielded_outputs;
    hw << bundle.view_grants;
    hw << bundle.proof;
    return hw.GetSHA256();
}

std::vector<Nullifier> CollectShieldedNullifiers(const CShieldedBundle& bundle)
{
    std::vector<Nullifier> out;
    out.reserve(bundle.GetShieldedInputCount());

    if (bundle.HasV2Bundle()) {
        const auto* v2_bundle = bundle.GetV2Bundle();
        switch (shielded::v2::GetBundleSemanticFamily(*v2_bundle)) {
        case shielded::v2::TransactionFamily::V2_SEND: {
            const auto& payload = std::get<shielded::v2::SendPayload>(v2_bundle->payload);
            for (const auto& spend : payload.spends) {
                out.push_back(spend.nullifier);
            }
            break;
        }
        case shielded::v2::TransactionFamily::V2_INGRESS_BATCH: {
            const auto& payload = std::get<shielded::v2::IngressBatchPayload>(v2_bundle->payload);
            for (const auto& spend : payload.consumed_spends) {
                out.push_back(spend.nullifier);
            }
            break;
        }
        case shielded::v2::TransactionFamily::V2_LIFECYCLE:
        case shielded::v2::TransactionFamily::V2_EGRESS_BATCH:
        case shielded::v2::TransactionFamily::V2_REBALANCE:
        case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
        case shielded::v2::TransactionFamily::V2_GENERIC:
            break;
        }
        return out;
    }

    for (const auto& spend : bundle.shielded_inputs) {
        out.push_back(spend.nullifier);
    }
    return out;
}

std::vector<uint256> CollectShieldedOutputCommitments(const CShieldedBundle& bundle)
{
    std::vector<uint256> out;
    out.reserve(bundle.GetShieldedOutputCount());

    if (bundle.HasV2Bundle()) {
        const auto* v2_bundle = bundle.GetV2Bundle();
        switch (shielded::v2::GetBundleSemanticFamily(*v2_bundle)) {
        case shielded::v2::TransactionFamily::V2_SEND: {
            const auto& payload = std::get<shielded::v2::SendPayload>(v2_bundle->payload);
            for (const auto& output : payload.outputs) {
                out.push_back(output.note_commitment);
            }
            break;
        }
        case shielded::v2::TransactionFamily::V2_INGRESS_BATCH: {
            const auto& payload = std::get<shielded::v2::IngressBatchPayload>(v2_bundle->payload);
            for (const auto& output : payload.reserve_outputs) {
                out.push_back(output.note_commitment);
            }
            break;
        }
        case shielded::v2::TransactionFamily::V2_EGRESS_BATCH: {
            const auto& payload = std::get<shielded::v2::EgressBatchPayload>(v2_bundle->payload);
            for (const auto& output : payload.outputs) {
                out.push_back(output.note_commitment);
            }
            break;
        }
        case shielded::v2::TransactionFamily::V2_REBALANCE: {
            const auto& payload = std::get<shielded::v2::RebalancePayload>(v2_bundle->payload);
            for (const auto& output : payload.reserve_outputs) {
                out.push_back(output.note_commitment);
            }
            break;
        }
        case shielded::v2::TransactionFamily::V2_LIFECYCLE:
        case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
        case shielded::v2::TransactionFamily::V2_GENERIC:
            break;
        }
        return out;
    }

    for (const auto& output : bundle.shielded_outputs) {
        out.push_back(output.note_commitment);
    }
    return out;
}

std::vector<std::pair<uint256, smile2::CompactPublicAccount>> CollectShieldedOutputSmileAccounts(
    const CShieldedBundle& bundle)
{
    std::vector<std::pair<uint256, smile2::CompactPublicAccount>> out;
    out.reserve(bundle.GetShieldedOutputCount());

    const auto append_outputs = [&](const auto& outputs) {
        for (const auto& output : outputs) {
            if (output.smile_account.has_value()) {
                out.emplace_back(output.note_commitment, *output.smile_account);
            }
        }
    };

    if (bundle.HasV2Bundle()) {
        const auto* v2_bundle = bundle.GetV2Bundle();
        switch (shielded::v2::GetBundleSemanticFamily(*v2_bundle)) {
        case shielded::v2::TransactionFamily::V2_SEND:
            append_outputs(std::get<shielded::v2::SendPayload>(v2_bundle->payload).outputs);
            break;
        case shielded::v2::TransactionFamily::V2_LIFECYCLE:
            break;
        case shielded::v2::TransactionFamily::V2_INGRESS_BATCH:
            append_outputs(std::get<shielded::v2::IngressBatchPayload>(v2_bundle->payload).reserve_outputs);
            break;
        case shielded::v2::TransactionFamily::V2_EGRESS_BATCH:
            append_outputs(std::get<shielded::v2::EgressBatchPayload>(v2_bundle->payload).outputs);
            break;
        case shielded::v2::TransactionFamily::V2_REBALANCE:
            append_outputs(std::get<shielded::v2::RebalancePayload>(v2_bundle->payload).reserve_outputs);
            break;
        case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
        case shielded::v2::TransactionFamily::V2_GENERIC:
            break;
        }
        return out;
    }

    return out;
}

std::optional<std::vector<uint256>> CollectShieldedOutputAccountLeafCommitments(
    const CShieldedBundle& bundle,
    bool use_nonced_bridge_tag)
{
    std::vector<uint256> out;
    out.reserve(bundle.GetShieldedOutputCount());

    const auto append_leaf_commitment =
        [&](const std::optional<shielded::registry::ShieldedAccountLeaf>& account_leaf) -> bool {
        if (!account_leaf.has_value()) return false;
        const uint256 commitment = shielded::registry::ComputeShieldedAccountLeafCommitment(*account_leaf);
        if (commitment.IsNull()) return false;
        out.push_back(commitment);
        return true;
    };

    if (bundle.HasV2Bundle()) {
        const auto* v2_bundle = bundle.GetV2Bundle();
        switch (shielded::v2::GetBundleSemanticFamily(*v2_bundle)) {
        case shielded::v2::TransactionFamily::V2_SEND: {
            const auto& payload = std::get<shielded::v2::SendPayload>(v2_bundle->payload);
            for (const auto& output : payload.outputs) {
                if (!append_leaf_commitment(shielded::registry::BuildDirectSendAccountLeaf(output))) {
                    return std::nullopt;
                }
            }
            break;
        }
        case shielded::v2::TransactionFamily::V2_LIFECYCLE:
            break;
        case shielded::v2::TransactionFamily::V2_INGRESS_BATCH: {
            const auto& payload = std::get<shielded::v2::IngressBatchPayload>(v2_bundle->payload);
            for (const auto& output : payload.reserve_outputs) {
                if (!append_leaf_commitment(
                        shielded::registry::BuildIngressAccountLeaf(output,
                                                                    payload.settlement_binding_digest,
                                                                    use_nonced_bridge_tag))) {
                    return std::nullopt;
                }
            }
            break;
        }
        case shielded::v2::TransactionFamily::V2_EGRESS_BATCH: {
            const auto& payload = std::get<shielded::v2::EgressBatchPayload>(v2_bundle->payload);
            for (const auto& output : payload.outputs) {
                if (!append_leaf_commitment(
                        shielded::registry::BuildEgressAccountLeaf(output,
                                                                   payload.settlement_binding_digest,
                                                                   payload.output_binding_digest,
                                                                   use_nonced_bridge_tag))) {
                    return std::nullopt;
                }
            }
            break;
        }
        case shielded::v2::TransactionFamily::V2_REBALANCE: {
            const auto& payload = std::get<shielded::v2::RebalancePayload>(v2_bundle->payload);
            for (const auto& output : payload.reserve_outputs) {
                if (!append_leaf_commitment(
                        shielded::registry::BuildRebalanceAccountLeaf(output,
                                                                      payload.settlement_binding_digest,
                                                                      use_nonced_bridge_tag))) {
                    return std::nullopt;
                }
            }
            break;
        }
        case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
        case shielded::v2::TransactionFamily::V2_GENERIC:
            break;
        }
        return out;
    }

    return out;
}

std::optional<std::vector<shielded::registry::ShieldedAccountLeaf>>
shielded::registry::CollectShieldedOutputAccountLeaves(const CShieldedBundle& bundle,
                                                       bool use_nonced_bridge_tag)
{
    std::vector<shielded::registry::ShieldedAccountLeaf> out;
    out.reserve(bundle.GetShieldedOutputCount());

    const auto append_leaf =
        [&](const std::optional<shielded::registry::ShieldedAccountLeaf>& account_leaf) -> bool {
        if (!account_leaf.has_value()) return false;
        out.push_back(*account_leaf);
        return true;
    };

    if (bundle.HasV2Bundle()) {
        const auto* v2_bundle = bundle.GetV2Bundle();
        switch (shielded::v2::GetBundleSemanticFamily(*v2_bundle)) {
        case shielded::v2::TransactionFamily::V2_SEND: {
            const auto& payload = std::get<shielded::v2::SendPayload>(v2_bundle->payload);
            for (const auto& output : payload.outputs) {
                if (!append_leaf(shielded::registry::BuildDirectSendAccountLeaf(output))) {
                    return std::nullopt;
                }
            }
            break;
        }
        case shielded::v2::TransactionFamily::V2_LIFECYCLE:
            break;
        case shielded::v2::TransactionFamily::V2_INGRESS_BATCH: {
            const auto& payload = std::get<shielded::v2::IngressBatchPayload>(v2_bundle->payload);
            for (const auto& output : payload.reserve_outputs) {
                if (!append_leaf(shielded::registry::BuildIngressAccountLeaf(
                        output,
                        payload.settlement_binding_digest,
                        use_nonced_bridge_tag))) {
                    return std::nullopt;
                }
            }
            break;
        }
        case shielded::v2::TransactionFamily::V2_EGRESS_BATCH: {
            const auto& payload = std::get<shielded::v2::EgressBatchPayload>(v2_bundle->payload);
            for (const auto& output : payload.outputs) {
                if (!append_leaf(shielded::registry::BuildEgressAccountLeaf(
                        output,
                        payload.settlement_binding_digest,
                        payload.output_binding_digest,
                        use_nonced_bridge_tag))) {
                    return std::nullopt;
                }
            }
            break;
        }
        case shielded::v2::TransactionFamily::V2_REBALANCE: {
            const auto& payload = std::get<shielded::v2::RebalancePayload>(v2_bundle->payload);
            for (const auto& output : payload.reserve_outputs) {
                if (!append_leaf(shielded::registry::BuildRebalanceAccountLeaf(
                        output,
                        payload.settlement_binding_digest,
                        use_nonced_bridge_tag))) {
                    return std::nullopt;
                }
            }
            break;
        }
        case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
        case shielded::v2::TransactionFamily::V2_GENERIC:
            break;
        }
        return out;
    }

    return out;
}

std::optional<std::vector<std::pair<uint256, uint256>>> CollectShieldedOutputAccountLeafEntries(
    const CShieldedBundle& bundle,
    bool use_nonced_bridge_tag)
{
    std::vector<std::pair<uint256, uint256>> out;
    out.reserve(bundle.GetShieldedOutputCount());

    const auto append_leaf_entry =
        [&](const uint256& note_commitment,
            const std::optional<shielded::registry::ShieldedAccountLeaf>& account_leaf) -> bool {
        if (!account_leaf.has_value()) return false;
        const uint256 account_leaf_commitment =
            shielded::registry::ComputeShieldedAccountLeafCommitment(*account_leaf);
        if (note_commitment.IsNull() || account_leaf_commitment.IsNull()) return false;
        out.emplace_back(note_commitment, account_leaf_commitment);
        return true;
    };

    if (bundle.HasV2Bundle()) {
        const auto* v2_bundle = bundle.GetV2Bundle();
        switch (shielded::v2::GetBundleSemanticFamily(*v2_bundle)) {
        case shielded::v2::TransactionFamily::V2_SEND: {
            const auto& payload = std::get<shielded::v2::SendPayload>(v2_bundle->payload);
            for (const auto& output : payload.outputs) {
                if (!append_leaf_entry(output.note_commitment,
                                       shielded::registry::BuildDirectSendAccountLeaf(output))) {
                    return std::nullopt;
                }
            }
            break;
        }
        case shielded::v2::TransactionFamily::V2_LIFECYCLE:
            break;
        case shielded::v2::TransactionFamily::V2_INGRESS_BATCH: {
            const auto& payload = std::get<shielded::v2::IngressBatchPayload>(v2_bundle->payload);
            for (const auto& output : payload.reserve_outputs) {
                if (!append_leaf_entry(
                        output.note_commitment,
                        shielded::registry::BuildIngressAccountLeaf(output,
                                                                    payload.settlement_binding_digest,
                                                                    use_nonced_bridge_tag))) {
                    return std::nullopt;
                }
            }
            break;
        }
        case shielded::v2::TransactionFamily::V2_EGRESS_BATCH: {
            const auto& payload = std::get<shielded::v2::EgressBatchPayload>(v2_bundle->payload);
            for (const auto& output : payload.outputs) {
                if (!append_leaf_entry(
                        output.note_commitment,
                        shielded::registry::BuildEgressAccountLeaf(output,
                                                                   payload.settlement_binding_digest,
                                                                   payload.output_binding_digest,
                                                                   use_nonced_bridge_tag))) {
                    return std::nullopt;
                }
            }
            break;
        }
        case shielded::v2::TransactionFamily::V2_REBALANCE: {
            const auto& payload = std::get<shielded::v2::RebalancePayload>(v2_bundle->payload);
            for (const auto& output : payload.reserve_outputs) {
                if (!append_leaf_entry(
                        output.note_commitment,
                        shielded::registry::BuildRebalanceAccountLeaf(output,
                                                                      payload.settlement_binding_digest,
                                                                      use_nonced_bridge_tag))) {
                    return std::nullopt;
                }
            }
            break;
        }
        case shielded::v2::TransactionFamily::V2_GENERIC:
            return std::nullopt;
        case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
            break;
        }
        return out;
    }

    return out;
}

std::vector<uint256> CollectShieldedAnchors(const CShieldedBundle& bundle)
{
    std::vector<uint256> out;

    if (bundle.HasV2Bundle()) {
        const auto* v2_bundle = bundle.GetV2Bundle();
        switch (shielded::v2::GetBundleSemanticFamily(*v2_bundle)) {
        case shielded::v2::TransactionFamily::V2_SEND: {
            const auto& payload = std::get<shielded::v2::SendPayload>(v2_bundle->payload);
            out.reserve(payload.spends.size() + (payload.spends.empty() ? 0 : 1));
            if (!payload.spends.empty()) {
                out.push_back(payload.spend_anchor);
            }
            for (const auto& spend : payload.spends) {
                out.push_back(spend.merkle_anchor);
            }
            break;
        }
        case shielded::v2::TransactionFamily::V2_LIFECYCLE:
            break;
        case shielded::v2::TransactionFamily::V2_INGRESS_BATCH: {
            const auto& payload = std::get<shielded::v2::IngressBatchPayload>(v2_bundle->payload);
            out.push_back(payload.spend_anchor);
            break;
        }
        case shielded::v2::TransactionFamily::V2_EGRESS_BATCH:
        case shielded::v2::TransactionFamily::V2_REBALANCE:
        case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
        case shielded::v2::TransactionFamily::V2_GENERIC:
            break;
        }
        return out;
    }

    out.reserve(bundle.shielded_outputs.size());
    for (const auto& output : bundle.shielded_outputs) {
        out.push_back(output.merkle_anchor);
    }
    return out;
}

std::vector<uint256> CollectShieldedAccountRegistryRefs(const CShieldedBundle& bundle)
{
    std::vector<uint256> out;
    if (!bundle.HasV2Bundle()) return out;

    const auto* v2_bundle = bundle.GetV2Bundle();
    if (v2_bundle == nullptr) return out;

    switch (shielded::v2::GetBundleSemanticFamily(*v2_bundle)) {
    case shielded::v2::TransactionFamily::V2_SEND: {
        const auto& payload = std::get<shielded::v2::SendPayload>(v2_bundle->payload);
        if (!payload.account_registry_anchor.IsNull()) {
            out.push_back(payload.account_registry_anchor);
        }
        break;
    }
    case shielded::v2::TransactionFamily::V2_INGRESS_BATCH: {
        const auto& payload = std::get<shielded::v2::IngressBatchPayload>(v2_bundle->payload);
        if (!payload.account_registry_anchor.IsNull()) {
            out.push_back(payload.account_registry_anchor);
        }
        break;
    }
    case shielded::v2::TransactionFamily::V2_EGRESS_BATCH:
    case shielded::v2::TransactionFamily::V2_REBALANCE:
    case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
    case shielded::v2::TransactionFamily::V2_LIFECYCLE:
    case shielded::v2::TransactionFamily::V2_GENERIC:
        break;
    }
    return out;
}

std::vector<uint256> CollectShieldedSettlementAnchorRefs(const CShieldedBundle& bundle)
{
    std::vector<uint256> out;
    if (!bundle.HasV2Bundle()) return out;

    const auto* v2_bundle = bundle.GetV2Bundle();
    if (v2_bundle == nullptr) return out;

    switch (shielded::v2::GetBundleSemanticFamily(*v2_bundle)) {
    case shielded::v2::TransactionFamily::V2_EGRESS_BATCH:
        out.push_back(std::get<shielded::v2::EgressBatchPayload>(v2_bundle->payload).settlement_anchor);
        break;
    case shielded::v2::TransactionFamily::V2_LIFECYCLE:
    case shielded::v2::TransactionFamily::V2_SEND:
    case shielded::v2::TransactionFamily::V2_INGRESS_BATCH:
    case shielded::v2::TransactionFamily::V2_REBALANCE:
    case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
    case shielded::v2::TransactionFamily::V2_GENERIC:
        break;
    }
    return out;
}

CAmount GetShieldedStateValueBalance(const CShieldedBundle& bundle)
{
    std::string reject_reason;
    const auto value_balance = TryGetShieldedStateValueBalance(bundle, reject_reason);
    return value_balance.value_or(0);
}

std::optional<CAmount> TryGetShieldedStateValueBalance(const CShieldedBundle& bundle,
                                                       std::string& reject_reason)
{
    if (!bundle.HasV2Bundle()) {
        return bundle.value_balance;
    }

    const auto* v2_bundle = bundle.GetV2Bundle();
    if (v2_bundle == nullptr) {
        reject_reason = "bad-shielded-v2-bundle";
        return std::nullopt;
    }

    switch (shielded::v2::GetBundleSemanticFamily(*v2_bundle)) {
    case shielded::v2::TransactionFamily::V2_SEND:
        return std::get<shielded::v2::SendPayload>(v2_bundle->payload).value_balance;
    case shielded::v2::TransactionFamily::V2_LIFECYCLE:
        return CAmount{0};
    case shielded::v2::TransactionFamily::V2_INGRESS_BATCH: {
        const auto& payload = std::get<shielded::v2::IngressBatchPayload>(v2_bundle->payload);
        auto witness = shielded::v2::ParseV2IngressWitness(*v2_bundle, reject_reason);
        if (!witness.has_value()) return std::nullopt;

        const auto state_delta = CheckedAdd(witness->header.statement.total_amount, payload.fee);
        if (!state_delta || !MoneyRange(*state_delta)) {
            reject_reason = "bad-shielded-v2-ingress-amount";
            return std::nullopt;
        }
        return *state_delta;
    }
    case shielded::v2::TransactionFamily::V2_EGRESS_BATCH: {
        auto witness = shielded::v2::proof::ParseSettlementWitness(v2_bundle->proof_payload,
                                                                   reject_reason);
        if (!witness.has_value()) return std::nullopt;
        return -witness->statement.total_amount;
    }
    case shielded::v2::TransactionFamily::V2_REBALANCE: {
        const auto& payload = std::get<shielded::v2::RebalancePayload>(v2_bundle->payload);
        auto total_positive = CheckedSumPositiveReserveDeltas(
            Span<const shielded::v2::ReserveDelta>{payload.reserve_deltas.data(),
                                                   payload.reserve_deltas.size()},
            reject_reason);
        if (!total_positive.has_value()) return std::nullopt;
        return -*total_positive;
    }
    case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
    case shielded::v2::TransactionFamily::V2_GENERIC:
        return CAmount{0};
    }

    reject_reason = "bad-shielded-v2-contextual";
    return std::nullopt;
}

CAmount GetShieldedTxValueBalance(const CShieldedBundle& bundle)
{
    if (!bundle.HasV2Bundle()) {
        return bundle.value_balance;
    }

    const auto* v2_bundle = bundle.GetV2Bundle();
    if (v2_bundle == nullptr) return 0;

    switch (shielded::v2::GetBundleSemanticFamily(*v2_bundle)) {
    case shielded::v2::TransactionFamily::V2_SEND:
        return std::get<shielded::v2::SendPayload>(v2_bundle->payload).value_balance;
    case shielded::v2::TransactionFamily::V2_LIFECYCLE:
        return 0;
    case shielded::v2::TransactionFamily::V2_INGRESS_BATCH:
        return std::get<shielded::v2::IngressBatchPayload>(v2_bundle->payload).fee;
    case shielded::v2::TransactionFamily::V2_EGRESS_BATCH:
    case shielded::v2::TransactionFamily::V2_REBALANCE:
    case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
    case shielded::v2::TransactionFamily::V2_GENERIC:
        return 0;
    }

    return 0;
}

namespace shielded {

bool UseShieldedCanonicalFeeBuckets(const Consensus::Params& consensus, int32_t height)
{
    return consensus.IsShieldedMatRiCTDisabled(height);
}

bool IsCanonicalShieldedFee(CAmount fee,
                            const Consensus::Params& consensus,
                            int32_t height)
{
    if (!UseShieldedCanonicalFeeBuckets(consensus, height) || fee == 0) {
        return true;
    }
    if (!MoneyRange(fee) || fee < 0) {
        return false;
    }
    return fee % SHIELDED_PRIVACY_FEE_QUANTUM == 0;
}

CAmount RoundShieldedFeeToCanonicalBucket(CAmount fee,
                                          const Consensus::Params& consensus,
                                          int32_t height)
{
    if (!UseShieldedCanonicalFeeBuckets(consensus, height) ||
        fee <= 0 ||
        !MoneyRange(fee)) {
        return fee;
    }

    const CAmount remainder = fee % SHIELDED_PRIVACY_FEE_QUANTUM;
    if (remainder == 0) {
        return fee;
    }
    return fee + (SHIELDED_PRIVACY_FEE_QUANTUM - remainder);
}

} // namespace shielded

uint64_t GetShieldedVerifyCost(const CShieldedBundle& bundle)
{
    return GetShieldedResourceUsage(bundle).verify_units;
}

ShieldedResourceUsage GetShieldedResourceUsage(const CShieldedBundle& bundle)
{
    ShieldedResourceUsage usage;

    if (!bundle.HasV2Bundle()) {
        usage.verify_units =
            static_cast<uint64_t>(bundle.shielded_inputs.size()) * SHIELDED_VERIFY_UNITS_PER_DIRECT_SPEND +
            static_cast<uint64_t>(bundle.shielded_outputs.size()) * SHIELDED_VERIFY_UNITS_PER_DIRECT_OUTPUT;
        usage.scan_units = bundle.shielded_outputs.size();
        usage.tree_update_units = bundle.shielded_inputs.size() + bundle.shielded_outputs.size();
        return usage;
    }

    const auto& v2_bundle = *bundle.GetV2Bundle();
    switch (shielded::v2::GetBundleSemanticFamily(v2_bundle)) {
    case shielded::v2::TransactionFamily::V2_SEND: {
        const auto& payload = std::get<shielded::v2::SendPayload>(v2_bundle.payload);
        const uint64_t spend_verify_units =
            payload.spends.empty() ? 0 : GetDirectShieldedSpendVerifyUnits(v2_bundle);
        usage.verify_units =
            static_cast<uint64_t>(payload.spends.size()) * spend_verify_units +
            static_cast<uint64_t>(payload.outputs.size()) * SHIELDED_VERIFY_UNITS_PER_DIRECT_OUTPUT;
        usage.scan_units = payload.outputs.size();
        usage.tree_update_units = payload.spends.size() + payload.outputs.size();
        break;
    }
    case shielded::v2::TransactionFamily::V2_LIFECYCLE:
        break;
    case shielded::v2::TransactionFamily::V2_INGRESS_BATCH: {
        const auto& payload = std::get<shielded::v2::IngressBatchPayload>(v2_bundle.payload);
        usage.verify_units = GetProofEnvelopeVerifyUnits(v2_bundle.header.proof_envelope,
                                                         v2_bundle.proof_shards.size());
        usage.tree_update_units = payload.consumed_spends.size() + payload.reserve_outputs.size();
        break;
    }
    case shielded::v2::TransactionFamily::V2_EGRESS_BATCH: {
        const auto& payload = std::get<shielded::v2::EgressBatchPayload>(v2_bundle.payload);
        usage.verify_units = GetProofEnvelopeVerifyUnits(v2_bundle.header.proof_envelope,
                                                         v2_bundle.proof_shards.size());
        usage.scan_units = payload.outputs.size() + v2_bundle.output_chunks.size();
        usage.tree_update_units = payload.outputs.size();
        break;
    }
    case shielded::v2::TransactionFamily::V2_REBALANCE: {
        const auto& payload = std::get<shielded::v2::RebalancePayload>(v2_bundle.payload);
        usage.verify_units = GetProofEnvelopeVerifyUnits(v2_bundle.header.proof_envelope,
                                                         v2_bundle.proof_shards.size());
        usage.tree_update_units = payload.reserve_outputs.size();
        break;
    }
    case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
    case shielded::v2::TransactionFamily::V2_GENERIC:
        usage.verify_units = GetProofEnvelopeVerifyUnits(v2_bundle.header.proof_envelope,
                                                         v2_bundle.proof_shards.size());
        break;
    }

    return usage;
}
