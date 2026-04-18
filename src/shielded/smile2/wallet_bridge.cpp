// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/smile2/wallet_bridge.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <logging.h>
#include <shielded/account_registry.h>
#include <shielded/lattice/params.h>
#include <shielded/smile2/ct_proof.h>
#include <shielded/smile2/membership.h>
#include <shielded/smile2/ntt.h>
#include <shielded/smile2/params.h>
#include <shielded/smile2/serialize.h>
#include <shielded/smile2/verify_dispatch.h>
#include <util/overflow.h>
#include <uint256.h>

#include <cassert>
#include <algorithm>
#include <cstring>

namespace smile2::wallet {

// Well-known global seed: SHA256("BTX-SMILE-V2-GLOBAL-MATRIX-SEED-V1")
const std::array<uint8_t, 32> SMILE_GLOBAL_SEED = []() {
    std::array<uint8_t, 32> seed{};
    CSHA256 hasher;
    const char* tag = "BTX-SMILE-V2-GLOBAL-MATRIX-SEED-V1";
    hasher.Write(reinterpret_cast<const uint8_t*>(tag), strlen(tag));
    hasher.Finalize(seed.data());
    return seed;
}();

namespace {

constexpr std::string_view TAG_SMILE_PROOF_ATTEMPT_SEED{"BTX_SMILE_V2_PROOF_ATTEMPT_SEED_V1"};
constexpr size_t MAX_SMILE_PROOF_SELF_VERIFY_ATTEMPTS{8};

std::array<uint8_t, 32> DeriveNoteSubKey(
    const ShieldedNote& note,
    const char* domain)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const uint8_t*>(domain), strlen(domain));
    hasher.Write(note.rho.begin(), note.rho.size());
    hasher.Write(note.rcm.begin(), note.rcm.size());
    hasher.Write(note.recipient_pk_hash.begin(), note.recipient_pk_hash.size());
    uint8_t value_buf[8];
    WriteLE64(value_buf, static_cast<uint64_t>(note.value));
    hasher.Write(value_buf, sizeof(value_buf));

    std::array<uint8_t, 32> result{};
    hasher.Finalize(result.data());
    return result;
}

// Convert a 32-byte hash into a deterministic key_seed for SampleTernary
uint64_t HashToKeySeed(const std::array<uint8_t, 32>& hash)
{
    const uint64_t seed = ReadLE64(hash.data());
    return seed == 0 ? 1 : seed; // Avoid zero seed
}

uint64_t DeriveProofAttemptSeed(Span<const uint8_t> rng_entropy, uint32_t attempt)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const uint8_t*>(TAG_SMILE_PROOF_ATTEMPT_SEED.data()),
                 TAG_SMILE_PROOF_ATTEMPT_SEED.size());
    hasher.Write(rng_entropy.data(), rng_entropy.size());
    uint8_t attempt_bytes[sizeof(attempt)];
    WriteLE32(attempt_bytes, attempt);
    hasher.Write(attempt_bytes, sizeof(attempt_bytes));

    std::array<uint8_t, 32> digest{};
    hasher.Finalize(digest.data());
    return HashToKeySeed(digest);
}

bool UseModernNoteTernaryDerivation(const ShieldedNote& note)
{
    return UsesModernShieldedNoteDerivation(note);
}

BDLOPCommitmentKey GetOutputCoinCommitmentKey()
{
    auto out_ck_seed = std::array<uint8_t, 32>{};
    out_ck_seed[0] = 0xCC;
    return BDLOPCommitmentKey::Generate(out_ck_seed, 1);
}

BDLOPCommitmentKey GetSerialNumberCommitmentKey()
{
    auto sn_ck_seed = std::array<uint8_t, 32>{};
    sn_ck_seed[0] = 0xAA;
    return BDLOPCommitmentKey::Generate(sn_ck_seed, 1);
}

SmilePolyVec DeriveOutputCoinOpeningFromNote(const ShieldedNote& note)
{
    const auto out_ck = GetOutputCoinCommitmentKey();
    const std::array<uint8_t, 32> seed =
        DeriveNoteSubKey(note, "BTX-SMILE-V2-NOTE-OUTPUT-COIN-OPENING");
    if (UseModernNoteTernaryDerivation(note)) {
        return SampleTernaryStrong(out_ck.rand_dim(), seed);
    }
    return SampleTernaryStrong(out_ck.rand_dim(), HashToKeySeed(seed));
}

BDLOPCommitment BuildOutputCoinFromNote(const ShieldedNote& note)
{
    const auto amount_poly = EncodeAmountToSmileAmountPoly(note.value);
    assert(amount_poly.has_value());
    const auto out_ck = GetOutputCoinCommitmentKey();
    return Commit(out_ck, {*amount_poly}, DeriveOutputCoinOpeningFromNote(note));
}

std::optional<uint256> ComputeDirectSendLeafCommitment(const uint256& note_commitment,
                                                       const CompactPublicAccount& account)
{
    const auto leaf = shielded::registry::BuildShieldedAccountLeaf(
        account,
        note_commitment,
        shielded::registry::AccountDomain::DIRECT_SEND);
    if (!leaf.has_value()) {
        return std::nullopt;
    }
    const uint256 account_leaf_commitment =
        shielded::registry::ComputeShieldedAccountLeafCommitment(*leaf);
    if (account_leaf_commitment.IsNull()) {
        return std::nullopt;
    }
    return account_leaf_commitment;
}

std::vector<std::vector<BDLOPCommitment>> BuildCoinRings(
    Span<const SmileRingMember> ring_members,
    size_t input_count)
{
    std::vector<BDLOPCommitment> ring;
    ring.reserve(ring_members.size());
    for (const auto& member : ring_members) {
        ring.push_back(member.public_coin);
    }

    std::vector<std::vector<BDLOPCommitment>> coin_rings;
    coin_rings.reserve(input_count);
    for (size_t i = 0; i < input_count; ++i) {
        coin_rings.push_back(ring);
    }
    return coin_rings;
}

std::vector<std::vector<CTPublicAccount>> BuildAccountRings(
    Span<const SmileRingMember> ring_members,
    Span<const SmileInputMaterial> inputs)
{
    std::vector<std::vector<CTPublicAccount>> account_rings;
    account_rings.reserve(inputs.size());
    for (const auto& input : inputs) {
        std::vector<CTPublicAccount> ring;
        ring.reserve(ring_members.size());
        for (const auto& member : ring_members) {
            ring.push_back(CTPublicAccount{
                member.note_commitment,
                member.public_key,
                member.public_coin,
                input.account_leaf_commitment,
            });
        }
        account_rings.push_back(std::move(ring));
    }
    return account_rings;
}

} // anonymous namespace

SmileKeyPair DeriveSmileKeyPairFromNote(
    const std::array<uint8_t, 32>& global_seed,
    const ShieldedNote& note)
{
    const std::array<uint8_t, 32> key_seed = DeriveNoteSubKey(note, "BTX-SMILE-V2-NOTE-TO-PK");
    if (UseModernNoteTernaryDerivation(note)) {
        return SmileKeyPair::Generate(global_seed, key_seed);
    }
    return SmileKeyPair::Generate(global_seed, HashToKeySeed(key_seed));
}

bool SmileRingMember::IsValid() const
{
    return !note_commitment.IsNull() &&
           !account_leaf_commitment.IsNull() &&
           public_key.pk.size() == KEY_ROWS &&
           public_key.A.size() == KEY_ROWS &&
           public_coin.t0.size() == BDLOP_RAND_DIM_BASE &&
           public_coin.t_msg.size() == 1 &&
           std::all_of(public_key.A.begin(), public_key.A.end(), [](const auto& row) {
               return row.size() == KEY_COLS;
           });
}

bool RingMembersMatch(const SmileRingMember& lhs, const SmileRingMember& rhs)
{
    return lhs.note_commitment == rhs.note_commitment &&
           lhs.account_leaf_commitment == rhs.account_leaf_commitment &&
           lhs.public_key.pk == rhs.public_key.pk &&
           lhs.public_key.A == rhs.public_key.A &&
           lhs.public_coin.t0 == rhs.public_coin.t0 &&
           lhs.public_coin.t_msg == rhs.public_coin.t_msg;
}

std::optional<SmileRingMember> BuildRingMemberFromNote(
    const std::array<uint8_t, 32>& global_seed,
    const ShieldedNote& note)
{
    return BuildRingMemberFromNote(global_seed, note, note.GetCommitment());
}

std::optional<SmileRingMember> BuildRingMemberFromNote(
    const std::array<uint8_t, 32>& global_seed,
    const ShieldedNote& note,
    const uint256& note_commitment)
{
    if (!note.IsValid() || note_commitment.IsNull()) {
        return std::nullopt;
    }
    CompactPublicAccount account;
    account.public_key = DeriveSmileKeyPairFromNote(global_seed, note).pub.pk;
    account.public_coin = BuildPublicCoinFromNote(note);
    if (!account.IsValid()) {
        return std::nullopt;
    }
    const auto account_leaf_commitment = ComputeDirectSendLeafCommitment(note_commitment, account);
    if (!account_leaf_commitment.has_value()) {
        return std::nullopt;
    }
    return BuildRingMemberFromNote(global_seed, note, note_commitment, *account_leaf_commitment);
}

std::optional<SmileRingMember> BuildRingMemberFromNote(
    const std::array<uint8_t, 32>& global_seed,
    const ShieldedNote& note,
    const uint256& note_commitment,
    const uint256& account_leaf_commitment)
{
    if (!note.IsValid() || note_commitment.IsNull()) {
        return std::nullopt;
    }

    SmileRingMember member;
    member.note_commitment = note_commitment;
    member.public_key = DeriveSmileKeyPairFromNote(global_seed, note).pub;
    member.public_coin = BuildPublicCoinFromNote(note);
    member.account_leaf_commitment = account_leaf_commitment;
    if (!member.IsValid()) {
        return std::nullopt;
    }
    return member;
}

std::optional<SmileRingMember> BuildRingMemberFromCompactPublicAccount(
    const std::array<uint8_t, 32>& global_seed,
    const uint256& note_commitment,
    const CompactPublicAccount& account)
{
    const auto account_leaf_commitment = ComputeDirectSendLeafCommitment(note_commitment, account);
    if (!account_leaf_commitment.has_value()) {
        return std::nullopt;
    }
    return BuildRingMemberFromCompactPublicAccount(global_seed,
                                                   note_commitment,
                                                   account,
                                                   *account_leaf_commitment);
}

std::optional<SmileRingMember> BuildRingMemberFromCompactPublicAccount(
    const std::array<uint8_t, 32>& global_seed,
    const uint256& note_commitment,
    const CompactPublicAccount& account,
    const uint256& account_leaf_commitment)
{
    if (note_commitment.IsNull() || !account.IsValid() ||
        ComputeCompactPublicAccountHash(account) != note_commitment) {
        return std::nullopt;
    }

    SmileRingMember member;
    member.note_commitment = note_commitment;
    member.public_key = ExpandCompactPublicKey(account, global_seed);
    member.public_coin = account.public_coin;
    member.account_leaf_commitment = account_leaf_commitment;
    if (!member.IsValid()) {
        return std::nullopt;
    }
    return member;
}

std::optional<CompactPublicAccount> BuildCompactPublicAccountFromNote(
    const std::array<uint8_t, 32>& global_seed,
    const ShieldedNote& note)
{
    const auto member = BuildRingMemberFromNote(global_seed, note);
    if (!member.has_value()) {
        return std::nullopt;
    }

    CompactPublicAccount account;
    account.public_key = member->public_key.pk;
    account.public_coin = member->public_coin;
    if (!account.IsValid()) {
        return std::nullopt;
    }
    return account;
}

SmilePolyVec DerivePublicCoinOpeningFromNote(const ShieldedNote& note)
{
    return DeriveOutputCoinOpeningFromNote(note);
}

BDLOPCommitment BuildPublicCoinFromNote(const ShieldedNote& note)
{
    return BuildOutputCoinFromNote(note);
}

std::optional<uint256> ComputeSmileNullifierFromNote(
    const std::array<uint8_t, 32>& global_seed,
    const ShieldedNote& note)
{
    if (!note.IsValid()) {
        return std::nullopt;
    }

    const auto key_pair = DeriveSmileKeyPairFromNote(global_seed, note);
    const SmilePoly serial_number = ComputeSerialNumber(GetSerialNumberCommitmentKey(), key_pair.sec);
    return ComputeSmileSerialHash(serial_number);
}

std::vector<SmilePublicKey> BuildAnonymitySet(Span<const SmileRingMember> ring_members)
{
    std::vector<SmilePublicKey> anon_set;
    anon_set.reserve(ring_members.size());
    for (const auto& member : ring_members) {
        anon_set.push_back(member.public_key);
    }
    return anon_set;
}

std::optional<SmileProofResult> CreateSmileProof(
    const std::array<uint8_t, 32>& global_seed,
    const std::vector<SmileInputMaterial>& inputs,
    const std::vector<ShieldedNote>& outputs,
    Span<const SmileRingMember> ring_members,
    Span<const uint8_t> rng_entropy,
    std::vector<uint256>& serial_hashes,
    int64_t public_fee,
    SmileProofCodecPolicy codec_policy,
    bool bind_anonset_context,
    std::string* error)
{
    static_assert(shielded::lattice::MAX_RING_SIZE <= NUM_NTT_SLOTS,
                  "DIRECT_SMILE supported ring size ceiling must fit in one SMILE recursion round");
    const auto fail = [&](const char* reason) -> std::optional<SmileProofResult> {
        LogDebug(BCLog::VALIDATION, "CreateSmileProof: aborting before prove loop: %s\n", reason);
        if (error != nullptr) *error = reason;
        return std::nullopt;
    };
    if (inputs.empty() || outputs.empty()) return fail("empty inputs or outputs");
    if (rng_entropy.size() < 32) return fail("insufficient rng entropy");
    if (ring_members.empty()) return fail("empty ring members");
    if (ring_members.size() > NUM_NTT_SLOTS) return fail("ring too large");
    if (public_fee < 0 || public_fee >= Q) return fail("public fee out of range");
    if (!std::all_of(ring_members.begin(), ring_members.end(), [](const SmileRingMember& member) {
            return member.IsValid();
        })) {
        return fail("invalid ring member");
    }

    int64_t total_input_amount{0};
    for (const auto& inp : inputs) {
        if (!inp.note.IsValid()) return fail("invalid input note");
        if (inp.ring_index >= ring_members.size()) return fail("input ring index out of range");
        if (inp.account_leaf_commitment.IsNull()) return fail("null input account leaf commitment");
        if (inp.note.value <= 0) return fail("input note value out of range");
        const uint256 effective_note_commitment =
            inp.note_commitment.IsNull() ? inp.note.GetCommitment() : inp.note_commitment;
        if (ring_members[inp.ring_index].note_commitment != effective_note_commitment) {
            return fail("input note commitment mismatch");
        }
        if (ring_members[inp.ring_index].account_leaf_commitment != inp.account_leaf_commitment) {
            return fail("input account leaf commitment mismatch");
        }
        if (!ring_members[inp.ring_index].IsValid()) return fail("invalid selected ring member");
        const auto canonical_member = BuildRingMemberFromNote(
            global_seed,
            inp.note,
            effective_note_commitment,
            inp.account_leaf_commitment);
        if (!canonical_member.has_value() ||
            !RingMembersMatch(ring_members[inp.ring_index], *canonical_member)) {
            return fail("selected ring member does not match canonical note derivation");
        }
        const auto next_total = CheckedAdd(total_input_amount, inp.note.value);
        if (!next_total) return fail("input total overflow");
        total_input_amount = *next_total;
    }

    int64_t total_output_amount{0};
    for (const ShieldedNote& output_note : outputs) {
        if (!output_note.IsValid()) return fail("invalid output note");
        if (output_note.value <= 0) return fail("output note value out of range");
        const auto next_total = CheckedAdd(total_output_amount, output_note.value);
        if (!next_total) return fail("output total overflow");
        total_output_amount = *next_total;
    }
    const auto total_output_plus_fee = CheckedAdd(total_output_amount, public_fee);
    if (!total_output_plus_fee) return fail("output-plus-fee overflow");
    if (total_input_amount != *total_output_plus_fee) {
        LogDebug(BCLog::VALIDATION,
                 "CreateSmileProof: amount mismatch total_input=%lld total_output=%lld public_fee=%lld\n",
                 static_cast<long long>(total_input_amount),
                 static_cast<long long>(total_output_amount),
                 static_cast<long long>(public_fee));
        return fail("input/output amount mismatch");
    }

    auto anon_set = BuildAnonymitySet(ring_members);
    if (anon_set.empty()) return fail("empty anonymity set");

    CTPublicData pub;
    pub.anon_set = std::move(anon_set);
    pub.coin_rings = BuildCoinRings(ring_members, inputs.size());
    pub.account_rings = BuildAccountRings(ring_members, inputs);

    std::vector<CTInput> ct_inputs;
    ct_inputs.reserve(inputs.size());

    for (const auto& inp : inputs) {
        auto kp = DeriveSmileKeyPairFromNote(global_seed, inp.note);

        CTInput ct_in;
        ct_in.secret_index = inp.ring_index;
        ct_in.sk = kp.sec;
        ct_in.coin_r = DerivePublicCoinOpeningFromNote(inp.note);
        ct_in.amount = inp.note.value;
        ct_inputs.push_back(std::move(ct_in));
    }

    std::vector<CTOutput> ct_outputs;
    ct_outputs.reserve(outputs.size());
    for (const ShieldedNote& output_note : outputs) {
        ct_outputs.push_back(CTOutput{output_note.value, DerivePublicCoinOpeningFromNote(output_note)});
    }

    std::optional<SmileCTProof> verified_proof;
    bool saw_candidate_proof{false};
    std::string prove_error;
    for (uint32_t attempt = 0; attempt < MAX_SMILE_PROOF_SELF_VERIFY_ATTEMPTS; ++attempt) {
        const uint64_t rng_seed = DeriveProofAttemptSeed(rng_entropy, attempt);
        LogDebug(BCLog::VALIDATION, "CreateSmileProof: starting ProveCT inputs=%u outputs=%u anon_set=%u attempt=%u\n",
                  static_cast<unsigned int>(ct_inputs.size()),
                  static_cast<unsigned int>(ct_outputs.size()),
                  static_cast<unsigned int>(pub.anon_set.size()),
                  attempt);
        auto proof = TryProveCT(ct_inputs,
                                ct_outputs,
                                pub,
                                rng_seed,
                                public_fee,
                                bind_anonset_context,
                                &prove_error);
        if (!proof.has_value()) {
            LogDebug(BCLog::VALIDATION, "CreateSmileProof: ProveCT exhausted or rejected attempt=%u\n", attempt);
            continue;
        }
        saw_candidate_proof = true;
        LogDebug(BCLog::VALIDATION, "CreateSmileProof: ProveCT done, serial_numbers=%u output_coins=%u attempt=%u\n",
                  static_cast<unsigned int>(proof->serial_numbers.size()),
                  static_cast<unsigned int>(proof->output_coins.size()),
                  attempt);
        if (VerifyCT(*proof,
                     ct_inputs.size(),
                     ct_outputs.size(),
                     pub,
                     public_fee,
                     bind_anonset_context)) {
            if (attempt != 0) {
                LogDebug(BCLog::VALIDATION, "CreateSmileProof: VerifyCT passed after retry attempt=%u\n", attempt);
            } else {
                LogDebug(BCLog::VALIDATION, "CreateSmileProof: VerifyCT passed\n");
            }
            verified_proof = std::move(*proof);
            break;
        }
        LogDebug(BCLog::VALIDATION, "CreateSmileProof: VerifyCT FAILED for inputs=%u outputs=%u anon_set=%u attempt=%u\n",
                  static_cast<unsigned int>(ct_inputs.size()),
                  static_cast<unsigned int>(ct_outputs.size()),
                  static_cast<unsigned int>(pub.anon_set.size()),
                  attempt);
    }
    if (!verified_proof.has_value()) {
        if (error != nullptr) {
            if (!saw_candidate_proof && !prove_error.empty()) {
                *error = prove_error;
            } else {
                *error = saw_candidate_proof ? "self-verify-failed" : "prove-exhausted";
            }
        }
        return std::nullopt;
    }
    SmileCTProof& proof = *verified_proof;

    // Extract serial number hashes for nullifier tracking
    serial_hashes.clear();
    serial_hashes.reserve(proof.serial_numbers.size());
    for (size_t i = 0; i < proof.serial_numbers.size(); ++i) {
        const uint256 serial_hash = ComputeSmileSerialHash(proof.serial_numbers[i]);
        const auto expected_nullifier = ComputeSmileNullifierFromNote(global_seed, inputs[i].note);
        if (!expected_nullifier.has_value() || *expected_nullifier != serial_hash) {
            if (error != nullptr) *error = "serial-mismatch";
            return std::nullopt;
        }
        serial_hashes.push_back(serial_hash);
    }

    // Extract output coins BEFORE serialization.
    // These are transmitted in the V2SendWitness, not inside the proof bytes.
    SmileProofResult result;
    result.output_coins = std::move(proof.output_coins);
    for (size_t i = 0; i < outputs.size(); ++i) {
        const BDLOPCommitment expected_output_coin = BuildPublicCoinFromNote(outputs[i]);
        if (result.output_coins[i].t0 != expected_output_coin.t0 ||
            result.output_coins[i].t_msg != expected_output_coin.t_msg) {
            if (error != nullptr) *error = "output-coin-mismatch";
            return std::nullopt;
        }
    }

    // Clear the output coins from the proof so SerializeCTProof does not include them.
    proof.output_coins.clear();

    // Serialize only the core proof (without coins/keys).
    result.proof_bytes = SerializeCTProof(proof, codec_policy);

    // Size breakdown logging
    LogDebug(BCLog::VALIDATION, "CreateSmileProof: proof_bytes=%u aux_t0=%u_polys aux_tmsg=%u_polys z=%u_polys z0=%u_inputs tuples=%u serial=%u g0=512 h2=124 seeds=32\n",
              static_cast<unsigned int>(result.proof_bytes.size()),
              static_cast<unsigned int>(proof.aux_commitment.t0.size()),
              static_cast<unsigned int>(proof.aux_commitment.t_msg.size()),
              static_cast<unsigned int>(proof.z.size()),
              static_cast<unsigned int>(proof.z0.size()),
              static_cast<unsigned int>(proof.input_tuples.size()),
              static_cast<unsigned int>(proof.serial_numbers.size()));

    return result;
}

} // namespace smile2::wallet
