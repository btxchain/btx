// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/smile2/verify_dispatch.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <shielded/smile2/ct_proof.h>
#include <shielded/smile2/params.h>
#include <shielded/smile2/serialize.h>
#include <shielded/smile2/wallet_bridge.h>
#include <hash.h>
#include <uint256.h>

#include <set>

namespace smile2 {

namespace {

void AppendCoinToHash(HashWriter& hw, const BDLOPCommitment& output_coin)
{
    for (const auto& poly : output_coin.t0) {
        std::vector<uint8_t> encoded;
        SerializePolyCompressed(poly, encoded, COMPRESS_D);
        hw.write(MakeByteSpan(encoded));
    }
    for (const auto& poly : output_coin.t_msg) {
        std::vector<uint8_t> encoded;
        SerializePoly(poly, encoded);
        hw.write(MakeByteSpan(encoded));
    }
}

void AppendPublicKeyToHash(HashWriter& hw, const SmilePublicKey& public_key)
{
    for (const auto& poly : public_key.pk) {
        std::vector<uint8_t> encoded;
        SerializePolyCompressed(poly, encoded, COMPRESS_D);
        hw.write(MakeByteSpan(encoded));
    }
    for (const auto& row : public_key.A) {
        for (const auto& poly : row) {
            std::vector<uint8_t> encoded;
            SerializePoly(poly, encoded);
            hw.write(MakeByteSpan(encoded));
        }
    }
}

} // namespace

std::optional<std::string> ParseSmile2Proof(
    const std::vector<uint8_t>& proof_bytes,
    size_t num_inputs,
    size_t num_outputs,
    SmileCTProof& proof,
    bool reject_rice_codec)
{
    // Size plausibility checks (DoS protection)
    if (proof_bytes.empty()) {
        return std::string{"bad-smile2-proof-missing"};
    }
    if (proof_bytes.size() < MIN_SMILE2_PROOF_BYTES) {
        return std::string{"bad-smile2-proof-too-small"};
    }
    if (proof_bytes.size() > MAX_SMILE2_PROOF_BYTES) {
        return std::string{"bad-smile2-proof-oversize"};
    }

    // Input/output count bounds
    if (num_inputs == 0 || num_inputs > 16) {
        return std::string{"bad-smile2-proof-input-count"};
    }
    if (num_outputs == 0 || num_outputs > 16) {
        return std::string{"bad-smile2-proof-output-count"};
    }

    // Deserialize
    switch (DecodeCTProof(proof_bytes, proof, num_inputs, num_outputs, reject_rice_codec)) {
    case SmileCTDecodeStatus::OK:
        break;
    case SmileCTDecodeStatus::DISALLOWED_RICE_CODEC:
        return std::string{"bad-smile2-proof-rice-codec"};
    case SmileCTDecodeStatus::MALFORMED:
        return std::string{"bad-smile2-proof-encoding"};
    }

    // Structural checks on deserialized proof
    if (proof.serial_numbers.size() != num_inputs) {
        return std::string{"bad-smile2-proof-serial-count"};
    }
    if (proof.z0.size() != num_inputs) {
        return std::string{"bad-smile2-proof-z0-count"};
    }
    // Output coins are NOT in the serialized proof — they come from the transaction.

    if (reject_rice_codec) {
        const auto canonical_bytes =
            SerializeCTProof(proof, SmileProofCodecPolicy::CANONICAL_NO_RICE);
        if (canonical_bytes != proof_bytes) {
            return std::string{"bad-smile2-proof-noncanonical-codec"};
        }
    }

    return std::nullopt;
}

std::optional<std::string> ValidateSmile2Proof(
    const SmileCTProof& proof,
    size_t num_inputs,
    size_t num_outputs,
    const std::vector<BDLOPCommitment>& output_coins,
    const CTPublicData& pub,
    int64_t public_fee,
    bool bind_anonset_context)
{
    const uint8_t expected_wire_version =
        bind_anonset_context
            ? SmileCTProof::WIRE_VERSION_M4_HARDENED
            : SmileCTProof::WIRE_VERSION_LEGACY;
    if (proof.wire_version != expected_wire_version) {
        return std::string{"bad-smile2-proof-wire-version"};
    }

    SmileCTProof proof_for_verification = proof;

    // Output coins are transmitted in the V2SendWitness (not inside the proof
    // bytes).  When provided (non-empty), verify the count matches and install
    // them into the proof struct so VerifyCT can use them.  When empty (e.g.
    // test harness calling ProveCT directly), VerifyCT uses the proof's own
    // output_coins populated by ProveCT at creation time.
    if (!output_coins.empty()) {
        if (output_coins.size() != num_outputs) {
            return std::string{"bad-smile2-proof-output-coin-count"};
        }
        proof_for_verification.output_coins = output_coins;
    }

    if (!VerifyCT(proof_for_verification,
                  num_inputs,
                  num_outputs,
                  pub,
                  public_fee,
                  bind_anonset_context)) {
        return std::string{"bad-smile2-proof-invalid"};
    }
    return std::nullopt;
}

std::optional<std::string> VerifySmile2CTFromBytes(
    const std::vector<uint8_t>& proof_bytes,
    size_t num_inputs,
    size_t num_outputs,
    const std::vector<BDLOPCommitment>& output_coins,
    const CTPublicData& pub,
    int64_t public_fee,
    bool reject_rice_codec,
    bool bind_anonset_context)
{
    SmileCTProof proof;
    auto parse_err = ParseSmile2Proof(proof_bytes,
                                      num_inputs,
                                      num_outputs,
                                      proof,
                                      reject_rice_codec);
    if (parse_err.has_value()) return parse_err;

    return ValidateSmile2Proof(proof,
                               num_inputs,
                               num_outputs,
                               output_coins,
                               pub,
                               public_fee,
                               bind_anonset_context);
}

std::optional<std::string> ExtractSmile2SerialNumbers(
    const SmileCTProof& proof,
    std::vector<SmilePoly>& serial_numbers)
{
    if (proof.serial_numbers.empty()) {
        return std::string{"bad-smile2-proof-no-serial-numbers"};
    }

    // Verify each serial number is non-null (at least one non-zero coefficient)
    for (size_t i = 0; i < proof.serial_numbers.size(); ++i) {
        SmilePoly sn = proof.serial_numbers[i];
        sn.Reduce();
        bool all_zero = true;
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            if (sn.coeffs[c] != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            return std::string{"bad-smile2-proof-null-serial-number"};
        }
    }

    // D3-1b/D3-2 fix: detect duplicate serial numbers within the same proof
    // M7 audit fix: add domain separator to prevent cross-context hash collisions
    std::set<uint256> seen_hashes;
    static constexpr char DUP_SERIAL_DOMAIN[] = "BTX_SMILE2_Dup_Serial_V1";
    for (const auto& sn : proof.serial_numbers) {
        // Hash the polynomial with domain separator for duplicate detection
        CSHA256 hasher;
        hasher.Write(reinterpret_cast<const uint8_t*>(DUP_SERIAL_DOMAIN), sizeof(DUP_SERIAL_DOMAIN) - 1);
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            uint8_t buf[8];
            WriteLE64(buf, static_cast<uint64_t>(mod_q(sn.coeffs[c])));
            hasher.Write(buf, sizeof(buf));
        }
        uint256 hash;
        hasher.Finalize(hash.begin());
        if (!seen_hashes.insert(hash).second) {
            return std::string{"bad-smile2-proof-duplicate-serial-number"};
        }
    }

    serial_numbers = proof.serial_numbers;
    return std::nullopt;
}

uint256 ComputeSmileSerialHash(const SmilePoly& serial_number)
{
    HashWriter hw;
    hw << std::string{"BTX_SMILE2_Serial_Nullifier_V1"};
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        const int64_t c = mod_q(serial_number.coeffs[i]);
        uint8_t buf[8];
        buf[0] = static_cast<uint8_t>(c);
        buf[1] = static_cast<uint8_t>(c >> 8);
        buf[2] = static_cast<uint8_t>(c >> 16);
        buf[3] = static_cast<uint8_t>(c >> 24);
        buf[4] = static_cast<uint8_t>(c >> 32);
        buf[5] = static_cast<uint8_t>(c >> 40);
        buf[6] = static_cast<uint8_t>(c >> 48);
        buf[7] = static_cast<uint8_t>(c >> 56);
        hw.write(AsBytes(Span<const uint8_t>{buf, sizeof(buf)}));
    }
    return hw.GetSHA256();
}

uint256 ComputeSmileOutputCoinHash(const BDLOPCommitment& output_coin)
{
    HashWriter hw;
    hw << std::string{"BTX_SMILE2_Output_Coin_V1"};
    AppendCoinToHash(hw, output_coin);
    return hw.GetSHA256();
}

uint256 ComputeSmileDirectInputBindingHash(
    Span<const wallet::SmileRingMember> ring_members,
    const uint256& merkle_anchor,
    uint32_t spend_index,
    const uint256& nullifier)
{
    HashWriter hw;
    hw << std::string{"BTX_SMILE2_Direct_Input_Binding_V1"}
       << merkle_anchor
       << spend_index
       << nullifier
       << static_cast<uint64_t>(ring_members.size());
    for (const auto& member : ring_members) {
        hw << member.note_commitment;
        hw << member.account_leaf_commitment;
        AppendPublicKeyToHash(hw, member.public_key);
        AppendCoinToHash(hw, member.public_coin);
    }
    return hw.GetSHA256();
}

} // namespace smile2
