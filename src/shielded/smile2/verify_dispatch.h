// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_SMILE2_VERIFY_DISPATCH_H
#define BTX_SHIELDED_SMILE2_VERIFY_DISPATCH_H

#include <shielded/smile2/ct_proof.h>
#include <shielded/smile2/serialize.h>
#include <span.h>

#include <cstdint>
#include <optional>
#include <string>
#include <uint256.h>
#include <vector>

namespace smile2::wallet {
struct SmileRingMember;
} // namespace smile2::wallet

namespace smile2 {

/**
 * Consensus validation entry point for SMILE v2 CT proofs.
 *
 * This mirrors the CShieldedProofCheck pattern used by the existing
 * MatRiCT validation path, providing a drop-in replacement once
 * SMILE v2 is activated.
 *
 * Workflow:
 *   1. ParseSmile2Proof()    — decode bytes into SmileCTProof
 *   2. ValidateSmile2Proof() — verify the proof against public data
 *
 * Both return std::nullopt on success, or a reject reason string.
 */

/** Maximum serialized SMILE v2 proof size in bytes.
 *  A 16-in-16-out at N=2^25 is the upper bound (~350 KB from paper Fig 3).
 *  Set to 512 KB to accommodate with headroom. */
static constexpr size_t MAX_SMILE2_PROOF_BYTES{512 * 1024};

/** Minimum plausible proof size in bytes for DoS protection.
 *  A 1-in-1-out at N=32 is the smallest valid proof (~15 KB). */
static constexpr size_t MIN_SMILE2_PROOF_BYTES{8 * 1024};

/**
 * Parse a serialized SMILE v2 CT proof from raw bytes.
 *
 * @param proof_bytes  Serialized proof data.
 * @param num_inputs   Expected number of inputs (from transaction structure).
 * @param num_outputs  Expected number of outputs.
 * @param[out] proof   Parsed proof on success.
 * @return std::nullopt on success, reject reason string on failure.
 */
[[nodiscard]] std::optional<std::string> ParseSmile2Proof(
    const std::vector<uint8_t>& proof_bytes,
    size_t num_inputs,
    size_t num_outputs,
    SmileCTProof& proof,
    bool reject_rice_codec = false);

/**
 * Validate a parsed SMILE v2 CT proof against public data.
 *
 * Checks:
 *   - h2 first d/l coefficients are zero (balance + framework proof)
 *   - Fiat-Shamir transcript consistency over the anonymity set, coin rings,
 *     and output coins
 *   - Key relation A·z0 = w0 + c0·pk for each input
 *   - Serial number presence and non-nullity
 *
 * Note: this validates the rebased in-tree reset-chain `DIRECT_SMILE`
 * launch verifier. Remaining work on
 * the registry-redesign activation branch
 * work rather than completion of the base Figure 17 launch relation.
 *
 * @param proof       Parsed SMILE v2 proof.
 * @param num_inputs  Number of inputs.
 * @param num_outputs Number of outputs.
 * @param pub         Public data (anonymity set, coin rings).
 * @return std::nullopt on success, reject reason string on failure.
 */
[[nodiscard]] std::optional<std::string> ValidateSmile2Proof(
    const SmileCTProof& proof,
    size_t num_inputs,
    size_t num_outputs,
    const std::vector<BDLOPCommitment>& output_coins,
    const CTPublicData& pub,
    int64_t public_fee = 0,
    bool bind_anonset_context = false);

/**
 * Combined parse + validate in one call (convenience for consensus).
 *
 * @param proof_bytes   Serialized proof data.
 * @param num_inputs    Expected number of inputs.
 * @param num_outputs   Expected number of outputs.
 * @param output_coins  Output coin commitments from the transaction.
 * @param pub           Public data.
 * @return std::nullopt on success, reject reason string on failure.
 */
[[nodiscard]] std::optional<std::string> VerifySmile2CTFromBytes(
    const std::vector<uint8_t>& proof_bytes,
    size_t num_inputs,
    size_t num_outputs,
    const std::vector<BDLOPCommitment>& output_coins,
    const CTPublicData& pub,
    int64_t public_fee = 0,
    bool reject_rice_codec = false,
    bool bind_anonset_context = false);

/**
 * Extract serial numbers from a parsed SMILE v2 proof.
 * Used for nullifier/double-spend checking at the consensus layer.
 *
 * @param proof       Parsed proof.
 * @param[out] serial_numbers  Extracted serial number polynomials.
 * @return std::nullopt on success, reject reason string on failure.
 */
[[nodiscard]] std::optional<std::string> ExtractSmile2SerialNumbers(
    const SmileCTProof& proof,
    std::vector<SmilePoly>& serial_numbers);

/** Canonical nullifier hash for a SMILE serial-number polynomial. */
[[nodiscard]] uint256 ComputeSmileSerialHash(const SmilePoly& serial_number);

/** Canonical hash for a public SMILE output coin commitment. */
[[nodiscard]] uint256 ComputeSmileOutputCoinHash(const BDLOPCommitment& output_coin);

/** Canonical hash for the public direct-spend input binding in a shared SMILE ring. */
[[nodiscard]] uint256 ComputeSmileDirectInputBindingHash(
    Span<const wallet::SmileRingMember> ring_members,
    const uint256& merkle_anchor,
    uint32_t spend_index,
    const uint256& nullifier);

} // namespace smile2

#endif // BTX_SHIELDED_SMILE2_VERIFY_DISPATCH_H
