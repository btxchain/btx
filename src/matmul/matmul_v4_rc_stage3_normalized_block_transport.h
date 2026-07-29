// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_BLOCK_TRANSPORT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_BLOCK_TRANSPORT_H

#include <matmul/matmul_v4_rc_stage3_normalized_relation_receipt_consumer.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class CBlock;

namespace matmul::v4::rc::normalized_block_transport {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace nav3 = normalized_authority;

/** Little-endian bytes "BNV3": the block carrier for one canonical NAV3 receipt. */
inline constexpr uint32_t kNormalizedBlockPayloadMagicV3 = 0x33564e42U;

/**
 * Canonical matrix_c_data envelope:
 *
 *   word[0] = kNormalizedBlockPayloadMagicV3
 *   word[1] = exact NAV3 byte length
 *   word[2..] = NAV3 bytes, little-endian within each word, zero padded
 *
 * Pack validates the complete NAV3 codec before emitting anything.  Unpack
 * requires the unique word count and zero padding and validates the decoded
 * receipt again.  Neither operation treats receipt hashes as mathematical
 * authority.
 */
[[nodiscard]] bool PackReceiptWordsV3(
    const std::vector<unsigned char>& receipt_bytes,
    std::vector<uint32_t>& out,
    std::string* why = nullptr);

[[nodiscard]] std::optional<std::vector<unsigned char>>
UnpackReceiptWordsV3(
    const std::vector<uint32_t>& words,
    std::string* why = nullptr);

[[nodiscard]] bool IsReceiptWordsV3(
    const std::vector<uint32_t>& words);

/** Atomic mechanism-layer attachment.  The block is unchanged on failure. */
[[nodiscard]] bool AttachReceiptV3(
    CBlock& block,
    const std::vector<unsigned char>& receipt_bytes,
    std::string* why = nullptr);

/**
 * Fresh verifier-side execution over the exact bytes carried by the block.
 *
 * The constraint system and verifier inputs must be rebuilt independently by
 * the caller.  This function never reconstructs episode/coupled witness data
 * and never accepts a serialized readiness bit: after strict envelope/NAV3
 * decoding it calls the native SAFE FixedTrace V3 parent verifier.
 *
 * This is a transport/mechanism API, not an activation API.  Consensus must not
 * call it until the canonical block-to-verifier rebuild and readiness gates are
 * complete.
 */
[[nodiscard]] bool VerifyAttachedReceiptV3(
    const CBlock& block,
    const aq::AirConstraintSystem<gf::Fp3>& rebuilt_parent_cs,
    const nav3::RebuiltVerifierInputsV3& rebuilt_inputs,
    aq::AirQuotientSplitRapRowsProof* decoded_parent_proof = nullptr,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::normalized_block_transport

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_BLOCK_TRANSPORT_H
