// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_BANK_HASH_BRIDGE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_BANK_HASH_BRIDGE_H

#include <matmul/matmul_v4_rc_stage3_coupled_bank_product.h>
#include <matmul/matmul_v4_rc_stage3_ctl.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

/**
 * Bounded executable endpoint-28 -> endpoint-29 bridge.
 *
 * The producer Split-RAP proof contains, in one trace:
 *   - the complete six-column CoupledBank dequant relation;
 *   - an eight-bit unsigned byte decomposition;
 *   - OUTPUT = BYTE - 256*BIT7; and
 *   - a dual-lane CTL send for (page-byte-address, BYTE).
 *
 * Its R0 row group is exactly endpoint 28's sole ordered commitment to the
 * six dequant columns. BYTE, bit, address and CTL columns are in Rdep and are
 * algebraically constrained from that proof-owned signed OUTPUT.
 *
 * The consumer Split-RAP proof contains the witness-owned vertical SHA256d
 * AIR.  Its first-pass message-word/byte exports are already in SHA epoch R0.
 * Four sparse byte ports in that same trace receive exactly the bank-byte
 * interval.  Every prefix/padding byte in a partly private message word is
 * equality-pinned inside the SHA trace, so masking a word cannot hide a
 * malformed tag or padding byte.
 *
 * The two roots are absorbed before the shared CTL challenges.  The proof is
 * a local executable bridge, not consensus authority: the normalized parent
 * still has to execute both Split-RAP verifiers. Endpoint 28 V2 has no
 * parallel per-column public authority.
 */
inline constexpr uint16_t
    kRCStage3CoupledBankHashBridgeVersion = 1;
inline constexpr uint32_t
    kRCStage3CoupledBankHashBridgeBusId = 0x42323832U; // "B282"

struct RCStage3CoupledBankHashBridgeProofV1 {
    uint16_t version{kRCStage3CoupledBankHashBridgeVersion};
    uint32_t bank_byte_count{0};
    uint32_t first_pass_blocks{0};
    uint256 source_pin_commitment{};
    uint256 sha_public_statement{};
    /** Sole ordered endpoint-28 dequant R0 row root (AlgHash). */
    uint256 bank_byte_alg_hash_root{};
    /** Complete proof-owned SHA R0 row root, including input byte exports. */
    uint256 sha_r0_root{};
    RCStage3CtlManifest manifest;
    std::vector<RCStage3CtlChildPin> pins;
    air_quotient::AirQuotientSplitRapRowsProof producer_proof;
    air_quotient::AirQuotientSplitRapRowsProof sha_proof;
    uint256 producer_proof_commitment{};
    uint256 sha_proof_commitment{};
    uint256 proof_commitment{};
    uint256 terminal_bus_commitment{};
};

struct RCStage3CoupledBankHashBridgeAuditV1 {
    uint32_t bank_byte_count{0};
    uint32_t first_pass_blocks{0};
    uint64_t producer_sends{0};
    uint64_t sha_receives{0};
    bool signed_output_range_and_u8_same_trace{false};
    bool producer_ctl_value_same_trace{false};
    bool bank_byte_alg_hash_root_verified{false};
    bool sha_first_pass_bytes_epoch_r0{false};
    bool sha_nonbank_bytes_pinned{false};
    bool sha_ctl_value_same_trace{false};
    bool shared_post_r0_challenges{false};
    bool producer_split_rap_verified{false};
    bool sha_split_rap_verified{false};
    bool dual_lane_terminal_equality{false};
    bool local_bridge_executable{false};
    bool endpoint28_producer_root_bound{false};
    bool normalized_child_verifiers_execute{false};
    bool recursively_consumed{false};
    bool authority{false};
    std::vector<std::string> residuals;
    bool valid{false};
    std::string note;
};

/**
 * Prover helper. `public_prefix` is the immutable endpoint-29 domain tag.
 * The private message is public_prefix followed by the two's-complement byte
 * projection proved from relation OUTPUT. SHA256d padding and chaining are
 * generated canonically.
 */
[[nodiscard]] bool ProveRCStage3CoupledBankHashBridgeV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const std::vector<std::vector<gkr_field::Fp3>>& relation_columns,
    const std::vector<uint8_t>& public_prefix,
    const uint256& fs_seed,
    RCStage3CoupledBankHashBridgeProofV1& out,
    std::string* why = nullptr);

/**
 * Public verifier. It receives no bank bytes and never replays dequant or
 * SHA natively. It reconstructs the producer/SHA constraint systems from the
 * source statement, public prefix, byte count and the two committed R0 roots.
 */
[[nodiscard]] RCStage3CoupledBankHashBridgeAuditV1
VerifyRCStage3CoupledBankHashBridgeV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const std::vector<uint8_t>& public_prefix,
    const uint256& fs_seed,
    const RCStage3CoupledBankHashBridgeProofV1& proof);

} // namespace matmul::v4::rc

#endif
