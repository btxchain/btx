// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_CANONICAL_ROLE_CHILD_ATTACHMENT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_CANONICAL_ROLE_CHILD_ATTACHMENT_H

#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>
#include <matmul/matmul_v4_rc_stage3_canonical_parent_production_verifier.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

class CBlock;

namespace Consensus {
struct Params;
}

namespace matmul::v4::rc::canonical_role_child_attachment {

namespace aqc = canonical_parent_production_verifier;
namespace aq = air_quotient;
namespace cpc = canonical_parent_consensus;
namespace u2 = universal_two_child_parent;

inline constexpr uint16_t kVersionV1 = 2;
inline constexpr uint32_t kChildCountV1 = 2;
inline constexpr size_t kMaxAttachmentBytesV1 =
    kRCStage3MaxProofBytes;

struct ChildEnvelopeV1 {
    uint16_t version{kVersionV1};
    uint16_t child_index{0};
    uint256 program_root{};
    uint256 shape_commitment{};
    uint256 phase_commitment{};
    uint256 child_identity{};
    std::vector<uint32_t> r0_base_column_indices;
    uint256 proof_root{};
    std::vector<unsigned char> proof_bytes;
    air_quotient::AirQuotientSplitRapRowsProof proof;
};

/**
 * Canonical ingress result for the two seven-role proof artifacts.
 *
 * `valid` means the byte envelopes, proof roots, ordered child identities,
 * consensus registry root, canonical ProgramTables and manifest-derived
 * shapes all match an independently reconstructed network assessment.
 *
 * It deliberately does not claim native child acceptance.  This transport now
 * admits only the SAFE Split-RAP V2 proof type and binds the independently
 * reconstructed, program-owned R0 schedule into each child identity.  The
 * normalized parent still has to replay and accept those proofs inside its own
 * relation system; until that consumer executes,
 * `native_child_proofs_verified` and `parent_consumption_compatible` remain
 * false.
 */
struct ValidatedPairV1 {
    uint16_t version{kVersionV1};
    aqc::FrozenSpecAssessmentV1 assessment;
    cpc::FrozenBinaryParentSpecV1 frozen_spec;
    uint256 consensus_registry_root{};
    std::array<ChildEnvelopeV1, kChildCountV1> child;
    uint256 pair_root{};
    bool exact_child_count{false};
    bool canonical_child_order{false};
    bool program_roots_reconstructed{false};
    bool shapes_reconstructed{false};
    bool r0_schedules_reconstructed{false};
    bool phase_commitments_verified{false};
    bool child_identities_verified{false};
    bool proof_codecs_canonical{false};
    bool proof_roots_verified{false};
    bool pair_root_verified{false};
    bool registry_root_verified{false};
    bool native_child_proofs_verified{false};
    bool parent_consumption_compatible{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] uint256 ComputeChildProofRootV1(
    uint16_t child_index,
    const uint256& child_identity,
    const std::vector<unsigned char>& canonical_proof_bytes);

[[nodiscard]] uint256 ComputeChildIdentityV1(
    uint16_t child_index,
    const uint256& program_root,
    const uint256& shape_commitment,
    const uint256& phase_commitment,
    const std::vector<uint32_t>&
        r0_base_column_indices);

[[nodiscard]] uint256 ComputePairRootV1(
    const uint256& consensus_registry_root,
    const std::array<ChildEnvelopeV1, kChildCountV1>& child);

/**
 * Prover-side canonical encoder. The immutable role split, ProgramTable roots,
 * shapes and registry root come only from the supplied network assessment.
 */
[[nodiscard]] bool SerializeAgainstAssessmentV1(
    const aqc::FrozenSpecAssessmentV1& assessment,
    const std::array<
        air_quotient::AirQuotientSplitRapRowsProof,
        kChildCountV1>& proofs,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);

/**
 * Audit/test decode against an assessment already rebuilt from network
 * parameters. Production callers should use DecodeAndValidateV1 below.
 */
[[nodiscard]] bool DecodeAgainstAssessmentV1(
    const aqc::FrozenSpecAssessmentV1& assessment,
    const std::vector<unsigned char>& encoded,
    ValidatedPairV1& out,
    std::string* why = nullptr);

/**
 * Production ingress. Rebuilds the complete canonical assessment from block,
 * network parameters and height before decoding any child proof envelope.
 */
[[nodiscard]] bool DecodeAndValidateV1(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const std::vector<unsigned char>& encoded,
    ValidatedPairV1& out,
    std::string* why = nullptr);

/**
 * Execute one decoded SAFE Split-RAP V2 child under the exact canonical
 * ProgramTable, trace shape, R0 schedule and independently derived public
 * Fiat--Shamir seed.  The program challenge vector is derived from the
 * authenticated R0 root; no challenge value is accepted from the proof or
 * caller.
 */
[[nodiscard]] bool VerifyNativeChildProofV1(
    const constraint_bytecode::ProgramTable& program,
    uint32_t expected_trace_rows,
    const std::vector<uint32_t>&
        expected_r0_base_column_indices,
    const uint256& expected_public_fs_seed,
    const air_quotient::AirQuotientSplitRapRowsProof& proof,
    std::string* why = nullptr);

/**
 * Native verification boundary for a decoded pair.
 *
 * `expected_child_fs_seed` must be rebuilt from the block statement and
 * complete role claims by the canonical parent consensus layer.  This
 * function rechecks every envelope against `assessment` before executing both
 * SAFE V2 verifiers.  It does not claim recursive parent consumption.
 */
[[nodiscard]] bool VerifyNativeChildPairV1(
    const aqc::FrozenSpecAssessmentV1& assessment,
    const std::array<uint256, kChildCountV1>&
        expected_child_fs_seed,
    ValidatedPairV1& pair,
    std::string* why = nullptr);

inline constexpr bool kExecutableV1 = true;
inline constexpr bool kNativeChildVerifierExecutableV1 = true;
inline constexpr bool kNativeChildAcceptanceReadyV1 = false;

static_assert(kExecutableV1);
static_assert(kNativeChildVerifierExecutableV1);
static_assert(!kNativeChildAcceptanceReadyV1);

} // namespace matmul::v4::rc::canonical_role_child_attachment

#endif
