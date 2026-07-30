// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_ALG_HASH_WIDE_H
#define BTX_MATMUL_MATMUL_V4_RC_ALG_HASH_WIDE_H

#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

// Experimental, additive Poseidon2 width-16 commitment primitive.
//
// This deliberately does NOT replace alg_hash::AlgHash, alter a proof version,
// or enter a consensus path.  Its purpose is to make the stronger commitment
// scenario executable and measurable:
//
//   Goldilocks; t=16; rate=8; capacity=8; digest=8; alpha=7;
//   R_F=8; R_P=22; M_E=circ(2*M4,M4,M4,M4).
//
// The round geometry matches the Poseidon2 reference parameter search for
// Goldilocks/t=16/alpha=7 at its 128-bit target.  Constants remain BTX-local,
// derived by a versioned SHA256d counter XOF.  The reference internal-matrix
// subspace condition is executed below, but the independent constants and
// sponge still require a construction-level review before production use.
// The audit API makes that limitation explicit.

namespace matmul::v4::rc::alg_hash_wide {

using gkr_field::Fp;
using gkr_field::Fp3;

inline constexpr uint32_t kWideVersion = 1;
inline constexpr uint32_t kWideT = 16;
inline constexpr uint32_t kWideRate = 8;
inline constexpr uint32_t kWideCapacity = 8;
inline constexpr uint32_t kWideDigestLen = 8;
inline constexpr uint32_t kWideFullRounds = 8;
inline constexpr uint32_t kWidePartialRounds = 22;
inline constexpr uint32_t kWideSboxPower = 7;
inline constexpr uint32_t kWideSboxCells =
    kWideFullRounds * kWideT + kWidePartialRounds;
inline constexpr uint32_t kWidePermCells = kWideT + kWideSboxCells;
inline constexpr char kWideDomainTag[] =
    "BTX_ALGHASH_P2_GL16_C8_V1_EXPERIMENTAL";

using State = std::array<Fp, kWideT>;
using Digest = std::array<Fp, kWideDigestLen>;

struct Constants {
    std::array<std::array<Fp, kWideT>, kWideFullRounds> rc_ext{};
    std::array<Fp, kWidePartialRounds> rc_int{};
    // M_I = J + diag(mu).  Thus the paper's diagonal is 1 + mu_i.
    std::array<Fp, kWideT> mu{};
    Fp node_domain{0};
    Fp row_domain{0};
    Fp transcript_domain{0};
};

[[nodiscard]] const Constants& GetConstants();
[[nodiscard]] uint256 ConstantsChecksum();

void ApplyExternalMatrix(State& state);
void ApplyInternalMatrix(State& state);
void Permute(State& state);
void InversePermute(State& state);

/**
 * Domain-separated rate-8/capacity-8 sponge.
 *
 * The encoded message is [domain, xs..., 1, 0...], padded to a rate multiple.
 * The domain is an absorbed field element, not an affine tweak of arbitrary
 * full-state input.  This preserves an injective encoding of (domain, xs).
 */
[[nodiscard]] Digest SpongeHashFpDomain(
    const std::vector<Fp>& xs, Fp domain);

/**
 * Exact two-child node encoding.  Sixteen child lanes plus the domain and
 * mandatory padding take three permutation calls.  This intentionally pays
 * for real domain separation instead of calling a one-permutation full-state
 * truncation a capacity-8 sponge.
 */
[[nodiscard]] Digest Compress(
    const Digest& left, const Digest& right);

/** Hash an Fp3 row and its row index under the distinct row domain. */
[[nodiscard]] Digest LeafHashRow(
    const std::vector<Fp3>& row, uint32_t index);

/**
 * Flattened executable permutation relation:
 * 16 input cells followed by 150 S-box output cells.  Linear layers remain
 * virtual, so the corresponding AIR geometry is 166 columns, 150 degree-7
 * constraints.  This checker is bounded R&D code, not a recursive proof.
 */
struct PermWitness {
    std::array<Fp, kWidePermCells> cells{};
    State output{};
};

[[nodiscard]] PermWitness BuildPermWitness(const State& input);
[[nodiscard]] bool VerifyPermWitness(
    const PermWitness& witness, std::string* why = nullptr);

/** Executable transcript for a domain-separated sponge invocation. */
struct SpongeWitness {
    Fp domain{0};
    std::vector<Fp> message;
    std::vector<PermWitness> permutations;
    Digest digest{};
};

[[nodiscard]] SpongeWitness BuildSpongeWitness(
    const std::vector<Fp>& xs, Fp domain);
[[nodiscard]] bool VerifySpongeWitness(
    const SpongeWitness& witness, std::string* why = nullptr);

[[nodiscard]] SpongeWitness BuildCompressWitness(
    const Digest& left, const Digest& right);

/**
 * Poseidon2 internal-matrix condition from the reference generator.
 *
 * For M_I = J + diag(mu), compute M_I^i for i=1..2t and require the
 * characteristic polynomial of every power to be irreducible of degree t.
 * Irreducibility is checked with the exact Rabin/Frobenius criterion in
 * Fp[x].  An irreducible degree-t characteristic polynomial is also the
 * degree-t minimal polynomial, which is the reference generator's required
 * defense against arbitrarily long invariant-subspace trails.
 */
struct InternalMatrixConditionAudit {
    uint32_t width{0};
    uint32_t powers_required{0};
    uint32_t powers_checked{0};
    uint32_t irreducible_powers{0};
    uint32_t first_failing_power{0};
    bool all_characteristic_polynomials_irreducible{false};
    uint256 characteristic_polynomials_checksum{};
};

[[nodiscard]] InternalMatrixConditionAudit
AuditInternalMatrixCondition(
    const std::array<Fp, kWideT>& mu);

/**
 * Executable comparison with Plonky3's canonical Goldilocks/t=16 parameters.
 * The reference Grain LFSR is replayed locally and pinned against its published
 * constants and permutation KAT.  BTX intentionally uses different versioned
 * constants; equality is reported, not assumed.
 */
struct ParameterConditionAudit {
    uint32_t active_version{0};
    InternalMatrixConditionAudit btx_matrix;
    InternalMatrixConditionAudit plonky3_matrix;
    uint256 btx_round_constants_checksum{};
    uint256 plonky3_round_constants_checksum{};
    bool reference_grain_replayed{false};
    bool reference_round_constant_pins_match{false};
    bool reference_permutation_kat_matches{false};
    bool round_geometry_equal{false};
    bool round_constants_equal{false};
    bool external_matrices_equal{false};
    bool internal_matrices_equal{false};
    bool btx_parameter_condition_closed{false};
    bool deterministic_regeneration_required{false};
};

[[nodiscard]] const ParameterConditionAudit&
AssessParameterConditions();

/**
 * Exact construction/resource inventory.  "Collision bits" are the strict
 * integer floor of min(log2(|Fp|^digest_lanes)/2,
 * log2(|Fp|^capacity_lanes)/2); they are a generic capacity diagnostic only,
 * not a security theorem for this instance.
 */
struct ResourceAudit {
    uint32_t version{0};
    uint32_t state_lanes{0};
    uint32_t rate_lanes{0};
    uint32_t capacity_lanes{0};
    uint32_t digest_lanes{0};
    uint32_t full_rounds{0};
    uint32_t partial_rounds{0};
    uint32_t sboxes_per_permutation{0};
    uint32_t perm_relation_columns{0};
    uint32_t perm_relation_constraints{0};
    uint32_t max_algebraic_degree{0};

    uint32_t node_permutations{0};
    uint32_t node_horizontal_columns{0};
    uint32_t node_relation_constraints{0};
    uint64_t node_sbox_evaluations{0};

    uint32_t row_columns{0};
    uint64_t row_field_elements{0};
    uint32_t row_permutations{0};
    uint64_t row_horizontal_columns{0};
    uint32_t row_vertical_columns{0};
    uint64_t row_sbox_evaluations{0};
    uint32_t declared_parent_column_cap{0};
    bool row_horizontal_fits_parent{false};
    bool row_vertical_fits_parent{false};

    uint32_t nominal_digest_bits{0};
    uint32_t nominal_capacity_bits{0};
    uint32_t strict_generic_collision_bits{0};
    uint32_t strict_common_binding_cap_bits{0};
    uint32_t production_security_claim_bits{0};

    bool external_matrix_invertible{false};
    bool internal_matrix_invertible{false};
    bool bounded_relation_checker_executable{false};
    bool round_geometry_matches_reference_search{false};
    bool constants_match_reference_grain_instance{false};
    bool internal_subspace_condition_verified{false};
    bool sponge_mode_reduction_complete{false};
    bool fri_air_integrated{false};
    bool recursive_verifier_consumes_digest{false};
    bool formal_security_reduction_complete{false};
    bool production_selected{false};
    bool consensus_enabled{false};
};

[[nodiscard]] ResourceAudit AssessResources(uint32_t row_columns);

} // namespace matmul::v4::rc::alg_hash_wide

#endif // BTX_MATMUL_MATMUL_V4_RC_ALG_HASH_WIDE_H
