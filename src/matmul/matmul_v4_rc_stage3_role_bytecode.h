// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_ROLE_BYTECODE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_ROLE_BYTECODE_H

#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>

#include <string>

namespace matmul::v4::rc {

/**
 * Canonical source for the endpoint-4 dequantization relation:
 *
 *   e = e0 + 2e1, factor = (1+e0)(1+3e1), out = mu*factor.
 *
 * The six columns are, in order, mantissa, repeated scale, e0, e1, scale
 * factor and output.  The table contains all five constraints executed by
 * RCStage3EpisodeBuilderTraceProduct.
 */
[[nodiscard]] bool BuildRCStage3EpisodeBuilderTraceProgramTable(
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Pin-independent canonical source for endpoint 25's byte-wise compact-target
 * equality.  The expected-target column remains verifier-owned preprocessing;
 * the program proves CURRENT[target_byte] = CURRENT[expected_byte].
 */
[[nodiscard]] bool BuildRCStage3EpisodeHeaderTargetEqualityProgramTable(
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/** Canonical twelve-column endpoint-26 digest<=target borrow-chain AIR. */
[[nodiscard]] bool BuildRCStage3EpisodePowProgramTable(
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Pin-independent canonical source for endpoint 28's six-column bank
 * dequantization relation.  This is the role-separated twin of the episode
 * builder table; the committed role prevents cross-role replay.
 */
[[nodiscard]] bool BuildRCStage3CoupledBankDequantProgramTableCanonical(
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Canonical pre-challenge endpoint-28 -> endpoint-29 byte bridge. The first
 * six columns are the proved bank dequant trace, followed by BYTE, its eight
 * bits and the verifier-owned row address. It proves unsigned-byte
 * reconstruction and OUTPUT = BYTE - 256*BIT7. The post-R0 CTL accumulator
 * remains a separate SplitRAP family.
 */
[[nodiscard]] bool BuildRCStage3CoupledBankByteBridgeProgramTable(
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Canonical source for the seven-column semantic memory export relation used
 * by every episode role.  The role is committed explicitly; all six episode
 * roles are accepted.
 */
[[nodiscard]] bool BuildRCStage3EpisodeSemanticMemoryProgramTable(
    RCStage3RelationRole role,
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Canonical source for the 197-column Extract mix relation.  The same
 * polynomial relation is used by the episode and coupled products, but the
 * role is committed explicitly so a table cannot be replayed across them.
 */
[[nodiscard]] bool BuildRCStage3ExtractMixProgramTable(
    RCStage3RelationRole role,
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Canonical source for the typed root-chain vector relation.  Only the three
 * owning roles are accepted: EpisodeDigest, CoupledBarrier and CoupledDigest.
 * The five columns are active, address, expected, value and export.
 */
[[nodiscard]] bool BuildRCStage3RootChainVectorProgramTable(
    RCStage3RelationRole role,
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Canonical endpoint-23 -> endpoint-24 byte bridge.  The thirteen columns
 * are ACTIVE, ADDRESS, EXPECTED, VALUE, EXPORT and eight little-endian byte
 * bits.  EXPECTED is verifier-owned from the exact episode-digest preimage;
 * VALUE is range-proved, equality-bound to EXPECTED, and exported to the
 * row-tagged CTL bus.
 */
[[nodiscard]] bool
BuildRCStage3EpisodeDigestPreimageByteBridgeProgramTable(
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Canonical source for the EpisodeWiring transpose dual-LogUp cross-shard
 * transport lane (SHA=0, ctl=26). The two grand-product lanes are expressed
 * as CHALLENGE-INDEPENDENT bytecode: the Fiat-Shamir challenges beta/gamma are
 * loaded from the verifier-owned post-challenge column class (width 4:
 * [beta0,gamma0,beta1,gamma1]) rather than baked as Constants, so the committed
 * relation table does not depend on the challenge. Eight trace columns
 * (mapped_index, source_value, dest_index, dest_value, inv1, run1, inv2, run2)
 * and six constraints (per lane: denominator-inverse deg 3, running-product
 * first-row deg 1, running-product cycle deg 3). The denominator-inverse is the
 * committed-aux-column trick: inv*(gamma-(dest_value+beta*dest_index)) - 1 = 0.
 */
[[nodiscard]] bool BuildRCStage3EpisodeWiringTransposeProgramTable(
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Canonical source for the CoupledPermutation indexed-permutation grand-product
 * transport lane. Two multiplicative LogUp lanes over a beta-vector/gamma
 * fingerprint (fingerprint = beta[0]*index + sum_l beta[l+1]*limb_l), with
 * beta/gamma loaded from the verifier-owned post-challenge column class (width
 * 12). Fourteen trace columns, six constraints (per lane: denominator-inverse
 * deg 3, product-first deg 1, product-cycle deg 3).
 */
[[nodiscard]] bool BuildRCStage3CoupledPermutationTransportProgramTable(
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Canonical source for the CoupledExchange transport lane: the SAME two
 * grand-product lanes as CoupledPermutation but over the material trace layout
 * (mixed-limb source, output-limb destination, 214-column width). The mixing
 * boolean/xor/limb-recompose constraints are pre-challenge and migrated
 * separately; this table is the challenge-baked transport lane only.
 */
[[nodiscard]] bool BuildRCStage3CoupledExchangeTransportProgramTable(
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Canonical source for the EpisodeExtract stream-CTL transport lane (additive
 * gamma-power LogUp). Two lanes over the tuple NS + gamma*tile + gamma^2*addr
 * + gamma^3*value, with gamma/alpha and the two verifier-owned terminal sums
 * loaded from the post-challenge column class (width 6). Seven trace columns
 * (source, mask, address, inverse1/2, running1/2) and twelve constraints. The
 * inverse constraint is recorded at raw degree 5 (gamma^3 * value * inverse).
 * `tile`/`multiplicity` are baked schedule constants (multiplicity in {+1,-1}).
 */
[[nodiscard]] bool BuildRCStage3EpisodeExtractStreamTransportProgramTable(
    uint32_t tile,
    int8_t multiplicity,
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Canonical source for the EpisodeTileTree producer-edge transport lane
 * (additive gamma-power LogUp over 32 output bytes). For each byte x lane an
 * inverse (first-row, raw degree 5) and a padding (transition) constraint, then
 * per lane running-first/transition/last; 134 constraints, 98 trace columns.
 * gamma/alpha and the two terminal sums are the width-6 post-challenge column
 * class; the tuple address is the byte index (a constant).
 */
[[nodiscard]] bool BuildRCStage3EpisodeTileTreeProducerTransportProgramTable(
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Canonical signed-byte bridge for endpoint-19 tile-stream values and the
 * byte-oriented tile-tree SHA preimages.  VALUE/EXPORT use the Extract
 * signed embedding [-128,127], while BYTE and its eight bits retain the
 * canonical octet. SIGN is equality-bound to bit seven, so the map
 *
 *   VALUE = BYTE - 256 * SIGN
 *
 * is unique and cannot alias a different octet in the base field.
 */
[[nodiscard]] bool BuildRCStage3EpisodeTileTreeByteBridgeProgramTable(
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * CoupledExtract sampler transport lane: the canonical T_M LogUp of the
 * RcSampler, expressed as CHALLENGE-INDEPENDENT bytecode over an 11-column
 * post-challenge class (mixed, acc, mu, phi, f, m, psi, S, tbl_a, tbl_b, tbl_c)
 * with verifier-owned gamma (0) and alpha (1). Six constraints: logup.phi,
 * logup.tfp.bind (the online-fingerprint identity that replaces the old
 * gamma-baked preprocessed t_fp column), logup.psi, and the running-sum S
 * first/transition/last. This is the sixth and final migrated transport lane.
 */
[[nodiscard]] bool BuildRCStage3CoupledExtractSamplerTransportProgramTable(
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * Native reference for the lane above, over the same 11-column class with
 * concrete (gamma, alpha). The constraint order matches the ProgramTable and
 * the RcSampler LogUp lane in air_quotient::BuildRcSamplerConstraintSystem, so
 * the two are differentially testable.
 */
[[nodiscard]] air_quotient::AirConstraintSystem<gkr_field::Fp3>
BuildRCStage3CoupledExtractSamplerTransportConstraintSystem(
    const gkr_field::Fp3& gamma,
    const gkr_field::Fp3& alpha,
    uint32_t n_rows = 8);

/**
 * CoupledExtract local kernel: the complete RcSampler relation as challenge-
 * independent bytecode. This is the bytecode form of
 * air_quotient::BuildRcSamplerConstraintSystem in its exact 47-constraint order
 * over the 40-column kRcSampler* layout. gamma (challenge 0) and alpha (challenge
 * 1) enter only through the verifier-owned post-challenge column class (gamma^2
 * is formed in-circuit), so the committed table stays challenge-independent. The
 * public scale exponent `scale_e` (0..3) is baked as the e0/e1 first-row
 * boundaries; it is differential-tested bit-identical for every exponent.
 */
[[nodiscard]] bool BuildRCStage3CoupledExtractLocalKernelProgramTable(
    uint8_t scale_e,
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * EpisodeExtract local kernel: the identical RcSampler relation as challenge-
 * independent bytecode, committed under the EpisodeExtract role. It is the
 * episode analogue of BuildRCStage3CoupledExtractLocalKernelProgramTable and is
 * the migrated relation source for the EpisodeExtract C_rho. Same 47-constraint
 * order, 40-column kRcSampler* layout, [gamma, alpha] post-challenge class, and
 * `scale_e` (0..3) baked as the e0/e1 first-row boundaries. It differs from the
 * coupled kernel only in the committed table role (anti cross-role replay), so
 * it is differential-tested bit-identical to the native RcSampler system.
 */
[[nodiscard]] bool BuildRCStage3EpisodeExtractLocalKernelProgramTable(
    uint8_t scale_e,
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/**
 * CoupledBarrier / CoupledDigest hash kernel: the selector-pinned SHA-256
 * compression AIR as bytecode. This is the bytecode form of
 * stage3_hash_air::BuildFixedProgramConstraintSystem over the canonical
 * Sha256Compression program, in the identical 462-constraint order over the
 * 144-column fixed-program layout. Both roles are DirectSha256d relations
 * executed by the same compression program and share this kernel; only the
 * committed table `role` differs so a table cannot be replayed across roles.
 * Only CoupledBarrier and CoupledDigest are accepted.
 */
[[nodiscard]] bool BuildRCStage3CoupledHashKernelProgramTable(
    RCStage3RelationRole role,
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_ROLE_BYTECODE_H
