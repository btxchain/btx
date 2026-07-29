// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_ROOT_CHAIN_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_ROOT_CHAIN_H

#include <matmul/matmul_v4_rc_stage3_coupled_bank_product.h>
#include <matmul/matmul_v4_rc_stage3_coupled_semantic.h>
#include <matmul/matmul_v4_rc_stage3_episode_header_target.h>
#include <matmul/matmul_v4_rc_stage3_episode_semantic.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

/**
 * Executable typed-vector seam for the global SHA256d root chain.
 *
 * The fixed-program hash proof authenticates SHA message words, chaining
 * values and terminal words.  This small AIR authenticates the semantic byte
 * vectors at either side of those proofs.  Its expected column is verifier
 * regenerated from a typed manifest; VALUE and EXPORT are proof columns with
 * degree-one equality constraints to that expected column.
 *
 * This is intentionally not a native SHA acceptance path.  The only hash
 * computation accepted by the root-chain verifiers below is the
 * FixedProgramProvenanceAir proof in stage3_hash_semantic.
 */
inline constexpr uint16_t kRCStage3RootChainVersion = 1;
inline constexpr uint32_t kRCStage3RootChainMaxVectorBytes = 1U << 24;

enum RCStage3RootChainColumn : uint32_t {
    kRCStage3RootChainActive = 0,
    kRCStage3RootChainAddress,
    kRCStage3RootChainExpected,
    kRCStage3RootChainValue,
    kRCStage3RootChainExport,
    kRCStage3RootChainColumns,
};

struct RCStage3RootChainVectorPin {
    uint16_t version{kRCStage3RootChainVersion};
    RCStage3RelationEndpoint endpoint{};
    uint256 statement_commitment{};
    /** Exact ordered typed-manifest collection. */
    uint256 collection_commitment{};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint64_t address_begin{0};
    uint256 value_root{};
    uint256 pin_commitment{};

    bool operator==(const RCStage3RootChainVectorPin&) const = default;
};

struct RCStage3RootChainVectorProof {
    uint16_t version{kRCStage3RootChainVersion};
    uint256 pin_commitment{};
    air_quotient::AirQuotientProof<gkr_field::Fp3> quotient;
};

[[nodiscard]] bool BuildRCStage3RootChainVectorPin(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& collection_commitment,
    const std::vector<uint8_t>& values,
    RCStage3RootChainVectorPin& out,
    std::string* why = nullptr);

[[nodiscard]] bool BuildRCStage3RootChainVectorConstraintSystem(
    const RCStage3RootChainVectorPin& pin,
    const std::vector<uint8_t>& expected_values,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);
[[nodiscard]] uint256 ComputeRCStage3RootChainVectorSeed(
    const RCStage3RootChainVectorPin& pin);

[[nodiscard]] bool ProveRCStage3RootChainVector(
    const RCStage3RootChainVectorPin& pin,
    const std::vector<uint8_t>& values,
    RCStage3RootChainVectorProof& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3RootChainVector(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& collection_commitment,
    const std::vector<uint8_t>& expected_values,
    const RCStage3RootChainVectorPin& pin,
    const RCStage3RootChainVectorProof& proof,
    std::string* why = nullptr);

/** Structural-only typed manifest validation.  These routines validate exact
 * tags, lengths, ordering, commitments, padding/chaining boundary statements
 * and relation identifiers. They never recompute SHA compression natively. */
[[nodiscard]] bool ValidateRCStage3EpisodeDigestManifestStructural(
    const stage3_hash_air::EpisodeDigestManifest& manifest,
    uint32_t expected_rounds,
    std::string* why = nullptr);
[[nodiscard]] bool ValidateRCStage3CoupledBarrierManifestStructural(
    const RCStage3CoupledShape& shape,
    uint32_t expected_barrier,
    const stage3_hash_air::CoupledBarrierManifest& manifest,
    std::string* why = nullptr);
[[nodiscard]] bool ValidateRCStage3CoupledDigestManifestStructural(
    const RCStage3CoupledShape& shape,
    const stage3_hash_air::CoupledDigestManifest& manifest,
    std::string* why = nullptr);

struct RCStage3EpisodeDigestRootChainProof {
    stage3_hash_air::EpisodeDigestManifest manifest;
    RCStage3RootChainVectorPin round_roots_pin;
    RCStage3RootChainVectorProof round_roots_proof;
    stage3_hash_semantic::FlatBoundaryProofBundle hash_bundle;
    RCStage3EpisodeHashSemanticBinding hash_binding;
    RCStage3RootChainVectorPin digest_pin;
    RCStage3RootChainVectorProof digest_proof;
};

/**
 * Executable endpoint-24 -> endpoint-26 equality seam.
 *
 * Each side is a same-trace product of its registered relation AIR and an
 * exact-row degree-two CTL child.  The bus uses identical namespace, stage
 * and byte-index tags with opposite multiplicities.  Thus endpoint 26's
 * DIGEST_BYTE column is not merely regenerated from the same public
 * statement: it is equality-constrained to endpoint 24's proof-owned VALUE
 * column under the dual independently sampled LogUp lanes.
 */
inline constexpr uint16_t kRCStage3EpisodeDigestPowCtlVersion = 1;
inline constexpr uint32_t kRCStage3EpisodeDigestPowCtlBusId =
    0x18241A00U;

struct RCStage3EpisodeDigestPowCtlLaneProof {
    RCStage3CtlManifest manifest;
    RCStage3CtlSchedule producer_schedule;
    RCStage3CtlSchedule consumer_schedule;
    std::vector<RCStage3CtlChildPin> pins;
    air_quotient::AirQuotientProof<gkr_field::Fp3> producer_product;
    air_quotient::AirQuotientProof<gkr_field::Fp3> consumer_product;
    uint256 producer_product_commitment{};
    uint256 consumer_product_commitment{};
    uint256 lane_commitment{};
};

struct RCStage3EpisodeDigestPowCtlProof {
    uint16_t version{kRCStage3EpisodeDigestPowCtlVersion};
    RCStage3EpisodePowPin pow_pin;
    /** Endpoint 24 VALUE -> endpoint 26 DIGEST_BYTE. */
    RCStage3EpisodeDigestPowCtlLaneProof digest_lane;
    /** Endpoint 25 TARGET_BYTE -> endpoint 26 TARGET_BYTE. */
    RCStage3EpisodeDigestPowCtlLaneProof target_lane;
    uint256 proof_commitment{};
};

[[nodiscard]] bool ProveRCStage3EpisodeDigestPowCtl(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const RCStage3EpisodeDigestRootChainProof& digest_chain,
    const RCStage3EpisodeHeaderTargetProduct& header_target,
    RCStage3EpisodeDigestPowCtlProof& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3EpisodeDigestPowCtl(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const RCStage3EpisodeDigestRootChainProof& digest_chain,
    const RCStage3EpisodeHeaderTargetProduct& header_target,
    const RCStage3EpisodeDigestPowCtlProof& proof,
    std::string* why = nullptr);

/** Honest all-child prover for the bounded episode digest chain. */
[[nodiscard]] bool ProveRCStage3EpisodeDigestRootChain(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const std::vector<uint256>& round_roots,
    RCStage3EpisodeDigestRootChainProof& out,
    std::string* why = nullptr);

/**
 * Executable links:
 *   EpisodeDigestRoundRoots -> typed episode preimage
 *   typed preimage -> complete SHA256d provenance proof
 *   hash terminal words -> EpisodeDigestValue -> public episode_digest.
 */
[[nodiscard]] bool VerifyRCStage3EpisodeDigestRootChain(
    const RCStage3SuccinctProof& statement,
    uint32_t expected_rounds,
    const RCStage3EpisodeDigestRootChainProof& proof,
    std::string* why = nullptr);

struct RCStage3CoupledBarrierRootChainEntry {
    stage3_hash_air::CoupledBarrierManifest manifest;
    stage3_hash_semantic::FlatBoundaryProofBundle hash_bundle;
    RCStage3CoupledHashSemanticPin hash_pin;
};

struct RCStage3CoupledRootChainProof {
    std::vector<RCStage3CoupledBarrierRootChainEntry> barriers;
    RCStage3RootChainVectorPin barrier_inputs_pin;
    RCStage3RootChainVectorProof barrier_inputs_proof;
    RCStage3RootChainVectorPin barrier_outputs_pin;
    RCStage3RootChainVectorProof barrier_outputs_proof;

    stage3_hash_air::CoupledDigestManifest digest_manifest;
    RCStage3RootChainVectorPin digest_inputs_pin;
    RCStage3RootChainVectorProof digest_inputs_proof;
    stage3_hash_semantic::FlatBoundaryProofBundle digest_hash_bundle;
    RCStage3CoupledHashSemanticPin digest_hash_pin;
    RCStage3RootChainVectorPin digest_value_pin;
    RCStage3RootChainVectorProof digest_value_proof;
};

/** Honest all-barrier and final-digest prover for the bounded coupled chain. */
[[nodiscard]] bool ProveRCStage3CoupledRootChain(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const uint256& bank_root,
    const std::vector<std::vector<uint8_t>>& barrier_state_bytes,
    RCStage3CoupledRootChainProof& out,
    std::string* why = nullptr);

/** Prover-visible commitment used by both barrier input/output vector pins. */
[[nodiscard]] uint256 ComputeRCStage3RootChainBarrierCollectionCommitment(
    const std::vector<RCStage3CoupledBarrierRootChainEntry>& barriers);

/**
 * Executes every barrier hash child in barrier-index order, proves the exact
 * input/output byte vectors, consumes those output digests in the coupled
 * digest preimage, executes that hash child and binds the terminal digest to
 * the public coupled_digest.
 */
[[nodiscard]] bool VerifyRCStage3CoupledRootChain(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledRootChainProof& proof,
    std::string* why = nullptr);

/** Barrier-role slice of the coupled root chain: every barrier SHA child plus
 * the exact barrier input/output vector AIRs. Digest proofs may be absent;
 * used by BarrierSha256dV1. */
[[nodiscard]] bool VerifyRCStage3CoupledBarrierRootChain(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledRootChainProof& proof,
    std::string* why = nullptr);

/** Digest-role slice: structural barrier manifests (roots into the digest
 * preimage), digest input/hash/value AIRs, and public coupled_digest binding.
 * Used by DigestSha256dV1; does not re-execute barrier hash AirQuotient. */
[[nodiscard]] bool VerifyRCStage3CoupledDigestRootChain(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledRootChainProof& proof,
    std::string* why = nullptr);

/**
 * Exact immediate producer seams for endpoint 50.
 *
 * Both variants first execute the endpoint-29 bank-root proof, then execute
 * every endpoint-48/49 barrier proof and the endpoint-50 vector/hash chain,
 * and finally require the proof-derived bank root to equal the first root in
 * the coupled-digest manifest. The streaming variant accepts the complete
 * recursive V1 tree; it is semantically exact but not a succinct fixed point.
 *
 * These verifiers intentionally do not claim transitive producer closure:
 * endpoint 28 must still prove equality to `expected_bank_page_byte_root`,
 * and endpoint 47 must still prove the ancestry of every barrier input.
 */
[[nodiscard]] bool VerifyRCStage3CoupledRootChainWithFlatBankProducer(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledBankRootExecution& bank,
    const RCStage3CoupledRootChainProof& proof,
    std::string* why = nullptr);

/** Bounded complete bank branch: execute 27/28, prove exact page-byte
 * equality into 29, execute 29, and bind its digest into endpoint 50.
 * Barrier-input ancestry and normalized recursive consumption remain outside
 * this verifier.
 */
[[nodiscard]] bool
VerifyRCStage3CoupledRootChainWithBoundedBankProductProducer(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledBankProduct& bank_product,
    const RCStage3CoupledBankRootExecution& flat_bank,
    const RCStage3CoupledRootChainProof& proof,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyRCStage3CoupledRootChainWithStreamingBankProducer(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const uint256& expected_bank_page_byte_root,
    const RCStage3CoupledBankStreamManifest& bank_manifest,
    const RCStage3CoupledBankStreamRecursiveProof& bank_root,
    const RCStage3CoupledBankStreamSecondPassProof& bank_second_pass,
    const RCStage3CoupledRootChainProof& proof,
    std::string* why = nullptr);

struct RCStage3RootChainEndpointAudit {
    RCStage3RelationEndpoint endpoint{};
    bool typed_manifest_executable{false};
    bool proof_owned_vector_executable{false};
    bool hash_provenance_executable{false};
    bool downstream_equality_executable{false};
    bool outer_statement_equality_executable{false};
    bool upstream_relation_equality_executable{false};
    /** This module executes the endpoint's immediate typed relation. */
    bool local_relation_complete{false};
    /** Every input is linked transitively to an executed producer/public pin. */
    bool producer_graph_complete{false};
    /** local_relation_complete && producer_graph_complete. */
    bool strict_semantic_complete{false};
    std::string remaining;
};

/** Exact audit for endpoints 23,24,47,48,49,50,51,52. */
[[nodiscard]] std::vector<RCStage3RootChainEndpointAudit>
CurrentRCStage3RootChainEndpointAudit();

inline constexpr bool kRCStage3GlobalRootChainExecutable = true;
inline constexpr bool kRCStage3GlobalRootChainRecursivelyConsumed = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_ROOT_CHAIN_H
