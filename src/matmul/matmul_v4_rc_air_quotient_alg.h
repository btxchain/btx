// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_AIR_QUOTIENT_ALG_H
#define BTX_MATMUL_MATMUL_V4_RC_AIR_QUOTIENT_ALG_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <uint256.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// ============================================================================
// ALGEBRAIC-HASH backend policy for the AIR constraint-quotient module — the
// RECURSION-side instantiation of the `Backend` parameter of
// AirQuotientProve / AirQuotientVerify / AirQuotientProof (spec §2.1/§4.2,
// scratchpad/stage-c-buildable-spec.md: an aggregation proof must have the
// SAME shape as the child proofs it verifies, both over the alg-hash
// proximity module — so the backend is threaded as an explicit policy, not
// inferred from the field type, which cannot distinguish the two Fp3
// substrates).
//
// This header is included ONLY by recursion-side callers (and the
// explicit-instantiation TU); matmul_v4_rc_air_quotient.h deliberately does
// not include it, so the episode/base SHA path never sees the alg module.
//
// SEMANTIC DIFFERENCES vs AirFriBackend<Fp3> (all forced by the ROW-WISE
// commitment layout of Fri3AlgBatch*, matmul_v4_rc_fri_ext3_alg.h §2.3):
//  • kRowWiseLayout = true — the batch commits ONE Poseidon2 row tree whose
//    leaf i is alg_hash::LeafHashRow over ALL column values at LDE row i;
//    there are NO per-column roots in the proof (Fri3AlgBatchProof carries
//    a single row_commit).
//  • ColumnRoot(col, n_coeffs) — the packed (uint256) root of a
//    SINGLE-column row tree (Fri3AlgBatchRowRoot({col}, n_coeffs)). This is
//    a deterministic, binding, per-column FS digest (two-epoch challenge
//    discipline / AirCommittedValuesRoot), but UNLIKE the SHA backend it is
//    NOT byte-identical to anything inside a multi-column batch proof — a
//    per-column root has no meaning in the row-wise layout.
//  • RowRoot(cols, n_coeffs) — the packed row root over a column SET; used
//    by AirQuotientProve as the trace-only commitment R_T that seeds the
//    constraint-batching challenge λ (the quotient depends on λ, so it
//    cannot ride the tree that seeds λ; R_T ships in
//    AirQuotientProof::trace_commit and is bound to the batch by per-query
//    cross-openings — see AirQuotientProof's layout note).
//  • MerklePath is AirAlgRowPath — a whole-ROW opening (values + one
//    sibling path of Fp^4 digests), not a single-value path.
//  • NumQueries() = kRCFri3AlgNumQueries = 192 (Stage-3 recursion soundness
//    parameterization, spec §5.2), not the SHA paths' 128.
// Everything else (BatchCommit/BatchVerify wiring, dual-OOD DEEP members
// z1/z2/evals_z1/evals_z2 consumed by the preprocessed OOD pin, n_coeffs,
// column_len degree bounds) matches AirFriBackend<Fp3> member-for-member in
// meaning.
// ============================================================================

namespace matmul::v4::rc::air_quotient {

/**
 * Row opening / authentication-path record for the row-wise backend (the
 * policy's MerklePath type). For the next-row openings `values` carries the
 * FULL row (all W+1 column values — required to recompute the row leaf);
 * for the trace-binding openings `values` is EMPTY (the leaf is recomputed
 * from the batch query's own opened trace values, which the row-wise batch
 * has already Merkle-verified).
 */
struct AirAlgRowPath {
    uint32_t index{0};
    std::vector<gkr_field::Fp3> values;
    std::vector<Fri3AlgDigest> siblings;
};

template <typename F>
struct AirFriBackendAlg;

template <>
struct AirFriBackendAlg<gkr_field::Fp3> {
    /** Row-wise commitment layout — see the header block for what changes. */
    static constexpr bool kRowWiseLayout = true;

    using BatchProof = Fri3AlgBatchProof;
    using BatchCommitResult = Fri3AlgBatchCommitResult;
    using MerklePath = AirAlgRowPath;
    /** Field-native Merkle digest (4 Goldilocks lanes). */
    using Digest = Fri3AlgDigest;

    using RowTreeCache = Fri3AlgRowTreeCache;

    static BatchCommitResult BatchCommit(const std::vector<std::vector<gkr_field::Fp3>>& cols,
                                         const uint256& fs_seed)
    {
        return Fri3AlgBatchCommit(cols, fs_seed);
    }

    // -----------------------------------------------------------------
    // PROVER FOOTPRINT POLICY (memory only — never soundness)
    //
    // The dense prover materializes the whole W x n_lde Fp3 extension. At the
    // MEASURED arity-4 real-role parent (W = 384,984, n_rows = 256 =>
    // n_lde = 4096) that is ~35 GiB and OOM-kills the prover; at the wide end
    // of the documented role range (~712k columns) ~65 GiB. Width is not the
    // problem — the column cap is 2^20 and query-proximity soundness is
    // W-independent — the FOOTPRINT is.
    //
    // Above kRCFri3AlgDenseLdeByteBudget this backend therefore takes the
    // streaming column-block route: it materializes K column LDEs at a time
    // and absorbs each block into the resident per-row sponge, so peak memory
    // is O(K x n_lde) and no longer depends on W. Below the budget it keeps
    // the dense route (which is also where the optional GPU row-leaf splice
    // lives), because dense is one LDE pass instead of several.
    //
    // BOTH ROUTES EMIT BYTE-IDENTICAL PROOFS. The column absorption order into
    // the row-leaf sponge is the column order in either case, and each column
    // LDE is an independent transform of its own coefficients. The threshold
    // can therefore never change a verifier outcome.
    // -----------------------------------------------------------------
    static bool StreamRows(uint64_t columns, uint32_t n_lde)
    {
        return Fri3AlgShouldStreamColumns(columns, n_lde);
    }

    /** BatchCommit under the footprint policy. `stream` MUST be the value the
     *  caller also used for the trace row root, so both halves of the proof
     *  agree on whether a dense column_lde exists. */
    static BatchCommitResult BatchCommitStreamed(
        const std::vector<std::vector<gkr_field::Fp3>>& cols,
        const uint256& fs_seed, bool stream)
    {
        return stream
                   ? Fri3AlgBatchCommitStreamingSharedCached(
                         cols, fs_seed)
                   : Fri3AlgBatchCommit(cols, fs_seed);
    }

    static uint256 RowRootCached(
        const std::vector<std::vector<gkr_field::Fp3>>& cols,
        uint32_t n_coeffs,
        std::shared_ptr<RowTreeCache>& cache,
        std::string* why)
    {
        auto built = std::make_shared<RowTreeCache>();
        if (!Fri3AlgBuildRowTreeCacheStreaming(
                cols, n_coeffs, *built, why)) {
            cache.reset();
            return {};
        }
        cache = std::move(built);
        return Fri3AlgDigestToUint256(cache->root);
    }

    static bool OpenRows(
        const std::vector<std::vector<gkr_field::Fp3>>& cols,
        uint32_t n_coeffs,
        const std::vector<uint32_t>& indices,
        const Digest& expected_root,
        std::vector<MerklePath>& out,
        std::string* why)
    {
        std::vector<Fri3AlgRowOpening> opened;
        if (!Fri3AlgOpenRowsStreamingShared(
                cols, n_coeffs, indices,
                expected_root, opened, why) ||
            opened.size() != indices.size()) {
            return false;
        }
        out.resize(opened.size());
        for (size_t i = 0; i < opened.size(); ++i) {
            out[i].index = indices[i];
            out[i].values = std::move(opened[i].values);
            out[i].siblings = std::move(opened[i].siblings);
        }
        return true;
    }

    static bool OpenRowsCached(
        const std::vector<std::vector<gkr_field::Fp3>>& cols,
        uint32_t n_coeffs,
        const std::vector<uint32_t>& indices,
        const Digest& expected_root,
        const std::shared_ptr<RowTreeCache>& cache,
        std::vector<MerklePath>& out,
        std::string* why)
    {
        if (!cache) {
            if (why != nullptr) *why = "missing row tree cache";
            return false;
        }
        std::vector<Fri3AlgRowOpening> opened;
        if (!Fri3AlgOpenRowsStreamingSharedCached(
                cols, n_coeffs, indices,
                expected_root, *cache, opened, why) ||
            opened.size() != indices.size()) {
            return false;
        }
        out.resize(opened.size());
        for (size_t i = 0; i < opened.size(); ++i) {
            out[i].index = indices[i];
            out[i].values = std::move(opened[i].values);
            out[i].siblings = std::move(opened[i].siblings);
        }
        return true;
    }

    static bool BatchVerify(const BatchProof& p, const uint256& fs_seed, std::string* why)
    {
        return Fri3AlgBatchVerify(p, fs_seed, why);
    }
    /** SINGLE-column row-tree root, packed — per-column FS digest ONLY (see
     *  the semantic notes above; not present in multi-column batch proofs). */
    static uint256 ColumnRoot(const std::vector<gkr_field::Fp3>& col, uint32_t n_coeffs)
    {
        return Fri3AlgDigestToUint256(Fri3AlgBatchRowRoot({col}, n_coeffs));
    }
    /** Row-tree root over a column SET, packed (the λ-seeding trace
     *  commitment R_T of AirQuotientProve). */
    static uint256 RowRoot(const std::vector<std::vector<gkr_field::Fp3>>& cols,
                           uint32_t n_coeffs)
    {
        return Fri3AlgDigestToUint256(Fri3AlgBatchRowRoot(cols, n_coeffs));
    }
    /** Leaf i of a row tree: LeafHashRow over the row's column values. */
    static Digest RowLeafHash(const std::vector<gkr_field::Fp3>& row, uint32_t index)
    {
        return alg_hash::LeafHashRow(row, index);
    }
    static Digest NodeHash(const Digest& l, const Digest& r) { return alg_hash::Compress(l, r); }
    static bool VerifyRowPath(const Digest& leaf, uint32_t index,
                              const std::vector<Digest>& siblings, const Digest& root,
                              uint32_t n_leaves)
    {
        return Fri3AlgVerifyPath(leaf, index, siblings, root, n_leaves);
    }
    /** Canonical Fp^4 ⇆ uint256 packing for FS/proof boundaries; Unpack
     *  REJECTS non-canonical limbs (nullopt). */
    static uint256 PackDigest(const Digest& d) { return Fri3AlgDigestToUint256(d); }
    static std::optional<Digest> UnpackDigest(const uint256& u)
    {
        return Fri3AlgDigestFromUint256(u);
    }
    static uint32_t NumQueries() { return kRCFri3AlgNumQueries; }
};

/**
 * Single-lane Q192 backend that emits the same proof as AirFriBackendAlg but
 * obtains current/next/trace row openings through two-pass column streaming.
 */
struct AirFriBackendAlgStreamingRows
    : public AirFriBackendAlg<gkr_field::Fp3> {
    using Base = AirFriBackendAlg<gkr_field::Fp3>;
    using BatchCommitResult = typename Base::BatchCommitResult;
    using Digest = typename Base::Digest;
    using MerklePath = typename Base::MerklePath;
    using RowTreeCache = Fri3AlgRowTreeCache;

    static BatchCommitResult BatchCommit(
        const std::vector<std::vector<gkr_field::Fp3>>& cols,
        const uint256& fs_seed)
    {
        return Fri3AlgBatchCommitStreamingSharedCached(
            cols, fs_seed);
    }

    static uint256 RowRoot(
        const std::vector<std::vector<gkr_field::Fp3>>& cols,
        uint32_t n_coeffs)
    {
        return Fri3AlgDigestToUint256(
            Fri3AlgBatchRowRootStreaming(
                cols, n_coeffs));
    }

    /** This backend streams UNCONDITIONALLY — that is its whole purpose — so
     *  it ignores the shared footprint threshold. RowRootCached / OpenRows /
     *  OpenRowsCached are inherited from the base, which now carries the same
     *  bounded-residency implementations. */
    static bool StreamRows(uint64_t /*columns*/,
                           uint32_t /*n_lde*/)
    {
        return true;
    }

    static BatchCommitResult BatchCommitStreamed(
        const std::vector<std::vector<gkr_field::Fp3>>& cols,
        const uint256& fs_seed, bool /*stream*/)
    {
        return Fri3AlgBatchCommitStreamingSharedCached(
            cols, fs_seed);
    }
};

template <>
inline constexpr bool AirBackendStreamsRowOpenings<
    AirFriBackendAlg<gkr_field::Fp3>> = true;

template <>
inline constexpr bool AirBackendStreamsRowOpenings<
    AirFriBackendAlgStreamingRows> = true;

using AirQuotientRowsProof =
    AirQuotientProof<
        gkr_field::Fp3,
        AirFriBackendAlgStreamingRows>;
using AirQuotientRowsProveResult =
    AirQuotientProveResult<
        gkr_field::Fp3,
        AirFriBackendAlgStreamingRows>;

/**
 * Public two-epoch receipt for challenge-dependent AIRs.
 *
 * Experimental record for the rejected sampled-cross-opening construction.
 * Epoch R0 commits the challenge-independent subset of trace columns and R1
 * opens R0 at R1's Fiat--Shamir query indices.
 *
 * IMPORTANT: this does NOT prove global R0=R1 oracle equality. A prover can
 * change an unsampled R0 leaf, globally change the derived challenge, and
 * evade the sampled equality check. Consequently the constructor returns a
 * diagnostic receipt with `low_degree_proximity_accounted=false`, and the
 * verifier rejects it. The production replacement is an ordered multi-root
 * FRI in which R0 is reused verbatim as one group and every group participates
 * in one RLC/DEEP/fold transcript.
 */
struct AirQuotientTwoEpochRowsReceipt {
    uint16_t version{1};
    uint32_t trace_rows{0};
    uint32_t n_coeffs{0};
    std::vector<uint32_t> base_column_indices;
    uint256 base_row_commitment{};
    std::vector<AirAlgRowPath> base_openings;
    AirQuotientRowsProof quotient;
    bool base_commitment_bound_in_fs{false};
    bool same_query_cross_openings{false};
    bool low_degree_proximity_accounted{false};
    bool valid{false};
    std::string note;
};

struct AirQuotientTwoEpochRowsProveResult {
    AirQuotientTwoEpochRowsReceipt receipt;
    bool ok{false};
    std::string note;
};

/**
 * Prover-local R0 session. The tree cache is retained across challenge
 * derivation and R1 proving, so producing R0 cross-openings never rebuilds
 * the R0 Merkle tree. This object is never serialized or trusted by the
 * verifier.
 */
struct AirQuotientTwoEpochBaseRowSession {
    uint32_t trace_rows{0};
    uint32_t n_coeffs{0};
    std::vector<uint32_t> base_column_indices;
    uint256 base_row_commitment{};
    std::shared_ptr<Fri3AlgRowTreeCache> row_tree_cache;
    bool valid{false};
    std::string note;
};

/** Additive row-streaming prover seam. This already avoids retaining the
 * backend's W×N_LDE matrix; quotient-coefficient external-store emission is
 * tracked separately and is not implied by this API. */
[[nodiscard]] AirQuotientRowsProveResult
AirQuotientProveRows(
    const AirConstraintSystem<gkr_field::Fp3>& cs,
    const std::vector<std::vector<gkr_field::Fp3>>& columns,
    const uint256& fs_seed,
    const AirProveOptions& opt = {});

[[nodiscard]] bool AirQuotientVerifyRows(
    const AirConstraintSystem<gkr_field::Fp3>& cs,
    const AirQuotientRowsProof& proof,
    const uint256& fs_seed,
    std::string* why = nullptr);

/**
 * Commit R0 and prove R1. `base_column_indices` must be strictly increasing
 * and name challenge-independent columns in `columns`.  The caller may first
 * obtain the same R0 commitment with AirQuotientTwoEpochBaseRowCommitment,
 * derive its AIR challenges, build `cs`/`columns`, and then call this routine;
 * the commitment is recomputed and checked here.
 */
[[nodiscard]] uint256 AirQuotientTwoEpochBaseRowCommitment(
    const AirConstraintSystem<gkr_field::Fp3>& cs,
    const std::vector<std::vector<gkr_field::Fp3>>& columns,
    const std::vector<uint32_t>& base_column_indices,
    std::string* why = nullptr);

[[nodiscard]] AirQuotientTwoEpochBaseRowSession
AirQuotientBuildTwoEpochBaseRowSession(
    const AirConstraintSystem<gkr_field::Fp3>& cs,
    const std::vector<std::vector<gkr_field::Fp3>>& columns,
    const std::vector<uint32_t>& base_column_indices);

[[nodiscard]] AirQuotientTwoEpochRowsProveResult
AirQuotientProveRowsTwoEpoch(
    const AirConstraintSystem<gkr_field::Fp3>& cs,
    const std::vector<std::vector<gkr_field::Fp3>>& columns,
    const std::vector<uint32_t>& base_column_indices,
    const uint256& public_fs_seed,
    const AirProveOptions& opt = {},
    const AirQuotientTwoEpochBaseRowSession*
        retained_r0 = nullptr);

/**
 * Fail-closed verifier for the experimental receipt. It intentionally rejects
 * until the ordered multi-root FRI backend replaces sampled R0/R1 equality.
 */
[[nodiscard]] bool AirQuotientVerifyRowsTwoEpoch(
    const AirConstraintSystem<gkr_field::Fp3>& cs,
    const AirQuotientTwoEpochRowsReceipt& receipt,
    const uint256& public_fs_seed,
    std::string* why = nullptr);

/**
 * Sound replacement for the rejected sampled two-epoch receipt.
 *
 * R0 contains exactly `base_column_indices`; Rdep contains the strict
 * complement in original AIR-column order; Rq contains the quotient. The
 * AIR constraint-batching challenge is drawn uniformly after the ordered
 * R0/Rdep roots. A separate post-all-roots seed drives MultiRow-V2, whose
 * own independent column vector is drawn only after every individual OOD
 * claim. Every FRI query opens all three current rows and these supplemental
 * records authenticate the next R0/Rdep rows needed by transition rules.
 *
 * The caller must reconstruct `cs` from authenticated public inputs and the
 * proof's R0 root when the relation itself has R0-derived challenges. This
 * generic layer proves the supplied CS; the application-specific public CS
 * builder remains outside it.
 */
struct AirQuotientSplitRapRowsProof {
    uint16_t version{1};
    uint32_t trace_rows{0};
    std::vector<uint32_t> base_column_indices;
    gkr_field::Fp3 air_constraint_lambda{};
    Fri3AlgMultiRowBatchProof batch;
    /** [query][0=R0,1=Rdep] at index query+|LDE|/trace_rows. */
    std::vector<std::vector<Fri3AlgRowOpening>>
        next_trace_group_rows;
};

inline constexpr uint16_t
    kAirQuotientSplitRapRowsProofVersionV1 = 1;
/** Additive typed SAFE outer transcript plus SAFE multi-row V13 backend. */
inline constexpr uint16_t
    kAirQuotientSplitRapRowsSafeProofVersionV2 = 2;

inline constexpr uint32_t
    kAirQuotientSplitRapRowsProofMagic =
        0x31525341u; // 'ASR1'
/** The outer proof carries one capped multi-row proof plus authenticated
 * next-row openings. Reject before allocation above this independent cap. */
inline constexpr size_t
    kAirQuotientSplitRapRowsMaxProofBytesHard =
        2 * kRCFriMaxProofBytesHard;

struct AirQuotientSplitRapRowsProveResult {
    bool ok{false};
    bool division_exact{false};
    std::string note;
    std::vector<gkr_field::Fp3> remainder;
    AirQuotientSplitRapRowsProof proof;
    /** Prover-local checked caches; never serialized or verifier-trusted. */
    std::vector<std::shared_ptr<Fri3AlgRowTreeCache>>
        group_row_tree_caches;
};

[[nodiscard]] AirQuotientSplitRapRowsProveResult
AirQuotientProveRowsSplitRap(
    const AirConstraintSystem<gkr_field::Fp3>& cs,
    const std::vector<std::vector<gkr_field::Fp3>>& columns,
    const std::vector<uint32_t>& base_column_indices,
    const uint256& public_fs_seed,
    const AirProveOptions& opt = {},
    const AirQuotientTwoEpochBaseRowSession*
        retained_r0 = nullptr);

[[nodiscard]] bool AirQuotientVerifyRowsSplitRap(
    const AirConstraintSystem<gkr_field::Fp3>& cs,
    const AirQuotientSplitRapRowsProof& proof,
    const std::vector<uint32_t>& expected_base_column_indices,
    const uint256& public_fs_seed,
    std::string* why = nullptr);

/**
 * Additive SAFE Split-RAP producer/verifier.  Both outer challenges
 * (constraint lambda and final FRI seed) use typed SAFECore instances, and the
 * nested proof must be the SAFE/Q192/K=2 multi-row V13 backend.  V1 remains
 * byte-for-byte frozen and is rejected by these wrappers.
 */
[[nodiscard]] AirQuotientSplitRapRowsProveResult
AirQuotientProveRowsSplitRapSafeV2(
    const AirConstraintSystem<gkr_field::Fp3>& cs,
    const std::vector<std::vector<gkr_field::Fp3>>& columns,
    const std::vector<uint32_t>& base_column_indices,
    const uint256& public_fs_seed,
    const AirProveOptions& opt = {},
    const AirQuotientTwoEpochBaseRowSession*
        retained_r0 = nullptr);

[[nodiscard]] bool AirQuotientVerifyRowsSplitRapSafeV2(
    const AirConstraintSystem<gkr_field::Fp3>& cs,
    const AirQuotientSplitRapRowsProof& proof,
    const std::vector<uint32_t>& expected_base_column_indices,
    const uint256& public_fs_seed,
    std::string* why = nullptr);

struct AirQuotientSplitRapSafeReplayV2 {
    std::vector<gkr_field::Fp> air_lambda_message;
    std::vector<gkr_field::Fp> fri_seed_message;
    alg_hash::Digest air_lambda_digest{};
    alg_hash::Digest fri_seed_digest{};
    gkr_field::Fp3 air_lambda{};
    uint256 fri_seed{};
    /** Set only after the complete unmodified SAFE V2 verifier accepts. */
    bool native_verified{false};
};

/**
 * Verify the whole SAFE V2 Split-RAP proof, then export the two exact typed
 * SAFECore messages/digests consumed by the native verifier.  Caller-supplied
 * replay values are never accepted as inputs.
 */
[[nodiscard]] bool
AirQuotientVerifyRowsSplitRapSafeV2Replay(
    const AirConstraintSystem<gkr_field::Fp3>& cs,
    const AirQuotientSplitRapRowsProof& proof,
    const std::vector<uint32_t>& expected_base_column_indices,
    const uint256& public_fs_seed,
    AirQuotientSplitRapSafeReplayV2& out,
    std::string* why = nullptr);

/** Canonical durable V1/V2 envelope for the complete current/next split-RAP
 * proof. It nests the version-matched canonical multi-row codec and pins the
 * exact two next-row groups at every one of its Q=192 query sites. */
[[nodiscard]] size_t
SerializeAirQuotientSplitRapRowsProof(
    const AirQuotientSplitRapRowsProof& proof,
    std::vector<unsigned char>& out);
[[nodiscard]] std::optional<AirQuotientSplitRapRowsProof>
DeserializeAirQuotientSplitRapRowsProof(
    const std::vector<unsigned char>& in);

/**
 * AIR-facing view of the experimental dual-Q128 proof. `repeated` is the
 * authoritative two-lane proof. The remaining fields are a checked,
 * flattened view used by the generic AirQuotient prover/verifier so it checks
 * the AIR quotient identity at all 256 independently sampled lane sites.
 */
struct AirFri3AlgDualBatchProof {
    Fri3AlgDualBatchProof repeated;
    uint32_t n_coeffs{0};
    Fri3AlgLayerCommit row_commit{};
    std::vector<uint32_t> column_len;
    gkr_field::Fp3 z1{};
    gkr_field::Fp3 z2{};
    std::vector<gkr_field::Fp3> evals_z1;
    std::vector<gkr_field::Fp3> evals_z2;
    std::vector<Fri3AlgBatchQuery> queries;
};

struct AirFri3AlgDualBatchCommitResult {
    AirFri3AlgDualBatchProof proof;
    std::vector<std::vector<gkr_field::Fp3>> column_lde;
    size_t proof_bytes{0};
    bool ok{false};
    std::string note;
};

template <typename F>
struct AirFriBackendAlgDual;

/**
 * Experimental AIR policy seam for the executable dual-Q128 backend. It is
 * opt-in and does not replace AirFriBackendAlg<Fp3> or any recursive codec.
 */
template <>
struct AirFriBackendAlgDual<gkr_field::Fp3>
    : public AirFriBackendAlg<gkr_field::Fp3> {
    using BatchProof = AirFri3AlgDualBatchProof;
    using BatchCommitResult = AirFri3AlgDualBatchCommitResult;

    static BatchCommitResult BatchCommit(
        const std::vector<std::vector<gkr_field::Fp3>>& cols,
        const uint256& fs_seed)
    {
        BatchCommitResult out;
        Fri3AlgDualBatchCommitResult repeated =
            Fri3AlgDualBatchCommit(cols, fs_seed);
        if (!repeated.ok) {
            out.note = repeated.note;
            return out;
        }
        out.proof.repeated = std::move(repeated.proof);
        const Fri3AlgBatchProof& lane0 = out.proof.repeated.lane[0];
        out.proof.n_coeffs = lane0.n_coeffs;
        out.proof.row_commit = lane0.row_commit;
        out.proof.column_len = lane0.column_len;
        out.proof.z1 = lane0.z1;
        out.proof.z2 = lane0.z2;
        out.proof.evals_z1 = lane0.evals_z1;
        out.proof.evals_z2 = lane0.evals_z2;
        out.proof.queries.reserve(kRCFri3AlgDualTotalQueries);
        for (const auto& lane : out.proof.repeated.lane) {
            out.proof.queries.insert(out.proof.queries.end(),
                                     lane.queries.begin(), lane.queries.end());
        }
        out.column_lde = std::move(repeated.column_lde);
        out.proof_bytes = repeated.proof_bytes;
        out.ok = true;
        out.note = repeated.note;
        return out;
    }

    static bool BatchVerify(const BatchProof& p, const uint256& fs_seed,
                            std::string* why)
    {
        auto fail = [&](const char* reason) {
            if (why) *why = reason;
            return false;
        };
        if (!Fri3AlgDualBatchVerify(p.repeated, fs_seed, why)) return false;
        const Fri3AlgBatchProof& lane0 = p.repeated.lane[0];
        if (p.n_coeffs != lane0.n_coeffs ||
            p.column_len != lane0.column_len ||
            p.row_commit.n_leaves != lane0.row_commit.n_leaves ||
            PackDigest(p.row_commit.root) != PackDigest(lane0.row_commit.root) ||
            !gkr_field::Eq(p.z1, lane0.z1) ||
            !gkr_field::Eq(p.z2, lane0.z2) ||
            !SameFp3Vector(p.evals_z1, lane0.evals_z1) ||
            !SameFp3Vector(p.evals_z2, lane0.evals_z2)) {
            return fail("dual AIR view header mismatch");
        }
        if (p.queries.size() != kRCFri3AlgDualTotalQueries)
            return fail("dual AIR query count");
        size_t flat = 0;
        for (const auto& lane : p.repeated.lane) {
            for (const auto& query : lane.queries) {
                if (!SameQuery(p.queries[flat++], query))
                    return fail("dual AIR query view mismatch");
            }
        }
        return true;
    }

    static uint32_t NumQueries() { return kRCFri3AlgDualTotalQueries; }

private:
    static bool SameFp3Vector(const std::vector<gkr_field::Fp3>& a,
                              const std::vector<gkr_field::Fp3>& b)
    {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            if (!gkr_field::Eq(a[i], b[i])) return false;
        }
        return true;
    }

    static bool SameDigestVector(const std::vector<Fri3AlgDigest>& a,
                                 const std::vector<Fri3AlgDigest>& b)
    {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            if (PackDigest(a[i]) != PackDigest(b[i])) return false;
        }
        return true;
    }

    static bool SameStep(const Fri3AlgFoldStep& a, const Fri3AlgFoldStep& b)
    {
        return a.even_index == b.even_index &&
               a.odd_index == b.odd_index &&
               gkr_field::Eq(a.even, b.even) &&
               gkr_field::Eq(a.odd, b.odd) &&
               SameDigestVector(a.even_siblings, b.even_siblings) &&
               SameDigestVector(a.odd_siblings, b.odd_siblings);
    }

    static bool SameQuery(const Fri3AlgBatchQuery& a,
                          const Fri3AlgBatchQuery& b)
    {
        if (a.index != b.index ||
            !SameFp3Vector(a.row.values, b.row.values) ||
            !SameDigestVector(a.row.siblings, b.row.siblings) ||
            a.steps.size() != b.steps.size()) {
            return false;
        }
        for (size_t i = 0; i < a.steps.size(); ++i) {
            if (!SameStep(a.steps[i], b.steps[i])) return false;
        }
        return true;
    }
};

/**
 * Bounded equivalence backend.  It executes both the ordinary materialized
 * dual-Q128 batch commit and the two-pass column-streaming commit, requires
 * their serialized proofs to be byte-identical, then returns the materialized
 * result so the generic AIR prover can still construct supplemental next-row
 * paths.  This is an audit seam, not the production streaming backend.
 */
struct AirFriBackendAlgDualStreamingAudit
    : public AirFriBackendAlgDual<gkr_field::Fp3> {
    using Base = AirFriBackendAlgDual<gkr_field::Fp3>;
    using BatchCommitResult = typename Base::BatchCommitResult;

    static BatchCommitResult BatchCommit(
        const std::vector<std::vector<gkr_field::Fp3>>& cols,
        const uint256& fs_seed)
    {
        BatchCommitResult dense =
            Base::BatchCommit(cols, fs_seed);
        if (!dense.ok) return dense;
        Fri3AlgDualBatchCommitResult streamed =
            Fri3AlgDualBatchCommitStreamingShared(
                cols, fs_seed);
        if (!streamed.ok) {
            dense.ok = false;
            dense.note =
                "streaming audit commit failed: " +
                streamed.note;
            return dense;
        }
        std::vector<unsigned char> dense_bytes;
        std::vector<unsigned char> streamed_bytes;
        const size_t dense_size =
            SerializeFri3AlgDualBatchProof(
            dense.proof.repeated, dense_bytes);
        const size_t streamed_size =
            SerializeFri3AlgDualBatchProof(
            streamed.proof, streamed_bytes);
        if (dense_size == 0 || streamed_size == 0 ||
            dense_size != streamed_size ||
            dense_bytes != streamed_bytes) {
            dense.ok = false;
            dense.note =
                "streaming audit transcript mismatch";
            return dense;
        }
        dense.note =
            "dense and two-pass streaming batch proofs "
            "byte-identical";
        return dense;
    }
};

} // namespace matmul::v4::rc::air_quotient

#endif // BTX_MATMUL_MATMUL_V4_RC_AIR_QUOTIENT_ALG_H
