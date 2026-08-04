// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_FIRST_COLLISION_AUDIT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_FIRST_COLLISION_AUDIT_H

#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3 {

/**
 * Conditional first-collision lemma.
 *
 * Let H be one fixed deterministic hash and let every binding node s use an
 * injective, prefix-free encoding Enc(s, value).  Suppose:
 *
 *  1. all nodes in the finite binding DAG have one public total order;
 *  2. an accepted false statement admits an extractor that outputs both the
 *     canonical intended and adversarial node inputs;
 *  3. local binding completeness guarantees that unequal global semantics
 *     with the same accepted root contain a node with unequal encodings and
 *     equal H outputs; and
 *  4. extraction and the scan preserve the adversary's adaptive
 *     Fiat--Shamir/PoW transcript.
 *
 * Then scanning the extracted nodes and outputting the first such node is a
 * collision-resistance reduction with no 1/S site-guessing factor:
 *
 *   Pr[B outputs an H collision]
 *     >= Pr[A forges and extraction/local binding succeed].
 *
 * The scan costs O(S).  This lemma does NOT remove:
 *
 *  - a knowledge-extraction or Fiat--Shamir forking loss;
 *  - the total work/query advantage of PoW grinding;
 *  - random-oracle birthday dependence on the total number of hash queries;
 *  - failures of canonical encoding, site enumeration, or local binding.
 *
 * If a hybrid proof must embed an external challenge at one unknown site, or
 * if the reduction sees only roots/openings and cannot extract both
 * preimages, the no-guessing premise fails and an S loss cannot be removed by
 * naming a "first" site after the fact.
 */

/** One fully extracted local binding comparison in canonical scan order. */
struct FirstCollisionObservation {
    uint64_t site_ordinal{0};
    std::vector<unsigned char> intended_encoding;
    std::vector<unsigned char> adversarial_encoding;
    uint256 intended_digest{};
    uint256 adversarial_digest{};
    bool both_preimages_extracted{false};
    bool digests_recomputed_from_encodings{false};
};

struct FirstCollisionScanResult {
    bool input_well_formed{false};
    bool collision_found{false};
    bool blocked_on_extraction{false};
    bool no_site_guessing_used{false};
    uint64_t selected_site_ordinal{0};
    uint64_t observations_scanned{0};
    std::string note;
};

/**
 * Deterministic structural extractor.  Digest recomputation belongs to the
 * caller's selected versioned AlgHash; this function refuses observations
 * that are not marked as recomputed from the supplied canonical encodings.
 */
[[nodiscard]] FirstCollisionScanResult
ScanFirstCollisionObservations(
    const std::vector<FirstCollisionObservation>& observations);

// ---------------------------------------------------------------------------
// O-EXTRACT-IMPL: the accepted-proof two-preimage collision extractor.
//
// Realizes doc section 3.2 (the reduction B). Over ONE accepted proof, build
// the exhibited-evaluation-pair multiset
//     E := { (x, d) : d = SHA256d(x) exhibited by the accepted proof }
// and first-collision-scan it in the canonical total order
//     (level, node_id, slot, ordinal).
// Straight-line: no rewinding, no 1/S site-guessing, no forking. Each in-circuit
// SHA-constraint satisfaction contributes one pair (preimage x from witness
// columns; digest d from the pinned boundary); native evaluations (Merkle path,
// manifest recompute, header hash) also contribute pairs. On finding two pairs
// with equal digest and distinct preimage, output the CRHF collision witness.
//
// Genuineness of each pair (that the pinned d really is SHA256d(x)) is charged
// to A-EXACT (O-EXACT, the 952-row SHA AIR functional-exactness audit), which
// remains OPEN. Witness availability is charged to A-EXTRACT (roadmap A1/A2).
// This extractor is the mechanical object whose ABSENCE was the audit's
// first_blocker; it does not by itself close O-EXACT or A-FS-INST.
// ---------------------------------------------------------------------------

/** One exhibited (preimage, digest) pair with its canonical position key. */
struct ExhibitedPair {
    uint8_t level{0};
    uint64_t node_id{0};
    uint32_t slot{0};
    uint32_t ordinal{0};
    std::vector<unsigned char> preimage; // x, from witness columns / tape
    uint256 digest{};                    // d, from pinned boundary / commitment
};

/** The CRHF collision witness produced by the extractor on branch (b). */
struct TwoPreimageCollisionWitness {
    bool found{false};
    std::vector<unsigned char> preimage_a;
    std::vector<unsigned char> preimage_b;
    uint256 digest{};
    uint64_t first_site_ordinal{0};
    uint64_t pairs_scanned{0};
    bool no_site_guessing_used{false};
    bool straight_line_single_run{true};
    std::string note;
};

/**
 * Build E from the exhibited pairs of one accepted proof, impose the canonical
 * (level, node_id, slot, ordinal) total order, and output the FIRST digest
 * exhibited with two distinct preimages. Returns found=false on an honest proof
 * (the map d -> x is a function on E, i.e. the alignment branch).
 *
 * Internally delegates the collision selection to ScanFirstCollisionObservations
 * so the reduction uses the exact vetted scanner shape (both_preimages_extracted
 * and digests_recomputed_from_encodings both populated true from the encodings).
 */
[[nodiscard]] TwoPreimageCollisionWitness
RunAcceptedProofTwoPreimageExtractor(std::vector<ExhibitedPair> pairs);

/** Current repository applicability audit.  It is intentionally fail closed. */
struct GlobalFirstCollisionHybridAudit {
    uint16_t version{1};
    uint32_t semantic_relation_endpoints{52};
    uint64_t known_site_inventory{994'229};
    uint64_t declared_site_upper_bound{uint64_t{1} << 28};
    uint32_t declared_pow_grinding_bits{40};

    bool deterministic_scanner_executable{false};
    bool canonical_total_order_specified{false};
    bool manifest_enforces_site_upper_bound{false};
    bool all_binding_nodes_use_injective_encoding{false};
    bool local_commitment_dag_binding_complete{false};
    bool accepted_proof_two_preimage_extractor_executable{false};
    bool adaptive_fs_extraction_loss_proved{false};
    bool pow_grinding_loss_accounted{false};

    bool conditional_no_site_guessing_lemma_valid{false};
    bool lemma_applicable_to_current_proof{false};
    bool global_reduction_complete{false};
    uint32_t promoted_security_bits{0};
    std::string first_blocker;
};

[[nodiscard]] GlobalFirstCollisionHybridAudit
AssessGlobalFirstCollisionHybrid();

} // namespace matmul::v4::rc::stage3

#endif
