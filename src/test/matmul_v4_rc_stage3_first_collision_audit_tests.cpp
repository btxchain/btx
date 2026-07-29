// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_first_collision_audit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace s3 = matmul::v4::rc::stage3;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_first_collision_audit_tests,
    BasicTestingSetup)

namespace {

uint256 Digest(uint8_t tag)
{
    uint256 out;
    out.data()[0] = tag;
    return out;
}

s3::FirstCollisionObservation Observation(
    uint64_t site, uint8_t left, uint8_t right,
    uint8_t left_digest, uint8_t right_digest)
{
    s3::FirstCollisionObservation out;
    out.site_ordinal = site;
    out.intended_encoding = {left};
    out.adversarial_encoding = {right};
    out.intended_digest = Digest(left_digest);
    out.adversarial_digest = Digest(right_digest);
    out.both_preimages_extracted = true;
    out.digests_recomputed_from_encodings = true;
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    deterministic_scan_selects_first_without_site_guess)
{
    const std::vector<s3::FirstCollisionObservation> observations{
        Observation(3, 1, 1, 9, 9),
        Observation(7, 2, 3, 10, 10),
        Observation(11, 4, 5, 12, 12),
    };
    const auto scan =
        s3::ScanFirstCollisionObservations(observations);
    BOOST_CHECK(scan.input_well_formed);
    BOOST_CHECK(scan.collision_found);
    BOOST_CHECK(!scan.blocked_on_extraction);
    BOOST_CHECK(scan.no_site_guessing_used);
    BOOST_CHECK_EQUAL(scan.selected_site_ordinal, 7U);
    BOOST_CHECK_EQUAL(scan.observations_scanned, 2U);
    BOOST_CHECK_EQUAL(scan.note, "first_collision:collision");
}

BOOST_AUTO_TEST_CASE(
    deterministic_scan_fails_closed_on_extractor_gap)
{
    std::vector<s3::FirstCollisionObservation> observations{
        Observation(3, 1, 1, 9, 9),
        Observation(7, 2, 3, 10, 10),
        Observation(11, 4, 5, 12, 12),
    };
    observations[1].both_preimages_extracted = false;
    const auto scan =
        s3::ScanFirstCollisionObservations(observations);
    BOOST_CHECK(scan.input_well_formed);
    BOOST_CHECK(!scan.collision_found);
    BOOST_CHECK(scan.blocked_on_extraction);
    BOOST_CHECK(!scan.no_site_guessing_used);
    BOOST_CHECK_EQUAL(scan.selected_site_ordinal, 7U);
    BOOST_CHECK_EQUAL(scan.note, "first_collision:extractor_gap");

    std::swap(observations[0], observations[1]);
    const auto unordered =
        s3::ScanFirstCollisionObservations(observations);
    BOOST_CHECK(!unordered.input_well_formed);
    BOOST_CHECK(!unordered.collision_found);
    BOOST_CHECK_EQUAL(
        unordered.note,
        "first_collision:noncanonical_inventory");
}

BOOST_AUTO_TEST_CASE(global_hybrid_audit_does_not_promote_bits)
{
    const auto audit =
        s3::AssessGlobalFirstCollisionHybrid();
    BOOST_CHECK_EQUAL(audit.version, 1U);
    BOOST_CHECK_EQUAL(audit.semantic_relation_endpoints, 52U);
    BOOST_CHECK_EQUAL(audit.known_site_inventory, 994'229U);
    BOOST_CHECK_EQUAL(
        audit.declared_site_upper_bound, uint64_t{1} << 28);
    BOOST_CHECK_EQUAL(audit.declared_pow_grinding_bits, 40U);
    BOOST_CHECK(audit.deterministic_scanner_executable);
    BOOST_CHECK(audit.canonical_total_order_specified);
    BOOST_CHECK(audit.conditional_no_site_guessing_lemma_valid);
    BOOST_CHECK(!audit.manifest_enforces_site_upper_bound);
    BOOST_CHECK(!audit.all_binding_nodes_use_injective_encoding);
    BOOST_CHECK(!audit.local_commitment_dag_binding_complete);
    // O-EXTRACT-IMPL: the accepted-proof two-preimage extractor is now
    // executable (this is the flag the doc's section 3.2 flips).
    BOOST_CHECK(
        audit.accepted_proof_two_preimage_extractor_executable);
    BOOST_CHECK(!audit.adaptive_fs_extraction_loss_proved);
    BOOST_CHECK(!audit.pow_grinding_loss_accounted);
    BOOST_CHECK(!audit.lemma_applicable_to_current_proof);
    BOOST_CHECK(!audit.global_reduction_complete);
    // Global reduction stays open; no bits promoted (O-EXACT / A-FS-INST).
    BOOST_CHECK_EQUAL(audit.promoted_security_bits, 0U);
    BOOST_CHECK(audit.first_blocker.find("A-EXACT") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    accepted_proof_extractor_finds_planted_collision)
{
    // Two exhibited pairs at distinct canonical sites carry the SAME pinned
    // digest but DISTINCT preimages: the case-(iii) event. The straight-line
    // extractor must output the CRHF collision witness.
    uint256 shared = Digest(0x77);
    std::vector<s3::ExhibitedPair> pairs;
    {
        s3::ExhibitedPair p;
        p.level = 1; p.node_id = 4; p.slot = 0; p.ordinal = 0;
        p.preimage = {0x04, 0xAA, 0xBB};
        p.digest = shared;
        pairs.push_back(p);
    }
    {
        s3::ExhibitedPair p; // child's own exhibited root: distinct preimage
        p.level = 2; p.node_id = 9; p.slot = 1; p.ordinal = 0;
        p.preimage = {0x03, 0xCC, 0xDD};
        p.digest = shared;
        pairs.push_back(p);
    }
    {
        s3::ExhibitedPair p; // an unrelated honest site
        p.level = 0; p.node_id = 0; p.slot = 0; p.ordinal = 0;
        p.preimage = {0x01, 0x11};
        p.digest = Digest(0x22);
        pairs.push_back(p);
    }
    const auto w = s3::RunAcceptedProofTwoPreimageExtractor(pairs);
    BOOST_CHECK(w.found);
    BOOST_CHECK(w.no_site_guessing_used);
    BOOST_CHECK(w.straight_line_single_run);
    BOOST_CHECK(w.preimage_a != w.preimage_b);
    BOOST_CHECK(w.digest == shared);
    BOOST_CHECK_EQUAL(w.note, "extractor:crhf_collision_witness");
}

BOOST_AUTO_TEST_CASE(
    accepted_proof_extractor_returns_none_on_honest_proof)
{
    // Every exhibited digest is distinct: the alignment branch. d -> x is a
    // function on E, so no collision witness exists.
    std::vector<s3::ExhibitedPair> pairs;
    for (uint32_t i = 0; i < 5; ++i) {
        s3::ExhibitedPair p;
        p.level = static_cast<uint8_t>(i);
        p.node_id = i;
        p.slot = 0;
        p.ordinal = 0;
        p.preimage = {static_cast<unsigned char>(0x04),
                      static_cast<unsigned char>(i)};
        p.digest = Digest(static_cast<uint8_t>(0x30 + i));
        pairs.push_back(p);
    }
    const auto w = s3::RunAcceptedProofTwoPreimageExtractor(pairs);
    BOOST_CHECK(!w.found);
    BOOST_CHECK(w.no_site_guessing_used);
    BOOST_CHECK_EQUAL(w.note, "extractor:aligned_no_collision");
    BOOST_CHECK_EQUAL(w.pairs_scanned, 5U);
}

BOOST_AUTO_TEST_CASE(
    accepted_proof_extractor_ignores_repeated_identical_pair)
{
    // Same (x, d) exhibited at two sites is NOT a collision (aligned).
    uint256 d = Digest(0x55);
    std::vector<s3::ExhibitedPair> pairs;
    {
        s3::ExhibitedPair p;
        p.level = 1; p.node_id = 1; p.slot = 0; p.ordinal = 0;
        p.preimage = {0x04, 0x01}; p.digest = d;
        pairs.push_back(p);
    }
    {
        s3::ExhibitedPair p;
        p.level = 2; p.node_id = 2; p.slot = 0; p.ordinal = 0;
        p.preimage = {0x04, 0x01}; p.digest = d; // identical preimage
        pairs.push_back(p);
    }
    const auto w = s3::RunAcceptedProofTwoPreimageExtractor(pairs);
    BOOST_CHECK(!w.found);
    BOOST_CHECK_EQUAL(w.note, "extractor:aligned_no_collision");
}

BOOST_AUTO_TEST_SUITE_END()
