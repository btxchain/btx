// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_coupled_bank_narrow.h>
#include <matmul/matmul_v4_rc_stage3_coupled_bank_stream.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

namespace rc = matmul::v4::rc;
namespace ha = rc::stage3_hash_air;
namespace gf = rc::gkr_field;
namespace aq = rc::air_quotient;
namespace ar = rc::air_recurse;

uint256 H(unsigned char value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{Span<const unsigned char>{
        bytes.data(), bytes.size()}};
}

rc::RCStage3SuccinctProof Statement()
{
    rc::RCStage3SuccinctProof statement;
    statement.statement = rc::RCStage3StatementKind::Composed;
    statement.public_inputs.height = 17;
    statement.public_inputs.episode_profile = 2;
    statement.public_inputs.coupled_profile = 4;
    statement.public_inputs.transcript_version = rc::ENC_RC_V4;
    statement.public_inputs.header_commitment = H(0x11);
    statement.public_inputs.params_commitment = H(0x22);
    statement.public_inputs.sigma = H(0x33);
    statement.public_inputs.coupled_digest = H(0x44);
    return statement;
}

rc::RCStage3CoupledShape ToyShape()
{
    return rc::MakeRCStage3CoupledShape(
        rc::MakeToyRCCoupParams(),
        rc::MakeV4RCCoupOptions());
}

uint64_t CeilDiv(uint64_t value, uint64_t divisor)
{
    return value / divisor + (value % divisor != 0);
}

std::vector<rc::RCStage3CoupledBankStreamIntervalReceipt>
SyntheticParentChildren(
    const rc::RCStage3CoupledBankStreamManifest& manifest,
    uint32_t first_block,
    std::array<uint32_t, 8> state)
{
    std::vector<rc::RCStage3CoupledBankStreamIntervalReceipt>
        children(4);
    for (uint32_t i = 0; i < children.size(); ++i) {
        auto& child = children[i];
        child.level = 0;
        child.index = first_block + i;
        child.first_block = first_block + i;
        child.block_count = 1;
        child.first_h_in = state;
        child.last_h_out = state;
        child.last_h_out[0] += i + 1;
        child.last_h_out[7] ^= UINT32_C(0x01010101) * (i + 1);
        state = child.last_h_out;
        child.child_commitments = {
            H(static_cast<unsigned char>(0x70 + i))};
        child.commitment =
            rc::CommitRCStage3CoupledBankStreamIntervalReceipt(
                manifest, child);
        BOOST_REQUIRE(!child.commitment.IsNull());
    }
    return children;
}

std::vector<rc::RCStage3CoupledBankStreamIntervalReceipt>
SyntheticFirstParentChildren(
    const rc::RCStage3CoupledBankStreamManifest& manifest)
{
    return SyntheticParentChildren(
        manifest, 0,
        ha::CanonicalSha256InitialState());
}

aq::AirConstraintSystem<gf::Fp3> NormalizedToyChildCS()
{
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 2;
    cs.n_columns = 1;
    cs.preprocessed_pin_ood = true;
    return cs;
}

ar::DualAlgAirProof ProveNormalizedToyChild(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const uint256& seed)
{
    const std::vector<std::vector<gf::Fp3>> columns{{
        gf::Fp3::FromFp(gf::FromU64(7)),
        gf::Fp3::FromFp(gf::FromU64(11))}};
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, ar::DualAlgB3>(
            cs, columns, seed, {});
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact, proved.note);
    return proved.proof;
}

} // namespace

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_coupled_bank_stream_tests)

BOOST_AUTO_TEST_CASE(production_schedule_is_manifest_derived_and_compact)
{
    const auto statement = Statement();
    const auto shape = rc::MakeRCStage3CoupledShape(
        rc::MakeProductionV3RCCoupParams(),
        rc::MakeV4RCCoupOptions());
    rc::RCStage3CoupledBankStreamManifest manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamManifest(
            statement, shape, H(0x51), manifest, &why),
        why);

    const uint64_t page_bytes =
        uint64_t{shape.bank_pages} * shape.lobe_width *
        shape.lobe_width;
    BOOST_CHECK_EQUAL(manifest.bank_page_bytes, page_bytes);
    BOOST_CHECK(
        manifest.bank_page_bytes >
        rc::kRCStage3CoupledBankStreamTestMaxBytes);
    BOOST_CHECK_EQUAL(
        manifest.source_chunks, CeilDiv(page_bytes, 64));
    BOOST_CHECK(
        manifest.source_tree_leaves >= manifest.source_chunks);
    BOOST_CHECK_EQUAL(
        manifest.source_tree_leaves,
        uint64_t{1} << manifest.source_tree_depth);
    BOOST_CHECK_EQUAL(
        manifest.first_pass_blocks,
        CeilDiv(manifest.first_message_bytes + 9, 64));
    BOOST_CHECK(
        manifest.commitment ==
        rc::CommitRCStage3CoupledBankStreamManifest(manifest));
    BOOST_CHECK(rc::ValidateRCStage3CoupledBankStreamManifest(
        statement, shape, H(0x51), manifest, &why));

    auto changed = manifest;
    ++changed.first_pass_blocks;
    BOOST_CHECK(!rc::ValidateRCStage3CoupledBankStreamManifest(
        statement, shape, H(0x51), changed, &why));
    BOOST_CHECK(!rc::ValidateRCStage3CoupledBankStreamManifest(
        statement, shape, H(0x52), manifest, &why));

    const auto estimate =
        rc::EstimateRCStage3CoupledBankStreamRecursiveCost(
            manifest, 1, 1);
    BOOST_CHECK_EQUAL(
        estimate.leaf_proofs, UINT64_C(1610612737));
    BOOST_CHECK_EQUAL(
        estimate.parent_proofs, UINT64_C(536870927));
    BOOST_CHECK_EQUAL(
        estimate.total_proofs, UINT64_C(2147483664));
    BOOST_CHECK_EQUAL(estimate.tree_depth, 16U);
    BOOST_CHECK_GT(estimate.expanded_verify_seconds, 2000.0L);
    BOOST_CHECK(!estimate.succinct);
}

BOOST_AUTO_TEST_CASE(source_openings_bind_every_byte_and_position)
{
    const auto statement = Statement();
    const auto shape = ToyShape();
    const uint64_t bank_bytes =
        uint64_t{shape.bank_pages} * shape.lobe_width *
        shape.lobe_width;
    std::vector<uint8_t> pages(bank_bytes);
    for (uint64_t i = 0; i < bank_bytes; ++i) {
        pages[i] = static_cast<uint8_t>(
            (i * UINT64_C(131) + 17) & 0xffU);
    }

    uint256 root;
    rc::RCStage3CoupledBankSourceOpening opening;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankSourceOpeningForTest(
            pages, 1, root, opening, &why),
        why);
    rc::RCStage3CoupledBankStreamManifest manifest;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamManifest(
            statement, shape, root, manifest, &why),
        why);
    BOOST_CHECK(rc::VerifyRCStage3CoupledBankSourceOpening(
        manifest, opening, &why));

    auto changed_byte = opening;
    changed_byte.bytes[7] ^= 1U;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledBankSourceOpening(
        manifest, changed_byte, &why));

    auto changed_position = opening;
    changed_position.chunk_index = 0;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledBankSourceOpening(
        manifest, changed_position, &why));

    auto changed_path = opening;
    BOOST_REQUIRE(!changed_path.authentication_path.empty());
    changed_path.authentication_path[0] = H(0x7a);
    BOOST_CHECK(!rc::VerifyRCStage3CoupledBankSourceOpening(
        manifest, changed_path, &why));
}

BOOST_AUTO_TEST_CASE(leaf_projection_fails_closed_before_recursive_authority)
{
    const auto statement = Statement();
    const auto shape = ToyShape();
    const uint64_t bank_bytes =
        uint64_t{shape.bank_pages} * shape.lobe_width *
        shape.lobe_width;
    std::vector<uint8_t> pages(bank_bytes, 0x5a);
    uint256 root;
    rc::RCStage3CoupledBankSourceOpening opening;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankSourceOpeningForTest(
            pages, 0, root, opening, &why),
        why);
    rc::RCStage3CoupledBankStreamManifest manifest;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamManifest(
            statement, shape, root, manifest, &why),
        why);

    rc::RCStage3CoupledBankStreamLeafProof leaf;
    leaf.block_index = 0;
    leaf.h_in = ha::CanonicalSha256InitialState();
    leaf.source_openings = {opening};
    const auto& tags =
        rc::RCCoupDomainTagsForVersion(shape.transcript_version);
    const auto* tag = reinterpret_cast<const uint8_t*>(tags.bank);
    const size_t tag_size = std::strlen(tags.bank);
    BOOST_REQUIRE_LT(tag_size, leaf.padded_block.size());
    std::copy_n(tag, tag_size, leaf.padded_block.begin());
    std::copy_n(
        pages.begin(), leaf.padded_block.size() - tag_size,
        leaf.padded_block.begin() + tag_size);
    // An unexecuted fixed-program proof must never become a leaf receipt,
    // even if the source opening itself is valid.
    BOOST_CHECK(!rc::VerifyRCStage3CoupledBankStreamLeaf(
        manifest, leaf, &why));
    BOOST_CHECK(
        why.find("leaf:compression_proof") != std::string::npos);

    auto changed_projection = leaf;
    changed_projection.padded_block[tag_size + 3] ^= 1U;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledBankStreamLeaf(
        manifest, changed_projection, &why));
    BOOST_CHECK(why.find("leaf:padded_block") != std::string::npos);

    rc::RCStage3CoupledBankStreamIntervalReceipt receipt;
    BOOST_CHECK(!rc::BuildRCStage3CoupledBankStreamLeafReceipt(
        manifest, leaf, receipt, &why));

    const auto audit =
        rc::CurrentRCStage3CoupledBankStreamAudit();
    BOOST_CHECK(audit.production_counts_manifest_derived);
    BOOST_CHECK(audit.source_chunk_openings_executable);
    BOOST_CHECK(audit.byte_to_sha_word_projection_executable);
    BOOST_CHECK(audit.fixed_program_leaf_proof_executable);
    BOOST_CHECK(
        audit.exact_chaining_aggregation_schedule_executable);
    BOOST_CHECK(audit.second_pass_and_bank_root_executable);
    BOOST_CHECK(audit.recursive_interval_proof_executable);
    BOOST_CHECK(!audit.succinct_fixed_point_executable);
    BOOST_CHECK(!audit.strict_semantic_complete);
    BOOST_CHECK(
        !rc::kRCStage3CoupledBankStreamingRecursiveAuthorityReady);
}

BOOST_AUTO_TEST_CASE(
    interval_air_proves_contiguity_chaining_and_parent_boundary)
{
    const auto statement = Statement();
    const auto shape = ToyShape();
    rc::RCStage3CoupledBankStreamManifest manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamManifest(
            statement, shape, H(0x51), manifest, &why),
        why);
    const auto children = SyntheticFirstParentChildren(manifest);
    rc::RCStage3CoupledBankStreamIntervalReceipt parent;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamParentReceipt(
            manifest, children, parent, &why),
        why);

    rc::RCStage3CoupledBankStreamIntervalAirProof proof;
    const auto prove_start = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3CoupledBankStreamIntervalRelation(
            manifest, children, parent, proof, &why),
        why);
    const auto prove_end = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3CoupledBankStreamIntervalRelation(
            manifest, children, parent, proof, &why),
        why);
    const auto verify_end = std::chrono::steady_clock::now();
    BOOST_TEST_MESSAGE(
        "bank interval AIR prove_us="
        << std::chrono::duration_cast<std::chrono::microseconds>(
               prove_end - prove_start).count()
        << " verify_us="
        << std::chrono::duration_cast<std::chrono::microseconds>(
               verify_end - prove_end).count()
        << " rows=4 columns=76");

    auto changed_chain = children;
    changed_chain[1].first_h_in[3] ^= 1U;
    changed_chain[1].commitment =
        rc::CommitRCStage3CoupledBankStreamIntervalReceipt(
            manifest, changed_chain[1]);
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledBankStreamIntervalRelation(
            manifest, changed_chain, parent, proof, &why));

    auto changed_child = children;
    changed_child[2].child_commitments[0] = H(0x28);
    changed_child[2].commitment =
        rc::CommitRCStage3CoupledBankStreamIntervalReceipt(
            manifest, changed_child[2]);
    rc::RCStage3CoupledBankStreamIntervalReceipt changed_parent;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamParentReceipt(
            manifest, changed_child, changed_parent, &why),
        why);
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledBankStreamIntervalRelation(
            manifest, changed_child, changed_parent, proof, &why));

    auto changed_proof = proof;
    BOOST_REQUIRE(!changed_proof.batch.queries.empty());
    BOOST_REQUIRE(
        !changed_proof.batch.queries[0].row.values.empty());
    changed_proof.batch.queries[0].row.values[0] =
        gf::Add(
            changed_proof.batch.queries[0].row.values[0],
            gf::Fp3::One());
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledBankStreamIntervalRelation(
            manifest, children, parent, changed_proof, &why));

    // A valid interval-relation proof cannot replace verification of the
    // embedded child leaf proofs.
    std::vector<rc::RCStage3CoupledBankStreamRecursiveProof>
        unproved_children(4);
    for (uint32_t i = 0; i < unproved_children.size(); ++i) {
        unproved_children[i].receipt = children[i];
    }
    rc::RCStage3CoupledBankStreamRecursiveProof recursive;
    recursive.receipt = parent;
    recursive.children = unproved_children;
    recursive.interval_relation_proof = proof;
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledBankStreamRecursiveProof(
            manifest, recursive, &why));

    const auto audit =
        rc::CurrentRCStage3CoupledBankStreamAudit();
    BOOST_CHECK(audit.interval_relation_air_executable);
    BOOST_CHECK(
        audit.recursive_child_tree_verifier_executable);
    BOOST_CHECK(audit.recursive_interval_proof_executable);
    BOOST_CHECK(!audit.succinct_fixed_point_executable);
    BOOST_CHECK(!audit.strict_semantic_complete);
    BOOST_CHECK(
        rc::kRCStage3CoupledBankStreamingRecursiveTreeVerifierExecutable);
    BOOST_CHECK(
        !rc::kRCStage3CoupledBankStreamingSuccinctFixedPointExecutable);
}

BOOST_AUTO_TEST_CASE(
    descendant_free_normalized_step_proves_and_verifies_two_levels)
{
    const auto leaf_cs = NormalizedToyChildCS();
    const uint256 leaf_seed = H(0x91);
    const auto leaf =
        ProveNormalizedToyChild(leaf_cs, leaf_seed);

    // The bounded proof run exercises the fixed-size descendant-free
    // composition twice. Full-family witness execution is covered by the
    // separate normalized V5 differential test; proving four full wide
    // mirrors would exceed the current backend width cap.
    ar::VerifierAirFamilies bounded;
    bounded.row_merkle = false;
    bounded.fold = false;
    bounded.deep = false;
    bounded.per_point = false;
    bounded.next_row = false;
    bounded.trace_binding = false;

    const auto level1 =
        rc::BuildRCStage3CoupledBankNormalizedVerifierStep(
            leaf_cs, {leaf}, leaf_seed, H(0x92), bounded);
    BOOST_REQUIRE_MESSAGE(level1.valid, level1.note);
    BOOST_CHECK(level1.descendant_free);
    BOOST_CHECK(level1.complete_child_proof_commitments);
    BOOST_CHECK(level1.fiat_shamir_replayed_on_host);
    BOOST_CHECK(!level1.fiat_shamir_equations_in_air);
    BOOST_CHECK(!level1.bank_interval_relation_same_trace);
    BOOST_CHECK(!level1.all_available_algebraic_families);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3CoupledBankNormalizedVerifierStep(
            level1, &why),
        why);

    const auto level1_cs =
        rc::BuildRCStage3CoupledBankNormalizedOutputConstraintSystem(
            level1);
    BOOST_REQUIRE_GT(level1_cs.n_rows, 0U);
    BOOST_REQUIRE_GT(level1_cs.n_columns, 0U);
    const auto level2 =
        rc::BuildRCStage3CoupledBankNormalizedVerifierStep(
            level1_cs, {level1.normalized_parent},
            level1.effective_fs_seed, H(0x93), bounded);
    BOOST_REQUIRE_MESSAGE(level2.valid, level2.note);
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3CoupledBankNormalizedVerifierStep(
            level2, &why),
        why);
    BOOST_CHECK(level2.descendant_free);
    BOOST_CHECK_EQUAL(level2.logical_children, 1U);
    BOOST_CHECK(!level2.commitment.IsNull());
    BOOST_TEST_MESSAGE(
        "bank normalized two-level step: level1(rows="
        << level1.rows << ",cols=" << level1.columns
        << ",prove_us=" << level1.prove_micros
        << ") level2(rows=" << level2.rows
        << ",cols=" << level2.columns
        << ",prove_us=" << level2.prove_micros << ")");

    auto changed_pin = level2;
    changed_pin.child_pins[0]
        .air_proof_commitment.begin()[0] ^= 1U;
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledBankNormalizedVerifierStep(
            changed_pin, &why));

    auto changed_parent = level2;
    changed_parent.normalized_parent.batch.repeated
        .lane_child_binding[0].begin()[0] ^= 1U;
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledBankNormalizedVerifierStep(
            changed_parent, &why));

    auto changed_seed = level2;
    changed_seed.parent_fs_seed = H(0x94);
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledBankNormalizedVerifierStep(
            changed_seed, &why));

    const auto audit =
        rc::CurrentRCStage3CoupledBankStreamAudit();
    BOOST_CHECK(
        audit.normalized_descendant_free_step_executable);
    BOOST_CHECK(audit.normalized_two_level_execution_tested);
    BOOST_CHECK(
        !audit.normalized_full_four_child_families_executable);
    BOOST_CHECK(!audit.succinct_fixed_point_executable);
}

BOOST_AUTO_TEST_CASE(
    full_normalized_family_scan_is_explicitly_non_authoritative)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_COUPLED_BANK_FULL_VCS_SCAN") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_COUPLED_BANK_FULL_VCS_SCAN=1 "
            "to execute the 12,668-column full V5 mirror scan");
        return;
    }
    const auto child_cs = NormalizedToyChildCS();
    const uint256 seed = H(0x95);
    const auto child =
        ProveNormalizedToyChild(child_cs, seed);
    const auto full =
        ar::BuildDualV5AggregateWitness(
            child_cs, {child}, seed, {});
    BOOST_REQUIRE_MESSAGE(full.ok, full.note);
    BOOST_CHECK_EQUAL(full.normalized_violations, 0U);
    BOOST_CHECK_EQUAL(full.normalized.cs.n_rows, 128U);
    BOOST_CHECK_LT(
        full.normalized.cs.n_columns,
        rc::kRCFri3AlgBatchMaxColumns);
    BOOST_CHECK_GT(
        full.normalized.cs.n_columns,
        rc::kRCFri3AlgBatchMaxColumns / 4);
    BOOST_CHECK_GT(
        4U * full.normalized.cs.n_columns,
        rc::kRCFri3AlgBatchMaxColumns);
    BOOST_CHECK(!ar::kDualV5FiatShamirEquationsInAir);
    BOOST_CHECK(!ar::kDualV5MasterBindingEquationsInAir);
    BOOST_CHECK(!ar::kDualV5CompleteVerifierAirExecutable);
}

BOOST_AUTO_TEST_CASE(
    full_binary_mirror_joins_interval_outputs_in_same_trace)
{
    const auto statement = Statement();
    const auto shape = ToyShape();
    rc::RCStage3CoupledBankStreamManifest manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamManifest(
            statement, shape, H(0x51), manifest, &why),
        why);
    const auto first_children =
        SyntheticFirstParentChildren(manifest);
    rc::RCStage3CoupledBankStreamIntervalReceipt first_parent;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamParentReceipt(
            manifest, first_children, first_parent, &why),
        why);
    const auto second_children =
        SyntheticParentChildren(
            manifest, 4, first_parent.last_h_out);
    rc::RCStage3CoupledBankStreamIntervalReceipt second_parent;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamParentReceipt(
            manifest, second_children, second_parent, &why),
        why);
    BOOST_REQUIRE_EQUAL(
        second_parent.first_block,
        first_parent.first_block + first_parent.block_count);
    BOOST_REQUIRE(
        second_parent.first_h_in ==
        first_parent.last_h_out);

    std::vector<aq::AirConstraintSystem<gf::Fp3>> child_css(2);
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamIntervalConstraintSystem(
            manifest, first_children, first_parent,
            child_css[0], &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamIntervalConstraintSystem(
            manifest, second_children, second_parent,
            child_css[1], &why),
        why);
    const std::vector<uint256> seeds{H(0xa1), H(0xa2)};
    std::vector<ar::DualAlgAirProof> proofs(2);
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3CoupledBankStreamDualIntervalRelation(
            manifest, first_children, first_parent,
            seeds[0], proofs[0], &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3CoupledBankStreamDualIntervalRelation(
            manifest, second_children, second_parent,
            seeds[1], proofs[1], &why),
        why);

    const auto binary =
        rc::BuildRCStage3CoupledBankFullBinaryMirrorWitness(
            child_css, proofs, seeds, {58, 58});
    BOOST_CHECK(!binary.valid);
    BOOST_CHECK(binary.independent_child_seeds);
    BOOST_CHECK(binary.both_children_executed);
    BOOST_CHECK(binary.all_vcs_families_enabled);
    BOOST_CHECK(binary.lane_output_equality_same_trace);
    BOOST_CHECK(binary.bank_interval_join_same_trace);
    BOOST_CHECK(!binary.under_column_cap);
    BOOST_CHECK(!binary.parent_proof_emitted);
    BOOST_CHECK_EQUAL(binary.violations, 0U);
    BOOST_CHECK_EQUAL(binary.parent_output_words[0], 0U);
    BOOST_CHECK_EQUAL(binary.parent_output_words[1], 8U);
    BOOST_CHECK_EQUAL(
        binary.parent_cs.n_columns,
        binary.parent_output_column_base + 18);
    BOOST_CHECK_GT(
        binary.parent_cs.n_columns,
        rc::kRCFri3AlgBatchMaxColumns);
    BOOST_TEST_MESSAGE(
        "bank full binary mirror rows="
        << binary.parent_cs.n_rows
        << " cols=" << binary.parent_cs.n_columns
        << " constraints="
        << binary.parent_cs.constraints.size()
        << " violations=" << binary.violations
        << " cap_excess="
        << binary.parent_cs.n_columns -
               rc::kRCFri3AlgBatchMaxColumns);

    auto changed_columns = binary.parent_columns;
    changed_columns[
        binary.parent_output_column_base + 1][0] =
        gf::Add(
            changed_columns[
                binary.parent_output_column_base + 1][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(
            binary.parent_cs, changed_columns),
        0U);

    const auto reused_seed =
        rc::BuildRCStage3CoupledBankFullBinaryMirrorWitness(
            child_css, proofs,
            {seeds[0], seeds[0]}, {58, 58});
    BOOST_CHECK(!reused_seed.valid);

    const auto audit =
        rc::CurrentRCStage3CoupledBankStreamAudit();
    BOOST_CHECK(
        !audit.normalized_full_binary_mirror_executable);
    BOOST_CHECK(audit.normalized_binary_interval_same_trace);
    BOOST_CHECK(
        !audit.normalized_full_binary_parent_proof_executable);
}

BOOST_AUTO_TEST_CASE(
    narrow_vertical_v5_hash_fold_and_terminal_relation_execute)
{
    const auto statement = Statement();
    const auto shape = ToyShape();
    rc::RCStage3CoupledBankStreamManifest manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamManifest(
            statement, shape, H(0x52), manifest, &why),
        why);
    const auto first_children =
        SyntheticFirstParentChildren(manifest);
    rc::RCStage3CoupledBankStreamIntervalReceipt first_parent;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamParentReceipt(
            manifest, first_children, first_parent, &why),
        why);
    const auto second_children =
        SyntheticParentChildren(
            manifest, 4, first_parent.last_h_out);
    rc::RCStage3CoupledBankStreamIntervalReceipt second_parent;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamParentReceipt(
            manifest, second_children, second_parent, &why),
        why);

    std::vector<aq::AirConstraintSystem<gf::Fp3>> child_css(2);
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamIntervalConstraintSystem(
            manifest, first_children, first_parent,
            child_css[0], &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamIntervalConstraintSystem(
            manifest, second_children, second_parent,
            child_css[1], &why),
        why);
    const std::vector<uint256> seeds{H(0xb1), H(0xb2)};
    std::vector<ar::DualAlgAirProof> proofs(2);
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3CoupledBankStreamDualIntervalRelation(
            manifest, first_children, first_parent,
            seeds[0], proofs[0], &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3CoupledBankStreamDualIntervalRelation(
            manifest, second_children, second_parent,
            seeds[1], proofs[1], &why),
        why);

    const auto narrow =
        rc::BuildRCStage3CoupledBankNarrowExecution(
            child_css, proofs, seeds, {58, 58});
    BOOST_TEST_MESSAGE(
        "narrow precheck note=" << narrow.note
        << " lanes=" << narrow.lanes.size()
        << " hash=" << narrow.hash_families_complete
        << " fold=" << narrow.fold_scalar_bus_complete
        << " terminal=" << narrow.terminal_relation_executable
        << " term_v=" << narrow.terminal_violations
        << " scalar_cols=" << narrow.scalar_columns_count
        << " scalar_v=" << narrow.scalar_violations
        << " semantic_cells=" << narrow.v5_semantic_cells
        << " semantic_v=" << narrow.v5_semantic_violations
        << " combined_active=" << narrow.combined_active_rows
        << " combined_trace=" << narrow.combined_trace_rows
        << " physical=" << narrow.physical_column_target
        << " selected=" << narrow.selected_full_parent_width
        << " selected_ok=" << narrow.selected_full_width_under_cap);
    BOOST_REQUIRE_MESSAGE(narrow.valid, narrow.note);
    BOOST_CHECK_EQUAL(narrow.lanes.size(), 4U);
    BOOST_CHECK(narrow.four_ordered_lanes_executed);
    BOOST_CHECK(narrow.exact_dual_transcripts_checked);
    BOOST_CHECK(narrow.hash_families_complete);
    BOOST_CHECK(narrow.fold_scalar_bus_complete);
    BOOST_CHECK(narrow.terminal_relation_executable);
    BOOST_CHECK(narrow.terminal_values_proof_derived);
    BOOST_CHECK(narrow.deep_dual_ood_executable);
    BOOST_CHECK(narrow.per_point_quotient_executable);
    BOOST_CHECK(narrow.scalar_openings_proof_derived);
    BOOST_CHECK(narrow.scalar_terminal_same_trace);
    BOOST_CHECK(narrow.v5_sha_semantic_boundary_executable);
    BOOST_CHECK(narrow.all_v5_consumer_cells_mapped);
    BOOST_CHECK(narrow.vertical_width_under_cap);
    BOOST_CHECK(narrow.selected_full_width_under_cap);
    BOOST_CHECK(narrow.combined_trace_within_selected);
    BOOST_CHECK(!narrow.hash_terminal_single_parent_proof);
    BOOST_CHECK(!narrow.complete_recursive_parent);
    BOOST_CHECK(!narrow.parent_proof_emitted);
    BOOST_CHECK(!narrow.consensus_authority);
    BOOST_CHECK_EQUAL(narrow.reusable_hash_columns, 526U);
    BOOST_CHECK_EQUAL(narrow.reusable_fold_bus_columns, 549U);
    BOOST_CHECK_EQUAL(narrow.terminal_bus_columns, 40U);
    BOOST_CHECK_EQUAL(narrow.scalar_rows, 512U);
    BOOST_CHECK_EQUAL(narrow.scalar_columns_count, 1044U);
    BOOST_CHECK_EQUAL(narrow.scalar_constraints, 467U);
    BOOST_CHECK_EQUAL(narrow.scalar_violations, 0U);
    BOOST_CHECK_EQUAL(narrow.v5_semantic_cells, 1520U);
    BOOST_CHECK_EQUAL(narrow.v5_semantic_rows, 2048U);
    BOOST_CHECK_EQUAL(narrow.v5_semantic_columns_count, 8U);
    BOOST_CHECK_EQUAL(narrow.v5_semantic_violations, 0U);
    BOOST_CHECK(!narrow.v5_sha_boundary_commitment.IsNull());
    BOOST_CHECK_EQUAL(
        narrow.scheduled_hash_active_rows, 68096U);
    BOOST_CHECK_EQUAL(
        narrow.combined_active_rows,
        narrow.scheduled_hash_active_rows +
            narrow.scalar_rows +
            narrow.v5_semantic_cells);
    BOOST_CHECK_EQUAL(narrow.combined_active_rows, 70128U);
    BOOST_CHECK_EQUAL(narrow.combined_trace_rows, 131072U);
    BOOST_CHECK_EQUAL(narrow.physical_column_target, 1044U);
    BOOST_CHECK_EQUAL(narrow.selected_full_parent_width, 2184U);
    BOOST_CHECK_EQUAL(
        narrow.unexecuted_family_column_reservation,
        1140U);
    BOOST_CHECK_EQUAL(narrow.parent_output_words[0], 0U);
    BOOST_CHECK_EQUAL(narrow.parent_output_words[1], 8U);
    BOOST_CHECK_EQUAL(narrow.terminal_violations, 0U);
    BOOST_TEST_MESSAGE(
        "bank narrow four-lane scheduled_rows="
        << narrow.scheduled_hash_rows
        << " physical_cols="
        << narrow.physical_column_target
        << " fixedpoint_target_cols="
        << narrow.selected_full_parent_width
        << " reserved_cols="
        << narrow.unexecuted_family_column_reservation);

    auto changed = narrow.terminal_columns;
    changed[18][0] = gf::Add(changed[18][0], gf::Fp3::One());
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(
            narrow.terminal_cs, changed),
        0U);

    auto changed_scalar = narrow.scalar_columns;
    changed_scalar[0][0] =
        gf::Add(changed_scalar[0][0], gf::Fp3::One());
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(
            narrow.scalar_cs, changed_scalar),
        0U);

    auto changed_terminal_alias = narrow.scalar_columns;
    changed_terminal_alias[
        narrow.scalar_eval_z1_column_base + 58][0] =
        gf::Add(
            changed_terminal_alias[
                narrow.scalar_eval_z1_column_base + 58][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(
            narrow.scalar_cs, changed_terminal_alias),
        0U);

    auto changed_semantic = narrow.v5_semantic_columns;
    changed_semantic[7][0] =
        gf::Add(changed_semantic[7][0], gf::Fp3::One());
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(
            narrow.v5_semantic_cs, changed_semantic),
        0U);

    const auto unified =
        rc::BuildRCStage3CoupledBankUnifiedParent(
            child_css, proofs, seeds, {58, 58});
    BOOST_REQUIRE_MESSAGE(unified.valid, unified.note);
    BOOST_CHECK(unified.one_selector_scheduled_trace);
    BOOST_CHECK(unified.exact_phase_transitions);
    BOOST_CHECK(unified.fixed_columns_publicly_pinned);
    BOOST_CHECK(unified.fs_public_boundary_bound);
    BOOST_CHECK(unified.scalar_terminal_output_carried);
    BOOST_CHECK(unified.all_phase_outputs_same_trace);
    BOOST_CHECK(unified.under_selected_width);
    BOOST_CHECK(!unified.proof_resource_feasible);
    BOOST_CHECK(!unified.parent_proof_emitted);
    BOOST_CHECK(!unified.parent_proof_verified);
    BOOST_CHECK(!unified.consensus_authority);
    BOOST_CHECK_EQUAL(unified.local_phase_columns, 1098U);
    BOOST_CHECK_EQUAL(unified.fixed_columns, 662U);
    BOOST_CHECK_EQUAL(unified.selector_columns, 24U);
    BOOST_CHECK_EQUAL(unified.carry_columns, 18U);
    BOOST_CHECK_EQUAL(unified.parent_columns_count, 1802U);
    BOOST_CHECK_EQUAL(unified.parent_rows, 65536U);
    BOOST_CHECK_EQUAL(unified.parent_constraints, 2624U);
    BOOST_CHECK_EQUAL(unified.parent_max_degree, 3U);
    BOOST_CHECK_EQUAL(unified.quotient_len, 131070U);
    BOOST_CHECK_EQUAL(unified.proof_coefficients, 131072U);
    BOOST_CHECK_EQUAL(unified.proof_lde, 2097152U);
    BOOST_CHECK_EQUAL(
        unified.estimated_lde_cells, 3781165056ULL);
    BOOST_CHECK_EQUAL(unified.violations, 0U);
    BOOST_CHECK_EQUAL(unified.parent_output_words[0], 0U);
    BOOST_CHECK_EQUAL(unified.parent_output_words[1], 8U);
    BOOST_CHECK(
        unified.v5_sha_boundary_commitment ==
        narrow.v5_sha_boundary_commitment);
    BOOST_CHECK(!unified.parent_fs_seed.IsNull());
    const auto streaming =
        rc::PlanRCStage3CoupledBankStreamingLde(
            unified.parent_rows,
            unified.parent_columns_count,
            unified.proof_lde);
    BOOST_REQUIRE_MESSAGE(streaming.valid, streaming.note);
    BOOST_CHECK_EQUAL(streaming.tile_rows, 4096U);
    BOOST_CHECK_EQUAL(streaming.passes, 5U);
    BOOST_CHECK_EQUAL(
        streaming.dense_lde_cells, 3781165056ULL);
    BOOST_CHECK_EQUAL(
        streaming.peak_live_cells, 14786560ULL);
    BOOST_CHECK_EQUAL(
        streaming.external_work_cells, 11343495168ULL);
    BOOST_CHECK(streaming.column_store_required);
    BOOST_CHECK(streaming.two_pass_row_merkle_required);
    BOOST_CHECK(!streaming.quotient_row_tiles_executable);
    BOOST_CHECK(!streaming.fri_fold_tiles_executable);
    BOOST_CHECK(!streaming.transcript_equivalence_proven);
    BOOST_CHECK(streaming.under_dense_cell_screen);
    BOOST_TEST_MESSAGE(
        "bank unified parent rows=" << unified.parent_rows
        << " cols=" << unified.parent_columns_count
        << " constraints=" << unified.parent_constraints
        << " degree=" << unified.parent_max_degree
        << " quotient=" << unified.quotient_len
        << " coeffs=" << unified.proof_coefficients
        << " lde=" << unified.proof_lde
        << " lde_cells=" << unified.estimated_lde_cells
        << " violations=" << unified.violations
        << " proof_feasible="
        << unified.proof_resource_feasible);
}

BOOST_AUTO_TEST_CASE(live_first_pass_leaf_proof_roundtrip)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_COUPLED_BANK_STREAM_PROVE") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_COUPLED_BANK_STREAM_PROVE=1 "
            "to execute the SHA provenance proof");
        return;
    }

    const auto statement = Statement();
    const auto shape = ToyShape();
    const uint64_t bank_bytes =
        uint64_t{shape.bank_pages} * shape.lobe_width *
        shape.lobe_width;
    std::vector<uint8_t> pages(bank_bytes);
    for (uint64_t i = 0; i < bank_bytes; ++i) {
        pages[i] = static_cast<uint8_t>(
            (i * UINT64_C(29) + 0xa7) & 0xffU);
    }
    uint256 root;
    rc::RCStage3CoupledBankSourceOpening opening;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankSourceOpeningForTest(
            pages, 0, root, opening, &why),
        why);
    rc::RCStage3CoupledBankStreamManifest manifest;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamManifest(
            statement, shape, root, manifest, &why),
        why);

    rc::RCStage3CoupledBankStreamLeafProof leaf;
    leaf.block_index = 0;
    leaf.h_in = ha::CanonicalSha256InitialState();
    leaf.source_openings = {opening};
    const auto& tags =
        rc::RCCoupDomainTagsForVersion(shape.transcript_version);
    const auto* tag = reinterpret_cast<const uint8_t*>(tags.bank);
    const size_t tag_size = std::strlen(tags.bank);
    BOOST_REQUIRE_LT(tag_size, leaf.padded_block.size());
    std::copy_n(tag, tag_size, leaf.padded_block.begin());
    std::copy_n(
        pages.begin(), leaf.padded_block.size() - tag_size,
        leaf.padded_block.begin() + tag_size);

    const auto program =
        ha::BuildCanonicalProgram(ha::ProgramKind::Sha256Compression);
    ha::FixedProgramBoundaryInstance boundary;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildSha256CompressionBoundaryInstance(
            leaf.padded_block, leaf.h_in, leaf.h_out,
            boundary, &why),
        why);
    ha::ProgramWitness witness;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildProgramWitness(
            program, boundary.external_values, witness, &why),
        why);
    BOOST_REQUIRE_EQUAL(witness.final_words.size(), leaf.h_out.size());
    std::copy(
        witness.final_words.begin(), witness.final_words.end(),
        leaf.h_out.begin());
    BOOST_REQUIRE_MESSAGE(
        ha::BuildSha256CompressionBoundaryInstance(
            leaf.padded_block, leaf.h_in, leaf.h_out,
            boundary, &why),
        why);
    const uint256 seed =
        rc::ComputeRCStage3CoupledBankStreamLeafSeed(
            manifest, leaf.block_index);
    const auto prove_start = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        ha::ProveFixedProgramProvenanceAir(
            program, witness, boundary.external_values,
            boundary.final_words, seed,
            leaf.compression_proof, &why),
        why);
    const auto prove_end = std::chrono::steady_clock::now();
    leaf.leaf_commitment =
        rc::CommitRCStage3CoupledBankStreamLeaf(manifest, leaf);
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3CoupledBankStreamLeaf(
            manifest, leaf, &why),
        why);
    const auto verify_end = std::chrono::steady_clock::now();
    BOOST_TEST_MESSAGE(
        "bank SHA leaf prove_us="
        << std::chrono::duration_cast<std::chrono::microseconds>(
               prove_end - prove_start).count()
        << " verify_us="
        << std::chrono::duration_cast<std::chrono::microseconds>(
               verify_end - prove_end).count());

    rc::RCStage3CoupledBankStreamIntervalReceipt receipt;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamLeafReceipt(
            manifest, leaf, receipt, &why),
        why);
    BOOST_CHECK_EQUAL(receipt.first_block, 0U);
    BOOST_CHECK_EQUAL(receipt.block_count, 1U);
    BOOST_CHECK(receipt.first_h_in == leaf.h_in);
    BOOST_CHECK(receipt.last_h_out == leaf.h_out);

    rc::RCStage3CoupledBankStreamRecursiveProof recursive_leaf;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankStreamRecursiveLeafProof(
            manifest, leaf, recursive_leaf, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3CoupledBankStreamRecursiveProof(
            manifest, recursive_leaf, &why),
        why);
    auto changed_recursive = recursive_leaf;
    changed_recursive.recursive_commitment.begin()[0] ^= 1U;
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledBankStreamRecursiveProof(
            manifest, changed_recursive, &why));

    auto changed_state = leaf;
    changed_state.h_out[0] ^= 1U;
    changed_state.leaf_commitment =
        rc::CommitRCStage3CoupledBankStreamLeaf(
            manifest, changed_state);
    BOOST_CHECK(!rc::VerifyRCStage3CoupledBankStreamLeaf(
        manifest, changed_state, &why));

    auto changed_source = leaf;
    changed_source.source_openings[0].bytes[0] ^= 1U;
    changed_source.leaf_commitment =
        rc::CommitRCStage3CoupledBankStreamLeaf(
            manifest, changed_source);
    BOOST_CHECK(!rc::VerifyRCStage3CoupledBankStreamLeaf(
        manifest, changed_source, &why));
}

BOOST_AUTO_TEST_SUITE_END()
