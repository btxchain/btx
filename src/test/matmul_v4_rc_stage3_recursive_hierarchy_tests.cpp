// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_recursive_hierarchy.h>

#include <algorithm>

namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
namespace rh =
    matmul::v4::rc::recursive_hierarchy;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_recursive_hierarchy_tests)

namespace {

uint256 Seed(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

aq::AirConstraintSystem<gf::Fp3> BooleanCs()
{
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 2;
    cs.n_columns = 1;
    aq::AirConstraint<gf::Fp3> boolean;
    boolean.name =
        "stage3.hierarchy.test.boolean";
    boolean.kind = aq::AirKind::kEverywhere;
    boolean.alg_degree = 2;
    boolean.eval =
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>&) {
            return gf::Mul(
                cur[0],
                gf::Sub(
                    cur[0], gf::Fp3::One()));
        };
    cs.constraints.push_back(std::move(boolean));
    return cs;
}

rh::ShardOrdinalManifestV1 Manifest()
{
    return rh::BuildShardOrdinalManifestV1(
        10,
        {{0, 0, 2, Seed(0x10)},
         {1, 2, 3, Seed(0x11)},
         {2, 5, 1, Seed(0x12)},
         {3, 6, 4, Seed(0x13)}});
}

} // namespace

BOOST_AUTO_TEST_CASE(
    manifest_and_level_coverage_are_exact_and_ordered)
{
    const auto manifest = Manifest();
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rh::ValidateShardOrdinalManifestV1(
            manifest, &why),
        why);

    const auto left =
        rh::BuildShardOrdinalCoverageV1(
            manifest, 0, 2);
    const auto middle =
        rh::BuildShardOrdinalCoverageV1(
            manifest, 2, 1);
    const auto right =
        rh::BuildShardOrdinalCoverageV1(
            manifest, 3, 1);
    BOOST_CHECK_MESSAGE(
        rh::ValidateExactHierarchyLevelCoverageV1(
            manifest,
            {left, middle, right},
            &why),
        why);

    // Omission cannot be hidden by changing a claimed total.
    BOOST_CHECK(
        !rh::ValidateExactHierarchyLevelCoverageV1(
            manifest, {left, middle}, nullptr));

    // Duplicate and reorder are rejected without sorting.
    BOOST_CHECK(
        !rh::ValidateExactHierarchyLevelCoverageV1(
            manifest,
            {left, middle, middle, right},
            nullptr));
    BOOST_CHECK(
        !rh::ValidateExactHierarchyLevelCoverageV1(
            manifest,
            {middle, left, right},
            nullptr));

    // A recomputed but overlapping interval is not a manifest-derived
    // coverage object and cannot pass as the next node.
    auto overlap =
        rh::BuildShardOrdinalCoverageV1(
            manifest, 1, 2);
    BOOST_REQUIRE(
        rh::ValidateShardOrdinalCoverageV1(
            manifest, overlap));
    BOOST_CHECK(
        !rh::ValidateExactHierarchyLevelCoverageV1(
            manifest,
            {left, overlap, right},
            nullptr));

    // A wrong statement root invalidates the committed manifest.
    auto wrong_root = manifest;
    wrong_root.entries[1].statement_root =
        Seed(0x99);
    BOOST_CHECK(
        !rh::ValidateShardOrdinalManifestV1(
            wrong_root, nullptr));
}

BOOST_AUTO_TEST_CASE(
    exact_set_manifest_covers_noncontiguous_ffd_shards)
{
    const auto manifest =
        rh::BuildShardOrdinalManifestV2(
            8,
            {{0, {0, 3, 6}, Seed(0x20)},
             {1, {1, 4, 7}, Seed(0x21)},
             {2, {2, 5}, Seed(0x22)}});
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rh::ValidateShardOrdinalManifestV2(
            manifest, &why),
        why);
    BOOST_CHECK_EQUAL(manifest.version, 2U);
    BOOST_CHECK_EQUAL(manifest.total_ordinals, 8U);
    BOOST_CHECK_EQUAL(manifest.entries.size(), 3U);
    BOOST_CHECK(!manifest.commitment.IsNull());

    // Same supplied count, but ordinal 7 is omitted while ordinal 6 is owned
    // by two shards. Recomputing the commitment cannot hide the bad union.
    auto same_count_omit_and_overlap = manifest;
    same_count_omit_and_overlap.entries[1].program_ordinals =
        {1, 4, 6};
    same_count_omit_and_overlap.commitment =
        rh::CommitShardOrdinalManifestV2(
            same_count_omit_and_overlap);
    BOOST_CHECK(
        !rh::ValidateShardOrdinalManifestV2(
            same_count_omit_and_overlap, nullptr));

    // Duplication inside one shard is rejected before set-union validation.
    auto duplicate = manifest;
    duplicate.entries[0].program_ordinals = {0, 3, 3};
    duplicate.commitment =
        rh::CommitShardOrdinalManifestV2(duplicate);
    BOOST_CHECK(
        !rh::ValidateShardOrdinalManifestV2(
            duplicate, nullptr));

    // A pure omission cannot be hidden behind a stale total.
    auto omission = manifest;
    omission.entries[2].program_ordinals.pop_back();
    omission.commitment =
        rh::CommitShardOrdinalManifestV2(omission);
    BOOST_CHECK(
        !rh::ValidateShardOrdinalManifestV2(
            omission, nullptr));

    // Canonical within-shard order is part of the statement.
    auto ordinal_reorder = manifest;
    std::swap(
        ordinal_reorder.entries[0].program_ordinals[0],
        ordinal_reorder.entries[0].program_ordinals[1]);
    ordinal_reorder.commitment =
        rh::CommitShardOrdinalManifestV2(
            ordinal_reorder);
    BOOST_CHECK(
        !rh::ValidateShardOrdinalManifestV2(
            ordinal_reorder, nullptr));

    // Shards are never sorted by the validator.
    auto shard_reorder = manifest;
    std::swap(
        shard_reorder.entries[0],
        shard_reorder.entries[1]);
    shard_reorder.commitment =
        rh::CommitShardOrdinalManifestV2(
            shard_reorder);
    BOOST_CHECK(
        !rh::ValidateShardOrdinalManifestV2(
            shard_reorder, nullptr));

    // The domain-separated public commitment detects statement-root
    // substitution without changing the manifest's public identity.
    auto root_substitution = manifest;
    root_substitution.entries[1].statement_root =
        Seed(0x99);
    BOOST_CHECK(
        !rh::ValidateShardOrdinalManifestV2(
            root_substitution, nullptr));
    root_substitution.commitment =
        rh::CommitShardOrdinalManifestV2(
            root_substitution);
    BOOST_REQUIRE(
        rh::ValidateShardOrdinalManifestV2(
            root_substitution));
    BOOST_CHECK(
        root_substitution.commitment !=
        manifest.commitment);

    // A verifier can rebuild the canonical statement and compare its exact
    // commitment; V1 and V2 domains cannot collide by construction.
    BOOST_CHECK(
        manifest.commitment != Manifest().commitment);
}

BOOST_AUTO_TEST_CASE(
    retained_node_owns_real_proof_and_rejects_label_only_artifacts)
{
    const auto manifest = Manifest();
    const auto coverage =
        rh::BuildShardOrdinalCoverageV1(
            manifest, 0, 4);
    const auto cs = BooleanCs();
    const uint256 fs_seed = Seed(0x51);
    const std::vector<std::vector<gf::Fp3>>
        columns{{gf::Fp3::Zero(),
                 gf::Fp3::One()}};
    const auto proved =
        aq::AirQuotientProve<
            gf::Fp3,
            aq::AirFriBackendAlg<gf::Fp3>>(
            cs, columns, fs_seed, {});
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact,
        proved.note);
    std::vector<gf::Fp3> proof_q;
    std::string q_why;
    BOOST_REQUIRE_MESSAGE(
        rh::ExtractProofQuotientTerminalsV1(
            cs, proved.proof, proof_q, &q_why),
        q_why);

    const auto retained =
        rh::RetainVerifiedHierarchyNodeV1(
            manifest,
            coverage,
            /*level=*/1,
            /*node_ordinal=*/0,
            cs,
            proved.proof,
            fs_seed,
            proof_q);
    BOOST_REQUIRE_MESSAGE(
        retained.valid, retained.note);
    BOOST_CHECK(retained.proof_retained);
    BOOST_CHECK(retained.native_proof_verified);
    BOOST_CHECK(retained.cryptographic_child);
    BOOST_CHECK(!retained.proof_bytes.empty());
    BOOST_CHECK_GT(retained.full_byte_count,
                   retained.proof_bytes.size());
    std::string why;
    std::vector<unsigned char> envelope;
    BOOST_REQUIRE_MESSAGE(
        rh::SerializeRetainedHierarchyNodeEnvelopeV1(
            retained, envelope, &why),
        why);
    BOOST_CHECK_EQUAL(
        envelope.size(), retained.full_byte_count);

    BOOST_CHECK_MESSAGE(
        rh::ValidateRetainedHierarchyNodeV1(
            manifest, cs, retained, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rh::ValidateRetainedHierarchyLevelV1(
            manifest, {cs}, {retained}, &why),
        why);

    auto wrong_node_order = retained;
    wrong_node_order.node_ordinal = 1;
    wrong_node_order.node_root =
        rh::ComputeRetainedHierarchyNodeRootV1(
            wrong_node_order);
    BOOST_CHECK(
        !rh::ValidateRetainedHierarchyLevelV1(
            manifest,
            {cs},
            {wrong_node_order},
            nullptr));

    // A prove=false/shape-only object cannot become cryptographic merely by
    // setting every outward-facing evidence label.
    auto labels_only = retained;
    labels_only.proof = {};
    labels_only.proof_bytes.clear();
    labels_only.proof_commitment = {};
    labels_only.node_root = {};
    labels_only.full_byte_count = 0;
    labels_only.valid = true;
    labels_only.proof_retained = true;
    labels_only.native_proof_verified = true;
    labels_only.cryptographic_child = true;
    BOOST_CHECK(
        !rh::ValidateRetainedHierarchyNodeV1(
            manifest, cs, labels_only, nullptr));

    auto wrong_root = retained;
    wrong_root.node_root.data()[0] ^= 1;
    BOOST_CHECK(
        !rh::ValidateRetainedHierarchyNodeV1(
            manifest, cs, wrong_root, nullptr));

    auto wrong_q = retained;
    wrong_q.quotient_terminals[0] =
        gf::Add(
            wrong_q.quotient_terminals[0],
            gf::Fp3::One());
    wrong_q.node_root =
        rh::ComputeRetainedHierarchyNodeRootV1(
            wrong_q);
    BOOST_REQUIRE(!wrong_q.node_root.IsNull());
    BOOST_CHECK(
        !rh::ValidateRetainedHierarchyNodeV1(
            manifest, cs, wrong_q, nullptr));

    // Goldilocks x and x+p aliases are forbidden at the receipt boundary.
    auto noncanonical_q = retained;
    noncanonical_q.quotient_terminals[0].c0 =
        gf::kP;
    noncanonical_q.node_root =
        rh::ComputeRetainedHierarchyNodeRootV1(
            noncanonical_q);
    BOOST_CHECK(noncanonical_q.node_root.IsNull());
    BOOST_CHECK(
        !rh::ValidateRetainedHierarchyNodeV1(
            manifest, cs, noncanonical_q, nullptr));

    auto wrong_bytes = retained;
    ++wrong_bytes.full_byte_count;
    BOOST_CHECK(
        !rh::ValidateRetainedHierarchyNodeV1(
            manifest, cs, wrong_bytes, nullptr));

    auto wrong_manifest = manifest;
    wrong_manifest.entries[0].statement_root =
        Seed(0xa1);
    wrong_manifest.commitment =
        rh::CommitShardOrdinalManifestV1(
            wrong_manifest);
    BOOST_REQUIRE(
        rh::ValidateShardOrdinalManifestV1(
            wrong_manifest));
    BOOST_CHECK(
        !rh::ValidateRetainedHierarchyNodeV1(
            wrong_manifest,
            cs,
            retained,
            nullptr));
}

BOOST_AUTO_TEST_CASE(
    verifier_reconstructed_constraint_system_is_authoritative)
{
    const auto manifest = Manifest();
    const auto coverage =
        rh::BuildShardOrdinalCoverageV1(
            manifest, 0, 4);
    const auto cs = BooleanCs();
    const uint256 fs_seed = Seed(0x61);
    const std::vector<std::vector<gf::Fp3>>
        columns{{gf::Fp3::Zero(),
                 gf::Fp3::One()}};
    const auto proved =
        aq::AirQuotientProve<
            gf::Fp3,
            aq::AirFriBackendAlg<gf::Fp3>>(
            cs, columns, fs_seed, {});
    BOOST_REQUIRE(proved.ok);
    std::vector<gf::Fp3> proof_q;
    std::string q_why;
    BOOST_REQUIRE_MESSAGE(
        rh::ExtractProofQuotientTerminalsV1(
            cs, proved.proof, proof_q, &q_why),
        q_why);
    const auto retained =
        rh::RetainVerifiedHierarchyNodeV1(
            manifest,
            coverage,
            2,
            0,
            cs,
            proved.proof,
            fs_seed,
            proof_q);
    BOOST_REQUIRE(retained.valid);

    auto different_cs = cs;
    different_cs.constraints[0].name =
        "stage3.hierarchy.test.different";
    BOOST_CHECK(
        !rh::ValidateRetainedHierarchyNodeV1(
            manifest,
            different_cs,
            retained,
            nullptr));

    auto forged_proof = retained;
    forged_proof.proof_bytes[
        forged_proof.proof_bytes.size() / 2] ^= 1;
    forged_proof.full_byte_count =
        rh::ComputeRetainedHierarchyNodeFullBytesV1(
            forged_proof);
    forged_proof.node_root =
        rh::ComputeRetainedHierarchyNodeRootV1(
            forged_proof);
    BOOST_CHECK(
        !rh::ValidateRetainedHierarchyNodeV1(
            manifest, cs, forged_proof, nullptr));
}

BOOST_AUTO_TEST_SUITE_END()
