// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_semantic_endpoint_receipt_intake.h>

#include <cstdlib>

namespace matmul::v4::rc {
namespace {

namespace intake =
    stage3_semantic_endpoint_receipt_intake;
namespace gf = gkr_field;

const RCStage3RoleAirProduct& WiringRole()
{
    static const RCStage3RoleAirProduct role = [] {
        std::string why;
        const gf::Fp3 copy =
            gf::Fp3::FromFp(gf::FromU64(0x9a21bc34U));
        auto out =
            BuildRCStage3EpisodeWiringRoleAir(
                &why, &copy);
        BOOST_REQUIRE_MESSAGE(out.ok, why);
        return out;
    }();
    return role;
}

const intake::ProofV1& SharedIntake()
{
    static const intake::ProofV1 proof =
        intake::ProveV1({WiringRole()}, {}, false);
    return proof;
}

struct RecursiveEvidenceReset {
    ~RecursiveEvidenceReset()
    {
        ClearRCStage3ParentVerifiedRecursiveChildEvidenceV1();
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_semantic_endpoint_receipt_intake_tests)

BOOST_AUTO_TEST_CASE(
    static_direct_aliases_never_count_without_concrete_receipts)
{
    intake::ManifestV1 manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        intake::BuildManifestV1(
            {}, {}, manifest, &why),
        why);
    BOOST_CHECK(manifest.valid);
    BOOST_CHECK_EQUAL(manifest.active_endpoints, 0U);
    BOOST_CHECK_EQUAL(
        manifest.residual_endpoints,
        intake::kEndpointCountV1);
    BOOST_CHECK_EQUAL(manifest.active_bitmap, 0U);
    BOOST_CHECK_EQUAL(
        manifest.residual_bitmap,
        intake::kEndpointMaskV1);
    BOOST_CHECK_EQUAL(manifest.active_roles, 0U);
    BOOST_CHECK(!manifest.complete_52);
    for (const auto& endpoint : manifest.endpoints) {
        BOOST_CHECK(!endpoint.present);
        BOOST_CHECK_EQUAL(
            endpoint.receipt_slot,
            intake::kNoReceiptSlotV1);
        BOOST_CHECK(!endpoint.residual.empty());
    }

    // Regardless of any local route-table/direct-alias accounting, none is
    // recursively admissible without a concrete role receipt.
    BOOST_CHECK_EQUAL(manifest.active_endpoints, 0U);
}

BOOST_AUTO_TEST_CASE(
    host_valid_stream_child_without_recursive_receipt_earns_zero)
{
    using Endpoint = RCStage3RelationEndpoint;
    const Endpoint endpoint =
        Endpoint::EpisodeTileTreeStream;
    const RCStage3StreamFamily family =
        RCStage3StreamFamilyForEndpoint(endpoint);
    std::array<uint32_t, 8> stream_value{};
    for (uint32_t word = 0;
         word < stream_value.size(); ++word) {
        stream_value[word] =
            0x760000U + 13U * word;
    }
    const auto stream_manifest =
        BuildRCStage3StreamEndpointCanonicalManifest(
            family, stream_value, 0, 1);
    uint256 seed;
    for (uint32_t byte = 0;
         byte < seed.size(); ++byte) {
        seed.begin()[byte] =
            static_cast<unsigned char>(
                9U * byte + 1U);
    }
    std::string why;
    const auto closure =
        RCStage3StreamEndpointClose(
            family, stream_manifest,
            seed, &why, true);
    BOOST_REQUIRE_MESSAGE(closure.ok, why);

    std::vector<std::array<uint32_t, 8>> roots(4);
    roots[0] = closure.committed_root;
    for (uint32_t index = 1;
         index < roots.size(); ++index) {
        for (uint32_t word = 0;
             word < roots[index].size(); ++word) {
            roots[index][word] =
                0x880000U +
                index * 0x1000U + word;
        }
    }
    const auto role =
        BuildRCStage3PureStreamRoleAirFromRoots(
            RCStage3RelationRole::EpisodeTileTree,
            roots, &why);
    BOOST_REQUIRE_MESSAGE(role.ok, why);
    intake::exports::StreamChildArtifactV1 child;
    child.endpoint = endpoint;
    child.closure = closure;

    intake::ManifestV1 manifest;
    BOOST_REQUIRE_MESSAGE(
        intake::BuildManifestV1(
            {role}, {child}, manifest, &why),
        why);
    const uint32_t ordinal =
        static_cast<uint32_t>(endpoint) - 1U;
    BOOST_REQUIRE(ordinal < manifest.endpoints.size());
    const auto& row = manifest.endpoints[ordinal];
    BOOST_CHECK(row.route.requires_stream_child);
    BOOST_CHECK(!row.present);
    BOOST_CHECK_EQUAL(
        row.receipt_slot,
        intake::kNoReceiptSlotV1);
    BOOST_CHECK(
        row.residual.find(
            "no verified recursive receipt") !=
        std::string::npos);
    BOOST_CHECK_EQUAL(
        manifest.active_bitmap &
            (uint64_t{1} << ordinal),
        0U);
    BOOST_CHECK(!manifest.complete_52);
}

BOOST_AUTO_TEST_CASE(
    episode_wiring_earns_exactly_four_of_fifty_two)
{
    intake::ManifestV1 manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        intake::BuildManifestV1(
            {WiringRole()}, {}, manifest, &why),
        why);
    BOOST_CHECK(manifest.valid);
    BOOST_CHECK_EQUAL(manifest.active_endpoints, 4U);
    BOOST_CHECK_EQUAL(manifest.residual_endpoints, 48U);
    BOOST_CHECK_EQUAL(manifest.active_roles, 1U);
    BOOST_CHECK(!manifest.complete_52);
    uint32_t present = 0;
    for (uint32_t ordinal = 0;
         ordinal < manifest.endpoints.size(); ++ordinal) {
        const auto& endpoint =
            manifest.endpoints[ordinal];
        BOOST_CHECK_EQUAL(
            endpoint.route.ordinal, ordinal);
        BOOST_CHECK_EQUAL(
            static_cast<uint32_t>(
                endpoint.route.endpoint),
            ordinal + 1U);
        if (endpoint.present) {
            ++present;
            BOOST_CHECK_EQUAL(endpoint.receipt_slot, 0U);
            BOOST_CHECK(endpoint.residual.empty());
        } else {
            BOOST_CHECK_EQUAL(
                endpoint.receipt_slot,
                intake::kNoReceiptSlotV1);
            BOOST_CHECK(!endpoint.residual.empty());
        }
    }
    BOOST_CHECK_EQUAL(present, 4U);
}

BOOST_AUTO_TEST_CASE(
    ordinary_receipt_intake_and_dual_fp3_link_verify)
{
    const auto& proof = SharedIntake();
    BOOST_REQUIRE_MESSAGE(
        proof.construction_valid, proof.note);
    BOOST_CHECK(
        proof.exact_no_omission_no_duplicate_intake);
    BOOST_CHECK(proof.all_ordinary_receipts_verified);
    BOOST_REQUIRE_EQUAL(proof.role_receipts.size(), 1U);
    BOOST_CHECK_EQUAL(
        proof.role_receipts.front()
            .endpoint_ordinals.size(),
        4U);
    BOOST_CHECK(
        proof.role_receipts.front()
            .proof_owned_terminal);
    BOOST_CHECK(
        !proof.role_receipts.front()
             .canonical_terminal_constraint_bytecode);
    BOOST_CHECK_NE(
        proof.role_receipts.front().terminal_columns[0],
        proof.role_receipts.front().terminal_columns[1]);
    BOOST_CHECK_EQUAL(
        proof.ordered_child_receipt_commitments.size(),
        2U);
    BOOST_CHECK(
        proof.ordered_child_receipt_commitments.front() ==
        proof.role_receipts.front().ordinary_proof
            .receipt.receipt_commitment);
    BOOST_CHECK(
        proof.ordered_child_receipt_commitments.back() ==
        proof.equality_link.ordinary_proof
            .receipt.receipt_commitment);
    const auto degree_two_shape =
        narrow_recurse::AssessNarrowNodeFriShape(
            proof.role_receipts.front()
                .ordinary_proof.receipt.active_rows);
    BOOST_CHECK_GT(
        proof.role_receipts.front()
            .ordinary_proof.receipt.n_lde,
        degree_two_shape.n_lde);
    BOOST_CHECK(
        proof.equality_link
            .dual_fp3_terminal_cancellation);
    BOOST_CHECK(
        proof.equality_link
            .ordered_receipts_bound);
    BOOST_CHECK(
        !proof.normalized_parent_proof_verified);
    BOOST_CHECK(
        !proof.canonical_terminal_constraint_bytecode_complete);
    BOOST_CHECK(
        !proof.recursive_child_verifier_constraints_complete);
    BOOST_CHECK(!proof.semantic_sites_credited);
    BOOST_CHECK(!proof.complete_fixed_point);
    BOOST_CHECK(!proof.authority_ready);
    std::string why;
    BOOST_CHECK_MESSAGE(
        intake::VerifyIntakeV1(
            {WiringRole()}, {}, proof, &why),
        why);
    BOOST_CHECK(
        !intake::VerifyV1(
            {WiringRole()}, {}, proof, &why));
    intake::VerifiedRecursiveReceiptEvidenceV1
        unverified_parent;
    BOOST_CHECK(
        !intake::BuildVerifiedRecursiveReceiptEvidenceV1(
            {WiringRole()}, {}, proof,
            unverified_parent, &why));
    BOOST_CHECK(!unverified_parent.valid);
}

BOOST_AUTO_TEST_CASE(
    omission_duplicate_reorder_root_and_x_plus_p_reject)
{
    std::string why;
    const auto& honest = SharedIntake();

    BOOST_CHECK(
        !intake::VerifyIntakeV1(
            {}, {}, honest, &why));
    intake::ManifestV1 manifest;
    BOOST_CHECK(
        !intake::BuildManifestV1(
            {WiringRole(), WiringRole()},
            {}, manifest, &why));

    auto reordered = WiringRole();
    std::swap(
        reordered.endpoints[0],
        reordered.endpoints[1]);
    std::swap(
        reordered.endpoint_committed_roots[0],
        reordered.endpoint_committed_roots[1]);
    BOOST_CHECK(
        !intake::BuildManifestV1(
            {reordered}, {}, manifest, &why));

    auto root = WiringRole();
    root.endpoint_committed_roots[0][0] =
        gf::Add(
            root.endpoint_committed_roots[0][0],
            gf::FromU64(1));
    BOOST_CHECK(
        !intake::BuildManifestV1(
            {root}, {}, manifest, &why));

    auto alias = WiringRole();
    BOOST_REQUIRE(!alias.witness.empty());
    BOOST_REQUIRE(!alias.witness.front().empty());
    alias.witness.front().front().c0 += gf::kP;
    BOOST_CHECK(
        !intake::BuildManifestV1(
            {alias}, {}, manifest, &why));
}

BOOST_AUTO_TEST_CASE(
    endpoint_receipt_terminal_link_and_transplant_attacks_reject)
{
    std::string why;
    const auto& honest = SharedIntake();

    {
        auto attacked = honest;
        attacked.manifest.endpoints[0].present =
            !attacked.manifest.endpoints[0].present;
        BOOST_CHECK(
            !intake::VerifyIntakeV1(
                {WiringRole()}, {}, attacked, &why));
    }
    {
        auto attacked = honest;
        attacked.role_receipts.clear();
        BOOST_CHECK(
            !intake::VerifyIntakeV1(
                {WiringRole()}, {}, attacked, &why));
    }
    {
        auto attacked = honest;
        attacked.role_receipts.push_back(
            attacked.role_receipts.front());
        BOOST_CHECK(
            !intake::VerifyIntakeV1(
                {WiringRole()}, {}, attacked, &why));
    }
    {
        auto attacked = honest;
        attacked.role_receipts.front()
            .terminal[0] =
            gf::Add(
                attacked.role_receipts.front()
                    .terminal[0],
                gf::Fp3::One());
        BOOST_CHECK(
            !intake::VerifyIntakeV1(
                {WiringRole()}, {}, attacked, &why));
    }
    {
        auto attacked = honest;
        attacked.role_receipts.front()
            .ordinary_proof.receipt
            .receipt_commitment.SetNull();
        BOOST_CHECK(
            !intake::VerifyIntakeV1(
                {WiringRole()}, {}, attacked, &why));
    }
    {
        auto attacked = honest;
        attacked.equality_link.ordinary_proof =
            attacked.role_receipts.front()
                .ordinary_proof;
        BOOST_CHECK(
            !intake::VerifyIntakeV1(
                {WiringRole()}, {}, attacked, &why));
    }
    {
        auto attacked = honest;
        attacked.equality_link.source_terminal[1] =
            gf::Add(
                attacked.equality_link
                    .source_terminal[1],
                gf::Fp3::One());
        BOOST_CHECK(
            !intake::VerifyIntakeV1(
                {WiringRole()}, {}, attacked, &why));
    }
}

BOOST_AUTO_TEST_CASE(
    retained_same_parent_proof_level_canary)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_SEMANTIC_INTAKE_PARENT") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_SEMANTIC_INTAKE_PARENT=1 "
            "for retained-parent proof canary");
        return;
    }
    static const intake::ProofV1 proof =
        intake::ProveV1({WiringRole()}, {}, true);
    BOOST_REQUIRE_MESSAGE(
        proof.construction_valid, proof.note);
    BOOST_REQUIRE(
        proof.normalized_parent_proof_verified);
    std::string why;
    BOOST_CHECK_MESSAGE(
        intake::VerifyV1(
            {WiringRole()}, {}, proof, &why),
        why);

    intake::VerifiedRecursiveReceiptEvidenceV1
        evidence;
    BOOST_REQUIRE_MESSAGE(
        intake::BuildVerifiedRecursiveReceiptEvidenceV1(
            {WiringRole()}, {}, proof,
            evidence, &why),
        why);
    BOOST_CHECK(evidence.valid);
    BOOST_CHECK_EQUAL(evidence.active_endpoints, 4U);
    BOOST_CHECK_EQUAL(evidence.residual_endpoints, 48U);
    BOOST_CHECK_EQUAL(evidence.active_roles, 1U);
    BOOST_CHECK(!evidence.complete_52_and_14);
    BOOST_CHECK(
        !evidence
             .recursive_child_acceptance_constraints_complete);
    BOOST_CHECK(!evidence.recursive_credit_eligible);
    BOOST_CHECK(
        !evidence.evidence_commitment.IsNull());
    BOOST_CHECK_MESSAGE(
        intake::VerifyRecursiveReceiptEvidenceV1(
            {WiringRole()}, {}, proof,
            evidence, &why),
        why);

    {
        auto omitted = proof;
        omitted.role_receipts.clear();
        intake::VerifiedRecursiveReceiptEvidenceV1
            rejected;
        BOOST_CHECK(
            !intake::
                BuildVerifiedRecursiveReceiptEvidenceV1(
                    {WiringRole()}, {}, omitted,
                    rejected, &why));
    }
    {
        // The 52-entry inventory is positional and canonical.  Reordering
        // entries must not be repairable by retaining the old commitment.
        auto permuted = proof;
        std::swap(
            permuted.manifest.endpoints[14],
            permuted.manifest.endpoints[15]);
        intake::VerifiedRecursiveReceiptEvidenceV1
            rejected;
        BOOST_CHECK(
            !intake::
                BuildVerifiedRecursiveReceiptEvidenceV1(
                    {WiringRole()}, {}, permuted,
                    rejected, &why));
    }
    {
        auto reordered = proof;
        BOOST_REQUIRE_EQUAL(
            reordered
                .ordered_child_receipt_commitments
                .size(),
            2U);
        std::swap(
            reordered
                .ordered_child_receipt_commitments[0],
            reordered
                .ordered_child_receipt_commitments[1]);
        intake::VerifiedRecursiveReceiptEvidenceV1
            rejected;
        BOOST_CHECK(
            !intake::
                BuildVerifiedRecursiveReceiptEvidenceV1(
                    {WiringRole()}, {}, reordered,
                    rejected, &why));
    }
    {
        auto forged = proof;
        forged.parent.receipt
            .proof_commitment.SetNull();
        intake::VerifiedRecursiveReceiptEvidenceV1
            rejected;
        BOOST_CHECK(
            !intake::
                BuildVerifiedRecursiveReceiptEvidenceV1(
                    {WiringRole()}, {}, forged,
                    rejected, &why));
    }
    {
        auto forged = evidence;
        forged
            .endpoint_receipt_commitments[14]
            .begin()[0] ^= 1U;
        forged.evidence_commitment =
            intake::
                ComputeVerifiedRecursiveReceiptEvidenceCommitmentV1(
                    forged);
        BOOST_CHECK(
            !intake::VerifyRecursiveReceiptEvidenceV1(
                {WiringRole()}, {}, proof,
                forged, &why));
    }
    {
        // A mutation of the evidence root itself is rejected even when every
        // retained receipt and manifest byte is unchanged.
        auto forged = evidence;
        forged.evidence_commitment.begin()[0] ^= 1U;
        BOOST_CHECK(
            !intake::VerifyRecursiveReceiptEvidenceV1(
                {WiringRole()}, {}, proof,
                forged, &why));
    }
    {
        // Recursive acceptance is not a claim bit.  It can become true only
        // when the independently rebuilt child-verifier constraints say so.
        auto forged = evidence;
        forged
            .recursive_child_acceptance_constraints_complete =
            true;
        forged.evidence_commitment =
            intake::
                ComputeVerifiedRecursiveReceiptEvidenceCommitmentV1(
                    forged);
        BOOST_CHECK(
            !intake::VerifyRecursiveReceiptEvidenceV1(
                {WiringRole()}, {}, proof,
                forged, &why));
    }

    // Evidence is a pure function of canonical inputs and proofs. Legacy
    // mutable process-global endpoint registrations cannot alter it.
    RecursiveEvidenceReset reset;
    ClearRCStage3ParentVerifiedRecursiveChildEvidenceV1();
    bool legacy_global_mutated = false;
    for (uint32_t ordinal = 1;
         ordinal <= intake::kEndpointCountV1;
         ++ordinal) {
        legacy_global_mutated |=
            RegisterRCStage3ParentVerifiedRecursiveChildEvidenceV1(
                static_cast<RCStage3RelationEndpoint>(
                    ordinal));
    }
    BOOST_REQUIRE(legacy_global_mutated);
    intake::VerifiedRecursiveReceiptEvidenceV1
        after_global_mutation;
    BOOST_REQUIRE_MESSAGE(
        intake::BuildVerifiedRecursiveReceiptEvidenceV1(
            {WiringRole()}, {}, proof,
            after_global_mutation, &why),
        why);
    BOOST_CHECK(after_global_mutation == evidence);

    auto attacked = proof;
    attacked.parent.receipt
        .proof_commitment.SetNull();
    BOOST_CHECK(
        !intake::VerifyV1(
            {WiringRole()}, {}, attacked, &why));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc
