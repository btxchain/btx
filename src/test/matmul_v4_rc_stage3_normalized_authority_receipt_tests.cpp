// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_normalized_authority_receipt.h>
#include <matmul/matmul_v4_rc_stage3_normalized_authority_composition.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>
#include <hash.h>

#include <array>
#include <utility>
#include <vector>

namespace na =
    matmul::v4::rc::normalized_authority;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_normalized_authority_receipt_tests,
    BasicTestingSetup)

namespace {

uint256 H(uint32_t tag)
{
    HashWriter hash;
    hash << uint64_t{0x3356414e'54534554ULL};
    hash << tag;
    return hash.GetHash();
}

na::RebuiltVerifierInputsV3 RebuiltFrom(
    const na::NormalizedAuthorityReceiptV3& receipt)
{
    na::RebuiltVerifierInputsV3 out;
    out.outer_statement_root = receipt.outer_statement_root;
    out.program_registry_root = receipt.program_registry_root;
    out.topology_manifest_root = receipt.topology_manifest_root;
    out.aggregation_schedule_root =
        receipt.aggregation_schedule_root;
    out.occurrence_manifest_root =
        receipt.occurrence_manifest_root;
    out.verifier_program_root = receipt.verifier_program_root;
    out.abi_plan_root = receipt.abi_plan_root;
    out.selection_plan_root = receipt.selection_plan_root;
    out.derived_hash_plan_root = receipt.derived_hash_plan_root;
    out.fixed_trace_columns = receipt.fixed_trace_columns;
    out.fixed_trace_row_root = receipt.fixed_trace_row_root;
    out.roles = receipt.roles;
    out.parent_shape = receipt.parent_shape;
    out.parent_node_binding = receipt.parent_node_binding;
    out.parent_context_binding = receipt.parent_context_binding;
    out.parent_program_root = receipt.parent_program_root;
    out.parent_cs_commitment = receipt.parent_cs_commitment;
    return out;
}

void FillRoleInventory(
    na::NormalizedAuthorityReceiptV3& receipt)
{
    uint32_t tag = 100;
    for (const rc::RCStage3RelationRole role :
         rc::RCStage3UnifiedRoleOrder()) {
        na::RolePinV3 pin;
        pin.role = role;
        pin.program_root = H(tag++);
        pin.relation_statement_root = H(tag++);
        for (const rc::RCStage3RelationEndpoint endpoint :
             rc::RequiredRCStage3RelationEndpoints(role)) {
            pin.endpoints.push_back({
                .endpoint = endpoint,
                .instance_count =
                    1 + static_cast<uint64_t>(tag),
                .manifest_root = H(tag++),
                .relation_proof_root = H(tag++),
                .semantic_root = H(tag++),
                .ctl_terminal_root = H(tag++),
                .recursive_child_statement_root = H(tag++),
            });
        }
        pin.endpoint_manifest_root =
            na::ComputeRoleEndpointManifestRootV3(pin);
        pin.role_statement_root =
            na::ComputeRoleStatementRootV3(pin);
        receipt.roles.push_back(std::move(pin));
    }
}

struct HonestFixture {
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    na::NormalizedAuthorityReceiptV3 receipt;
    na::RebuiltVerifierInputsV3 rebuilt;
};

HonestFixture BuildHonestFixture()
{
    constexpr uint32_t n = 8;
    HonestFixture out;
    out.columns.assign(
        3, std::vector<gf::Fp3>(
               n, gf::Fp3::Zero()));
    for (uint32_t row = 0; row < n; ++row) {
        out.columns[0][row] =
            gf::Fp3::FromFp(gf::FromU64(11 + row));
        out.columns[1][row] =
            gf::Add(
                out.columns[0][row],
                out.columns[0][row]);
        if (row + 1 < n) {
            out.columns[2][row + 1] =
                gf::Add(
                    out.columns[2][row],
                    out.columns[1][row]);
        }
    }

    out.cs.n_rows = n;
    out.cs.n_columns = 3;
    aq::AirConstraint<gf::Fp3> relation;
    relation.name =
        "test.authority_v3.derived_value";
    relation.kind = aq::AirKind::kEverywhere;
    relation.alg_degree = 1;
    relation.eval =
        [](const std::vector<gf::Fp3>& current,
           const std::vector<gf::Fp3>&) {
            return gf::Sub(
                current[1],
                gf::Add(current[0], current[0]));
        };
    out.cs.constraints.push_back(std::move(relation));

    aq::AirConstraint<gf::Fp3> first;
    first.name =
        "test.authority_v3.accumulator_first";
    first.kind = aq::AirKind::kFirstRow;
    first.alg_degree = 1;
    first.eval =
        [](const std::vector<gf::Fp3>& current,
           const std::vector<gf::Fp3>&) {
            return current[2];
        };
    out.cs.constraints.push_back(std::move(first));

    aq::AirConstraint<gf::Fp3> transition;
    transition.name =
        "test.authority_v3.accumulator_transition";
    transition.kind = aq::AirKind::kTransition;
    transition.alg_degree = 1;
    transition.eval =
        [](const std::vector<gf::Fp3>& current,
           const std::vector<gf::Fp3>& next) {
            return gf::Sub(
                next[2],
                gf::Add(current[2], current[1]));
        };
    out.cs.constraints.push_back(std::move(transition));

    auto& receipt = out.receipt;
    receipt.outer_statement_root = H(1);
    receipt.program_registry_root = H(2);
    receipt.topology_manifest_root = H(3);
    receipt.aggregation_schedule_root = H(4);
    receipt.occurrence_manifest_root = H(5);
    receipt.verifier_program_root = H(6);
    receipt.abi_plan_root = H(7);
    receipt.selection_plan_root = H(8);
    receipt.derived_hash_plan_root = H(9);
    receipt.fixed_trace_columns = {0};
    const auto retained =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns,
            receipt.fixed_trace_columns);
    BOOST_REQUIRE_MESSAGE(
        retained.valid, retained.note);
    receipt.fixed_trace_row_root =
        retained.base_row_commitment;
    FillRoleInventory(receipt);
    receipt.parent_node_binding = H(10);
    receipt.parent_context_binding = H(11);
    receipt.parent_program_root = H(12);
    receipt.parent_cs_commitment = H(13);

    const aq::AirQuotientFixedTracePinV3 fixed{
        .version = 1,
        .ordered_columns =
            receipt.fixed_trace_columns,
        .row_root = receipt.fixed_trace_row_root,
    };
    const auto shape_probe =
        aq::AirQuotientProveRowsSplitRapSafeFixedV3(
            out.cs, out.columns, fixed, H(14), {},
            &retained);
    BOOST_REQUIRE_MESSAGE(
        shape_probe.ok, shape_probe.note);
    receipt.parent_shape = {
        .trace_rows = n,
        .semantic_columns = 3,
        .proof_columns = 3,
        .constraints =
            static_cast<uint32_t>(
                out.cs.constraints.size()),
        .max_constraint_degree = 1,
        .quotient_rows =
            shape_probe.proof.batch.column_len.back(),
        .fri_n_coeffs =
            shape_probe.proof.batch.n_coeffs,
        .lde_rows =
            shape_probe.proof.batch.n_coeffs *
            rc::kRCFriBlowup,
    };
    receipt.fixed_trace_manifest_root =
        na::ComputeFixedTraceManifestRootV3(
            receipt.parent_shape,
            receipt.fixed_trace_columns,
            receipt.fixed_trace_row_root);
    receipt.role_manifest_root =
        na::ComputeRoleManifestRootV3(receipt.roles);
    out.rebuilt = RebuiltFrom(receipt);
    receipt.parent_statement_root =
        na::ComputeParentStatementRootV3(out.rebuilt);
    receipt.parent_fs_seed =
        na::DeriveParentFsSeedV3(
            receipt.parent_statement_root);

    const auto proved =
        aq::AirQuotientProveRowsSplitRapSafeFixedV3(
            out.cs, out.columns, fixed,
            receipt.parent_fs_seed, {},
            &retained);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE_GT(
        aq::SerializeAirQuotientSplitRapRowsProof(
            proved.proof,
            receipt.parent_proof_bytes),
        0U);
    receipt.parent_proof_root =
        na::ComputeParentProofRootV3(
            receipt.parent_proof_bytes);
    receipt.receipt_root =
        na::ComputeReceiptRootV3(receipt);
    out.rebuilt = RebuiltFrom(receipt);
    return out;
}

const HonestFixture& Honest()
{
    static const HonestFixture fixture =
        BuildHonestFixture();
    return fixture;
}

void ResealPublicStatement(
    na::NormalizedAuthorityReceiptV3& receipt)
{
    for (na::RolePinV3& role : receipt.roles) {
        role.endpoint_manifest_root =
            na::ComputeRoleEndpointManifestRootV3(role);
        role.role_statement_root =
            na::ComputeRoleStatementRootV3(role);
    }
    receipt.fixed_trace_manifest_root =
        na::ComputeFixedTraceManifestRootV3(
            receipt.parent_shape,
            receipt.fixed_trace_columns,
            receipt.fixed_trace_row_root);
    receipt.role_manifest_root =
        na::ComputeRoleManifestRootV3(receipt.roles);
    const auto rebuilt = RebuiltFrom(receipt);
    receipt.parent_statement_root =
        na::ComputeParentStatementRootV3(rebuilt);
    receipt.parent_fs_seed =
        na::DeriveParentFsSeedV3(
            receipt.parent_statement_root);
    receipt.parent_proof_root =
        na::ComputeParentProofRootV3(
            receipt.parent_proof_bytes);
    receipt.receipt_root =
        na::ComputeReceiptRootV3(receipt);
}

rc::RCStage3SuccinctProof BuildOuterProof(
    const HonestFixture& honest)
{
    rc::RCStage3SuccinctProof proof;
    auto& public_inputs = proof.public_inputs;
    public_inputs.height = 101;
    public_inputs.n_bits = 0x1f00ffffU;
    public_inputs.episode_profile = 2;
    public_inputs.coupled_profile = 1;
    public_inputs.transcript_version = 13;
    public_inputs.program_consensus_pin
        .recursive_alg_hash_root =
            honest.receipt.program_registry_root;
    public_inputs.program_consensus_pin
        .external_sha256d_audit_root = H(9501);
    public_inputs.program_consensus_pin
        .registry_binding = H(9502);
    public_inputs.header_commitment = H(9503);
    public_inputs.params_commitment = H(9504);
    public_inputs.target = H(9505);
    public_inputs.sigma = H(9506);
    public_inputs.episode_digest = H(9507);
    public_inputs.coupled_digest = H(9508);
    public_inputs.final_digest =
        rc::ComputeRCStage3FinalDigest(proof);
    BOOST_REQUIRE(!public_inputs.final_digest.IsNull());

    proof.commitments.reserve(
        na::kRoleCountV3 + 1);
    proof.sections.reserve(
        na::kRoleCountV3 + 1);
    for (size_t index = 0;
         index < honest.receipt.roles.size();
         ++index) {
        const auto& role = honest.receipt.roles[index];
        proof.commitments.push_back({
            role.role, role.relation_statement_root});
        proof.sections.push_back({
            role.role,
            {
                static_cast<unsigned char>(index + 1),
                static_cast<unsigned char>(index + 17),
            }});
    }
    proof.commitments.push_back({
        rc::RCStage3RelationRole::CompositionLink,
        H(9509)});
    proof.sections.push_back({
        rc::RCStage3RelationRole::CompositionLink,
        {1}});

    auto receipt = honest.receipt;
    receipt.outer_statement_root =
        na::ComputeOuterStatementRootV3(proof);
    BOOST_REQUIRE(!receipt.outer_statement_root.IsNull());
    receipt.parent_statement_root =
        na::ComputeParentStatementRootV3(
            RebuiltFrom(receipt));
    receipt.parent_fs_seed =
        na::DeriveParentFsSeedV3(
            receipt.parent_statement_root);
    const aq::AirQuotientFixedTracePinV3 fixed{
        .version = 1,
        .ordered_columns =
            receipt.fixed_trace_columns,
        .row_root = receipt.fixed_trace_row_root,
    };
    const auto proved =
        aq::AirQuotientProveRowsSplitRapSafeFixedV3(
            honest.cs, honest.columns, fixed,
            receipt.parent_fs_seed);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE_GT(
        aq::SerializeAirQuotientSplitRapRowsProof(
            proved.proof,
            receipt.parent_proof_bytes),
        0U);
    receipt.parent_proof_root =
        na::ComputeParentProofRootV3(
            receipt.parent_proof_bytes);
    receipt.receipt_root =
        na::ComputeReceiptRootV3(receipt);
    std::vector<unsigned char> receipt_wire;
    BOOST_REQUIRE_GT(
        na::SerializeNormalizedAuthorityReceiptV3(
            receipt, receipt_wire),
        0U);
    proof.commitments.back().root =
        receipt.receipt_root;
    proof.sections.back().proof =
        std::move(receipt_wire);
    public_inputs.transcript_commitment =
        rc::ComputeRCStage3TranscriptCommitment(proof);
    BOOST_REQUIRE(
        rc::ValidateRCStage3ProofStructure(proof));
    return proof;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    canonical_round_trip_exports_native_verifier_inputs)
{
    const HonestFixture& honest = Honest();
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        na::ValidateNormalizedAuthorityReceiptV3(
            honest.receipt, &why),
        why);

    std::vector<unsigned char> wire;
    BOOST_REQUIRE_GT(
        na::SerializeNormalizedAuthorityReceiptV3(
            honest.receipt, wire),
        0U);
    BOOST_CHECK_LE(wire.size(), rc::kRCStage3MaxProofBytes);
    const auto decoded =
        na::DeserializeNormalizedAuthorityReceiptV3(
            wire, &why);
    BOOST_REQUIRE_MESSAGE(decoded.has_value(), why);
    BOOST_CHECK(*decoded == honest.receipt);

    aq::AirQuotientSplitRapRowsProof parent_proof;
    aq::AirQuotientFixedTracePinV3 fixed;
    BOOST_REQUIRE_MESSAGE(
        na::ValidateAndDecodeVerifierInputsV3(
            *decoded, honest.rebuilt,
            parent_proof, fixed, &why),
        why);
    BOOST_CHECK_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRapSafeFixedV3(
            honest.cs, parent_proof, fixed,
            honest.receipt.parent_fs_seed, &why),
        why);
}

BOOST_AUTO_TEST_CASE(
    rejects_substitution_even_when_attacker_reseals_receipt_roots)
{
    const HonestFixture& honest = Honest();
    auto substituted = honest.receipt;
    substituted.parent_cs_commitment = H(9001);
    ResealPublicStatement(substituted);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        na::ValidateNormalizedAuthorityReceiptV3(
            substituted, &why),
        why);

    aq::AirQuotientSplitRapRowsProof proof;
    aq::AirQuotientFixedTracePinV3 fixed;
    BOOST_CHECK(
        !na::ValidateAndDecodeVerifierInputsV3(
            substituted, honest.rebuilt,
            proof, fixed, &why));
    BOOST_CHECK_EQUAL(
        why,
        "stage3:normalized_authority_v3:"
        "verifier_input_substitution");
}

BOOST_AUTO_TEST_CASE(
    rejects_truncation_trailing_and_version_relabel)
{
    const HonestFixture& honest = Honest();
    std::vector<unsigned char> wire;
    BOOST_REQUIRE_GT(
        na::SerializeNormalizedAuthorityReceiptV3(
            honest.receipt, wire),
        0U);
    const std::array<size_t, 5> cuts{
        0, 1, 15, wire.size() / 2, wire.size() - 1};
    for (size_t cut : cuts) {
        std::vector<unsigned char> truncated(
            wire.begin(), wire.begin() +
                static_cast<ptrdiff_t>(cut));
        BOOST_CHECK(
            !na::DeserializeNormalizedAuthorityReceiptV3(
                truncated).has_value());
    }
    auto trailing = wire;
    trailing.push_back(0);
    BOOST_CHECK(
        !na::DeserializeNormalizedAuthorityReceiptV3(
            trailing).has_value());

    auto relabelled = honest.receipt;
    relabelled.version = na::kReceiptVersionV3 + 1;
    relabelled.receipt_root =
        na::ComputeReceiptRootV3(relabelled);
    BOOST_CHECK(
        !na::ValidateNormalizedAuthorityReceiptV3(
            relabelled));
}

BOOST_AUTO_TEST_CASE(
    rejects_role_endpoint_and_fixed_column_reordering)
{
    const HonestFixture& honest = Honest();
    auto role_reorder = honest.receipt;
    std::swap(role_reorder.roles[0], role_reorder.roles[1]);
    ResealPublicStatement(role_reorder);
    BOOST_CHECK(
        !na::ValidateNormalizedAuthorityReceiptV3(
            role_reorder));

    auto endpoint_reorder = honest.receipt;
    std::swap(
        endpoint_reorder.roles[0].endpoints[0],
        endpoint_reorder.roles[0].endpoints[1]);
    ResealPublicStatement(endpoint_reorder);
    BOOST_CHECK(
        !na::ValidateNormalizedAuthorityReceiptV3(
            endpoint_reorder));

    auto fixed_reorder = honest.receipt;
    fixed_reorder.fixed_trace_columns = {1, 0};
    ResealPublicStatement(fixed_reorder);
    BOOST_CHECK(
        !na::ValidateNormalizedAuthorityReceiptV3(
            fixed_reorder));
}

BOOST_AUTO_TEST_CASE(
    rejects_missing_parent_cs_proof_and_root_transplants)
{
    const HonestFixture& honest = Honest();

    auto no_cs = honest.receipt;
    no_cs.parent_cs_commitment.SetNull();
    ResealPublicStatement(no_cs);
    BOOST_CHECK(
        !na::ValidateNormalizedAuthorityReceiptV3(no_cs));

    auto no_proof = honest.receipt;
    no_proof.parent_proof_bytes.clear();
    ResealPublicStatement(no_proof);
    BOOST_CHECK(
        !na::ValidateNormalizedAuthorityReceiptV3(no_proof));

    auto root_transplant = honest.receipt;
    root_transplant.parent_proof_root = H(9991);
    root_transplant.receipt_root =
        na::ComputeReceiptRootV3(root_transplant);
    BOOST_CHECK(
        !na::ValidateNormalizedAuthorityReceiptV3(
            root_transplant));

    auto byte_transplant = honest.receipt;
    byte_transplant.parent_proof_bytes[
        byte_transplant.parent_proof_bytes.size() / 2] ^= 1;
    byte_transplant.parent_proof_root =
        na::ComputeParentProofRootV3(
            byte_transplant.parent_proof_bytes);
    byte_transplant.receipt_root =
        na::ComputeReceiptRootV3(byte_transplant);
    // A self-consistently rehashed canonical proof is intentionally beyond
    // the codec's authority.  The mandatory parent AIR verifier, rather than
    // any serialized flag or receipt hash, must reject it.
    std::string why;
    aq::AirQuotientSplitRapRowsProof transplanted_proof;
    aq::AirQuotientFixedTracePinV3 fixed;
    BOOST_REQUIRE_MESSAGE(
        na::ValidateAndDecodeVerifierInputsV3(
            byte_transplant, honest.rebuilt,
            transplanted_proof, fixed, &why),
        why);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRapSafeFixedV3(
            honest.cs, transplanted_proof, fixed,
            honest.receipt.parent_fs_seed, &why));
}

BOOST_AUTO_TEST_CASE(
    composition_link_binds_outer_roles_then_requires_parent_verify)
{
    const HonestFixture& honest = Honest();
    const auto proof = BuildOuterProof(honest);
    na::BoundCompositionLinkV3 bound;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        na::DecodeAndBindCompositionLinkV3(
            proof, bound, &why),
        why);
    BOOST_CHECK_EQUAL(
        why,
        "stage3:normalized_authority_composition_v3:"
        "outer_bound_parent_cs_verify_required");

    const auto rebuilt = RebuiltFrom(bound.receipt);
    aq::AirQuotientSplitRapRowsProof parent_proof;
    aq::AirQuotientFixedTracePinV3 fixed;
    BOOST_REQUIRE_MESSAGE(
        na::ValidateAndDecodeVerifierInputsV3(
            bound.receipt, rebuilt,
            parent_proof, fixed, &why),
        why);
    BOOST_CHECK_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRapSafeFixedV3(
            honest.cs, parent_proof, fixed,
            bound.receipt.parent_fs_seed, &why),
        why);

    auto section_substitution = proof;
    section_substitution.sections[0].proof[0] ^= 1;
    section_substitution.public_inputs
        .transcript_commitment =
            rc::ComputeRCStage3TranscriptCommitment(
                section_substitution);
    BOOST_CHECK(
        !na::DecodeAndBindCompositionLinkV3(
            section_substitution, bound, &why));
    BOOST_CHECK_EQUAL(
        why,
        "stage3:normalized_authority_composition_v3:"
        "outer_statement_root");

    auto receipt_root_substitution = proof;
    receipt_root_substitution.commitments.back().root =
        H(9601);
    receipt_root_substitution.public_inputs
        .transcript_commitment =
            rc::ComputeRCStage3TranscriptCommitment(
                receipt_root_substitution);
    BOOST_CHECK(
        !na::DecodeAndBindCompositionLinkV3(
            receipt_root_substitution,
            bound, &why));
    BOOST_CHECK_EQUAL(
        why,
        "stage3:normalized_authority_composition_v3:"
        "receipt_commitment");
}

BOOST_AUTO_TEST_SUITE_END()
