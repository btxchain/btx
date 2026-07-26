// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_recursive_parent_air.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>
#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <functional>
#include <cstdlib>
#include <map>

namespace matmul::v4::rc::recursive_parent_air {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace sc = splitrap_ctl;
using AlgB3 = aq::AirFriBackendAlg<gf::Fp3>;

uint256 Seed(unsigned char byte)
{
    uint256 out;
    out.SetNull();
    out.data()[0] = byte;
    return out;
}

struct Fixture {
    RCStage3CoupledBankDequantPin pin;
    std::vector<std::vector<gf::Fp3>> columns;
};

Fixture BuildFixture()
{
    Fixture out;
    constexpr uint32_t rows = 2;
    out.columns.assign(
        kRCStage3CoupledBankDequantColumns,
        std::vector<gf::Fp3>(
            rows, gf::Fp3::Zero()));
    const uint64_t mantissas[rows] = {3, 5};
    const uint64_t scales[rows] = {1, 3};
    for (uint32_t row = 0; row < rows; ++row) {
        const uint64_t b0 = scales[row] & 1U;
        const uint64_t b1 =
            (scales[row] >> 1) & 1U;
        const uint64_t factor =
            uint64_t{1} << scales[row];
        out.columns[
            kRCStage3CoupledBankMantissa][row] =
            gf::FromU64_3(mantissas[row]);
        out.columns[
            kRCStage3CoupledBankRepeatedScale][row] =
            gf::FromU64_3(scales[row]);
        out.columns[
            kRCStage3CoupledBankScaleBit0][row] =
            gf::FromU64_3(b0);
        out.columns[
            kRCStage3CoupledBankScaleBit1][row] =
            gf::FromU64_3(b1);
        out.columns[
            kRCStage3CoupledBankScaleFactor][row] =
            gf::FromU64_3(factor);
        out.columns[
            kRCStage3CoupledBankOutput][row] =
            gf::FromU64_3(
                mantissas[row] * factor);
    }
    out.pin.statement_commitment = Seed(0x81);
    out.pin.shape_commitment = Seed(0x82);
    out.pin.sigma = Seed(0x83);
    out.pin.logical_rows = rows;
    out.pin.n_rows = rows;
    out.pin.n_coeffs = rows;
    auto root_columns = out.columns;
    root_columns.emplace_back(
        rows, gf::Fp3::Zero());
    aq::AirConstraintSystem<gf::Fp3> row_shape;
    row_shape.n_rows = rows;
    row_shape.n_columns =
        root_columns.size();
    const auto r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            row_shape, root_columns,
            {0, 1, 2, 3, 4, 5});
    BOOST_REQUIRE(r0.valid);
    out.pin.r0_row_group_root =
        r0.base_row_commitment;
    out.pin.pin_commitment =
        ComputeRCStage3CoupledBankDequantPinCommitment(
            out.pin);
    BOOST_REQUIRE(
        !out.pin.pin_commitment.IsNull());
    return out;
}

NormalizedUniversalParentPublicStatementV1
BuildStatement(
    const Fixture& fixture,
    const sc::CoupledBankEqualityReceiptV1& receipt,
    const uint256& public_seed,
    const constraint_bytecode::ProgramTable& program)
{
    NormalizedUniversalParentPublicStatementV1 out;
    out.public_seed = public_seed;
    out.selected_registry_program_key =
        constraint_bytecode::CommitProgramTableAlgHash(
            program);
    out.child_field_abi_root =
        ComputeNormalizedUniversalChildFieldAbiRootV1(
            fixture.pin, receipt,
            public_seed, 0, program);
    const auto map =
        sc::BuildCoupledBankEqualityReceiptCellMapV1(
            fixture.pin, receipt, public_seed);
    BOOST_REQUIRE(map.valid);
    out.outer_transport_root =
        map.transport_commitment;
    out.universal_parent_statement_root =
        alg_hash::SpongeHashFp({
            gf::FromU64(0x5550),
            gf::FromU64(1),
        });
    out.field_abi_is_recursive_consensus_codec =
        true;
    return out;
}

std::vector<FamilyVerifierOutputCellV1>
FamilyOutputCells()
{
    std::vector<FamilyVerifierOutputCellV1> out;
    uint64_t value = 1;
    for (uint32_t slot = 0; slot < 4; ++slot) {
        const uint32_t first =
            static_cast<uint32_t>(
                FamilyVerifierOutputKindV1::
                    CurrentOpening);
        const uint32_t last =
            slot < 2
            ? static_cast<uint32_t>(
                  FamilyVerifierOutputKindV1::
                      ChildReceiptRootWord)
            : static_cast<uint32_t>(
                  FamilyVerifierOutputKindV1::
                      ChildReceiptRootWord);
        const uint32_t begin =
            slot < 2
            ? first
            : last;
        for (uint32_t kind = begin;
             kind <= last; ++kind) {
            const uint32_t items =
                kind ==
                    static_cast<uint32_t>(
                        FamilyVerifierOutputKindV1::
                            ChildReceiptRootWord)
                ? Arity4FamilyReceiptLayoutV1::
                      kChildRootWords
                : 1;
            for (uint32_t item = 0;
                 item < items; ++item) {
                const gf::Fp3 cell_value{
                    gf::FromU64(value++),
                    gf::FromU64(value++),
                    gf::FromU64(value++)};
                out.push_back({
                    slot,
                    static_cast<
                        FamilyVerifierOutputKindV1>(
                            kind),
                    item,
                    0,
                    cell_value,
                    cell_value,
                });
            }
        }
    }
    return out;
}

aq::AirConstraintSystem<gf::Fp3> ToyFriChildCs()
{
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 2;
    cs.n_columns = 1;
    aq::AirConstraint<gf::Fp3> boolean;
    boolean.name = "one_slot.toy.boolean";
    boolean.kind = aq::AirKind::kEverywhere;
    boolean.alg_degree = 2;
    boolean.eval =
        [](const std::vector<gf::Fp3>& current,
           const std::vector<gf::Fp3>&) {
            return gf::Mul(
                current[0],
                gf::Sub(
                    current[0],
                    gf::Fp3::One()));
        };
    cs.constraints.push_back(
        std::move(boolean));
    return cs;
}

FourSlotNodeContextV1 NodeContext(
    uint32_t level = 1, uint32_t index = 0)
{
    FourSlotNodeContextV1 ctx;
    ctx.level = level;
    ctx.index = index;
    ctx.pub[0] = gf::FromU64_3(0x9001);
    ctx.pub[1] = gf::FromU64_3(0x9002);
    for (uint32_t word = 0;
         word <
         Arity4FamilyReceiptLayoutV1::kChildRootWords;
         ++word) {
        ctx.parent_receipt_root[word] =
            gf::FromU64_3(0x7000 + word);
    }
    return ctx;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_recursive_parent_air_tests)

BOOST_AUTO_TEST_CASE(
    four_slot_authenticated_verifier_output_bus_is_executable)
{
    const auto cells = FamilyOutputCells();
    const auto root =
        ComputeFamilyVerifierOutputBusRootV1(
            cells);
    const auto bus =
        BuildAuthenticatedFamilyVerifierOutputBusV1(
            cells, root);
    BOOST_REQUIRE_MESSAGE(bus.valid, bus.note);
    BOOST_CHECK_EQUAL(bus.active_slots, 2U);
    BOOST_CHECK_EQUAL(bus.padding_slots, 2U);
    BOOST_CHECK(bus.exact_four_slot_tags);
    BOOST_CHECK(
        bus.source_root_caller_pinned_in_air);
    BOOST_CHECK(
        bus.current_next_q_points_and_fs_mapped);
    BOOST_CHECK(bus.every_fp3_coordinate_equal);
    BOOST_CHECK(
        !bus.same_parent_verifies_child_receipt);
    BOOST_CHECK(!bus.self_similar);
    BOOST_CHECK(!bus.authority);
    std::string why;
    BOOST_CHECK_MESSAGE(
        ValidateAuthenticatedFamilyVerifierOutputBusV1(
            cells, root, bus, &why),
        why);
}

BOOST_AUTO_TEST_CASE(
    output_bus_rejects_source_consumer_root_and_tag_attacks)
{
    const auto cells = FamilyOutputCells();
    const auto root =
        ComputeFamilyVerifierOutputBusRootV1(
            cells);
    const auto bus =
        BuildAuthenticatedFamilyVerifierOutputBusV1(
            cells, root);
    BOOST_REQUIRE(bus.valid);

    auto consumer_attack = cells;
    consumer_attack[0].consumer_input =
        gf::Add(
            consumer_attack[0].consumer_input,
            gf::Fp3::One());
    BOOST_CHECK(
        !BuildAuthenticatedFamilyVerifierOutputBusV1(
             consumer_attack, root)
             .valid);

    auto source_attack = cells;
    source_attack[0].verifier_output =
        gf::Add(
            source_attack[0].verifier_output,
            gf::Fp3::One());
    BOOST_CHECK(
        !BuildAuthenticatedFamilyVerifierOutputBusV1(
             source_attack, root)
             .valid);

    auto missing_fs = cells;
    const auto found = std::find_if(
        missing_fs.begin(),
        missing_fs.end(),
        [](const auto& cell) {
            return cell.slot == 0 &&
                cell.kind ==
                    FamilyVerifierOutputKindV1::
                        FiatShamirChallenge;
        });
    BOOST_REQUIRE(found != missing_fs.end());
    missing_fs.erase(found);
    const auto missing_root =
        ComputeFamilyVerifierOutputBusRootV1(
            missing_fs);
    BOOST_CHECK(
        !BuildAuthenticatedFamilyVerifierOutputBusV1(
             missing_fs, missing_root)
             .valid);

    auto witness_attack = bus;
    witness_attack.witness[
        witness_attack.consumer_base][0] =
        gf::Add(
            witness_attack.witness[
                witness_attack.consumer_base][0],
            gf::Fp3::One());
    std::string why;
    BOOST_CHECK(
        !ValidateAuthenticatedFamilyVerifierOutputBusV1(
            cells, root,
            witness_attack, &why));
}

BOOST_AUTO_TEST_CASE(
    one_slot_parent_executes_vcs_and_sources_bus_from_verified_cells)
{
    const auto child_cs = ToyFriChildCs();
    const uint256 seed = Seed(0xa1);
    const std::vector<std::vector<gf::Fp3>>
        columns{{
            gf::Fp3::Zero(),
            gf::Fp3::One()}};
    const auto proved =
        aq::AirQuotientProve<
            gf::Fp3, AlgB3>(
                child_cs, columns, seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    const auto root =
        ComputeOneSlotNormalizedFriParentOutputRootV1(
            child_cs, proved.proof, seed);
    BOOST_REQUIRE(root != alg_hash::Digest{});
    const auto parent =
        BuildOneSlotNormalizedFriParentV1(
            child_cs, proved.proof,
            seed, root);
    BOOST_REQUIRE_MESSAGE(parent.valid, parent.note);
    BOOST_CHECK_EQUAL(parent.active_slots, 1U);
    BOOST_CHECK_EQUAL(parent.padding_slots, 3U);
    BOOST_CHECK(parent.all_vcs_families_execute);
    BOOST_CHECK(
        parent.merkle_fold_deep_quotient_same_parent);
    BOOST_CHECK(parent.exact_four_slot_layout);
    BOOST_CHECK(
        parent.output_bus_exclusively_from_vcs_cells);
    BOOST_CHECK(
        parent.output_bus_authenticated_in_parent);
    BOOST_CHECK(
        parent.exact_child_proof_codec_roundtrip);
    BOOST_CHECK_GT(
        parent.exact_child_proof_bytes, 0U);
    BOOST_CHECK(
        !parent.child_proof_bytes_owned_by_parent_air);
    BOOST_CHECK(
        parent.fiat_shamir_value_consumed_in_parent);
    BOOST_CHECK(
        parent.exact_sha_call_preimages_inventoried);
    BOOST_CHECK(
        parent.sha_preimage_codec_alias_map_complete);
    BOOST_CHECK_GT(
        parent.fiat_shamir_preimage_bytes, 0U);
    BOOST_CHECK_GT(
        parent.fiat_shamir_preimage_codec_alias_bytes,
        0U);
    BOOST_CHECK(
        parent.fiat_shamir_sha_execution
            .exact_domain_tags_and_order);
    BOOST_CHECK(
        parent.fiat_shamir_sha_execution
            .every_digest_matches_claim);
    BOOST_CHECK(
        parent.fiat_shamir_sha_execution
            .exact_sha256d_padding_and_chaining);
    BOOST_CHECK(
        !parent.fiat_shamir_sha_execution
             .fixed_schedule);
    BOOST_CHECK(
        parent.fiat_shamir_sha_execution
            .proof_codec_byte_origins_complete);
    BOOST_CHECK(
        !parent.fiat_shamir_sha_execution
             .recursively_consumed);
    BOOST_CHECK(
        !parent.fiat_shamir_sha_replayed_in_parent);
    BOOST_CHECK(
        parent.invalid_child_witness_rejected_by_parent);
    BOOST_CHECK(
        !parent.same_parent_verifies_child_receipt);
    BOOST_CHECK(!parent.recursive_fixed_point);
    BOOST_CHECK(!parent.authority);
    BOOST_CHECK_EQUAL(parent.witness_violations, 0U);
    BOOST_CHECK_GT(
        parent.parent_columns,
        parent.vcs_columns);

    std::vector<unsigned char> encoded;
    std::string codec_why;
    BOOST_REQUIRE_MESSAGE(
        SerializeOneSlotNormalizedFriChildProofV1(
            proved.proof, encoded,
            &codec_why),
        codec_why);
    OneSlotNormalizedFriParentV1::ChildProof
        decoded;
    BOOST_REQUIRE_MESSAGE(
        DeserializeOneSlotNormalizedFriChildProofV1(
            encoded, decoded,
            &codec_why),
        codec_why);
    std::vector<unsigned char> reencoded;
    BOOST_REQUIRE(
        SerializeOneSlotNormalizedFriChildProofV1(
            decoded, reencoded,
            &codec_why));
    BOOST_CHECK_EQUAL_COLLECTIONS(
        encoded.begin(), encoded.end(),
        reencoded.begin(), reencoded.end());
    const auto byte_parent =
        BuildOneSlotNormalizedFriParentFromBytesV1(
            child_cs, encoded, seed, root);
    BOOST_REQUIRE_MESSAGE(
        byte_parent.valid, byte_parent.note);
    BOOST_CHECK(
        byte_parent
            .exact_child_proof_bytes_parsed_at_ingress);
    BOOST_CHECK(
        !byte_parent
             .child_proof_bytes_owned_by_parent_air);

    auto trailing_attack = encoded;
    trailing_attack.push_back(0);
    BOOST_CHECK(
        !BuildOneSlotNormalizedFriParentFromBytesV1(
             child_cs, trailing_attack,
             seed, root)
             .valid);

    auto body_attack = encoded;
    BOOST_REQUIRE_GT(body_attack.size(), 64U);
    body_attack[body_attack.size() / 2] ^= 1U;
    const auto attacked =
        BuildOneSlotNormalizedFriParentFromBytesV1(
            child_cs, body_attack,
            seed, root);
    BOOST_CHECK(!attacked.valid);
}

BOOST_AUTO_TEST_CASE(
    one_slot_parent_rejects_internally_consistent_bad_merkle_and_fold)
{
    const auto child_cs = ToyFriChildCs();
    const uint256 seed = Seed(0xa2);
    const std::vector<std::vector<gf::Fp3>>
        columns{{
            gf::Fp3::Zero(),
            gf::Fp3::One()}};
    const auto proved =
        aq::AirQuotientProve<
            gf::Fp3, AlgB3>(
                child_cs, columns, seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);

    auto bad_merkle = proved.proof;
    BOOST_REQUIRE(
        !bad_merkle.batch.queries.empty());
    BOOST_REQUIRE(
        !bad_merkle.batch.queries[0]
             .row.siblings.empty());
    bad_merkle.batch.queries[0]
        .row.siblings[0][0] =
        gf::Add(
            bad_merkle.batch.queries[0]
                .row.siblings[0][0],
            gf::Fp{1});
    // Recompute the public output root over the forged child's own outputs.
    // The root and bus are internally consistent; only the in-parent Merkle
    // equations expose the invalid path.
    const auto bad_merkle_root =
        ComputeOneSlotNormalizedFriParentOutputRootV1(
            child_cs, bad_merkle, seed);
    BOOST_REQUIRE(
        bad_merkle_root != alg_hash::Digest{});
    const auto merkle_parent =
        BuildOneSlotNormalizedFriParentV1(
            child_cs, bad_merkle, seed,
            bad_merkle_root);
    BOOST_CHECK(!merkle_parent.valid);
    BOOST_CHECK_GT(
        merkle_parent.witness_violations, 0U);

    auto bad_fold = proved.proof;
    BOOST_REQUIRE(
        !bad_fold.batch.queries.empty());
    BOOST_REQUIRE(
        !bad_fold.batch.queries[0]
             .steps.empty());
    bad_fold.batch.queries[0].steps[0].even =
        gf::Add(
            bad_fold.batch.queries[0]
                .steps[0].even,
            gf::Fp3::One());
    const auto bad_fold_root =
        ComputeOneSlotNormalizedFriParentOutputRootV1(
            child_cs, bad_fold, seed);
    BOOST_REQUIRE(
        bad_fold_root != alg_hash::Digest{});
    const auto fold_parent =
        BuildOneSlotNormalizedFriParentV1(
            child_cs, bad_fold, seed,
            bad_fold_root);
    BOOST_CHECK(!fold_parent.valid);
    BOOST_CHECK_GT(
        fold_parent.witness_violations, 0U);
}

BOOST_AUTO_TEST_CASE(
    heterogeneous_episode_sha_dispatch_is_registry_pinned_and_one_hot)
{
    constraint_bytecode::ProgramTable episode;
    BOOST_REQUIRE(
        BuildRCStage3CoupledBankDequantProgramTableCanonical(
            episode));
    auto sha = episode;
    sha.role = RCStage3RelationRole::EpisodeDigest;
    for (auto& program : sha.programs) {
        program.role =
            RCStage3RelationRole::EpisodeDigest;
    }
    BOOST_REQUIRE(
        constraint_bytecode::ValidateProgramTable(
            episode));
    BOOST_REQUIRE(
        constraint_bytecode::ValidateProgramTable(
            sha));
    BOOST_REQUIRE(
        constraint_bytecode::CommitProgramTableAlgHash(
            episode) !=
        constraint_bytecode::CommitProgramTableAlgHash(
            sha));

    HeterogeneousChildEnvelopeV1 envelope;
    envelope.program_id =
        HeterogeneousChildProgramIdV1::
            ShaCompressionVerifier;
    envelope.registry_root =
        ComputeHeterogeneousProgramRegistryRootV1(
            episode, sha);
    envelope.program_root =
        constraint_bytecode::
            CommitProgramTableAlgHash(sha);
    envelope.proof_bytes_root =
        alg_hash::SpongeHashFp({
            gf::FromU64(0x50524f4f46),
            gf::FromU64(7),
        });
    envelope.public_inputs_root =
        alg_hash::SpongeHashFp({
            gf::FromU64(0x5055424c49),
            gf::FromU64(9),
        });
    const auto envelope_root =
        ComputeHeterogeneousChildEnvelopeRootV1(
            envelope);
    const auto parent =
        BuildHeterogeneousChildDispatchParentV1(
            episode, sha, envelope,
            envelope.registry_root,
            envelope_root);
    BOOST_REQUIRE_MESSAGE(
        parent.valid, parent.note);
    BOOST_CHECK(
        parent.both_program_tables_canonical);
    BOOST_CHECK(
        parent.registry_root_pinned_in_air);
    BOOST_CHECK(parent.exact_two_program_ids);
    BOOST_CHECK(
        parent.dispatch_selectors_boolean);
    BOOST_CHECK(
        parent.dispatch_selector_one_hot);
    BOOST_CHECK(
        parent.selected_program_root_equality_constrained);
    BOOST_CHECK(
        parent.proof_and_public_roots_authenticated);
    BOOST_CHECK(
        !parent.selected_child_proof_verified_in_parent);
    BOOST_CHECK(
        !parent.sha_child_proof_verified_in_parent);
    BOOST_CHECK(
        !parent.same_parent_verifies_child_receipt);
    BOOST_CHECK(!parent.recursive_fixed_point);
    BOOST_CHECK(!parent.authority);
    BOOST_CHECK_EQUAL(
        parent.witness_violations, 0U);

    auto selector_attack = parent.columns;
    selector_attack[9][0] =
        gf::Fp3::One();
    BOOST_CHECK_GT(
        va::CountVerifierScalarViolations(
            parent.cs, selector_attack),
        0U);

    auto root_attack = envelope;
    root_attack.program_root[0] =
        gf::Add(
            root_attack.program_root[0],
            gf::Fp{1});
    const auto attacked_root =
        ComputeHeterogeneousChildEnvelopeRootV1(
            root_attack);
    BOOST_CHECK(
        !BuildHeterogeneousChildDispatchParentV1(
             episode, sha, root_attack,
             envelope.registry_root,
             attacked_root)
             .valid);

    auto wrong_registry =
        envelope.registry_root;
    wrong_registry[0] =
        gf::Add(
            wrong_registry[0],
            gf::Fp{1});
    BOOST_CHECK(
        !BuildHeterogeneousChildDispatchParentV1(
             episode, sha, envelope,
             wrong_registry,
             envelope_root)
             .valid);
}

BOOST_AUTO_TEST_CASE(
    caller_pinned_program_and_field_roots_reject_substitution)
{
    if (std::getenv(
            "BTX_STAGE3_RUN_RECURSIVE_PARENT_CANARY") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_STAGE3_RUN_RECURSIVE_PARENT_CANARY=1 "
            "for the proof-producing parent canary");
        return;
    }
    const Fixture fixture = BuildFixture();
    const uint256 public_seed = Seed(0x91);
    sc::CoupledBankEqualityReceiptV1 receipt;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        sc::ProveCoupledBankEqualityReceiptV1(
            fixture.pin, fixture.columns,
            public_seed, receipt, &why),
        why);
    constraint_bytecode::ProgramTable program;
    BOOST_REQUIRE(
        BuildRCStage3CoupledBankDequantProgramTableCanonical(
            program));
    const auto statement =
        BuildStatement(
            fixture, receipt,
            public_seed, program);
    const auto candidate =
        BuildNormalizedUniversalParentCandidateV1(
            fixture.pin, receipt, 0,
            program, statement);
    BOOST_REQUIRE_MESSAGE(
        candidate.valid, candidate.note);
    BOOST_CHECK(
        candidate.canonical_program_key_bound_in_air);
    BOOST_CHECK(
        candidate.private_receipt_payload_bound_in_air);
    BOOST_CHECK(
        candidate.registry_program_key_selected_by_caller);
    BOOST_CHECK_EQUAL(
        candidate.proof_cells_semantically_mapped,
        candidate.proof_cells_required);
    BOOST_CHECK_GT(
        candidate.proof_cells_required, 0U);
    BOOST_CHECK(
        !candidate.outer_transport_to_field_root_in_parent);
    BOOST_CHECK(
        !candidate.registry_program_interpreter_executes_in_parent);
    BOOST_CHECK(
        !candidate.complete_splitrap_verifier_in_air);
    BOOST_CHECK(!candidate.recursive_fixed_point);
    BOOST_CHECK(!candidate.authority);
    BOOST_CHECK(
        ValidateNormalizedUniversalParentCandidateV1(
            fixture.pin, receipt, 0,
            program, statement,
            candidate, &why));

    auto wrong_field_root = statement;
    wrong_field_root.child_field_abi_root[0] =
        gf::Add(
            wrong_field_root.child_field_abi_root[0],
            gf::Fp{1});
    BOOST_CHECK(
        !BuildNormalizedUniversalParentCandidateV1(
             fixture.pin, receipt, 0,
             program, wrong_field_root)
             .valid);

    auto wrong_program_key = statement;
    wrong_program_key.selected_registry_program_key[0] =
        gf::Add(
            wrong_program_key
                .selected_registry_program_key[0],
            gf::Fp{1});
    BOOST_CHECK(
        !BuildNormalizedUniversalParentCandidateV1(
             fixture.pin, receipt, 0,
             program, wrong_program_key)
             .valid);

    auto changed_program = program;
    BOOST_REQUIRE(
        !changed_program.programs.empty());
    BOOST_REQUIRE(
        !changed_program.programs[0]
             .instructions.empty());
    auto constant = std::find_if(
        changed_program.programs[0]
            .instructions.begin(),
        changed_program.programs[0]
            .instructions.end(),
        [](const auto& instruction) {
            return instruction.opcode ==
                constraint_bytecode::Opcode::Constant;
        });
    BOOST_REQUIRE(
        constant !=
        changed_program.programs[0]
            .instructions.end());
    constant->constant =
        gf::Add(
            constant->constant,
            gf::Fp3::One());
    BOOST_REQUIRE(
        constraint_bytecode::ValidateProgramTable(
            changed_program));
    BOOST_CHECK(
        constraint_bytecode::CommitProgramTableAlgHash(
            changed_program) !=
        statement.selected_registry_program_key);
    BOOST_CHECK(
        !BuildNormalizedUniversalParentCandidateV1(
             fixture.pin, receipt, 0,
             changed_program, statement)
             .valid);
}

BOOST_AUTO_TEST_CASE(
    field_cell_and_active_lane_mutations_fail_parent_relation)
{
    if (std::getenv(
            "BTX_STAGE3_RUN_RECURSIVE_PARENT_CANARY") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_STAGE3_RUN_RECURSIVE_PARENT_CANARY=1 "
            "for the proof-producing parent canary");
        return;
    }
    const Fixture fixture = BuildFixture();
    const uint256 public_seed = Seed(0x92);
    sc::CoupledBankEqualityReceiptV1 receipt;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        sc::ProveCoupledBankEqualityReceiptV1(
            fixture.pin, fixture.columns,
            public_seed, receipt, &why),
        why);
    constraint_bytecode::ProgramTable program;
    BOOST_REQUIRE(
        BuildRCStage3CoupledBankDequantProgramTableCanonical(
            program));
    const auto statement =
        BuildStatement(
            fixture, receipt,
            public_seed, program);
    const auto candidate =
        BuildNormalizedUniversalParentCandidateV1(
            fixture.pin, receipt, 0,
            program, statement);
    BOOST_REQUIRE(candidate.valid);

    auto field_attack = candidate;
    field_attack.parent_columns_witness[
        field_attack.receipt_sponge.Field(0)][0] =
        gf::Add(
            field_attack.parent_columns_witness[
                field_attack.receipt_sponge.Field(0)][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        va::CountVerifierScalarViolations(
            field_attack.parent_cs,
            field_attack.parent_columns_witness),
        0U);
    BOOST_CHECK(
        !ValidateNormalizedUniversalParentCandidateV1(
            fixture.pin, receipt, 0,
            program, statement,
            field_attack, &why));

    auto lane_attack = candidate;
    lane_attack.proof_cells_semantically_mapped =
        lane_attack.proof_cells_required - 1;
    lane_attack.complete_proof_cell_equality_map =
        false;
    BOOST_CHECK(
        !ValidateNormalizedUniversalParentCandidateV1(
            fixture.pin, receipt, 0,
            program, statement,
            lane_attack, &why));
}

BOOST_AUTO_TEST_CASE(
    four_slot_self_similar_parent_verifies_children_sources_roots_and_decomposes_statement)
{
    const auto child_cs = ToyFriChildCs();
    const uint256 seed = Seed(0xc4);
    const std::vector<std::vector<gf::Fp3>>
        columns{{
            gf::Fp3::Zero(),
            gf::Fp3::One()}};
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(
            child_cs, columns, seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);

    const std::array<
        FourSlotSelfSimilarCtlParentV1::ChildProof, 4>
        proofs{
            proved.proof, proved.proof,
            proved.proof, proved.proof};

    // Honest caller pins the binding parent statement h_nu.
    const auto ctx = NodeContext();
    const auto statement =
        ComputeFourSlotSelfSimilarParentStatementV1(
            child_cs, proofs, seed, ctx);
    const auto parent =
        BuildFourSlotSelfSimilarCtlParentV1(
            child_cs, proofs, seed, ctx, statement);
    BOOST_REQUIRE_MESSAGE(parent.valid, parent.note);

    BOOST_CHECK_EQUAL(parent.active_slots, 4U);
    BOOST_CHECK_EQUAL(
        parent.terminal_lanes_per_slot, 8U);
    BOOST_CHECK_EQUAL(
        parent.sourced_root_lanes, 32U);
    BOOST_CHECK_EQUAL(parent.witness_violations, 0U);
    BOOST_CHECK(
        parent.all_four_children_verified_in_parent_air);
    BOOST_CHECK(
        parent.merkle_fold_deep_quotient_same_parent);
    BOOST_CHECK(
        parent
            .terminal_lanes_sourced_from_in_parent_verifier);
    BOOST_CHECK(
        parent
            .four_child_roots_sourced_from_verifier_outputs);
    // Binding sponge (D3b) over the full child public-IO tuples, plus the D3c
    // relational equalities.
    BOOST_CHECK(
        parent.statement_bound_by_alg_hash_sponge);
    BOOST_CHECK(parent.full_child_pubio_absorbed);
    BOOST_CHECK(parent.public_context_threaded);
    BOOST_CHECK(parent.position_threading_affine);
    BOOST_CHECK(parent.link_accumulator_folded);
    BOOST_CHECK_EQUAL(parent.node_sponge_count, 5U);
    BOOST_CHECK(
        parent.statement_decomposition_enforced_in_air);
    BOOST_CHECK(
        parent.parent_statement_equals_child_aggregation);
    BOOST_CHECK_GT(
        parent.child_pubio_lanes_absorbed, 0U);
    BOOST_CHECK(parent.self_similar_arity4_shape);
    // Deliberately-open gates: the parent's own FRI proof is not produced and
    // the child Fiat-Shamir transcript is not replayed in-parent, so the
    // recursive fixed point and consensus authority are NOT claimed.
    BOOST_CHECK(
        !parent.child_fiat_shamir_replayed_in_parent);
    BOOST_CHECK(
        !parent.parent_own_fri_proof_produced);
    BOOST_CHECK(!parent.recursive_fixed_point);
    BOOST_CHECK(!parent.authority);
    BOOST_CHECK_GT(
        parent.parent_columns, parent.vcs_columns);

    // In-circuit binding enforcement: the parent statement is the AlgHash of the
    // four children's public IO. Tampering the pinned sponge-output digit breaks
    // the in-circuit sponge-output identity (not just a host check).
    auto tampered_digest_witness = parent.parent_witness;
    const uint32_t expected_root_column =
        parent.statement_sponge.ExpectedRoot(0);
    // The sponge output identity terminal*(perm_output - expected)=0 fires on the
    // sponge's terminal row; tamper the pinned digest there.
    const uint32_t terminal_row =
        parent.statement_sponge_audit.active_rows - 1;
    tampered_digest_witness[expected_root_column]
                           [terminal_row] =
        gf::Add(
            tampered_digest_witness[expected_root_column]
                                   [terminal_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        air_recurse::CountWitnessViolationsOnH(
            parent.parent_cs, tampered_digest_witness),
        0U);

    // Counterexample (build-time binding pin): four TRUE children under a
    // mis-aggregated claim (statement != AlgHash(child pubIO)) must REJECT. Only
    // the claimed digest changes; the four child proofs are still valid.
    auto misaggregated = statement;
    misaggregated[0] =
        gf::Add(misaggregated[0], gf::Fp{1});
    const auto forged =
        BuildFourSlotSelfSimilarCtlParentV1(
            child_cs, proofs, seed, ctx, misaggregated);
    BOOST_CHECK(!forged.valid);
    BOOST_CHECK(
        !forged.parent_statement_equals_child_aggregation);
    BOOST_CHECK(!forged.self_similar_arity4_shape);
    // The children's actual binding statement is unchanged.
    BOOST_CHECK(
        forged.computed_parent_statement == statement);
}

BOOST_AUTO_TEST_CASE(
    four_slot_child_air_challenge_reconstructed_in_parent_and_forgery_rejected)
{
    // g4 decoder half: each child's AIR-quotient challenge air_lambda is
    // RE-DERIVED inside the parent's own constraints from the pinned airq_lambda
    // transcript-digest bytes and bound by equality to the challenge the
    // in-parent verifier AIR consumes.  Honest -> accepts; a forged consumed
    // challenge (inconsistent with the transcript digest) -> parent CS rejects.
    const auto child_cs = ToyFriChildCs();
    const uint256 seed = Seed(0xa7);
    const std::vector<std::vector<gf::Fp3>>
        columns{{gf::Fp3::Zero(), gf::Fp3::One()}};
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(
            child_cs, columns, seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);

    const std::array<
        FourSlotSelfSimilarCtlParentV1::ChildProof, 4>
        proofs{proved.proof, proved.proof,
               proved.proof, proved.proof};
    const auto ctx = NodeContext();
    const auto statement =
        ComputeFourSlotSelfSimilarParentStatementV1(
            child_cs, proofs, seed, ctx);
    const auto parent =
        BuildFourSlotSelfSimilarCtlParentV1(
            child_cs, proofs, seed, ctx, statement);
    BOOST_REQUIRE_MESSAGE(parent.valid, parent.note);

    // Honest: the in-circuit reconstruction is wired for all four slots with
    // zero constraint violations, and each slot exposes a challenge column.
    BOOST_CHECK(
        parent.child_air_challenge_reconstructed_in_parent_cs);
    BOOST_CHECK_EQUAL(parent.witness_violations, 0U);
    for (uint32_t slot = 0; slot < 4; ++slot) {
        BOOST_CHECK_GT(
            parent.child_air_challenge_value_column[slot],
            parent.vcs_columns);
    }
    // This is the DECODER half only; the SHA256d seed->digest compression is
    // NOT yet a parent constraint, so the full-replay gate stays false.
    BOOST_CHECK(
        !parent.child_fiat_shamir_replayed_in_parent);

    // Forgery: tamper slot 2's reconstructed-challenge cell to a value that is
    // NOT the recompose of the pinned digest bytes (and not the consumed
    // air_lambda).  Both the basis-reconstruction identity and the
    // bound-to-consumed equality now fail -> the parent CS rejects.
    auto forged = parent.parent_witness;
    const uint32_t chal_col =
        parent.child_air_challenge_value_column[2];
    for (auto& cell : forged[chal_col]) {
        cell = gf::Add(cell, gf::Fp3::One());
    }
    BOOST_CHECK_GT(
        air_recurse::CountWitnessViolationsOnH(
            parent.parent_cs, forged),
        0U);

    // Forgery via a mismatched consumed challenge only (leave the honest
    // reconstruction in place): flip one digest byte's derived word so the
    // recompose lane no longer matches -> reject.  Confirms the recompose
    // lanes are live, not just the terminal equality.
    auto forged_word = parent.parent_witness;
    const uint32_t word_col = chal_col - 1;  // word2 sits just below challenge
    for (auto& cell : forged_word[word_col]) {
        cell = gf::Add(cell, gf::Fp3::One());
    }
    BOOST_CHECK_GT(
        air_recurse::CountWitnessViolationsOnH(
            parent.parent_cs, forged_word),
        0U);
}

BOOST_AUTO_TEST_CASE(
    four_slot_child_airq_lambda_sha256d_replayed_in_cs_and_coordinated_forgery_rejected)
{
    // g4 MECHANISM: the child's airq_lambda challenge is re-derived through a
    // REAL in-circuit SHA256d compression whose 32-byte OUTPUT constrains the
    // digest bytes the decoder consumes (no longer a free preprocessed column).
    //
    // HEAVY (env-gated): the airq_lambda transcript is a 113-byte preimage, so
    // its SHA256d is three real fixed-program compressions; building that
    // vertical AIR + scanning the full CS costs ~1.6k CPU-seconds per instance
    // (single-slot, single-kind — the full 4-slot × 8-kind coverage is the GPU
    // scale-up). Gated so the default suite stays fast; run with
    // BTX_RUN_HEAVY_CHILD_FS_SHA=1.
    if (std::getenv("BTX_RUN_HEAVY_CHILD_FS_SHA") == nullptr) {
        BOOST_TEST_MESSAGE(
            "skipping heavy airq_lambda SHA256d in-CS replay "
            "(set BTX_RUN_HEAVY_CHILD_FS_SHA=1 to run)");
        return;
    }
    const auto child_cs = ToyFriChildCs();
    const uint256 seed = Seed(0x5e);
    const std::vector<std::vector<gf::Fp3>>
        columns{{gf::Fp3::Zero(), gf::Fp3::One()}};
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(
            child_cs, columns, seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    const std::array<
        FourSlotSelfSimilarCtlParentV1::ChildProof, 4>
        proofs{proved.proof, proved.proof,
               proved.proof, proved.proof};
    const auto ctx = NodeContext();
    const auto statement =
        ComputeFourSlotSelfSimilarParentStatementV1(
            child_cs, proofs, seed, ctx);
    const auto parent =
        BuildFourSlotSelfSimilarCtlParentV1(
            child_cs, proofs, seed, ctx, statement);
    BOOST_REQUIRE_MESSAGE(parent.valid, parent.note);

    // The exact challenge (air_lambda) the in-parent verifier consumes for slot
    // 0, and the child's trace commitment + AIR shape that seed its transcript.
    const auto& pi0 = parent.child_verifier.pis[0];
    const gf::Fp3 consumed = pi0.air_lambda;

    const auto replay =
        BuildChildAirChallengeShaReplayV1(
            seed, proved.proof.trace_commit,
            pi0.child_n_rows, pi0.child_quotient_len,
            pi0.child_w, consumed);
    BOOST_REQUIRE_MESSAGE(replay.valid, replay.note);

    // The in-CS SHA256d output equals the child's real airq_lambda digest, and
    // the reconstructed challenge equals the consumed air_lambda.
    BOOST_CHECK_EQUAL(replay.witness_violations, 0U);
    BOOST_CHECK(replay.sha_output_binds_digest_bytes);
    BOOST_CHECK(replay.challenge_bound_to_consumed);
    BOOST_CHECK(gf::Eq(replay.reconstructed_challenge, consumed));
    // Real double-hash transcript: 2 first-pass blocks + 1 second-pass block.
    BOOST_CHECK_EQUAL(replay.sha_semantic_compressions, 3U);
    // Committed SHA output cells equal the native digest bytes.
    const uint32_t obb = replay.sha_output_byte_base;
    for (uint32_t k = 0; k < 24; ++k) {
        BOOST_CHECK(gf::Eq(
            replay.columns[obb + k][0],
            gf::Fp3::FromFp(
                gf::FromU64(replay.digest.data()[k]))));
    }

    // COORDINATED FORGERY (the case the decoder-only pass could NOT catch):
    // present a fully self-consistent WRONG (digest', challenge') pair — flip a
    // digest byte AND recompute the challenge limbs so the digest->challenge map
    // still holds, keeping the SHA input honest. Previously the digest bytes
    // were a free preprocessed column so this passed; now the in-CS SHA
    // compression constraints reject it because output != SHA(input). One
    // full-CS scan (the SHA trace is large — see the per-instance cost note).
    {
        auto bad = replay.columns;
        std::array<unsigned char, 24> dbytes{};
        for (uint32_t k = 0; k < 24; ++k) {
            dbytes[k] = replay.digest.data()[k];
        }
        dbytes[5] ^= 0x01;
        for (uint32_t k = 0; k < 24; ++k) {
            const gf::Fp3 b =
                gf::FromU64_3(static_cast<uint64_t>(dbytes[k]));
            for (auto& cell : bad[obb + k]) cell = b;
        }
        const gf::Fp3 recon2 =
            gf::FromChallengeBytes3(dbytes.data());
        const std::array<gf::Fp3, 3> limbs2 = {
            gf::Fp3::FromFp(recon2.c0),
            gf::Fp3::FromFp(recon2.c1),
            gf::Fp3::FromFp(recon2.c2)};
        for (uint32_t j = 0; j < 3; ++j) {
            for (auto& cell :
                 bad[replay.challenge_limb_columns[j]]) {
                cell = limbs2[j];
            }
        }
        BOOST_CHECK_GT(
            air_recurse::CountWitnessViolationsOnH(
                replay.cs, bad),
            0U);
    }
}

BOOST_AUTO_TEST_CASE(
    four_slot_child_fs_seed_owned_by_parent_binding_digest)
{
    // Edge 1: the child transcript seed is bound by equality to the parent's
    // AlgHash binding digest h_cj (slot 0) across the field-domain boundary.
    const auto child_cs = ToyFriChildCs();
    const std::vector<std::vector<gf::Fp3>>
        columns{{gf::Fp3::Zero(), gf::Fp3::One()}};
    const auto ctx = NodeContext();

    // Prove once with an arbitrary probe seed to obtain the seed-INDEPENDENT
    // binding digest h_c0 (io/rho are committed before Fiat–Shamir, so h_c0
    // does not depend on the transcript seed).
    const uint256 probe_seed = Seed(0xc4);
    const auto probed =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(
            child_cs, columns, probe_seed, {});
    BOOST_REQUIRE_MESSAGE(probed.ok, probed.note);
    const std::array<
        FourSlotSelfSimilarCtlParentV1::ChildProof, 4>
        probe_proofs{
            probed.proof, probed.proof,
            probed.proof, probed.proof};
    const auto probe_statement =
        ComputeFourSlotSelfSimilarParentStatementV1(
            child_cs, probe_proofs, probe_seed, ctx);
    const auto probe_parent =
        BuildFourSlotSelfSimilarCtlParentV1(
            child_cs, probe_proofs, probe_seed, ctx,
            probe_statement);
    BOOST_REQUIRE_MESSAGE(
        probe_parent.valid, probe_parent.note);

    // An arbitrary caller seed is NOT owned by the parent binding digest, yet
    // all four per-slot ownership buses are canonical (the taxonomy is built).
    BOOST_CHECK(
        probe_parent.child_seed_ownership_bus_canonical);
    BOOST_CHECK(
        !probe_parent
             .child_fs_seed_bound_to_parent_binding_digest);

    // Honest caller: seed the child transcript FROM h_c0 = the parent binding
    // digest of slot 0.  owned_seed is its canonical LE-limb packing.
    const auto h_c0 = probe_parent.child_binding_digests[0];
    const uint256 owned_seed =
        Fri3AlgDigestToUint256(h_c0);

    // Re-prove the children under the owned seed.  The committed roots (hence
    // h_c0) are unchanged; only the FS-derived openings differ.
    const auto owned =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(
            child_cs, columns, owned_seed, {});
    BOOST_REQUIRE_MESSAGE(owned.ok, owned.note);
    const std::array<
        FourSlotSelfSimilarCtlParentV1::ChildProof, 4>
        owned_proofs{
            owned.proof, owned.proof,
            owned.proof, owned.proof};
    const auto owned_statement =
        ComputeFourSlotSelfSimilarParentStatementV1(
            child_cs, owned_proofs, owned_seed, ctx);
    const auto owned_parent =
        BuildFourSlotSelfSimilarCtlParentV1(
            child_cs, owned_proofs, owned_seed, ctx,
            owned_statement);
    BOOST_REQUIRE_MESSAGE(
        owned_parent.valid, owned_parent.note);

    // The binding digest is unchanged and the seed now binds with 0 violations.
    BOOST_CHECK(
        owned_parent.child_binding_digests[0] == h_c0);
    BOOST_CHECK(
        owned_parent.child_seed_ownership_bus_canonical);
    BOOST_CHECK(
        owned_parent
            .child_fs_seed_bound_to_parent_binding_digest);
    BOOST_CHECK_EQUAL(
        va::FiatShamirSeedBusViolations(
            owned_parent.child_seed_ownership_bus[0],
            owned_seed),
        0U);

    // Tamper (host bus): bumping one limb of the pinned binding digest changes
    // its owned seed image, so the previously-owned seed no longer binds.
    auto tampered = h_c0;
    tampered[1] = tampered[1] + 1;
    const auto tampered_bus =
        va::BuildFiatShamirSeedOwnershipBusV1(tampered);
    BOOST_CHECK(
        tampered_bus.owned_seed != owned_seed);
    BOOST_CHECK_GT(
        va::FiatShamirSeedBusViolations(
            tampered_bus, owned_seed),
        0U);

    // Edge 1 in-circuit promotion: the owned-seed limb cells are bound to the
    // h_cj sponge digest cells by AIR equalities (independent of the caller's
    // input seed, so it holds for BOTH constructions).
    BOOST_CHECK(
        probe_parent.seed_ownership_bound_in_parent_cs);
    BOOST_CHECK(
        owned_parent.seed_ownership_bound_in_parent_cs);
    BOOST_REQUIRE_GT(
        owned_parent.fs_seed_ownership_limb_base, 0U);

    // Constraint-level tamper: perturbing an owned-seed limb witness cell so it
    // no longer equals its h_cj digest cell makes the parent CS reject.
    auto tampered_witness = owned_parent.parent_witness;
    tampered_witness[owned_parent.fs_seed_ownership_limb_base][0] =
        gf::Add(
            tampered_witness
                [owned_parent.fs_seed_ownership_limb_base][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        air_recurse::CountWitnessViolationsOnH(
            owned_parent.parent_cs, tampered_witness),
        0U);
}

BOOST_AUTO_TEST_CASE(
    four_slot_parent_binding_rejects_alternate_decomposition)
{
    const auto child_cs = ToyFriChildCs();
    const auto ctx = NodeContext();
    // io = (pub, nu, rho, A) excludes the FS transcript, so two child sets must
    // differ in their COMMITTED TRACE (rho) to have different public IO. Set A
    // and set B use different valid boolean traces.
    const std::vector<std::vector<gf::Fp3>>
        columns_a{{
            gf::Fp3::Zero(),
            gf::Fp3::One()}};
    const std::vector<std::vector<gf::Fp3>>
        columns_b{{
            gf::Fp3::One(),
            gf::Fp3::Zero()}};

    // Child set A and its binding parent statement.
    const uint256 seed_a = Seed(0xa7);
    const auto proved_a =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(
            child_cs, columns_a, seed_a, {});
    BOOST_REQUIRE_MESSAGE(proved_a.ok, proved_a.note);
    const std::array<
        FourSlotSelfSimilarCtlParentV1::ChildProof, 4>
        proofs_a{
            proved_a.proof, proved_a.proof,
            proved_a.proof, proved_a.proof};
    const auto statement_a =
        ComputeFourSlotSelfSimilarParentStatementV1(
            child_cs, proofs_a, seed_a, ctx);

    // A DIFFERENT valid child set B (different committed trace -> different rho
    // -> different public IO).
    const uint256 seed_b = Seed(0xb7);
    const auto proved_b =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(
            child_cs, columns_b, seed_b, {});
    BOOST_REQUIRE_MESSAGE(proved_b.ok, proved_b.note);
    const std::array<
        FourSlotSelfSimilarCtlParentV1::ChildProof, 4>
        proofs_b{
            proved_b.proof, proved_b.proof,
            proved_b.proof, proved_b.proof};
    const auto statement_b =
        ComputeFourSlotSelfSimilarParentStatementV1(
            child_cs, proofs_b, seed_b, ctx);

    // The two child sets bind to DIFFERENT parent statements (D3b branch (b)).
    BOOST_CHECK(statement_a != statement_b);

    // Attempting to decompose parent statement A into the alternate child set B
    // must REJECT: it would require AlgHash(tag_io(nu) || enc(io_nu) ||
    // h_c0(B)..h_c3(B)) == statement_A, i.e. an AlgHash collision (~2^-128). A
    // random alternate set does not collide.
    const auto forged =
        BuildFourSlotSelfSimilarCtlParentV1(
            child_cs, proofs_b, seed_b, ctx, statement_a);
    BOOST_CHECK(!forged.valid);
    BOOST_CHECK(
        !forged.parent_statement_equals_child_aggregation);
    BOOST_CHECK(
        forged.computed_parent_statement == statement_b);

    // Child set B under its OWN binding statement is accepted.
    const auto honest_b =
        BuildFourSlotSelfSimilarCtlParentV1(
            child_cs, proofs_b, seed_b, ctx, statement_b);
    BOOST_REQUIRE_MESSAGE(honest_b.valid, honest_b.note);
    BOOST_CHECK(
        honest_b.statement_bound_by_alg_hash_sponge);
    BOOST_CHECK(honest_b.full_child_pubio_absorbed);
}

BOOST_AUTO_TEST_CASE(
    four_slot_parent_rejects_tampered_child_root_lane)
{
    const auto child_cs = ToyFriChildCs();
    const uint256 seed = Seed(0xc5);
    const std::vector<std::vector<gf::Fp3>>
        columns{{
            gf::Fp3::Zero(),
            gf::Fp3::One()}};
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(
            child_cs, columns, seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    const std::array<
        FourSlotSelfSimilarCtlParentV1::ChildProof, 4>
        proofs{
            proved.proof, proved.proof,
            proved.proof, proved.proof};
    const auto ctx = NodeContext();
    const auto statement =
        ComputeFourSlotSelfSimilarParentStatementV1(
            child_cs, proofs, seed, ctx);
    const auto parent =
        BuildFourSlotSelfSimilarCtlParentV1(
            child_cs, proofs, seed, ctx, statement);
    BOOST_REQUIRE_MESSAGE(parent.valid, parent.note);

    // Tampering any sourced child-root lane (the first persistent child-root
    // column at its terminal-lane row) breaks the in-parent sourcing identity.
    const uint32_t child_root_column = parent.vcs_columns + 4;
    auto tampered = parent.parent_witness;
    BOOST_REQUIRE_GT(
        tampered.size(), child_root_column);
    tampered[child_root_column][0] =
        gf::Add(
            tampered[child_root_column][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        air_recurse::CountWitnessViolationsOnH(
            parent.parent_cs, tampered),
        0U);
}

BOOST_AUTO_TEST_CASE(
    four_slot_parent_rejects_tampered_child_ctl_terminal)
{
    const auto child_cs = ToyFriChildCs();
    const uint256 seed = Seed(0xc6);
    const std::vector<std::vector<gf::Fp3>>
        columns{{
            gf::Fp3::Zero(),
            gf::Fp3::One()}};
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(
            child_cs, columns, seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);

    // Forge one child's committed CTL proof (a fold-step opening). The in-parent
    // verifier's fold equations expose it; the parent witness no longer
    // satisfies its constraints, so the whole four-slot parent is rejected.
    auto bad = proved.proof;
    BOOST_REQUIRE(!bad.batch.queries.empty());
    BOOST_REQUIRE(!bad.batch.queries[0].steps.empty());
    bad.batch.queries[0].steps[0].even =
        gf::Add(
            bad.batch.queries[0].steps[0].even,
            gf::Fp3::One());
    const std::array<
        FourSlotSelfSimilarCtlParentV1::ChildProof, 4>
        proofs{
            bad, proved.proof,
            proved.proof, proved.proof};
    const auto ctx = NodeContext();
    // Pin the bad set's OWN binding statement so the sponge passes and the
    // in-parent verifier's fold violation is what rejects (not the digest pin).
    const auto statement =
        ComputeFourSlotSelfSimilarParentStatementV1(
            child_cs, proofs, seed, ctx);
    const auto parent =
        BuildFourSlotSelfSimilarCtlParentV1(
            child_cs, proofs, seed, ctx, statement);
    BOOST_CHECK(!parent.valid);
    BOOST_CHECK_GT(parent.witness_violations, 0U);
    BOOST_CHECK(
        !parent
             .all_four_children_verified_in_parent_air);
    BOOST_CHECK(!parent.self_similar_arity4_shape);
}

// PR-89 rung-4: a recursion parent proves ITSELF via ProveParentOwnFriV1, which
// runs AirQuotientProve<Fp3, AlgB3> over a parent V_CS and round-trips the
// emitted FRI proof through AirQuotientVerify.  This exercises the exact
// production wiring (prove -> verify -> tamper-reject -> wrong-seed-reject) on a
// COMPACT parent V_CS so it advances the scoped closure flag
// parent_own_fri_proof_produced quickly.  The real one-slot / four-slot
// child-verifier parents use the identical call (see the following cases): the
// one-slot fits the cap but its 192-query, ~4.2k-column V_CS is CPU-prohibitive
// to prove in-suite (GPU-integration lane), and the four-slot exceeds the cap.
BOOST_AUTO_TEST_CASE(
    parent_own_fri_wiring_produces_and_verifies_proof)
{
    // A compact multi-column parent-shaped V_CS: booleanity on each column
    // (mirrors the kEverywhere shape of the verifier's boolean lanes), small
    // enough to prove in milliseconds while committing a real batched FRI trace.
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 8;
    cs.n_columns = 6;
    for (uint32_t col = 0; col < cs.n_columns; ++col) {
        aq::AirConstraint<gf::Fp3> boolean;
        boolean.name = "parent_own_fri.compact.boolean";
        boolean.kind = aq::AirKind::kEverywhere;
        boolean.alg_degree = 2;
        boolean.eval =
            [col](const std::vector<gf::Fp3>& r,
                  const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    r[col], gf::Sub(r[col], gf::Fp3::One()));
            };
        cs.constraints.push_back(std::move(boolean));
    }
    // Column-major witness of 0/1 values (satisfies booleanity everywhere).
    std::vector<std::vector<gf::Fp3>> witness(
        cs.n_columns, std::vector<gf::Fp3>(cs.n_rows, gf::Fp3::Zero()));
    for (uint32_t col = 0; col < cs.n_columns; ++col) {
        for (uint32_t row = 0; row < cs.n_rows; ++row) {
            witness[col][row] =
                ((row + col) & 1U) ? gf::Fp3::One() : gf::Fp3::Zero();
        }
    }

    const uint256 seed = Seed(0xd2);
    const auto own = ProveParentOwnFriV1(cs, witness, seed);
    BOOST_REQUIRE_MESSAGE(
        own.parent_own_fri_proof_produced, own.note);
    BOOST_CHECK(own.within_backend_column_cap);
    BOOST_CHECK(own.prove_ok);
    BOOST_CHECK(own.division_exact);
    BOOST_CHECK(own.verify_ok);
    BOOST_CHECK_EQUAL(own.parent_rows, cs.n_rows);
    BOOST_CHECK_EQUAL(own.parent_columns, cs.n_columns);
    // The emitted proof is a real, non-empty batched FRI instance.
    BOOST_CHECK(!own.proof.batch.queries.empty());

    // Round-trip is FS-bound: a different seed must fail (no transcript reuse).
    std::string why;
    BOOST_CHECK(
        (!aq::AirQuotientVerify<gf::Fp3, AlgB3>(
            cs, own.proof, Seed(0xd3), &why)));

    // Tampering a query opening breaks verification: the proof genuinely commits
    // to the parent V_CS trace, it is not a stub.
    auto tampered = own.proof;
    BOOST_REQUIRE(!tampered.batch.queries.empty());
    BOOST_REQUIRE(!tampered.batch.queries[0].steps.empty());
    tampered.batch.queries[0].steps[0].even =
        gf::Add(
            tampered.batch.queries[0].steps[0].even,
            gf::Fp3::One());
    BOOST_CHECK(
        (!aq::AirQuotientVerify<gf::Fp3, AlgB3>(
            cs, tampered, seed, &why)));
}

// The reduced-arity (one active + three padding) normalized-FRI parent is a real
// recursion node whose V_CS fits the alg column cap.  Building it and confirming
// the fit is cheap; the actual self-prove of its ~4.2k-column, 192-query V_CS is
// CPU-prohibitive in-suite (>20 min) and is the GPU-integration lane's concern,
// so the heavy prove runs only under BTX_RUN_HEAVY_PARENT_FRI.
BOOST_AUTO_TEST_CASE(
    one_slot_reduced_parent_is_a_capfitting_recursion_node)
{
    const auto child_cs = ToyFriChildCs();
    const uint256 seed = Seed(0xd4);
    const std::vector<std::vector<gf::Fp3>>
        columns{{
            gf::Fp3::Zero(),
            gf::Fp3::One()}};
    const auto proved_child =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(
            child_cs, columns, seed, {});
    BOOST_REQUIRE_MESSAGE(proved_child.ok, proved_child.note);

    const auto root =
        ComputeOneSlotNormalizedFriParentOutputRootV1(
            child_cs, proved_child.proof, seed);
    BOOST_REQUIRE(root != alg_hash::Digest{});
    const auto parent =
        BuildOneSlotNormalizedFriParentV1(
            child_cs, proved_child.proof, seed, root);
    BOOST_REQUIRE_MESSAGE(parent.valid, parent.note);

    BOOST_TEST_MESSAGE(
        "ONE_SLOT_SHAPE rows=" << parent.parent_rows
        << " columns=" << parent.parent_columns
        << " vcs_columns=" << parent.vcs_columns);
    // Real recursion node, and its V_CS fits the alg batch column cap.
    BOOST_CHECK_LE(parent.parent_columns, 16384U);

    if (std::getenv("BTX_RUN_HEAVY_PARENT_FRI") != nullptr) {
        const auto own =
            ProveOneSlotNormalizedFriParentOwnFriV1(
                parent, Seed(0xd5));
        BOOST_REQUIRE_MESSAGE(
            own.parent_own_fri_proof_produced, own.note);
        BOOST_CHECK(own.within_backend_column_cap);
        BOOST_CHECK(own.prove_ok);
        BOOST_CHECK(own.verify_ok);
        BOOST_CHECK(!own.proof.batch.queries.empty());
    }
}

// PR-89 rung-4 (cap raised 2^14 -> 2^15): the FULL arity-4 four-slot parent
// verifies four 192-query FRI children in-AIR; even at the toy child shape that
// V_CS is ~16996 columns.  With kRCFri3AlgBatchMaxColumns = 2^15 = 32768 it now
// FITS the AirFriBackendAlg cap, so the full-arity parent can commit its OWN FRI
// proof.  The cap-fit is asserted cheaply always; the actual self-prove of the
// ~17k-column, 192-query four-slot V_CS is CPU-heavy (tens of minutes) and runs
// only under BTX_RUN_HEAVY_PARENT_FRI (GPU-integration lane owns full shape).
BOOST_AUTO_TEST_CASE(
    four_slot_self_similar_parent_own_fri_fits_alg_column_cap)
{
    const auto child_cs = ToyFriChildCs();
    const uint256 seed = Seed(0xe1);
    const std::vector<std::vector<gf::Fp3>>
        columns{{
            gf::Fp3::Zero(),
            gf::Fp3::One()}};
    const auto proved_child =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(
            child_cs, columns, seed, {});
    BOOST_REQUIRE_MESSAGE(proved_child.ok, proved_child.note);

    const std::array<
        FourSlotSelfSimilarCtlParentV1::ChildProof, 4>
        proofs{
            proved_child.proof, proved_child.proof,
            proved_child.proof, proved_child.proof};
    const auto ctx = NodeContext();
    const auto statement =
        ComputeFourSlotSelfSimilarParentStatementV1(
            child_cs, proofs, seed, ctx);
    const auto parent =
        BuildFourSlotSelfSimilarCtlParentV1(
            child_cs, proofs, seed, ctx, statement);
    BOOST_REQUIRE_MESSAGE(parent.valid, parent.note);
    // The builder itself still never claims to have proven the parent.
    BOOST_CHECK(!parent.parent_own_fri_proof_produced);

    BOOST_TEST_MESSAGE(
        "FOUR_SLOT_SHAPE rows=" << parent.parent_rows
        << " columns=" << parent.parent_columns
        << " vcs_columns=" << parent.vcs_columns
        << " cap=" << 32768U);
    // ~16996 columns: over the old 2^14 cap, under the new 2^15 cap.
    BOOST_CHECK_GT(parent.parent_columns, 16384U);
    BOOST_CHECK_LE(parent.parent_columns, 32768U);

    if (std::getenv("BTX_RUN_HEAVY_PARENT_FRI") != nullptr) {
        const uint256 parent_seed = Seed(0xe2);
        const auto own =
            ProveFourSlotSelfSimilarParentOwnFriV1(
                parent, parent_seed);
        // Full-arity four-slot parent now produces AND verifies its own proof.
        BOOST_REQUIRE_MESSAGE(
            own.parent_own_fri_proof_produced, own.note);
        BOOST_CHECK(own.within_backend_column_cap);
        BOOST_CHECK(own.prove_ok);
        BOOST_CHECK(own.division_exact);
        BOOST_CHECK(own.verify_ok);
        BOOST_CHECK(!own.proof.batch.queries.empty());
        // FS-bound + tamper-sensitive, same as the reduced-shape node.
        std::string why;
        BOOST_CHECK(
            (!aq::AirQuotientVerify<gf::Fp3, AlgB3>(
                parent.parent_cs, own.proof, Seed(0xe3), &why)));
        auto tampered = own.proof;
        BOOST_REQUIRE(!tampered.batch.queries.empty());
        BOOST_REQUIRE(!tampered.batch.queries[0].steps.empty());
        tampered.batch.queries[0].steps[0].even =
            gf::Add(
                tampered.batch.queries[0].steps[0].even,
                gf::Fp3::One());
        BOOST_CHECK(
            (!aq::AirQuotientVerify<gf::Fp3, AlgB3>(
                parent.parent_cs, tampered, parent_seed, &why)));
    }
}

// A parent that fails in-AIR child verification has no honest quotient and must
// not be presented as a provable recursion node.
BOOST_AUTO_TEST_CASE(
    four_slot_parent_own_fri_refused_when_parent_not_in_air_valid)
{
    const auto child_cs = ToyFriChildCs();
    const uint256 seed = Seed(0xd4);
    const std::vector<std::vector<gf::Fp3>>
        columns{{
            gf::Fp3::Zero(),
            gf::Fp3::One()}};
    const auto proved_child =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(
            child_cs, columns, seed, {});
    BOOST_REQUIRE_MESSAGE(proved_child.ok, proved_child.note);

    auto bad = proved_child.proof;
    BOOST_REQUIRE(!bad.batch.queries.empty());
    BOOST_REQUIRE(!bad.batch.queries[0].steps.empty());
    bad.batch.queries[0].steps[0].even =
        gf::Add(
            bad.batch.queries[0].steps[0].even,
            gf::Fp3::One());
    const std::array<
        FourSlotSelfSimilarCtlParentV1::ChildProof, 4>
        proofs{
            bad, proved_child.proof,
            proved_child.proof, proved_child.proof};
    const auto ctx = NodeContext();
    const auto statement =
        ComputeFourSlotSelfSimilarParentStatementV1(
            child_cs, proofs, seed, ctx);
    const auto parent =
        BuildFourSlotSelfSimilarCtlParentV1(
            child_cs, proofs, seed, ctx, statement);
    BOOST_REQUIRE(!parent.valid);
    BOOST_CHECK_GT(parent.witness_violations, 0U);

    const auto own =
        ProveFourSlotSelfSimilarParentOwnFriV1(
            parent, Seed(0xd5));
    BOOST_CHECK(!own.parent_own_fri_proof_produced);
    BOOST_CHECK(!own.prove_ok);
}

// DIAGNOSTIC (GPU-migration lane): dump the exact parent V_CS composition
// inventory — constraint count, family histogram, degree histogram — and time a
// full composition pass over the trace rows so the CPU baseline and the
// bytecode-migration surface are concrete measured numbers.
BOOST_AUTO_TEST_CASE(parent_composition_inventory_diag)
{
    const auto child_cs = ToyFriChildCs();
    const uint256 seed = Seed(0xe1);
    const std::vector<std::vector<gf::Fp3>>
        columns{{gf::Fp3::Zero(), gf::Fp3::One()}};
    const auto proved_child =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(
            child_cs, columns, seed, {});
    BOOST_REQUIRE_MESSAGE(proved_child.ok, proved_child.note);
    const std::array<
        FourSlotSelfSimilarCtlParentV1::ChildProof, 4>
        proofs{proved_child.proof, proved_child.proof,
               proved_child.proof, proved_child.proof};
    const auto ctx = NodeContext();
    const auto statement =
        ComputeFourSlotSelfSimilarParentStatementV1(
            child_cs, proofs, seed, ctx);
    const auto parent =
        BuildFourSlotSelfSimilarCtlParentV1(
            child_cs, proofs, seed, ctx, statement);
    BOOST_REQUIRE_MESSAGE(parent.valid, parent.note);

    const auto& cs = parent.parent_cs;
    BOOST_TEST_MESSAGE(
        "PARENT_INVENTORY rows=" << cs.n_rows
        << " columns=" << cs.n_columns
        << " constraints=" << cs.constraints.size());

    // Family histogram by name prefix (up to the 3rd dot) + degree histogram.
    std::map<std::string, uint32_t> fam;
    std::map<uint32_t, uint32_t> deg;
    uint32_t max_deg = 0;
    for (const auto& con : cs.constraints) {
        std::string key = con.name;
        size_t dot = 0;
        for (int i = 0; i < 3 && dot != std::string::npos; ++i) {
            size_t n = key.find('.', dot);
            if (n == std::string::npos) break;
            dot = n + 1;
        }
        if (dot > 0 && dot != std::string::npos && dot <= key.size())
            key = key.substr(0, dot - 1);
        fam[key]++;
        deg[con.alg_degree]++;
        max_deg = std::max(max_deg, con.alg_degree);
    }
    for (const auto& [k, v] : fam)
        BOOST_TEST_MESSAGE("  FAM " << k << " = " << v);
    for (const auto& [d, v] : deg)
        BOOST_TEST_MESSAGE("  DEG " << d << " = " << v);
    BOOST_TEST_MESSAGE("  MAX_DEG " << max_deg);

    // Time a full composition pass over the trace rows: for every row r and
    // every constraint, evaluate con.eval(row_r, row_{r+1}). This is the exact
    // per-point work the quotient prover does (it does it over the blown-up LDE
    // domain; here over the 256 trace rows to get a per-eval cost).
    const uint32_t R = cs.n_rows;
    std::vector<std::vector<gf::Fp3>> rows(
        R, std::vector<gf::Fp3>(cs.n_columns, gf::Fp3::Zero()));
    for (uint32_t c = 0; c < cs.n_columns && c < parent.parent_witness.size(); ++c)
        for (uint32_t r = 0; r < R; ++r)
            rows[r][c] = parent.parent_witness[c][r];

    gf::Fp3 acc = gf::Fp3::Zero();
    const auto t0 = std::chrono::steady_clock::now();
    for (uint32_t r = 0; r < R; ++r) {
        const auto& cur = rows[r];
        const auto& nxt = rows[(r + 1) % R];
        for (const auto& con : cs.constraints)
            acc = gf::Add(acc, con.eval(cur, nxt));
    }
    const auto t1 = std::chrono::steady_clock::now();
    const double ms =
        std::chrono::duration<double, std::milli>(t1 - t0).count();
    const uint64_t evals =
        uint64_t{R} * cs.constraints.size();
    BOOST_TEST_MESSAGE(
        "COMPOSITION_PASS trace_rows=" << R
        << " evals=" << evals
        << " ms=" << ms
        << " ns_per_eval=" << (ms * 1e6 / double(evals))
        << " acc_c0=" << gf::Canonical(acc.c0));
    // Project the real prove: LDE domain M=2^17 vs 256 trace rows = 512x, and
    // AirQuotientProve evaluates the composition on that blown-up domain.
    BOOST_TEST_MESSAGE(
        "COMPOSITION_LDE_PROJECTION M=131072 "
        "projected_full_eval_ms="
        << (ms * (131072.0 / double(R))));
}

// GPU-MIGRATION lane: migrate the parent composition's DOMINANT family
// (recurse.perm.sbox — 14750 of 16682 = 88.4%, degree 7) to constraint bytecode
// and differential-test it BIT-IDENTICALLY vs the native air_recurse closures,
// then emit a .bc for the CUDA VM (vm_gpu) GPU-parity check. This is the exact
// analog of the proven poseidon-472 POSEIDON_QUOTIENT_PARITY, but on the parent
// relation's own S-box (one degree-7 program per S-box, no aux decomposition).
BOOST_AUTO_TEST_CASE(parent_perm_sbox_bytecode_gpu_parity)
{
    namespace cb = constraint_bytecode;
    namespace ar = air_recurse;
    using gf::Fp3;

    const ar::PermLayout layout{0};
    const uint32_t width = ar::kPermCellsPerPerm; // 130
    const auto native = ar::BuildPermRoundConstraints(layout);
    BOOST_REQUIRE_EQUAL(native.size(), ar::kPermSboxCells);

    // Recover the affine S-box input A_s over the 130 cells by unit-vector
    // probing the public PermSboxInput evaluator (base-field coeffs embed in
    // Fp3), exactly as poseidon_bytecode::RecoverAffine does.
    auto emit_const = [](std::vector<cb::Instruction>& ins, const Fp3& v) {
        cb::Instruction i; i.opcode = cb::Opcode::Constant; i.constant = v;
        ins.push_back(i); return uint32_t(ins.size()) - 1;
    };
    auto emit_load = [](std::vector<cb::Instruction>& ins, uint32_t col) {
        cb::Instruction i; i.opcode = cb::Opcode::Current; i.lhs = col;
        ins.push_back(i); return uint32_t(ins.size()) - 1;
    };
    auto emit_bin = [](std::vector<cb::Instruction>& ins, cb::Opcode op,
                       uint32_t l, uint32_t r) {
        cb::Instruction i; i.opcode = op; i.lhs = l; i.rhs = r;
        ins.push_back(i); return uint32_t(ins.size()) - 1;
    };

    cb::ProgramTable table;
    table.version = cb::kConstraintBytecodeVersion;
    table.role = RCStage3RelationRole::CompositionLink;
    table.current_width = width;
    table.next_width = 0;
    table.challenge_width = 0;

    std::vector<Fp3> zero(width, Fp3::Zero());
    for (uint32_t s = 0; s < ar::kPermSboxCells; ++s) {
        const Fp3 c0 = ar::PermSboxInput(layout, zero, s);
        cb::Program p;
        p.version = cb::kConstraintBytecodeVersion;
        p.role = RCStage3RelationRole::CompositionLink;
        p.constraint_ordinal = s;
        p.kind = aq::AirKind::kEverywhere;
        p.declared_degree = 7;
        p.current_width = width;
        p.next_width = 0;
        p.challenge_width = 0;
        uint32_t acc = emit_const(p.instructions, c0);
        for (uint32_t col = 0; col < width; ++col) {
            std::vector<Fp3> e = zero; e[col] = Fp3::One();
            const Fp3 coeff = gf::Sub(ar::PermSboxInput(layout, e, s), c0);
            if (gf::IsZero(coeff)) continue;
            const uint32_t k = emit_const(p.instructions, coeff);
            const uint32_t x = emit_load(p.instructions, col);
            const uint32_t t = emit_bin(p.instructions, cb::Opcode::Mul, k, x);
            acc = emit_bin(p.instructions, cb::Opcode::Add, acc, t);
        }
        // x^7 = ((x2)^2)*(x2*x)  == x4*x3, matching Pow7Ext exactly.
        const uint32_t x2 = emit_bin(p.instructions, cb::Opcode::Mul, acc, acc);
        const uint32_t x3 = emit_bin(p.instructions, cb::Opcode::Mul, x2, acc);
        const uint32_t x4 = emit_bin(p.instructions, cb::Opcode::Mul, x2, x2);
        const uint32_t x7 = emit_bin(p.instructions, cb::Opcode::Mul, x4, x3);
        const uint32_t y = emit_load(p.instructions, layout.SboxCol(s));
        emit_bin(p.instructions, cb::Opcode::Sub, y, x7);
        table.programs.push_back(std::move(p));
    }
    std::string why;
    BOOST_REQUIRE_MESSAGE(cb::ValidateProgramTable(table, &why), why);

    // CPU DIFFERENTIAL TEST: bytecode == native closure, bit-for-bit.
    const std::vector<Fp3> empty_next;
    auto rnd = [](uint32_t w, uint64_t seed) {
        std::vector<Fp3> row(w);
        uint64_t st = seed;
        auto nx = [&st]() {
            st += 0x9e3779b97f4a7c15ULL;
            uint64_t z = st;
            z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
            z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
            return gf::FromU64(z ^ (z >> 31));
        };
        for (auto& c : row) c = Fp3{nx(), nx(), nx()};
        return row;
    };
    const uint32_t R = 64;
    std::vector<std::vector<Fp3>> rows;
    uint64_t mism = 0, total = 0;
    for (uint32_t r = 0; r < R; ++r) {
        rows.push_back(rnd(width, (r + 1) * 0xd1342543de82ef95ULL));
        for (uint32_t s = 0; s < table.programs.size(); ++s) {
            Fp3 got;
            BOOST_REQUIRE(cb::EvaluateProgram(
                table.programs[s], rows.back(), empty_next, got, &why));
            const Fp3 want = native[s].eval(rows.back(), rows.back());
            ++total;
            if (!gf::Eq(got, want)) ++mism;
        }
    }
    BOOST_TEST_MESSAGE(
        "PARENT_SBOX_VM_PARITY programs=" << table.programs.size()
        << " rows=" << R << " evals=" << total
        << " mismatches=" << mism);
    BOOST_CHECK_EQUAL(mism, 0U);

    // Emit .bc for the CUDA VM (vm_gpu) in the same ASCII format as poseidon.bc:
    // "P CW NW R", then per program "P ninstr" + "op lhs rhs k0 k1 k2", then the
    // R*(CW+NW) row Fp3 limbs, then P*R golden EvaluateProgram Fp3 limbs.
    const char* out = std::getenv("BTX_PARENT_SBOX_BC");
    if (out != nullptr) {
        FILE* f = std::fopen(out, "w");
        BOOST_REQUIRE(f != nullptr);
        std::fprintf(f, "%zu %u 0 %u\n", table.programs.size(), width, R);
        for (const auto& p : table.programs) {
            std::fprintf(f, "P %zu\n", p.instructions.size());
            for (const auto& in : p.instructions)
                std::fprintf(f, "%d %u %u %llu %llu %llu\n",
                             int(in.opcode), in.lhs, in.rhs,
                             (unsigned long long)gf::Canonical(in.constant.c0),
                             (unsigned long long)gf::Canonical(in.constant.c1),
                             (unsigned long long)gf::Canonical(in.constant.c2));
        }
        for (uint32_t r = 0; r < R; ++r)
            for (uint32_t c = 0; c < width; ++c)
                std::fprintf(f, "%llu %llu %llu\n",
                             (unsigned long long)gf::Canonical(rows[r][c].c0),
                             (unsigned long long)gf::Canonical(rows[r][c].c1),
                             (unsigned long long)gf::Canonical(rows[r][c].c2));
        for (uint32_t s = 0; s < table.programs.size(); ++s)
            for (uint32_t r = 0; r < R; ++r) {
                Fp3 got; cb::EvaluateProgram(
                    table.programs[s], rows[r], empty_next, got, &why);
                std::fprintf(f, "%llu %llu %llu\n",
                             (unsigned long long)gf::Canonical(got.c0),
                             (unsigned long long)gf::Canonical(got.c1),
                             (unsigned long long)gf::Canonical(got.c2));
            }
        std::fclose(f);
        BOOST_TEST_MESSAGE("PARENT_SBOX_BC_WRITTEN " << out);
    }
}

// Support-size / next-usage histogram per degree: decides recovery tractability
// for the full-composition bytecode synthesis.
BOOST_AUTO_TEST_CASE(parent_support_histogram_diag)
{
    using gf::Fp3;
    const auto child_cs = ToyFriChildCs();
    const uint256 seed = Seed(0xe1);
    const std::vector<std::vector<Fp3>> columns{{Fp3::Zero(), Fp3::One()}};
    const auto pc = aq::AirQuotientProve<gf::Fp3, AlgB3>(child_cs, columns, seed, {});
    BOOST_REQUIRE(pc.ok);
    const std::array<FourSlotSelfSimilarCtlParentV1::ChildProof, 4>
        proofs{pc.proof, pc.proof, pc.proof, pc.proof};
    const auto ctx = NodeContext();
    const auto st = ComputeFourSlotSelfSimilarParentStatementV1(child_cs, proofs, seed, ctx);
    const auto parent = BuildFourSlotSelfSimilarCtlParentV1(child_cs, proofs, seed, ctx, st);
    BOOST_REQUIRE(parent.valid);
    const auto& cs = parent.parent_cs;
    const uint32_t W = cs.n_columns;

    auto splitmix = [](uint64_t& s) {
        s += 0x9e3779b97f4a7c15ULL; uint64_t z = s;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return gf::FromU64(z ^ (z >> 31));
    };
    auto rrow = [&](uint64_t sd) {
        std::vector<Fp3> r(W); uint64_t s = sd;
        for (auto& c : r) c = Fp3{splitmix(s), splitmix(s), splitmix(s)};
        return r;
    };
    // Two random bases; a column is "support" if changing it (to another random
    // value) changes the output on either base. next-usage: does a fully random
    // next row differ from a zero next row?
    const std::vector<Fp3> b1 = rrow(11), b2 = rrow(22);
    const std::vector<Fp3> nz(W, Fp3::Zero()), nr = rrow(33);
    std::map<uint32_t, std::map<uint32_t, uint32_t>> hist; // degree -> supportsize -> count
    std::map<uint32_t, uint32_t> next_used; // degree -> count using next
    uint32_t idx = 0;
    for (const auto& con : cs.constraints) {
        const bool usesnext =
            !gf::Eq(con.eval(b1, nz), con.eval(b1, nr));
        if (usesnext) next_used[con.alg_degree]++;
        uint32_t sup = 0;
        const Fp3 f1 = con.eval(b1, nz), f2 = con.eval(b2, nz);
        for (uint32_t c = 0; c < W; ++c) {
            auto t1 = b1; t1[c] = Fp3{gf::FromU64(0x1234 + c), gf::FromU64(7), gf::FromU64(3)};
            auto t2 = b2; t2[c] = Fp3{gf::FromU64(0x9abc + c), gf::FromU64(5), gf::FromU64(9)};
            if (!gf::Eq(con.eval(t1, nz), f1) || !gf::Eq(con.eval(t2, nz), f2)) ++sup;
        }
        hist[con.alg_degree][sup]++;
        if (++idx % 2000 == 0) BOOST_TEST_MESSAGE("  probed " << idx);
    }
    for (const auto& [deg, m] : hist) {
        uint32_t maxs = 0, tot = 0;
        for (const auto& [s, c] : m) { maxs = std::max(maxs, s); tot += c; }
        BOOST_TEST_MESSAGE("DEG " << deg << " constraints=" << tot
            << " next_used=" << next_used[deg] << " max_support=" << maxs);
        for (const auto& [s, c] : m)
            BOOST_TEST_MESSAGE("    support=" << s << " count=" << c);
    }
}

// FULL parent composition -> bytecode, family-agnostic black-box synthesis from
// the assembled BuildAggregateWitness closures, differential-tested bit-identical
// vs the native closure (item 2), and emitted as a .bc for the GPU VM (item 3).
//   - degree 7  : S-box `y - A(cur)^7`, A affine recovered by unique 7th roots
//                 (x^7 is a bijection on Fp3: 7 does not divide p^3-1).
//   - degree<=3 : general polynomial recovered by Vandermonde solve over the
//                 detected support (bit-exact for any total-degree-<=d poly).
// A constraint is UNRESOLVED only if its (support,degree) monomial count exceeds
// the solve cap; those are reported precisely, not silently dropped.
BOOST_AUTO_TEST_CASE(parent_full_composition_bytecode_gpu_parity)
{
    namespace cb = constraint_bytecode;
    using gf::Fp3;

    const auto child_cs = ToyFriChildCs();
    const uint256 seed = Seed(0xe1);
    const std::vector<std::vector<Fp3>> columns{{Fp3::Zero(), Fp3::One()}};
    const auto pc = aq::AirQuotientProve<gf::Fp3, AlgB3>(child_cs, columns, seed, {});
    BOOST_REQUIRE(pc.ok);
    const std::array<FourSlotSelfSimilarCtlParentV1::ChildProof, 4>
        proofs{pc.proof, pc.proof, pc.proof, pc.proof};
    const auto ctx = NodeContext();
    const auto stmt = ComputeFourSlotSelfSimilarParentStatementV1(child_cs, proofs, seed, ctx);
    const auto parent = BuildFourSlotSelfSimilarCtlParentV1(child_cs, proofs, seed, ctx, stmt);
    BOOST_REQUIRE(parent.valid);
    const auto& cs = parent.parent_cs;
    const uint32_t W = cs.n_columns;

    auto smix = [](uint64_t& s) {
        s += 0x9e3779b97f4a7c15ULL; uint64_t z = s;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return gf::FromU64(z ^ (z >> 31));
    };
    auto rrow = [&](uint64_t sd) {
        std::vector<Fp3> r(W); uint64_t s = sd;
        for (auto& c : r) c = Fp3{smix(s), smix(s), smix(s)};
        return r;
    };
    const std::vector<Fp3> ZN(W, Fp3::Zero());

    // Unique 7th root on Fp3: x^e7, e7 = 7^{-1} mod (p^3-1), 192-bit LE limbs.
    auto root7 = [](Fp3 x) {
        static const uint64_t E7[3] = {
            0xdb6db6d9b6db6db7ULL, 0xb6db6db2db6db6deULL, 0x9249249092492495ULL};
        Fp3 r = Fp3::One();
        for (int i = 191; i >= 0; --i) {
            r = gf::Mul(r, r);
            if ((E7[i >> 6] >> (i & 63)) & 1ULL) r = gf::Mul(r, x);
        }
        return r;
    };
    { // sanity: root7 inverts x^7
        const Fp3 x{gf::FromU64(123456789), gf::FromU64(2468), gf::FromU64(13)};
        const Fp3 x2 = gf::Mul(x, x), x3 = gf::Mul(x2, x), x4 = gf::Mul(x2, x2);
        BOOST_REQUIRE(gf::Eq(root7(gf::Mul(x4, x3)), x));
    }

    auto ld = [](std::vector<cb::Instruction>& ins, bool nxt, uint32_t col) {
        cb::Instruction i; i.opcode = nxt ? cb::Opcode::Next : cb::Opcode::Current;
        i.lhs = col; ins.push_back(i); return uint32_t(ins.size()) - 1;
    };
    auto kc = [](std::vector<cb::Instruction>& ins, const Fp3& v) {
        cb::Instruction i; i.opcode = cb::Opcode::Constant; i.constant = v;
        ins.push_back(i); return uint32_t(ins.size()) - 1;
    };
    auto bin = [](std::vector<cb::Instruction>& ins, cb::Opcode op, uint32_t a, uint32_t b) {
        cb::Instruction i; i.opcode = op; i.lhs = a; i.rhs = b;
        ins.push_back(i); return uint32_t(ins.size()) - 1;
    };

    struct Var { bool nxt; uint32_t col; };
    // random probe values for support detection
    auto probeval = [&](uint32_t c, uint32_t k) {
        return Fp3{gf::FromU64(0x1000003U * (c + 1) + 7 * k + 1),
                   gf::FromU64(11 * k + 3), gf::FromU64(5 * k + 2)};
    };

    const std::vector<Fp3> B[3] = {rrow(101), rrow(202), rrow(303)};
    const uint32_t kMonomialCap = 5000; // Vandermonde solve cap

    cb::ProgramTable table;
    table.version = cb::kConstraintBytecodeVersion;
    table.role = RCStage3RelationRole::CompositionLink;
    table.current_width = W;
    table.next_width = W;
    table.challenge_width = 0;

    uint32_t n_deg1 = 0, n_solve = 0, n_sbox = 0, n_unresolved = 0, n_zero = 0;
    uint32_t max_support = 0, max_monomials = 0;
    std::vector<uint32_t> unresolved_ord;
    std::vector<uint32_t> sup_sz(cs.constraints.size(), 0);
    std::vector<uint8_t> nxt_used(cs.constraints.size(), 0);

    for (uint32_t ord = 0; ord < cs.constraints.size(); ++ord) {
        const auto& con = cs.constraints[ord];
        // next usage
        bool uses_next = false;
        for (int b = 0; b < 3 && !uses_next; ++b) {
            auto nr = rrow(9000 + b);
            if (!gf::Eq(con.eval(B[b], ZN), con.eval(B[b], nr))) uses_next = true;
        }
        // support via divide-and-conquer: O(support * log W) closure evals.
        // depends(nxt,lo,hi): does con change when cols [lo,hi) of the chosen
        // row (cur or next) are perturbed to random, others at base?
        std::vector<Var> sup;
        // Use nonzero values in BOTH rows so cross cur*next terms are detected.
        const std::vector<Fp3> NB[3] = {rrow(5001), rrow(5002), rrow(5003)};
        auto depends = [&](bool nxt, uint32_t lo, uint32_t hi) {
            for (int trial = 0; trial < 2; ++trial) {
                for (int b = 0; b < 3; ++b) {
                    auto cur = B[b];
                    auto nx = NB[b];
                    const Fp3 f0 = con.eval(cur, nx);
                    auto& tgt = nxt ? nx : cur;
                    uint64_t sd = 0xabc + lo * 131 + hi * 17 + trial * 999 + b * 7;
                    for (uint32_t c = lo; c < hi; ++c) tgt[c] = Fp3{smix(sd), smix(sd), smix(sd)};
                    if (!gf::Eq(con.eval(cur, nx), f0)) return true;
                }
            }
            return false;
        };
        std::function<void(bool, uint32_t, uint32_t)> dc =
            [&](bool nxt, uint32_t lo, uint32_t hi) {
                if (hi <= lo || !depends(nxt, lo, hi)) return;
                if (hi - lo == 1) { sup.push_back({nxt, lo}); return; }
                uint32_t mid = lo + (hi - lo) / 2;
                dc(nxt, lo, mid); dc(nxt, mid, hi);
            };
        dc(false, 0, W);
        if (uses_next) dc(true, 0, W);
        max_support = std::max<uint32_t>(max_support, (uint32_t)sup.size());
        sup_sz[ord] = (uint32_t)sup.size();
        nxt_used[ord] = uses_next ? 1 : 0;

        cb::Program p;
        p.version = cb::kConstraintBytecodeVersion;
        p.role = RCStage3RelationRole::CompositionLink;
        p.constraint_ordinal = ord;
        p.kind = con.kind;
        p.current_width = W;
        p.next_width = W;
        p.challenge_width = 0;
        auto& ins = p.instructions;
        uint32_t declared = 1;

        if (con.alg_degree == 7) {
            // Identify y (the SboxCol): con = y - A^7, so slope wrt y is EXACTLY
            // 1 at every point: con(row + delta*e_y) - con(row) == delta. No
            // A-column has this, so it is a strong unique discriminator.
            // slope==1 discriminator using the already-generated bases B/NB
            // (no per-candidate full-row regeneration).
            int yidx = -1;
            for (uint32_t vi = 0; vi < sup.size() && yidx < 0; ++vi) {
                bool is_y = true;
                uint64_t sd = 0x5eed + ord * 7 + vi;
                for (int b = 0; b < 3 && is_y; ++b) {
                    auto cur = B[b]; auto nx = NB[b];
                    const Fp3 f0 = con.eval(cur, nx);
                    const Fp3 delta{smix(sd), smix(sd), smix(sd)};
                    auto& tgt = sup[vi].nxt ? nx : cur;
                    tgt[sup[vi].col] = gf::Add(tgt[sup[vi].col], delta);
                    if (!gf::Eq(gf::Sub(con.eval(cur, nx), f0), delta)) is_y = false;
                }
                if (is_y) yidx = int(vi);
            }
            BOOST_REQUIRE_MESSAGE(yidx >= 0, "sbox y not found ord=" << ord);
            const Var yv = sup[yidx];
            // Build zeroed row helper (all zero); A(zero)=a0, con = y - A^7 with y=0 => a0=root7(-con).
            auto evalz = [&](const std::vector<Var>& setvars, const std::vector<Fp3>& vals) {
                auto cur = ZN; auto nx = ZN;
                for (uint32_t i = 0; i < setvars.size(); ++i)
                    (setvars[i].nxt ? nx : cur)[setvars[i].col] = vals[i];
                return con.eval(cur, nx);
            };
            const Fp3 a0 = root7(gf::Sub(Fp3::Zero(), evalz({}, {})));
            // Emit affine acc, then ^7, then y - acc^7.
            uint32_t acc = kc(ins, a0);
            for (uint32_t vi = 0; vi < sup.size(); ++vi) {
                if (int(vi) == yidx) continue;
                const Fp3 v1 = root7(gf::Sub(Fp3::Zero(), evalz({sup[vi]}, {Fp3::One()})));
                const Fp3 ai = gf::Sub(v1, a0);
                if (gf::IsZero(ai)) continue;
                const uint32_t k = kc(ins, ai);
                const uint32_t x = ld(ins, sup[vi].nxt, sup[vi].col);
                acc = bin(ins, cb::Opcode::Add, acc, bin(ins, cb::Opcode::Mul, k, x));
            }
            const uint32_t x2 = bin(ins, cb::Opcode::Mul, acc, acc);
            const uint32_t x3 = bin(ins, cb::Opcode::Mul, x2, acc);
            const uint32_t x4 = bin(ins, cb::Opcode::Mul, x2, x2);
            const uint32_t x7 = bin(ins, cb::Opcode::Mul, x4, x3);
            const uint32_t y = ld(ins, yv.nxt, yv.col);
            bin(ins, cb::Opcode::Sub, y, x7);
            declared = 7;
            ++n_sbox;
        } else {
            const uint32_t d = std::min<uint32_t>(con.alg_degree, 3);
            const uint32_t k = sup.size();
            // enumerate monomials as sorted multisets of var-indices, size 0..d
            std::vector<std::vector<uint32_t>> mons;
            mons.push_back({});
            std::function<void(uint32_t, std::vector<uint32_t>&)> gen =
                [&](uint32_t start, std::vector<uint32_t>& cur2) {
                    if (cur2.size() == d) return;
                    for (uint32_t v = start; v < k; ++v) {
                        cur2.push_back(v);
                        mons.push_back(cur2);
                        gen(v, cur2);
                        cur2.pop_back();
                    }
                };
            { std::vector<uint32_t> tmp; if (k > 0) gen(0, tmp); }
            const uint32_t M = mons.size();
            max_monomials = std::max(max_monomials, M);
            if (M > kMonomialCap) {
                ++n_unresolved; unresolved_ord.push_back(ord);
                // emit placeholder zero (won't be parity-correct; flagged)
                bin(ins, cb::Opcode::Mul, kc(ins, Fp3::Zero()), ld(ins, false, 0));
                declared = 1;
                table.programs.push_back(std::move(p));
                continue;
            }
            // Vandermonde: M random sample points on support, solve A c = b.
            std::vector<std::vector<Fp3>> A(M, std::vector<Fp3>(M));
            std::vector<Fp3> rhs(M);
            uint64_t sd = 0x51ed270b + ord * 2654435761u;
            for (uint32_t r = 0; r < M; ++r) {
                std::vector<Fp3> val(k);
                auto cur = ZN; auto nx = ZN;
                for (uint32_t v = 0; v < k; ++v) {
                    val[v] = Fp3{smix(sd), smix(sd), smix(sd)};
                    (sup[v].nxt ? nx : cur)[sup[v].col] = val[v];
                }
                rhs[r] = con.eval(cur, nx);
                for (uint32_t m = 0; m < M; ++m) {
                    Fp3 pv = Fp3::One();
                    for (uint32_t vi : mons[m]) pv = gf::Mul(pv, val[vi]);
                    A[r][m] = pv;
                }
            }
            // Gaussian elimination over Fp3
            std::vector<Fp3> coef(M, Fp3::Zero());
            bool ok = true;
            for (uint32_t col = 0; col < M && ok; ++col) {
                uint32_t piv = col;
                while (piv < M && gf::IsZero(A[piv][col])) ++piv;
                if (piv == M) { ok = false; break; }
                std::swap(A[piv], A[col]); std::swap(rhs[piv], rhs[col]);
                const Fp3 invp = gf::Inv(A[col][col]);
                for (uint32_t j = col; j < M; ++j) A[col][j] = gf::Mul(A[col][j], invp);
                rhs[col] = gf::Mul(rhs[col], invp);
                for (uint32_t r = 0; r < M; ++r) {
                    if (r == col || gf::IsZero(A[r][col])) continue;
                    const Fp3 f = A[r][col];
                    for (uint32_t j = col; j < M; ++j)
                        A[r][j] = gf::Sub(A[r][j], gf::Mul(f, A[col][j]));
                    rhs[r] = gf::Sub(rhs[r], gf::Mul(f, rhs[col]));
                }
            }
            BOOST_REQUIRE_MESSAGE(ok, "singular vandermonde ord=" << ord << " M=" << M);
            for (uint32_t m = 0; m < M; ++m) coef[m] = rhs[m];
            // Emit sum coef_m * prod(vars in mon_m); track max degree.
            int acc = -1;
            for (uint32_t m = 0; m < M; ++m) {
                if (gf::IsZero(coef[m])) continue;
                declared = std::max<uint32_t>(declared, std::max<uint32_t>(1, mons[m].size()));
                uint32_t term = kc(ins, coef[m]);
                for (uint32_t vi : mons[m])
                    term = bin(ins, cb::Opcode::Mul, term, ld(ins, sup[vi].nxt, sup[vi].col));
                acc = (acc < 0) ? int(term) : int(bin(ins, cb::Opcode::Add, uint32_t(acc), term));
            }
            if (acc < 0) { // identically zero: emit 0 * cur[0]
                bin(ins, cb::Opcode::Mul, kc(ins, Fp3::Zero()), ld(ins, false, 0));
                declared = 1; ++n_zero;
            } else if (d <= 1) ++n_deg1; else ++n_solve;
        }
        p.declared_degree = declared;
        table.programs.push_back(std::move(p));
        if ((ord + 1) % 2000 == 0) BOOST_TEST_MESSAGE("  synthesized " << (ord + 1));
    }

    BOOST_TEST_MESSAGE("SYNTH_SUMMARY total=" << table.programs.size()
        << " sbox=" << n_sbox << " solve=" << n_solve << " deg1=" << n_deg1
        << " zero=" << n_zero << " unresolved=" << n_unresolved
        << " max_support=" << max_support << " max_monomials=" << max_monomials);

    // DIFFERENTIAL TEST: bytecode == closure on fresh full-random rows.
    const uint32_t R = 24;
    std::vector<std::vector<Fp3>> cur_rows, nxt_rows;
    uint64_t mism = 0, total = 0;
    std::string why;
    for (uint32_t r = 0; r < R; ++r) {
        cur_rows.push_back(rrow(700000 + r * 13));
        nxt_rows.push_back(rrow(900000 + r * 29));
    }
    for (uint32_t ord = 0; ord < table.programs.size(); ++ord) {
        bool skip = false;
        for (uint32_t u : unresolved_ord) if (u == ord) { skip = true; break; }
        if (skip) continue;
        uint32_t local_mism = 0;
        for (uint32_t r = 0; r < R; ++r) {
            Fp3 got;
            BOOST_REQUIRE(cb::EvaluateProgram(
                table.programs[ord], cur_rows[r], nxt_rows[r], got, &why));
            const Fp3 want = cs.constraints[ord].eval(cur_rows[r], nxt_rows[r]);
            ++total;
            if (!gf::Eq(got, want)) { ++mism; ++local_mism; }
        }
        if (local_mism > 0)
            BOOST_TEST_MESSAGE("  MISMATCH ord=" << ord
                << " name=" << cs.constraints[ord].name
                << " alg_degree=" << cs.constraints[ord].alg_degree
                << " declared=" << table.programs[ord].declared_degree
                << " support=" << sup_sz[ord]
                << " uses_next=" << int(nxt_used[ord])
                << " rows_wrong=" << local_mism);
        {
        }
    }
    BOOST_TEST_MESSAGE("FULL_COMPOSITION_PARITY constraints_tested="
        << (table.programs.size() - n_unresolved) << " rows=" << R
        << " evals=" << total << " mismatches=" << mism);
    BOOST_CHECK_EQUAL(mism, 0U);
    BOOST_CHECK_EQUAL(n_unresolved, 0U);

    // Emit full .bc (cur+next) for the GPU VM.
    const char* out = std::getenv("BTX_PARENT_FULL_BC");
    if (out != nullptr && n_unresolved == 0) {
        FILE* f = std::fopen(out, "w");
        BOOST_REQUIRE(f != nullptr);
        std::fprintf(f, "%zu %u %u %u\n", table.programs.size(), W, W, R);
        for (const auto& p : table.programs) {
            std::fprintf(f, "P %zu\n", p.instructions.size());
            for (const auto& in : p.instructions)
                std::fprintf(f, "%d %u %u %llu %llu %llu\n", int(in.opcode), in.lhs, in.rhs,
                    (unsigned long long)gf::Canonical(in.constant.c0),
                    (unsigned long long)gf::Canonical(in.constant.c1),
                    (unsigned long long)gf::Canonical(in.constant.c2));
        }
        for (uint32_t r = 0; r < R; ++r) {
            for (uint32_t c = 0; c < W; ++c)
                std::fprintf(f, "%llu %llu %llu\n",
                    (unsigned long long)gf::Canonical(cur_rows[r][c].c0),
                    (unsigned long long)gf::Canonical(cur_rows[r][c].c1),
                    (unsigned long long)gf::Canonical(cur_rows[r][c].c2));
            for (uint32_t c = 0; c < W; ++c)
                std::fprintf(f, "%llu %llu %llu\n",
                    (unsigned long long)gf::Canonical(nxt_rows[r][c].c0),
                    (unsigned long long)gf::Canonical(nxt_rows[r][c].c1),
                    (unsigned long long)gf::Canonical(nxt_rows[r][c].c2));
        }
        for (uint32_t ord = 0; ord < table.programs.size(); ++ord)
            for (uint32_t r = 0; r < R; ++r) {
                Fp3 got; cb::EvaluateProgram(table.programs[ord], cur_rows[r], nxt_rows[r], got, &why);
                std::fprintf(f, "%llu %llu %llu\n",
                    (unsigned long long)gf::Canonical(got.c0),
                    (unsigned long long)gf::Canonical(got.c1),
                    (unsigned long long)gf::Canonical(got.c2));
            }
        std::fclose(f);
        BOOST_TEST_MESSAGE("PARENT_FULL_BC_WRITTEN " << out);
    }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::recursive_parent_air
