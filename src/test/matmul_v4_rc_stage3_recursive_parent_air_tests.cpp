// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_recursive_parent_air.h>
#include <matmul/matmul_v4_rc_stage3_global_soundness_ledger.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>
#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_fs_selection_air.h>

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
namespace ha = stage3_hash_air;
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
    // g4 MECHANISM + ADVERSARIAL DELIVERABLE.
    //
    // The parent decoder re-derives air_lambda from 24 "digest bytes" that are
    // PREPROCESSED cells: parent_cs constrains only their FIELD IMAGE (word
    // recompose -> basis reconstruction -> equality with the consumed
    // challenge), never that they are SHA256d(transcript).  The g4 CS-domain
    // CTL bus binds those exact cells to the companion SHA CS's constrained
    // output bytes.  This test (a) shows the honest case reconciles, and
    // (b) constructs TWO coordinated Fiat-Shamir forgeries that parent_cs alone
    // accepts with ZERO violations, and shows the bus rejects both.
    //
    // HEAVY (env-gated): the airq_lambda transcript is a 113-byte preimage, so
    // its SHA256d is three real fixed-program compressions; building that
    // vertical AIR + scanning the full CS is expensive. Gated so the default
    // suite stays fast; run with BTX_RUN_HEAVY_CHILD_FS_SHA=1.
    if (std::getenv("BTX_RUN_HEAVY_CHILD_FS_SHA") == nullptr) {
        BOOST_TEST_MESSAGE(
            "skipping heavy airq_lambda SHA256d in-CS replay "
            "(set BTX_RUN_HEAVY_CHILD_FS_SHA=1 to run)");
        return;
    }
    const auto child_cs = ToyFriChildCs();
    const uint256 seed = Seed(0x5e);
    // COVERAGE (a): FOUR DISTINCT children, so the four slots carry four
    // GENUINELY DIFFERENT transcripts (different trace_commit => different
    // airq_lambda digest => different byte window).  With four identical
    // children the per-slot binding would be vacuously equal and would prove
    // nothing about slot separation.  The toy child AIR is one boolean column
    // over two rows, so (0,1) (1,0) (0,0) (1,1) are four distinct valid
    // witnesses.
    const std::array<std::vector<std::vector<gf::Fp3>>, 4> child_columns{
        std::vector<std::vector<gf::Fp3>>{{gf::Fp3::Zero(), gf::Fp3::One()}},
        std::vector<std::vector<gf::Fp3>>{{gf::Fp3::One(), gf::Fp3::Zero()}},
        std::vector<std::vector<gf::Fp3>>{{gf::Fp3::Zero(), gf::Fp3::Zero()}},
        std::vector<std::vector<gf::Fp3>>{{gf::Fp3::One(), gf::Fp3::One()}}};
    std::array<FourSlotSelfSimilarCtlParentV1::ChildProof, 4> proofs{};
    for (uint32_t i = 0; i < 4; ++i) {
        const auto p =
            aq::AirQuotientProve<gf::Fp3, AlgB3>(
                child_cs, child_columns[i], seed, {});
        BOOST_REQUIRE_MESSAGE(p.ok, p.note);
        proofs[i] = p.proof;
    }
    // The four transcripts really are distinct.
    for (uint32_t i = 1; i < 4; ++i) {
        BOOST_REQUIRE(proofs[i].trace_commit != proofs[0].trace_commit);
    }
    const auto proved_first_ok = true;
    BOOST_REQUIRE(proved_first_ok);
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
            seed, proofs[0].trace_commit,
            pi0.child_n_rows, pi0.child_quotient_len,
            pi0.child_w, consumed);
    BOOST_TEST_MESSAGE(
        "G4_SHA_CS_SHAPE rows=" << replay.sha_rows
        << " columns=" << replay.sha_columns
        << " compressions=" << replay.sha_semantic_compressions);
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

    // ---- HONEST: the two-table CTL boundary reconciles.
    const auto bound = VerifyChildFsShaBoundV1(parent, replay, 0);
    BOOST_CHECK_MESSAGE(bound.valid, bound.note);
    BOOST_CHECK(bound.parent_cs_satisfied);
    BOOST_CHECK(bound.sha_cs_satisfied);
    BOOST_CHECK(bound.boundary_reconciled);
    BOOST_CHECK_EQUAL(bound.parent_violations, 0U);
    BOOST_CHECK_EQUAL(bound.sha_violations, 0U);
    BOOST_CHECK(gf::Eq(bound.c_parent, bound.c_sha));
    // The consumer lane really was appended over the decoder's own cells.
    BOOST_CHECK_EQUAL(
        bound.consumer_lane.byte_base,
        parent.child_air_challenge_byte_base[0]);
    BOOST_CHECK_EQUAL(bound.producer_lane.byte_base, obb);
    // Both challenge lanes are distinct and nonzero (no degenerate bus).
    BOOST_CHECK(!gf::Eq(bound.challenges.gamma1, bound.challenges.gamma2));
    BOOST_CHECK(!gf::Eq(bound.challenges.alpha1, bound.challenges.alpha2));

    // ---- FORGERY 1: COMPENSATING DIGEST-CELL TAMPER.
    // The decoder computes word_0 = sum_i byte[i]*256^i in Fp3 and never range-
    // checks the cells.  So byte[0] += 1 together with byte[1] -= 1/256 leaves
    // word_0 -- hence the reconstructed challenge, hence EVERY parent
    // constraint -- untouched.  The forger has changed the claimed transcript
    // digest without touching anything parent_cs can see.  This is exactly the
    // coordinated FS forgery: a self-consistent (digest', challenge') pair.
    {
        auto forged = parent;
        const uint32_t bb = forged.child_air_challenge_byte_base[0];
        const gf::Fp3 inv256 = gf::Inv(gf::FromU64_3(256));
        const auto tamper =
            [&](uint32_t k, const gf::Fp3& delta) {
                for (auto& cell : forged.parent_witness[bb + k]) {
                    cell = gf::Add(cell, delta);
                }
                for (auto& pp : forged.parent_cs.preprocessed) {
                    if (pp.first != bb + k) continue;
                    for (auto& cell : pp.second) {
                        cell = gf::Add(cell, delta);
                    }
                }
            };
        tamper(0, gf::Fp3::One());
        tamper(1, gf::Sub(gf::Fp3::Zero(), inv256));

        // (a) WITHOUT THE BUS the forgery is ACCEPTED: the parent's own
        //     constraint system is still perfectly satisfied.
        const uint32_t forged_violations =
            air_recurse::CountWitnessViolationsOnH(
                forged.parent_cs, forged.parent_witness);
        BOOST_CHECK_EQUAL(forged_violations, 0U);
        // and the digest cells genuinely differ from the SHA output.
        BOOST_CHECK(!gf::Eq(
            forged.parent_witness[bb + 0][0],
            replay.columns[obb + 0][0]));

        // (b) WITH THE BUS it is REJECTED, in parent verification.
        const auto forged_bound =
            VerifyChildFsShaBoundV1(forged, replay, 0);
        BOOST_CHECK_MESSAGE(
            !forged_bound.valid,
            "compensating digest tamper was NOT rejected: " +
                forged_bound.note);
        BOOST_CHECK(!forged_bound.boundary_reconciled);
        BOOST_CHECK(!gf::Eq(
            forged_bound.c_parent, forged_bound.c_sha));
        // The rejection is the CTL boundary, not a table violation: each table
        // in isolation is still satisfied.  Only the cross-domain bus sees it.
        BOOST_CHECK_EQUAL(forged_bound.sha_violations, 0U);
        BOOST_CHECK_EQUAL(
            forged_bound.note,
            std::string(
                "stage3:child_fs_sha_bound:rejected:ctl_boundary"));
    }

    // ---- FORGERY 2: TRANSCRIPT SUBSTITUTION.
    // Two individually-valid tables that do not belong together: a parent built
    // over transcript seed' paired with the companion SHA replay of transcript
    // seed.  Each table has zero violations on its own; the mismatch exists
    // only across the domain boundary.
    {
        const uint256 seed2 = Seed(0x5f);
        std::array<FourSlotSelfSimilarCtlParentV1::ChildProof, 4> proofs2{};
        for (uint32_t i = 0; i < 4; ++i) {
            const auto p2 =
                aq::AirQuotientProve<gf::Fp3, AlgB3>(
                    child_cs, child_columns[i], seed2, {});
            BOOST_REQUIRE_MESSAGE(p2.ok, p2.note);
            proofs2[i] = p2.proof;
        }
        const auto statement2 =
            ComputeFourSlotSelfSimilarParentStatementV1(
                child_cs, proofs2, seed2, ctx);
        const auto parent2 =
            BuildFourSlotSelfSimilarCtlParentV1(
                child_cs, proofs2, seed2, ctx, statement2);
        BOOST_REQUIRE_MESSAGE(parent2.valid, parent2.note);
        // Both tables are individually satisfied.
        BOOST_CHECK_EQUAL(parent2.witness_violations, 0U);
        BOOST_CHECK_EQUAL(replay.witness_violations, 0U);
        // Different transcript => different digest cells.
        const uint32_t bb2 =
            parent2.child_air_challenge_byte_base[0];
        bool any_differs = false;
        for (uint32_t k = 0; k < 24; ++k) {
            if (!gf::Eq(parent2.parent_witness[bb2 + k][0],
                        replay.columns[obb + k][0])) {
                any_differs = true;
            }
        }
        BOOST_REQUIRE(any_differs);
        const auto mixed =
            VerifyChildFsShaBoundV1(parent2, replay, 0);
        BOOST_CHECK_MESSAGE(
            !mixed.valid,
            "transcript substitution was NOT rejected: " + mixed.note);
        BOOST_CHECK(!mixed.boundary_reconciled);
        BOOST_CHECK(!gf::Eq(mixed.c_parent, mixed.c_sha));
        BOOST_CHECK_EQUAL(mixed.parent_violations, 0U);
        BOOST_CHECK_EQUAL(mixed.sha_violations, 0U);
    }

    // ---- COVERAGE (a): ALL FOUR SLOTS, four genuinely different transcripts.
    // Each slot gets its OWN companion SHA replay over its own child's
    // trace_commit, and each slot's bus must reconcile against its own replay.
    std::array<ChildAirChallengeShaReplayV1, 4> replays{};
    replays[0] = replay;
    for (uint32_t slot = 1; slot < 4; ++slot) {
        const auto& pi = parent.child_verifier.pis[slot];
        replays[slot] = BuildChildAirChallengeShaReplayV1(
            seed, proofs[slot].trace_commit, pi.child_n_rows,
            pi.child_quotient_len, pi.child_w, pi.air_lambda);
        BOOST_REQUIRE_MESSAGE(replays[slot].valid, replays[slot].note);
    }
    // The four digests are genuinely distinct (slot separation is real).
    for (uint32_t i = 1; i < 4; ++i) {
        BOOST_CHECK(replays[i].digest != replays[0].digest);
    }
    for (uint32_t slot = 0; slot < 4; ++slot) {
        const auto b = VerifyChildFsShaBoundV1(parent, replays[slot], slot);
        BOOST_CHECK_MESSAGE(
            b.valid,
            "slot " + std::to_string(slot) + " did not reconcile: " + b.note);
        BOOST_CHECK_EQUAL(b.parent_violations, 0U);
        BOOST_CHECK_EQUAL(b.sha_violations, 0U);
        BOOST_CHECK_EQUAL(
            b.consumer_lane.byte_base,
            parent.child_air_challenge_byte_base[slot]);
    }

    // ---- FORGERY 3: CROSS-SLOT REPLAY.  Slot i's decoder window presented
    // against slot j's companion SHA replay.  Both tables are individually
    // valid; only the bus sees that the transcripts belong to different
    // children.  This is the attack that four IDENTICAL children could not
    // express.
    for (uint32_t i = 0; i < 4; ++i) {
        for (uint32_t j = 0; j < 4; ++j) {
            if (i == j) continue;
            const auto cross = VerifyChildFsShaBoundV1(parent, replays[j], i);
            BOOST_CHECK_MESSAGE(
                !cross.valid,
                "cross-slot replay " + std::to_string(i) + "<-" +
                    std::to_string(j) + " was NOT rejected: " + cross.note);
            BOOST_CHECK(!cross.boundary_reconciled);
            BOOST_CHECK_EQUAL(cross.parent_violations, 0U);
            BOOST_CHECK_EQUAL(cross.sha_violations, 0U);
        }
    }

    // ---- OBLIGATION (b) ON THE REAL PRODUCER: a genuine FRI proof of the
    // BUS-AUGMENTED companion SHA CS (real SHA256d rounds + the producer lane),
    // verified by the real unmodified Split-RAP verifier.
    //
    // The separate BTX_RUN_G4_SHA_FRI gate that used to guard this block is
    // GONE.  It was justified as "the expensive half", but the whole enclosing
    // heavy case was MEASURED end-to-end WITH this block running at 3:37.87
    // wall / 1975.7 s CPU / 1.50 GB peak RSS -- the FRI proof is not the
    // dominant cost, the SHA replay build is.  A second gate over a
    // non-dominant cost only produced runs that reported PASS having proved
    // nothing.  It now runs whenever the enclosing BTX_RUN_HEAVY_CHILD_FS_SHA
    // case runs.
    {
        std::vector<gf::Fp3> pcells, ccells;
        const uint32_t bb0 = parent.child_air_challenge_byte_base[0];
        for (uint32_t k = 0; k < 24; ++k) {
            pcells.push_back(parent.parent_witness[bb0 + k][0]);
            ccells.push_back(replay.columns[obb + k][0]);
        }
        RCStage3CtlChallenges ch;
        std::string why;
        BOOST_REQUIRE(DeriveChildFsDigestBusChallengesV1(
            parent.computed_parent_statement, replay.digest, 0,
            pcells, ccells, ch, &why));
        auto sha_cs = replay.cs;
        auto sha_cols = replay.columns;
        ChildFsDigestBusLaneV1 lane;
        BOOST_REQUIRE(AppendChildFsDigestBusLaneV1(
            obb, ch, nullptr, sha_cs, &sha_cols, lane, &why));
        BOOST_TEST_MESSAGE(
            "G4_SHA_BUS_FRI cols=" << sha_cs.n_columns
            << " rows=" << sha_cs.n_rows
            << " constraints=" << sha_cs.constraints.size());
        // The vertical SHA AIR carries preprocessed ROW-GROUP roots, so the
        // plain AirQuotientVerify refuses it outright ("preprocessed row-group
        // roots require Split-RAP", air_quotient.cpp:1623) -- with or without
        // the bus.  It must go through the two-epoch Split-RAP path, where the
        // SHA AIR's own columns are epoch R0 and the post-challenge bus lane
        // lands in the second epoch, which is where a CTL auxiliary lane
        // belongs.
        const uint256 sseed = Seed(0xc1);
        BOOST_REQUIRE(!replay.base_column_indices.empty());
        const auto sp =
            aq::AirQuotientProveRowsSplitRap(
                sha_cs, sha_cols, replay.base_column_indices,
                sseed, {});
        // REQUIRE, not CHECK: a run that reaches here and does not prove has
        // told us nothing, and must not be able to report PASS.
        BOOST_REQUIRE_MESSAGE(sp.ok, sp.note);
        BOOST_CHECK(sp.division_exact);
        BOOST_CHECK(aq::AirQuotientVerifyRowsSplitRap(
            sha_cs, sp.proof, replay.base_column_indices,
            sseed, &why));
        BOOST_CHECK(!aq::AirQuotientVerifyRowsSplitRap(
            sha_cs, sp.proof, replay.base_column_indices,
            Seed(0xc9), &why));
    }
}

BOOST_AUTO_TEST_CASE(
    g4_digest_bus_lane_verifier_side_reconstruction_pins_the_terminal)
{
    // FAST unit test of the g4 lane itself (no SHA), covering the path a real
    // recursive verifier uses: rebuild the lane AIR from PUBLIC data only
    // (constraints, no witness) against a CLAIMED terminal.  The claimed
    // terminal must be exactly the one the honest cells produce -- that is what
    // makes the cross-table terminal comparison meaningful.
    const uint32_t kBytes = 24;
    const auto make_cs = [&]() {
        aq::AirConstraintSystem<gf::Fp3> cs;
        cs.n_rows = 4;
        cs.n_columns = kBytes;
        return cs;
    };
    // 24 row-constant "digest byte" columns.
    std::vector<std::vector<gf::Fp3>> cells;
    std::vector<gf::Fp3> row0;
    for (uint32_t k = 0; k < kBytes; ++k) {
        const gf::Fp3 v = gf::FromU64_3(7 * k + 11);
        cells.emplace_back(4, v);
        row0.push_back(v);
    }
    ah::Digest statement{};
    const uint256 digest = Seed(0x31);
    RCStage3CtlChallenges ch;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        DeriveChildFsDigestBusChallengesV1(
            statement, digest, 0, row0, row0, ch, &why),
        why);
    BOOST_CHECK(!gf::Eq(ch.gamma1, ch.gamma2));
    BOOST_CHECK(!gf::Eq(ch.alpha1, ch.alpha2));

    // PROVER side: build with witness; the lane derives and pins its terminal.
    auto prover_cs = make_cs();
    auto prover_cols = cells;
    ChildFsDigestBusLaneV1 prover_lane;
    BOOST_REQUIRE_MESSAGE(
        AppendChildFsDigestBusLaneV1(
            0, ch, nullptr, prover_cs, &prover_cols, prover_lane, &why),
        why);
    BOOST_CHECK(prover_lane.valid);
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(prover_cs, prover_cols),
        0U);

    // VERIFIER side: constraints only, against the CLAIMED terminal.  Same
    // relation, same column indices, accepts the honest lane witness.
    {
        auto verifier_cs = make_cs();
        ChildFsDigestBusLaneV1 verifier_lane;
        BOOST_REQUIRE_MESSAGE(
            AppendChildFsDigestBusLaneV1(
                0, ch, &prover_lane.terminal, verifier_cs, nullptr,
                verifier_lane, &why),
            why);
        BOOST_CHECK_EQUAL(verifier_lane.columns, prover_lane.columns);
        BOOST_CHECK_EQUAL(
            verifier_cs.constraints.size(),
            prover_cs.constraints.size());
        BOOST_CHECK_EQUAL(
            air_recurse::CountWitnessViolationsOnH(
                verifier_cs, prover_cols),
            0U);
    }
    // A CLAIMED terminal that is not the honest one is rejected: the kLastRow
    // running constraint no longer closes.  (This is what stops a forger from
    // simply asserting the producer's terminal on his own cells.)
    {
        auto verifier_cs = make_cs();
        RCStage3CtlTerminal lied = prover_lane.terminal;
        lied.alpha1_sum = gf::Add(lied.alpha1_sum, gf::Fp3::One());
        ChildFsDigestBusLaneV1 verifier_lane;
        BOOST_REQUIRE(AppendChildFsDigestBusLaneV1(
            0, ch, &lied, verifier_cs, nullptr, verifier_lane, &why));
        BOOST_CHECK_GT(
            air_recurse::CountWitnessViolationsOnH(
                verifier_cs, prover_cols),
            0U);
    }
    // Changing ONE cell changes the terminal: the lane is byte-sensitive, which
    // is the whole point of the cross-domain comparison.
    {
        auto other_cols = cells;
        for (auto& cell : other_cols[3]) {
            cell = gf::Add(cell, gf::Fp3::One());
        }
        std::vector<gf::Fp3> other_row0 = row0;
        other_row0[3] = gf::Add(other_row0[3], gf::Fp3::One());
        // Same challenge on purpose: isolate the lane's byte sensitivity from
        // the FS re-derivation.
        auto cs2 = make_cs();
        ChildFsDigestBusLaneV1 lane2;
        BOOST_REQUIRE(AppendChildFsDigestBusLaneV1(
            0, ch, nullptr, cs2, &other_cols, lane2, &why));
        BOOST_CHECK(!gf::Eq(
            lane2.terminal.alpha1_sum,
            prover_lane.terminal.alpha1_sum));
        BOOST_CHECK(!gf::Eq(
            lane2.terminal.alpha2_sum,
            prover_lane.terminal.alpha2_sum));
        BOOST_CHECK(!(lane2.terminal == prover_lane.terminal));
    }
    // Shape guard: a byte window that runs past the host's columns is refused.
    {
        auto cs3 = make_cs();
        ChildFsDigestBusLaneV1 lane3;
        BOOST_CHECK(!AppendChildFsDigestBusLaneV1(
            1, ch, &prover_lane.terminal, cs3, nullptr, lane3, &why));
        BOOST_CHECK_EQUAL(why, std::string("bus:byte_window"));
    }
}

BOOST_AUTO_TEST_CASE(
    g4_digest_bus_is_discharged_by_real_fri_proofs_and_rejects_five_ways)
{
    // OBLIGATION (b): discharge the g4 bus obligations with REAL FRI PROOFS of
    // the bus-augmented AIRs, not with CountWitnessViolationsOnH.
    //
    // Two tables, each carrying the SAME lane relation over its own 24-byte
    // window, each proved with the production AirQuotientProve<Fp3,
    // AirFriBackendAlg<Fp3>> and verified with the real unmodified
    // AirQuotientVerify.  The tables model the two g4 endpoints exactly:
    //   PRODUCER  bytes are CONSTRAINED to fixed values (what the SHA
    //             compression rounds do to sha_output_byte_base);
    //   CONSUMER  bytes are FREE and reachable only through their FIELD IMAGE
    //             (what the parent decoder does: word recompose -> challenge),
    //             which is precisely the freedom g4 has to remove.
    // Structured real data: the byte window is a genuine production
    // AirChallengeDigest, not synthetic values.
    const uint256 d = aq::AirChallengeDigest(
        Seed(0x5e), "airq_lambda", {Seed(0xa7)}, {2u, 4u, 1u});
    std::array<unsigned char, 24> bytes{};
    for (uint32_t i = 0; i < 24; ++i) bytes[i] = d.data()[i];
    const uint32_t kRows = 8;
    const uint32_t kBytes = 24;

    // word0 = sum_i b[i]*256^i over the first 8 bytes, in Fp3 (the exact
    // arithmetic the parent decoder uses).
    const auto word0_of = [&](const std::array<gf::Fp3, 24>& cells) {
        gf::Fp3 acc = gf::Fp3::Zero();
        for (uint32_t i = 0; i < 8; ++i) {
            acc = gf::Add(
                acc,
                gf::Mul(cells[i],
                        gf::FromU64_3(uint64_t{1} << (8 * i))));
        }
        return acc;
    };
    std::array<gf::Fp3, 24> honest{};
    for (uint32_t i = 0; i < kBytes; ++i) {
        honest[i] = gf::FromU64_3(static_cast<uint64_t>(bytes[i]));
    }

    // --- PRODUCER: bytes pinned by constraints (stands in for the SHA rounds).
    const auto build_producer =
        [&](const std::array<gf::Fp3, 24>& cells,
            aq::AirConstraintSystem<gf::Fp3>& cs,
            std::vector<std::vector<gf::Fp3>>& cols) {
            cs = {};
            cs.n_rows = kRows;
            cs.n_columns = kBytes;
            cols.assign(kBytes, std::vector<gf::Fp3>(kRows, gf::Fp3::Zero()));
            for (uint32_t k = 0; k < kBytes; ++k) {
                cols[k].assign(kRows, cells[k]);
                aq::AirConstraint<gf::Fp3> c;
                c.name = "g4test.producer.byte_pinned";
                c.kind = aq::AirKind::kEverywhere;
                c.alg_degree = 1;
                const gf::Fp3 want = cells[k];
                c.eval = [k, want](const std::vector<gf::Fp3>& r,
                                   const std::vector<gf::Fp3>&) {
                    return gf::Sub(r[k], want);
                };
                cs.constraints.push_back(std::move(c));
            }
        };
    // --- CONSUMER: bytes FREE, reachable only via word0 (the decoder gap).
    const auto build_consumer =
        [&](const std::array<gf::Fp3, 24>& cells,
            aq::AirConstraintSystem<gf::Fp3>& cs,
            std::vector<std::vector<gf::Fp3>>& cols) {
            cs = {};
            cs.n_rows = kRows;
            cs.n_columns = kBytes + 1;
            cols.assign(kBytes + 1,
                        std::vector<gf::Fp3>(kRows, gf::Fp3::Zero()));
            for (uint32_t k = 0; k < kBytes; ++k) {
                cols[k].assign(kRows, cells[k]);
            }
            cols[kBytes].assign(kRows, word0_of(cells));
            {   // word0 - sum b_i*256^i = 0
                aq::AirConstraint<gf::Fp3> c;
                c.name = "g4test.consumer.word_recompose";
                c.kind = aq::AirKind::kEverywhere;
                c.alg_degree = 1;
                c.eval = [](const std::vector<gf::Fp3>& r,
                            const std::vector<gf::Fp3>&) {
                    gf::Fp3 acc = gf::Fp3::Zero();
                    for (uint32_t i = 0; i < 8; ++i) {
                        acc = gf::Add(
                            acc,
                            gf::Mul(r[i],
                                    gf::FromU64_3(uint64_t{1} << (8 * i))));
                    }
                    return gf::Sub(r[24], acc);
                };
                cs.constraints.push_back(std::move(c));
            }
            {   // word0 pinned to the HONEST challenge image: the consumer's
                // challenge is fixed, exactly as the parent binds air_lambda.
                aq::AirConstraint<gf::Fp3> c;
                c.name = "g4test.consumer.challenge_bound";
                c.kind = aq::AirKind::kEverywhere;
                c.alg_degree = 1;
                const gf::Fp3 want = word0_of(honest);
                c.eval = [want](const std::vector<gf::Fp3>& r,
                                const std::vector<gf::Fp3>&) {
                    return gf::Sub(r[24], want);
                };
                cs.constraints.push_back(std::move(c));
            }
        };

    std::vector<gf::Fp3> row0(honest.begin(), honest.end());
    RCStage3CtlChallenges ch;
    std::string why;
    ah::Digest statement{};
    BOOST_REQUIRE_MESSAGE(
        DeriveChildFsDigestBusChallengesV1(
            statement, d, 0, row0, row0, ch, &why), why);

    // ---- HONEST: build + append lane + PROVE + VERIFY, both tables.
    aq::AirConstraintSystem<gf::Fp3> pcs, ccs;
    std::vector<std::vector<gf::Fp3>> pcols, ccols;
    ChildFsDigestBusLaneV1 plane, clane;
    build_producer(honest, pcs, pcols);
    build_consumer(honest, ccs, ccols);
    BOOST_REQUIRE(AppendChildFsDigestBusLaneV1(
        0, ch, nullptr, pcs, &pcols, plane, &why));
    BOOST_REQUIRE(AppendChildFsDigestBusLaneV1(
        0, ch, nullptr, ccs, &ccols, clane, &why));
    BOOST_TEST_MESSAGE(
        "G4_BUS_PROOF_SHAPE producer_cols=" << pcs.n_columns
        << " consumer_cols=" << ccs.n_columns
        << " rows=" << kRows
        << " producer_constraints=" << pcs.constraints.size()
        << " consumer_constraints=" << ccs.constraints.size());

    const uint256 pseed = Seed(0xb1);
    const uint256 cseed = Seed(0xb2);
    const auto pproof =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(pcs, pcols, pseed, {});
    BOOST_REQUIRE_MESSAGE(pproof.ok, pproof.note);
    BOOST_CHECK(pproof.division_exact);
    const auto cproof =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(ccs, ccols, cseed, {});
    BOOST_REQUIRE_MESSAGE(cproof.ok, cproof.note);
    BOOST_CHECK(cproof.division_exact);
    // REAL, UNMODIFIED verifier accepts both bus-augmented AIRs.
    BOOST_CHECK((aq::AirQuotientVerify<gf::Fp3, AlgB3>(
        pcs, pproof.proof, pseed, &why)));
    BOOST_CHECK((aq::AirQuotientVerify<gf::Fp3, AlgB3>(
        ccs, cproof.proof, cseed, &why)));
    BOOST_CHECK(!pproof.proof.batch.queries.empty());
    BOOST_CHECK(!cproof.proof.batch.queries.empty());
    // Cross-domain boundary reconciles on the PROVEN terminals.
    BOOST_CHECK(plane.terminal == clane.terminal);

    // ================= FIVE PROOF-LEVEL REJECTS =================

    // REJECT 1 -- LIED TERMINAL.  The consumer claims the producer's terminal
    // while its cells say otherwise.  The kLastRow running constraint no longer
    // closes, so the quotient is not exact: there IS NO valid proof.
    {
        aq::AirConstraintSystem<gf::Fp3> cs2;
        std::vector<std::vector<gf::Fp3>> cols2;
        build_consumer(honest, cs2, cols2);
        RCStage3CtlTerminal lied = clane.terminal;
        lied.alpha1_sum = gf::Add(lied.alpha1_sum, gf::Fp3::One());
        ChildFsDigestBusLaneV1 lane2;
        BOOST_REQUIRE(AppendChildFsDigestBusLaneV1(
            0, ch, &lied, cs2, nullptr, lane2, &why));
        cols2.resize(cs2.n_columns,
                     std::vector<gf::Fp3>(kRows, gf::Fp3::Zero()));
        for (uint32_t i = 0; i < ccols.size() && i < cols2.size(); ++i) {
            cols2[i] = ccols[i];
        }
        const auto bad =
            aq::AirQuotientProve<gf::Fp3, AlgB3>(cs2, cols2, cseed, {});
        const bool accepted =
            bad.ok && bad.division_exact &&
            aq::AirQuotientVerify<gf::Fp3, AlgB3>(
                cs2, bad.proof, cseed, &why);
        BOOST_CHECK_MESSAGE(!accepted, "lied terminal produced a valid proof");
    }

    // REJECT 2 -- COORDINATED FS FORGERY, AT PROOF LEVEL.  This is the g4
    // property.  Compensating tamper (b0 += 1, b1 -= 1/256) leaves word0 -- and
    // therefore EVERY consumer constraint -- untouched, so the forger obtains a
    // FULLY VALID FRI PROOF of his consumer AIR.  He is still rejected, because
    // his PROVEN terminal is not the producer's.
    {
        std::array<gf::Fp3, 24> forged = honest;
        forged[0] = gf::Add(forged[0], gf::Fp3::One());
        forged[1] = gf::Sub(
            forged[1], gf::Inv(gf::FromU64_3(256)));
        BOOST_REQUIRE(gf::Eq(word0_of(forged), word0_of(honest)));
        aq::AirConstraintSystem<gf::Fp3> cs3;
        std::vector<std::vector<gf::Fp3>> cols3;
        build_consumer(forged, cs3, cols3);
        std::vector<gf::Fp3> frow0(forged.begin(), forged.end());
        RCStage3CtlChallenges ch3;
        BOOST_REQUIRE(DeriveChildFsDigestBusChallengesV1(
            statement, d, 0, frow0, row0, ch3, &why));
        ChildFsDigestBusLaneV1 lane3;
        BOOST_REQUIRE(AppendChildFsDigestBusLaneV1(
            0, ch3, nullptr, cs3, &cols3, lane3, &why));
        const auto fproof =
            aq::AirQuotientProve<gf::Fp3, AlgB3>(cs3, cols3, cseed, {});
        // The forger's own proof is genuinely VALID -- nothing in his AIR is
        // violated.  Without the bus this is an accepted parent.
        BOOST_CHECK_MESSAGE(fproof.ok, fproof.note);
        BOOST_CHECK(fproof.division_exact);
        BOOST_CHECK((aq::AirQuotientVerify<gf::Fp3, AlgB3>(
            cs3, fproof.proof, cseed, &why)));
        // And the bus rejects him anyway.
        BOOST_CHECK(!(lane3.terminal == plane.terminal));
        BOOST_CHECK(!gf::Eq(
            lane3.terminal.alpha1_sum, plane.terminal.alpha1_sum));
    }

    // REJECT 3 -- INVERSE-COLUMN TAMPER.  Keep the claimed terminal, corrupt an
    // inverse cell: the well-formedness constraint breaks, no valid proof.
    {
        auto cols4 = ccols;
        cols4[clane.inverse1_base + 5][0] =
            gf::Add(cols4[clane.inverse1_base + 5][0], gf::Fp3::One());
        const auto bad =
            aq::AirQuotientProve<gf::Fp3, AlgB3>(ccs, cols4, cseed, {});
        const bool accepted =
            bad.ok && bad.division_exact &&
            aq::AirQuotientVerify<gf::Fp3, AlgB3>(
                ccs, bad.proof, cseed, &why);
        BOOST_CHECK_MESSAGE(!accepted, "inverse tamper produced a valid proof");
    }

    // REJECT 4 -- CROSS-TABLE PROOF REPLAY.  The consumer's proof presented
    // against the producer's AIR (different relation, different pinned
    // terminal) is refused by the real verifier.
    {
        BOOST_CHECK((!aq::AirQuotientVerify<gf::Fp3, AlgB3>(
            pcs, cproof.proof, pseed, &why)));
        BOOST_CHECK((!aq::AirQuotientVerify<gf::Fp3, AlgB3>(
            ccs, pproof.proof, cseed, &why)));
    }

    // REJECT 5 -- WRONG FIAT-SHAMIR SEED.  A valid proof under a foreign seed
    // is refused: the bus lane is inside the FS-bound transcript, not beside it.
    {
        BOOST_CHECK((!aq::AirQuotientVerify<gf::Fp3, AlgB3>(
            ccs, cproof.proof, Seed(0xb9), &why)));
        BOOST_CHECK((!aq::AirQuotientVerify<gf::Fp3, AlgB3>(
            pcs, pproof.proof, Seed(0xb9), &why)));
    }
}

BOOST_AUTO_TEST_CASE(
    g4_bus_augmented_four_slot_parent_produces_and_verifies_its_own_fri_proof)
{
    // OBLIGATION (b), CONSUMER ENDPOINT, ON THE REAL PARENT.
    //
    // The g4 consumer lane is appended to the ACTUAL four-slot self-similar
    // parent_cs, over the ACTUAL cells its airq_lambda decoder consumes, and
    // the bus-augmented parent is then proved with the production
    // AirQuotientProve<Fp3, AirFriBackendAlg<Fp3>> and checked by the real
    // unmodified AirQuotientVerify.  This replaces CountWitnessViolationsOnH
    // with a real FRI proof on the consumer side.
    //
    // The companion SHA CS is NOT rebuilt here (that is the 276 s half, covered
    // by the heavy replay test); the digest is computed natively with the same
    // production AirChallengeDigest the SHA AIR reproduces, so the byte window
    // under test is identical.
    const auto child_cs = ToyFriChildCs();
    const uint256 seed = Seed(0x71);
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

    const auto& pi0 = parent.child_verifier.pis[0];
    const uint256 d = aq::AirChallengeDigest(
        seed, "airq_lambda", {proofs[0].trace_commit},
        {pi0.child_n_rows, pi0.child_quotient_len, pi0.child_w});
    const uint32_t bb = parent.child_air_challenge_byte_base[0];
    BOOST_REQUIRE(bb != 0);
    // The parent's decoder cells really are the production digest bytes.
    std::vector<gf::Fp3> pcells, scells;
    for (uint32_t k = 0; k < 24; ++k) {
        pcells.push_back(parent.parent_witness[bb + k][0]);
        scells.push_back(gf::FromU64_3(
            static_cast<uint64_t>(d.data()[k])));
        BOOST_REQUIRE(gf::Eq(pcells[k], scells[k]));
    }
    RCStage3CtlChallenges ch;
    std::string why;
    BOOST_REQUIRE(DeriveChildFsDigestBusChallengesV1(
        parent.computed_parent_statement, d, 0, pcells, scells, ch, &why));

    auto cs = parent.parent_cs;
    auto cols = parent.parent_witness;
    ChildFsDigestBusLaneV1 lane;
    BOOST_REQUIRE_MESSAGE(
        AppendChildFsDigestBusLaneV1(bb, ch, nullptr, cs, &cols, lane, &why),
        why);
    BOOST_TEST_MESSAGE(
        "G4_PARENT_BUS_SHAPE base_cols=" << parent.parent_columns
        << " bus_augmented_cols=" << cs.n_columns
        << " rows=" << cs.n_rows
        << " constraints=" << cs.constraints.size()
        << " cap=" << kRCFri3AlgBatchMaxColumns);
    // The bus costs 50 columns on a ~17k-column parent.
    BOOST_CHECK_EQUAL(cs.n_columns, parent.parent_columns + 50);
    BOOST_CHECK_LE(cs.n_columns, kRCFri3AlgBatchMaxColumns);
    // The augmented system is satisfied (necessary before proving).
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(cs, cols), 0U);

    if (std::getenv("BTX_RUN_G4_PARENT_FRI") == nullptr) {
        BOOST_TEST_MESSAGE(
            "skipping bus-augmented parent FRI self-proof "
            "(set BTX_RUN_G4_PARENT_FRI=1 to run)");
        return;
    }
    // ---- REAL FRI PROOF of the bus-augmented parent.
    const uint256 pseed = Seed(0x72);
    const auto own = ProveParentOwnFriV1(cs, cols, pseed);
    BOOST_REQUIRE_MESSAGE(own.parent_own_fri_proof_produced, own.note);
    BOOST_CHECK(own.within_backend_column_cap);
    BOOST_CHECK(own.prove_ok);
    BOOST_CHECK(own.division_exact);
    BOOST_CHECK(own.verify_ok);
    BOOST_CHECK(!own.proof.batch.queries.empty());
    // FS-bound: a foreign seed is refused.
    BOOST_CHECK((!aq::AirQuotientVerify<gf::Fp3, AlgB3>(
        cs, own.proof, Seed(0x79), &why)));

    // ---- COORDINATED FORGERY, REJECTED WITH A VALID PROOF IN HAND.
    // The forger applies the compensating tamper (b0 += 1, b1 -= 1/256): every
    // parent constraint still holds, so he obtains a GENUINE FRI PROOF of his
    // bus-augmented parent.  The bus rejects him on the terminal alone.
    {
        auto fcs = parent.parent_cs;
        auto fcols = parent.parent_witness;
        const gf::Fp3 inv256 = gf::Inv(gf::FromU64_3(256));
        const auto tamper = [&](uint32_t k, const gf::Fp3& delta) {
            for (auto& cell : fcols[bb + k]) cell = gf::Add(cell, delta);
            for (auto& pp : fcs.preprocessed) {
                if (pp.first != bb + k) continue;
                for (auto& cell : pp.second) cell = gf::Add(cell, delta);
            }
        };
        tamper(0, gf::Fp3::One());
        tamper(1, gf::Sub(gf::Fp3::Zero(), inv256));
        // Forger's own (post-tamper) challenge and lane.
        std::vector<gf::Fp3> fcells;
        for (uint32_t k = 0; k < 24; ++k) {
            fcells.push_back(fcols[bb + k][0]);
        }
        RCStage3CtlChallenges fch;
        BOOST_REQUIRE(DeriveChildFsDigestBusChallengesV1(
            parent.computed_parent_statement, d, 0, fcells, scells,
            fch, &why));
        ChildFsDigestBusLaneV1 flane;
        BOOST_REQUIRE(AppendChildFsDigestBusLaneV1(
            bb, fch, nullptr, fcs, &fcols, flane, &why));
        // His augmented parent is fully satisfied ...
        BOOST_CHECK_EQUAL(
            air_recurse::CountWitnessViolationsOnH(fcs, fcols), 0U);
        // ... and genuinely PROVES and VERIFIES.
        const auto fown = ProveParentOwnFriV1(fcs, fcols, pseed);
        BOOST_CHECK_MESSAGE(
            fown.parent_own_fri_proof_produced, fown.note);
        BOOST_CHECK(fown.division_exact);
        BOOST_CHECK(fown.verify_ok);
        // The honest producer terminal for the SAME challenge the forger used.
        aq::AirConstraintSystem<gf::Fp3> scs;
        scs.n_rows = 8;
        scs.n_columns = 24;
        std::vector<std::vector<gf::Fp3>> scols(
            24, std::vector<gf::Fp3>(8, gf::Fp3::Zero()));
        for (uint32_t k = 0; k < 24; ++k) scols[k].assign(8, scells[k]);
        ChildFsDigestBusLaneV1 slane;
        BOOST_REQUIRE(AppendChildFsDigestBusLaneV1(
            0, fch, nullptr, scs, &scols, slane, &why));
        // A VALID FRI PROOF IS NOT ENOUGH: the CTL terminal rejects him.
        BOOST_CHECK(!(flane.terminal == slane.terminal));
        BOOST_CHECK(!gf::Eq(
            flane.terminal.alpha1_sum, slane.terminal.alpha1_sum));
        BOOST_CHECK(!gf::Eq(
            flane.terminal.alpha2_sum, slane.terminal.alpha2_sum));
    }
}

BOOST_AUTO_TEST_CASE(
    g4_closure_assessment_is_computed_and_enumerates_its_open_conjuncts)
{
    // The ledger's `fiat_shamir_replay_complete` is COMPUTED from this. Assert
    // the residual is enumerable rather than a bare constant, and that the gate
    // cannot report closed while any obligation is open.
    const auto a = AssessChildFsReplayClosureV1();
    BOOST_TEST_MESSAGE("G4_CLOSURE note=\"" << a.note << "\"");
    BOOST_TEST_MESSAGE(
        "G4_CLOSURE slots=" << a.slots_covered << "/" << a.slots_required
        << " kinds=" << a.challenge_kinds_covered << "/"
        << a.challenge_kinds_required
        << " transcript_bound=" << a.challenge_kinds_transcript_bound
        << "/" << a.challenge_kinds_required
        << " lane_fri=" << a.lane_relation_fri_proven
        << " producer_fri=" << a.producer_endpoint_fri_proven
        << " consumer_fri=" << a.consumer_endpoint_fri_proven
        << " recursion_parent=" << a.recursion_parent_hosts_replay
        << " closed=" << a.closed);
    // The bus half is genuinely built and adversarially tested.
    BOOST_CHECK(a.bus_constructed);
    BOOST_CHECK(a.bus_rejects_coordinated_forgery);
    BOOST_CHECK(a.recursion_parent_hosts_replay);
    BOOST_CHECK(a.lane_relation_fri_proven);
    // `closed` is a CONJUNCTION, not an assertion: every open obligation must
    // force it false.
    BOOST_CHECK_EQUAL(
        a.closed,
        a.bus_constructed && a.bus_rejects_coordinated_forgery &&
            a.covers_all_slots_and_kinds && a.discharged_by_fri_proof &&
            a.recursion_parent_hosts_replay);
    BOOST_CHECK_EQUAL(
        a.discharged_by_fri_proof,
        a.lane_relation_fri_proven && a.producer_endpoint_fri_proven &&
            a.consumer_endpoint_fri_proven);
    BOOST_CHECK_EQUAL(
        a.covers_all_slots_and_kinds,
        a.slots_covered >= a.slots_required &&
            a.challenge_kinds_covered >= a.challenge_kinds_required &&
            a.challenge_kinds_transcript_bound >=
                a.challenge_kinds_required &&
            a.real_child_shape_covered);
    // The two kind counters are NOT the same claim.  Decoding a kind in-AIR is
    // cheap; owning its transcript bytes in-AIR is the >= 52*W object.  The
    // second must never silently ride on the first.
    BOOST_CHECK_LE(
        a.challenge_kinds_transcript_bound, a.challenge_kinds_covered);
    // Today: OPEN, and the note says why.
    BOOST_CHECK(!a.closed);
    BOOST_CHECK(a.note.rfind("stage3:child_fs_replay:open:", 0) == 0);
    BOOST_CHECK(a.note.find("kinds") != std::string::npos);
    // And the ledger reports exactly this, with zero certified bits.
    const auto audit =
        matmul::v4::rc::global_soundness_ledger::
            AssessExecutableGlobalSoundnessLedgerV1();
    BOOST_CHECK_EQUAL(audit.fiat_shamir_replay_complete, a.closed);
    BOOST_CHECK(!audit.composition_gate.child_fiat_shamir_replay_closed);
    BOOST_CHECK(!audit.composition_gate.all_clear);
    BOOST_CHECK_EQUAL(audit.certified_bits, 0U);
}

BOOST_AUTO_TEST_CASE(
    g4_child_fs_transcript_is_independently_replayed_and_cross_checked)
{
    // The parent cannot decode a challenge it cannot re-derive.  This replays
    // the child's WHOLE Q192-V3 Fiat-Shamir transcript from the child's public
    // proof data plus the parent-owned seed, with plain SHA256d over an
    // explicitly rebuilt buffer -- deliberately NOT by calling fri_ext3_alg's
    // transcript object -- and cross-checks every re-derived value against the
    // value the proof actually ships.  That cross-check is the divergence
    // detector: edit either side alone and matches_protocol goes false while
    // both halves still look internally consistent.
    const auto child_cs = ToyFriChildCs();
    const uint256 seed = Seed(0x5e);
    const std::vector<std::vector<gf::Fp3>> columns{
        {gf::Fp3::Zero(), gf::Fp3::One()}};
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(child_cs, columns, seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    const auto pi = air_recurse::ExtractChildPublicInputs(
        child_cs, proved.proof, seed);
    BOOST_REQUIRE(pi.ok);

    const auto replay = ReplayChildFsTranscriptV1(seed, proved.proof, pi);
    BOOST_REQUIRE_MESSAGE(replay.valid, replay.note);
    BOOST_TEST_MESSAGE(
        "G4_FS_REPLAY note=\"" << replay.note << "\""
        << " child_w=" << replay.child_w
        << " n_coeffs=" << replay.n_coeffs
        << " n_lde=" << replay.n_lde
        << " n_folds=" << replay.n_folds
        << " queries=" << replay.queries
        << " draws=" << replay.draws.size()
        << " terminal_transcript_bytes="
        << replay.transcript_bytes_at_terminal);
    BOOST_TEST_MESSAGE(
        "G4_FS_REPLAY_COST sha_compressions=" << replay.total_sha_compressions
        << " forked=" << replay.forked_sha_compressions
        << " vertical_rows=" << replay.total_sha_rows
        << " forked_rows=" << replay.forked_sha_rows);
    for (uint32_t k = 0; k < kChildFsChallengeKindCountV1; ++k) {
        BOOST_TEST_MESSAGE(
            "G4_FS_KIND " << k
            << " draws=" << replay.kind_draw_count[k]
            << " matches_protocol=" << replay.kind_matches_protocol[k]);
    }
    // EVERY kind was drawn and EVERY draw re-derived to the shipped value.
    BOOST_CHECK(replay.all_kinds_match);
    for (uint32_t k = 0; k < kChildFsChallengeKindCountV1; ++k) {
        BOOST_CHECK_MESSAGE(
            replay.kind_matches_protocol[k], "kind " << k << " diverged");
        BOOST_CHECK_GT(replay.kind_draw_count[k], 0U);
    }
    // Non-vacuity: the query draws really are the shipped count, and they
    // really do all share one terminal transcript state (they are drawn after
    // the last absorb, so no draw's preimage is shorter than the terminal).
    BOOST_CHECK_EQUAL(
        replay.kind_draw_count[static_cast<uint32_t>(
            ChildFsChallengeKindV1::Fra3Query)],
        replay.queries);
    BOOST_CHECK_GT(replay.queries, 1U);
    for (const auto& d : replay.draws) {
        if (d.kind != ChildFsChallengeKindV1::Fra3Query) continue;
        BOOST_CHECK_GT(
            d.preimage_bytes, replay.transcript_bytes_at_terminal);
    }
    // The shared-midstate fork is a real saving here, not a hoped-for one.
    BOOST_CHECK_LT(
        replay.forked_sha_compressions, replay.total_sha_compressions);

    // DIVERGENCE DETECTOR, exercised rather than asserted: perturb ONE shipped
    // value and the replay must notice.
    auto tampered_proof = proved.proof;
    tampered_proof.batch.w1 =
        gf::Add(tampered_proof.batch.w1, gf::Fp3::One());
    const auto bad = ReplayChildFsTranscriptV1(seed, tampered_proof, pi);
    BOOST_REQUIRE(bad.valid);
    BOOST_CHECK(!bad.all_kinds_match);
    BOOST_CHECK(!bad.kind_matches_protocol[
        static_cast<uint32_t>(ChildFsChallengeKindV1::Fra3W1)]);
}

BOOST_AUTO_TEST_CASE(
    g4_challenge_decoder_table_covers_every_kind_and_rejects_per_kind_tamper)
{
    // The deliverable: a parent-side, in-AIR decoder for EVERY challenge kind
    // the child draws, one row per draw, bound to the scalar the in-parent
    // verifier consumes.  What it does NOT do is own the transcript bytes --
    // those are pinned public cells for all but airq_lambda, and the assessment
    // keeps that as a separate, still-open counter.
    const auto& cov = AssessChildFsChallengeDecoderCoverageV1();
    BOOST_TEST_MESSAGE("G4_DECODER note=\"" << cov.note << "\"");
    BOOST_REQUIRE_MESSAGE(cov.valid, cov.note);
    BOOST_TEST_MESSAGE(
        "G4_DECODER_TABLE rows=" << cov.table_rows
        << " columns=" << cov.table_columns
        << " constraints=" << cov.table_constraints
        << " max_alg_degree=" << cov.table_max_alg_degree
        << " violations=" << cov.table_violations
        << " draws_decoded=" << cov.draws_decoded
        << " child_w=" << cov.child_w
        << " child_n_rows=" << cov.child_n_rows);
    BOOST_TEST_MESSAGE(
        "G4_DECODER_PROBES batch_w_a=" << cov.probe_child_w_a
        << " batch_w_b=" << cov.probe_child_w_b);
    for (uint32_t k = 0; k < kChildFsChallengeKindCountV1; ++k) {
        BOOST_TEST_MESSAGE(
            "G4_DECODER_KIND " << k
            << " decoded=" << cov.decoded_in_air[k]
            << " replayed=" << cov.transcript_replayed[k]
            << " tamper_rejected=" << cov.tamper_rejected[k]
            << " transcript_bound=" << cov.transcript_bound_in_air[k]
            << " | preimage_a=" << cov.preimage_bytes_a[k]
            << " preimage_b=" << cov.preimage_bytes_b[k]
            << " width_independent=" << cov.preimage_width_independent[k]
            << " companion_sha_rows=" << cov.companion_sha_rows[k]
            << " companion_built=" << cov.companion_cs_built[k]
            << " companion_cols=" << cov.companion_cs_columns[k]
            << " companion_rows=" << cov.companion_cs_rows[k]);
    }
    // NON-VACUITY of the width probe: the two probes really are at different
    // batch widths, so "preimage unchanged" is information and not tautology.
    BOOST_REQUIRE_NE(cov.probe_child_w_a, cov.probe_child_w_b);
    // PR-89 g4 ACTIVATION changed what this probe measures, and the check is
    // rewritten to the post-activation FACT rather than deleted.
    //
    // BEFORE: exactly one kind (airq_lambda) had a width-independent preimage;
    // the other seven inherited the 4*W column_len block and the 48*W OOD
    // evaluation block, so their preimages moved with the child's width and
    // the assertion below was `== is_airq`.
    // AFTER: the short-transcript lane replaces both blocks with 32-byte
    // Poseidon2 commitments, so EVERY kind is width-independent.  That is the
    // whole point of the activation and it is asserted here.
    //
    // NON-VACUITY is preserved in two ways: the two probes are still at
    // different batch widths (BOOST_REQUIRE_NE above), and every preimage is
    // still required to be NONZERO -- a kind that simply failed to be drawn
    // would otherwise read as trivially width-independent.
    BOOST_CHECK(kRCFri3AlgShortFsActivatedV1);
    for (uint32_t k = 0; k < kChildFsChallengeKindCountV1; ++k) {
        BOOST_CHECK_MESSAGE(
            cov.preimage_bytes_a[k] != 0 && cov.preimage_bytes_b[k] != 0,
            "kind " << k << " has no measured preimage at one of the probes");
        BOOST_CHECK_MESSAGE(
            cov.preimage_width_independent[k],
            "kind " << k << " preimage still moves with width: "
                    << cov.preimage_bytes_a[k] << " vs "
                    << cov.preimage_bytes_b[k]);
        BOOST_CHECK_EQUAL(cov.preimage_bytes_a[k], cov.preimage_bytes_b[k]);
    }
    BOOST_CHECK_EQUAL(cov.table_violations, 0U);
    // Every kind decoded, every kind's tamper rejected.
    for (uint32_t k = 0; k < kChildFsChallengeKindCountV1; ++k) {
        BOOST_CHECK_MESSAGE(
            cov.tamper_rejected[k],
            "kind " << k << " tamper NOT rejected -- binding is decorative");
        BOOST_CHECK_MESSAGE(
            cov.decoded_in_air[k], "kind " << k << " has no in-AIR decoder");
    }
    BOOST_CHECK_EQUAL(cov.kinds_decoded, kChildFsChallengeKindCountV1);
    BOOST_CHECK_EQUAL(cov.kinds_replayed, kChildFsChallengeKindCountV1);
    // The standing warning on this counter was: "if this ever reads 8 without
    // a companion hash CS for the other kinds landing first, something was
    // flipped rather than earned."  ACTIVATION alone WOULD have done exactly
    // that -- it makes both of the old conjuncts (width independence, chip
    // capacity) true for all eight kinds without building anything.  So the
    // predicate gained a third conjunct in the same change, and what is
    // asserted here is the companion CS itself, not the cost model.
    for (uint32_t k = 0; k < kChildFsChallengeKindCountV1; ++k) {
        BOOST_CHECK_MESSAGE(
            cov.companion_cs_built[k],
            "kind " << k << " has NO built companion hash CS -- its digest "
                       "bytes are still free public cells");
        // The counter may never exceed the thing that earns it.
        if (cov.transcript_bound_in_air[k]) {
            BOOST_CHECK(cov.companion_cs_built[k]);
        }
    }
    BOOST_CHECK_EQUAL(cov.kinds_companion_built,
                      kChildFsChallengeKindCountV1);
    BOOST_CHECK_EQUAL(cov.kinds_transcript_bound,
                      kChildFsChallengeKindCountV1);
    BOOST_CHECK_LE(cov.kinds_transcript_bound, cov.kinds_companion_built);
    BOOST_CHECK(cov.transcript_bound_in_air[
        static_cast<uint32_t>(ChildFsChallengeKindV1::AirqLambda)]);

    // The table is the reason this fits at all: one row per draw, not one
    // constraint system per draw.
    BOOST_CHECK_GE(cov.table_rows, cov.draws_decoded);
    BOOST_CHECK_LT(cov.table_columns, 256U);
}

BOOST_AUTO_TEST_CASE(
    g4_poseidon2_companion_replays_airq_lambda_and_rejects_forgery)
{
    // The Poseidon2 companion, built and adversarially checked at the DEFAULT
    // (query-sound) height.  Cheap enough to run in the default suite, which is
    // itself part of the point -- the SHA companion is not.
    const auto child_cs = ToyFriChildCs();
    const uint256 seed = Seed(0x5e);
    const std::vector<std::vector<gf::Fp3>> cols{
        {gf::Fp3::Zero(), gf::Fp3::One()}};
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(child_cs, cols, seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    const auto pi = air_recurse::ExtractChildPublicInputs(
        child_cs, proved.proof, seed);
    BOOST_REQUIRE(pi.ok);

    // The consumed challenge for the Poseidon2 ROUTE is that route's own
    // digest -- the SHA route's airq_lambda is a different value by
    // construction (distinct domain tag), which is exactly what makes the two
    // routes non-interchangeable.
    const uint256 d_p2 = aq::AirChallengeDigestP2(
        seed, "airq_lambda", {proved.proof.trace_commit},
        {pi.child_n_rows, pi.child_quotient_len, pi.child_w});
    const gf::Fp3 consumed_p2 = gf::FromChallengeBytes3(d_p2.data());
    BOOST_CHECK_MESSAGE(
        !gf::Eq(consumed_p2, pi.air_lambda),
        "P2 and SHA routes must not share a challenge value");

    const auto p2 = BuildChildAirChallengeP2ReplayV1(
        seed, proved.proof.trace_commit, pi.child_n_rows,
        pi.child_quotient_len, pi.child_w, consumed_p2);
    BOOST_TEST_MESSAGE(
        "G4_P2_COMPANION note=\"" << p2.note << "\""
        << " lanes=" << p2.n_lanes
        << " permutations=" << p2.permutations
        << " rows=" << p2.n_rows
        << " cols=" << p2.n_columns
        << " constraints=" << p2.n_constraints
        << " max_deg=" << p2.max_alg_degree
        << " n_lde=" << p2.n_lde
        << " query_sound=" << p2.query_sound_shape
        << " violations=" << p2.witness_violations);
    BOOST_REQUIRE_MESSAGE(p2.valid, p2.note);
    BOOST_CHECK_EQUAL(p2.witness_violations, 0U);
    BOOST_CHECK(p2.sponge_chained_in_cs);
    BOOST_CHECK(p2.query_sound_shape);
    // 32 lanes -> 40 after 10*-padding -> 5 permutations, ONE ROW EACH.
    BOOST_CHECK_EQUAL(p2.permutations, 5U);
    BOOST_CHECK_EQUAL(p2.n_rows, kChildAirChallengeP2QuerySoundRowsV1);
    // The whole decode is three lane pins: no 24 byte columns, no recompose.
    BOOST_CHECK_LT(p2.n_columns, 500U);

    // FORGERY: a challenge that is not the sponge output must be REJECTED, not
    // merely different.  This is the constraint that makes the companion mean
    // anything.
    const gf::Fp3 forged = gf::Add(consumed_p2, gf::Fp3::One());
    const auto bad = BuildChildAirChallengeP2ReplayV1(
        seed, proved.proof.trace_commit, pi.child_n_rows,
        pi.child_quotient_len, pi.child_w, consumed_p2, 0, &forged);
    BOOST_CHECK_GT(bad.witness_violations, 0U);
    BOOST_CHECK(!bad.valid);

    // QUERY DEGENERACY IS REPORTED, NOT SILENTLY ACCEPTED.  At 8 rows the
    // n_lde is 128 < 192 queries; such a table proves fast and proves nothing,
    // and the builder must refuse to call it valid.
    const auto degenerate = BuildChildAirChallengeP2ReplayV1(
        seed, proved.proof.trace_commit, pi.child_n_rows,
        pi.child_quotient_len, pi.child_w, consumed_p2, 8);
    BOOST_TEST_MESSAGE(
        "G4_P2_DEGENERATE rows=" << degenerate.n_rows
        << " n_lde=" << degenerate.n_lde
        << " query_sound=" << degenerate.query_sound_shape
        << " violations=" << degenerate.witness_violations
        << " note=\"" << degenerate.note << "\"");
    BOOST_CHECK_EQUAL(degenerate.witness_violations, 0U);
    BOOST_CHECK(!degenerate.query_sound_shape);
    BOOST_CHECK(!degenerate.valid);
}

BOOST_AUTO_TEST_CASE(
    g4_p2_limb_bus_reconciles_producer_and_decoder_and_rejects_forgery)
{
    // THE INTERFACE MISMATCH, CLOSED.  BuildChildAirChallengeP2ReplayV1's
    // companion has no byte columns -- its three challenge_limb_columns ARE
    // the canonical output lanes.  AppendChildFsDigestBusLaneV1 binds a
    // 24-BYTE window, so it cannot reconcile that companion with anything
    // without re-adding byte decomposition (defeating the point). This test
    // exercises the LIMB-MODE bus (AppendChildFsLimbBusLaneV1) added for
    // exactly this: a minimal P2-route decoder
    // (BuildChildFsChallengeP2DecoderV1, no byte columns, no recompose) as
    // consumer, the P2 companion as producer, reconciled the same
    // post-commitment dual-lane LogUp way VerifyChildFsShaBoundV1 reconciles
    // the SHA route -- proving the INTERFACE, not activation: this decoder is
    // NOT wired into BuildFourSlotSelfSimilarCtlParentV1, which still
    // consumes the SHA digest.
    const auto child_cs = ToyFriChildCs();
    const uint256 seed = Seed(0x5e);
    const std::vector<std::vector<gf::Fp3>> cols{
        {gf::Fp3::Zero(), gf::Fp3::One()}};
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(child_cs, cols, seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    const auto pi = air_recurse::ExtractChildPublicInputs(
        child_cs, proved.proof, seed);
    BOOST_REQUIRE(pi.ok);

    const uint256 d_p2 = aq::AirChallengeDigestP2(
        seed, "airq_lambda", {proved.proof.trace_commit},
        {pi.child_n_rows, pi.child_quotient_len, pi.child_w});
    const gf::Fp3 consumed_p2 = gf::FromChallengeBytes3(d_p2.data());

    const auto p2 = BuildChildAirChallengeP2ReplayV1(
        seed, proved.proof.trace_commit, pi.child_n_rows,
        pi.child_quotient_len, pi.child_w, consumed_p2);
    BOOST_REQUIRE_MESSAGE(p2.valid, p2.note);

    const auto decoder =
        BuildChildFsChallengeP2DecoderV1(d_p2, consumed_p2);
    BOOST_TEST_MESSAGE(
        "G4_P2_DECODER note=\"" << decoder.note << "\""
        << " violations=" << decoder.witness_violations
        << " columns=" << decoder.cs.n_columns);
    BOOST_REQUIRE_MESSAGE(decoder.valid, decoder.note);
    // The decoder that would consume the P2 route is strictly smaller than
    // the SHA route's parent-side block: 3 preprocessed limb columns and 3
    // bound-to-consumed equalities, no 24 bytes and no word recompose.
    BOOST_CHECK_EQUAL(decoder.cs.n_columns, kChildFsLimbBusCellsV1);
    BOOST_CHECK_EQUAL(
        static_cast<uint32_t>(decoder.cs.constraints.size()),
        kChildFsLimbBusCellsV1);

    const auto ok = VerifyChildFsP2BoundV1(decoder, p2);
    BOOST_TEST_MESSAGE(
        "G4_P2_BOUND note=\"" << ok.note << "\""
        << " decoder_ok=" << ok.decoder_cs_satisfied
        << " p2_ok=" << ok.p2_cs_satisfied
        << " reconciled=" << ok.boundary_reconciled);
    BOOST_REQUIRE_MESSAGE(ok.valid, ok.note);
    BOOST_CHECK_EQUAL(ok.decoder_violations, 0U);
    BOOST_CHECK_EQUAL(ok.p2_violations, 0U);
    BOOST_CHECK(ok.boundary_reconciled);

    // FORGERY 1: a decoder that is SELF-consistent (its own pinned digest and
    // its own "consumed" target agree, so decoder_violations == 0) but pinned
    // from a DIFFERENT P2 digest than the one the producer actually built.
    // This is the compensating-tamper shape: neither table alone is
    // violated, only the cross-domain boundary can catch it.
    const uint256 d_other = aq::AirChallengeDigestP2(
        seed, "airq_lambda", {proved.proof.trace_commit},
        {pi.child_n_rows, pi.child_quotient_len, pi.child_w + 1});
    BOOST_REQUIRE(d_other != d_p2);
    const gf::Fp3 consumed_other = gf::FromChallengeBytes3(d_other.data());
    const auto forged_decoder =
        BuildChildFsChallengeP2DecoderV1(d_other, consumed_other);
    BOOST_REQUIRE_MESSAGE(forged_decoder.valid, forged_decoder.note);
    const auto rejected = VerifyChildFsP2BoundV1(forged_decoder, p2);
    BOOST_TEST_MESSAGE(
        "G4_P2_BOUND_FORGED_DIGEST note=\"" << rejected.note << "\"");
    BOOST_CHECK(!rejected.valid);
    BOOST_CHECK(rejected.decoder_cs_satisfied);
    BOOST_CHECK(rejected.p2_cs_satisfied);
    BOOST_CHECK(!rejected.boundary_reconciled);

    // FORGERY 2: the decoder's pinned digest is the REAL one (so its window
    // matches the producer's), but the consumed target it is bound to is
    // wrong -- caught locally, by the decoder's own constraints, same as the
    // SHA route's bound-to-consumed equality.
    const gf::Fp3 wrong_consumed = gf::Add(consumed_p2, gf::Fp3::One());
    const auto bad_decoder =
        BuildChildFsChallengeP2DecoderV1(d_p2, consumed_p2, &wrong_consumed);
    BOOST_CHECK_GT(bad_decoder.witness_violations, 0U);
    BOOST_CHECK(!bad_decoder.valid);
}

BOOST_AUTO_TEST_CASE(
    g4_producer_endpoint_recompute_cost_is_profiled_phase_by_phase)
{
    // LEVER 1: PROFILE BEFORE OPTIMISING.  The producer endpoint was MEASURED
    // at 3:37.87 wall for the WHOLE enclosing heavy case, which mixes four
    // child proves, a four-slot parent build, the SHA replay build, two full
    // CS scans and the Split-RAP prove/verify.  That number cannot tell us
    // which phase to attack.  This isolates the phases the ledger assessor
    // would actually have to recompute, and times each one separately.
    //
    // Gated because the whole point is that it is expensive; run with
    // BTX_RUN_G4_PRODUCER_PROFILE=1.
    if (std::getenv("BTX_RUN_G4_PRODUCER_PROFILE") == nullptr) {
        BOOST_TEST_MESSAGE(
            "skipping producer-endpoint profile "
            "(set BTX_RUN_G4_PRODUCER_PROFILE=1 to run)");
        return;
    }
    using Clock = std::chrono::steady_clock;
    const auto mark = [](const char* what, Clock::time_point since) {
        const double s =
            std::chrono::duration<double>(Clock::now() - since).count();
        BOOST_TEST_MESSAGE("G4_PROD_PHASE " << what << " " << s << " s");
        return s;
    };

    const auto child_cs = ToyFriChildCs();
    const uint256 seed = Seed(0x5e);
    const std::vector<std::vector<gf::Fp3>> cols{
        {gf::Fp3::Zero(), gf::Fp3::One()}};

    auto t = Clock::now();
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(child_cs, cols, seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    const double t_child = mark("child_prove", t);

    t = Clock::now();
    const auto pi = air_recurse::ExtractChildPublicInputs(
        child_cs, proved.proof, seed);
    BOOST_REQUIRE(pi.ok);
    const double t_pi = mark("extract_public_inputs", t);

    // PHASE A: build the companion SHA CS (the airq_lambda transcript replay).
    t = Clock::now();
    const auto replay = BuildChildAirChallengeShaReplayV1(
        seed, proved.proof.trace_commit, pi.child_n_rows,
        pi.child_quotient_len, pi.child_w, pi.air_lambda);
    BOOST_REQUIRE_MESSAGE(replay.valid, replay.note);
    const double t_build = mark("A_build_sha_companion_cs", t);
    BOOST_TEST_MESSAGE(
        "G4_PROD_SHAPE sha_rows=" << replay.sha_rows
        << " sha_cols=" << replay.sha_columns
        << " compressions=" << replay.sha_semantic_compressions
        << " constraints=" << replay.cs.constraints.size()
        << " base_cols=" << replay.base_column_indices.size());

    // PHASE B: the full-CS violation scan the builder already does once.
    t = Clock::now();
    const uint32_t viol =
        air_recurse::CountWitnessViolationsOnH(replay.cs, replay.columns);
    const double t_scan = mark("B_count_violations_on_H", t);
    BOOST_CHECK_EQUAL(viol, 0U);

    // PHASE C: derive bus challenges + append the producer lane.
    t = Clock::now();
    const uint32_t obb = replay.sha_output_byte_base;
    std::vector<gf::Fp3> pcells, ccells;
    for (uint32_t k = 0; k < 24; ++k) {
        pcells.push_back(replay.columns[obb + k][0]);
        ccells.push_back(replay.columns[obb + k][0]);
    }
    RCStage3CtlChallenges ch;
    std::string why;
    ah::Digest fake_statement{};
    BOOST_REQUIRE(DeriveChildFsDigestBusChallengesV1(
        fake_statement, replay.digest, 0, pcells, ccells, ch, &why));
    auto sha_cs = replay.cs;
    auto sha_cols = replay.columns;
    ChildFsDigestBusLaneV1 lane;
    BOOST_REQUIRE(AppendChildFsDigestBusLaneV1(
        obb, ch, nullptr, sha_cs, &sha_cols, lane, &why));
    const double t_bus = mark("C_derive_challenges_and_append_bus", t);
    BOOST_TEST_MESSAGE(
        "G4_PROD_BUS_SHAPE cols=" << sha_cs.n_columns
        << " rows=" << sha_cs.n_rows
        << " constraints=" << sha_cs.constraints.size());

    // PHASE D: the Split-RAP PROVE -- the phase everyone assumes dominates.
    t = Clock::now();
    const uint256 sseed = Seed(0xc1);
    const auto sp = aq::AirQuotientProveRowsSplitRap(
        sha_cs, sha_cols, replay.base_column_indices, sseed, {});
    BOOST_REQUIRE_MESSAGE(sp.ok, sp.note);
    const double t_prove = mark("D_splitrap_PROVE", t);

    // PHASE E: the Split-RAP VERIFY -- the direction an assessor could afford.
    t = Clock::now();
    BOOST_CHECK(aq::AirQuotientVerifyRowsSplitRap(
        sha_cs, sp.proof, replay.base_column_indices, sseed, &why));
    const double t_verify = mark("E_splitrap_VERIFY", t);

    const double total =
        t_child + t_pi + t_build + t_scan + t_bus + t_prove + t_verify;
    BOOST_TEST_MESSAGE(
        "G4_PROD_TOTAL " << total << " s"
        << " | prove_share=" << (100.0 * t_prove / total) << "%"
        << " build_share=" << (100.0 * t_build / total) << "%"
        << " scan_share=" << (100.0 * t_scan / total) << "%"
        << " verify_share=" << (100.0 * t_verify / total) << "%"
        << " | PROVE/VERIFY ratio=" << (t_prove / std::max(1e-9, t_verify)));

    // ---- HEAD TO HEAD: the SAME phases over the POSEIDON2 companion, which is
    // the proposed replacement for the vertical SHA replay above.  Measured in
    // the same process, on the same box, back to back -- the only comparison
    // worth quoting.
    const uint256 d_p2 = aq::AirChallengeDigestP2(
        seed, "airq_lambda", {proved.proof.trace_commit},
        {pi.child_n_rows, pi.child_quotient_len, pi.child_w});
    const gf::Fp3 consumed_p2 = gf::FromChallengeBytes3(d_p2.data());

    t = Clock::now();
    const auto p2 = BuildChildAirChallengeP2ReplayV1(
        seed, proved.proof.trace_commit, pi.child_n_rows,
        pi.child_quotient_len, pi.child_w, consumed_p2);
    BOOST_REQUIRE_MESSAGE(p2.valid, p2.note);
    const double t_p2_build = mark("P2_A_build_companion_cs", t);
    BOOST_TEST_MESSAGE(
        "G4_P2_SHAPE rows=" << p2.n_rows << " cols=" << p2.n_columns
        << " constraints=" << p2.n_constraints
        << " permutations=" << p2.permutations
        << " max_deg=" << p2.max_alg_degree
        << " n_lde=" << p2.n_lde);

    // The Poseidon2 companion has no preprocessed ROW-GROUP roots, so unlike
    // the SHA companion it can use the plain algebraic prover.
    t = Clock::now();
    const auto p2p = aq::AirQuotientProve<gf::Fp3, AlgB3>(
        p2.cs, p2.columns, Seed(0xc2), {});
    BOOST_REQUIRE_MESSAGE(p2p.ok, p2p.note);
    const double t_p2_prove = mark("P2_D_PROVE", t);

    t = Clock::now();
    BOOST_CHECK((aq::AirQuotientVerify<gf::Fp3, AlgB3>(
        p2.cs, p2p.proof, Seed(0xc2))));
    const double t_p2_verify = mark("P2_E_VERIFY", t);

    const double p2_total = t_p2_build + t_p2_prove + t_p2_verify;
    BOOST_TEST_MESSAGE(
        "G4_P2_TOTAL " << p2_total << " s"
        << " | vs SHA companion "
        << (t_build + t_prove + t_verify) << " s"
        << " | build_speedup="
        << (t_build / std::max(1e-9, t_p2_build))
        << " prove_speedup="
        << (t_prove / std::max(1e-9, t_p2_prove))
        << " end_to_end_speedup="
        << ((t_build + t_prove + t_verify) / std::max(1e-9, p2_total)));
}

BOOST_AUTO_TEST_CASE(
    g4_ood_eval_commit_in_air_recompute_is_budgeted_and_cross_checked)
{
    // THE OBLIGATION THE SHORT-FS LANE (proof version 7, NOT ACTIVATED) HANDS
    // TO THE PARENT.  Committing the two OOD evaluation vectors deletes the
    // 48*W-byte absorb from every challenge preimage, but the commitment binds
    // nothing in-circuit unless the parent recomputes Fri3AlgOodEvalCommit
    // IN-AIR over all 2W cells.  Budget it here, computed from the shipped
    // preimage layout and the real sponge padding rule.
    namespace fs = ::matmul::v4::rc::stage3_fs_selection_air;
    const auto toy = fs::MeasureOodEvalCommitReplayCostV1(2);
    const auto real = fs::MeasureOodEvalCommitReplayCostV1(384984);
    BOOST_REQUIRE(toy.valid && real.valid);
    for (const auto* c : {&toy, &real}) {
        BOOST_TEST_MESSAGE(
            "G4_OOD_COMMIT W=" << c->child_w
            << " lanes=" << c->preimage_lanes
            << " permutations=" << c->permutations
            << " poseidon_rows=" << c->poseidon_rows
            << " x" << c->poseidon_columns << "cols"
            << " deg=" << c->poseidon_max_degree
            << " | legacy_sha_comps_per_challenge="
            << c->legacy_sha_compressions_per_challenge
            << " legacy_sha_rows_per_challenge="
            << c->legacy_sha_rows_per_challenge);
    }
    // ONE permutation per rate block, ONE row per permutation.
    BOOST_CHECK_EQUAL(real.preimage_lanes, 8ull + 6ull * 384984ull);
    BOOST_CHECK_EQUAL(real.poseidon_rows, 524288ull);
    BOOST_CHECK_EQUAL(real.poseidon_columns, 484U);
    // CROSS-CHECK against the transcript lane's independently stated figure of
    // 0.75*W permutations.  They are not identical -- the 8 header lanes and
    // the 10* padding put this 2 permutations above 0.75*W -- and agreeing to
    // within the padding is the point: two derivations, one shape.
    const uint64_t lane_figure = (uint64_t{3} * 384984) / 4;  // 288,738
    BOOST_CHECK_GE(real.permutations, lane_figure);
    BOOST_CHECK_LE(real.permutations - lane_figure, 4ull);
    // And the saving is real: this is paid ONCE, where the legacy absorb it
    // replaces was inside EVERY challenge preimage at 1024 rows a compression.
    BOOST_CHECK_LT(real.poseidon_rows, real.legacy_sha_rows_per_challenge);
}

BOOST_AUTO_TEST_CASE(
    g4_v3_query_index_rule_is_exactly_the_low_bit_mask_of_the_canonical_lane)
{
    // The in-AIR mask decodes the SHIPPED V3 rule
    //   index = ((Canonical(c1) << 64) | Canonical(c0)) % n_lde
    // as the low log2(n_lde) bits of Canonical(c0).  That reduction is exact
    // only because n_lde is a power of two dividing 2^64 -- so the c1 term is a
    // multiple of the modulus and vanishes.  Pin it over the shipped domain
    // sizes with c1 chosen NONZERO, which is what makes the check non-vacuous.
    namespace fs = ::matmul::v4::rc::stage3_fs_selection_air;
    uint32_t checked = 0;
    for (uint32_t n_lde = 32; n_lde <= (1u << 20); n_lde <<= 1) {
        for (uint64_t s = 1; s <= 64; ++s) {
            const gf::Fp3 ch{
                gf::FromU64(0x9e3779b97f4a7c15ull * s),
                gf::FromU64(0xbf58476d1ce4e5b9ull * s + 7ull),
                gf::FromU64(s)};
            BOOST_REQUIRE(gf::Canonical(ch.c1) != 0);
            const uint32_t rule =
                fs::Fri3AlgV3QueryIndexFromChallengeV1(ch, n_lde);
            const uint32_t mask =
                static_cast<uint32_t>(
                    gf::Canonical(ch.c0) & 0xFFFFFFFFull) & (n_lde - 1);
            BOOST_CHECK_EQUAL(rule, mask);
            ++checked;
        }
    }
    BOOST_CHECK_EQUAL(checked, 16U * 64U);
    BOOST_TEST_MESSAGE(
        "G4_V3_INDEX_RULE cross-checked over " << checked << " cases");
}

BOOST_AUTO_TEST_CASE(
    g4_sha_chip_forks_a_shared_midstate_to_divergent_tails)
{
    // THE fra3_query QUESTION, ANSWERED EXECUTABLY.
    //
    // 148 fra3_query draws share an identical transcript `buf` and differ only
    // in a trailing 4 bytes.  Collapsing them needs the SHA chip to FORK one
    // midstate into many divergent tail compressions, instead of re-hashing the
    // shared prefix per draw.  This test builds exactly that shape with the
    // public API and real, correctly-valued chaining states.
    //
    // Two preimages sharing their first 64 bytes and diverging after: their
    // block-0 boundary is identical, and their block-1 boundaries carry the
    // SAME h_in (the shared midstate) with DIFFERENT message words.
    std::vector<uint8_t> pre1(100), pre2(100);
    for (uint32_t i = 0; i < 100; ++i) {
        pre1[i] = static_cast<uint8_t>(7 * i + 1);
        pre2[i] = pre1[i];
    }
    for (uint32_t i = 64; i < 100; ++i) {
        pre2[i] = static_cast<uint8_t>(pre1[i] ^ 0xa5);  // diverge AFTER block 0
    }
    std::string why;
    ha::ShaManifest m1, m2;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildShaManifest(pre1, ha::ShaMode::Double, m1, &why), why);
    BOOST_REQUIRE_MESSAGE(
        ha::BuildShaManifest(pre2, ha::ShaMode::Double, m2, &why), why);
    std::vector<ha::FixedProgramBoundaryInstance> b1, b2;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildShaManifestBoundaryInstances(m1, b1, &why), why);
    BOOST_REQUIRE_MESSAGE(
        ha::BuildShaManifestBoundaryInstances(m2, b2, &why), why);
    BOOST_REQUIRE_EQUAL(m1.first.padded_blocks.size(), 2U);
    BOOST_REQUIRE_EQUAL(m2.first.padded_blocks.size(), 2U);

    const auto program =
        ha::BuildCanonicalProgram(ha::ProgramKind::Sha256Compression);
    // instance 0 = the SHARED prefix block; instances 1 and 2 = the two
    // divergent tails, both fed from instance 0's output state.
    std::vector<ha::FixedProgramBoundaryInstance> boundaries{
        b1[0], b1[1], b2[1]};
    // Sanity: the two tails really do differ, and really do share an h_in.
    BOOST_REQUIRE(b1[1].external_values != b2[1].external_values);
    for (uint32_t w = 0; w < 8; ++w) {
        BOOST_REQUIRE_EQUAL(
            b1[1].external_values[16 + w],
            b2[1].external_values[16 + w]);
    }

    std::vector<std::vector<uint8_t>> masks(
        3, std::vector<uint8_t>(program.external_address_count, 1));
    std::vector<ha::FixedProgramWitnessBoundaryLink> links;
    for (uint32_t w = 0; w < 8; ++w) {
        masks[1][16 + w] = 0;
        masks[2][16 + w] = 0;
        // FAN-OUT: both links share source (0, w) AND a single link_id -- the
        // documented "fan-out-safe LogUp multiplicity" form.
        links.push_back({.source_instance = 0,
                         .source_final_word = w,
                         .target_instance = 1,
                         .target_external_address = 17 + w,
                         .link_id = 1000 + w});
        links.push_back({.source_instance = 0,
                         .source_final_word = w,
                         .target_instance = 2,
                         .target_external_address = 17 + w,
                         .link_id = 1000 + w});
    }
    const auto inst =
        ha::BuildFixedProgramVerticalWitnessBoundaryInstance(
            program, boundaries, masks, links, Seed(0x4f));
    BOOST_REQUIRE_MESSAGE(inst.valid, inst.note);
    BOOST_TEST_MESSAGE(
        "G4_FORK semantic=" << inst.semantic_instances
        << " scheduled=" << inst.scheduled_instances
        << " rows=" << inst.cs.n_rows
        << " cols=" << inst.cs.n_columns);
    // The forked AIR is satisfied: one midstate legitimately drives two tails.
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(inst.cs, inst.columns), 0U);

    // NEGATIVE CONTROL: distinct link_ids on the SAME source is the aliasing
    // form and must be REFUSED -- proving the acceptance above is the
    // multiplicity-tracked fan-out path, not an unchecked one.
    {
        auto bad = links;
        bad[1].link_id = 9999;  // same source (0,0), different id
        const auto rej =
            ha::BuildFixedProgramVerticalWitnessBoundaryInstance(
                program, boundaries, masks, bad, Seed(0x4f));
        BOOST_CHECK_MESSAGE(
            !rej.valid,
            "same-source links with different link_ids were accepted");
    }
    // NEGATIVE CONTROL: one id shared across DIFFERENT sources must be refused.
    {
        auto bad = links;
        bad[2].link_id = 1000;  // source (0,1) reusing word 0's id
        const auto rej =
            ha::BuildFixedProgramVerticalWitnessBoundaryInstance(
                program, boundaries, masks, bad, Seed(0x4f));
        BOOST_CHECK_MESSAGE(
            !rej.valid, "cross-source link_id aliasing was accepted");
    }
}

BOOST_AUTO_TEST_CASE(
    g4_diag_vertical_sha_air_fri_roundtrip_with_and_without_bus)
{
    // DIAGNOSTIC for the observed failure: the bus-augmented companion SHA CS
    // PROVES (division exact) but FAILS AirQuotientVerify.  The missing control
    // is whether the vertical SHA AIR round-trips through AirQuotientProve/
    // Verify AT ALL, bus or no bus.  Uses the cheap 3-instance vertical SHA AIR
    // (same builder as the companion CS), not the 113-byte airq_lambda replay.
    std::vector<uint8_t> pre(100);
    for (uint32_t i = 0; i < 100; ++i) pre[i] = static_cast<uint8_t>(7 * i + 1);
    std::string why;
    ha::ShaManifest m;
    BOOST_REQUIRE(ha::BuildShaManifest(pre, ha::ShaMode::Double, m, &why));
    std::vector<ha::FixedProgramBoundaryInstance> b;
    BOOST_REQUIRE(ha::BuildShaManifestBoundaryInstances(m, b, &why));
    const auto program =
        ha::BuildCanonicalProgram(ha::ProgramKind::Sha256Compression);
    const uint32_t n_first =
        static_cast<uint32_t>(m.first.padded_blocks.size());
    std::vector<std::vector<uint8_t>> masks(
        b.size(), std::vector<uint8_t>(program.external_address_count, 1));
    std::vector<ha::FixedProgramWitnessBoundaryLink> links;
    for (uint32_t i = 1; i < n_first; ++i) {
        for (uint32_t w = 0; w < 8; ++w) {
            masks[i][16 + w] = 0;
            links.push_back({.source_instance = i - 1,
                             .source_final_word = w,
                             .target_instance = i,
                             .target_external_address = 17 + w});
        }
    }
    for (uint32_t w = 0; w < 8; ++w) {
        masks[n_first][w] = 0;
        links.push_back({.source_instance = n_first - 1,
                         .source_final_word = w,
                         .target_instance = n_first,
                         .target_external_address = 1 + w});
    }
    const auto inst =
        ha::BuildFixedProgramVerticalWitnessBoundaryInstance(
            program, b, masks, links, Seed(0x61));
    BOOST_REQUIRE_MESSAGE(inst.valid, inst.note);
    BOOST_TEST_MESSAGE(
        "DIAG base cols=" << inst.cs.n_columns << " rows=" << inst.cs.n_rows
        << " constraints=" << inst.cs.constraints.size()
        << " preprocessed=" << inst.cs.preprocessed.size()
        << " pin_ood=" << inst.cs.preprocessed_pin_ood);
    BOOST_CHECK_EQUAL(
        air_recurse::CountWitnessViolationsOnH(inst.cs, inst.columns), 0U);

    // ---- CONTROL: no bus at all.
    {
        const uint256 s = Seed(0x62);
        const auto p = aq::AirQuotientProveRowsSplitRap(
            inst.cs, inst.columns, inst.base_column_indices, s, {});
        BOOST_TEST_MESSAGE("DIAG control(splitrap) prove_ok=" << p.ok
                           << " div_exact=" << p.division_exact
                           << " note=\"" << p.note << "\"");
        if (p.ok) {
            std::string w2;
            const bool v = aq::AirQuotientVerifyRowsSplitRap(
                inst.cs, p.proof, inst.base_column_indices, s, &w2);
            BOOST_TEST_MESSAGE("DIAG control(splitrap) verify=" << v
                               << " why=\"" << w2 << "\"");
            BOOST_CHECK(v);
        }
    }
    // ---- TREATMENT: with the g4 bus lane appended.
    {
        auto cs = inst.cs;
        auto cols = inst.columns;
        const uint32_t obb = inst.output_byte_base;
        std::vector<gf::Fp3> cells;
        for (uint32_t k = 0; k < 24; ++k) cells.push_back(cols[obb + k][0]);
        RCStage3CtlChallenges ch;
        ah::Digest st{};
        BOOST_REQUIRE(DeriveChildFsDigestBusChallengesV1(
            st, Seed(0x63), 0, cells, cells, ch, &why));
        ChildFsDigestBusLaneV1 lane;
        BOOST_REQUIRE(AppendChildFsDigestBusLaneV1(
            obb, ch, nullptr, cs, &cols, lane, &why));
        BOOST_CHECK_EQUAL(
            air_recurse::CountWitnessViolationsOnH(cs, cols), 0U);
        const uint256 s = Seed(0x62);
        const auto p = aq::AirQuotientProveRowsSplitRap(
            cs, cols, inst.base_column_indices, s, {});
        BOOST_TEST_MESSAGE("DIAG bus(splitrap) prove_ok=" << p.ok
                           << " div_exact=" << p.division_exact
                           << " note=\"" << p.note << "\"");
        if (p.ok) {
            std::string w2;
            const bool v = aq::AirQuotientVerifyRowsSplitRap(
                cs, p.proof, inst.base_column_indices, s, &w2);
            BOOST_TEST_MESSAGE("DIAG bus(splitrap) verify=" << v
                               << " why=\"" << w2 << "\"");
            BOOST_CHECK(v);
        }
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

// ===========================================================================
// PR-89 LOAD-BEARING INTEGRATION: does the four-slot self-similar aggregation
// consume REAL normalized role C_rho children (not toy leaves)?  Every prior
// four-slot test used ToyFriChildCs().  Here the four slots are a REAL role's
// C_rho FRI proof (CoupledPermutation / CoupledMix), which uses OOD-pinned
// preprocessed columns.  Honest -> parent accepts (witness_violations==0);
// tamper a real child proof -> the in-parent verifier rejects (violations>0).
// The self-similar shape verifies four proofs of ONE identical child_cs, so
// each homogeneous set is one real role (heterogeneous distinct roles is the
// HeterogeneousChildDispatchParentV1's job).
// ===========================================================================
namespace {
void RunFourSlotRealRoleChildren(const char* tag,
                                 const RCStage3RoleAirProduct& product,
                                 unsigned char seed_byte)
{
    BOOST_REQUIRE_MESSAGE(product.ok, product.note);
    // The real role C_rho uses OOD-pinned preprocessed columns (ae5302e
    // normalization), not per-column preprocessed Merkle roots.
    BOOST_CHECK(product.cs.preprocessed_roots.empty());
    BOOST_CHECK(product.cs.preprocessed_pin_ood);
    // Honest role witness satisfies C_rho on H.
    BOOST_REQUIRE_EQUAL(
        air_recurse::CountWitnessViolationsOnH(product.cs, product.witness), 0U);

    const auto& child_cs = product.cs;
    const uint256 seed = Seed(seed_byte);

    // A GENUINE role child FRI proof (the same object that verifies standalone).
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(child_cs, product.witness, seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_CHECK(proved.division_exact);
    std::string vwhy;
    const bool child_accepts =
        aq::AirQuotientVerify<gf::Fp3, AlgB3>(child_cs, proved.proof, seed, &vwhy);
    BOOST_REQUIRE_MESSAGE(
        child_accepts, std::string(tag) + " standalone verify: " + vwhy);

    // Four slots = four REAL role children of the identical child_cs.
    const std::array<FourSlotSelfSimilarCtlParentV1::ChildProof, 4> proofs{
        proved.proof, proved.proof, proved.proof, proved.proof};
    const auto ctx = NodeContext();
    const auto statement =
        ComputeFourSlotSelfSimilarParentStatementV1(child_cs, proofs, seed, ctx);
    const auto parent =
        BuildFourSlotSelfSimilarCtlParentV1(child_cs, proofs, seed, ctx, statement);

    BOOST_TEST_MESSAGE(
        std::string("REAL_ROLE_FOURSLOT ") + tag
        << " child_cols=" << child_cs.n_columns
        << " child_rows=" << child_cs.n_rows
        << " vcs_cols=" << parent.vcs_columns
        << " parent_cols=" << parent.parent_columns
        << " parent_rows=" << parent.parent_rows
        << " valid=" << parent.valid
        << " violations=" << parent.witness_violations
        << " note=\"" << parent.note << "\"");

    // HONEST ACCEPT with real children.
    BOOST_REQUIRE_MESSAGE(parent.valid, std::string(tag) + ": " + parent.note);
    BOOST_CHECK_EQUAL(parent.witness_violations, 0U);
    BOOST_CHECK_EQUAL(parent.active_slots, 4U);
    BOOST_CHECK(parent.all_four_children_verified_in_parent_air);
    BOOST_CHECK(parent.merkle_fold_deep_quotient_same_parent);
    BOOST_CHECK(parent.terminal_lanes_sourced_from_in_parent_verifier);
    BOOST_CHECK(parent.four_child_roots_sourced_from_verifier_outputs);
    BOOST_CHECK(parent.parent_statement_equals_child_aggregation);
    BOOST_CHECK(parent.self_similar_arity4_shape);

    // STAGE 2 probe (aggregate ROOT self-prove): attempt the parent's OWN batched
    // FRI proof over the real-children parent V_CS.  Executable record of the
    // backend column-cap residual: with REAL role children (W>>1) the parent V_CS
    // is far wider than with toy leaves, so this documents whether the aggregate
    // root can be FRI-proven at real-child shape.
    {
        const auto own = ProveFourSlotSelfSimilarParentOwnFriV1(parent, Seed(0x2a));
        BOOST_TEST_MESSAGE(
            std::string("REAL_ROLE_FOURSLOT_STAGE2 ") + tag
            << " parent_cols=" << own.parent_columns
            << " cap=" << kRCFri3AlgBatchMaxColumns
            << " within_cap=" << own.within_backend_column_cap
            << " prove_ok=" << own.prove_ok
            << " verify_ok=" << own.verify_ok
            << " root_produced=" << own.parent_own_fri_proof_produced
            << " note=\"" << own.note << "\"");
    }

    // CHEAP TAMPER (no rebuild): mutate the pinned statement-sponge digest cell in
    // the honest parent witness -> the in-circuit AlgHash sponge-output identity
    // fires (the parent statement is genuinely bound to the four real children's
    // public IO, not a free column).
    {
        auto tw = parent.parent_witness;
        const uint32_t root_col = parent.statement_sponge.ExpectedRoot(0);
        const uint32_t term_row =
            parent.statement_sponge_audit.active_rows - 1;
        tw[root_col][term_row] = gf::Add(tw[root_col][term_row], gf::Fp3::One());
        const uint32_t v = air_recurse::CountWitnessViolationsOnH(
            parent.parent_cs, tw);
        BOOST_TEST_MESSAGE(std::string("REAL_ROLE_FOURSLOT_TAMPER_STATEMENT ")
                           + tag << " violations=" << v);
        BOOST_CHECK_GT(v, 0U);
    }

    // TAMPER-REJECT PATH A (build-time binding pin): tamper a REAL child proof
    // (bad Merkle sibling in slot 0) while REUSING the honest statement.  The
    // forged child's public IO no longer hashes to the pinned statement, so the
    // parent-statement-binding gate rejects (valid=false, "statement_not_binding
    // _hash_of_children").  A tampered real child cannot ride the honest claim.
    auto bad = proved.proof;
    BOOST_REQUIRE(!bad.batch.queries.empty());
    BOOST_REQUIRE(!bad.batch.queries[0].row.siblings.empty());
    bad.batch.queries[0].row.siblings[0][0] =
        gf::Add(bad.batch.queries[0].row.siblings[0][0], gf::Fp{1});
    const std::array<FourSlotSelfSimilarCtlParentV1::ChildProof, 4> tproofs{
        bad, proved.proof, proved.proof, proved.proof};
    {
        const auto tparent = BuildFourSlotSelfSimilarCtlParentV1(
            child_cs, tproofs, seed, ctx, statement);
        BOOST_TEST_MESSAGE(
            std::string("REAL_ROLE_FOURSLOT_TAMPER_BIND ") + tag
            << " valid=" << tparent.valid
            << " violations=" << tparent.witness_violations
            << " note=\"" << tparent.note << "\"");
        BOOST_CHECK_MESSAGE(!tparent.valid,
                            std::string(tag) + " tampered child must reject");
    }

    // TAMPER-REJECT PATH B (in-circuit FRI equation): same forged child, but the
    // statement is RECOMPUTED over the forged proofs so the binding gate passes
    // and ONLY the in-parent Merkle/fold equation can expose the bad sibling ->
    // witness_violations > 0 (the child proof is verified in-constraint, not
    // host-side).  One extra heavy rebuild.
    {
        const auto tstatement = ComputeFourSlotSelfSimilarParentStatementV1(
            child_cs, tproofs, seed, ctx);
        const auto tparent = BuildFourSlotSelfSimilarCtlParentV1(
            child_cs, tproofs, seed, ctx, tstatement);
        BOOST_TEST_MESSAGE(
            std::string("REAL_ROLE_FOURSLOT_TAMPER_INCIRCUIT ") + tag
            << " valid=" << tparent.valid
            << " violations=" << tparent.witness_violations
            << " note=\"" << tparent.note << "\"");
        BOOST_CHECK_MESSAGE(
            !tparent.valid && tparent.witness_violations > 0U,
            std::string(tag) + " in-circuit merkle must reject with violations, got"
                + " valid=" + std::to_string(tparent.valid) + " viol="
                + std::to_string(tparent.witness_violations) + " note="
                + tparent.note);
    }
}
} // namespace

BOOST_AUTO_TEST_CASE(
    four_slot_self_similar_parent_consumes_real_coupled_permutation_children)
{
    const gf::Fp3 cell = gf::Fp3::FromFp(gf::FromU64(0x2bad10ULL));
    RunFourSlotRealRoleChildren(
        "CoupledPermutation",
        BuildRCStage3CoupledPermutationRoleAir(cell, 0, /*path_len=*/3, nullptr),
        0xd1);
}

BOOST_AUTO_TEST_CASE(
    four_slot_self_similar_parent_consumes_real_coupled_mix_children)
{
    RunFourSlotRealRoleChildren(
        "CoupledMix",
        BuildRCStage3CoupledScalarRoleAir(RCStage3RelationRole::CoupledMix, 0,
                                          /*path_len=*/3, nullptr),
        0xd2);
}

// ===========================================================================
// g4 REAL-CHILD-SHAPE COVERAGE (env-gated): the g4 digest bus reconciled and
// adversarially exercised against the REAL CoupledPermutation four-slot parent
// (MEASURED W = 384,984 x 256 rows), not ToyFriChildCs.  This is the
// `real_child_shape_covered` obligation of AssessChildFsReplayClosureV1:
// every prior bus run used the toy child (one boolean column, two rows), so
// nothing had shown the bus reconciling — and rejecting forgeries — on a
// parent whose decoder windows sit inside a real-role V_CS.
//
// SHAPE-IMPOSED LIMIT, recorded not smoothed over: the real role's witness is
// CS-DETERMINED (the canonical manifests, hence the committed roots, hence the
// honest endpoint cells are baked into child_cs by (role, cell, leaf_index,
// path_len)), so four slots of one identical child_cs necessarily carry four
// IDENTICAL transcripts.  Slot separation over four DISTINCT transcripts
// therefore remains the toy-shape result (four distinct toy witnesses of one
// toy CS); the cross-TRANSCRIPT rejection a homogeneous real role CAN express
// is transcript substitution (seed vs seed'), exercised below at full shape.
//
// HEAVY: each VerifyChildFsShaBoundV1 copies and rescans the 384,984-column
// parent.  Gated so the default suite stays fast; run with
// BTX_RUN_G4_REAL_CHILD_BUS=1.
// ===========================================================================
BOOST_AUTO_TEST_CASE(
    four_slot_real_coupled_permutation_child_g4_bus_reconciles_and_rejects_forgery)
{
    if (std::getenv("BTX_RUN_G4_REAL_CHILD_BUS") == nullptr) {
        BOOST_TEST_MESSAGE(
            "skipping real-child-shape g4 bus run "
            "(set BTX_RUN_G4_REAL_CHILD_BUS=1 to run)");
        return;
    }
    using Clock = std::chrono::steady_clock;
    const auto t_start = Clock::now();
    const auto mark = [&](const std::string& what, Clock::time_point since) {
        const double s =
            std::chrono::duration<double>(Clock::now() - since).count();
        BOOST_TEST_MESSAGE("G4_REALCHILD_T " << what << " " << s << " s");
    };

    // REAL child: CoupledPermutation C_rho, identical (cell, leaf, path_len)
    // to four_slot_self_similar_parent_consumes_real_coupled_permutation_
    // children, so the parent shape matches its MEASURED W=384,984.
    const gf::Fp3 cell = gf::Fp3::FromFp(gf::FromU64(0x2bad10ULL));
    const auto product =
        BuildRCStage3CoupledPermutationRoleAir(cell, 0, /*path_len=*/3, nullptr);
    BOOST_REQUIRE_MESSAGE(product.ok, product.note);
    const auto& child_cs = product.cs;
    BOOST_REQUIRE_EQUAL(
        air_recurse::CountWitnessViolationsOnH(child_cs, product.witness), 0U);

    const uint256 seed = Seed(0xb5);
    auto t0 = Clock::now();
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(child_cs, product.witness, seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    mark("child_prove", t0);
    const std::array<FourSlotSelfSimilarCtlParentV1::ChildProof, 4> proofs{
        proved.proof, proved.proof, proved.proof, proved.proof};
    const auto ctx = NodeContext();
    t0 = Clock::now();
    const auto statement =
        ComputeFourSlotSelfSimilarParentStatementV1(child_cs, proofs, seed, ctx);
    mark("statement", t0);
    t0 = Clock::now();
    const auto parent =
        BuildFourSlotSelfSimilarCtlParentV1(child_cs, proofs, seed, ctx,
                                            statement);
    mark("parent_build", t0);
    BOOST_REQUIRE_MESSAGE(parent.valid, parent.note);
    BOOST_CHECK_EQUAL(parent.witness_violations, 0U);
    BOOST_TEST_MESSAGE(
        "G4_REALCHILD_PARENT child_cols=" << child_cs.n_columns
        << " child_rows=" << child_cs.n_rows
        << " parent_cols=" << parent.parent_columns
        << " parent_rows=" << parent.parent_rows);

    const auto& pi0 = parent.child_verifier.pis[0];
    const gf::Fp3 consumed = pi0.air_lambda;
    BOOST_REQUIRE(parent.child_air_challenge_byte_base[0] != 0U);

    t0 = Clock::now();
    const auto replay = BuildChildAirChallengeShaReplayV1(
        seed, proofs[0].trace_commit, pi0.child_n_rows,
        pi0.child_quotient_len, pi0.child_w, consumed);
    mark("sha_replay_build", t0);
    BOOST_REQUIRE_MESSAGE(replay.valid, replay.note);
    BOOST_TEST_MESSAGE(
        "G4_REALCHILD_SHA_CS rows=" << replay.sha_rows
        << " columns=" << replay.sha_columns
        << " compressions=" << replay.sha_semantic_compressions);
    BOOST_CHECK_EQUAL(replay.witness_violations, 0U);
    BOOST_CHECK(replay.sha_output_binds_digest_bytes);
    BOOST_CHECK(replay.challenge_bound_to_consumed);
    BOOST_CHECK(gf::Eq(replay.reconstructed_challenge, consumed));
    const uint32_t obb = replay.sha_output_byte_base;

    // ---- HONEST at real child shape: the two-table CTL boundary reconciles.
    t0 = Clock::now();
    const auto bound = VerifyChildFsShaBoundV1(parent, replay, 0);
    mark("honest_bound_slot0", t0);
    BOOST_CHECK_MESSAGE(bound.valid, bound.note);
    BOOST_CHECK(bound.parent_cs_satisfied);
    BOOST_CHECK(bound.sha_cs_satisfied);
    BOOST_CHECK(bound.boundary_reconciled);
    BOOST_CHECK_EQUAL(bound.parent_violations, 0U);
    BOOST_CHECK_EQUAL(bound.sha_violations, 0U);
    BOOST_CHECK(gf::Eq(bound.c_parent, bound.c_sha));
    BOOST_CHECK_EQUAL(bound.consumer_lane.byte_base,
                      parent.child_air_challenge_byte_base[0]);
    BOOST_CHECK_EQUAL(bound.producer_lane.byte_base, obb);
    BOOST_CHECK(!gf::Eq(bound.challenges.gamma1, bound.challenges.gamma2));
    BOOST_CHECK(!gf::Eq(bound.challenges.alpha1, bound.challenges.alpha2));
    // Bus-augmented parent width at real child shape (toy: 17108 -> 17158).
    // ChildFsDigestBusLaneV1::columns is the augmented TOTAL (append impl sets
    // cs.n_columns = out.columns = base + 50).
    BOOST_TEST_MESSAGE(
        "G4_REALCHILD_BUS parent_cols=" << parent.parent_columns
        << " lane_base=" << bound.consumer_lane.inverse1_base
        << " augmented_cols=" << bound.consumer_lane.columns
        << " bus_delta_cols="
        << (bound.consumer_lane.columns - bound.consumer_lane.inverse1_base));

    // ---- FORGERY 1 at real child shape: COMPENSATING DIGEST-CELL TAMPER.
    // Same construction as the toy test: byte[0] += 1, byte[1] -= 1/256 leaves
    // the decoder's word_0 — hence every parent constraint — untouched, so the
    // real-shape parent_cs alone ACCEPTS the forged transcript digest; only
    // the bus can see it.
    {
        auto forged = parent;
        const uint32_t bb = forged.child_air_challenge_byte_base[0];
        const gf::Fp3 inv256 = gf::Inv(gf::FromU64_3(256));
        const auto tamper =
            [&](uint32_t k, const gf::Fp3& delta) {
                for (auto& c : forged.parent_witness[bb + k]) {
                    c = gf::Add(c, delta);
                }
                for (auto& pp : forged.parent_cs.preprocessed) {
                    if (pp.first != bb + k) continue;
                    for (auto& c : pp.second) {
                        c = gf::Add(c, delta);
                    }
                }
            };
        tamper(0, gf::Fp3::One());
        tamper(1, gf::Sub(gf::Fp3::Zero(), inv256));

        // (a) WITHOUT the bus the forgery is ACCEPTED at real shape.
        t0 = Clock::now();
        const uint32_t forged_violations =
            air_recurse::CountWitnessViolationsOnH(
                forged.parent_cs, forged.parent_witness);
        mark("forgery1_busless_scan", t0);
        BOOST_CHECK_EQUAL(forged_violations, 0U);
        BOOST_CHECK(!gf::Eq(
            forged.parent_witness[bb + 0][0],
            replay.columns[obb + 0][0]));

        // (b) WITH the bus it is REJECTED, at the CTL boundary, with both
        //     tables individually satisfied.
        t0 = Clock::now();
        const auto forged_bound = VerifyChildFsShaBoundV1(forged, replay, 0);
        mark("forgery1_bound", t0);
        BOOST_CHECK_MESSAGE(
            !forged_bound.valid,
            "REAL-SHAPE compensating digest tamper was NOT rejected: " +
                forged_bound.note);
        BOOST_CHECK(!forged_bound.boundary_reconciled);
        BOOST_CHECK(!gf::Eq(forged_bound.c_parent, forged_bound.c_sha));
        BOOST_CHECK_EQUAL(forged_bound.sha_violations, 0U);
        BOOST_CHECK_EQUAL(
            forged_bound.note,
            std::string("stage3:child_fs_sha_bound:rejected:ctl_boundary"));
    }

    // ---- FORGERY 2 at real child shape: TRANSCRIPT SUBSTITUTION.  A parent
    // built over seed' paired with the companion SHA replay of seed: both
    // tables individually valid, mismatch visible only across the boundary.
    // This is the cross-transcript rejection a homogeneous real role can
    // express (see the shape-imposed-limit note above).
    {
        const uint256 seed2 = Seed(0xb6);
        t0 = Clock::now();
        const auto proved2 = aq::AirQuotientProve<gf::Fp3, AlgB3>(
            child_cs, product.witness, seed2, {});
        BOOST_REQUIRE_MESSAGE(proved2.ok, proved2.note);
        const std::array<FourSlotSelfSimilarCtlParentV1::ChildProof, 4>
            proofs2{proved2.proof, proved2.proof, proved2.proof,
                    proved2.proof};
        const auto statement2 =
            ComputeFourSlotSelfSimilarParentStatementV1(
                child_cs, proofs2, seed2, ctx);
        const auto parent2 = BuildFourSlotSelfSimilarCtlParentV1(
            child_cs, proofs2, seed2, ctx, statement2);
        mark("forgery2_parent2_build", t0);
        BOOST_REQUIRE_MESSAGE(parent2.valid, parent2.note);
        BOOST_CHECK_EQUAL(parent2.witness_violations, 0U);
        BOOST_CHECK_EQUAL(replay.witness_violations, 0U);
        const uint32_t bb2 = parent2.child_air_challenge_byte_base[0];
        bool any_differs = false;
        for (uint32_t k = 0; k < kChildFsDigestBusBytesV1; ++k) {
            if (!gf::Eq(parent2.parent_witness[bb2 + k][0],
                        replay.columns[obb + k][0])) {
                any_differs = true;
            }
        }
        BOOST_REQUIRE(any_differs);
        t0 = Clock::now();
        const auto mixed = VerifyChildFsShaBoundV1(parent2, replay, 0);
        mark("forgery2_bound", t0);
        BOOST_CHECK_MESSAGE(
            !mixed.valid,
            "REAL-SHAPE transcript substitution was NOT rejected: " +
                mixed.note);
        BOOST_CHECK(!mixed.boundary_reconciled);
        BOOST_CHECK(!gf::Eq(mixed.c_parent, mixed.c_sha));
        BOOST_CHECK_EQUAL(mixed.parent_violations, 0U);
        BOOST_CHECK_EQUAL(mixed.sha_violations, 0U);
    }

    // ---- ALL FOUR SLOTS at real child shape.  With a CS-determined witness
    // the four transcripts are identical, so this verifies per-slot decoder
    // ANCHORING (each consumer lane appended over that slot's own byte window)
    // and per-slot challenge domain separation — NOT slot separation over
    // distinct transcripts, which stays a toy-shape-only result.
    for (uint32_t slot = 1; slot < 4; ++slot) {
        t0 = Clock::now();
        const auto b = VerifyChildFsShaBoundV1(parent, replay, slot);
        mark("honest_bound_slot" + std::to_string(slot), t0);
        BOOST_CHECK_MESSAGE(
            b.valid,
            "slot " + std::to_string(slot) + " did not reconcile: " + b.note);
        BOOST_CHECK_EQUAL(b.parent_violations, 0U);
        BOOST_CHECK_EQUAL(b.sha_violations, 0U);
        BOOST_CHECK_EQUAL(b.consumer_lane.byte_base,
                          parent.child_air_challenge_byte_base[slot]);
        // Slot index is absorbed into the joint challenge, so lanes differ
        // across slots even over identical byte windows.
        BOOST_CHECK(!gf::Eq(b.challenges.alpha1, bound.challenges.alpha1));
    }
    mark("total", t_start);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::recursive_parent_air
