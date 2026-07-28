// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_unified_verifier_air.h>

#include <hash.h>

#include <boost/test/unit_test.hpp>

namespace rc =
    matmul::v4::rc;
namespace uv =
    rc::stage3_multirow_v11_unified_verifier_air;
namespace aq = rc::air_quotient;
namespace alg_hash = rc::alg_hash;
namespace backend =
    rc::stage3_multirow_v11_backend;
namespace cb = rc::constraint_bytecode;
namespace dvm =
    rc::stage3_multirow_v11_deep_vm;
namespace gf = rc::gkr_field;
namespace tp =
    rc::stage3_multirow_p2_transcript;
namespace rv =
    rc::stage3_multirow_v11_recursive_verifier;

namespace {

using gf::Fp3;

uint256 Seed(uint32_t tag)
{
    HashWriter hash;
    hash <<
        "BTX/RC/STAGE3/DEEP-VM/PUBLIC-PLAN/TEST";
    hash << tag;
    return hash.GetHash();
}

cb::Instruction Load(
    cb::Opcode opcode,
    uint32_t column)
{
    cb::Instruction out;
    out.opcode = opcode;
    out.lhs = column;
    return out;
}

cb::Instruction Constant(uint64_t value)
{
    cb::Instruction out;
    out.opcode = cb::Opcode::Constant;
    out.constant = gf::FromU64_3(value);
    return out;
}

cb::Instruction Binary(
    cb::Opcode opcode,
    uint32_t left,
    uint32_t right)
{
    cb::Instruction out;
    out.opcode = opcode;
    out.lhs = left;
    out.rhs = right;
    return out;
}

cb::ProgramTable ChildProgram()
{
    cb::Program step;
    step.role =
        rc::RCStage3RelationRole::EpisodeGemm;
    step.kind =
        aq::AirKind::kTransition;
    step.declared_degree = 1;
    step.current_width = 2;
    step.next_width = 2;
    step.instructions = {
        Load(cb::Opcode::Next, 0),
        Load(cb::Opcode::Current, 0),
        Binary(cb::Opcode::Sub, 0, 1),
        Constant(1),
        Binary(cb::Opcode::Sub, 2, 3),
    };

    cb::Program twice;
    twice.role =
        rc::RCStage3RelationRole::EpisodeGemm;
    twice.constraint_ordinal = 1;
    twice.kind =
        aq::AirKind::kEverywhere;
    twice.declared_degree = 1;
    twice.current_width = 2;
    twice.next_width = 2;
    twice.instructions = {
        Load(cb::Opcode::Current, 1),
        Load(cb::Opcode::Current, 0),
        Constant(2),
        Binary(cb::Opcode::Mul, 1, 2),
        Binary(cb::Opcode::Sub, 0, 3),
    };

    cb::ProgramTable out;
    out.role =
        rc::RCStage3RelationRole::EpisodeGemm;
    out.current_width = 2;
    out.next_width = 2;
    out.programs = {step, twice};
    return out;
}

aq::AirConstraintSystem<Fp3> ChildAir()
{
    aq::AirConstraintSystem<Fp3> out;
    out.n_rows = 1024;
    out.n_columns = 2;
    out.constraints.push_back({
        "step", aq::AirKind::kTransition, 1,
        [](const auto& current,
           const auto& next) {
            return gf::Sub(
                gf::Sub(next[0], current[0]),
                Fp3::One());
        }});
    out.constraints.push_back({
        "twice", aq::AirKind::kEverywhere, 1,
        [](const auto& current,
           const auto&) {
            return gf::Sub(
                current[1],
                gf::Mul(
                    current[0],
                    gf::FromU64_3(2)));
        }});
    return out;
}

std::vector<std::vector<Fp3>>
ChildTrace(uint32_t offset)
{
    std::vector<std::vector<Fp3>> out(
        2,
        std::vector<Fp3>(1024));
    for (uint32_t row = 0;
         row < 1024; ++row) {
        out[0][row] =
            gf::FromU64_3(offset + row);
        out[1][row] =
            gf::Mul(
                out[0][row],
                gf::FromU64_3(2));
    }
    return out;
}

dvm::ProductV1 BuildDeep(
    uint32_t offset,
    uint32_t seed_tag,
    const cb::ProgramTable& child,
    const alg_hash::Digest& root)
{
    const auto proved =
        backend::ProveAirQuotientV1(
            ChildAir(),
            ChildTrace(offset),
            {0},
            Seed(seed_tag));
    BOOST_REQUIRE_MESSAGE(
        proved.ok, proved.note);
    tp::ReceiptV1 receipt;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        backend::VerifyV1(
            proved.proximity.proof,
            &receipt,
            &why),
        why);
    auto out = dvm::BuildProductV1(
        proved.proximity.proof,
        receipt,
        child,
        root,
        0, 1);
    BOOST_REQUIRE_MESSAGE(
        out.valid, out.note);
    return out;
}

bool SameFp3(
    const std::vector<Fp3>& left,
    const std::vector<Fp3>& right)
{
    if (left.size() != right.size()) {
        return false;
    }
    for (uint32_t i = 0;
         i < left.size(); ++i) {
        if (!gf::Eq(left[i], right[i])) {
            return false;
        }
    }
    return true;
}

bool SamePreprocessed(
    const aq::AirConstraintSystem<Fp3>& left,
    const aq::AirConstraintSystem<Fp3>& right)
{
    if (left.preprocessed.size() !=
        right.preprocessed.size()) {
        return false;
    }
    for (uint32_t i = 0;
         i < left.preprocessed.size(); ++i) {
        if (left.preprocessed[i].first !=
                right.preprocessed[i].first ||
            !SameFp3(
                left.preprocessed[i].second,
                right.preprocessed[i].second)) {
            return false;
        }
    }
    return true;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_deep_vm_public_plan_tests)

BOOST_AUTO_TEST_CASE(
    distinct_child_proofs_share_one_public_cs_and_reject_substitution)
{
    const cb::ProgramTable child =
        ChildProgram();
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(child, &why),
        why);
    const alg_hash::Digest root =
        cb::CommitProgramTableAlgHash(child);
    const rv::QueryRangeV1 range{0, 0, 1};

    const dvm::ProductV1 first =
        BuildDeep(11, 1, child, root);
    const dvm::ProductV1 second =
        BuildDeep(73, 2, child, root);
    BOOST_CHECK(
        first.preprocessed_row_group_root !=
        second.preprocessed_row_group_root);

    const uv::DeepVmPublicPlanV1 plan_a =
        uv::BuildDeepVmPublicPlanV1(
            child, root, range);
    const uv::DeepVmPublicPlanV1 plan_b =
        uv::BuildDeepVmPublicPlanV1(
            child, root, range);
    BOOST_REQUIRE_MESSAGE(
        plan_a.valid, plan_a.note);
    BOOST_REQUIRE_MESSAGE(
        plan_b.valid, plan_b.note);
    BOOST_CHECK(plan_a.proof_independent);
    BOOST_CHECK(
        plan_a.program == plan_b.program);
    BOOST_CHECK(
        plan_a.statement_schedule_root ==
        plan_b.statement_schedule_root);
    BOOST_CHECK(
        plan_a.statement_manifest_columns ==
        plan_b.statement_manifest_columns);
    BOOST_CHECK(
        SamePreprocessed(
            plan_a.cs, plan_b.cs));
    BOOST_CHECK(
        SameFp3(
            plan_a.challenge,
            plan_b.challenge));
    BOOST_CHECK_EQUAL(
        plan_a.cs.n_rows,
        plan_b.cs.n_rows);
    BOOST_CHECK_EQUAL(
        plan_a.cs.n_columns,
        plan_b.cs.n_columns);
    BOOST_CHECK_EQUAL(
        plan_a.cs.constraints.size(),
        plan_b.cs.constraints.size());
    for (uint32_t ordinal = 0;
         ordinal <
             plan_a.cs.constraints.size();
         ++ordinal) {
        BOOST_CHECK(
            plan_a.cs.constraints[ordinal].kind ==
            plan_b.cs.constraints[ordinal].kind);
        BOOST_CHECK_EQUAL(
            plan_a.cs.constraints[ordinal].alg_degree,
            plan_b.cs.constraints[ordinal].alg_degree);
    }

    const auto first_phase =
        uv::MaterializeDeepVmCanonicalPhaseV1(
            plan_a, first);
    const auto second_phase =
        uv::MaterializeDeepVmCanonicalPhaseV1(
            plan_a, second);
    BOOST_REQUIRE_MESSAGE(
        first_phase.valid,
        first_phase.note);
    BOOST_REQUIRE_MESSAGE(
        second_phase.valid,
        second_phase.note);
    BOOST_CHECK(
        first_phase.program ==
        second_phase.program);
    BOOST_CHECK(
        SamePreprocessed(
            first_phase.cs,
            second_phase.cs));

    bool witness_differs = false;
    for (uint32_t column = 0;
         column < first.layout.n_columns &&
         !witness_differs;
         ++column) {
        witness_differs =
            !SameFp3(
                first_phase.columns[column],
                second_phase.columns[column]);
    }
    BOOST_CHECK(witness_differs);

    auto root_substitution = plan_a;
    root_substitution
        .statement_schedule_root.begin()[0] ^= 1U;
    BOOST_CHECK(
        !uv::MaterializeDeepVmCanonicalPhaseV1(
             root_substitution,
             first).valid);

    auto schedule_substitution = plan_a;
    schedule_substitution
        .cs.preprocessed[0].second[0] =
        gf::Add(
            schedule_substitution
                .cs.preprocessed[0].second[0],
            Fp3::One());
    BOOST_CHECK(
        !uv::MaterializeDeepVmCanonicalPhaseV1(
             schedule_substitution,
             first).valid);

    auto proof_schedule_substitution = first;
    proof_schedule_substitution
        .columns[first.layout.active][0] =
        Fp3::Zero();
    BOOST_CHECK(
        !uv::MaterializeDeepVmCanonicalPhaseV1(
             plan_a,
             proof_schedule_substitution).valid);

    auto proof_root_substitution = first;
    proof_root_substitution.program_root[0] =
        gf::Add(
            proof_root_substitution.program_root[0],
            gf::FromU64(1));
    BOOST_CHECK(
        !uv::MaterializeDeepVmCanonicalPhaseV1(
             plan_a,
             proof_root_substitution).valid);
}

BOOST_AUTO_TEST_SUITE_END()
