// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_ordinary_recursive_leaf.h>

#include <algorithm>
#include <cstdlib>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace aq = rc::air_quotient;
namespace gf = rc::gkr_field;
namespace leaf =
    rc::stage3_ordinary_recursive_leaf;
namespace fixedpoint =
    rc::recursive_fixedpoint;

namespace {

uint256 Seed(uint8_t tag)
{
    uint256 out;
    for (uint32_t index = 0;
         index < out.size(); ++index) {
        out.begin()[index] =
            static_cast<unsigned char>(
                tag + 17 * index);
    }
    if (out.IsNull()) out.begin()[0] = 1;
    return out;
}

struct Fixture {
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>>
        columns;
};

Fixture BuildFixture()
{
    Fixture out;
    out.cs.n_rows = 16;
    out.cs.n_columns = 2;

    aq::AirConstraint<gf::Fp3> cubic;
    cubic.name =
        "ordinary_leaf.x_is_seven_cubic";
    cubic.kind = aq::AirKind::kEverywhere;
    cubic.alg_degree = 3;
    cubic.eval = [](
        const std::vector<gf::Fp3>& current,
        const std::vector<gf::Fp3>&) {
        const gf::Fp3 delta =
            gf::Sub(
                current[0],
                gf::Fp3::FromFp(
                    gf::FromU64(7)));
        return gf::Mul(
            gf::Mul(delta, delta), delta);
    };
    out.cs.constraints.push_back(
        std::move(cubic));

    aq::AirConstraint<gf::Fp3> linked;
    linked.name =
        "ordinary_leaf.y_is_x_plus_one";
    linked.kind = aq::AirKind::kEverywhere;
    linked.alg_degree = 1;
    linked.eval = [](
        const std::vector<gf::Fp3>& current,
        const std::vector<gf::Fp3>&) {
        return gf::Sub(
            gf::Sub(
                current[1], current[0]),
            gf::Fp3::One());
    };
    out.cs.constraints.push_back(
        std::move(linked));

    out.columns.assign(
        out.cs.n_columns,
        std::vector<gf::Fp3>(
            out.cs.n_rows,
            gf::Fp3::Zero()));
    std::fill(
        out.columns[0].begin(),
        out.columns[0].end(),
        gf::Fp3::FromFp(
            gf::FromU64(7)));
    std::fill(
        out.columns[1].begin(),
        out.columns[1].end(),
        gf::Fp3::FromFp(
            gf::FromU64(8)));
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_ordinary_recursive_leaf_tests)

BOOST_AUTO_TEST_CASE(
    ordinary_proof_reenters_narrow_receipt_and_rejects_substitution)
{
    const Fixture fixture = BuildFixture();
    const leaf::PublicBindingV1 binding{
        .node_binding = Seed(0x31),
        .program_binding = Seed(0x32),
        .proof_context_binding = Seed(0x33),
        .public_statement_binding = Seed(0x34),
        .fs_seed = Seed(0x35),
    };
    const leaf::ProofV1 proof =
        leaf::ProveV1(
            fixture.cs, fixture.columns,
            binding);
    BOOST_REQUIRE_MESSAGE(
        proof.valid, proof.note);
    BOOST_CHECK(
        proof.native_streaming_proof_verified);
    BOOST_CHECK(
        proof.ordinary_reentry_verified);
    BOOST_CHECK(
        proof.proof_tamper_rejected);
    BOOST_CHECK(proof.receipt.valid);

    std::string why;
    const auto expected_recursive =
        leaf::BuildExpectedRecursiveBindingV2(
            fixture.cs, binding);
    BOOST_REQUIRE(
        !expected_recursive
             .statement_commitment.IsNull());
    BOOST_CHECK_MESSAGE(
        fixedpoint::
            ValidateNarrowRecursiveProofReceiptV2(
                proof.receipt, fixture.cs,
                expected_recursive, &why),
        why);
    BOOST_CHECK_MESSAGE(
        leaf::VerifyV1(
            proof, fixture.cs, binding,
            &why),
        why);

    auto wrong = binding;
    wrong.node_binding = Seed(0x41);
    BOOST_CHECK(
        !leaf::VerifyV1(
            proof, fixture.cs, wrong, &why));
    wrong = binding;
    wrong.program_binding = Seed(0x42);
    BOOST_CHECK(
        !leaf::VerifyV1(
            proof, fixture.cs, wrong, &why));
    wrong = binding;
    wrong.proof_context_binding =
        Seed(0x43);
    BOOST_CHECK(
        !leaf::VerifyV1(
            proof, fixture.cs, wrong, &why));
    wrong = binding;
    wrong.public_statement_binding =
        Seed(0x44);
    BOOST_CHECK(
        !leaf::VerifyV1(
            proof, fixture.cs, wrong, &why));
    wrong = binding;
    wrong.fs_seed = Seed(0x45);
    BOOST_CHECK(
        !leaf::VerifyV1(
            proof, fixture.cs, wrong, &why));

    auto bytes = proof;
    bytes.receipt.proof_bytes.back() ^=
        0x01U;
    BOOST_CHECK(
        !leaf::VerifyV1(
            bytes, fixture.cs, binding,
            &why));

    auto opened = proof;
    BOOST_REQUIRE(
        !opened.receipt.proof.batch
             .queries.empty());
    BOOST_REQUIRE(
        !opened.receipt.proof.batch
             .queries[0].row.values.empty());
    auto& value =
        opened.receipt.proof.batch
            .queries[0].row.values[0];
    value = gf::Add(value, gf::Fp3::One());
    BOOST_CHECK(
        !leaf::VerifyV1(
            opened, fixture.cs, binding,
            &why));

    auto wrong_cs = fixture.cs;
    wrong_cs.constraints[0].eval = [](
        const std::vector<gf::Fp3>&,
        const std::vector<gf::Fp3>&) {
        return gf::Fp3::One();
    };
    BOOST_CHECK(
        !leaf::VerifyV1(
            proof, wrong_cs, binding,
            &why));

    // Exhibit the relabeling attack that the additive V2 parent entry stops.
    // A V1 caller supplies only node/program, so changing the semantic
    // context and statement and recomputing the envelope commitment leaves
    // the underlying valid proof untouched.  V2 receives both values from
    // the independent child protocol and rejects this exact construction.
    auto context_relabel = proof.receipt;
    context_relabel.proof_context_binding =
        Seed(0x46);
    context_relabel.receipt_commitment =
        fixedpoint::
            CommitNarrowRecursiveProofReceiptV1(
                context_relabel);
    BOOST_REQUIRE_MESSAGE(
        fixedpoint::
            ValidateNarrowRecursiveProofReceiptV1(
                context_relabel, fixture.cs,
                binding.node_binding,
                binding.program_binding,
                &why),
        why);
    BOOST_CHECK(
        !fixedpoint::
            ValidateNarrowRecursiveProofReceiptV2(
                context_relabel, fixture.cs,
                expected_recursive, &why));

    auto statement_relabel = proof.receipt;
    statement_relabel.statement_commitment =
        Seed(0x47);
    statement_relabel.receipt_commitment =
        fixedpoint::
            CommitNarrowRecursiveProofReceiptV1(
                statement_relabel);
    BOOST_REQUIRE_MESSAGE(
        fixedpoint::
            ValidateNarrowRecursiveProofReceiptV1(
                statement_relabel, fixture.cs,
                binding.node_binding,
                binding.program_binding,
                &why),
        why);
    BOOST_CHECK(
        !fixedpoint::
            ValidateNarrowRecursiveProofReceiptV2(
                statement_relabel, fixture.cs,
                expected_recursive, &why));

    auto wrong_fs = expected_recursive;
    wrong_fs.fs_seed = Seed(0x48);
    BOOST_CHECK(
        !fixedpoint::
            ValidateNarrowRecursiveProofReceiptV2(
                proof.receipt, fixture.cs,
                wrong_fs, &why));

    // Both validators now derive the exact proof domain from the
    // verifier-owned AIR.  A smaller accounting class is not a valid V1
    // receipt even if its degree-two shape is internally consistent.
    auto undercharged = proof.receipt;
    undercharged.active_rows /= 2;
    undercharged.n_lde =
        rc::narrow_recurse::
            AssessNarrowNodeFriShape(
                undercharged.active_rows)
                .n_lde;
    undercharged.receipt_commitment =
        fixedpoint::
            CommitNarrowRecursiveProofReceiptV1(
                undercharged);
    BOOST_CHECK(
        !fixedpoint::
            ValidateNarrowRecursiveProofReceiptV1(
                undercharged, fixture.cs,
                binding.node_binding,
                binding.program_binding,
                &why));
    BOOST_CHECK(
        !fixedpoint::
            ValidateNarrowRecursiveProofReceiptV2(
                undercharged, fixture.cs,
                expected_recursive, &why));
}

BOOST_AUTO_TEST_CASE(
    two_ordinary_leaves_enter_a_real_narrow_recursive_parent)
{
    const char* run =
        std::getenv(
            "BTX_RUN_STAGE3_ORDINARY_LEAF_RECURSION");
    if (run == nullptr || run[0] == '\0' ||
        run[0] == '0') {
        BOOST_TEST_MESSAGE(
            "skip: set "
            "BTX_RUN_STAGE3_ORDINARY_LEAF_RECURSION=1 "
            "for two ordinary proofs -> real narrow parent proof");
        return;
    }
    const Fixture fixture = BuildFixture();
    const leaf::PublicBindingV1 left_binding{
        .node_binding = Seed(0x51),
        .program_binding = Seed(0x52),
        .proof_context_binding = Seed(0x53),
        .public_statement_binding = Seed(0x54),
        .fs_seed = Seed(0x55),
    };
    const leaf::PublicBindingV1 right_binding{
        .node_binding = Seed(0x61),
        .program_binding = Seed(0x62),
        .proof_context_binding = Seed(0x63),
        .public_statement_binding = Seed(0x64),
        .fs_seed = Seed(0x65),
    };
    const leaf::ProofV1 left =
        leaf::ProveV1(
            fixture.cs, fixture.columns,
            left_binding);
    const leaf::ProofV1 right =
        leaf::ProveV1(
            fixture.cs, fixture.columns,
            right_binding);
    BOOST_REQUIRE_MESSAGE(left.valid, left.note);
    BOOST_REQUIRE_MESSAGE(right.valid, right.note);
    BOOST_REQUIRE(
        left.receipt.proof_commitment !=
        right.receipt.proof_commitment);
    const auto left_expected =
        leaf::BuildExpectedRecursiveBindingV2(
            fixture.cs, left_binding);
    const auto right_expected =
        leaf::BuildExpectedRecursiveBindingV2(
            fixture.cs, right_binding);

    const auto parent =
        fixedpoint::
            ExecuteNarrowRetainedReceiptParentV2(
                {left.receipt, right.receipt},
                {fixture.cs, fixture.cs},
                {left_expected, right_expected},
                Seed(0x71), Seed(0x72),
                /*prove=*/true);
    BOOST_REQUIRE_MESSAGE(
        parent.cryptographically_valid,
        parent.note);
    BOOST_CHECK(parent.all_children_validated);
    BOOST_CHECK(parent.ordered_child_context_bound);
    BOOST_CHECK(parent.child_tamper_rejected);
    BOOST_CHECK(
        parent.consumed
            .parent_reentry_verified);
    BOOST_CHECK(
        parent.consumed
            .parent_proof_tamper_rejected);
    BOOST_CHECK(parent.receipt.valid);

    // The parent refuses a proof copied into the other recursive slot even
    // when both leaf AIR shapes are identical.
    const auto substituted =
        fixedpoint::
            ExecuteNarrowRetainedReceiptParentV2(
                {left.receipt, right.receipt},
                {fixture.cs, fixture.cs},
                {right_expected, left_expected},
                Seed(0x71), Seed(0x72),
                /*prove=*/false);
    BOOST_CHECK(
        !substituted.cryptographically_valid);

    auto relabeled = left.receipt;
    relabeled.proof_context_binding =
        Seed(0x73);
    relabeled.statement_commitment =
        Seed(0x74);
    relabeled.receipt_commitment =
        fixedpoint::
            CommitNarrowRecursiveProofReceiptV1(
                relabeled);
    const auto semantic_substitution =
        fixedpoint::
            ExecuteNarrowRetainedReceiptParentV2(
                {relabeled, right.receipt},
                {fixture.cs, fixture.cs},
                {left_expected, right_expected},
                Seed(0x71), Seed(0x72),
                /*prove=*/false);
    BOOST_CHECK(
        !semantic_substitution
             .cryptographically_valid);
}

BOOST_AUTO_TEST_CASE(
    native_alg_proof_is_canonically_retained_and_mutations_reject)
{
    const Fixture fixture = BuildFixture();
    const leaf::PublicBindingV1 binding{
        .node_binding = Seed(0x81),
        .program_binding = Seed(0x82),
        .proof_context_binding = Seed(0x83),
        .public_statement_binding = Seed(0x84),
        .fs_seed = Seed(0x85),
    };
    const auto proved =
        aq::AirQuotientProve<
            gf::Fp3,
            aq::AirFriBackendAlg<gf::Fp3>>(
                fixture.cs, fixture.columns,
                binding.fs_seed, {});
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact,
        proved.note);

    const leaf::ProofV1 retained =
        leaf::RetainAlgProofV1(
            fixture.cs, proved.proof, binding);
    BOOST_REQUIRE_MESSAGE(
        retained.valid, retained.note);
    BOOST_CHECK(
        retained.native_streaming_proof_verified);
    BOOST_CHECK(
        retained.ordinary_reentry_verified);
    BOOST_CHECK(retained.proof_tamper_rejected);
    BOOST_CHECK(retained.receipt.valid);
    BOOST_CHECK(!retained.receipt.proof_bytes.empty());

    std::string why;
    const auto expected =
        leaf::BuildExpectedRecursiveBindingV2(
            fixture.cs, binding);
    BOOST_CHECK_MESSAGE(
        fixedpoint::
            ValidateNarrowRecursiveProofReceiptV2(
                retained.receipt, fixture.cs,
                expected, &why),
        why);
    BOOST_CHECK_MESSAGE(
        leaf::VerifyV1(
            retained, fixture.cs, binding,
            &why),
        why);

    auto query_value = proved.proof;
    BOOST_REQUIRE(
        !query_value.batch.queries.empty());
    BOOST_REQUIRE(
        !query_value.batch.queries[0]
             .row.values.empty());
    auto& value =
        query_value.batch.queries[0]
            .row.values[0];
    value = gf::Add(value, gf::Fp3::One());
    BOOST_CHECK(
        !leaf::RetainAlgProofV1(
             fixture.cs, query_value,
             binding).valid);

    auto query_index = proved.proof;
    query_index.batch.queries[0].index ^= 1U;
    BOOST_CHECK(
        !leaf::RetainAlgProofV1(
             fixture.cs, query_index,
             binding).valid);

    auto wrong = binding;
    wrong.node_binding = Seed(0x91);
    BOOST_CHECK(
        !leaf::VerifyV1(
             retained, fixture.cs, wrong,
             &why));
    wrong = binding;
    wrong.proof_context_binding = Seed(0x92);
    BOOST_CHECK(
        !leaf::VerifyV1(
             retained, fixture.cs, wrong,
             &why));
    wrong = binding;
    wrong.public_statement_binding = Seed(0x93);
    BOOST_CHECK(
        !leaf::VerifyV1(
             retained, fixture.cs, wrong,
             &why));
    wrong = binding;
    wrong.fs_seed = Seed(0x94);
    BOOST_CHECK(
        !leaf::VerifyV1(
             retained, fixture.cs, wrong,
             &why));
}

BOOST_AUTO_TEST_SUITE_END()
