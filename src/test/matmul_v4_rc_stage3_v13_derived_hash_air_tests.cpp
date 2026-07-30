// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_v13_derived_hash_air.h>

#include <algorithm>

namespace derived =
    matmul::v4::rc::stage3_v13_derived_hash_air;
namespace proofabi =
    matmul::v4::rc::stage3_multirow_v11_proof_abi;
namespace tape =
    matmul::v4::rc::stage3_multirow_v13_proof_tape_air;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
namespace rc = matmul::v4::rc;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_v13_derived_hash_air_tests)

namespace {

uint256 TestSeed(uint32_t value)
{
    uint256 out;
    for (uint32_t index = 0; index < out.size(); ++index) {
        out.begin()[index] =
            static_cast<unsigned char>(
                (value + 31U * index) & 0xffU);
    }
    if (out.IsNull()) out.begin()[0] = 1;
    return out;
}

struct Fixture {
    uint256 seed{};
    tape::PublicShapeV1 shape{};
    std::vector<uint32_t> words;
    std::vector<proofabi::SourceCellV1> sources;
    derived::SelectedPointsV1 selected{};
    derived::ProductV1 product{};
    rc::Fri3AlgDigest native_shape{};
    rc::Fri3AlgDigest native_ood{};
};

Fixture BuildFixture()
{
    constexpr uint32_t N = 8;
    Fixture out;
    out.seed = TestSeed(0xd341);
    std::vector<std::vector<gf::Fp3>> columns(
        4, std::vector<gf::Fp3>(
               N, gf::Fp3::Zero()));
    for (uint32_t row = 0; row < N; ++row) {
        columns[0][row] =
            gf::Fp3::FromFp(
                gf::FromU64(
                    5 + 3 * row + row * row));
        columns[1][row] =
            gf::Fp3::FromFp(
                gf::FromU64(11 + 7 * row));
    }
    const auto make_cs =
        [](const gf::Fp3& relation_challenge) {
            aq::AirConstraintSystem<gf::Fp3> cs;
            cs.n_rows = N;
            cs.n_columns = 4;
            aq::AirConstraint<gf::Fp3> relation;
            relation.name =
                "test.v13_derived_hash.relation";
            relation.kind = aq::AirKind::kEverywhere;
            relation.alg_degree = 1;
            relation.eval =
                [relation_challenge](
                    const auto& cur,
                    const auto&) {
                    return gf::Sub(
                        cur[2],
                        gf::Add(
                            cur[0],
                            gf::Mul(
                                relation_challenge,
                                cur[1])));
                };
            cs.constraints.push_back(
                std::move(relation));
            aq::AirConstraint<gf::Fp3> transition;
            transition.name =
                "test.v13_derived_hash.transition";
            transition.kind = aq::AirKind::kTransition;
            transition.alg_degree = 1;
            transition.eval =
                [](const auto& cur,
                   const auto& next) {
                    return gf::Sub(
                        next[3],
                        gf::Add(cur[3], cur[2]));
                };
            cs.constraints.push_back(
                std::move(transition));
            return cs;
        };
    const std::vector<uint32_t> base_indices{0, 1};
    const auto shape_cs = make_cs(gf::Fp3::Zero());
    const auto r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            shape_cs, columns, base_indices);
    BOOST_REQUIRE_MESSAGE(r0.valid, r0.note);
    const uint256 relation_digest =
        aq::AirChallengeDigest(
            out.seed,
            "test.v13_derived_hash.relation",
            {r0.base_row_commitment}, {N, 4});
    const gf::Fp3 relation_challenge =
        gf::FromChallengeBytes3(
            relation_digest.data());
    auto cs = make_cs(relation_challenge);
    for (uint32_t row = 0; row < N; ++row) {
        columns[2][row] =
            gf::Add(
                columns[0][row],
                gf::Mul(
                    relation_challenge,
                    columns[1][row]));
        if (row + 1 < N) {
            columns[3][row + 1] =
                gf::Add(
                    columns[3][row],
                    columns[2][row]);
        }
    }
    cs.preprocessed.emplace_back(1, columns[1]);
    cs.preprocessed_pin_ood = true;
    cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role =
            aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns = base_indices,
        .root = r0.base_row_commitment,
    });
    const auto proved =
        aq::AirQuotientProveRowsSplitRapSafeV2(
            cs, columns, base_indices,
            out.seed, {}, &r0);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);

    proofabi::EnvelopeV1 envelope;
    for (uint32_t word = 0;
         word < envelope.public_fs_seed.size(); ++word) {
        for (uint32_t byte = 0; byte < 4; ++byte) {
            envelope.public_fs_seed[word] |=
                uint32_t{
                    out.seed.data()[4 * word + byte]}
                << (8 * byte);
        }
    }
    envelope.trace_columns = cs.n_columns;
    BOOST_REQUIRE(!proved.proof.batch.column_len.empty());
    envelope.quotient_len =
        proved.proof.batch.column_len.back();
    envelope.split = proved.proof;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        proofabi::EncodeCanonicalSafeV13(
            envelope, out.words,
            &out.sources, &why),
        why);

    out.shape.trace_rows = cs.n_rows;
    out.shape.trace_columns = cs.n_columns;
    out.shape.quotient_len = envelope.quotient_len;
    out.shape.n_coeffs =
        proved.proof.batch.n_coeffs;
    out.shape.base_column_indices = base_indices;
    out.selected.z1 = proved.proof.batch.z1;
    out.selected.z2 = proved.proof.batch.z2;
    out.native_shape =
        rc::Fri3AlgShapeCommit(
            proved.proof.batch.n_coeffs,
            proved.proof.batch.column_len);
    out.native_ood =
        rc::Fri3AlgOodEvalCommit(
            proved.proof.batch.z1,
            proved.proof.batch.z2,
            proved.proof.batch.evals_z1,
            proved.proof.batch.evals_z2);
    out.product =
        derived::BuildProductV1(
            out.shape, out.words, out.selected);
    return out;
}

void RequireForcedProofReject(
    const Fixture& fixture,
    std::vector<std::vector<gf::Fp3>> columns,
    const char* label)
{
    BOOST_REQUIRE_GT(
        derived::CountViolationsV1(
            fixture.product.cs, columns),
        0U);
    aq::AirProveOptions adversarial;
    adversarial.force_commit_on_inexact = true;
    const auto forged =
        aq::AirQuotientProveRows(
            fixture.product.cs, columns,
            fixture.seed, adversarial);
    BOOST_REQUIRE_MESSAGE(
        forged.ok, label << ": " << forged.note);
    BOOST_CHECK_MESSAGE(
        !forged.division_exact, label);
    derived::ProofV1 envelope;
    envelope.binding = fixture.product.binding;
    envelope.proof = forged.proof;
    std::string why;
    BOOST_CHECK_MESSAGE(
        !derived::VerifyV1(
            fixture.shape,
            fixture.product.binding,
            envelope, fixture.seed, &why),
        label << ": " << why);
}

} // namespace

BOOST_AUTO_TEST_CASE(
    exact_native_hashes_prove_and_all_transplants_reject)
{
    const Fixture fixture = BuildFixture();
    const auto& product = fixture.product;
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(
        product.binding.shape_commit ==
        fixture.native_shape);
    BOOST_CHECK(
        product.binding.ood_evaluation_commit ==
        fixture.native_ood);
    BOOST_CHECK(
        product.canonical_safe_v13_tape_decoded);
    BOOST_CHECK(product.source_values_ordinary_columns);
    BOOST_CHECK(product.no_preprocessed_proof_values);
    BOOST_CHECK(
        product.canonical_two_u32_goldilocks_air);
    BOOST_CHECK(
        product.selected_points_equal_tape_z_air);
    BOOST_CHECK(product.exact_poseidon2_relations);
    BOOST_CHECK(
        !product.proof_tape_same_parent_equality_executed);
    BOOST_CHECK(!product.recursively_consumed);
    BOOST_CHECK(!product.recursive_authority_ready);
    BOOST_CHECK(
        !derived::kProofTapeSameParentEqualityExecutedV1);
    BOOST_CHECK(
        !derived::kDerivedHashRecursiveAuthorityReadyV1);
    BOOST_REQUIRE_EQUAL(
        product.schedule.digest_exports.size(), 2U);
    for (const auto& digest :
         product.schedule.digest_exports) {
        BOOST_CHECK(
            digest.value_is_virtual_poseidon2_output);
    }
    for (const auto& source :
         product.schedule.source_exports) {
        BOOST_CHECK_NE(
            source.source_address, UINT32_MAX);
        if (source.has_high_source) {
            BOOST_CHECK_NE(
                source.high_source_address, UINT32_MAX);
        }
    }

    derived::ProofV1 proof;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        derived::ProveV1(
            product, fixture.seed, proof, &why),
        why);
    BOOST_CHECK(
        derived::VerifyV1(
            fixture.shape, product.binding,
            proof, fixture.seed, &why));

    // Attack 1: alter one ordinary-column input bit while preserving
    // the source word. The quotient is inexact and the unmodified
    // verifier rejects the force-committed proof.
    {
        auto columns = product.columns;
        const auto source = std::find_if(
            product.schedule.source_exports.begin(),
            product.schedule.source_exports.end(),
            [](const auto& item) {
                return item.u32_source;
            });
        BOOST_REQUIRE(
            source !=
            product.schedule.source_exports.end());
        const uint32_t bit =
            product.layout.Bit(source->lane, 0);
        columns[bit][source->row] =
            gf::Sub(
                gf::Fp3::One(),
                columns[bit][source->row]);
        RequireForcedProofReject(
            fixture, std::move(columns),
            "input-bit transplant");
    }

    // Attack 2: transplant a separately witness-selected z cell. It
    // must equal the corresponding canonical proof-tape ABI source.
    {
        auto columns = product.columns;
        const auto source = std::find_if(
            product.schedule.source_exports.begin(),
            product.schedule.source_exports.end(),
            [](const auto& item) {
                return item.selected_point_source;
            });
        BOOST_REQUIRE(
            source !=
            product.schedule.source_exports.end());
        columns[
            product.layout.SelectedValue(
                source->lane)][source->row] =
            gf::Add(
                columns[
                    product.layout.SelectedValue(
                        source->lane)][source->row],
                gf::Fp3::One());
        RequireForcedProofReject(
            fixture, std::move(columns),
            "selected-z transplant");

        auto selected = fixture.selected;
        selected.z1.c0 =
            gf::Add(selected.z1.c0, gf::FromU64(1));
        const auto changed =
            derived::BuildProductV1(
                fixture.shape, fixture.words, selected);
        BOOST_CHECK(!changed.valid);
        BOOST_CHECK_GT(changed.violations, 0U);
    }

    // Attack 3: transplant one output digest byte. Also show that a
    // public digest transplant cannot validate the original proof.
    {
        auto columns = product.columns;
        const auto& digest =
            product.schedule.digest_exports[0];
        const uint32_t column =
            digest.byte_column[0][0];
        columns[column][digest.terminal_row] =
            gf::Add(
                columns[column][digest.terminal_row],
                gf::Fp3::One());
        RequireForcedProofReject(
            fixture, std::move(columns),
            "output-digest transplant");

        auto changed = proof;
        changed.binding.shape_commit[0] =
            gf::Add(
                changed.binding.shape_commit[0],
                gf::FromU64(1));
        BOOST_CHECK(
            !derived::VerifyV1(
                fixture.shape, changed.binding,
                changed, fixture.seed, &why));
    }

    // Attack 4: committed cells outside their semantic selector are
    // canonical zero, rather than unconstrained witness slack.
    {
        auto columns = product.columns;
        uint32_t fixed_row = UINT32_MAX;
        uint32_t fixed_lane = UINT32_MAX;
        for (uint32_t row = 0;
             row < product.schedule.active_rows &&
             fixed_row == UINT32_MAX; ++row) {
            for (uint32_t lane = 0;
                 lane < derived::kRateV1; ++lane) {
                if (gf::IsZero(
                        product.columns[
                            product.layout.SourceActive(
                                lane)][row])) {
                    fixed_row = row;
                    fixed_lane = lane;
                    break;
                }
            }
        }
        BOOST_REQUIRE_NE(fixed_row, UINT32_MAX);
        BOOST_REQUIRE_NE(fixed_lane, UINT32_MAX);
        const uint32_t bit =
            product.layout.Bit(fixed_lane, 0);
        columns[bit][fixed_row] =
            gf::Fp3::One();
        RequireForcedProofReject(
            fixture, std::move(columns),
            "fixed-padding-source-bit transplant");
    }
    {
        auto columns = product.columns;
        uint32_t nonterminal_row = 0;
        while (
            nonterminal_row ==
                product.schedule.shape_terminal_row ||
            nonterminal_row ==
                product.schedule.ood_terminal_row) {
            ++nonterminal_row;
        }
        BOOST_REQUIRE_LT(
            nonterminal_row, product.cs.n_rows);
        const uint32_t byte =
            product.layout.DigestByte(0, 0);
        columns[byte][nonterminal_row] =
            gf::Fp3::One();
        RequireForcedProofReject(
            fixture, std::move(columns),
            "inactive-digest-byte transplant");
    }

    // Attack 5: session-reset state is exactly zero. In particular,
    // no unconsumed row-zero state can carry arbitrary committed data.
    {
        auto columns = product.columns;
        columns[product.layout.State(0)][0] =
            gf::Fp3::One();
        RequireForcedProofReject(
            fixture, std::move(columns),
            "row-zero-state transplant");
    }
    {
        auto columns = product.columns;
        const uint32_t ood_first =
            product.schedule.shape_terminal_row + 1;
        BOOST_REQUIRE_LT(
            ood_first, product.schedule.active_rows);
        BOOST_CHECK(gf::IsZero(
            columns[product.layout.State(0)][ood_first]));
        columns[product.layout.State(0)][ood_first] =
            gf::Fp3::One();
        RequireForcedProofReject(
            fixture, std::move(columns),
            "session-reset-state transplant");
    }

    // Attack 6: x and x+p may be the same base-field element after
    // reduction, but p is not a canonical two-u32 ABI value. The V13
    // decoder rejects it before any proof witness can be built.
    {
        auto words = fixture.words;
        const proofabi::SourceKeyV1 low{
            proofabi::FieldKindV1::Z1, 0, 0, 0, 0, 0};
        const proofabi::SourceKeyV1 high{
            proofabi::FieldKindV1::Z1, 0, 0, 0, 0, 1};
        const auto low_address =
            proofabi::FindSourceAddressV1(
                fixture.sources, low);
        const auto high_address =
            proofabi::FindSourceAddressV1(
                fixture.sources, high);
        BOOST_REQUIRE(low_address.has_value());
        BOOST_REQUIRE(high_address.has_value());
        const auto value_word =
            [&](uint32_t address) {
                const uint32_t offset =
                    6 + 2 * address;
                BOOST_REQUIRE_LT(offset + 1, words.size());
                BOOST_REQUIRE_EQUAL(
                    words[offset], address);
                return offset + 1;
            };
        words[value_word(*low_address)] = 1;
        words[value_word(*high_address)] = UINT32_MAX;
        BOOST_CHECK(
            !proofabi::DecodeCanonicalSafeV13(
                words, &why).has_value());
        const auto changed =
            derived::BuildProductV1(
                fixture.shape, words,
                fixture.selected);
        BOOST_CHECK(!changed.valid);
    }

    BOOST_TEST_MESSAGE(
        "V13_DERIVED_HASH_AIR rows="
        << product.cs.n_rows
        << " columns=" << product.cs.n_columns
        << " constraints="
        << product.cs.constraints.size()
        << " sources="
        << product.schedule.source_exports.size());
}

BOOST_AUTO_TEST_SUITE_END()
