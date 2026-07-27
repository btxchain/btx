// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_mlink.h>

#include <matmul/matmul_v4_rc_gkr_field_ext3.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <string>
#include <vector>

namespace ml = matmul::v4::rc::stage3_mlink;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_mlink_tests, BasicTestingSetup)

namespace {

uint256 Filled(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

ml::MLinkCellV1 Cell(uint64_t row, uint64_t value)
{
    return ml::MLinkCellV1{row, gf::FromU64_3(value)};
}

// Two cross-shard equality obligations whose anchor and replica multisets are
// identical (honest transported columns).
std::vector<ml::MLinkObligationV1> HonestObligations()
{
    std::vector<ml::MLinkObligationV1> obs;

    ml::MLinkObligationV1 a;
    a.link_index = 0;
    a.global_column = 7;
    a.anchor_shard = 0;
    a.replica_shard = 1;
    a.anchor_cells = {Cell(0, 11), Cell(1, 22), Cell(2, 33), Cell(3, 44)};
    a.replica_cells = a.anchor_cells; // identical (row_index, value) tuples
    obs.push_back(a);

    ml::MLinkObligationV1 b;
    b.link_index = 1;
    b.global_column = 12;
    b.anchor_shard = 0;
    b.replica_shard = 2;
    b.anchor_cells = {Cell(0, 100), Cell(1, 200), Cell(2, 300)};
    b.replica_cells = b.anchor_cells;
    obs.push_back(b);

    return obs;
}

std::vector<uint256> Roots()
{
    return {Filled(0x11), Filled(0x22), Filled(0x33)};
}

} // namespace

// Honest witness: both lanes accumulate to root 0, 0 violations, executable.
BOOST_AUTO_TEST_CASE(mlink_honest_root_zero_both_lanes)
{
    const auto obs = HonestObligations();
    const auto ch =
        ml::DeriveMLinkChallengesV1(Roots(), Filled(0xAB), obs);
    BOOST_CHECK(ch.drawn_after_all_shard_commitments);
    BOOST_CHECK(ch.degenerate_free);

    const auto eval = ml::EvaluateMLinkV1(obs, ch);
    BOOST_CHECK(eval.executable);
    BOOST_CHECK_EQUAL(eval.link_count, 2U);
    BOOST_CHECK(eval.lane[0].root_is_zero);
    BOOST_CHECK(eval.lane[1].root_is_zero);
    BOOST_CHECK(eval.lane[0].inverse_witness_consistent);
    BOOST_CHECK(eval.lane[1].inverse_witness_consistent);
    BOOST_CHECK(eval.honest_all_roots_zero);
    BOOST_CHECK(!eval.link_fires);
    BOOST_CHECK_EQUAL(eval.violated_link_index, 0xFFFFFFFFu);
    BOOST_CHECK(gf::IsZero(eval.lane[0].accumulator_root));
    BOOST_CHECK(gf::IsZero(eval.lane[1].accumulator_root));
}

// Tamper: a single mismatched cross-shard VALUE makes the link fire.
BOOST_AUTO_TEST_CASE(mlink_value_mismatch_fires)
{
    auto obs = HonestObligations();
    // Corrupt one replica value on link 1 (row 2: 300 -> 301).
    obs[1].replica_cells[2] = Cell(2, 301);

    const auto ch =
        ml::DeriveMLinkChallengesV1(Roots(), Filled(0xAB), obs);
    BOOST_CHECK(ch.degenerate_free);

    const auto eval = ml::EvaluateMLinkV1(obs, ch);
    BOOST_CHECK(eval.executable);
    BOOST_CHECK(eval.link_fires);
    BOOST_CHECK(!eval.honest_all_roots_zero);
    // At least one lane's accumulator is non-zero.
    BOOST_CHECK(!eval.lane[0].root_is_zero || !eval.lane[1].root_is_zero);
    BOOST_CHECK_EQUAL(eval.violated_link_index, 1U);
}

// Tamper: a pure ROW permutation (same values, permuted rows) also fires,
// because the tuple is (row_index, value) tagged. Value-only equality would
// miss this.
BOOST_AUTO_TEST_CASE(mlink_row_permutation_fires)
{
    auto obs = HonestObligations();
    // Same value multiset, rows permuted on the replica of link 0.
    obs[0].replica_cells = {Cell(1, 11), Cell(0, 22), Cell(2, 33), Cell(3, 44)};

    const auto ch =
        ml::DeriveMLinkChallengesV1(Roots(), Filled(0xAB), obs);
    BOOST_CHECK(ch.degenerate_free);

    const auto eval = ml::EvaluateMLinkV1(obs, ch);
    BOOST_CHECK(eval.executable);
    BOOST_CHECK(eval.link_fires);
    BOOST_CHECK_EQUAL(eval.violated_link_index, 0U);
}

// Challenges are a deterministic function of the ordered shard roots (and the
// manifest commitment); changing a root changes the draw. This documents that
// the roots are inputs to the challenge, never the reverse (no FS fixed point).
BOOST_AUTO_TEST_CASE(mlink_challenges_bind_all_shard_roots)
{
    const auto obs = HonestObligations();
    const auto ch1 = ml::DeriveMLinkChallengesV1(Roots(), Filled(0xAB), obs);

    auto roots2 = Roots();
    roots2[2] = Filled(0x34); // perturb the last shard root
    const auto ch2 = ml::DeriveMLinkChallengesV1(roots2, Filled(0xAB), obs);

    BOOST_CHECK(!gf::Eq(ch1.gamma[0], ch2.gamma[0]) ||
                !gf::Eq(ch1.gamma[1], ch2.gamma[1]));

    // Honest witness still verifies to root 0 under the rebound challenges.
    const auto eval2 = ml::EvaluateMLinkV1(obs, ch2);
    BOOST_CHECK(eval2.honest_all_roots_zero);
}

// The single global gamma-injectivity floor is ~2^-94 under the production
// event envelope and clears both the 64-bit acceptance line and the q*=76
// threat-model bar. ONE epsilon for the whole link, not a 2*Lambda union.
BOOST_AUTO_TEST_CASE(mlink_soundness_floor_clears_bars)
{
    const auto sound = ml::AssessMLinkSoundnessV1();
    BOOST_CHECK(sound.one_global_epsilon);
    BOOST_CHECK(sound.dual_independent_lanes);
    // 189 - log2(37,488,397) - log2(52*2^24) - 40 ~= 94.14.
    BOOST_CHECK_CLOSE(sound.epsilon_mlink_bits, 94.1396, 1e-2);
    BOOST_CHECK(sound.clears_minimum_acceptance_bar);   // >= 64
    BOOST_CHECK(sound.clears_qstar_76_threat_bar);      // >= 76
    BOOST_CHECK_GE(sound.epsilon_mlink_bits, 64.0);
}

// The executable evaluator is what backs the composition-ledger flag.
BOOST_AUTO_TEST_CASE(mlink_backs_composition_ledger_flag)
{
    BOOST_CHECK(ml::MLinkDualLaneArithmeticExecutable());
    BOOST_CHECK_EQUAL(std::string(ml::kMLinkSatisfiedCompositionLedgerFlag),
                      "ctl_dual_lane_arithmetic_executable");
    // Executable + tamper-tested, but NOT a certified theorem.
    BOOST_CHECK(!ml::kMLinkFormalSoundnessReady);
}

BOOST_AUTO_TEST_SUITE_END()
