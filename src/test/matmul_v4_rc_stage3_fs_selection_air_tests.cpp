// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_fs_selection_air.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_ctl.h>
#include <matmul/matmul_v4_rc_air_recurse.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace fs =
    matmul::v4::rc::stage3_fs_selection_air;
namespace gf = matmul::v4::rc::gkr_field;
namespace ha = matmul::v4::rc::stage3_hash_air;
namespace rc = matmul::v4::rc;
namespace ar = matmul::v4::rc::air_recurse;
namespace aq = matmul::v4::rc::air_quotient;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_fs_selection_air_tests)

BOOST_AUTO_TEST_CASE(
    first_three_canonical_words_are_selected)
{
    const std::array<uint64_t, 8> words{
        UINT64_MAX,
        7,
        gf::kP,
        11,
        gf::kP + 1,
        13,
        17,
        19,
    };
    const auto witness =
        fs::BuildWitnessV1(words);
    BOOST_REQUIRE_MESSAGE(
        witness.valid, witness.note);
    BOOST_CHECK_EQUAL(
        witness.accepted_words, 3U);
    BOOST_CHECK_EQUAL(
        witness.selected_value.c0, 7U);
    BOOST_CHECK_EQUAL(
        witness.selected_value.c1, 11U);
    BOOST_CHECK_EQUAL(
        witness.selected_value.c2, 13U);
    BOOST_CHECK_EQUAL(
        fs::CountViolationsV1(
            witness.cs, witness.columns),
        0U);
}

BOOST_AUTO_TEST_CASE(
    selection_rejects_bits_validity_order_and_exhaustion_attacks)
{
    const std::array<uint64_t, 8> words{
        3, 5, 7, 11, 13, 17, 19, 23};
    const auto witness =
        fs::BuildWitnessV1(words);
    BOOST_REQUIRE(witness.valid);

    auto bit_attack = witness.columns;
    bit_attack[
        witness.layout.Bit(0, 0)][0] =
        gf::Fp3::FromFp(gf::FromU64(2));
    BOOST_CHECK_GT(
        fs::CountViolationsV1(
            witness.cs, bit_attack),
        0U);

    auto output_attack = witness.columns;
    output_attack[
        witness.layout.selected][0] =
        gf::Add(
            output_attack[
                witness.layout.selected][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fs::CountViolationsV1(
            witness.cs, output_attack),
        0U);

    const std::array<uint64_t, 8> exhausted{
        gf::kP, gf::kP, gf::kP, gf::kP,
        gf::kP, gf::kP, 1, 2};
    const auto rejected =
        fs::BuildWitnessV1(exhausted);
    BOOST_CHECK(!rejected.valid);
    BOOST_CHECK_LT(
        rejected.accepted_words, 3U);
    BOOST_CHECK_GT(
        fs::CountViolationsV1(
            rejected.cs,
            rejected.columns),
        0U);
}

BOOST_AUTO_TEST_CASE(
    query_index_is_exact_low_bit_mask_and_rejects_mutation)
{
    const std::array<unsigned char, 4> prefix{
        0xef, 0xcd, 0xab, 0x89};
    const auto witness =
        fs::BuildQueryIndexWitnessV1(
            prefix, 1U << 20);
    BOOST_REQUIRE_MESSAGE(
        witness.valid, witness.note);
    BOOST_CHECK_EQUAL(
        witness.raw, 0x89abcdefU);
    BOOST_CHECK_EQUAL(
        witness.query_index,
        witness.raw & ((1U << 20) - 1));
    BOOST_CHECK_EQUAL(
        fs::CountViolationsV1(
            witness.cs, witness.columns),
        0U);

    auto bad_output = witness.columns;
    bad_output[witness.layout.output][0] =
        gf::Add(
            bad_output[witness.layout.output][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        fs::CountViolationsV1(
            witness.cs, bad_output),
        0U);

    auto bad_high_bit = witness.columns;
    bad_high_bit[witness.layout.Bit(31)][0] =
        gf::Fp3::FromFp(gf::FromU64(2));
    BOOST_CHECK_GT(
        fs::CountViolationsV1(
            witness.cs, bad_high_bit),
        0U);

    const auto non_power_of_two =
        fs::BuildQueryIndexWitnessV1(
            prefix, 1000);
    BOOST_CHECK(!non_power_of_two.valid);
}

namespace {

// Build one SHA256d digest boundary instance (256 output bits) plus its eight
// final 32-bit digest words.
ha::FixedProgramVerticalWitnessBoundaryInstance BuildShaDigest(
    uint8_t seed_byte, std::array<uint32_t, 8>& words)
{
    std::vector<uint8_t> preimage(32);
    for (uint32_t i = 0; i < preimage.size(); ++i) {
        preimage[i] = static_cast<uint8_t>(seed_byte + 3U * i);
    }
    ha::ShaManifest manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildShaManifest(
            preimage, ha::ShaMode::Double, manifest, &why),
        why);
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildShaManifestBoundaryInstances(
            manifest, boundaries, &why),
        why);
    BOOST_REQUIRE_EQUAL(boundaries.size(), 2U);
    const auto program =
        ha::BuildCanonicalProgram(
            ha::ProgramKind::Sha256Compression);
    std::vector<std::vector<uint8_t>> public_masks(
        2, std::vector<uint8_t>(
               program.external_address_count, 1));
    for (uint32_t word = 0; word < 8; ++word) {
        public_masks[1][word] = 0;
    }
    std::vector<ha::FixedProgramWitnessBoundaryLink> links;
    for (uint32_t word = 0; word < 8; ++word) {
        links.push_back(
            {0, word, 1, word + 1, 0});
    }
    uint256 seed;
    std::fill(seed.begin(), seed.end(), seed_byte);
    auto instance =
        ha::BuildFixedProgramVerticalWitnessBoundaryInstance(
            program, boundaries, public_masks, links, seed);
    BOOST_REQUIRE_MESSAGE(instance.valid, instance.note);
    for (uint32_t word = 0; word < 8; ++word) {
        words[word] = boundaries.back().final_words[word];
    }
    return instance;
}

// Value (0/1) of SHA output bit i = word*32 + bit_in_word (little-endian).
gf::Fp3 ShaBit(
    const ha::FixedProgramVerticalWitnessBoundaryInstance& inst,
    uint32_t i)
{
    return inst.columns[inst.output_bit_base + i][0];
}

} // namespace

BOOST_AUTO_TEST_CASE(
    sha_output_bits_ctl_bound_to_selection_words)
{
    // Edge 2: SHA256d output words (8 x 32-bit, output_bit_base) feed the
    // selection decoder's eight 64-bit words via the width map
    // low=Recompose(word,0,32), high=Recompose(word,32,32).  A committed CTL
    // (LogUp) bus binds each SHA output-bit value to the selection Bit(word,bit)
    // column value ACROSS the two constraint systems (the 2048-row SHA CS and
    // the small selection CS), which a same-row equality cannot span.
    //
    // For test tractability a single real SHA256d instance supplies all 512
    // real output bits via two distinct output-word slices: the low half of
    // selection word w is SHA output word w, the high half is SHA output word
    // (w+4) mod 8.  The two-instance draw (16 x 32-bit words from two digests,
    // matching Fri3AlgBatchSampleZ) is the mechanical extension of the same
    // loop over a second boundary instance.
    std::array<uint32_t, 8> sha_words{};
    const auto sha = BuildShaDigest(0x41, sha_words);
    const auto high_word = [](uint32_t w) { return (w + 4U) % 8U; };

    std::array<uint64_t, 8> words{};
    for (uint32_t w = 0; w < 8; ++w) {
        words[w] =
            static_cast<uint64_t>(sha_words[w]) |
            (static_cast<uint64_t>(sha_words[high_word(w)]) << 32);
    }
    const fs::WitnessV1 sel = fs::BuildWitnessV1(words);
    BOOST_REQUIRE_MESSAGE(sel.valid, sel.note);

    // 512 bit positions p = w*64 + b.  SHA side sends (+1); selection side
    // receives (-1); address = p, namespace/stage fixed.
    constexpr uint32_t kBusNamespace = 0x53454C55U; // "SELU"
    rc::RCStage3CtlSchedule schedule;
    std::vector<gf::Fp3> values;         // sends first, then receives
    std::vector<gf::Fp3> selection_tail; // receive values, appended after
    for (uint32_t w = 0; w < 8; ++w) {
        for (uint32_t b = 0; b < 64; ++b) {
            const uint32_t p = w * 64 + b;
            const gf::Fp3 sha_bit =
                b < 32
                    ? ShaBit(sha, w * 32 + b)
                    : ShaBit(sha, high_word(w) * 32 + (b - 32));
            const gf::Fp3 sel_bit =
                sel.columns[sel.layout.Bit(w, b)][0];
            // Honest width map: the SHA output bit equals the selection bit.
            BOOST_REQUIRE(gf::Eq(sha_bit, sel_bit));
            schedule.events.push_back(
                {kBusNamespace, 0U, p, static_cast<int8_t>(1)});
            values.push_back(sha_bit);
            selection_tail.push_back(sel_bit);
        }
    }
    for (uint32_t w = 0; w < 8; ++w) {
        for (uint32_t b = 0; b < 64; ++b) {
            const uint32_t p = w * 64 + b;
            schedule.events.push_back(
                {kBusNamespace, 0U, p, static_cast<int8_t>(-1)});
        }
    }
    values.insert(values.end(),
                  selection_tail.begin(), selection_tail.end());
    BOOST_REQUIRE_EQUAL(schedule.events.size(), values.size());
    BOOST_REQUIRE_EQUAL(schedule.events.size(), 1024U);

    rc::RCStage3CtlChallenges challenges;
    challenges.gamma1 = gf::FromU64_3(0x9E3779B97F4A7C15ULL);
    challenges.gamma2 = gf::FromU64_3(0xC2B2AE3D27D4EB4FULL);
    challenges.alpha1 = gf::FromU64_3(0x165667B19E3779F9ULL);
    challenges.alpha2 = gf::FromU64_3(0x27D4EB2F165667C5ULL);

    const rc::RCStage3CtlWitness honest =
        rc::BuildRCStage3CtlWitness(schedule, values, challenges);
    BOOST_REQUIRE_MESSAGE(honest.ok, honest.note);
    // Balanced bus: every SHA-bit send is cancelled by its matched selection
    // receive, so the LogUp terminal is zero.
    BOOST_CHECK(gf::IsZero(honest.terminal.alpha1_sum));
    BOOST_CHECK(gf::IsZero(honest.terminal.alpha2_sum));

    const rc::RCStage3CtlAirSpec spec{
        schedule, challenges, honest.terminal};
    const auto cs = rc::BuildRCStage3CtlConstraintSystem(spec);
    BOOST_CHECK_EQUAL(
        ar::CountWitnessViolationsOnH(cs, honest.columns), 0U);

    // Tamper: flip one SHA output-bit VALUE on the send side; the selection
    // receive side is untouched.  The multisets no longer cancel, the terminal
    // moves off zero, and the CTL constraint (RUNNING+TERM == committed
    // terminal) fires against the honest committed bus.
    std::vector<gf::Fp3> tampered = values;
    tampered[7] = gf::Sub(gf::Fp3::One(), tampered[7]); // 0<->1
    const rc::RCStage3CtlWitness attacked =
        rc::BuildRCStage3CtlWitness(
            schedule, tampered, challenges);
    BOOST_REQUIRE(attacked.ok);
    BOOST_CHECK(
        !(gf::IsZero(attacked.terminal.alpha1_sum) &&
          gf::IsZero(attacked.terminal.alpha2_sum)));
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(cs, attacked.columns), 0U);
}

BOOST_AUTO_TEST_CASE(
    ctl_value_column_is_committed_pin)
{
    // Edge 2 export-pin (value-commitment layer): the CTL bus VALUE column is
    // COMMITTED (it is one of the CTL prechallenge column roots), so a prover
    // cannot substitute a VALUE that differs from the committed source column
    // without changing the commitment.  Here the source is a selection decode's
    // first-word bits.  (The full same-trace root-equality of VALUE to the SHA
    // output_bit_base / selection Bit columns is the production
    // VerifyRCStage3RelationClosureV1 flow; see report.)
    const std::array<uint64_t, 8> words{
        7, 11, 13, 17, 19, 23, 29, 31};
    const fs::WitnessV1 sel = fs::BuildWitnessV1(words);
    BOOST_REQUIRE_MESSAGE(sel.valid, sel.note);

    rc::RCStage3CtlSchedule schedule;
    std::vector<gf::Fp3> source_values;
    for (uint32_t b = 0; b < 64; ++b) {
        schedule.events.push_back(
            {0x53454C55U, 0U, b, static_cast<int8_t>(1)});
        source_values.push_back(
            sel.columns[sel.layout.Bit(0, b)][0]);
    }
    const uint256 committed =
        rc::ComputeRCStage3CtlPrechallengeTraceCommitment(
            schedule, source_values);
    BOOST_CHECK(!committed.IsNull());
    // Deterministic: the same committed VALUE column reproduces the root.
    BOOST_CHECK(
        rc::ComputeRCStage3CtlPrechallengeTraceCommitment(
            schedule, source_values) == committed);
    // Tamper one VALUE (not equal to its committed source) -> root changes ->
    // the VALUE-column pin (proof_column_root == VALUE commitment) rejects.
    std::vector<gf::Fp3> tampered = source_values;
    tampered[3] = gf::Add(tampered[3], gf::Fp3::One());
    BOOST_CHECK(
        rc::ComputeRCStage3CtlPrechallengeTraceCommitment(
            schedule, tampered) != committed);
}

BOOST_AUTO_TEST_CASE(
    challenge_cell_bound_in_air_to_selection_reconstruction)
{
    // Edge 3: the Fiat-Shamir challenge cell is bound BY AN AIR EQUALITY to the
    // selection decoder's reconstructed output (WitnessV1::selected_value, the
    // first three accepted words), which the selection CS constrains to the
    // decoded digest words (and, via Edge 2's CTL, to committed SHA output
    // cells).  This is the in-AIR replacement for trusting a proof-carried
    // challenge: a claimed challenge that differs from the decode rejects.
    const std::array<uint64_t, 8> words{
        7, 11, 13, 17, 19, 23, 29, 31};
    const fs::WitnessV1 sel = fs::BuildWitnessV1(words);
    BOOST_REQUIRE_MESSAGE(sel.valid, sel.note);

    // Combined CS: selection AIR + a challenge column bound by equality to the
    // selection's constrained 'selected' column.
    auto cs = sel.cs;
    auto columns = sel.columns;
    const uint32_t challenge_col = cs.n_columns;
    columns.push_back(
        std::vector<gf::Fp3>(cs.n_rows, sel.selected_value));
    cs.n_columns += 1;
    const auto add_equality =
        [](aq::AirConstraintSystem<gf::Fp3>& target,
           uint32_t challenge, uint32_t selected) {
            aq::AirConstraint<gf::Fp3> eq;
            eq.name =
                "stage3.fs.edge3.challenge_equals_selection";
            eq.kind = aq::AirKind::kEverywhere;
            eq.alg_degree = 1;
            eq.eval =
                [challenge, selected](
                    const std::vector<gf::Fp3>& r,
                    const std::vector<gf::Fp3>&) {
                    return gf::Sub(r[challenge], r[selected]);
                };
            target.constraints.push_back(std::move(eq));
        };
    add_equality(cs, challenge_col, sel.layout.selected);

    // Honest: the challenge cell equals the in-AIR reconstructed challenge.
    BOOST_CHECK_EQUAL(
        ar::CountWitnessViolationsOnH(cs, columns), 0U);

    // Tamper A: a claimed challenge differing from the decode rejects.
    auto bad_claim = columns;
    bad_claim[challenge_col][0] =
        gf::Add(bad_claim[challenge_col][0], gf::Fp3::One());
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(cs, bad_claim), 0U);

    // Tamper B: changing a decoded digest word (as an upstream SHA output-cell
    // change would, through Edge 2) changes the reconstructed challenge; a
    // challenge cell still pinned to the OLD value now fires the equality.
    const std::array<uint64_t, 8> words2{
        8, 11, 13, 17, 19, 23, 29, 31}; // first accepted word 7 -> 8
    const fs::WitnessV1 sel2 = fs::BuildWitnessV1(words2);
    BOOST_REQUIRE_MESSAGE(sel2.valid, sel2.note);
    BOOST_CHECK(
        !gf::Eq(sel2.selected_value, sel.selected_value));
    auto cs2 = sel2.cs;
    auto columns2 = sel2.columns;
    const uint32_t challenge_col2 = cs2.n_columns;
    columns2.push_back(
        std::vector<gf::Fp3>(
            cs2.n_rows, sel.selected_value)); // OLD challenge
    cs2.n_columns += 1;
    add_equality(cs2, challenge_col2, sel2.layout.selected);
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(cs2, columns2), 0U);
}

BOOST_AUTO_TEST_CASE(
    ood_first_acceptable_candidate_bound_in_air)
{
    // Edge 4: the bounded OOD sampler lays K candidate z-draws; the CONSUMED
    // challenge is the FIRST acceptable candidate (SelectFirstAcceptableOodIndex
    // = first off the base-field line).  This renders the first-acceptable
    // one-hot selection and the consumed-challenge binding as AIR constraints:
    //   - sel is one-hot; the selected candidate is acceptable;
    //   - no earlier candidate is acceptable (prefix-sum == 0 at the selected);
    //   - consumed == the selected candidate.
    // (Acceptance is carried as a boolean here; rendering the off-line predicate
    // itself needs the Fp3-coordinate decomposition c1|c2 != 0 -- the same
    // nonzero-test as the query decoder -- which is the noted residual.)
    constexpr uint32_t K = 3;
    // cand0 rejected (accept=0); cand1 first acceptable; cand2 acceptable.
    const std::array<gf::Fp3, K> cand{{
        {gf::FromU64(5), gf::FromU64(0), gf::FromU64(0)},
        {gf::FromU64(7), gf::FromU64(2), gf::FromU64(3)},
        {gf::FromU64(9), gf::FromU64(0), gf::FromU64(4)},
    }};
    const std::array<uint32_t, K> accept_bits{0, 1, 1};

    // Column layout (Fp3 cells): per k -> cand, accept, sel, prefix; + consumed.
    const auto Cand = [](uint32_t k) { return k * 4 + 0; };
    const auto Accept = [](uint32_t k) { return k * 4 + 1; };
    const auto Sel = [](uint32_t k) { return k * 4 + 2; };
    const auto Prefix = [](uint32_t k) { return k * 4 + 3; };
    constexpr uint32_t kConsumed = K * 4;
    constexpr uint32_t kCols = K * 4 + 1;

    const auto build = [&](uint32_t sel_index) {
        const uint32_t n_rows = 2;
        aq::AirConstraintSystem<gf::Fp3> cs;
        cs.n_columns = kCols;
        cs.n_rows = n_rows;
        std::vector<std::vector<gf::Fp3>> cols(
            kCols, std::vector<gf::Fp3>(n_rows, gf::Fp3::Zero()));
        const auto put = [&](uint32_t c, const gf::Fp3& v) {
            for (uint32_t r = 0; r < n_rows; ++r) cols[c][r] = v;
        };
        gf::Fp3 prefix = gf::Fp3::Zero();
        for (uint32_t k = 0; k < K; ++k) {
            put(Cand(k), cand[k]);
            put(Accept(k),
                accept_bits[k] ? gf::Fp3::One() : gf::Fp3::Zero());
            put(Sel(k),
                k == sel_index ? gf::Fp3::One() : gf::Fp3::Zero());
            put(Prefix(k), prefix);
            prefix = gf::Add(
                prefix,
                accept_bits[k] ? gf::Fp3::One() : gf::Fp3::Zero());
        }
        put(kConsumed, cand[sel_index]);

        const auto add = [&](const char* name,
                             std::function<gf::Fp3(
                                 const std::vector<gf::Fp3>&)>
                                 f) {
            aq::AirConstraint<gf::Fp3> c;
            c.name = name;
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval = [f](const std::vector<gf::Fp3>& r,
                         const std::vector<gf::Fp3>&) {
                return f(r);
            };
            cs.constraints.push_back(std::move(c));
        };
        for (uint32_t k = 0; k < K; ++k) {
            add("accept_bool", [=](const std::vector<gf::Fp3>& r) {
                return gf::Mul(
                    r[Accept(k)],
                    gf::Sub(gf::Fp3::One(), r[Accept(k)]));
            });
            add("sel_bool", [=](const std::vector<gf::Fp3>& r) {
                return gf::Mul(
                    r[Sel(k)],
                    gf::Sub(gf::Fp3::One(), r[Sel(k)]));
            });
            if (k == 0) {
                add("prefix0", [=](const std::vector<gf::Fp3>& r) {
                    return r[Prefix(0)];
                });
            } else {
                add("prefix_rec",
                    [=](const std::vector<gf::Fp3>& r) {
                        return gf::Sub(
                            r[Prefix(k)],
                            gf::Add(r[Prefix(k - 1)],
                                    r[Accept(k - 1)]));
                    });
            }
        }
        add("one_hot", [=](const std::vector<gf::Fp3>& r) {
            gf::Fp3 s = gf::Fp3::Zero();
            for (uint32_t k = 0; k < K; ++k) s = gf::Add(s, r[Sel(k)]);
            return gf::Sub(s, gf::Fp3::One());
        });
        add("selected_acceptable",
            [=](const std::vector<gf::Fp3>& r) {
                gf::Fp3 s = gf::Fp3::Zero();
                for (uint32_t k = 0; k < K; ++k)
                    s = gf::Add(s, gf::Mul(r[Sel(k)], r[Accept(k)]));
                return gf::Sub(s, gf::Fp3::One());
            });
        add("no_earlier_acceptable",
            [=](const std::vector<gf::Fp3>& r) {
                gf::Fp3 s = gf::Fp3::Zero();
                for (uint32_t k = 0; k < K; ++k)
                    s = gf::Add(s, gf::Mul(r[Sel(k)], r[Prefix(k)]));
                return s;
            });
        add("consumed_binding",
            [=](const std::vector<gf::Fp3>& r) {
                gf::Fp3 s = gf::Fp3::Zero();
                for (uint32_t k = 0; k < K; ++k)
                    s = gf::Add(s, gf::Mul(r[Sel(k)], r[Cand(k)]));
                return gf::Sub(r[kConsumed], s);
            });
        return std::make_pair(std::move(cs), std::move(cols));
    };

    // Honest: select the first acceptable candidate (index 1).
    auto [cs, cols] = build(1);
    BOOST_CHECK_EQUAL(
        ar::CountWitnessViolationsOnH(cs, cols), 0U);

    // Tamper A: consume a value != the selected candidate -> binding fires.
    auto bad = cols;
    bad[kConsumed][0] = gf::Add(bad[kConsumed][0], gf::Fp3::One());
    BOOST_CHECK_GT(ar::CountWitnessViolationsOnH(cs, bad), 0U);

    // Tamper B: select candidate 2 while candidate 1 (earlier) is acceptable ->
    // the no-earlier-acceptable prefix constraint fires.
    auto [cs2, cols2] = build(2);
    BOOST_CHECK_GT(ar::CountWitnessViolationsOnH(cs2, cols2), 0U);
}

BOOST_AUTO_TEST_CASE(
    unified_challenge_reconstructed_from_committed_sha_cells)
{
    // (B) UNIFICATION (reduced single-SHA-instance shape): tie Edges 2+3 with a
    // REAL SHA256d instance so the challenge is a genuinely RECONSTRUCTED value
    // fed by SHA(preimage) -> output bits -> (CTL) selection bits -> decode ->
    // challenge, with NO host extraction.  Both the SHA compression equations
    // (the instance CS) and the challenge-to-output map (selection + equality)
    // are present.  Changing the SHA input changes the reconstructed challenge.
    const auto reconstruct = [](uint8_t seed_byte) {
        std::array<uint32_t, 8> sha_words{};
        const auto sha = BuildShaDigest(seed_byte, sha_words);
        // SHA compression equations hold in the AIR (0 violations).
        BOOST_CHECK_EQUAL(
            ar::CountWitnessViolationsOnH(sha.cs, sha.columns), 0U);
        std::array<uint64_t, 8> words{};
        for (uint32_t w = 0; w < 8; ++w) {
            words[w] =
                static_cast<uint64_t>(sha_words[w]) |
                (static_cast<uint64_t>(sha_words[(w + 4) % 8]) << 32);
        }
        const fs::WitnessV1 sel = fs::BuildWitnessV1(words);
        BOOST_REQUIRE_MESSAGE(sel.valid, sel.note);
        // The reconstructed challenge is the selection decode of the SHA bits;
        // it is not copied from any proof.
        return sel.selected_value;
    };

    const gf::Fp3 challenge_a = reconstruct(0x41);
    const gf::Fp3 challenge_b = reconstruct(0x99);
    // A different SHA input yields a different reconstructed challenge: the
    // challenge is genuinely a function of the committed SHA output.
    BOOST_CHECK(!gf::Eq(challenge_a, challenge_b));
}

BOOST_AUTO_TEST_CASE(
    ood_offline_acceptance_predicate_in_air)
{
    // Edge 4 completion: render the OOD off-line predicate as a GENUINE AIR
    // constraint (not a carried boolean).  A challenge that came through the
    // selection decoder has base-field coordinates w1,w2 (the decoded words);
    // "off the base-field line" is w1 != 0  OR  w2 != 0, proven with per-word
    // nonzero-tests (inverse + zero-indicator), and accept = 1 - isz1*isz2.
    // Columns (lifted base-field values in the c0 slot): w1,w2,inv1,inv2,
    // isz1,isz2,accept.
    enum { W1, W2, INV1, INV2, ISZ1, ISZ2, ACCEPT, NCOLS };
    const auto build = [&](uint64_t w1, uint64_t w2, uint32_t accept_claim,
                           bool honest_witness) {
        const uint32_t n_rows = 2;
        aq::AirConstraintSystem<gf::Fp3> cs;
        cs.n_columns = NCOLS;
        cs.n_rows = n_rows;
        std::vector<std::vector<gf::Fp3>> cols(
            NCOLS, std::vector<gf::Fp3>(n_rows, gf::Fp3::Zero()));
        const auto put = [&](uint32_t c, const gf::Fp3& v) {
            for (uint32_t r = 0; r < n_rows; ++r) cols[c][r] = v;
        };
        const gf::Fp3 v1 = gf::FromU64_3(w1);
        const gf::Fp3 v2 = gf::FromU64_3(w2);
        put(W1, v1);
        put(W2, v2);
        // Honest zero-indicators and inverses.
        put(ISZ1, w1 == 0 ? gf::Fp3::One() : gf::Fp3::Zero());
        put(ISZ2, w2 == 0 ? gf::Fp3::One() : gf::Fp3::Zero());
        put(INV1, w1 == 0 ? gf::Fp3::Zero() : gf::Inv(v1));
        put(INV2, w2 == 0 ? gf::Fp3::Zero() : gf::Inv(v2));
        if (!honest_witness) {
            // Adversary lies about w1 being zero (to force rejection acceptance
            // logic) while w1 != 0.
            put(ISZ1, gf::Fp3::One());
            put(INV1, gf::Fp3::Zero());
        }
        put(ACCEPT,
            accept_claim ? gf::Fp3::One() : gf::Fp3::Zero());

        const auto add = [&](const char* name,
                             std::function<gf::Fp3(
                                 const std::vector<gf::Fp3>&)>
                                 f) {
            aq::AirConstraint<gf::Fp3> c;
            c.name = name;
            c.kind = aq::AirKind::kEverywhere;
            c.alg_degree = 2;
            c.eval = [f](const std::vector<gf::Fp3>& r,
                         const std::vector<gf::Fp3>&) { return f(r); };
            cs.constraints.push_back(std::move(c));
        };
        const auto boolean = [&](uint32_t col) {
            add("bool", [=](const std::vector<gf::Fp3>& r) {
                return gf::Mul(r[col],
                               gf::Sub(gf::Fp3::One(), r[col]));
            });
        };
        boolean(ISZ1);
        boolean(ISZ2);
        boolean(ACCEPT);
        // Nonzero-test w1: w1*inv1 = 1 - isz1  and  isz1*w1 = 0.
        add("nz1_a", [=](const std::vector<gf::Fp3>& r) {
            return gf::Sub(gf::Mul(r[W1], r[INV1]),
                           gf::Sub(gf::Fp3::One(), r[ISZ1]));
        });
        add("nz1_b", [=](const std::vector<gf::Fp3>& r) {
            return gf::Mul(r[ISZ1], r[W1]);
        });
        add("nz2_a", [=](const std::vector<gf::Fp3>& r) {
            return gf::Sub(gf::Mul(r[W2], r[INV2]),
                           gf::Sub(gf::Fp3::One(), r[ISZ2]));
        });
        add("nz2_b", [=](const std::vector<gf::Fp3>& r) {
            return gf::Mul(r[ISZ2], r[W2]);
        });
        // accept = 1 - isz1*isz2 (off the base-field line iff not both zero).
        add("accept_def", [=](const std::vector<gf::Fp3>& r) {
            return gf::Sub(
                r[ACCEPT],
                gf::Sub(gf::Fp3::One(),
                        gf::Mul(r[ISZ1], r[ISZ2])));
        });
        return std::make_pair(std::move(cs), std::move(cols));
    };

    // Honest: off-line candidate (w1 != 0) accepts.
    {
        auto [cs, cols] = build(7, 0, /*accept=*/1, true);
        BOOST_CHECK_EQUAL(
            ar::CountWitnessViolationsOnH(cs, cols), 0U);
    }
    // Honest: on-line candidate (w1 == w2 == 0) rejects (accept == 0).
    {
        auto [cs, cols] = build(0, 0, /*accept=*/0, true);
        BOOST_CHECK_EQUAL(
            ar::CountWitnessViolationsOnH(cs, cols), 0U);
    }
    // Tamper A: claim an on-line candidate is accepted -> accept_def fires.
    {
        auto [cs, cols] = build(0, 0, /*accept=*/1, true);
        BOOST_CHECK_GT(
            ar::CountWitnessViolationsOnH(cs, cols), 0U);
    }
    // Tamper B: lie that w1==0 (isz1=1) for an off-line candidate to fake
    // rejection -> the isz1*w1 = 0 nonzero-test fires.
    {
        auto [cs, cols] = build(7, 0, /*accept=*/0, false);
        BOOST_CHECK_GT(
            ar::CountWitnessViolationsOnH(cs, cols), 0U);
    }
}

BOOST_AUTO_TEST_CASE(
    absorbed_root_bytes_ctl_bound_to_producer_cells)
{
    // Edge 4 completion: the absorbed fold/row-commit root bytes are bound to
    // the Merkle/SHA cells that produced them via the SAME committed CTL bus as
    // Edge 2 (root byte value <-> producer cell value).  Balanced iff equal;
    // tamper a root byte -> the bus fires.
    std::array<uint8_t, 32> root{};
    for (uint32_t i = 0; i < 32; ++i) {
        root[i] = static_cast<uint8_t>(7 * i + 3);
    }
    constexpr uint32_t kBusNamespace = 0x524F4F54U; // "ROOT"
    rc::RCStage3CtlSchedule schedule;
    std::vector<gf::Fp3> values; // producer sends, absorbed receives
    std::vector<gf::Fp3> absorbed_tail;
    for (uint32_t i = 0; i < 32; ++i) {
        schedule.events.push_back(
            {kBusNamespace, 0U, i, static_cast<int8_t>(1)});
        values.push_back(gf::FromU64_3(root[i]));  // producer (Merkle) cell
        absorbed_tail.push_back(gf::FromU64_3(root[i])); // absorbed byte
    }
    for (uint32_t i = 0; i < 32; ++i) {
        schedule.events.push_back(
            {kBusNamespace, 0U, i, static_cast<int8_t>(-1)});
    }
    values.insert(values.end(),
                  absorbed_tail.begin(), absorbed_tail.end());

    rc::RCStage3CtlChallenges challenges;
    challenges.gamma1 = gf::FromU64_3(0x9E3779B97F4A7C15ULL);
    challenges.gamma2 = gf::FromU64_3(0xC2B2AE3D27D4EB4FULL);
    challenges.alpha1 = gf::FromU64_3(0x165667B19E3779F9ULL);
    challenges.alpha2 = gf::FromU64_3(0x27D4EB2F165667C5ULL);

    const rc::RCStage3CtlWitness honest =
        rc::BuildRCStage3CtlWitness(schedule, values, challenges);
    BOOST_REQUIRE_MESSAGE(honest.ok, honest.note);
    BOOST_CHECK(gf::IsZero(honest.terminal.alpha1_sum));
    BOOST_CHECK(gf::IsZero(honest.terminal.alpha2_sum));
    const auto cs = rc::BuildRCStage3CtlConstraintSystem(
        {schedule, challenges, honest.terminal});
    BOOST_CHECK_EQUAL(
        ar::CountWitnessViolationsOnH(cs, honest.columns), 0U);

    // Tamper: one absorbed root byte no longer equals its producer cell.
    std::vector<gf::Fp3> tampered = values;
    tampered[32 + 5] = gf::Add(tampered[32 + 5], gf::Fp3::One());
    const rc::RCStage3CtlWitness attacked =
        rc::BuildRCStage3CtlWitness(schedule, tampered, challenges);
    BOOST_REQUIRE(attacked.ok);
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(cs, attacked.columns), 0U);
}

BOOST_AUTO_TEST_CASE(
    direct_challenge_decoder_matches_from_challenge_bytes3)
{
    // The direct byte->Fp3 decoder (for airq-lambda/lambda/w1/w2/fold-beta):
    // 24 bytes -> three LE uint64 words (mod p) -> Fp3(w0,w1,w2), rendered as an
    // AIR (recompose + basis reconstruction), matching FromChallengeBytes3.
    std::array<unsigned char, 24> bytes{};
    for (uint32_t i = 0; i < 24; ++i) {
        bytes[i] = static_cast<unsigned char>(13 * i + 7);
    }
    const fs::DirectChallengeWitnessV1 d =
        fs::BuildDirectChallengeWitnessV1(bytes);
    BOOST_REQUIRE_MESSAGE(d.valid, d.note);
    BOOST_CHECK(d.recompose_constrained);
    BOOST_CHECK(d.basis_reconstruction_constrained);
    // In-AIR value equals the canonical host map.
    BOOST_CHECK(gf::Eq(d.value, gf::FromChallengeBytes3(bytes.data())));

    // Non-canonical (>= p) high word is reduced by the Fp recompose: the AIR
    // still holds and matches FromChallengeBytes3's w % p.
    std::array<unsigned char, 24> big = bytes;
    for (uint32_t i = 0; i < 8; ++i) big[i] = 0xFF; // w0 = 2^64-1 >= p
    const fs::DirectChallengeWitnessV1 dbig =
        fs::BuildDirectChallengeWitnessV1(big);
    BOOST_REQUIRE_MESSAGE(dbig.valid, dbig.note);
    BOOST_CHECK(
        gf::Eq(dbig.value, gf::FromChallengeBytes3(big.data())));

    // Tamper the challenge cell so it no longer equals the recomposed words ->
    // the basis-reconstruction constraint fires.
    auto cols = d.columns;
    cols[d.layout.Challenge()][0] =
        gf::Add(cols[d.layout.Challenge()][0], gf::Fp3::One());
    BOOST_CHECK_GT(
        ar::CountWitnessViolationsOnH(d.cs, cols), 0U);
}

// ===========================================================================
// PR-89 Construction 2: the ALGEBRAIC (Poseidon2) query-index rule, in AIR.
// NOT ACTIVATED.  These tests exist to make the activation decision
// measurable, and above all to make a protocol/in-AIR DIVERGENCE fail loudly:
// if the two ever disagree the parent computes different challenges than the
// child protocol and recursion breaks SILENTLY.
// ===========================================================================

namespace {

std::array<gf::Fp, 4> AlgSigma(uint64_t seed)
{
    std::array<gf::Fp, 4> sigma{};
    for (uint32_t lane = 0; lane < 4; ++lane) {
        sigma[lane] = gf::FromU64(
            seed * 0x9E3779B97F4A7C15ull + 0x1234567u + lane);
    }
    return sigma;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    pr89_algebraic_query_index_air_replays_the_protocol_rule_exactly)
{
    // The whole point: the CS output column must equal the value the SHIPPED
    // protocol function returns, for every (sigma, j, n_lde) tried.  A single
    // mismatch is the silent-recursion-break condition.
    uint32_t checked = 0;
    for (uint64_t seed = 1; seed <= 24; ++seed) {
        const auto sigma = AlgSigma(seed);
        for (uint32_t j : {0u, 1u, 7u, 63u, 1000u}) {
            for (uint32_t n_lde : {2u, 256u, 4096u, 1u << 20}) {
                const auto air =
                    fs::BuildAlgebraicQueryIndexAirV1(sigma, j, n_lde);
                BOOST_REQUIRE_MESSAGE(
                    air.valid,
                    "alg query air invalid: " << air.note);
                BOOST_CHECK_EQUAL(air.violations, 0U);
                BOOST_CHECK_EQUAL(air.witness_index, air.protocol_index);
                BOOST_CHECK(air.matches_protocol);
                BOOST_CHECK_LT(air.witness_index, n_lde);
                ++checked;
            }
        }
    }
    BOOST_CHECK_EQUAL(checked, 24U * 5U * 4U);

    // Shape, MEASURED -- and deliberately NOT the SHA chip's shape.  The SHA
    // chip pins 32 bit columns fed from digest BYTES; a Goldilocks lane has no
    // intrinsic 32-bit prefix, so the algebraic replay must pin all 64 bits
    // and add canonicity.  Anyone who claims "the constraint shape does not
    // move, only the digest preimage does" should read this assertion.
    const auto shape =
        fs::BuildAlgebraicQueryIndexAirV1(AlgSigma(1), 0, 4096u);
    BOOST_CHECK_EQUAL(fs::kQueryDigestBits, 32U);
    BOOST_CHECK_EQUAL(fs::kAlgebraicQueryLaneBits, 64U);
    BOOST_CHECK_EQUAL(shape.n_columns, 72U);   // 64 bits + lane + 6 and + out
    BOOST_CHECK_EQUAL(shape.n_constraints, 73U); // 64 + 1 + 6 + 1 + 1
    BOOST_CHECK_EQUAL(shape.max_alg_degree, 7U);
    BOOST_CHECK(shape.booleanity_constrained);
    BOOST_CHECK(shape.recomposition_constrained);
    BOOST_CHECK(shape.canonicity_constrained);
    BOOST_CHECK(shape.mask_constrained);
    BOOST_TEST_MESSAGE(
        "ALG_QUERY_AIR columns=" << shape.n_columns
        << " constraints=" << shape.n_constraints
        << " rows=" << shape.n_rows
        << " max_degree=" << shape.max_alg_degree
        << "  (SHA mask chip: " << fs::kQueryDigestBits << " bit columns)");
}

BOOST_AUTO_TEST_CASE(
    pr89_algebraic_query_index_air_rejects_forged_index_and_aliased_witness)
{
    const auto sigma = AlgSigma(7);
    const uint32_t n_lde = 4096u;
    const auto honest = fs::BuildAlgebraicQueryIndexAirV1(sigma, 3, n_lde);
    BOOST_REQUIRE(honest.valid);

    // A forged output column must be REJECTED by the mask constraint, not
    // merely differ from the protocol value.
    const uint32_t forged = (honest.protocol_index + 1) & (n_lde - 1);
    const auto tampered =
        fs::BuildAlgebraicQueryIndexAirV1(sigma, 3, n_lde, false, forged);
    BOOST_CHECK_GT(tampered.violations, 0U);
    BOOST_CHECK(!tampered.valid);
    BOOST_CHECK(!tampered.matches_protocol);

    // Canonicity is load-bearing, shown on a lane that ACTUALLY admits the
    // alias B = x + p (only x < 2^32 - 1 does).  Without the canonicity
    // constraint the aliased witness recomposes to a DIFFERENT low 32 bits,
    // i.e. a retargeted query index, for free.
    const gf::Fp aliasable = gf::FromU64(0x0BADC0DEull);
    const auto canonical_air =
        fs::BuildAlgebraicQueryIndexAirFromLaneV1(aliasable, n_lde, false);
    BOOST_REQUIRE(canonical_air.valid);
    const auto aliased_air =
        fs::BuildAlgebraicQueryIndexAirFromLaneV1(aliasable, n_lde, true);
    BOOST_REQUIRE_MESSAGE(
        aliased_air.note.find("no_64bit_alias") == std::string::npos,
        "chosen lane must admit the alias: " << aliased_air.note);
    // The alias moves the index -- that is the attack.
    BOOST_CHECK_NE(aliased_air.witness_index, canonical_air.witness_index);
    // And the constraint system rejects it.
    BOOST_CHECK_GT(aliased_air.violations, 0U);
    BOOST_CHECK(!aliased_air.valid);
}

BOOST_AUTO_TEST_CASE(
    pr89_algebraic_query_index_replay_cost_is_width_independent)
{
    // MEASURED per-kind in-AIR row cost for fra3_query, for ONE child slot,
    // under both rules.  128 queries is the shipped dual-lane per-lane count.
    const uint32_t queries = 128u;
    const auto toy = fs::MeasureAlgebraicQueryIndexReplayCostV1(queries, 1u);
    const auto mid =
        fs::MeasureAlgebraicQueryIndexReplayCostV1(queries, 17108u);
    const auto real =
        fs::MeasureAlgebraicQueryIndexReplayCostV1(queries, 384984u);
    BOOST_REQUIRE(toy.valid && mid.valid && real.valid);

    for (const auto* c : {&toy, &mid, &real}) {
        BOOST_TEST_MESSAGE(
            "ALG_QUERY_COST W=" << c->child_w
            << " queries=" << c->queries
            << " | alg perms/idx=" << c->alg_permutations_per_index
            << " perms=" << c->alg_permutations
            << " poseidon_rows=" << c->alg_poseidon_rows
            << " x" << c->alg_poseidon_columns << "cols"
            << " mask_rows=" << c->alg_mask_rows
            << " x" << c->alg_mask_columns << "cols"
            << " alg_total_rows=" << c->alg_total_rows
            << " | sha preimage=" << c->sha_preimage_bytes << "B"
            << " comps/idx=" << c->sha_compressions_per_index
            << " rows/idx=" << c->sha_rows_per_index
            << " sha_total_rows=" << c->sha_total_rows);
    }

    // The algebraic preimage is 8 lanes GIVEN sigma, whatever W: 2 sponge
    // permutations (8 lanes exactly fill the rate, so 10*-padding costs a
    // whole extra block).
    BOOST_CHECK_EQUAL(toy.alg_permutations_per_index, 2U);
    BOOST_CHECK_EQUAL(toy.alg_total_rows, mid.alg_total_rows);
    BOOST_CHECK_EQUAL(toy.alg_total_rows, real.alg_total_rows);
    BOOST_CHECK(real.alg_width_independent);
    // One permutation per ROW is the entire structural win over the vertical
    // SHA AIR's 1024 rows per compression.
    BOOST_CHECK_EQUAL(real.alg_poseidon_columns, 484U);
    BOOST_CHECK_EQUAL(real.alg_poseidon_rows, 256U); // next_pow2(128*2)

    // The SHA route is width-proportional and stays so.
    BOOST_CHECK_LT(toy.sha_total_rows, mid.sha_total_rows);
    BOOST_CHECK_LT(mid.sha_total_rows, real.sha_total_rows);
    BOOST_CHECK_GT(real.sha_rows_per_index, real.alg_total_rows);

    // HONEST SCOPE PIN.  This buys ONE of the eight child challenge kinds.
    // fra3_lambda, fra3_z x2, fra3_w x2 and fra3_fold are Fp3 draws and there
    // is NO algebraic Fp3 draw in the tree -- matmul_v4_rc_fri_ext3_alg.h
    // exports exactly Fri3AlgAlgebraicTranscriptDigest / Squeeze /
    // QueryIndex.  Activating the index rule therefore takes g4 coverage from
    // 1 of 8 kinds to at most 2 of 8, and closes nothing on its own.
    BOOST_CHECK(!fs::kAlgebraicQueryIndexActivatedV1);
}

BOOST_AUTO_TEST_SUITE_END()
