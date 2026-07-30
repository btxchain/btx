// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_v6_fs.h>

#include <algorithm>
#include <cmath>
#include <limits>
#include <utility>

namespace matmul::v4::rc::stage3_v6_fs {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace pa = stage3_poseidon_air;

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3:v6_fs:" + message;
    return false;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    if (value <= 2) return 2;
    --value;
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
    return value + 1;
}

bool IsPowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
}

uint8_t PowerOfTwoLog2(uint32_t value)
{
    uint8_t bits = 0;
    while (value > 1) {
        value >>= 1;
        ++bits;
    }
    return bits;
}

Fp CanonicalFp(uint64_t value)
{
    return gf::FromU64(value);
}

struct EncodedWord {
    Fp value{0};
    WordOrigin origin{WordOrigin::Fixed};
    int32_t payload_index{-1};
};

std::vector<EncodedWord> EncodeFrame(const Frame& frame, bool first)
{
    std::vector<EncodedWord> words;
    words.reserve(16 + frame.payload.size());

    // First rate block.  The four previous-digest slots are overwritten by
    // BuildWitness and linked to the preceding frame's output by the AIR.
    words.push_back({kTranscriptDomain, WordOrigin::Fixed, -1});
    words.push_back(
        {CanonicalFp(static_cast<uint16_t>(frame.kind)),
         WordOrigin::Fixed, -1});
    words.push_back({CanonicalFp(frame.lane), WordOrigin::Fixed, -1});
    words.push_back({CanonicalFp(frame.index), WordOrigin::Fixed, -1});
    for (uint32_t i = 0; i < kDigest; ++i) {
        words.push_back(
            {0, first ? WordOrigin::Fixed : WordOrigin::ProofDerived, -1});
    }

    // Second rate block starts with version and exact payload length.
    words.push_back({CanonicalFp(kVersion), WordOrigin::Fixed, -1});
    words.push_back(
        {CanonicalFp(frame.payload.size()), WordOrigin::Fixed, -1});
    for (uint32_t i = 0; i < frame.payload.size(); ++i) {
        words.push_back(
            {frame.payload[i].value, frame.payload[i].origin,
             static_cast<int32_t>(i)});
    }

    // 10* field padding is injective for the exact payload length.
    words.push_back({1, WordOrigin::Fixed, -1});
    while ((words.size() % kRate) != 0) {
        words.push_back({0, WordOrigin::Fixed, -1});
    }
    return words;
}

void AddPreprocessed(aq::AirConstraintSystem<Fp3>& cs, uint32_t column,
                     const std::vector<Fp3>& values)
{
    cs.preprocessed.emplace_back(column, values);
}

std::vector<aq::AirConstraint<Fp3>>
BuildConstraints(const Layout& layout, uint8_t query_domain_bits)
{
    std::vector<aq::AirConstraint<Fp3>> out =
        pa::BuildFixedConstraints(layout.poseidon);
    out.reserve(out.size() + 64);

    // On a start row the per-frame sponge state is reset to zero, so the
    // permutation input is exactly the first source block.
    for (uint32_t lane = 0; lane < kRate; ++lane) {
        aq::AirConstraint<Fp3> c;
        c.name = "stage3.v6_fs.start.rate";
        c.kind = aq::AirKind::kEverywhere;
        c.alg_degree = 2;
        c.eval = [layout, lane](const std::vector<Fp3>& cur,
                                const std::vector<Fp3>&) {
            return gf::Mul(
                cur[layout.start],
                gf::Sub(cur[layout.poseidon.perm.InputCol(lane)],
                        cur[layout.Source(lane)]));
        };
        out.push_back(std::move(c));
    }
    for (uint32_t lane = kRate; lane < alg_hash::kAlgHashT; ++lane) {
        aq::AirConstraint<Fp3> c;
        c.name = "stage3.v6_fs.start.capacity_zero";
        c.kind = aq::AirKind::kEverywhere;
        c.alg_degree = 2;
        c.eval = [layout, lane](const std::vector<Fp3>& cur,
                                const std::vector<Fp3>&) {
            return gf::Mul(
                cur[layout.start],
                cur[layout.poseidon.perm.InputCol(lane)]);
        };
        out.push_back(std::move(c));
    }

    // Every continuation row absorbs its source into the previous
    // permutation's rate while carrying capacity forward unchanged.
    for (uint32_t lane = 0; lane < kRate; ++lane) {
        aq::AirConstraint<Fp3> c;
        c.name = "stage3.v6_fs.continue.rate";
        c.kind = aq::AirKind::kTransition;
        c.alg_degree = 2;
        c.eval = [layout, lane](const std::vector<Fp3>& cur,
                                const std::vector<Fp3>& next) {
            const Fp3 expected = gf::Add(
                air_recurse::PermOutputLane(
                    layout.poseidon.perm, cur, lane),
                next[layout.Source(lane)]);
            return gf::Mul(
                next[layout.continue_from_previous_row],
                gf::Sub(
                    next[layout.poseidon.perm.InputCol(lane)],
                    expected));
        };
        out.push_back(std::move(c));
    }
    for (uint32_t lane = kRate; lane < alg_hash::kAlgHashT; ++lane) {
        aq::AirConstraint<Fp3> c;
        c.name = "stage3.v6_fs.continue.capacity";
        c.kind = aq::AirKind::kTransition;
        c.alg_degree = 2;
        c.eval = [layout, lane](const std::vector<Fp3>& cur,
                                const std::vector<Fp3>& next) {
            return gf::Mul(
                next[layout.continue_from_previous_row],
                gf::Sub(
                    next[layout.poseidon.perm.InputCol(lane)],
                    air_recurse::PermOutputLane(
                        layout.poseidon.perm, cur, lane)));
        };
        out.push_back(std::move(c));
    }

    // The next frame's header absorbs all four lanes of the exact preceding
    // frame digest.  This is the recursive master/child/challenge chain.
    for (uint32_t lane = 0; lane < kDigest; ++lane) {
        aq::AirConstraint<Fp3> c;
        c.name = "stage3.v6_fs.frame_chain";
        c.kind = aq::AirKind::kTransition;
        c.alg_degree = 2;
        c.eval = [layout, lane](const std::vector<Fp3>& cur,
                                const std::vector<Fp3>& next) {
            return gf::Mul(
                cur[layout.chain_digest_to_next_frame],
                gf::Sub(
                    next[layout.Source(4 + lane)],
                    air_recurse::PermOutputLane(
                        layout.poseidon.perm, cur, lane)));
        };
        out.push_back(std::move(c));
    }

    // Canonical framing/public statement words are verifier-pinned.
    for (uint32_t lane = 0; lane < kRate; ++lane) {
        aq::AirConstraint<Fp3> fixed;
        fixed.name = "stage3.v6_fs.fixed_source";
        fixed.kind = aq::AirKind::kEverywhere;
        fixed.alg_degree = 2;
        fixed.eval = [layout, lane](const std::vector<Fp3>& cur,
                                    const std::vector<Fp3>&) {
            return gf::Mul(
                cur[layout.FixedMask(lane)],
                gf::Sub(cur[layout.Source(lane)],
                        cur[layout.FixedValue(lane)]));
        };
        out.push_back(std::move(fixed));

        // This is the important non-metadata seam: every proof-derived word
        // is an AIR equality, not a host boolean or commitment.
        aq::AirConstraint<Fp3> proof;
        proof.name = "stage3.v6_fs.proof_source_equality";
        proof.kind = aq::AirKind::kEverywhere;
        proof.alg_degree = 2;
        proof.eval = [layout, lane](const std::vector<Fp3>& cur,
                                    const std::vector<Fp3>&) {
            return gf::Mul(
                cur[layout.ProofMask(lane)],
                gf::Sub(cur[layout.Source(lane)],
                        cur[layout.ExternalSource(lane)]));
        };
        out.push_back(std::move(proof));
    }

    // Fixed-candidate unbiased query-index reduction. A field output is
    // decomposed into one canonical 64-bit integer. For Goldilocks
    // p=0xffffffff00000001 and N=2^k, k<=32, p mod N=1, so the exact
    // rejection threshold is p-1=0xffffffff00000000. The canonical value
    // p-1 is the sole rejection; accepted values reduce to their low k bits.
    for (uint32_t bit = 0; bit < 64; ++bit) {
        aq::AirConstraint<Fp3> boolean;
        boolean.name = "stage3.v6_fs.query.bit_boolean";
        boolean.kind = aq::AirKind::kEverywhere;
        boolean.alg_degree = 3;
        boolean.eval = [layout, bit](
                           const std::vector<Fp3>& cur,
                           const std::vector<Fp3>&) {
            const Fp3 b = cur[layout.QueryBit(bit)];
            return gf::Mul(
                cur[layout.query_candidate_end],
                gf::Mul(b, gf::Sub(b, Fp3::One())));
        };
        out.push_back(std::move(boolean));
    }

    aq::AirConstraint<Fp3> reconstruction;
    reconstruction.name = "stage3.v6_fs.query.canonical_reconstruction";
    reconstruction.kind = aq::AirKind::kEverywhere;
    reconstruction.alg_degree = 2;
    reconstruction.eval = [layout](
                              const std::vector<Fp3>& cur,
                              const std::vector<Fp3>&) {
        Fp3 value = Fp3::Zero();
        Fp power = 1;
        for (uint32_t bit = 0; bit < 64; ++bit) {
            value = gf::Add(
                value,
                gf::Mul(
                    Fp3::FromFp(power),
                    cur[layout.QueryBit(bit)]));
            power = gf::Add(power, power);
        }
        return gf::Mul(
            cur[layout.query_candidate_end],
            gf::Sub(
                value,
                air_recurse::PermOutputLane(
                    layout.poseidon.perm, cur, 0)));
    };
    out.push_back(std::move(reconstruction));

    // top[i] is the AND of bits 63..(64-i), while low_zero[i] is the
    // AND of (1-bit) for bits 31..(32-i).
    for (uint32_t which = 0; which < 2; ++which) {
        aq::AirConstraint<Fp3> initial;
        initial.name = which == 0
            ? "stage3.v6_fs.query.top_prefix_initial"
            : "stage3.v6_fs.query.low_zero_prefix_initial";
        initial.kind = aq::AirKind::kEverywhere;
        initial.alg_degree = 2;
        initial.eval = [layout, which](
                           const std::vector<Fp3>& cur,
                           const std::vector<Fp3>&) {
            const uint32_t column = which == 0
                ? layout.QueryTopOnesPrefix(0)
                : layout.QueryLowZeroPrefix(0);
            return gf::Mul(
                cur[layout.query_candidate_end],
                gf::Sub(cur[column], Fp3::One()));
        };
        out.push_back(std::move(initial));
    }
    for (uint32_t step = 0; step < 32; ++step) {
        aq::AirConstraint<Fp3> top;
        top.name = "stage3.v6_fs.query.top_prefix";
        top.kind = aq::AirKind::kEverywhere;
        top.alg_degree = 3;
        top.eval = [layout, step](
                       const std::vector<Fp3>& cur,
                       const std::vector<Fp3>&) {
            const Fp3 expected = gf::Mul(
                cur[layout.QueryTopOnesPrefix(step)],
                cur[layout.QueryBit(63 - step)]);
            return gf::Mul(
                cur[layout.query_candidate_end],
                gf::Sub(
                    cur[layout.QueryTopOnesPrefix(step + 1)],
                    expected));
        };
        out.push_back(std::move(top));

        aq::AirConstraint<Fp3> low_zero;
        low_zero.name = "stage3.v6_fs.query.low_zero_prefix";
        low_zero.kind = aq::AirKind::kEverywhere;
        low_zero.alg_degree = 3;
        low_zero.eval = [layout, step](
                            const std::vector<Fp3>& cur,
                            const std::vector<Fp3>&) {
            const Fp3 expected = gf::Mul(
                cur[layout.QueryLowZeroPrefix(step)],
                gf::Sub(
                    Fp3::One(),
                    cur[layout.QueryBit(31 - step)]));
            return gf::Mul(
                cur[layout.query_candidate_end],
                gf::Sub(
                    cur[layout.QueryLowZeroPrefix(step + 1)],
                    expected));
        };
        out.push_back(std::move(low_zero));
    }

    // If the high word is all ones, canonicality forces the low word to
    // zero. This excludes p and every alternative x+p decomposition.
    aq::AirConstraint<Fp3> canonical;
    canonical.name = "stage3.v6_fs.query.bits_canonical";
    canonical.kind = aq::AirKind::kEverywhere;
    canonical.alg_degree = 3;
    canonical.eval = [layout](
                         const std::vector<Fp3>& cur,
                         const std::vector<Fp3>&) {
        return gf::Mul(
            cur[layout.query_candidate_end],
            gf::Mul(
                cur[layout.QueryTopOnesPrefix(32)],
                gf::Sub(
                    Fp3::One(),
                    cur[layout.QueryLowZeroPrefix(32)])));
    };
    out.push_back(std::move(canonical));

    aq::AirConstraint<Fp3> valid;
    valid.name = "stage3.v6_fs.query.valid_below_p_minus_one";
    valid.kind = aq::AirKind::kEverywhere;
    valid.alg_degree = 3;
    valid.eval = [layout](
                     const std::vector<Fp3>& cur,
                     const std::vector<Fp3>&) {
        const Fp3 rejected = gf::Mul(
            cur[layout.QueryTopOnesPrefix(32)],
            cur[layout.QueryLowZeroPrefix(32)]);
        return gf::Mul(
            cur[layout.query_candidate_end],
            gf::Sub(
                cur[layout.query_valid],
                gf::Sub(Fp3::One(), rejected)));
    };
    out.push_back(std::move(valid));

    aq::AirConstraint<Fp3> selected;
    selected.name = "stage3.v6_fs.query.first_valid";
    selected.kind = aq::AirKind::kEverywhere;
    selected.alg_degree = 3;
    selected.eval = [layout](
                        const std::vector<Fp3>& cur,
                        const std::vector<Fp3>&) {
        const Fp3 expected = gf::Mul(
            cur[layout.query_valid],
            gf::Sub(
                Fp3::One(),
                cur[layout.query_have_selected]));
        return gf::Mul(
            cur[layout.query_candidate_end],
            gf::Sub(cur[layout.query_selected], expected));
    };
    out.push_back(std::move(selected));

    aq::AirConstraint<Fp3> index_term;
    index_term.name = "stage3.v6_fs.query.low_bits";
    index_term.kind = aq::AirKind::kEverywhere;
    index_term.alg_degree = 3;
    index_term.eval = [layout, query_domain_bits](
                          const std::vector<Fp3>& cur,
                          const std::vector<Fp3>&) {
        Fp3 low = Fp3::Zero();
        Fp power = 1;
        for (uint32_t bit = 0; bit < query_domain_bits; ++bit) {
            low = gf::Add(
                low,
                gf::Mul(
                    Fp3::FromFp(power),
                    cur[layout.QueryBit(bit)]));
            power = gf::Add(power, power);
        }
        return gf::Mul(
            cur[layout.query_candidate_end],
            gf::Sub(
                cur[layout.query_index_term],
                gf::Mul(cur[layout.query_selected], low)));
    };
    out.push_back(std::move(index_term));

    for (const uint32_t column :
         {layout.query_have_selected, layout.query_selected,
          layout.query_valid}) {
        aq::AirConstraint<Fp3> boolean;
        boolean.name = "stage3.v6_fs.query.state_boolean";
        boolean.kind = aq::AirKind::kEverywhere;
        boolean.alg_degree = 2;
        boolean.eval = [column](
                           const std::vector<Fp3>& cur,
                           const std::vector<Fp3>&) {
            return gf::Mul(
                cur[column],
                gf::Sub(cur[column], Fp3::One()));
        };
        out.push_back(std::move(boolean));
    }

    for (const uint32_t column :
         {layout.query_selected, layout.query_valid,
          layout.query_index_term, layout.query_reduced_index}) {
        aq::AirConstraint<Fp3> inactive;
        inactive.name = "stage3.v6_fs.query.inactive_zero";
        inactive.kind = aq::AirKind::kEverywhere;
        inactive.alg_degree = 2;
        inactive.eval = [layout, column](
                            const std::vector<Fp3>& cur,
                            const std::vector<Fp3>&) {
            return gf::Mul(
                gf::Sub(
                    Fp3::One(),
                    cur[layout.query_candidate_end]),
                cur[column]);
        };
        out.push_back(std::move(inactive));
    }

    for (const uint32_t column :
         {layout.query_have_selected,
          layout.query_index_accumulator}) {
        aq::AirConstraint<Fp3> reset;
        reset.name = "stage3.v6_fs.query.group_reset";
        reset.kind = aq::AirKind::kEverywhere;
        reset.alg_degree = 2;
        reset.eval = [layout, column](
                         const std::vector<Fp3>& cur,
                         const std::vector<Fp3>&) {
            return gf::Mul(
                cur[layout.query_group_start], cur[column]);
        };
        out.push_back(std::move(reset));
    }

    aq::AirConstraint<Fp3> have_transition;
    have_transition.name = "stage3.v6_fs.query.have_transition";
    have_transition.kind = aq::AirKind::kTransition;
    have_transition.alg_degree = 3;
    have_transition.eval = [layout](
                               const std::vector<Fp3>& cur,
                               const std::vector<Fp3>& next) {
        return gf::Mul(
            next[layout.active],
            gf::Mul(
                gf::Sub(
                    Fp3::One(),
                    next[layout.query_group_start]),
                gf::Sub(
                    next[layout.query_have_selected],
                    gf::Add(
                        cur[layout.query_have_selected],
                        cur[layout.query_selected]))));
    };
    out.push_back(std::move(have_transition));

    aq::AirConstraint<Fp3> index_transition;
    index_transition.name = "stage3.v6_fs.query.index_transition";
    index_transition.kind = aq::AirKind::kTransition;
    index_transition.alg_degree = 3;
    index_transition.eval = [layout](
                                const std::vector<Fp3>& cur,
                                const std::vector<Fp3>& next) {
        return gf::Mul(
            next[layout.active],
            gf::Mul(
                gf::Sub(
                    Fp3::One(),
                    next[layout.query_group_start]),
                gf::Sub(
                    next[layout.query_index_accumulator],
                    gf::Add(
                        cur[layout.query_index_accumulator],
                        cur[layout.query_index_term]))));
    };
    out.push_back(std::move(index_transition));

    aq::AirConstraint<Fp3> completion;
    completion.name = "stage3.v6_fs.query.fixed_pool_not_exhausted";
    completion.kind = aq::AirKind::kEverywhere;
    completion.alg_degree = 2;
    completion.eval = [layout](
                          const std::vector<Fp3>& cur,
                          const std::vector<Fp3>&) {
        return gf::Mul(
            cur[layout.query_group_final],
            gf::Sub(
                gf::Add(
                    cur[layout.query_have_selected],
                    cur[layout.query_selected]),
                Fp3::One()));
    };
    out.push_back(std::move(completion));

    aq::AirConstraint<Fp3> reduced;
    reduced.name = "stage3.v6_fs.query.reduced_index";
    reduced.kind = aq::AirKind::kEverywhere;
    reduced.alg_degree = 2;
    reduced.eval = [layout](
                       const std::vector<Fp3>& cur,
                       const std::vector<Fp3>&) {
        return gf::Mul(
            cur[layout.query_group_final],
            gf::Sub(
                cur[layout.query_reduced_index],
                gf::Add(
                    cur[layout.query_index_accumulator],
                    cur[layout.query_index_term])));
    };
    out.push_back(std::move(reduced));

    // Bounded dual-OOD selection. Candidate frames 0/1 select z1 and frames
    // 2/3 select z2. Each candidate is the first three lanes of the frame
    // digest. The extension-coordinate and distinctness predicates use exact
    // inverse-or-zero witnesses; no host acceptance bit is trusted.
    const std::array<uint32_t, 2> ext_inverse{
        layout.ood_c1_inverse, layout.ood_c2_inverse};
    const std::array<uint32_t, 2> ext_nonzero{
        layout.ood_c1_nonzero, layout.ood_c2_nonzero};
    for (uint32_t coordinate = 0; coordinate < 2; ++coordinate) {
        const uint32_t output_lane = coordinate + 1;
        const uint32_t inverse = ext_inverse[coordinate];
        const uint32_t nonzero = ext_nonzero[coordinate];

        aq::AirConstraint<Fp3> boolean;
        boolean.name = "stage3.v6_fs.ood.ext_nonzero_boolean";
        boolean.kind = aq::AirKind::kEverywhere;
        boolean.alg_degree = 3;
        boolean.eval = [layout, nonzero](
                           const std::vector<Fp3>& cur,
                           const std::vector<Fp3>&) {
            return gf::Mul(
                cur[layout.ood_candidate_end],
                gf::Mul(
                    cur[nonzero],
                    gf::Sub(cur[nonzero], Fp3::One())));
        };
        out.push_back(std::move(boolean));

        aq::AirConstraint<Fp3> zero;
        zero.name = "stage3.v6_fs.ood.ext_zero_branch";
        zero.kind = aq::AirKind::kEverywhere;
        zero.alg_degree = 3;
        zero.eval = [layout, output_lane, nonzero](
                        const std::vector<Fp3>& cur,
                        const std::vector<Fp3>&) {
            return gf::Mul(
                cur[layout.ood_candidate_end],
                gf::Mul(
                    air_recurse::PermOutputLane(
                        layout.poseidon.perm, cur, output_lane),
                    gf::Sub(Fp3::One(), cur[nonzero])));
        };
        out.push_back(std::move(zero));

        aq::AirConstraint<Fp3> invert;
        invert.name = "stage3.v6_fs.ood.ext_inverse";
        invert.kind = aq::AirKind::kEverywhere;
        invert.alg_degree = 3;
        invert.eval = [layout, output_lane, inverse, nonzero](
                          const std::vector<Fp3>& cur,
                          const std::vector<Fp3>&) {
            return gf::Mul(
                cur[layout.ood_candidate_end],
                gf::Sub(
                    gf::Mul(
                        air_recurse::PermOutputLane(
                            layout.poseidon.perm, cur, output_lane),
                        cur[inverse]),
                    cur[nonzero]));
        };
        out.push_back(std::move(invert));
    }

    aq::AirConstraint<Fp3> ext_or;
    ext_or.name = "stage3.v6_fs.ood.has_extension_coordinate";
    ext_or.kind = aq::AirKind::kEverywhere;
    ext_or.alg_degree = 3;
    ext_or.eval = [layout](
                      const std::vector<Fp3>& cur,
                      const std::vector<Fp3>&) {
        const Fp3 expected = gf::Sub(
            gf::Add(
                cur[layout.ood_c1_nonzero],
                cur[layout.ood_c2_nonzero]),
            gf::Mul(
                cur[layout.ood_c1_nonzero],
                cur[layout.ood_c2_nonzero]));
        return gf::Mul(
            cur[layout.ood_candidate_end],
            gf::Sub(cur[layout.ood_ext_nonzero], expected));
    };
    out.push_back(std::move(ext_or));

    for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
        const uint32_t inverse =
            layout.OodDiffInverse(coordinate);
        const uint32_t nonzero =
            layout.OodDiffNonzero(coordinate);

        aq::AirConstraint<Fp3> boolean;
        boolean.name = "stage3.v6_fs.ood.diff_nonzero_boolean";
        boolean.kind = aq::AirKind::kEverywhere;
        boolean.alg_degree = 3;
        boolean.eval = [layout, nonzero](
                           const std::vector<Fp3>& cur,
                           const std::vector<Fp3>&) {
            return gf::Mul(
                cur[layout.ood_candidate_end],
                gf::Mul(
                    cur[nonzero],
                    gf::Sub(cur[nonzero], Fp3::One())));
        };
        out.push_back(std::move(boolean));

        aq::AirConstraint<Fp3> zero;
        zero.name = "stage3.v6_fs.ood.diff_zero_branch";
        zero.kind = aq::AirKind::kEverywhere;
        zero.alg_degree = 3;
        zero.eval = [layout, coordinate, nonzero](
                        const std::vector<Fp3>& cur,
                        const std::vector<Fp3>&) {
            const Fp3 difference = gf::Sub(
                air_recurse::PermOutputLane(
                    layout.poseidon.perm, cur, coordinate),
                cur[layout.OodAcceptedZ1(coordinate)]);
            return gf::Mul(
                cur[layout.ood_candidate_end],
                gf::Mul(
                    difference,
                    gf::Sub(Fp3::One(), cur[nonzero])));
        };
        out.push_back(std::move(zero));

        aq::AirConstraint<Fp3> invert;
        invert.name = "stage3.v6_fs.ood.diff_inverse";
        invert.kind = aq::AirKind::kEverywhere;
        invert.alg_degree = 3;
        invert.eval = [layout, coordinate, inverse, nonzero](
                          const std::vector<Fp3>& cur,
                          const std::vector<Fp3>&) {
            const Fp3 difference = gf::Sub(
                air_recurse::PermOutputLane(
                    layout.poseidon.perm, cur, coordinate),
                cur[layout.OodAcceptedZ1(coordinate)]);
            return gf::Mul(
                cur[layout.ood_candidate_end],
                gf::Sub(
                    gf::Mul(difference, cur[inverse]),
                    cur[nonzero]));
        };
        out.push_back(std::move(invert));
    }

    aq::AirConstraint<Fp3> diff01;
    diff01.name = "stage3.v6_fs.ood.diff_any01";
    diff01.kind = aq::AirKind::kEverywhere;
    diff01.alg_degree = 3;
    diff01.eval = [layout](
                       const std::vector<Fp3>& cur,
                       const std::vector<Fp3>&) {
        const Fp3 d0 = cur[layout.OodDiffNonzero(0)];
        const Fp3 d1 = cur[layout.OodDiffNonzero(1)];
        const Fp3 expected =
            gf::Sub(gf::Add(d0, d1), gf::Mul(d0, d1));
        return gf::Mul(
            cur[layout.ood_candidate_end],
            gf::Sub(cur[layout.ood_diff_any01], expected));
    };
    out.push_back(std::move(diff01));

    aq::AirConstraint<Fp3> distinct;
    distinct.name = "stage3.v6_fs.ood.distinct_from_z1";
    distinct.kind = aq::AirKind::kEverywhere;
    distinct.alg_degree = 3;
    distinct.eval = [layout](
                        const std::vector<Fp3>& cur,
                        const std::vector<Fp3>&) {
        const Fp3 d01 = cur[layout.ood_diff_any01];
        const Fp3 d2 = cur[layout.OodDiffNonzero(2)];
        const Fp3 expected =
            gf::Sub(gf::Add(d01, d2), gf::Mul(d01, d2));
        return gf::Mul(
            cur[layout.ood_candidate_end],
            gf::Sub(cur[layout.ood_distinct], expected));
    };
    out.push_back(std::move(distinct));

    aq::AirConstraint<Fp3> z1_valid;
    z1_valid.name = "stage3.v6_fs.ood.z1_valid";
    z1_valid.kind = aq::AirKind::kEverywhere;
    z1_valid.alg_degree = 2;
    z1_valid.eval = [layout](
                        const std::vector<Fp3>& cur,
                        const std::vector<Fp3>&) {
        return gf::Mul(
            cur[layout.ood_z1_candidate_end],
            gf::Sub(
                cur[layout.ood_valid],
                cur[layout.ood_ext_nonzero]));
    };
    out.push_back(std::move(z1_valid));

    aq::AirConstraint<Fp3> z2_valid;
    z2_valid.name = "stage3.v6_fs.ood.z2_valid_and_distinct";
    z2_valid.kind = aq::AirKind::kEverywhere;
    z2_valid.alg_degree = 3;
    z2_valid.eval = [layout](
                        const std::vector<Fp3>& cur,
                        const std::vector<Fp3>&) {
        return gf::Mul(
            cur[layout.ood_z2_candidate_end],
            gf::Sub(
                cur[layout.ood_valid],
                gf::Mul(
                    cur[layout.ood_ext_nonzero],
                    cur[layout.ood_distinct])));
    };
    out.push_back(std::move(z2_valid));

    aq::AirConstraint<Fp3> first_valid;
    first_valid.name = "stage3.v6_fs.ood.first_valid";
    first_valid.kind = aq::AirKind::kEverywhere;
    first_valid.alg_degree = 3;
    first_valid.eval = [layout](
                           const std::vector<Fp3>& cur,
                           const std::vector<Fp3>&) {
        const Fp3 expected = gf::Mul(
            cur[layout.ood_valid],
            gf::Sub(
                Fp3::One(),
                cur[layout.ood_have_selected]));
        return gf::Mul(
            cur[layout.ood_candidate_end],
            gf::Sub(cur[layout.ood_selected], expected));
    };
    out.push_back(std::move(first_valid));

    for (const uint32_t column :
         {layout.ood_valid, layout.ood_selected,
          layout.ood_have_selected}) {
        aq::AirConstraint<Fp3> boolean;
        boolean.name = "stage3.v6_fs.ood.state_boolean";
        boolean.kind = aq::AirKind::kEverywhere;
        boolean.alg_degree = 2;
        boolean.eval = [column](
                           const std::vector<Fp3>& cur,
                           const std::vector<Fp3>&) {
            return gf::Mul(
                cur[column],
                gf::Sub(cur[column], Fp3::One()));
        };
        out.push_back(std::move(boolean));
    }
    for (const uint32_t column :
         {layout.ood_valid, layout.ood_selected}) {
        aq::AirConstraint<Fp3> inactive;
        inactive.name = "stage3.v6_fs.ood.inactive_zero";
        inactive.kind = aq::AirKind::kEverywhere;
        inactive.alg_degree = 2;
        inactive.eval = [layout, column](
                            const std::vector<Fp3>& cur,
                            const std::vector<Fp3>&) {
            return gf::Mul(
                gf::Sub(
                    Fp3::One(),
                    cur[layout.ood_candidate_end]),
                cur[column]);
        };
        out.push_back(std::move(inactive));
    }

    aq::AirConstraint<Fp3> reset;
    reset.name = "stage3.v6_fs.ood.group_reset";
    reset.kind = aq::AirKind::kEverywhere;
    reset.alg_degree = 2;
    reset.eval = [layout](
                     const std::vector<Fp3>& cur,
                     const std::vector<Fp3>&) {
        return gf::Mul(
            cur[layout.ood_group_start],
            cur[layout.ood_have_selected]);
    };
    out.push_back(std::move(reset));

    aq::AirConstraint<Fp3> ood_have_transition;
    ood_have_transition.name = "stage3.v6_fs.ood.have_transition";
    ood_have_transition.kind = aq::AirKind::kTransition;
    ood_have_transition.alg_degree = 3;
    ood_have_transition.eval = [layout](
                               const std::vector<Fp3>& cur,
                               const std::vector<Fp3>& next) {
        return gf::Mul(
            next[layout.active],
            gf::Mul(
                gf::Sub(
                    Fp3::One(),
                    next[layout.ood_group_start]),
                gf::Sub(
                    next[layout.ood_have_selected],
                    gf::Add(
                        cur[layout.ood_have_selected],
                        cur[layout.ood_selected]))));
    };
    out.push_back(std::move(ood_have_transition));

    aq::AirConstraint<Fp3> ood_completion;
    ood_completion.name = "stage3.v6_fs.ood.fixed_pool_not_exhausted";
    ood_completion.kind = aq::AirKind::kEverywhere;
    ood_completion.alg_degree = 2;
    ood_completion.eval = [layout](
                          const std::vector<Fp3>& cur,
                          const std::vector<Fp3>&) {
        return gf::Mul(
            cur[layout.ood_group_final],
            gf::Sub(
                gf::Add(
                    cur[layout.ood_have_selected],
                    cur[layout.ood_selected]),
                Fp3::One()));
    };
    out.push_back(std::move(ood_completion));

    for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
        aq::AirConstraint<Fp3> bind_z1;
        bind_z1.name = "stage3.v6_fs.ood.bind_selected_z1";
        bind_z1.kind = aq::AirKind::kEverywhere;
        bind_z1.alg_degree = 3;
        bind_z1.eval = [layout, coordinate](
                           const std::vector<Fp3>& cur,
                           const std::vector<Fp3>&) {
            return gf::Mul(
                cur[layout.ood_z1_candidate_end],
                gf::Mul(
                    cur[layout.ood_selected],
                    gf::Sub(
                        cur[layout.OodAcceptedZ1(coordinate)],
                        air_recurse::PermOutputLane(
                            layout.poseidon.perm, cur, coordinate))));
        };
        out.push_back(std::move(bind_z1));

        aq::AirConstraint<Fp3> bind_z2;
        bind_z2.name = "stage3.v6_fs.ood.bind_selected_z2";
        bind_z2.kind = aq::AirKind::kEverywhere;
        bind_z2.alg_degree = 3;
        bind_z2.eval = [layout, coordinate](
                           const std::vector<Fp3>& cur,
                           const std::vector<Fp3>&) {
            return gf::Mul(
                cur[layout.ood_z2_candidate_end],
                gf::Mul(
                    cur[layout.ood_selected],
                    gf::Sub(
                        cur[layout.OodAcceptedZ2(coordinate)],
                        air_recurse::PermOutputLane(
                            layout.poseidon.perm, cur, coordinate))));
        };
        out.push_back(std::move(bind_z2));

        aq::AirConstraint<Fp3> carry_z1;
        carry_z1.name = "stage3.v6_fs.ood.carry_z1";
        carry_z1.kind = aq::AirKind::kTransition;
        carry_z1.alg_degree = 3;
        carry_z1.eval = [layout, coordinate](
                            const std::vector<Fp3>& cur,
                            const std::vector<Fp3>& next) {
            return gf::Mul(
                next[layout.active],
                gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        next[layout.ood_z1_group_start]),
                    gf::Sub(
                        next[layout.OodAcceptedZ1(coordinate)],
                        cur[layout.OodAcceptedZ1(coordinate)])));
        };
        out.push_back(std::move(carry_z1));

        aq::AirConstraint<Fp3> carry_z2;
        carry_z2.name = "stage3.v6_fs.ood.carry_z2";
        carry_z2.kind = aq::AirKind::kTransition;
        carry_z2.alg_degree = 3;
        carry_z2.eval = [layout, coordinate](
                            const std::vector<Fp3>& cur,
                            const std::vector<Fp3>& next) {
            return gf::Mul(
                next[layout.active],
                gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        next[layout.ood_z2_group_start]),
                    gf::Sub(
                        next[layout.OodAcceptedZ2(coordinate)],
                        cur[layout.OodAcceptedZ2(coordinate)])));
        };
        out.push_back(std::move(carry_z2));
    }
    return out;
}

bool SameProgramRow(const ProgramRow& a, const ProgramRow& b)
{
    return a.frame == b.frame && a.block == b.block &&
           a.active == b.active && a.start == b.start &&
           a.end == b.end &&
           a.continue_from_previous_row ==
               b.continue_from_previous_row &&
           a.chain_digest_to_next_frame ==
               b.chain_digest_to_next_frame &&
           a.query_candidate_end == b.query_candidate_end &&
           a.query_group_start == b.query_group_start &&
           a.query_group_final == b.query_group_final &&
           a.ood_candidate_end == b.ood_candidate_end &&
           a.ood_group_start == b.ood_group_start &&
           a.ood_group_final == b.ood_group_final &&
           a.ood_second_point == b.ood_second_point &&
           a.ood_z1_group_start == b.ood_z1_group_start &&
           a.ood_z2_group_start == b.ood_z2_group_start &&
           a.ood_z1_candidate_end == b.ood_z1_candidate_end &&
           a.ood_z2_candidate_end == b.ood_z2_candidate_end &&
           a.query_domain_bits == b.query_domain_bits &&
           a.source == b.source && a.fixed_mask == b.fixed_mask &&
           a.proof_mask == b.proof_mask;
}

} // namespace

Program BuildProgram(const std::vector<Frame>& frames)
{
    Program out;
    out.frames = frames;
    if (frames.empty()) {
        out.note = "stage3:v6_fs:no_frames";
        return out;
    }
    if (frames.size() > kMaxFrames) {
        out.note = "stage3:v6_fs:too_many_frames";
        return out;
    }

    uint64_t payload_words = 0;
    std::array<uint32_t, 2> next_query_candidate{};
    std::array<uint32_t, 2> next_ood_candidate{};
    uint8_t query_domain_bits = 0;
    for (const Frame& frame : frames) {
        payload_words += frame.payload.size();
        if (payload_words > kMaxPayloadWords) {
            out.note = "stage3:v6_fs:payload_cap";
            return out;
        }
        if (frame.kind == FrameKind::OodCandidate) {
            if (frame.lane >= next_ood_candidate.size() ||
                !frame.payload.empty() ||
                frame.index != next_ood_candidate[frame.lane] ||
                next_ood_candidate[frame.lane] >= 4) {
                out.note = "stage3:v6_fs:ood_candidate_order";
                return out;
            }
            ++next_ood_candidate[frame.lane];
            continue;
        }
        if (frame.kind != FrameKind::QueryCandidate) continue;
        if (frame.lane >= next_query_candidate.size() ||
            frame.payload.size() != 1 ||
            frame.payload[0].origin != WordOrigin::PublicStatement ||
            frame.payload[0].value >
                std::numeric_limits<uint32_t>::max()) {
            out.note = "stage3:v6_fs:query_frame_shape";
            return out;
        }
        const uint32_t domain =
            static_cast<uint32_t>(frame.payload[0].value);
        if (!IsPowerOfTwo(domain)) {
            out.note = "stage3:v6_fs:query_domain_not_power_of_two";
            return out;
        }
        const uint8_t bits = PowerOfTwoLog2(domain);
        if (bits > kMaxQueryDomainBits ||
            (query_domain_bits != 0 && query_domain_bits != bits)) {
            out.note = "stage3:v6_fs:query_domain_mismatch";
            return out;
        }
        query_domain_bits = bits;
        if (frame.index != next_query_candidate[frame.lane]++) {
            out.note = "stage3:v6_fs:query_candidate_order";
            return out;
        }
    }
    for (const uint32_t count : next_query_candidate) {
        if ((count % kQueryCandidatesPerIndex) != 0) {
            out.note = "stage3:v6_fs:query_candidate_incomplete";
            return out;
        }
    }
    for (const uint32_t count : next_ood_candidate) {
        if (count != 0 && count != 4) {
            out.note = "stage3:v6_fs:ood_candidate_incomplete";
            return out;
        }
    }
    out.query_domain_bits = query_domain_bits;

    for (uint32_t frame_index = 0; frame_index < frames.size();
         ++frame_index) {
        const auto encoded =
            EncodeFrame(frames[frame_index], frame_index == 0);
        const uint32_t blocks =
            static_cast<uint32_t>(encoded.size() / kRate);
        for (uint32_t block = 0; block < blocks; ++block) {
            ProgramRow row;
            row.frame = frame_index;
            row.block = block;
            row.active = true;
            row.start = block == 0;
            row.end = block + 1 == blocks;
            row.continue_from_previous_row = block != 0;
            row.chain_digest_to_next_frame =
                row.end && frame_index + 1 < frames.size();
            if (frames[frame_index].kind ==
                FrameKind::QueryCandidate) {
                const uint32_t ordinal =
                    frames[frame_index].index %
                    kQueryCandidatesPerIndex;
                row.query_candidate_end = row.end;
                row.query_group_start =
                    row.start && ordinal == 0;
                row.query_group_final =
                    row.end &&
                    ordinal + 1 == kQueryCandidatesPerIndex;
                row.query_domain_bits = query_domain_bits;
            }
            if (frames[frame_index].kind ==
                FrameKind::OodCandidate) {
                const uint32_t ordinal =
                    frames[frame_index].index;
                row.ood_candidate_end = row.end;
                row.ood_group_start =
                    row.start && (ordinal == 0 || ordinal == 2);
                row.ood_group_final =
                    row.end && (ordinal == 1 || ordinal == 3);
                row.ood_second_point = ordinal >= 2;
                row.ood_z1_group_start =
                    row.start && ordinal == 0;
                row.ood_z2_group_start =
                    row.start && ordinal == 2;
                row.ood_z1_candidate_end =
                    row.end && ordinal < 2;
                row.ood_z2_candidate_end =
                    row.end && ordinal >= 2;
            }
            for (uint32_t lane = 0; lane < kRate; ++lane) {
                const EncodedWord& word =
                    encoded[block * kRate + lane];
                row.source[lane] = word.value;
                // Public-statement values are as verifier-pinned as literals.
                if (word.origin != WordOrigin::ProofDerived ||
                    (frame_index == 0 && block == 0 && lane >= 4)) {
                    row.fixed_mask[lane] = 1;
                }
                if (word.origin == WordOrigin::ProofDerived &&
                    word.payload_index >= 0) {
                    row.proof_mask[lane] = 1;
                }
                if (word.payload_index >= 0) {
                    out.payload_cells.push_back(
                        {frame_index,
                         static_cast<uint32_t>(word.payload_index),
                         static_cast<uint32_t>(out.rows.size()),
                         lane, word.origin});
                }
            }
            out.rows.push_back(row);
        }
    }

    out.active_rows = static_cast<uint32_t>(out.rows.size());
    out.trace_rows = NextPowerOfTwo(out.active_rows);
    if (out.trace_rows < out.active_rows) {
        out.note = "stage3:v6_fs:row_overflow";
        return out;
    }
    out.rows.resize(out.trace_rows);
    out.valid = true;
    out.note = "stage3:v6_fs:canonical_program";
    return out;
}

bool ValidateProgram(const Program& program, std::string* why)
{
    if (!program.valid) return Fail(why, "program_not_valid");
    const Program expected = BuildProgram(program.frames);
    if (!expected.valid || expected.active_rows != program.active_rows ||
        program.trace_rows < expected.trace_rows ||
        !IsPowerOfTwo(program.trace_rows) ||
        expected.query_domain_bits != program.query_domain_bits ||
        program.rows.size() != program.trace_rows ||
        expected.payload_cells != program.payload_cells) {
        return Fail(why, "program_shape_mismatch");
    }
    const ProgramRow inactive{};
    for (uint32_t row = 0; row < program.rows.size(); ++row) {
        const ProgramRow& want =
            row < expected.rows.size() ? expected.rows[row] : inactive;
        if (!SameProgramRow(want, program.rows[row])) {
            return Fail(why, "program_row_mismatch");
        }
    }
    return true;
}

Program PadProgramToTraceRows(const Program& program, uint32_t trace_rows)
{
    Program out = program;
    std::string why;
    if (!ValidateProgram(program, &why) ||
        trace_rows < program.trace_rows ||
        !IsPowerOfTwo(trace_rows)) {
        out.valid = false;
        out.note = "stage3:v6_fs:invalid_trace_padding";
        return out;
    }
    out.trace_rows = trace_rows;
    out.rows.resize(trace_rows);
    out.valid = true;
    out.note = trace_rows == program.trace_rows
        ? program.note
        : "stage3:v6_fs:canonical_zero_padded_program";
    return out;
}

Layout CanonicalLayout(uint32_t base)
{
    Layout out;
    out.poseidon = pa::CanonicalLayout(base);
    out.source_base = out.poseidon.End();
    out.external_source_base = out.source_base + kRate;
    out.active = out.external_source_base + kRate;
    out.start = out.active + 1;
    out.continue_from_previous_row = out.start + 1;
    out.chain_digest_to_next_frame =
        out.continue_from_previous_row + 1;
    out.fixed_mask_base = out.chain_digest_to_next_frame + 1;
    out.fixed_value_base = out.fixed_mask_base + kRate;
    out.proof_mask_base = out.fixed_value_base + kRate;
    out.query_bit_base = out.proof_mask_base + kRate;
    out.query_top_ones_prefix_base = out.query_bit_base + 64;
    out.query_low_zero_prefix_base =
        out.query_top_ones_prefix_base + 33;
    out.query_valid = out.query_low_zero_prefix_base + 33;
    out.query_selected = out.query_valid + 1;
    out.query_have_selected = out.query_selected + 1;
    out.query_index_term = out.query_have_selected + 1;
    out.query_index_accumulator = out.query_index_term + 1;
    out.query_reduced_index = out.query_index_accumulator + 1;
    out.query_candidate_end = out.query_reduced_index + 1;
    out.query_group_start = out.query_candidate_end + 1;
    out.query_group_final = out.query_group_start + 1;
    out.ood_c1_inverse = out.query_group_final + 1;
    out.ood_c2_inverse = out.ood_c1_inverse + 1;
    out.ood_c1_nonzero = out.ood_c2_inverse + 1;
    out.ood_c2_nonzero = out.ood_c1_nonzero + 1;
    out.ood_ext_nonzero = out.ood_c2_nonzero + 1;
    out.ood_diff_inverse_base = out.ood_ext_nonzero + 1;
    out.ood_diff_nonzero_base = out.ood_diff_inverse_base + 3;
    out.ood_diff_any01 = out.ood_diff_nonzero_base + 3;
    out.ood_distinct = out.ood_diff_any01 + 1;
    out.ood_valid = out.ood_distinct + 1;
    out.ood_selected = out.ood_valid + 1;
    out.ood_have_selected = out.ood_selected + 1;
    out.ood_accepted_z1_base = out.ood_have_selected + 1;
    out.ood_accepted_z2_base = out.ood_accepted_z1_base + 3;
    out.ood_candidate_end = out.ood_accepted_z2_base + 3;
    out.ood_group_start = out.ood_candidate_end + 1;
    out.ood_group_final = out.ood_group_start + 1;
    out.ood_second_point = out.ood_group_final + 1;
    out.ood_z1_group_start = out.ood_second_point + 1;
    out.ood_z2_group_start = out.ood_z1_group_start + 1;
    out.ood_z1_candidate_end = out.ood_z2_group_start + 1;
    out.ood_z2_candidate_end = out.ood_z1_candidate_end + 1;
    return out;
}

namespace {

bool BuildConstraintSystemAtLayout(
    const Program& program,
    const Layout& layout,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    if (!ValidateProgram(program, why)) return false;
    out = {};
    out.n_rows = program.trace_rows;
    out.n_columns = layout.End();
    out.constraints =
        BuildConstraints(layout, program.query_domain_bits);
    // The recursion backend is row-wise and deliberately has no
    // per-column Merkle root to regenerate.  Pin canonical schedule/framing
    // columns at both FS OOD points, as the existing recursive V_CS does.
    out.preprocessed_pin_ood = true;

    std::vector<Fp3> active(program.trace_rows, Fp3::Zero());
    std::vector<Fp3> start(program.trace_rows, Fp3::Zero());
    std::vector<Fp3> cont(program.trace_rows, Fp3::Zero());
    std::vector<Fp3> chain(program.trace_rows, Fp3::Zero());
    std::vector<Fp3> query_candidate_end(
        program.trace_rows, Fp3::Zero());
    std::vector<Fp3> query_group_start(
        program.trace_rows, Fp3::Zero());
    std::vector<Fp3> query_group_final(
        program.trace_rows, Fp3::Zero());
    std::vector<Fp3> ood_candidate_end(
        program.trace_rows, Fp3::Zero());
    std::vector<Fp3> ood_group_start(
        program.trace_rows, Fp3::Zero());
    std::vector<Fp3> ood_group_final(
        program.trace_rows, Fp3::Zero());
    std::vector<Fp3> ood_second_point(
        program.trace_rows, Fp3::Zero());
    std::vector<Fp3> ood_z1_group_start(
        program.trace_rows, Fp3::Zero());
    std::vector<Fp3> ood_z2_group_start(
        program.trace_rows, Fp3::Zero());
    std::vector<Fp3> ood_z1_candidate_end(
        program.trace_rows, Fp3::Zero());
    std::vector<Fp3> ood_z2_candidate_end(
        program.trace_rows, Fp3::Zero());
    std::array<std::vector<Fp3>, kRate> fixed_mask;
    std::array<std::vector<Fp3>, kRate> fixed_value;
    std::array<std::vector<Fp3>, kRate> proof_mask;
    for (uint32_t lane = 0; lane < kRate; ++lane) {
        fixed_mask[lane].assign(program.trace_rows, Fp3::Zero());
        fixed_value[lane].assign(program.trace_rows, Fp3::Zero());
        proof_mask[lane].assign(program.trace_rows, Fp3::Zero());
    }
    for (uint32_t row = 0; row < program.trace_rows; ++row) {
        const ProgramRow& spec = program.rows[row];
        active[row] = Fp3::FromFp(spec.active ? 1 : 0);
        start[row] = Fp3::FromFp(spec.start ? 1 : 0);
        cont[row] = Fp3::FromFp(
            spec.continue_from_previous_row ? 1 : 0);
        chain[row] = Fp3::FromFp(
            spec.chain_digest_to_next_frame ? 1 : 0);
        query_candidate_end[row] =
            Fp3::FromFp(spec.query_candidate_end ? 1 : 0);
        query_group_start[row] =
            Fp3::FromFp(spec.query_group_start ? 1 : 0);
        query_group_final[row] =
            Fp3::FromFp(spec.query_group_final ? 1 : 0);
        ood_candidate_end[row] =
            Fp3::FromFp(spec.ood_candidate_end ? 1 : 0);
        ood_group_start[row] =
            Fp3::FromFp(spec.ood_group_start ? 1 : 0);
        ood_group_final[row] =
            Fp3::FromFp(spec.ood_group_final ? 1 : 0);
        ood_second_point[row] =
            Fp3::FromFp(spec.ood_second_point ? 1 : 0);
        ood_z1_group_start[row] =
            Fp3::FromFp(spec.ood_z1_group_start ? 1 : 0);
        ood_z2_group_start[row] =
            Fp3::FromFp(spec.ood_z2_group_start ? 1 : 0);
        ood_z1_candidate_end[row] =
            Fp3::FromFp(spec.ood_z1_candidate_end ? 1 : 0);
        ood_z2_candidate_end[row] =
            Fp3::FromFp(spec.ood_z2_candidate_end ? 1 : 0);
        for (uint32_t lane = 0; lane < kRate; ++lane) {
            fixed_mask[lane][row] =
                Fp3::FromFp(spec.fixed_mask[lane] ? 1 : 0);
            fixed_value[lane][row] =
                Fp3::FromFp(spec.source[lane]);
            proof_mask[lane][row] =
                Fp3::FromFp(spec.proof_mask[lane] ? 1 : 0);
        }
    }
    AddPreprocessed(out, layout.active, active);
    AddPreprocessed(out, layout.start, start);
    AddPreprocessed(out, layout.continue_from_previous_row, cont);
    AddPreprocessed(out, layout.chain_digest_to_next_frame, chain);
    AddPreprocessed(
        out, layout.query_candidate_end, query_candidate_end);
    AddPreprocessed(
        out, layout.query_group_start, query_group_start);
    AddPreprocessed(
        out, layout.query_group_final, query_group_final);
    AddPreprocessed(
        out, layout.ood_candidate_end, ood_candidate_end);
    AddPreprocessed(
        out, layout.ood_group_start, ood_group_start);
    AddPreprocessed(
        out, layout.ood_group_final, ood_group_final);
    AddPreprocessed(
        out, layout.ood_second_point, ood_second_point);
    AddPreprocessed(
        out, layout.ood_z1_group_start, ood_z1_group_start);
    AddPreprocessed(
        out, layout.ood_z2_group_start, ood_z2_group_start);
    AddPreprocessed(
        out, layout.ood_z1_candidate_end, ood_z1_candidate_end);
    AddPreprocessed(
        out, layout.ood_z2_candidate_end, ood_z2_candidate_end);
    for (uint32_t lane = 0; lane < kRate; ++lane) {
        AddPreprocessed(out, layout.FixedMask(lane), fixed_mask[lane]);
        AddPreprocessed(out, layout.FixedValue(lane), fixed_value[lane]);
        AddPreprocessed(out, layout.ProofMask(lane), proof_mask[lane]);
    }
    return true;
}

Layout DirectAliasLayout(
    uint32_t child_columns, uint32_t child_export_base)
{
    Layout out;
    out.poseidon = pa::CanonicalLayout(child_columns);
    out.source_base = out.poseidon.End();
    out.external_source_base = child_export_base;
    uint32_t cursor = out.source_base + kRate;
    out.active = cursor++;
    out.start = cursor++;
    out.continue_from_previous_row = cursor++;
    out.chain_digest_to_next_frame = cursor++;
    out.fixed_mask_base = cursor;
    cursor += kRate;
    out.fixed_value_base = cursor;
    cursor += kRate;
    out.proof_mask_base = cursor;
    cursor += kRate;
    out.query_bit_base = cursor;
    cursor += 64;
    out.query_top_ones_prefix_base = cursor;
    cursor += 33;
    out.query_low_zero_prefix_base = cursor;
    cursor += 33;
    out.query_valid = cursor++;
    out.query_selected = cursor++;
    out.query_have_selected = cursor++;
    out.query_index_term = cursor++;
    out.query_index_accumulator = cursor++;
    out.query_reduced_index = cursor++;
    out.query_candidate_end = cursor++;
    out.query_group_start = cursor++;
    out.query_group_final = cursor++;
    out.ood_c1_inverse = cursor++;
    out.ood_c2_inverse = cursor++;
    out.ood_c1_nonzero = cursor++;
    out.ood_c2_nonzero = cursor++;
    out.ood_ext_nonzero = cursor++;
    out.ood_diff_inverse_base = cursor;
    cursor += 3;
    out.ood_diff_nonzero_base = cursor;
    cursor += 3;
    out.ood_diff_any01 = cursor++;
    out.ood_distinct = cursor++;
    out.ood_valid = cursor++;
    out.ood_selected = cursor++;
    out.ood_have_selected = cursor++;
    out.ood_accepted_z1_base = cursor;
    cursor += 3;
    out.ood_accepted_z2_base = cursor;
    cursor += 3;
    out.ood_candidate_end = cursor++;
    out.ood_group_start = cursor++;
    out.ood_group_final = cursor++;
    out.ood_second_point = cursor++;
    out.ood_z1_group_start = cursor++;
    out.ood_z2_group_start = cursor++;
    out.ood_z1_candidate_end = cursor++;
    out.ood_z2_candidate_end = cursor++;
    return out;
}

} // namespace

bool BuildConstraintSystem(const Program& program,
                           aq::AirConstraintSystem<Fp3>& out,
                           std::string* why)
{
    return BuildConstraintSystemAtLayout(
        program, CanonicalLayout(), out, why);
}

Witness BuildWitness(const Program& program)
{
    Witness out;
    std::string why;
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildConstraintSystem(program, cs, &why)) {
        out.note = why;
        return out;
    }
    const Layout layout = CanonicalLayout();
    out.columns.assign(
        cs.n_columns,
        std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    for (const auto& [column, values] : cs.preprocessed) {
        out.columns[column] = values;
    }

    alg_hash::Digest previous_digest{};
    alg_hash::State state{};
    uint32_t current_frame = std::numeric_limits<uint32_t>::max();
    bool query_have_selected = false;
    uint32_t query_index_accumulator = 0;
    for (uint32_t row = 0; row < program.active_rows; ++row) {
        const ProgramRow& spec = program.rows[row];
        if (spec.query_group_start) {
            query_have_selected = false;
            query_index_accumulator = 0;
        }
        out.columns[layout.query_have_selected][row] =
            Fp3::FromFp(query_have_selected ? 1 : 0);
        out.columns[layout.query_index_accumulator][row] =
            Fp3::FromFp(query_index_accumulator);
        std::array<Fp, kRate> source = spec.source;
        if (spec.start) {
            state = {};
            current_frame = spec.frame;
            if (spec.frame != 0) {
                for (uint32_t lane = 0; lane < kDigest; ++lane) {
                    source[4 + lane] = previous_digest[lane];
                }
            }
        }
        alg_hash::State input = state;
        for (uint32_t lane = 0; lane < kRate; ++lane) {
            input[lane] = gf::Add(input[lane], source[lane]);
        }
        const pa::Witness permutation =
            pa::BuildWitness(layout.poseidon, input);
        for (uint32_t column = 0;
             column < layout.poseidon.End(); ++column) {
            out.columns[column][row] = permutation.row[column];
        }
        for (uint32_t lane = 0; lane < kRate; ++lane) {
            out.columns[layout.Source(lane)][row] =
                Fp3::FromFp(source[lane]);
            if (spec.proof_mask[lane]) {
                out.columns[layout.ExternalSource(lane)][row] =
                    Fp3::FromFp(source[lane]);
            }
        }
        state = permutation.output;
        if (spec.query_candidate_end) {
            const Fp candidate = gf::Canonical(state[0]);
            for (uint32_t bit = 0; bit < 64; ++bit) {
                out.columns[layout.QueryBit(bit)][row] =
                    Fp3::FromFp((candidate >> bit) & 1U);
            }

            bool top_all_ones = true;
            bool low_all_zero = true;
            out.columns[layout.QueryTopOnesPrefix(0)][row] =
                Fp3::One();
            out.columns[layout.QueryLowZeroPrefix(0)][row] =
                Fp3::One();
            for (uint32_t step = 0; step < 32; ++step) {
                top_all_ones =
                    top_all_ones &&
                    (((candidate >> (63 - step)) & 1U) != 0);
                low_all_zero =
                    low_all_zero &&
                    (((candidate >> (31 - step)) & 1U) == 0);
                out.columns[
                    layout.QueryTopOnesPrefix(step + 1)][row] =
                    Fp3::FromFp(top_all_ones ? 1 : 0);
                out.columns[
                    layout.QueryLowZeroPrefix(step + 1)][row] =
                    Fp3::FromFp(low_all_zero ? 1 : 0);
            }
            const bool valid = candidate != gf::kP - 1;
            const bool selected =
                valid && !query_have_selected;
            const uint32_t domain =
                uint32_t{1} << program.query_domain_bits;
            const uint32_t reduced =
                static_cast<uint32_t>(candidate & (domain - 1));
            const uint32_t term = selected ? reduced : 0;
            out.columns[layout.query_valid][row] =
                Fp3::FromFp(valid ? 1 : 0);
            out.columns[layout.query_selected][row] =
                Fp3::FromFp(selected ? 1 : 0);
            out.columns[layout.query_index_term][row] =
                Fp3::FromFp(term);
            if (spec.query_group_final) {
                out.columns[layout.query_reduced_index][row] =
                    Fp3::FromFp(
                        query_index_accumulator + term);
            }
            query_have_selected =
                query_have_selected || selected;
            query_index_accumulator += term;
        }
        if (spec.end) {
            alg_hash::Digest digest{};
            for (uint32_t lane = 0; lane < kDigest; ++lane) {
                digest[lane] = state[lane];
            }
            out.frame_digests.push_back(digest);
            previous_digest = digest;
        }
    }

    struct OodLaneWitness {
        std::array<std::array<Fp3, 3>, 4> candidate{};
        std::array<uint32_t, 4> row{};
        uint32_t count{0};
        uint32_t selected_z1{std::numeric_limits<uint32_t>::max()};
        uint32_t selected_z2{std::numeric_limits<uint32_t>::max()};
        std::array<Fp3, 3> z1{};
        std::array<Fp3, 3> z2{};
    };
    std::array<OodLaneWitness, 2> ood{};
    for (uint32_t row = 0; row < program.active_rows; ++row) {
        const ProgramRow& spec = program.rows[row];
        if (!spec.ood_candidate_end) continue;
        const Frame& frame = program.frames[spec.frame];
        if (frame.lane >= ood.size() || frame.index >= 4) {
            out.note = "stage3:v6_fs:ood_witness_schedule";
            return out;
        }
        OodLaneWitness& lane = ood[frame.lane];
        std::vector<Fp3> values(cs.n_columns);
        for (uint32_t column = 0; column < cs.n_columns; ++column) {
            values[column] = out.columns[column][row];
        }
        for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
            lane.candidate[frame.index][coordinate] =
                air_recurse::PermOutputLane(
                    layout.poseidon.perm, values, coordinate);
        }
        lane.row[frame.index] = row;
        ++lane.count;
    }
    for (OodLaneWitness& lane : ood) {
        if (lane.count == 0) continue;
        if (lane.count != 4) {
            out.note = "stage3:v6_fs:ood_witness_count";
            return out;
        }
        for (uint32_t candidate = 0; candidate < 2; ++candidate) {
            if (gf::IsZero(lane.candidate[candidate][1]) &&
                gf::IsZero(lane.candidate[candidate][2])) {
                continue;
            }
            lane.selected_z1 = candidate;
            lane.z1 = lane.candidate[candidate];
            break;
        }
        for (uint32_t candidate = 2; candidate < 4; ++candidate) {
            const auto& value = lane.candidate[candidate];
            const bool has_extension =
                !gf::IsZero(value[1]) || !gf::IsZero(value[2]);
            bool distinct = false;
            for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
                distinct =
                    distinct ||
                    !gf::Eq(value[coordinate], lane.z1[coordinate]);
            }
            if (!has_extension || !distinct) continue;
            lane.selected_z2 = candidate;
            lane.z2 = value;
            break;
        }
    }

    std::array<Fp3, 3> accepted_z1{};
    std::array<Fp3, 3> accepted_z2{};
    bool ood_have_selected = false;
    for (uint32_t row = 0; row < program.active_rows; ++row) {
        const ProgramRow& spec = program.rows[row];
        const Frame& frame = program.frames[spec.frame];
        if (spec.ood_z1_group_start) {
            accepted_z1 = ood[frame.lane].z1;
        }
        if (spec.ood_z2_group_start) {
            accepted_z2 = ood[frame.lane].z2;
        }
        if (spec.ood_group_start) ood_have_selected = false;
        out.columns[layout.ood_have_selected][row] =
            Fp3::FromFp(ood_have_selected ? 1 : 0);
        for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
            out.columns[layout.OodAcceptedZ1(coordinate)][row] =
                accepted_z1[coordinate];
            out.columns[layout.OodAcceptedZ2(coordinate)][row] =
                accepted_z2[coordinate];
        }
        if (!spec.ood_candidate_end) continue;

        const OodLaneWitness& lane = ood[frame.lane];
        const auto& candidate = lane.candidate[frame.index];
        const bool c1_nonzero = !gf::IsZero(candidate[1]);
        const bool c2_nonzero = !gf::IsZero(candidate[2]);
        out.columns[layout.ood_c1_nonzero][row] =
            Fp3::FromFp(c1_nonzero ? 1 : 0);
        out.columns[layout.ood_c2_nonzero][row] =
            Fp3::FromFp(c2_nonzero ? 1 : 0);
        out.columns[layout.ood_c1_inverse][row] =
            c1_nonzero ? gf::Inv(candidate[1]) : Fp3::Zero();
        out.columns[layout.ood_c2_inverse][row] =
            c2_nonzero ? gf::Inv(candidate[2]) : Fp3::Zero();
        const bool has_extension = c1_nonzero || c2_nonzero;
        out.columns[layout.ood_ext_nonzero][row] =
            Fp3::FromFp(has_extension ? 1 : 0);

        std::array<bool, 3> difference_nonzero{};
        for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
            const Fp3 difference = gf::Sub(
                candidate[coordinate], accepted_z1[coordinate]);
            difference_nonzero[coordinate] =
                !gf::IsZero(difference);
            out.columns[layout.OodDiffNonzero(coordinate)][row] =
                Fp3::FromFp(
                    difference_nonzero[coordinate] ? 1 : 0);
            out.columns[layout.OodDiffInverse(coordinate)][row] =
                difference_nonzero[coordinate]
                ? gf::Inv(difference) : Fp3::Zero();
        }
        const bool diff_any01 =
            difference_nonzero[0] || difference_nonzero[1];
        const bool is_distinct =
            diff_any01 || difference_nonzero[2];
        out.columns[layout.ood_diff_any01][row] =
            Fp3::FromFp(diff_any01 ? 1 : 0);
        out.columns[layout.ood_distinct][row] =
            Fp3::FromFp(is_distinct ? 1 : 0);

        const bool valid = has_extension &&
            (!spec.ood_second_point || is_distinct);
        const bool selected = valid && !ood_have_selected;
        out.columns[layout.ood_valid][row] =
            Fp3::FromFp(valid ? 1 : 0);
        out.columns[layout.ood_selected][row] =
            Fp3::FromFp(selected ? 1 : 0);
        ood_have_selected = ood_have_selected || selected;
    }

    // Padding rows still carry a valid fully-decomposed permutation so the
    // fixed Poseidon table remains selector-free and quadratic.
    for (uint32_t row = program.active_rows;
         row < program.trace_rows; ++row) {
        const pa::Witness padding =
            pa::BuildWitness(layout.poseidon, {});
        for (uint32_t column = 0;
             column < layout.poseidon.End(); ++column) {
            out.columns[column][row] = padding.row[column];
        }
    }
    if (current_frame + 1 != program.frames.size() ||
        out.frame_digests.size() != program.frames.size()) {
        out.note = "stage3:v6_fs:witness_frame_count";
        return out;
    }
    out.proof_payload_equality_hooks_satisfied =
        CountViolations(cs, out.columns) == 0;
    out.external_sources_owned_by_child_verifier = false;
    out.valid = out.proof_payload_equality_hooks_satisfied;
    out.note = out.valid
        ? "stage3:v6_fs:witness_ok_external_ownership_open"
        : "stage3:v6_fs:witness_constraint_failure";
    return out;
}

std::vector<QueryReductionResult>
ExtractQueryReductions(const Program& program, const Witness& witness)
{
    std::vector<QueryReductionResult> out;
    if (!program.valid || !witness.valid) return out;
    const Layout layout = CanonicalLayout();
    if (witness.columns.size() != layout.End()) return out;

    uint32_t selected_candidate = 0;
    bool saw_selected = false;
    for (uint32_t row = 0; row < program.active_rows; ++row) {
        const ProgramRow& spec = program.rows[row];
        if (spec.query_group_start) saw_selected = false;
        if (!spec.query_candidate_end) continue;
        const Frame& frame = program.frames[spec.frame];
        const uint32_t candidate =
            frame.index % kQueryCandidatesPerIndex;
        if (gf::Eq(
                witness.columns[layout.query_selected][row],
                Fp3::One())) {
            selected_candidate = candidate;
            saw_selected = true;
        }
        if (!spec.query_group_final) continue;
        const Fp3 reduced =
            witness.columns[layout.query_reduced_index][row];
        if (reduced.c1 != 0 || reduced.c2 != 0 ||
            reduced.c0 >=
                (uint64_t{1} << program.query_domain_bits)) {
            return {};
        }
        out.push_back(
            {frame.lane,
             frame.index / kQueryCandidatesPerIndex,
             selected_candidate,
             static_cast<uint32_t>(reduced.c0),
             saw_selected});
        if (!saw_selected) return {};
    }
    return out;
}

std::vector<OodSelectionResult>
ExtractOodSelections(const Program& program, const Witness& witness)
{
    std::vector<OodSelectionResult> out;
    if (!program.valid || !witness.valid) return out;
    const Layout layout = CanonicalLayout();
    if (witness.columns.size() != layout.End()) return out;

    std::array<OodSelectionResult, 2> lane{};
    std::array<bool, 2> present{};
    for (uint32_t row = 0; row < program.active_rows; ++row) {
        const ProgramRow& spec = program.rows[row];
        if (!spec.ood_candidate_end) continue;
        const Frame& frame = program.frames[spec.frame];
        if (frame.lane >= lane.size()) return {};
        OodSelectionResult& selected = lane[frame.lane];
        selected.lane = frame.lane;
        if (gf::Eq(
                witness.columns[layout.ood_selected][row],
                Fp3::One())) {
            if (spec.ood_second_point) {
                selected.z2_candidate = frame.index;
            } else {
                selected.z1_candidate = frame.index;
            }
        }
        if (!spec.ood_group_final) continue;
        std::array<Fp, 3> coordinates{};
        for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
            const Fp3 word =
                witness.columns[
                    spec.ood_second_point
                        ? layout.OodAcceptedZ2(coordinate)
                        : layout.OodAcceptedZ1(coordinate)][row];
            if (word.c1 != 0 || word.c2 != 0) return {};
            coordinates[coordinate] = word.c0;
        }
        if (spec.ood_second_point) {
            selected.z2 = {
                coordinates[0], coordinates[1], coordinates[2]};
            selected.z2_trace_row = row;
            selected.valid = true;
            present[frame.lane] = true;
        } else {
            selected.z1 = {
                coordinates[0], coordinates[1], coordinates[2]};
            selected.z1_trace_row = row;
        }
    }
    for (uint32_t i = 0; i < lane.size(); ++i) {
        if (present[i]) out.push_back(lane[i]);
    }
    return out;
}

QuerySamplerAssessment AssessQuerySampler(
    uint32_t domain_size, uint64_t global_sites)
{
    QuerySamplerAssessment out;
    out.domain_size = domain_size;
    out.candidates = kQueryCandidatesPerIndex;
    out.rejection_threshold = gf::kP - 1;
    if (!IsPowerOfTwo(domain_size)) return out;
    out.domain_bits = PowerOfTwoLog2(domain_size);
    if (out.domain_bits > kMaxQueryDomainBits) return out;
    const long double p = static_cast<long double>(gf::kP);
    out.exhaustion_bits_per_index =
        kQueryCandidatesPerIndex * std::log2(p);
    out.exhaustion_bits_after_sites =
        out.exhaustion_bits_per_index -
        std::log2(static_cast<long double>(
            std::max<uint64_t>(global_sites, 1)));
    out.exact_power_of_two_reduction = true;
    out.air_executable = kV6QueryReductionAirExecutable;
    out.global_transcript_independence_proved = false;
    return out;
}

bool BuildDirectAliasConstraintSystem(
    const Program& program,
    const aq::AirConstraintSystem<Fp3>& child_cs,
    uint32_t child_export_base,
    aq::AirConstraintSystem<Fp3>& out,
    DirectAliasComposition* composition,
    std::string* why)
{
    DirectAliasComposition local;
    local.child_columns = child_cs.n_columns;
    local.child_export_base = child_export_base;
    local.same_trace = child_cs.n_rows == program.trace_rows;
    if (!local.same_trace) {
        if (composition != nullptr) *composition = local;
        return Fail(why, "direct_alias_row_mismatch");
    }
    if (child_cs.constraints.empty()) {
        if (composition != nullptr) *composition = local;
        return Fail(why, "direct_alias_unconstrained_child");
    }
    if (child_export_base > child_cs.n_columns ||
        child_cs.n_columns - child_export_base < kRate) {
        if (composition != nullptr) *composition = local;
        return Fail(why, "direct_alias_export_range");
    }
    for (const auto& [column, values] : child_cs.preprocessed) {
        if (column >= child_cs.n_columns ||
            values.size() != child_cs.n_rows) {
            if (composition != nullptr) *composition = local;
            return Fail(why, "direct_alias_child_preprocessed_shape");
        }
    }

    local.transcript =
        DirectAliasLayout(child_cs.n_columns, child_export_base);
    aq::AirConstraintSystem<Fp3> transcript_cs;
    if (!BuildConstraintSystemAtLayout(
            program, local.transcript, transcript_cs, why)) {
        if (composition != nullptr) *composition = local;
        return false;
    }
    out = std::move(transcript_cs);
    out.constraints.insert(
        out.constraints.begin(),
        child_cs.constraints.begin(), child_cs.constraints.end());
    out.preprocessed.insert(
        out.preprocessed.begin(),
        child_cs.preprocessed.begin(), child_cs.preprocessed.end());
    out.preprocessed_pin_ood =
        out.preprocessed_pin_ood || child_cs.preprocessed_pin_ood;

    local.total_columns = out.n_columns;
    local.direct_alias =
        local.transcript.external_source_base == child_export_base;
    local.valid = local.same_trace && local.direct_alias;
    local.note = local.valid
        ? "stage3:v6_fs:direct_alias_composed"
        : "stage3:v6_fs:direct_alias_invalid";
    if (composition != nullptr) *composition = local;
    return local.valid;
}

Witness BuildDirectAliasWitness(
    const Program& program,
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const std::vector<std::vector<Fp3>>& child_columns,
    uint32_t child_export_base)
{
    Witness out;
    aq::AirConstraintSystem<Fp3> combined_cs;
    DirectAliasComposition composition;
    std::string why;
    if (!BuildDirectAliasConstraintSystem(
            program, child_cs, child_export_base, combined_cs,
            &composition, &why)) {
        out.note = why;
        return out;
    }
    if (child_columns.size() != child_cs.n_columns) {
        out.note = "stage3:v6_fs:direct_alias_child_column_count";
        return out;
    }
    for (const auto& column : child_columns) {
        if (column.size() != child_cs.n_rows) {
            out.note = "stage3:v6_fs:direct_alias_child_row_count";
            return out;
        }
    }

    const Witness transcript = BuildWitness(program);
    if (!transcript.valid) {
        out.note = transcript.note;
        return out;
    }
    const Layout canonical = CanonicalLayout();
    const Layout& owned = composition.transcript;
    out.columns.assign(
        combined_cs.n_columns,
        std::vector<Fp3>(combined_cs.n_rows, Fp3::Zero()));
    for (uint32_t column = 0; column < child_cs.n_columns;
         ++column) {
        out.columns[column] = child_columns[column];
    }
    for (const auto& [column, values] : combined_cs.preprocessed) {
        out.columns[column] = values;
    }

    for (uint32_t offset = 0;
         offset < stage3_poseidon_air::kFixedColumns; ++offset) {
        out.columns[owned.poseidon.perm.base + offset] =
            transcript.columns[
                canonical.poseidon.perm.base + offset];
    }
    for (uint32_t lane = 0; lane < kRate; ++lane) {
        out.columns[owned.Source(lane)] =
            transcript.columns[canonical.Source(lane)];
    }
    for (uint32_t offset = 0;
         canonical.active + offset < canonical.End(); ++offset) {
        out.columns[owned.active + offset] =
            transcript.columns[canonical.active + offset];
    }

    out.frame_digests = transcript.frame_digests;
    out.proof_payload_equality_hooks_satisfied =
        CountViolations(combined_cs, out.columns) == 0;
    out.external_sources_owned_by_child_verifier =
        out.proof_payload_equality_hooks_satisfied;
    out.valid =
        out.proof_payload_equality_hooks_satisfied &&
        out.external_sources_owned_by_child_verifier;
    out.note = out.valid
        ? "stage3:v6_fs:direct_alias_witness_ok"
        : "stage3:v6_fs:direct_alias_child_or_transcript_failure";
    return out;
}

uint32_t CountViolations(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t* first_row,
    std::string* first_constraint)
{
    if (columns.size() != cs.n_columns) {
        if (first_constraint != nullptr) {
            *first_constraint = "stage3.v6_fs.shape";
        }
        return 1;
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            if (first_constraint != nullptr) {
                *first_constraint = "stage3.v6_fs.shape";
            }
            return 1;
        }
    }
    std::vector<Fp3> cur(cs.n_columns);
    std::vector<Fp3> next(cs.n_columns);
    uint32_t violations = 0;
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        const uint32_t next_row = (row + 1) % cs.n_rows;
        for (uint32_t column = 0; column < cs.n_columns; ++column) {
            cur[column] = columns[column][row];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint : cs.constraints) {
            bool applies = true;
            if (constraint.kind == aq::AirKind::kTransition) {
                applies = row + 1 < cs.n_rows;
            } else if (constraint.kind == aq::AirKind::kFirstRow) {
                applies = row == 0;
            } else if (constraint.kind == aq::AirKind::kLastRow) {
                applies = row + 1 == cs.n_rows;
            }
            if (applies &&
                !gf::IsZero(constraint.eval(cur, next))) {
                if (violations == 0) {
                    if (first_row != nullptr) *first_row = row;
                    if (first_constraint != nullptr) {
                        *first_constraint =
                            constraint.name != nullptr
                                ? constraint.name : "";
                    }
                }
                ++violations;
            }
        }
    }
    return violations;
}

Program BuildMasterBindingProgram(const MasterBindingInput& input)
{
    Frame master;
    master.kind = FrameKind::MasterStatement;
    master.lane = 0;
    master.index = 0;
    master.payload.reserve(32 + 3 + 2 * kDigest);
    for (uint8_t byte : input.public_statement_sha256d) {
        master.payload.push_back(
            {CanonicalFp(byte), WordOrigin::PublicStatement});
    }
    master.payload.push_back(
        {CanonicalFp(input.batch_columns),
         WordOrigin::PublicStatement});
    master.payload.push_back(
        {CanonicalFp(input.n_coeffs),
         WordOrigin::PublicStatement});
    master.payload.push_back(
        {CanonicalFp(input.n_lde),
         WordOrigin::PublicStatement});
    for (uint32_t lane = 0; lane < 2; ++lane) {
        for (Fp limb : input.ordered_lane_row_roots[lane]) {
            master.payload.push_back(
                {limb, WordOrigin::ProofDerived});
        }
    }

    Frame lane0;
    lane0.kind = FrameKind::LaneSeed;
    lane0.lane = 0;
    lane0.index = 0;
    Frame lane1 = lane0;
    lane1.lane = 1;
    return BuildProgram({master, lane0, lane1});
}

Program BuildFullTranscriptProgram(const FullTranscriptInput& input)
{
    if (input.master.batch_columns == 0 ||
        input.folds == 0 || input.queries == 0) {
        Program invalid;
        invalid.note = "stage3:v6_fs:full_shape";
        return invalid;
    }
    const Program master =
        BuildMasterBindingProgram(input.master);
    if (!master.valid || master.frames.empty()) return master;

    std::vector<Frame> frames;
    frames.reserve(
        1 + 2 * (3 + input.master.batch_columns + 4 + 3 +
                 2 * input.folds +
                 kQueryCandidatesPerIndex * input.queries));
    frames.push_back(master.frames.front());

    auto add_digest_payload =
        [](Frame& frame, const alg_hash::Digest& digest) {
            for (Fp limb : digest) {
                frame.payload.push_back(
                    {limb, WordOrigin::ProofDerived});
            }
        };
    auto add_fp3_payload =
        [](Frame& frame, const Fp3& value) {
            frame.payload.push_back(
                {value.c0, WordOrigin::ProofDerived});
            frame.payload.push_back(
                {value.c1, WordOrigin::ProofDerived});
            frame.payload.push_back(
                {value.c2, WordOrigin::ProofDerived});
        };

    for (uint32_t lane = 0; lane < 2; ++lane) {
        const LaneProofInput& proof = input.lane[lane];
        if (proof.row_root !=
                input.master.ordered_lane_row_roots[lane] ||
            proof.evals_z1.size() != input.master.batch_columns ||
            proof.evals_z2.size() != input.master.batch_columns ||
            proof.fold_roots.size() != input.folds) {
            Program invalid;
            invalid.note =
                "stage3:v6_fs:full_proof_shape_or_root";
            return invalid;
        }

        Frame trace;
        trace.kind = FrameKind::AbsorbCommitment;
        trace.lane = lane;
        trace.index = 0;
        add_digest_payload(trace, proof.trace_root);
        frames.push_back(std::move(trace));

        Frame air_challenge;
        air_challenge.kind = FrameKind::AirQuotientChallenge;
        air_challenge.lane = lane;
        frames.push_back(std::move(air_challenge));

        Frame lane_seed;
        lane_seed.kind = FrameKind::LaneSeed;
        lane_seed.lane = lane;
        frames.push_back(std::move(lane_seed));

        for (uint32_t column = 0;
             column < input.master.batch_columns; ++column) {
            Frame coefficient;
            coefficient.kind = FrameKind::BatchCoefficient;
            coefficient.lane = lane;
            coefficient.index = column;
            frames.push_back(std::move(coefficient));
        }
        for (uint32_t candidate = 0; candidate < 4; ++candidate) {
            Frame ood;
            ood.kind = FrameKind::OodCandidate;
            ood.lane = lane;
            ood.index = candidate;
            frames.push_back(std::move(ood));
        }

        Frame evaluations;
        evaluations.kind = FrameKind::AbsorbEvaluation;
        evaluations.lane = lane;
        for (const Fp3& value : proof.evals_z1) {
            add_fp3_payload(evaluations, value);
        }
        for (const Fp3& value : proof.evals_z2) {
            add_fp3_payload(evaluations, value);
        }
        frames.push_back(std::move(evaluations));

        for (uint32_t weight = 0; weight < 2; ++weight) {
            Frame deep;
            deep.kind = FrameKind::DeepWeight;
            deep.lane = lane;
            deep.index = weight;
            frames.push_back(std::move(deep));
        }
        for (uint32_t fold = 0; fold < input.folds; ++fold) {
            Frame root;
            root.kind = FrameKind::AbsorbCommitment;
            root.lane = lane;
            root.index = fold + 1;
            add_digest_payload(root, proof.fold_roots[fold]);
            frames.push_back(std::move(root));

            Frame challenge;
            challenge.kind = FrameKind::FoldChallenge;
            challenge.lane = lane;
            challenge.index = fold;
            frames.push_back(std::move(challenge));
        }
        for (uint32_t query = 0; query < input.queries; ++query) {
            for (uint32_t ordinal = 0;
                 ordinal < kQueryCandidatesPerIndex; ++ordinal) {
                Frame candidate;
                candidate.kind = FrameKind::QueryCandidate;
                candidate.lane = lane;
                candidate.index =
                    query * kQueryCandidatesPerIndex + ordinal;
                candidate.payload.push_back(
                    {CanonicalFp(input.master.n_lde),
                     WordOrigin::PublicStatement});
                frames.push_back(std::move(candidate));
            }
        }
    }
    return BuildProgram(frames);
}

std::array<ScenarioAssessment, 3>
AssessScenarios(const Program& v6_program,
                uint64_t sha256d_compression_blocks)
{
    const Layout layout = CanonicalLayout();
    ScenarioAssessment sha;
    sha.scenario = Scenario::ExistingSha256dAir;
    sha.existing_wire_compatible = true;
    sha.algebraic_transcript_in_air = false;
    sha.master_and_lane_binding_in_air = false;
    sha.proof_payload_equality_seam = true;
    sha.host_digest_trust_removed = true;
    sha.query_reduction_closed = true;
    sha.child_source_integration_closed = false;
    sha.production_authority_ready = false;
    sha.trace_width = 144; // current fixed-program SHA table width
    sha.permutation_or_compression_rows =
        sha256d_compression_blocks;
    sha.verdict =
        "compatible but bit-level SHA program/CTL attachment remains open";

    ScenarioAssessment v6;
    v6.scenario = Scenario::AlgebraicV6;
    v6.existing_wire_compatible = false;
    v6.algebraic_transcript_in_air =
        kV6AlgebraicTranscriptAirExecutable;
    v6.master_and_lane_binding_in_air =
        kV6MasterLaneBindingAirExecutable;
    v6.proof_payload_equality_seam = true;
    v6.host_digest_trust_removed = true;
    v6.query_reduction_closed =
        kV6QueryReductionAirExecutable;
    v6.child_source_integration_closed =
        kV6ChildProofSourceIntegrationExecutable;
    v6.production_authority_ready = false;
    v6.trace_width = layout.End();
    v6.permutation_or_compression_rows =
        v6_program.valid ? v6_program.active_rows : 0;
    v6.verdict =
        "selected V1 route: executable algebraic replay and exact fixed-pool "
        "query reduction with complete proof-payload source ownership; "
        "challenge feedback and the recursive fixed point remain open";

    ScenarioAssessment hybrid;
    hybrid.scenario = Scenario::HostDigestHybrid;
    hybrid.existing_wire_compatible = false;
    hybrid.algebraic_transcript_in_air = true;
    hybrid.master_and_lane_binding_in_air = true;
    hybrid.proof_payload_equality_seam = false;
    hybrid.host_digest_trust_removed = false;
    hybrid.query_reduction_closed = false;
    hybrid.child_source_integration_closed = false;
    hybrid.production_authority_ready = false;
    hybrid.trace_width = layout.End();
    hybrid.permutation_or_compression_rows = 1;
    hybrid.verdict =
        "rejected for authority: a host-produced digest is not a proof-derived "
        "child transcript";
    return {sha, v6, hybrid};
}

} // namespace matmul::v4::rc::stage3_v6_fs
