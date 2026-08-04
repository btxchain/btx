// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_airq_p2_transcript.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>

namespace matmul::v4::rc::stage3_airq_p2_transcript {
namespace {

namespace ah = alg_hash;
namespace ar = air_recurse;

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) {
        *why = "stage3:airq_p2_transcript:" + message;
    }
    return false;
}

bool IsPowerOfTwo(uint32_t value)
{
    return value >= 2 &&
           (value & (value - 1)) == 0;
}

uint32_t NextPow2AtLeast2(uint32_t value)
{
    uint32_t out = 2;
    while (out < value) {
        if (out >
            std::numeric_limits<uint32_t>::max() / 2) {
            return 0;
        }
        out <<= 1;
    }
    return out;
}

uint32_t ReadLE32(const unsigned char* bytes)
{
    uint32_t out = 0;
    for (uint32_t byte = 0; byte < 4; ++byte) {
        out |= static_cast<uint32_t>(bytes[byte])
               << (8 * byte);
    }
    return out;
}

uint64_t ReadLE64(const unsigned char* bytes)
{
    uint64_t out = 0;
    for (uint32_t byte = 0; byte < 8; ++byte) {
        out |= static_cast<uint64_t>(bytes[byte])
               << (8 * byte);
    }
    return out;
}

std::vector<gf::Fp> PaddedLanes(
    std::vector<gf::Fp> lanes)
{
    lanes.push_back(gf::FromU64(1));
    while (lanes.size() % ah::kAlgHashRate != 0) {
        lanes.push_back(gf::FromU64(0));
    }
    return lanes;
}

void AddConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    cs.constraints.push_back(
        {name, kind, degree, std::move(eval)});
}

uint32_t MaxDegree(
    const aq::AirConstraintSystem<Fp3>& cs)
{
    uint32_t out = 0;
    for (const auto& constraint : cs.constraints) {
        out = std::max(
            out, constraint.alg_degree);
    }
    return out;
}

bool ValidateStatement(
    const Statement& statement,
    std::string* why)
{
    if (statement.route_version !=
        aq::kAirChallengeP2RouteVersion) {
        return Fail(why, "wrong_route_version");
    }
    if (statement.domain_tag !=
        aq::kAirChallengeP2DomainTag) {
        return Fail(why, "wrong_domain");
    }
    if (statement.label != kLambdaLabel) {
        return Fail(why, "wrong_label");
    }
    if (!IsPowerOfTwo(statement.n_rows)) {
        return Fail(why, "n_rows_not_power_of_two");
    }
    if (!IsPowerOfTwo(statement.quotient_len)) {
        return Fail(
            why, "quotient_len_not_power_of_two");
    }
    if (statement.trace_width == 0) {
        return Fail(why, "zero_trace_width");
    }
    return true;
}

} // namespace

uint32_t Layout::MessageCol(uint32_t lane) const
{
    return message_base + lane;
}

uint32_t Layout::DigestCol(uint32_t lane) const
{
    return digest_base + lane;
}

uint32_t Layout::LambdaCol(uint32_t coord) const
{
    return lambda_base + coord;
}

uint32_t Layout::End() const
{
    return lambda_base + 3;
}

bool Layout::IsCanonical(std::string* why) const
{
    if (poseidon.perm.base != 0 ||
        message_base != poseidon.End() ||
        active_col !=
            message_base + ah::kAlgHashRate ||
        start_col != active_col + 1 ||
        terminal_col != start_col + 1 ||
        digest_base != terminal_col + 1 ||
        lambda_base != digest_base + 4) {
        return Fail(why, "noncanonical_layout");
    }
    return poseidon.IsCanonical(why);
}

Layout CanonicalLayout()
{
    Layout out;
    out.poseidon = pa::CanonicalLayout(0);
    out.message_base = out.poseidon.End();
    out.active_col =
        out.message_base + ah::kAlgHashRate;
    out.start_col = out.active_col + 1;
    out.terminal_col = out.start_col + 1;
    out.digest_base = out.terminal_col + 1;
    out.lambda_base = out.digest_base + 4;
    return out;
}

BuildResult BuildAirqLambdaTranscriptAir(
    const Statement& statement)
{
    BuildResult out;
    out.statement = statement;
    out.layout = CanonicalLayout();
    std::string why;
    if (!out.layout.IsCanonical(&why) ||
        !ValidateStatement(statement, &why)) {
        out.note = why;
        return out;
    }
    out.canonical_statement = true;

    out.native_lanes =
        aq::AirChallengeP2Lanes(
            statement.fs_seed, statement.label.c_str(),
            {statement.trace_commit},
            {statement.n_rows,
             statement.quotient_len,
             statement.trace_width});
    if (out.native_lanes.empty()) {
        out.note =
            "stage3:airq_p2_transcript:empty_lanes";
        return out;
    }
    for (const gf::Fp lane : out.native_lanes) {
        if (gf::Canonical(lane) >=
            (uint64_t{1} << 32)) {
            out.note =
                "stage3:airq_p2_transcript:"
                "non_u32_lane";
            return out;
        }
    }
    out.exact_air_challenge_lanes = true;

    out.native_digest =
        aq::AirChallengeDigestP2(
            statement.fs_seed, statement.label.c_str(),
            {statement.trace_commit},
            {statement.n_rows,
             statement.quotient_len,
             statement.trace_width});
    out.native_lambda =
        gf::FromChallengeBytes3(
            out.native_digest.data());

    const std::vector<gf::Fp> padded =
        PaddedLanes(out.native_lanes);
    const uint32_t active_rows =
        static_cast<uint32_t>(
            padded.size() / ah::kAlgHashRate);
    if (active_rows !=
        aq::AirChallengeP2Permutations(
            out.native_lanes.size())) {
        out.note =
            "stage3:airq_p2_transcript:"
            "padding_schedule_mismatch";
        return out;
    }
    const uint32_t n_rows =
        NextPow2AtLeast2(active_rows);
    if (n_rows == 0) {
        out.note =
            "stage3:airq_p2_transcript:row_overflow";
        return out;
    }
    out.active_rows = active_rows;
    out.n_rows = n_rows;
    out.n_columns = out.layout.End();

    out.cs.n_rows = n_rows;
    out.cs.n_columns = out.layout.End();
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(n_rows, Fp3::Zero()));
    out.cs.constraints =
        pa::BuildFixedConstraints(out.layout.poseidon);

    for (uint32_t row = 0;
         row < active_rows;
         ++row) {
        out.columns[out.layout.active_col][row] =
            Fp3::One();
        out.columns[out.layout.start_col][row] =
            row == 0 ? Fp3::One() : Fp3::Zero();
        out.columns[out.layout.terminal_col][row] =
            row + 1 == active_rows
                ? Fp3::One()
                : Fp3::Zero();
        for (uint32_t lane = 0;
             lane < ah::kAlgHashRate;
             ++lane) {
            out.columns[
                out.layout.MessageCol(lane)][row] =
                Fp3::FromFp(
                    padded[
                        row * ah::kAlgHashRate +
                        lane]);
        }
    }

    ah::State state{};
    for (uint32_t row = 0;
         row < active_rows;
         ++row) {
        for (uint32_t lane = 0;
             lane < ah::kAlgHashRate;
             ++lane) {
            state[lane] = gf::Add(
                state[lane],
                padded[
                    row * ah::kAlgHashRate +
                    lane]);
        }
        const pa::Witness witness =
            pa::BuildWitness(
                out.layout.poseidon, state);
        for (uint32_t column =
                 out.layout.poseidon.perm.base;
             column < out.layout.poseidon.End();
             ++column) {
            out.columns[column][row] =
                witness.row[column];
        }
        state = witness.output;
    }
    const uint32_t terminal = active_rows - 1;
    for (uint32_t lane = 0; lane < 4; ++lane) {
        out.columns[
            out.layout.DigestCol(lane)][terminal] =
            Fp3::FromFp(state[lane]);
    }
    for (uint32_t coord = 0; coord < 3; ++coord) {
        const gf::Fp value =
            coord == 0
                ? out.native_lambda.c0
                : coord == 1
                      ? out.native_lambda.c1
                      : out.native_lambda.c2;
        out.columns[
            out.layout.LambdaCol(coord)][terminal] =
            Fp3::FromFp(value);
    }

    const ah::State zero{};
    for (uint32_t row = active_rows;
         row < n_rows;
         ++row) {
        const pa::Witness witness =
            pa::BuildWitness(
                out.layout.poseidon, zero);
        for (uint32_t column =
                 out.layout.poseidon.perm.base;
             column < out.layout.poseidon.End();
             ++column) {
            out.columns[column][row] =
                witness.row[column];
        }
    }

    const std::array<uint32_t, 11> pinned{
        out.layout.MessageCol(0),
        out.layout.MessageCol(1),
        out.layout.MessageCol(2),
        out.layout.MessageCol(3),
        out.layout.MessageCol(4),
        out.layout.MessageCol(5),
        out.layout.MessageCol(6),
        out.layout.MessageCol(7),
        out.layout.active_col,
        out.layout.start_col,
        out.layout.terminal_col};
    for (const uint32_t column : pinned) {
        out.cs.preprocessed.push_back(
            {column, out.columns[column]});
    }
    out.cs.preprocessed_pin_ood = true;
    out.absorb_lanes_preprocessed_pinned = true;

    for (uint32_t lane = 0;
         lane < ah::kAlgHashRate;
         ++lane) {
        const uint32_t input =
            out.layout.poseidon.perm.InputCol(lane);
        const uint32_t message =
            out.layout.MessageCol(lane);
        AddConstraint(
            out.cs, "stage3.airq_p2.first_absorb",
            aq::AirKind::kFirstRow, 1,
            [input, message](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    cur[input], cur[message]);
            });

        const uint32_t active =
            out.layout.active_col;
        const pa::Layout poseidon =
            out.layout.poseidon;
        AddConstraint(
            out.cs, "stage3.airq_p2.sponge_chain",
            aq::AirKind::kTransition, 2,
            [poseidon, input, message, active, lane](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>& next) {
                return gf::Mul(
                    next[active],
                    gf::Sub(
                        next[input],
                        gf::Add(
                            ar::PermOutputLane(
                                poseidon.perm,
                                cur, lane),
                            next[message])));
            });
    }
    for (uint32_t lane = ah::kAlgHashRate;
         lane < ah::kAlgHashT;
         ++lane) {
        const uint32_t input =
            out.layout.poseidon.perm.InputCol(lane);
        const uint32_t active =
            out.layout.active_col;
        const pa::Layout poseidon =
            out.layout.poseidon;
        AddConstraint(
            out.cs, "stage3.airq_p2.first_capacity",
            aq::AirKind::kFirstRow, 1,
            [input](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return cur[input];
            });
        AddConstraint(
            out.cs, "stage3.airq_p2.capacity_chain",
            aq::AirKind::kTransition, 2,
            [poseidon, input, active, lane](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>& next) {
                return gf::Mul(
                    next[active],
                    gf::Sub(
                        next[input],
                        ar::PermOutputLane(
                            poseidon.perm,
                            cur, lane)));
            });
    }

    for (uint32_t lane = 0; lane < 4; ++lane) {
        const uint32_t digest =
            out.layout.DigestCol(lane);
        const uint32_t terminal_col =
            out.layout.terminal_col;
        const pa::Layout poseidon =
            out.layout.poseidon;
        const Fp3 expected =
            Fp3::FromFp(
                gf::FromU64(
                    ReadLE64(
                        out.native_digest.data() +
                        8 * lane)));
        AddConstraint(
            out.cs, "stage3.airq_p2.digest_output",
            aq::AirKind::kEverywhere, 2,
            [poseidon, digest, terminal_col, lane](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[terminal_col],
                    gf::Sub(
                        cur[digest],
                        ar::PermOutputLane(
                            poseidon.perm,
                            cur, lane)));
            });
        AddConstraint(
            out.cs, "stage3.airq_p2.digest_public",
            aq::AirKind::kEverywhere, 2,
            [digest, terminal_col, expected](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[terminal_col],
                    gf::Sub(
                        cur[digest], expected));
            });
        AddConstraint(
            out.cs, "stage3.airq_p2.digest_off_terminal",
            aq::AirKind::kEverywhere, 2,
            [digest, terminal_col](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        cur[terminal_col]),
                    cur[digest]);
            });
    }
    for (uint32_t coord = 0; coord < 3; ++coord) {
        const uint32_t lambda =
            out.layout.LambdaCol(coord);
        const uint32_t digest =
            out.layout.DigestCol(coord);
        const uint32_t terminal_col =
            out.layout.terminal_col;
        AddConstraint(
            out.cs, "stage3.airq_p2.lambda_digest",
            aq::AirKind::kEverywhere, 2,
            [lambda, digest, terminal_col](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[terminal_col],
                    gf::Sub(
                        cur[lambda], cur[digest]));
            });
        AddConstraint(
            out.cs, "stage3.airq_p2.lambda_off_terminal",
            aq::AirKind::kEverywhere, 2,
            [lambda, terminal_col](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        cur[terminal_col]),
                    cur[lambda]);
            });
    }

    for (uint32_t word = 0; word < 8; ++word) {
        out.source_map.seed_u32[word] =
            ReadLE32(
                statement.fs_seed.data() + 4 * word);
        out.source_map.trace_commit_u32[word] =
            ReadLE32(
                statement.trace_commit.data() +
                4 * word);
    }
    out.source_map.shape_u32 = {
        statement.n_rows,
        statement.quotient_len,
        statement.trace_width};
    out.source_map.absorb_lanes =
        out.native_lanes;
    out.source_map.canonical_u32_encoding = true;
    out.appendable_source_map_canonical = true;

    out.consumer_map.terminal_row = terminal;
    out.consumer_map.lambda_columns = {
        out.layout.LambdaCol(0),
        out.layout.LambdaCol(1),
        out.layout.LambdaCol(2)};
    out.consumer_map.lambda = out.native_lambda;
    out.appendable_consumer_map_canonical = true;

    const uint256 digest_from_state = [&] {
        unsigned char bytes[32]{};
        for (uint32_t lane = 0; lane < 4; ++lane) {
            const uint64_t value =
                gf::Canonical(state[lane]);
            for (uint32_t byte = 0; byte < 8; ++byte) {
                bytes[8 * lane + byte] =
                    static_cast<unsigned char>(
                        value >> (8 * byte));
            }
        }
        return uint256{
            Span<const unsigned char>{bytes, 32}};
    }();
    out.exact_air_challenge_digest =
        digest_from_state == out.native_digest;
    out.exact_from_challenge_bytes3 =
        gf::Eq(
            gf::FromChallengeBytes3(
                digest_from_state.data()),
            out.native_lambda);
    out.poseidon_permutations_constrained =
        out.cs.constraints.size() >=
        pa::kFixedConstraints;
    out.sponge_state_chain_constrained = true;
    out.digest_and_lambda_constrained = true;
    out.n_constraints =
        static_cast<uint32_t>(
            out.cs.constraints.size());
    out.max_alg_degree = MaxDegree(out.cs);
    out.violations =
        CountViolations(out.cs, out.columns);

    out.proof_owned_source_cells_bound = false;
    out.same_parent_consumer_cells_bound = false;
    out.recursive_authority = false;
    out.local_air_complete =
        out.canonical_statement &&
        out.exact_air_challenge_lanes &&
        out.exact_air_challenge_digest &&
        out.exact_from_challenge_bytes3 &&
        out.absorb_lanes_preprocessed_pinned &&
        out.poseidon_permutations_constrained &&
        out.sponge_state_chain_constrained &&
        out.digest_and_lambda_constrained &&
        out.appendable_source_map_canonical &&
        out.appendable_consumer_map_canonical &&
        out.violations == 0;
    out.valid =
        out.local_air_complete &&
        !out.proof_owned_source_cells_bound &&
        !out.same_parent_consumer_cells_bound &&
        !out.recursive_authority;
    out.note = out.valid
        ? "exact AIRQ P2 lambda replay executes; proof-owned root/shape "
          "and same-parent consumer equalities remain open"
        : "stage3:airq_p2_transcript:local_incomplete";
    return out;
}

uint32_t CountViolations(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != cs.n_columns) {
        return 1;
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return 1;
        }
    }
    uint32_t violations = 0;
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        std::vector<Fp3> cur(cs.n_columns);
        std::vector<Fp3> next(cs.n_columns);
        const uint32_t next_row =
            (row + 1) % cs.n_rows;
        for (uint32_t column = 0;
             column < cs.n_columns;
             ++column) {
            cur[column] = columns[column][row];
            next[column] =
                columns[column][next_row];
        }
        for (const auto& constraint : cs.constraints) {
            bool enabled =
                constraint.kind ==
                    aq::AirKind::kEverywhere ||
                (constraint.kind ==
                     aq::AirKind::kFirstRow &&
                 row == 0) ||
                (constraint.kind ==
                     aq::AirKind::kLastRow &&
                 row + 1 == cs.n_rows) ||
                (constraint.kind ==
                     aq::AirKind::kTransition &&
                 row + 1 < cs.n_rows);
            if (enabled &&
                !gf::IsZero(
                    constraint.eval(cur, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

} // namespace matmul::v4::rc::stage3_airq_p2_transcript
