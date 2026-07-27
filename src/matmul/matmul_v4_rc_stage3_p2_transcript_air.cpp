// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_p2_transcript_air.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <iterator>
#include <limits>
#include <utility>

namespace matmul::v4::rc::stage3_p2_transcript_air {
namespace {

namespace ar = air_recurse;
namespace ah = alg_hash;

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) {
        *why = "stage3:p2_transcript_air:" + message;
    }
    return false;
}

void AppendLE32(std::vector<unsigned char>& out, uint32_t value)
{
    for (uint32_t i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
}

void AppendLE64(std::vector<unsigned char>& out, uint64_t value)
{
    for (uint32_t i = 0; i < 8; ++i) {
        out.push_back(
            static_cast<unsigned char>(value >> (8 * i)));
    }
}

uint32_t NextPow2AtLeast2(uint32_t value)
{
    uint32_t out = 2;
    while (out < value) {
        if (out > std::numeric_limits<uint32_t>::max() / 2) return 0;
        out <<= 1;
    }
    return out;
}

std::vector<gf::Fp> PaddedSpongeLanes(std::vector<gf::Fp> lanes)
{
    lanes.push_back(gf::FromU64(1));
    while (lanes.size() % ah::kAlgHashRate != 0) {
        lanes.push_back(gf::FromU64(0));
    }
    return lanes;
}

Fp3 Coord(const Fp3& value, uint32_t coord)
{
    if (coord == 0) return Fp3::FromFp(value.c0);
    if (coord == 1) return Fp3::FromFp(value.c1);
    return Fp3::FromFp(value.c2);
}

uint32_t ConstraintMaxDegree(
    const aq::AirConstraintSystem<Fp3>& cs)
{
    uint32_t out = 0;
    for (const auto& constraint : cs.constraints) {
        out = std::max(out, constraint.alg_degree);
    }
    return out;
}

uint32_t CountConstraintsNamed(
    const aq::AirConstraintSystem<Fp3>& cs,
    const char* name)
{
    uint32_t out = 0;
    for (const auto& constraint : cs.constraints) {
        if (std::strcmp(constraint.name, name) == 0) ++out;
    }
    return out;
}

bool ValidateParameters(
    const Statement& statement,
    std::string* why)
{
    if (statement.version != kArtifactVersion) {
        return Fail(why, "wrong_version");
    }
    if (statement.queries != kQueries) {
        return Fail(why, "wrong_query_count");
    }
    if (statement.ood_candidates != kOodCandidates) {
        return Fail(why, "wrong_ood_window");
    }
    if (statement.n_folds == 0 ||
        statement.n_folds > kMaxFolds) {
        return Fail(why, "bad_fold_count");
    }
    if (statement.query_modulus < 2 ||
        (statement.query_modulus &
         (statement.query_modulus - 1)) != 0) {
        return Fail(why, "query_modulus_not_power_of_two");
    }
    return true;
}

ah::Digest CommitPrefixBytes(
    const std::vector<unsigned char>& bytes)
{
    std::vector<gf::Fp> lanes;
    lanes.reserve(1 + (bytes.size() + 3) / 4);
    lanes.push_back(
        gf::FromU64(static_cast<uint32_t>(bytes.size())));
    for (size_t offset = 0; offset < bytes.size(); offset += 4) {
        uint32_t word = 0;
        for (size_t byte = 0;
             byte < 4 && offset + byte < bytes.size();
             ++byte) {
            word |= static_cast<uint32_t>(
                        bytes[offset + byte])
                    << (8 * byte);
        }
        lanes.push_back(gf::FromU64(word));
    }
    return ah::SpongeHashFp(lanes);
}

void AddConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<Fp3(const std::vector<Fp3>&,
                      const std::vector<Fp3>&)> eval)
{
    cs.constraints.push_back(
        {name, kind, degree, std::move(eval)});
}

} // namespace

uint32_t Layout::MessageCol(uint32_t candidate_index,
                            uint32_t lane) const
{
    return message_base[candidate_index] + lane;
}

uint32_t Layout::ZeroCol(uint32_t candidate_index,
                         uint32_t ext_coord) const
{
    return zero_base + 2 * candidate_index + ext_coord;
}

uint32_t Layout::InverseCol(uint32_t candidate_index,
                            uint32_t ext_coord) const
{
    return inverse_base + 2 * candidate_index + ext_coord;
}

uint32_t Layout::ExtAcceptCol(uint32_t candidate_index) const
{
    return ext_accept_base + candidate_index;
}

uint32_t Layout::EligibleCol(uint32_t candidate_index) const
{
    return eligible_base + candidate_index;
}

uint32_t Layout::SelectedCol(uint32_t z_slot, uint32_t coord) const
{
    return selected_base + 3 * z_slot + coord;
}

uint32_t Layout::Z1MemoryCol(uint32_t coord) const
{
    return z1_memory_base + coord;
}

uint32_t Layout::DiffZeroCol(uint32_t candidate_index,
                             uint32_t coord) const
{
    return diff_zero_base + 3 * candidate_index + coord;
}

uint32_t Layout::DiffInverseCol(uint32_t candidate_index,
                                uint32_t coord) const
{
    return diff_inverse_base + 3 * candidate_index + coord;
}

uint32_t Layout::DiffAndCol(uint32_t candidate_index,
                            uint32_t stage) const
{
    return diff_and_base + 2 * candidate_index + stage;
}

uint32_t Layout::DistinctCol(uint32_t candidate_index) const
{
    return distinct_base + candidate_index;
}

uint32_t Layout::QueryBitCol(uint32_t bit) const
{
    return query_bit_base + bit;
}

uint32_t Layout::QueryHighAndCol(uint32_t stage) const
{
    return query_high_and_base + stage;
}

uint32_t Layout::End() const
{
    return query_low_inverse_col + 1;
}

bool Layout::IsCanonical(std::string* why) const
{
    if (candidate[0].End() != candidate[1].perm.base ||
        !candidate[0].IsCanonical(why) ||
        !candidate[1].IsCanonical(why) ||
        message_base[0] != candidate[1].End() ||
        message_base[1] != message_base[0] + ah::kAlgHashRate ||
        active_col != message_base[1] + ah::kAlgHashRate ||
        event_start_col != active_col + 1 ||
        terminal_col != event_start_col + 1 ||
        event_ordinal_col != terminal_col + 1 ||
        event_kind_col != event_ordinal_col + 1 ||
        semantic_index_col != event_kind_col + 1 ||
        draw_index_col != semantic_index_col + 1 ||
        z1_terminal_col != draw_index_col + 1 ||
        z2_terminal_col != z1_terminal_col + 1 ||
        query_terminal_col != z2_terminal_col + 1 ||
        query_index_col != query_terminal_col + 1 ||
        zero_base != query_index_col + 1 ||
        inverse_base != zero_base + 4 ||
        ext_accept_base != inverse_base + 4 ||
        eligible_base != ext_accept_base + 2 ||
        selected_base != eligible_base + 2 ||
        z1_memory_base != selected_base + 6 ||
        diff_zero_base != z1_memory_base + 3 ||
        diff_inverse_base != diff_zero_base + 6 ||
        diff_and_base != diff_inverse_base + 6 ||
        distinct_base != diff_and_base + 4 ||
        query_bit_base != distinct_base + 2 ||
        query_high_and_base != query_bit_base + 64 ||
        query_low_zero_col != query_high_and_base + 32 ||
        query_low_inverse_col != query_low_zero_col + 1) {
        return Fail(why, "noncanonical_layout");
    }
    return true;
}

Layout CanonicalLayout(uint32_t base)
{
    Layout out;
    out.candidate[0] = pa::CanonicalLayout(base);
    out.candidate[1] = pa::CanonicalLayout(out.candidate[0].End());
    out.message_base[0] = out.candidate[1].End();
    out.message_base[1] =
        out.message_base[0] + ah::kAlgHashRate;
    out.active_col =
        out.message_base[1] + ah::kAlgHashRate;
    out.event_start_col = out.active_col + 1;
    out.terminal_col = out.event_start_col + 1;
    out.event_ordinal_col = out.terminal_col + 1;
    out.event_kind_col = out.event_ordinal_col + 1;
    out.semantic_index_col = out.event_kind_col + 1;
    out.draw_index_col = out.semantic_index_col + 1;
    out.z1_terminal_col = out.draw_index_col + 1;
    out.z2_terminal_col = out.z1_terminal_col + 1;
    out.query_terminal_col = out.z2_terminal_col + 1;
    out.query_index_col = out.query_terminal_col + 1;
    out.zero_base = out.query_index_col + 1;
    out.inverse_base = out.zero_base + 4;
    out.ext_accept_base = out.inverse_base + 4;
    out.eligible_base = out.ext_accept_base + 2;
    out.selected_base = out.eligible_base + 2;
    out.z1_memory_base = out.selected_base + 6;
    out.diff_zero_base = out.z1_memory_base + 3;
    out.diff_inverse_base = out.diff_zero_base + 6;
    out.diff_and_base = out.diff_inverse_base + 6;
    out.distinct_base = out.diff_and_base + 4;
    out.query_bit_base = out.distinct_base + 2;
    out.query_high_and_base = out.query_bit_base + 64;
    out.query_low_zero_col = out.query_high_and_base + 32;
    out.query_low_inverse_col = out.query_low_zero_col + 1;
    return out;
}

bool CanonicalStatementPrefix(
    const Statement& statement,
    std::vector<unsigned char>& out,
    std::string* why)
{
    out.clear();
    if (!ValidateParameters(statement, why)) return false;
    std::vector<EventDescriptor> manifest;
    if (!CanonicalEventManifest(
            statement, manifest, why)) {
        return false;
    }
    if (statement.event_prefixes.size() !=
        manifest.size()) {
        return Fail(why, "event_prefix_schedule_size");
    }

    constexpr uint32_t domain_len = static_cast<uint32_t>(
        sizeof(kStatementDomainTag) - 1);
    out.reserve(
        4 + domain_len + 6 * 4 +
        manifest.size() * (5 * 4 + 32));
    AppendLE32(out, domain_len);
    out.insert(
        out.end(), kStatementDomainTag,
        kStatementDomainTag + domain_len);
    AppendLE32(out, statement.version);
    AppendLE32(out, statement.queries);
    AppendLE32(out, statement.ood_candidates);
    AppendLE32(out, statement.n_folds);
    AppendLE32(out, statement.query_modulus);
    AppendLE32(out, kZ1FirstDrawIndex);
    AppendLE32(
        out, static_cast<uint32_t>(manifest.size()));
    for (size_t index = 0;
         index < manifest.size();
         ++index) {
        const EventDescriptor& event = manifest[index];
        const EventPrefix& prefix =
            statement.event_prefixes[index];
        if (prefix.kind != event.kind ||
            prefix.semantic_index !=
                event.semantic_index) {
            return Fail(
                why,
                "event_prefix_schedule_order_" +
                    std::to_string(index));
        }
        if (prefix.bytes.empty() ||
            prefix.bytes.size() > kMaxPayloadBytes ||
            prefix.bytes.size() >
                std::numeric_limits<uint32_t>::max()) {
            return Fail(
                why,
                "bad_event_prefix_size_" +
                    std::to_string(index));
        }
        const ah::Digest commitment =
            CommitPrefixBytes(prefix.bytes);
        AppendLE32(out, event.ordinal);
        AppendLE32(
            out, static_cast<uint32_t>(event.kind));
        AppendLE32(out, event.semantic_index);
        AppendLE32(out, event.draw_index);
        AppendLE32(
            out,
            static_cast<uint32_t>(
                prefix.bytes.size()));
        for (const gf::Fp limb : commitment) {
            AppendLE64(out, gf::Canonical(limb));
        }
    }
    return true;
}

bool CanonicalEventPrefix(
    const Statement& statement,
    const EventDescriptor& event,
    std::vector<unsigned char>& out,
    std::string* why)
{
    out.clear();
    std::vector<unsigned char> ignored;
    if (!CanonicalStatementPrefix(
            statement, ignored, why)) {
        return false;
    }
    if (event.ordinal >=
        statement.event_prefixes.size()) {
        return Fail(why, "event_prefix_ordinal");
    }
    const EventPrefix& prefix =
        statement.event_prefixes[event.ordinal];
    if (prefix.kind != event.kind ||
        prefix.semantic_index != event.semantic_index) {
        return Fail(why, "event_prefix_descriptor");
    }
    out = prefix.bytes;
    return true;
}

bool CanonicalEventManifest(
    const Statement& statement,
    std::vector<EventDescriptor>& out,
    std::string* why)
{
    out.clear();
    if (!ValidateParameters(statement, why)) return false;
    const auto append = [&](EventKind kind,
                            uint32_t semantic_index,
                            uint32_t draw_index,
                            const char* label) {
        out.push_back(
            {static_cast<uint32_t>(out.size()), kind,
             semantic_index, draw_index, label});
    };
    append(EventKind::FriLambda, 0, 0, "fra3_lambda");
    append(EventKind::OodZ1, 0, kZ1FirstDrawIndex, kOodLabel);
    append(EventKind::OodZ2, 1, kZ2FirstDrawIndex, kOodLabel);
    append(EventKind::DeepW1, 0, 0, "fra3_w");
    append(EventKind::DeepW2, 1, 1, "fra3_w");
    for (uint32_t fold = 0; fold < statement.n_folds; ++fold) {
        append(EventKind::Fold, fold, fold, "fra3_fold");
    }
    for (uint32_t query = 0; query < kQueries; ++query) {
        append(EventKind::Query, query, query, "fra3_query");
    }
    return true;
}

bool IsCanonicalEventManifest(
    const Statement& statement,
    const std::vector<EventDescriptor>& manifest,
    std::string* why)
{
    std::vector<EventDescriptor> expected;
    if (!CanonicalEventManifest(statement, expected, why)) {
        return false;
    }
    if (manifest.size() != expected.size()) {
        return Fail(why, "event_manifest_size");
    }
    for (size_t i = 0; i < expected.size(); ++i) {
        const auto& a = manifest[i];
        const auto& b = expected[i];
        if (a.ordinal != b.ordinal ||
            a.kind != b.kind ||
            a.semantic_index != b.semantic_index ||
            a.draw_index != b.draw_index ||
            a.label != b.label) {
            return Fail(
                why, "event_manifest_order_" +
                         std::to_string(i));
        }
    }
    return true;
}

BuildResult BuildTranscriptAirV10At(
    const Statement& statement,
    uint32_t base_column,
    uint32_t minimum_rows)
{
    struct EventExecution {
        EventDescriptor descriptor;
        std::array<std::vector<gf::Fp>, kOodCandidates> padded;
        std::array<Fp3, kOodCandidates> challenge{};
        uint32_t start_row{0};
        uint32_t terminal_row{0};
        uint32_t blocks{0};
        uint32_t query_index{0};
    };

    BuildResult out;
    out.statement = statement;
    out.layout = CanonicalLayout(base_column);
    std::string why;
    if (!out.layout.IsCanonical(&why)) {
        out.note = why;
        return out;
    }

    std::vector<unsigned char> statement_commitment;
    if (!CanonicalStatementPrefix(
            statement, statement_commitment, &why)) {
        out.note = why;
        return out;
    }
    if (!CanonicalEventManifest(statement, out.manifest, &why) ||
        !IsCanonicalEventManifest(
            statement, out.manifest, &why)) {
        out.note = why;
        return out;
    }
    out.canonical_parameters = true;
    out.prefix_free_v10_statement = true;
    out.canonical_event_manifest = true;

    std::vector<EventExecution> events;
    events.reserve(out.manifest.size());
    uint64_t active_rows64 = 0;
    for (const EventDescriptor& descriptor : out.manifest) {
        EventExecution event;
        event.descriptor = descriptor;
        const std::vector<unsigned char>& event_prefix =
            statement.event_prefixes[
                descriptor.ordinal].bytes;
        for (uint32_t candidate = 0;
             candidate < kOodCandidates;
             ++candidate) {
            uint32_t draw = descriptor.draw_index;
            if (descriptor.kind == EventKind::OodZ1 ||
                descriptor.kind == EventKind::OodZ2) {
                draw += candidate;
            }
            event.padded[candidate] = PaddedSpongeLanes(
                Fri3AlgP2SqueezeAbsorbLanes(
                    event_prefix,
                    descriptor.label.c_str(), draw));
            if (event.padded[candidate].empty() ||
                event.padded[candidate].size() %
                        ah::kAlgHashRate != 0) {
                out.note =
                    "stage3:p2_transcript_air:"
                    "bad_event_lane_shape";
                return out;
            }
            const uint32_t blocks =
                static_cast<uint32_t>(
                    event.padded[candidate].size() /
                    ah::kAlgHashRate);
            if (candidate == 0) {
                event.blocks = blocks;
            } else if (event.blocks != blocks) {
                out.note =
                    "stage3:p2_transcript_air:"
                    "event_candidate_shape_mismatch";
                return out;
            }
            event.challenge[candidate] =
                Fri3AlgP2SqueezeChallengeFp3(
                    event_prefix,
                    descriptor.label.c_str(), draw);
        }
        if (event.blocks == 0 ||
            active_rows64 + event.blocks >
                std::numeric_limits<uint32_t>::max()) {
            out.note =
                "stage3:p2_transcript_air:"
                "event_row_overflow";
            return out;
        }
        event.start_row =
            static_cast<uint32_t>(active_rows64);
        active_rows64 += event.blocks;
        event.terminal_row =
            static_cast<uint32_t>(active_rows64 - 1);
        if (out.permutations_per_scalar_event == 0 &&
            descriptor.kind != EventKind::OodZ1 &&
            descriptor.kind != EventKind::OodZ2) {
            out.permutations_per_scalar_event =
                event.blocks;
        }
        events.push_back(std::move(event));
    }

    const uint32_t active_rows =
        static_cast<uint32_t>(active_rows64);
    uint32_t n_rows =
        NextPow2AtLeast2(active_rows);
    if (active_rows == 0 || n_rows == 0 ||
        (minimum_rows != 0 &&
         (minimum_rows < n_rows ||
          minimum_rows < 2 ||
          (minimum_rows & (minimum_rows - 1)) != 0))) {
        out.note =
            "stage3:p2_transcript_air:row_overflow";
        return out;
    }
    if (minimum_rows != 0) {
        n_rows = minimum_rows;
    }
    out.active_rows = active_rows;
    out.n_rows = n_rows;
    out.n_columns = out.layout.End();

    out.cs = {};
    out.cs.n_rows = n_rows;
    out.cs.n_columns = out.layout.End();
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(n_rows, Fp3::Zero()));

    for (uint32_t candidate = 0;
         candidate < kOodCandidates;
         ++candidate) {
        auto permutation_constraints =
            pa::BuildFixedConstraints(
                out.layout.candidate[candidate]);
        out.cs.constraints.insert(
            out.cs.constraints.end(),
            std::make_move_iterator(
                permutation_constraints.begin()),
            std::make_move_iterator(
                permutation_constraints.end()));
    }

    // Materialize the canonical, verifier-regenerated event manifest. Every
    // row of one event repeats its tags; start/terminal are single-row flags.
    for (const EventExecution& event : events) {
        const bool z1 =
            event.descriptor.kind == EventKind::OodZ1;
        const bool z2 =
            event.descriptor.kind == EventKind::OodZ2;
        const bool query =
            event.descriptor.kind == EventKind::Query;
        for (uint32_t block = 0;
             block < event.blocks;
             ++block) {
            const uint32_t row = event.start_row + block;
            out.columns[out.layout.active_col][row] =
                Fp3::One();
            out.columns[out.layout.event_start_col][row] =
                block == 0 ? Fp3::One() : Fp3::Zero();
            out.columns[out.layout.terminal_col][row] =
                block + 1 == event.blocks
                    ? Fp3::One()
                    : Fp3::Zero();
            out.columns[out.layout.event_ordinal_col][row] =
                Fp3::FromFp(gf::FromU64(
                    event.descriptor.ordinal));
            out.columns[out.layout.event_kind_col][row] =
                Fp3::FromFp(gf::FromU64(
                    static_cast<uint32_t>(
                        event.descriptor.kind)));
            out.columns[out.layout.semantic_index_col][row] =
                Fp3::FromFp(gf::FromU64(
                    event.descriptor.semantic_index));
            out.columns[out.layout.draw_index_col][row] =
                Fp3::FromFp(gf::FromU64(
                    event.descriptor.draw_index));
            if (block + 1 == event.blocks) {
                out.columns[out.layout.z1_terminal_col][row] =
                    z1 ? Fp3::One() : Fp3::Zero();
                out.columns[out.layout.z2_terminal_col][row] =
                    z2 ? Fp3::One() : Fp3::Zero();
                out.columns[out.layout.query_terminal_col][row] =
                    query ? Fp3::One() : Fp3::Zero();
            }
            for (uint32_t candidate = 0;
                 candidate < kOodCandidates;
                 ++candidate) {
                for (uint32_t lane = 0;
                     lane < ah::kAlgHashRate;
                     ++lane) {
                    out.columns[
                        out.layout.MessageCol(
                            candidate, lane)][row] =
                        Fp3::FromFp(
                            event.padded[candidate][
                                block *
                                    ah::kAlgHashRate +
                                lane]);
                }
            }
        }
    }

    // Execute every event with the same two fixed-width Poseidon blocks.
    out.event_challenges.resize(
        events.size(), Fp3::Zero());
    out.query_indices.reserve(kQueries);
    for (size_t event_index = 0;
         event_index < events.size();
         ++event_index) {
        EventExecution& event = events[event_index];
        std::array<ah::State, kOodCandidates> state{};
        for (uint32_t block = 0;
             block < event.blocks;
             ++block) {
            const uint32_t row = event.start_row + block;
            for (uint32_t candidate = 0;
                 candidate < kOodCandidates;
                 ++candidate) {
                for (uint32_t lane = 0;
                     lane < ah::kAlgHashRate;
                     ++lane) {
                    state[candidate][lane] = gf::Add(
                        state[candidate][lane],
                        event.padded[candidate][
                            block * ah::kAlgHashRate +
                            lane]);
                }
                const pa::Witness witness =
                    pa::BuildWitness(
                        out.layout.candidate[candidate],
                        state[candidate]);
                for (uint32_t column =
                         out.layout.candidate[candidate]
                             .perm.base;
                     column <
                         out.layout.candidate[candidate]
                             .End();
                     ++column) {
                    out.columns[column][row] =
                        witness.row[column];
                }
                state[candidate] = witness.output;
            }
        }
        for (uint32_t candidate = 0;
             candidate < kOodCandidates;
             ++candidate) {
            const Fp3 computed{
                gf::Canonical(state[candidate][0]),
                gf::Canonical(state[candidate][1]),
                gf::Canonical(state[candidate][2])};
            if (!gf::Eq(
                    computed,
                    event.challenge[candidate])) {
                out.note =
                    "stage3:p2_transcript_air:"
                    "native_p2_divergence";
                return out;
            }
        }
        if (event.descriptor.kind != EventKind::OodZ1 &&
            event.descriptor.kind != EventKind::OodZ2) {
            out.event_challenges[event_index] =
                event.challenge[0];
        }
        if (event.descriptor.kind == EventKind::Query) {
            event.query_index =
                static_cast<uint32_t>(
                    gf::Canonical(
                        event.challenge[0].c0)) &
                (statement.query_modulus - 1);
            out.query_indices.push_back(
                event.query_index);
            out.columns[
                out.layout.query_index_col]
                [event.terminal_row] =
                Fp3::FromFp(
                    gf::FromU64(event.query_index));
        }
    }

    // Fixed Poseidon identities also apply on padding rows.
    const ah::State zero_state{};
    for (uint32_t row = active_rows;
         row < n_rows;
         ++row) {
        for (uint32_t candidate = 0;
             candidate < kOodCandidates;
             ++candidate) {
            const pa::Witness witness =
                pa::BuildWitness(
                    out.layout.candidate[candidate],
                    zero_state);
            for (uint32_t column =
                     out.layout.candidate[candidate]
                         .perm.base;
                 column <
                     out.layout.candidate[candidate]
                         .End();
                 ++column) {
                out.columns[column][row] =
                    witness.row[column];
            }
        }
    }
    out.exact_p2_absorb_lanes = true;

    const auto has_ext = [](const Fp3& x) {
        return gf::Canonical(x.c1) != 0 ||
               gf::Canonical(x.c2) != 0;
    };
    size_t z1_event_index = events.size();
    size_t z2_event_index = events.size();
    for (size_t i = 0; i < events.size(); ++i) {
        if (events[i].descriptor.kind == EventKind::OodZ1) {
            z1_event_index = i;
        } else if (
            events[i].descriptor.kind == EventKind::OodZ2) {
            z2_event_index = i;
        }
    }
    if (z1_event_index == events.size() ||
        z2_event_index == events.size()) {
        out.note =
            "stage3:p2_transcript_air:"
            "ood_events_missing";
        return out;
    }
    for (uint32_t candidate = 0;
         candidate < kOodCandidates;
         ++candidate) {
        out.z_candidate[0][candidate] =
            events[z1_event_index].challenge[candidate];
        out.z_candidate[1][candidate] =
            events[z2_event_index].challenge[candidate];
    }
    const bool z1_accept[2] = {
        has_ext(out.z_candidate[0][0]),
        has_ext(out.z_candidate[0][1])};
    if (!z1_accept[0] && !z1_accept[1]) {
        out.note =
            "stage3:p2_transcript_air:"
            "z1_k2_window_exhausted";
        return out;
    }
    out.selected_z1 = z1_accept[0]
        ? out.z_candidate[0][0]
        : out.z_candidate[0][1];
    const bool z2_accept[2] = {
        has_ext(out.z_candidate[1][0]) &&
            !gf::Eq(
                out.z_candidate[1][0],
                out.selected_z1),
        has_ext(out.z_candidate[1][1]) &&
            !gf::Eq(
                out.z_candidate[1][1],
                out.selected_z1)};
    if (!z2_accept[0] && !z2_accept[1]) {
        out.note =
            "stage3:p2_transcript_air:"
            "z2_k2_window_exhausted";
        return out;
    }
    out.selected_z2 = z2_accept[0]
        ? out.z_candidate[1][0]
        : out.z_candidate[1][1];
    out.event_challenges[z1_event_index] =
        out.selected_z1;
    out.event_challenges[z2_event_index] =
        out.selected_z2;

    // Populate the row-multiplexed OOD selector witnesses.
    for (uint32_t z_slot = 0;
         z_slot < 2;
         ++z_slot) {
        const EventExecution& event =
            events[z_slot == 0
                       ? z1_event_index
                       : z2_event_index];
        const uint32_t row = event.terminal_row;
        for (uint32_t candidate = 0;
             candidate < kOodCandidates;
             ++candidate) {
            bool ext_zero[2]{};
            for (uint32_t ext = 0; ext < 2; ++ext) {
                const Fp3 x = Coord(
                    out.z_candidate[z_slot][candidate],
                    ext + 1);
                ext_zero[ext] = gf::IsZero(x);
                out.columns[
                    out.layout.ZeroCol(
                        candidate, ext)][row] =
                    ext_zero[ext]
                        ? Fp3::One()
                        : Fp3::Zero();
                out.columns[
                    out.layout.InverseCol(
                        candidate, ext)][row] =
                    ext_zero[ext]
                        ? Fp3::Zero()
                        : gf::Inv(x);
            }
            const bool ext_accept =
                !(ext_zero[0] && ext_zero[1]);
            out.columns[
                out.layout.ExtAcceptCol(candidate)][row] =
                ext_accept
                    ? Fp3::One()
                    : Fp3::Zero();

            bool eligible = ext_accept;
            if (z_slot == 1) {
                bool diff_zero[3]{};
                for (uint32_t coord = 0;
                     coord < 3;
                     ++coord) {
                    const Fp3 diff = gf::Sub(
                        Coord(
                            out.z_candidate[1][candidate],
                            coord),
                        Coord(out.selected_z1, coord));
                    diff_zero[coord] = gf::IsZero(diff);
                    out.columns[
                        out.layout.DiffZeroCol(
                            candidate, coord)][row] =
                        diff_zero[coord]
                            ? Fp3::One()
                            : Fp3::Zero();
                    out.columns[
                        out.layout.DiffInverseCol(
                            candidate, coord)][row] =
                        diff_zero[coord]
                            ? Fp3::Zero()
                            : gf::Inv(diff);
                }
                const bool and01 =
                    diff_zero[0] && diff_zero[1];
                const bool equal =
                    and01 && diff_zero[2];
                out.columns[
                    out.layout.DiffAndCol(
                        candidate, 0)][row] =
                    and01 ? Fp3::One() : Fp3::Zero();
                out.columns[
                    out.layout.DiffAndCol(
                        candidate, 1)][row] =
                    equal ? Fp3::One() : Fp3::Zero();
                out.columns[
                    out.layout.DistinctCol(
                        candidate)][row] =
                    equal ? Fp3::Zero() : Fp3::One();
                eligible = ext_accept && !equal;
            }
            out.columns[
                out.layout.EligibleCol(candidate)][row] =
                eligible ? Fp3::One() : Fp3::Zero();
        }
        const Fp3 selected =
            z_slot == 0
                ? out.selected_z1
                : out.selected_z2;
        for (uint32_t coord = 0;
             coord < 3;
             ++coord) {
            out.columns[
                out.layout.SelectedCol(
                    z_slot, coord)][row] =
                Coord(selected, coord);
        }
    }

    // Carry z1 as an actual trace value into the z2 distinctness row.
    const uint32_t z1_terminal =
        events[z1_event_index].terminal_row;
    for (uint32_t row = z1_terminal;
         row < n_rows;
         ++row) {
        for (uint32_t coord = 0;
             coord < 3;
             ++coord) {
            out.columns[
                out.layout.Z1MemoryCol(coord)][row] =
                Coord(out.selected_z1, coord);
        }
    }

    // Canonically decompose each query's c0.  The additional comparison
    // excludes the Goldilocks x+p alias before projecting low bits.
    for (const EventExecution& event : events) {
        if (event.descriptor.kind != EventKind::Query) {
            continue;
        }
        const uint32_t row = event.terminal_row;
        const uint64_t c0 =
            gf::Canonical(event.challenge[0].c0);
        for (uint32_t bit = 0; bit < 64; ++bit) {
            out.columns[
                out.layout.QueryBitCol(bit)][row] =
                ((c0 >> bit) & 1)
                    ? Fp3::One()
                    : Fp3::Zero();
        }
        bool high_and = true;
        for (uint32_t stage = 0;
             stage < 32;
             ++stage) {
            high_and =
                high_and &&
                (((c0 >> (32 + stage)) & 1) != 0);
            out.columns[
                out.layout.QueryHighAndCol(stage)][row] =
                high_and
                    ? Fp3::One()
                    : Fp3::Zero();
        }
        const uint32_t low =
            static_cast<uint32_t>(c0);
        const bool low_zero = low == 0;
        out.columns[
            out.layout.query_low_zero_col][row] =
            low_zero ? Fp3::One() : Fp3::Zero();
        out.columns[
            out.layout.query_low_inverse_col][row] =
            low_zero
                ? Fp3::Zero()
                : gf::Inv(Fp3::FromFp(
                      gf::FromU64(low)));
    }

    // Pin the complete canonical event image, including all Q192 query
    // indices. Source ownership remains a separate, explicitly false seam.
    const std::array<uint32_t, 27> preprocessed_columns = {
        out.layout.MessageCol(0, 0),
        out.layout.MessageCol(0, 1),
        out.layout.MessageCol(0, 2),
        out.layout.MessageCol(0, 3),
        out.layout.MessageCol(0, 4),
        out.layout.MessageCol(0, 5),
        out.layout.MessageCol(0, 6),
        out.layout.MessageCol(0, 7),
        out.layout.MessageCol(1, 0),
        out.layout.MessageCol(1, 1),
        out.layout.MessageCol(1, 2),
        out.layout.MessageCol(1, 3),
        out.layout.MessageCol(1, 4),
        out.layout.MessageCol(1, 5),
        out.layout.MessageCol(1, 6),
        out.layout.MessageCol(1, 7),
        out.layout.active_col,
        out.layout.event_start_col,
        out.layout.terminal_col,
        out.layout.event_ordinal_col,
        out.layout.event_kind_col,
        out.layout.semantic_index_col,
        out.layout.draw_index_col,
        out.layout.z1_terminal_col,
        out.layout.z2_terminal_col,
        out.layout.query_terminal_col,
        out.layout.query_index_col};
    for (const uint32_t column :
         preprocessed_columns) {
        out.cs.preprocessed.push_back(
            {column, out.columns[column]});
    }
    out.cs.preprocessed_pin_ood = true;

    // First row always begins the first canonical event.
    for (uint32_t candidate = 0;
         candidate < kOodCandidates;
         ++candidate) {
        const pa::Layout poseidon =
            out.layout.candidate[candidate];
        for (uint32_t lane = 0;
             lane < ah::kAlgHashRate;
             ++lane) {
            const uint32_t input =
                poseidon.perm.InputCol(lane);
            const uint32_t message =
                out.layout.MessageCol(candidate, lane);
            AddConstraint(
                out.cs,
                "stage3.p2tx.event.first_absorb",
                aq::AirKind::kFirstRow, 1,
                [input, message](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Sub(
                        cur[input], cur[message]);
                });
        }
        for (uint32_t lane = ah::kAlgHashRate;
             lane < ah::kAlgHashT;
             ++lane) {
            const uint32_t input =
                poseidon.perm.InputCol(lane);
            AddConstraint(
                out.cs,
                "stage3.p2tx.event.first_capacity",
                aq::AirKind::kFirstRow, 1,
                [input](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return cur[input];
                });
        }

        // A start row resets the sponge; every other active row continues it.
        for (uint32_t lane = 0;
             lane < ah::kAlgHashRate;
             ++lane) {
            const uint32_t input =
                poseidon.perm.InputCol(lane);
            const uint32_t message =
                out.layout.MessageCol(candidate, lane);
            const uint32_t active =
                out.layout.active_col;
            const uint32_t start =
                out.layout.event_start_col;
            AddConstraint(
                out.cs,
                "stage3.p2tx.event.absorb_chain",
                aq::AirKind::kTransition, 3,
                [poseidon, input, message,
                 active, start, lane](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>& next) {
                    const Fp3 continued = gf::Mul(
                        gf::Sub(
                            Fp3::One(), next[start]),
                        ar::PermOutputLane(
                            poseidon.perm, cur, lane));
                    return gf::Mul(
                        next[active],
                        gf::Sub(
                            next[input],
                            gf::Add(
                                next[message],
                                continued)));
                });
        }
        for (uint32_t lane = ah::kAlgHashRate;
             lane < ah::kAlgHashT;
             ++lane) {
            const uint32_t input =
                poseidon.perm.InputCol(lane);
            const uint32_t active =
                out.layout.active_col;
            const uint32_t start =
                out.layout.event_start_col;
            AddConstraint(
                out.cs,
                "stage3.p2tx.event.capacity_chain",
                aq::AirKind::kTransition, 3,
                [poseidon, input, active, start, lane](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>& next) {
                    return gf::Mul(
                        next[active],
                        gf::Sub(
                            next[input],
                            gf::Mul(
                                gf::Sub(
                                    Fp3::One(),
                                    next[start]),
                                ar::PermOutputLane(
                                    poseidon.perm,
                                    cur, lane))));
                });
        }
    }

    // Algebraic event continuity makes omissions/reorders detectable even
    // before the verifier-side preprocessed commitment check.
    const uint32_t active_col = out.layout.active_col;
    const uint32_t start_col = out.layout.event_start_col;
    const uint32_t ordinal_col =
        out.layout.event_ordinal_col;
    AddConstraint(
        out.cs,
        "stage3.p2tx.event.first_ordinal",
        aq::AirKind::kFirstRow, 1,
        [ordinal_col](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return cur[ordinal_col];
        });
    AddConstraint(
        out.cs,
        "stage3.p2tx.event.ordinal_progression",
        aq::AirKind::kTransition, 2,
        [active_col, start_col, ordinal_col](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>& next) {
            return gf::Mul(
                next[active_col],
                gf::Sub(
                    next[ordinal_col],
                    gf::Add(
                        cur[ordinal_col],
                        next[start_col])));
        });
    for (const uint32_t tag_col : {
             out.layout.event_kind_col,
             out.layout.semantic_index_col,
             out.layout.draw_index_col}) {
        AddConstraint(
            out.cs,
            "stage3.p2tx.event.tag_stable",
            aq::AirKind::kTransition, 3,
            [active_col, start_col, tag_col](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>& next) {
                return gf::Mul(
                    next[active_col],
                    gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            next[start_col]),
                        gf::Sub(
                            next[tag_col],
                            cur[tag_col])));
            });
    }

    const uint32_t z1_selector =
        out.layout.z1_terminal_col;
    const uint32_t z2_selector =
        out.layout.z2_terminal_col;
    // Both OOD windows use the same row-local zero and selection columns.
    for (uint32_t candidate = 0;
         candidate < kOodCandidates;
         ++candidate) {
        const pa::Layout poseidon =
            out.layout.candidate[candidate];
        for (uint32_t ext = 0; ext < 2; ++ext) {
            const uint32_t lane = ext + 1;
            const uint32_t zero =
                out.layout.ZeroCol(candidate, ext);
            const uint32_t inverse =
                out.layout.InverseCol(candidate, ext);
            AddConstraint(
                out.cs,
                "stage3.p2tx.ood.zero_boolean",
                aq::AirKind::kEverywhere, 3,
                [z1_selector, z2_selector, zero](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        gf::Add(
                            cur[z1_selector],
                            cur[z2_selector]),
                        gf::Mul(
                            cur[zero],
                            gf::Sub(
                                cur[zero],
                                Fp3::One())));
                });
            AddConstraint(
                out.cs,
                "stage3.p2tx.ood.zero_sound",
                aq::AirKind::kEverywhere, 3,
                [poseidon, z1_selector,
                 z2_selector, zero, lane](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        gf::Add(
                            cur[z1_selector],
                            cur[z2_selector]),
                        gf::Mul(
                            ar::PermOutputLane(
                                poseidon.perm,
                                cur, lane),
                            cur[zero]));
                });
            AddConstraint(
                out.cs,
                "stage3.p2tx.ood.nonzero_inverse",
                aq::AirKind::kEverywhere, 3,
                [poseidon, z1_selector,
                 z2_selector, zero, inverse, lane](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        gf::Add(
                            cur[z1_selector],
                            cur[z2_selector]),
                        gf::Sub(
                            gf::Mul(
                                ar::PermOutputLane(
                                    poseidon.perm,
                                    cur, lane),
                                cur[inverse]),
                            gf::Sub(
                                Fp3::One(),
                                cur[zero])));
                });
        }
        const uint32_t accept =
            out.layout.ExtAcceptCol(candidate);
        const uint32_t zc1 =
            out.layout.ZeroCol(candidate, 0);
        const uint32_t zc2 =
            out.layout.ZeroCol(candidate, 1);
        AddConstraint(
            out.cs,
            "stage3.p2tx.ood.ext_accept_definition",
            aq::AirKind::kEverywhere, 3,
            [z1_selector, z2_selector,
             accept, zc1, zc2](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    gf::Add(
                        cur[z1_selector],
                        cur[z2_selector]),
                    gf::Sub(
                        cur[accept],
                        gf::Sub(
                            Fp3::One(),
                            gf::Mul(
                                cur[zc1],
                                cur[zc2]))));
            });

        // z2 candidate equality to z1 is a three-coordinate zero test.
        for (uint32_t coord = 0;
             coord < 3;
             ++coord) {
            const uint32_t zero =
                out.layout.DiffZeroCol(
                    candidate, coord);
            const uint32_t inverse =
                out.layout.DiffInverseCol(
                    candidate, coord);
            const uint32_t memory =
                out.layout.Z1MemoryCol(coord);
            AddConstraint(
                out.cs,
                "stage3.p2tx.z2.diff_zero_boolean",
                aq::AirKind::kEverywhere, 3,
                [z2_selector, zero](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        cur[z2_selector],
                        gf::Mul(
                            cur[zero],
                            gf::Sub(
                                cur[zero],
                                Fp3::One())));
                });
            AddConstraint(
                out.cs,
                "stage3.p2tx.z2.diff_zero_sound",
                aq::AirKind::kEverywhere, 3,
                [poseidon, z2_selector,
                 zero, memory, coord](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    const Fp3 diff = gf::Sub(
                        ar::PermOutputLane(
                            poseidon.perm,
                            cur, coord),
                        cur[memory]);
                    return gf::Mul(
                        cur[z2_selector],
                        gf::Mul(diff, cur[zero]));
                });
            AddConstraint(
                out.cs,
                "stage3.p2tx.z2.diff_nonzero_inverse",
                aq::AirKind::kEverywhere, 3,
                [poseidon, z2_selector,
                 zero, inverse, memory, coord](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    const Fp3 diff = gf::Sub(
                        ar::PermOutputLane(
                            poseidon.perm,
                            cur, coord),
                        cur[memory]);
                    return gf::Mul(
                        cur[z2_selector],
                        gf::Sub(
                            gf::Mul(
                                diff, cur[inverse]),
                            gf::Sub(
                                Fp3::One(),
                                cur[zero])));
                });
        }
        const uint32_t and01 =
            out.layout.DiffAndCol(candidate, 0);
        const uint32_t equal =
            out.layout.DiffAndCol(candidate, 1);
        const uint32_t d0 =
            out.layout.DiffZeroCol(candidate, 0);
        const uint32_t d1 =
            out.layout.DiffZeroCol(candidate, 1);
        const uint32_t d2 =
            out.layout.DiffZeroCol(candidate, 2);
        const uint32_t distinct =
            out.layout.DistinctCol(candidate);
        AddConstraint(
            out.cs,
            "stage3.p2tx.z2.equal_and01",
            aq::AirKind::kEverywhere, 3,
            [z2_selector, and01, d0, d1](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[z2_selector],
                    gf::Sub(
                        cur[and01],
                        gf::Mul(cur[d0], cur[d1])));
            });
        AddConstraint(
            out.cs,
            "stage3.p2tx.z2.equal_all",
            aq::AirKind::kEverywhere, 3,
            [z2_selector, equal, and01, d2](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[z2_selector],
                    gf::Sub(
                        cur[equal],
                        gf::Mul(
                            cur[and01], cur[d2])));
            });
        AddConstraint(
            out.cs,
            "stage3.p2tx.z2.distinct_definition",
            aq::AirKind::kEverywhere, 2,
            [z2_selector, distinct, equal](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[z2_selector],
                    gf::Sub(
                        cur[distinct],
                        gf::Sub(
                            Fp3::One(),
                            cur[equal])));
            });
        const uint32_t eligible =
            out.layout.EligibleCol(candidate);
        AddConstraint(
            out.cs,
            "stage3.p2tx.z1.eligible_definition",
            aq::AirKind::kEverywhere, 2,
            [z1_selector, eligible, accept](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[z1_selector],
                    gf::Sub(
                        cur[eligible],
                        cur[accept]));
            });
        AddConstraint(
            out.cs,
            "stage3.p2tx.z2.eligible_definition",
            aq::AirKind::kEverywhere, 3,
            [z2_selector, eligible,
             accept, distinct](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[z2_selector],
                    gf::Sub(
                        cur[eligible],
                        gf::Mul(
                            cur[accept],
                            cur[distinct])));
            });
    }

    for (uint32_t z_slot = 0;
         z_slot < 2;
         ++z_slot) {
        const uint32_t selector =
            z_slot == 0
                ? z1_selector
                : z2_selector;
        const uint32_t a0 =
            out.layout.EligibleCol(0);
        const uint32_t a1 =
            out.layout.EligibleCol(1);
        AddConstraint(
            out.cs,
            "stage3.p2tx.ood.window_nonempty",
            aq::AirKind::kEverywhere, 3,
            [selector, a0, a1](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[selector],
                    gf::Mul(
                        gf::Sub(
                            Fp3::One(), cur[a0]),
                        gf::Sub(
                            Fp3::One(), cur[a1])));
            });
        for (uint32_t coord = 0;
             coord < 3;
             ++coord) {
            const uint32_t selected =
                out.layout.SelectedCol(
                    z_slot, coord);
            const pa::Layout p0 =
                out.layout.candidate[0];
            const pa::Layout p1 =
                out.layout.candidate[1];
            AddConstraint(
                out.cs,
                "stage3.p2tx.ood.first_acceptable",
                aq::AirKind::kEverywhere, 3,
                [selector, a0, selected,
                 p0, p1, coord](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    const Fp3 want = gf::Add(
                        gf::Mul(
                            cur[a0],
                            ar::PermOutputLane(
                                p0.perm,
                                cur, coord)),
                        gf::Mul(
                            gf::Sub(
                                Fp3::One(), cur[a0]),
                            ar::PermOutputLane(
                                p1.perm,
                                cur, coord)));
                    return gf::Mul(
                        cur[selector],
                        gf::Sub(
                            cur[selected], want));
                });
            const Fp3 public_value =
                Coord(
                    z_slot == 0
                        ? out.selected_z1
                        : out.selected_z2,
                    coord);
            AddConstraint(
                out.cs,
                "stage3.p2tx.ood.selected_public_pin",
                aq::AirKind::kEverywhere, 2,
                [selector, selected,
                 public_value](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        cur[selector],
                        gf::Sub(
                            cur[selected],
                            public_value));
                });
        }
    }

    // z1 is introduced exactly once, then carried into the z2 event.
    for (uint32_t coord = 0;
         coord < 3;
         ++coord) {
        const uint32_t memory =
            out.layout.Z1MemoryCol(coord);
        const uint32_t selected =
            out.layout.SelectedCol(0, coord);
        AddConstraint(
            out.cs,
            "stage3.p2tx.z1_memory.first_zero",
            aq::AirKind::kFirstRow, 1,
            [memory](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return cur[memory];
            });
        AddConstraint(
            out.cs,
            "stage3.p2tx.z1_memory.selected",
            aq::AirKind::kEverywhere, 2,
            [z1_selector, memory, selected](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[z1_selector],
                    gf::Sub(
                        cur[memory],
                        cur[selected]));
            });
        AddConstraint(
            out.cs,
            "stage3.p2tx.z1_memory.carry",
            aq::AirKind::kTransition, 2,
            [z1_selector, memory, selected](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>& next) {
                const Fp3 want = gf::Add(
                    gf::Mul(
                        next[z1_selector],
                        next[selected]),
                    gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            next[z1_selector]),
                        cur[memory]));
                return gf::Sub(
                    next[memory], want);
            });
    }

    // Query c0 is a canonical 64-bit Goldilocks representative; the query
    // index is its exact low log2(modulus) bits.
    const uint32_t query_selector =
        out.layout.query_terminal_col;
    std::array<Fp3, 64> pow2{};
    pow2[0] = Fp3::One();
    for (uint32_t bit = 1; bit < 64; ++bit) {
        pow2[bit] = gf::Add(
            pow2[bit - 1], pow2[bit - 1]);
    }
    for (uint32_t bit = 0; bit < 64; ++bit) {
        const uint32_t column =
            out.layout.QueryBitCol(bit);
        AddConstraint(
            out.cs,
            "stage3.p2tx.query.bit_boolean",
            aq::AirKind::kEverywhere, 3,
            [query_selector, column](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[query_selector],
                    gf::Mul(
                        cur[column],
                        gf::Sub(
                            cur[column],
                            Fp3::One())));
            });
    }
    const pa::Layout query_poseidon =
        out.layout.candidate[0];
    AddConstraint(
        out.cs,
        "stage3.p2tx.query.canonical_decomposition",
        aq::AirKind::kEverywhere, 2,
        [query_selector, query_poseidon,
         layout = out.layout, pow2](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            Fp3 sum = Fp3::Zero();
            for (uint32_t bit = 0;
                 bit < 64;
                 ++bit) {
                sum = gf::Add(
                    sum,
                    gf::Mul(
                        pow2[bit],
                        cur[layout.QueryBitCol(bit)]));
            }
            return gf::Mul(
                cur[query_selector],
                gf::Sub(
                    ar::PermOutputLane(
                        query_poseidon.perm,
                        cur, 0),
                    sum));
        });
    for (uint32_t stage = 0;
         stage < 32;
         ++stage) {
        const uint32_t column =
            out.layout.QueryHighAndCol(stage);
        const uint32_t bit =
            out.layout.QueryBitCol(32 + stage);
        if (stage == 0) {
            AddConstraint(
                out.cs,
                "stage3.p2tx.query.high_and_first",
                aq::AirKind::kEverywhere, 2,
                [query_selector, column, bit](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        cur[query_selector],
                        gf::Sub(
                            cur[column],
                            cur[bit]));
                });
        } else {
            const uint32_t previous =
                out.layout.QueryHighAndCol(stage - 1);
            AddConstraint(
                out.cs,
                "stage3.p2tx.query.high_and_step",
                aq::AirKind::kEverywhere, 3,
                [query_selector, column,
                 previous, bit](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        cur[query_selector],
                        gf::Sub(
                            cur[column],
                            gf::Mul(
                                cur[previous],
                                cur[bit])));
                });
        }
    }
    const uint32_t low_zero =
        out.layout.query_low_zero_col;
    const uint32_t low_inverse =
        out.layout.query_low_inverse_col;
    AddConstraint(
        out.cs,
        "stage3.p2tx.query.low_zero_boolean",
        aq::AirKind::kEverywhere, 3,
        [query_selector, low_zero](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return gf::Mul(
                cur[query_selector],
                gf::Mul(
                    cur[low_zero],
                    gf::Sub(
                        cur[low_zero],
                        Fp3::One())));
        });
    AddConstraint(
        out.cs,
        "stage3.p2tx.query.low_zero_sound",
        aq::AirKind::kEverywhere, 3,
        [query_selector, low_zero,
         layout = out.layout, pow2](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            Fp3 low = Fp3::Zero();
            for (uint32_t bit = 0; bit < 32; ++bit) {
                low = gf::Add(
                    low,
                    gf::Mul(
                        pow2[bit],
                        cur[layout.QueryBitCol(bit)]));
            }
            return gf::Mul(
                cur[query_selector],
                gf::Mul(low, cur[low_zero]));
        });
    AddConstraint(
        out.cs,
        "stage3.p2tx.query.low_nonzero_inverse",
        aq::AirKind::kEverywhere, 3,
        [query_selector, low_zero,
         low_inverse, layout = out.layout, pow2](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            Fp3 low = Fp3::Zero();
            for (uint32_t bit = 0; bit < 32; ++bit) {
                low = gf::Add(
                    low,
                    gf::Mul(
                        pow2[bit],
                        cur[layout.QueryBitCol(bit)]));
            }
            return gf::Mul(
                cur[query_selector],
                gf::Sub(
                    gf::Mul(
                        low,
                        cur[low_inverse]),
                    gf::Sub(
                        Fp3::One(),
                        cur[low_zero])));
        });
    AddConstraint(
        out.cs,
        "stage3.p2tx.query.goldilocks_canonical",
        aq::AirKind::kEverywhere, 3,
        [query_selector, low_zero,
         high_all =
             out.layout.QueryHighAndCol(31)](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            // Values >= p are precisely high32=0xffffffff and low32!=0.
            return gf::Mul(
                cur[query_selector],
                gf::Mul(
                    cur[high_all],
                    gf::Sub(
                        Fp3::One(),
                        cur[low_zero])));
        });
    uint32_t query_bits = 0;
    for (uint32_t modulus = statement.query_modulus;
         modulus > 1;
         modulus >>= 1) {
        ++query_bits;
    }
    AddConstraint(
        out.cs,
        "stage3.p2tx.query.index_projection",
        aq::AirKind::kEverywhere, 2,
        [query_selector,
         query_index_col =
             out.layout.query_index_col,
         query_bits, layout = out.layout, pow2](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            Fp3 index = Fp3::Zero();
            for (uint32_t bit = 0;
                 bit < query_bits;
                 ++bit) {
                index = gf::Add(
                    index,
                    gf::Mul(
                        pow2[bit],
                        cur[layout.QueryBitCol(bit)]));
            }
            return gf::Mul(
                cur[query_selector],
                gf::Sub(
                    cur[query_index_col],
                    index));
        });

    // Canonicalize every row-local auxiliary outside its tagged row.
    std::vector<uint32_t> z_aux;
    for (uint32_t column = out.layout.zero_base;
         column < out.layout.z1_memory_base;
         ++column) {
        z_aux.push_back(column);
    }
    for (uint32_t column = out.layout.diff_zero_base;
         column < out.layout.query_bit_base;
         ++column) {
        z_aux.push_back(column);
    }
    for (const uint32_t column : z_aux) {
        AddConstraint(
            out.cs,
            "stage3.p2tx.ood.aux_inactive_zero",
            aq::AirKind::kEverywhere, 2,
            [z1_selector, z2_selector, column](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        gf::Add(
                            cur[z1_selector],
                            cur[z2_selector])),
                    cur[column]);
            });
    }
    for (uint32_t column = out.layout.query_bit_base;
         column < out.layout.End();
         ++column) {
        AddConstraint(
            out.cs,
            "stage3.p2tx.query.aux_inactive_zero",
            aq::AirKind::kEverywhere, 2,
            [query_selector, column](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Mul(
                    gf::Sub(
                        Fp3::One(),
                        cur[query_selector]),
                    cur[column]);
            });
    }

    // Padding inputs are canonical zero; fixed Poseidon constraints determine
    // every other padding witness cell.
    for (uint32_t candidate = 0;
         candidate < kOodCandidates;
         ++candidate) {
        for (uint32_t lane = 0;
             lane < ah::kAlgHashT;
             ++lane) {
            const uint32_t input =
                out.layout.candidate[candidate]
                    .perm.InputCol(lane);
            AddConstraint(
                out.cs,
                "stage3.p2tx.padding.input_zero",
                aq::AirKind::kEverywhere, 2,
                [active_col, input](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            cur[active_col]),
                        cur[input]);
                });
        }
    }

    bool preprocessed_ok =
        out.cs.preprocessed_pin_ood &&
        out.cs.preprocessed.size() ==
            preprocessed_columns.size();
    for (size_t i = 0;
         preprocessed_ok &&
         i < preprocessed_columns.size();
         ++i) {
        const uint32_t expected =
            preprocessed_columns[i];
        const auto& entry = out.cs.preprocessed[i];
        preprocessed_ok =
            entry.first == expected &&
            entry.second.size() == n_rows &&
            out.columns[expected].size() == n_rows;
        for (uint32_t row = 0;
             preprocessed_ok && row < n_rows;
             ++row) {
            preprocessed_ok = gf::Eq(
                entry.second[row],
                out.columns[expected][row]);
        }
    }
    out.absorb_lanes_preprocessed_pinned =
        preprocessed_ok;
    out.poseidon_permutations_constrained =
        CountConstraintsNamed(
            out.cs, "stage3.poseidon.sbox.x2") ==
                2 * ar::kPermSboxCells &&
        CountConstraintsNamed(
            out.cs, "stage3.poseidon.sbox.x4") ==
                2 * ar::kPermSboxCells &&
        CountConstraintsNamed(
            out.cs, "stage3.poseidon.sbox.x6") ==
                2 * ar::kPermSboxCells &&
        CountConstraintsNamed(
            out.cs, "stage3.poseidon.sbox.output") ==
                2 * ar::kPermSboxCells;
    out.sponge_state_chain_constrained =
        CountConstraintsNamed(
            out.cs,
            "stage3.p2tx.event.first_absorb") ==
                2 * ah::kAlgHashRate &&
        CountConstraintsNamed(
            out.cs,
            "stage3.p2tx.event.first_capacity") ==
                2 *
                (ah::kAlgHashT -
                 ah::kAlgHashRate) &&
        CountConstraintsNamed(
            out.cs,
            "stage3.p2tx.event.absorb_chain") ==
                2 * ah::kAlgHashRate &&
        CountConstraintsNamed(
            out.cs,
            "stage3.p2tx.event.capacity_chain") ==
                2 *
                (ah::kAlgHashT -
                 ah::kAlgHashRate);
    out.all_event_challenges_constrained =
        out.event_challenges.size() ==
            out.manifest.size() &&
        out.exact_p2_absorb_lanes &&
        out.poseidon_permutations_constrained &&
        out.sponge_state_chain_constrained;
    out.z1_k2_selection_constrained =
        CountConstraintsNamed(
            out.cs,
            "stage3.p2tx.z1.eligible_definition") == 2 &&
        CountConstraintsNamed(
            out.cs,
            "stage3.p2tx.ood.first_acceptable") == 6 &&
        CountConstraintsNamed(
            out.cs,
            "stage3.p2tx.ood.window_nonempty") == 2;
    out.z2_k2_distinct_selection_constrained =
        CountConstraintsNamed(
            out.cs,
            "stage3.p2tx.z2.diff_zero_boolean") == 6 &&
        CountConstraintsNamed(
            out.cs,
            "stage3.p2tx.z2.diff_zero_sound") == 6 &&
        CountConstraintsNamed(
            out.cs,
            "stage3.p2tx.z2.diff_nonzero_inverse") == 6 &&
        CountConstraintsNamed(
            out.cs,
            "stage3.p2tx.z2.eligible_definition") == 2 &&
        !gf::Eq(out.selected_z1, out.selected_z2);
    out.selected_values_publicly_pinned =
        CountConstraintsNamed(
            out.cs,
            "stage3.p2tx.ood.selected_public_pin") == 6;
    out.all_query_indices_constrained =
        out.query_indices.size() == kQueries &&
        CountConstraintsNamed(
            out.cs,
            "stage3.p2tx.query.bit_boolean") == 64 &&
        CountConstraintsNamed(
            out.cs,
            "stage3.p2tx.query.canonical_decomposition") == 1 &&
        CountConstraintsNamed(
            out.cs,
            "stage3.p2tx.query.goldilocks_canonical") == 1 &&
        CountConstraintsNamed(
            out.cs,
            "stage3.p2tx.query.index_projection") == 1;

    // Deliberately fail closed at every integration seam not implemented by
    // this local transcript program.
    out.proof_owned_source_cells_bound = false;
    out.recursive_consumer_cells_bound = false;
    out.recursive_authority = false;

    out.n_constraints =
        static_cast<uint32_t>(
            out.cs.constraints.size());
    out.max_alg_degree =
        ConstraintMaxDegree(out.cs);
    out.violations =
        CountViolations(out.cs, out.columns);
    out.local_air_complete =
        out.canonical_parameters &&
        out.prefix_free_v10_statement &&
        out.canonical_event_manifest &&
        out.exact_p2_absorb_lanes &&
        out.all_event_challenges_constrained &&
        out.all_query_indices_constrained &&
        out.absorb_lanes_preprocessed_pinned &&
        out.poseidon_permutations_constrained &&
        out.sponge_state_chain_constrained &&
        out.z1_k2_selection_constrained &&
        out.z2_k2_distinct_selection_constrained &&
        out.selected_values_publicly_pinned &&
        out.violations == 0;
    out.valid =
        out.local_air_complete &&
        !out.proof_owned_source_cells_bound &&
        !out.recursive_consumer_cells_bound &&
        !out.recursive_authority;
    out.note = out.valid
        ? "stage3:p2_transcript_air:"
          "v10_q192_k2_all_events_local_air_complete;"
          "proof_source_consumer_recursion_open"
        : "stage3:p2_transcript_air:"
          "all_events_local_air_invalid";
    return out;
}

BuildResult BuildTranscriptAirV10(
    const Statement& statement)
{
    return BuildTranscriptAirV10At(statement, 0, 0);
}

bool AppendTranscriptAirV10ToParent(
    aq::AirConstraintSystem<Fp3>& parent_cs,
    std::vector<std::vector<Fp3>>& parent_columns,
    const Statement& statement,
    BuildResult& transcript,
    std::string* why)
{
    if (parent_cs.n_rows < 2 ||
        (parent_cs.n_rows & (parent_cs.n_rows - 1)) != 0 ||
        parent_columns.size() != parent_cs.n_columns) {
        return Fail(why, "append_parent_shape");
    }
    for (const auto& column : parent_columns) {
        if (column.size() != parent_cs.n_rows) {
            return Fail(why, "append_parent_column_rows");
        }
    }
    const uint32_t base = parent_cs.n_columns;
    BuildResult local = BuildTranscriptAirV10At(
        statement, base, parent_cs.n_rows);
    if (!local.valid ||
        local.cs.n_rows != parent_cs.n_rows ||
        local.layout.candidate[0].perm.base != base ||
        local.columns.size() != local.cs.n_columns ||
        local.cs.n_columns <= base) {
        return Fail(why, "append_transcript_build");
    }
    parent_columns.reserve(local.cs.n_columns);
    for (uint32_t column = base;
         column < local.cs.n_columns; ++column) {
        parent_columns.push_back(
            local.columns[column]);
    }
    parent_cs.n_columns = local.cs.n_columns;
    parent_cs.constraints.insert(
        parent_cs.constraints.end(),
        local.cs.constraints.begin(),
        local.cs.constraints.end());
    parent_cs.preprocessed.insert(
        parent_cs.preprocessed.end(),
        local.cs.preprocessed.begin(),
        local.cs.preprocessed.end());
    parent_cs.preprocessed_pin_ood =
        parent_cs.preprocessed_pin_ood ||
        local.cs.preprocessed_pin_ood;
    transcript = std::move(local);
    if (why != nullptr) {
        *why =
            "stage3:p2_transcript_air:"
            "same_parent_append_ok";
    }
    return true;
}

uint32_t CountViolations(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (cs.n_rows < 2 ||
        columns.size() != cs.n_columns) {
        return 1;
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) return 1;
    }
    std::vector<Fp3> cur(cs.n_columns);
    std::vector<Fp3> next(cs.n_columns);
    uint32_t violations = 0;
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        const uint32_t next_row =
            row + 1 < cs.n_rows ? row + 1 : row;
        for (uint32_t column = 0;
             column < cs.n_columns;
             ++column) {
            cur[column] = columns[column][row];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint : cs.constraints) {
            if (constraint.kind == aq::AirKind::kTransition &&
                row + 1 == cs.n_rows) {
                continue;
            }
            if (constraint.kind == aq::AirKind::kFirstRow &&
                row != 0) {
                continue;
            }
            if (constraint.kind == aq::AirKind::kLastRow &&
                row + 1 != cs.n_rows) {
                continue;
            }
            if (!gf::IsZero(
                    constraint.eval(cur, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

} // namespace matmul::v4::rc::stage3_p2_transcript_air
