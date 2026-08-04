// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_v5_v6_bus.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <numeric>
#include <string>
#include <vector>

namespace ah = matmul::v4::rc::alg_hash;
namespace aq = matmul::v4::rc::air_quotient;
namespace ar = matmul::v4::rc::air_recurse;
namespace bus = matmul::v4::rc::stage3_v5_v6_bus;
namespace gf = matmul::v4::rc::gkr_field;
namespace v6 = matmul::v4::rc::stage3_v6_fs;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_v5_v6_bus_tests,
                         BasicTestingSetup)

namespace {

using DualB3 = aq::AirFriBackendAlgDual<gf::Fp3>;
using ParentB3 = aq::AirFriBackendAlg<gf::Fp3>;

aq::AirConstraintSystem<gf::Fp3> ToyChildCS()
{
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 2;
    cs.n_columns = 1;
    aq::AirConstraint<gf::Fp3> boolean;
    boolean.name = "v5_v6.toy.boolean";
    boolean.kind = aq::AirKind::kEverywhere;
    boolean.alg_degree = 2;
    boolean.eval = [](
                       const std::vector<gf::Fp3>& cur,
                       const std::vector<gf::Fp3>&) {
        return gf::Mul(
            cur[0], gf::Sub(cur[0], gf::Fp3::One()));
    };
    cs.constraints.push_back(std::move(boolean));
    return cs;
}

aq::AirConstraintSystem<gf::Fp3> WideBooleanChildCS(uint32_t width)
{
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 2;
    cs.n_columns = width;
    for (uint32_t column = 0; column < width; ++column) {
        aq::AirConstraint<gf::Fp3> boolean;
        boolean.name = "v5_v6.wide.boolean";
        boolean.kind = aq::AirKind::kEverywhere;
        boolean.alg_degree = 2;
        boolean.eval = [column](
                           const std::vector<gf::Fp3>& cur,
                           const std::vector<gf::Fp3>&) {
            return gf::Mul(
                cur[column],
                gf::Sub(cur[column], gf::Fp3::One()));
        };
        cs.constraints.push_back(std::move(boolean));
    }
    return cs;
}

uint256 Seed(uint8_t first)
{
    uint256 out;
    for (uint32_t i = 0; i < 32; ++i) {
        out.begin()[i] = static_cast<uint8_t>(first + i);
    }
    return out;
}

std::array<uint8_t, 32> PublicBoundary()
{
    std::array<uint8_t, 32> out{};
    for (uint32_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>(3 * i + 7);
    }
    return out;
}

ar::VerifierAirFamilies RowRootFamilies()
{
    ar::VerifierAirFamilies families;
    families.row_merkle = true;
    families.fold = false;
    families.deep = false;
    families.per_point = false;
    families.next_row = false;
    families.trace_binding = false;
    return families;
}

ar::DualAlgAirProof ToyDualProof(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const uint256& seed)
{
    const std::vector<std::vector<gf::Fp3>> columns{{
        gf::Fp3::Zero(), gf::Fp3::One()}};
    const auto proved = aq::AirQuotientProve<gf::Fp3, DualB3>(
        cs, columns, seed, {});
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact, proved.note);
    return proved.proof;
}

size_t ProofBytes(
    const aq::AirQuotientProof<gf::Fp3, ParentB3>& proof)
{
    std::vector<unsigned char> encoded;
    size_t bytes =
        matmul::v4::rc::SerializeFri3AlgBatchProof(
            proof.batch, encoded);
    bytes += 32;
    bytes += 4;
    for (const auto& query : proof.next_openings) {
        bytes += 4;
        for (const auto& path : query) {
            bytes += 4;
            bytes += 4 + path.values.size() * 3 * sizeof(uint64_t);
            bytes +=
                4 + path.siblings.size() *
                    ah::kAlgHashDigestLen * sizeof(uint64_t);
        }
    }
    return bytes;
}

size_t ProofBytes(
    const aq::AirQuotientProof<gf::Fp3>& proof)
{
    std::vector<unsigned char> encoded;
    size_t bytes =
        matmul::v4::rc::SerializeFri3BatchProof(
            proof.batch, encoded);
    bytes += 32 + 4;
    for (const auto& query : proof.next_openings) {
        bytes += 4;
        for (const auto& path : query) {
            bytes += 4 + 3 * sizeof(uint64_t) + 4;
            bytes += path.siblings.size() * 32;
        }
    }
    return bytes;
}

[[maybe_unused]] size_t ProofBytes(
    const aq::AirQuotientRowsProof& proof)
{
    std::vector<unsigned char> encoded;
    size_t bytes =
        matmul::v4::rc::SerializeFri3AlgBatchProof(
            proof.batch, encoded);
    bytes += 32 + 4;
    for (const auto& query : proof.next_openings) {
        bytes += 4;
        for (const auto& path : query) {
            bytes += 8;
            bytes += path.values.size() *
                3 * sizeof(uint64_t);
            bytes += path.siblings.size() *
                ah::kAlgHashDigestLen *
                sizeof(uint64_t);
        }
    }
    return bytes;
}

std::vector<v6::PayloadCell> ProofCells(const v6::Program& program)
{
    std::vector<v6::PayloadCell> out;
    std::copy_if(
        program.payload_cells.begin(), program.payload_cells.end(),
        std::back_inserter(out),
        [](const v6::PayloadCell& cell) {
            return cell.origin == v6::WordOrigin::ProofDerived;
        });
    return out;
}

bool HasViolationAtRow(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns,
    uint32_t row)
{
    if (columns.size() != cs.n_columns ||
        row >= cs.n_rows) {
        return true;
    }
    std::vector<gf::Fp3> cur(cs.n_columns);
    std::vector<gf::Fp3> next(cs.n_columns);
    for (uint32_t column = 0; column < cs.n_columns; ++column) {
        if (columns[column].size() != cs.n_rows) return true;
        cur[column] = columns[column][row];
        next[column] =
            columns[column][(row + 1) % cs.n_rows];
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
            return true;
        }
    }
    return false;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    normalized_v5_exports_are_literal_v6_sources_and_mutation_closed)
{
    const auto child_cs = ToyChildCS();
    const uint256 child_seed = Seed(21);
    const auto child = ToyDualProof(child_cs, child_seed);

    const bus::SameTraceComposition honest =
        bus::BuildSameTraceComposition(
            child_cs, child, child_seed, PublicBoundary(),
            bus::TranscriptScope::MasterBinding, {});
    BOOST_REQUIRE_MESSAGE(honest.valid, honest.note);
    BOOST_CHECK(honest.native_v5_verified);
    BOOST_CHECK(honest.finite_v5_transcript_replayed_on_host);
    BOOST_CHECK(honest.export_bus_constrained_in_air);
    BOOST_CHECK(honest.literal_v6_alias);
    BOOST_CHECK(!honest.v6_challenges_drive_v5_equations);
    BOOST_CHECK(!honest.sha_public_boundary_in_air);
    BOOST_CHECK(!honest.production_authority_ready);
    BOOST_CHECK_EQUAL(honest.original_v5_rows, 128U);
    BOOST_CHECK_EQUAL(honest.aligned_rows, 128U);
    BOOST_CHECK_EQUAL(honest.program.trace_rows, 128U);
    BOOST_CHECK_EQUAL(honest.proof_derived_payload_cells, 8U);
    BOOST_CHECK_EQUAL(
        honest.row_root_payload_cells_directly_aliased, 8U);
    BOOST_CHECK_EQUAL(
        honest.transcript_layout.external_source_base,
        honest.export_base);
    BOOST_CHECK_EQUAL(
        v6::CountViolations(
            honest.combined, honest.combined_columns),
        0U);
    BOOST_TEST_MESSAGE(
        "full-family normalized V5->V6 root bus: rows="
        << honest.aligned_rows
        << " v5_cols=" << honest.original_v5_columns
        << " combined_cols=" << honest.combined_columns_count
        << " constraints=" << honest.combined_constraints
        << " payload_cells="
        << honest.row_root_payload_cells_directly_aliased
        << " witness_us=" << honest.witness_build_micros
        << " scan_us=" << honest.constraint_scan_micros);

    const auto proof_cells = ProofCells(honest.program);
    BOOST_REQUIRE_EQUAL(proof_cells.size(), 8U);
    const auto& cell = proof_cells.front();

    // V6-only source mutation: literal source/export equality breaks.
    auto source_only = honest.combined_columns;
    source_only[honest.transcript_layout.Source(cell.rate_lane)]
               [cell.trace_row] =
        gf::Add(
            source_only[
                honest.transcript_layout.Source(cell.rate_lane)]
                       [cell.trace_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        v6::CountViolations(honest.combined, source_only), 0U);

    // Synchronized source+export mutation still breaks the proof-derived V5
    // expected-column equality.
    auto synchronized = honest.combined_columns;
    synchronized[
        honest.transcript_layout.Source(cell.rate_lane)]
                [cell.trace_row] =
        gf::Add(
            synchronized[
                honest.transcript_layout.Source(cell.rate_lane)]
                        [cell.trace_row],
            gf::Fp3::One());
    synchronized[honest.export_base + cell.rate_lane]
                [cell.trace_row] =
        gf::Add(
            synchronized[honest.export_base + cell.rate_lane]
                        [cell.trace_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        v6::CountViolations(honest.combined, synchronized), 0U);

    // Find a constrained V5-only cell without relying on private V_CS layout.
    bool found_v5_mutation = false;
    for (uint32_t column = 0;
         column < honest.original_v5_columns &&
         !found_v5_mutation; ++column) {
        auto changed = honest.combined_columns;
        changed[column][0] =
            gf::Add(changed[column][0], gf::Fp3::One());
        found_v5_mutation =
            v6::CountViolations(honest.combined, changed) != 0;
    }
    BOOST_CHECK(found_v5_mutation);

    // Swap two different proof words on both sides. Equality to the ordered
    // proof-derived expected columns preserves neither lane nor word order.
    auto pair = proof_cells.end();
    for (auto it = proof_cells.begin(); it != proof_cells.end(); ++it) {
        pair = std::find_if(
            std::next(it), proof_cells.end(),
            [&](const v6::PayloadCell& other) {
                return other.trace_row == it->trace_row &&
                       other.rate_lane != it->rate_lane &&
                       !gf::Eq(
                           honest.combined_columns[
                               honest.export_base + other.rate_lane]
                               [other.trace_row],
                           honest.combined_columns[
                               honest.export_base + it->rate_lane]
                               [it->trace_row]);
            });
        if (pair != proof_cells.end()) {
            const auto& a = *it;
            const auto& b = *pair;
            auto swapped = honest.combined_columns;
            std::swap(
                swapped[honest.export_base + a.rate_lane][a.trace_row],
                swapped[honest.export_base + b.rate_lane][b.trace_row]);
            std::swap(
                swapped[honest.transcript_layout.Source(a.rate_lane)]
                       [a.trace_row],
                swapped[honest.transcript_layout.Source(b.rate_lane)]
                       [b.trace_row]);
            BOOST_CHECK_GT(
                v6::CountViolations(honest.combined, swapped), 0U);
            break;
        }
    }
    BOOST_REQUIRE(pair != proof_cells.end());

    // Transcript-state mutation is detected independently of the bus.
    auto transcript = honest.combined_columns;
    transcript[honest.transcript_layout.poseidon.perm.base][0] =
        gf::Add(
            transcript[honest.transcript_layout.poseidon.perm.base][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        v6::CountViolations(honest.combined, transcript), 0U);

    // A row-root mutation in the source V5 proof fails before any bus witness
    // can be emitted.
    auto root_mutation = child;
    root_mutation.batch.repeated.lane[0].row_commit.root[0] =
        gf::Add(
            root_mutation.batch.repeated.lane[0]
                .row_commit.root[0],
            gf::Fp{1});
    const auto rejected = bus::BuildSameTraceComposition(
        child_cs, root_mutation, child_seed, PublicBoundary(),
        bus::TranscriptScope::MasterBinding, {});
    BOOST_CHECK(!rejected.valid);

    static_assert(bus::kNormalizedV5EightLaneExportBusExecutable);
    static_assert(bus::kV5V6LiteralSameTraceAliasExecutable);
    static_assert(ar::kDualV5RowRootExportBusInAir);
    static_assert(ar::kDualV5FullTranscriptExportBusInAir);
    static_assert(bus::kV5V6FullTranscriptPayloadBusExecutable);
    static_assert(!bus::kV6ChallengesDriveNormalizedV5Equations);
    static_assert(!bus::kV5ShaTranscriptEquationsInCombinedAir);
    static_assert(!bus::kV5V6CombinedAuthorityReady);
}

BOOST_AUTO_TEST_CASE(
    master_same_trace_combined_quotient_round_trip_and_measurement)
{
    if (std::getenv("BTX_RUN_STAGE3_V5_V6_BUS_PROVE") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_V5_V6_BUS_PROVE=1 for the "
            "292,736-cell combined V5->V6 quotient round trip");
        return;
    }
    const auto child_cs = ToyChildCS();
    const uint256 child_seed = Seed(31);
    const auto child = ToyDualProof(child_cs, child_seed);
    const bus::SameTraceComposition combined =
        bus::BuildSameTraceComposition(
            child_cs, child, child_seed, PublicBoundary(),
            bus::TranscriptScope::MasterBinding,
            RowRootFamilies());
    BOOST_REQUIRE_MESSAGE(combined.valid, combined.note);

    const uint256 parent_seed = Seed(77);
    const auto prove_start = std::chrono::steady_clock::now();
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, ParentB3>(
            combined.combined, combined.combined_columns,
            parent_seed, {});
    const auto prove_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - prove_start)
            .count();
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);

    std::string why;
    const auto verify_start = std::chrono::steady_clock::now();
    const bool accepted =
        aq::AirQuotientVerify<gf::Fp3, ParentB3>(
            combined.combined, proved.proof, parent_seed, &why);
    const auto verify_us =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - verify_start)
            .count();
    BOOST_CHECK_MESSAGE(accepted, why);
    BOOST_TEST_MESSAGE(
        "V5->V6 same-trace master quotient: rows="
        << combined.aligned_rows
        << " v5_cols=" << combined.original_v5_columns
        << " combined_cols=" << combined.combined_columns_count
        << " constraints=" << combined.combined_constraints
        << " cells="
        << static_cast<uint64_t>(combined.aligned_rows) *
               combined.combined_columns_count
        << " proof_bytes=" << ProofBytes(proved.proof)
        << " witness_us=" << combined.witness_build_micros
        << " scan_us=" << combined.constraint_scan_micros
        << " prove_ms=" << prove_ms
        << " verify_us=" << verify_us);
}

BOOST_AUTO_TEST_CASE(
    full_transcript_maps_all_48_payload_cells_to_v5_equation_sources)
{
    const auto child_cs = ToyChildCS();
    const uint256 child_seed = Seed(41);
    const auto child = ToyDualProof(child_cs, child_seed);

    bus::SameTraceComposition full =
        bus::BuildSameTraceComposition(
            child_cs, child, child_seed, PublicBoundary(),
            bus::TranscriptScope::FullTranscript, {});
    BOOST_REQUIRE_MESSAGE(full.valid, full.note);
    BOOST_CHECK_EQUAL(full.original_v5_rows, 128U);
    BOOST_CHECK_GE(full.program.trace_rows, full.original_v5_rows);
    BOOST_CHECK_EQUAL(full.aligned_rows, full.program.trace_rows);
    BOOST_CHECK_EQUAL(full.proof_derived_payload_cells, 48U);
    BOOST_CHECK_EQUAL(
        full.row_root_payload_cells_directly_aliased, 8U);
    BOOST_CHECK_EQUAL(
        full.transcript_payload_cells_directly_aliased, 48U);
    BOOST_CHECK_EQUAL(full.selector_columns, 48U);
    BOOST_REQUIRE_EQUAL(full.payload_mappings.size(), 48U);
    BOOST_CHECK_EQUAL(
        v6::CountViolations(
            full.combined, full.combined_columns),
        0U);

    const bus::ChallengeFeedbackAssessment feedback =
        bus::AssessChallengeFeedback(full);
    BOOST_REQUIRE_MESSAGE(feedback.valid, feedback.note);
    BOOST_CHECK_EQUAL(feedback.required_cells, 304U);
    BOOST_CHECK_EQUAL(
        feedback.structurally_addressable_v6_cells, 304U);
    BOOST_CHECK_EQUAL(
        feedback.direct_same_trace_alias_cells, 0U);
    BOOST_CHECK(!feedback.derivation_domains_equal);
    BOOST_CHECK(feedback.ood_selection_output_in_v6);
    BOOST_CHECK(!feedback.feedback_complete);
    std::array<uint32_t, 7> feedback_counts{};
    for (const auto& cell : feedback.cells) {
        const size_t family =
            static_cast<size_t>(cell.family);
        BOOST_REQUIRE_LT(family, feedback_counts.size());
        ++feedback_counts[family];
        BOOST_CHECK(!cell.direct_same_trace_alias);
    }
    BOOST_CHECK_EQUAL(feedback_counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::AirQuotient)], 6U);
    BOOST_CHECK_EQUAL(feedback_counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::BatchCoefficient)], 12U);
    BOOST_CHECK_EQUAL(feedback_counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::OodPoint)], 12U);
    BOOST_CHECK_EQUAL(feedback_counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::DeepWeight)], 12U);
    BOOST_CHECK_EQUAL(feedback_counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::FoldChallenge)], 6U);
    BOOST_CHECK_EQUAL(feedback_counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::QueryIndex)], 256U);

    const auto ood_output = std::find_if(
        feedback.cells.begin(), feedback.cells.end(),
        [](const bus::ChallengeFeedbackCell& cell) {
            return cell.family ==
                       bus::ChallengeFeedbackFamily::OodPoint &&
                   cell.v6_source_present;
        });
    BOOST_REQUIRE(ood_output != feedback.cells.end());
    auto attacked_ood = full.combined_columns;
    attacked_ood[ood_output->v6_source_column]
                [ood_output->v6_trace_row] =
        gf::Add(
            attacked_ood[ood_output->v6_source_column]
                        [ood_output->v6_trace_row],
            gf::Fp3::One());
    BOOST_CHECK(
        HasViolationAtRow(
            full.combined, attacked_ood,
            ood_output->v6_trace_row) ||
        (ood_output->v6_trace_row > 0 &&
         HasViolationAtRow(
             full.combined, attacked_ood,
             ood_output->v6_trace_row - 1)));

    // The first incompatible V6 query result can be forced to equal its V5
    // SHA-derived index only by violating the V6 sampler equations. This
    // mutation prevents accidental equality from being counted as feedback.
    const auto incompatible_query = std::find_if(
        feedback.cells.begin(), feedback.cells.end(),
        [](const bus::ChallengeFeedbackCell& cell) {
            return cell.family ==
                       bus::ChallengeFeedbackFamily::QueryIndex &&
                   cell.v6_source_present &&
                   !cell.honest_values_equal;
        });
    BOOST_REQUIRE(incompatible_query != feedback.cells.end());
    const gf::Fp3 saved_query =
        full.combined_columns[
            incompatible_query->v6_source_column]
            [incompatible_query->v6_trace_row];
    full.combined_columns[
        incompatible_query->v6_source_column]
        [incompatible_query->v6_trace_row] =
        gf::Fp3::FromFp(gf::FromU64(
            full.lane_pis[incompatible_query->lane]
                .query_index[incompatible_query->item_index]));
    BOOST_CHECK(
        HasViolationAtRow(
            full.combined, full.combined_columns,
            incompatible_query->v6_trace_row));
    const auto forced_feedback =
        bus::AssessChallengeFeedback(full);
    BOOST_REQUIRE(forced_feedback.valid);
    BOOST_CHECK_EQUAL(
        forced_feedback.honest_value_equal_cells,
        feedback.honest_value_equal_cells + 1);
    BOOST_CHECK_EQUAL(
        forced_feedback.direct_same_trace_alias_cells, 0U);
    full.combined_columns[
        incompatible_query->v6_source_column]
        [incompatible_query->v6_trace_row] = saved_query;

    std::array<uint32_t, 6> family_counts{};
    for (const auto& mapping : full.payload_mappings) {
        const size_t family =
            static_cast<size_t>(mapping.source.kind);
        BOOST_REQUIRE_LT(family, family_counts.size());
        ++family_counts[family];
        BOOST_CHECK(mapping.source_is_v5_witness_column);
        BOOST_CHECK(mapping.equation_consumer_present);
        BOOST_CHECK(mapping.same_trace_constrained);
        BOOST_CHECK(mapping.source.equation_consumer != nullptr);
        BOOST_CHECK_EQUAL(
            mapping.export_column,
            full.export_base + mapping.payload.rate_lane);
        BOOST_CHECK_GE(
            mapping.selector_column, full.selector_base);
        BOOST_CHECK_LT(
            mapping.selector_column,
            full.selector_base + full.selector_columns);
    }
    BOOST_CHECK_EQUAL(family_counts[static_cast<size_t>(
        ar::VerifierAirTranscriptOutputKind::RowRoot)], 8U);
    BOOST_CHECK_EQUAL(family_counts[static_cast<size_t>(
        ar::VerifierAirTranscriptOutputKind::TraceRoot)], 8U);
    BOOST_CHECK_EQUAL(family_counts[static_cast<size_t>(
        ar::VerifierAirTranscriptOutputKind::EvaluationZ1)], 12U);
    BOOST_CHECK_EQUAL(family_counts[static_cast<size_t>(
        ar::VerifierAirTranscriptOutputKind::EvaluationZ2)], 12U);
    BOOST_CHECK_EQUAL(family_counts[static_cast<size_t>(
        ar::VerifierAirTranscriptOutputKind::FoldRoot)], 8U);

    // One synchronized source+export attack for every payload family must
    // still disagree with the named V5 terminal/evaluation source.
    for (size_t family = 1; family < family_counts.size(); ++family) {
        const auto it = std::find_if(
            full.payload_mappings.begin(),
            full.payload_mappings.end(),
            [family](const bus::PayloadMapping& mapping) {
                return static_cast<size_t>(
                           mapping.source.kind) == family;
            });
        BOOST_REQUIRE(it != full.payload_mappings.end());
        auto attacked = full.combined_columns;
        attacked[it->export_column][it->payload.trace_row] =
            gf::Add(
                attacked[it->export_column][it->payload.trace_row],
                gf::Fp3::One());
        attacked[
            full.transcript_layout.Source(
                it->payload.rate_lane)]
            [it->payload.trace_row] =
            gf::Add(
                attacked[
                    full.transcript_layout.Source(
                        it->payload.rate_lane)]
                    [it->payload.trace_row],
                gf::Fp3::One());
        gf::Fp3 source_delta = gf::Fp3::One();
        if (it->source.kind ==
                ar::VerifierAirTranscriptOutputKind::EvaluationZ1 ||
            it->source.kind ==
                ar::VerifierAirTranscriptOutputKind::EvaluationZ2) {
            source_delta = gf::Fp3::Zero();
            if (it->source.coordinate == 0)
                source_delta.c0 = 1;
            else if (it->source.coordinate == 1)
                source_delta.c1 = 1;
            else
                source_delta.c2 = 1;
        }
        attacked[it->source.source_column]
                [it->payload.trace_row] =
            gf::Add(
                attacked[it->source.source_column]
                        [it->payload.trace_row],
                source_delta);
        BOOST_CHECK(
            HasViolationAtRow(
                full.combined, attacked,
                it->payload.trace_row));
    }

    // Ordered-lane attack: synchronously swap two distinct row-root payload
    // words on the V6 and export sides. V5 terminal aliases preserve order.
    auto lane0 = full.payload_mappings.end();
    auto lane1 = full.payload_mappings.end();
    for (auto first = full.payload_mappings.begin();
         first != full.payload_mappings.end() &&
         lane0 == full.payload_mappings.end(); ++first) {
        if (first->source.child_index != 0) continue;
        const auto second = std::find_if(
            full.payload_mappings.begin(),
            full.payload_mappings.end(),
            [&](const bus::PayloadMapping& mapping) {
                return mapping.source.child_index == 1 &&
                       mapping.source.kind == first->source.kind &&
                       !gf::Eq(
                           full.combined_columns[
                               first->export_column]
                               [first->payload.trace_row],
                           full.combined_columns[
                               mapping.export_column]
                               [mapping.payload.trace_row]);
            });
        if (second != full.payload_mappings.end()) {
            lane0 = first;
            lane1 = second;
        }
    }
    BOOST_REQUIRE(lane0 != full.payload_mappings.end());
    BOOST_REQUIRE(lane1 != full.payload_mappings.end());
    auto swapped = full.combined_columns;
    std::swap(
        swapped[lane0->export_column][lane0->payload.trace_row],
        swapped[lane1->export_column][lane1->payload.trace_row]);
    std::swap(
        swapped[full.transcript_layout.Source(
                    lane0->payload.rate_lane)]
               [lane0->payload.trace_row],
        swapped[full.transcript_layout.Source(
                    lane1->payload.rate_lane)]
               [lane1->payload.trace_row]);
    BOOST_CHECK(
        HasViolationAtRow(
            full.combined, swapped,
            lane0->payload.trace_row) ||
        HasViolationAtRow(
            full.combined, swapped,
            lane1->payload.trace_row));

    const bus::Shape shape = bus::MeasureSameTraceComposition(
        full.lane_pis, PublicBoundary(),
        bus::TranscriptScope::FullTranscript, {});
    BOOST_REQUIRE_MESSAGE(shape.valid, shape.note);
    BOOST_CHECK_EQUAL(shape.proof_derived_payload_cells, 48U);
    BOOST_CHECK_EQUAL(
        shape.transcript_payload_cells_directly_aliased, 48U);
    BOOST_CHECK_EQUAL(shape.selector_columns, 48U);
    BOOST_TEST_MESSAGE(
        "V5->V6 full-transcript 48/48 mapping: v5_rows="
        << shape.v5_rows << " v6_rows=" << shape.v6_rows
        << " rows=" << shape.aligned_rows
        << " v5_cols=" << shape.v5_columns
        << " combined_cols=" << shape.combined_columns
        << " constraints=" << shape.combined_constraints
        << " mapped=" << shape.transcript_payload_cells_directly_aliased
        << "/" << shape.proof_derived_payload_cells
        << " fs_feedback="
        << feedback.direct_same_trace_alias_cells
        << "/" << feedback.required_cells
        << " fs_addressable="
        << feedback.structurally_addressable_v6_cells
        << " witness_us=" << full.witness_build_micros
        << " scan_us=" << full.constraint_scan_micros);
}

BOOST_AUTO_TEST_CASE(
    v5_sha_boundary_materializes_all_304_consumer_cells_and_rejects_each_family)
{
    const auto child_cs = ToyChildCS();
    const uint256 child_seed = Seed(47);
    const auto child = ToyDualProof(child_cs, child_seed);
    const bus::SameTraceComposition full =
        bus::BuildSameTraceComposition(
            child_cs, child, child_seed, PublicBoundary(),
            bus::TranscriptScope::FullTranscript, {});
    BOOST_REQUIRE_MESSAGE(full.valid, full.note);

    const bus::V5SemanticMaterialization semantic =
        bus::BuildV5SemanticMaterialization(full);
    BOOST_REQUIRE_MESSAGE(semantic.valid, semantic.note);
    BOOST_CHECK_EQUAL(
        semantic.logical_cells,
        bus::kV5SemanticConsumerCells);
    BOOST_CHECK_EQUAL(
        semantic.trace_rows,
        bus::kV5SemanticConsumerRows);
    BOOST_CHECK_EQUAL(
        semantic.total_columns,
        bus::kV5SemanticConsumerColumns);
    BOOST_CHECK_EQUAL(semantic.proof_owned_columns, 1U);
    BOOST_CHECK_EQUAL(semantic.verifier_fixed_columns, 7U);
    BOOST_CHECK_EQUAL(semantic.width_overhead, 8U);
    BOOST_CHECK_EQUAL(semantic.trace_cell_overhead, 4096U);
    BOOST_CHECK(semantic.under_recursive_column_cap);
    BOOST_CHECK(semantic.verifier_recomputed_sha_boundary);
    BOOST_CHECK(semantic.all_cells_semantically_mapped);
    BOOST_CHECK(semantic.all_cells_air_equality_constrained);
    BOOST_CHECK(!semantic.direct_v6_challenge_feedback);
    BOOST_REQUIRE_EQUAL(
        semantic.cells.size(),
        bus::kV5SemanticConsumerCells);

    std::array<uint32_t, 7> counts{};
    for (uint32_t row = 0; row < semantic.cells.size(); ++row) {
        const auto& cell = semantic.cells[row];
        BOOST_CHECK_EQUAL(cell.semantic_row, row);
        BOOST_CHECK(!cell.direct_v6_challenge_feedback);
        const size_t family =
            static_cast<size_t>(cell.family);
        BOOST_REQUIRE_LT(family, counts.size());
        ++counts[family];
        BOOST_CHECK(gf::Eq(
            semantic.witness_columns[
                bus::kV5SemanticWitness][row],
            gf::Fp3::FromFp(cell.expected_v5_value)));
    }
    BOOST_CHECK_EQUAL(counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::AirQuotient)], 6U);
    BOOST_CHECK_EQUAL(counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::BatchCoefficient)], 12U);
    BOOST_CHECK_EQUAL(counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::OodPoint)], 12U);
    BOOST_CHECK_EQUAL(counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::DeepWeight)], 12U);
    BOOST_CHECK_EQUAL(counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::FoldChallenge)], 6U);
    BOOST_CHECK_EQUAL(counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::QueryIndex)], 256U);

    const auto proved = aq::AirQuotientProve<gf::Fp3>(
        semantic.constraint_system, semantic.witness_columns,
        semantic.air_seed);
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact, proved.note);
    std::string why;
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5SemanticMaterialization(
            full, semantic.public_boundary_commitment,
            proved.proof, &why),
        why);

    uint256 wrong_boundary =
        semantic.public_boundary_commitment;
    wrong_boundary.begin()[0] ^= 1;
    BOOST_CHECK(!bus::VerifyV5SemanticMaterialization(
        full, wrong_boundary, proved.proof, &why));

    for (uint8_t family = static_cast<uint8_t>(
             bus::ChallengeFeedbackFamily::AirQuotient);
         family <= static_cast<uint8_t>(
             bus::ChallengeFeedbackFamily::QueryIndex);
         ++family) {
        const auto it = std::find_if(
            semantic.cells.begin(), semantic.cells.end(),
            [family](
                const bus::V5SemanticConsumerCell& cell) {
                return static_cast<uint8_t>(cell.family) ==
                    family;
            });
        BOOST_REQUIRE(it != semantic.cells.end());
        auto attacked = semantic.witness_columns;
        attacked[bus::kV5SemanticWitness]
                [it->semantic_row] =
            gf::Add(
                attacked[bus::kV5SemanticWitness]
                        [it->semantic_row],
                gf::Fp3::One());
        BOOST_CHECK_GT(
            v6::CountViolations(
                semantic.constraint_system, attacked),
            0U);
        const auto rejected = aq::AirQuotientProve<gf::Fp3>(
            semantic.constraint_system, attacked,
            semantic.air_seed);
        BOOST_CHECK(
            !rejected.ok || !rejected.division_exact);
    }

    BOOST_TEST_MESSAGE(
        "V5 SHA semantic boundary: logical_cells="
        << semantic.logical_cells
        << " rows=" << semantic.trace_rows
        << " width_overhead=" << semantic.width_overhead
        << " trace_cells=" << semantic.trace_cell_overhead
        << " recursive_cap="
        << bus::kStage3RecursiveColumnCap
        << " direct_v6_feedback="
        << semantic.direct_v6_challenge_feedback);
}

BOOST_AUTO_TEST_CASE(
    normalized_feedback_receipt_binds_all_304_cells_and_fails_closed_on_domain_mismatch)
{
    const auto child_cs = ToyChildCS();
    const uint256 child_seed = Seed(46);
    const auto child = ToyDualProof(child_cs, child_seed);
    const bus::SameTraceComposition full =
        bus::BuildSameTraceComposition(
            child_cs, child, child_seed, PublicBoundary(),
            bus::TranscriptScope::FullTranscript, {});
    BOOST_REQUIRE_MESSAGE(full.valid, full.note);

    const bus::NormalizedChallengeFeedbackReceiptV1 receipt =
        bus::BuildNormalizedChallengeFeedbackReceiptV1(full);
    BOOST_REQUIRE_MESSAGE(receipt.valid, receipt.note);
    BOOST_CHECK_EQUAL(receipt.version, 1U);
    BOOST_CHECK_EQUAL(
        receipt.required_cells,
        bus::kV5SemanticConsumerCells);
    BOOST_CHECK_EQUAL(
        receipt.structurally_mapped_cells,
        bus::kV5SemanticConsumerCells);
    BOOST_CHECK_EQUAL(
        receipt.local_equality_obligations,
        bus::kV5SemanticConsumerCells);
    BOOST_CHECK_EQUAL(
        receipt.cells.size(),
        bus::kV5SemanticConsumerCells);
    BOOST_CHECK_EQUAL(
        receipt.trace_rows,
        bus::kV5SemanticConsumerRows);
    BOOST_CHECK_EQUAL(
        receipt.trace_columns,
        bus::kNormalizedFeedbackColumns);
    BOOST_CHECK(receipt.canonical_order);
    BOOST_CHECK(receipt.v6_outputs_checked_locally);
    BOOST_CHECK(receipt.v5_public_inputs_checked_locally);
    BOOST_CHECK(receipt.local_binding_complete);
    BOOST_CHECK(!receipt.recursively_child_proof_owned);
    BOOST_CHECK(!receipt.schedule_commitment.IsNull());
    BOOST_CHECK(!receipt.v6_output_commitment.IsNull());
    BOOST_CHECK(!receipt.v5_input_commitment.IsNull());
    BOOST_CHECK(!receipt.receipt_commitment.IsNull());
    BOOST_CHECK_EQUAL(
        receipt.local_equality_violations,
        v6::CountViolations(
            receipt.constraint_system,
            receipt.witness_columns));

    std::array<uint32_t, 7> counts{};
    for (uint32_t ordinal = 0;
         ordinal < receipt.cells.size();
         ++ordinal) {
        const auto& cell = receipt.cells[ordinal];
        BOOST_CHECK_EQUAL(cell.ordinal, ordinal);
        const size_t family =
            static_cast<size_t>(cell.family);
        BOOST_REQUIRE_LT(family, counts.size());
        ++counts[family];
        BOOST_CHECK_EQUAL(
            cell.values_equal,
            cell.v6_output_value == cell.v5_public_input);
    }
    BOOST_CHECK_EQUAL(counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::AirQuotient)], 6U);
    BOOST_CHECK_EQUAL(counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::BatchCoefficient)], 12U);
    BOOST_CHECK_EQUAL(counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::OodPoint)], 12U);
    BOOST_CHECK_EQUAL(counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::DeepWeight)], 12U);
    BOOST_CHECK_EQUAL(counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::FoldChallenge)], 6U);
    BOOST_CHECK_EQUAL(counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::QueryIndex)], 256U);

    std::string why;
    BOOST_CHECK_MESSAGE(
        bus::ValidateNormalizedChallengeFeedbackReceiptV1(
            full, receipt, &why),
        why);

    // This is the migration canary's security-critical result: the current
    // V5 SHA transcript and V6 algebraic transcript do not yield a direct
    // recursive challenge feedback fixed point.
    BOOST_CHECK_LT(
        receipt.locally_equal_cells,
        bus::kV5SemanticConsumerCells);
    BOOST_CHECK_GT(receipt.local_equality_violations, 0U);
    BOOST_CHECK(
        !receipt.current_assignment_satisfies_local_equality);
    why.clear();
    BOOST_CHECK(
        !bus::VerifyNormalizedChallengeFeedbackLocalEqualityV1(
            full, receipt, &why));
    BOOST_CHECK_NE(
        why.find("normalized_feedback_value_mismatch"),
        std::string::npos);

    // Exact receipt validation rejects every structural ambiguity class.
    auto omitted = receipt;
    omitted.cells.pop_back();
    BOOST_CHECK(
        !bus::ValidateNormalizedChallengeFeedbackReceiptV1(
            full, omitted, &why));

    auto reordered = receipt;
    std::swap(reordered.cells[0], reordered.cells[1]);
    BOOST_CHECK(
        !bus::ValidateNormalizedChallengeFeedbackReceiptV1(
            full, reordered, &why));

    auto substituted = receipt;
    substituted.cells[0].v5_public_input =
        gf::Add(
            substituted.cells[0].v5_public_input,
            gf::FromU64(1));
    BOOST_CHECK(
        !bus::ValidateNormalizedChallengeFeedbackReceiptV1(
            full, substituted, &why));

    auto source_substituted = receipt;
    ++source_substituted.cells[0].v6_source_column;
    BOOST_CHECK(
        !bus::ValidateNormalizedChallengeFeedbackReceiptV1(
            full, source_substituted, &why));

    auto witness_substituted = receipt;
    witness_substituted.witness_columns[
        bus::kNormalizedFeedbackWitnessV5][0] =
            gf::Add(
                witness_substituted.witness_columns[
                    bus::kNormalizedFeedbackWitnessV5][0],
                gf::Fp3::One());
    BOOST_CHECK_GT(
        v6::CountViolations(
            witness_substituted.constraint_system,
            witness_substituted.witness_columns),
        0U);
    BOOST_CHECK(
        !bus::ValidateNormalizedChallengeFeedbackReceiptV1(
            full, witness_substituted, &why));

    auto constraint_substituted = receipt;
    constraint_substituted.constraint_system.constraints.pop_back();
    BOOST_CHECK(
        !bus::ValidateNormalizedChallengeFeedbackReceiptV1(
            full, constraint_substituted, &why));

    static_assert(
        bus::kV5V6NormalizedFeedbackReceiptBindingExecutable);
    static_assert(
        !bus::kV5V6NormalizedFeedbackRecursiveOwnershipReady);
    static_assert(!bus::kV6ChallengesDriveNormalizedV5Equations);
    static_assert(!bus::kV5V6CombinedAuthorityReady);
}

BOOST_AUTO_TEST_CASE(
    split_transcript_commits_and_same_trace_aliases_all_304_v5_consumers)
{
    const auto child_cs = ToyChildCS();
    const uint256 child_seed = Seed(49);
    const auto child = ToyDualProof(child_cs, child_seed);
    const bus::SameTraceComposition full =
        bus::BuildSameTraceComposition(
            child_cs, child, child_seed, PublicBoundary(),
            bus::TranscriptScope::FullTranscript, {});
    BOOST_REQUIRE_MESSAGE(full.valid, full.note);

    const bus::V5CommittedFeedbackComposition feedback =
        bus::BuildV5CommittedFeedbackComposition(full);
    BOOST_REQUIRE_MESSAGE(feedback.valid, feedback.note);
    BOOST_CHECK_EQUAL(
        feedback.cells.size(),
        bus::kV5SemanticConsumerCells);
    BOOST_CHECK_EQUAL(
        feedback.committed_same_trace_feedback_alias_cells,
        bus::kV5SemanticConsumerCells);
    BOOST_CHECK_EQUAL(
        feedback.algebraic_v6_challenge_derivation_cells, 0U);
    BOOST_CHECK_EQUAL(
        feedback.recursive_sha_derivation_cells, 0U);
    BOOST_CHECK(feedback.ordered_feedback_stream_bound);
    BOOST_CHECK(!feedback.sha_rejection_sampling_in_air);
    BOOST_CHECK(!feedback.production_authority_ready);
    BOOST_CHECK(feedback.under_recursive_column_cap);
    BOOST_CHECK_LT(
        feedback.combined_columns_count,
        bus::kStage3RecursiveColumnCap);
    BOOST_CHECK_EQUAL(
        v6::CountViolations(
            feedback.combined, feedback.combined_columns),
        0U);

    std::array<uint32_t, 7> counts{};
    for (uint32_t index = 0;
         index < feedback.cells.size(); ++index) {
        const auto& cell = feedback.cells[index];
        BOOST_CHECK_EQUAL(cell.semantic_row, index);
        BOOST_CHECK(cell.v5_consumer_equality);
        BOOST_CHECK(cell.v6_proof_payload_equality);
        BOOST_CHECK(cell.same_trace_alias);
        BOOST_CHECK(!cell.algebraic_v6_challenge_derivation);
        BOOST_CHECK(!cell.recursive_sha_derivation);
        const size_t family =
            static_cast<size_t>(cell.family);
        BOOST_REQUIRE_LT(family, counts.size());
        ++counts[family];

        // Exhaustive synchronized source+export attack.  The V6 seam alone
        // remains satisfied; the exact V5-consumer expected-value equality
        // must reject every one of the 304 cells.
        auto attacked = feedback.combined_columns;
        attacked[cell.export_column][cell.payload.trace_row] =
            gf::Add(
                attacked[cell.export_column]
                        [cell.payload.trace_row],
                gf::Fp3::One());
        attacked[
            feedback.transcript_layout.Source(
                cell.payload.rate_lane)]
            [cell.payload.trace_row] =
            gf::Add(
                attacked[
                    feedback.transcript_layout.Source(
                        cell.payload.rate_lane)]
                    [cell.payload.trace_row],
                gf::Fp3::One());
        BOOST_CHECK(
            HasViolationAtRow(
                feedback.combined, attacked,
                cell.payload.trace_row));
    }
    BOOST_CHECK_EQUAL(counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::AirQuotient)], 6U);
    BOOST_CHECK_EQUAL(counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::BatchCoefficient)], 12U);
    BOOST_CHECK_EQUAL(counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::OodPoint)], 12U);
    BOOST_CHECK_EQUAL(counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::DeepWeight)], 12U);
    BOOST_CHECK_EQUAL(counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::FoldChallenge)], 6U);
    BOOST_CHECK_EQUAL(counts[static_cast<size_t>(
        bus::ChallengeFeedbackFamily::QueryIndex)], 256U);

    // Order is semantic: swapping two distinct cells on both sides of the
    // V6 seam still violates the verifier-fixed V5 consumer values.
    auto first = feedback.cells.end();
    auto second = feedback.cells.end();
    for (auto a = feedback.cells.begin();
         a != feedback.cells.end() &&
         first == feedback.cells.end(); ++a) {
        const auto b = std::find_if(
            std::next(a), feedback.cells.end(),
            [&](const bus::V5CommittedFeedbackCell& candidate) {
                return !gf::Eq(
                    feedback.combined_columns[a->export_column]
                        [a->payload.trace_row],
                    feedback.combined_columns[
                        candidate.export_column]
                        [candidate.payload.trace_row]);
            });
        if (b != feedback.cells.end()) {
            first = a;
            second = b;
        }
    }
    BOOST_REQUIRE(first != feedback.cells.end());
    BOOST_REQUIRE(second != feedback.cells.end());
    auto swapped = feedback.combined_columns;
    std::swap(
        swapped[first->export_column][first->payload.trace_row],
        swapped[second->export_column][second->payload.trace_row]);
    std::swap(
        swapped[feedback.transcript_layout.Source(
                    first->payload.rate_lane)]
               [first->payload.trace_row],
        swapped[feedback.transcript_layout.Source(
                    second->payload.rate_lane)]
               [second->payload.trace_row]);
    BOOST_CHECK(
        HasViolationAtRow(
            feedback.combined, swapped,
            first->payload.trace_row) ||
        HasViolationAtRow(
            feedback.combined, swapped,
            second->payload.trace_row));

    if (std::getenv(
            "BTX_RUN_STAGE3_V5_V6_FEEDBACK_PROVE") != nullptr) {
        HashWriter seed_hash;
        seed_hash
            << "BTX_RC_STAGE3_V5_V6_COMMITTED_FEEDBACK_AIR_V1";
        seed_hash << feedback.public_boundary_commitment;
        seed_hash << feedback.program.active_rows;
        seed_hash << feedback.program.trace_rows;
        seed_hash << static_cast<uint32_t>(
            feedback.program.frames.size());
        seed_hash << static_cast<uint32_t>(
            feedback.program.payload_cells.size());
        const uint256 parent_seed = seed_hash.GetHash();
        const auto proved = aq::AirQuotientProve<gf::Fp3>(
            feedback.combined, feedback.combined_columns,
            parent_seed);
        BOOST_REQUIRE_MESSAGE(
            proved.ok && proved.division_exact, proved.note);
        std::string why;
        BOOST_CHECK_MESSAGE(
            bus::VerifyV5CommittedFeedbackComposition(
                full, feedback.public_boundary_commitment,
                proved.proof, &why),
            why);
        uint256 wrong = feedback.public_boundary_commitment;
        wrong.begin()[0] ^= 1U;
        BOOST_CHECK(
            !bus::VerifyV5CommittedFeedbackComposition(
                full, wrong, proved.proof, &why));
    }

    BOOST_TEST_MESSAGE(
        "cycle-free committed V5-SHA feedback: aliases="
        << feedback.committed_same_trace_feedback_alias_cells
        << "/" << bus::kV5SemanticConsumerCells
        << " algebraic_derivation="
        << feedback.algebraic_v6_challenge_derivation_cells
        << "/" << bus::kV5SemanticConsumerCells
        << " recursive_sha_derivation="
        << feedback.recursive_sha_derivation_cells
        << "/" << bus::kV5SemanticConsumerCells
        << " rows=" << feedback.trace_rows
        << " bridge_cols=" << feedback.bridge_columns
        << " combined_cols="
        << feedback.combined_columns_count
        << " constraints="
        << feedback.combined_constraints
        << " trace_cells="
        << feedback.combined_trace_cells);

    static_assert(bus::kV5V6CommittedFeedbackBusExecutable);
    static_assert(
        bus::kV5V6CommittedFeedbackAliasCells == 304);
    static_assert(
        bus::kV5V6AlgebraicChallengeDerivationCells == 0);
    static_assert(!bus::kV5V6CombinedAuthorityReady);
}

BOOST_AUTO_TEST_CASE(
    packed_sha_air_produces_six_air_lambda_feedback_cells_in_same_parent)
{
    const auto child_cs = ToyChildCS();
    const uint256 child_seed = Seed(50);
    const auto child = ToyDualProof(child_cs, child_seed);
    const bus::SameTraceComposition full =
        bus::BuildSameTraceComposition(
            child_cs, child, child_seed, PublicBoundary(),
            bus::TranscriptScope::FullTranscript, {});
    BOOST_REQUIRE_MESSAGE(full.valid, full.note);

    const bus::V5ShaProducedFeedbackComposition produced =
        bus::BuildV5ShaProducedFeedbackComposition(
            full, child_seed);
    BOOST_REQUIRE_MESSAGE(produced.valid, produced.note);
    BOOST_CHECK_EQUAL(
        produced.committed_same_trace_feedback_alias_cells,
        304U);
    BOOST_CHECK_EQUAL(produced.sha_air_derivation_cells, 6U);
    BOOST_CHECK_EQUAL(
        produced.recursive_sha_derivation_cells, 6U);
    BOOST_CHECK_EQUAL(
        produced.algebraic_v6_challenge_derivation_cells, 0U);
    BOOST_CHECK_EQUAL(
        produced.sha256d_compression_blocks, 3U);
    BOOST_CHECK_EQUAL(produced.packed_sha_lanes, 4U);
    BOOST_CHECK(
        produced.sha_compression_provenance_in_same_air);
    BOOST_CHECK(produced.digest_to_fp3_in_same_air);
    BOOST_CHECK(produced.under_recursive_column_cap);
    BOOST_CHECK(!produced.production_authority_ready);
    BOOST_CHECK_LT(
        produced.combined_columns_count,
        bus::kStage3RecursiveColumnCap);
    BOOST_CHECK_EQUAL(
        v6::CountViolations(
            produced.combined, produced.combined_columns),
        0U);

    uint32_t sha_derived = 0;
    for (const auto& cell : produced.cells) {
        BOOST_CHECK(!cell.algebraic_v6_challenge_derivation);
        if (cell.recursive_sha_derivation) {
            ++sha_derived;
            BOOST_CHECK(
                cell.family ==
                bus::ChallengeFeedbackFamily::AirQuotient);
        } else {
            BOOST_CHECK(
                cell.family !=
                bus::ChallengeFeedbackFamily::AirQuotient);
        }
    }
    BOOST_CHECK_EQUAL(sha_derived, 6U);

    // The packed SHA fixed-program table is not a detached host report.
    auto sha_attack = produced.combined_columns;
    sha_attack[0][0] =
        gf::Add(sha_attack[0][0], gf::Fp3::One());
    BOOST_CHECK(HasViolationAtRow(
        produced.combined, sha_attack, 0));

    // Digest-word bit decomposition and byte-order/Fp reduction are active
    // equations, not a native conversion assertion.
    auto digest_bit_attack = produced.combined_columns;
    digest_bit_attack[produced.digest_bit_base][0] =
        gf::Sub(
            gf::Fp3::One(),
            digest_bit_attack[produced.digest_bit_base][0]);
    BOOST_CHECK(HasViolationAtRow(
        produced.combined, digest_bit_attack, 0));

    const auto air_cell = std::find_if(
        produced.cells.begin(), produced.cells.end(),
        [](const bus::V5CommittedFeedbackCell& cell) {
            return cell.recursive_sha_derivation;
        });
    BOOST_REQUIRE(air_cell != produced.cells.end());

    // Mutating every value-bearing copy at one derived feedback site still
    // fails the SHA digest-to-Fp3 conversion relation.
    auto synchronized = produced.combined_columns;
    synchronized[air_cell->export_column]
                [air_cell->payload.trace_row] =
        gf::Add(
            synchronized[air_cell->export_column]
                        [air_cell->payload.trace_row],
            gf::Fp3::One());
    synchronized[
        produced.transcript_layout.Source(
            air_cell->payload.rate_lane)]
        [air_cell->payload.trace_row] =
        gf::Add(
            synchronized[
                produced.transcript_layout.Source(
                    air_cell->payload.rate_lane)]
                [air_cell->payload.trace_row],
            gf::Fp3::One());
    synchronized[
        produced.challenge_output_base +
            air_cell->coordinate]
        [air_cell->payload.trace_row] =
        gf::Add(
            synchronized[
                produced.challenge_output_base +
                    air_cell->coordinate]
                [air_cell->payload.trace_row],
            gf::Fp3::One());
    BOOST_CHECK(HasViolationAtRow(
        produced.combined, synchronized,
        air_cell->payload.trace_row));

    BOOST_TEST_MESSAGE(
        "same-parent SHA feedback producer: sha_cells="
        << produced.recursive_sha_derivation_cells
        << "/304 committed_aliases="
        << produced.committed_same_trace_feedback_alias_cells
        << "/304 algebraic_cells="
        << produced.algebraic_v6_challenge_derivation_cells
        << "/304 sha_blocks="
        << produced.sha256d_compression_blocks
        << " packed_sha_lanes=" << produced.packed_sha_lanes
        << " rows=" << produced.trace_rows
        << " columns=" << produced.combined_columns_count
        << " constraints=" << produced.combined_constraints
        << " cells=" << produced.combined_trace_cells);

    static_assert(
        bus::kV5V6RecursiveShaDerivationCells == 6);
    static_assert(!bus::kV5V6CombinedAuthorityReady);
}

BOOST_AUTO_TEST_CASE(
    exact_sha_producer_plan_replays_uniform_and_query_transcripts)
{
    const auto child_cs = ToyChildCS();
    const uint256 child_seed = Seed(52);
    const auto child = ToyDualProof(child_cs, child_seed);
    const bus::SameTraceComposition full =
        bus::BuildSameTraceComposition(
            child_cs, child, child_seed, PublicBoundary(),
            bus::TranscriptScope::FullTranscript, {});
    BOOST_REQUIRE_MESSAGE(full.valid, full.note);

    const bus::V5ShaProducerPlan plan =
        bus::AssessV5ShaProducerPlan(
            full, child, child_seed);
    BOOST_REQUIRE_MESSAGE(plan.valid, plan.note);
    BOOST_CHECK_EQUAL(plan.lane_seed_sha256d_calls, 2U);
    BOOST_CHECK_EQUAL(plan.uniform_fp3_draws, 18U);
    BOOST_CHECK_EQUAL(
        plan.uniform_fp3_sha256d_calls, 36U);
    BOOST_CHECK_EQUAL(plan.uniform_consumer_cells, 42U);
    BOOST_CHECK_EQUAL(
        plan.query_index_sha256d_calls, 256U);
    BOOST_CHECK_EQUAL(plan.query_consumer_cells, 256U);
    BOOST_CHECK(plan.all_preimages_replayed);
    BOOST_CHECK(plan.all_uniform_outputs_match);
    BOOST_CHECK(plan.all_query_outputs_match);
    BOOST_CHECK_EQUAL(
        plan.currently_recursive_sha_cells, 6U);
    BOOST_CHECK_EQUAL(
        plan.proof_owned_sha_derivation_cells, 0U);
    BOOST_CHECK_EQUAL(
        plan.recursively_consumed_sha_derivation_cells, 6U);
    BOOST_CHECK_EQUAL(plan.pending_uniform_cells, 42U);
    BOOST_CHECK_EQUAL(plan.pending_query_cells, 256U);
    BOOST_CHECK(plan.uniform_shards_preserve_typed_draws);
    BOOST_CHECK(plan.uniform_output_root_equality_pending);
    BOOST_CHECK_EQUAL(
        plan.uniform_shard_compression_blocks.size(), 3U);
    BOOST_CHECK_EQUAL(
        plan.uniform_shard_consumer_cells.size(), 3U);
    BOOST_CHECK_EQUAL(
        std::accumulate(
            plan.uniform_shard_compression_blocks.begin(),
            plan.uniform_shard_compression_blocks.end(),
            uint32_t{0}),
        plan.uniform_sha_compression_blocks);
    BOOST_CHECK_EQUAL(
        std::accumulate(
            plan.uniform_shard_consumer_cells.begin(),
            plan.uniform_shard_consumer_cells.end(),
            uint32_t{0}),
        plan.uniform_consumer_cells);
    BOOST_CHECK(plan.query_shards_preserve_typed_draws);
    BOOST_CHECK(plan.query_output_root_equality_pending);
    BOOST_CHECK_EQUAL(
        plan.query_shard_compression_blocks.size(), 26U);
    BOOST_CHECK_EQUAL(
        plan.query_shard_consumer_cells.size(), 26U);
    BOOST_CHECK_EQUAL(
        std::accumulate(
            plan.query_shard_compression_blocks.begin(),
            plan.query_shard_compression_blocks.end(),
            uint32_t{0}),
        plan.query_sha_compression_blocks);
    BOOST_CHECK_EQUAL(
        std::accumulate(
            plan.query_shard_consumer_cells.begin(),
            plan.query_shard_consumer_cells.end(),
            uint32_t{0}),
        plan.query_consumer_cells);
    BOOST_CHECK(std::all_of(
        plan.query_shard_compression_blocks.begin(),
        plan.query_shard_compression_blocks.end() - 1,
        [](uint32_t blocks) { return blocks == 90; }));
    BOOST_CHECK(std::all_of(
        plan.query_shard_consumer_cells.begin(),
        plan.query_shard_consumer_cells.end() - 1,
        [](uint32_t cells) { return cells == 10; }));
    BOOST_CHECK_EQUAL(
        plan.query_shard_compression_blocks.back(), 54U);
    BOOST_CHECK_EQUAL(
        plan.query_shard_consumer_cells.back(), 6U);
    BOOST_REQUIRE_GT(
        plan.packed_provenance_instance_capacity, 0U);
    BOOST_CHECK_EQUAL(
        plan.uniform_minimum_parent_shards,
        (plan.uniform_sha_compression_blocks +
         plan.packed_provenance_instance_capacity - 1) /
            plan.packed_provenance_instance_capacity);
    BOOST_CHECK_EQUAL(
        plan.query_minimum_parent_shards,
        (plan.query_sha_compression_blocks +
         plan.packed_provenance_instance_capacity - 1) /
            plan.packed_provenance_instance_capacity);
    BOOST_CHECK_EQUAL(
        plan.uniform_fits_one_parent,
        plan.uniform_sha_compression_blocks <=
            plan.packed_provenance_instance_capacity);
    BOOST_CHECK_EQUAL(
        plan.query_fits_one_parent,
        plan.query_sha_compression_blocks <=
            plan.packed_provenance_instance_capacity);

    auto substituted_parent = full;
    substituted_parent.lane_pis[0].query_index[0] ^= 1U;
    const auto substituted_plan =
        bus::AssessV5ShaProducerPlan(
            substituted_parent, child, child_seed);
    BOOST_CHECK(!substituted_plan.valid);
    BOOST_CHECK_EQUAL(
        substituted_plan.note,
        "stage3:v5_v6_bus:sha_plan:"
        "normalized_child_mismatch");

    BOOST_TEST_MESSAGE(
        "exact V5 SHA producer inventory: lane_seed_calls="
        << plan.lane_seed_sha256d_calls
        << " uniform_draws=" << plan.uniform_fp3_draws
        << " uniform_sha256d_calls="
        << plan.uniform_fp3_sha256d_calls
        << " uniform_compression_blocks="
        << plan.uniform_sha_compression_blocks
        << " uniform_cells=" << plan.uniform_consumer_cells
        << " query_sha256d_calls="
        << plan.query_index_sha256d_calls
        << " query_compression_blocks="
        << plan.query_sha_compression_blocks
        << " query_cells=" << plan.query_consumer_cells
        << " per_parent_capacity="
        << plan.packed_provenance_instance_capacity
        << " uniform_min_shards="
        << plan.uniform_minimum_parent_shards
        << " query_min_shards="
        << plan.query_minimum_parent_shards
        << " typed_uniform_shard_blocks="
        << plan.uniform_shard_compression_blocks[0] << ","
        << plan.uniform_shard_compression_blocks[1] << ","
        << plan.uniform_shard_compression_blocks[2]
        << " typed_uniform_shard_cells="
        << plan.uniform_shard_consumer_cells[0] << ","
        << plan.uniform_shard_consumer_cells[1] << ","
        << plan.uniform_shard_consumer_cells[2]
        << " recursively_derived="
        << plan.currently_recursive_sha_cells
        << "/304");
}

BOOST_AUTO_TEST_CASE(
    full_transcript_witness_shard_plan_maps_all_304_consumers)
{
    const auto child_cs = ToyChildCS();
    const uint256 child_seed = Seed(55);
    const auto child = ToyDualProof(child_cs, child_seed);
    const bus::SameTraceComposition full =
        bus::BuildSameTraceComposition(
            child_cs, child, child_seed, PublicBoundary(),
            bus::TranscriptScope::FullTranscript, {});
    BOOST_REQUIRE_MESSAGE(full.valid, full.note);
    const auto plan =
        bus::BuildV5FullTranscriptWitnessShardPlan(
            full, child, child_seed);
    BOOST_REQUIRE_MESSAGE(plan.valid, plan.note);
    std::string why;
    BOOST_CHECK_MESSAGE(
        bus::ValidateV5FullTranscriptWitnessShardPlan(
            plan, &why),
        why);
    BOOST_CHECK_EQUAL(plan.sha256d_calls, 296U);
    BOOST_CHECK_EQUAL(plan.prequery_sha256d_calls, 40U);
    BOOST_CHECK_EQUAL(plan.query_sha256d_calls, 256U);
    BOOST_CHECK_EQUAL(plan.parent_shards, 30U);
    BOOST_CHECK_EQUAL(plan.vertical_leaf_proofs, 57U);
    BOOST_CHECK_EQUAL(plan.mapped_consumer_cells, 304U);
    BOOST_CHECK_EQUAL(plan.calls.size(), 296U);
    BOOST_CHECK_EQUAL(plan.consumers.size(), 304U);
    BOOST_CHECK_EQUAL(plan.fanout_links.size(), 16U);
    BOOST_CHECK_EQUAL(plan.shards.size(), 30U);
    BOOST_CHECK(plan.exact_304_source_mapping);
    BOOST_CHECK(plan.fanout_safe_unique_link_ids);
    BOOST_CHECK(
        plan.public_only_schedule_reconstruction);
    BOOST_CHECK(
        !plan.public_only_proof_verifier_reconstruction);
    BOOST_CHECK_EQUAL(
        plan.proof_owned_sha_derivation_cells, 0U);
    BOOST_CHECK_EQUAL(
        plan.recursively_consumed_sha_derivation_cells, 0U);
    BOOST_CHECK_EQUAL(plan.shards[0].consumer_cells, 6U);
    BOOST_CHECK_EQUAL(plan.shards[1].compression_blocks, 63U);
    BOOST_CHECK_EQUAL(plan.shards[2].compression_blocks, 69U);
    BOOST_CHECK_EQUAL(plan.shards[3].compression_blocks, 86U);
    BOOST_CHECK_EQUAL(plan.shards[1].consumer_cells, 12U);
    BOOST_CHECK_EQUAL(plan.shards[2].consumer_cells, 15U);
    BOOST_CHECK_EQUAL(plan.shards[3].consumer_cells, 15U);
    for (uint32_t shard = 4; shard < 29; ++shard) {
        BOOST_CHECK_EQUAL(
            plan.shards[shard].compression_blocks, 90U);
        BOOST_CHECK_EQUAL(
            plan.shards[shard].consumer_cells, 10U);
        BOOST_CHECK_EQUAL(plan.shards[shard].leaf_count, 2U);
    }
    BOOST_CHECK_EQUAL(plan.shards[29].compression_blocks, 54U);
    BOOST_CHECK_EQUAL(plan.shards[29].consumer_cells, 6U);
    BOOST_CHECK_EQUAL(plan.shards[29].leaf_count, 1U);
    for (const auto& link : plan.fanout_links) {
        BOOST_CHECK_EQUAL(link.target_count, 146U);
        BOOST_CHECK_EQUAL(
            link.target_call_ordinals.size(), 146U);
    }

    const auto unification =
        bus::BuildV5TranscriptUnificationCanaryV1(plan);
    BOOST_REQUIRE_MESSAGE(
        unification.valid, unification.note);
    BOOST_CHECK_MESSAGE(
        bus::ValidateV5TranscriptUnificationCanaryV1(
            plan, unification, &why),
        why);
    BOOST_CHECK_EQUAL(unification.version, 1U);
    BOOST_CHECK_EQUAL(unification.sha256d_calls, 296U);
    BOOST_CHECK_EQUAL(
        unification.direct_sha256d_calls, 294U);
    BOOST_CHECK_EQUAL(
        unification.dependency_sha256d_calls, 2U);
    BOOST_CHECK_EQUAL(
        unification.direct_sha256d_calls +
            unification.dependency_sha256d_calls,
        unification.sha256d_calls);
    BOOST_CHECK_EQUAL(unification.semantic_cells, 304U);
    BOOST_CHECK_EQUAL(
        unification.locally_executable_cells, 6U);
    BOOST_CHECK_EQUAL(unification.proof_owned_cells, 0U);
    BOOST_CHECK_EQUAL(
        unification.recursively_consumed_cells, 0U);
    BOOST_CHECK_EQUAL(unification.pending_cells, 304U);
    BOOST_CHECK_EQUAL(
        unification.direct_v6_to_v5_feedback_cells, 0U);
    BOOST_CHECK_EQUAL(
        unification.trace_rows,
        bus::kV5TranscriptUnificationRowsV1);
    BOOST_CHECK_EQUAL(
        unification.trace_columns,
        bus::kV5TranscriptUnificationColumns);
    BOOST_CHECK(unification.exact_sha256d_call_inventory);
    BOOST_CHECK(
        unification.exact_semantic_cell_inventory);
    BOOST_CHECK(
        unification.v5_sha256d_xof_schedule_selected);
    BOOST_CHECK(
        unification
            .incompatible_v6_alghash_feedback_rejected);
    BOOST_CHECK(
        unification.public_schedule_cs_reconstructible);
    BOOST_CHECK(
        unification.public_schedule_cs_satisfied);
    BOOST_CHECK(!unification.full_sha256d_execution_proved);
    BOOST_CHECK(!unification.complete_xof_selection_proved);
    BOOST_CHECK(
        !unification.public_proof_verifier_reconstructible);
    BOOST_CHECK(
        !unification.recursive_consumption_complete);
    BOOST_CHECK(!unification.production_authority_ready);
    const std::array<uint32_t, 6> family_cells{
        6, 12, 12, 12, 6, 256};
    const std::array<uint32_t, 6> family_calls{
        2, 8, 16, 8, 4, 256};
    uint32_t family_compression_blocks = 0;
    for (uint32_t family = 0;
         family < unification.families.size(); ++family) {
        const auto& coverage =
            unification.families[family];
        BOOST_CHECK_EQUAL(
            static_cast<uint32_t>(coverage.family),
            family + 1);
        BOOST_CHECK_EQUAL(
            coverage.semantic_cells,
            family_cells[family]);
        BOOST_CHECK_EQUAL(
            coverage.direct_sha256d_calls,
            family_calls[family]);
        BOOST_CHECK_EQUAL(
            coverage.locally_executable_cells,
            family == 0 ? 6U : 0U);
        BOOST_CHECK_EQUAL(coverage.proof_owned_cells, 0U);
        BOOST_CHECK_EQUAL(
            coverage.recursively_consumed_cells, 0U);
        BOOST_CHECK_EQUAL(
            coverage.pending_cells,
            coverage.semantic_cells);
        family_compression_blocks +=
            coverage.direct_sha256d_compression_blocks;
    }
    BOOST_CHECK_EQUAL(
        family_compression_blocks,
        unification.direct_sha256d_compression_blocks);
    BOOST_CHECK_EQUAL(
        unification.direct_sha256d_compression_blocks +
            unification.dependency_sha256d_compression_blocks,
        unification.sha256d_compression_blocks);
    BOOST_CHECK_EQUAL(
        v6::CountViolations(
            unification.public_constraint_system,
            unification.public_columns),
        0U);

    aq::AirConstraintSystem<gf::Fp3> reconstructed_cs;
    std::vector<std::vector<gf::Fp3>>
        reconstructed_columns;
    BOOST_CHECK_MESSAGE(
        bus::
            ReconstructV5TranscriptUnificationPublicConstraintSystemV1(
                plan,
                unification.public_schedule_statement,
                reconstructed_cs,
                reconstructed_columns,
                &why),
        why);
    BOOST_CHECK_EQUAL(
        reconstructed_cs.n_rows,
        unification.public_constraint_system.n_rows);
    BOOST_CHECK_EQUAL(
        reconstructed_cs.n_columns,
        unification.public_constraint_system.n_columns);
    BOOST_REQUIRE_EQUAL(
        reconstructed_columns.size(),
        unification.public_columns.size());
    for (uint32_t column = 0;
         column < reconstructed_columns.size(); ++column) {
        BOOST_REQUIRE_EQUAL(
            reconstructed_columns[column].size(),
            unification.public_columns[column].size());
        for (uint32_t row = 0;
             row < reconstructed_columns[column].size();
             ++row) {
            BOOST_CHECK(gf::Eq(
                reconstructed_columns[column][row],
                unification.public_columns[column][row]));
        }
    }
    uint256 wrong_schedule =
        unification.public_schedule_statement;
    wrong_schedule.begin()[0] ^= 1;
    BOOST_CHECK(
        !bus::
            ReconstructV5TranscriptUnificationPublicConstraintSystemV1(
                plan, wrong_schedule, reconstructed_cs,
                reconstructed_columns, &why));

    auto unearned_canary = unification;
    unearned_canary.proof_owned_cells = 1;
    BOOST_CHECK(
        !bus::ValidateV5TranscriptUnificationCanaryV1(
            plan, unearned_canary, &why));

    auto attacked_schedule = unification;
    attacked_schedule.public_columns[
        bus::kV5TranscriptUnificationPending][0] =
        gf::Fp3::Zero();
    BOOST_CHECK(
        !bus::ValidateV5TranscriptUnificationCanaryV1(
            plan, attacked_schedule, &why));

    const auto attachments =
        bus::BuildV5TranscriptProofAttachmentBundleV1(
            plan);
    BOOST_REQUIRE_MESSAGE(
        attachments.valid, attachments.note);
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            attachments, &why),
        why);
    BOOST_CHECK_EQUAL(
        attachments.vertical_leaves, 57U);
    BOOST_CHECK_EQUAL(attachments.sha256d_calls, 296U);
    BOOST_CHECK_EQUAL(attachments.semantic_cells, 304U);
    BOOST_CHECK_EQUAL(
        attachments.lane_seed_fanouts, 2U);
    BOOST_CHECK_EQUAL(attachments.leaves.size(), 57U);
    BOOST_CHECK_EQUAL(
        attachments.consumers.size(), 304U);
    BOOST_CHECK(attachments.exact_leaf_call_partition);
    BOOST_CHECK(
        attachments.exact_consumer_source_binding);
    BOOST_CHECK(attachments.exact_lane_seed_fanouts);
    BOOST_CHECK_EQUAL(
        attachments.proof_attached_leaves, 0U);
    BOOST_CHECK_EQUAL(attachments.proof_owned_cells, 0U);
    BOOST_CHECK_EQUAL(
        attachments.algebraically_bound_output_cells, 0U);
    BOOST_CHECK_EQUAL(
        attachments.recursively_consumed_cells, 0U);
    BOOST_CHECK_EQUAL(attachments.pending_cells, 304U);
    BOOST_CHECK_EQUAL(attachments.encoded_proof_bytes, 0U);
    BOOST_CHECK(
        !attachments.attached_proofs_publicly_verified);
    BOOST_CHECK(!attachments.all_57_leaf_proofs_attached);
    BOOST_CHECK(
        !attachments.recursive_consumption_complete);
    BOOST_CHECK(!attachments.production_authority_ready);

    std::array<uint8_t, 296> attachment_call_seen{};
    uint32_t attachment_blocks = 0;
    uint32_t attachment_edges = 0;
    for (uint32_t leaf = 0;
         leaf < attachments.leaves.size(); ++leaf) {
        const auto& schedule = attachments.leaves[leaf];
        BOOST_CHECK_EQUAL(schedule.leaf_ordinal, leaf);
        BOOST_CHECK(!schedule.schedule_statement.IsNull());
        BOOST_CHECK_LE(schedule.compression_blocks, 63U);
        attachment_blocks += schedule.compression_blocks;
        attachment_edges += schedule.consumer_source_edges;
        for (uint32_t call : schedule.call_ordinals) {
            BOOST_REQUIRE_LT(call, attachment_call_seen.size());
            BOOST_CHECK(!attachment_call_seen[call]);
            attachment_call_seen[call] = 1;
            BOOST_CHECK_EQUAL(
                plan.calls[call].parent_shard,
                schedule.parent_shard);
            BOOST_CHECK_EQUAL(
                plan.calls[call].leaf_in_parent,
                schedule.leaf_in_parent);
        }
    }
    BOOST_CHECK(std::all_of(
        attachment_call_seen.begin(),
        attachment_call_seen.end(),
        [](uint8_t seen) { return seen == 1; }));
    BOOST_CHECK_EQUAL(
        attachment_blocks,
        unification.sha256d_compression_blocks);
    uint32_t expected_source_edges = 0;
    for (const auto& consumer : plan.consumers) {
        expected_source_edges +=
            consumer.source_call_count;
    }
    BOOST_CHECK_EQUAL(
        attachment_edges, expected_source_edges);
    for (uint32_t row = 0;
         row < attachments.consumers.size(); ++row) {
        const auto& binding =
            attachments.consumers[row];
        BOOST_CHECK_EQUAL(binding.semantic_row, row);
        BOOST_CHECK_EQUAL(
            binding.source_call_count,
            plan.consumers[row].source_call_count);
        for (uint32_t source = 0;
             source < binding.source_call_count;
             ++source) {
            const uint32_t leaf =
                binding.source_leaf_ordinals[source];
            BOOST_REQUIRE_LT(
                leaf, attachments.leaves.size());
            BOOST_CHECK(std::find(
                attachments.leaves[leaf]
                    .call_ordinals.begin(),
                attachments.leaves[leaf]
                    .call_ordinals.end(),
                binding.source_call_ordinals[source]) !=
                attachments.leaves[leaf]
                    .call_ordinals.end());
        }
    }
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const auto& fanout = attachments.fanouts[lane];
        BOOST_CHECK_EQUAL(fanout.lane, lane);
        BOOST_CHECK_EQUAL(
            fanout.source_call_ordinal,
            2U + 19U * lane);
        BOOST_CHECK_EQUAL(
            fanout.target_call_ordinals.size(), 146U);
        BOOST_CHECK_EQUAL(
            fanout.target_leaf_ordinals.size(), 146U);
        for (uint64_t link_id : fanout.word_link_ids) {
            BOOST_CHECK_NE(link_id, 0U);
        }
    }

    // Strict transitive OOD provenance: z1 needs candidates 0/1, while z2
    // also depends on those candidates through the selected-z1 collision
    // exclusion and therefore carries all eight SHA source calls.
    for (const auto& consumer : plan.consumers) {
        if (consumer.family !=
            bus::ChallengeFeedbackFamily::OodPoint) {
            continue;
        }
        BOOST_CHECK_EQUAL(
            consumer.source_call_count,
            consumer.item_index == 0 ? 4U : 8U);
    }
    for (const auto& consumer : plan.consumers) {
        const bool deep =
            consumer.family ==
            bus::ChallengeFeedbackFamily::DeepWeight;
        const bool fold =
            consumer.family ==
            bus::ChallengeFeedbackFamily::FoldChallenge;
        if (!deep && !fold) continue;
        BOOST_REQUIRE_EQUAL(
            consumer.source_call_count, 2U);
        const uint32_t draw =
            deep ? 6U + consumer.item_index
                 : 8U + consumer.item_index;
        const uint32_t lane_base =
            2U + 19U * consumer.lane;
        BOOST_CHECK_EQUAL(
            consumer.source_call_ordinals[0],
            lane_base + 1U + 2U * draw);
        BOOST_CHECK_EQUAL(
            consumer.source_call_ordinals[1],
            lane_base + 2U + 2U * draw);
        BOOST_CHECK_EQUAL(
            consumer.dependency_lane_seed_call,
            lane_base);
    }
    BOOST_CHECK_EQUAL(
        bus::kV5TranscriptNonQueryProofAttachmentCountV1,
        14U);
    BOOST_CHECK_EQUAL(
        bus::kV5TranscriptLocalProofOwnedCellsV1,
        42U);
    BOOST_CHECK(
        bus::kV5QueryIndexSplitRapPromotedV1);
    BOOST_CHECK_EQUAL(
        bus::kV5TranscriptWithQueryProofOwnedCellsV1,
        298U);
    BOOST_CHECK_EQUAL(
        bus::kV5TranscriptAirQuotientPendingCellsV1,
        6U);

    for (uint32_t lane = 0; lane < 2; ++lane) {
        for (uint32_t point = 0; point < 2; ++point) {
            const auto selector =
                bus::BuildV5OodPointSelectorWitnessV1(
                    full, child, child_seed, lane, point);
            BOOST_REQUIRE_MESSAGE(
                selector.valid, selector.note);
            BOOST_CHECK_EQUAL(selector.lane, lane);
            BOOST_CHECK_EQUAL(selector.point, point);
            BOOST_CHECK_LT(
                selector.selected_candidate, 4U);
            BOOST_CHECK_EQUAL(
                v6::CountViolations(
                    selector.cs, selector.columns),
                0U);
            BOOST_CHECK(
                !selector.selector_statement.IsNull());
            BOOST_CHECK(
                !selector.vertical_air_seed.IsNull());
            if (point == 0) {
                BOOST_CHECK_LT(
                    selector.selected_candidate, 2U);
            } else {
                BOOST_CHECK_GE(
                    selector.selected_candidate, 2U);
            }
        }
    }

    const auto selector =
        bus::BuildV5OodPointSelectorWitnessV1(
            full, child, child_seed, 0, 0);
    BOOST_REQUIRE_MESSAGE(selector.valid, selector.note);
    BOOST_REQUIRE_EQUAL(selector.selected_candidate, 0U);

    auto skipped_earlier_valid = selector.columns;
    skipped_earlier_valid[
        selector.selector_column_base][0] =
        gf::Fp3::Zero();
    skipped_earlier_valid[
        selector.selector_column_base][1] =
        gf::Fp3::One();
    BOOST_CHECK_GT(
        v6::CountViolations(
            selector.cs, skipped_earlier_valid),
        0U);

    auto all_invalid = selector.columns;
    for (uint32_t candidate = 0; candidate < 2;
         ++candidate) {
        all_invalid[
            selector.candidate_column_base + 1]
            [candidate] = gf::Fp3::Zero();
        all_invalid[
            selector.candidate_column_base + 2]
            [candidate] = gf::Fp3::Zero();
    }
    BOOST_CHECK_GT(
        v6::CountViolations(selector.cs, all_invalid),
        0U);

    auto candidate_swap = selector.columns;
    for (uint32_t coordinate = 0;
         coordinate < 3; ++coordinate) {
        std::swap(
            candidate_swap[
                selector.candidate_column_base +
                coordinate][0],
            candidate_swap[
                selector.candidate_column_base +
                coordinate][1]);
    }
    BOOST_CHECK_GT(
        v6::CountViolations(selector.cs, candidate_swap),
        0U);

    auto pool_reset_corruption = selector.columns;
    pool_reset_corruption[
        selector.selector_column_base - 1][2] =
        gf::Fp3::One();
    BOOST_CHECK_GT(
        v6::CountViolations(
            selector.cs, pool_reset_corruption),
        0U);

    const auto z2_selector =
        bus::BuildV5OodPointSelectorWitnessV1(
            full, child, child_seed, 0, 1);
    BOOST_REQUIRE_MESSAGE(
        z2_selector.valid, z2_selector.note);
    auto z_collision = z2_selector.columns;
    for (uint32_t coordinate = 0;
         coordinate < 3; ++coordinate) {
        z_collision[
            z2_selector.candidate_column_base +
            coordinate][2] =
            z_collision[
                z2_selector.selected_output_base -
                3 + coordinate][0];
    }
    BOOST_CHECK_GT(
        v6::CountViolations(
            z2_selector.cs, z_collision),
        0U);

    std::array<uint256, 4> deep_statements{};
    for (uint32_t lane = 0; lane < 2; ++lane) {
        for (uint32_t item = 0; item < 2; ++item) {
            const auto deep =
                bus::BuildV5DeepWeightDrawWitnessPrefix(
                    full, child, child_seed, lane, item);
            BOOST_REQUIRE_MESSAGE(deep.valid, deep.note);
            BOOST_CHECK(
                deep.relation ==
                bus::V5UniformDrawRelationV1::DeepWeight);
            BOOST_CHECK_EQUAL(deep.lane, lane);
            BOOST_CHECK_EQUAL(deep.batch_item, item);
            BOOST_CHECK_EQUAL(
                deep.v5_semantic_cell_count, 3U);
            BOOST_CHECK_EQUAL(
                v6::CountViolations(
                    deep.sha_execution.cs,
                    deep.sha_execution.columns),
                0U);
            deep_statements[2 * lane + item] =
                deep.prefix_statement;
        }
        const auto fold =
            bus::BuildV5FoldChallengeDrawWitnessPrefix(
                full, child, child_seed, lane, 0);
        BOOST_REQUIRE_MESSAGE(fold.valid, fold.note);
        BOOST_CHECK(
            fold.relation ==
            bus::V5UniformDrawRelationV1::FoldChallenge);
        BOOST_CHECK_EQUAL(fold.lane, lane);
        BOOST_CHECK_EQUAL(fold.batch_item, 0U);
        BOOST_CHECK_EQUAL(
            fold.v5_semantic_cell_count, 3U);
        BOOST_CHECK_EQUAL(
            v6::CountViolations(
                fold.sha_execution.cs,
                fold.sha_execution.columns),
            0U);
        BOOST_CHECK(
            fold.prefix_statement !=
            deep_statements[2 * lane]);
    }
    BOOST_CHECK(
        deep_statements[0] != deep_statements[1]);
    BOOST_CHECK(
        deep_statements[0] != deep_statements[2]);

    uint32_t packed_query_rows = 0;
    uint32_t packed_query_leaves = 0;
    for (const auto& leaf : attachments.leaves) {
        uint32_t leaf_queries = 0;
        for (uint32_t row :
             leaf.consumer_semantic_rows) {
            if (row < attachments.consumers.size() &&
                attachments.consumers[row].family ==
                    bus::ChallengeFeedbackFamily::
                        QueryIndex) {
                ++leaf_queries;
            }
        }
        if (leaf_queries == 0) continue;
        BOOST_CHECK_LE(
            leaf_queries,
            bus::kV5QueryIndexLeafMaxQueriesV1);
        packed_query_rows += leaf_queries;
        ++packed_query_leaves;
    }
    BOOST_CHECK_EQUAL(packed_query_rows, 256U);
    BOOST_CHECK_GT(packed_query_leaves, 0U);
    for (const auto& consumer : plan.consumers) {
        if (consumer.family !=
            bus::ChallengeFeedbackFamily::QueryIndex) {
            continue;
        }
        BOOST_REQUIRE_EQUAL(
            consumer.source_call_count, 1U);
        BOOST_CHECK_EQUAL(
            consumer.source_call_ordinals[0],
            40U + 128U * consumer.lane +
                consumer.item_index);
        BOOST_CHECK_EQUAL(
            consumer.dependency_lane_seed_call,
            2U + 19U * consumer.lane);
    }

    for (uint32_t lane = 0; lane < 2; ++lane) {
        for (uint32_t query : {0U, 127U}) {
            const auto prefix =
                bus::BuildV5QueryIndexDrawWitnessPrefix(
                    full, child, child_seed, lane, query);
            BOOST_REQUIRE_MESSAGE(
                prefix.valid, prefix.note);
            BOOST_CHECK(
                prefix.relation ==
                bus::V5UniformDrawRelationV1::QueryIndex);
            BOOST_CHECK_EQUAL(
                prefix.v5_semantic_cell_count, 1U);
            BOOST_CHECK_EQUAL(
                v6::CountViolations(
                    prefix.sha_execution.cs,
                    prefix.sha_execution.columns),
                0U);
            const uint32_t index =
                static_cast<uint32_t>(gf::Canonical(
                    prefix.draw_output[0].c0));
            BOOST_CHECK_LT(
                index,
                child.batch.repeated.lane[lane]
                    .row_commit.n_leaves);

            auto bit_attack =
                prefix.sha_execution.columns;
            bit_attack[prefix.candidate_bit_base][0] =
                gf::Add(
                    bit_attack[
                        prefix.candidate_bit_base][0],
                    gf::Fp3::One());
            BOOST_CHECK_GT(
                v6::CountViolations(
                    prefix.sha_execution.cs,
                    bit_attack),
                0U);

            auto out_of_range =
                prefix.sha_execution.columns;
            out_of_range[prefix.draw_output_base][0] =
                gf::Fp3::FromFp(gf::FromU64(
                    child.batch.repeated.lane[lane]
                        .row_commit.n_leaves));
            BOOST_CHECK_GT(
                v6::CountViolations(
                    prefix.sha_execution.cs,
                    out_of_range),
                0U);
        }
    }

    std::vector<unsigned char> attachment_wire;
    BOOST_REQUIRE_GT(
        bus::SerializeV5TranscriptProofAttachmentBundleV1(
            plan, attachments, attachment_wire),
        0U);
    BOOST_CHECK_LE(
        attachment_wire.size(),
        bus::kV5TranscriptAttachmentBundleMaxBytesV1);
    const auto decoded_attachments =
        bus::DeserializeV5TranscriptProofAttachmentBundleV1(
            plan, attachment_wire);
    BOOST_REQUIRE(decoded_attachments.has_value());
    BOOST_CHECK(
        !decoded_attachments
             ->attached_proofs_publicly_verified);
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            *decoded_attachments, &why),
        why);
    std::vector<unsigned char> attachment_wire_again;
    BOOST_CHECK_EQUAL(
        bus::SerializeV5TranscriptProofAttachmentBundleV1(
            plan, *decoded_attachments,
            attachment_wire_again),
        attachment_wire.size());
    BOOST_CHECK(attachment_wire_again == attachment_wire);

    auto omitted_leaf = attachments;
    omitted_leaf.leaves.pop_back();
    BOOST_CHECK(
        !bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            omitted_leaf, &why));
    BOOST_CHECK_EQUAL(
        bus::SerializeV5TranscriptProofAttachmentBundleV1(
            plan, omitted_leaf, attachment_wire_again),
        0U);

    auto reordered_leaves = attachments;
    std::swap(
        reordered_leaves.leaves[0],
        reordered_leaves.leaves[1]);
    BOOST_CHECK(
        !bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            reordered_leaves, &why));

    auto substituted_source = attachments;
    substituted_source.consumers[0]
        .source_leaf_ordinals[0] =
        (substituted_source.consumers[0]
             .source_leaf_ordinals[0] +
         1) %
        substituted_source.leaves.size();
    BOOST_CHECK(
        !bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            substituted_source, &why));

    auto substituted_fanout = attachments;
    std::swap(
        substituted_fanout.fanouts[0]
            .target_call_ordinals[0],
        substituted_fanout.fanouts[0]
            .target_call_ordinals[1]);
    BOOST_CHECK(
        !bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            substituted_fanout, &why));

    auto trailing_attachment_wire = attachment_wire;
    trailing_attachment_wire.push_back(0);
    BOOST_CHECK(
        !bus::DeserializeV5TranscriptProofAttachmentBundleV1(
             plan, trailing_attachment_wire)
             .has_value());

    // Declare one proof whose nested size exceeds the independent per-leaf
    // codec cap. The decoder rejects before allocating the claimed payload.
    auto oversized_nested_wire = attachment_wire;
    BOOST_REQUIRE_EQUAL(oversized_nested_wire.size(), 108U);
    oversized_nested_wire.resize(76);
    oversized_nested_wire[72] = 1;
    const auto append_u32 =
        [&](uint32_t value) {
            for (uint32_t byte = 0; byte < 4; ++byte) {
                oversized_nested_wire.push_back(
                    static_cast<unsigned char>(
                        value >> (8 * byte)));
            }
        };
    append_u32(1);
    append_u32(0);
    append_u32(static_cast<uint32_t>(
        bus::V5TranscriptLeafProofKindV1::
            BatchCoefficientSplitRap));
    append_u32(0);
    append_u32(0);
    oversized_nested_wire.insert(
        oversized_nested_wire.end(), 32, 0);
    append_u32(1);
    append_u32(0);
    append_u32(static_cast<uint32_t>(
        bus::kV5TranscriptLeafProofMaxBytesV1 + 1));
    BOOST_CHECK(
        !bus::DeserializeV5TranscriptProofAttachmentBundleV1(
             plan, oversized_nested_wire)
             .has_value());

    auto omitted = plan;
    omitted.consumers.pop_back();
    BOOST_CHECK(
        !bus::ValidateV5FullTranscriptWitnessShardPlan(
            omitted, &why));

    auto remapped = plan;
    remapped.consumers[0].source_call_ordinals[0] =
        static_cast<uint32_t>(remapped.calls.size());
    BOOST_CHECK(
        !bus::ValidateV5FullTranscriptWitnessShardPlan(
            remapped, &why));

    auto provenance_downgrade = plan;
    const auto z2_source = std::find_if(
        provenance_downgrade.consumers.begin(),
        provenance_downgrade.consumers.end(),
        [](const auto& consumer) {
            return consumer.family ==
                       bus::ChallengeFeedbackFamily::OodPoint &&
                   consumer.lane == 0 &&
                   consumer.item_index == 1 &&
                   consumer.coordinate == 0;
        });
    BOOST_REQUIRE(
        z2_source !=
        provenance_downgrade.consumers.end());
    z2_source->source_call_count = 4;
    BOOST_CHECK(
        !bus::ValidateV5FullTranscriptWitnessShardPlan(
            provenance_downgrade, &why));

    auto link_collision = plan;
    link_collision.fanout_links[1].link_id =
        link_collision.fanout_links[0].link_id;
    BOOST_CHECK(
        !bus::ValidateV5FullTranscriptWitnessShardPlan(
            link_collision, &why));

    auto reordered = plan;
    std::swap(
        reordered.shards[4].call_ordinals[0],
        reordered.shards[5].call_ordinals[0]);
    BOOST_CHECK(
        !bus::ValidateV5FullTranscriptWitnessShardPlan(
            reordered, &why));

    auto unearned_proof = plan;
    unearned_proof.shards[0].proof.proof_owned_cells = 6;
    BOOST_CHECK(
        !bus::ValidateV5FullTranscriptWitnessShardPlan(
            unearned_proof, &why));

    auto unearned_public_verifier = plan;
    unearned_public_verifier
        .public_only_proof_verifier_reconstruction =
        true;
    BOOST_CHECK(
        !bus::ValidateV5FullTranscriptWitnessShardPlan(
            unearned_public_verifier, &why));

    BOOST_TEST_MESSAGE(
        "full witness-owned transcript plan: calls="
        << plan.sha256d_calls
        << " parents=" << plan.parent_shards
        << " vertical_leaves="
        << plan.vertical_leaf_proofs
        << " mapped_cells="
        << plan.mapped_consumer_cells
        << " fanout_links="
        << plan.fanout_links.size()
        << " proof_owned="
        << plan.proof_owned_sha_derivation_cells
        << " recursively_consumed="
        << plan.recursively_consumed_sha_derivation_cells);
}

BOOST_AUTO_TEST_CASE(
    first_uniform_shard_executes_vertical_namespaced_sha_air)
{
    const auto child_cs = ToyChildCS();
    const uint256 child_seed = Seed(53);
    const auto child = ToyDualProof(child_cs, child_seed);
    const bus::SameTraceComposition full =
        bus::BuildSameTraceComposition(
            child_cs, child, child_seed, PublicBoundary(),
            bus::TranscriptScope::FullTranscript, {});
    BOOST_REQUIRE_MESSAGE(full.valid, full.note);
    const auto shard =
        bus::BuildV5FirstUniformVerticalShard(
            full, child, child_seed);
    BOOST_REQUIRE_MESSAGE(shard.valid, shard.note);
    BOOST_CHECK_EQUAL(shard.compression_blocks, 63U);
    BOOST_CHECK_EQUAL(shard.consumer_cells, 12U);
    BOOST_CHECK_EQUAL(shard.boundaries.size(), 63U);
    BOOST_CHECK(!shard.ordered_output_commitment.IsNull());
    BOOST_CHECK_EQUAL(
        shard.sha_execution.semantic_instances, 63U);
    BOOST_CHECK_EQUAL(
        shard.sha_execution.scheduled_instances, 64U);
    BOOST_CHECK_EQUAL(
        shard.sha_execution.cs.n_rows, 65536U);
    BOOST_CHECK_EQUAL(
        shard.sha_execution.cs.n_columns,
        348U);
    BOOST_CHECK_GE(
        shard.sha_execution.cs.n_columns,
        matmul::v4::rc::stage3_hash_air::
            kFixedProgramVerticalProvenanceColumns);
    BOOST_CHECK_LT(
        shard.sha_execution.cs.n_columns,
        bus::kStage3RecursiveColumnCap);
    BOOST_CHECK_EQUAL(
        shard.proof_owned_sha_derivation_cells, 0U);
    BOOST_CHECK_EQUAL(
        shard.recursively_consumed_sha_derivation_cells,
        0U);
    BOOST_CHECK(!shard.sampler_selection_conversion_pending);
    BOOST_CHECK(!shard.output_root_equality_pending);

    const auto& columns = shard.sha_execution.columns;
    const uint32_t active_column =
        matmul::v4::rc::stage3_hash_air::
            kFixedProgramVerticalActiveColumn;
    BOOST_CHECK(gf::Eq(
        columns[active_column][62U * 1024U],
        gf::Fp3::One()));
    BOOST_CHECK(gf::IsZero(
        columns[active_column][63U * 1024U]));

    // A cross-instance value substitution cannot preserve the namespaced
    // producer/consumer multiset.
    auto swapped = columns;
    const uint32_t value_column =
        matmul::v4::rc::stage3_hash_air::ValueColumn(0);
    std::swap(
        swapped[value_column][1024U],
        swapped[value_column][2U * 1024U]);
    BOOST_CHECK(
        HasViolationAtRow(
            shard.sha_execution.cs, swapped, 1024U) ||
        HasViolationAtRow(
            shard.sha_execution.cs, swapped,
            2U * 1024U));

    auto output_substitution = columns;
    output_substitution[
        shard.sampler_final_output_base][0] =
        gf::Add(
            output_substitution[
                shard.sampler_final_output_base][0],
            gf::Fp3::One());
    BOOST_CHECK(HasViolationAtRow(
        shard.sha_execution.cs, output_substitution, 0));

    if (std::getenv(
            "BTX_RUN_STAGE3_VERTICAL_SHA_PROVE") != nullptr) {
        const auto prove_start =
            std::chrono::steady_clock::now();
        const auto proved = aq::AirQuotientProve<gf::Fp3>(
            shard.sha_execution.cs,
            shard.sha_execution.columns,
            shard.vertical_air_seed, {});
        const auto prove_end =
            std::chrono::steady_clock::now();
        BOOST_REQUIRE_MESSAGE(
            proved.ok && proved.division_exact, proved.note);
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            aq::AirQuotientVerify<gf::Fp3>(
                shard.sha_execution.cs, proved.proof,
                shard.vertical_air_seed, &why),
            why);
        const auto verify_end =
            std::chrono::steady_clock::now();
        const double vertical_prove_ms =
            std::chrono::duration<double, std::milli>(
                prove_end - prove_start).count();
        const double vertical_verify_ms =
            std::chrono::duration<double, std::milli>(
                verify_end - prove_end).count();
        BOOST_TEST_MESSAGE(
            "vertical SHA quotient: proof_bytes="
            << ProofBytes(proved.proof)
            << " prove_ms="
            << vertical_prove_ms
            << " verify_ms="
            << vertical_verify_ms);
    }

    BOOST_TEST_MESSAGE(
        "vertical SHA shard0: semantic_instances="
        << shard.sha_execution.semantic_instances
        << " scheduled_instances="
        << shard.sha_execution.scheduled_instances
        << " rows=" << shard.sha_execution.cs.n_rows
        << " columns=" << shard.sha_execution.cs.n_columns
        << " constraints="
        << shard.sha_execution.cs.constraints.size()
        << " compression_blocks="
        << shard.compression_blocks
        << " consumer_cells=" << shard.consumer_cells
        << " proof_owned="
        << shard.proof_owned_sha_derivation_cells
        << " recursively_consumed="
        << shard.recursively_consumed_sha_derivation_cells);
}

BOOST_AUTO_TEST_CASE(
    first_uniform_draw_witness_prefix_closes_sha_sampler_and_v5_cells)
{
    const auto child_cs = ToyChildCS();
    const uint256 child_seed = Seed(54);
    const auto child = ToyDualProof(child_cs, child_seed);
    const bus::SameTraceComposition full =
        bus::BuildSameTraceComposition(
            child_cs, child, child_seed, PublicBoundary(),
            bus::TranscriptScope::FullTranscript, {});
    BOOST_REQUIRE_MESSAGE(full.valid, full.note);
    auto prefix =
        bus::BuildV5FirstUniformDrawWitnessPrefix(
            full, child, child_seed);
    BOOST_REQUIRE_MESSAGE(prefix.valid, prefix.note);
    BOOST_CHECK_EQUAL(prefix.compression_blocks, 13U);
    BOOST_CHECK_EQUAL(prefix.boundaries.size(), 13U);
    BOOST_CHECK_EQUAL(prefix.exact_word_links, 80U);
    BOOST_CHECK_EQUAL(prefix.digest_message_words, 18U);
    BOOST_CHECK_EQUAL(
        prefix.sha_execution.semantic_instances, 13U);
    BOOST_CHECK_EQUAL(
        prefix.sha_execution.scheduled_instances, 16U);
    BOOST_CHECK_EQUAL(prefix.trace_rows, 16384U);
    BOOST_CHECK_LT(
        prefix.trace_columns,
        bus::kStage3RecursiveColumnCap);
    BOOST_CHECK(!prefix.prefix_statement.IsNull());
    BOOST_CHECK_EQUAL(
        prefix.proof_owned_sha_derivation_cells, 0U);
    BOOST_CHECK_EQUAL(
        prefix.recursively_consumed_sha_derivation_cells, 0U);
    BOOST_CHECK_EQUAL(
        v6::CountViolations(
            prefix.sha_execution.cs,
            prefix.sha_execution.columns),
        0U);

    const auto split_plan =
        bus::BuildV5FirstUniformSplitFriPlan(prefix);
    BOOST_REQUIRE_MESSAGE(
        split_plan.valid, split_plan.note);
    BOOST_REQUIRE_EQUAL(
        split_plan.groups.size(), 3U);
    BOOST_CHECK_GT(split_plan.n_coeffs, 0U);
    BOOST_CHECK_EQUAL(
        split_plan.n_lde,
        split_plan.n_coeffs *
            matmul::v4::rc::kRCFriBlowup);
    BOOST_CHECK_EQUAL(
        split_plan.query_count,
        matmul::v4::rc::kRCFri3AlgNumQueries);
    BOOST_CHECK(
        !split_plan.group_schedule_commitment.IsNull());
    BOOST_CHECK_EQUAL(
        split_plan.groups[0].air_column_indices.size() +
            split_plan.groups[1].air_column_indices.size(),
        prefix.trace_columns);
    BOOST_CHECK_EQUAL(
        split_plan.groups[2].air_column_indices.size(),
        1U);
    BOOST_CHECK_EQUAL(
        split_plan.groups[2].air_column_indices[0],
        prefix.trace_columns);
    BOOST_CHECK(
        split_plan.groups[0].row_commitment ==
        prefix.sha_execution.base_row_commitment);
    BOOST_CHECK(split_plan.backend_executable);
    BOOST_CHECK(
        !split_plan.global_soundness_accounted);
    std::string split_why;
    BOOST_CHECK_MESSAGE(
        bus::ValidateV5FirstUniformSplitFriPlan(
            prefix, split_plan, &split_why),
        split_why);

    auto reordered_groups = split_plan;
    std::swap(
        reordered_groups.groups[0],
        reordered_groups.groups[1]);
    BOOST_CHECK(
        !bus::ValidateV5FirstUniformSplitFriPlan(
            prefix, reordered_groups, &split_why));

    auto duplicated_column = split_plan;
    duplicated_column.groups[1]
        .air_column_indices.push_back(
            duplicated_column.groups[0]
                .air_column_indices.front());
    BOOST_CHECK(
        !bus::ValidateV5FirstUniformSplitFriPlan(
            prefix, duplicated_column, &split_why));

    auto missing_column = split_plan;
    BOOST_REQUIRE(
        !missing_column.groups[1]
             .air_column_indices.empty());
    missing_column.groups[1]
        .air_column_indices.pop_back();
    BOOST_CHECK(
        !bus::ValidateV5FirstUniformSplitFriPlan(
            prefix, missing_column, &split_why));

    auto root_mutation = split_plan;
    root_mutation.groups[0].row_commitment =
        Seed(55);
    BOOST_CHECK(
        !bus::ValidateV5FirstUniformSplitFriPlan(
            prefix, root_mutation, &split_why));

    auto stage_reorder = split_plan;
    stage_reorder.rdep_precedes_constraint_batch_challenge =
        false;
    BOOST_CHECK(
        !bus::ValidateV5FirstUniformSplitFriPlan(
            prefix, stage_reorder, &split_why));

    auto domain_mutation = split_plan;
    domain_mutation.n_lde *= 2;
    BOOST_CHECK(
        !bus::ValidateV5FirstUniformSplitFriPlan(
            prefix, domain_mutation, &split_why));

    auto query_mutation = split_plan;
    --query_mutation.query_count;
    BOOST_CHECK(
        !bus::ValidateV5FirstUniformSplitFriPlan(
            prefix, query_mutation, &split_why));

    auto schedule_commitment_mutation = split_plan;
    schedule_commitment_mutation
        .group_schedule_commitment = Seed(56);
    BOOST_CHECK(
        !bus::ValidateV5FirstUniformSplitFriPlan(
            prefix, schedule_commitment_mutation,
            &split_why));

    auto missing_backend = split_plan;
    missing_backend.backend_executable = false;
    BOOST_CHECK(
        !bus::ValidateV5FirstUniformSplitFriPlan(
            prefix, missing_backend, &split_why));

    auto unearned_completion = split_plan;
    unearned_completion.global_soundness_accounted =
        true;
    unearned_completion.proof_owned_sha_derivation_cells =
        3;
    BOOST_CHECK(
        !bus::ValidateV5FirstUniformSplitFriPlan(
            prefix, unearned_completion, &split_why));

    auto candidate_attack =
        prefix.sha_execution.columns;
    candidate_attack[prefix.candidate_bit_base][0] =
        gf::Add(
            candidate_attack[prefix.candidate_bit_base][0],
            gf::Fp3::One());
    BOOST_CHECK(HasViolationAtRow(
        prefix.sha_execution.cs, candidate_attack, 0));

    auto count_attack =
        prefix.sha_execution.columns;
    count_attack[prefix.accepted_count_base][0] =
        gf::Add(
            count_attack[prefix.accepted_count_base][0],
            gf::Fp3::One());
    BOOST_CHECK(HasViolationAtRow(
        prefix.sha_execution.cs, count_attack, 0));

    auto output_attack =
        prefix.sha_execution.columns;
    output_attack[prefix.draw_output_base][0] =
        gf::Add(
            output_attack[prefix.draw_output_base][0],
            gf::Fp3::One());
    BOOST_CHECK(HasViolationAtRow(
        prefix.sha_execution.cs, output_attack, 0));

    // Attack one exact SHA chaining target.
    BOOST_REQUIRE(!prefix.links.empty());
    const auto& link = prefix.links.front();
    uint32_t linked_row = UINT32_MAX;
    uint32_t linked_input = UINT32_MAX;
    const auto program =
        matmul::v4::rc::stage3_hash_air::
            BuildCanonicalProgram(
                matmul::v4::rc::stage3_hash_air::
                    ProgramKind::Sha256Compression);
    for (uint32_t row = 0;
         row < program.rows.size(); ++row) {
        for (uint32_t input = 0;
             input < program.rows[row].input_count;
             ++input) {
            if (program.rows[row].input_address[input] ==
                link.target_external_address) {
                linked_row =
                    1024 * link.target_instance + row;
                linked_input = input;
                break;
            }
        }
        if (linked_row != UINT32_MAX) break;
    }
    BOOST_REQUIRE_NE(linked_row, UINT32_MAX);
    auto chain_attack =
        prefix.sha_execution.columns;
    chain_attack[
        matmul::v4::rc::stage3_hash_air::
            ValueColumn(linked_input)][linked_row] =
        gf::Add(
            chain_attack[
                matmul::v4::rc::stage3_hash_air::
                    ValueColumn(linked_input)][linked_row],
            gf::Fp3::One());
    BOOST_CHECK(HasViolationAtRow(
        prefix.sha_execution.cs, chain_attack, linked_row));

    // Attack an unaligned lane-seed digest/message bit.
    uint32_t message_instance = UINT32_MAX;
    uint32_t message_address = UINT32_MAX;
    for (uint32_t instance = 0;
         instance < prefix.public_external_masks.size() &&
         message_instance == UINT32_MAX; ++instance) {
        for (uint32_t address = 9; address <= 16; ++address) {
            if (!prefix.public_external_masks[instance]
                    [address - 1]) {
                message_instance = instance;
                message_address = address;
                break;
            }
        }
    }
    BOOST_REQUIRE_NE(message_instance, UINT32_MAX);
    uint32_t message_row = UINT32_MAX;
    for (uint32_t row = 0;
         row < program.rows.size(); ++row) {
        for (uint32_t input = 0;
             input < program.rows[row].input_count;
             ++input) {
            if (program.rows[row].input_address[input] ==
                message_address) {
                message_row = 1024 * message_instance + row;
                break;
            }
        }
        if (message_row != UINT32_MAX) break;
    }
    BOOST_REQUIRE_NE(message_row, UINT32_MAX);
    auto message_attack =
        prefix.sha_execution.columns;
    message_attack[prefix.message_bit_base][message_row] =
        gf::Add(
            message_attack[prefix.message_bit_base][message_row],
            gf::Fp3::One());
    BOOST_CHECK(HasViolationAtRow(
        prefix.sha_execution.cs, message_attack, message_row));

    if (std::getenv(
            "BTX_RUN_STAGE3_FIRST_UNIFORM_PREFIX_PROVE") != nullptr) {
        const auto prove_start =
            std::chrono::steady_clock::now();
        const auto proved =
            bus::ProveV5FirstUniformSplitRap(
                prefix);
        const auto prove_end =
            std::chrono::steady_clock::now();
        BOOST_REQUIRE_MESSAGE(
            proved.ok,
            proved.note);
        std::string verify_why;
        BOOST_REQUIRE_MESSAGE(
            bus::VerifyV5FirstUniformSplitRap(
                full, child, child_seed,
                proved.proof, &verify_why),
            verify_why);
        const auto verify_end =
            std::chrono::steady_clock::now();

        auto substituted_claim = proved.proof;
        substituted_claim.proved_v5_exports[0] =
            gf::Add(
                substituted_claim
                    .proved_v5_exports[0],
                gf::Fp3::One());
        BOOST_CHECK(
            !bus::VerifyV5FirstUniformSplitRap(
                full, child, child_seed,
                substituted_claim,
                &verify_why));
        const double prove_ms =
            std::chrono::duration<double, std::milli>(
                prove_end - prove_start).count();
        const double verify_ms =
            std::chrono::duration<double, std::milli>(
                verify_end - prove_end).count();
        BOOST_TEST_MESSAGE(
            "first-uniform Split-RAP proof:"
            << " prove_ms=" << prove_ms
            << " verify_ms=" << verify_ms
            << " proof_codec_pending=1"
            << " proof_owned_exports="
            << proved.proof
                   .proof_owned_v5_cells
            << " recursive_consumed_exports=0");
    }

    BOOST_TEST_MESSAGE(
        "witness-owned first uniform draw prefix: blocks="
        << prefix.compression_blocks
        << " links=" << prefix.exact_word_links
        << " digest_message_words="
        << prefix.digest_message_words
        << " rows=" << prefix.trace_rows
        << " columns=" << prefix.trace_columns
        << " constraints=" << prefix.constraints
        << " v5_rows="
        << prefix.v5_semantic_rows[0] << ","
        << prefix.v5_semantic_rows[1] << ","
        << prefix.v5_semantic_rows[2]);
}

BOOST_AUTO_TEST_CASE(
    first_uniform_split_rap_public_only_roundtrip)
{
    const char* enabled =
        std::getenv(
            "BTX_RUN_STAGE3_FIRST_UNIFORM_SPLIT_RAP");
    if (enabled == nullptr ||
        std::string{enabled} != "1") {
        BOOST_TEST_MESSAGE(
            "first-uniform Split-RAP roundtrip skipped "
            "(BTX_RUN_STAGE3_FIRST_UNIFORM_SPLIT_RAP!=1)");
        return;
    }
    const auto child_cs = ToyChildCS();
    const uint256 child_seed = Seed(58);
    const auto child =
        ToyDualProof(child_cs, child_seed);
    const bus::SameTraceComposition full =
        bus::BuildSameTraceComposition(
            child_cs, child, child_seed,
            PublicBoundary(),
            bus::TranscriptScope::FullTranscript,
            {});
    BOOST_REQUIRE_MESSAGE(full.valid, full.note);
    auto prefix =
        bus::BuildV5FirstUniformDrawWitnessPrefix(
            full, child, child_seed);
    BOOST_REQUIRE_MESSAGE(
        prefix.valid, prefix.note);
    BOOST_CHECK(
        !prefix.vertical_air_seed.IsNull());

    const auto proved =
        bus::ProveV5FirstUniformSplitRap(prefix);
    BOOST_REQUIRE_MESSAGE(
        proved.ok, proved.note);
    BOOST_CHECK_EQUAL(
        proved.proof.proof_owned_v5_cells, 3U);
    BOOST_CHECK_EQUAL(
        proved.proof
            .recursively_consumed_v5_cells,
        0U);
    BOOST_CHECK(
        !proved.proof.full_304_transcript);
    BOOST_CHECK(
        proved.proof.canonical_r0 ==
        prefix.sha_execution
            .base_row_commitment);
    BOOST_CHECK_EQUAL(
        proved.proof.quotient.batch.version,
        matmul::v4::rc::
            kRCFri3AlgMultiRowBatchProofVersion);

    std::string why;
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5FirstUniformSplitRap(
            full, child, child_seed,
            proved.proof, &why),
        why);

    const auto plan =
        bus::BuildV5FullTranscriptWitnessShardPlan(
            full, child, child_seed);
    BOOST_REQUIRE_MESSAGE(plan.valid, plan.note);
    auto attachments =
        bus::BuildV5TranscriptProofAttachmentBundleV1(
            plan);
    BOOST_REQUIRE_MESSAGE(
        attachments.valid, attachments.note);
    BOOST_CHECK_MESSAGE(
        bus::AttachV5FirstUniformSplitRapV1(
            full, child, child_seed, plan,
            proved.proof, attachments, &why),
        why);
    BOOST_REQUIRE_EQUAL(attachments.proofs.size(), 1U);
    BOOST_CHECK_EQUAL(
        attachments.proof_attached_leaves, 1U);
    BOOST_CHECK_EQUAL(attachments.proof_owned_cells, 3U);
    BOOST_CHECK_EQUAL(
        attachments.algebraically_bound_output_cells, 3U);
    BOOST_CHECK_EQUAL(
        attachments.recursively_consumed_cells, 0U);
    BOOST_CHECK_EQUAL(attachments.pending_cells, 301U);
    BOOST_CHECK_GT(attachments.encoded_proof_bytes, 0U);
    BOOST_CHECK_LE(
        attachments.encoded_proof_bytes,
        bus::kV5TranscriptLeafProofMaxBytesV1);
    BOOST_CHECK(
        attachments.attached_proofs_publicly_verified);
    BOOST_CHECK(!attachments.all_57_leaf_proofs_attached);
    BOOST_CHECK(
        !attachments.recursive_consumption_complete);
    BOOST_CHECK(!attachments.production_authority_ready);
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            attachments, &why),
        why);

    std::vector<unsigned char> attachment_wire;
    BOOST_REQUIRE_GT(
        bus::SerializeV5TranscriptProofAttachmentBundleV1(
            plan, attachments, attachment_wire),
        0U);
    const auto decoded_attachments =
        bus::DeserializeV5TranscriptProofAttachmentBundleV1(
            plan, attachment_wire);
    BOOST_REQUIRE(decoded_attachments.has_value());
    BOOST_CHECK(
        !decoded_attachments
             ->attached_proofs_publicly_verified);
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            *decoded_attachments, &why),
        why);
    const auto lane0_semantic_rows =
        prefix.v5_semantic_rows;
    prefix = {};

    // The same fixed-program/Split-RAP adapter proves lane 1's first batch
    // coefficient from its independently domain-separated lane seed.
    auto lane1_prefix =
        bus::BuildV5BatchCoefficientDrawWitnessPrefix(
            full, child, child_seed, 1, 0);
    BOOST_REQUIRE_MESSAGE(
        lane1_prefix.valid, lane1_prefix.note);
    BOOST_CHECK_EQUAL(lane1_prefix.lane, 1U);
    BOOST_CHECK_EQUAL(lane1_prefix.batch_item, 0U);
    BOOST_CHECK_EQUAL(lane1_prefix.compression_blocks, 13U);
    BOOST_CHECK(
        lane1_prefix.v5_semantic_rows !=
        lane0_semantic_rows);
    const auto lane1_partition =
        bus::BuildV5FirstUniformSplitFriPlan(
            lane1_prefix);
    BOOST_REQUIRE_MESSAGE(
        lane1_partition.valid,
        lane1_partition.note);
    BOOST_REQUIRE_EQUAL(
        lane1_partition.groups.size(), 3U);
    BOOST_CHECK(
        lane1_partition.groups[0].role ==
        bus::V5SplitFriGroupRole::R0Base);
    BOOST_CHECK(
        lane1_partition.groups[1].role ==
        bus::V5SplitFriGroupRole::Rdep);
    BOOST_CHECK(
        lane1_partition.groups[2].role ==
        bus::V5SplitFriGroupRole::Rq);
    BOOST_CHECK(
        lane1_partition
            .logical_columns_partitioned_once);
    BOOST_CHECK(
        lane1_partition.shared_query_opens_all_groups);

    const auto lane1_proved =
        bus::ProveV5FirstUniformSplitRap(
            lane1_prefix);
    BOOST_REQUIRE_MESSAGE(
        lane1_proved.ok, lane1_proved.note);
    lane1_prefix = {};
    BOOST_REQUIRE_EQUAL(
        lane1_proved.proof.quotient
            .next_trace_group_rows.size(),
        matmul::v4::rc::kRCFri3AlgNumQueries);
    for (const auto& next :
         lane1_proved.proof.quotient
             .next_trace_group_rows) {
        BOOST_CHECK_EQUAL(next.size(), 2U);
    }
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5BatchCoefficientDrawSplitRap(
            full, child, child_seed, 1, 0,
            lane1_proved.proof, &why),
        why);
    BOOST_CHECK(
        !bus::VerifyV5BatchCoefficientDrawSplitRap(
            full, child, child_seed, 0, 0,
            lane1_proved.proof, &why));
    BOOST_CHECK(
        !bus::VerifyV5BatchCoefficientDrawSplitRap(
            full, child, child_seed, 1, 0,
            proved.proof, &why));

    auto two_attachments = attachments;
    BOOST_CHECK_MESSAGE(
        bus::AttachV5BatchCoefficientDrawSplitRapV1(
            full, child, child_seed, plan,
            1, 0, lane1_proved.proof,
            two_attachments, &why),
        why);
    BOOST_REQUIRE_EQUAL(two_attachments.proofs.size(), 2U);
    BOOST_CHECK_EQUAL(
        two_attachments.proof_attached_leaves, 2U);
    BOOST_CHECK_EQUAL(
        two_attachments.proof_owned_cells, 6U);
    BOOST_CHECK_EQUAL(
        two_attachments.algebraically_bound_output_cells,
        6U);
    BOOST_CHECK_EQUAL(
        two_attachments.recursively_consumed_cells, 0U);
    BOOST_CHECK_EQUAL(two_attachments.pending_cells, 298U);
    BOOST_CHECK(
        two_attachments.proofs[0].leaf_ordinal <
        two_attachments.proofs[1].leaf_ordinal);
    BOOST_CHECK_EQUAL(two_attachments.proofs[0].lane, 0U);
    BOOST_CHECK_EQUAL(two_attachments.proofs[1].lane, 1U);
    BOOST_CHECK(!two_attachments.production_authority_ready);
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            two_attachments, &why),
        why);
    std::vector<unsigned char> two_attachment_wire;
    BOOST_REQUIRE_GT(
        bus::SerializeV5TranscriptProofAttachmentBundleV1(
            plan, two_attachments,
            two_attachment_wire),
        0U);
    const auto decoded_two =
        bus::DeserializeV5TranscriptProofAttachmentBundleV1(
            plan, two_attachment_wire);
    BOOST_REQUIRE(decoded_two.has_value());
    BOOST_CHECK(
        !decoded_two->attached_proofs_publicly_verified);
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            *decoded_two, &why),
        why);

    auto lane0_item1_prefix =
        bus::BuildV5BatchCoefficientDrawWitnessPrefix(
            full, child, child_seed, 0, 1);
    BOOST_REQUIRE_MESSAGE(
        lane0_item1_prefix.valid,
        lane0_item1_prefix.note);
    BOOST_CHECK_EQUAL(lane0_item1_prefix.lane, 0U);
    BOOST_CHECK_EQUAL(
        lane0_item1_prefix.batch_item, 1U);
    const auto lane0_item1_proved =
        bus::ProveV5FirstUniformSplitRap(
            lane0_item1_prefix);
    BOOST_REQUIRE_MESSAGE(
        lane0_item1_proved.ok,
        lane0_item1_proved.note);
    lane0_item1_prefix = {};
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5BatchCoefficientDrawSplitRap(
            full, child, child_seed, 0, 1,
            lane0_item1_proved.proof, &why),
        why);
    BOOST_CHECK(
        !bus::VerifyV5BatchCoefficientDrawSplitRap(
            full, child, child_seed, 0, 0,
            lane0_item1_proved.proof, &why));

    auto four_attachments = two_attachments;
    BOOST_CHECK_MESSAGE(
        bus::AttachV5BatchCoefficientDrawSplitRapV1(
            full, child, child_seed, plan,
            0, 1, lane0_item1_proved.proof,
            four_attachments, &why),
        why);

    auto lane1_item1_prefix =
        bus::BuildV5BatchCoefficientDrawWitnessPrefix(
            full, child, child_seed, 1, 1);
    BOOST_REQUIRE_MESSAGE(
        lane1_item1_prefix.valid,
        lane1_item1_prefix.note);
    BOOST_CHECK_EQUAL(lane1_item1_prefix.lane, 1U);
    BOOST_CHECK_EQUAL(
        lane1_item1_prefix.batch_item, 1U);
    const auto lane1_item1_proved =
        bus::ProveV5FirstUniformSplitRap(
            lane1_item1_prefix);
    BOOST_REQUIRE_MESSAGE(
        lane1_item1_proved.ok,
        lane1_item1_proved.note);
    lane1_item1_prefix = {};
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5BatchCoefficientDrawSplitRap(
            full, child, child_seed, 1, 1,
            lane1_item1_proved.proof, &why),
        why);
    BOOST_CHECK(
        !bus::VerifyV5BatchCoefficientDrawSplitRap(
            full, child, child_seed, 1, 0,
            lane1_item1_proved.proof, &why));
    BOOST_CHECK(
        !bus::VerifyV5BatchCoefficientDrawSplitRap(
            full, child, child_seed, 1, 1,
            lane1_proved.proof, &why));

    BOOST_CHECK_MESSAGE(
        bus::AttachV5BatchCoefficientDrawSplitRapV1(
            full, child, child_seed, plan,
            1, 1, lane1_item1_proved.proof,
            four_attachments, &why),
        why);
    BOOST_REQUIRE_EQUAL(
        four_attachments.proofs.size(), 4U);
    BOOST_CHECK_EQUAL(
        four_attachments.proof_owned_cells, 12U);
    BOOST_CHECK_EQUAL(
        four_attachments.algebraically_bound_output_cells,
        12U);
    BOOST_CHECK_EQUAL(
        four_attachments.recursively_consumed_cells, 0U);
    BOOST_CHECK_EQUAL(four_attachments.pending_cells, 292U);
    const std::array<std::pair<uint32_t, uint32_t>, 4>
        expected_draw_order{{
            {0, 0}, {0, 1}, {1, 0}, {1, 1}}};
    for (uint32_t index = 0; index < 4; ++index) {
        BOOST_CHECK_EQUAL(
            four_attachments.proofs[index].lane,
            expected_draw_order[index].first);
        BOOST_CHECK_EQUAL(
            four_attachments.proofs[index].batch_item,
            expected_draw_order[index].second);
        BOOST_CHECK_EQUAL(
            four_attachments.proofs[index]
                .proof_owned_semantic_rows.size(),
            3U);
    }
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            four_attachments, &why),
        why);
    std::vector<unsigned char> four_attachment_wire;
    BOOST_REQUIRE_GT(
        bus::SerializeV5TranscriptProofAttachmentBundleV1(
            plan, four_attachments,
            four_attachment_wire),
        0U);
    BOOST_CHECK_LE(
        four_attachment_wire.size(),
        bus::kV5TranscriptAttachmentBundleMaxBytesV1);
    auto decoded_four =
        bus::DeserializeV5TranscriptProofAttachmentBundleV1(
            plan, four_attachment_wire);
    BOOST_REQUIRE(decoded_four.has_value());
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            *decoded_four, &why),
        why);
    decoded_four.reset();

    {
        auto duplicate = four_attachments;
        BOOST_CHECK(
            !bus::AttachV5BatchCoefficientDrawSplitRapV1(
                full, child, child_seed, plan,
                0, 1, lane0_item1_proved.proof,
                duplicate, &why));
        BOOST_CHECK_EQUAL(duplicate.proofs.size(), 4U);
        BOOST_CHECK_EQUAL(
            duplicate.proof_owned_cells, 12U);
    }
    {
        auto item_swap = four_attachments;
        item_swap.proofs[1].batch_item = 0;
        BOOST_CHECK(
            !bus::VerifyV5TranscriptProofAttachmentBundleV1(
                full, child, child_seed, plan,
                item_swap, &why));
    }
    {
        auto omitted_item = four_attachments;
        omitted_item.proofs.erase(
            omitted_item.proofs.begin() + 1);
        BOOST_CHECK(
            !bus::VerifyV5TranscriptProofAttachmentBundleV1(
                full, child, child_seed, plan,
                omitted_item, &why));
    }
    {
        auto unchanged_four = four_attachments;
        BOOST_CHECK(
            !bus::AttachV5BatchCoefficientDrawSplitRapV1(
                full, child, child_seed, plan,
                0, 0, lane0_item1_proved.proof,
                unchanged_four, &why));
        BOOST_CHECK_EQUAL(
            unchanged_four.proof_owned_cells, 12U);
    }

    auto omitted_second = two_attachments;
    omitted_second.proofs.pop_back();
    BOOST_CHECK(
        !bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            omitted_second, &why));

    auto reordered_proofs = two_attachments;
    std::swap(
        reordered_proofs.proofs[0],
        reordered_proofs.proofs[1]);
    BOOST_CHECK(
        !bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            reordered_proofs, &why));

    auto substituted_lane = two_attachments;
    substituted_lane.proofs[1].lane = 0;
    BOOST_CHECK(
        !bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            substituted_lane, &why));

    auto substituted_lane_proof = lane1_proved.proof;
    substituted_lane_proof.quotient
        .next_trace_group_rows[0][0]
        .values[0] =
        gf::Add(
            substituted_lane_proof.quotient
                .next_trace_group_rows[0][0]
                .values[0],
            gf::Fp3::One());
    auto unchanged = attachments;
    BOOST_CHECK(
        !bus::AttachV5BatchCoefficientDrawSplitRapV1(
            full, child, child_seed, plan,
            1, 0, substituted_lane_proof,
            unchanged, &why));
    BOOST_CHECK_EQUAL(unchanged.proofs.size(), 1U);
    BOOST_CHECK_EQUAL(unchanged.proof_owned_cells, 3U);

    auto omitted_proof = attachments;
    omitted_proof.proofs[0].proof_bytes.clear();
    BOOST_CHECK(
        !bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            omitted_proof, &why));

    auto reordered_rows = attachments;
    std::swap(
        reordered_rows.proofs[0]
            .proof_owned_semantic_rows[0],
        reordered_rows.proofs[0]
            .proof_owned_semantic_rows[1]);
    BOOST_CHECK(
        !bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            reordered_rows, &why));

    auto substituted_proof = attachments;
    substituted_proof.proofs[0].proof_bytes.back() ^= 1;
    BOOST_CHECK(
        !bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            substituted_proof, &why));

    auto wrong_leaf = attachments;
    ++wrong_leaf.proofs[0].leaf_ordinal;
    BOOST_CHECK(
        !bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            wrong_leaf, &why));

    auto unearned_recursive = attachments;
    unearned_recursive.proofs[0]
        .recursively_consumed_cells = 3;
    unearned_recursive.recursively_consumed_cells = 3;
    BOOST_CHECK(
        !bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            unearned_recursive, &why));

    auto export_attack = proved.proof;
    export_attack.proved_v5_exports[0] =
        gf::Add(
            export_attack.proved_v5_exports[0],
            gf::Fp3::One());
    BOOST_CHECK(
        !bus::VerifyV5FirstUniformSplitRap(
            full, child, child_seed,
            export_attack, &why));

    auto r0_attack = proved.proof;
    r0_attack.canonical_r0 = Seed(59);
    BOOST_CHECK(
        !bus::VerifyV5FirstUniformSplitRap(
            full, child, child_seed,
            r0_attack, &why));

    auto next_attack = proved.proof;
    next_attack.quotient
        .next_trace_group_rows[0][1]
        .values[0] =
        gf::Add(
            next_attack.quotient
                .next_trace_group_rows[0][1]
                .values[0],
            gf::Fp3::One());
    BOOST_CHECK(
        !bus::VerifyV5FirstUniformSplitRap(
            full, child, child_seed,
            next_attack, &why));

    auto counter_attack = proved.proof;
    counter_attack.proof_owned_v5_cells =
        304;
    counter_attack.full_304_transcript = true;
    BOOST_CHECK(
        !bus::VerifyV5FirstUniformSplitRap(
            full, child, child_seed,
            counter_attack, &why));

    BOOST_CHECK(
        !bus::VerifyV5FirstUniformSplitRap(
            full, child, Seed(60),
            proved.proof, &why));
}

BOOST_AUTO_TEST_CASE(
    query_index_leaf_split_rap_public_only_roundtrip)
{
    const char* enabled =
        std::getenv("BTX_RUN_STAGE3_QUERY_SPLIT_RAP");
    if (enabled == nullptr ||
        std::string{enabled} != "1") {
        BOOST_TEST_MESSAGE(
            "QueryIndex leaf Split-RAP roundtrip skipped "
            "(BTX_RUN_STAGE3_QUERY_SPLIT_RAP!=1)");
        return;
    }
    const auto child_cs = ToyChildCS();
    const uint256 child_seed = Seed(63);
    const auto child =
        ToyDualProof(child_cs, child_seed);
    const bus::SameTraceComposition full =
        bus::BuildSameTraceComposition(
            child_cs, child, child_seed,
            PublicBoundary(),
            bus::TranscriptScope::FullTranscript,
            {});
    BOOST_REQUIRE_MESSAGE(full.valid, full.note);
    const auto plan =
        bus::BuildV5FullTranscriptWitnessShardPlan(
            full, child, child_seed);
    BOOST_REQUIRE_MESSAGE(plan.valid, plan.note);
    const auto empty =
        bus::BuildV5TranscriptProofAttachmentBundleV1(
            plan);
    BOOST_REQUIRE_MESSAGE(empty.valid, empty.note);

    uint32_t lane0_leaf = UINT32_MAX;
    uint32_t lane1_leaf = UINT32_MAX;
    for (const auto& leaf : empty.leaves) {
        for (uint32_t row :
             leaf.consumer_semantic_rows) {
            if (row >= empty.consumers.size()) continue;
            const auto& consumer =
                empty.consumers[row];
            if (consumer.family !=
                bus::ChallengeFeedbackFamily::QueryIndex) {
                continue;
            }
            uint32_t& selected =
                consumer.lane == 0
                ? lane0_leaf : lane1_leaf;
            if (selected == UINT32_MAX) {
                selected = leaf.leaf_ordinal;
            }
        }
    }
    BOOST_REQUIRE_NE(lane0_leaf, UINT32_MAX);
    BOOST_REQUIRE_NE(lane1_leaf, UINT32_MAX);

    const auto proved =
        bus::ProveV5QueryIndexLeafSplitRapV1(
            full, child, child_seed,
            plan, lane0_leaf);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_CHECK_EQUAL(proved.proof.lane, 0U);
    BOOST_CHECK_GT(proved.proof.queries.size(), 0U);
    BOOST_CHECK_LE(
        proved.proof.queries.size(),
        bus::kV5QueryIndexLeafMaxQueriesV1);
    BOOST_CHECK_EQUAL(
        proved.proof.proof_owned_v5_cells,
        proved.proof.queries.size());
    BOOST_CHECK_EQUAL(
        proved.proof.recursively_consumed_v5_cells, 0U);

    std::string why;
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5QueryIndexLeafSplitRapV1(
            full, child, child_seed, plan,
            lane0_leaf, proved.proof, &why),
        why);
    BOOST_CHECK(
        !bus::VerifyV5QueryIndexLeafSplitRapV1(
            full, child, child_seed, plan,
            lane1_leaf, proved.proof, &why));

    auto query_replay = proved.proof;
    ++query_replay.first_query;
    BOOST_CHECK(
        !bus::VerifyV5QueryIndexLeafSplitRapV1(
            full, child, child_seed, plan,
            lane0_leaf, query_replay, &why));

    if (proved.proof.queries.size() > 1) {
        auto order_attack = proved.proof;
        std::swap(
            order_attack.queries[0],
            order_attack.queries[1]);
        std::swap(
            order_attack.query_proofs[0],
            order_attack.query_proofs[1]);
        std::swap(
            order_attack.proved_indices[0],
            order_attack.proved_indices[1]);
        std::swap(
            order_attack.v5_semantic_rows[0],
            order_attack.v5_semantic_rows[1]);
        BOOST_CHECK(
            !bus::VerifyV5QueryIndexLeafSplitRapV1(
                full, child, child_seed, plan,
                lane0_leaf, order_attack, &why));
    }

    auto omission = proved.proof;
    omission.queries.pop_back();
    omission.query_proofs.pop_back();
    omission.proved_indices.pop_back();
    omission.v5_semantic_rows.pop_back();
    --omission.proof_owned_v5_cells;
    BOOST_CHECK(
        !bus::VerifyV5QueryIndexLeafSplitRapV1(
            full, child, child_seed, plan,
            lane0_leaf, omission, &why));

    auto index_attack = proved.proof;
    index_attack.proved_indices[0] =
        child.batch.repeated.lane[0]
            .row_commit.n_leaves;
    BOOST_CHECK(
        !bus::VerifyV5QueryIndexLeafSplitRapV1(
            full, child, child_seed, plan,
            lane0_leaf, index_attack, &why));

    auto attachments = empty;
    BOOST_CHECK_MESSAGE(
        bus::AttachV5QueryIndexLeafSplitRapV1(
            full, child, child_seed, plan,
            proved.proof, attachments, &why),
        why);
    BOOST_REQUIRE_EQUAL(attachments.proofs.size(), 1U);
    BOOST_CHECK_EQUAL(
        attachments.proof_owned_cells,
        proved.proof.queries.size());
    BOOST_CHECK_EQUAL(
        attachments.recursively_consumed_cells, 0U);
    BOOST_CHECK(
        !attachments.production_authority_ready);
    BOOST_CHECK(
        !bus::AttachV5QueryIndexLeafSplitRapV1(
            full, child, child_seed, plan,
            proved.proof, attachments, &why));

    std::vector<unsigned char> wire;
    BOOST_REQUIRE_GT(
        bus::SerializeV5TranscriptProofAttachmentBundleV1(
            plan, attachments, wire),
        0U);
    const auto decoded =
        bus::DeserializeV5TranscriptProofAttachmentBundleV1(
            plan, wire);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            *decoded, &why),
        why);
}

BOOST_AUTO_TEST_CASE(
    unified_v5_sha_receipt_exact_304_local_coverage_roundtrip)
{
    const char* enabled =
        std::getenv("BTX_RUN_STAGE3_UNIFIED_SHA_RECEIPT");
    if (enabled == nullptr ||
        std::string{enabled} != "1") {
        BOOST_TEST_MESSAGE(
            "Unified V5 SHA receipt roundtrip skipped "
            "(BTX_RUN_STAGE3_UNIFIED_SHA_RECEIPT!=1)");
        return;
    }
    const auto child_cs = ToyChildCS();
    const uint256 child_seed = Seed(64);
    const auto child =
        ToyDualProof(child_cs, child_seed);
    const auto full =
        bus::BuildSameTraceComposition(
            child_cs, child, child_seed,
            PublicBoundary(),
            bus::TranscriptScope::FullTranscript,
            {});
    BOOST_REQUIRE_MESSAGE(full.valid, full.note);
    const auto plan =
        bus::BuildV5FullTranscriptWitnessShardPlan(
            full, child, child_seed);
    BOOST_REQUIRE_MESSAGE(plan.valid, plan.note);
    auto attachments =
        bus::BuildV5TranscriptProofAttachmentBundleV1(
            plan);
    BOOST_REQUIRE_MESSAGE(
        attachments.valid, attachments.note);
    std::string why;

    for (uint32_t lane = 0; lane < 2; ++lane) {
        for (uint32_t item = 0; item < 2; ++item) {
            auto prefix =
                bus::BuildV5BatchCoefficientDrawWitnessPrefix(
                    full, child, child_seed, lane, item);
            BOOST_REQUIRE_MESSAGE(prefix.valid, prefix.note);
            const auto proved =
                bus::ProveV5FirstUniformSplitRap(prefix);
            BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
            BOOST_REQUIRE_MESSAGE(
                bus::AttachV5BatchCoefficientDrawSplitRapV1(
                    full, child, child_seed, plan,
                    lane, item, proved.proof,
                    attachments, &why),
                why);
        }
        for (uint32_t point = 0; point < 2; ++point) {
            const auto proved =
                bus::ProveV5OodPointSplitRapV1(
                    full, child, child_seed,
                    lane, point);
            BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
            BOOST_REQUIRE_MESSAGE(
                bus::AttachV5OodPointSplitRapV1(
                    full, child, child_seed, plan,
                    lane, point, proved.proof,
                    attachments, &why),
                why);
        }
        for (uint32_t item = 0; item < 2; ++item) {
            auto prefix =
                bus::BuildV5DeepWeightDrawWitnessPrefix(
                    full, child, child_seed, lane, item);
            BOOST_REQUIRE_MESSAGE(prefix.valid, prefix.note);
            const auto proved =
                bus::ProveV5FirstUniformSplitRap(prefix);
            BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
            BOOST_REQUIRE_MESSAGE(
                bus::AttachV5DeepWeightSplitRapV1(
                    full, child, child_seed, plan,
                    lane, item, proved.proof,
                    attachments, &why),
                why);
        }
        auto fold_prefix =
            bus::BuildV5FoldChallengeDrawWitnessPrefix(
                full, child, child_seed, lane, 0);
        BOOST_REQUIRE_MESSAGE(
            fold_prefix.valid, fold_prefix.note);
        const auto fold_proved =
            bus::ProveV5FirstUniformSplitRap(
                fold_prefix);
        BOOST_REQUIRE_MESSAGE(
            fold_proved.ok, fold_proved.note);
        BOOST_REQUIRE_MESSAGE(
            bus::AttachV5FoldChallengeSplitRapV1(
                full, child, child_seed, plan,
                lane, 0, fold_proved.proof,
                attachments, &why),
            why);
    }

    for (const auto& leaf : attachments.leaves) {
        const bool has_query =
            std::any_of(
                leaf.consumer_semantic_rows.begin(),
                leaf.consumer_semantic_rows.end(),
                [&](uint32_t row) {
                    return row < attachments.consumers.size() &&
                        attachments.consumers[row].family ==
                            bus::ChallengeFeedbackFamily::
                                QueryIndex;
                });
        if (!has_query) continue;
        const auto proved =
            bus::ProveV5QueryIndexLeafSplitRapV1(
                full, child, child_seed,
                plan, leaf.leaf_ordinal);
        BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
        BOOST_REQUIRE_MESSAGE(
            bus::AttachV5QueryIndexLeafSplitRapV1(
                full, child, child_seed, plan,
                proved.proof, attachments, &why),
            why);
    }
    BOOST_REQUIRE_EQUAL(
        attachments.proof_owned_cells,
        bus::kV5TranscriptWithQueryProofOwnedCellsV1);
    BOOST_REQUIRE_EQUAL(
        attachments.pending_cells,
        bus::kV5TranscriptAirQuotientPendingCellsV1);

    const auto sha =
        bus::BuildV5ShaProducedFeedbackComposition(
            full, child_seed);
    BOOST_REQUIRE_MESSAGE(sha.valid, sha.note);
    const auto sha_proved =
        aq::AirQuotientProve<gf::Fp3>(
            sha.combined, sha.combined_columns,
            sha.combined_air_seed, {});
    BOOST_REQUIRE_MESSAGE(
        sha_proved.ok && sha_proved.division_exact,
        sha_proved.note);

    const auto receipt =
        bus::BuildV5UnifiedShaReceiptV1(
            full, child, child_seed, plan,
            attachments, sha_proved.proof);
    BOOST_REQUIRE_MESSAGE(receipt.valid, receipt.note);
    BOOST_CHECK_EQUAL(
        receipt.split_rap_local_cells, 298U);
    BOOST_CHECK_EQUAL(receipt.same_parent_sha_cells, 6U);
    BOOST_CHECK_EQUAL(
        receipt.proof_owned_local_cells, 304U);
    BOOST_CHECK_EQUAL(
        receipt.normalized_recursive_cells, 0U);
    BOOST_CHECK_EQUAL(
        receipt.direct_v6_feedback_cells, 0U);
    BOOST_CHECK_EQUAL(
        receipt.pending_normalized_recursive_cells, 304U);
    BOOST_CHECK(receipt.exact_disjoint_304_coverage);
    BOOST_CHECK(receipt.complete_local_sha_transcript_proof);
    BOOST_CHECK_EQUAL(
        receipt.encoded_airq_proof_bytes,
        ProofBytes(sha_proved.proof) + 12U);
    BOOST_CHECK(
        !receipt.normalized_recursive_consumption_complete);
    BOOST_CHECK(!receipt.production_authority_ready);
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5UnifiedShaReceiptV1(
            full, child, child_seed, plan,
            receipt, &why),
        why);

    const auto compatibility =
        bus::BuildV6ShaCompatibilityModeV1(
            full, child, child_seed, plan, receipt);
    BOOST_REQUIRE_MESSAGE(
        compatibility.valid, compatibility.note);
    BOOST_CHECK_EQUAL(
        compatibility.semantic_cells, 304U);
    BOOST_CHECK_EQUAL(
        compatibility.local_direct_feedback_cells, 304U);
    BOOST_CHECK_EQUAL(
        compatibility.normalized_recursive_cells, 0U);
    BOOST_CHECK_EQUAL(
        compatibility.pending_normalized_recursive_cells,
        304U);
    BOOST_CHECK_EQUAL(
        compatibility.trace_columns,
        bus::kV6ShaCompatibilityColumns);
    BOOST_CHECK(
        compatibility.unified_receipt_publicly_verified);
    BOOST_CHECK(compatibility.exact_schedule_and_order);
    BOOST_CHECK(compatibility.exact_statement_equality);
    BOOST_CHECK(compatibility.exact_seed_equality);
    BOOST_CHECK(
        compatibility
            .receipt_outputs_drive_normalized_v5_equations);
    BOOST_CHECK(
        compatibility.legacy_alghash_semantics_unchanged);
    BOOST_CHECK(
        compatibility.alghash_domain_substitution_rejected);
    BOOST_CHECK(
        !compatibility
             .normalized_recursive_consumption_complete);
    BOOST_CHECK(!compatibility.production_authority_ready);
    BOOST_CHECK_EQUAL(
        v6::CountViolations(
            compatibility.constraint_system,
            compatibility.witness_columns),
        0U);
    BOOST_CHECK_MESSAGE(
        bus::VerifyV6ShaCompatibilityModeV1(
            full, child, child_seed, plan, receipt,
            compatibility, &why),
        why);

    const auto legacy_substitution =
        bus::BuildV6ShaCompatibilityModeV1(
            full, child, child_seed, plan, receipt,
            bus::V6ChallengeSourceDomainV1::
                LegacyAlgHash);
    BOOST_CHECK(!legacy_substitution.valid);
    BOOST_CHECK(
        legacy_substitution
            .alghash_domain_substitution_rejected);

    auto domain_attack = compatibility;
    domain_attack.challenge_source_domain =
        bus::V6ChallengeSourceDomainV1::LegacyAlgHash;
    BOOST_CHECK(
        !bus::VerifyV6ShaCompatibilityModeV1(
            full, child, child_seed, plan, receipt,
            domain_attack, &why));

    auto order_attack = compatibility;
    std::swap(
        order_attack.cells[0],
        order_attack.cells[1]);
    BOOST_CHECK(
        !bus::VerifyV6ShaCompatibilityModeV1(
            full, child, child_seed, plan, receipt,
            order_attack, &why));

    auto statement_attack = compatibility;
    statement_attack.public_schedule_statement.begin()[0] ^=
        1U;
    BOOST_CHECK(
        !bus::VerifyV6ShaCompatibilityModeV1(
            full, child, child_seed, plan, receipt,
            statement_attack, &why));

    auto seed_attack = compatibility;
    seed_attack.child_fs_seed.begin()[0] ^= 1U;
    BOOST_CHECK(
        !bus::VerifyV6ShaCompatibilityModeV1(
            full, child, child_seed, plan, receipt,
            seed_attack, &why));

    auto value_attack = compatibility;
    value_attack.witness_columns[
        bus::kV6ShaCompatibilityNormalizedInput][0] =
            gf::Add(
                value_attack.witness_columns[
                    bus::kV6ShaCompatibilityNormalizedInput][0],
                gf::Fp3::One());
    BOOST_CHECK_GT(
        v6::CountViolations(
            value_attack.constraint_system,
            value_attack.witness_columns),
        0U);
    BOOST_CHECK(
        !bus::VerifyV6ShaCompatibilityModeV1(
            full, child, child_seed, plan, receipt,
            value_attack, &why));

    std::vector<unsigned char> wire;
    BOOST_REQUIRE_GT(
        bus::SerializeV5UnifiedShaReceiptV1(
            receipt, wire),
        0U);
    const auto decoded =
        bus::DeserializeV5UnifiedShaReceiptV1(
            plan, wire);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(
        !decoded->attached_proofs_publicly_verified);
    BOOST_CHECK(
        !decoded->airq_sha_proof_publicly_verified);
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5UnifiedShaReceiptV1(
            full, child, child_seed, plan,
            *decoded, &why),
        why);

    auto byte_attack = wire;
    byte_attack[byte_attack.size() / 2] ^= 1U;
    const auto attacked =
        bus::DeserializeV5UnifiedShaReceiptV1(
            plan, byte_attack);
    if (attacked.has_value()) {
        BOOST_CHECK(
            !bus::VerifyV5UnifiedShaReceiptV1(
                full, child, child_seed, plan,
                *attacked, &why));
    }
    BOOST_CHECK(
        !bus::VerifyV5UnifiedShaReceiptV1(
            full, child, Seed(65), plan,
            receipt, &why));

    const auto airq_split =
        bus::ProveV5AirLambdaSplitRapV1(
            full, child_seed);
    BOOST_REQUIRE_MESSAGE(
        airq_split.valid, airq_split.note);
    BOOST_CHECK_EQUAL(
        airq_split.locally_proved_cells, 6U);
    BOOST_CHECK_EQUAL(
        airq_split.normalized_recursive_cells, 0U);
    BOOST_CHECK_EQUAL(
        airq_split.r0_columns +
            airq_split.rdep_columns,
        airq_split.trace_columns);
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5AirLambdaSplitRapV1(
            full, child_seed, airq_split, &why),
        why);
    auto base_attack = airq_split;
    base_attack.base_column_indices.pop_back();
    BOOST_CHECK(
        !bus::VerifyV5AirLambdaSplitRapV1(
            full, child_seed, base_attack, &why));

    static_assert(
        bus::kV5AirLambdaArityParentSlotsV1 == 4);
    static_assert(
        bus::kV5AirLambdaArityParentGroupsV1 == 3);
    static_assert(
        bus::kV5AirLambdaArityParentNextGroupsV1 == 2);
    static_assert(
        bus::kV5AirLambdaArityParentOutputsV1 == 6);
    const auto airq_parent =
        bus::BuildV5AirLambdaArityParentContractV1(
            full, child_seed, airq_split);
    BOOST_REQUIRE_MESSAGE(
        airq_parent.valid, airq_parent.note);
    BOOST_CHECK_EQUAL(airq_parent.child_count, 1U);
    BOOST_CHECK_EQUAL(
        airq_parent.group_width[0],
        airq_split.r0_columns);
    BOOST_CHECK_EQUAL(
        airq_parent.group_width[1],
        airq_split.rdep_columns);
    BOOST_CHECK_EQUAL(
        airq_parent.group_width[2], 1U);
    for (uint32_t group = 0; group < 3; ++group) {
        BOOST_CHECK_EQUAL(
            airq_parent.current_group_openings[group],
            airq_split.quotient.batch.queries.size());
    }
    for (uint32_t group = 0; group < 2; ++group) {
        BOOST_CHECK_EQUAL(
            airq_parent.next_group_openings[group],
            airq_split.quotient.batch.queries.size());
    }
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const auto& lambda =
            full.lane_pis[lane].air_lambda;
        BOOST_CHECK(gf::Eq(
            airq_parent.outputs[lane * 3 + 0],
            gf::Fp3::FromFp(lambda.c0)));
        BOOST_CHECK(gf::Eq(
            airq_parent.outputs[lane * 3 + 1],
            gf::Fp3::FromFp(lambda.c1)));
        BOOST_CHECK(gf::Eq(
            airq_parent.outputs[lane * 3 + 2],
            gf::Fp3::FromFp(lambda.c2)));
    }
    BOOST_CHECK_EQUAL(
        airq_parent.public_statement,
        airq_split.semantic_boundary_commitment);
    BOOST_CHECK_EQUAL(
        airq_parent.verifier_seed,
        airq_split.combined_air_seed);
    BOOST_CHECK_EQUAL(
        airq_parent.child_commitment[0],
        airq_split.proof_statement);
    BOOST_CHECK(
        airq_parent.child_commitment[1] !=
        airq_parent.child_commitment[2]);
    BOOST_CHECK(
        airq_parent.child_commitment[2] !=
        airq_parent.child_commitment[3]);
    BOOST_CHECK(airq_parent.codec_canonical);
    BOOST_CHECK(airq_parent.canonical_padding);
    BOOST_CHECK(airq_parent.verifier_api_pending);
    BOOST_CHECK_EQUAL(
        airq_parent.normalized_recursive_cells, 0U);
    BOOST_CHECK_MESSAGE(
        bus::ValidateV5AirLambdaArityParentContractV1(
            full, child_seed, airq_split,
            airq_parent, &why),
        why);

    auto parent_attack = airq_parent;
    parent_attack.child_count = 2;
    BOOST_CHECK(
        !bus::ValidateV5AirLambdaArityParentContractV1(
            full, child_seed, airq_split,
            parent_attack, &why));
    parent_attack = airq_parent;
    ++parent_attack.group_width[0];
    BOOST_CHECK(
        !bus::ValidateV5AirLambdaArityParentContractV1(
            full, child_seed, airq_split,
            parent_attack, &why));
    parent_attack = airq_parent;
    ++parent_attack.current_group_openings[1];
    BOOST_CHECK(
        !bus::ValidateV5AirLambdaArityParentContractV1(
            full, child_seed, airq_split,
            parent_attack, &why));
    parent_attack = airq_parent;
    ++parent_attack.next_group_openings[0];
    BOOST_CHECK(
        !bus::ValidateV5AirLambdaArityParentContractV1(
            full, child_seed, airq_split,
            parent_attack, &why));
    parent_attack = airq_parent;
    parent_attack.outputs[5] =
        gf::Add(
            parent_attack.outputs[5],
            gf::Fp3::One());
    BOOST_CHECK(
        !bus::ValidateV5AirLambdaArityParentContractV1(
            full, child_seed, airq_split,
            parent_attack, &why));
    parent_attack = airq_parent;
    parent_attack.public_statement.begin()[0] ^= 1U;
    BOOST_CHECK(
        !bus::ValidateV5AirLambdaArityParentContractV1(
            full, child_seed, airq_split,
            parent_attack, &why));
    parent_attack = airq_parent;
    parent_attack.verifier_seed.begin()[0] ^= 1U;
    BOOST_CHECK(
        !bus::ValidateV5AirLambdaArityParentContractV1(
            full, child_seed, airq_split,
            parent_attack, &why));
    parent_attack = airq_parent;
    parent_attack.child_commitment[2] =
        parent_attack.child_commitment[1];
    BOOST_CHECK(
        !bus::ValidateV5AirLambdaArityParentContractV1(
            full, child_seed, airq_split,
            parent_attack, &why));
    parent_attack = airq_parent;
    parent_attack.normalized_recursive_cells = 6;
    BOOST_CHECK(
        !bus::ValidateV5AirLambdaArityParentContractV1(
            full, child_seed, airq_split,
            parent_attack, &why));
    parent_attack = airq_parent;
    parent_attack.verifier_api_pending = false;
    BOOST_CHECK(
        !bus::ValidateV5AirLambdaArityParentContractV1(
            full, child_seed, airq_split,
            parent_attack, &why));
    parent_attack = airq_parent;
    parent_attack.codec_canonical = false;
    BOOST_CHECK(
        !bus::ValidateV5AirLambdaArityParentContractV1(
            full, child_seed, airq_split,
            parent_attack, &why));

    const auto recursive_plan =
        bus::BuildV5UnifiedShaRecursivePlanV1(
            full, child, child_seed, plan,
            receipt, airq_split);
    BOOST_REQUIRE_MESSAGE(
        recursive_plan.valid,
        recursive_plan.note);
    BOOST_CHECK_EQUAL(
        recursive_plan.total_leaf_children, 58U);
    BOOST_CHECK_EQUAL(
        recursive_plan.aggregation_levels, 3U);
    BOOST_CHECK_EQUAL(
        recursive_plan.aggregation_parent_nodes, 20U);
    BOOST_CHECK(
        recursive_plan.exact_arity_four_schedule);
    BOOST_CHECK(
        recursive_plan
            .canonical_empty_children_domain_bound);
    BOOST_CHECK(
        !recursive_plan
             .recursive_schedule_commitment.IsNull());
    BOOST_CHECK(
        recursive_plan.all_child_codecs_durable);
    BOOST_CHECK(
        recursive_plan.airq_split_rap_locally_verified);
    BOOST_CHECK_EQUAL(
        recursive_plan.locally_proof_owned_cells, 304U);
    BOOST_CHECK_EQUAL(
        recursive_plan.normalized_recursive_cells, 0U);
    BOOST_CHECK_EQUAL(
        recursive_plan.pending_normalized_recursive_cells,
        304U);
    BOOST_CHECK(
        !recursive_plan.parent_verifier_air_executable);
    BOOST_CHECK(
        !recursive_plan.production_authority_ready);
    BOOST_CHECK_EQUAL(
        recursive_plan.residuals.size(), 3U);
}

BOOST_AUTO_TEST_CASE(
    deep_and_fold_split_rap_public_only_roundtrip)
{
    const char* enabled =
        std::getenv(
            "BTX_RUN_STAGE3_DEEP_FOLD_SPLIT_RAP");
    if (enabled == nullptr ||
        std::string{enabled} != "1") {
        BOOST_TEST_MESSAGE(
            "DEEP/fold Split-RAP roundtrip skipped "
            "(BTX_RUN_STAGE3_DEEP_FOLD_SPLIT_RAP!=1)");
        return;
    }
    const auto child_cs = ToyChildCS();
    const uint256 child_seed = Seed(62);
    const auto child =
        ToyDualProof(child_cs, child_seed);
    const bus::SameTraceComposition full =
        bus::BuildSameTraceComposition(
            child_cs, child, child_seed,
            PublicBoundary(),
            bus::TranscriptScope::FullTranscript,
            {});
    BOOST_REQUIRE_MESSAGE(full.valid, full.note);
    const auto plan =
        bus::BuildV5FullTranscriptWitnessShardPlan(
            full, child, child_seed);
    BOOST_REQUIRE_MESSAGE(plan.valid, plan.note);
    auto attachments =
        bus::BuildV5TranscriptProofAttachmentBundleV1(
            plan);
    BOOST_REQUIRE_MESSAGE(
        attachments.valid, attachments.note);

    std::string why;
    std::optional<bus::V5FirstUniformSplitRapProof>
        first_deep;
    for (uint32_t lane = 0; lane < 2; ++lane) {
        for (uint32_t item = 0; item < 2; ++item) {
            auto prefix =
                bus::BuildV5DeepWeightDrawWitnessPrefix(
                    full, child, child_seed, lane, item);
            BOOST_REQUIRE_MESSAGE(prefix.valid, prefix.note);
            const auto proved =
                bus::ProveV5FirstUniformSplitRap(prefix);
            BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
            prefix = {};
            BOOST_CHECK_MESSAGE(
                bus::VerifyV5DeepWeightDrawSplitRap(
                    full, child, child_seed,
                    lane, item, proved.proof, &why),
                why);
            BOOST_CHECK(
                !bus::VerifyV5DeepWeightDrawSplitRap(
                    full, child, child_seed,
                    1 - lane, item,
                    proved.proof, &why));
            BOOST_CHECK(
                !bus::VerifyV5DeepWeightDrawSplitRap(
                    full, child, child_seed,
                    lane, 1 - item,
                    proved.proof, &why));
            BOOST_CHECK_MESSAGE(
                bus::AttachV5DeepWeightSplitRapV1(
                    full, child, child_seed, plan,
                    lane, item, proved.proof,
                    attachments, &why),
                why);
            if (!first_deep.has_value()) {
                first_deep = proved.proof;
            }
        }
    }
    BOOST_REQUIRE(first_deep.has_value());
    BOOST_CHECK(
        !bus::VerifyV5FoldChallengeDrawSplitRap(
            full, child, child_seed, 0, 0,
            *first_deep, &why));

    for (uint32_t lane = 0; lane < 2; ++lane) {
        auto prefix =
            bus::BuildV5FoldChallengeDrawWitnessPrefix(
                full, child, child_seed, lane, 0);
        BOOST_REQUIRE_MESSAGE(prefix.valid, prefix.note);
        const auto proved =
            bus::ProveV5FirstUniformSplitRap(prefix);
        BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
        prefix = {};
        BOOST_CHECK_MESSAGE(
            bus::VerifyV5FoldChallengeDrawSplitRap(
                full, child, child_seed,
                lane, 0, proved.proof, &why),
            why);
        BOOST_CHECK(
            !bus::VerifyV5FoldChallengeDrawSplitRap(
                full, child, child_seed,
                1 - lane, 0, proved.proof, &why));
        BOOST_CHECK(
            !bus::VerifyV5DeepWeightDrawSplitRap(
                full, child, child_seed,
                lane, 0, proved.proof, &why));
        BOOST_CHECK_MESSAGE(
            bus::AttachV5FoldChallengeSplitRapV1(
                full, child, child_seed, plan,
                lane, 0, proved.proof,
                attachments, &why),
            why);
    }
    BOOST_REQUIRE_EQUAL(attachments.proofs.size(), 6U);
    BOOST_CHECK_EQUAL(
        attachments.proof_owned_cells, 18U);
    BOOST_CHECK_EQUAL(
        attachments.algebraically_bound_output_cells, 18U);
    BOOST_CHECK_EQUAL(
        attachments.recursively_consumed_cells, 0U);
    BOOST_CHECK_EQUAL(attachments.pending_cells, 286U);
    BOOST_CHECK(
        !attachments.production_authority_ready);
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            attachments, &why),
        why);

    auto omitted = attachments;
    omitted.proofs.pop_back();
    BOOST_CHECK(
        !bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            omitted, &why));
    auto reordered = attachments;
    std::swap(
        reordered.proofs[0], reordered.proofs[1]);
    BOOST_CHECK(
        !bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            reordered, &why));
    BOOST_CHECK(
        !bus::AttachV5DeepWeightSplitRapV1(
            full, child, child_seed, plan,
            0, 0, *first_deep,
            attachments, &why));

    std::vector<unsigned char> wire;
    BOOST_REQUIRE_GT(
        bus::SerializeV5TranscriptProofAttachmentBundleV1(
            plan, attachments, wire),
        0U);
    const auto decoded =
        bus::DeserializeV5TranscriptProofAttachmentBundleV1(
            plan, wire);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            *decoded, &why),
        why);
}

BOOST_AUTO_TEST_CASE(
    ood_first_valid_split_rap_public_only_roundtrip)
{
    const char* enabled =
        std::getenv("BTX_RUN_STAGE3_OOD_SPLIT_RAP");
    if (enabled == nullptr ||
        std::string{enabled} != "1") {
        BOOST_TEST_MESSAGE(
            "OOD first-valid Split-RAP roundtrip skipped "
            "(BTX_RUN_STAGE3_OOD_SPLIT_RAP!=1)");
        return;
    }
    const auto child_cs = ToyChildCS();
    const uint256 child_seed = Seed(61);
    const auto child =
        ToyDualProof(child_cs, child_seed);
    const bus::SameTraceComposition full =
        bus::BuildSameTraceComposition(
            child_cs, child, child_seed,
            PublicBoundary(),
            bus::TranscriptScope::FullTranscript,
            {});
    BOOST_REQUIRE_MESSAGE(full.valid, full.note);

    const auto proved =
        bus::ProveV5OodPointSplitRapV1(
            full, child, child_seed, 0, 1);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_CHECK_EQUAL(proved.proof.lane, 0U);
    BOOST_CHECK_EQUAL(proved.proof.point, 1U);
    BOOST_CHECK_GE(
        proved.proof.selected_candidate, 2U);
    BOOST_CHECK_EQUAL(
        proved.proof.proof_owned_v5_cells, 3U);
    BOOST_CHECK_EQUAL(
        proved.proof.recursively_consumed_v5_cells, 0U);
    BOOST_CHECK(
        !proved.proof.full_304_transcript);

    std::string why;
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5OodPointSplitRapV1(
            full, child, child_seed, 0, 1,
            proved.proof, &why),
        why);
    BOOST_CHECK(
        !bus::VerifyV5OodPointSplitRapV1(
            full, child, child_seed, 1, 1,
            proved.proof, &why));
    BOOST_CHECK(
        !bus::VerifyV5OodPointSplitRapV1(
            full, child, child_seed, 0, 0,
            proved.proof, &why));

    auto candidate_swap = proved.proof;
    std::swap(
        candidate_swap.candidate_proofs[0],
        candidate_swap.candidate_proofs[1]);
    std::swap(
        candidate_swap.proved_candidates[0],
        candidate_swap.proved_candidates[1]);
    BOOST_CHECK(
        !bus::VerifyV5OodPointSplitRapV1(
            full, child, child_seed, 0, 1,
            candidate_swap, &why));

    auto candidate_omission = proved.proof;
    candidate_omission.candidate_proofs[0] = {};
    BOOST_CHECK(
        !bus::VerifyV5OodPointSplitRapV1(
            full, child, child_seed, 0, 1,
            candidate_omission, &why));

    auto export_attack = proved.proof;
    export_attack.proved_v5_exports[0] =
        gf::Add(
            export_attack.proved_v5_exports[0],
            gf::Fp3::One());
    BOOST_CHECK(
        !bus::VerifyV5OodPointSplitRapV1(
            full, child, child_seed, 0, 1,
            export_attack, &why));

    const auto plan =
        bus::BuildV5FullTranscriptWitnessShardPlan(
            full, child, child_seed);
    BOOST_REQUIRE_MESSAGE(plan.valid, plan.note);
    auto attachments =
        bus::BuildV5TranscriptProofAttachmentBundleV1(
            plan);
    BOOST_REQUIRE_MESSAGE(
        attachments.valid, attachments.note);
    BOOST_CHECK_MESSAGE(
        bus::AttachV5OodPointSplitRapV1(
            full, child, child_seed, plan,
            0, 1, proved.proof, attachments, &why),
        why);
    BOOST_REQUIRE_EQUAL(attachments.proofs.size(), 1U);
    BOOST_CHECK(
        attachments.proofs[0].kind ==
        bus::V5TranscriptLeafProofKindV1::
            OodPointSplitRap);
    BOOST_CHECK_EQUAL(attachments.proof_owned_cells, 3U);
    BOOST_CHECK_EQUAL(
        attachments.algebraically_bound_output_cells, 3U);
    BOOST_CHECK_EQUAL(
        attachments.recursively_consumed_cells, 0U);
    BOOST_CHECK_EQUAL(attachments.pending_cells, 301U);
    BOOST_CHECK(
        !attachments.production_authority_ready);
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            attachments, &why),
        why);

    std::vector<unsigned char> wire;
    BOOST_REQUIRE_GT(
        bus::SerializeV5TranscriptProofAttachmentBundleV1(
            plan, attachments, wire),
        0U);
    const auto decoded =
        bus::DeserializeV5TranscriptProofAttachmentBundleV1(
            plan, wire);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_MESSAGE(
        bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            *decoded, &why),
        why);

    auto item_swap = attachments;
    item_swap.proofs[0].batch_item = 0;
    BOOST_CHECK(
        !bus::VerifyV5TranscriptProofAttachmentBundleV1(
            full, child, child_seed, plan,
            item_swap, &why));
}

BOOST_AUTO_TEST_CASE(
    production_shard_w26_master_bus_fits_recursive_width_cap)
{
    constexpr uint32_t WIDTH = 26;
    const auto child_cs = WideBooleanChildCS(WIDTH);
    const uint256 child_seed = Seed(51);
    std::vector<std::vector<gf::Fp3>> columns(
        WIDTH, std::vector<gf::Fp3>{
                   gf::Fp3::Zero(), gf::Fp3::One()});
    const auto proved = aq::AirQuotientProve<gf::Fp3, DualB3>(
        child_cs, columns, child_seed, {});
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact, proved.note);
    const ar::DualV5AggregateWitness v5 =
        ar::BuildDualV5AggregateWitness(
            child_cs, {proved.proof}, child_seed,
            RowRootFamilies());
    BOOST_REQUIRE_MESSAGE(v5.ok, v5.note);

    const bus::Shape shape = bus::MeasureSameTraceComposition(
        v5.normalized.pis, PublicBoundary(),
        bus::TranscriptScope::MasterBinding,
        RowRootFamilies());
    BOOST_REQUIRE_MESSAGE(shape.valid, shape.note);
    BOOST_CHECK_EQUAL(shape.v5_rows, 128U);
    BOOST_CHECK_EQUAL(shape.aligned_rows, 128U);
    BOOST_CHECK_EQUAL(
        shape.row_root_payload_cells_directly_aliased, 8U);
    BOOST_CHECK_LE(
        shape.combined_columns,
        matmul::v4::rc::kRCFri3AlgBatchMaxColumns);
    BOOST_TEST_MESSAGE(
        "W26 production-shard V5->V6 master bus: rows="
        << shape.aligned_rows
        << " v5_cols=" << shape.v5_columns
        << " combined_cols=" << shape.combined_columns
        << " constraints=" << shape.combined_constraints
        << " cells=" << shape.combined_cells
        << " width_cap="
        << matmul::v4::rc::kRCFri3AlgBatchMaxColumns);
}

BOOST_AUTO_TEST_SUITE_END()
