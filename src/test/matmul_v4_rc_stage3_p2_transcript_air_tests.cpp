// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_p2_transcript_air.h>
#include <matmul/matmul_v4_rc_stage3_p2_transcript_binding.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
namespace p2tx =
    matmul::v4::rc::stage3_p2_transcript_air;
namespace p2bind =
    matmul::v4::rc::stage3_p2_transcript_binding;
namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_p2_transcript_air_tests,
    BasicTestingSetup)

namespace {

p2tx::Statement TestStatement(uint32_t n_folds = 2)
{
    p2tx::Statement out;
    out.n_folds = n_folds;
    static constexpr unsigned char payload[] = {
        0x46, 0x42, 0x41, 0x33, // canonical proof-codec magic image
        0x08, 0x00, 0x00, 0x00, // source lane version (owned-link still open)
        0x10, 0x00, 0x00, 0x00,
        0x7d, 0xa1, 0x20, 0x4c,
        0x99, 0x00, 0xee, 0x31,
    };
    std::vector<p2tx::EventDescriptor> manifest;
    std::string why;
    if (!p2tx::CanonicalEventManifest(
            out, manifest, &why)) {
        return {};
    }
    for (const auto& event : manifest) {
        p2tx::EventPrefix prefix;
        prefix.kind = event.kind;
        prefix.semantic_index = event.semantic_index;
        prefix.bytes.assign(
            std::begin(payload), std::end(payload));
        uint32_t phase = 0;
        switch (event.kind) {
        case p2tx::EventKind::FriLambda:
            phase = 1;
            break;
        case p2tx::EventKind::OodZ1:
        case p2tx::EventKind::OodZ2:
            phase = 2;
            break;
        case p2tx::EventKind::DeepW1:
        case p2tx::EventKind::DeepW2:
            phase = 3;
            break;
        case p2tx::EventKind::Fold:
            phase = 10 + event.semantic_index;
            break;
        case p2tx::EventKind::Query:
            phase = 100;
            break;
        }
        prefix.bytes.push_back(
            static_cast<unsigned char>(phase));
        out.event_prefixes.push_back(
            std::move(prefix));
    }
    return out;
}

const std::vector<unsigned char>& EventPrefixBytes(
    const p2tx::Statement& statement,
    p2tx::EventKind kind,
    uint32_t semantic_index)
{
    for (const auto& prefix :
         statement.event_prefixes) {
        if (prefix.kind == kind &&
            prefix.semantic_index == semantic_index) {
            return prefix.bytes;
        }
    }
    throw std::runtime_error("missing event prefix");
}

uint256 Seed(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

uint32_t EventTerminalRow(
    const p2tx::BuildResult& built,
    p2tx::EventKind kind,
    uint32_t semantic_index)
{
    for (uint32_t row = 0; row < built.active_rows; ++row) {
        if (gf::Canonical(
                built.columns[
                    built.layout.terminal_col][row].c0) != 1) {
            continue;
        }
        if (gf::Canonical(
                built.columns[
                    built.layout.event_kind_col][row].c0) !=
                static_cast<uint32_t>(kind)) {
            continue;
        }
        if (gf::Canonical(
                built.columns[
                    built.layout.semantic_index_col][row].c0) ==
            semantic_index) {
            return row;
        }
    }
    return std::numeric_limits<uint32_t>::max();
}

std::pair<uint32_t, uint32_t> EventRowRange(
    const p2tx::BuildResult& built,
    uint32_t ordinal)
{
    uint32_t first = std::numeric_limits<uint32_t>::max();
    uint32_t last = std::numeric_limits<uint32_t>::max();
    for (uint32_t row = 0; row < built.active_rows; ++row) {
        if (gf::Canonical(
                built.columns[
                    built.layout.event_ordinal_col][row].c0) !=
            ordinal) {
            continue;
        }
        if (first == std::numeric_limits<uint32_t>::max()) {
            first = row;
        }
        last = row;
    }
    return {first, last};
}

} // namespace

BOOST_AUTO_TEST_CASE(v10_statement_is_prefix_free_and_fail_closed)
{
    const p2tx::Statement statement = TestStatement();
    std::vector<unsigned char> prefix;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        p2tx::CanonicalStatementPrefix(
            statement, prefix, &why),
        why);
    BOOST_CHECK(!prefix.empty());

    p2tx::Statement changed = statement;
    changed.event_prefixes[0].bytes.push_back(0);
    std::vector<unsigned char> changed_prefix;
    BOOST_REQUIRE(
        p2tx::CanonicalStatementPrefix(
            changed, changed_prefix, &why));
    BOOST_CHECK(prefix != changed_prefix);

    changed = statement;
    changed.version = 8;
    BOOST_CHECK(
        !p2tx::CanonicalStatementPrefix(
            changed, changed_prefix, &why));
    BOOST_CHECK(
        why.find("wrong_version") != std::string::npos);

    changed = statement;
    changed.queries = 191;
    BOOST_CHECK(
        !p2tx::CanonicalStatementPrefix(
            changed, changed_prefix, &why));
    BOOST_CHECK(
        why.find("wrong_query_count") != std::string::npos);

    changed = statement;
    changed.ood_candidates = 1;
    BOOST_CHECK(
        !p2tx::CanonicalStatementPrefix(
            changed, changed_prefix, &why));
    BOOST_CHECK(
        why.find("wrong_ood_window") != std::string::npos);

    changed = statement;
    changed.n_folds = 0;
    BOOST_CHECK(
        !p2tx::CanonicalStatementPrefix(
            changed, changed_prefix, &why));
    BOOST_CHECK(
        why.find("bad_fold_count") != std::string::npos);

    changed = statement;
    changed.query_modulus = 1000;
    BOOST_CHECK(
        !p2tx::CanonicalStatementPrefix(
            changed, changed_prefix, &why));
    BOOST_CHECK(
        why.find("query_modulus_not_power_of_two") !=
        std::string::npos);

    changed = statement;
    changed.event_prefixes[0].bytes.clear();
    BOOST_CHECK(
        !p2tx::CanonicalStatementPrefix(
            changed, changed_prefix, &why));
    BOOST_CHECK(
        why.find("bad_event_prefix_size") !=
        std::string::npos);

    changed = statement;
    changed.event_prefixes.erase(
        changed.event_prefixes.begin() + 2);
    BOOST_CHECK(
        !p2tx::CanonicalStatementPrefix(
            changed, changed_prefix, &why));
    BOOST_CHECK(
        why.find("event_prefix_schedule_size") !=
        std::string::npos);

    changed = statement;
    std::swap(
        changed.event_prefixes[1],
        changed.event_prefixes[2]);
    BOOST_CHECK(
        !p2tx::CanonicalStatementPrefix(
            changed, changed_prefix, &why));
    BOOST_CHECK(
        why.find("event_prefix_schedule_order") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    honest_k2_window_matches_native_p2_and_keeps_links_open)
{
    const p2tx::Statement statement = TestStatement();
    const p2tx::BuildResult built =
        p2tx::BuildOodWindowAirV10(statement);
    BOOST_REQUIRE_MESSAGE(built.valid, built.note);
    BOOST_CHECK(built.local_air_complete);
    BOOST_CHECK_EQUAL(built.violations, 0U);
    BOOST_CHECK_EQUAL(built.statement.version, 10U);
    BOOST_CHECK_EQUAL(built.statement.queries, 192U);
    BOOST_CHECK_EQUAL(
        built.statement.ood_candidates, 2U);
    BOOST_CHECK_GE(
        built.permutations_per_scalar_event, 2U);
    BOOST_CHECK_EQUAL(
        built.n_columns, built.layout.End());
    BOOST_CHECK_EQUAL(built.max_alg_degree, 3U);
    BOOST_CHECK(built.canonical_event_manifest);
    BOOST_CHECK(built.all_event_challenges_constrained);
    BOOST_CHECK(built.all_query_indices_constrained);
    BOOST_CHECK(built.z1_k2_selection_constrained);
    BOOST_CHECK(
        built.z2_k2_distinct_selection_constrained);
    BOOST_CHECK(
        built.selected_values_publicly_pinned);
    BOOST_REQUIRE_EQUAL(
        built.manifest.size(),
        5U + statement.n_folds + p2tx::kQueries);
    BOOST_REQUIRE_EQUAL(
        built.event_challenges.size(),
        built.manifest.size());
    BOOST_REQUIRE_EQUAL(
        built.query_indices.size(), p2tx::kQueries);

    const auto& z1_prefix = EventPrefixBytes(
        statement, p2tx::EventKind::OodZ1, 0);
    const auto& z2_prefix = EventPrefixBytes(
        statement, p2tx::EventKind::OodZ2, 1);
    for (uint32_t i = 0; i < p2tx::kOodCandidates; ++i) {
        const gf::Fp3 native =
            rc::Fri3AlgP2SqueezeChallengeFp3(
                z1_prefix, p2tx::kOodLabel,
                p2tx::kZ1FirstDrawIndex + i);
        BOOST_CHECK(
            gf::Eq(native, built.z_candidate[0][i]));
        const gf::Fp3 native_z2 =
            rc::Fri3AlgP2SqueezeChallengeFp3(
                z2_prefix, p2tx::kOodLabel,
                p2tx::kZ2FirstDrawIndex + i);
        BOOST_CHECK(
            gf::Eq(
                native_z2,
                built.z_candidate[1][i]));
    }
    const bool first_accepts =
        gf::Canonical(
            built.z_candidate[0][0].c1) != 0 ||
        gf::Canonical(
            built.z_candidate[0][0].c2) != 0;
    BOOST_CHECK(
        gf::Eq(
            built.selected_z1,
            first_accepts
                ? built.z_candidate[0][0]
                : built.z_candidate[0][1]));
    BOOST_CHECK(
        !gf::Eq(
            built.selected_z1,
            built.selected_z2));

    // These false values are load-bearing honesty, not missing test setup.
    BOOST_CHECK(!built.proof_owned_source_cells_bound);
    BOOST_CHECK(!built.recursive_consumer_cells_bound);
    BOOST_CHECK(!built.recursive_authority);
}

BOOST_AUTO_TEST_CASE(
    canonical_manifest_is_complete_ordered_and_constant_width)
{
    const p2tx::Statement statement = TestStatement();
    std::vector<p2tx::EventDescriptor> manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        p2tx::CanonicalEventManifest(
            statement, manifest, &why),
        why);
    BOOST_REQUIRE_EQUAL(
        manifest.size(),
        5U + statement.n_folds + p2tx::kQueries);
    BOOST_CHECK(
        manifest[0].kind ==
        p2tx::EventKind::FriLambda);
    BOOST_CHECK(
        manifest[1].kind ==
        p2tx::EventKind::OodZ1);
    BOOST_CHECK(
        manifest[2].kind ==
        p2tx::EventKind::OodZ2);
    BOOST_CHECK(
        manifest[5].kind ==
        p2tx::EventKind::Fold);
    BOOST_CHECK(
        manifest.back().kind ==
        p2tx::EventKind::Query);
    BOOST_CHECK_EQUAL(
        manifest.back().semantic_index,
        p2tx::kQueries - 1);
    BOOST_CHECK(
        p2tx::IsCanonicalEventManifest(
            statement, manifest, &why));

    auto omitted = manifest;
    omitted.erase(omitted.begin() + 5);
    BOOST_CHECK(
        !p2tx::IsCanonicalEventManifest(
            statement, omitted, &why));
    BOOST_CHECK(
        why.find("event_manifest_size") !=
        std::string::npos);

    auto reordered = manifest;
    std::swap(
        reordered[reordered.size() - 1],
        reordered[reordered.size() - 2]);
    BOOST_CHECK(
        !p2tx::IsCanonicalEventManifest(
            statement, reordered, &why));
    BOOST_CHECK(
        why.find("event_manifest_order") !=
        std::string::npos);

    const p2tx::Statement wider = TestStatement(7);
    const p2tx::BuildResult a =
        p2tx::BuildTranscriptAirV10(statement);
    const p2tx::BuildResult b =
        p2tx::BuildTranscriptAirV10(wider);
    BOOST_REQUIRE_MESSAGE(a.valid, a.note);
    BOOST_REQUIRE_MESSAGE(b.valid, b.note);
    BOOST_CHECK_EQUAL(a.n_columns, b.n_columns);
    BOOST_CHECK_GT(b.active_rows, a.active_rows);
}

BOOST_AUTO_TEST_CASE(all_rate_padding_residues_match_native_p2)
{
    for (uint32_t payload_size = 1;
         payload_size <= 32;
        ++payload_size) {
        p2tx::Statement statement = TestStatement();
        for (auto& prefix : statement.event_prefixes) {
            prefix.bytes.resize(payload_size);
            for (uint32_t i = 0; i < payload_size; ++i) {
                prefix.bytes[i] =
                    static_cast<unsigned char>(
                        19 * i + payload_size);
            }
        }
        const p2tx::BuildResult built =
            p2tx::BuildOodWindowAirV10(statement);
        BOOST_REQUIRE_MESSAGE(
            built.valid,
            "payload_size=" << payload_size
                << ": " << built.note);
        BOOST_CHECK_EQUAL(built.violations, 0U);

        const auto& prefix = EventPrefixBytes(
            statement, p2tx::EventKind::OodZ1, 0);
        for (uint32_t candidate = 0;
             candidate < p2tx::kOodCandidates;
             ++candidate) {
            BOOST_CHECK(
                gf::Eq(
                    built.z_candidate[0][candidate],
                    rc::Fri3AlgP2SqueezeChallengeFp3(
                        prefix, p2tx::kOodLabel,
                        p2tx::kZ1FirstDrawIndex +
                            candidate)));
        }
    }
}

BOOST_AUTO_TEST_CASE(
    genuine_v10_proof_prefix_schedule_matches_air_but_not_parent)
{
    std::vector<std::vector<gf::Fp3>> columns(
        1, std::vector<gf::Fp3>{
               gf::Fp3::FromFp(3),
               gf::Fp3::FromFp(5)});
    const uint256 seed = Seed(0x33);
    const auto source =
        rc::Fri3AlgP2Q192K2V10BatchCommit(
            columns, seed);
    BOOST_REQUIRE_MESSAGE(source.ok, source.note);

    const p2bind::BindingResult binding =
        p2bind::BuildProofOwnedTranscriptBindingV10(
            source.proof, seed);
    BOOST_REQUIRE_MESSAGE(binding.valid, binding.note);
    const p2tx::BuildResult built =
        p2tx::BuildOodWindowAirV10(
            binding.statement);
    BOOST_REQUIRE_MESSAGE(built.valid, built.note);
    BOOST_CHECK(built.local_air_complete);
    BOOST_CHECK_EQUAL(built.violations, 0U);
    std::vector<uint32_t> mismatches;
    std::string why;
    BOOST_CHECK(
        !p2bind::AssessLocalAirConsumerEqualityV10(
            binding, built, mismatches, &why));
    BOOST_CHECK(mismatches.empty());
    BOOST_CHECK(
        why.find("same_parent_cells_not_exported") !=
        std::string::npos);
    // The AIR itself does not own either side of the equality seam.
    BOOST_CHECK(!built.proof_owned_source_cells_bound);
    BOOST_CHECK(!built.recursive_consumer_cells_bound);
}

BOOST_AUTO_TEST_CASE(
    algebraic_z2_selector_manifest_and_query_attacks_reject)
{
    const p2tx::BuildResult built =
        p2tx::BuildOodWindowAirV10(TestStatement());
    BOOST_REQUIRE_MESSAGE(built.valid, built.note);
    const uint32_t z1_terminal = EventTerminalRow(
        built, p2tx::EventKind::OodZ1, 0);
    const uint32_t z2_terminal = EventTerminalRow(
        built, p2tx::EventKind::OodZ2, 1);
    const uint32_t fold0_terminal = EventTerminalRow(
        built, p2tx::EventKind::Fold, 0);
    const uint32_t query0_terminal = EventTerminalRow(
        built, p2tx::EventKind::Query, 0);
    BOOST_REQUIRE_NE(
        z1_terminal,
        std::numeric_limits<uint32_t>::max());
    BOOST_REQUIRE_NE(
        z2_terminal,
        std::numeric_limits<uint32_t>::max());
    BOOST_REQUIRE_NE(
        fold0_terminal,
        std::numeric_limits<uint32_t>::max());
    BOOST_REQUIRE_NE(
        query0_terminal,
        std::numeric_limits<uint32_t>::max());

    {
        auto forged = built.columns;
        forged[
            built.layout.MessageCol(0, 0)][0] =
            gf::Add(
                forged[
                    built.layout.MessageCol(0, 0)][0],
                gf::Fp3{1, 7, 11});
        BOOST_CHECK_GT(
            p2tx::CountViolations(built.cs, forged), 0U);
    }
    {
        auto forged = built.columns;
        forged[
            built.layout.candidate[1].X4Col(3)][0] =
            gf::Add(
                forged[
                    built.layout.candidate[1].X4Col(3)][0],
                gf::Fp3{3, 5, 9});
        BOOST_CHECK_GT(
            p2tx::CountViolations(built.cs, forged), 0U);
    }
    {
        auto forged = built.columns;
        // Terminal-only values are canonical zero elsewhere; future CTLs
        // cannot accidentally consume an unconstrained off-tag value.
        forged[built.layout.SelectedCol(0, 0)][0] =
            gf::Fp3::One();
        BOOST_CHECK_GT(
            p2tx::CountViolations(built.cs, forged), 0U);
    }
    {
        auto forged = built.columns;
        forged[
            built.layout.SelectedCol(1, 0)]
            [z2_terminal] =
            built.columns[
                built.layout.SelectedCol(0, 0)]
                [z1_terminal];
        forged[
            built.layout.SelectedCol(1, 1)]
            [z2_terminal] =
            built.columns[
                built.layout.SelectedCol(0, 1)]
                [z1_terminal];
        forged[
            built.layout.SelectedCol(1, 2)]
            [z2_terminal] =
            built.columns[
                built.layout.SelectedCol(0, 2)]
                [z1_terminal];
        BOOST_CHECK_GT(
            p2tx::CountViolations(built.cs, forged), 0U);
    }
    {
        auto forged = built.columns;
        forged[
            built.layout.EligibleCol(0)][z2_terminal] =
            gf::Sub(
                gf::Fp3::One(),
                forged[
                    built.layout.EligibleCol(0)]
                    [z2_terminal]);
        BOOST_CHECK_GT(
            p2tx::CountViolations(built.cs, forged), 0U);
    }
    {
        auto forged = built.columns;
        // Claim that candidate 0 equals z1 without changing the algebraically
        // carried z1 value or the Poseidon output.
        for (uint32_t coord = 0; coord < 3; ++coord) {
            forged[
                built.layout.DiffZeroCol(0, coord)]
                [z2_terminal] = gf::Fp3::One();
            forged[
                built.layout.DiffInverseCol(0, coord)]
                [z2_terminal] = gf::Fp3::Zero();
        }
        forged[
            built.layout.DiffAndCol(0, 0)]
            [z2_terminal] = gf::Fp3::One();
        forged[
            built.layout.DiffAndCol(0, 1)]
            [z2_terminal] = gf::Fp3::One();
        forged[
            built.layout.DistinctCol(0)]
            [z2_terminal] = gf::Fp3::Zero();
        BOOST_CHECK_GT(
            p2tx::CountViolations(built.cs, forged), 0U);
    }
    {
        auto forged = built.columns;
        forged[built.layout.query_index_col]
              [query0_terminal] =
            gf::Add(
                forged[built.layout.query_index_col]
                      [query0_terminal],
                gf::Fp3::One());
        BOOST_CHECK_GT(
            p2tx::CountViolations(built.cs, forged), 0U);
    }
    {
        auto forged = built.columns;
        // Omit the complete first fold event. The next start would jump two
        // ordinals, which the event progression identity rejects.
        const auto range = EventRowRange(built, 5);
        BOOST_REQUIRE_NE(
            range.first,
            std::numeric_limits<uint32_t>::max());
        for (uint32_t row = range.first;
             row <= range.second;
             ++row) {
            forged[built.layout.active_col][row] =
                gf::Fp3::Zero();
        }
        BOOST_CHECK_GT(
            p2tx::CountViolations(built.cs, forged), 0U);
    }
    {
        auto forged = built.columns;
        // Reorder two equal-shape query events while leaving their Poseidon
        // witnesses and tags in place. Sponge/message identities reject.
        const uint32_t query0_ordinal =
            5 + built.statement.n_folds;
        const auto first =
            EventRowRange(built, query0_ordinal);
        const auto second =
            EventRowRange(built, query0_ordinal + 1);
        BOOST_REQUIRE_EQUAL(
            first.second - first.first,
            second.second - second.first);
        for (uint32_t offset = 0;
             offset <= first.second - first.first;
             ++offset) {
            for (uint32_t candidate = 0;
                 candidate < p2tx::kOodCandidates;
                 ++candidate) {
                for (uint32_t lane = 0;
                     lane <
                     matmul::v4::rc::alg_hash::
                         kAlgHashRate;
                     ++lane) {
                    std::swap(
                        forged[
                            built.layout.MessageCol(
                                candidate, lane)]
                              [first.first + offset],
                        forged[
                            built.layout.MessageCol(
                                candidate, lane)]
                              [second.first + offset]);
                }
            }
        }
        BOOST_CHECK_GT(
            p2tx::CountViolations(built.cs, forged), 0U);
    }
    // Explicitly use the located fold terminal so a future manifest edit
    // cannot silently turn this into a non-fold-only test.
    BOOST_CHECK_LT(fold0_terminal, built.active_rows);
}

BOOST_AUTO_TEST_CASE(
    q192_rowwise_proof_accepts_and_opening_tamper_rejects)
{
    using Backend = aq::AirFriBackendAlg<gf::Fp3>;
    const p2tx::BuildResult built =
        p2tx::BuildOodWindowAirV10(TestStatement());
    BOOST_REQUIRE_MESSAGE(built.valid, built.note);

    const uint256 seed = Seed(0x5a);
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, Backend>(
            built.cs, built.columns, seed);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    BOOST_REQUIRE_EQUAL(
        proved.proof.batch.queries.size(),
        p2tx::kQueries);

    std::string why;
    BOOST_CHECK_MESSAGE(
        (aq::AirQuotientVerify<gf::Fp3, Backend>(
            built.cs, proved.proof, seed, &why)),
        why);

    // Reuse the canonical Q192 proof codec instead of inventing a V10-local
    // serializer. The batch proof remains the active, separately versioned
    // inner proximity proof; V10 versions this transcript-AIR statement.
    std::vector<unsigned char> encoded;
    const size_t written =
        rc::SerializeFri3AlgBatchProof(
            proved.proof.batch, encoded);
    BOOST_REQUIRE_EQUAL(written, encoded.size());
    BOOST_REQUIRE_GT(written, 0U);
    const auto decoded =
        rc::DeserializeFri3AlgBatchProof(encoded);
    BOOST_REQUIRE(decoded.has_value());
    auto roundtripped = proved.proof;
    roundtripped.batch = *decoded;
    why.clear();
    BOOST_CHECK_MESSAGE(
        (aq::AirQuotientVerify<gf::Fp3, Backend>(
            built.cs, roundtripped, seed, &why)),
        why);

    p2tx::Statement different_statement = TestStatement();
    different_statement.event_prefixes[0]
        .bytes[0] ^= 0x01;
    const p2tx::BuildResult different =
        p2tx::BuildOodWindowAirV10(different_statement);
    BOOST_REQUIRE_MESSAGE(different.valid, different.note);
    BOOST_REQUIRE_EQUAL(
        different.cs.n_columns, built.cs.n_columns);
    BOOST_REQUIRE_EQUAL(
        different.cs.n_rows, built.cs.n_rows);
    why.clear();
    BOOST_CHECK(
        !(aq::AirQuotientVerify<gf::Fp3, Backend>(
            different.cs, proved.proof, seed, &why)));
    BOOST_CHECK(!why.empty());

    for (const uint32_t pinned_column : {
             built.layout.active_col,
             built.layout.terminal_col,
             built.layout.event_ordinal_col,
             built.layout.event_kind_col,
             built.layout.semantic_index_col,
             built.layout.query_index_col}) {
        auto selector_forged = proved.proof;
        BOOST_REQUIRE(
            !selector_forged.batch.queries.empty());
        BOOST_REQUIRE_GT(
            selector_forged.batch.queries[0]
                .row.values.size(),
            pinned_column);
        selector_forged.batch.queries[0]
            .row.values[pinned_column] =
            gf::Add(
                selector_forged.batch.queries[0]
                    .row.values[pinned_column],
                gf::Fp3::One());
        why.clear();
        BOOST_CHECK(
            !(aq::AirQuotientVerify<gf::Fp3, Backend>(
                built.cs, selector_forged,
                seed, &why)));
        BOOST_CHECK(!why.empty());
    }

    // Proof-level candidate/selector and z2=z1 attacks. These mutate real
    // Q192 openings and are rejected by AirQuotientVerify, not merely by a
    // witness-domain diagnostic.
    for (const uint32_t attacked_column : {
             built.layout.ExtAcceptCol(0),
             built.layout.EligibleCol(0),
             built.layout.DiffZeroCol(0, 0),
             built.layout.SelectedCol(1, 0)}) {
        auto forged = proved.proof;
        BOOST_REQUIRE(!forged.batch.queries.empty());
        BOOST_REQUIRE_GT(
            forged.batch.queries[0].row.values.size(),
            attacked_column);
        forged.batch.queries[0]
            .row.values[attacked_column] =
            gf::Add(
                forged.batch.queries[0]
                    .row.values[attacked_column],
                gf::Fp3::One());
        why.clear();
        BOOST_CHECK(
            !(aq::AirQuotientVerify<gf::Fp3, Backend>(
                built.cs, forged, seed, &why)));
        BOOST_CHECK(!why.empty());
    }

    // Omitting a fold changes the canonical manifest and every subsequent
    // query ordinal. The same proof cannot verify under that statement even
    // when the power-of-two AIR shape remains unchanged.
    const p2tx::Statement omitted_fold =
        TestStatement(1);
    const p2tx::BuildResult omitted =
        p2tx::BuildTranscriptAirV10(omitted_fold);
    BOOST_REQUIRE_MESSAGE(omitted.valid, omitted.note);
    BOOST_REQUIRE_EQUAL(
        omitted.cs.n_columns, built.cs.n_columns);
    BOOST_REQUIRE_EQUAL(
        omitted.cs.n_rows, built.cs.n_rows);
    why.clear();
    BOOST_CHECK(
        !(aq::AirQuotientVerify<gf::Fp3, Backend>(
            omitted.cs, proved.proof, seed, &why)));
    BOOST_CHECK(!why.empty());
}

BOOST_AUTO_TEST_SUITE_END()
