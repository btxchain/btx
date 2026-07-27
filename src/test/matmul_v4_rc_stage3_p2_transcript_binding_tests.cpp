// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_p2_transcript_binding.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <string>
#include <vector>

namespace p2bind =
    matmul::v4::rc::stage3_p2_transcript_binding;
namespace gf = matmul::v4::rc::gkr_field;
namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_p2_transcript_binding_tests,
    BasicTestingSetup)

namespace {

uint256 Seed(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

std::vector<std::vector<rc::Fp3>> Columns()
{
    return {
        {gf::FromSigned3(3), gf::FromSigned3(5)},
        {gf::FromSigned3(7), gf::FromSigned3(11)}};
}

} // namespace

BOOST_AUTO_TEST_CASE(
    proof_owned_source_and_appendable_consumer_manifest_are_exact)
{
    const uint256 seed = Seed(0x6d);
    const rc::Fri3AlgBatchCommitResult committed =
        rc::Fri3AlgP2Q192K2V10BatchCommit(
            Columns(), seed, 0);
    BOOST_REQUIRE_MESSAGE(
        committed.ok, committed.note);

    const p2bind::BindingResult binding =
        p2bind::BuildProofOwnedTranscriptBindingV10(
            committed.proof, seed);
    BOOST_REQUIRE_MESSAGE(binding.valid, binding.note);
    BOOST_CHECK(binding.canonical_proof_codec);
    BOOST_CHECK(binding.native_proof_verified);
    BOOST_CHECK(binding.proof_owned_prefix_reconstructed);
    BOOST_CHECK(binding.compact_prefix_schedule_canonical);
    BOOST_CHECK(binding.exact_active_transcript_replayed);
    BOOST_CHECK(binding.source_event_order_complete);
    BOOST_CHECK(binding.consumer_mapping_canonical);
    BOOST_CHECK(binding.proof_owned_source_cells_bound);
    BOOST_CHECK(
        binding.local_air_event_prefixes_match_active_protocol);
    BOOST_CHECK(binding.v10_k2_protocol_producer_executable);
    BOOST_CHECK(!binding.recursive_consumer_cells_bound);
    BOOST_CHECK(!binding.recursive_authority);
    BOOST_CHECK(
        binding.consumer_manifest.appendable_layout_only);
    BOOST_CHECK(
        !binding.consumer_manifest.same_parent_cells_bound);
    BOOST_REQUIRE(binding.prefix_schedule.size() >= 6);
    BOOST_CHECK(
        !binding.prefix_schedule[0].proof_owned);
    BOOST_CHECK(
        binding.prefix_schedule[0].fs_prefix.empty());
    BOOST_CHECK(
        binding.prefix_schedule[1].source_kind ==
        p2bind::PrefixSourceKind::FriInitialLambda);
    BOOST_CHECK(
        binding.prefix_schedule[2].source_kind ==
        p2bind::PrefixSourceKind::FriPostLambdaOod);
    BOOST_CHECK(
        binding.prefix_schedule[1].fs_prefix !=
        binding.prefix_schedule[2].fs_prefix);
    BOOST_CHECK(
        binding.prefix_schedule.back().event_count ==
        rc::kRCFri3AlgNumQueries);

    std::string why;
    BOOST_CHECK_MESSAGE(
        p2bind::ValidateProofOwnedTranscriptBindingV10(
            binding, committed.proof, seed, &why),
        why);
}

BOOST_AUTO_TEST_CASE(
    source_root_challenge_and_payload_substitutions_reject)
{
    const uint256 seed = Seed(0x71);
    const rc::Fri3AlgBatchCommitResult committed =
        rc::Fri3AlgP2Q192K2V10BatchCommit(
            Columns(), seed, 0);
    BOOST_REQUIRE(committed.ok);
    const p2bind::BindingResult honest =
        p2bind::BuildProofOwnedTranscriptBindingV10(
            committed.proof, seed);
    BOOST_REQUIRE(honest.valid);
    std::string why;

    rc::Fri3AlgBatchProof root_changed =
        committed.proof;
    root_changed.row_commit.root[0] =
        gf::Add(
            root_changed.row_commit.root[0],
            gf::FromU64(1));
    BOOST_CHECK(
        !p2bind::BuildProofOwnedTranscriptBindingV10(
             root_changed, seed)
             .valid);

    p2bind::BindingResult changed = honest;
    changed.consumer_manifest.entries[1]
        .fp3_value.c0 =
        gf::Add(
            changed.consumer_manifest.entries[1]
                .fp3_value.c0,
            gf::FromU64(1));
    BOOST_CHECK(
        !p2bind::ValidateProofOwnedTranscriptBindingV10(
            changed, committed.proof, seed, &why));

    changed = honest;
    changed.statement.event_prefixes[0]
        .bytes.pop_back();
    BOOST_CHECK(
        !p2bind::ValidateProofOwnedTranscriptBindingV10(
            changed, committed.proof, seed, &why));

    changed = honest;
    changed.statement.event_prefixes[0]
        .bytes.push_back(0);
    BOOST_CHECK(
        !p2bind::ValidateProofOwnedTranscriptBindingV10(
            changed, committed.proof, seed, &why));
}

BOOST_AUTO_TEST_CASE(
    local_air_to_consumer_equality_residual_is_executable)
{
    const uint256 seed = Seed(0x75);
    const rc::Fri3AlgBatchCommitResult committed =
        rc::Fri3AlgP2Q192K2V10BatchCommit(
            Columns(), seed, 0);
    BOOST_REQUIRE(committed.ok);
    const p2bind::BindingResult binding =
        p2bind::BuildProofOwnedTranscriptBindingV10(
            committed.proof, seed);
    BOOST_REQUIRE(binding.valid);
    const auto air =
        p2bind::p2tx::BuildTranscriptAirV10(
            binding.statement);
    BOOST_REQUIRE_MESSAGE(air.valid, air.note);

    std::vector<uint32_t> mismatches;
    std::string why;
    BOOST_CHECK(
        !p2bind::AssessLocalAirConsumerEqualityV10(
            binding, air, mismatches, &why));
    BOOST_CHECK(
        why.find("same_parent_cells_not_exported") !=
        std::string::npos);
    BOOST_CHECK(mismatches.empty());
}

BOOST_AUTO_TEST_CASE(
    omitted_reordered_and_query_swapped_cells_reject)
{
    const uint256 seed = Seed(0x7b);
    const rc::Fri3AlgBatchCommitResult committed =
        rc::Fri3AlgP2Q192K2V10BatchCommit(
            Columns(), seed, 0);
    BOOST_REQUIRE(committed.ok);
    const p2bind::BindingResult honest =
        p2bind::BuildProofOwnedTranscriptBindingV10(
            committed.proof, seed);
    BOOST_REQUIRE(honest.valid);
    std::string why;

    p2bind::BindingResult changed = honest;
    changed.consumer_manifest.entries.erase(
        changed.consumer_manifest.entries.begin() + 4);
    BOOST_CHECK(
        !p2bind::ValidateProofOwnedTranscriptBindingV10(
            changed, committed.proof, seed, &why));

    changed = honest;
    std::swap(
        changed.consumer_manifest.entries[1],
        changed.consumer_manifest.entries[2]);
    BOOST_CHECK(
        !p2bind::ValidateProofOwnedTranscriptBindingV10(
            changed, committed.proof, seed, &why));

    changed = honest;
    const size_t query0 =
        changed.consumer_manifest.entries.size() -
        rc::kRCFri3AlgNumQueries;
    std::swap(
        changed.consumer_manifest.entries[query0],
        changed.consumer_manifest.entries[query0 + 1]);
    BOOST_CHECK(
        !p2bind::ValidateProofOwnedTranscriptBindingV10(
            changed, committed.proof, seed, &why));

    changed = honest;
    changed.source_events.erase(
        changed.source_events.begin() + 3);
    BOOST_CHECK(
        !p2bind::ValidateProofOwnedTranscriptBindingV10(
            changed, committed.proof, seed, &why));

    changed = honest;
    changed.prefix_schedule[2].fs_prefix =
        changed.prefix_schedule[1].fs_prefix;
    BOOST_CHECK(
        !p2bind::ValidateProofOwnedTranscriptBindingV10(
            changed, committed.proof, seed, &why));
}

BOOST_AUTO_TEST_CASE(
    v8_v5_binding_domain_replay_and_overclaim_reject)
{
    const uint256 seed = Seed(0x83);
    const rc::Fri3AlgBatchCommitResult committed =
        rc::Fri3AlgP2Q192K2V10BatchCommit(
            Columns(), seed, 0);
    BOOST_REQUIRE(committed.ok);
    const p2bind::BindingResult honest =
        p2bind::BuildProofOwnedTranscriptBindingV10(
            committed.proof, seed);
    BOOST_REQUIRE(honest.valid);
    std::string why;

    p2bind::BindingResult changed = honest;
    changed.version = 8;
    changed.domain_tag =
        rc::kRCFri3AlgP2SqueezeDomainTag;
    BOOST_CHECK(
        !p2bind::ValidateProofOwnedTranscriptBindingV10(
            changed, committed.proof, seed, &why));

    changed = honest;
    changed.domain_tag =
        rc::kRCFri3AlgDualLane0DomainTag;
    BOOST_CHECK(
        !p2bind::ValidateProofOwnedTranscriptBindingV10(
            changed, committed.proof, seed, &why));

    changed = honest;
    changed.recursive_consumer_cells_bound = true;
    changed.recursive_authority = true;
    BOOST_CHECK(
        !p2bind::ValidateProofOwnedTranscriptBindingV10(
            changed, committed.proof, seed, &why));
}

BOOST_AUTO_TEST_SUITE_END()
