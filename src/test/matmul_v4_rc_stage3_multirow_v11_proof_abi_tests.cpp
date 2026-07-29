// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_proof_abi.h>

#include <algorithm>
#include <set>

namespace matmul::v4::rc::stage3_multirow_v11_proof_abi {
namespace {

gf::Fp3 U(uint64_t value)
{
    return {value, value + 1, value + 2};
}

Fri3AlgDigest D(uint64_t value)
{
    return {value, value + 1, value + 2, value + 3};
}

Fri3AlgRowOpening Row(
    uint64_t value,
    uint32_t columns,
    uint32_t depth)
{
    Fri3AlgRowOpening out;
    for (uint32_t c = 0; c < columns; ++c) {
        out.values.push_back(U(value + 10 * c));
    }
    for (uint32_t i = 0; i < depth; ++i) {
        out.siblings.push_back(D(value + 100 + 10 * i));
    }
    return out;
}

EnvelopeV1 Envelope()
{
    EnvelopeV1 out;
    for (uint32_t i = 0; i < out.public_fs_seed.size(); ++i) {
        out.public_fs_seed[i] = 0x10203040U + i;
    }
    out.trace_columns = 2;
    out.quotient_len = 2;
    auto& split = out.split;
    split.version = 1;
    split.trace_rows = 2;
    split.base_column_indices = {0};
    split.air_constraint_lambda = U(10);
    auto& batch = split.batch;
    batch.version = kRCFri3AlgMultiRowBatchProofVersion;
    batch.pow_grind_nonce = 0x0123456789abcdefULL;
    batch.blowup = kRCFriBlowup;
    batch.n_coeffs = 2;
    batch.groups = {
        {Fri3AlgMultiRowGroupRole::MainTrace, 0, 1, {D(100), 32}},
        {Fri3AlgMultiRowGroupRole::AuxiliaryTrace, 1, 1, {D(200), 32}},
        {Fri3AlgMultiRowGroupRole::Quotient, 2, 1, {D(300), 32}},
    };
    batch.column_len = {2, 2, 2};
    batch.lambda = U(20);
    batch.z1 = U(30);
    batch.z2 = U(40);
    batch.evals_z1 = {U(50), U(60), U(70)};
    batch.evals_z2 = {U(80), U(90), U(100)};
    batch.w1 = U(110);
    batch.w2 = U(120);
    batch.fold_layers = {{D(400), 32}, {D(500), 16}};
    batch.final_value = U(130);
    batch.fold_challenges = {U(140)};
    batch.queries.resize(kQueryCountV11);
    split.next_trace_group_rows.resize(kQueryCountV11);
    for (uint32_t q = 0; q < kQueryCountV11; ++q) {
        auto& query = batch.queries[q];
        query.index = q & 31U;
        query.group_rows = {
            Row(2000 + 100 * q, 1, 5),
            Row(3000 + 100 * q, 1, 5),
            Row(4000 + 100 * q, 1, 5),
        };
        Fri3AlgFoldStep step;
        step.even_index = query.index % 16;
        step.odd_index = step.even_index + 16;
        step.even = U(5000 + 100 * q);
        step.odd = U(6000 + 100 * q);
        for (uint32_t i = 0; i < 5; ++i) {
            step.even_siblings.push_back(D(7000 + 100 * q + 10 * i));
            step.odd_siblings.push_back(D(8000 + 100 * q + 10 * i));
        }
        query.steps = {step};
        split.next_trace_group_rows[q] = {
            Row(9000 + 100 * q, 1, 5),
            Row(10000 + 100 * q, 1, 5),
        };
    }
    return out;
}

std::array<QueryCandidatesV1, kQueryCountV11> Candidates()
{
    std::array<QueryCandidatesV1, kQueryCountV11> out{};
    for (uint32_t q = 0; q < kQueryCountV11; ++q) {
        out[q].digest[0] = D(32 * (1000 + q) + (q & 31U));
        out[q].digest[1] = D(32 * (2000 + q) + (q & 31U));
        out[q].selected_ordinal = 0;
    }
    return out;
}

size_t ValueWord(uint32_t address)
{
    return kFieldAbiHeaderWordsV1 + size_t{address} * 2 + 1;
}

} // namespace

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_multirow_v11_proof_abi_tests)

BOOST_AUTO_TEST_CASE(
    canonical_roundtrip_inventory_and_stable_source_addresses)
{
    const auto envelope = Envelope();
    std::vector<uint32_t> words;
    std::vector<SourceCellV1> sources;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        EncodeCanonicalV1(envelope, words, &sources, &why), why);
    BOOST_REQUIRE_EQUAL(words[5], sources.size());
    BOOST_CHECK_EQUAL(
        words.size(),
        kFieldAbiHeaderWordsV1 + sources.size() * 2);
    BOOST_REQUIRE_MESSAGE(
        ValidateSourceCellsV1(sources, &why), why);

    const auto decoded = DecodeCanonicalV1(words, &why);
    BOOST_REQUIRE_MESSAGE(decoded.has_value(), why);
    BOOST_CHECK(decoded->canonical);
    BOOST_CHECK(decoded->complete);
    BOOST_CHECK(decoded->addresses_unique);
    BOOST_CHECK(decoded->semantic_keys_unique);
    BOOST_CHECK_GT(decoded->public_statement_cells, 0U);
    BOOST_CHECK_GT(decoded->child_proof_cells, 0U);
    BOOST_CHECK_EQUAL(decoded->derived_transcript_cells, 0U);
    BOOST_CHECK_EQUAL(
        decoded->public_statement_cells +
            decoded->child_proof_cells,
        decoded->sources.size());
    BOOST_TEST_MESSAGE(
        "v11_field_abi source_cells=" << decoded->sources.size()
        << " public_statement=" << decoded->public_statement_cells
        << " child_proof=" << decoded->child_proof_cells
        << " encoded_u32_words=" << words.size());
    BOOST_CHECK_EQUAL(
        decoded->envelope.split.batch.queries.size(),
        kQueryCountV11);
    BOOST_CHECK_EQUAL(
        decoded->envelope.split.next_trace_group_rows.size(),
        kQueryCountV11);

    const SourceKeyV1 query_index{
        FieldKindV1::QueryIndex, 37, 0, 0, 0, 0};
    const auto address = FindSourceAddressV1(sources, query_index);
    BOOST_REQUIRE(address.has_value());
    const auto second = FindSourceAddressV1(decoded->sources, query_index);
    BOOST_REQUIRE(second.has_value());
    BOOST_CHECK_EQUAL(*address, *second);
    BOOST_CHECK_EQUAL(
        words[ValueWord(*address)],
        envelope.split.batch.queries[37].index);

    const auto derived =
        BuildDerivedQueryCandidateExportsV1(*decoded, Candidates());
    BOOST_REQUIRE_MESSAGE(derived.valid, derived.note);
    BOOST_CHECK(derived.canonical_candidates);
    BOOST_CHECK(derived.k2_first_valid);
    BOOST_CHECK(derived.selected_indices_match_proof);
    BOOST_CHECK(!derived.transcript_equality_constrained);
    BOOST_CHECK(!derived.recursively_consumed);
    BOOST_CHECK_EQUAL(
        derived.sources.front().address,
        kDerivedTranscriptAddressBaseV1);
    BOOST_CHECK_GT(
        derived.sources.front().address,
        sources.back().address);
    BOOST_CHECK(std::all_of(
        derived.sources.begin(), derived.sources.end(),
        [](const SourceCellV1& cell) {
            return cell.ownership ==
                OwnershipClassV1::DerivedTranscript;
        }));
    std::set<uint16_t> semantic_families;
    for (const auto& source : decoded->sources) {
        semantic_families.insert(
            static_cast<uint16_t>(
                source.key.kind));
    }
    for (const auto& source : derived.sources) {
        semantic_families.insert(
            static_cast<uint16_t>(
                source.key.kind));
    }
    BOOST_REQUIRE_EQUAL(semantic_families.size(), 60U);
    for (uint16_t family = 1;
         family <= 60; ++family) {
        BOOST_CHECK(
            semantic_families.contains(family));
    }

    std::vector<ParentPublicCellV1> parent;
    uint32_t parent_column = 100;
    for (const auto& source : decoded->sources) {
        if (source.ownership == OwnershipClassV1::PublicStatement) {
            parent.push_back({
                source.key, parent_column++, source.value});
        }
    }
    const auto public_join =
        BuildPublicStatementJoinV1(*decoded, parent);
    BOOST_REQUIRE_MESSAGE(public_join.valid, public_join.note);
    BOOST_CHECK_EQUAL(
        public_join.required_cells,
        decoded->public_statement_cells);
    BOOST_CHECK_EQUAL(
        public_join.matched_cells,
        decoded->public_statement_cells);
    BOOST_CHECK(public_join.exact_public_inventory);
    BOOST_CHECK(public_join.values_equal);
    BOOST_CHECK(public_join.parent_columns_unique);
    BOOST_CHECK(!public_join.actual_air_constraints_appended);

    const auto readiness = CurrentReadinessV1();
    BOOST_CHECK(readiness.canonical_decoder_executable);
    BOOST_CHECK(readiness.exact_field_inventory_executable);
    BOOST_CHECK(readiness.stable_source_addresses_executable);
    BOOST_CHECK(readiness.public_statement_join_plan_executable);
    BOOST_CHECK(!readiness.public_statement_air_equalities_appended);
    BOOST_CHECK(!readiness.same_parent_consumer_joins_executable);
    BOOST_CHECK(!readiness.v11_backend_executable);
    BOOST_CHECK(!readiness.recursive_authority_ready);
}

BOOST_AUTO_TEST_CASE(
    safe_v13_roundtrip_is_complete_and_domain_separated_from_v11)
{
    auto envelope = Envelope();
    envelope.split.version =
        aq::kAirQuotientSplitRapRowsSafeProofVersionV2;
    envelope.split.batch.version =
        kRCFri3AlgMultiRowSafeQ192K2ProofVersionV13;
    std::vector<uint32_t> words;
    std::vector<SourceCellV1> sources;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        EncodeCanonicalSafeV13(
            envelope, words, &sources, &why),
        why);
    BOOST_REQUIRE_EQUAL(words[5], sources.size());
    BOOST_CHECK_EQUAL(
        words[2], kMultiRowProtocolVersionV13);
    BOOST_CHECK_EQUAL(
        words[3],
        static_cast<uint32_t>(
            kMultiRowProtocolDomainV13));
    BOOST_CHECK_EQUAL(
        words[4],
        static_cast<uint32_t>(
            kMultiRowProtocolDomainV13 >> 32));

    const auto decoded =
        DecodeCanonicalSafeV13(words, &why);
    BOOST_REQUIRE_MESSAGE(decoded.has_value(), why);
    BOOST_CHECK(decoded->canonical);
    BOOST_CHECK(decoded->complete);
    BOOST_CHECK(decoded->addresses_unique);
    BOOST_CHECK(decoded->semantic_keys_unique);
    BOOST_CHECK_GT(decoded->public_statement_cells, 0U);
    BOOST_CHECK_GT(decoded->child_proof_cells, 0U);
    BOOST_CHECK_EQUAL(
        decoded->sources.size(), sources.size());
    BOOST_REQUIRE(!sources.empty());
    BOOST_CHECK_EQUAL(
        decoded->sources.front().address,
        sources.front().address);
    BOOST_CHECK(
        decoded->sources.front().key ==
        sources.front().key);
    BOOST_CHECK_EQUAL(
        decoded->sources.back().address,
        sources.back().address);
    BOOST_CHECK(
        decoded->sources.back().key ==
        sources.back().key);
    BOOST_CHECK(decoded->sources == sources);
    auto changed_sources = sources;
    changed_sources.back().value ^= 1U;
    BOOST_CHECK(decoded->sources != changed_sources);

    // A canonical V13 envelope is never accepted under the frozen V11
    // protocol header, even though both revisions share the complete
    // 60-family field inventory.
    BOOST_CHECK(!DecodeCanonicalV1(words).has_value());
    auto v11 = Envelope();
    std::vector<uint32_t> v11_words;
    BOOST_REQUIRE(EncodeCanonicalV1(v11, v11_words));
    BOOST_CHECK(
        !DecodeCanonicalSafeV13(v11_words).has_value());

    auto bad_domain = words;
    bad_domain[3] ^= 1U;
    BOOST_CHECK(
        !DecodeCanonicalSafeV13(
            bad_domain).has_value());
    auto bad_batch = words;
    const SourceKeyV1 batch_version{
        FieldKindV1::BatchVersion, 0, 0, 0, 0, 0};
    const auto batch_address =
        FindSourceAddressV1(sources, batch_version);
    BOOST_REQUIRE(batch_address.has_value());
    bad_batch[ValueWord(*batch_address)] =
        kRCFri3AlgMultiRowBatchProofVersion;
    BOOST_CHECK(
        !DecodeCanonicalSafeV13(
            bad_batch).has_value());
}

BOOST_AUTO_TEST_CASE(
    noncanonical_goldilocks_alias_is_rejected)
{
    std::vector<uint32_t> words;
    std::vector<SourceCellV1> sources;
    BOOST_REQUIRE(EncodeCanonicalV1(Envelope(), words, &sources));
    const SourceKeyV1 lo{
        FieldKindV1::EvalZ1, 0, 0, 0, 0, 0};
    const SourceKeyV1 hi{
        FieldKindV1::EvalZ1, 0, 0, 0, 0, 1};
    const auto lo_address = FindSourceAddressV1(sources, lo);
    const auto hi_address = FindSourceAddressV1(sources, hi);
    BOOST_REQUIRE(lo_address.has_value());
    BOOST_REQUIRE(hi_address.has_value());
    const uint64_t alias = gf::kP + 50;
    words[ValueWord(*lo_address)] = static_cast<uint32_t>(alias);
    words[ValueWord(*hi_address)] = static_cast<uint32_t>(alias >> 32);
    BOOST_CHECK(!DecodeCanonicalV1(words).has_value());
}

BOOST_AUTO_TEST_CASE(
    omitted_duplicate_reordered_and_trailing_records_are_rejected)
{
    std::vector<uint32_t> words;
    BOOST_REQUIRE(EncodeCanonicalV1(Envelope(), words));

    auto omitted = words;
    omitted.erase(
        omitted.begin() + kFieldAbiHeaderWordsV1 + 20,
        omitted.begin() + kFieldAbiHeaderWordsV1 + 22);
    BOOST_CHECK(!DecodeCanonicalV1(omitted).has_value());

    auto duplicated = words;
    duplicated.insert(
        duplicated.begin() + kFieldAbiHeaderWordsV1 + 22,
        words.begin() + kFieldAbiHeaderWordsV1 + 20,
        words.begin() + kFieldAbiHeaderWordsV1 + 22);
    ++duplicated[5];
    BOOST_CHECK(!DecodeCanonicalV1(duplicated).has_value());

    auto reordered = words;
    const size_t a = kFieldAbiHeaderWordsV1 + 20;
    const size_t b = kFieldAbiHeaderWordsV1 + 22;
    std::swap(reordered[a], reordered[b]);
    std::swap(reordered[a + 1], reordered[b + 1]);
    BOOST_CHECK(!DecodeCanonicalV1(reordered).has_value());

    auto trailing = words;
    trailing.push_back(0);
    BOOST_CHECK(!DecodeCanonicalV1(trailing).has_value());
}

BOOST_AUTO_TEST_CASE(
    query_candidate_link_and_consumer_address_collisions_fail_closed)
{
    std::vector<uint32_t> words;
    auto wrong_index = Envelope();
    wrong_index.split.batch.queries[0].index = 32;
    BOOST_CHECK(!EncodeCanonicalV1(wrong_index, words));

    std::vector<SourceCellV1> sources;
    BOOST_REQUIRE(EncodeCanonicalV1(Envelope(), words, &sources));
    const auto decoded = DecodeCanonicalV1(words);
    BOOST_REQUIRE(decoded.has_value());
    auto wrong_candidates = Candidates();
    wrong_candidates[0].selected_ordinal = 1;
    BOOST_CHECK(
        !BuildDerivedQueryCandidateExportsV1(
            *decoded, wrong_candidates).valid);
    wrong_candidates = Candidates();
    wrong_candidates[0].digest[0][0] ^= 1;
    BOOST_CHECK(
        !BuildDerivedQueryCandidateExportsV1(
            *decoded, wrong_candidates).valid);

    BOOST_REQUIRE_GT(sources.size(), 2U);
    auto address_collision = sources;
    address_collision[2].address = address_collision[1].address;
    BOOST_CHECK(!ValidateSourceCellsV1(address_collision));

    auto key_collision = sources;
    key_collision[2].key = key_collision[1].key;
    BOOST_CHECK(!ValidateSourceCellsV1(key_collision));
    BOOST_CHECK(
        !FindSourceAddressV1(
            key_collision, key_collision[1].key).has_value());

    std::vector<ParentPublicCellV1> parent;
    for (const auto& source : decoded->sources) {
        if (source.ownership == OwnershipClassV1::PublicStatement) {
            parent.push_back({
                source.key,
                static_cast<uint32_t>(parent.size()),
                source.value});
        }
    }
    BOOST_REQUIRE(!parent.empty());
    auto omitted = parent;
    omitted.pop_back();
    BOOST_CHECK(!BuildPublicStatementJoinV1(*decoded, omitted).valid);
    auto substituted = parent;
    substituted[0].value ^= 1;
    BOOST_CHECK(!BuildPublicStatementJoinV1(*decoded, substituted).valid);
    auto collision = parent;
    collision[1].parent_column = collision[0].parent_column;
    BOOST_CHECK(!BuildPublicStatementJoinV1(*decoded, collision).valid);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_proof_abi
