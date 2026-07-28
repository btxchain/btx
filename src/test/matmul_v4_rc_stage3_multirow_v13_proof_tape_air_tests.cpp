// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v13_proof_tape_air.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <set>

namespace matmul::v4::rc::stage3_multirow_v13_proof_tape_air {
namespace {

uint256 Root(uint8_t byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

PublicShapeV1 ToyShape()
{
    PublicShapeV1 out;
    out.trace_rows = 2;
    out.trace_columns = 2;
    out.quotient_len = 2;
    out.n_coeffs = 2;
    out.base_column_indices = {0};
    return out;
}

PublicBindingV1 ToyBinding()
{
    PublicBindingV1 out;
    out.program_root = Root(0x11);
    out.statement_root = Root(0x22);
    out.public_fs_seed = Root(0x33);
    out.proof_wire_root = Root(0x44);
    out.tape_root = {1, 2, 3, 4};
    return out;
}

size_t SemanticRecord(uint32_t address)
{
    return kPublicPrefixRecordsV1 +
        kHeaderRecordsV1 + address;
}

std::vector<uint32_t> CanonicalZeroWords(
    const ScheduleV1& schedule)
{
    std::vector<uint32_t> out(
        kHeaderRecordsV1 +
            size_t{schedule.source_records} * 2);
    for (uint32_t header = 0;
         header < kHeaderRecordsV1; ++header) {
        out[header] =
            schedule.records[
                kPublicPrefixRecordsV1 +
                header].expected_value;
    }
    for (uint32_t address = 0;
         address < schedule.source_records;
         ++address) {
        const auto& record =
            schedule.records[SemanticRecord(address)];
        const size_t offset =
            kHeaderRecordsV1 + size_t{address} * 2;
        out[offset] = record.expected_address;
        out[offset + 1] = record.fixed_value
            ? record.expected_value
            : schedule.semantic_sources[address].value;
    }
    return out;
}

size_t SourceValueWord(uint32_t address)
{
    return kHeaderRecordsV1 + size_t{address} * 2 + 1;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v13_proof_tape_air_tests)

BOOST_AUTO_TEST_CASE(
    verifier_regenerates_the_exact_v13_schedule_from_public_shape)
{
    const PublicShapeV1 shape = ToyShape();
    const PublicBindingV1 binding = ToyBinding();
    const ScheduleV1 schedule =
        BuildScheduleV1(shape, binding);
    BOOST_REQUIRE_MESSAGE(schedule.valid, schedule.note);
    BOOST_CHECK(schedule.exact_safe_v13_header);
    BOOST_CHECK(schedule.semantic_schedule_regenerated);
    BOOST_CHECK(schedule.stable_addresses);
    BOOST_REQUIRE_EQUAL(
        schedule.source_records,
        schedule.semantic_sources.size());
    BOOST_CHECK_EQUAL(
        schedule.active_records,
        kPublicPrefixRecordsV1 +
            kHeaderRecordsV1 +
            schedule.source_records);
    BOOST_CHECK(
        schedule.trace_rows >= schedule.active_rows);
    BOOST_CHECK(
        (schedule.trace_rows &
         (schedule.trace_rows - 1)) == 0);

    std::set<abi::SourceKeyV1> keys;
    std::set<uint32_t> addresses;
    for (uint32_t address = 0;
         address < schedule.source_records;
         ++address) {
        const auto& source =
            schedule.semantic_sources[address];
        const auto& record =
            schedule.records[SemanticRecord(address)];
        BOOST_CHECK_EQUAL(source.address, address);
        BOOST_CHECK_EQUAL(
            record.expected_address, address);
        BOOST_CHECK(record.source_record);
        BOOST_CHECK(record.key == source.key);
        BOOST_CHECK(
            record.ownership == source.ownership);
        keys.insert(record.key);
        addresses.insert(record.expected_address);
    }
    BOOST_CHECK_EQUAL(keys.size(), schedule.source_records);
    BOOST_CHECK_EQUAL(
        addresses.size(), schedule.source_records);

    bool group_count_fixed = false;
    bool fold_count_fixed = false;
    bool query_count_fixed = false;
    uint32_t final_value_address = UINT32_MAX;
    uint32_t first_query_address = UINT32_MAX;
    for (uint32_t address = 0;
         address < schedule.source_records;
         ++address) {
        const auto& record =
            schedule.records[SemanticRecord(address)];
        switch (record.key.kind) {
        case abi::FieldKindV1::GroupCount:
            group_count_fixed =
                record.fixed_value &&
                record.expected_value == 3;
            break;
        case abi::FieldKindV1::FoldLayerCount:
        case abi::FieldKindV1::FoldChallengeCount:
            fold_count_fixed =
                fold_count_fixed ||
                record.fixed_value;
            break;
        case abi::FieldKindV1::QueryCount:
            query_count_fixed =
                record.fixed_value &&
                record.expected_value ==
                    abi::kQueryCountV11;
            break;
        case abi::FieldKindV1::FinalValue:
            final_value_address =
                std::min(final_value_address, address);
            break;
        case abi::FieldKindV1::QueryIndex:
        case abi::FieldKindV1::QueryGroupCount:
        case abi::FieldKindV1::QueryRowValue:
            first_query_address =
                std::min(first_query_address, address);
            break;
        default:
            break;
        }
    }
    BOOST_CHECK(group_count_fixed);
    BOOST_CHECK(fold_count_fixed);
    BOOST_CHECK(query_count_fixed);
    BOOST_REQUIRE_NE(final_value_address, UINT32_MAX);
    BOOST_REQUIRE_NE(first_query_address, UINT32_MAX);
    BOOST_CHECK_LT(final_value_address, first_query_address);

    // Public roots alter only the fixed prefix values. They cannot alter
    // the ABI inventory, source addresses, semantic keys or row count.
    PublicBindingV1 transplanted = binding;
    transplanted.program_root = Root(0x91);
    transplanted.statement_root = Root(0x92);
    transplanted.public_fs_seed = Root(0x93);
    transplanted.proof_wire_root = Root(0x94);
    const ScheduleV1 second =
        BuildScheduleV1(shape, transplanted);
    BOOST_REQUIRE_MESSAGE(second.valid, second.note);
    BOOST_REQUIRE_EQUAL(
        second.semantic_sources.size(),
        schedule.semantic_sources.size());
    BOOST_CHECK_EQUAL(second.trace_rows, schedule.trace_rows);
    for (uint32_t address = 0;
         address < schedule.source_records;
         ++address) {
        BOOST_CHECK(
            second.semantic_sources[address].key ==
            schedule.semantic_sources[address].key);
        BOOST_CHECK(
            second.semantic_sources[address].ownership ==
            schedule.semantic_sources[address].ownership);
        BOOST_CHECK_EQUAL(
            second.semantic_sources[address].address,
            schedule.semantic_sources[address].address);
    }
}

BOOST_AUTO_TEST_CASE(
    canonical_decoder_rejects_omission_reorder_address_and_x_plus_p)
{
    const PublicShapeV1 shape = ToyShape();
    const PublicBindingV1 binding = ToyBinding();
    const ScheduleV1 schedule =
        BuildScheduleV1(shape, binding);
    BOOST_REQUIRE_MESSAGE(schedule.valid, schedule.note);
    const std::vector<uint32_t> honest =
        CanonicalZeroWords(schedule);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        abi::DecodeCanonicalSafeV13(honest, &why)
            .has_value(),
        why);

    std::vector<uint32_t> omission = honest;
    omission.erase(omission.end() - 2, omission.end());
    BOOST_CHECK(
        !abi::DecodeCanonicalSafeV13(omission, &why)
             .has_value());

    std::vector<uint32_t> duplicate = honest;
    duplicate[kHeaderRecordsV1 + 2] = 0;
    BOOST_CHECK(
        !abi::DecodeCanonicalSafeV13(duplicate, &why)
             .has_value());

    std::vector<uint32_t> reordered = honest;
    std::swap(
        reordered[kHeaderRecordsV1],
        reordered[kHeaderRecordsV1 + 2]);
    std::swap(
        reordered[kHeaderRecordsV1 + 1],
        reordered[kHeaderRecordsV1 + 3]);
    BOOST_CHECK(
        !abi::DecodeCanonicalSafeV13(reordered, &why)
             .has_value());

    std::vector<uint32_t> address_transplant = honest;
    address_transplant[kHeaderRecordsV1 + 4] =
        schedule.source_records - 1;
    BOOST_CHECK(
        !abi::DecodeCanonicalSafeV13(
             address_transplant, &why).has_value());

    uint32_t fp_low = UINT32_MAX;
    for (uint32_t address = 0;
         address < schedule.source_records;
         ++address) {
        if (schedule.records[
                SemanticRecord(address)].fp_low_limb) {
            fp_low = address;
            break;
        }
    }
    BOOST_REQUIRE_NE(fp_low, UINT32_MAX);
    BOOST_REQUIRE_LT(fp_low + 1, schedule.source_records);
    std::vector<uint32_t> x_plus_p = honest;
    x_plus_p[SourceValueWord(fp_low)] = 1;
    x_plus_p[SourceValueWord(fp_low + 1)] =
        UINT32_MAX;
    BOOST_CHECK(
        !abi::DecodeCanonicalSafeV13(x_plus_p, &why)
             .has_value());
    BOOST_CHECK(
        why.find("noncanonical_fp") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    tape_root_binds_proof_wire_root_before_proof_challenges)
{
    const PublicShapeV1 shape = ToyShape();
    PublicBindingV1 first = ToyBinding();
    const ScheduleV1 first_schedule =
        BuildScheduleV1(shape, first);
    BOOST_REQUIRE(first_schedule.valid);
    const std::vector<uint32_t> words =
        CanonicalZeroWords(first_schedule);
    std::string why;
    const alg_hash::Digest first_root =
        ComputeTapeRootV1(shape, first, words, &why);
    BOOST_REQUIRE_MESSAGE(
        !std::all_of(
            first_root.begin(), first_root.end(),
            [](gf::Fp lane) { return lane == 0; }),
        why);

    PublicBindingV1 second = first;
    second.proof_wire_root = Root(0xa4);
    const ScheduleV1 second_schedule =
        BuildScheduleV1(shape, second);
    BOOST_REQUIRE(second_schedule.valid);
    const alg_hash::Digest second_root =
        ComputeTapeRootV1(
            shape, second,
            CanonicalZeroWords(second_schedule), &why);
    BOOST_CHECK(first_root != second_root);

    first.tape_root = first_root;
    second.tape_root = second_root;
    BOOST_CHECK(
        DeriveProofFsSeedV1(shape, first) !=
        DeriveProofFsSeedV1(shape, second));
    BOOST_CHECK(!kCompleteV13ConsumptionV1);
    BOOST_CHECK(!kRecursiveAuthorityReadyV1);
}

BOOST_AUTO_TEST_CASE(
    fixed_constraint_system_has_no_preprocessed_proof_value)
{
    if (std::getenv("BTX_RUN_V13_PROOF_TAPE_AIR") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_V13_PROOF_TAPE_AIR=1 for the "
            "full fixed-CS inventory test");
        return;
    }
    const PublicShapeV1 shape = ToyShape();
    const PublicBindingV1 binding = ToyBinding();
    aq::AirConstraintSystem<gf::Fp3> cs;
    LayoutV1 layout;
    ScheduleV1 schedule;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        BuildConstraintSystemV1(
            shape, binding, cs,
            &layout, &schedule, &why),
        why);
    BOOST_CHECK_EQUAL(cs.n_rows, schedule.trace_rows);
    BOOST_CHECK_EQUAL(cs.n_columns, layout.End());
    BOOST_CHECK(cs.preprocessed_pin_ood);
    BOOST_REQUIRE(
        layout.dependent_zero + 1 == cs.n_columns);

    std::set<uint32_t> preprocessed;
    for (const auto& [column, values] : cs.preprocessed) {
        BOOST_REQUIRE_EQUAL(values.size(), cs.n_rows);
        preprocessed.insert(column);
    }
    for (uint32_t slot = 0;
         slot < kRecordsPerRowV1; ++slot) {
        BOOST_CHECK(!preprocessed.contains(layout.Address(slot)));
        BOOST_CHECK(!preprocessed.contains(layout.Value(slot)));
        BOOST_CHECK(
            !preprocessed.contains(layout.HighIsMax(slot)));
        BOOST_CHECK(
            !preprocessed.contains(
                layout.HighDeltaInverse(slot)));
        for (uint32_t bit = 0; bit < 32; ++bit) {
            BOOST_CHECK(
                !preprocessed.contains(
                    layout.Bit(slot, bit)));
        }
        BOOST_CHECK(preprocessed.contains(layout.Active(slot)));
        BOOST_CHECK(preprocessed.contains(layout.Source(slot)));
        BOOST_CHECK(
            preprocessed.contains(
                layout.ExpectedAddress(slot)));
        BOOST_CHECK(
            preprocessed.contains(
                layout.SemanticKind(slot)));
    }
    for (uint32_t column = 0;
         column < layout.poseidon.End(); ++column) {
        BOOST_CHECK(!preprocessed.contains(column));
    }
    BOOST_CHECK(
        !preprocessed.contains(layout.dependent_zero));
    static_assert(kProofTapeAirExecutableV1);
    static_assert(!kCompleteV13ConsumptionV1);
    static_assert(!kRecursiveAuthorityReadyV1);
}

BOOST_AUTO_TEST_CASE(
    safe_split_rap_proof_accepts_and_rejects_bound_transplants)
{
    if (std::getenv("BTX_RUN_V13_PROOF_TAPE_PROOF") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_V13_PROOF_TAPE_PROOF=1 for the "
            "proof-level SAFE Split-RAP matrix");
        return;
    }

    const PublicShapeV1 shape = ToyShape();
    PublicBindingV1 binding = ToyBinding();
    ScheduleV1 schedule =
        BuildScheduleV1(shape, binding);
    BOOST_REQUIRE_MESSAGE(schedule.valid, schedule.note);
    const std::vector<uint32_t> words =
        CanonicalZeroWords(schedule);
    std::string why;
    binding.tape_root =
        ComputeTapeRootV1(shape, binding, words, &why);
    BOOST_REQUIRE_MESSAGE(
        !std::all_of(
            binding.tape_root.begin(),
            binding.tape_root.end(),
            [](gf::Fp lane) { return lane == 0; }),
        why);

    const auto product_start =
        std::chrono::steady_clock::now();
    const ProductV1 product =
        BuildProductV1(shape, binding, words);
    const auto product_ms =
        std::chrono::duration_cast<
            std::chrono::milliseconds>(
            std::chrono::steady_clock::now() -
            product_start).count();
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(product.fixed_verifier_owned_schedule);
    BOOST_CHECK(product.no_preprocessed_proof_values);
    BOOST_CHECK(product.canonical_u32_decomposition_air);
    BOOST_CHECK(product.canonical_fp_pairs_air);
    BOOST_CHECK(
        product.monotone_no_omission_addresses_air);
    BOOST_CHECK(product.fixed_protocol_header_air);
    BOOST_CHECK(product.public_bindings_in_r0);
    BOOST_CHECK(product.stable_source_exports);
    BOOST_CHECK(!product.proof_wire_codec_correspondence);
    BOOST_CHECK(
        !product.public_root_preimage_correspondence);
    BOOST_CHECK(!product.complete_v13_consumption);
    BOOST_CHECK(!product.recursive_authority_ready);

    ProofV1 proof;
    const auto prove_start =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        ProveV1(product, proof, &why), why);
    const auto prove_ms =
        std::chrono::duration_cast<
            std::chrono::milliseconds>(
            std::chrono::steady_clock::now() -
            prove_start).count();
    const auto verify_start =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        VerifyV1(shape, binding, proof, &why), why);
    const auto verify_us =
        std::chrono::duration_cast<
            std::chrono::microseconds>(
            std::chrono::steady_clock::now() -
            verify_start).count();

    std::vector<unsigned char> encoded;
    const size_t proof_bytes =
        aq::SerializeAirQuotientSplitRapRowsProof(
            proof.proof, encoded);
    BOOST_REQUIRE_EQUAL(proof_bytes, encoded.size());
    BOOST_CHECK_GT(proof_bytes, 0U);

    ProofV1 group_root_tamper = proof;
    BOOST_REQUIRE(
        !group_root_tamper.proof.batch.groups.empty());
    group_root_tamper.proof.batch.groups[0]
        .row_commit.root[0] =
        gf::Add(
            group_root_tamper.proof.batch.groups[0]
                .row_commit.root[0],
            gf::FromU64(1));
    BOOST_CHECK(
        !VerifyV1(
            shape, binding,
            group_root_tamper, &why));

    ProofV1 source_word_tamper = proof;
    BOOST_REQUIRE(
        !source_word_tamper.proof.batch.queries.empty());
    BOOST_REQUIRE(
        !source_word_tamper.proof.batch.queries[0]
             .group_rows.empty());
    BOOST_REQUIRE(
        !source_word_tamper.proof.batch.queries[0]
             .group_rows[0].values.empty());
    source_word_tamper.proof.batch.queries[0]
        .group_rows[0].values[0].c0 =
        gf::Add(
            source_word_tamper.proof.batch.queries[0]
                .group_rows[0].values[0].c0,
            gf::FromU64(1));
    BOOST_CHECK(
        !VerifyV1(
            shape, binding,
            source_word_tamper, &why));

    PublicBindingV1 wrong_seed = binding;
    wrong_seed.public_fs_seed = Root(0xb3);
    BOOST_CHECK(
        !VerifyV1(shape, wrong_seed, proof, &why));

    PublicBindingV1 wrong_wire = binding;
    wrong_wire.proof_wire_root = Root(0xc4);
    BOOST_CHECK(
        !VerifyV1(shape, wrong_wire, proof, &why));

    BOOST_TEST_MESSAGE(
        "V13_PROOF_TAPE_AIR proof_bytes="
        << proof_bytes
        << " trace_rows=" << product.cs.n_rows
        << " trace_columns=" << product.cs.n_columns
        << " constraints=" << product.cs.constraints.size()
        << " semantic_sources="
        << product.schedule.source_records
        << " product_ms=" << product_ms
        << " prove_ms=" << prove_ms
        << " verify_us=" << verify_us
        << " proof_level_group_root_reject=1"
        << " proof_level_source_word_reject=1"
        << " wrong_public_seed_reject=1"
        << " proof_wire_root_transplant_reject=1"
        << " codec_join=0 phase_consumption=0 authority=0");
}

BOOST_AUTO_TEST_CASE(
    malformed_public_shapes_fail_closed_without_a_schedule)
{
    const PublicBindingV1 binding = ToyBinding();
    for (const PublicShapeV1& bad : {
             PublicShapeV1{1, 2, 2, 2, {0}},
             PublicShapeV1{2, 2, 2, 3, {0}},
             PublicShapeV1{2, 2, 2, 2, {}},
             PublicShapeV1{2, 2, 2, 2, {2}},
             PublicShapeV1{2, 2, 2, 2, {0, 0}},
         }) {
        BOOST_CHECK(!BuildScheduleV1(bad, binding).valid);
    }
    PublicBindingV1 bad_binding = binding;
    bad_binding.proof_wire_root.SetNull();
    BOOST_CHECK(
        !BuildScheduleV1(ToyShape(), bad_binding).valid);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v13_proof_tape_air
