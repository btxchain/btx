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

std::vector<alg_hash::State> BoundaryStatesForPlans(
    const ScheduleV1& schedule,
    const std::vector<uint32_t>& words,
    const std::vector<ShardPlanV2>& plans,
    std::vector<uint32_t>* first_record_values = nullptr,
    std::vector<uint32_t>* next_record_values = nullptr)
{
    std::vector<uint32_t> addresses(
        schedule.records.size(), 0);
    std::vector<uint32_t> values(
        schedule.records.size(), 0);
    for (uint32_t record = 0;
         record < schedule.active_records;
         ++record) {
        const auto& expected =
            schedule.records[record];
        addresses[record] =
            expected.expected_address;
        if (record <
                kPublicPrefixRecordsV1) {
            values[record] =
                expected.expected_value;
        } else if (
            record <
                kPublicPrefixRecordsV1 +
                    kHeaderRecordsV1) {
            values[record] =
                words[record -
                    kPublicPrefixRecordsV1];
        } else {
            const uint32_t source =
                record -
                kPublicPrefixRecordsV1 -
                kHeaderRecordsV1;
            const size_t offset =
                kHeaderRecordsV1 +
                size_t{source} * 2;
            addresses[record] =
                words[offset];
            values[record] =
                words[offset + 1];
        }
    }
    std::vector<alg_hash::State> out(
        plans.size() + 1);
    if (first_record_values != nullptr) {
        first_record_values->assign(
            plans.size(), 0);
    }
    if (next_record_values != nullptr) {
        next_record_values->assign(
            plans.size(), 0);
    }
    for (uint32_t index = 0;
         index < plans.size(); ++index) {
        if (first_record_values != nullptr) {
            (*first_record_values)[index] =
                values[plans[index].record_begin];
        }
        if (next_record_values != nullptr &&
            index + 1 < plans.size()) {
            (*next_record_values)[index] =
                values[
                    plans[index].record_begin +
                    plans[index].record_count];
        }
    }
    alg_hash::State state{};
    uint32_t boundary = 1;
    for (uint32_t row = 0;
         row < schedule.trace_rows; ++row) {
        for (uint32_t slot = 0;
             slot < kRecordsPerRowV1;
             ++slot) {
            const uint32_t record =
                row * kRecordsPerRowV1 +
                slot;
            state[2 * slot] = gf::Add(
                state[2 * slot],
                gf::FromU64(
                    addresses[record]));
            state[2 * slot + 1] = gf::Add(
                state[2 * slot + 1],
                gf::FromU64(
                    values[record]));
        }
        alg_hash::Permute(state);
        if (boundary < out.size() &&
            row + 1 ==
                plans[boundary - 1].row_begin +
                plans[boundary - 1].trace_rows) {
            out[boundary++] = state;
        }
    }
    return out;
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

BOOST_AUTO_TEST_CASE(
    packed_v2_preserves_digest_and_rejects_record_stream_attacks)
{
    const PublicShapeV1 shape = ToyShape();
    PublicBindingV1 binding = ToyBinding();
    const ScheduleV1 legacy =
        BuildScheduleV1(shape, binding);
    BOOST_REQUIRE_MESSAGE(legacy.valid, legacy.note);
    const std::vector<uint32_t> honest =
        CanonicalZeroWords(legacy);
    std::string why;
    binding.tape_root =
        ComputeTapeRootV1(
            shape, binding, honest, &why);
    BOOST_REQUIRE_MESSAGE(
        binding.tape_root != alg_hash::Digest{},
        why);

    const ScheduleV2 packed =
        BuildScheduleV2(shape, binding);
    BOOST_REQUIRE_MESSAGE(packed.valid, packed.note);
    BOOST_CHECK_EQUAL(
        packed.source_records,
        legacy.source_records);
    BOOST_CHECK_EQUAL(
        packed.active_records,
        legacy.active_records);
    BOOST_CHECK_EQUAL(
        packed.active_schedule.size(),
        packed.active_records);
    BOOST_CHECK_EQUAL(
        packed.trace_rows * kRecordsPerRowV2,
        legacy.trace_rows * kRecordsPerRowV1);
    BOOST_CHECK_EQUAL(
        packed.padding_records,
        packed.trace_rows * kRecordsPerRowV2 -
            packed.active_records);
    BOOST_CHECK(packed.exact_v1_record_order);
    BOOST_CHECK(packed.immutable_row_slot_mapping);
    BOOST_CHECK(packed.exact_source_multiplicity);
    BOOST_CHECK(packed.canonical_padding);
    BOOST_CHECK(!packed.source_inventory_root.IsNull());

    const LayoutV2 layout = CanonicalLayoutV2();
    BOOST_CHECK_EQUAL(
        layout.poseidon.size(),
        kPoseidonInstancesPerRowV2);
    for (uint32_t block = 1;
         block < layout.poseidon.size(); ++block) {
        BOOST_CHECK_EQUAL(
            layout.poseidon[block].perm.base,
            layout.poseidon[block - 1].End());
    }
    BOOST_CHECK_LT(layout.End(), 1U << 20);

    const auto v2_root =
        ComputeTapeRootV2(
            shape, binding, honest, &why);
    BOOST_CHECK(v2_root == binding.tape_root);
    BOOST_REQUIRE_MESSAGE(
        VerifyPackedWordsV2(
            shape, binding, honest, &why),
        why);
    BOOST_CHECK(
        DeriveProofFsSeedV2(
            shape, binding,
            packed.source_inventory_root) !=
        DeriveProofFsSeedV1(shape, binding));

    // Any proof-value mutation remains canonically decodable but changes the
    // authenticated tape root.
    std::vector<uint32_t> value_tamper = honest;
    bool changed_value = false;
    for (uint32_t source = 0;
         source < legacy.source_records; ++source) {
        const auto& record =
            legacy.records[
                SemanticRecord(source)];
        if (!record.fixed_value) {
            value_tamper[
                SourceValueWord(source)] ^= 1U;
            changed_value = true;
            break;
        }
    }
    BOOST_REQUIRE(changed_value);
    BOOST_CHECK(
        !VerifyPackedWordsV2(
            shape, binding,
            value_tamper, &why));

    // Wrong address, duplicate, omission and whole-record reorder are all
    // rejected by the canonical SAFE decoder / immutable source schedule.
    std::vector<uint32_t> wrong_address = honest;
    wrong_address[kHeaderRecordsV1] ^= 1U;
    BOOST_CHECK(
        !VerifyPackedWordsV2(
            shape, binding,
            wrong_address, &why));

    std::vector<uint32_t> duplicate = honest;
    duplicate[
        kHeaderRecordsV1 + 2] =
        duplicate[kHeaderRecordsV1];
    BOOST_CHECK(
        !VerifyPackedWordsV2(
            shape, binding, duplicate, &why));

    std::vector<uint32_t> omission = honest;
    omission.resize(omission.size() - 2);
    BOOST_CHECK(
        !VerifyPackedWordsV2(
            shape, binding, omission, &why));

    std::vector<uint32_t> reorder = honest;
    BOOST_REQUIRE_GE(legacy.source_records, 2U);
    for (uint32_t limb = 0; limb < 2; ++limb) {
        std::swap(
            reorder[
                kHeaderRecordsV1 + limb],
            reorder[
                kHeaderRecordsV1 + 2 + limb]);
    }
    BOOST_CHECK(
        !VerifyPackedWordsV2(
            shape, binding, reorder, &why));

    // Explicitly cross one 4-record Poseidon chunk boundary inside a packed
    // row. This attack used to be invisible to a naive 64-record/one-perm
    // generalization; the exact address schedule rejects it before hashing.
    const uint32_t first_source_record =
        kPublicPrefixRecordsV1 +
        kHeaderRecordsV1;
    const uint32_t next_boundary =
        ((first_source_record + 3U) / 4U) * 4U;
    BOOST_REQUIRE_GT(next_boundary, first_source_record);
    BOOST_REQUIRE_LT(
        next_boundary,
        first_source_record +
            legacy.source_records);
    const uint32_t left_source =
        next_boundary - 1U -
        first_source_record;
    const uint32_t right_source =
        next_boundary -
        first_source_record;
    std::vector<uint32_t> boundary_swap = honest;
    for (uint32_t limb = 0; limb < 2; ++limb) {
        std::swap(
            boundary_swap[
                kHeaderRecordsV1 +
                2 * left_source + limb],
            boundary_swap[
                kHeaderRecordsV1 +
                2 * right_source + limb]);
    }
    BOOST_CHECK(
        !VerifyPackedWordsV2(
            shape, binding,
            boundary_swap, &why));
}

BOOST_AUTO_TEST_CASE(
    streaming_shard_chain_covers_padding_and_rejects_boundary_attacks)
{
    const PublicShapeV1 shape = ToyShape();
    PublicBindingV1 binding = ToyBinding();
    const ScheduleV1 schedule =
        BuildScheduleV1(shape, binding);
    BOOST_REQUIRE(schedule.valid);
    const std::vector<uint32_t> words =
        CanonicalZeroWords(schedule);
    binding.tape_root =
        ComputeTapeRootV1(
            shape, binding, words);
    BOOST_REQUIRE(
        binding.tape_root !=
            alg_hash::Digest{});
    BOOST_REQUIRE_GE(schedule.trace_rows, 8U);
    const uint32_t max_rows =
        schedule.trace_rows / 4;
    const auto plans =
        BuildShardPlansForMaxRowsV2(
            shape, binding, max_rows);
    BOOST_REQUIRE_EQUAL(plans.size(), 4U);
    for (uint32_t left = 0;
         left < 4; ++left) {
        for (uint32_t right = 0;
             right < 4; ++right) {
            if (left == right) continue;
            BOOST_CHECK(
                !gf::Eq(
                    ShardAddressTagV2(left, 17),
                    ShardAddressTagV2(right, 17)));
        }
    }
    std::vector<uint32_t> first_record_values;
    std::vector<uint32_t> next_record_values;
    const auto states =
        BoundaryStatesForPlans(
            schedule, words, plans,
            &first_record_values,
            &next_record_values);
    BOOST_REQUIRE_EQUAL(
        states.size(), plans.size() + 1);
    BOOST_REQUIRE_EQUAL(
        first_record_values.size(),
        plans.size());
    BOOST_REQUIRE_EQUAL(
        next_record_values.size(),
        plans.size());
    const uint256 inventory =
        ComputeShardSourceInventoryRootV2(
            shape, binding);
    BOOST_REQUIRE(!inventory.IsNull());
    std::vector<ShardReceiptV2> receipts;
    for (uint32_t index = 0;
         index < plans.size(); ++index) {
        receipts.push_back({
            .plan = plans[index],
            .start_state = states[index],
            .end_state = states[index + 1],
            .first_record_value =
                first_record_values[index],
            .next_record_value =
                next_record_values[index],
            .source_inventory_root =
                inventory,
        });
    }
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        VerifyShardCoverageChainForMaxRowsV2(
            shape, binding, receipts,
            max_rows, &why),
        why);
    BOOST_CHECK(plans.back().
        contains_canonical_padding);
    BOOST_CHECK_EQUAL(
        plans.front().record_begin, 0U);
    BOOST_CHECK_EQUAL(
        plans.back().record_begin +
            plans.back().record_count,
        plans.back().total_records);

    auto omission = receipts;
    omission.erase(omission.begin() + 1);
    BOOST_CHECK(
        !VerifyShardCoverageChainForMaxRowsV2(
            shape, binding, omission,
            max_rows, &why));

    auto reorder = receipts;
    std::swap(reorder[1], reorder[2]);
    BOOST_CHECK(
        !VerifyShardCoverageChainForMaxRowsV2(
            shape, binding, reorder,
            max_rows, &why));

    auto duplicate = receipts;
    duplicate[2] = duplicate[1];
    BOOST_CHECK(
        !VerifyShardCoverageChainForMaxRowsV2(
            shape, binding, duplicate,
            max_rows, &why));

    auto wrong_boundary = receipts;
    wrong_boundary[1].start_state[0] =
        gf::Add(
            wrong_boundary[1].start_state[0],
            gf::FromU64(1));
    BOOST_CHECK(
        !VerifyShardCoverageChainForMaxRowsV2(
            shape, binding, wrong_boundary,
            max_rows, &why));

    // The four digest lanes are unchanged.  Mutating a hidden capacity lane
    // must still fail because all twelve state lanes are chained.
    auto hidden_capacity = receipts;
    hidden_capacity[1].start_state[
        alg_hash::kAlgHashRate] =
        gf::Add(
            hidden_capacity[1].start_state[
                alg_hash::kAlgHashRate],
            gf::FromU64(1));
    BOOST_CHECK(
        !VerifyShardCoverageChainForMaxRowsV2(
            shape, binding,
            hidden_capacity,
            max_rows, &why));

    auto wrong_interval = receipts;
    ++wrong_interval[1].plan.active_records;
    BOOST_CHECK(
        !VerifyShardCoverageChainForMaxRowsV2(
            shape, binding,
            wrong_interval,
            max_rows, &why));

    for (uint32_t boundary = 1;
         boundary < receipts.size();
         ++boundary) {
        auto wrong_record_boundary = receipts;
        ++wrong_record_boundary[boundary].
            first_record_value;
        BOOST_CHECK(
            !VerifyShardCoverageChainForMaxRowsV2(
                shape, binding,
                wrong_record_boundary,
                max_rows, &why));
    }

    auto wrong_final_next = receipts;
    wrong_final_next.back().
        next_record_value = 1;
    BOOST_CHECK(
        !VerifyShardCoverageChainForMaxRowsV2(
            shape, binding,
            wrong_final_next,
            max_rows, &why));
}

BOOST_AUTO_TEST_CASE(
    streaming_shard_air_proves_and_rejects_proof_and_state_tamper)
{
    if (std::getenv(
            "BTX_RUN_V13_TAPE_SHARD_PROOF") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_V13_TAPE_SHARD_PROOF=1 "
            "for the proof-level shard matrix");
        return;
    }
    const PublicShapeV1 shape = ToyShape();
    PublicBindingV1 binding = ToyBinding();
    const ScheduleV1 schedule =
        BuildScheduleV1(shape, binding);
    BOOST_REQUIRE(schedule.valid);
    const std::vector<uint32_t> words =
        CanonicalZeroWords(schedule);
    binding.tape_root =
        ComputeTapeRootV1(
            shape, binding, words);
    const auto plans =
        BuildShardPlansV2(shape, binding);
    BOOST_REQUIRE_EQUAL(plans.size(), 1U);
    const auto boundaries =
        ComputeShardBoundaryStatesV2(
            shape, binding, words);
    BOOST_REQUIRE_MESSAGE(
        boundaries.valid, boundaries.note);
    ShardStatementV2 statement{
        .child_shape = shape,
        .binding = binding,
        .plan = plans[0],
        .start_state =
            boundaries.states[0],
        .end_state =
            boundaries.states[1],
        .first_record_value =
            boundaries.first_record_values[0],
        .next_record_value =
            boundaries.next_record_values[0],
        .source_inventory_root =
            ComputeShardSourceInventoryRootV2(
                shape, binding),
    };
    const ShardProductV2 product =
        BuildShardProductV2(
            statement, words);
    BOOST_REQUIRE_MESSAGE(
        product.valid, product.note);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(product.exact_schedule_slice);
    BOOST_CHECK(product.exact_state_boundary);
    BOOST_CHECK(product.stable_source_exports);
    BOOST_CHECK_LE(
        product.cs.n_columns, 847U);
    uint32_t max_everywhere = 0;
    uint32_t max_transition = 0;
    uint32_t max_boundary = 0;
    for (const auto& c :
         product.cs.constraints) {
        if (c.kind == aq::AirKind::kEverywhere) {
            max_everywhere =
                std::max(
                    max_everywhere,
                    c.alg_degree);
        } else if (
            c.kind ==
                aq::AirKind::kTransition) {
            max_transition =
                std::max(
                    max_transition,
                    c.alg_degree);
        } else {
            max_boundary =
                std::max(
                    max_boundary,
                    c.alg_degree);
        }
    }
    BOOST_CHECK_LE(max_everywhere, 3U);
    BOOST_CHECK_LE(max_transition, 3U);
    BOOST_CHECK_LE(max_boundary, 2U);
    BOOST_CHECK_LE(
        product.cs.QuotientLen(),
        2 * product.cs.n_rows);

    std::set<uint32_t> preprocessed;
    for (const auto& [column, values] :
         product.cs.preprocessed) {
        BOOST_REQUIRE_EQUAL(
            values.size(),
            product.cs.n_rows);
        preprocessed.insert(column);
    }
    for (uint32_t slot = 0;
         slot < kRecordsPerRowV1; ++slot) {
        BOOST_CHECK(
            !preprocessed.contains(
                product.layout.tape.
                    Address(slot)));
        BOOST_CHECK(
            !preprocessed.contains(
                product.layout.tape.
                    Value(slot)));
    }

    ShardProofV2 proof;
    std::string why;
    const ShardJoinContextV2 join_context =
        BuildShardJoinContextV2(
            shape, binding,
            {product.r0_session.
                base_row_commitment},
            {Root(0xd1), Root(0xd2)});
    BOOST_REQUIRE(join_context.valid);
    ShardSourceChallengesV2 challenges;
    BOOST_REQUIRE(
        DeriveShardSourceChallengesV2(
            statement,
            product.r0_session.
                base_row_commitment,
            join_context, challenges));
    ShardSourceChallengesV2 challenges_again;
    BOOST_REQUIRE(
        DeriveShardSourceChallengesV2(
            statement,
            product.r0_session.
                base_row_commitment,
            join_context,
            challenges_again));
    for (uint32_t lane = 0;
         lane < 2; ++lane) {
        BOOST_CHECK(gf::Eq(
            challenges.gamma[lane],
            challenges_again.gamma[lane]));
        BOOST_CHECK(gf::Eq(
            challenges.alpha[lane],
            challenges_again.alpha[lane]));
    }
    BOOST_CHECK(
        !DeriveShardSourceChallengesV2(
            statement, Root(0xfe),
            join_context,
            challenges_again));
    BOOST_REQUIRE_MESSAGE(
        ProveShardV2(
            product, join_context,
            proof, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        VerifyShardV2(
            statement, join_context,
            proof, &why),
        why);
    std::vector<unsigned char> encoded;
    const size_t proof_bytes =
        aq::SerializeAirQuotientSplitRapRowsProof(
            proof.proof, encoded);
    BOOST_REQUIRE_EQUAL(
        proof_bytes, encoded.size());
    BOOST_CHECK_LT(
        proof_bytes, 16U * 1024U * 1024U);

    ShardProofV2 proof_tamper = proof;
    BOOST_REQUIRE(
        !proof_tamper.proof.batch.
            queries.empty());
    BOOST_REQUIRE(
        !proof_tamper.proof.batch.
            queries[0].group_rows.empty());
    BOOST_REQUIRE(
        !proof_tamper.proof.batch.
            queries[0].group_rows[0].
                values.empty());
    proof_tamper.proof.batch.
        queries[0].group_rows[0].
        values[0].c0 =
        gf::Add(
            proof_tamper.proof.batch.
                queries[0].group_rows[0].
                values[0].c0,
            gf::FromU64(1));
    BOOST_CHECK(
        !VerifyShardV2(
            statement, join_context,
            proof_tamper, &why));

    ShardProofV2 terminal_tamper = proof;
    terminal_tamper.source_terminal[0] =
        gf::Add(
            terminal_tamper.source_terminal[0],
            gf::Fp3::One());
    BOOST_CHECK(
        !VerifyShardV2(
            statement, join_context,
            terminal_tamper, &why));

    ShardStatementV2 wrong_state =
        statement;
    wrong_state.start_state[
        alg_hash::kAlgHashRate] =
        gf::Add(
            wrong_state.start_state[
                alg_hash::kAlgHashRate],
            gf::FromU64(1));
    BOOST_CHECK(
        !VerifyShardV2(
            wrong_state, join_context,
            proof, &why));

    ShardJoinContextV2 wrong_context =
        join_context;
    wrong_context.consumer_r0_roots[0] =
        Root(0xe1);
    wrong_context =
        BuildShardJoinContextV2(
            shape, binding,
            wrong_context.tape_r0_roots,
            wrong_context.consumer_r0_roots);
    BOOST_REQUIRE(wrong_context.valid);
    ShardSourceChallengesV2 wrong_challenges;
    BOOST_REQUIRE(
        DeriveShardSourceChallengesV2(
            statement,
            product.r0_session.
                base_row_commitment,
            wrong_context,
            wrong_challenges));
    BOOST_CHECK(
        !gf::Eq(
            challenges.gamma[0],
            wrong_challenges.gamma[0]) ||
        !gf::Eq(
            challenges.alpha[0],
            wrong_challenges.alpha[0]));
    BOOST_CHECK(
        !VerifyShardV2(
            statement, wrong_context,
            proof, &why));

    const ShardJoinContextV2 wrong_r0_context =
        BuildShardJoinContextV2(
            shape, binding,
            {Root(0xe2)},
            join_context.consumer_r0_roots);
    BOOST_REQUIRE(wrong_r0_context.valid);
    BOOST_CHECK(
        !DeriveShardSourceChallengesV2(
            statement, proof.r0_row_root,
            wrong_r0_context,
            wrong_challenges));
    BOOST_CHECK(
        !VerifyShardV2(
            statement, wrong_r0_context,
            proof, &why));

    const ShardJoinContextV2 wrong_order =
        BuildShardJoinContextV2(
            shape, binding,
            join_context.tape_r0_roots,
            {Root(0xd2), Root(0xd1)});
    BOOST_REQUIRE(wrong_order.valid);
    BOOST_CHECK(
        !VerifyShardV2(
            statement, wrong_order,
            proof, &why));

    ShardSourceChallengesV2 public_challenges;
    BOOST_REQUIRE(
        DeriveShardPublicSourceChallengesV3(
            shape, binding,
            statement.source_inventory_root,
            statement.plan.shard_count,
            public_challenges));
    ShardProofV3 public_proof;
    BOOST_REQUIRE_MESSAGE(
        ProveShardPublicV3(
            product, public_proof, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        VerifyShardPublicV3(
            statement, public_proof, &why),
        why);

    auto public_proof_tamper =
        public_proof;
    BOOST_REQUIRE(
        !public_proof_tamper.proof.batch.
            queries.empty());
    BOOST_REQUIRE(
        !public_proof_tamper.proof.batch.
            queries[0].row.values.empty());
    public_proof_tamper.proof.batch.
        queries[0].row.values[0] =
        gf::Add(
            public_proof_tamper.proof.batch.
                queries[0].row.values[0],
            gf::Fp3::One());
    BOOST_CHECK(
        !VerifyShardPublicV3(
            statement, public_proof_tamper,
            &why));

    auto public_terminal_tamper =
        public_proof;
    public_terminal_tamper.
        source_terminal[0] =
        gf::Add(
            public_terminal_tamper.
                source_terminal[0],
            gf::Fp3::One());
    BOOST_CHECK(
        !VerifyShardPublicV3(
            statement,
            public_terminal_tamper, &why));

    ShardStatementV2 changed_tape =
        statement;
    changed_tape.binding.tape_root[0] =
        gf::Add(
            changed_tape.binding.tape_root[0],
            gf::FromU64(1));
    changed_tape.source_inventory_root =
        ComputeShardSourceInventoryRootV2(
            shape, changed_tape.binding);
    ShardSourceChallengesV2
        changed_tape_challenges;
    BOOST_REQUIRE(
        DeriveShardPublicSourceChallengesV3(
            shape, changed_tape.binding,
            changed_tape.source_inventory_root,
            changed_tape.plan.shard_count,
            changed_tape_challenges));
    BOOST_CHECK(
        !gf::Eq(
            public_challenges.gamma[0],
            changed_tape_challenges.gamma[0]) ||
        !gf::Eq(
            public_challenges.alpha[0],
            changed_tape_challenges.alpha[0]));
    BOOST_CHECK(
        !VerifyShardPublicV3(
            changed_tape, public_proof,
            &why));

    ShardStatementV2 cross_context =
        statement;
    cross_context.binding.proof_wire_root =
        Root(0xf3);
    cross_context.source_inventory_root =
        ComputeShardSourceInventoryRootV2(
            shape, cross_context.binding);
    BOOST_CHECK(
        !VerifyShardPublicV3(
            cross_context, public_proof,
            &why));

    ShardProductV2 adaptive_witness =
        product;
    adaptive_witness.columns[
        product.layout.tape.Value(0)][0] =
        gf::Add(
            adaptive_witness.columns[
                product.layout.tape.Value(0)][0],
            gf::Fp3::One());
    ShardProofV3 adaptive_proof;
    BOOST_CHECK(
        !ProveShardPublicV3(
            adaptive_witness,
            adaptive_proof, &why));

    ShardStatementV2 relabel =
        statement;
    relabel.plan.shard_index = 1;
    BOOST_CHECK(
        !VerifyShardV2(
            relabel, join_context,
            proof, &why));

    const ShardReceiptV2 receipt{
        .plan = statement.plan,
        .start_state = statement.start_state,
        .end_state = statement.end_state,
        .first_record_value =
            statement.first_record_value,
        .next_record_value =
            statement.next_record_value,
        .source_inventory_root =
            statement.source_inventory_root,
        .proof = proof,
    };
    BOOST_REQUIRE_MESSAGE(
        VerifyShardReceiptChainV2(
            shape, binding, join_context,
            {receipt}, &why),
        why);

    BOOST_TEST_MESSAGE(
        "V13_TAPE_SHARD W=" <<
        product.cs.n_columns <<
        " N=" << product.cs.n_rows <<
        " dmax=" <<
        product.cs.MaxComposedDegreeBound() <<
        " Lq=" << product.cs.QuotientLen() <<
        " proof_bytes=" << proof_bytes);
}

BOOST_AUTO_TEST_CASE(
    production_shard_fixedpoint_shape_is_four_by_two_to_19)
{
    if (std::getenv(
            "BTX_RUN_V13_TAPE_SHARD_PRODUCTION_SHAPE") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_V13_TAPE_SHARD_PRODUCTION_SHAPE=1 "
            "for the production inventory recurrence");
        return;
    }
    PublicShapeV1 shape;
    shape.trace_rows = 16;
    shape.trace_columns = 1804;
    shape.quotient_len = 90;
    shape.n_coeffs = 128;
    shape.base_column_indices.resize(1803);
    for (uint32_t column = 0;
         column < 1803; ++column) {
        shape.base_column_indices[column] =
            column;
    }
    const PublicBindingV1 binding =
        ToyBinding();
    const ScheduleV1 global =
        BuildScheduleV1(shape, binding);
    BOOST_REQUIRE_MESSAGE(
        global.valid, global.note);
    BOOST_CHECK_EQUAL(
        global.source_records, 4463758U);
    BOOST_CHECK_EQUAL(
        global.active_records, 4463796U);
    BOOST_CHECK_EQUAL(
        global.trace_rows, 1U << 21);
    const auto plans =
        BuildShardPlansV2(shape, binding);
    BOOST_REQUIRE_EQUAL(plans.size(), 4U);
    uint32_t fp_pair_boundary_count = 0;
    for (uint32_t index = 0;
         index < plans.size(); ++index) {
        BOOST_CHECK(plans[index].valid);
        BOOST_CHECK_EQUAL(
            plans[index].shard_index,
            index);
        BOOST_CHECK_EQUAL(
            plans[index].trace_rows,
            1U << 19);
        BOOST_CHECK_EQUAL(
            plans[index].record_count,
            1U << 21);
        if (index + 1 < plans.size()) {
            const uint32_t last_record =
                plans[index].record_begin +
                plans[index].record_count - 1;
            BOOST_REQUIRE_LT(
                last_record,
                global.records.size());
            fp_pair_boundary_count +=
                global.records[last_record].
                    fp_low_limb ? 1U : 0U;
        }
    }
    // Production inventory has two low/high field pairs split by the fixed
    // shard cuts.  The shard statement's proof-owned next value closes them.
    BOOST_CHECK_EQUAL(
        fp_pair_boundary_count, 2U);
    BOOST_CHECK_EQUAL(
        plans[0].active_records,
        1U << 21);
    BOOST_CHECK_EQUAL(
        plans[1].active_records,
        1U << 21);
    BOOST_CHECK_EQUAL(
        plans[2].active_records,
        269492U);
    BOOST_CHECK_EQUAL(
        plans[3].active_records, 0U);
    BOOST_CHECK_EQUAL(
        plans[0].active_records -
            kPublicPrefixRecordsV1 -
            kHeaderRecordsV1,
        (1U << 21) -
            kPublicPrefixRecordsV1 -
            kHeaderRecordsV1);
    BOOST_CHECK_EQUAL(
        plans[2].active_records, 269492U);
    BOOST_CHECK(
        plans[3].
            contains_canonical_padding);
    const uint32_t N = 1U << 19;
    const uint64_t dmax =
        uint64_t{3} * (N - 1) + 1;
    const uint32_t quotient_len =
        static_cast<uint32_t>(
            dmax - N + 1);
    BOOST_CHECK_EQUAL(
        quotient_len, (1U << 20) - 1);
    const uint32_t n_coeffs = 1U << 20;
    const uint32_t n_lde =
        n_coeffs * kRCFriBlowup;
    BOOST_CHECK_EQUAL(n_lde, 1U << 24);
    BOOST_CHECK_LE(
        CanonicalShardLayoutV2().End(),
        847U);
    BOOST_CHECK_EQUAL(
        CanonicalShardLayoutV2().End(),
        723U);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v13_proof_tape_air
