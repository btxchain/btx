// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_p2_prefix_source_air.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <vector>

namespace rc = matmul::v4::rc;
namespace fp = matmul::v4::rc::recursive_fixedpoint;
namespace gf = matmul::v4::rc::gkr_field;
namespace bind =
    matmul::v4::rc::stage3_p2_transcript_binding;
namespace exports =
    matmul::v4::rc::stage3_p2_normalized_exports;
namespace source =
    matmul::v4::rc::stage3_p2_prefix_source_air;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_p2_prefix_source_air_tests)

namespace {

uint256 Seed(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

uint32_t SeedWord(const uint256& seed, uint32_t word)
{
    uint32_t out = 0;
    for (uint32_t byte = 0; byte < 4; ++byte) {
        out |= uint32_t{seed.data()[4 * word + byte]}
            << (8 * byte);
    }
    return out;
}

void AddOneToCodecWord(
    fp::FoldBusComposition& parent,
    const fp::NormalizedAlgAirProofFieldBusAttachmentV1&
        proof_bus,
    uint32_t word)
{
    const uint32_t position = 5 + word;
    const uint32_t row =
        position /
        fp::kNormalizedAlgAirProofFieldBusRate;
    const uint32_t lane =
        position %
        fp::kNormalizedAlgAirProofFieldBusRate;
    parent.columns[proof_bus.layout.Field(lane)][row] =
        gf::Add(
            parent.columns[
                proof_bus.layout.Field(lane)][row],
            gf::Fp3::One());
}

struct Fixture {
    uint256 seed;
    rc::Fri3AlgBatchProof proof;
    bind::BindingResult binding;
    fp::FoldBusComposition parent;
    fp::NormalizedAlgAirProofFieldBusAttachmentV1 proof_bus;
    fp::NormalizedAlgAirCodecDecoderAttachmentV1 decoder;
    source::ReceiptSeedSourceRefsV1 seed_source;
};

Fixture MakeFixture()
{
    Fixture out;
    out.seed = Seed(0x6d);
    const std::vector<std::vector<gf::Fp3>> columns{{
        gf::FromSigned3(3),
        gf::FromSigned3(5),
    }};
    const auto committed =
        rc::Fri3AlgP2Q192K2V10BatchCommit(
            columns, out.seed, 0);
    BOOST_REQUIRE_MESSAGE(committed.ok, committed.note);
    out.proof = committed.proof;
    out.binding =
        bind::BuildProofOwnedTranscriptBindingV10(
            out.proof, out.seed);
    BOOST_REQUIRE_MESSAGE(
        out.binding.valid, out.binding.note);

    std::string why;
    fp::NormalizedAlgAirBatchCodecMapV1 map;
    BOOST_REQUIRE_MESSAGE(
        fp::BuildNormalizedAlgAirBatchCodecMapV1(
            out.proof, map, &why),
        why);
    const uint32_t needed_rows =
        std::max<uint32_t>(
            64,
            (5 + map.codec_words +
             fp::kNormalizedAlgAirProofFieldBusRate - 1) /
                fp::kNormalizedAlgAirProofFieldBusRate);
    uint32_t rows = 2;
    while (rows < needed_rows) rows <<= 1;

    for (uint32_t word = 0;
         word < source::kSeedWordsV1; ++word) {
        out.seed_source.u32_word[word] = {word, 0};
    }
    out.seed_source.canonical_receipt_statement = true;
    out.seed_source.verifier_recomputed_seed = true;
    out.seed_source.cells_bound_before_first_commitment = true;
    out.seed_source.complete_child_verifier_same_parent = false;

    out.proof_bus.layout =
        fp::NormalizedAlgAirProofFieldBusLayout(
            source::kSeedWordsV1);
    out.proof_bus.parent_rows = rows;
    out.proof_bus.batch_codec_bytes = map.codec_bytes;
    out.proof_bus.batch_codec_words = map.codec_words;
    out.proof_bus.active_sponge_rows =
        (5 + map.codec_words +
         fp::kNormalizedAlgAirProofFieldBusRate - 1) /
        fp::kNormalizedAlgAirProofFieldBusRate;
    out.proof_bus.proof_commitment = Seed(0xa1);
    out.proof_bus.valid = true;

    out.decoder.layout =
        fp::NormalizedAlgAirCodecDecoderLayout(
            out.proof_bus.layout.End());
    out.decoder.map = map;
    out.decoder.parent_rows = rows;
    out.decoder.active_word_slots = map.codec_words;
    out.decoder.valid_byte_slots = map.codec_bytes;
    out.decoder.canonical_fp_elements = map.fp_elements;
    out.decoder.added_columns =
        out.decoder.layout.End() - out.decoder.layout.base;
    out.decoder.exact_length_constrained = true;
    out.decoder.every_word_decomposed = true;
    out.decoder.every_byte_range_checked = true;
    out.decoder.little_endian_recomposition_constrained = true;
    out.decoder.final_word_padding_zero = true;
    out.decoder.every_fp_encoding_canonical = true;
    out.decoder.no_unconsumed_codec_bytes = true;
    out.decoder.valid = true;

    out.parent.combined.n_rows = rows;
    out.parent.combined.n_columns =
        out.decoder.layout.End();
    out.parent.columns.assign(
        out.parent.combined.n_columns,
        std::vector<gf::Fp3>(
            rows, gf::Fp3::Zero()));
    for (uint32_t word = 0;
         word < source::kSeedWordsV1; ++word) {
        out.parent.columns[word][0] =
            gf::Fp3::FromFp(
                gf::FromU64(SeedWord(out.seed, word)));
    }
    for (uint32_t word = 0;
         word < map.codec_words; ++word) {
        const uint32_t position = 5 + word;
        const uint32_t row =
            position /
            fp::kNormalizedAlgAirProofFieldBusRate;
        const uint32_t lane =
            position %
            fp::kNormalizedAlgAirProofFieldBusRate;
        out.parent.columns[
            out.proof_bus.layout.Field(lane)][row] =
            gf::Fp3::FromFp(
                gf::FromU64(map.entries[word].value));
        for (uint32_t byte = 0; byte < 4; ++byte) {
            out.parent.columns[
                out.decoder.layout.Byte(lane, byte)][row] =
                gf::Fp3::FromFp(gf::FromU64(
                    (map.entries[word].value >>
                     (8 * byte)) &
                    0xff));
        }
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    seed_shape_and_ood_sources_are_executable_same_parent_air)
{
    Fixture fixture = MakeFixture();
    source::AttachmentV1 attachment;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        source::AttachV10PrefixSourceAirV1(
            fixture.parent, fixture.proof, fixture.seed,
            fixture.proof_bus, fixture.decoder,
            fixture.seed_source, attachment, &why),
        why);
    BOOST_CHECK(attachment.valid);
    BOOST_CHECK(attachment.receipt_seed_cells_preexisting);
    BOOST_CHECK(
        attachment.receipt_seed_byte_decomposition_constrained);
    BOOST_CHECK(attachment.shape_payload_direct_codec_aliases);
    BOOST_CHECK(attachment.ood_payload_direct_codec_aliases);
    BOOST_CHECK(attachment.eval_counts_equality_constrained);
    BOOST_CHECK(
        attachment.sparse_poseidon_permutations_constrained);
    BOOST_CHECK(
        attachment.sponge_state_transitions_constrained);
    BOOST_CHECK(attachment.digest_outputs_canonical_bytes);
    BOOST_CHECK(!attachment.source_values_preprocessed);
    BOOST_CHECK(attachment.selectors_only_preprocessed);
    BOOST_CHECK(!attachment.complete_child_verifier_same_parent);
    BOOST_CHECK(!attachment.recursively_consumed);
    BOOST_CHECK(!attachment.recursive_authority);
    BOOST_CHECK_EQUAL(
        source::CountViolations(fixture.parent), 0U);
    BOOST_REQUIRE_MESSAGE(
        source::ValidateV10PrefixSourceAirV1(
            fixture.parent, fixture.proof, fixture.seed,
            fixture.proof_bus, fixture.decoder,
            fixture.seed_source, attachment, &why),
        why);

    exports::InventoryV1 inventory;
    BOOST_REQUIRE_MESSAGE(
        exports::BuildNormalizedV10ExportInventoryV1(
            fixture.proof, fixture.seed, fixture.binding,
            fixture.decoder, nullptr, &fixture.parent,
            nullptr, &attachment.exports,
            inventory, &why),
        why);
    BOOST_CHECK(inventory.every_prefix_byte_owned);
    BOOST_CHECK_EQUAL(inventory.missing_seed_bytes, 0U);
    BOOST_CHECK_EQUAL(
        inventory.missing_shape_commit_bytes, 0U);
    BOOST_CHECK_EQUAL(
        inventory.missing_ood_eval_commit_bytes, 0U);
    BOOST_CHECK(!inventory.recursive_authority);
    BOOST_TEST_MESSAGE(
        "V10_PREFIX_SOURCE_AIR added_columns="
        << attachment.added_columns
        << " constraints=" << attachment.added_constraints
        << " shape_fields="
        << attachment.shape_payload_fields
        << " ood_fields="
        << attachment.ood_payload_fields
        << " shape_blocks=" << attachment.shape_blocks
        << " ood_blocks=" << attachment.ood_blocks
        << " gathered=" << attachment.gathered_source_fields
        << " cross_row_fp="
        << attachment.cross_row_fp_sources);
}

BOOST_AUTO_TEST_CASE(
    seed_codec_digest_and_eval_count_substitutions_reject)
{
    {
        Fixture fixture = MakeFixture();
        fixture.parent.columns[
            fixture.seed_source.u32_word[0].column][0] =
            gf::Fp3{
                gf::kP + SeedWord(fixture.seed, 0), 0, 0};
        source::AttachmentV1 ignored;
        std::string why;
        // The raw x+p representative is rejected before any field equality
        // can erase the non-canonical encoding.
        BOOST_CHECK(
            !source::AttachV10PrefixSourceAirV1(
                fixture.parent, fixture.proof,
                fixture.seed, fixture.proof_bus,
                fixture.decoder, fixture.seed_source,
                ignored, &why));
    }

    Fixture fixture = MakeFixture();
    source::AttachmentV1 attachment;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        source::AttachV10PrefixSourceAirV1(
            fixture.parent, fixture.proof, fixture.seed,
            fixture.proof_bus, fixture.decoder,
            fixture.seed_source, attachment, &why),
        why);

    auto attack = fixture.parent;
    AddOneToCodecWord(attack, fixture.proof_bus, 5);
    BOOST_CHECK_GT(source::CountViolations(attack), 0U);

    // The first z1 limb is an OOD payload source, so changing a canonical
    // codec word without changing its P2 derivation is rejected.
    attack = fixture.parent;
    const uint32_t width =
        static_cast<uint32_t>(
            fixture.proof.column_len.size());
    const uint32_t z1_word = 16 + width + 6;
    AddOneToCodecWord(
        attack, fixture.proof_bus, z1_word);
    BOOST_CHECK_GT(source::CountViolations(attack), 0U);

    // The two serialized eval counts are independently present in the codec
    // and equality-constrained before the OOD commitment can consume them.
    attack = fixture.parent;
    const uint32_t eval_z1_count_word =
        16 + width + 6 + 6 + 6;
    AddOneToCodecWord(
        attack, fixture.proof_bus,
        eval_z1_count_word);
    BOOST_CHECK_GT(source::CountViolations(attack), 0U);

    attack = fixture.parent;
    const auto seed_cell =
        fixture.seed_source.u32_word.front();
    attack.columns[seed_cell.column][seed_cell.row] =
        gf::Add(
            attack.columns[seed_cell.column][seed_cell.row],
            gf::Fp3::One());
    BOOST_CHECK_GT(source::CountViolations(attack), 0U);

    attack = fixture.parent;
    const auto shape_byte =
        attachment.exports.shape_commit.byte.front();
    attack.columns[shape_byte.column][shape_byte.row] =
        gf::Add(
            attack.columns[shape_byte.column][shape_byte.row],
            gf::Fp3::One());
    BOOST_CHECK_GT(source::CountViolations(attack), 0U);

    attack = fixture.parent;
    const auto ood_byte =
        attachment.exports.ood_eval_commit.byte.back();
    attack.columns[ood_byte.column][ood_byte.row] =
        gf::Add(
            attack.columns[ood_byte.column][ood_byte.row],
            gf::Fp3::One());
    BOOST_CHECK_GT(source::CountViolations(attack), 0U);

    // Wrong parent statement => a different precommit seed. A valid V10
    // child under the original statement cannot be attached under it.
    const uint256 wrong_seed = Seed(0x6e);
    source::AttachmentV1 wrong;
    BOOST_CHECK(
        !source::AttachV10PrefixSourceAirV1(
            fixture.parent, fixture.proof, wrong_seed,
            fixture.proof_bus, fixture.decoder,
            fixture.seed_source, wrong, &why));

    // Export metadata is part of the normalized-parent ABI, not an
    // advisory host label. A relabelled source cell must not validate.
    auto relabelled = attachment;
    ++relabelled.exports.fs_seed.byte.front().column;
    BOOST_CHECK(
        !source::ValidateV10PrefixSourceAirV1(
            fixture.parent, fixture.proof, fixture.seed,
            fixture.proof_bus, fixture.decoder,
            fixture.seed_source, relabelled, &why));
}

BOOST_AUTO_TEST_CASE(
    prefix_schedule_swap_is_not_an_alternate_valid_statement)
{
    Fixture fixture = MakeFixture();
    source::AttachmentV1 attachment;
    std::string why;
    BOOST_REQUIRE(
        source::AttachV10PrefixSourceAirV1(
            fixture.parent, fixture.proof, fixture.seed,
            fixture.proof_bus, fixture.decoder,
            fixture.seed_source, attachment, &why));
    auto swapped = fixture.binding;
    BOOST_REQUIRE_GT(swapped.prefix_schedule.size(), 3U);
    std::swap(
        swapped.prefix_schedule[1],
        swapped.prefix_schedule[2]);
    exports::InventoryV1 ignored;
    BOOST_CHECK(
        !exports::BuildNormalizedV10ExportInventoryV1(
            fixture.proof, fixture.seed, swapped,
            fixture.decoder, nullptr, &fixture.parent,
            nullptr, &attachment.exports,
            ignored, &why));
}

BOOST_AUTO_TEST_SUITE_END()
