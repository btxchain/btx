// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_p2_normalized_exports.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstring>

namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;
namespace fp = matmul::v4::rc::recursive_fixedpoint;
namespace bind =
    matmul::v4::rc::stage3_p2_transcript_binding;
namespace p2air =
    matmul::v4::rc::stage3_p2_transcript_air;
namespace exports =
    matmul::v4::rc::stage3_p2_normalized_exports;
namespace join =
    matmul::v4::rc::stage3_p2_same_parent_join;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_p2_normalized_exports_tests)

namespace {

uint256 Seed(unsigned char value)
{
    uint256 out;
    std::fill(out.begin(), out.end(), value);
    return out;
}

std::vector<std::vector<gf::Fp3>> Columns()
{
    return {{
        gf::FromSigned3(3),
        gf::FromSigned3(5)}};
}

struct Fixture {
    uint256 seed;
    rc::Fri3AlgBatchProof proof;
    bind::BindingResult binding;
    fp::NormalizedAlgAirCodecDecoderAttachmentV1 decoder;
    fp::FoldBusComposition parent;
};

Fixture MakeFixture()
{
    Fixture out;
    out.seed = Seed(0xb4);
    const auto committed =
        rc::Fri3AlgP2Q192K2V10BatchCommit(
            Columns(), out.seed, 0);
    BOOST_REQUIRE_MESSAGE(committed.ok, committed.note);
    out.proof = committed.proof;
    out.binding =
        bind::BuildProofOwnedTranscriptBindingV10(
            out.proof, out.seed);
    BOOST_REQUIRE_MESSAGE(
        out.binding.valid, out.binding.note);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        fp::BuildNormalizedAlgAirBatchCodecMapV1(
            out.proof, out.decoder.map, &why),
        why);
    out.decoder.layout =
        fp::NormalizedAlgAirCodecDecoderLayout(0);
    const uint32_t needed_rows =
        std::max<uint32_t>(
            64,
            (5 + out.decoder.map.codec_words +
             fp::kNormalizedAlgAirCodecWordLanes - 1) /
                fp::kNormalizedAlgAirCodecWordLanes);
    out.decoder.parent_rows = 2;
    while (out.decoder.parent_rows < needed_rows) {
        out.decoder.parent_rows <<= 1;
    }
    out.decoder.active_word_slots =
        out.decoder.map.codec_words;
    out.decoder.valid_byte_slots =
        out.decoder.map.codec_bytes;
    out.decoder.canonical_fp_elements =
        out.decoder.map.fp_elements;
    out.decoder.added_columns =
        out.decoder.layout.End();
    out.decoder.exact_length_constrained = true;
    out.decoder.every_word_decomposed = true;
    out.decoder.every_byte_range_checked = true;
    out.decoder.little_endian_recomposition_constrained =
        true;
    out.decoder.final_word_padding_zero = true;
    out.decoder.every_fp_encoding_canonical = true;
    out.decoder.no_unconsumed_codec_bytes = true;
    out.decoder.valid = true;

    out.parent.combined.n_rows =
        out.decoder.parent_rows;
    out.parent.combined.n_columns =
        out.decoder.layout.End();
    out.parent.columns.assign(
        out.parent.combined.n_columns,
        std::vector<gf::Fp3>(
            out.parent.combined.n_rows,
            gf::Fp3::Zero()));
    for (uint32_t offset = 0;
         offset < out.decoder.map.codec_bytes; ++offset) {
        const uint32_t word = offset / 4;
        const uint32_t position = 5 + word;
        const uint32_t row =
            position /
            fp::kNormalizedAlgAirCodecWordLanes;
        const uint32_t lane =
            position %
            fp::kNormalizedAlgAirCodecWordLanes;
        const uint8_t byte = static_cast<uint8_t>(
            out.decoder.map.entries[word].value >>
            (8 * (offset % 4)));
        out.parent.columns[
            out.decoder.layout.Byte(
                lane, offset % 4)][row] =
            gf::Fp3::FromFp(gf::FromU64(byte));
    }
    return out;
}

fp::NormalizedAlgAirRemoteExportAttachmentV1
InstallRemoteConsumers(
    Fixture& fixture,
    const exports::InventoryV1& absent)
{
    fp::NormalizedAlgAirRemoteExportAttachmentV1 remote;
    remote.layout =
        fp::NormalizedAlgAirRemoteExportLayout(
            fixture.parent.combined.n_columns);
    remote.parent_rows =
        fixture.parent.combined.n_rows;
    remote.valid = true;
    remote.literal_same_row_aliases = true;
    fixture.parent.combined.n_columns =
        remote.layout.End();
    fixture.parent.columns.resize(
        fixture.parent.combined.n_columns,
        std::vector<gf::Fp3>(
            fixture.parent.combined.n_rows,
            gf::Fp3::Zero()));
    uint32_t slot = 0;
    for (const auto& consumer : absent.consumers) {
        if (consumer.event_ordinal < 5) continue;
        const uint32_t row =
            slot /
            fp::NormalizedAlgAirCodecCtlLayout::kPorts;
        const uint32_t port =
            slot %
            fp::NormalizedAlgAirCodecCtlLayout::kPorts;
        BOOST_REQUIRE_LT(row, remote.parent_rows);
        const auto& event =
            fixture.binding.consumer_manifest.entries[
                consumer.event_ordinal];
        const gf::Fp3 value =
            event.width == 1
            ? gf::Fp3::FromFp(gf::FromU64(
                  event.index_value))
            : event.fp3_value;
        fixture.parent.columns[
            remote.layout.bus.Value(false, port)][row] =
            value;
        fixture.parent.columns[
            remote.layout.bus.Address(false, port)][row] =
            gf::Fp3::FromFp(gf::FromU64(
                consumer.semantic_address));
        fixture.parent.columns[
            remote.layout.bus.Active(false, port)][row] =
            gf::Fp3::One();
        ++slot;
    }
    remote.remote_events = slot;
    remote.query_index_events =
        rc::kRCFri3AlgNumQueries;
    return remote;
}

fp::NormalizedAlgAirCodecCtlAttachmentV1
InstallCodecCtlConsumers(
    Fixture& fixture,
    const exports::InventoryV1& absent)
{
    fp::NormalizedAlgAirCodecCtlAttachmentV1 ctl;
    ctl.layout =
        fp::NormalizedAlgAirCodecCtlLayout(
            fixture.parent.combined.n_columns);
    ctl.parent_rows =
        fixture.parent.combined.n_rows;
    ctl.valid = true;
    ctl.exact_semantic_addresses = true;
    ctl.exact_multiplicity_one = true;
    ctl.dual_rational_identity_terminal_zero = true;
    ctl.denominator_nonzero = true;
    ctl.decoder_values_aliased = true;
    fixture.parent.combined.n_columns =
        ctl.layout.End();
    fixture.parent.columns.resize(
        fixture.parent.combined.n_columns,
        std::vector<gf::Fp3>(
            fixture.parent.combined.n_rows,
            gf::Fp3::Zero()));
    BOOST_REQUIRE_GE(absent.consumers.size(), 5U);
    for (uint32_t event = 0; event < 5; ++event) {
        const auto& consumer = absent.consumers[event];
        const uint32_t position =
            5 + consumer.codec_word;
        const uint32_t row =
            position /
            fp::NormalizedAlgAirCodecCtlLayout::kPorts;
        const uint32_t port =
            position %
            fp::NormalizedAlgAirCodecCtlLayout::kPorts;
        const gf::Fp3 value =
            fixture.binding.consumer_manifest.entries[
                event].fp3_value;
        fixture.parent.columns[
            ctl.layout.Value(false, port)][row] =
            value;
        fixture.parent.columns[
            ctl.layout.Address(false, port)][row] =
            gf::Fp3::FromFp(gf::FromU64(
                consumer.semantic_address));
        fixture.parent.columns[
            ctl.layout.Active(false, port)][row] =
            gf::Fp3::One();
        fixture.parent.columns[
            ctl.layout.ProducerFp3(port)][row] =
            gf::Fp3::One();
    }
    return ctl;
}

void WriteLE64(
    std::vector<unsigned char>& bytes,
    size_t offset,
    uint64_t value)
{
    BOOST_REQUIRE_LE(offset + 8, bytes.size());
    for (uint32_t byte = 0; byte < 8; ++byte) {
        bytes[offset + byte] =
            static_cast<unsigned char>(
                value >> (8 * byte));
    }
}

} // namespace

BOOST_AUTO_TEST_CASE(
    normalized_decoder_is_version_aware_and_canonical)
{
    Fixture fixture = MakeFixture();
    std::string why;
    BOOST_CHECK(fixture.decoder.map.valid);
    BOOST_CHECK_EQUAL(
        fixture.proof.version,
        rc::kRCFri3AlgP2Q192K2ProofVersionV10);

    std::vector<unsigned char> encoded;
    // Sequence the serialize call before reading encoded.size(): the order in
    // which BOOST_REQUIRE_EQUAL evaluates its two arguments is unspecified, and
    // SerializeFri3AlgBatchProof clears the output vector before filling it. On
    // this toolchain size() is evaluated first, so the check compared the real
    // byte count against 0 and the case was red in the default suite.
    const size_t written{
        rc::SerializeFri3AlgBatchProof(fixture.proof, encoded)};
    BOOST_REQUIRE_EQUAL(written, encoded.size());
    BOOST_CHECK_MESSAGE(
        fp::ValidateNormalizedAlgAirBatchCodecBytesV1(
            fixture.proof, encoded, &why),
        why);
    // The active V8 decoder must not accidentally parse V10.
    BOOST_CHECK(
        !rc::DeserializeFri3AlgBatchProof(
            encoded).has_value());

    const auto active =
        rc::Fri3AlgP2SqueezeBatchCommit(
            Columns(), fixture.seed, 0);
    BOOST_REQUIRE_MESSAGE(active.ok, active.note);
    fp::NormalizedAlgAirBatchCodecMapV1 active_map;
    BOOST_CHECK_MESSAGE(
        fp::BuildNormalizedAlgAirBatchCodecMapV1(
            active.proof, active_map, &why),
        why);
    BOOST_CHECK(active_map.valid);

    auto unsupported = fixture.proof;
    unsupported.version = 0x7ffffffeU;
    fp::NormalizedAlgAirBatchCodecMapV1 unsupported_map;
    BOOST_CHECK(
        !fp::BuildNormalizedAlgAirBatchCodecMapV1(
            unsupported, unsupported_map, &why));

    // x+p with x=0 aliases zero in Fp. Canonical roundtrip rejects the
    // alternate 64-bit encoding rather than treating it as the same cell.
    auto alias = encoded;
    const size_t lambda =
        64 + 4 * fixture.proof.column_len.size();
    WriteLE64(alias, lambda, gf::kP);
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirBatchCodecBytesV1(
            fixture.proof, alias, &why));

    auto wrong_endian = encoded;
    std::reverse(
        wrong_endian.begin() + lambda,
        wrong_endian.begin() + lambda + 8);
    BOOST_CHECK(
        !fp::ValidateNormalizedAlgAirBatchCodecBytesV1(
            fixture.proof, wrong_endian, &why));

    // A byte carry cannot be hidden in a field cell: 256 is outside the
    // boolean-decomposed byte range and differs from the exact decoder cell.
    const uint32_t nonce_word = 8 / 4;
    const uint32_t nonce_position = 5 + nonce_word;
    const uint32_t nonce_row =
        nonce_position /
        fp::kNormalizedAlgAirCodecWordLanes;
    const uint32_t nonce_lane =
        nonce_position %
        fp::kNormalizedAlgAirCodecWordLanes;
    fixture.parent.columns[
        fixture.decoder.layout.Byte(nonce_lane, 0)]
        [nonce_row] =
        gf::Fp3::FromFp(gf::FromU64(256));
    exports::InventoryV1 carried;
    BOOST_CHECK(
        !exports::BuildNormalizedV10ExportInventoryV1(
            fixture.proof, fixture.seed,
            fixture.binding, fixture.decoder,
            nullptr, &fixture.parent, nullptr, nullptr,
            carried, &why));
}

BOOST_AUTO_TEST_CASE(
    v10_prefix_inventory_preserves_misalignment_and_residuals)
{
    Fixture fixture = MakeFixture();
    exports::InventoryV1 absent;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        exports::BuildNormalizedV10ExportInventoryV1(
            fixture.proof, fixture.seed,
            fixture.binding, fixture.decoder,
            nullptr, &fixture.parent, nullptr, nullptr,
            absent, &why),
        why);
    BOOST_CHECK(absent.valid);
    BOOST_CHECK(absent.canonical_v10_binding);
    BOOST_CHECK(absent.codec_map_exact);
    BOOST_CHECK(absent.decoder_bytes_range_owned);
    BOOST_CHECK(absent.decoder_little_endian_owned);
    BOOST_CHECK(absent.decoder_goldilocks_canonical);
    BOOST_CHECK(!absent.every_prefix_byte_owned);
    BOOST_CHECK(!absent.every_consumer_owned);
    BOOST_CHECK(!absent.recursive_authority);
    BOOST_CHECK_EQUAL(
        absent.missing_fiat_shamir_consumer_events,
        absent.total_consumer_events);
    BOOST_CHECK_EQUAL(
        absent.total_consumer_events,
        5 + fixture.proof.fold_challenges.size() +
            rc::kRCFri3AlgNumQueries);
    BOOST_CHECK_GT(absent.missing_seed_bytes, 0U);
    BOOST_CHECK_GT(
        absent.missing_shape_commit_bytes, 0U);
    BOOST_CHECK_GT(
        absent.missing_ood_eval_commit_bytes, 0U);
    BOOST_CHECK_EQUAL(
        absent.row_commit_root.byte.size(), 32U);
    BOOST_REQUIRE_EQUAL(
        absent.fold_roots.size(),
        fixture.proof.fold_layers.size());
    for (const auto& root : absent.fold_roots) {
        BOOST_CHECK_EQUAL(root.byte.size(), 32U);
    }

    auto codec_ctl =
        InstallCodecCtlConsumers(fixture, absent);
    auto remote =
        InstallRemoteConsumers(fixture, absent);
    exports::InventoryV1 owned;
    BOOST_REQUIRE_MESSAGE(
        exports::BuildNormalizedV10ExportInventoryV1(
            fixture.proof, fixture.seed,
            fixture.binding, fixture.decoder,
            &codec_ctl, &fixture.parent, &remote, nullptr,
            owned, &why),
        why);
    BOOST_CHECK(owned.fold_query_remote_exports_owned);
    BOOST_CHECK_EQUAL(
        owned.verifier_owned_fold_events,
        fixture.proof.fold_challenges.size());
    BOOST_CHECK_EQUAL(
        owned.verifier_owned_query_events,
        rc::kRCFri3AlgNumQueries);
    BOOST_CHECK_EQUAL(
        owned.verifier_owned_deep_fs_events, 5U);
    BOOST_CHECK_EQUAL(
        owned.missing_fiat_shamir_consumer_events, 0U);
    BOOST_CHECK(owned.every_consumer_owned);
    BOOST_TEST_MESSAGE(
        "V10_EXPORT_OWNERSHIP prefix_bytes="
        << owned.total_distinct_prefix_bytes
        << " codec=" << owned.codec_decoder_owned_bytes
        << " fixed=" << owned.fixed_protocol_bytes
        << " seed_missing=" << owned.missing_seed_bytes
        << " shape_missing="
        << owned.missing_shape_commit_bytes
        << " ood_missing="
        << owned.missing_ood_eval_commit_bytes
        << " consumers=" << owned.total_consumer_events
        << " remote_owned="
        << owned.verifier_owned_consumer_events
        << " fs_missing="
        << owned.missing_fiat_shamir_consumer_events
        << " residuals=" << owned.residuals.size());

    p2air::BuildResult transcript;
    BOOST_REQUIRE_MESSAGE(
        p2air::AppendTranscriptAirV10ToParent(
            fixture.parent.combined,
            fixture.parent.columns,
            fixture.binding.statement,
            transcript, &why),
        why);
    BOOST_REQUIRE(transcript.valid);
    join::JoinPlanV1 plan;
    uint32_t joined_words = 0;
    uint32_t cross_rows = 0;
    std::vector<std::string> residuals;
    BOOST_REQUIRE_MESSAGE(
        exports::BuildOwnedSubsetJoinPlanV1(
            owned, transcript, plan,
            joined_words, cross_rows,
            residuals, &why),
        why);
    // The 30-byte V10 domain shifts the nonce by two bytes. Cross-row words
    // are retained for the carry-safe transport gadget, not omitted.
    BOOST_CHECK_GT(cross_rows, 0U);
    BOOST_CHECK_GT(joined_words, 0U);
    BOOST_CHECK_EQUAL(
        plan.fri_consumer_equalities,
        owned.total_consumer_events);
    BOOST_CHECK(!residuals.empty());
    BOOST_TEST_MESSAGE(
        "V10_EXPORT_JOIN joined_prefix_words="
        << joined_words
        << " cross_decoder_rows=" << cross_rows
        << " joined_consumers="
        << plan.fri_consumer_equalities
        << " residuals=" << residuals.size());

    join::AppendResultV1 appended;
    BOOST_REQUIRE_MESSAGE(
        join::AppendSameParentJoinV1(
            fixture.parent.combined,
            fixture.parent.columns,
            plan, appended, &why),
        why);
    BOOST_CHECK_EQUAL(
        join::CountViolations(
            fixture.parent.combined,
            fixture.parent.columns),
        0U);
    BOOST_CHECK_EQUAL(
        appended.equality_count,
        plan.equalities.size());

    size_t transported = appended.equality_layouts.size();
    for (size_t i = 0;
         i < appended.equality_layouts.size(); ++i) {
        if (!appended.equality_layouts[i]
                 .transport_carriers.empty()) {
            transported = i;
            break;
        }
    }
    BOOST_REQUIRE_LT(
        transported, appended.equality_layouts.size());
    BOOST_REQUIRE(
        !appended.equality_layouts[transported]
             .transport_carriers.empty());
    auto attack = fixture.parent.columns;
    const uint32_t transport_carrier =
        appended.equality_layouts[transported]
            .transport_carriers.front();
    const uint32_t carry_selector =
        appended.equality_layouts[transported]
            .transport_carry_selectors.front();
    uint32_t carried_row = 0;
    while (carried_row + 1 <
               fixture.parent.combined.n_rows &&
           gf::IsZero(
               attack[carry_selector][carried_row])) {
        ++carried_row;
    }
    BOOST_REQUIRE_LT(
        carried_row + 1,
        fixture.parent.combined.n_rows);
    attack[transport_carrier][carried_row] =
        gf::Add(
            attack[transport_carrier][carried_row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        join::CountViolations(
            fixture.parent.combined, attack),
        0U);

    attack = fixture.parent.columns;
    BOOST_REQUIRE(
        owned.consumers[0].verifier_owned);
    const auto first_fs_consumer =
        owned.consumers[0].parent_cell;
    attack[first_fs_consumer.column]
          [first_fs_consumer.row] =
        gf::Add(
            attack[first_fs_consumer.column]
                  [first_fs_consumer.row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        join::CountViolations(
            fixture.parent.combined, attack),
        0U);
}

BOOST_AUTO_TEST_CASE(
    omitted_relabelled_and_misaddressed_consumers_reject)
{
    Fixture fixture = MakeFixture();
    exports::InventoryV1 absent;
    std::string why;
    BOOST_REQUIRE(
        exports::BuildNormalizedV10ExportInventoryV1(
            fixture.proof, fixture.seed,
            fixture.binding, fixture.decoder,
            nullptr, &fixture.parent, nullptr, nullptr,
            absent, &why));

    auto omitted = fixture.binding;
    omitted.consumer_manifest.entries.pop_back();
    exports::InventoryV1 ignored;
    BOOST_CHECK(
        !exports::BuildNormalizedV10ExportInventoryV1(
            fixture.proof, fixture.seed,
            omitted, fixture.decoder,
            nullptr, &fixture.parent, nullptr, nullptr,
            ignored, &why));

    auto relabelled = fixture.binding;
    const size_t first_query =
        5 + fixture.proof.fold_challenges.size();
    BOOST_REQUIRE_LT(
        first_query,
        relabelled.consumer_manifest.entries.size());
    ++relabelled.consumer_manifest.entries[
          first_query].semantic_index;
    BOOST_CHECK(
        !exports::BuildNormalizedV10ExportInventoryV1(
            fixture.proof, fixture.seed,
            relabelled, fixture.decoder,
            nullptr, &fixture.parent, nullptr, nullptr,
            ignored, &why));

    auto remote =
        InstallRemoteConsumers(fixture, absent);
    const auto& victim = absent.consumers[first_query];
    bool corrupted = false;
    for (uint32_t row = 0;
         row < remote.parent_rows && !corrupted; ++row) {
        for (uint32_t port = 0;
             port <
                 fp::NormalizedAlgAirCodecCtlLayout::kPorts;
             ++port) {
            const uint32_t address_col =
                remote.layout.bus.Address(false, port);
            const uint32_t active_col =
                remote.layout.bus.Active(false, port);
            if (!gf::IsZero(
                    fixture.parent.columns[
                        active_col][row]) &&
                gf::Canonical(
                    fixture.parent.columns[
                        address_col][row].c0) ==
                    victim.semantic_address) {
                fixture.parent.columns[
                    address_col][row] =
                    gf::Fp3::FromFp(gf::FromU64(
                        victim.semantic_address + 1));
                corrupted = true;
                break;
            }
        }
    }
    BOOST_REQUIRE(corrupted);
    exports::InventoryV1 misaddressed;
    BOOST_REQUIRE(
        exports::BuildNormalizedV10ExportInventoryV1(
            fixture.proof, fixture.seed,
            fixture.binding, fixture.decoder,
            nullptr, &fixture.parent, &remote, nullptr,
            misaddressed, &why));
    BOOST_CHECK(!misaddressed.fold_query_remote_exports_owned);
    BOOST_CHECK_EQUAL(
        misaddressed.verifier_owned_query_events,
        rc::kRCFri3AlgNumQueries - 1);
    BOOST_CHECK_EQUAL(
        misaddressed.missing_fiat_shamir_consumer_events,
        6U);
    BOOST_CHECK(!misaddressed.recursive_authority);
}

BOOST_AUTO_TEST_SUITE_END()
