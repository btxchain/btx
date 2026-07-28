// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_winner_capture.h>

#include <primitives/block.h>

#include <boost/test/unit_test.hpp>

#include <array>

namespace {

namespace rc = matmul::v4::rc;

uint256 H(uint8_t value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{
        Span<const unsigned char>{
            bytes.data(), bytes.size()}};
}

CBlockHeader Header(uint64_t nonce)
{
    CBlockHeader out;
    out.nVersion = 0x20000004;
    out.hashPrevBlock = H(0x41);
    out.hashMerkleRoot = H(0x72);
    out.nTime = 1'770'000'000;
    out.nBits = 0x207fffffU;
    out.nNonce = static_cast<uint32_t>(nonce);
    out.nNonce64 = nonce;
    out.seed_a = H(0x13);
    out.seed_b = H(0x24);
    out.matmul_digest = H(0x35);
    return out;
}

class CountingForwardSink final
    : public rc::RCCoupProofWitnessSink {
public:
    explicit CountingForwardSink(
        rc::RCStage3CoupledWinnerCaptureV1& capture)
        : m_capture(capture)
    {
    }

    void OnInitialState(
        const rc::RCCoupInitialStateProofWitnessView& view) override
    {
        ++initial_calls;
        m_capture.OnInitialState(view);
    }
    void OnGemm(
        const rc::RCCoupGemmProofWitnessView& view) override
    {
        ++gemm_calls;
        m_capture.OnGemm(view);
    }
    void OnPermutation(
        const rc::RCCoupPermutationProofWitnessView& view) override
    {
        m_capture.OnPermutation(view);
    }
    void OnMix(
        const rc::RCCoupMixProofWitnessView& view) override
    {
        m_capture.OnMix(view);
    }
    void OnMaterialExchange(
        const rc::RCCoupMaterialExchangeProofWitnessView& view) override
    {
        m_capture.OnMaterialExchange(view);
    }
    void OnBarrier(
        const rc::RCCoupBarrierProofWitnessView& view) override
    {
        m_capture.OnBarrier(view);
    }
    void OnEpisode(
        const rc::RCCoupEpisodeProofWitnessView& view) override
    {
        ++terminal_calls;
        m_capture.OnEpisode(view);
    }

    uint32_t initial_calls{0};
    uint64_t gemm_calls{0};
    uint32_t terminal_calls{0};

private:
    rc::RCStage3CoupledWinnerCaptureV1& m_capture;
};

class DropFirstGemm final : public rc::RCCoupProofWitnessSink {
public:
    explicit DropFirstGemm(
        rc::RCStage3CoupledWinnerCaptureV1& capture)
        : m_capture(capture)
    {
    }

    void OnInitialState(
        const rc::RCCoupInitialStateProofWitnessView& view) override
    {
        m_capture.OnInitialState(view);
    }

    void OnGemm(
        const rc::RCCoupGemmProofWitnessView& view) override
    {
        if (!m_dropped) {
            m_dropped = true;
            return;
        }
        m_capture.OnGemm(view);
    }

    void OnPermutation(
        const rc::RCCoupPermutationProofWitnessView& view) override
    {
        m_capture.OnPermutation(view);
    }

    void OnMix(
        const rc::RCCoupMixProofWitnessView& view) override
    {
        m_capture.OnMix(view);
    }

    void OnMaterialExchange(
        const rc::RCCoupMaterialExchangeProofWitnessView& view) override
    {
        m_capture.OnMaterialExchange(view);
    }

    void OnBarrier(
        const rc::RCCoupBarrierProofWitnessView& view) override
    {
        m_capture.OnBarrier(view);
    }

    void OnEpisode(
        const rc::RCCoupEpisodeProofWitnessView& view) override
    {
        m_capture.OnEpisode(view);
    }

private:
    rc::RCStage3CoupledWinnerCaptureV1& m_capture;
    bool m_dropped{false};
};

void Recommit(
    rc::RCStage3CoupledWinnerReceiptV1& receipt,
    uint32_t barrier,
    uint32_t lobe,
    uint32_t page)
{
    auto& barrier_item = receipt.barriers.at(barrier);
    auto& lobe_item = barrier_item.lobes.at(lobe);
    auto& page_item = lobe_item.pages.at(page);
    page_item.event_commitment =
        rc::CommitRCStage3CoupledPageCaptureV1(
            page_item);
    lobe_item.lobe_commitment =
        rc::CommitRCStage3CoupledLobeCaptureV1(
            lobe_item);
    barrier_item.stage_adjacency_commitment =
        rc::CommitRCStage3CoupledBarrierCaptureV1(
            barrier_item);
    receipt.receipt_commitment =
        rc::CommitRCStage3CoupledWinnerReceiptV2(
            receipt);
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_coupled_winner_capture_tests)

BOOST_AUTO_TEST_CASE(
    real_winner_callbacks_make_bounded_header_bound_receipt)
{
    constexpr int32_t kHeight = 707;
    const CBlockHeader header = Header(19);
    const rc::RCCoupParams params =
        rc::MakeToyRCCoupParams();
    rc::RCCoupOptions options;
    options.mode = rc::RCCoupExecMode::Streamed;
    options.full_bank_schedule = true;

    rc::RCStage3CoupledWinnerCaptureV1 capture(
        header, kHeight, params, options);
    const uint256 digest =
        rc::MineCoupledPuzzleWithProofWitness(
            header, kHeight, params,
            capture, {}, options);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        capture.Complete(&why), why);
    const auto& receipt = capture.Receipt();
    BOOST_CHECK(receipt.coupled_digest == digest);
    BOOST_CHECK_EQUAL(
        receipt.gemm_callbacks,
        uint64_t{params.barriers} *
            params.lobes *
            params.pages_per_barrier_lobe);
    BOOST_CHECK_EQUAL(
        receipt.barriers.size(),
        params.barriers);
    BOOST_CHECK(
        receipt.retained_receipt_bytes_upper_bound <
        receipt.captured_payload_bytes);
    BOOST_CHECK_EQUAL(
        receipt.peak_accumulation_scratch_bytes,
        uint64_t{
            params.rows_per_lobe == 0
                ? 1
                : params.rows_per_lobe} *
            params.lobe_width *
            sizeof(int64_t));
    BOOST_CHECK(receipt.no_bank_pages_retained);
    BOOST_CHECK(
        receipt.no_flat_tile_proofs_materialized);
    BOOST_CHECK(
        !receipt.recursive_relation_proofs_bound);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3CoupledWinnerReceiptV2(
            header, kHeight, params, options,
            receipt, &why),
        why);

    CBlockHeader other = header;
    ++other.nNonce64;
    ++other.nNonce;
    BOOST_CHECK(
        !rc::VerifyRCStage3CoupledWinnerReceiptV2(
            other, kHeight, params, options,
            receipt, &why));
}

BOOST_AUTO_TEST_CASE(
    precommit_single_pass_finalizes_once_without_replay)
{
    constexpr int32_t kHeight = 711;
    CBlockHeader prefinal = Header(23);
    prefinal.matmul_digest.SetNull();
    const rc::RCCoupParams params =
        rc::MakeToyRCCoupParams();
    rc::RCCoupOptions options;
    options.mode = rc::RCCoupExecMode::Streamed;
    options.full_bank_schedule = true;

    rc::RCStage3CoupledWinnerCaptureV1 capture(
        prefinal, kHeight, params, options);
    CountingForwardSink counted(capture);
    const uint256 coupled_digest =
        rc::MineCoupledPuzzleWithProofWitness(
            prefinal, kHeight, params,
            counted, {}, options);
    BOOST_REQUIRE(!coupled_digest.IsNull());
    BOOST_CHECK_EQUAL(counted.initial_calls, 1U);
    BOOST_CHECK_EQUAL(counted.terminal_calls, 1U);
    BOOST_CHECK_EQUAL(
        counted.gemm_calls,
        uint64_t{params.barriers} *
            params.lobes *
            params.pages_per_barrier_lobe);

    std::string why;
    BOOST_CHECK(!capture.Complete(&why));
    BOOST_CHECK(
        why.find("incomplete") !=
        std::string::npos);
    CBlockHeader finalized = prefinal;
    finalized.matmul_digest = H(0x81);
    BOOST_REQUIRE_MESSAGE(
        capture.FinalizeHeaderBindingV2(
            finalized, coupled_digest, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        capture.Complete(&why), why);
    BOOST_CHECK(
        capture.Receipt().winner_header_precommit ==
        rc::CommitRCStage3CoupledWinnerHeaderPrecommitV2(
            finalized));
    BOOST_CHECK(
        capture.Receipt().finalized_header_hash ==
        finalized.GetHash());

    // The terminal binding is one-shot, and neither a wrong workload terminal
    // nor a changed immutable header can be finalized.
    BOOST_CHECK(
        !capture.FinalizeHeaderBindingV2(
            finalized, coupled_digest, &why));
    BOOST_CHECK(
        why.find("header_binding_repeated") !=
        std::string::npos);

    {
        CBlockHeader base = prefinal;
        rc::RCStage3CoupledWinnerCaptureV1 wrong_terminal(
            base, kHeight, params, options);
        const uint256 digest =
            rc::MineCoupledPuzzleWithProofWitness(
                base, kHeight, params,
                wrong_terminal, {}, options);
        CBlockHeader final = base;
        final.matmul_digest = H(0x82);
        BOOST_CHECK(
            !wrong_terminal.FinalizeHeaderBindingV2(
                final, H(0x99), &why));
        BOOST_CHECK(
            why.find("header_binding_terminal") !=
            std::string::npos);
        BOOST_CHECK(!digest.IsNull());
    }
    {
        CBlockHeader base = prefinal;
        rc::RCStage3CoupledWinnerCaptureV1 changed_context(
            base, kHeight, params, options);
        const uint256 digest =
            rc::MineCoupledPuzzleWithProofWitness(
                base, kHeight, params,
                changed_context, {}, options);
        CBlockHeader final = base;
        ++final.nNonce64;
        ++final.nNonce;
        final.matmul_digest = H(0x83);
        BOOST_CHECK(
            !changed_context.FinalizeHeaderBindingV2(
                final, digest, &why));
        BOOST_CHECK(
            why.find("header_binding_context") !=
            std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(
    coherent_schedule_and_adjacency_tampering_reject)
{
    constexpr int32_t kHeight = 708;
    const CBlockHeader header = Header(20);
    const rc::RCCoupParams params =
        rc::MakeToyRCCoupParams();
    rc::RCCoupOptions options;
    options.mode = rc::RCCoupExecMode::Streamed;
    options.full_bank_schedule = true;
    rc::RCStage3CoupledWinnerCaptureV1 capture(
        header, kHeight, params, options);
    BOOST_REQUIRE(
        !rc::MineCoupledPuzzleWithProofWitness(
             header, kHeight, params,
             capture, {}, options)
             .IsNull());
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        capture.Complete(&why), why);

    {
        auto omitted = capture.Receipt();
        omitted.barriers[0].lobes[0].pages.erase(
            omitted.barriers[0].lobes[0].pages.begin());
        omitted.barriers[0].lobes[0].lobe_commitment =
            rc::CommitRCStage3CoupledLobeCaptureV1(
                omitted.barriers[0].lobes[0]);
        omitted.barriers[0].stage_adjacency_commitment =
            rc::CommitRCStage3CoupledBarrierCaptureV1(
                omitted.barriers[0]);
        omitted.receipt_commitment =
            rc::CommitRCStage3CoupledWinnerReceiptV2(
                omitted);
        BOOST_CHECK(
            !rc::VerifyRCStage3CoupledWinnerReceiptV2(
                header, kHeight, params,
                options, omitted, &why));
    }
    {
        auto reordered = capture.Receipt();
        auto& pages =
            reordered.barriers[0].lobes[0].pages;
        BOOST_REQUIRE(pages.size() >= 2);
        std::swap(pages[0], pages[1]);
        for (uint32_t page = 0;
             page < pages.size(); ++page) {
            pages[page].page_ordinal = page;
            pages[page].event_commitment =
                rc::CommitRCStage3CoupledPageCaptureV1(
                    pages[page]);
        }
        reordered.barriers[0].lobes[0].lobe_commitment =
            rc::CommitRCStage3CoupledLobeCaptureV1(
                reordered.barriers[0].lobes[0]);
        reordered.barriers[0].stage_adjacency_commitment =
            rc::CommitRCStage3CoupledBarrierCaptureV1(
                reordered.barriers[0]);
        reordered.receipt_commitment =
            rc::CommitRCStage3CoupledWinnerReceiptV2(
                reordered);
        BOOST_CHECK(
            !rc::VerifyRCStage3CoupledWinnerReceiptV2(
                header, kHeight, params,
                options, reordered, &why));
    }
    {
        auto broken_chain = capture.Receipt();
        auto& pages =
            broken_chain.barriers[0]
                .lobes[0].pages;
        BOOST_REQUIRE(pages.size() >= 2);
        pages[1].accumulation_before_root = H(0xa5);
        Recommit(broken_chain, 0, 0, 1);
        BOOST_CHECK(
            !rc::VerifyRCStage3CoupledWinnerReceiptV2(
                header, kHeight, params,
                options, broken_chain, &why));
    }
    {
        auto digest_substitution = capture.Receipt();
        digest_substitution.coupled_digest = H(0x5a);
        digest_substitution.receipt_commitment =
            rc::CommitRCStage3CoupledWinnerReceiptV2(
                digest_substitution);
        BOOST_CHECK(
            !rc::VerifyRCStage3CoupledWinnerReceiptV2(
                header, kHeight, params,
                options, digest_substitution,
                &why));
    }
}

BOOST_AUTO_TEST_CASE(
    missing_real_callback_fails_closed)
{
    constexpr int32_t kHeight = 709;
    const CBlockHeader header = Header(21);
    const rc::RCCoupParams params =
        rc::MakeToyRCCoupParams();
    rc::RCCoupOptions options;
    options.mode = rc::RCCoupExecMode::Streamed;
    options.full_bank_schedule = true;
    rc::RCStage3CoupledWinnerCaptureV1 capture(
        header, kHeight, params, options);
    DropFirstGemm proxy(capture);
    BOOST_REQUIRE(
        !rc::MineCoupledPuzzleWithProofWitness(
             header, kHeight, params,
             proxy, {}, options)
             .IsNull());
    std::string why;
    BOOST_CHECK(!capture.Complete(&why));
    BOOST_CHECK(!why.empty());
}

BOOST_AUTO_TEST_CASE(
    winner_store_is_header_keyed_single_slot_and_rejects_incomplete)
{
    constexpr int32_t kHeight = 710;
    const CBlockHeader header = Header(22);
    const rc::RCCoupParams params =
        rc::MakeToyRCCoupParams();
    rc::RCCoupOptions options;
    options.mode = rc::RCCoupExecMode::Streamed;
    options.full_bank_schedule = true;

    rc::RCStage3CoupledWinnerStoreClearForTestV1();
    auto capture = std::make_shared<
        rc::RCStage3CoupledWinnerCaptureV1>(
            header, kHeight, params, options);
    BOOST_REQUIRE(
        !rc::MineCoupledPuzzleWithProofWitness(
             header, kHeight, params,
             *capture, {}, options)
             .IsNull());
    std::string why;
    BOOST_REQUIRE_MESSAGE(capture->Complete(&why), why);
    const uint256 key = header.GetHash();
    BOOST_REQUIRE_MESSAGE(
        rc::RCStage3CoupledWinnerStorePutV1(
            key, capture, &why),
        why);
    BOOST_CHECK(
        rc::RCStage3CoupledWinnerStoreGetV1(key) ==
        capture);

    CBlockHeader other = header;
    ++other.nNonce64;
    ++other.nNonce;
    BOOST_CHECK(
        rc::RCStage3CoupledWinnerStoreGetV1(
            other.GetHash()) == nullptr);
    BOOST_CHECK(
        !rc::RCStage3CoupledWinnerStorePutV1(
            other.GetHash(), capture, &why));
    BOOST_CHECK(
        rc::RCStage3CoupledWinnerStoreGetV1(key) ==
        capture);
    rc::RCStage3CoupledWinnerStoreEraseV1(
        other.GetHash());
    BOOST_CHECK(
        rc::RCStage3CoupledWinnerStoreGetV1(key) ==
        capture);
    rc::RCStage3CoupledWinnerStoreEraseV1(key);
    BOOST_CHECK(
        rc::RCStage3CoupledWinnerStoreGetV1(key) ==
        nullptr);

    auto incomplete = std::make_shared<
        rc::RCStage3CoupledWinnerCaptureV1>(
            header, kHeight, params, options);
    BOOST_CHECK(
        !rc::RCStage3CoupledWinnerStorePutV1(
            key, incomplete, &why));
    BOOST_CHECK(
        rc::RCStage3CoupledWinnerStoreGetV1(key) ==
        nullptr);
}

BOOST_AUTO_TEST_SUITE_END()
