// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_winner_child_binding.h>

#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <primitives/block.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <limits>
#include <utility>
#include <vector>

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

CBlockHeader Header()
{
    CBlockHeader out;
    out.nVersion = 0x20000004;
    out.hashPrevBlock = H(0x31);
    out.hashMerkleRoot = H(0x42);
    out.nTime = 1'770'000'100;
    out.nBits = 0x207fffffU;
    out.nNonce = 17;
    out.nNonce64 = 17;
    out.seed_a = H(0x53);
    out.seed_b = H(0x64);
    return out;
}

rc::RCCoupParams Params()
{
    rc::RCCoupParams out;
    out.barriers = 4;
    out.lobes = 1;
    out.lobe_width = 32;
    out.bank_pages = 1;
    out.rows_per_lobe = 1;
    out.pages_per_barrier_lobe = 1;
    return out;
}

rc::RCCoupOptions Options()
{
    rc::RCCoupOptions out;
    out.mode = rc::RCCoupExecMode::Streamed;
    out.transcript_version = rc::ENC_RC_V4;
    out.full_bank_schedule = true;
    out.material_exchange = false;
    out.exchange_rows = 32;
    out.exchange_rounds = 0;
    return out;
}

rc::RCStage3SuccinctProof Statement(
    const CBlockHeader& header,
    int32_t height,
    const uint256& coupled_digest)
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Composed;
    out.public_inputs.height = height;
    out.public_inputs.n_bits = header.nBits;
    out.public_inputs.episode_profile = 2;
    out.public_inputs.coupled_profile = 4;
    out.public_inputs.transcript_version = rc::ENC_RC_V4;
    out.public_inputs.header_commitment =
        rc::RCStage3HeaderCommitment(header);
    out.public_inputs.params_commitment = H(0x75);
    out.public_inputs.sigma =
        matmul::v4::DeriveSigma(header);
    out.public_inputs.episode_digest = H(0x86);
    out.public_inputs.coupled_digest = coupled_digest;
    out.public_inputs.program_consensus_pin
        .recursive_alg_hash_root = H(0x97);
    out.public_inputs.program_consensus_pin
        .external_sha256d_audit_root = H(0xa8);
    out.public_inputs.program_consensus_pin
        .registry_binding = H(0xb9);
    arith_uint256 target;
    target.SetCompact(header.nBits);
    out.public_inputs.target = ArithToUint256(target);
    const auto roles =
        rc::RequiredRCStage3RelationRoles(out.statement);
    for (uint32_t i = 0; i < roles.size(); ++i) {
        out.commitments.push_back(
            {roles[i],
             H(static_cast<uint8_t>(0xc0 + i))});
        out.sections.push_back(
            {roles[i],
             {static_cast<uint8_t>(i), 0xa5, 0x5a}});
    }
    out.public_inputs.final_digest =
        rc::ComputeRCStage3FinalDigest(out);
    out.public_inputs.transcript_commitment =
        rc::ComputeRCStage3TranscriptCommitment(out);
    return out;
}

struct Stage {
    uint32_t barrier{0};
    uint32_t round{0};
    std::vector<int64_t> input;
    std::vector<int64_t> output;
};

class ProofOwnedCapture final
    : public rc::RCCoupProofWitnessSink {
public:
    explicit ProofOwnedCapture(
        rc::RCStage3CoupledWinnerCaptureV1& winner)
        : m_winner(winner)
    {
    }

    void OnInitialState(
        const rc::RCCoupInitialStateProofWitnessView& view) override
    {
        m_winner.OnInitialState(view);
        initial_state.assign(
            view.state, view.state + view.state_cells);
    }

    void OnGemm(
        const rc::RCCoupGemmProofWitnessView& view) override
    {
        m_winner.OnGemm(view);
        rc::RCStage3CoupledGemmOpening opening;
        const uint64_t output_cells =
            uint64_t{view.rows} * view.width;
        const uint64_t page_cells =
            uint64_t{view.width} * view.width;
        opening.operand_a.assign(
            view.operand_a,
            view.operand_a + output_cells);
        opening.operand_b.assign(
            view.operand_b,
            view.operand_b + page_cells);
        opening.output_y.assign(
            view.gemm_y,
            view.gemm_y + output_cells);
        gemm_openings.push_back(std::move(opening));
    }

    void OnPermutation(
        const rc::RCCoupPermutationProofWitnessView& view) override
    {
        m_winner.OnPermutation(view);
        permutations.push_back(
            CopyStage(
                view.barrier, 0, view.state_cells,
                view.input, view.output));
    }

    void OnMix(
        const rc::RCCoupMixProofWitnessView& view) override
    {
        m_winner.OnMix(view);
        mixes.push_back(
            CopyStage(
                view.barrier, 0, view.state_cells,
                view.input, view.output));
    }

    void OnMaterialExchange(
        const rc::RCCoupMaterialExchangeProofWitnessView& view) override
    {
        m_winner.OnMaterialExchange(view);
        material.push_back(
            CopyStage(
                view.barrier, view.round,
                view.state_cells,
                view.input, view.output));
    }

    void OnBarrier(
        const rc::RCCoupBarrierProofWitnessView& view) override
    {
        m_winner.OnBarrier(view);
        std::vector<int64_t> extract(
            view.extract_input,
            view.extract_input + view.state_cells);
        for (uint32_t tile = 0;
             tile < view.state_cells / rc::kRCMxBlockLen;
             ++tile) {
            std::array<int64_t, rc::kRCMxBlockLen> values{};
            std::copy_n(
                extract.begin() +
                    uint64_t{tile} * rc::kRCMxBlockLen,
                rc::kRCMxBlockLen, values.begin());
            extract_inputs.push_back(values);
        }
        barrier_states.emplace_back(
            view.extract_output,
            view.extract_output + view.state_cells);
    }

    void OnEpisode(
        const rc::RCCoupEpisodeProofWitnessView& view) override
    {
        m_winner.OnEpisode(view);
        bank_root = view.bank_root;
        digest = view.coupled_digest;
    }

    rc::RCStage3CoupledExchangePermutationWitness
    ExchangeWitness(
        const rc::RCCoupParams& params) const
    {
        rc::RCStage3CoupledExchangePermutationWitness out;
        const uint64_t lobe_cells =
            uint64_t{params.rows_per_lobe} *
            params.lobe_width;
        for (const auto& stage : permutations) {
            out.permutation_inputs.push_back(stage.input);
            for (uint32_t lobe = 0;
                 lobe < params.lobes; ++lobe) {
                out.fixed_exchange_inputs.emplace_back(
                    stage.input.begin() +
                        uint64_t{lobe} * lobe_cells,
                    stage.input.begin() +
                        uint64_t{lobe + 1} * lobe_cells);
            }
        }
        for (const auto& stage : material) {
            out.material_exchange_inputs.push_back(
                stage.input);
        }
        return out;
    }

    std::vector<std::vector<int64_t>> MixInputs() const
    {
        std::vector<std::vector<int64_t>> out;
        for (const auto& stage : mixes) {
            out.push_back(stage.input);
        }
        return out;
    }

    static Stage CopyStage(
        uint32_t barrier,
        uint32_t round,
        uint32_t cells,
        const int64_t* input,
        const int64_t* output)
    {
        Stage out;
        out.barrier = barrier;
        out.round = round;
        out.input.assign(input, input + cells);
        out.output.assign(output, output + cells);
        return out;
    }

    rc::RCStage3CoupledWinnerCaptureV1& m_winner;
    std::vector<int8_t> initial_state;
    std::vector<rc::RCStage3CoupledGemmOpening> gemm_openings;
    std::vector<Stage> permutations;
    std::vector<Stage> mixes;
    std::vector<Stage> material;
    std::vector<std::array<int64_t, rc::kRCMxBlockLen>>
        extract_inputs;
    std::vector<std::vector<uint8_t>> barrier_states;
    uint256 bank_root{};
    uint256 digest{};
};

struct Fixture {
    static Fixture Build()
    {
        Fixture fixture;
        std::string why;
        // The production solver first discovers the coupled digest, installs
        // the composed digest in the header, and only then performs the
        // winner-only proof-witness reseal.  Mirror that exact ordering so
        // the capture roots are keyed by the finalized header identity.
        uint256 discovered_digest;
        {
            rc::RCStage3CoupledWinnerCaptureV1 discovery_capture(
                fixture.header, fixture.height,
                fixture.params, fixture.options);
            ProofOwnedCapture discovery_sink(discovery_capture);
            discovered_digest =
                rc::MineCoupledPuzzleWithProofWitness(
                    fixture.header, fixture.height,
                    fixture.params, discovery_sink, {},
                    fixture.options);
        }
        BOOST_REQUIRE_MESSAGE(
            !discovered_digest.IsNull(),
            "winner discovery");
        const auto provisional_statement =
            Statement(
                fixture.header, fixture.height,
                discovered_digest);
        fixture.header.matmul_digest =
            provisional_statement.public_inputs.final_digest;

        rc::RCStage3CoupledWinnerCaptureV1 capture(
            fixture.header, fixture.height,
            fixture.params, fixture.options);
        ProofOwnedCapture sink(capture);
        fixture.digest =
            rc::MineCoupledPuzzleWithProofWitness(
                fixture.header, fixture.height,
                fixture.params, sink, {},
                fixture.options);
        BOOST_REQUIRE_MESSAGE(
            !fixture.digest.IsNull(), "winner computation");
        BOOST_REQUIRE(
            fixture.digest == discovered_digest);
        BOOST_REQUIRE_MESSAGE(capture.Complete(&why), why);
        fixture.winner = capture.Receipt();
        BOOST_REQUIRE_MESSAGE(
            rc::VerifyRCStage3CoupledWinnerReceiptV2(
                fixture.header, fixture.height,
                fixture.params, fixture.options,
                fixture.winner, &why),
            why);
        fixture.statement =
            Statement(
                fixture.header, fixture.height,
                fixture.digest);
        fixture.shape =
            rc::MakeRCStage3CoupledShape(
                fixture.params, fixture.options);

        BOOST_TEST_MESSAGE("coupled binder phase: bank proof");
        BOOST_REQUIRE_MESSAGE(
            rc::ProveRCStage3CoupledBankProduct(
                fixture.statement, fixture.header,
                fixture.shape, fixture.children.bank,
                &why),
            why);
        BOOST_TEST_MESSAGE("coupled binder phase: initial-state proof");
        BOOST_REQUIRE_MESSAGE(
            rc::ProveRCStage3CoupledInitialStateProduct(
                fixture.statement, fixture.shape,
                fixture.children.initial_state,
                &why),
            why);
        BOOST_TEST_MESSAGE("coupled binder phase: GEMM proofs");
        BOOST_REQUIRE_MESSAGE(
            rc::ProveRCStage3CoupledGemmProduct(
                fixture.statement, fixture.shape,
                sink.gemm_openings,
                fixture.children.gemm, &why),
            why);
        BOOST_TEST_MESSAGE("coupled binder phase: signed-range link");
        BOOST_REQUIRE_MESSAGE(
            rc::ProveRCStage3CoupledSignedRangeGemmLink(
                fixture.statement, fixture.shape,
                fixture.children.gemm,
                fixture.children.signed_range,
                &why),
            why);
        BOOST_TEST_MESSAGE(
            "coupled binder phase: exchange/permutation proofs");
        BOOST_REQUIRE_MESSAGE(
            rc::ProveRCStage3CoupledExchangePermutationProduct(
                fixture.statement, fixture.shape,
                sink.ExchangeWitness(fixture.params),
                fixture.children.exchange_permutation,
                &why),
            why);
        BOOST_TEST_MESSAGE("coupled binder phase: mix proofs");
        BOOST_REQUIRE_MESSAGE(
            rc::ProveRCStage3CoupledMixProduct(
                fixture.statement, fixture.shape,
                sink.MixInputs(),
                fixture.children.mix, &why),
            why);
        BOOST_TEST_MESSAGE("coupled binder phase: Extract proofs");
        BOOST_REQUIRE_MESSAGE(
            rc::ProveRCStage3CoupledExtractProduct(
                fixture.statement, fixture.shape,
                sink.extract_inputs,
                fixture.children.extract, &why),
            why);
        std::vector<uint8_t> bank_bytes;
        for (const auto& page :
             fixture.children.bank.pages) {
            for (int8_t byte : page.page_bytes) {
                bank_bytes.push_back(
                    static_cast<uint8_t>(byte));
            }
        }
        BOOST_TEST_MESSAGE("coupled binder phase: bank-root proof");
        BOOST_REQUIRE_MESSAGE(
            rc::ProveRCStage3CoupledBankRootExecution(
                fixture.statement, fixture.shape,
                bank_bytes,
                fixture.children.bank_root, &why),
            why);
        BOOST_TEST_MESSAGE("coupled binder phase: root-chain proofs");
        BOOST_REQUIRE_MESSAGE(
            rc::ProveRCStage3CoupledRootChain(
                fixture.statement, fixture.shape,
                sink.bank_root, sink.barrier_states,
                fixture.children.root_chain, &why),
            why);
        return fixture;
    }

    CBlockHeader header{Header()};
    int32_t height{811};
    rc::RCCoupParams params{Params()};
    rc::RCCoupOptions options{Options()};
    uint256 digest{};
    rc::RCStage3CoupledShape shape{};
    rc::RCStage3SuccinctProof statement{};
    rc::RCStage3CoupledWinnerReceiptV1 winner{};
    rc::RCStage3BoundedCoupledSemanticComposition children{};
};

void RecommitPage(
    rc::RCStage3CoupledWinnerReceiptV1& receipt,
    uint32_t barrier,
    uint32_t lobe,
    uint32_t page)
{
    auto& b = receipt.barriers.at(barrier);
    auto& l = b.lobes.at(lobe);
    auto& p = l.pages.at(page);
    p.event_commitment =
        rc::CommitRCStage3CoupledPageCaptureV1(p);
    l.lobe_commitment =
        rc::CommitRCStage3CoupledLobeCaptureV1(l);
    b.stage_adjacency_commitment =
        rc::CommitRCStage3CoupledBarrierCaptureV1(b);
    receipt.receipt_commitment =
        rc::CommitRCStage3CoupledWinnerReceiptV2(receipt);
}

void RecommitBarrier(
    rc::RCStage3CoupledWinnerReceiptV1& receipt,
    uint32_t barrier)
{
    receipt.barriers.at(barrier)
        .stage_adjacency_commitment =
        rc::CommitRCStage3CoupledBarrierCaptureV1(
            receipt.barriers.at(barrier));
    receipt.receipt_commitment =
        rc::CommitRCStage3CoupledWinnerReceiptV2(receipt);
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_coupled_winner_child_binding_tests)

BOOST_AUTO_TEST_CASE(
    exact_winner_openings_bind_to_executed_child_proofs)
{
    const auto fixture = Fixture::Build();
    rc::RCStage3CoupledWinnerChildBindingV1 binding;
    std::string why;
    BOOST_TEST_MESSAGE("coupled binder phase: integrated verification");
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3CoupledWinnerChildBindingV1(
            fixture.header, fixture.height,
            fixture.params, fixture.options,
            fixture.statement, fixture.winner,
            fixture.children, binding, &why),
        why);
    BOOST_CHECK(!binding.product_commitment.IsNull());
    BOOST_CHECK_EQUAL(
        binding.version,
        rc::kRCStage3CoupledWinnerChildBindingVersionV2);
    BOOST_CHECK(
        !binding.representative_cell_binding.IsNull());
    BOOST_CHECK_EQUAL(binding.scheduled_page_instances, 4U);
    BOOST_CHECK_EQUAL(binding.accumulation_links, 4U);
    BOOST_CHECK_EQUAL(binding.barrier_links, 4U);

    {
        using Receipt =
            rc::RCStage3CoupledWinnerReceiptV1;
        using Mutator = void (*)(Receipt&);
        const std::array<Mutator, 6> mutations{{
            +[](Receipt& receipt) {
                receipt.representative_cells
                    .first_gemm_operand_a ^= 1;
            },
            +[](Receipt& receipt) {
                receipt.representative_cells
                    .first_gemm_operand_b ^= 1;
            },
            +[](Receipt& receipt) {
                receipt.representative_cells
                    .first_bank_nibble ^= 1U;
            },
            +[](Receipt& receipt) {
                receipt.representative_cells
                    .first_extract_input_a ^= 1;
            },
            +[](Receipt& receipt) {
                receipt.representative_cells
                    .first_extract_input_b ^= 1;
            },
            +[](Receipt& receipt) {
                receipt.representative_cells
                    .first_extract_output ^= 1;
            },
        }};
        for (const auto mutate : mutations) {
            auto forged = fixture.winner;
            mutate(forged);
            forged.receipt_commitment =
                rc::CommitRCStage3CoupledWinnerReceiptV2(
                    forged);
            // This is a coherent outer-receipt attack: the public receipt
            // verifier accepts its recomputed commitment.  Rejection must
            // come from equality to the proof-owned child opening.
            BOOST_REQUIRE_MESSAGE(
                rc::VerifyRCStage3CoupledWinnerReceiptV2(
                    fixture.header, fixture.height,
                    fixture.params, fixture.options,
                    forged, &why),
                why);
            BOOST_CHECK(
                !rc::VerifyRCStage3CoupledWinnerChildBindingV1(
                    fixture.header, fixture.height,
                    fixture.params, fixture.options,
                    fixture.statement, forged,
                    fixture.children, binding, &why));
            BOOST_CHECK(
                why.find("representative_child_equality") !=
                std::string::npos);
        }
    }

    {
        auto forged = fixture.statement;
        // Keep the statement internally self-consistent while changing the
        // episode half of the composed claim.  Recomputing both derived
        // commitments prevents this attack from being rejected merely as a
        // stale transcript; the binder must enforce equality to the digest
        // installed in the finalized block header.
        forged.public_inputs.episode_digest = H(0xcf);
        forged.public_inputs.final_digest =
            rc::ComputeRCStage3FinalDigest(forged);
        forged.public_inputs.transcript_commitment =
            rc::ComputeRCStage3TranscriptCommitment(forged);
        BOOST_CHECK(
            !rc::VerifyRCStage3CoupledWinnerChildBindingV1(
                fixture.header, fixture.height,
                fixture.params, fixture.options,
                forged, fixture.winner,
                fixture.children, binding, &why));
    }
    {
        auto forged = fixture.statement;
        forged.public_inputs.transcript_commitment = H(0xce);
        BOOST_CHECK(
            !rc::VerifyRCStage3CoupledWinnerChildBindingV1(
                fixture.header, fixture.height,
                fixture.params, fixture.options,
                forged, fixture.winner,
                fixture.children, binding, &why));
    }
    {
        auto forged = fixture.winner;
        forged.barriers[0].lobes[0].pages[0]
            .gemm_y_root = H(0xd1);
        RecommitPage(forged, 0, 0, 0);
        BOOST_REQUIRE_MESSAGE(
            rc::VerifyRCStage3CoupledWinnerReceiptV2(
                fixture.header, fixture.height,
                fixture.params, fixture.options,
                forged, &why),
            why);
        BOOST_CHECK(
            !rc::VerifyRCStage3CoupledWinnerChildBindingV1(
                fixture.header, fixture.height,
                fixture.params, fixture.options,
                fixture.statement, forged,
                fixture.children, binding, &why));
    }
    {
        auto forged = fixture.winner;
        const uint256 substituted = H(0xd2);
        forged.barriers[0].permutation_output_root =
            substituted;
        forged.barriers[0].mix_input_root = substituted;
        RecommitBarrier(forged, 0);
        BOOST_REQUIRE_MESSAGE(
            rc::VerifyRCStage3CoupledWinnerReceiptV2(
                fixture.header, fixture.height,
                fixture.params, fixture.options,
                forged, &why),
            why);
        BOOST_CHECK(
            !rc::VerifyRCStage3CoupledWinnerChildBindingV1(
                fixture.header, fixture.height,
                fixture.params, fixture.options,
                fixture.statement, forged,
                fixture.children, binding, &why));
    }
    {
        auto omitted = fixture.children;
        omitted.gemm.gemms.pop_back();
        BOOST_CHECK(
            !rc::VerifyRCStage3CoupledWinnerChildBindingV1(
                fixture.header, fixture.height,
                fixture.params, fixture.options,
                fixture.statement, fixture.winner,
                omitted, binding, &why));
    }
    {
        auto proof_tamper = fixture.children;
        BOOST_REQUIRE(
            !proof_tamper.gemm.gemms.empty());
        BOOST_REQUIRE(
            !proof_tamper.gemm.gemms[0].tiles.empty());
        BOOST_REQUIRE(
            !proof_tamper.gemm.gemms[0]
                 .tiles[0].proof.batch.columns.empty());
        // This GEMM child uses the per-column backend, where trace_commit is
        // intentionally unused. Mutate the quotient column's Merkle root so
        // rejection must come from the actual FRI/AIR verifier rather than
        // the schedule's pinned trace-column roots.
        proof_tamper.gemm.gemms[0]
            .tiles[0].proof.batch.columns.back().root =
                H(0xd3);
        BOOST_CHECK(
            !rc::VerifyRCStage3CoupledWinnerChildBindingV1(
                fixture.header, fixture.height,
                fixture.params, fixture.options,
                fixture.statement, fixture.winner,
                proof_tamper, binding, &why));
    }
}

BOOST_AUTO_TEST_SUITE_END()
