// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <matmul/matmul_v4_rc_stage3_coupled_signed_range_stream.h>
#include <primitives/block.h>

#include <array>
#include <cstdint>
#include <limits>
#include <string>

namespace {

namespace rc = matmul::v4::rc;
namespace sr = rc::coupled_signed_range_stream;

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
    out.hashPrevBlock = H(0x11);
    out.hashMerkleRoot = H(0x22);
    out.nTime = 1'770'100'001;
    out.nBits = 0x207fffffU;
    out.nNonce = 31;
    out.nNonce64 = 31;
    out.seed_a = H(0x33);
    out.seed_b = H(0x44);
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
    out.public_inputs.header_commitment = header.GetHash();
    out.public_inputs.params_commitment = H(0x55);
    out.public_inputs.sigma = matmul::v4::DeriveSigma(header);
    out.public_inputs.episode_digest = H(0x66);
    out.public_inputs.coupled_digest = coupled_digest;
    out.public_inputs.program_consensus_pin
        .recursive_alg_hash_root = H(0x77);
    out.public_inputs.program_consensus_pin
        .external_sha256d_audit_root = H(0x88);
    out.public_inputs.program_consensus_pin
        .registry_binding = H(0x99);
    arith_uint256 target;
    target.SetCompact(header.nBits);
    out.public_inputs.target = ArithToUint256(target);
    const auto roles =
        rc::RequiredRCStage3RelationRoles(out.statement);
    for (uint32_t i = 0; i < roles.size(); ++i) {
        out.commitments.push_back(
            {roles[i], H(static_cast<uint8_t>(0xa0 + i))});
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

class ForwardingSink final : public rc::RCCoupProofWitnessSink {
public:
    enum class Mode {
        Honest,
        DropLast,
        ReorderFirst,
    };

    ForwardingSink(
        sr::StreamProverV1& target,
        uint64_t expected_gemms,
        Mode mode)
        : target_(target),
          expected_gemms_(expected_gemms),
          mode_(mode)
    {
    }

    void OnInitialState(
        const rc::RCCoupInitialStateProofWitnessView& view) override
    {
        target_.OnInitialState(view);
    }

    void OnGemm(
        const rc::RCCoupGemmProofWitnessView& view) override
    {
        if (mode_ == Mode::DropLast &&
            seen_ + 1 == expected_gemms_) {
            ++seen_;
            return;
        }
        if (mode_ == Mode::ReorderFirst && seen_ == 0) {
            auto changed = view;
            changed.barrier = 1;
            target_.OnGemm(changed);
        } else {
            target_.OnGemm(view);
        }
        ++seen_;
    }

    void OnPermutation(
        const rc::RCCoupPermutationProofWitnessView& view) override
    {
        target_.OnPermutation(view);
    }

    void OnMix(const rc::RCCoupMixProofWitnessView& view) override
    {
        target_.OnMix(view);
    }

    void OnMaterialExchange(
        const rc::RCCoupMaterialExchangeProofWitnessView& view) override
    {
        target_.OnMaterialExchange(view);
    }

    void OnBarrier(
        const rc::RCCoupBarrierProofWitnessView& view) override
    {
        target_.OnBarrier(view);
    }

    void OnEpisode(
        const rc::RCCoupEpisodeProofWitnessView& view) override
    {
        target_.OnEpisode(view);
    }

private:
    sr::StreamProverV1& target_;
    uint64_t expected_gemms_{0};
    uint64_t seen_{0};
    Mode mode_{Mode::Honest};
};

void Recommit(sr::ReceiptV1& receipt)
{
    for (auto& interval : receipt.intervals) {
        interval.link_commitment =
            sr::CommitYIntervalLinkV1(interval);
    }
    receipt.receipt_commitment =
        sr::CommitReceiptV1(receipt);
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_coupled_signed_range_stream_tests)

BOOST_AUTO_TEST_CASE(
    real_solver_callbacks_prove_clear_and_verify_proof_only_receipt)
{
    constexpr int32_t height = 733;
    const CBlockHeader header = Header();
    const auto params = Params();
    const auto options = Options();
    const uint256 discovered =
        rc::MineCoupledPuzzle(
            header, height, params, {}, options);
    BOOST_REQUIRE(!discovered.IsNull());
    const auto statement =
        Statement(header, height, discovered);
    const auto shape =
        rc::MakeRCStage3CoupledShape(params, options);

    sr::StreamProverV1 prover(statement, shape);
    const uint256 replayed =
        rc::MineCoupledPuzzleWithProofWitness(
            header, height, params, prover, {}, options);
    BOOST_REQUIRE(replayed == discovered);
    std::string why;
    BOOST_REQUIRE_MESSAGE(prover.Complete(&why), why);
    BOOST_CHECK_EQUAL(prover.RetainedNativeYBytes(), 0U);
    BOOST_CHECK(
        prover.PeakRetainedNativeYBytes() <=
        sr::kMaxRetainedNativeYBytesV1);
    BOOST_CHECK_EQUAL(
        prover.PeakRetainedNativeYBytes(),
        uint64_t{params.barriers} *
            params.rows_per_lobe *
            params.lobe_width * sizeof(int64_t));

    const auto& receipt = prover.Receipt();
    BOOST_REQUIRE_EQUAL(receipt.execution.shards.size(), 1U);
    BOOST_REQUIRE_EQUAL(receipt.intervals.size(), 1U);
    BOOST_CHECK(receipt.every_range_child_verified);
    BOOST_CHECK(!receipt.gemm_y_interval_ctl_consumed);
    BOOST_CHECK(!receipt.normalized_parent_consumed);
    BOOST_CHECK(!receipt.production_authority);
    BOOST_CHECK_MESSAGE(
        sr::VerifyReceiptV1(
            statement, shape, receipt, &why),
        why);

    // A value/root substitution remains a locally valid receipt encoding only
    // after recomputation, but fails the exact callback-root == VALUE-root
    // equality.
    auto changed_value = receipt;
    changed_value.intervals[0].callback_y_root.begin()[0] ^= 1;
    Recommit(changed_value);
    BOOST_CHECK(
        !sr::VerifyReceiptV1(
            statement, shape, changed_value, &why));

    // Even if an attacker recommits the outer receipt, changing a committed
    // proof root is rejected by the actual range AIR verifier.
    auto changed_proof = receipt;
    changed_proof.execution.shards[0]
        .proof.batch.columns[0].root.begin()[0] ^= 1;
    changed_proof.intervals[0]
        .range_child_proof_commitment =
        sr::CommitAirQuotientProofV1(
            changed_proof.execution.shards[0].proof);
    Recommit(changed_proof);
    BOOST_CHECK(
        !sr::VerifyReceiptV1(
            statement, shape, changed_proof, &why));

    // Interval position is canonical; changing it and recomputing both hashes
    // cannot turn the altered schedule into an accepted receipt.
    auto changed_interval = receipt;
    ++changed_interval.intervals[0].cell_begin;
    Recommit(changed_interval);
    BOOST_CHECK(
        !sr::VerifyReceiptV1(
            statement, shape, changed_interval, &why));
}

BOOST_AUTO_TEST_CASE(
    omitted_and_reordered_solver_callbacks_fail_closed)
{
    constexpr int32_t height = 739;
    const CBlockHeader header = Header();
    const auto params = Params();
    const auto options = Options();
    const uint256 digest =
        rc::MineCoupledPuzzle(
            header, height, params, {}, options);
    BOOST_REQUIRE(!digest.IsNull());
    const auto statement =
        Statement(header, height, digest);
    const auto shape =
        rc::MakeRCStage3CoupledShape(params, options);
    const uint64_t gemms =
        uint64_t{params.barriers} * params.lobes *
        params.pages_per_barrier_lobe;

    sr::StreamProverV1 omitted(statement, shape);
    ForwardingSink drop(
        omitted, gemms, ForwardingSink::Mode::DropLast);
    BOOST_REQUIRE(
        rc::MineCoupledPuzzleWithProofWitness(
            header, height, params, drop, {}, options) ==
        digest);
    std::string why;
    BOOST_CHECK(!omitted.Complete(&why));
    BOOST_CHECK(
        why.find("incomplete_schedule") !=
        std::string::npos);

    sr::StreamProverV1 reordered(statement, shape);
    ForwardingSink swap(
        reordered, gemms,
        ForwardingSink::Mode::ReorderFirst);
    BOOST_REQUIRE(
        rc::MineCoupledPuzzleWithProofWitness(
            header, height, params, swap, {}, options) ==
        digest);
    BOOST_CHECK(reordered.Poisoned());
    BOOST_CHECK(!reordered.Complete(&why));
    BOOST_CHECK(
        why.find("callback_schedule") !=
        std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
