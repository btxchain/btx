// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_winner_capture.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <matmul/matmul_v4.h>
#include <primitives/block.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <utility>

namespace matmul::v4::rc {
namespace {

constexpr char kContextDomainV2[] =
    "BTX_RC_STAGE3_COUPLED_WINNER_CONTEXT_V2";
constexpr char kHeaderPrecommitDomain[] =
    "BTX_RC_STAGE3_COUPLED_WINNER_HEADER_PRECOMMIT_V2";
constexpr char kInitialDomain[] =
    "BTX_RC_STAGE3_COUPLED_INITIAL_STATE_V2";
constexpr char kLobeStateDomain[] =
    "BTX_RC_STAGE3_COUPLED_LOBE_STATE_V2";
constexpr char kPageDomain[] =
    "BTX_RC_STAGE3_COUPLED_BANK_PAGE_V2";
constexpr char kPartialDomain[] =
    "BTX_RC_STAGE3_COUPLED_GEMM_PARTIAL_V2";
constexpr char kAccumulatorDomain[] =
    "BTX_RC_STAGE3_COUPLED_ACCUMULATION_V2";
constexpr char kBoundaryDomain[] =
    "BTX_RC_STAGE3_COUPLED_STAGE_BOUNDARY_V2";
constexpr char kExtractOutputDomain[] =
    "BTX_RC_STAGE3_COUPLED_EXTRACT_OUTPUT_V2";
constexpr char kPageEventDomain[] =
    "BTX_RC_STAGE3_COUPLED_PAGE_EVENT_V2";
constexpr char kLobeDomain[] =
    "BTX_RC_STAGE3_COUPLED_LOBE_RECEIPT_V2";
constexpr char kBarrierDomain[] =
    "BTX_RC_STAGE3_COUPLED_BARRIER_RECEIPT_V2";
constexpr char kBankScheduleDomain[] =
    "BTX_RC_STAGE3_COUPLED_BANK_SCHEDULE_V2";
constexpr char kReceiptDomainV2[] =
    "BTX_RC_STAGE3_COUPLED_WINNER_RECEIPT_V2";

std::mutex g_coupled_winner_store_mutex;
uint256 g_coupled_winner_store_header;
std::shared_ptr<
    const RCStage3CoupledWinnerCaptureV1>
    g_coupled_winner_store_capture;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:coupled_winner_capture:" + detail;
    }
    return false;
}

bool SameParams(
    const RCCoupParams& a,
    const RCCoupParams& b)
{
    return
        a.barriers == b.barriers &&
        a.lobes == b.lobes &&
        a.lobe_width == b.lobe_width &&
        a.bank_pages == b.bank_pages &&
        a.rows_per_lobe == b.rows_per_lobe &&
        a.pages_per_barrier_lobe ==
            b.pages_per_barrier_lobe;
}

bool SameConsensusOptions(
    const RCCoupOptions& a,
    const RCCoupOptions& b)
{
    return
        a.transcript_version ==
            b.transcript_version &&
        a.full_bank_schedule ==
            b.full_bank_schedule &&
        a.material_exchange ==
            b.material_exchange &&
        a.exchange_rows == b.exchange_rows &&
        a.exchange_rounds == b.exchange_rounds &&
        a.force_signed_mix == b.force_signed_mix &&
        !a.skip_barrier && !a.skip_bank_page &&
        !b.skip_barrier && !b.skip_bank_page;
}

class RootWriter {
public:
    explicit RootWriter(
        const char* domain,
        uint16_t version =
            kRCStage3CoupledWinnerCaptureVersionV2)
    {
        Bytes(
            reinterpret_cast<const unsigned char*>(domain),
            std::strlen(domain));
        U32(version);
    }

    void U8(uint8_t value)
    {
        m_sha.Write(&value, 1);
    }

    void U32(uint32_t value)
    {
        unsigned char bytes[4];
        WriteLE32(bytes, value);
        Bytes(bytes, sizeof(bytes));
    }

    void I32(int32_t value)
    {
        U32(static_cast<uint32_t>(value));
    }

    void U64(uint64_t value)
    {
        unsigned char bytes[8];
        WriteLE64(bytes, value);
        Bytes(bytes, sizeof(bytes));
    }

    void Hash(const uint256& value)
    {
        Bytes(value.data(), value.size());
    }

    void Bytes(
        const unsigned char* values,
        size_t count)
    {
        if (count != 0) m_sha.Write(values, count);
    }

    void I8(const int8_t* values, uint64_t count)
    {
        Bytes(
            reinterpret_cast<const unsigned char*>(
                values),
            static_cast<size_t>(count));
    }

    void I64(const int64_t* values, uint64_t count)
    {
        std::array<unsigned char, 8192> buffer{};
        uint64_t offset = 0;
        while (offset < count) {
            const uint64_t items = std::min<uint64_t>(
                count - offset,
                buffer.size() / sizeof(uint64_t));
            for (uint64_t i = 0; i < items; ++i) {
                WriteLE64(
                    buffer.data() + 8 * i,
                    static_cast<uint64_t>(
                        values[offset + i]));
            }
            Bytes(buffer.data(), 8 * items);
            offset += items;
        }
    }

    uint256 Finish()
    {
        uint8_t first[CSHA256::OUTPUT_SIZE];
        m_sha.Finalize(first);
        uint8_t second[CSHA256::OUTPUT_SIZE];
        CSHA256()
            .Write(first, sizeof(first))
            .Finalize(second);
        return uint256{
            Span<const unsigned char>{
                second, sizeof(second)}};
    }

private:
    CSHA256 m_sha;
};

void WriteParams(RootWriter& out, const RCCoupParams& params)
{
    out.U32(params.barriers);
    out.U32(params.lobes);
    out.U32(params.lobe_width);
    out.U32(params.bank_pages);
    out.U32(params.rows_per_lobe);
    out.U32(params.pages_per_barrier_lobe);
}

void WriteOptions(RootWriter& out, const RCCoupOptions& options)
{
    out.U32(options.transcript_version);
    out.U8(options.full_bank_schedule ? 1 : 0);
    out.U8(options.material_exchange ? 1 : 0);
    out.U32(options.exchange_rows);
    out.U32(options.exchange_rounds);
    out.U8(options.force_signed_mix ? 1 : 0);
}

uint256 InitialStateRoot(
    const uint256& header,
    uint64_t cells,
    const int8_t* values)
{
    RootWriter hash(kInitialDomain);
    hash.Hash(header);
    hash.U64(cells);
    hash.I8(values, cells);
    return hash.Finish();
}

uint256 LobeStateRoot(
    const uint256& header,
    uint32_t input_barrier,
    uint32_t lobe,
    uint32_t rows,
    uint32_t width,
    const int8_t* values)
{
    RootWriter hash(kLobeStateDomain);
    hash.Hash(header);
    hash.U32(input_barrier);
    hash.U32(lobe);
    hash.U32(rows);
    hash.U32(width);
    hash.U64(uint64_t{rows} * width);
    hash.I8(values, uint64_t{rows} * width);
    return hash.Finish();
}

uint256 BankPageRoot(
    const uint256& header,
    uint32_t page_id,
    uint32_t width,
    const int8_t* values)
{
    RootWriter hash(kPageDomain);
    hash.Hash(header);
    hash.U32(page_id);
    hash.U32(width);
    hash.U64(uint64_t{width} * width);
    hash.I8(values, uint64_t{width} * width);
    return hash.Finish();
}

uint256 PartialRoot(
    const uint256& header,
    uint32_t barrier,
    uint32_t lobe,
    uint32_t page_ordinal,
    uint32_t rows,
    uint32_t width,
    const int64_t* values)
{
    RootWriter hash(kPartialDomain);
    hash.Hash(header);
    hash.U32(barrier);
    hash.U32(lobe);
    hash.U32(page_ordinal);
    hash.U32(rows);
    hash.U32(width);
    hash.U64(uint64_t{rows} * width);
    hash.I64(values, uint64_t{rows} * width);
    return hash.Finish();
}

uint256 AccumulatorRoot(
    const uint256& header,
    uint32_t barrier,
    uint32_t lobe,
    uint32_t prefix_pages,
    uint32_t rows,
    uint32_t width,
    const int64_t* values)
{
    RootWriter hash(kAccumulatorDomain);
    hash.Hash(header);
    hash.U32(barrier);
    hash.U32(lobe);
    hash.U32(prefix_pages);
    hash.U32(rows);
    hash.U32(width);
    hash.U64(uint64_t{rows} * width);
    hash.I64(values, uint64_t{rows} * width);
    return hash.Finish();
}

uint256 BoundaryRoot(
    const uint256& header,
    uint32_t barrier,
    uint32_t position,
    uint64_t cells,
    const int64_t* values)
{
    RootWriter hash(kBoundaryDomain);
    hash.Hash(header);
    hash.U32(barrier);
    hash.U32(position);
    hash.U64(cells);
    hash.I64(values, cells);
    return hash.Finish();
}

uint256 ExtractOutputRoot(
    const uint256& header,
    uint32_t barrier,
    uint64_t cells,
    const int8_t* values)
{
    RootWriter hash(kExtractOutputDomain);
    hash.Hash(header);
    hash.U32(barrier);
    hash.U64(cells);
    hash.I8(values, cells);
    return hash.Finish();
}

uint256 NativeBarrierRoot(
    uint32_t barrier,
    const int8_t* values,
    uint64_t cells,
    uint32_t transcript_version)
{
    const auto& tags =
        RCCoupDomainTagsForVersion(transcript_version);
    CSHA256 outer;
    outer.Write(
        reinterpret_cast<const unsigned char*>(
            tags.barrier),
        std::strlen(tags.barrier));
    unsigned char le[4];
    WriteLE32(le, barrier);
    outer.Write(le, sizeof(le));
    outer.Write(
        reinterpret_cast<const unsigned char*>(
            values),
        static_cast<size_t>(cells));
    uint8_t first[CSHA256::OUTPUT_SIZE];
    outer.Finalize(first);
    uint8_t second[CSHA256::OUTPUT_SIZE];
    CSHA256()
        .Write(first, sizeof(first))
        .Finalize(second);
    return uint256{
        Span<const unsigned char>{
            second, sizeof(second)}};
}

uint256 PageCommitmentInternal(
    const RCStage3CoupledPageCaptureV1& page)
{
    HashWriter hash;
    hash << kPageEventDomain
         << kRCStage3CoupledWinnerCaptureVersionV2
         << page.barrier << page.lobe
         << page.page_ordinal << page.page_id
         << page.operand_a_root
         << page.operand_b_root
         << page.gemm_y_root
         << page.accumulation_before_root
         << page.accumulation_after_root;
    return hash.GetHash();
}

uint256 LobeCommitmentInternal(
    const RCStage3CoupledLobeCaptureV1& lobe)
{
    HashWriter hash;
    hash << kLobeDomain
         << kRCStage3CoupledWinnerCaptureVersionV2
         << lobe.barrier << lobe.lobe
         << lobe.input_state_lobe_root
         << static_cast<uint32_t>(lobe.pages.size());
    for (const auto& page : lobe.pages) {
        hash << page.event_commitment;
    }
    hash << lobe.final_accumulation_root;
    return hash.GetHash();
}

uint256 BarrierCommitmentInternal(
    const RCStage3CoupledBarrierCaptureV1& barrier)
{
    HashWriter hash;
    hash << kBarrierDomain
         << kRCStage3CoupledWinnerCaptureVersionV2
         << barrier.barrier
         << static_cast<uint32_t>(
                barrier.input_state_lobe_roots.size());
    for (const auto& root :
         barrier.input_state_lobe_roots) {
        hash << root;
    }
    hash << static_cast<uint32_t>(barrier.lobes.size());
    for (const auto& lobe : barrier.lobes) {
        hash << lobe.lobe_commitment;
    }
    hash << barrier.gemm_accumulation_root
         << barrier.permutation_input_root
         << barrier.permutation_output_root
         << barrier.mix_input_root
         << barrier.mix_output_root
         << static_cast<uint32_t>(
                barrier.material_exchange.size());
    for (const auto& exchange :
         barrier.material_exchange) {
        hash << exchange.round
             << exchange.input_root
             << exchange.output_root;
    }
    hash << barrier.extract_prf
         << barrier.extract_input_root
         << barrier.extract_output_root
         << static_cast<uint32_t>(
                barrier.extract_output_lobe_roots.size());
    for (const auto& root :
         barrier.extract_output_lobe_roots) {
        hash << root;
    }
    hash << barrier.barrier_root;
    return hash.GetHash();
}

uint256 BankScheduleCommitment(
    const std::vector<uint256>& roots,
    const std::vector<bool>& seen)
{
    if (roots.size() != seen.size()) return {};
    HashWriter hash;
    hash << kBankScheduleDomain
         << kRCStage3CoupledWinnerCaptureVersionV2
         << static_cast<uint32_t>(roots.size());
    for (uint32_t page = 0;
         page < roots.size(); ++page) {
        hash << page
             << static_cast<uint8_t>(
                    seen[page] ? 1 : 0)
             << roots[page];
    }
    return hash.GetHash();
}

uint64_t ReceiptBytesUpperBound(
    const RCStage3CoupledWinnerReceiptV1& receipt)
{
    // Canonical conservative wire upper bound, independent of host ABI.
    uint64_t bytes = 1024;
    for (const auto& barrier : receipt.barriers) {
        bytes +=
            1024 +
            uint64_t{barrier.input_state_lobe_roots.size()} *
                32 +
            uint64_t{barrier.extract_output_lobe_roots.size()} *
                32 +
            uint64_t{barrier.material_exchange.size()} *
                96;
        for (const auto& lobe : barrier.lobes) {
            bytes +=
                256 +
                uint64_t{lobe.pages.size()} * 224;
        }
    }
    return bytes;
}

bool AddBytes(uint64_t& total, uint64_t count)
{
    if (count >
        std::numeric_limits<uint64_t>::max() - total) {
        return false;
    }
    total += count;
    return true;
}

bool NonNull(const uint256& value)
{
    return !value.IsNull();
}

} // namespace

uint256 CommitRCStage3CoupledPageCaptureV1(
    const RCStage3CoupledPageCaptureV1& page)
{
    return PageCommitmentInternal(page);
}

uint256 CommitRCStage3CoupledLobeCaptureV1(
    const RCStage3CoupledLobeCaptureV1& lobe)
{
    return LobeCommitmentInternal(lobe);
}

uint256 CommitRCStage3CoupledBarrierCaptureV1(
    const RCStage3CoupledBarrierCaptureV1& barrier)
{
    return BarrierCommitmentInternal(barrier);
}

class RCStage3CoupledWinnerCaptureV1::BoundaryHasher {
public:
    BoundaryHasher(
        const uint256& header,
        uint32_t barrier,
        uint32_t position,
        uint64_t cells)
        : m_hash(kBoundaryDomain),
          m_expected(cells)
    {
        m_hash.Hash(header);
        m_hash.U32(barrier);
        m_hash.U32(position);
        m_hash.U64(cells);
    }

    bool Append(const int64_t* values, uint64_t cells)
    {
        if (values == nullptr ||
            cells > m_expected - m_written) {
            return false;
        }
        m_hash.I64(values, cells);
        m_written += cells;
        return true;
    }

    uint256 Finish()
    {
        if (m_written != m_expected) return {};
        return m_hash.Finish();
    }

private:
    RootWriter m_hash;
    uint64_t m_expected{0};
    uint64_t m_written{0};
};

uint256 CommitRCStage3CoupledWinnerHeaderPrecommitV2(
    const CBlockHeader& header)
{
    CBlockHeader projected = header;
    projected.matmul_digest.SetNull();
    RootWriter hash(kHeaderPrecommitDomain);
    hash.Hash(projected.GetHash());
    hash.Hash(matmul::v4::DeriveSigma(projected));
    return hash.Finish();
}

uint256 CommitRCStage3CoupledWinnerContextV2(
    const CBlockHeader& header,
    int32_t height,
    const RCCoupParams& params,
    const RCCoupOptions& options)
{
    if (!ValidateRCCoupParams(params) ||
        options.skip_barrier ||
        options.skip_bank_page) {
        return {};
    }
    RootWriter hash(kContextDomainV2);
    hash.Hash(
        CommitRCStage3CoupledWinnerHeaderPrecommitV2(
            header));
    hash.Hash(matmul::v4::DeriveSigma(header));
    hash.I32(height);
    WriteParams(hash, params);
    WriteOptions(hash, options);
    return hash.Finish();
}

uint256 CommitRCStage3CoupledWinnerReceiptV2(
    const RCStage3CoupledWinnerReceiptV1& receipt)
{
    if (receipt.version !=
            kRCStage3CoupledWinnerCaptureVersionV2 ||
        !NonNull(receipt.winner_header_precommit) ||
        !NonNull(receipt.finalized_header_hash) ||
        !NonNull(receipt.context_commitment) ||
        !NonNull(receipt.initial_state_root) ||
        !NonNull(receipt.scheduled_bank_pages_commitment) ||
        !NonNull(receipt.bank_root) ||
        !NonNull(receipt.coupled_digest)) {
        return {};
    }
    HashWriter hash;
    hash << kReceiptDomainV2 << receipt.version
         << receipt.winner_header_precommit
         << receipt.finalized_header_hash
         << receipt.sigma << receipt.height
         << receipt.params.barriers
         << receipt.params.lobes
         << receipt.params.lobe_width
         << receipt.params.bank_pages
         << receipt.params.rows_per_lobe
         << receipt.params.pages_per_barrier_lobe
         << receipt.transcript_version
         << static_cast<uint8_t>(
                receipt.full_bank_schedule ? 1 : 0)
         << static_cast<uint8_t>(
                receipt.material_exchange ? 1 : 0)
         << receipt.exchange_rows
         << receipt.exchange_rounds
         << static_cast<uint8_t>(
                receipt.force_signed_mix ? 1 : 0)
         << receipt.context_commitment
         << receipt.initial_state_root
         << static_cast<uint32_t>(
                receipt.initial_state_lobe_roots.size());
    for (const auto& root :
         receipt.initial_state_lobe_roots) {
        hash << root;
    }
    hash << static_cast<uint32_t>(
                receipt.barriers.size());
    for (const auto& barrier : receipt.barriers) {
        hash << barrier.stage_adjacency_commitment;
    }
    hash << receipt.scheduled_bank_pages_commitment
         << receipt.bank_root
         << static_cast<uint32_t>(
                receipt.barrier_roots.size());
    for (const auto& root : receipt.barrier_roots) {
        hash << root;
    }
    hash << receipt.coupled_digest
         << static_cast<uint8_t>(
                receipt.representative_cells
                    .first_gemm_operand_a)
         << static_cast<uint8_t>(
                receipt.representative_cells
                    .first_gemm_operand_b)
         << receipt.representative_cells
                .first_bank_nibble
         << static_cast<uint64_t>(
                receipt.representative_cells
                    .first_extract_input_a)
         << static_cast<uint64_t>(
                receipt.representative_cells
                    .first_extract_input_b)
         << static_cast<uint8_t>(
                receipt.representative_cells
                    .first_extract_output)
         << static_cast<uint8_t>(
                receipt.representative_cells
                    .gemm_observed ? 1 : 0)
         << static_cast<uint8_t>(
                receipt.representative_cells
                    .extract_observed ? 1 : 0)
         << receipt.gemm_callbacks
         << receipt.captured_payload_bytes
         << receipt.retained_receipt_bytes_upper_bound
         << receipt.peak_accumulation_scratch_bytes
         << static_cast<uint8_t>(
                receipt.capture_complete ? 1 : 0)
         << static_cast<uint8_t>(
                receipt.no_bank_pages_retained ? 1 : 0)
         << static_cast<uint8_t>(
                receipt.no_flat_tile_proofs_materialized
                    ? 1 : 0)
         << static_cast<uint8_t>(
                receipt.recursive_relation_proofs_bound
                    ? 1 : 0);
    return hash.GetHash();
}

bool VerifyRCStage3CoupledWinnerReceiptV2(
    const CBlockHeader& finalized_header,
    int32_t height,
    const RCCoupParams& params,
    const RCCoupOptions& options,
    const RCStage3CoupledWinnerReceiptV1& receipt,
    std::string* why)
{
    if (receipt.version !=
            kRCStage3CoupledWinnerCaptureVersionV2 ||
        !ValidateRCCoupParams(params) ||
        options.skip_barrier ||
        options.skip_bank_page ||
        receipt.winner_header_precommit !=
            CommitRCStage3CoupledWinnerHeaderPrecommitV2(
                finalized_header) ||
        receipt.finalized_header_hash !=
            finalized_header.GetHash() ||
        receipt.sigma !=
            matmul::v4::DeriveSigma(finalized_header) ||
        receipt.height != height ||
        !SameParams(receipt.params, params)) {
        return Fail(why, "context");
    }
    RCCoupOptions encoded;
    encoded.transcript_version =
        receipt.transcript_version;
    encoded.full_bank_schedule =
        receipt.full_bank_schedule;
    encoded.material_exchange =
        receipt.material_exchange;
    encoded.exchange_rows =
        receipt.exchange_rows;
    encoded.exchange_rounds =
        receipt.exchange_rounds;
    encoded.force_signed_mix =
        receipt.force_signed_mix;
    const uint256 expected_context =
        CommitRCStage3CoupledWinnerContextV2(
            finalized_header, height,
            params, options);
    if (!SameConsensusOptions(encoded, options) ||
        receipt.context_commitment !=
            expected_context ||
        !receipt.capture_complete ||
        !receipt.no_bank_pages_retained ||
        !receipt.no_flat_tile_proofs_materialized ||
        receipt.recursive_relation_proofs_bound ||
        !receipt.representative_cells.gemm_observed ||
        !receipt.representative_cells.extract_observed ||
        receipt.representative_cells.first_bank_nibble > 0x0fU ||
        receipt.initial_state_lobe_roots.size() !=
            params.lobes ||
        receipt.barriers.size() != params.barriers ||
        receipt.barrier_roots.size() != params.barriers) {
        return Fail(why, "inventory");
    }

    std::vector<uint256> page_roots(
        params.bank_pages);
    std::vector<bool> page_seen(
        params.bank_pages, false);
    uint64_t callback_count = 0;
    std::vector<uint256> prior_lobe_roots =
        receipt.initial_state_lobe_roots;
    for (uint32_t barrier = 0;
         barrier < params.barriers; ++barrier) {
        const auto& item =
            receipt.barriers[barrier];
        if (item.barrier != barrier ||
            item.input_state_lobe_roots !=
                prior_lobe_roots ||
            item.lobes.size() != params.lobes ||
            item.extract_output_lobe_roots.size() !=
                params.lobes ||
            item.material_exchange.size() !=
                options.exchange_rounds ||
            !NonNull(item.gemm_accumulation_root) ||
            item.permutation_input_root !=
                item.gemm_accumulation_root ||
            item.mix_input_root !=
                item.permutation_output_root ||
            !NonNull(item.mix_output_root) ||
            !NonNull(item.extract_output_root) ||
            !NonNull(item.extract_prf) ||
            item.barrier_root !=
                receipt.barrier_roots[barrier]) {
            return Fail(
                why, "barrier_" +
                    std::to_string(barrier));
        }

        uint256 expected_stage_input =
            item.mix_output_root;
        for (uint32_t round = 0;
             round < options.exchange_rounds;
             ++round) {
            const auto& exchange =
                item.material_exchange[round];
            if (exchange.round != round ||
                exchange.input_root !=
                    expected_stage_input ||
                !NonNull(exchange.output_root)) {
                return Fail(
                    why, "exchange_" +
                        std::to_string(barrier) +
                        "_" + std::to_string(round));
            }
            expected_stage_input =
                exchange.output_root;
        }
        if (item.extract_input_root !=
                expected_stage_input) {
            return Fail(
                why, "extract_adjacency_" +
                    std::to_string(barrier));
        }

        for (uint32_t lobe = 0;
             lobe < params.lobes; ++lobe) {
            const auto& slot = item.lobes[lobe];
            const auto schedule =
                SelectCoupledBankPageIds(
                    barrier, lobe, params,
                    receipt.sigma,
                    options.full_bank_schedule,
                    options.transcript_version);
            if (slot.barrier != barrier ||
                slot.lobe != lobe ||
                slot.input_state_lobe_root !=
                    prior_lobe_roots[lobe] ||
                slot.pages.size() !=
                    schedule.size() ||
                slot.pages.empty()) {
                return Fail(
                    why, "lobe_" +
                        std::to_string(barrier) +
                        "_" + std::to_string(lobe));
            }
            uint256 prior_accumulator;
            for (uint32_t ordinal = 0;
                 ordinal < schedule.size();
                 ++ordinal) {
                const auto& page =
                    slot.pages[ordinal];
                if (page.barrier != barrier ||
                    page.lobe != lobe ||
                    page.page_ordinal != ordinal ||
                    page.page_id != schedule[ordinal] ||
                    page.page_id >= params.bank_pages ||
                    page.operand_a_root !=
                        slot.input_state_lobe_root ||
                    !NonNull(page.operand_b_root) ||
                    !NonNull(page.gemm_y_root) ||
                    !NonNull(
                        page.accumulation_before_root) ||
                    !NonNull(
                        page.accumulation_after_root) ||
                    page.event_commitment !=
                        CommitRCStage3CoupledPageCaptureV1(page) ||
                    (ordinal != 0 &&
                     page.accumulation_before_root !=
                        prior_accumulator)) {
                    return Fail(
                        why, "page_" +
                            std::to_string(barrier) +
                            "_" + std::to_string(lobe) +
                            "_" + std::to_string(ordinal));
                }
                if (page_seen[page.page_id] &&
                    page_roots[page.page_id] !=
                        page.operand_b_root) {
                    return Fail(
                        why, "bank_page_substitution");
                }
                page_seen[page.page_id] = true;
                page_roots[page.page_id] =
                    page.operand_b_root;
                prior_accumulator =
                    page.accumulation_after_root;
                ++callback_count;
            }
            if (slot.final_accumulation_root !=
                    prior_accumulator ||
                slot.lobe_commitment !=
                    CommitRCStage3CoupledLobeCaptureV1(slot)) {
                return Fail(
                    why, "lobe_commitment");
            }
        }
        if (item.stage_adjacency_commitment !=
                CommitRCStage3CoupledBarrierCaptureV1(item)) {
            return Fail(
                why, "barrier_commitment");
        }
        prior_lobe_roots =
            item.extract_output_lobe_roots;
    }

    if (callback_count != receipt.gemm_callbacks ||
        BankScheduleCommitment(
            page_roots, page_seen) !=
            receipt.scheduled_bank_pages_commitment ||
        AssembleCoupledEpisodeDigest(
            receipt.bank_root,
            receipt.barrier_roots,
            options.transcript_version) !=
            receipt.coupled_digest ||
        receipt.retained_receipt_bytes_upper_bound !=
            ReceiptBytesUpperBound(receipt) ||
        receipt.peak_accumulation_scratch_bytes !=
            uint64_t{
                params.rows_per_lobe == 0
                    ? 1
                    : params.rows_per_lobe} *
                params.lobe_width *
                sizeof(int64_t) ||
        receipt.receipt_commitment !=
            CommitRCStage3CoupledWinnerReceiptV2(
                receipt)) {
        return Fail(why, "terminal");
    }
    return true;
}

uint256 CommitRCStage3CoupledWinnerReceiptV1(
    const RCStage3CoupledWinnerReceiptV1& receipt)
{
    if (receipt.version !=
            kRCStage3CoupledWinnerCaptureVersionV2) {
        return {};
    }
    return CommitRCStage3CoupledWinnerReceiptV2(
        receipt);
}

bool VerifyRCStage3CoupledWinnerReceiptV1(
    const CBlockHeader& finalized_header,
    int32_t height,
    const RCCoupParams& params,
    const RCCoupOptions& options,
    const RCStage3CoupledWinnerReceiptV1& receipt,
    std::string* why)
{
    if (receipt.version !=
            kRCStage3CoupledWinnerCaptureVersionV2) {
        return Fail(
            why, "v1_source_alias_requires_v2");
    }
    return VerifyRCStage3CoupledWinnerReceiptV2(
        finalized_header, height, params,
        options, receipt, why);
}

RCStage3CoupledWinnerCaptureV1::
RCStage3CoupledWinnerCaptureV1(
    const CBlockHeader& finalized_header,
    int32_t height,
    const RCCoupParams& params,
    const RCCoupOptions& options)
    : m_options(options)
{
    m_work_header_precommit =
        CommitRCStage3CoupledWinnerHeaderPrecommitV2(
            finalized_header);
    m_receipt.winner_header_precommit =
        m_work_header_precommit;
    if (!finalized_header.matmul_digest.IsNull()) {
        m_header =
            std::make_unique<const CBlockHeader>(
                finalized_header);
        m_receipt.finalized_header_hash =
            finalized_header.GetHash();
        m_header_binding_finalized = true;
    }
    m_receipt.sigma =
        matmul::v4::DeriveSigma(finalized_header);
    m_receipt.height = height;
    m_receipt.params = params;
    m_receipt.transcript_version =
        options.transcript_version;
    m_receipt.full_bank_schedule =
        options.full_bank_schedule;
    m_receipt.material_exchange =
        options.material_exchange;
    m_receipt.exchange_rows =
        options.exchange_rows;
    m_receipt.exchange_rounds =
        options.exchange_rounds;
    m_receipt.force_signed_mix =
        options.force_signed_mix;
    m_receipt.no_bank_pages_retained = true;
    m_receipt.no_flat_tile_proofs_materialized = true;
    m_receipt.recursive_relation_proofs_bound = false;
    if (!ValidateRCCoupParams(params) ||
        options.skip_barrier ||
        options.skip_bank_page ||
        m_work_header_precommit.IsNull()) {
        Reject("constructor");
        return;
    }
    m_receipt.context_commitment =
        CommitRCStage3CoupledWinnerContextV2(
            finalized_header, height,
            params, options);
    m_expected_lobe_roots.resize(params.lobes);
    m_bank_page_roots.resize(params.bank_pages);
    m_bank_page_seen.assign(
        params.bank_pages, false);
    const uint32_t rows =
        params.rows_per_lobe == 0
            ? 1
            : params.rows_per_lobe;
    const uint64_t lobe_cells =
        uint64_t{rows} * params.lobe_width;
    if (lobe_cells >
            std::numeric_limits<size_t>::max() ||
        lobe_cells >
            std::numeric_limits<uint64_t>::max() /
                sizeof(int64_t)) {
        Reject("scratch_overflow");
        return;
    }
    m_lobe_accumulator.assign(
        static_cast<size_t>(lobe_cells), 0);
    m_receipt.peak_accumulation_scratch_bytes =
        lobe_cells * sizeof(int64_t);
}

RCStage3CoupledWinnerCaptureV1::
~RCStage3CoupledWinnerCaptureV1() = default;

void RCStage3CoupledWinnerCaptureV1::Reject(
    const std::string& why)
{
    if (m_error.empty()) m_error = why;
    m_complete_checked = false;
    m_complete_ok = false;
    m_complete_error.clear();
}

bool RCStage3CoupledWinnerCaptureV1::SealReceipt(
    std::string* why)
{
    if (m_sealed ||
        !m_header_binding_finalized ||
        m_header == nullptr ||
        !m_episode_seen ||
        !m_receipt.capture_complete ||
        m_receipt.finalized_header_hash !=
            m_header->GetHash()) {
        Reject("header_binding_not_finalizable");
        return Fail(
            why, "header_binding_not_finalizable");
    }
    m_receipt.receipt_commitment =
        CommitRCStage3CoupledWinnerReceiptV2(
            m_receipt);
    if (m_receipt.receipt_commitment.IsNull()) {
        Reject("receipt_commitment");
        return Fail(why, "receipt_commitment");
    }
    m_lobe_accumulator.clear();
    m_lobe_accumulator.shrink_to_fit();
    m_expected_lobe_roots.clear();
    m_bank_page_roots.clear();
    m_bank_page_seen.clear();
    m_current_barrier = {};
    m_gemm_boundary.reset();
    m_sealed = true;
    m_complete_checked = false;
    return true;
}

void RCStage3CoupledWinnerCaptureV1::StartBarrier(
    uint32_t barrier)
{
    m_current_barrier = {};
    m_current_barrier.barrier = barrier;
    m_current_barrier.input_state_lobe_roots =
        m_expected_lobe_roots;
    m_gemm_boundary =
        std::make_unique<BoundaryHasher>(
            m_work_header_precommit,
            barrier, 0,
            m_receipt.params.StateBytes());
    m_next_lobe = 0;
    m_next_page = 0;
    m_next_exchange_round = 0;
    m_permutation_seen = false;
    m_mix_seen = false;
    m_post_stage_root.SetNull();
}

bool RCStage3CoupledWinnerCaptureV1::
ReadyForBarrierStage(
    uint32_t barrier,
    const char* stage)
{
    if (!m_error.empty() ||
        !m_initial_seen ||
        m_episode_seen ||
        barrier != m_next_barrier ||
        m_next_lobe != m_receipt.params.lobes ||
        m_next_page != 0) {
        Reject(std::string(stage) + "_order");
        return false;
    }
    return true;
}

void RCStage3CoupledWinnerCaptureV1::OnInitialState(
    const RCCoupInitialStateProofWitnessView& view)
{
    if (!m_error.empty()) return;
    const auto& params = m_receipt.params;
    const uint32_t rows =
        params.rows_per_lobe == 0
            ? 1
            : params.rows_per_lobe;
    const uint64_t lobe_cells =
        uint64_t{rows} * params.lobe_width;
    if (m_initial_seen ||
        view.state == nullptr ||
        view.state_cells != params.StateBytes()) {
        Reject("initial_state");
        return;
    }
    m_receipt.initial_state_root =
        InitialStateRoot(
            m_work_header_precommit,
            view.state_cells, view.state);
    m_receipt.initial_state_lobe_roots.resize(
        params.lobes);
    for (uint32_t lobe = 0;
         lobe < params.lobes; ++lobe) {
        const auto root = LobeStateRoot(
            m_work_header_precommit,
            0, lobe, rows,
            params.lobe_width,
            view.state + uint64_t{lobe} *
                lobe_cells);
        m_receipt.initial_state_lobe_roots[lobe] =
            root;
        m_expected_lobe_roots[lobe] = root;
    }
    if (!AddBytes(
            m_receipt.captured_payload_bytes,
            view.state_cells)) {
        Reject("payload_overflow");
        return;
    }
    m_initial_seen = true;
    StartBarrier(0);
    m_complete_checked = false;
}

void RCStage3CoupledWinnerCaptureV1::OnGemm(
    const RCCoupGemmProofWitnessView& view)
{
    if (!m_error.empty()) return;
    const auto& params = m_receipt.params;
    const uint32_t rows =
        params.rows_per_lobe == 0
            ? 1
            : params.rows_per_lobe;
    const uint64_t lobe_cells =
        uint64_t{rows} * params.lobe_width;
    const uint64_t page_cells =
        uint64_t{params.lobe_width} *
        params.lobe_width;
    if (!m_initial_seen ||
        m_episode_seen ||
        view.barrier != m_next_barrier ||
        view.lobe != m_next_lobe ||
        view.rows != rows ||
        view.width != params.lobe_width ||
        view.operand_a == nullptr ||
        view.operand_b == nullptr ||
        view.gemm_y == nullptr ||
        m_next_lobe >= params.lobes) {
        Reject("gemm_shape_or_order");
        return;
    }
    const auto schedule =
        SelectCoupledBankPageIds(
            m_next_barrier, m_next_lobe,
            params, m_receipt.sigma,
            m_options.full_bank_schedule,
            m_options.transcript_version);
    if (schedule.empty() ||
        m_next_page >= schedule.size() ||
        view.page_id != schedule[m_next_page] ||
        view.page_id >= params.bank_pages) {
        Reject("gemm_page_schedule");
        return;
    }
    if (m_next_page == 0) {
        std::fill(
            m_lobe_accumulator.begin(),
            m_lobe_accumulator.end(), 0);
        RCStage3CoupledLobeCaptureV1 lobe;
        lobe.barrier = m_next_barrier;
        lobe.lobe = m_next_lobe;
        lobe.input_state_lobe_root =
            m_expected_lobe_roots[m_next_lobe];
        lobe.pages.reserve(schedule.size());
        m_current_barrier.lobes.push_back(
            std::move(lobe));
    }
    if (!m_receipt.representative_cells
             .gemm_observed) {
        m_receipt.representative_cells
            .first_gemm_operand_a =
                view.operand_a[0];
        m_receipt.representative_cells
            .first_gemm_operand_b =
                view.operand_b[0];
        m_receipt.representative_cells
            .first_bank_nibble =
                static_cast<uint8_t>(
                    view.operand_b[0]) &
                0x0fU;
        m_receipt.representative_cells
            .gemm_observed = true;
    }
    auto& lobe =
        m_current_barrier.lobes.back();
    RCStage3CoupledPageCaptureV1 page;
    page.barrier = m_next_barrier;
    page.lobe = m_next_lobe;
    page.page_ordinal = m_next_page;
    page.page_id = view.page_id;
    page.operand_a_root = LobeStateRoot(
        m_work_header_precommit,
        m_next_barrier, m_next_lobe,
        rows, params.lobe_width,
        view.operand_a);
    if (page.operand_a_root !=
            lobe.input_state_lobe_root) {
        Reject("gemm_input_feed_forward");
        return;
    }
    page.operand_b_root = BankPageRoot(
        m_work_header_precommit,
        view.page_id, params.lobe_width,
        view.operand_b);
    if (m_bank_page_seen[view.page_id] &&
        m_bank_page_roots[view.page_id] !=
            page.operand_b_root) {
        Reject("bank_page_substitution");
        return;
    }
    m_bank_page_seen[view.page_id] = true;
    m_bank_page_roots[view.page_id] =
        page.operand_b_root;
    page.gemm_y_root = PartialRoot(
        m_work_header_precommit,
        m_next_barrier, m_next_lobe,
        m_next_page, rows, params.lobe_width,
        view.gemm_y);
    page.accumulation_before_root =
        AccumulatorRoot(
            m_work_header_precommit,
            m_next_barrier, m_next_lobe,
            m_next_page, rows,
            params.lobe_width,
            m_lobe_accumulator.data());
    const uint64_t partial_bound =
        uint64_t{params.lobe_width} *
        kRCCoupInt8ProdAbsMax;
    for (uint64_t cell = 0;
         cell < lobe_cells; ++cell) {
        const int64_t value = view.gemm_y[cell];
        const uint64_t magnitude =
            value < 0
                ? uint64_t{0} -
                    static_cast<uint64_t>(value)
                : static_cast<uint64_t>(value);
        if (magnitude > partial_bound ||
            (value > 0 &&
             m_lobe_accumulator[cell] >
                 std::numeric_limits<int64_t>::max() -
                     value) ||
            (value < 0 &&
             m_lobe_accumulator[cell] <
                 std::numeric_limits<int64_t>::min() -
                     value)) {
            Reject("gemm_partial_range");
            return;
        }
        m_lobe_accumulator[cell] += value;
    }
    page.accumulation_after_root =
        AccumulatorRoot(
            m_work_header_precommit,
            m_next_barrier, m_next_lobe,
            m_next_page + 1, rows,
            params.lobe_width,
            m_lobe_accumulator.data());
    page.event_commitment =
        CommitRCStage3CoupledPageCaptureV1(page);
    lobe.pages.push_back(page);
    ++m_receipt.gemm_callbacks;
    if (!AddBytes(
            m_receipt.captured_payload_bytes,
            lobe_cells +
                page_cells +
                lobe_cells * sizeof(int64_t))) {
        Reject("payload_overflow");
        return;
    }
    ++m_next_page;
    if (m_next_page == schedule.size()) {
        lobe.final_accumulation_root =
            page.accumulation_after_root;
        lobe.lobe_commitment =
            CommitRCStage3CoupledLobeCaptureV1(lobe);
        if (!m_gemm_boundary->Append(
                m_lobe_accumulator.data(),
                lobe_cells)) {
            Reject("gemm_boundary_stream");
            return;
        }
        m_next_page = 0;
        ++m_next_lobe;
    }
    m_complete_checked = false;
}

void RCStage3CoupledWinnerCaptureV1::OnPermutation(
    const RCCoupPermutationProofWitnessView& view)
{
    if (!ReadyForBarrierStage(
            view.barrier, "permutation") ||
        m_permutation_seen ||
        view.state_cells !=
            m_receipt.params.StateBytes() ||
        view.input == nullptr ||
        view.output == nullptr) {
        if (m_error.empty()) Reject("permutation_shape");
        return;
    }
    m_current_barrier.gemm_accumulation_root =
        m_gemm_boundary->Finish();
    m_current_barrier.permutation_input_root =
        BoundaryRoot(
            m_work_header_precommit,
            m_next_barrier, 0,
            view.state_cells, view.input);
    if (m_current_barrier.permutation_input_root !=
            m_current_barrier
                .gemm_accumulation_root) {
        Reject("permutation_input_adjacency");
        return;
    }
    m_current_barrier.permutation_output_root =
        BoundaryRoot(
            m_work_header_precommit,
            m_next_barrier, 1,
            view.state_cells, view.output);
    m_post_stage_root =
        m_current_barrier.permutation_output_root;
    m_permutation_seen = true;
    if (!AddBytes(
            m_receipt.captured_payload_bytes,
            uint64_t{2} * view.state_cells *
                sizeof(int64_t))) {
        Reject("payload_overflow");
    }
    m_complete_checked = false;
}

void RCStage3CoupledWinnerCaptureV1::OnMix(
    const RCCoupMixProofWitnessView& view)
{
    if (!ReadyForBarrierStage(
            view.barrier, "mix") ||
        !m_permutation_seen ||
        m_mix_seen ||
        view.state_cells !=
            m_receipt.params.StateBytes() ||
        view.input == nullptr ||
        view.output == nullptr) {
        if (m_error.empty()) Reject("mix_shape");
        return;
    }
    m_current_barrier.mix_input_root =
        BoundaryRoot(
            m_work_header_precommit,
            m_next_barrier, 1,
            view.state_cells, view.input);
    if (m_current_barrier.mix_input_root !=
            m_post_stage_root) {
        Reject("mix_input_adjacency");
        return;
    }
    m_current_barrier.mix_output_root =
        BoundaryRoot(
            m_work_header_precommit,
            m_next_barrier, 2,
            view.state_cells, view.output);
    m_post_stage_root =
        m_current_barrier.mix_output_root;
    m_mix_seen = true;
    if (!AddBytes(
            m_receipt.captured_payload_bytes,
            uint64_t{2} * view.state_cells *
                sizeof(int64_t))) {
        Reject("payload_overflow");
    }
    m_complete_checked = false;
}

void RCStage3CoupledWinnerCaptureV1::
OnMaterialExchange(
    const RCCoupMaterialExchangeProofWitnessView& view)
{
    if (!ReadyForBarrierStage(
            view.barrier, "exchange") ||
        !m_mix_seen ||
        view.round != m_next_exchange_round ||
        view.round >= m_options.exchange_rounds ||
        view.state_cells !=
            m_receipt.params.StateBytes() ||
        view.input == nullptr ||
        view.output == nullptr) {
        if (m_error.empty()) Reject("exchange_shape");
        return;
    }
    RCStage3CoupledExchangeCaptureV1 exchange;
    exchange.round = view.round;
    exchange.input_root =
        BoundaryRoot(
            m_work_header_precommit,
            m_next_barrier, 2 + view.round,
            view.state_cells, view.input);
    if (exchange.input_root !=
            m_post_stage_root) {
        Reject("exchange_input_adjacency");
        return;
    }
    exchange.output_root =
        BoundaryRoot(
            m_work_header_precommit,
            m_next_barrier, 3 + view.round,
            view.state_cells, view.output);
    m_post_stage_root = exchange.output_root;
    m_current_barrier.material_exchange.push_back(
        exchange);
    ++m_next_exchange_round;
    if (!AddBytes(
            m_receipt.captured_payload_bytes,
            uint64_t{2} * view.state_cells *
                sizeof(int64_t))) {
        Reject("payload_overflow");
    }
    m_complete_checked = false;
}

void RCStage3CoupledWinnerCaptureV1::OnBarrier(
    const RCCoupBarrierProofWitnessView& view)
{
    if (!ReadyForBarrierStage(
            view.barrier, "barrier") ||
        !m_mix_seen ||
        m_next_exchange_round !=
            m_options.exchange_rounds ||
        view.state_cells < 2 ||
        view.state_cells !=
            m_receipt.params.StateBytes() ||
        view.extract_input == nullptr ||
        view.extract_output == nullptr ||
        view.extract_prf.IsNull()) {
        if (m_error.empty()) Reject("barrier_shape");
        return;
    }
    if (!m_receipt.representative_cells
             .extract_observed) {
        m_receipt.representative_cells
            .first_extract_input_a =
                view.extract_input[0];
        m_receipt.representative_cells
            .first_extract_input_b =
                view.extract_input[1];
        m_receipt.representative_cells
            .first_extract_output =
                view.extract_output[0];
        m_receipt.representative_cells
            .extract_observed = true;
    }
    m_current_barrier.extract_input_root =
        BoundaryRoot(
            m_work_header_precommit,
            m_next_barrier,
            2 + m_options.exchange_rounds,
            view.state_cells,
            view.extract_input);
    if (m_current_barrier.extract_input_root !=
            m_post_stage_root) {
        Reject("extract_input_adjacency");
        return;
    }
    m_current_barrier.extract_prf =
        view.extract_prf;
    m_current_barrier.extract_output_root =
        ExtractOutputRoot(
            m_work_header_precommit,
            m_next_barrier,
            view.state_cells,
            view.extract_output);
    const uint256 expected_barrier_root =
        NativeBarrierRoot(
            view.barrier,
            view.extract_output,
            view.state_cells,
            m_options.transcript_version);
    if (expected_barrier_root !=
            view.barrier_root ||
        view.barrier_root.IsNull()) {
        Reject("barrier_root_substitution");
        return;
    }
    m_current_barrier.barrier_root =
        view.barrier_root;
    m_receipt.barrier_roots.push_back(
        view.barrier_root);

    const auto& params = m_receipt.params;
    const uint32_t rows =
        params.rows_per_lobe == 0
            ? 1
            : params.rows_per_lobe;
    const uint64_t lobe_cells =
        uint64_t{rows} * params.lobe_width;
    m_current_barrier
        .extract_output_lobe_roots
        .resize(params.lobes);
    for (uint32_t lobe = 0;
         lobe < params.lobes; ++lobe) {
        const auto root = LobeStateRoot(
            m_work_header_precommit,
            m_next_barrier + 1,
            lobe, rows, params.lobe_width,
            view.extract_output +
                uint64_t{lobe} * lobe_cells);
        m_current_barrier
            .extract_output_lobe_roots[lobe] =
                root;
        m_expected_lobe_roots[lobe] = root;
    }
    m_current_barrier
        .stage_adjacency_commitment =
            CommitRCStage3CoupledBarrierCaptureV1(
                m_current_barrier);
    m_receipt.barriers.push_back(
        std::move(m_current_barrier));
    if (!AddBytes(
            m_receipt.captured_payload_bytes,
            uint64_t{view.state_cells} *
                (sizeof(int64_t) +
                 sizeof(int8_t)))) {
        Reject("payload_overflow");
        return;
    }
    ++m_next_barrier;
    if (m_next_barrier <
            m_receipt.params.barriers) {
        StartBarrier(m_next_barrier);
    } else {
        m_gemm_boundary.reset();
    }
    m_complete_checked = false;
}

void RCStage3CoupledWinnerCaptureV1::OnEpisode(
    const RCCoupEpisodeProofWitnessView& view)
{
    if (!m_error.empty()) return;
    if (m_episode_seen ||
        m_next_barrier !=
            m_receipt.params.barriers ||
        view.barrier_roots == nullptr ||
        view.barrier_roots->size() !=
            m_receipt.params.barriers ||
        *view.barrier_roots !=
            m_receipt.barrier_roots ||
        view.bank_root.IsNull() ||
        view.coupled_digest.IsNull() ||
        AssembleCoupledEpisodeDigest(
            view.bank_root,
            *view.barrier_roots,
            m_options.transcript_version) !=
            view.coupled_digest) {
        Reject("episode_terminal");
        return;
    }
    m_receipt.scheduled_bank_pages_commitment =
        BankScheduleCommitment(
            m_bank_page_roots,
            m_bank_page_seen);
    m_receipt.bank_root = view.bank_root;
    m_receipt.coupled_digest =
        view.coupled_digest;
    m_receipt.capture_complete = true;
    m_receipt.retained_receipt_bytes_upper_bound =
        ReceiptBytesUpperBound(m_receipt);
    m_episode_seen = true;
    m_complete_checked = false;
    if (m_header_binding_finalized) {
        (void)SealReceipt(nullptr);
    }
}

bool RCStage3CoupledWinnerCaptureV1::
FinalizeHeaderBindingV2(
    const CBlockHeader& finalized_header,
    const uint256& expected_coupled_digest,
    std::string* why)
{
    if (m_header_binding_finalized ||
        m_sealed) {
        return Fail(why, "header_binding_repeated");
    }
    if (!m_error.empty() ||
        !m_episode_seen ||
        !m_receipt.capture_complete) {
        Reject("header_binding_before_terminal");
        return Fail(
            why, "header_binding_before_terminal");
    }
    if (finalized_header.matmul_digest.IsNull() ||
        expected_coupled_digest.IsNull() ||
        expected_coupled_digest !=
            m_receipt.coupled_digest) {
        Reject("header_binding_terminal");
        return Fail(why, "header_binding_terminal");
    }
    if (CommitRCStage3CoupledWinnerHeaderPrecommitV2(
            finalized_header) !=
            m_work_header_precommit ||
        matmul::v4::DeriveSigma(finalized_header) !=
            m_receipt.sigma) {
        Reject("header_binding_context");
        return Fail(why, "header_binding_context");
    }
    m_header =
        std::make_unique<const CBlockHeader>(
            finalized_header);
    m_receipt.finalized_header_hash =
        finalized_header.GetHash();
    m_header_binding_finalized = true;
    return SealReceipt(why);
}

bool RCStage3CoupledWinnerCaptureV1::Complete(
    std::string* why) const
{
    if (m_complete_checked) {
        if (!m_complete_ok && why != nullptr) {
            *why = m_complete_error;
        }
        return m_complete_ok;
    }
    const auto finish =
        [this, why](
            bool ok,
            const std::string& error = {}) {
            m_complete_checked = true;
            m_complete_ok = ok;
            m_complete_error = error;
            if (!ok && why != nullptr) {
                *why = error;
            }
            return ok;
        };
    if (!m_error.empty()) {
        std::string error;
        (void)Fail(&error, m_error);
        return finish(false, error);
    }
    if (!m_initial_seen ||
        !m_episode_seen ||
        !m_header_binding_finalized ||
        !m_sealed ||
        m_header == nullptr) {
        std::string error;
        (void)Fail(&error, "incomplete");
        return finish(false, error);
    }
    std::string error;
    if (!VerifyRCStage3CoupledWinnerReceiptV2(
            *m_header,
            m_receipt.height,
            m_receipt.params,
            m_options,
            m_receipt,
            &error)) {
        return finish(false, error);
    }
    return finish(true);
}

bool RCStage3CoupledWinnerStorePutV1(
    const uint256& finalized_header_hash,
    std::shared_ptr<
        const RCStage3CoupledWinnerCaptureV1> capture,
    std::string* why)
{
    if (finalized_header_hash.IsNull() ||
        capture == nullptr ||
        !capture->Complete(why) ||
        capture->Receipt().finalized_header_hash !=
            finalized_header_hash) {
        return Fail(why, "winner_store_incomplete");
    }
    std::lock_guard<std::mutex> lock(
        g_coupled_winner_store_mutex);
    g_coupled_winner_store_header =
        finalized_header_hash;
    g_coupled_winner_store_capture =
        std::move(capture);
    return true;
}

std::shared_ptr<
    const RCStage3CoupledWinnerCaptureV1>
RCStage3CoupledWinnerStoreGetV1(
    const uint256& finalized_header_hash)
{
    if (finalized_header_hash.IsNull()) return {};
    std::lock_guard<std::mutex> lock(
        g_coupled_winner_store_mutex);
    if (g_coupled_winner_store_capture == nullptr ||
        g_coupled_winner_store_header !=
            finalized_header_hash) {
        return {};
    }
    return g_coupled_winner_store_capture;
}

void RCStage3CoupledWinnerStoreEraseV1(
    const uint256& finalized_header_hash)
{
    std::lock_guard<std::mutex> lock(
        g_coupled_winner_store_mutex);
    if (g_coupled_winner_store_header ==
            finalized_header_hash) {
        g_coupled_winner_store_header.SetNull();
        g_coupled_winner_store_capture.reset();
    }
}

void RCStage3CoupledWinnerStoreClearForTestV1()
{
    std::lock_guard<std::mutex> lock(
        g_coupled_winner_store_mutex);
    g_coupled_winner_store_header.SetNull();
    g_coupled_winner_store_capture.reset();
}

} // namespace matmul::v4::rc
