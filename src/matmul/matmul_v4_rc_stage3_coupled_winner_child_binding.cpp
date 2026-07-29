// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_winner_child_binding.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <primitives/block.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <vector>

namespace matmul::v4::rc {
namespace {

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
constexpr char kProductDomain[] =
    "BTX_RC_STAGE3_COUPLED_WINNER_CHILD_BINDING_V2";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:coupled_winner_child_binding:" +
            detail;
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

bool SameOptions(
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
    explicit RootWriter(const char* domain)
    {
        Bytes(
            reinterpret_cast<const unsigned char*>(
                domain),
            std::strlen(domain));
        U32(kRCStage3CoupledWinnerCaptureVersionV2);
    }

    void U32(uint32_t value)
    {
        unsigned char bytes[4];
        WriteLE32(bytes, value);
        Bytes(bytes, sizeof(bytes));
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

uint256 InitialRoot(
    const uint256& header,
    const std::vector<int8_t>& values)
{
    RootWriter hash(kInitialDomain);
    hash.Hash(header);
    hash.U64(values.size());
    hash.I8(values.data(), values.size());
    return hash.Finish();
}

uint256 LobeRoot(
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

uint256 PageRoot(
    const uint256& header,
    uint32_t page,
    uint32_t width,
    const std::vector<int8_t>& values)
{
    RootWriter hash(kPageDomain);
    hash.Hash(header);
    hash.U32(page);
    hash.U32(width);
    hash.U64(uint64_t{width} * width);
    hash.I8(values.data(), values.size());
    return hash.Finish();
}

uint256 PartialRoot(
    const uint256& header,
    uint32_t barrier,
    uint32_t lobe,
    uint32_t page_ordinal,
    uint32_t rows,
    uint32_t width,
    const std::vector<int64_t>& values)
{
    RootWriter hash(kPartialDomain);
    hash.Hash(header);
    hash.U32(barrier);
    hash.U32(lobe);
    hash.U32(page_ordinal);
    hash.U32(rows);
    hash.U32(width);
    hash.U64(uint64_t{rows} * width);
    hash.I64(values.data(), values.size());
    return hash.Finish();
}

uint256 AccumulatorRoot(
    const uint256& header,
    uint32_t barrier,
    uint32_t lobe,
    uint32_t prefix_pages,
    uint32_t rows,
    uint32_t width,
    const std::vector<int64_t>& values)
{
    RootWriter hash(kAccumulatorDomain);
    hash.Hash(header);
    hash.U32(barrier);
    hash.U32(lobe);
    hash.U32(prefix_pages);
    hash.U32(rows);
    hash.U32(width);
    hash.U64(uint64_t{rows} * width);
    hash.I64(values.data(), values.size());
    return hash.Finish();
}

uint256 BoundaryRoot(
    const uint256& header,
    uint32_t barrier,
    uint32_t position,
    const std::vector<int64_t>& values)
{
    RootWriter hash(kBoundaryDomain);
    hash.Hash(header);
    hash.U32(barrier);
    hash.U32(position);
    hash.U64(values.size());
    hash.I64(values.data(), values.size());
    return hash.Finish();
}

uint256 ExtractRoot(
    const uint256& header,
    uint32_t barrier,
    const std::vector<int8_t>& values)
{
    RootWriter hash(kExtractOutputDomain);
    hash.Hash(header);
    hash.U32(barrier);
    hash.U64(values.size());
    hash.I8(values.data(), values.size());
    return hash.Finish();
}

void HashRoots(
    HashWriter& hash,
    const std::vector<uint256>& roots)
{
    hash << static_cast<uint64_t>(roots.size());
    for (const auto& root : roots) hash << root;
}

bool CheckedAccumulate(
    std::vector<int64_t>& accumulator,
    const std::vector<int64_t>& addend)
{
    if (accumulator.size() != addend.size()) {
        return false;
    }
    for (uint64_t i = 0; i < accumulator.size(); ++i) {
        const __int128 next =
            static_cast<__int128>(accumulator[i]) +
            static_cast<__int128>(addend[i]);
        if (next <
                std::numeric_limits<int64_t>::min() ||
            next >
                std::numeric_limits<int64_t>::max()) {
            return false;
        }
        accumulator[i] = static_cast<int64_t>(next);
    }
    return true;
}

const RCStage3CoupledExchangeStageProduct*
FindExchangeStage(
    const RCStage3CoupledExchangePermutationProduct& product,
    RCStage3CoupledExchangeStageKind kind,
    uint32_t barrier,
    uint32_t lobe_or_round)
{
    const auto found = std::find_if(
        product.exchange_stages.begin(),
        product.exchange_stages.end(),
        [=](const auto& stage) {
            return stage.schedule.kind == kind &&
                stage.schedule.barrier == barrier &&
                stage.schedule.lobe_or_round ==
                    lobe_or_round;
        });
    if (found == product.exchange_stages.end()) {
        return nullptr;
    }
    return &*found;
}

const RCStage3CoupledPermutationStageProduct*
FindPermutationStage(
    const RCStage3CoupledExchangePermutationProduct& product,
    uint32_t barrier)
{
    const auto found = std::find_if(
        product.permutation_stages.begin(),
        product.permutation_stages.end(),
        [=](const auto& stage) {
            return stage.schedule.barrier == barrier;
        });
    if (found == product.permutation_stages.end()) {
        return nullptr;
    }
    return &*found;
}

uint256 ChildFamilyBinding(
    const RCStage3BoundedCoupledSemanticComposition& child,
    const RCStage3CoupledChainProduct& chain,
    const uint256& initial_link)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_COUPLED_WINNER_CHILD_FAMILIES_V2";
    hash << child.bank.product_commitment;
    hash << child.bank_root.manifest.commitment;
    hash << child.bank_root.bank_bytes.semantic_memory_root;
    hash << child.bank_root.bank_digest.semantic_memory_root;
    hash << child.initial_state.product_commitment;
    hash << initial_link;
    hash << child.gemm.product_commitment;
    hash << child.signed_range.value_roots_commitment;
    hash << child.exchange_permutation.product_commitment;
    hash << child.mix.product_commitment;
    hash << child.extract.product_commitment;
    hash << child.extract.output_to_barrier.pin.link_commitment;
    hash << chain.product_commitment;
    hash << child.root_chain.barrier_inputs_pin.pin_commitment;
    hash << child.root_chain.barrier_outputs_pin.pin_commitment;
    hash << child.root_chain.digest_inputs_pin.pin_commitment;
    hash << child.root_chain.digest_value_pin.pin_commitment;
    return hash.GetHash();
}

} // namespace

uint256 CommitRCStage3CoupledWinnerChildBindingV1(
    const RCStage3CoupledWinnerChildBindingV1& binding)
{
    HashWriter hash;
    hash << kProductDomain << binding.version;
    hash << binding.finalized_header_hash;
    hash << binding.statement_commitment;
    hash << binding.coupled_shape_commitment;
    hash << binding.winner_receipt_commitment;
    hash << binding.scheduled_page_instances;
    hash << binding.accumulation_links;
    hash << binding.stage_boundary_links;
    hash << binding.barrier_links;
    hash << binding.initial_state_binding;
    hash << binding.scheduled_page_binding;
    hash << binding.accumulation_binding;
    hash << binding.stage_boundary_binding;
    hash << binding.bank_hash_binding;
    hash << binding.barrier_digest_binding;
    hash << binding.representative_cell_binding;
    hash << binding.child_proof_family_binding;
    return hash.GetHash();
}

bool VerifyRCStage3CoupledWinnerChildBindingV1(
    const CBlockHeader& finalized_header,
    int32_t height,
    const RCCoupParams& params,
    const RCCoupOptions& options,
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledWinnerReceiptV1& winner,
    const RCStage3BoundedCoupledSemanticComposition& children,
    RCStage3CoupledWinnerChildBindingV1& out,
    std::string* why)
{
    out = {};
    const uint256 header_hash =
        finalized_header.GetHash();
    const RCStage3CoupledShape shape =
        MakeRCStage3CoupledShape(params, options);
    const uint256 statement_commitment =
        CommitRCStage3CoupledStatement(
            statement.public_inputs);
    const uint256 shape_commitment =
        CommitRCStage3CoupledShape(shape);
    std::string composition_why;
    if (!ValidateRCCoupParams(params) ||
        statement_commitment.IsNull() ||
        shape_commitment.IsNull() ||
        statement.statement !=
            RCStage3StatementKind::Composed ||
        statement.public_inputs.height != height ||
        statement.public_inputs.n_bits !=
            finalized_header.nBits ||
        statement.public_inputs.header_commitment !=
            RCStage3HeaderCommitment(
                finalized_header) ||
        statement.public_inputs.sigma !=
            matmul::v4::DeriveSigma(
                finalized_header) ||
        statement.public_inputs.transcript_version !=
            options.transcript_version ||
        statement.public_inputs.final_digest !=
            finalized_header.matmul_digest ||
        statement.public_inputs.coupled_digest !=
            winner.coupled_digest ||
        !SameParams(params, winner.params) ||
        !VerifyRCStage3CompositionLink(
            statement, &composition_why)) {
        return Fail(why, "public_context");
    }
    RCCoupOptions winner_options;
    winner_options.transcript_version =
        winner.transcript_version;
    winner_options.full_bank_schedule =
        winner.full_bank_schedule;
    winner_options.material_exchange =
        winner.material_exchange;
    winner_options.exchange_rows =
        winner.exchange_rows;
    winner_options.exchange_rounds =
        winner.exchange_rounds;
    winner_options.force_signed_mix =
        winner.force_signed_mix;
    if (!SameOptions(options, winner_options) ||
        winner.version !=
            kRCStage3CoupledWinnerCaptureVersionV2 ||
        !VerifyRCStage3CoupledWinnerReceiptV2(
            finalized_header, height, params,
            options, winner, why)) {
        return Fail(why, "winner_receipt");
    }
    const uint256 receipt_root_key =
        winner.winner_header_precommit;
    if (receipt_root_key.IsNull() ||
        receipt_root_key !=
            CommitRCStage3CoupledWinnerHeaderPrecommitV2(
                finalized_header)) {
        return Fail(why, "winner_root_key");
    }

    RCStage3CoupledChainProduct chain;
    uint256 initial_link;

    const uint32_t rows =
        params.rows_per_lobe == 0
            ? 1
            : params.rows_per_lobe;
    const uint64_t lobe_cells =
        uint64_t{rows} * params.lobe_width;
    const uint64_t state_cells =
        uint64_t{params.lobes} * lobe_cells;
    const uint64_t page_cells =
        uint64_t{params.lobe_width} *
        params.lobe_width;
    if (winner.barriers.size() != params.barriers ||
        winner.initial_state_lobe_roots.size() !=
            params.lobes ||
        winner.barrier_roots.size() !=
            params.barriers ||
        children.initial_state.lobes.size() !=
            params.lobes ||
        children.bank.pages.size() !=
            params.bank_pages ||
        children.mix.input_states.size() !=
            params.barriers ||
        children.mix.output_states.size() !=
            params.barriers ||
        children.root_chain.barriers.size() !=
            params.barriers) {
        return Fail(why, "child_inventory");
    }

    // The normalized no-replay parent consumes these six receipt cells
    // directly.  Root equality alone is insufficient for that handoff: an
    // attacker can alter a receipt cell and recompute the outer receipt
    // commitment without changing any captured vector root.  Bind each cell
    // to the corresponding executed child's concrete opening before any
    // expensive proof replay.
    if (children.gemm.gemms.empty() ||
        children.extract.tiles.empty() ||
        children.gemm.gemms.front()
            .operand_a.empty() ||
        children.gemm.gemms.front()
            .operand_b.empty() ||
        children.extract.tiles.front()
            .input.size() < 2 ||
        children.extract.tiles.front()
            .output.empty()) {
        return Fail(
            why, "representative_child_inventory");
    }
    const auto& representative =
        winner.representative_cells;
    const auto& representative_gemm =
        children.gemm.gemms.front();
    const auto& representative_extract =
        children.extract.tiles.front();
    const uint8_t proof_owned_bank_nibble =
        static_cast<uint8_t>(
            representative_gemm.operand_b.front()) &
        0x0fU;
    if (!representative.gemm_observed ||
        !representative.extract_observed ||
        representative.first_gemm_operand_a !=
            representative_gemm.operand_a.front() ||
        representative.first_gemm_operand_b !=
            representative_gemm.operand_b.front() ||
        representative.first_bank_nibble !=
            proof_owned_bank_nibble ||
        representative.first_extract_input_a !=
            representative_extract.input[0] ||
        representative.first_extract_input_b !=
            representative_extract.input[1] ||
        representative.first_extract_output !=
            representative_extract.output[0]) {
        return Fail(
            why, "representative_child_equality");
    }
    if (representative_gemm.schedule.page_id >=
            children.bank.pages.size()) {
        return Fail(
            why, "representative_bank_page");
    }
    {
        HashWriter hash;
        hash <<
            "BTX_RC_STAGE3_COUPLED_WINNER_REPRESENTATIVE_CELLS_V2";
        hash << static_cast<uint8_t>(
                    representative.first_gemm_operand_a)
             << static_cast<uint8_t>(
                    representative.first_gemm_operand_b)
             << representative.first_bank_nibble
             << static_cast<uint64_t>(
                    representative.first_extract_input_a)
             << static_cast<uint64_t>(
                    representative.first_extract_input_b)
             << static_cast<uint8_t>(
                    representative.first_extract_output)
             << representative_gemm
                    .instance_receipt_commitment
             << children.bank
                    .pages[
                        representative_gemm
                            .schedule.page_id]
                    .page_receipt_commitment
             << representative_extract.tile_commitment;
        out.representative_cell_binding =
            hash.GetHash();
    }

    std::vector<int8_t> initial_state;
    initial_state.reserve(state_cells);
    std::vector<uint256> initial_roots;
    for (uint32_t lobe = 0; lobe < params.lobes; ++lobe) {
        const auto& child =
            children.initial_state.lobes[lobe];
        if (child.lobe != lobe ||
            child.expanded_tile.size() <
                lobe_cells) {
            return Fail(why, "initial_lobe_shape");
        }
        const auto root = LobeRoot(
            receipt_root_key, 0, lobe, rows,
            params.lobe_width,
            child.expanded_tile.data());
        if (root !=
            winner.initial_state_lobe_roots[lobe]) {
            return Fail(why, "initial_lobe_root");
        }
        initial_roots.push_back(root);
        initial_state.insert(
            initial_state.end(),
            child.expanded_tile.begin(),
            child.expanded_tile.begin() +
                lobe_cells);
    }
    if (initial_state.size() != state_cells ||
        InitialRoot(receipt_root_key, initial_state) !=
            winner.initial_state_root) {
        return Fail(why, "initial_state_root");
    }
    {
        HashWriter hash;
        hash << "BTX_RC_STAGE3_COUPLED_WINNER_INITIAL_BINDING_V2";
        hash << winner.initial_state_root;
        HashRoots(hash, initial_roots);
        hash << children.initial_state.product_commitment;
        out.initial_state_binding = hash.GetHash();
    }

    std::vector<uint256> canonical_page_roots(
        params.bank_pages);
    for (uint32_t page = 0;
         page < params.bank_pages; ++page) {
        const auto& child = children.bank.pages[page];
        if (child.page_index != page ||
            child.page_bytes.size() != page_cells) {
            return Fail(why, "bank_page_shape");
        }
        canonical_page_roots[page] =
            PageRoot(
                receipt_root_key, page,
                params.lobe_width,
                child.page_bytes);
        if (canonical_page_roots[page].IsNull()) {
            return Fail(why, "bank_page_root");
        }
    }

    HashWriter scheduled_binding;
    scheduled_binding <<
        "BTX_RC_STAGE3_COUPLED_WINNER_SCHEDULED_PAGES_V2";
    HashWriter accumulation_binding;
    accumulation_binding <<
        "BTX_RC_STAGE3_COUPLED_WINNER_ACCUMULATION_V2";
    HashWriter stage_binding;
    stage_binding <<
        "BTX_RC_STAGE3_COUPLED_WINNER_STAGE_BOUNDARIES_V2";
    uint64_t gemm_cursor = 0;
    uint64_t extract_cursor = 0;
    for (uint32_t barrier = 0;
         barrier < params.barriers; ++barrier) {
        const auto& captured =
            winner.barriers[barrier];
        if (captured.barrier != barrier ||
            captured.lobes.size() !=
                params.lobes ||
            captured.extract_output_lobe_roots.size() !=
                params.lobes) {
            return Fail(why, "barrier_capture_shape");
        }
        std::vector<int64_t> complete_accumulation;
        complete_accumulation.reserve(state_cells);
        for (uint32_t lobe = 0;
             lobe < params.lobes; ++lobe) {
            const auto& lobe_capture =
                captured.lobes[lobe];
            if (lobe_capture.barrier != barrier ||
                lobe_capture.lobe != lobe ||
                lobe_capture.pages.size() !=
                    params.pages_per_barrier_lobe) {
                return Fail(why, "lobe_capture_shape");
            }
            std::vector<int64_t> accumulator(
                lobe_cells, 0);
            for (uint32_t page_slot = 0;
                 page_slot <
                    params.pages_per_barrier_lobe;
                 ++page_slot) {
                if (gemm_cursor >=
                    children.gemm.gemms.size()) {
                    return Fail(why, "gemm_child_omission");
                }
                const auto& child =
                    children.gemm.gemms[gemm_cursor];
                const auto& page =
                    lobe_capture.pages[page_slot];
                if (page.page_id >= params.bank_pages ||
                    child.schedule.schedule_index !=
                        gemm_cursor ||
                    child.schedule.barrier != barrier ||
                    child.schedule.lobe != lobe ||
                    child.schedule.page_slot != page_slot ||
                    child.schedule.page_id !=
                        page.page_id ||
                    child.operand_a.size() !=
                        lobe_cells ||
                    child.operand_b.size() !=
                        page_cells ||
                    child.output_y.size() !=
                        lobe_cells) {
                    return Fail(why, "gemm_child_schedule");
                }
                const uint256 a_root =
                    LobeRoot(
                        receipt_root_key, barrier, lobe,
                        rows, params.lobe_width,
                        child.operand_a.data());
                const uint256 b_root =
                    PageRoot(
                        receipt_root_key, page.page_id,
                        params.lobe_width,
                        child.operand_b);
                const uint256 y_root =
                    PartialRoot(
                        receipt_root_key, barrier, lobe,
                        page_slot, rows,
                        params.lobe_width,
                        child.output_y);
                const uint256 before_root =
                    AccumulatorRoot(
                        receipt_root_key, barrier, lobe,
                        page_slot, rows,
                        params.lobe_width,
                        accumulator);
                if (!CheckedAccumulate(
                        accumulator,
                        child.output_y)) {
                    return Fail(
                        why, "accumulation_overflow");
                }
                const uint256 after_root =
                    AccumulatorRoot(
                        receipt_root_key, barrier, lobe,
                        page_slot + 1, rows,
                        params.lobe_width,
                        accumulator);
                if (a_root != page.operand_a_root ||
                    b_root != page.operand_b_root ||
                    b_root !=
                        canonical_page_roots[
                            page.page_id] ||
                    y_root != page.gemm_y_root ||
                    before_root !=
                        page.accumulation_before_root ||
                    after_root !=
                        page.accumulation_after_root) {
                    return Fail(
                        why, "gemm_page_opening_root");
                }
                scheduled_binding <<
                    page.event_commitment;
                accumulation_binding <<
                    page.accumulation_before_root <<
                    page.gemm_y_root <<
                    page.accumulation_after_root;
                ++out.scheduled_page_instances;
                ++out.accumulation_links;
                ++gemm_cursor;
            }
            if (AccumulatorRoot(
                    receipt_root_key, barrier, lobe,
                    params.pages_per_barrier_lobe,
                    rows, params.lobe_width,
                    accumulator) !=
                    lobe_capture
                        .final_accumulation_root) {
                return Fail(
                    why, "lobe_accumulation_terminal");
            }
            const auto* fixed =
                FindExchangeStage(
                    children.exchange_permutation,
                    RCStage3CoupledExchangeStageKind::
                        FixedSegment,
                    barrier, lobe);
            if (fixed == nullptr ||
                fixed->input != accumulator) {
                return Fail(
                    why, "gemm_to_exchange_child");
            }
            complete_accumulation.insert(
                complete_accumulation.end(),
                accumulator.begin(),
                accumulator.end());
        }
        if (complete_accumulation.size() !=
                state_cells ||
            BoundaryRoot(
                receipt_root_key, barrier, 0,
                complete_accumulation) !=
                captured.gemm_accumulation_root ||
            captured.gemm_accumulation_root !=
                captured.permutation_input_root) {
            return Fail(
                why, "gemm_boundary_root");
        }
        const auto* permutation =
            FindPermutationStage(
                children.exchange_permutation,
                barrier);
        if (permutation == nullptr ||
            permutation->input !=
                complete_accumulation ||
            permutation->input.size() !=
                state_cells ||
            permutation->output.size() !=
                state_cells ||
            BoundaryRoot(
                receipt_root_key, barrier, 0,
                permutation->input) !=
                captured.permutation_input_root ||
            BoundaryRoot(
                receipt_root_key, barrier, 1,
                permutation->output) !=
                captured.permutation_output_root) {
            return Fail(
                why, "permutation_boundary_root");
        }
        if (children.mix.input_states[barrier] !=
                permutation->output ||
            BoundaryRoot(
                receipt_root_key, barrier, 1,
                children.mix.input_states[barrier]) !=
                captured.mix_input_root ||
            BoundaryRoot(
                receipt_root_key, barrier, 2,
                children.mix.output_states[barrier]) !=
                captured.mix_output_root) {
            return Fail(why, "mix_boundary_root");
        }
        stage_binding <<
            captured.gemm_accumulation_root <<
            captured.permutation_output_root <<
            captured.mix_output_root;
        out.stage_boundary_links += 4;

        const std::vector<int64_t>* extract_input =
            &children.mix.output_states[barrier];
        if (captured.material_exchange.size() !=
                options.exchange_rounds) {
            return Fail(
                why, "material_exchange_inventory");
        }
        for (uint32_t round = 0;
             round < options.exchange_rounds;
             ++round) {
            const auto* exchange =
                FindExchangeStage(
                    children.exchange_permutation,
                    RCStage3CoupledExchangeStageKind::
                        MaterialRound,
                    barrier, round);
            const auto& link =
                captured.material_exchange[round];
            if (exchange == nullptr ||
                exchange->input != *extract_input ||
                BoundaryRoot(
                    receipt_root_key, barrier,
                    2 + round, exchange->input) !=
                    link.input_root ||
                BoundaryRoot(
                    receipt_root_key, barrier,
                    3 + round, exchange->output) !=
                    link.output_root) {
                return Fail(
                    why, "material_exchange_boundary");
            }
            stage_binding <<
                link.input_root << link.output_root;
            extract_input = &exchange->output;
            out.stage_boundary_links += 2;
        }
        if (BoundaryRoot(
                receipt_root_key, barrier,
                2 + options.exchange_rounds,
                *extract_input) !=
                captured.extract_input_root) {
            return Fail(
                why, "extract_input_boundary");
        }

        std::vector<int64_t> extract_values;
        std::vector<int8_t> extract_output;
        extract_values.reserve(state_cells);
        extract_output.reserve(state_cells);
        const uint64_t tiles =
            state_cells / kRCMxBlockLen;
        for (uint32_t tile = 0;
             tile < tiles; ++tile) {
            if (extract_cursor >=
                children.extract.tiles.size()) {
                return Fail(
                    why, "extract_child_omission");
            }
            const auto& child =
                children.extract.tiles[
                    extract_cursor++];
            if (child.schedule.barrier != barrier ||
                child.schedule.tile != tile ||
                child.schedule.extract_prf !=
                    captured.extract_prf) {
                return Fail(
                    why, "extract_child_schedule");
            }
            extract_values.insert(
                extract_values.end(),
                child.input.begin(),
                child.input.end());
            extract_output.insert(
                extract_output.end(),
                child.output.begin(),
                child.output.end());
        }
        if (extract_values != *extract_input ||
            BoundaryRoot(
                receipt_root_key, barrier,
                2 + options.exchange_rounds,
                extract_values) !=
                captured.extract_input_root ||
            ExtractRoot(
                receipt_root_key, barrier,
                extract_output) !=
                captured.extract_output_root) {
            return Fail(
                why, "extract_opening_root");
        }
        for (uint32_t lobe = 0;
             lobe < params.lobes; ++lobe) {
            if (LobeRoot(
                    receipt_root_key, barrier + 1, lobe,
                    rows, params.lobe_width,
                    extract_output.data() +
                        uint64_t{lobe} *
                            lobe_cells) !=
                captured
                    .extract_output_lobe_roots[
                        lobe]) {
                return Fail(
                    why, "extract_lobe_root");
            }
        }
        if (children.root_chain.barriers[barrier]
                .manifest.direct.digest !=
                captured.barrier_root ||
            captured.barrier_root !=
                winner.barrier_roots[barrier]) {
            return Fail(
                why, "barrier_proof_terminal");
        }
        stage_binding <<
            captured.extract_input_root <<
            captured.extract_output_root <<
            captured.barrier_root;
        out.stage_boundary_links += 3;
        ++out.barrier_links;
    }
    if (gemm_cursor != children.gemm.gemms.size() ||
        extract_cursor !=
            children.extract.tiles.size()) {
        return Fail(why, "child_trailing_instances");
    }

    out.scheduled_page_binding =
        scheduled_binding.GetHash();
    out.accumulation_binding =
        accumulation_binding.GetHash();
    out.stage_boundary_binding =
        stage_binding.GetHash();
    if (children.bank_root.manifest.bank_root !=
            winner.bank_root ||
        children.root_chain.digest_manifest
                .direct.digest !=
            winner.coupled_digest ||
        winner.coupled_digest !=
            statement.public_inputs.coupled_digest) {
        return Fail(why, "root_chain_terminal");
    }
    {
        HashWriter hash;
        hash << "BTX_RC_STAGE3_COUPLED_WINNER_BANK_HASH_BINDING_V2";
        HashRoots(hash, canonical_page_roots);
        hash << children.bank.bank_page_byte_root;
        hash << children.bank_root.manifest.commitment;
        hash << children.bank_root.manifest.bank_root;
        hash << winner.bank_root;
        out.bank_hash_binding = hash.GetHash();
    }
    {
        HashWriter hash;
        hash <<
            "BTX_RC_STAGE3_COUPLED_WINNER_BARRIER_DIGEST_BINDING_V2";
        HashRoots(hash, winner.barrier_roots);
        hash << children.root_chain
                    .barrier_inputs_pin.pin_commitment;
        hash << children.root_chain
                    .barrier_outputs_pin.pin_commitment;
        hash << children.root_chain
                    .digest_inputs_pin.pin_commitment;
        hash << children.root_chain
                    .digest_value_pin.pin_commitment;
        hash << winner.bank_root;
        hash << winner.coupled_digest;
        out.barrier_digest_binding = hash.GetHash();
    }

    out.finalized_header_hash = header_hash;
    out.statement_commitment = statement_commitment;
    out.coupled_shape_commitment = shape_commitment;
    out.winner_receipt_commitment =
        winner.receipt_commitment;
    // Execute proof cryptography only after the cheap exact-root inventory
    // has failed closed. This ordering is a DoS property, not an acceptance
    // shortcut: no binding object is returned before every child verifies.
    if (!VerifyRCStage3CoupledChainProduct(
            statement, finalized_header, shape,
            children.bank, children.gemm,
            children.exchange_permutation,
            children.mix, children.extract,
            chain, why)) {
        return Fail(why, "child_chain_proofs");
    }
    if (!VerifyRCStage3CoupledInitialStateGemmLink(
            statement, shape,
            children.initial_state,
            children.gemm, initial_link, why)) {
        return Fail(why, "child_initial_state_proof");
    }
    if (!VerifyRCStage3CoupledSignedRangeGemmLink(
            statement, shape, children.gemm,
            children.signed_range, why)) {
        return Fail(why, "child_signed_range_proof");
    }
    if (!VerifyRCStage3CoupledRootChainWithBoundedBankProductProducer(
            statement, finalized_header, shape,
            children.bank, children.bank_root,
            children.root_chain, why)) {
        return Fail(why, "child_bank_barrier_digest_proofs");
    }
    out.child_proof_family_binding =
        ChildFamilyBinding(
            children, chain, initial_link);
    if (out.initial_state_binding.IsNull() ||
        out.scheduled_page_binding.IsNull() ||
        out.accumulation_binding.IsNull() ||
        out.stage_boundary_binding.IsNull() ||
        out.bank_hash_binding.IsNull() ||
        out.barrier_digest_binding.IsNull() ||
        out.representative_cell_binding.IsNull() ||
        out.child_proof_family_binding.IsNull()) {
        return Fail(why, "null_binding");
    }
    out.product_commitment =
        CommitRCStage3CoupledWinnerChildBindingV1(out);
    if (out.product_commitment.IsNull()) {
        return Fail(why, "product_commitment");
    }
    if (why != nullptr) {
        *why =
            "stage3:coupled_winner_child_binding:"
            "bounded_child_proofs_and_exact_winner_openings_bound;"
            "recursive_compression_pending";
    }
    return true;
}

} // namespace matmul::v4::rc
