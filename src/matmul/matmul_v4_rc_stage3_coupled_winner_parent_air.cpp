// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_winner_parent_air.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <primitives/block.h>

#include <algorithm>
#include <array>
#include <functional>
#include <limits>
#include <numeric>
#include <utility>

namespace matmul::v4::rc::coupled_winner_parent_air {
namespace {

using AirConstraint = aq::AirConstraint<gf::Fp3>;
using AirCS = aq::AirConstraintSystem<gf::Fp3>;

constexpr char kTableDomain[] =
    "BTX_RC_STAGE3_COUPLED_WINNER_PARENT_TERMINALS_V1";
constexpr char kFsDomain[] =
    "BTX_RC_STAGE3_COUPLED_WINNER_PARENT_FS_V1";
constexpr uint32_t kParentProofMagicV1 =
    0x31505743U; // "CWP1", little-endian.

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:coupled_winner_parent_air:" +
            detail;
    }
    return false;
}

void AppendU16(
    std::vector<unsigned char>& out,
    uint16_t value)
{
    out.push_back(
        static_cast<unsigned char>(value));
    out.push_back(
        static_cast<unsigned char>(value >> 8));
}

void AppendU32(
    std::vector<unsigned char>& out,
    uint32_t value)
{
    for (uint32_t i = 0; i < 4; ++i) {
        out.push_back(
            static_cast<unsigned char>(
                value >> (8U * i)));
    }
}

void AppendRoot(
    std::vector<unsigned char>& out,
    const uint256& root)
{
    out.insert(
        out.end(), root.begin(), root.end());
}

class CodecReader {
public:
    explicit CodecReader(
        const std::vector<unsigned char>& bytes)
        : m_cursor(bytes.data()),
          m_end(bytes.data() + bytes.size())
    {
    }

    bool U16(uint16_t& value)
    {
        if (Remaining() < 2) return false;
        value =
            static_cast<uint16_t>(m_cursor[0]) |
            (static_cast<uint16_t>(m_cursor[1]) << 8);
        m_cursor += 2;
        return true;
    }

    bool U32(uint32_t& value)
    {
        if (Remaining() < 4) return false;
        value =
            static_cast<uint32_t>(m_cursor[0]) |
            (static_cast<uint32_t>(m_cursor[1]) << 8) |
            (static_cast<uint32_t>(m_cursor[2]) << 16) |
            (static_cast<uint32_t>(m_cursor[3]) << 24);
        m_cursor += 4;
        return true;
    }

    bool Root(uint256& value)
    {
        if (Remaining() < value.size()) return false;
        value = uint256{
            Span<const unsigned char>{
                m_cursor, value.size()}};
        m_cursor += value.size();
        return true;
    }

    bool Bytes(
        uint32_t count,
        std::vector<unsigned char>& out)
    {
        if (Remaining() < count) return false;
        out.assign(m_cursor, m_cursor + count);
        m_cursor += count;
        return true;
    }

    size_t Remaining() const
    {
        return static_cast<size_t>(m_end - m_cursor);
    }

private:
    const unsigned char* m_cursor;
    const unsigned char* m_end;
};

gf::Fp3 U64(uint64_t value)
{
    return gf::Fp3::FromFp(gf::FromU64(value));
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    uint32_t out = 2;
    while (out < value) {
        if (out > (1U << 30)) return 0;
        out <<= 1;
    }
    return out;
}

uint256 EncodeCount(uint64_t value)
{
    std::array<unsigned char, 32> bytes{};
    for (uint32_t i = 0; i < 8; ++i) {
        bytes[i] =
            static_cast<unsigned char>(
                value >> (8U * i));
    }
    return uint256{
        Span<const unsigned char>{
            bytes.data(), bytes.size()}};
}

std::array<uint32_t, kRootLimbsV1>
RootLimbs(const uint256& root)
{
    std::array<uint32_t, kRootLimbsV1> out{};
    for (uint32_t limb = 0;
         limb < out.size(); ++limb) {
        const uint32_t offset = 4U * limb;
        out[limb] =
            static_cast<uint32_t>(
                root.begin()[offset]) |
            (static_cast<uint32_t>(
                 root.begin()[offset + 1]) << 8) |
            (static_cast<uint32_t>(
                 root.begin()[offset + 2]) << 16) |
            (static_cast<uint32_t>(
                 root.begin()[offset + 3]) << 24);
    }
    return out;
}

void AddConstraint(
    AirCS& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<gf::Fp3(
        const std::vector<gf::Fp3>&,
        const std::vector<gf::Fp3>&)> eval)
{
    AirConstraint constraint;
    constraint.name = name;
    constraint.kind = kind;
    constraint.alg_degree = degree;
    constraint.eval = std::move(eval);
    cs.constraints.push_back(
        std::move(constraint));
}

void Push(
    std::vector<TerminalCellV1>& out,
    TerminalFamilyV1 family,
    TerminalKindV1 kind,
    uint64_t instance,
    uint32_t subordinal,
    const uint256& value)
{
    out.push_back(
        {family, kind, instance,
         subordinal, value});
}

void PushBinding(
    std::vector<TerminalCellV1>& out,
    uint32_t ordinal,
    TerminalKindV1 kind,
    const uint256& value)
{
    Push(
        out, TerminalFamilyV1::Binding,
        kind, ordinal, 0, value);
}

void PushProduct(
    std::vector<TerminalCellV1>& out,
    uint32_t ordinal,
    const uint256& value)
{
    Push(
        out, TerminalFamilyV1::Product,
        TerminalKindV1::ProductRoot,
        ordinal, 0, value);
}

template <typename Backend>
void PushAirProof(
    std::vector<TerminalCellV1>& out,
    TerminalFamilyV1 family,
    uint64_t instance,
    const aq::AirQuotientProof<
        gf::Fp3, Backend>& proof)
{
    Push(
        out, family,
        TerminalKindV1::TraceRoot,
        instance, 0,
        proof.trace_commit);
}

void PushSplitRapProof(
    std::vector<TerminalCellV1>& out,
    TerminalFamilyV1 family,
    uint64_t instance,
    const aq::AirQuotientSplitRapRowsProof& proof)
{
    for (uint32_t group = 0;
         group < proof.batch.groups.size();
         ++group) {
        TerminalKindV1 kind =
            TerminalKindV1::R0GroupRoot;
        if (group == 1) {
            kind =
                TerminalKindV1::DependentGroupRoot;
        } else if (group >= 2) {
            kind =
                TerminalKindV1::QuotientGroupRoot;
        }
        Push(
            out, family, kind, instance,
            group,
            Fri3AlgDigestToUint256(
                proof.batch.groups[group]
                    .row_commit.root));
    }
}

void PushFlatBundle(
    std::vector<TerminalCellV1>& out,
    TerminalFamilyV1 family,
    uint64_t& instance,
    const stage3_hash_semantic::
        FlatBoundaryProofBundle& bundle)
{
    for (const auto& proof : bundle.proofs) {
        const uint64_t current = instance++;
        Push(
            out, family,
            TerminalKindV1::StatementRoot,
            current, 0,
            proof.boundary_statement);
        Push(
            out, family,
            TerminalKindV1::PinRoot,
            current, 0,
            proof.challenge_commitment);
        PushAirProof(
            out, family, current,
            proof.quotient);
    }
}

void PushSemanticBundle(
    std::vector<TerminalCellV1>& out,
    uint64_t& instance,
    const RCStage3CoupledSemanticFlatBundle& bundle)
{
    for (const auto& shard : bundle.shards) {
        const uint64_t current = instance++;
        Push(
            out, TerminalFamilyV1::SemanticShard,
            TerminalKindV1::StatementRoot,
            current,
            static_cast<uint32_t>(
                bundle.endpoint),
            shard.pin.statement_commitment);
        Push(
            out, TerminalFamilyV1::SemanticShard,
            TerminalKindV1::ShapeRoot,
            current,
            static_cast<uint32_t>(
                bundle.endpoint),
            shard.pin.shape_commitment);
        Push(
            out, TerminalFamilyV1::SemanticShard,
            TerminalKindV1::PinRoot,
            current,
            static_cast<uint32_t>(
                bundle.endpoint),
            shard.pin.semantic_memory_root);
        PushAirProof(
            out, TerminalFamilyV1::SemanticShard,
            current, shard.proof);
        Push(
            out, TerminalFamilyV1::SemanticShard,
            TerminalKindV1::TerminalRoot,
            current,
            static_cast<uint32_t>(
                bundle.endpoint),
            bundle.bundle_commitment);
    }
}

bool BindingEqual(
    const RCStage3CoupledWinnerChildBindingV1& a,
    const RCStage3CoupledWinnerChildBindingV1& b)
{
    return a == b;
}

uint256 PublicFsSeed(
    const RCStage3CoupledWinnerChildBindingV1& binding,
    const uint256& table_commitment)
{
    HashWriter hash;
    hash << kFsDomain;
    hash << kVersionV1;
    hash << binding.finalized_header_hash;
    hash << binding.statement_commitment;
    hash << binding.coupled_shape_commitment;
    hash << binding.winner_receipt_commitment;
    hash << binding.product_commitment;
    hash << table_commitment;
    return hash.GetHash();
}

bool BuildApplication(
    const std::vector<TerminalCellV1>& cells,
    AirCS& cs,
    LayoutV1& layout,
    std::vector<std::vector<gf::Fp3>>& columns,
    aq::AirQuotientFixedTracePinV3& fixed_trace,
    aq::AirQuotientTwoEpochBaseRowSession& r0,
    std::string* why)
{
    if (!BuildConstraintSystemV1(
            cells.size(), cs, &layout, why) ||
        !BuildWitnessV1(
            cells, layout, cs.n_rows,
            columns, why)) {
        return false;
    }
    fixed_trace = {};
    fixed_trace.ordered_columns.resize(
        layout.phase0_end);
    std::iota(
        fixed_trace.ordered_columns.begin(),
        fixed_trace.ordered_columns.end(), 0);
    r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            cs, columns,
            fixed_trace.ordered_columns);
    if (!r0.valid ||
        r0.base_row_commitment.IsNull()) {
        return Fail(why, "r0_session");
    }
    fixed_trace.row_root =
        r0.base_row_commitment;
    return true;
}

} // namespace

size_t SerializeParentProofV1(
    const ParentProofV1& proof,
    std::vector<unsigned char>& out,
    std::string* why)
{
    out.clear();
    if (proof.version != kVersionV1 ||
        proof.terminal_cells == 0 ||
        proof.terminal_cells >
            kMaxTerminalCellsV1 ||
        proof.trace_rows < 2 ||
        (proof.trace_rows &
         (proof.trace_rows - 1U)) != 0 ||
        proof.terminal_cells >
            proof.trace_rows ||
        proof.terminal_table_commitment.IsNull() ||
        proof.r0_row_group_root.IsNull() ||
        proof.proof.version !=
            aq::
                kAirQuotientSplitRapRowsSafeFixedProofVersionV3 ||
        proof.proof.trace_rows !=
            proof.trace_rows) {
        Fail(why, "codec_statement");
        return 0;
    }
    std::vector<unsigned char> native;
    const size_t native_size =
        aq::SerializeAirQuotientSplitRapRowsProof(
            proof.proof, native);
    constexpr size_t kHeaderBytes =
        4 + 2 + 2 + 4 + 4 + 32 + 32 + 4;
    if (native_size == 0 ||
        native_size != native.size() ||
        native_size >
            std::numeric_limits<uint32_t>::max() ||
        native_size >
            kRCStage3MaxProofBytes -
                kHeaderBytes) {
        Fail(why, "codec_native_proof");
        return 0;
    }
    out.reserve(kHeaderBytes + native_size);
    AppendU32(out, kParentProofMagicV1);
    AppendU16(out, proof.version);
    AppendU16(out, 0);
    AppendU32(out, proof.terminal_cells);
    AppendU32(out, proof.trace_rows);
    AppendRoot(
        out, proof.terminal_table_commitment);
    AppendRoot(out, proof.r0_row_group_root);
    AppendU32(
        out,
        static_cast<uint32_t>(native_size));
    out.insert(
        out.end(), native.begin(), native.end());
    if (why != nullptr) {
        *why =
            "stage3:coupled_winner_parent_air:"
            "parent_codec_canonical";
    }
    return out.size();
}

std::optional<ParentProofV1>
DeserializeParentProofV1(
    const std::vector<unsigned char>& bytes,
    std::string* why)
{
    const auto fail =
        [&](const std::string& detail)
            -> std::optional<ParentProofV1> {
        Fail(why, "codec_decode_" + detail);
        return std::nullopt;
    };
    constexpr size_t kHeaderBytes =
        4 + 2 + 2 + 4 + 4 + 32 + 32 + 4;
    if (bytes.size() <= kHeaderBytes ||
        bytes.size() >
            kRCStage3MaxProofBytes) {
        return fail("size");
    }
    CodecReader reader(bytes);
    uint32_t magic = 0;
    uint16_t reserved = 0;
    ParentProofV1 out;
    uint32_t native_size = 0;
    if (!reader.U32(magic) ||
        !reader.U16(out.version) ||
        !reader.U16(reserved) ||
        !reader.U32(out.terminal_cells) ||
        !reader.U32(out.trace_rows) ||
        !reader.Root(
            out.terminal_table_commitment) ||
        !reader.Root(out.r0_row_group_root) ||
        !reader.U32(native_size) ||
        magic != kParentProofMagicV1 ||
        out.version != kVersionV1 ||
        reserved != 0 ||
        out.terminal_cells == 0 ||
        out.terminal_cells >
            kMaxTerminalCellsV1 ||
        out.trace_rows < 2 ||
        (out.trace_rows &
         (out.trace_rows - 1U)) != 0 ||
        out.terminal_cells >
            out.trace_rows ||
        out.terminal_table_commitment.IsNull() ||
        out.r0_row_group_root.IsNull() ||
        native_size == 0 ||
        reader.Remaining() != native_size) {
        return fail("statement");
    }
    std::vector<unsigned char> native;
    if (!reader.Bytes(native_size, native) ||
        reader.Remaining() != 0) {
        return fail("native_bytes");
    }
    const auto decoded =
        aq::DeserializeAirQuotientSplitRapRowsProof(
            native);
    if (!decoded.has_value()) {
        return fail("native_proof");
    }
    out.proof = *decoded;
    std::vector<unsigned char> canonical_native;
    if (aq::SerializeAirQuotientSplitRapRowsProof(
            out.proof,
            canonical_native) != native_size ||
        canonical_native != native ||
        out.proof.version !=
            aq::
                kAirQuotientSplitRapRowsSafeFixedProofVersionV3 ||
        out.proof.trace_rows !=
            out.trace_rows) {
        return fail("native_noncanonical");
    }
    std::vector<unsigned char> canonical;
    if (SerializeParentProofV1(
            out, canonical, nullptr) !=
            bytes.size() ||
        canonical != bytes) {
        return fail("noncanonical");
    }
    if (why != nullptr) {
        *why =
            "stage3:coupled_winner_parent_air:"
            "parent_codec_decoded";
    }
    return out;
}

bool CollectTerminalCellsV1(
    const RCStage3CoupledWinnerChildBindingV1& binding,
    const RCStage3BoundedCoupledSemanticComposition& children,
    std::vector<TerminalCellV1>& out,
    std::string* why)
{
    out.clear();
    if (binding.version !=
            kRCStage3CoupledWinnerChildBindingVersionV1 ||
        binding.product_commitment !=
            CommitRCStage3CoupledWinnerChildBindingV1(
                binding)) {
        return Fail(why, "binding_commitment");
    }

    PushBinding(
        out, 0, TerminalKindV1::StatementRoot,
        binding.finalized_header_hash);
    PushBinding(
        out, 1, TerminalKindV1::StatementRoot,
        binding.statement_commitment);
    PushBinding(
        out, 2, TerminalKindV1::ShapeRoot,
        binding.coupled_shape_commitment);
    PushBinding(
        out, 3, TerminalKindV1::TerminalRoot,
        binding.winner_receipt_commitment);
    PushBinding(
        out, 4, TerminalKindV1::Count,
        EncodeCount(
            binding.scheduled_page_instances));
    PushBinding(
        out, 5, TerminalKindV1::Count,
        EncodeCount(
            binding.accumulation_links));
    PushBinding(
        out, 6, TerminalKindV1::Count,
        EncodeCount(
            binding.stage_boundary_links));
    PushBinding(
        out, 7, TerminalKindV1::Count,
        EncodeCount(binding.barrier_links));
    const std::array<uint256, 9> roots{
        binding.initial_state_binding,
        binding.scheduled_page_binding,
        binding.accumulation_binding,
        binding.stage_boundary_binding,
        binding.bank_hash_binding,
        binding.barrier_digest_binding,
        binding.child_proof_family_binding,
        binding.product_commitment,
        children.extract.output_to_barrier
            .pin.link_commitment,
    };
    for (uint32_t i = 0;
         i < roots.size(); ++i) {
        PushBinding(
            out, 8 + i,
            TerminalKindV1::TerminalRoot,
            roots[i]);
    }

    const std::array<uint256, 12> products{
        children.bank.product_commitment,
        children.bank_root.manifest.commitment,
        children.bank_root.bank_bytes
            .semantic_memory_root,
        children.bank_root.bank_digest
            .semantic_memory_root,
        children.initial_state.product_commitment,
        children.gemm.product_commitment,
        children.signed_range
            .value_roots_commitment,
        children.exchange_permutation
            .product_commitment,
        children.mix.product_commitment,
        children.extract.product_commitment,
        children.root_chain
            .barrier_inputs_pin.pin_commitment,
        children.root_chain
            .digest_value_pin.pin_commitment,
    };
    for (uint32_t i = 0;
         i < products.size(); ++i) {
        PushProduct(out, i, products[i]);
    }

    uint64_t bank_hash_instance = 0;
    PushFlatBundle(
        out, TerminalFamilyV1::BankHash,
        bank_hash_instance,
        children.bank.bank_root_seed.proof);
    for (const auto& page : children.bank.pages) {
        PushFlatBundle(
            out, TerminalFamilyV1::BankHash,
            bank_hash_instance,
            page.page_seed.proof);
        PushFlatBundle(
            out, TerminalFamilyV1::BankHash,
            bank_hash_instance,
            page.mantissa_proof);
        PushFlatBundle(
            out, TerminalFamilyV1::BankHash,
            bank_hash_instance,
            page.scale_proof);
        Push(
            out, TerminalFamilyV1::BankDequant,
            TerminalKindV1::StatementRoot,
            page.page_index, 0,
            page.dequant_pin
                .statement_commitment);
        Push(
            out, TerminalFamilyV1::BankDequant,
            TerminalKindV1::PinRoot,
            page.page_index, 0,
            page.dequant_pin.pin_commitment);
        Push(
            out, TerminalFamilyV1::BankDequant,
            TerminalKindV1::R0GroupRoot,
            page.page_index, 0,
            page.dequant_pin
                .r0_row_group_root);
        PushSplitRapProof(
            out, TerminalFamilyV1::BankDequant,
            page.page_index,
            page.dequant_proof);
        Push(
            out, TerminalFamilyV1::BankDequant,
            TerminalKindV1::TerminalRoot,
            page.page_index, 0,
            page.page_receipt_commitment);
    }

    uint64_t initial_hash_instance = 0;
    for (const auto& lobe :
         children.initial_state.lobes) {
        PushFlatBundle(
            out, TerminalFamilyV1::InitialHash,
            initial_hash_instance,
            lobe.lobe_seed.proof);
        PushFlatBundle(
            out, TerminalFamilyV1::InitialHash,
            initial_hash_instance,
            lobe.mantissa_proof);
        PushFlatBundle(
            out, TerminalFamilyV1::InitialHash,
            initial_hash_instance,
            lobe.scale_proof);
        Push(
            out, TerminalFamilyV1::InitialDequant,
            TerminalKindV1::StatementRoot,
            lobe.lobe, 0,
            lobe.dequant_pin
                .statement_commitment);
        Push(
            out, TerminalFamilyV1::InitialDequant,
            TerminalKindV1::PinRoot,
            lobe.lobe, 0,
            lobe.dequant_pin.pin_commitment);
        Push(
            out, TerminalFamilyV1::InitialDequant,
            TerminalKindV1::R0GroupRoot,
            lobe.lobe, 0,
            lobe.dequant_pin
                .r0_row_group_root);
        PushSplitRapProof(
            out, TerminalFamilyV1::InitialDequant,
            lobe.lobe, lobe.dequant_proof);
        Push(
            out, TerminalFamilyV1::InitialDequant,
            TerminalKindV1::TerminalRoot,
            lobe.lobe, 0,
            lobe.receipt_commitment);
    }

    uint64_t gemm_instance = 0;
    for (const auto& gemm :
         children.gemm.gemms) {
        for (const auto& tile : gemm.tiles) {
            Push(
                out, TerminalFamilyV1::Gemm,
                TerminalKindV1::StatementRoot,
                gemm_instance, 0,
                tile.pin.statement_commitment);
            Push(
                out, TerminalFamilyV1::Gemm,
                TerminalKindV1::PinRoot,
                gemm_instance, 0,
                tile.pin.pin_commitment);
            PushAirProof(
                out, TerminalFamilyV1::Gemm,
                gemm_instance, tile.proof);
            Push(
                out, TerminalFamilyV1::Gemm,
                TerminalKindV1::TerminalRoot,
                gemm_instance, 0,
                gemm.instance_receipt_commitment);
            ++gemm_instance;
        }
    }

    for (uint64_t i = 0;
         i < children.signed_range.shards.size();
         ++i) {
        const auto& shard =
            children.signed_range.shards[i];
        Push(
            out, TerminalFamilyV1::SignedRange,
            TerminalKindV1::StatementRoot,
            i, 0,
            shard.pin.statement_commitment);
        Push(
            out, TerminalFamilyV1::SignedRange,
            TerminalKindV1::PinRoot,
            i, 0,
            ComputeRCStage3SignedRangePinCommitment(
                shard.pin));
        PushAirProof(
            out, TerminalFamilyV1::SignedRange,
            i, shard.proof);
        Push(
            out, TerminalFamilyV1::SignedRange,
            TerminalKindV1::TerminalRoot,
            i, 0,
            children.signed_range
                .value_roots_commitment);
    }

    uint64_t exchange_hash_instance = 0;
    for (const auto& stage :
         children.exchange_permutation
             .exchange_stages) {
        for (const auto& hash :
             stage.hash_executions) {
            PushFlatBundle(
                out, TerminalFamilyV1::ExchangeHash,
                exchange_hash_instance,
                hash.proof);
        }
        Push(
            out, TerminalFamilyV1::Exchange,
            TerminalKindV1::StatementRoot,
            stage.schedule.schedule_index, 0,
            stage.pin.statement_commitment);
        Push(
            out, TerminalFamilyV1::Exchange,
            TerminalKindV1::PinRoot,
            stage.schedule.schedule_index, 0,
            stage.pin.pin_commitment);
        PushAirProof(
            out, TerminalFamilyV1::Exchange,
            stage.schedule.schedule_index,
            stage.proof);
        Push(
            out, TerminalFamilyV1::Exchange,
            TerminalKindV1::TerminalRoot,
            stage.schedule.schedule_index, 0,
            stage.stage_commitment);
    }
    for (const auto& stage :
         children.exchange_permutation
             .permutation_stages) {
        Push(
            out, TerminalFamilyV1::Permutation,
            TerminalKindV1::StatementRoot,
            stage.schedule.schedule_index, 0,
            stage.pin.statement_commitment);
        Push(
            out, TerminalFamilyV1::Permutation,
            TerminalKindV1::PinRoot,
            stage.schedule.schedule_index, 0,
            stage.pin.pin_commitment);
        PushAirProof(
            out, TerminalFamilyV1::Permutation,
            stage.schedule.schedule_index,
            stage.proof);
        Push(
            out, TerminalFamilyV1::Permutation,
            TerminalKindV1::TerminalRoot,
            stage.schedule.schedule_index, 0,
            stage.stage_commitment);
    }

    uint64_t mix_hash_instance = 0;
    for (const auto& seed :
         children.mix.barrier_seeds) {
        PushFlatBundle(
            out, TerminalFamilyV1::MixHash,
            mix_hash_instance,
            seed.mix_seed.proof);
        PushFlatBundle(
            out, TerminalFamilyV1::MixHash,
            mix_hash_instance,
            seed.mask_block.proof);
    }
    Push(
        out, TerminalFamilyV1::Mix,
        TerminalKindV1::StatementRoot,
        0, 0,
        children.mix.arithmetic_pin
            .statement_commitment);
    Push(
        out, TerminalFamilyV1::Mix,
        TerminalKindV1::PinRoot,
        0, 0,
        children.mix.arithmetic_pin
            .pin_commitment);
    PushAirProof(
        out, TerminalFamilyV1::Mix, 0,
        children.mix.arithmetic_proof);
    Push(
        out, TerminalFamilyV1::Mix,
        TerminalKindV1::TerminalRoot,
        0, 0,
        children.mix.product_commitment);

    uint64_t extract_hash_instance = 0;
    for (const auto& tile :
         children.extract.tiles) {
        PushFlatBundle(
            out, TerminalFamilyV1::ExtractHash,
            extract_hash_instance,
            tile.hashes.chacha_proofs);
        PushFlatBundle(
            out, TerminalFamilyV1::ExtractHash,
            extract_hash_instance,
            tile.hashes.scale_proofs);
        Push(
            out, TerminalFamilyV1::Extract,
            TerminalKindV1::StatementRoot,
            tile.schedule.instance, 0,
            tile.mix_pin.statement_commitment);
        Push(
            out, TerminalFamilyV1::Extract,
            TerminalKindV1::PinRoot,
            tile.schedule.instance, 0,
            tile.mix_pin.pin_commitment);
        PushAirProof(
            out, TerminalFamilyV1::Extract,
            tile.schedule.instance,
            tile.mix_proof);
        Push(
            out, TerminalFamilyV1::Extract,
            TerminalKindV1::TerminalRoot,
            tile.schedule.instance, 0,
            tile.tile_commitment);
    }
    uint64_t semantic_instance = 0;
    PushSemanticBundle(
        out, semantic_instance,
        children.extract.input_cells);
    PushSemanticBundle(
        out, semantic_instance,
        children.extract.sampler_cells);
    PushSemanticBundle(
        out, semantic_instance,
        children.extract.scale_cells);
    PushSemanticBundle(
        out, semantic_instance,
        children.extract.output_to_barrier
            .extract_outputs);

    uint64_t bank_root_hash_instance = 0;
    PushFlatBundle(
        out, TerminalFamilyV1::BankRootHash,
        bank_root_hash_instance,
        children.bank_root.hash_proofs);

    uint64_t barrier_hash_instance = 0;
    for (const auto& barrier :
         children.extract.output_to_barrier
             .barriers) {
        PushFlatBundle(
            out, TerminalFamilyV1::BarrierHash,
            barrier_hash_instance,
            barrier.hash_proofs);
    }
    for (const auto& barrier :
         children.root_chain.barriers) {
        PushFlatBundle(
            out, TerminalFamilyV1::BarrierHash,
            barrier_hash_instance,
            barrier.hash_bundle);
    }
    uint64_t digest_hash_instance = 0;
    PushFlatBundle(
        out, TerminalFamilyV1::DigestHash,
        digest_hash_instance,
        children.root_chain.digest_hash_bundle);

    const std::array<const RCStage3RootChainVectorProof*, 4>
        vectors{
            &children.root_chain
                 .barrier_inputs_proof,
            &children.root_chain
                 .barrier_outputs_proof,
            &children.root_chain
                 .digest_inputs_proof,
            &children.root_chain
                 .digest_value_proof,
        };
    for (uint64_t i = 0;
         i < vectors.size(); ++i) {
        Push(
            out, TerminalFamilyV1::RootVector,
            TerminalKindV1::PinRoot,
            i, 0,
            vectors[i]->pin_commitment);
        PushAirProof(
            out, TerminalFamilyV1::RootVector,
            i, vectors[i]->quotient);
    }

    if (out.empty() ||
        out.size() > kMaxTerminalCellsV1 ||
        std::any_of(
            out.begin(), out.end(),
            [](const auto& cell) {
                return cell.value.IsNull();
            })) {
        out.clear();
        return Fail(
            why, "terminal_inventory");
    }
    return true;
}

uint256 CommitTerminalCellsV1(
    const std::vector<TerminalCellV1>& cells)
{
    HashWriter hash;
    hash << kTableDomain;
    hash << kVersionV1;
    hash << static_cast<uint64_t>(
        cells.size());
    for (uint64_t ordinal = 0;
         ordinal < cells.size(); ++ordinal) {
        const auto& cell = cells[ordinal];
        hash << ordinal;
        hash << static_cast<uint16_t>(
            cell.family);
        hash << static_cast<uint16_t>(
            cell.kind);
        hash << cell.instance;
        hash << cell.subordinal;
        hash << cell.value;
    }
    return hash.GetHash();
}

bool BuildConstraintSystemV1(
    uint32_t terminal_cells,
    AirCS& out,
    LayoutV1* layout_out,
    std::string* why)
{
    out = {};
    if (terminal_cells == 0 ||
        terminal_cells >
            kMaxTerminalCellsV1) {
        return Fail(why, "terminal_count");
    }
    const uint32_t rows =
        NextPowerOfTwo(terminal_cells);
    if (rows == 0) {
        return Fail(why, "trace_rows");
    }
    LayoutV1 layout;
    uint32_t next = 0;
    layout.active = next++;
    layout.ordinal = next++;
    layout.family = next++;
    layout.kind = next++;
    layout.instance_lo = next++;
    layout.instance_hi = next++;
    layout.subordinal = next++;
    layout.claimed_root_base = next;
    next += kRootLimbsV1;
    layout.verified_root_base = next;
    next += kRootLimbsV1;
    layout.phase0_end = next;
    layout.difference_base = next;
    next += kRootLimbsV1;
    layout.n_columns = next;

    out.n_rows = rows;
    out.n_columns = layout.n_columns;
    AddConstraint(
        out, "coupled.parent.active_boolean",
        aq::AirKind::kEverywhere, 2,
        [layout](const auto& cur,
                 const auto&) {
            return gf::Mul(
                cur[layout.active],
                gf::Sub(
                    cur[layout.active],
                    gf::Fp3::One()));
        });
    for (uint32_t limb = 0;
         limb < kRootLimbsV1; ++limb) {
        AddConstraint(
            out, "coupled.parent.difference",
            aq::AirKind::kEverywhere, 2,
            [layout, limb](
                const auto& cur,
                const auto&) {
                const auto expected =
                    gf::Sub(
                        cur[
                            layout
                                .claimed_root_base +
                            limb],
                        cur[
                            layout
                                .verified_root_base +
                            limb]);
                return gf::Mul(
                    cur[layout.active],
                    gf::Sub(
                        expected,
                        cur[
                            layout
                                .difference_base +
                            limb]));
            });
        AddConstraint(
            out, "coupled.parent.equal",
            aq::AirKind::kEverywhere, 1,
            [layout, limb](
                const auto& cur,
                const auto&) {
                return cur[
                    layout.difference_base +
                    limb];
            });
    }
    AddConstraint(
        out, "coupled.parent.ordinal_step",
        aq::AirKind::kTransition, 2,
        [layout](const auto& cur,
                 const auto& next_row) {
            return gf::Mul(
                next_row[layout.active],
                gf::Sub(
                    next_row[layout.ordinal],
                    gf::Add(
                        cur[layout.ordinal],
                        gf::Fp3::One())));
        });
    if (layout_out != nullptr) {
        *layout_out = layout;
    }
    return true;
}

bool BuildWitnessV1(
    const std::vector<TerminalCellV1>& cells,
    const LayoutV1& layout,
    uint32_t trace_rows,
    std::vector<std::vector<gf::Fp3>>& out,
    std::string* why)
{
    out.assign(
        layout.n_columns,
        std::vector<gf::Fp3>(
            trace_rows, gf::Fp3::Zero()));
    if (cells.empty() ||
        cells.size() > trace_rows ||
        trace_rows < 2 ||
        (trace_rows &
         (trace_rows - 1U)) != 0) {
        out.clear();
        return Fail(why, "witness_shape");
    }
    for (uint32_t row = 0;
         row < cells.size(); ++row) {
        const auto& cell = cells[row];
        const auto limbs =
            RootLimbs(cell.value);
        out[layout.active][row] =
            gf::Fp3::One();
        out[layout.ordinal][row] =
            U64(row);
        out[layout.family][row] =
            U64(static_cast<uint16_t>(
                cell.family));
        out[layout.kind][row] =
            U64(static_cast<uint16_t>(
                cell.kind));
        out[layout.instance_lo][row] =
            U64(static_cast<uint32_t>(
                cell.instance));
        out[layout.instance_hi][row] =
            U64(static_cast<uint32_t>(
                cell.instance >> 32));
        out[layout.subordinal][row] =
            U64(cell.subordinal);
        for (uint32_t limb = 0;
             limb < limbs.size(); ++limb) {
            const auto value =
                U64(limbs[limb]);
            out[
                layout.claimed_root_base +
                limb][row] = value;
            out[
                layout.verified_root_base +
                limb][row] = value;
        }
    }
    return true;
}

bool ProveV1(
    const CBlockHeader& finalized_header,
    int32_t height,
    const RCCoupParams& params,
    const RCCoupOptions& options,
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledWinnerReceiptV1& winner,
    const RCStage3BoundedCoupledSemanticComposition& children,
    const RCStage3CoupledWinnerChildBindingV1& expected_binding,
    ParentProofV1& out,
    const aq::AirProveOptions& prove_options,
    std::string* why)
{
    out = {};
    RCStage3CoupledWinnerChildBindingV1
        verified_binding;
    if (!VerifyRCStage3CoupledWinnerChildBindingV1(
            finalized_header, height,
            params, options, statement,
            winner, children,
            verified_binding, why) ||
        !BindingEqual(
            expected_binding,
            verified_binding)) {
        return Fail(why, "native_child_binding");
    }
    std::vector<TerminalCellV1> cells;
    if (!CollectTerminalCellsV1(
            verified_binding, children,
            cells, why)) {
        return false;
    }
    const uint256 table_commitment =
        CommitTerminalCellsV1(cells);
    if (table_commitment.IsNull()) {
        return Fail(why, "table_commitment");
    }
    AirCS cs;
    LayoutV1 layout;
    std::vector<std::vector<gf::Fp3>>
        columns;
    aq::AirQuotientFixedTracePinV3
        fixed_trace;
    aq::AirQuotientTwoEpochBaseRowSession
        r0;
    if (!BuildApplication(
            cells, cs, layout, columns,
            fixed_trace, r0, why)) {
        return false;
    }
    const uint256 fs_seed =
        PublicFsSeed(
            verified_binding,
            table_commitment);
    auto proved =
        aq::AirQuotientProveRowsSplitRapSafeFixedV3(
            cs, columns, fixed_trace,
            fs_seed, prove_options, &r0);
    if (!proved.ok ||
        !proved.division_exact) {
        return Fail(
            why,
            "parent_prove:" + proved.note);
    }
    out.version = kVersionV1;
    out.terminal_cells =
        static_cast<uint32_t>(
            cells.size());
    out.trace_rows = cs.n_rows;
    out.terminal_table_commitment =
        table_commitment;
    out.r0_row_group_root =
        fixed_trace.row_root;
    out.proof =
        std::move(proved.proof);
    std::string proof_why;
    if (!VerifyV1(
            finalized_header, height,
            params, options, statement,
            winner, children,
            expected_binding, out,
            &proof_why)) {
        out = {};
        return Fail(
            why,
            "self_verify:" + proof_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:coupled_winner_parent_air:"
            "native_children_verified_and_all_terminal_cells_mapped;"
            "recursive_child_verifier_pending";
    }
    return true;
}

bool VerifyV1(
    const CBlockHeader& finalized_header,
    int32_t height,
    const RCCoupParams& params,
    const RCCoupOptions& options,
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledWinnerReceiptV1& winner,
    const RCStage3BoundedCoupledSemanticComposition& children,
    const RCStage3CoupledWinnerChildBindingV1& expected_binding,
    const ParentProofV1& proof,
    std::string* why)
{
    RCStage3CoupledWinnerChildBindingV1
        verified_binding;
    if (!VerifyRCStage3CoupledWinnerChildBindingV1(
            finalized_header, height,
            params, options, statement,
            winner, children,
            verified_binding, why) ||
        !BindingEqual(
            expected_binding,
            verified_binding)) {
        return Fail(
            why, "verify_native_child_binding");
    }
    std::vector<TerminalCellV1> cells;
    if (!CollectTerminalCellsV1(
            verified_binding, children,
            cells, why)) {
        return false;
    }
    const uint256 table_commitment =
        CommitTerminalCellsV1(cells);
    AirCS cs;
    LayoutV1 layout;
    std::vector<std::vector<gf::Fp3>>
        columns;
    aq::AirQuotientFixedTracePinV3
        fixed_trace;
    aq::AirQuotientTwoEpochBaseRowSession
        r0;
    if (proof.version != kVersionV1 ||
        proof.terminal_cells != cells.size() ||
        proof.terminal_table_commitment !=
            table_commitment ||
        !BuildApplication(
            cells, cs, layout, columns,
            fixed_trace, r0, why) ||
        proof.trace_rows != cs.n_rows ||
        proof.r0_row_group_root !=
            fixed_trace.row_root) {
        return Fail(
            why, "verify_public_statement");
    }
    const uint256 fs_seed =
        PublicFsSeed(
            verified_binding,
            table_commitment);
    std::string proof_why;
    if (!aq::AirQuotientVerifyRowsSplitRapSafeFixedV3(
            cs, proof.proof,
            fixed_trace, fs_seed,
            &proof_why)) {
        return Fail(
            why,
            "verify_parent_proof:" +
                proof_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:coupled_winner_parent_air:"
            "native_v1_parent_ok";
    }
    return true;
}

} // namespace matmul::v4::rc::coupled_winner_parent_air
