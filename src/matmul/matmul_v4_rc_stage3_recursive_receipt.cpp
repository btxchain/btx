// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_recursive_receipt.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>

namespace matmul::v4::rc::recursive_receipt {
namespace {

constexpr uint32_t kQuotientRowKindV1 = 8;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:recursive_receipt:" + detail;
    }
    return false;
}

void WriteU16(std::vector<unsigned char>& out, uint16_t value)
{
    out.push_back(static_cast<unsigned char>(value));
    out.push_back(static_cast<unsigned char>(value >> 8));
}

void WriteU32(std::vector<unsigned char>& out, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
}

void WriteU64(std::vector<unsigned char>& out, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) {
        out.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
}

void WriteHash(std::vector<unsigned char>& out, const uint256& value)
{
    out.insert(out.end(), value.begin(), value.end());
}

class Reader {
public:
    explicit Reader(const std::vector<unsigned char>& bytes)
        : m_bytes(bytes)
    {
    }

    bool U16(uint16_t& out)
    {
        if (Remaining() < 2) return false;
        out = static_cast<uint16_t>(m_bytes[m_pos]) |
            static_cast<uint16_t>(m_bytes[m_pos + 1]) << 8;
        m_pos += 2;
        return true;
    }

    bool U32(uint32_t& out)
    {
        if (Remaining() < 4) return false;
        out = 0;
        for (unsigned i = 0; i < 4; ++i) {
            out |= static_cast<uint32_t>(m_bytes[m_pos + i])
                << (8 * i);
        }
        m_pos += 4;
        return true;
    }

    bool U64(uint64_t& out)
    {
        if (Remaining() < 8) return false;
        out = 0;
        for (unsigned i = 0; i < 8; ++i) {
            out |= static_cast<uint64_t>(m_bytes[m_pos + i])
                << (8 * i);
        }
        m_pos += 8;
        return true;
    }

    bool Hash(uint256& out)
    {
        if (Remaining() < out.size()) return false;
        std::copy_n(
            m_bytes.begin() + static_cast<ptrdiff_t>(m_pos),
            out.size(), out.begin());
        m_pos += out.size();
        return true;
    }

    bool Bytes(uint32_t count, std::vector<unsigned char>& out)
    {
        if (count > Remaining()) return false;
        out.assign(
            m_bytes.begin() + static_cast<ptrdiff_t>(m_pos),
            m_bytes.begin() +
                static_cast<ptrdiff_t>(m_pos + count));
        m_pos += count;
        return true;
    }

    [[nodiscard]] size_t Remaining() const
    {
        return m_bytes.size() - m_pos;
    }

private:
    const std::vector<unsigned char>& m_bytes;
    size_t m_pos{0};
};

fp::AlgAirProof ToCanonicalAlgProof(
    aq::AirQuotientRowsProof proof)
{
    fp::AlgAirProof out;
    out.batch = std::move(proof.batch);
    out.next_openings = std::move(proof.next_openings);
    out.trace_commit = proof.trace_commit;
    return out;
}

const std::vector<gf::Fp3>* FindPreprocessed(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    uint32_t column)
{
    const auto it = std::find_if(
        cs.preprocessed.begin(), cs.preprocessed.end(),
        [column](const auto& item) {
            return item.first == column;
        });
    return it == cs.preprocessed.end() ? nullptr : &it->second;
}

bool SameFp3Vectors(
    const std::vector<gf::Fp3>& a,
    const std::vector<gf::Fp3>& b)
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (!gf::Eq(a[i], b[i])) return false;
    }
    return true;
}

bool BindingMatchesConstraintSystem(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const ShardTerminalBindingV1& binding,
    std::string* why)
{
    if (!binding.valid ||
        binding.version != kShardReceiptVersionV1 ||
        binding.layout.expected_local_q !=
            binding.original_columns ||
        binding.layout.query_index !=
            binding.original_columns + 1 ||
        binding.layout.End() != cs.n_columns ||
        binding.queries == 0 ||
        binding.query_indices.size() != binding.queries ||
        binding.local_q_per_query.size() != binding.queries) {
        return Fail(why, "binding_shape");
    }
    const uint32_t bytecode_width =
        fp::BytecodeBusLayout(0).End();
    if (binding.original_columns < bytecode_width) {
        return Fail(why, "binding_bytecode_width");
    }
    const fp::BytecodeBusLayout bus(
        binding.original_columns - bytecode_width);
    if (bus.End() != binding.original_columns) {
        return Fail(why, "binding_bytecode_layout");
    }
    const auto* quotient_rows =
        FindPreprocessed(
            cs, bus.RowKind(kQuotientRowKindV1));
    const auto* expected =
        FindPreprocessed(
            cs, binding.layout.expected_local_q);
    const auto* query_indices =
        FindPreprocessed(
            cs, binding.layout.query_index);
    if (quotient_rows == nullptr || expected == nullptr ||
        query_indices == nullptr ||
        quotient_rows->size() != cs.n_rows ||
        expected->size() != cs.n_rows ||
        query_indices->size() != cs.n_rows) {
        return Fail(why, "binding_preprocessed");
    }
    uint32_t query = 0;
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        const bool active = !gf::IsZero((*quotient_rows)[row]);
        if (!active) {
            if (!gf::IsZero((*expected)[row]) ||
                !gf::IsZero((*query_indices)[row])) {
                return Fail(why, "binding_padding_nonzero");
            }
            continue;
        }
        if (!gf::Eq((*quotient_rows)[row], gf::Fp3::One()) ||
            query >= binding.queries ||
            !gf::Eq(
                (*expected)[row],
                binding.local_q_per_query[query]) ||
            !gf::Eq(
                (*query_indices)[row],
                gf::Fp3::FromFp(gf::FromU64(
                    binding.query_indices[query])))) {
            return Fail(why, "binding_terminal_values");
        }
        ++query;
    }
    if (query != binding.queries) {
        return Fail(why, "binding_terminal_count");
    }
    const bool has_alias = std::any_of(
        cs.constraints.begin(), cs.constraints.end(),
        [](const auto& constraint) {
            return constraint.name ==
                "stage3.fixedpoint.bytecode."
                "shard_receipt_local_q";
        });
    if (!has_alias) return Fail(why, "binding_alias_missing");
    return true;
}

ShardTerminalBindingV1 BindingFromReceipt(
    const ShardReceiptV1& receipt)
{
    ShardTerminalBindingV1 out;
    out.shard_index = receipt.shard_index;
    out.program_count = receipt.program_count;
    out.queries = receipt.queries;
    out.original_columns =
        receipt.n_columns >= 2 ? receipt.n_columns - 2 : 0;
    out.layout = ShardTerminalLayoutV1(out.original_columns);
    out.program_commitment = receipt.program_commitment;
    out.bytecode_prechallenge_commitment =
        receipt.bytecode_prechallenge_commitment;
    out.statement_commitment = receipt.statement_commitment;
    out.query_indices = receipt.query_indices;
    out.local_q_per_query = receipt.local_q_per_query;
    out.canonical_quotient_rows = true;
    out.expected_q_preprocessed = true;
    out.query_indices_preprocessed = true;
    out.q_terminal_equality_constrained = true;
    out.valid = true;
    return out;
}

uint32_t NextPow2Local(uint32_t n)
{
    uint32_t out = 1;
    while (out < n) {
        if (out > (std::numeric_limits<uint32_t>::max() >> 1)) {
            return 0;
        }
        out <<= 1;
    }
    return out;
}

/** Eight LE-u32 limbs of a uint256 as Fp3 cells. */
std::array<gf::Fp3, 8> Uint256ToLimbCells(const uint256& value)
{
    std::array<gf::Fp3, 8> out{};
    for (uint32_t limb = 0; limb < 8; ++limb) {
        const uint32_t word =
            static_cast<uint32_t>(value.begin()[4U * limb]) |
            (static_cast<uint32_t>(
                 value.begin()[4U * limb + 1])
             << 8) |
            (static_cast<uint32_t>(
                 value.begin()[4U * limb + 2])
             << 16) |
            (static_cast<uint32_t>(
                 value.begin()[4U * limb + 3])
             << 24);
        out[limb] = gf::Fp3::FromFp(gf::FromU64(word));
    }
    return out;
}

bool BuildBooleanCompanionChild(
    unsigned char seed_tag,
    aq::AirConstraintSystem<gf::Fp3>& out_cs,
    fp::AlgAirProof& out_proof,
    uint256& out_seed)
{
    out_cs = aq::AirConstraintSystem<gf::Fp3>{};
    out_cs.n_rows = 2;
    out_cs.n_columns = 1;
    aq::AirConstraint<gf::Fp3> boolean;
    boolean.name =
        "stage3.recursive_receipt.q_join_parent_companion";
    boolean.kind = aq::AirKind::kEverywhere;
    boolean.alg_degree = 2;
    boolean.eval =
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>&) {
            return gf::Mul(
                cur[0],
                gf::Sub(cur[0], gf::Fp3::One()));
        };
    out_cs.constraints.push_back(std::move(boolean));

    HashWriter seed_hash;
    seed_hash <<
        "BTX_RC_STAGE3_RECEIPT_Q_JOIN_PARENT_COMPANION_V1";
    seed_hash << seed_tag;
    out_seed = seed_hash.GetHash();

    std::vector<std::vector<gf::Fp3>> columns(
        1, std::vector<gf::Fp3>(2, gf::Fp3::Zero()));
    columns[0][1] = gf::Fp3::One();
    const auto proved =
        aq::AirQuotientProve<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            out_cs, columns, out_seed, {});
    if (!proved.ok || !proved.division_exact) {
        return false;
    }
    out_proof = proved.proof;
    return true;
}

struct RetainedQuotientJoinAir {
    bool valid{false};
    aq::AirConstraintSystem<gf::Fp3> cs;
    fp::AlgAirProof proof;
    uint256 seed{};
    uint32_t n_rows{0};
    uint32_t n_columns{0};
    std::string note;
};

RetainedQuotientJoinAir ProveRetainedQuotientJoinAir(
    const std::vector<gf::Fp3>& bound_q_per_query,
    const std::vector<std::vector<gf::Fp3>>& shard_local_q,
    bool absolute_parent_bound)
{
    RetainedQuotientJoinAir out;
    if (bound_q_per_query.empty() ||
        shard_local_q.size() < 2) {
        out.note = "retained_q_join_input";
        return out;
    }
    const uint32_t queries =
        static_cast<uint32_t>(bound_q_per_query.size());
    for (const auto& shard : shard_local_q) {
        if (shard.size() != queries) {
            out.note = "retained_q_join_query_mismatch";
            return out;
        }
    }
    for (uint32_t q = 0; q < queries; ++q) {
        gf::Fp3 sum = gf::Fp3::Zero();
        for (const auto& shard : shard_local_q) {
            sum = gf::Add(sum, shard[q]);
        }
        if (!gf::IsZero(
                gf::Sub(sum, bound_q_per_query[q]))) {
            out.note = "retained_q_join_bound_mismatch";
            return out;
        }
    }
    const uint32_t n_rows = NextPow2Local(queries);
    const uint32_t n_columns =
        1U + static_cast<uint32_t>(shard_local_q.size());
    if (n_rows < 2 || n_columns < 3) {
        out.note = "retained_q_join_shape";
        return out;
    }
    out.n_rows = n_rows;
    out.n_columns = n_columns;
    out.cs.n_rows = n_rows;
    out.cs.n_columns = n_columns;
    const uint32_t shard_count =
        static_cast<uint32_t>(shard_local_q.size());
    out.cs.constraints.push_back(
        {"stage3.recursive_receipt.retained_q_join_sum_eq",
         aq::AirKind::kEverywhere,
         /*alg_degree=*/1,
         [shard_count](
             const std::vector<gf::Fp3>& cur,
             const std::vector<gf::Fp3>&) {
             gf::Fp3 sum = gf::Fp3::Zero();
             for (uint32_t s = 0; s < shard_count; ++s) {
                 sum = gf::Add(sum, cur[1U + s]);
             }
             return gf::Sub(sum, cur[0]);
         }});
    std::vector<std::vector<gf::Fp3>> columns(
        n_columns,
        std::vector<gf::Fp3>(n_rows, gf::Fp3::Zero()));
    for (uint32_t q = 0; q < queries; ++q) {
        columns[0][q] = bound_q_per_query[q];
        for (uint32_t s = 0; s < shard_count; ++s) {
            columns[1U + s][q] = shard_local_q[s][q];
        }
    }
    HashWriter seed_hash;
    seed_hash <<
        "BTX_RC_STAGE3_RECEIPT_RETAINED_Q_JOIN_AIR_V1";
    seed_hash << queries;
    seed_hash << shard_count;
    seed_hash << n_rows;
    seed_hash << static_cast<uint8_t>(
        absolute_parent_bound ? 1 : 0);
    for (uint32_t q = 0; q < queries; ++q) {
        seed_hash << gf::Canonical(
            bound_q_per_query[q].c0);
        seed_hash << gf::Canonical(
            bound_q_per_query[q].c1);
        seed_hash << gf::Canonical(
            bound_q_per_query[q].c2);
    }
    out.seed = seed_hash.GetHash();
    const auto proved =
        aq::AirQuotientProve<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            out.cs, columns, out.seed, {});
    if (!proved.ok || !proved.division_exact) {
        out.note = "retained_q_join_prove:" + proved.note;
        return out;
    }
    out.proof = proved.proof;
    out.valid = true;
    out.note = "retained_q_join_ok";
    return out;
}

} // namespace

uint256 ComputeShardTerminalStatementCommitmentV1(
    const ShardTerminalBindingV1& binding,
    uint32_t n_rows,
    uint32_t n_columns,
    uint32_t n_constraints)
{
    if (binding.version != kShardReceiptVersionV1 ||
        binding.queries == 0 ||
        binding.query_indices.size() != binding.queries ||
        binding.local_q_per_query.size() != binding.queries ||
        binding.program_commitment.IsNull() ||
        binding.bytecode_prechallenge_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << "BTX_RC_STAGE3_SHARD_TERMINAL_STATEMENT_V1";
    hash << binding.version;
    hash << binding.shard_index;
    hash << binding.program_count;
    hash << binding.queries;
    hash << binding.original_columns;
    hash << binding.layout.expected_local_q;
    hash << binding.layout.query_index;
    hash << n_rows;
    hash << n_columns;
    hash << n_constraints;
    hash << binding.program_commitment;
    hash << binding.bytecode_prechallenge_commitment;
    for (uint32_t query = 0; query < binding.queries; ++query) {
        hash << binding.query_indices[query];
        hash << gf::Canonical(
            binding.local_q_per_query[query].c0);
        hash << gf::Canonical(
            binding.local_q_per_query[query].c1);
        hash << gf::Canonical(
            binding.local_q_per_query[query].c2);
    }
    return hash.GetHash();
}

uint256 ComputeShardReceiptFsSeedV1(
    const ShardTerminalBindingV1& binding,
    uint32_t n_rows,
    uint32_t n_columns,
    uint32_t n_constraints)
{
    const uint256 statement =
        ComputeShardTerminalStatementCommitmentV1(
            binding, n_rows, n_columns, n_constraints);
    if (statement.IsNull()) return {};
    HashWriter hash;
    hash << "BTX_RC_STAGE3_SHARD_RECEIPT_FS_V1";
    hash << statement;
    hash << binding.bytecode_prechallenge_commitment;
    hash << binding.program_commitment;
    hash << n_rows;
    hash << n_columns;
    hash << n_constraints;
    return hash.GetHash();
}

uint256 ComputeShardReceiptRootV1(
    const ShardReceiptV1& receipt)
{
    if (receipt.version != kShardReceiptVersionV1 ||
        receipt.queries == 0 ||
        receipt.query_indices.size() != receipt.queries ||
        receipt.local_q_per_query.size() != receipt.queries ||
        receipt.program_commitment.IsNull() ||
        receipt.bytecode_prechallenge_commitment.IsNull() ||
        receipt.statement_commitment.IsNull() ||
        receipt.fs_seed.IsNull() ||
        receipt.proof_commitment.IsNull() ||
        receipt.proof_bytes.empty()) {
        return {};
    }
    HashWriter hash;
    hash << "BTX_RC_STAGE3_SHARD_RECEIPT_ROOT_V1";
    hash << receipt.version;
    hash << receipt.shard_index;
    hash << receipt.program_count;
    hash << receipt.queries;
    hash << receipt.n_rows;
    hash << receipt.n_columns;
    hash << receipt.n_constraints;
    hash << receipt.program_commitment;
    hash << receipt.bytecode_prechallenge_commitment;
    hash << receipt.statement_commitment;
    hash << receipt.fs_seed;
    hash << receipt.proof_commitment;
    for (uint32_t query = 0; query < receipt.queries; ++query) {
        hash << receipt.query_indices[query];
        hash << gf::Canonical(
            receipt.local_q_per_query[query].c0);
        hash << gf::Canonical(
            receipt.local_q_per_query[query].c1);
        hash << gf::Canonical(
            receipt.local_q_per_query[query].c2);
    }
    return hash.GetHash();
}

uint256 ComputeOrderedShardReceiptSetRootV1(
    const std::vector<ShardReceiptV1>& receipts)
{
    if (receipts.size() < 2 ||
        receipts.size() >
            std::numeric_limits<uint32_t>::max()) {
        return {};
    }
    HashWriter hash;
    hash << "BTX_RC_STAGE3_ORDERED_SHARD_RECEIPT_SET_V1";
    hash << kShardReceiptVersionV1;
    hash << static_cast<uint32_t>(receipts.size());
    uint32_t previous_shard = 0;
    bool have_previous = false;
    for (const ShardReceiptV1& receipt : receipts) {
        const uint256 root =
            ComputeShardReceiptRootV1(receipt);
        if (root.IsNull() ||
            receipt.receipt_root != root ||
            (have_previous &&
             receipt.shard_index <= previous_shard)) {
            return {};
        }
        hash << receipt.shard_index;
        hash << receipt.receipt_root;
        hash << receipt.statement_commitment;
        hash << receipt.fs_seed;
        hash << receipt.proof_commitment;
        previous_shard = receipt.shard_index;
        have_previous = true;
    }
    return hash.GetHash();
}

ShardTerminalBindingV1 BindShardLocalQuotientTerminalsV1(
    fp::FoldBusComposition& attached_shard,
    const fp::BytecodeInterpreterAttachment& interpreter,
    uint32_t shard_index)
{
    ShardTerminalBindingV1 out;
    out.shard_index = shard_index;
    out.program_count = static_cast<uint32_t>(
        interpreter.program_table.programs.size());
    if (!attached_shard.valid || !interpreter.valid ||
        !interpreter.quotient_opening_equality ||
        interpreter.program_commitment.IsNull() ||
        interpreter.prechallenge_commitment.IsNull() ||
        attached_shard.columns.size() !=
            attached_shard.combined.n_columns ||
        interpreter.layout.End() !=
            attached_shard.combined.n_columns) {
        out.note =
            "stage3:recursive_receipt:bind_input";
        return out;
    }
    out.queries = static_cast<uint32_t>(
        attached_shard.hash.program.public_inputs
            .query_index.size());
    out.query_indices =
        attached_shard.hash.program.public_inputs.query_index;
    if (out.queries == 0 ||
        interpreter.quotient_rows != out.queries) {
        out.note =
            "stage3:recursive_receipt:bind_query_count";
        return out;
    }
    out.original_columns =
        attached_shard.combined.n_columns;
    out.layout = ShardTerminalLayoutV1(
        out.original_columns);
    out.program_commitment =
        interpreter.program_commitment;
    out.bytecode_prechallenge_commitment =
        interpreter.prechallenge_commitment;

    std::vector<uint32_t> quotient_rows;
    for (uint32_t row = 0;
         row < attached_shard.combined.n_rows; ++row) {
        if (!gf::IsZero(
                attached_shard.columns[
                    interpreter.layout.RowKind(
                        kQuotientRowKindV1)][row])) {
            quotient_rows.push_back(row);
            out.local_q_per_query.push_back(
                attached_shard.columns[
                    interpreter.layout.Value(3)][row]);
        }
    }
    if (quotient_rows.size() != out.queries ||
        out.local_q_per_query.size() != out.queries) {
        out.note =
            "stage3:recursive_receipt:bind_quotient_rows";
        return out;
    }
    out.canonical_quotient_rows = true;

    attached_shard.combined.n_columns = out.layout.End();
    attached_shard.columns.resize(
        out.layout.End(),
        std::vector<gf::Fp3>(
            attached_shard.combined.n_rows,
            gf::Fp3::Zero()));
    for (uint32_t query = 0; query < out.queries; ++query) {
        const uint32_t row = quotient_rows[query];
        attached_shard.columns[
            out.layout.expected_local_q][row] =
            out.local_q_per_query[query];
        attached_shard.columns[
            out.layout.query_index][row] =
            gf::Fp3::FromFp(gf::FromU64(
                out.query_indices[query]));
    }
    attached_shard.combined.preprocessed_pin_ood = true;
    attached_shard.combined.preprocessed.emplace_back(
        out.layout.expected_local_q,
        attached_shard.columns[
            out.layout.expected_local_q]);
    attached_shard.combined.preprocessed.emplace_back(
        out.layout.query_index,
        attached_shard.columns[
            out.layout.query_index]);
    out.expected_q_preprocessed = true;
    out.query_indices_preprocessed = true;

    aq::AirConstraint<gf::Fp3> alias;
    alias.name =
        "stage3.fixedpoint.bytecode.shard_receipt_local_q";
    alias.kind = aq::AirKind::kEverywhere;
    alias.alg_degree = 2;
    alias.eval =
        [bus = interpreter.layout,
         layout = out.layout](
            const std::vector<gf::Fp3>& cur,
            const std::vector<gf::Fp3>&) {
            return gf::Mul(
                cur[bus.RowKind(kQuotientRowKindV1)],
                gf::Sub(
                    cur[bus.Value(3)],
                    cur[layout.expected_local_q]));
        };
    attached_shard.combined.constraints.push_back(
        std::move(alias));
    out.q_terminal_equality_constrained = true;
    out.statement_commitment =
        ComputeShardTerminalStatementCommitmentV1(
            out,
            attached_shard.combined.n_rows,
            attached_shard.combined.n_columns,
            static_cast<uint32_t>(
                attached_shard.combined.constraints.size()));
    if (out.statement_commitment.IsNull()) {
        out.note =
            "stage3:recursive_receipt:bind_statement";
        return out;
    }
    // BindingMatchesConstraintSystem is also the public validation routine and
    // therefore requires the validity bit. Set it only after every field and
    // load-bearing constraint above has been constructed, and clear it again
    // on any self-audit failure.
    out.valid = true;
    std::string why;
    if (!BindingMatchesConstraintSystem(
            attached_shard.combined, out, &why)) {
        out.valid = false;
        out.note = why;
        return out;
    }
    out.note =
        "stage3:recursive_receipt:"
        "local_q_public_terminal_bound";
    return out;
}

ShardReceiptProveResultV1 ProveShardReceiptV1(
    const fp::FoldBusComposition& attached_shard,
    const ShardTerminalBindingV1& binding)
{
    ShardReceiptProveResultV1 out;
    std::string why;
    if (!attached_shard.valid ||
        !BindingMatchesConstraintSystem(
            attached_shard.combined, binding, &why) ||
        binding.statement_commitment !=
            ComputeShardTerminalStatementCommitmentV1(
                binding,
                attached_shard.combined.n_rows,
                attached_shard.combined.n_columns,
                static_cast<uint32_t>(
                    attached_shard.combined.constraints.size()))) {
        out.note = why.empty()
            ? "stage3:recursive_receipt:prove_binding"
            : why;
        return out;
    }
    out.terminal_binding_valid = true;
    const uint256 fs_seed =
        ComputeShardReceiptFsSeedV1(
            binding,
            attached_shard.combined.n_rows,
            attached_shard.combined.n_columns,
            static_cast<uint32_t>(
                attached_shard.combined.constraints.size()));
    if (fs_seed.IsNull()) {
        out.note =
            "stage3:recursive_receipt:prove_seed";
        return out;
    }
    const auto t0 = std::chrono::steady_clock::now();
    auto proved = aq::AirQuotientProveRows(
        attached_shard.combined,
        attached_shard.columns,
        fs_seed, {});
    const auto t1 = std::chrono::steady_clock::now();
    out.prove_micros = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            t1 - t0).count());
    out.proved = proved.ok && proved.division_exact;
    if (!out.proved) {
        out.note =
            "stage3:recursive_receipt:prove:" +
            proved.note;
        return out;
    }
    std::string verify_why;
    const auto t2 = std::chrono::steady_clock::now();
    out.verified = aq::AirQuotientVerifyRows(
        attached_shard.combined,
        proved.proof, fs_seed, &verify_why);
    const auto t3 = std::chrono::steady_clock::now();
    out.verify_micros = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            t3 - t2).count());
    if (!out.verified) {
        out.note =
            "stage3:recursive_receipt:verify:" +
            verify_why;
        return out;
    }

    fp::AlgAirProof proof =
        ToCanonicalAlgProof(std::move(proved.proof));
    ShardReceiptV1 receipt;
    receipt.shard_index = binding.shard_index;
    receipt.program_count = binding.program_count;
    receipt.queries = binding.queries;
    receipt.n_rows = attached_shard.combined.n_rows;
    receipt.n_columns = attached_shard.combined.n_columns;
    receipt.n_constraints = static_cast<uint32_t>(
        attached_shard.combined.constraints.size());
    receipt.program_commitment =
        binding.program_commitment;
    receipt.bytecode_prechallenge_commitment =
        binding.bytecode_prechallenge_commitment;
    receipt.statement_commitment =
        binding.statement_commitment;
    receipt.fs_seed = fs_seed;
    receipt.query_indices = binding.query_indices;
    receipt.local_q_per_query =
        binding.local_q_per_query;
    receipt.proof_commitment =
        fp::ComputeNormalizedAlgAirProofCommitment(proof);
    if (receipt.proof_commitment.IsNull() ||
        !SerializeAirQuotientProofAlg(
            proof, receipt.proof_bytes, &why)) {
        out.note =
            "stage3:recursive_receipt:proof_codec:" + why;
        return out;
    }
    out.proof_retained = true;
    receipt.receipt_root =
        ComputeShardReceiptRootV1(receipt);
    if (receipt.receipt_root.IsNull()) {
        out.note =
            "stage3:recursive_receipt:receipt_root";
        return out;
    }
    out.receipt = std::move(receipt);

    std::vector<unsigned char> encoded;
    out.wire_fits =
        SerializeShardReceiptV1(
            out.receipt, encoded, &why);
    out.encoded_bytes = encoded.size();
    if (!out.wire_fits) {
        out.note =
            "stage3:recursive_receipt:wire:" + why;
        return out;
    }
    const auto decoded =
        DeserializeShardReceiptV1(encoded, &why);
    out.canonical_codec_round_trip =
        decoded.has_value() &&
        decoded->receipt_root == out.receipt.receipt_root &&
        decoded->proof_bytes == out.receipt.proof_bytes;
    if (!out.canonical_codec_round_trip ||
        !VerifyShardReceiptV1(
            attached_shard.combined,
            binding, out.receipt, &why)) {
        out.note =
            "stage3:recursive_receipt:round_trip:" + why;
        return out;
    }

    ShardReceiptV1 forged = out.receipt;
    forged.local_q_per_query[0] =
        gf::Add(
            forged.local_q_per_query[0],
            gf::Fp3::One());
    ShardTerminalBindingV1 forged_binding =
        BindingFromReceipt(forged);
    forged.statement_commitment =
        ComputeShardTerminalStatementCommitmentV1(
            forged_binding,
            forged.n_rows,
            forged.n_columns,
            forged.n_constraints);
    forged_binding.statement_commitment =
        forged.statement_commitment;
    forged.fs_seed =
        ComputeShardReceiptFsSeedV1(
            forged_binding,
            forged.n_rows,
            forged.n_columns,
            forged.n_constraints);
    forged.receipt_root =
        ComputeShardReceiptRootV1(forged);
    out.forgery_rejected =
        !VerifyShardReceiptV1(
            attached_shard.combined,
            forged_binding, forged, nullptr);
    out.valid =
        out.terminal_binding_valid &&
        out.proof_retained &&
        out.proved && out.verified &&
        out.canonical_codec_round_trip &&
        out.wire_fits &&
        out.forgery_rejected;
    out.note =
        std::string(
            "stage3:recursive_receipt:l1_receipt") +
        ";rows=" + std::to_string(out.receipt.n_rows) +
        ";cols=" + std::to_string(out.receipt.n_columns) +
        ";queries=" + std::to_string(out.receipt.queries) +
        ";bytes=" + std::to_string(out.encoded_bytes) +
        ";proved=" + (out.proved ? "1" : "0") +
        ";verified=" + (out.verified ? "1" : "0") +
        ";forgery=" + (out.forgery_rejected ? "1" : "0") +
        ";recursive_consumption=0";
    return out;
}

bool VerifyShardReceiptV1(
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const ShardTerminalBindingV1& expected_binding,
    const ShardReceiptV1& receipt,
    std::string* why)
{
    if (!BindingMatchesConstraintSystem(
            child_cs, expected_binding, why)) {
        return false;
    }
    if (receipt.version != kShardReceiptVersionV1 ||
        receipt.shard_index != expected_binding.shard_index ||
        receipt.program_count != expected_binding.program_count ||
        receipt.queries != expected_binding.queries ||
        receipt.n_rows != child_cs.n_rows ||
        receipt.n_columns != child_cs.n_columns ||
        receipt.n_constraints != child_cs.constraints.size() ||
        receipt.program_commitment !=
            expected_binding.program_commitment ||
        receipt.bytecode_prechallenge_commitment !=
            expected_binding.bytecode_prechallenge_commitment ||
        receipt.query_indices !=
            expected_binding.query_indices ||
        !SameFp3Vectors(
            receipt.local_q_per_query,
            expected_binding.local_q_per_query)) {
        return Fail(why, "receipt_statement_fields");
    }
    const uint256 statement =
        ComputeShardTerminalStatementCommitmentV1(
            expected_binding,
            receipt.n_rows,
            receipt.n_columns,
            receipt.n_constraints);
    const uint256 fs_seed =
        ComputeShardReceiptFsSeedV1(
            expected_binding,
            receipt.n_rows,
            receipt.n_columns,
            receipt.n_constraints);
    if (statement.IsNull() || fs_seed.IsNull() ||
        receipt.statement_commitment != statement ||
        receipt.fs_seed != fs_seed) {
        return Fail(why, "receipt_statement_seed");
    }
    std::string codec_why;
    const auto proof =
        DeserializeAirQuotientProofAlg(
            receipt.proof_bytes, &codec_why);
    if (!proof.has_value()) {
        return Fail(
            why, "receipt_proof_codec:" + codec_why);
    }
    if (receipt.proof_commitment !=
            fp::ComputeNormalizedAlgAirProofCommitment(
                *proof) ||
        receipt.receipt_root !=
            ComputeShardReceiptRootV1(receipt)) {
        return Fail(why, "receipt_commitment");
    }
    std::vector<unsigned char> encoded;
    if (!SerializeShardReceiptV1(
            receipt, encoded, &codec_why) ||
        encoded.size() > kRCStage3MaxProofBytes) {
        return Fail(
            why, "receipt_wire:" + codec_why);
    }
    std::string verify_why;
    if (!aq::AirQuotientVerify<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            child_cs, *proof, receipt.fs_seed,
            &verify_why)) {
        return Fail(
            why, "receipt_child_verify:" + verify_why);
    }
    return true;
}

ShardReceiptOwnershipAuditV1
AssessShardReceiptOwnershipV1(
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const ShardTerminalBindingV1& expected_binding,
    const ShardReceiptV1& receipt)
{
    ShardReceiptOwnershipAuditV1 out;
    std::string why;
    out.canonical_receipt =
        receipt.version == kShardReceiptVersionV1 &&
        receipt.receipt_root ==
            ComputeShardReceiptRootV1(receipt);
    out.local_q_public_statement_bound =
        BindingMatchesConstraintSystem(
            child_cs, expected_binding, nullptr) &&
        receipt.statement_commitment ==
            expected_binding.statement_commitment &&
        SameFp3Vectors(
            receipt.local_q_per_query,
            expected_binding.local_q_per_query);
    out.program_and_query_identity_bound =
        receipt.program_commitment ==
            expected_binding.program_commitment &&
        receipt.query_indices ==
            expected_binding.query_indices &&
        receipt.shard_index ==
            expected_binding.shard_index;
    out.receipt_root_recomputed =
        !receipt.receipt_root.IsNull() &&
        receipt.receipt_root ==
            ComputeShardReceiptRootV1(receipt);
    std::vector<unsigned char> encoded;
    out.wire_fits =
        SerializeShardReceiptV1(
            receipt, encoded, nullptr) &&
        encoded.size() <= kRCStage3MaxProofBytes;
    out.native_child_proof_verified =
        VerifyShardReceiptV1(
            child_cs, expected_binding,
            receipt, &why);
    out.recursively_consumed_by_parent = false;
    if (!out.recursively_consumed_by_parent) {
        out.residuals.push_back(
            "l2_parent_does_not_yet_consume_receipt_proof_"
            "and_public_terminal_cells");
    }
    out.valid =
        out.canonical_receipt &&
        out.native_child_proof_verified &&
        out.local_q_public_statement_bound &&
        out.program_and_query_identity_bound &&
        out.receipt_root_recomputed &&
        out.wire_fits &&
        !out.recursively_consumed_by_parent;
    out.note =
        out.valid
        ? "stage3:recursive_receipt:"
          "l1_ownership_closed_l2_consumption_open"
        : "stage3:recursive_receipt:ownership_audit_failed:" +
              why;
    return out;
}

OrderedReceiptSetRootParentAirPinV1
PinOrderedReceiptSetRootParentAirV1(
    const uint256& ordered_receipt_set_root)
{
    OrderedReceiptSetRootParentAirPinV1 out;
    out.ordered_receipt_set_root = ordered_receipt_set_root;
    if (ordered_receipt_set_root.IsNull()) {
        out.note =
            "stage3:recursive_receipt:ordered_root_pin_null";
        return out;
    }
    constexpr uint32_t kLimbs = 8;
    constexpr uint32_t kExpectedCol = 0;
    constexpr uint32_t kClaimedCol = 1;
    out.n_rows = kLimbs;
    out.n_columns = 2;
    const auto limbs =
        Uint256ToLimbCells(ordered_receipt_set_root);

    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = kLimbs;
    cs.n_columns = 2;
    cs.preprocessed_pin_ood = true;
    std::vector<gf::Fp3> expected_col(kLimbs, gf::Fp3::Zero());
    for (uint32_t i = 0; i < kLimbs; ++i) {
        expected_col[i] = limbs[i];
    }
    cs.preprocessed.emplace_back(kExpectedCol, expected_col);

    aq::AirConstraint<gf::Fp3> equality;
    equality.name =
        "stage3.recursive_receipt.ordered_receipt_set_root_eq";
    equality.kind = aq::AirKind::kEverywhere;
    equality.alg_degree = 1;
    equality.eval =
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>&) {
            return gf::Sub(cur[kClaimedCol], cur[kExpectedCol]);
        };
    cs.constraints.push_back(std::move(equality));
    out.public_cells_installed = true;
    out.equality_constrained = true;

    std::vector<std::vector<gf::Fp3>> columns(
        2, std::vector<gf::Fp3>(kLimbs, gf::Fp3::Zero()));
    for (uint32_t i = 0; i < kLimbs; ++i) {
        columns[kExpectedCol][i] = limbs[i];
        columns[kClaimedCol][i] = limbs[i];
    }

    HashWriter seed_hash;
    seed_hash <<
        "BTX_RC_STAGE3_ORDERED_RECEIPT_SET_ROOT_PARENT_AIR_V1";
    seed_hash << ordered_receipt_set_root;
    seed_hash << kLimbs;
    const uint256 seed = seed_hash.GetHash();

    const auto proved =
        aq::AirQuotientProve<gf::Fp3>(cs, columns, seed);
    out.proved = proved.ok && proved.division_exact;
    if (!out.proved) {
        out.note =
            "stage3:recursive_receipt:ordered_root_pin_prove:" +
            proved.note;
        return out;
    }
    std::string verify_why;
    out.verified = aq::AirQuotientVerify<gf::Fp3>(
        cs, proved.proof, seed, &verify_why);
    if (!out.verified) {
        out.note =
            "stage3:recursive_receipt:ordered_root_pin_verify:" +
            verify_why;
        return out;
    }

    auto forged = columns;
    forged[kClaimedCol][0] =
        gf::Add(forged[kClaimedCol][0], gf::Fp3::One());
    const auto forged_proved =
        aq::AirQuotientProve<gf::Fp3>(cs, forged, seed);
    const bool forged_ok =
        forged_proved.ok && forged_proved.division_exact;
    bool forged_verified = false;
    if (forged_ok) {
        std::string forged_why;
        forged_verified = aq::AirQuotientVerify<gf::Fp3>(
            cs, forged_proved.proof, seed, &forged_why);
    }
    out.forgery_rejected = !forged_ok || !forged_verified;
    out.valid =
        out.public_cells_installed &&
        out.equality_constrained &&
        out.proved && out.verified && out.forgery_rejected;
    out.note =
        out.valid
            ? (std::string(
                   "stage3:recursive_receipt:"
                   "ordered_receipt_set_root_parent_air_pin") +
               ";rows=" + std::to_string(out.n_rows) +
               ";cols=" + std::to_string(out.n_columns) +
               ";proved=1;verified=1;forgery=1")
            : "stage3:recursive_receipt:ordered_root_pin_failed";
    return out;
}

ReceiptOwnedQuotientJoinParentConsumeV1
ConsumeReceiptOwnedQuotientJoinAsNormalizedParentChildV1(
    const std::vector<gf::Fp3>& bound_q_per_query,
    const std::vector<std::vector<gf::Fp3>>& shard_local_q,
    bool absolute_parent_bound,
    bool prove)
{
    ReceiptOwnedQuotientJoinParentConsumeV1 out;
    const RetainedQuotientJoinAir retained =
        ProveRetainedQuotientJoinAir(
            bound_q_per_query, shard_local_q,
            absolute_parent_bound);
    out.join_air_proof_retained = retained.valid;
    out.join_n_rows = retained.n_rows;
    out.join_n_columns = retained.n_columns;
    if (!retained.valid) {
        out.note =
            "stage3:recursive_receipt:q_join_parent_retain:" +
            retained.note;
        return out;
    }

    aq::AirConstraintSystem<gf::Fp3> companion_cs;
    fp::AlgAirProof companion_proof;
    uint256 companion_seed;
    out.companion_child_built = BuildBooleanCompanionChild(
        /*seed_tag=*/0x71, companion_cs, companion_proof,
        companion_seed);
    if (!out.companion_child_built) {
        out.note =
            "stage3:recursive_receipt:q_join_parent_companion";
        return out;
    }

    const std::vector<aq::AirConstraintSystem<gf::Fp3>>
        child_css{retained.cs, companion_cs};
    const std::vector<fp::AlgAirProof> children{
        retained.proof, companion_proof};
    const std::vector<uint256> seeds{
        retained.seed, companion_seed};
    out.parent = fp::ExecuteNarrowMultiChildL2FriConsumeV1(
        child_css, children, seeds, prove);
    out.parent_fold_bus_built = out.parent.fold_bus_built;
    out.forgery_rejected = out.parent.forgery_rejected;
    out.cryptographically_consumed =
        out.parent.valid && out.parent.fold_bus_built &&
        out.parent.forgery_rejected &&
        (!prove || (out.parent.proved && out.parent.verified));
    out.valid =
        out.join_air_proof_retained &&
        out.companion_child_built &&
        out.cryptographically_consumed;
    out.note =
        out.valid
            ? (std::string(
                   "stage3:recursive_receipt:"
                   "q_join_normalized_parent_child") +
               ";join_rows=" +
               std::to_string(out.join_n_rows) +
               ";join_cols=" +
               std::to_string(out.join_n_columns) +
               ";parent_arity=" +
               std::to_string(out.parent.arity) +
               ";fold=1;forgery=1" +
               (prove ? ";prove=1" : ";prove=0"))
            : ("stage3:recursive_receipt:"
               "q_join_parent_consume_failed:" +
               out.parent.note);
    return out;
}

ShardReceiptL2ConsumeV1
ConsumeShardReceiptsL2V1(
    const std::vector<
        aq::AirConstraintSystem<gf::Fp3>>& child_css,
    const std::vector<ShardTerminalBindingV1>& bindings,
    const std::vector<ShardReceiptV1>& receipts,
    bool prove)
{
    ShardReceiptL2ConsumeV1 out;
    out.arity = static_cast<uint32_t>(receipts.size());
    if (receipts.size() < 2 ||
        child_css.size() != receipts.size() ||
        bindings.size() != receipts.size()) {
        out.note =
            "stage3:recursive_receipt:l2_arity";
        return out;
    }

    out.ordered_receipt_set_root =
        ComputeOrderedShardReceiptSetRootV1(receipts);
    out.canonical_shard_order =
        !out.ordered_receipt_set_root.IsNull();
    if (!out.canonical_shard_order) {
        out.note =
            "stage3:recursive_receipt:l2_order";
        return out;
    }

    out.unique_receipt_roots = true;
    out.common_query_schedule = true;
    out.local_q_cells_child_air_bound = true;
    std::vector<fp::AlgAirProof> child_proofs;
    std::vector<uint256> child_seeds;
    child_proofs.reserve(receipts.size());
    child_seeds.reserve(receipts.size());
    for (size_t index = 0;
         index < receipts.size(); ++index) {
        std::string why;
        if (!VerifyShardReceiptV1(
                child_css[index], bindings[index],
                receipts[index], &why)) {
            out.note =
                "stage3:recursive_receipt:l2_child[" +
                std::to_string(index) + "]:" + why;
            return out;
        }
        if (!BindingMatchesConstraintSystem(
                child_css[index], bindings[index],
                nullptr)) {
            out.local_q_cells_child_air_bound = false;
        }
        for (size_t prior = 0; prior < index; ++prior) {
            if (receipts[prior].receipt_root ==
                receipts[index].receipt_root) {
                out.unique_receipt_roots = false;
            }
        }
        if (index > 0) {
            if (receipts[index].query_indices !=
                receipts[0].query_indices) {
                out.common_query_schedule = false;
            }
        }
        std::vector<unsigned char> encoded;
        if (!SerializeShardReceiptV1(
                receipts[index], encoded, &why) ||
            encoded.size() >
                std::numeric_limits<uint64_t>::max() -
                    out.encoded_child_bytes) {
            out.note =
                "stage3:recursive_receipt:l2_wire[" +
                std::to_string(index) + "]:" + why;
            return out;
        }
        out.encoded_child_bytes += encoded.size();
        const auto proof =
            DeserializeAirQuotientProofAlg(
                receipts[index].proof_bytes, &why);
        if (!proof.has_value()) {
            out.note =
                "stage3:recursive_receipt:l2_codec[" +
                std::to_string(index) + "]:" + why;
            return out;
        }
        child_proofs.push_back(*proof);
        child_seeds.push_back(receipts[index].fs_seed);
    }
    out.receipts_verified = true;
    out.child_prechallenges_bound = true;
    out.child_proofs_decoded =
        child_proofs.size() == receipts.size();
    if (!out.unique_receipt_roots ||
        !out.common_query_schedule ||
        !out.child_prechallenges_bound ||
        !out.local_q_cells_child_air_bound ||
        !out.child_proofs_decoded) {
        out.note =
            "stage3:recursive_receipt:l2_identity";
        return out;
    }

    out.l2 = fp::ExecuteNarrowMultiChildL2FriConsumeV1(
        child_css, child_proofs, child_seeds, prove);
    out.child_proofs_cryptographically_consumed =
        out.l2.valid && out.l2.fold_bus_built &&
        out.l2.forgery_rejected &&
        (!prove || (out.l2.proved && out.l2.verified));

    std::vector<ShardReceiptV1> reordered = receipts;
    std::reverse(reordered.begin(), reordered.end());
    out.reordered_receipts_rejected =
        ComputeOrderedShardReceiptSetRootV1(
            reordered).IsNull();

    // Residual 1: equality-constrain the ordered receipt-set root as a
    // parent-AIR public cell. Residual 2 (q-join recursive consume) is
    // closed on ShardReceiptQuotientJoinV1, not on this L2 consume type.
    out.ordered_root_pin =
        PinOrderedReceiptSetRootParentAirV1(
            out.ordered_receipt_set_root);
    out.ordered_receipt_root_parent_air_bound =
        out.ordered_root_pin.valid &&
        out.ordered_root_pin.public_cells_installed &&
        out.ordered_root_pin.equality_constrained &&
        out.ordered_root_pin.proved &&
        out.ordered_root_pin.verified &&
        out.ordered_root_pin.forgery_rejected;
    out.full_parent_q_join_recursively_consumed = false;
    if (!out.ordered_receipt_root_parent_air_bound) {
        out.residuals.push_back(
            "ordered_receipt_set_root_not_equality_constrained_"
            "to_parent_air_public_cell");
    }
    out.residuals.push_back(
        "receipt_owned_full_parent_q_join_not_recursively_"
        "consumed_on_l2_consume_type_see_quotient_join");
    out.valid =
        out.receipts_verified &&
        out.canonical_shard_order &&
        out.unique_receipt_roots &&
        out.common_query_schedule &&
        out.child_prechallenges_bound &&
        out.child_proofs_decoded &&
        out.child_proofs_cryptographically_consumed &&
        out.local_q_cells_child_air_bound &&
        out.reordered_receipts_rejected &&
        out.ordered_receipt_root_parent_air_bound &&
        !out.full_parent_q_join_recursively_consumed;
    out.note =
        out.valid
            ? (std::string(
                   "stage3:recursive_receipt:"
                   "l1_receipts_consumed_by_l2") +
               ";arity=" + std::to_string(out.arity) +
               ";child_bytes=" +
               std::to_string(out.encoded_child_bytes) +
               ";fold=1;forgery=1" +
               (prove
                    ? ";parent_proved=1;parent_verified=1"
                    : ";parent_prove=0") +
               ";parent_receipt_root_pin=1")
            : "stage3:recursive_receipt:"
              "l2_consume_failed:" +
                  (out.ordered_receipt_root_parent_air_bound
                       ? out.l2.note
                       : out.ordered_root_pin.note);
    return out;
}

ShardReceiptQuotientJoinV1
JoinShardReceiptLocalQuotientsV1(
    const fp::FoldBusComposition& authenticated_parent,
    uint32_t parent_current_width,
    uint32_t programs_total,
    const std::vector<
        aq::AirConstraintSystem<gf::Fp3>>& child_css,
    const std::vector<ShardTerminalBindingV1>& bindings,
    const std::vector<ShardReceiptV1>& receipts)
{
    ShardReceiptQuotientJoinV1 out;
    out.shard_count =
        static_cast<uint32_t>(receipts.size());
    if (receipts.size() < 2 ||
        child_css.size() != receipts.size() ||
        bindings.size() != receipts.size() ||
        parent_current_width == 0 ||
        programs_total == 0) {
        out.note =
            "stage3:recursive_receipt:q_join_arity";
        return out;
    }
    std::vector<gf::Fp3> authenticated_parent_q;
    std::string parent_why;
    if (!fp::ExtractAuthenticatedParentQuotientOpenings(
            authenticated_parent, parent_current_width,
            authenticated_parent_q, &parent_why)) {
        out.note =
            "stage3:recursive_receipt:q_join_parent:" +
            parent_why;
        return out;
    }
    out.authenticated_parent_q_extracted = true;
    out.queries = static_cast<uint32_t>(
        authenticated_parent_q.size());
    out.ordered_receipt_set_root =
        ComputeOrderedShardReceiptSetRootV1(receipts);
    out.canonical_shard_order =
        !out.ordered_receipt_set_root.IsNull();
    if (!out.canonical_shard_order) {
        out.note =
            "stage3:recursive_receipt:q_join_order";
        return out;
    }

    std::vector<std::vector<gf::Fp3>>
        receipt_local_q;
    receipt_local_q.reserve(receipts.size());
    out.common_query_schedule = true;
    uint32_t programs_covered = 0;
    for (size_t index = 0;
         index < receipts.size(); ++index) {
        std::string why;
        if (!VerifyShardReceiptV1(
                child_css[index], bindings[index],
                receipts[index], &why)) {
            out.note =
                "stage3:recursive_receipt:q_join_child[" +
                std::to_string(index) + "]:" + why;
            return out;
        }
        if (receipts[index].queries !=
                out.queries ||
            receipts[index].query_indices !=
                authenticated_parent.hash.program
                    .public_inputs.query_index ||
            (index > 0 &&
             receipts[index].query_indices !=
                 receipts[0].query_indices)) {
            out.common_query_schedule = false;
            out.note =
                "stage3:recursive_receipt:"
                "q_join_query_schedule";
            return out;
        }
        if (receipts[index].program_count >
            std::numeric_limits<uint32_t>::max() -
                programs_covered) {
            out.note =
                "stage3:recursive_receipt:"
                "q_join_program_overflow";
            return out;
        }
        programs_covered +=
            receipts[index].program_count;
        receipt_local_q.push_back(
            receipts[index].local_q_per_query);
    }
    out.receipts_verified = true;
    out.program_partition_full =
        programs_covered == programs_total;
    if (!out.program_partition_full) {
        out.note =
            "stage3:recursive_receipt:"
            "q_join_program_partition";
        return out;
    }
    const auto joined =
        fp::JoinNarrowBytecodeShardLocalQuotientsV1(
            authenticated_parent_q, receipt_local_q,
            programs_covered, programs_total);
    out.parent_q_absolute =
        joined.valid &&
        joined.covers_full_table &&
        joined.parent_extracted &&
        joined.sum_equals_parent;
    out.air_join = joined.air_mirror;
    out.air_join_proved =
        joined.air_mirrored &&
        out.air_join.valid && out.air_join.proved;
    out.air_join_verified =
        out.air_join.valid && out.air_join.verified;
    out.air_join_forgery_rejected =
        out.air_join.valid &&
        out.air_join.forgery_rejected;

    // Residual 2: retained join AIR proof becomes a recursively consumed
    // normalized-parent child (companion boolean for arity≥2 fold-bus).
    if (out.air_join_proved && out.air_join_verified &&
        out.air_join_forgery_rejected &&
        out.parent_q_absolute) {
        out.parent_consume =
            ConsumeReceiptOwnedQuotientJoinAsNormalizedParentChildV1(
                authenticated_parent_q,
                receipt_local_q,
                /*absolute_parent_bound=*/true,
                /*prove=*/false);
        out.recursively_consumed_by_parent =
            out.parent_consume.valid &&
            out.parent_consume.cryptographically_consumed;
    } else {
        out.recursively_consumed_by_parent = false;
    }
    if (!out.recursively_consumed_by_parent) {
        out.residuals.push_back(
            "receipt_owned_q_join_proof_not_yet_a_child_of_"
            "normalized_parent");
    }
    out.valid =
        out.receipts_verified &&
        out.canonical_shard_order &&
        out.common_query_schedule &&
        out.authenticated_parent_q_extracted &&
        out.program_partition_full &&
        out.parent_q_absolute &&
        out.air_join_proved &&
        out.air_join_verified &&
        out.air_join_forgery_rejected &&
        out.recursively_consumed_by_parent;
    out.note =
        out.valid
            ? (std::string(
                   "stage3:recursive_receipt:"
                   "receipt_owned_q_join") +
               ";shards=" +
               std::to_string(out.shard_count) +
               ";queries=" +
               std::to_string(out.queries) +
               ";proved=1;verified=1;forgery=1;"
               "recursive_consumption=1")
            : "stage3:recursive_receipt:"
              "q_join_failed:" +
                  (out.air_join_proved
                       ? out.parent_consume.note
                       : out.air_join.note);
    return out;
}

bool SerializeShardReceiptV1(
    const ShardReceiptV1& receipt,
    std::vector<unsigned char>& out,
    std::string* why)
{
    out.clear();
    if (receipt.version != kShardReceiptVersionV1 ||
        receipt.queries == 0 ||
        receipt.query_indices.size() != receipt.queries ||
        receipt.local_q_per_query.size() != receipt.queries ||
        receipt.proof_bytes.empty() ||
        receipt.proof_bytes.size() >
            std::numeric_limits<uint32_t>::max() ||
        receipt.receipt_root.IsNull() ||
        receipt.receipt_root !=
            ComputeShardReceiptRootV1(receipt)) {
        return Fail(why, "serialize_shape");
    }
    WriteU32(out, kShardReceiptMagicV1);
    WriteU16(out, receipt.version);
    WriteU16(out, 0);
    WriteU32(out, receipt.shard_index);
    WriteU32(out, receipt.program_count);
    WriteU32(out, receipt.queries);
    WriteU32(out, receipt.n_rows);
    WriteU32(out, receipt.n_columns);
    WriteU32(out, receipt.n_constraints);
    WriteHash(out, receipt.program_commitment);
    WriteHash(
        out, receipt.bytecode_prechallenge_commitment);
    WriteHash(out, receipt.statement_commitment);
    WriteHash(out, receipt.fs_seed);
    WriteHash(out, receipt.proof_commitment);
    WriteHash(out, receipt.receipt_root);
    for (uint32_t value : receipt.query_indices) {
        WriteU32(out, value);
    }
    for (const gf::Fp3& value :
         receipt.local_q_per_query) {
        WriteU64(out, gf::Canonical(value.c0));
        WriteU64(out, gf::Canonical(value.c1));
        WriteU64(out, gf::Canonical(value.c2));
    }
    WriteU32(
        out, static_cast<uint32_t>(
                 receipt.proof_bytes.size()));
    out.insert(
        out.end(),
        receipt.proof_bytes.begin(),
        receipt.proof_bytes.end());
    if (out.size() > kRCStage3MaxProofBytes) {
        out.clear();
        return Fail(why, "serialize_oversize");
    }
    return true;
}

std::optional<ShardReceiptV1>
DeserializeShardReceiptV1(
    const std::vector<unsigned char>& bytes,
    std::string* why)
{
    if (bytes.empty() ||
        bytes.size() > kRCStage3MaxProofBytes) {
        Fail(why, "deserialize_size");
        return std::nullopt;
    }
    Reader reader(bytes);
    uint32_t magic = 0;
    uint16_t reserved = 0;
    ShardReceiptV1 out;
    if (!reader.U32(magic) ||
        !reader.U16(out.version) ||
        !reader.U16(reserved) ||
        magic != kShardReceiptMagicV1 ||
        out.version != kShardReceiptVersionV1 ||
        reserved != 0 ||
        !reader.U32(out.shard_index) ||
        !reader.U32(out.program_count) ||
        !reader.U32(out.queries) ||
        !reader.U32(out.n_rows) ||
        !reader.U32(out.n_columns) ||
        !reader.U32(out.n_constraints) ||
        out.queries == 0 ||
        out.queries > kRCFri3AlgNumQueries ||
        !reader.Hash(out.program_commitment) ||
        !reader.Hash(
            out.bytecode_prechallenge_commitment) ||
        !reader.Hash(out.statement_commitment) ||
        !reader.Hash(out.fs_seed) ||
        !reader.Hash(out.proof_commitment) ||
        !reader.Hash(out.receipt_root)) {
        Fail(why, "deserialize_header");
        return std::nullopt;
    }
    out.query_indices.resize(out.queries);
    for (uint32_t& value : out.query_indices) {
        if (!reader.U32(value)) {
            Fail(why, "deserialize_query_indices");
            return std::nullopt;
        }
    }
    out.local_q_per_query.resize(out.queries);
    for (gf::Fp3& value : out.local_q_per_query) {
        uint64_t c0 = 0;
        uint64_t c1 = 0;
        uint64_t c2 = 0;
        if (!reader.U64(c0) ||
            !reader.U64(c1) ||
            !reader.U64(c2) ||
            c0 >= gf::kP ||
            c1 >= gf::kP ||
            c2 >= gf::kP) {
            Fail(why, "deserialize_noncanonical_fp3");
            return std::nullopt;
        }
        value = gf::Fp3{c0, c1, c2};
    }
    uint32_t proof_size = 0;
    if (!reader.U32(proof_size) ||
        proof_size == 0 ||
        proof_size > reader.Remaining() ||
        !reader.Bytes(proof_size, out.proof_bytes) ||
        reader.Remaining() != 0 ||
        out.receipt_root.IsNull() ||
        out.receipt_root != ComputeShardReceiptRootV1(out)) {
        Fail(why, "deserialize_proof_or_root");
        return std::nullopt;
    }
    std::string proof_why;
    if (!DeserializeAirQuotientProofAlg(
            out.proof_bytes, &proof_why).has_value()) {
        Fail(
            why, "deserialize_proof_codec:" + proof_why);
        return std::nullopt;
    }
    std::vector<unsigned char> canonical;
    if (!SerializeShardReceiptV1(
            out, canonical, why) ||
        canonical != bytes) {
        Fail(why, "deserialize_noncanonical");
        return std::nullopt;
    }
    return out;
}

} // namespace matmul::v4::rc::recursive_receipt
