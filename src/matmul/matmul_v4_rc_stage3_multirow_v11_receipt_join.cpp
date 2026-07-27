// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_receipt_join.h>

#include <algorithm>
#include <functional>
#include <limits>

namespace matmul::v4::rc::stage3_multirow_v11_receipt_join {
namespace {

using gf::Fp;
using gf::Fp3;

constexpr uint64_t kReceiptDomainV1 =
    0x31565253'50434552ULL; // recursive-verifier "RECPSRV1"
constexpr uint64_t kSetDomainV1 =
    0x31565253'54455352ULL; // recursive-verifier set domain
constexpr uint64_t kBinaryNodeDomainV1 =
    0x31564a52'4e494252ULL; // "RBINRJV1"
constexpr uint64_t kPaddingDomainV1 =
    0x31564a52'44415052ULL; // "RPADRJV1"

constexpr uint32_t kReceiptProgramRootV1 = 46;
constexpr uint32_t kReceiptProgramRootEndV1 = 50;
constexpr uint32_t kReceiptCommonEndV1 = 58;

void AppendU32(std::vector<Fp>& out, uint32_t value)
{
    out.push_back(gf::FromU64(value));
}

void AppendU64(std::vector<Fp>& out, uint64_t value)
{
    AppendU32(out, static_cast<uint32_t>(value));
    AppendU32(out, static_cast<uint32_t>(value >> 32));
}

void AppendUint256(std::vector<Fp>& out, const uint256& value)
{
    for (uint32_t word = 0; word < 4; ++word) {
        AppendU64(out, value.GetUint64(word));
    }
}

void AppendDigest(
    std::vector<Fp>& out,
    const alg_hash::Digest& digest)
{
    for (Fp limb : digest) {
        out.push_back(gf::Canonical(limb));
    }
}

uint256 Pack(const alg_hash::Digest& digest)
{
    return Fri3AlgDigestToUint256(digest);
}

bool Equal(
    const alg_hash::Digest& a,
    const alg_hash::Digest& b)
{
    for (uint32_t limb = 0; limb < a.size(); ++limb) {
        if (gf::Canonical(a[limb]) !=
            gf::Canonical(b[limb])) {
            return false;
        }
    }
    return true;
}

bool Nonzero(const alg_hash::Digest& digest)
{
    return std::any_of(
        digest.begin(), digest.end(),
        [](Fp limb) {
            return gf::Canonical(limb) != 0;
        });
}

bool CanonicalDigest(const alg_hash::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](Fp limb) {
            return limb < gf::kP;
        });
}

std::vector<Fp> BuildDirectSetPreimage(
    const std::array<
        rv::ShardReceiptV1,
        rv::kQueryShardsV1>& receipts)
{
    std::vector<Fp> out;
    out.reserve(28);
    AppendU64(out, kSetDomainV1);
    AppendU32(out, rv::kRecursiveVerifierVersionV1);
    AppendU32(out, rv::kQueryShardsV1);
    for (const auto& receipt : receipts) {
        AppendUint256(out, receipt.receipt_root);
    }
    return out;
}

std::vector<Fp> BuildBinaryNodePreimage(
    uint32_t ordinal,
    uint32_t left_first,
    uint32_t left_count,
    uint32_t right_first,
    uint32_t right_count,
    uint32_t output_first,
    uint32_t output_count,
    uint32_t child_count,
    const uint256& left_root,
    const uint256& right_root,
    const uint256* direct_set_root)
{
    std::vector<Fp> out;
    out.reserve(direct_set_root == nullptr ? 29 : 37);
    AppendU64(out, kBinaryNodeDomainV1);
    AppendU32(out, kReceiptJoinVersionV1);
    AppendU32(out, 0); // overwritten by the exact encoded lane count
    AppendU32(out, ordinal);
    AppendU32(out, left_first);
    AppendU32(out, left_count);
    AppendU32(out, right_first);
    AppendU32(out, right_count);
    AppendU32(out, output_first);
    AppendU32(out, output_count);
    AppendU32(out, child_count);
    AppendU32(out, direct_set_root != nullptr ? 1 : 0);
    AppendUint256(out, left_root);
    AppendUint256(out, right_root);
    if (direct_set_root != nullptr) {
        AppendUint256(out, *direct_set_root);
    }
    out[3] = gf::FromU64(
        static_cast<uint32_t>(out.size()));
    return out;
}

bool ExactPartition(const StatementV1& statement)
{
    const auto expected = rv::CanonicalQueryRangesV1();
    for (uint32_t shard = 0;
         shard < statement.receipts.size();
         ++shard) {
        if (statement.receipts[shard].version !=
                rv::kRecursiveVerifierVersionV1 ||
            statement.receipts[shard].range !=
                expected[shard]) {
            return false;
        }
    }
    return true;
}

bool ExactCommonIdentity(const StatementV1& statement)
{
    const auto& first = statement.receipts[0];
    if (first.child_abi_root.IsNull() ||
        first.child_wire_root.IsNull() ||
        first.child_statement_root.IsNull() ||
        first.full_q192_transcript_root.IsNull() ||
        first.public_fs_seed.IsNull() ||
        first.parent_join_r0_root.IsNull() ||
        !CanonicalDigest(first.program_root) ||
        !Nonzero(first.program_root)) {
        return false;
    }
    for (uint32_t shard = 1;
         shard < statement.receipts.size();
         ++shard) {
        const auto& item = statement.receipts[shard];
        if (item.child_abi_root != first.child_abi_root ||
            item.child_wire_root != first.child_wire_root ||
            item.child_statement_root !=
                first.child_statement_root ||
            item.full_q192_transcript_root !=
                first.full_q192_transcript_root ||
            item.public_fs_seed != first.public_fs_seed ||
            !CanonicalDigest(item.program_root) ||
            item.program_root != first.program_root ||
            item.parent_join_r0_root !=
                first.parent_join_r0_root) {
            return false;
        }
    }
    return true;
}

void AddConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    aq::AirConstraint<Fp3> constraint;
    constraint.name = name;
    constraint.kind = kind;
    constraint.alg_degree = degree;
    constraint.eval = std::move(eval);
    cs.constraints.push_back(std::move(constraint));
}

bool Applies(
    aq::AirKind kind,
    uint32_t row,
    uint32_t rows)
{
    switch (kind) {
    case aq::AirKind::kEverywhere:
        return true;
    case aq::AirKind::kTransition:
        return row + 1 < rows;
    case aq::AirKind::kFirstRow:
        return row == 0;
    case aq::AirKind::kLastRow:
        return row + 1 == rows;
    }
    return false;
}

uint64_t CountViolations(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != cs.n_columns) {
        return std::numeric_limits<uint64_t>::max();
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return std::numeric_limits<uint64_t>::max();
        }
    }
    std::vector<Fp3> current(cs.n_columns);
    std::vector<Fp3> next(cs.n_columns);
    uint64_t violations = 0;
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        const uint32_t next_row =
            (row + 1) % cs.n_rows;
        for (uint32_t column = 0;
             column < cs.n_columns;
             ++column) {
            current[column] = columns[column][row];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint : cs.constraints) {
            if (Applies(
                    constraint.kind,
                    row, cs.n_rows) &&
                !gf::IsZero(
                    constraint.eval(
                        current, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

void BuildConstraints(
    const LayoutV1& layout,
    aq::AirConstraintSystem<Fp3>& cs)
{
    cs.constraints =
        pa::BuildFixedConstraints(layout.poseidon);

    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashRate;
         ++lane) {
        for (uint32_t bit = 0;
             bit < kU32BitsV1;
             ++bit) {
            AddConstraint(
                cs,
                "stage3.v11_receipt_join.u32_bit_boolean",
                aq::AirKind::kEverywhere, 2,
                [column = layout.U32Bit(lane, bit)](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        cur[column],
                        gf::Sub(
                            cur[column],
                            Fp3::One()));
                });
        }
        AddConstraint(
            cs,
            "stage3.v11_receipt_join.u32_recompose",
            aq::AirKind::kEverywhere, 2,
            [layout, lane](
                const auto& cur,
                const auto&) {
                Fp3 recomposed = Fp3::Zero();
                Fp3 power = Fp3::One();
                for (uint32_t bit = 0;
                     bit < kU32BitsV1;
                     ++bit) {
                    recomposed = gf::Add(
                        recomposed,
                        gf::Mul(
                            power,
                            cur[
                                layout.U32Bit(
                                    lane, bit)]));
                    power = gf::Add(power, power);
                }
                return gf::Mul(
                    cur[layout.U32Mask(lane)],
                    gf::Sub(
                        cur[layout.Absorb(lane)],
                        recomposed));
            });
        AddConstraint(
            cs,
            "stage3.v11_receipt_join.bound_absorb",
            aq::AirKind::kEverywhere, 2,
            [layout, lane](
                const auto& cur,
                const auto&) {
                return gf::Mul(
                    cur[layout.BindMask(lane)],
                    gf::Sub(
                        cur[layout.Absorb(lane)],
                        cur[
                            layout.BindExpected(
                                lane)]));
            });
    }

    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashT;
         ++lane) {
        AddConstraint(
            cs,
            "stage3.v11_receipt_join.first_input",
            aq::AirKind::kFirstRow, 1,
            [layout, lane](
                const auto& cur,
                const auto&) {
                const Fp3 expected =
                    lane < alg_hash::kAlgHashRate
                    ? cur[layout.Absorb(lane)]
                    : Fp3::Zero();
                return gf::Sub(
                    cur[
                        layout.poseidon.perm
                            .InputCol(lane)],
                    expected);
            });
        AddConstraint(
            cs,
            "stage3.v11_receipt_join.sponge_transition",
            aq::AirKind::kTransition, 2,
            [layout, lane](
                const auto& cur,
                const auto& next) {
                Fp3 expected =
                    lane < alg_hash::kAlgHashRate
                    ? next[layout.Absorb(lane)]
                    : Fp3::Zero();
                expected = gf::Add(
                    expected,
                    gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            next[layout.first_block]),
                        air_recurse::PermOutputLane(
                            layout.poseidon.perm,
                            cur, lane)));
                return gf::Sub(
                    next[
                        layout.poseidon.perm
                            .InputCol(lane)],
                    expected);
            });
    }

    for (uint32_t limb = 0;
         limb < alg_hash::kAlgHashDigestLen;
         ++limb) {
        AddConstraint(
            cs,
            "stage3.v11_receipt_join.digest_capture",
            aq::AirKind::kEverywhere, 2,
            [layout, limb](
                const auto& cur,
                const auto&) {
                return gf::Mul(
                    cur[layout.last_block],
                    gf::Sub(
                        air_recurse::PermOutputLane(
                            layout.poseidon.perm,
                            cur, limb),
                        cur[
                            layout.ExpectedDigest(
                                limb)]));
            });
    }
}

struct JobV1 {
    std::vector<Fp> padded;
    std::vector<uint8_t> u32;
    std::vector<uint8_t> bind;
    std::vector<Fp> bind_expected;
    alg_hash::Digest expected_digest{};
};

JobV1 BuildJob(
    std::vector<Fp> preimage,
    std::vector<uint8_t> u32,
    std::vector<uint8_t> bind,
    std::vector<Fp> bind_expected,
    const alg_hash::Digest& expected)
{
    JobV1 out;
    if (preimage.size() != u32.size() ||
        preimage.size() != bind.size() ||
        preimage.size() != bind_expected.size()) {
        return out;
    }
    out.padded = std::move(preimage);
    out.u32 = std::move(u32);
    out.bind = std::move(bind);
    out.bind_expected = std::move(bind_expected);
    out.expected_digest = expected;
    out.padded.push_back(1);
    out.u32.push_back(1);
    out.bind.push_back(0);
    out.bind_expected.push_back(0);
    while (out.padded.size() %
               alg_hash::kAlgHashRate !=
           0) {
        out.padded.push_back(0);
        out.u32.push_back(1);
        out.bind.push_back(0);
        out.bind_expected.push_back(0);
    }
    return out;
}

std::vector<uint8_t> ReceiptU32Mask()
{
    std::vector<uint8_t> out(
        kReceiptPreimageLanesV1, 1);
    for (uint32_t lane = kReceiptProgramRootV1;
         lane < kReceiptProgramRootEndV1;
         ++lane) {
        out[lane] = 0;
    }
    return out;
}

bool AddReceiptJob(
    const StatementV1& statement,
    uint32_t shard,
    std::vector<JobV1>& jobs,
    bool& root_matches)
{
    const auto preimage =
        BuildReceiptPreimageV1(
            statement.receipts[shard]);
    if (preimage.size() !=
        kReceiptPreimageLanesV1) {
        return false;
    }
    const auto expected =
        Fri3AlgDigestFromUint256(
            statement.receipts[shard]
                .receipt_root);
    if (!expected.has_value()) return false;
    const auto native =
        alg_hash::SpongeHashFp(preimage);
    root_matches =
        root_matches &&
        Equal(native, *expected) &&
        Pack(native) ==
            rv::ComputeShardReceiptRootV1(
                statement.receipts[shard]);

    std::vector<uint8_t> bind(
        preimage.size(), 0);
    std::vector<Fp> bind_expected(
        preimage.size(), 0);
    const auto common =
        BuildReceiptPreimageV1(
            statement.receipts[0]);
    for (uint32_t lane = 0;
         lane < kReceiptCommonEndV1;
         ++lane) {
        bind[lane] = 1;
        bind_expected[lane] = common[lane];
    }
    const auto ranges =
        rv::CanonicalQueryRangesV1();
    bind_expected[2] =
        gf::FromU64(
            rv::kRecursiveVerifierVersionV1);
    bind_expected[3] =
        gf::FromU64(ranges[shard].ordinal);
    bind_expected[4] =
        gf::FromU64(
            ranges[shard].first_query);
    bind_expected[5] =
        gf::FromU64(
            ranges[shard].query_count);
    jobs.push_back(BuildJob(
        preimage, ReceiptU32Mask(),
        std::move(bind),
        std::move(bind_expected),
        *expected));
    return !jobs.back().padded.empty();
}

void AddU32Job(
    const std::vector<Fp>& preimage,
    const alg_hash::Digest& expected,
    std::vector<JobV1>& jobs)
{
    jobs.push_back(BuildJob(
        preimage,
        std::vector<uint8_t>(
            preimage.size(), 1),
        std::vector<uint8_t>(
            preimage.size(), 0),
        std::vector<Fp>(
            preimage.size(), 0),
        expected));
}

} // namespace

std::vector<Fp> BuildReceiptPreimageV1(
    const rv::ShardReceiptV1& receipt)
{
    std::vector<Fp> out;
    out.reserve(kReceiptPreimageLanesV1);
    AppendU64(out, kReceiptDomainV1);
    AppendU32(out, receipt.version);
    AppendU32(out, receipt.range.ordinal);
    AppendU32(out, receipt.range.first_query);
    AppendU32(out, receipt.range.query_count);
    AppendUint256(out, receipt.child_abi_root);
    AppendUint256(out, receipt.child_wire_root);
    AppendUint256(out, receipt.child_statement_root);
    AppendUint256(out, receipt.full_q192_transcript_root);
    AppendUint256(out, receipt.public_fs_seed);
    AppendDigest(out, receipt.program_root);
    AppendUint256(out, receipt.parent_join_r0_root);
    AppendUint256(out, receipt.merkle_hash_r0_root);
    AppendUint256(out, receipt.merkle_fold_r0_root);
    AppendUint256(out, receipt.deep_vm_r0_root);
    AppendUint256(out, receipt.decoder_join_r0_root);
    AppendU32(out, receipt.merkle_hash_rows);
    AppendU32(out, receipt.merkle_hash_columns);
    AppendU32(out, receipt.merkle_fold_rows);
    AppendU32(out, receipt.merkle_fold_columns);
    AppendU32(out, receipt.deep_vm_rows);
    AppendU32(out, receipt.deep_vm_columns);
    AppendU32(out, receipt.decoder_join_rows);
    AppendU32(out, receipt.decoder_join_columns);
    AppendU64(out, receipt.materialized_trace_cells);
    AppendU64(
        out,
        receipt.measured_unaggregated_wire_bytes);
    return out;
}

uint256 ComputeBinaryRootV1(
    const std::array<
        rv::ShardReceiptV1,
        rv::kQueryShardsV1>& receipts,
    const uint256& shard_set_root)
{
    if (shard_set_root.IsNull()) return {};
    for (const auto& receipt : receipts) {
        if (!Fri3AlgDigestFromUint256(
                receipt.receipt_root).has_value()) {
            return {};
        }
    }
    const auto left_preimage =
        BuildBinaryNodePreimage(
            0, 0, 64, 64, 64,
            0, 128, 2,
            receipts[0].receipt_root,
            receipts[1].receipt_root,
            nullptr);
    const uint256 left =
        Pack(alg_hash::SpongeHashFp(
            left_preimage));
    const auto root_preimage =
        BuildBinaryNodePreimage(
            1, 0, 128, 128, 64,
            0, 192, 3,
            left,
            receipts[2].receipt_root,
            &shard_set_root);
    return Pack(
        alg_hash::SpongeHashFp(
            root_preimage));
}

StatementV1 BuildStatementV1(
    const std::array<
        rv::ShardReceiptV1,
        rv::kQueryShardsV1>& receipts)
{
    StatementV1 out;
    out.receipts = receipts;
    out.expected_shard_set_root =
        rv::ComputeShardSetRootV1(receipts);
    out.expected_binary_root =
        ComputeBinaryRootV1(
            receipts,
            out.expected_shard_set_root);
    return out;
}

LayoutV1 CanonicalLayoutV1()
{
    LayoutV1 out;
    out.poseidon = pa::CanonicalLayout(0);
    uint32_t cursor = out.poseidon.End();
    out.absorb_base = cursor;
    cursor += alg_hash::kAlgHashRate;
    out.u32_mask_base = cursor;
    cursor += alg_hash::kAlgHashRate;
    out.u32_bit_base = cursor;
    cursor +=
        alg_hash::kAlgHashRate *
        kU32BitsV1;
    out.first_block = cursor++;
    out.last_block = cursor++;
    out.expected_digest_base = cursor;
    cursor += alg_hash::kAlgHashDigestLen;
    out.bind_mask_base = cursor;
    cursor += alg_hash::kAlgHashRate;
    out.bind_expected_base = cursor;
    cursor += alg_hash::kAlgHashRate;
    out.n_columns = cursor;
    return out;
}

ProductV1 BuildProductV1(
    const StatementV1& statement)
{
    ProductV1 out;
    out.statement = statement;
    out.layout = CanonicalLayoutV1();
    out.trace_rows = kTraceRowsV1;
    out.trace_columns =
        out.layout.n_columns;
    out.materialized_trace_cells =
        uint64_t{out.trace_rows} *
        out.trace_columns;
    out.exact_q192_partition =
        ExactPartition(statement);
    out.exact_common_child_identity =
        ExactCommonIdentity(statement);
    auto fail = [&out](
                    const std::string& detail) {
        out.valid = false;
        out.recursive_authority_ready = false;
        out.note =
            "stage3:v11_receipt_join:" +
            detail;
        return out;
    };
    if (statement.version !=
            kReceiptJoinVersionV1 ||
        statement.expected_shard_set_root.IsNull() ||
        statement.expected_binary_root.IsNull()) {
        return fail("statement");
    }

    std::vector<JobV1> jobs;
    jobs.reserve(6);
    bool leaf_roots = true;
    for (uint32_t shard = 0;
         shard < statement.receipts.size();
         ++shard) {
        if (!AddReceiptJob(
                statement, shard,
                jobs, leaf_roots)) {
            return fail("leaf_codec");
        }
    }
    out.all_leaf_receipt_roots_recomputed =
        leaf_roots;

    const auto set_preimage =
        BuildDirectSetPreimage(
            statement.receipts);
    const auto set_native =
        alg_hash::SpongeHashFp(
            set_preimage);
    out.computed_shard_set_root =
        Pack(set_native);
    out.direct_shard_set_root_recomputed =
        out.computed_shard_set_root ==
            statement.expected_shard_set_root &&
        out.computed_shard_set_root ==
            rv::ComputeShardSetRootV1(
                statement.receipts);
    AddU32Job(set_preimage, set_native, jobs);

    const auto left_preimage =
        BuildBinaryNodePreimage(
            0, 0, 64, 64, 64,
            0, 128, 2,
            statement.receipts[0]
                .receipt_root,
            statement.receipts[1]
                .receipt_root,
            nullptr);
    const auto left_native =
        alg_hash::SpongeHashFp(
            left_preimage);
    const uint256 left_root =
        Pack(left_native);
    AddU32Job(
        left_preimage, left_native, jobs);

    const auto root_preimage =
        BuildBinaryNodePreimage(
            1, 0, 128, 128, 64,
            0, 192, 3,
            left_root,
            statement.receipts[2]
                .receipt_root,
            &out.computed_shard_set_root);
    const auto root_native =
        alg_hash::SpongeHashFp(
            root_preimage);
    out.computed_binary_root =
        Pack(root_native);
    out.ordered_binary_tree_recomputed =
        out.computed_binary_root ==
            statement.expected_binary_root &&
        out.computed_binary_root ==
            ComputeBinaryRootV1(
                statement.receipts,
                statement
                    .expected_shard_set_root);
    AddU32Job(
        root_preimage, root_native, jobs);

    uint32_t real_rows = 0;
    for (const auto& job : jobs) {
        if (job.padded.empty() ||
            job.padded.size() %
                alg_hash::kAlgHashRate !=
                0) {
            return fail("job_shape");
        }
        real_rows +=
            static_cast<uint32_t>(
                job.padded.size() /
                alg_hash::kAlgHashRate);
    }
    if (real_rows != kRealHashRowsV1 ||
        real_rows > kTraceRowsV1) {
        return fail("row_inventory");
    }
    for (uint32_t row = real_rows;
         row < kTraceRowsV1;
         ++row) {
        std::vector<Fp> padding;
        AppendU64(padding, kPaddingDomainV1);
        AppendU32(padding, row);
        const auto digest =
            alg_hash::SpongeHashFp(padding);
        AddU32Job(padding, digest, jobs);
    }

    out.cs.n_rows = kTraceRowsV1;
    out.cs.n_columns =
        out.layout.n_columns;
    BuildConstraints(out.layout, out.cs);
    out.constraints =
        static_cast<uint32_t>(
            out.cs.constraints.size());
    for (const auto& constraint :
         out.cs.constraints) {
        out.max_constraint_degree =
            std::max(
                out.max_constraint_degree,
                constraint.alg_degree);
    }
    out.quotient_len =
        out.cs.QuotientLen();
    out.columns.assign(
        out.layout.n_columns,
        std::vector<Fp3>(
            kTraceRowsV1,
            Fp3::Zero()));
    auto set = [&out](
                   uint32_t column,
                   uint32_t row,
                   const Fp3& value) {
        out.columns[column][row] = value;
    };

    uint32_t trace_row = 0;
    for (const auto& job : jobs) {
        alg_hash::State state{};
        const uint32_t blocks =
            static_cast<uint32_t>(
                job.padded.size() /
                alg_hash::kAlgHashRate);
        for (uint32_t block = 0;
             block < blocks;
             ++block, ++trace_row) {
            for (uint32_t lane = 0;
                 lane < alg_hash::kAlgHashRate;
                 ++lane) {
                const uint32_t offset =
                    block *
                        alg_hash::kAlgHashRate +
                    lane;
                const Fp absorb =
                    gf::Canonical(
                        job.padded[offset]);
                set(
                    out.layout.Absorb(lane),
                    trace_row,
                    Fp3::FromFp(absorb));
                set(
                    out.layout.U32Mask(lane),
                    trace_row,
                    job.u32[offset] != 0
                    ? Fp3::One()
                    : Fp3::Zero());
                if (job.u32[offset] != 0) {
                    if (absorb >
                        std::numeric_limits<
                            uint32_t>::max()) {
                        return fail(
                            "noncanonical_u32");
                    }
                    for (uint32_t bit = 0;
                         bit < kU32BitsV1;
                         ++bit) {
                        set(
                            out.layout.U32Bit(
                                lane, bit),
                            trace_row,
                            ((absorb >> bit) &
                             1U) != 0
                            ? Fp3::One()
                            : Fp3::Zero());
                    }
                }
                set(
                    out.layout.BindMask(lane),
                    trace_row,
                    job.bind[offset] != 0
                    ? Fp3::One()
                    : Fp3::Zero());
                set(
                    out.layout.BindExpected(lane),
                    trace_row,
                    Fp3::FromFp(
                        gf::Canonical(
                            job.bind_expected[
                                offset])));
                state[lane] =
                    gf::Add(state[lane], absorb);
            }
            if (block == 0) {
                set(
                    out.layout.first_block,
                    trace_row,
                    Fp3::One());
            }
            if (block + 1 == blocks) {
                set(
                    out.layout.last_block,
                    trace_row,
                    Fp3::One());
            }
            for (uint32_t limb = 0;
                 limb <
                     alg_hash::kAlgHashDigestLen;
                 ++limb) {
                set(
                    out.layout.ExpectedDigest(
                        limb),
                    trace_row,
                    Fp3::FromFp(
                        gf::Canonical(
                            job.expected_digest[
                                limb])));
            }
            const auto witness =
                pa::BuildWitness(
                    out.layout.poseidon,
                    state);
            for (uint32_t column = 0;
                 column <
                     out.layout.poseidon.End();
                 ++column) {
                set(
                    column, trace_row,
                    witness.row[column]);
            }
            state = witness.output;
        }
    }
    if (trace_row != kTraceRowsV1) {
        return fail("trace_fill");
    }
    const auto binary_digest =
        Fri3AlgDigestFromUint256(
            out.computed_binary_root);
    out.binary_root_export_constrained =
        binary_digest.has_value() &&
        gf::Eq(
            out.columns[
                out.layout.last_block]
                [kBinaryRootExportRowV1],
            Fp3::One());
    if (binary_digest.has_value()) {
        for (uint32_t limb = 0;
             limb <
                 alg_hash::kAlgHashDigestLen;
             ++limb) {
            out.binary_root_export_constrained =
                out.binary_root_export_constrained &&
                gf::Eq(
                    out.columns[
                        out.layout
                            .ExpectedDigest(
                                limb)]
                        [kBinaryRootExportRowV1],
                    Fp3::FromFp(
                        (*binary_digest)[limb]));
        }
    }

    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashRate;
         ++lane) {
        out.preprocessed_columns.push_back(
            out.layout.Absorb(lane));
        out.preprocessed_columns.push_back(
            out.layout.U32Mask(lane));
    }
    out.preprocessed_columns.push_back(
        out.layout.first_block);
    out.preprocessed_columns.push_back(
        out.layout.last_block);
    for (uint32_t limb = 0;
         limb < alg_hash::kAlgHashDigestLen;
         ++limb) {
        out.preprocessed_columns.push_back(
            out.layout.ExpectedDigest(limb));
    }
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashRate;
         ++lane) {
        out.preprocessed_columns.push_back(
            out.layout.BindMask(lane));
        out.preprocessed_columns.push_back(
            out.layout.BindExpected(lane));
    }
    std::sort(
        out.preprocessed_columns.begin(),
        out.preprocessed_columns.end());
    out.preprocessed_columns.erase(
        std::unique(
            out.preprocessed_columns.begin(),
            out.preprocessed_columns.end()),
        out.preprocessed_columns.end());
    for (uint32_t column :
         out.preprocessed_columns) {
        out.cs.preprocessed.emplace_back(
            column, out.columns[column]);
    }
    out.cs.preprocessed_pin_ood = true;
    const auto session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns,
            out.preprocessed_columns);
    if (!session.valid ||
        session.base_row_commitment.IsNull()) {
        return fail(
            "preprocessed_root:" +
            session.note);
    }
    out.preprocessed_row_group_root =
        session.base_row_commitment;
    out.cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role =
            aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns =
            out.preprocessed_columns,
        .root =
            out.preprocessed_row_group_root,
    });

    out.canonical_u32_absorb_encoding = true;
    out.preprocessed_values_root_pinned = true;
    out.quadratic_poseidon_air =
        out.max_constraint_degree <= 2;
    out.child_receipt_proofs_verified_in_air =
        false;
    out.recursive_authority_ready = false;
    out.violations =
        CountViolations(out.cs, out.columns);
    out.valid =
        out.exact_q192_partition &&
        out.exact_common_child_identity &&
        out.all_leaf_receipt_roots_recomputed &&
        out.direct_shard_set_root_recomputed &&
        out.ordered_binary_tree_recomputed &&
        out.binary_root_export_constrained &&
        out.canonical_u32_absorb_encoding &&
        out.preprocessed_values_root_pinned &&
        out.quadratic_poseidon_air &&
        out.violations == 0 &&
        !out.child_receipt_proofs_verified_in_air &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "stage3:v11_receipt_join:"
          "binary_2_plus_1_executable;"
          "child_proof_verification_pending"
        : "stage3:v11_receipt_join:"
          "statement_or_constraint_failure";
    return out;
}

ProveResultV1 ProveV1(
    const StatementV1& statement,
    const uint256& public_fs_seed)
{
    ProveResultV1 out;
    const auto product =
        BuildProductV1(statement);
    out.preprocessed_row_group_root =
        product.preprocessed_row_group_root;
    out.binary_root =
        product.computed_binary_root;
    out.trace_rows = product.trace_rows;
    out.trace_columns =
        product.trace_columns;
    out.constraints = product.constraints;
    out.max_constraint_degree =
        product.max_constraint_degree;
    out.quotient_len =
        product.quotient_len;
    if (!product.valid ||
        public_fs_seed.IsNull()) {
        out.note =
            "stage3:v11_receipt_join:prove:" +
            product.note;
        return out;
    }
    const auto proved =
        aq::AirQuotientProveRowsSplitRap(
            product.cs, product.columns,
            product.preprocessed_columns,
            public_fs_seed);
    if (!proved.ok ||
        !proved.division_exact ||
        proved.proof.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            proved.proof.batch.groups[0]
                .row_commit.root) !=
            product.preprocessed_row_group_root) {
        out.note =
            "stage3:v11_receipt_join:prove:" +
            proved.note;
        return out;
    }
    std::vector<unsigned char> wire;
    const size_t bytes =
        aq::SerializeAirQuotientSplitRapRowsProof(
            proved.proof, wire);
    if (bytes == 0 || bytes != wire.size()) {
        out.note =
            "stage3:v11_receipt_join:"
            "prove:serialize";
        return out;
    }
    out.proof = proved.proof;
    out.proof_wire_bytes = bytes;
    out.ok = true;
    out.note =
        "stage3:v11_receipt_join:"
        "prove:split_rap_q192";
    return out;
}

VerificationAuditV1 VerifyV1(
    const StatementV1& statement,
    const aq::AirQuotientSplitRapRowsProof& proof,
    const uint256& public_fs_seed)
{
    VerificationAuditV1 out;
    const auto product =
        BuildProductV1(statement);
    out.preprocessed_row_group_root =
        product.preprocessed_row_group_root;
    out.binary_root =
        product.computed_binary_root;
    out.trace_rows = product.trace_rows;
    out.trace_columns =
        product.trace_columns;
    out.constraints = product.constraints;
    out.max_constraint_degree =
        product.max_constraint_degree;
    out.quotient_len =
        product.quotient_len;
    auto fail = [&out](
                    const std::string& detail) {
        out.valid = false;
        out.recursive_authority_ready = false;
        out.note =
            "stage3:v11_receipt_join:"
            "verify:" + detail;
        return out;
    };
    if (!product.valid ||
        public_fs_seed.IsNull()) {
        return fail(product.note);
    }
    std::string why;
    if (!aq::AirQuotientVerifyRowsSplitRap(
            product.cs, proof,
            product.preprocessed_columns,
            public_fs_seed, &why)) {
        return fail(why);
    }
    if (proof.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            proof.batch.groups[0]
                .row_commit.root) !=
            product.preprocessed_row_group_root) {
        return fail(
            "preprocessed_row_group_root");
    }
    out.exact_q192_partition =
        product.exact_q192_partition;
    out.exact_common_child_identity =
        product.exact_common_child_identity;
    out.all_leaf_receipt_roots_recomputed =
        product.all_leaf_receipt_roots_recomputed;
    out.ordered_binary_tree_recomputed =
        product.ordered_binary_tree_recomputed;
    out.binary_root_export_constrained =
        product.binary_root_export_constrained;
    out.canonical_u32_absorb_encoding_verified =
        product.canonical_u32_absorb_encoding;
    out.split_rap_quotient_fri_verified =
        true;
    out.child_receipt_proofs_verified_in_air =
        false;
    out.recursive_authority_ready = false;
    out.valid =
        out.exact_q192_partition &&
        out.exact_common_child_identity &&
        out.all_leaf_receipt_roots_recomputed &&
        out.ordered_binary_tree_recomputed &&
        out.binary_root_export_constrained &&
        out.canonical_u32_absorb_encoding_verified &&
        out.split_rap_quotient_fri_verified &&
        !out.child_receipt_proofs_verified_in_air &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "stage3:v11_receipt_join:"
          "verify:binary_2_plus_1;"
          "child_proof_verification_pending"
        : "stage3:v11_receipt_join:"
          "verify:invariant";
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_receipt_join
