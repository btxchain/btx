// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_receipt_join_q96.h>

#include <algorithm>
#include <functional>
#include <limits>

namespace matmul::v4::rc::stage3_multirow_v11_receipt_join_q96 {
namespace {

using gf::Fp;
using gf::Fp3;

constexpr uint64_t kQ96SetDomainV1 =
    0x31564a52'36395152ULL; // "RQ96RJV1"
constexpr uint64_t kPaddingDomainV1 =
    0x31564a52'36504452ULL; // "RDP6RJV1"
constexpr uint32_t kReceiptProgramRootBeginV1 = 46;
constexpr uint32_t kReceiptProgramRootEndV1 = 50;
constexpr uint32_t kReceiptCommonEndV1 = 58;
constexpr uint32_t kU32BitsV1 = base::kU32BitsV1;

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

bool EqualDigest(
    const alg_hash::Digest& lhs,
    const alg_hash::Digest& rhs)
{
    for (uint32_t lane = 0; lane < lhs.size(); ++lane) {
        if (gf::Canonical(lhs[lane]) !=
            gf::Canonical(rhs[lane])) {
            return false;
        }
    }
    return true;
}

std::vector<Fp> BuildSetPreimageV1(
    const std::array<
        rv::ShardReceiptV1,
        base::kQ96QueryShardsV1>& receipts)
{
    std::vector<Fp> out;
    out.reserve(27);
    AppendU64(out, kQ96SetDomainV1);
    AppendU32(out, base::kReceiptJoinVersionV1);
    AppendU32(out, 0);
    AppendU32(out, base::kQ96QueryShardsV1);
    for (const auto& receipt : receipts) {
        AppendU32(out, receipt.range.ordinal);
        AppendU32(out, receipt.range.first_query);
        AppendU32(out, receipt.range.query_count);
        AppendUint256(out, receipt.receipt_root);
    }
    out[3] = gf::FromU64(
        static_cast<uint32_t>(out.size()));
    return out;
}

template <typename Eval>
void AddConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    Eval&& eval)
{
    aq::AirConstraint<Fp3> constraint;
    constraint.name = name;
    constraint.kind = kind;
    constraint.alg_degree = degree;
    constraint.eval =
        std::forward<Eval>(eval);
    cs.constraints.push_back(
        std::move(constraint));
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
                "stage3.v11_receipt_join_q96."
                "u32_bit_boolean",
                aq::AirKind::kEverywhere, 2,
                [column =
                     layout.U32Bit(lane, bit)](
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
            "stage3.v11_receipt_join_q96."
            "u32_recompose",
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
                            cur[layout.U32Bit(
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
            "stage3.v11_receipt_join_q96."
            "bound_absorb",
            aq::AirKind::kEverywhere, 2,
            [layout, lane](
                const auto& cur,
                const auto&) {
                return gf::Mul(
                    cur[layout.BindMask(lane)],
                    gf::Sub(
                        cur[layout.Absorb(lane)],
                        cur[layout.BindExpected(
                            lane)]));
            });
    }

    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashT;
         ++lane) {
        AddConstraint(
            cs,
            "stage3.v11_receipt_join_q96."
            "first_input",
            aq::AirKind::kFirstRow, 1,
            [layout, lane](
                const auto& cur,
                const auto&) {
                const Fp3 expected =
                    lane < alg_hash::kAlgHashRate
                    ? cur[layout.Absorb(lane)]
                    : Fp3::Zero();
                return gf::Sub(
                    cur[layout.poseidon.perm
                            .InputCol(lane)],
                    expected);
            });
        AddConstraint(
            cs,
            "stage3.v11_receipt_join_q96."
            "sponge_transition",
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
                    next[layout.poseidon.perm
                             .InputCol(lane)],
                    expected);
            });
    }

    for (uint32_t limb = 0;
         limb < alg_hash::kAlgHashDigestLen;
         ++limb) {
        AddConstraint(
            cs,
            "stage3.v11_receipt_join_q96."
            "digest_capture",
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
                        cur[layout.ExpectedDigest(
                            limb)]));
            });
    }
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
            current[column] =
                columns[column][row];
            next[column] =
                columns[column][next_row];
        }
        for (const auto& constraint :
             cs.constraints) {
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
    out.bind_expected =
        std::move(bind_expected);
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
        base::kReceiptPreimageLanesV1, 1);
    for (uint32_t lane =
             kReceiptProgramRootBeginV1;
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
        base::BuildReceiptPreimageV1(
            statement.receipts[shard]);
    if (preimage.size() !=
        base::kReceiptPreimageLanesV1) {
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
        EqualDigest(native, *expected) &&
        Fri3AlgDigestToUint256(native) ==
            rv::ComputeShardReceiptRootV1(
                statement.receipts[shard]);

    const auto common =
        base::BuildReceiptPreimageV1(
            statement.receipts[0]);
    std::vector<uint8_t> bind(
        preimage.size(), 0);
    std::vector<Fp> bind_expected(
        preimage.size(), 0);
    for (uint32_t lane = 0;
         lane < kReceiptCommonEndV1;
         ++lane) {
        bind[lane] = 1;
        bind_expected[lane] = common[lane];
    }
    const auto ranges =
        base::CanonicalQ96QueryRangesV1();
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

StatementV1 BuildStatementV1(
    const std::array<
        rv::ShardReceiptV1,
        base::kQ96QueryShardsV1>& receipts)
{
    StatementV1 out;
    out.receipts = receipts;
    out.expected_receipt_set_root =
        base::ComputeQ96ReceiptSetRootV1(
            receipts);
    return out;
}

ProductV1 BuildProductV1(
    const StatementV1& statement)
{
    ProductV1 out;
    out.statement = statement;
    out.layout = base::CanonicalLayoutV1();
    out.trace_rows = kTraceRowsV1;
    out.trace_columns = out.layout.n_columns;
    out.materialized_trace_cells =
        uint64_t{out.trace_rows} *
        out.trace_columns;

    const auto profile =
        base::BuildQ96ReceiptSetV1(
            statement.receipts);
    out.exact_single_q192_partition =
        profile.exact_single_q192_partition;
    out.exact_common_child_identity =
        profile.common_child_identity;

    auto fail = [&out](
                    const std::string& detail) {
        out.valid = false;
        out.recursive_authority_ready = false;
        out.note =
            "stage3:v11_receipt_join_q96:" +
            detail;
        return out;
    };
    if (statement.version != kVersionV1 ||
        statement
            .expected_receipt_set_root
            .IsNull()) {
        return fail("statement");
    }

    std::vector<JobV1> jobs;
    jobs.reserve(4);
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
        BuildSetPreimageV1(
            statement.receipts);
    const auto set_native =
        alg_hash::SpongeHashFp(
            set_preimage);
    out.computed_receipt_set_root =
        Fri3AlgDigestToUint256(set_native);
    out.ordered_receipt_set_root_recomputed =
        out.computed_receipt_set_root ==
            statement
                .expected_receipt_set_root &&
        out.computed_receipt_set_root ==
            base::ComputeQ96ReceiptSetRootV1(
                statement.receipts);
    AddU32Job(
        set_preimage, set_native, jobs);

    uint32_t real_rows = 0;
    for (const auto& job : jobs) {
        if (job.padded.empty() ||
            job.padded.size() %
                alg_hash::kAlgHashRate != 0) {
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
        AddU32Job(
            padding, digest, jobs);
    }

    out.cs.n_rows = kTraceRowsV1;
    out.cs.n_columns = out.layout.n_columns;
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
    out.quotient_len = out.cs.QuotientLen();
    out.columns.assign(
        out.layout.n_columns,
        std::vector<Fp3>(
            kTraceRowsV1, Fp3::Zero()));
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
                    out.layout
                        .BindExpected(lane),
                    trace_row,
                    Fp3::FromFp(
                        gf::Canonical(
                            job.bind_expected[
                                offset])));
                state[lane] =
                    gf::Add(
                        state[lane], absorb);
            }
            if (block == 0) {
                set(
                    out.layout.first_block,
                    trace_row, Fp3::One());
            }
            if (block + 1 == blocks) {
                set(
                    out.layout.last_block,
                    trace_row, Fp3::One());
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

    const auto root_digest =
        Fri3AlgDigestFromUint256(
            out.computed_receipt_set_root);
    out.root_export_constrained =
        root_digest.has_value() &&
        gf::Eq(
            out.columns[
                out.layout.last_block]
                [kRootExportRowV1],
            Fp3::One());
    if (root_digest.has_value()) {
        for (uint32_t limb = 0;
             limb <
                 alg_hash::kAlgHashDigestLen;
             ++limb) {
            out.root_export_constrained =
                out.root_export_constrained &&
                gf::Eq(
                    out.columns[
                        out.layout
                            .ExpectedDigest(
                                limb)]
                        [kRootExportRowV1],
                    Fp3::FromFp(
                        (*root_digest)[limb]));
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
        out.exact_single_q192_partition &&
        out.exact_common_child_identity &&
        out.all_leaf_receipt_roots_recomputed &&
        out.ordered_receipt_set_root_recomputed &&
        out.root_export_constrained &&
        out.canonical_u32_absorb_encoding &&
        out.preprocessed_values_root_pinned &&
        out.quadratic_poseidon_air &&
        out.violations == 0 &&
        !out.child_receipt_proofs_verified_in_air &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "stage3:v11_receipt_join_q96:"
          "ordered_two_receipt_executable;"
          "child_proof_verification_pending"
        : "stage3:v11_receipt_join_q96:"
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
    out.receipt_set_root =
        product.computed_receipt_set_root;
    out.trace_rows = product.trace_rows;
    out.trace_columns = product.trace_columns;
    out.constraints = product.constraints;
    out.max_constraint_degree =
        product.max_constraint_degree;
    out.quotient_len = product.quotient_len;
    if (!product.valid ||
        public_fs_seed.IsNull()) {
        out.note =
            "stage3:v11_receipt_join_q96:"
            "prove:" + product.note;
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
            "stage3:v11_receipt_join_q96:"
            "prove:" + proved.note;
        return out;
    }
    std::vector<unsigned char> wire;
    const size_t bytes =
        aq::SerializeAirQuotientSplitRapRowsProof(
            proved.proof, wire);
    if (bytes == 0 || bytes != wire.size()) {
        out.note =
            "stage3:v11_receipt_join_q96:"
            "prove:serialize";
        return out;
    }
    out.proof = proved.proof;
    out.proof_wire_bytes = bytes;
    out.ok = true;
    out.note =
        "stage3:v11_receipt_join_q96:"
        "prove:split_rap_one_q192_transcript";
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
    out.receipt_set_root =
        product.computed_receipt_set_root;
    out.trace_rows = product.trace_rows;
    out.trace_columns = product.trace_columns;
    out.constraints = product.constraints;
    out.max_constraint_degree =
        product.max_constraint_degree;
    out.quotient_len = product.quotient_len;
    auto fail = [&out](
                    const std::string& detail) {
        out.valid = false;
        out.recursive_authority_ready = false;
        out.note =
            "stage3:v11_receipt_join_q96:"
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
    out.exact_single_q192_partition =
        product.exact_single_q192_partition;
    out.exact_common_child_identity =
        product.exact_common_child_identity;
    out.all_leaf_receipt_roots_recomputed =
        product.all_leaf_receipt_roots_recomputed;
    out.ordered_receipt_set_root_recomputed =
        product.ordered_receipt_set_root_recomputed;
    out.root_export_constrained =
        product.root_export_constrained;
    out.canonical_u32_absorb_encoding_verified =
        product.canonical_u32_absorb_encoding;
    out.split_rap_quotient_fri_verified = true;
    out.child_receipt_proofs_verified_in_air =
        false;
    out.recursive_authority_ready = false;
    out.valid =
        out.exact_single_q192_partition &&
        out.exact_common_child_identity &&
        out.all_leaf_receipt_roots_recomputed &&
        out.ordered_receipt_set_root_recomputed &&
        out.root_export_constrained &&
        out.canonical_u32_absorb_encoding_verified &&
        out.split_rap_quotient_fri_verified &&
        !out.child_receipt_proofs_verified_in_air &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "stage3:v11_receipt_join_q96:"
          "verify:ordered_two_receipt;"
          "child_proof_verification_pending"
        : "stage3:v11_receipt_join_q96:"
          "verify:invariant";
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_receipt_join_q96
