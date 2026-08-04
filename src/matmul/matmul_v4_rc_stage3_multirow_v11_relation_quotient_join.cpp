// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_relation_quotient_join.h>

#include <algorithm>
#include <chrono>
#include <limits>
#include <utility>

namespace matmul::v4::rc::stage3_multirow_v11_relation_quotient_join {
namespace {

using gf::Fp3;

uint32_t AllocateScalarPair(
    uint32_t& next,
    ScalarPairLayoutV1& pair)
{
    pair.claim = next++;
    pair.expected = next++;
    return next;
}

uint32_t AllocateDigestPair(
    uint32_t& next,
    DigestPairLayoutV1& pair)
{
    for (uint32_t limb = 0;
         limb < alg_hash::kAlgHashDigestLen;
         ++limb) {
        pair.claim[limb] = next++;
        pair.expected[limb] = next++;
    }
    return next;
}

bool CanonicalFp3(const Fp3& value)
{
    return value.c0 < gf::kP &&
        value.c1 < gf::kP &&
        value.c2 < gf::kP;
}

bool CanonicalDigest(const alg_hash::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp limb) {
            return limb < gf::kP;
        });
}

void AddConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    aq::AirConstraint<Fp3> constraint;
    constraint.name = name;
    constraint.kind = aq::AirKind::kEverywhere;
    constraint.alg_degree = degree;
    constraint.eval = std::move(eval);
    cs.constraints.push_back(std::move(constraint));
}

void AddPairConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
    const ScalarPairLayoutV1& pair,
    const char* name)
{
    AddConstraint(
        cs, name, 1,
        [pair](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return gf::Sub(
                cur[pair.claim],
                cur[pair.expected]);
        });
}

void AddDigestPairConstraints(
    aq::AirConstraintSystem<Fp3>& cs,
    const DigestPairLayoutV1& pair,
    const char* name)
{
    for (uint32_t limb = 0;
         limb < alg_hash::kAlgHashDigestLen;
         ++limb) {
        AddConstraint(
            cs, name, 1,
            [pair, limb](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    cur[pair.claim[limb]],
                    cur[pair.expected[limb]]);
            });
    }
}

void BuildConstraints(
    const LayoutV1& layout,
    aq::AirConstraintSystem<Fp3>& cs)
{
    AddConstraint(
        cs, "stage3.v11_relation_qjoin.active_boolean", 2,
        [column = layout.active.claim](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return gf::Mul(
                cur[column],
                gf::Sub(cur[column], Fp3::One()));
        });
    AddPairConstraint(
        cs, layout.active,
        "stage3.v11_relation_qjoin.active_pin");
    AddPairConstraint(
        cs, layout.query_ordinal,
        "stage3.v11_relation_qjoin.query_pin");
    AddPairConstraint(
        cs, layout.range_ordinal,
        "stage3.v11_relation_qjoin.range_pin");
    AddPairConstraint(
        cs, layout.range_local_ordinal,
        "stage3.v11_relation_qjoin.range_local_pin");
    AddPairConstraint(
        cs, layout.y,
        "stage3.v11_relation_qjoin.y_pin");
    AddPairConstraint(
        cs, layout.zh,
        "stage3.v11_relation_qjoin.zh_pin");
    AddDigestPairConstraints(
        cs, layout.manifest_root,
        "stage3.v11_relation_qjoin.manifest_pin");
    AddDigestPairConstraints(
        cs, layout.transcript_root,
        "stage3.v11_relation_qjoin.transcript_pin");

    for (uint32_t shard = 0;
         shard < kRelationShardsV1;
         ++shard) {
        const auto leaf = layout.leaves[shard];
        AddPairConstraint(
            cs, leaf.relation_ordinal,
            "stage3.v11_relation_qjoin.relation_pin");
        AddDigestPairConstraints(
            cs, leaf.local_program_root,
            "stage3.v11_relation_qjoin.program_root_pin");
        AddDigestPairConstraints(
            cs, leaf.receipt_root,
            "stage3.v11_relation_qjoin.receipt_root_pin");

        for (uint32_t limb = 0;
             limb < alg_hash::kAlgHashDigestLen;
             ++limb) {
            AddConstraint(
                cs,
                "stage3.v11_relation_qjoin.manifest_alias",
                1,
                [leaf, layout, limb](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Sub(
                        cur[leaf.manifest_root_alias[limb]],
                        cur[layout.manifest_root.claim[limb]]);
                });
            AddConstraint(
                cs,
                "stage3.v11_relation_qjoin.transcript_alias",
                1,
                [leaf, layout, limb](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Sub(
                        cur[leaf.transcript_root_alias[limb]],
                        cur[layout.transcript_root.claim[limb]]);
                });
        }
        AddConstraint(
            cs, "stage3.v11_relation_qjoin.query_alias", 1,
            [leaf, layout](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    cur[leaf.query_ordinal_alias],
                    cur[layout.query_ordinal.claim]);
            });
        AddConstraint(
            cs, "stage3.v11_relation_qjoin.range_alias", 1,
            [leaf, layout](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    cur[leaf.range_ordinal_alias],
                    cur[layout.range_ordinal.claim]);
            });
        AddConstraint(
            cs, "stage3.v11_relation_qjoin.range_local_alias", 1,
            [leaf, layout](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    cur[leaf.range_local_ordinal_alias],
                    cur[layout.range_local_ordinal.claim]);
            });
        AddConstraint(
            cs, "stage3.v11_relation_qjoin.y_alias", 1,
            [leaf, layout](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    cur[leaf.y_alias],
                    cur[layout.y.claim]);
            });
        AddConstraint(
            cs, "stage3.v11_relation_qjoin.zh_alias", 1,
            [leaf, layout](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    cur[leaf.zh_alias],
                    cur[layout.zh.claim]);
            });
        AddConstraint(
            cs, "stage3.v11_relation_qjoin.partial_quotient", 2,
            [leaf](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    cur[leaf.partial_composition],
                    gf::Mul(
                        cur[leaf.zh_alias],
                        cur[leaf.partial_quotient]));
            });
        AddConstraint(
            cs, "stage3.v11_relation_qjoin.composition_step", 1,
            [leaf](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    cur[leaf.composition_after],
                    gf::Add(
                        cur[leaf.composition_before],
                        cur[leaf.partial_composition]));
            });
        AddConstraint(
            cs, "stage3.v11_relation_qjoin.quotient_step", 1,
            [leaf](
                const std::vector<Fp3>& cur,
                const std::vector<Fp3>&) {
                return gf::Sub(
                    cur[leaf.quotient_after],
                    gf::Add(
                        cur[leaf.quotient_before],
                        cur[leaf.partial_quotient]));
            });
        if (shard == 0) {
            AddConstraint(
                cs,
                "stage3.v11_relation_qjoin.composition_zero",
                1,
                [leaf](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return cur[leaf.composition_before];
                });
            AddConstraint(
                cs,
                "stage3.v11_relation_qjoin.quotient_zero",
                1,
                [leaf](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return cur[leaf.quotient_before];
                });
        } else {
            const auto previous =
                layout.leaves[shard - 1];
            AddConstraint(
                cs,
                "stage3.v11_relation_qjoin.composition_chain",
                1,
                [leaf, previous](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Sub(
                        cur[leaf.composition_before],
                        cur[previous.composition_after]);
                });
            AddConstraint(
                cs,
                "stage3.v11_relation_qjoin.quotient_chain",
                1,
                [leaf, previous](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>&) {
                    return gf::Sub(
                        cur[leaf.quotient_before],
                        cur[previous.quotient_after]);
                });
        }
    }
    const auto last =
        layout.leaves[kRelationShardsV1 - 1];
    AddConstraint(
        cs, "stage3.v11_relation_qjoin.total_identity", 2,
        [last, layout](
            const std::vector<Fp3>& cur,
            const std::vector<Fp3>&) {
            return gf::Sub(
                cur[last.composition_after],
                gf::Mul(
                    cur[layout.zh.claim],
                    cur[last.quotient_after]));
        });
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

uint64_t CountConstraintViolations(
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
        const uint32_t next_row = (row + 1) % cs.n_rows;
        for (uint32_t column = 0;
             column < cs.n_columns;
             ++column) {
            current[column] = columns[column][row];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint : cs.constraints) {
            if (Applies(constraint.kind, row, cs.n_rows) &&
                !gf::IsZero(
                    constraint.eval(current, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

} // namespace

LayoutV1 CanonicalLayoutV1()
{
    LayoutV1 out;
    uint32_t next = 0;
    AllocateScalarPair(next, out.active);
    AllocateScalarPair(next, out.query_ordinal);
    AllocateScalarPair(next, out.range_ordinal);
    AllocateScalarPair(next, out.range_local_ordinal);
    AllocateScalarPair(next, out.y);
    AllocateScalarPair(next, out.zh);
    AllocateDigestPair(next, out.manifest_root);
    AllocateDigestPair(next, out.transcript_root);
    for (auto& leaf : out.leaves) {
        AllocateScalarPair(next, leaf.relation_ordinal);
        AllocateDigestPair(next, leaf.local_program_root);
        AllocateDigestPair(next, leaf.receipt_root);
        for (auto& column : leaf.manifest_root_alias) {
            column = next++;
        }
        for (auto& column : leaf.transcript_root_alias) {
            column = next++;
        }
        leaf.query_ordinal_alias = next++;
        leaf.range_ordinal_alias = next++;
        leaf.range_local_ordinal_alias = next++;
        leaf.y_alias = next++;
        leaf.zh_alias = next++;
        leaf.partial_composition = next++;
        leaf.partial_quotient = next++;
        leaf.composition_before = next++;
        leaf.composition_after = next++;
        leaf.quotient_before = next++;
        leaf.quotient_after = next++;
    }
    out.n_columns = next;
    return out;
}

ProductV1 BuildProductV1(const InputV1& input)
{
    ProductV1 out;
    out.input = input;
    out.layout = CanonicalLayoutV1();
    out.trace_rows = kTraceRowsV1;
    out.active_query_rows = kRealQueryRowsV1;
    out.scheduler_reserve_rows =
        kSchedulerReserveRowsV1;
    out.trace_columns = out.layout.n_columns;
    out.leaf_receipts = kLeafReceiptsV1;
    out.materialized_trace_cells =
        static_cast<uint64_t>(out.trace_rows) *
        out.trace_columns;
    auto fail = [&out](const std::string& detail) {
        out.valid = false;
        out.relation_leaf_receipt_payloads_verified =
            false;
        out.recursive_authority_ready = false;
        out.note =
            "stage3:v11_relation_qjoin:" + detail;
        return out;
    };

    if (!input.relation_plan.valid_foundation ||
        !input.relation_plan.exact_program_reassembly ||
        !input.relation_plan.symbolic_composition.valid ||
        input.relation_plan.fallback_query_shards !=
            kQueryRangesV1 ||
        input.relation_plan.fallback_queries_per_query_shard !=
            kQueriesPerRangeV1 ||
        input.relation_plan.fallback_leaf_receipts !=
            kLeafReceiptsV1) {
        return fail("relation_plan");
    }
    if (input.queries.size() !=
        kRealQueryRowsV1 ||
        !CanonicalDigest(
            input.full_q192_transcript_root) ||
        !CanonicalDigest(
            input.relation_plan.shard_manifest_root)) {
        return fail("input_shape_or_encoding");
    }
    for (uint32_t shard = 0;
         shard < kRelationShardsV1;
         ++shard) {
        if (input.relation_plan.shards[shard].ordinal !=
                shard ||
            !input.relation_plan.shards[shard].valid ||
            !CanonicalDigest(
                input.relation_plan.shards[shard]
                    .local_program_root)) {
            return fail("relation_shard");
        }
    }
    for (uint32_t range = 0;
         range < kQueryRangesV1;
         ++range) {
        for (uint32_t shard = 0;
             shard < kRelationShardsV1;
             ++shard) {
            if (!CanonicalDigest(
                    input.leaf_receipt_roots[range][shard])) {
                return fail("leaf_receipt_root_encoding");
            }
        }
    }
    for (uint32_t query = 0;
         query < kRealQueryRowsV1;
         ++query) {
        const auto& item = input.queries[query];
        if (item.query_ordinal != query ||
            !CanonicalFp3(item.y) ||
            !CanonicalFp3(item.zh)) {
            return fail("query_order_or_encoding");
        }
        for (uint32_t shard = 0;
             shard < kRelationShardsV1;
             ++shard) {
            if (!CanonicalFp3(
                    item.partial_compositions[shard]) ||
                !CanonicalFp3(
                    item.partial_quotients[shard])) {
                return fail("partial_encoding");
            }
        }
    }

    out.cs.n_rows = kTraceRowsV1;
    out.cs.n_columns = out.layout.n_columns;
    BuildConstraints(out.layout, out.cs);
    out.constraints =
        static_cast<uint32_t>(out.cs.constraints.size());
    for (const auto& constraint : out.cs.constraints) {
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
    auto set_pair = [&set](
                        const ScalarPairLayoutV1& pair,
                        uint32_t row,
                        const Fp3& value) {
        set(pair.claim, row, value);
        set(pair.expected, row, value);
    };
    auto set_digest_pair = [&set](
                               const DigestPairLayoutV1& pair,
                               uint32_t row,
                               const alg_hash::Digest& digest) {
        for (uint32_t limb = 0;
             limb < alg_hash::kAlgHashDigestLen;
             ++limb) {
            const Fp3 value =
                Fp3::FromFp(digest[limb]);
            set(pair.claim[limb], row, value);
            set(pair.expected[limb], row, value);
        }
    };

    for (uint32_t row = 0;
         row < kRealQueryRowsV1;
         ++row) {
        const uint32_t range =
            row / kQueriesPerRangeV1;
        const uint32_t local =
            row % kQueriesPerRangeV1;
        const auto& query = input.queries[row];
        set_pair(out.layout.active, row, Fp3::One());
        set_pair(
            out.layout.query_ordinal, row,
            Fp3::FromFp(gf::FromU64(row)));
        set_pair(
            out.layout.range_ordinal, row,
            Fp3::FromFp(gf::FromU64(range)));
        set_pair(
            out.layout.range_local_ordinal, row,
            Fp3::FromFp(gf::FromU64(local)));
        set_pair(out.layout.y, row, query.y);
        set_pair(out.layout.zh, row, query.zh);
        set_digest_pair(
            out.layout.manifest_root, row,
            input.relation_plan.shard_manifest_root);
        set_digest_pair(
            out.layout.transcript_root, row,
            input.full_q192_transcript_root);

        Fp3 composition = Fp3::Zero();
        Fp3 quotient = Fp3::Zero();
        for (uint32_t shard = 0;
             shard < kRelationShardsV1;
             ++shard) {
            const auto& leaf =
                out.layout.leaves[shard];
            set_pair(
                leaf.relation_ordinal, row,
                Fp3::FromFp(gf::FromU64(shard)));
            set_digest_pair(
                leaf.local_program_root, row,
                input.relation_plan.shards[shard]
                    .local_program_root);
            set_digest_pair(
                leaf.receipt_root, row,
                input.leaf_receipt_roots[range][shard]);
            for (uint32_t limb = 0;
                 limb < alg_hash::kAlgHashDigestLen;
                 ++limb) {
                set(
                    leaf.manifest_root_alias[limb],
                    row,
                    Fp3::FromFp(
                        input.relation_plan
                            .shard_manifest_root[limb]));
                set(
                    leaf.transcript_root_alias[limb],
                    row,
                    Fp3::FromFp(
                        input.full_q192_transcript_root[
                            limb]));
            }
            set(
                leaf.query_ordinal_alias, row,
                Fp3::FromFp(gf::FromU64(row)));
            set(
                leaf.range_ordinal_alias, row,
                Fp3::FromFp(gf::FromU64(range)));
            set(
                leaf.range_local_ordinal_alias, row,
                Fp3::FromFp(gf::FromU64(local)));
            set(leaf.y_alias, row, query.y);
            set(leaf.zh_alias, row, query.zh);
            set(
                leaf.partial_composition, row,
                query.partial_compositions[shard]);
            set(
                leaf.partial_quotient, row,
                query.partial_quotients[shard]);
            set(
                leaf.composition_before, row,
                composition);
            set(
                leaf.quotient_before, row,
                quotient);
            composition = gf::Add(
                composition,
                query.partial_compositions[shard]);
            quotient = gf::Add(
                quotient,
                query.partial_quotients[shard]);
            set(
                leaf.composition_after, row,
                composition);
            set(
                leaf.quotient_after, row,
                quotient);
        }
    }

    auto add_preprocessed_pair =
        [&out](const ScalarPairLayoutV1& pair) {
            out.preprocessed_columns.push_back(
                pair.expected);
        };
    auto add_preprocessed_digest =
        [&out](const DigestPairLayoutV1& pair) {
            for (uint32_t limb = 0;
                 limb < alg_hash::kAlgHashDigestLen;
                 ++limb) {
                out.preprocessed_columns.push_back(
                    pair.expected[limb]);
            }
        };
    add_preprocessed_pair(out.layout.active);
    add_preprocessed_pair(out.layout.query_ordinal);
    add_preprocessed_pair(out.layout.range_ordinal);
    add_preprocessed_pair(
        out.layout.range_local_ordinal);
    add_preprocessed_pair(out.layout.y);
    add_preprocessed_pair(out.layout.zh);
    add_preprocessed_digest(out.layout.manifest_root);
    add_preprocessed_digest(out.layout.transcript_root);
    for (const auto& leaf : out.layout.leaves) {
        add_preprocessed_pair(leaf.relation_ordinal);
        add_preprocessed_digest(leaf.local_program_root);
        add_preprocessed_digest(leaf.receipt_root);
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
        return fail("preprocessed_root:" + session.note);
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

    out.q64x3_production_safe_fallback =
        kQueryRangesV1 == 3 &&
        kQueriesPerRangeV1 == 64 &&
        out.scheduler_reserve_rows == 64;
    out.exact_q192_partition =
        out.active_query_rows == 192 &&
        kQueryRangesV1 * kQueriesPerRangeV1 ==
            out.active_query_rows;
    out.exact_relation_partition =
        input.relation_plan.symbolic_composition
            .coefficientwise_lambda_identity &&
        input.relation_plan.symbolic_composition
            .covered_terms ==
            input.relation_plan.full_programs;
    out.ordered_quotient_sum_identity =
        input.relation_plan.symbolic_composition
            .quotient_sum_identity;
    out.preprocessed_values_root_pinned = true;
    out.fiat_shamir_query_derivation_verified =
        false;
    out.relation_leaf_receipt_payloads_verified =
        false;
    out.recursive_authority_ready = false;
    out.violations =
        RecountViolationsV1(out, out.columns);
    out.valid =
        out.q64x3_production_safe_fallback &&
        out.exact_q192_partition &&
        out.exact_relation_partition &&
        out.ordered_quotient_sum_identity &&
        out.preprocessed_values_root_pinned &&
        out.violations == 0 &&
        !out.fiat_shamir_query_derivation_verified &&
        !out.relation_leaf_receipt_payloads_verified &&
        !out.recursive_authority_ready;
    out.note = out.valid
        ? "stage3:v11_relation_qjoin:"
          "q64x3_executable;"
          "fs_derivation_and_child_payloads_pending"
        : "stage3:v11_relation_qjoin:"
          "constraint_or_binding_failure";
    return out;
}

uint64_t RecountViolationsV1(
    const ProductV1& product,
    const std::vector<std::vector<Fp3>>& columns)
{
    uint64_t violations =
        CountConstraintViolations(
            product.cs, columns);
    if (violations ==
        std::numeric_limits<uint64_t>::max()) {
        return violations;
    }
    const auto session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            product.cs, columns,
            product.preprocessed_columns);
    if (!session.valid ||
        session.base_row_commitment !=
            product.preprocessed_row_group_root) {
        ++violations;
    }
    return violations;
}

ProveResultV1 ProveV1(
    const InputV1& input,
    const uint256& public_fs_seed)
{
    ProveResultV1 out;
    const auto product = BuildProductV1(input);
    out.preprocessed_row_group_root =
        product.preprocessed_row_group_root;
    if (!product.valid ||
        public_fs_seed.IsNull()) {
        out.note =
            "stage3:v11_relation_qjoin:prove:" +
            product.note;
        return out;
    }
    const auto begin =
        std::chrono::steady_clock::now();
    const auto proved =
        aq::AirQuotientProveRowsSplitRap(
            product.cs, product.columns,
            product.preprocessed_columns,
            public_fs_seed);
    out.prove_micros =
        std::chrono::duration_cast<
            std::chrono::microseconds>(
                std::chrono::steady_clock::now() -
                begin).count();
    if (!proved.ok ||
        !proved.division_exact ||
        proved.proof.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            proved.proof.batch.groups[0]
                .row_commit.root) !=
            product.preprocessed_row_group_root) {
        out.note =
            "stage3:v11_relation_qjoin:prove:" +
            proved.note;
        return out;
    }
    std::vector<unsigned char> wire;
    const size_t bytes =
        aq::SerializeAirQuotientSplitRapRowsProof(
            proved.proof, wire);
    if (bytes == 0 ||
        bytes != wire.size()) {
        out.note =
            "stage3:v11_relation_qjoin:prove:serialize";
        return out;
    }
    out.proof = proved.proof;
    out.proof_wire_bytes = bytes;
    out.ok = true;
    out.note =
        "stage3:v11_relation_qjoin:prove:q64x3";
    return out;
}

VerifyResultV1 VerifyV1(
    const InputV1& input,
    const aq::AirQuotientSplitRapRowsProof& proof,
    const uint256& public_fs_seed)
{
    VerifyResultV1 out;
    const auto product = BuildProductV1(input);
    if (!product.valid ||
        public_fs_seed.IsNull()) {
        out.note =
            "stage3:v11_relation_qjoin:verify:" +
            product.note;
        return out;
    }
    std::string why;
    const auto begin =
        std::chrono::steady_clock::now();
    out.accepted =
        aq::AirQuotientVerifyRowsSplitRap(
            product.cs, proof,
            product.preprocessed_columns,
            public_fs_seed, &why);
    out.verify_micros =
        std::chrono::duration_cast<
            std::chrono::microseconds>(
                std::chrono::steady_clock::now() -
                begin).count();
    if (out.accepted &&
        (proof.batch.groups.empty() ||
         Fri3AlgDigestToUint256(
             proof.batch.groups[0]
                 .row_commit.root) !=
             product.preprocessed_row_group_root)) {
        out.accepted = false;
        why = "preprocessed_row_group_root";
    }
    out.relation_leaf_receipt_payloads_verified =
        false;
    out.recursive_authority_ready = false;
    out.note = out.accepted
        ? "stage3:v11_relation_qjoin:verify:"
          "q64x3;child_payloads_pending"
        : "stage3:v11_relation_qjoin:verify:" + why;
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_relation_quotient_join
