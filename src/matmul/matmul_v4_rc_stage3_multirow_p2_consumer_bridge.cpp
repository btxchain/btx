// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_p2_consumer_bridge.h>

#include <algorithm>
#include <functional>
#include <limits>
#include <set>

namespace matmul::v4::rc::stage3_multirow_p2_consumer_bridge {
namespace {

using gf::Fp;
using gf::Fp3;

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

bool PowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
}

uint32_t Log2Exact(uint32_t value)
{
    if (!PowerOfTwo(value)) return 0;
    uint32_t out = 0;
    while (value > 1) {
        value >>= 1;
        ++out;
    }
    return out;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    uint32_t out = 2;
    while (out < value) {
        if (out > std::numeric_limits<uint32_t>::max() / 2) return 0;
        out <<= 1;
    }
    return out;
}

Fp3 SourceValue(const LayoutV1& layout, const std::vector<Fp3>& row)
{
    return {
        gf::Canonical(row[layout.SourceCoord(0)].c0),
        gf::Canonical(row[layout.SourceCoord(1)].c0),
        gf::Canonical(row[layout.SourceCoord(2)].c0)};
}

void AddConstraint(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name, aq::AirKind kind, uint32_t degree,
    std::function<Fp3(const std::vector<Fp3>&,
                      const std::vector<Fp3>&)> eval)
{
    aq::AirConstraint<Fp3> constraint;
    constraint.name = name;
    constraint.kind = kind;
    constraint.alg_degree = degree;
    constraint.eval = std::move(eval);
    cs.constraints.push_back(std::move(constraint));
}

void AddBoolean(aq::AirConstraintSystem<Fp3>& cs,
                const char* name, uint32_t column)
{
    AddConstraint(
        cs, name, aq::AirKind::kEverywhere, 2,
        [column](const auto& cur, const auto&) {
            return gf::Mul(
                cur[column], gf::Sub(cur[column], Fp3::One()));
        });
}

void AddNonzero(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* inverse_name,
    const char* zero_name,
    uint32_t value_column,
    uint32_t nonzero_column,
    uint32_t inverse_column)
{
    AddBoolean(cs, "stage3.multirow_consumer.nonzero_boolean",
               nonzero_column);
    AddConstraint(
        cs, inverse_name, aq::AirKind::kEverywhere, 2,
        [value_column, nonzero_column, inverse_column](
            const auto& cur, const auto&) {
            return gf::Sub(
                gf::Mul(cur[value_column], cur[inverse_column]),
                cur[nonzero_column]);
        });
    AddConstraint(
        cs, zero_name, aq::AirKind::kEverywhere, 2,
        [value_column, nonzero_column](
            const auto& cur, const auto&) {
            return gf::Mul(
                cur[value_column],
                gf::Sub(Fp3::One(), cur[nonzero_column]));
        });
}

void BuildConstraints(const LayoutV1& l, uint32_t n_lde,
                      const Fp3& expected_z1,
                      const Fp3& expected_z2,
                      aq::AirConstraintSystem<Fp3>& cs)
{
    const uint32_t domain_log = Log2Exact(n_lde);
    for (uint32_t column :
         {l.active, l.ood_active, l.query_active,
          l.coefficient_active, l.candidate_first,
          l.ood_z1_active, l.ood_z2_active,
          l.distinct_required, l.candidate_valid,
          l.candidate_prior_valid, l.candidate_selected}) {
        AddBoolean(cs, "stage3.multirow_consumer.boolean", column);
    }
    AddConstraint(
        cs, "stage3.multirow_consumer.selector_one_hot",
        aq::AirKind::kEverywhere, 1,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.active],
                gf::Add(
                    cur[l.ood_active],
                    gf::Add(
                        cur[l.query_active],
                        cur[l.coefficient_active])));
        });

    AddConstraint(
        cs, "stage3.multirow_consumer.selected_z1_claim",
        aq::AirKind::kFirstRow, 1,
        [l, expected_z1](const auto& cur, const auto&) {
            return gf::Sub(cur[l.selected_z1], expected_z1);
        });
    AddConstraint(
        cs, "stage3.multirow_consumer.selected_z2_claim",
        aq::AirKind::kFirstRow, 1,
        [l, expected_z2](const auto& cur, const auto&) {
            return gf::Sub(cur[l.selected_z2], expected_z2);
        });
    for (uint32_t column : {l.selected_z1, l.selected_z2}) {
        AddConstraint(
            cs, "stage3.multirow_consumer.selected_ood_constant",
            aq::AirKind::kTransition, 1,
            [column](const auto& cur, const auto& next) {
                return gf::Sub(next[column], cur[column]);
            });
    }

    AddConstraint(
        cs, "stage3.multirow_consumer.pow_start",
        aq::AirKind::kEverywhere, 1,
        [l](const auto& cur, const auto&) {
            return gf::Sub(cur[l.Pow(0)], SourceValue(l, cur));
        });
    for (uint32_t step = 1; step <= kMaxDomainLogV1; ++step) {
        AddConstraint(
            cs, "stage3.multirow_consumer.pow_square",
            aq::AirKind::kEverywhere, 2,
            [l, step](const auto& cur, const auto&) {
                return gf::Sub(
                    cur[l.Pow(step)],
                    gf::Mul(cur[l.Pow(step - 1)],
                            cur[l.Pow(step - 1)]));
            });
    }

    AddNonzero(cs, "stage3.multirow_consumer.c1_inverse",
               "stage3.multirow_consumer.c1_zero",
               l.SourceCoord(1), l.c1_nonzero, l.c1_inverse);
    AddNonzero(cs, "stage3.multirow_consumer.c2_inverse",
               "stage3.multirow_consumer.c2_zero",
               l.SourceCoord(2), l.c2_nonzero, l.c2_inverse);
    AddConstraint(
        cs, "stage3.multirow_consumer.extension_nonzero",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.ext_nonzero],
                gf::Sub(
                    gf::Add(cur[l.c1_nonzero], cur[l.c2_nonzero]),
                    gf::Mul(cur[l.c1_nonzero], cur[l.c2_nonzero])));
        });
    AddBoolean(cs, "stage3.multirow_consumer.ext_boolean", l.ext_nonzero);

    AddConstraint(
        cs, "stage3.multirow_consumer.domain_inverse",
        aq::AirKind::kEverywhere, 2,
        [l, domain_log](const auto& cur, const auto&) {
            const Fp3 delta =
                gf::Sub(cur[l.Pow(domain_log)], Fp3::One());
            return gf::Sub(
                gf::Mul(delta, cur[l.domain_inverse]),
                cur[l.domain_nonzero]);
        });
    AddConstraint(
        cs, "stage3.multirow_consumer.domain_zero_case",
        aq::AirKind::kEverywhere, 2,
        [l, domain_log](const auto& cur, const auto&) {
            return gf::Mul(
                gf::Sub(cur[l.Pow(domain_log)], Fp3::One()),
                gf::Sub(Fp3::One(), cur[l.domain_nonzero]));
        });
    AddBoolean(cs, "stage3.multirow_consumer.domain_boolean",
               l.domain_nonzero);

    AddConstraint(
        cs, "stage3.multirow_consumer.distinct_inverse",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            const Fp3 delta =
                gf::Sub(SourceValue(l, cur), cur[l.selected_z1]);
            return gf::Sub(
                gf::Mul(delta, cur[l.distinct_inverse]),
                cur[l.distinct_nonzero]);
        });
    AddConstraint(
        cs, "stage3.multirow_consumer.distinct_zero_case",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                gf::Sub(SourceValue(l, cur), cur[l.selected_z1]),
                gf::Sub(Fp3::One(), cur[l.distinct_nonzero]));
        });
    AddBoolean(cs, "stage3.multirow_consumer.distinct_boolean",
               l.distinct_nonzero);
    AddConstraint(
        cs, "stage3.multirow_consumer.ood_base_valid",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.ood_base_valid],
                gf::Mul(cur[l.ext_nonzero], cur[l.domain_nonzero]));
        });
    AddConstraint(
        cs, "stage3.multirow_consumer.distinct_gate",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.distinct_gate],
                gf::Add(
                    gf::Sub(Fp3::One(), cur[l.distinct_required]),
                    gf::Mul(cur[l.distinct_required],
                            cur[l.distinct_nonzero])));
        });
    AddConstraint(
        cs, "stage3.multirow_consumer.ood_valid",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.ood_valid],
                gf::Mul(cur[l.ood_base_valid], cur[l.distinct_gate]));
        });

    for (uint32_t bit = 0; bit < kRawBitsV1; ++bit) {
        AddBoolean(cs, "stage3.multirow_consumer.raw_bit",
                   l.RawBit(bit));
    }
    AddConstraint(
        cs, "stage3.multirow_consumer.raw_recompose",
        aq::AirKind::kEverywhere, 1,
        [l](const auto& cur, const auto&) {
            Fp3 sum = Fp3::Zero();
            Fp3 power = Fp3::One();
            for (uint32_t bit = 0; bit < kRawBitsV1; ++bit) {
                sum = gf::Add(sum, gf::Mul(power, cur[l.RawBit(bit)]));
                power = gf::Add(power, power);
            }
            return gf::Sub(cur[l.SourceCoord(0)], sum);
        });
    AddConstraint(
        cs, "stage3.multirow_consumer.raw_low",
        aq::AirKind::kEverywhere, 1,
        [l](const auto& cur, const auto&) {
            Fp3 sum = Fp3::Zero();
            Fp3 power = Fp3::One();
            for (uint32_t bit = 0; bit < 32; ++bit) {
                sum = gf::Add(sum, gf::Mul(power, cur[l.RawBit(bit)]));
                power = gf::Add(power, power);
            }
            return gf::Sub(cur[l.raw_low], sum);
        });
    AddNonzero(cs, "stage3.multirow_consumer.low_inverse",
               "stage3.multirow_consumer.low_zero",
               l.raw_low, l.raw_low_nonzero, l.raw_low_inverse);
    for (uint32_t bit = 0; bit < kHighAndV1; ++bit) {
        AddConstraint(
            cs, "stage3.multirow_consumer.high_and",
            aq::AirKind::kEverywhere, bit == 0 ? 1 : 2,
            [l, bit](const auto& cur, const auto&) {
                const Fp3 expected = bit == 0
                    ? cur[l.RawBit(32)]
                    : gf::Mul(cur[l.HighAnd(bit - 1)],
                              cur[l.RawBit(32 + bit)]);
                return gf::Sub(cur[l.HighAnd(bit)], expected);
            });
    }
    AddConstraint(
        cs, "stage3.multirow_consumer.goldilocks_canonical",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.HighAnd(kHighAndV1 - 1)],
                cur[l.raw_low_nonzero]);
        });

    AddConstraint(
        cs, "stage3.multirow_consumer.raw_nonminusone_inverse",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            const Fp3 value =
                gf::Add(cur[l.SourceCoord(0)], Fp3::One());
            return gf::Sub(
                gf::Mul(value, cur[l.raw_nonminusone_inverse]),
                cur[l.raw_nonminusone]);
        });
    AddConstraint(
        cs, "stage3.multirow_consumer.raw_nonminusone_zero",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                gf::Add(cur[l.SourceCoord(0)], Fp3::One()),
                gf::Sub(Fp3::One(), cur[l.raw_nonminusone]));
        });
    AddBoolean(cs, "stage3.multirow_consumer.raw_nonminusone_boolean",
               l.raw_nonminusone);
    AddConstraint(
        cs, "stage3.multirow_consumer.query_index_bits",
        aq::AirKind::kEverywhere, 1,
        [l, domain_log](const auto& cur, const auto&) {
            Fp3 sum = Fp3::Zero();
            Fp3 power = Fp3::One();
            for (uint32_t bit = 0; bit < domain_log; ++bit) {
                sum = gf::Add(sum, gf::Mul(power, cur[l.RawBit(bit)]));
                power = gf::Add(power, power);
            }
            return gf::Sub(cur[l.candidate_index], sum);
        });

    AddConstraint(
        cs, "stage3.multirow_consumer.candidate_valid_kind",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.candidate_valid],
                gf::Add(
                    gf::Mul(cur[l.query_active],
                            cur[l.raw_nonminusone]),
                    gf::Mul(cur[l.ood_active], cur[l.ood_valid])));
        });
    AddConstraint(
        cs, "stage3.multirow_consumer.first_prior_zero",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.candidate_first],
                cur[l.candidate_prior_valid]);
        });
    AddConstraint(
        cs, "stage3.multirow_consumer.prior_link",
        aq::AirKind::kTransition, 2,
        [l](const auto& cur, const auto& next) {
            return gf::Mul(
                cur[l.candidate_first],
                gf::Sub(next[l.candidate_prior_valid],
                        cur[l.candidate_valid]));
        });
    AddConstraint(
        cs, "stage3.multirow_consumer.first_valid_selection",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Sub(
                cur[l.candidate_selected],
                gf::Mul(
                    cur[l.candidate_valid],
                    gf::Sub(Fp3::One(),
                            cur[l.candidate_prior_valid])));
        });
    AddConstraint(
        cs, "stage3.multirow_consumer.k2_exactly_one",
        aq::AirKind::kTransition, 2,
        [l](const auto& cur, const auto& next) {
            return gf::Mul(
                cur[l.candidate_first],
                gf::Sub(
                    gf::Add(cur[l.candidate_selected],
                            next[l.candidate_selected]),
                    Fp3::One()));
        });
    AddConstraint(
        cs, "stage3.multirow_consumer.selected_value",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.candidate_selected],
                gf::Sub(SourceValue(l, cur), cur[l.consumer_value]));
        });
    AddConstraint(
        cs, "stage3.multirow_consumer.selected_index",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.candidate_selected],
                gf::Sub(cur[l.candidate_index], cur[l.consumer_index]));
        });
    AddConstraint(
        cs, "stage3.multirow_consumer.pair_consumer_index",
        aq::AirKind::kTransition, 2,
        [l](const auto& cur, const auto& next) {
            return gf::Mul(
                cur[l.candidate_first],
                gf::Sub(next[l.consumer_index], cur[l.consumer_index]));
        });
    AddConstraint(
        cs, "stage3.multirow_consumer.z1_consumer",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.ood_z1_active],
                gf::Sub(cur[l.consumer_value], cur[l.selected_z1]));
        });
    AddConstraint(
        cs, "stage3.multirow_consumer.z2_consumer",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.ood_z2_active],
                gf::Sub(cur[l.consumer_value], cur[l.selected_z2]));
        });
    AddConstraint(
        cs, "stage3.multirow_consumer.coefficient_value",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.coefficient_active],
                gf::Sub(cur[l.consumer_value], SourceValue(l, cur)));
        });
    AddConstraint(
        cs, "stage3.multirow_consumer.coefficient_label",
        aq::AirKind::kEverywhere, 2,
        [l](const auto& cur, const auto&) {
            return gf::Mul(
                cur[l.coefficient_active],
                gf::Sub(cur[l.consumer_index], cur[l.schedule_index]));
        });
}

bool Applies(aq::AirKind kind, uint32_t row, uint32_t rows)
{
    switch (kind) {
    case aq::AirKind::kEverywhere: return true;
    case aq::AirKind::kTransition: return row + 1 < rows;
    case aq::AirKind::kFirstRow: return row == 0;
    case aq::AirKind::kLastRow: return row + 1 == rows;
    }
    return false;
}

struct ScheduleRow {
    Fp3 source{};
    Fp3 consumer_value{};
    uint32_t consumer_index{0};
    uint32_t schedule_index{0};
    bool active{false};
    bool ood{false};
    bool query{false};
    bool coefficient{false};
    bool first{false};
    bool z1{false};
    bool z2{false};
    bool distinct_required{false};
};

Fp3 Pow2Chain(Fp3 value, uint32_t step)
{
    for (uint32_t i = 0; i < step; ++i) value = gf::Mul(value, value);
    return value;
}

} // namespace

LayoutV1 CanonicalLayoutV1()
{
    LayoutV1 out;
    uint32_t cursor = 0;
    out.source_coord_base = cursor;
    cursor += 3;
    out.consumer_value = cursor++;
    out.consumer_index = cursor++;
    out.schedule_index = cursor++;
    out.active = cursor++;
    out.ood_active = cursor++;
    out.query_active = cursor++;
    out.coefficient_active = cursor++;
    out.candidate_first = cursor++;
    out.ood_z1_active = cursor++;
    out.ood_z2_active = cursor++;
    out.distinct_required = cursor++;
    out.candidate_valid = cursor++;
    out.candidate_prior_valid = cursor++;
    out.candidate_selected = cursor++;
    out.selected_z1 = cursor++;
    out.selected_z2 = cursor++;
    out.pow_base = cursor;
    cursor += kMaxDomainLogV1 + 1;
    out.c1_nonzero = cursor++;
    out.c1_inverse = cursor++;
    out.c2_nonzero = cursor++;
    out.c2_inverse = cursor++;
    out.ext_nonzero = cursor++;
    out.domain_nonzero = cursor++;
    out.domain_inverse = cursor++;
    out.distinct_nonzero = cursor++;
    out.distinct_inverse = cursor++;
    out.ood_base_valid = cursor++;
    out.distinct_gate = cursor++;
    out.ood_valid = cursor++;
    out.raw_bit_base = cursor;
    cursor += kRawBitsV1;
    out.high_and_base = cursor;
    cursor += kHighAndV1;
    out.raw_low = cursor++;
    out.raw_low_nonzero = cursor++;
    out.raw_low_inverse = cursor++;
    out.raw_nonminusone = cursor++;
    out.raw_nonminusone_inverse = cursor++;
    out.candidate_index = cursor++;
    out.n_columns = cursor;
    return out;
}

CanonicalRawAuditV1 AuditCanonicalRawV1(
    Fp field_value, uint64_t bits_source)
{
    CanonicalRawAuditV1 out;
    out.field_value = gf::Canonical(field_value);
    out.bits_source = bits_source;
    if (gf::Canonical(gf::FromU64(bits_source)) != out.field_value) {
        ++out.violations;
    }
    const uint64_t low = bits_source & 0xffffffffULL;
    const uint64_t high = bits_source >> 32;
    if (high == 0xffffffffULL && low != 0) ++out.violations;
    out.valid = out.violations == 0;
    return out;
}

uint64_t RecountViolationsV1(
    const ProductV1& product,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != product.cs.n_columns) {
        return std::numeric_limits<uint64_t>::max();
    }
    std::vector<Fp3> cur(product.cs.n_columns);
    std::vector<Fp3> next(product.cs.n_columns);
    uint64_t violations = 0;
    for (uint32_t row = 0; row < product.cs.n_rows; ++row) {
        for (uint32_t column = 0; column < product.cs.n_columns; ++column) {
            if (columns[column].size() != product.cs.n_rows) {
                return std::numeric_limits<uint64_t>::max();
            }
            cur[column] = columns[column][row];
            next[column] = columns[column][(row + 1) % product.cs.n_rows];
        }
        for (const auto& constraint : product.cs.constraints) {
            if (Applies(constraint.kind, row, product.cs.n_rows) &&
                !gf::IsZero(constraint.eval(cur, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

std::string FirstViolation(
    const ProductV1& product,
    const std::vector<std::vector<Fp3>>& columns)
{
    std::vector<Fp3> cur(product.cs.n_columns);
    std::vector<Fp3> next(product.cs.n_columns);
    for (uint32_t row = 0; row < product.cs.n_rows; ++row) {
        for (uint32_t column = 0; column < product.cs.n_columns; ++column) {
            cur[column] = columns[column][row];
            next[column] = columns[column][(row + 1) % product.cs.n_rows];
        }
        for (const auto& constraint : product.cs.constraints) {
            if (Applies(constraint.kind, row, product.cs.n_rows) &&
                !gf::IsZero(constraint.eval(cur, next))) {
                return std::string{constraint.name} +
                    ":row=" + std::to_string(row);
            }
        }
    }
    return {};
}

ProductV1 BuildProductV1(const tp::ProductV1& transcript)
{
    ProductV1 out;
    out.layout = CanonicalLayoutV1();
    out.transcript_receipt = transcript.receipt;
    std::string receipt_why;
    if (!transcript.valid ||
        !tp::VerifyReceiptV1(
            transcript.statement, transcript.receipt, &receipt_why)) {
        out.note = "stage3:multirow_consumer:transcript:" + receipt_why;
        return out;
    }
    const uint32_t n_lde =
        transcript.statement.n_coeffs * transcript.statement.blowup;
    const uint32_t domain_log = Log2Exact(n_lde);
    if (domain_log == 0 || domain_log > kMaxDomainLogV1) {
        out.note = "stage3:multirow_consumer:domain";
        return out;
    }

    std::vector<ScheduleRow> schedule;
    schedule.reserve(
        4 + tp::kQueriesV1 * tp::kQueryCandidatesV1 +
        transcript.receipt.batching_coefficients.size());
    const uint32_t z1_consumer_index = static_cast<uint32_t>(
        gf::Canonical(transcript.receipt.z1.c0) & (n_lde - 1));
    const uint32_t z2_consumer_index = static_cast<uint32_t>(
        gf::Canonical(transcript.receipt.z2.c0) & (n_lde - 1));
    for (uint32_t candidate = 0; candidate < tp::kOodCandidatesV1;
         ++candidate) {
        schedule.push_back({
            transcript.receipt.z1_candidates[candidate],
            transcript.receipt.z1, z1_consumer_index, candidate,
            true, true, false,
            false, candidate == 0, true, false, false});
    }
    for (uint32_t candidate = 0; candidate < tp::kOodCandidatesV1;
         ++candidate) {
        schedule.push_back({
            transcript.receipt.z2_candidates[candidate],
            transcript.receipt.z2, z2_consumer_index, candidate,
            true, true, false,
            false, candidate == 0, false, true, true});
    }
    for (uint32_t query = 0; query < tp::kQueriesV1; ++query) {
        const auto& q = transcript.receipt.queries[query];
        const Fp3 selected = Fp3::FromFp(
            q.candidate_digest[q.selected_ordinal][0]);
        for (uint32_t candidate = 0;
             candidate < tp::kQueryCandidatesV1; ++candidate) {
            schedule.push_back({
                Fp3::FromFp(q.candidate_digest[candidate][0]),
                selected, q.index, query, true, false, true, false,
                candidate == 0, false, false, false});
        }
    }
    for (uint32_t coefficient = 0;
         coefficient < transcript.receipt.batching_coefficients.size();
         ++coefficient) {
        schedule.push_back({
            transcript.receipt.batching_coefficients[coefficient],
            transcript.receipt.batching_coefficients[coefficient],
            coefficient, coefficient, true, false, false, true,
            false, false, false, false});
    }
    out.real_rows = static_cast<uint32_t>(schedule.size());
    out.trace_rows = NextPowerOfTwo(out.real_rows);
    if (out.trace_rows == 0) {
        out.note = "stage3:multirow_consumer:rows";
        return out;
    }
    schedule.resize(out.trace_rows);

    out.cs.n_rows = out.trace_rows;
    out.cs.n_columns = out.layout.n_columns;
    BuildConstraints(
        out.layout, n_lde, transcript.receipt.z1,
        transcript.receipt.z2, out.cs);
    out.constraints = static_cast<uint32_t>(out.cs.constraints.size());
    for (const auto& constraint : out.cs.constraints) {
        out.max_constraint_degree =
            std::max(out.max_constraint_degree, constraint.alg_degree);
    }
    out.columns.assign(
        out.layout.n_columns,
        std::vector<Fp3>(out.trace_rows, Fp3::Zero()));
    auto set = [&out](uint32_t column, uint32_t row, const Fp3& value) {
        out.columns[column][row] = value;
    };

    const auto nonzero = [](const Fp3& value) {
        return !gf::IsZero(value);
    };
    bool pair_prior = false;
    for (uint32_t row = 0; row < out.trace_rows; ++row) {
        const auto& s = schedule[row];
        set(out.layout.SourceCoord(0), row, Fp3::FromFp(s.source.c0));
        set(out.layout.SourceCoord(1), row, Fp3::FromFp(s.source.c1));
        set(out.layout.SourceCoord(2), row, Fp3::FromFp(s.source.c2));
        set(out.layout.consumer_value, row, s.consumer_value);
        set(out.layout.consumer_index, row, U(s.consumer_index));
        set(out.layout.schedule_index, row, U(s.schedule_index));
        set(out.layout.active, row, s.active ? Fp3::One() : Fp3::Zero());
        set(out.layout.ood_active, row, s.ood ? Fp3::One() : Fp3::Zero());
        set(out.layout.query_active, row, s.query ? Fp3::One() : Fp3::Zero());
        set(out.layout.coefficient_active, row,
            s.coefficient ? Fp3::One() : Fp3::Zero());
        set(out.layout.candidate_first, row,
            s.first ? Fp3::One() : Fp3::Zero());
        set(out.layout.ood_z1_active, row, s.z1 ? Fp3::One() : Fp3::Zero());
        set(out.layout.ood_z2_active, row, s.z2 ? Fp3::One() : Fp3::Zero());
        set(out.layout.distinct_required, row,
            s.distinct_required ? Fp3::One() : Fp3::Zero());
        set(out.layout.selected_z1, row, transcript.receipt.z1);
        set(out.layout.selected_z2, row, transcript.receipt.z2);
        for (uint32_t step = 0; step <= kMaxDomainLogV1; ++step) {
            set(out.layout.Pow(step), row, Pow2Chain(s.source, step));
        }
        const bool c1_nz = gf::Canonical(s.source.c1) != 0;
        const bool c2_nz = gf::Canonical(s.source.c2) != 0;
        set(out.layout.c1_nonzero, row,
            c1_nz ? Fp3::One() : Fp3::Zero());
        set(out.layout.c1_inverse, row,
            c1_nz ? gf::Inv(Fp3::FromFp(s.source.c1)) : Fp3::Zero());
        set(out.layout.c2_nonzero, row,
            c2_nz ? Fp3::One() : Fp3::Zero());
        set(out.layout.c2_inverse, row,
            c2_nz ? gf::Inv(Fp3::FromFp(s.source.c2)) : Fp3::Zero());
        const bool ext_nz = c1_nz || c2_nz;
        set(out.layout.ext_nonzero, row,
            ext_nz ? Fp3::One() : Fp3::Zero());
        const Fp3 domain_delta =
            gf::Sub(Pow2Chain(s.source, domain_log), Fp3::One());
        const bool domain_nz = nonzero(domain_delta);
        set(out.layout.domain_nonzero, row,
            domain_nz ? Fp3::One() : Fp3::Zero());
        set(out.layout.domain_inverse, row,
            domain_nz ? gf::Inv(domain_delta) : Fp3::Zero());
        const Fp3 distinct_delta =
            gf::Sub(s.source, transcript.receipt.z1);
        const bool distinct_nz = nonzero(distinct_delta);
        set(out.layout.distinct_nonzero, row,
            distinct_nz ? Fp3::One() : Fp3::Zero());
        set(out.layout.distinct_inverse, row,
            distinct_nz ? gf::Inv(distinct_delta) : Fp3::Zero());
        const bool ood_base = ext_nz && domain_nz;
        const bool distinct_gate =
            !s.distinct_required || distinct_nz;
        const bool ood_valid = ood_base && distinct_gate;
        set(out.layout.ood_base_valid, row,
            ood_base ? Fp3::One() : Fp3::Zero());
        set(out.layout.distinct_gate, row,
            distinct_gate ? Fp3::One() : Fp3::Zero());
        set(out.layout.ood_valid, row,
            ood_valid ? Fp3::One() : Fp3::Zero());

        const uint64_t raw = gf::Canonical(s.source.c0);
        for (uint32_t bit = 0; bit < kRawBitsV1; ++bit) {
            set(out.layout.RawBit(bit), row,
                ((raw >> bit) & 1U) != 0
                ? Fp3::One() : Fp3::Zero());
        }
        bool high_and = true;
        for (uint32_t bit = 0; bit < kHighAndV1; ++bit) {
            high_and =
                high_and && ((raw >> (32 + bit)) & 1U) != 0;
            set(out.layout.HighAnd(bit), row,
                high_and ? Fp3::One() : Fp3::Zero());
        }
        const uint32_t low = static_cast<uint32_t>(raw);
        const bool low_nz = low != 0;
        set(out.layout.raw_low, row, U(low));
        set(out.layout.raw_low_nonzero, row,
            low_nz ? Fp3::One() : Fp3::Zero());
        set(out.layout.raw_low_inverse, row,
            low_nz ? gf::Inv(U(low)) : Fp3::Zero());
        const bool raw_valid = raw != gf::kP - 1;
        set(out.layout.raw_nonminusone, row,
            raw_valid ? Fp3::One() : Fp3::Zero());
        set(out.layout.raw_nonminusone_inverse, row,
            raw_valid
            ? gf::Inv(gf::Add(U(raw), Fp3::One()))
            : Fp3::Zero());
        const uint32_t candidate_index =
            static_cast<uint32_t>(raw) & (n_lde - 1);
        set(out.layout.candidate_index, row, U(candidate_index));

        const bool candidate_valid =
            s.query ? raw_valid : (s.ood ? ood_valid : false);
        if (s.first) pair_prior = false;
        set(out.layout.candidate_prior_valid, row,
            pair_prior ? Fp3::One() : Fp3::Zero());
        const bool selected = candidate_valid && !pair_prior;
        set(out.layout.candidate_valid, row,
            candidate_valid ? Fp3::One() : Fp3::Zero());
        set(out.layout.candidate_selected, row,
            selected ? Fp3::One() : Fp3::Zero());
        if (s.ood || s.query) pair_prior = pair_prior || candidate_valid;
        else pair_prior = true;
    }

    for (uint32_t column :
         {out.layout.SourceCoord(0), out.layout.SourceCoord(1),
          out.layout.SourceCoord(2), out.layout.schedule_index,
          out.layout.active, out.layout.ood_active,
          out.layout.query_active, out.layout.coefficient_active,
          out.layout.candidate_first, out.layout.ood_z1_active,
          out.layout.ood_z2_active, out.layout.distinct_required}) {
        out.preprocessed_columns.push_back(column);
        out.cs.preprocessed.emplace_back(column, out.columns[column]);
    }
    out.cs.preprocessed_pin_ood = true;
    const auto session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns, out.preprocessed_columns);
    if (!session.valid || session.base_row_commitment.IsNull()) {
        out.note = "stage3:multirow_consumer:preprocessed:" + session.note;
        return out;
    }
    out.preprocessed_row_group_root = session.base_row_commitment;
    out.cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role = aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns = out.preprocessed_columns,
        .root = out.preprocessed_row_group_root,
    });
    out.violations = RecountViolationsV1(out, out.columns);
    std::set<uint32_t> distinct_queries;
    for (const auto& query : transcript.receipt.queries) {
        distinct_queries.insert(query.index);
    }
    out.duplicate_query_count =
        tp::kQueriesV1 - distinct_queries.size();
    out.transcript_receipt_verified = true;
    out.transcript_event_cells_schedule_bound = true;
    out.k2_ood_first_valid_air_constrained = true;
    out.q192_first_valid_air_constrained = true;
    out.q192_index_decomposition_canonical = true;
    out.q192_selected_index_consumer_equal = true;
    out.duplicate_queries_permitted = true;
    out.independent_coefficient_consumer_equal = true;
    out.coefficient_labels_bound = true;
    out.proof_owned_consumer_cells = true;
    out.same_parent_event_cell_aliases = false;
    out.backend_v11_codec_executable = false;
    out.production_authority_ready = false;
    out.valid =
        out.violations == 0 &&
        out.transcript_receipt_verified &&
        out.transcript_event_cells_schedule_bound &&
        out.k2_ood_first_valid_air_constrained &&
        out.q192_first_valid_air_constrained &&
        out.q192_index_decomposition_canonical &&
        out.q192_selected_index_consumer_equal &&
        out.duplicate_queries_permitted &&
        out.independent_coefficient_consumer_equal &&
        out.coefficient_labels_bound &&
        out.proof_owned_consumer_cells &&
        !out.same_parent_event_cell_aliases &&
        !out.backend_v11_codec_executable &&
        !out.production_authority_ready;
    out.note = out.valid
        ? "stage3:multirow_consumer:selection_and_consumers_constrained;"
          "same_parent_backend_alias_pending"
        : "stage3:multirow_consumer:constraint_failure:" +
          FirstViolation(out, out.columns);
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_p2_consumer_bridge
