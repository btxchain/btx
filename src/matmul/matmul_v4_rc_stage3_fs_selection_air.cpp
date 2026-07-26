// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_fs_selection_air.h>

#include <algorithm>

namespace matmul::v4::rc::stage3_fs_selection_air {
namespace {

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:fs_selection_air:" + detail;
    }
    return false;
}

gf::Fp3 Recompose(
    const std::vector<gf::Fp3>& row,
    const LayoutV1& layout,
    uint32_t word,
    uint32_t begin,
    uint32_t bits)
{
    gf::Fp3 value = gf::Fp3::Zero();
    gf::Fp3 power = gf::Fp3::One();
    for (uint32_t bit = 0; bit < bits; ++bit) {
        value = gf::Add(
            value,
            gf::Mul(
                power,
                row[layout.Bit(
                    word, begin + bit)]));
        power = gf::Add(power, power);
    }
    return value;
}

gf::Fp3 Candidate(
    const std::vector<gf::Fp3>& row,
    const LayoutV1& layout,
    uint32_t word)
{
    const gf::Fp3 low =
        Recompose(row, layout, word, 0, 32);
    const gf::Fp3 high =
        Recompose(row, layout, word, 32, 32);
    return gf::Add(
        low,
        gf::Mul(
            high,
            gf::Fp3::FromFp(
                gf::FromU64(
                    UINT64_C(1) << 32))));
}

} // namespace

bool BuildConstraintSystemV1(
    uint32_t n_rows,
    aq::AirConstraintSystem<gf::Fp3>& out,
    std::string* why)
{
    out = {};
    if (n_rows < 2 ||
        (n_rows & (n_rows - 1)) != 0) {
        return Fail(why, "rows");
    }
    const LayoutV1 layout;
    out.n_rows = n_rows;
    out.n_columns = layout.End();
    out.preprocessed_pin_ood = true;

    const auto append =
        [&out](aq::AirConstraint<gf::Fp3> constraint) {
            out.constraints.push_back(
                std::move(constraint));
        };
    for (uint32_t word = 0;
         word < kCandidateWords; ++word) {
        for (uint32_t bit = 0;
             bit < kWordBits; ++bit) {
            aq::AirConstraint<gf::Fp3> boolean;
            boolean.name =
                "stage3.fs.fp3.word_bit_boolean";
            boolean.kind = aq::AirKind::kEverywhere;
            boolean.alg_degree = 2;
            boolean.eval =
                [column = layout.Bit(word, bit)](
                    const std::vector<gf::Fp3>& row,
                    const std::vector<gf::Fp3>&) {
                    return gf::Mul(
                        row[column],
                        gf::Sub(
                            row[column],
                            gf::Fp3::One()));
                };
            append(std::move(boolean));
        }

        aq::AirConstraint<gf::Fp3> high_first;
        high_first.name =
            "stage3.fs.fp3.high_and_first";
        high_first.kind =
            aq::AirKind::kEverywhere;
        high_first.alg_degree = 1;
        high_first.eval =
            [column = layout.HighAnd(word, 0)](
                const std::vector<gf::Fp3>& row,
                const std::vector<gf::Fp3>&) {
                return gf::Sub(
                    row[column],
                    gf::Fp3::One());
            };
        append(std::move(high_first));
        for (uint32_t step = 0;
             step < 32; ++step) {
            aq::AirConstraint<gf::Fp3> high_and;
            high_and.name =
                "stage3.fs.fp3.high_and_step";
            high_and.kind =
                aq::AirKind::kEverywhere;
            high_and.alg_degree = 2;
            high_and.eval =
                [before =
                     layout.HighAnd(word, step),
                 bit =
                     layout.Bit(word, 32 + step),
                 after =
                     layout.HighAnd(
                         word, step + 1)](
                    const std::vector<gf::Fp3>& row,
                    const std::vector<gf::Fp3>&) {
                    return gf::Sub(
                        row[after],
                        gf::Mul(
                            row[before],
                            row[bit]));
                };
            append(std::move(high_and));
        }

        aq::AirConstraint<gf::Fp3> zero_boolean;
        zero_boolean.name =
            "stage3.fs.fp3.low_zero_boolean";
        zero_boolean.kind =
            aq::AirKind::kEverywhere;
        zero_boolean.alg_degree = 2;
        zero_boolean.eval =
            [zero = layout.LowIsZero(word)](
                const std::vector<gf::Fp3>& row,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    row[zero],
                    gf::Sub(
                        row[zero],
                        gf::Fp3::One()));
            };
        append(std::move(zero_boolean));

        aq::AirConstraint<gf::Fp3> zero_product;
        zero_product.name =
            "stage3.fs.fp3.low_zero_product";
        zero_product.kind =
            aq::AirKind::kEverywhere;
        zero_product.alg_degree = 2;
        zero_product.eval =
            [layout, word,
             zero = layout.LowIsZero(word)](
                const std::vector<gf::Fp3>& row,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    Recompose(
                        row, layout, word, 0, 32),
                    row[zero]);
            };
        append(std::move(zero_product));

        aq::AirConstraint<gf::Fp3> zero_inverse;
        zero_inverse.name =
            "stage3.fs.fp3.low_zero_inverse";
        zero_inverse.kind =
            aq::AirKind::kEverywhere;
        zero_inverse.alg_degree = 2;
        zero_inverse.eval =
            [layout, word,
             zero = layout.LowIsZero(word),
             inverse = layout.LowInverse(word)](
                const std::vector<gf::Fp3>& row,
                const std::vector<gf::Fp3>&) {
                return gf::Sub(
                    gf::Mul(
                        Recompose(
                            row, layout,
                            word, 0, 32),
                        row[inverse]),
                    gf::Sub(
                        gf::Fp3::One(),
                        row[zero]));
            };
        append(std::move(zero_inverse));

        aq::AirConstraint<gf::Fp3> valid;
        valid.name =
            "stage3.fs.fp3.goldilocks_valid";
        valid.kind =
            aq::AirKind::kEverywhere;
        valid.alg_degree = 2;
        valid.eval =
            [high_max =
                 layout.HighAnd(word, 32),
             low_zero =
                 layout.LowIsZero(word),
             valid_column =
                 layout.Valid(word)](
                const std::vector<gf::Fp3>& row,
                const std::vector<gf::Fp3>&) {
                const gf::Fp3 expected =
                    gf::Add(
                        gf::Sub(
                            gf::Fp3::One(),
                            row[high_max]),
                        gf::Mul(
                            row[high_max],
                            row[low_zero]));
                return gf::Sub(
                    row[valid_column],
                    expected);
            };
        append(std::move(valid));

        for (uint32_t count = 0;
             count < kCountStates; ++count) {
            aq::AirConstraint<gf::Fp3> boolean;
            boolean.name =
                "stage3.fs.fp3.count_boolean";
            boolean.kind =
                aq::AirKind::kEverywhere;
            boolean.alg_degree = 2;
            boolean.eval =
                [column =
                     layout.CountBefore(
                         word, count)](
                    const std::vector<gf::Fp3>& row,
                    const std::vector<gf::Fp3>&) {
                    return gf::Mul(
                        row[column],
                        gf::Sub(
                            row[column],
                            gf::Fp3::One()));
                };
            append(std::move(boolean));
        }
        aq::AirConstraint<gf::Fp3> one_hot;
        one_hot.name =
            "stage3.fs.fp3.count_one_hot";
        one_hot.kind =
            aq::AirKind::kEverywhere;
        one_hot.alg_degree = 1;
        one_hot.eval =
            [layout, word](
                const std::vector<gf::Fp3>& row,
                const std::vector<gf::Fp3>&) {
                gf::Fp3 sum = gf::Fp3::Zero();
                for (uint32_t count = 0;
                     count < kCountStates; ++count) {
                    sum = gf::Add(
                        sum,
                        row[layout.CountBefore(
                            word, count)]);
                }
                return gf::Sub(
                    sum, gf::Fp3::One());
            };
        append(std::move(one_hot));
    }

    for (uint32_t count = 0;
         count < kCountStates; ++count) {
        aq::AirConstraint<gf::Fp3> initial;
        initial.name =
            "stage3.fs.fp3.count_initial";
        initial.kind =
            aq::AirKind::kEverywhere;
        initial.alg_degree = 1;
        initial.eval =
            [column =
                 layout.CountBefore(0, count),
             expected =
                 count == 0
                 ? gf::Fp3::One()
                 : gf::Fp3::Zero()](
                const std::vector<gf::Fp3>& row,
                const std::vector<gf::Fp3>&) {
                return gf::Sub(
                    row[column], expected);
            };
        append(std::move(initial));
    }
    for (uint32_t word = 0;
         word + 1 < kCandidateWords; ++word) {
        for (uint32_t count = 0;
             count < kCountStates; ++count) {
            aq::AirConstraint<gf::Fp3> step;
            step.name =
                "stage3.fs.fp3.count_step";
            step.kind =
                aq::AirKind::kEverywhere;
            step.alg_degree = 2;
            step.eval =
                [layout, word, count](
                    const std::vector<gf::Fp3>& row,
                    const std::vector<gf::Fp3>&) {
                    const gf::Fp3 valid =
                        row[layout.Valid(word)];
                    const gf::Fp3 stay =
                        gf::Mul(
                            row[layout.CountBefore(
                                word, count)],
                            count == 3
                            ? gf::Fp3::One()
                            : gf::Sub(
                                  gf::Fp3::One(),
                                  valid));
                    gf::Fp3 advance =
                        gf::Fp3::Zero();
                    if (count != 0) {
                        advance = gf::Mul(
                            row[layout.CountBefore(
                                word, count - 1)],
                            valid);
                    }
                    return gf::Sub(
                        row[layout.CountBefore(
                            word + 1, count)],
                        gf::Add(stay, advance));
                };
            append(std::move(step));
        }
    }

    aq::AirConstraint<gf::Fp3> final_three;
    final_three.name =
        "stage3.fs.fp3.final_three";
    final_three.kind =
        aq::AirKind::kEverywhere;
    final_three.alg_degree = 2;
    final_three.eval =
        [layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            const uint32_t last =
                kCandidateWords - 1;
            const gf::Fp3 reaches_three =
                gf::Add(
                    row[layout.CountBefore(
                        last, 3)],
                    gf::Mul(
                        row[layout.CountBefore(
                            last, 2)],
                        row[layout.Valid(last)]));
            return gf::Sub(
                reaches_three,
                gf::Fp3::One());
        };
    append(std::move(final_three));

    aq::AirConstraint<gf::Fp3> output;
    output.name =
        "stage3.fs.fp3.selected_output";
    output.kind =
        aq::AirKind::kEverywhere;
    output.alg_degree = 3;
    output.eval =
        [layout](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            std::array<gf::Fp3, 3> selected{};
            for (uint32_t word = 0;
                 word < kCandidateWords; ++word) {
                const gf::Fp3 candidate =
                    Candidate(row, layout, word);
                for (uint32_t coordinate = 0;
                     coordinate < 3; ++coordinate) {
                    selected[coordinate] =
                        gf::Add(
                            selected[coordinate],
                            gf::Mul(
                                row[layout.Valid(word)],
                                gf::Mul(
                                    row[layout.CountBefore(
                                        word,
                                        coordinate)],
                                    candidate)));
                }
            }
            const gf::Fp3 expected{
                selected[0].c0,
                selected[1].c0,
                selected[2].c0};
            return gf::Sub(
                row[layout.selected],
                expected);
        };
    append(std::move(output));
    return true;
}

WitnessV1 BuildWitnessV1(
    const std::array<uint64_t, kCandidateWords>& words)
{
    WitnessV1 out;
    out.words = words;
    if (!BuildConstraintSystemV1(
            2, out.cs, &out.note)) {
        return out;
    }
    out.columns.assign(
        out.cs.n_columns,
        std::vector<gf::Fp3>(
            out.cs.n_rows,
            gf::Fp3::Zero()));
    std::array<uint8_t, kCountStates> count{};
    count[0] = 1;
    std::array<gf::Fp, 3> selected{};
    uint32_t selected_count = 0;
    for (uint32_t word = 0;
         word < kCandidateWords; ++word) {
        const uint32_t low =
            static_cast<uint32_t>(words[word]);
        const uint32_t high =
            static_cast<uint32_t>(
                words[word] >> 32);
        uint8_t high_and = 1;
        for (uint32_t row = 0;
             row < out.cs.n_rows; ++row) {
            for (uint32_t bit = 0;
                 bit < 64; ++bit) {
                out.columns[
                    out.layout.Bit(word, bit)][row] =
                    gf::Fp3::FromFp(
                        gf::FromU64(
                            (words[word] >> bit) &
                            1U));
            }
            out.columns[
                out.layout.HighAnd(word, 0)][row] =
                gf::Fp3::One();
        }
        for (uint32_t step = 0;
             step < 32; ++step) {
            high_and &=
                (high >> step) & 1U;
            for (uint32_t row = 0;
                 row < out.cs.n_rows; ++row) {
                out.columns[
                    out.layout.HighAnd(
                        word, step + 1)][row] =
                    gf::Fp3::FromFp(
                        gf::FromU64(high_and));
            }
        }
        const uint8_t low_zero =
            low == 0 ? 1 : 0;
        const uint8_t valid =
            words[word] < gf::kP ? 1 : 0;
        for (uint32_t row = 0;
             row < out.cs.n_rows; ++row) {
            out.columns[
                out.layout.LowIsZero(word)][row] =
                gf::Fp3::FromFp(
                    gf::FromU64(low_zero));
            out.columns[
                out.layout.LowInverse(word)][row] =
                low == 0
                ? gf::Fp3::Zero()
                : gf::Inv(
                      gf::Fp3::FromFp(
                          gf::FromU64(low)));
            out.columns[
                out.layout.Valid(word)][row] =
                gf::Fp3::FromFp(
                    gf::FromU64(valid));
            for (uint32_t state = 0;
                 state < kCountStates; ++state) {
                out.columns[
                    out.layout.CountBefore(
                        word, state)][row] =
                    gf::Fp3::FromFp(
                        gf::FromU64(
                            count[state]));
            }
        }
        if (valid != 0 && selected_count < 3) {
            selected[selected_count++] =
                words[word];
        }
        if (valid != 0 && count[3] == 0) {
            std::array<uint8_t, kCountStates> next{};
            next[1] = count[0];
            next[2] = count[1];
            next[3] = count[2] | count[3];
            count = next;
        }
    }
    out.accepted_words = selected_count;
    if (selected_count == 3) {
        out.selected_value = {
            selected[0],
            selected[1],
            selected[2]};
    }
    for (uint32_t row = 0;
         row < out.cs.n_rows; ++row) {
        out.columns[out.layout.selected][row] =
            out.selected_value;
    }
    out.first_three_selection_constrained = true;
    out.fewer_than_three_rejects = true;
    out.valid =
        selected_count == 3 &&
        CountViolationsV1(
            out.cs, out.columns) == 0;
    out.note = out.valid
        ? "stage3:fs_selection_air:"
          "first_three_uniform_fp3"
        : "stage3:fs_selection_air:"
          "insufficient_or_invalid";
    return out;
}

uint32_t CountViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns)
{
    if (columns.size() != cs.n_columns) {
        return 1;
    }
    uint32_t violations = 0;
    std::vector<gf::Fp3> current(
        cs.n_columns, gf::Fp3::Zero());
    std::vector<gf::Fp3> next(
        cs.n_columns, gf::Fp3::Zero());
    for (uint32_t row = 0;
         row < cs.n_rows; ++row) {
        for (uint32_t column = 0;
             column < cs.n_columns; ++column) {
            if (columns[column].size() !=
                cs.n_rows) {
                return 1;
            }
            current[column] =
                columns[column][row];
            next[column] =
                columns[column][
                    (row + 1) %
                    cs.n_rows];
        }
        for (const auto& constraint :
             cs.constraints) {
            if (!gf::IsZero(
                    constraint.eval(
                        current, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

bool BuildQueryIndexConstraintSystemV1(
    uint32_t n_rows,
    uint32_t modulus,
    aq::AirConstraintSystem<gf::Fp3>& out,
    std::string* why)
{
    out = {};
    if (n_rows < 2 ||
        (n_rows & (n_rows - 1)) != 0 ||
        modulus == 0 ||
        (modulus & (modulus - 1)) != 0) {
        return Fail(why, "query_shape");
    }
    uint32_t domain_bits = 0;
    for (uint32_t value = modulus;
         value > 1; value >>= 1) {
        ++domain_bits;
    }

    const QueryIndexLayoutV1 layout;
    out.n_rows = n_rows;
    out.n_columns = layout.End();
    out.preprocessed_pin_ood = true;
    for (uint32_t bit = 0;
         bit < kQueryDigestBits; ++bit) {
        aq::AirConstraint<gf::Fp3> boolean;
        boolean.name =
            "stage3.fs.query.digest_bit_boolean";
        boolean.kind = aq::AirKind::kEverywhere;
        boolean.alg_degree = 2;
        boolean.eval =
            [column = layout.Bit(bit)](
                const std::vector<gf::Fp3>& row,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    row[column],
                    gf::Sub(
                        row[column],
                        gf::Fp3::One()));
            };
        out.constraints.push_back(
            std::move(boolean));
    }

    aq::AirConstraint<gf::Fp3> reduction;
    reduction.name =
        "stage3.fs.query.power_of_two_mask";
    reduction.kind = aq::AirKind::kEverywhere;
    reduction.alg_degree = 1;
    reduction.eval =
        [layout, domain_bits](
            const std::vector<gf::Fp3>& row,
            const std::vector<gf::Fp3>&) {
            gf::Fp3 expected = gf::Fp3::Zero();
            gf::Fp3 power = gf::Fp3::One();
            for (uint32_t bit = 0;
                 bit < domain_bits; ++bit) {
                expected = gf::Add(
                    expected,
                    gf::Mul(
                        power,
                        row[layout.Bit(bit)]));
                power = gf::Add(power, power);
            }
            return gf::Sub(
                row[layout.output], expected);
        };
    out.constraints.push_back(
        std::move(reduction));
    return true;
}

QueryIndexWitnessV1 BuildQueryIndexWitnessV1(
    const std::array<unsigned char, 4>& digest_prefix,
    uint32_t modulus)
{
    QueryIndexWitnessV1 out;
    out.modulus = modulus;
    out.raw =
        uint32_t{digest_prefix[0]} |
        (uint32_t{digest_prefix[1]} << 8) |
        (uint32_t{digest_prefix[2]} << 16) |
        (uint32_t{digest_prefix[3]} << 24);
    std::string why;
    if (!BuildQueryIndexConstraintSystemV1(
            2, modulus, out.cs, &why)) {
        out.note = why;
        return out;
    }
    for (uint32_t value = modulus;
         value > 1; value >>= 1) {
        ++out.domain_bits;
    }
    out.query_index = out.raw & (modulus - 1);
    out.columns.assign(
        out.cs.n_columns,
        std::vector<gf::Fp3>(
            out.cs.n_rows,
            gf::Fp3::Zero()));
    for (uint32_t bit = 0;
         bit < kQueryDigestBits; ++bit) {
        const gf::Fp3 value =
            gf::Fp3::FromFp(
                gf::FromU64(
                    (out.raw >> bit) & 1u));
        std::fill(
            out.columns[out.layout.Bit(bit)].begin(),
            out.columns[out.layout.Bit(bit)].end(),
            value);
    }
    const gf::Fp3 query =
        gf::Fp3::FromFp(
            gf::FromU64(out.query_index));
    std::fill(
        out.columns[out.layout.output].begin(),
        out.columns[out.layout.output].end(),
        query);

    out.digest_bits_boolean = true;
    out.power_of_two_mask_constrained = true;
    out.valid =
        CountViolationsV1(out.cs, out.columns) == 0;
    out.note = out.valid
        ? "stage3:fs_selection_air:"
          "query_index_mask_ok"
        : "stage3:fs_selection_air:"
          "query_index_mask_violation";
    return out;
}

DirectChallengeWitnessV1 BuildDirectChallengeWitnessV1(
    const std::array<unsigned char, 24>& bytes)
{
    DirectChallengeWitnessV1 out;
    const DirectChallengeLayoutV1 layout = out.layout;
    const uint32_t n_rows = 2;
    out.cs.n_rows = n_rows;
    out.cs.n_columns = layout.End();

    // word_j - sum_i byte[8j+i] * 256^i = 0  (Fp arithmetic auto-reduces mod p).
    for (uint32_t j = 0; j < 3; ++j) {
        aq::AirConstraint<gf::Fp3> c;
        c.name = "stage3.fs.direct.word_recompose";
        c.kind = aq::AirKind::kEverywhere;
        c.alg_degree = 1;
        c.eval =
            [layout, j](const std::vector<gf::Fp3>& r,
                        const std::vector<gf::Fp3>&) {
                gf::Fp3 acc = gf::Fp3::Zero();
                for (uint32_t i = 0; i < 8; ++i) {
                    acc = gf::Add(
                        acc,
                        gf::Mul(r[layout.Byte(8 * j + i)],
                                gf::FromU64_3(uint64_t{1}
                                              << (8 * i))));
                }
                return gf::Sub(r[layout.Word(j)], acc);
            };
        out.cs.constraints.push_back(std::move(c));
    }
    // challenge - (word0*1 + word1*X + word2*X^2) = 0.
    {
        aq::AirConstraint<gf::Fp3> c;
        c.name = "stage3.fs.direct.basis_reconstruction";
        c.kind = aq::AirKind::kEverywhere;
        c.alg_degree = 1;
        c.eval =
            [layout](const std::vector<gf::Fp3>& r,
                     const std::vector<gf::Fp3>&) {
                gf::Fp3 e1{};
                e1.c1 = gf::FromU64(1);
                gf::Fp3 e2{};
                e2.c2 = gf::FromU64(1);
                const gf::Fp3 recon = gf::Add(
                    r[layout.Word(0)],
                    gf::Add(gf::Mul(r[layout.Word(1)], e1),
                            gf::Mul(r[layout.Word(2)], e2)));
                return gf::Sub(r[layout.Challenge()], recon);
            };
        out.cs.constraints.push_back(std::move(c));
    }

    out.columns.assign(
        out.cs.n_columns,
        std::vector<gf::Fp3>(n_rows, gf::Fp3::Zero()));
    const auto put = [&](uint32_t col, const gf::Fp3& v) {
        std::fill(out.columns[col].begin(),
                  out.columns[col].end(), v);
    };
    for (uint32_t i = 0; i < 24; ++i) {
        put(layout.Byte(i), gf::FromU64_3(bytes[i]));
    }
    uint64_t w[3] = {0, 0, 0};
    for (uint32_t j = 0; j < 3; ++j) {
        for (uint32_t i = 0; i < 8; ++i) {
            w[j] |= static_cast<uint64_t>(bytes[8 * j + i])
                    << (8 * i);
        }
    }
    for (uint32_t j = 0; j < 3; ++j) {
        put(layout.Word(j), gf::FromU64_3(w[j]));
    }
    out.value = gf::FromChallengeBytes3(bytes.data());
    put(layout.Challenge(), out.value);

    out.recompose_constrained = true;
    out.basis_reconstruction_constrained = true;
    out.valid = CountViolationsV1(out.cs, out.columns) == 0;
    out.note = out.valid
                   ? "stage3:fs_selection_air:direct_challenge_ok"
                   : "stage3:fs_selection_air:"
                     "direct_challenge_violation";
    return out;
}

} // namespace matmul::v4::rc::stage3_fs_selection_air
