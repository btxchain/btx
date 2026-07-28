// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_extract_chacha_sampler_child.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_gkr_air.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_episode_extract_product.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <algorithm>
#include <array>
#include <limits>
#include <numeric>

namespace matmul::v4::rc::extract_chacha_sampler_child {
namespace {

namespace cb = constraint_bytecode;
namespace ga = gkr_air;
namespace gf = gkr_field;
namespace ha = stage3_hash_air;

using Fp3 = gf::Fp3;
using AirCS = aq::AirConstraintSystem<Fp3>;

constexpr uint32_t GOLDEN = 0x9E3779B9U;
constexpr uint32_t MX_BLOCK_LANE = 0x4D58424CU;
constexpr uint32_t LANE_ROWS = 1024;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:extract_chacha_sampler_child:" + detail;
    }
    return false;
}

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

void Add(
    AirCS& cs, const char* name, aq::AirKind kind,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    cs.constraints.push_back(
        {name, kind, degree, std::move(eval)});
}

struct Attachment {
    uint32_t base{0};
    uint32_t semantic_columns{0};
    uint32_t wrap_base{0};
    bool lifted{false};
};

bool AppendExact(
    AirCS& parent, const AirCS& child,
    Attachment& out, std::string* why)
{
    out = {};
    if (child.n_rows < 2 || child.n_columns == 0 ||
        (parent.n_columns != 0 &&
         parent.n_rows != child.n_rows)) {
        return Fail(why, "append_exact_shape");
    }
    if (parent.n_columns == 0) parent.n_rows = child.n_rows;
    out.base = parent.n_columns;
    out.semantic_columns = child.n_columns;
    parent.n_columns += child.n_columns;
    parent.preprocessed_pin_ood =
        parent.preprocessed_pin_ood ||
        child.preprocessed_pin_ood;
    for (const auto& constraint : child.constraints) {
        if (!constraint.eval ||
            constraint.alg_degree == 0) {
            return Fail(why, "append_exact_constraint");
        }
        auto shifted = constraint;
        const auto eval = constraint.eval;
        const uint32_t base = out.base;
        const uint32_t width = child.n_columns;
        shifted.eval =
            [eval, base, width](
                const std::vector<Fp3>& current,
                const std::vector<Fp3>& next) {
                if (current.size() < base + width ||
                    next.size() < base + width) {
                    return Fp3::One();
                }
                std::vector<Fp3> c(
                    current.begin() + base,
                    current.begin() + base + width);
                std::vector<Fp3> n(
                    next.begin() + base,
                    next.begin() + base + width);
                return eval(c, n);
            };
        parent.constraints.push_back(std::move(shifted));
    }
    for (const auto& [column, values] :
         child.preprocessed) {
        if (column >= child.n_columns ||
            values.size() != child.n_rows) {
            return Fail(why, "append_exact_preprocessed");
        }
        parent.preprocessed.emplace_back(
            out.base + column, values);
    }
    for (const auto& [column, root] :
         child.preprocessed_roots) {
        parent.preprocessed_roots.emplace_back(
            out.base + column, root);
    }
    return true;
}

bool AppendLifted(
    AirCS& parent, const AirCS& child,
    Attachment& out, std::string* why)
{
    if (parent.n_rows < child.n_rows ||
        parent.n_rows % child.n_rows != 0 ||
        !child.preprocessed_roots.empty() ||
        !child.preprocessed_row_group_roots.empty()) {
        return Fail(why, "append_lifted_shape");
    }
    constexpr uint32_t ACTIVE = 0;
    constexpr uint32_t TRANSITION = 1;
    constexpr uint32_t FIRST = 2;
    constexpr uint32_t LAST = 3;
    constexpr uint32_t PADDING = 4;
    constexpr uint32_t SELECTORS = 5;
    AirCS lifted;
    lifted.n_rows = parent.n_rows;
    const uint32_t wrap = child.n_columns;
    const uint32_t selectors = child.n_columns * 2U;
    lifted.n_columns = selectors + SELECTORS;
    lifted.preprocessed_pin_ood =
        child.preprocessed_pin_ood;
    for (const auto& [column, values] :
         child.preprocessed) {
        if (column >= child.n_columns ||
            values.size() != child.n_rows) {
            return Fail(why, "append_lifted_preprocessed");
        }
        std::vector<Fp3> padded(
            parent.n_rows, Fp3::Zero());
        std::copy(
            values.begin(), values.end(),
            padded.begin());
        lifted.preprocessed.emplace_back(
            column, std::move(padded));
    }
    std::array<std::vector<Fp3>, SELECTORS> selector;
    for (auto& values : selector) {
        values.assign(parent.n_rows, Fp3::Zero());
    }
    for (uint32_t row = 0; row < parent.n_rows; ++row) {
        selector[row < child.n_rows ? ACTIVE : PADDING][row] =
            Fp3::One();
        if (row + 1 < child.n_rows) {
            selector[TRANSITION][row] = Fp3::One();
        }
    }
    selector[FIRST][0] = Fp3::One();
    selector[LAST][child.n_rows - 1] = Fp3::One();
    for (uint32_t i = 0; i < SELECTORS; ++i) {
        lifted.preprocessed.emplace_back(
            selectors + i, std::move(selector[i]));
    }
    for (uint32_t column = 0;
         column < child.n_columns; ++column) {
        Add(
            lifted, "extract_child.lift.wrap.first",
            aq::AirKind::kFirstRow, 1,
            [column, wrap](
                const auto& cur, const auto&) {
                return gf::Sub(
                    cur[wrap + column], cur[column]);
            });
        Add(
            lifted, "extract_child.lift.wrap.constant",
            aq::AirKind::kTransition, 1,
            [column, wrap](
                const auto& cur, const auto& next) {
                return gf::Sub(
                    next[wrap + column],
                    cur[wrap + column]);
            });
    }
    const auto gated =
        [&](const aq::AirConstraint<Fp3>& source,
            uint32_t selector_index, bool wrap_next) {
            aq::AirConstraint<Fp3> out_constraint;
            out_constraint.name = source.name;
            out_constraint.kind = aq::AirKind::kEverywhere;
            out_constraint.alg_degree =
                source.alg_degree + 1;
            const auto eval = source.eval;
            const uint32_t width = child.n_columns;
            out_constraint.eval =
                [eval, width, wrap, selectors,
                 selector_index, wrap_next](
                    const std::vector<Fp3>& cur,
                    const std::vector<Fp3>& next) {
                    std::vector<Fp3> c(
                        cur.begin(), cur.begin() + width);
                    std::vector<Fp3> n;
                    if (wrap_next) {
                        n.assign(
                            cur.begin() + wrap,
                            cur.begin() + wrap + width);
                    } else {
                        n.assign(
                            next.begin(),
                            next.begin() + width);
                    }
                    return gf::Mul(
                        cur[selectors + selector_index],
                        eval(c, n));
                };
            lifted.constraints.push_back(
                std::move(out_constraint));
        };
    for (const auto& constraint : child.constraints) {
        switch (constraint.kind) {
        case aq::AirKind::kEverywhere:
            gated(constraint, TRANSITION, false);
            gated(constraint, LAST, true);
            break;
        case aq::AirKind::kTransition:
            gated(constraint, TRANSITION, false);
            break;
        case aq::AirKind::kFirstRow:
            gated(constraint, FIRST, false);
            break;
        case aq::AirKind::kLastRow:
            gated(constraint, LAST, true);
            break;
        }
    }
    for (uint32_t column = 0;
         column < child.n_columns; ++column) {
        Add(
            lifted, "extract_child.lift.padding.zero",
            aq::AirKind::kEverywhere, 2,
            [column, selectors](
                const auto& cur, const auto&) {
                return gf::Mul(
                    cur[selectors + PADDING],
                    cur[column]);
            });
    }
    if (!AppendExact(parent, lifted, out, why)) {
        return false;
    }
    out.semantic_columns = child.n_columns;
    out.wrap_base = out.base + wrap;
    out.lifted = true;
    return true;
}

void AppendWitness(
    const AirCS& parent, const AirCS& child,
    const std::vector<std::vector<Fp3>>& child_columns,
    const Attachment& attachment,
    std::vector<std::vector<Fp3>>& columns)
{
    columns.resize(
        parent.n_columns,
        std::vector<Fp3>(
            parent.n_rows, Fp3::Zero()));
    if (!attachment.lifted) {
        for (uint32_t column = 0;
             column < child.n_columns; ++column) {
            columns[attachment.base + column] =
                child_columns[column];
        }
        return;
    }
    for (uint32_t column = 0;
         column < child.n_columns; ++column) {
        std::copy(
            child_columns[column].begin(),
            child_columns[column].end(),
            columns[attachment.base + column].begin());
        std::fill(
            columns[attachment.wrap_base + column].begin(),
            columns[attachment.wrap_base + column].end(),
            child_columns[column][0]);
    }
}

struct Alias {
    CellV1 source;
    CellV1 sink;
};

bool AppendAliases(
    AirCS& cs,
    const std::vector<Alias>& aliases,
    std::vector<std::vector<Fp3>>* columns,
    std::vector<uint32_t>* base_columns,
    std::string* why)
{
    if (aliases.empty()) return true;
    const uint32_t carrier_base = cs.n_columns;
    const uint32_t selector_base =
        carrier_base +
        static_cast<uint32_t>(aliases.size());
    cs.n_columns +=
        static_cast<uint32_t>(aliases.size()) * 3U;
    if (columns != nullptr) {
        columns->resize(
            cs.n_columns,
            std::vector<Fp3>(
                cs.n_rows, Fp3::Zero()));
    }
    for (uint32_t i = 0; i < aliases.size(); ++i) {
        const auto& alias = aliases[i];
        if (alias.source.column >= carrier_base ||
            alias.sink.column >= carrier_base ||
            alias.source.row >= cs.n_rows ||
            alias.sink.row >= cs.n_rows) {
            return Fail(why, "alias_shape");
        }
        const uint32_t carrier = carrier_base + i;
        const uint32_t source_selector =
            selector_base + 2U * i;
        const uint32_t sink_selector =
            source_selector + 1U;
        std::vector<Fp3> source_values(
            cs.n_rows, Fp3::Zero());
        std::vector<Fp3> sink_values(
            cs.n_rows, Fp3::Zero());
        source_values[alias.source.row] = Fp3::One();
        sink_values[alias.sink.row] = Fp3::One();
        cs.preprocessed.emplace_back(
            source_selector, std::move(source_values));
        cs.preprocessed.emplace_back(
            sink_selector, std::move(sink_values));
        Add(
            cs, "extract_child.alias.carry",
            aq::AirKind::kTransition, 1,
            [carrier](const auto& cur, const auto& next) {
                return gf::Sub(next[carrier], cur[carrier]);
            });
        Add(
            cs, "extract_child.alias.source",
            aq::AirKind::kEverywhere, 2,
            [carrier, source_selector,
             source = alias.source.column](
                const auto& cur, const auto&) {
                return gf::Mul(
                    cur[source_selector],
                    gf::Sub(cur[carrier], cur[source]));
            });
        Add(
            cs, "extract_child.alias.sink",
            aq::AirKind::kEverywhere, 2,
            [carrier, sink_selector,
             sink = alias.sink.column](
                const auto& cur, const auto&) {
                return gf::Mul(
                    cur[sink_selector],
                    gf::Sub(cur[carrier], cur[sink]));
            });
        if (columns != nullptr) {
            const Fp3 source_value =
                (*columns)[alias.source.column]
                          [alias.source.row];
            const Fp3 sink_value =
                (*columns)[alias.sink.column]
                          [alias.sink.row];
            if (!gf::Eq(source_value, sink_value)) {
                return Fail(
                    why,
                    "alias_value_mismatch:index=" +
                        std::to_string(i) +
                        ":source_column=" +
                        std::to_string(alias.source.column) +
                        ":source_row=" +
                        std::to_string(alias.source.row) +
                        ":sink_column=" +
                        std::to_string(alias.sink.column) +
                        ":sink_row=" +
                        std::to_string(alias.sink.row));
            }
            std::fill(
                (*columns)[carrier].begin(),
                (*columns)[carrier].end(),
                source_value);
        }
        if (base_columns != nullptr) {
            base_columns->push_back(carrier);
        }
    }
    return true;
}

uint256 ChildChallengeDigest(
    const uint256& public_fs_seed,
    const uint256& r0_root,
    const char* label,
    const TileStatementV1& statement)
{
    HashWriter hash;
    hash << std::string{
        "BTX_RC_STAGE3_EXTRACT_CHACHA_SAMPLER_CHILD_FS_V1"}
         // Serialize the label bytes, not the decayed C-string pointer.  The
         // generic serializer treats a non-null pointer as the same boolean
         // value for every label, which would make gamma == alpha and force
         // a LogUp denominator collision whenever a witness fingerprint is
         // gamma (for example the canonical (mixed,acc,mu)=(0,1,0) row).
         << std::string{label}
         << public_fs_seed << r0_root
         << statement.statement_commitment
         << statement.prf_key << statement.row
         << statement.block << statement.chacha_blocks
         << statement.candidate_rows << statement.trace_rows
         << statement.scale_e;
    return hash.GetHash();
}

std::array<Fp3, 2> ChildChallenges(
    const TileStatementV1& statement,
    const uint256& r0_root)
{
    const uint256 gamma = ChildChallengeDigest(
        statement.public_fs_seed, r0_root,
        "gamma", statement);
    const uint256 alpha = ChildChallengeDigest(
        statement.public_fs_seed, r0_root,
        "alpha", statement);
    return {
        gf::FromChallengeBytes3(gamma.data()),
        gf::FromChallengeBytes3(alpha.data())};
}

uint256 ProofSeed(const TileStatementV1& statement)
{
    HashWriter hash;
    hash << std::string{
        "BTX_RC_STAGE3_EXTRACT_CHACHA_SAMPLER_CHILD_PROOF_V1"}
         << statement.retained_node_commitment;
    return hash.GetHash();
}

bool BuildBoundaries(
    const TileStatementV1& statement,
    std::vector<ha::FixedProgramBoundaryInstance>& honest,
    std::vector<ha::FixedProgramBoundaryInstance>& public_templates,
    std::vector<std::vector<uint8_t>>& masks,
    std::string* why)
{
    if (statement.prf_key.IsNull() ||
        statement.chacha_blocks == 0 ||
        statement.chacha_blocks > 4) {
        return Fail(why, "boundary_shape");
    }
    std::array<uint8_t, 32> key{};
    std::copy_n(
        statement.prf_key.begin(), key.size(), key.begin());
    ha::ChaChaConsumptionManifest manifest;
    if (!ha::BuildChaChaConsumptionManifest(
            key, statement.block ^ MX_BLOCK_LANE,
            (static_cast<uint64_t>(statement.row) << 32) |
                statement.block,
            0, uint64_t{statement.chacha_blocks} * 64,
            manifest, why) ||
        !ha::BuildChaChaManifestBoundaryInstances(
            manifest, honest, why) ||
        honest.size() != statement.chacha_blocks) {
        return Fail(why, "boundary_manifest");
    }
    public_templates = honest;
    masks.resize(honest.size());
    const auto program = ha::BuildCanonicalProgram(
        ha::ProgramKind::ChaCha20Block);
    for (uint32_t i = 0; i < honest.size(); ++i) {
        public_templates[i].final_words.assign(
            program.final_addresses.size(), 0);
        masks[i].assign(
            program.external_address_count, 1);
    }
    return true;
}

void FillMixBits(
    std::vector<std::vector<Fp3>>& columns,
    uint32_t begin, uint32_t row, uint32_t value)
{
    for (uint32_t bit = 0; bit < 32; ++bit) {
        columns[begin + bit][row] =
            U((value >> bit) & 1U);
    }
}

bool BuildMixWitness(
    const ga::TileWitness& witness,
    const std::vector<std::vector<Fp3>>& sampler,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    if (sampler.size() != aq::kRcSamplerNumCols ||
        sampler.empty() ||
        witness.cands.size() > sampler[0].size()) {
        return Fail(why, "mix_witness_shape");
    }
    const uint32_t rows =
        static_cast<uint32_t>(sampler[0].size());
    columns.assign(
        kRCStage3EpisodeExtractMixColumns,
        std::vector<Fp3>(rows, Fp3::Zero()));
    for (uint32_t row = 0; row < rows; ++row) {
        columns[kRCStage3ExtractMixU][row] =
            sampler[aq::kColUMix][row];
        columns[kRCStage3ExtractMixQ][row] =
            sampler[aq::kColGoldQ][row];
        columns[kRCStage3ExtractMixV][row] =
            sampler[aq::kColGoldV][row];
        columns[kRCStage3ExtractMixH][row] =
            sampler[aq::kColH][row];
        if (row >= witness.cands.size()) {
            FillMixBits(
                columns,
                kRCStage3ExtractMixQDifferenceBits,
                row, GOLDEN);
            continue;
        }
        const auto& candidate = witness.cands[row];
        columns[kRCStage3ExtractMixBranch][row] =
            U(candidate.branch);
        FillMixBits(
            columns, kRCStage3ExtractMixYLoBits,
            row, candidate.y_lo);
        FillMixBits(
            columns, kRCStage3ExtractMixYHiBits,
            row, candidate.y_hi);
        FillMixBits(
            columns, kRCStage3ExtractMixUBits,
            row, candidate.u_mix);
        FillMixBits(
            columns, kRCStage3ExtractMixQBits,
            row, candidate.gold_q);
        FillMixBits(
            columns, kRCStage3ExtractMixVBits,
            row, candidate.gold_v);
        FillMixBits(
            columns,
            kRCStage3ExtractMixQDifferenceBits,
            row, GOLDEN - candidate.gold_q);
    }
    return true;
}

bool FillSamplerDependent(
    std::vector<std::vector<Fp3>>& columns,
    const ga::TableTM& table,
    const Fp3& gamma,
    const Fp3& alpha,
    std::string* why)
{
    if (columns.size() != aq::kRcSamplerNumCols ||
        columns.empty()) {
        return Fail(why, "sampler_dependent_shape");
    }
    const uint32_t rows =
        static_cast<uint32_t>(columns[0].size());
    const Fp3 g2 = gf::Mul(gamma, gamma);
    for (uint32_t column :
         {uint32_t{aq::kColPhi}, uint32_t{aq::kColTfp},
          uint32_t{aq::kColM}, uint32_t{aq::kColPsi},
          uint32_t{aq::kColS}}) {
        std::fill(
            columns[column].begin(),
            columns[column].end(), Fp3::Zero());
    }
    std::vector<Fp3> table_fp(rows, Fp3::Zero());
    std::vector<Fp3> witness_fp(rows, Fp3::Zero());
    for (uint32_t row = 0; row < rows; ++row) {
        const uint32_t n = row < 16 ? row : 0;
        columns[aq::kColTblA][row] = U(n);
        columns[aq::kColTblB][row] = U(table.acc[n]);
        columns[aq::kColTblC][row] =
            Fp3::FromFp(gf::FromSigned(table.mu[n]));
        table_fp[row] = gf::Add(
            columns[aq::kColTblA][row],
            gf::Add(
                gf::Mul(
                    gamma, columns[aq::kColTblB][row]),
                gf::Mul(
                    g2, columns[aq::kColTblC][row])));
        columns[aq::kColTfp][row] = table_fp[row];
        witness_fp[row] = gf::Add(
            columns[aq::kColMixed][row],
            gf::Add(
                gf::Mul(
                    gamma, columns[aq::kColAcc][row]),
                gf::Mul(
                    g2, columns[aq::kColMu][row])));
        const Fp3 denominator =
            gf::Sub(alpha, witness_fp[row]);
        if (gf::IsZero(denominator)) {
            const auto a = gf::ToU64Triple(alpha);
            const auto w = gf::ToU64Triple(witness_fp[row]);
            return Fail(
                why,
                "sampler_witness_collision:row=" +
                    std::to_string(row) +
                    ":alpha=" +
                    std::to_string(a[0]) + "," +
                    std::to_string(a[1]) + "," +
                    std::to_string(a[2]) +
                    ":witness=" +
                    std::to_string(w[0]) + "," +
                    std::to_string(w[1]) + "," +
                    std::to_string(w[2]));
        }
        columns[aq::kColPhi][row] =
            gf::Inv(denominator);
    }
    for (uint32_t entry = 0;
         entry < 16 && entry < rows; ++entry) {
        uint64_t multiplicity = 0;
        for (uint32_t row = 0; row < rows; ++row) {
            if (gf::Eq(
                    witness_fp[row],
                    table_fp[entry])) {
                ++multiplicity;
            }
        }
        columns[aq::kColM][entry] = U(multiplicity);
        const Fp3 denominator =
            gf::Sub(alpha, table_fp[entry]);
        if (gf::IsZero(denominator)) {
            return Fail(why, "sampler_table_collision");
        }
        columns[aq::kColPsi][entry] =
            gf::Mul(
                columns[aq::kColM][entry],
                gf::Inv(denominator));
    }
    for (uint32_t row = 1; row < rows; ++row) {
        columns[aq::kColS][row] =
            gf::Add(
                columns[aq::kColS][row - 1],
                gf::Sub(
                    columns[aq::kColPhi][row - 1],
                    columns[aq::kColPsi][row - 1]));
    }
    const Fp3 total = gf::Add(
        columns[aq::kColS][rows - 1],
        gf::Sub(
            columns[aq::kColPhi][rows - 1],
            columns[aq::kColPsi][rows - 1]));
    return gf::IsZero(total) ||
        Fail(why, "sampler_logup_imbalance");
}

bool BuildSamplerCs(
    uint32_t rows, uint8_t scale_e,
    const std::array<Fp3, 2>& challenge,
    const ga::TableTM& table,
    AirCS& cs, std::string* why)
{
    cb::ProgramTable program;
    if (!BuildRCStage3EpisodeExtractLocalKernelProgramTable(
            scale_e, program, why) ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            program, rows,
            {challenge[0], challenge[1]},
            cs, why)) {
        return Fail(why, "sampler_cs");
    }
    for (uint32_t column :
         {uint32_t{aq::kColTblA},
          uint32_t{aq::kColTblB},
          uint32_t{aq::kColTblC}}) {
        std::vector<Fp3> values(
            rows, Fp3::Zero());
        for (uint32_t row = 0; row < rows; ++row) {
            const uint32_t n = row < 16 ? row : 0;
            if (column == aq::kColTblA) {
                values[row] = U(n);
            } else if (column == aq::kColTblB) {
                values[row] = U(table.acc[n]);
            } else {
                values[row] =
                    Fp3::FromFp(
                        gf::FromSigned(table.mu[n]));
            }
        }
        cs.preprocessed.emplace_back(
            column, std::move(values));
    }
    return true;
}

bool BuildMixCs(
    uint32_t rows, AirCS& cs, std::string* why)
{
    cb::ProgramTable table;
    if (!BuildRCStage3ExtractMixProgramTable(
            RCStage3RelationRole::EpisodeExtract,
            table, why) ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            table, rows, cs, why)) {
        return Fail(why, "mix_cs");
    }
    return true;
}

struct Built {
    AirCS cs;
    std::vector<std::vector<Fp3>> columns;
    std::vector<uint32_t> base_columns;
    Attachment hash;
    Attachment sampler;
    Attachment mix;
    std::vector<Alias> aliases;
    std::array<CellV1, 32> outputs{};
    std::vector<CellV1> positions;
    std::vector<std::array<CellV1, 64>> input_bits;
    uint256 public_boundary_statement{};
};

void AddBaseMapping(
    const Attachment& attachment,
    const std::vector<uint32_t>& child_base,
    std::vector<uint32_t>& parent_base)
{
    for (uint32_t column : child_base) {
        parent_base.push_back(attachment.base + column);
        if (attachment.lifted) {
            parent_base.push_back(
                attachment.wrap_base + column);
        }
    }
}

bool BuildComposition(
    const TileStatementV1& statement,
    const uint256& r0_root,
    const ga::TileWitness* witness,
    bool base_only,
    Built& out, std::string* why)
{
    out = {};
    const bool prover = witness != nullptr;
    if (base_only && !prover) {
        return Fail(why, "base_only_verifier");
    }
    std::vector<ha::FixedProgramBoundaryInstance> honest;
    std::vector<ha::FixedProgramBoundaryInstance> public_templates;
    std::vector<std::vector<uint8_t>> masks;
    if (!BuildBoundaries(
            statement, honest, public_templates,
            masks, why)) {
        return false;
    }
    const auto hash_program =
        ha::BuildCanonicalProgram(
            ha::ProgramKind::ChaCha20Block);
    ha::FixedProgramVerticalWitnessBoundaryInstance
        hash_prover;
    ha::FixedProgramVerticalWitnessBoundaryVerifierInstance
        hash_verifier;
    const uint256 boundary_seed =
        ChildChallengeDigest(
            statement.public_fs_seed,
            r0_root, "chacha", statement);
    if (prover) {
        hash_prover =
            ha::BuildFixedProgramVerticalWitnessBoundaryInstance(
                hash_program, honest, masks, {},
                boundary_seed, r0_root);
        if (!hash_prover.valid) {
            return Fail(
                why, "hash_prover:" +
                    hash_prover.note);
        }
        out.public_boundary_statement =
            hash_prover.public_statement;
        if (!AppendExact(
                out.cs, hash_prover.cs,
                out.hash, why)) {
            return false;
        }
        out.columns = hash_prover.columns;
        AddBaseMapping(
            out.hash,
            hash_prover.base_column_indices,
            out.base_columns);
    } else {
        hash_verifier =
            ha::BuildFixedProgramVerticalWitnessBoundaryVerifierInstance(
                hash_program, public_templates,
                masks, {}, boundary_seed, r0_root);
        if (!hash_verifier.valid) {
            return Fail(
                why, "hash_verifier:" +
                    hash_verifier.note);
        }
        out.public_boundary_statement =
            hash_verifier.public_statement;
        if (!AppendExact(
                out.cs, hash_verifier.cs,
                out.hash, why)) {
            return false;
        }
        AddBaseMapping(
            out.hash,
            hash_verifier.base_column_indices,
            out.base_columns);
    }
    if (out.cs.n_rows != statement.trace_rows) {
        return Fail(why, "hash_trace_rows");
    }

    const auto challenges = base_only
        ? std::array<Fp3, 2>{
              Fp3::Zero(), Fp3::Zero()}
        : ChildChallenges(statement, r0_root);
    const ga::TableTM table;
    AirCS sampler_cs;
    if (!BuildSamplerCs(
            statement.trace_rows >= 2
                ? std::max<uint32_t>(
                      64, FriNextPow2(
                              statement.candidate_rows))
                : 0,
            statement.scale_e, challenges,
            table, sampler_cs, why) ||
        sampler_cs.n_rows > out.cs.n_rows) {
        return Fail(why, "sampler_rows");
    }
    std::vector<std::vector<Fp3>> sampler_columns;
    std::vector<std::vector<Fp3>> mix_columns;
    if (prover) {
        const auto initial =
            aq::BuildRcSamplerInstance<Fp3>(
                *witness, table,
                statement.public_fs_seed);
        if (!initial.ok ||
            initial.n_rows != sampler_cs.n_rows) {
            return Fail(
                why, "sampler_witness:" +
                    initial.note);
        }
        sampler_columns = initial.columns;
        if ((!base_only &&
             !FillSamplerDependent(
                 sampler_columns, table,
                 challenges[0], challenges[1], why)) ||
            !BuildMixWitness(
                *witness, sampler_columns,
                mix_columns, why)) {
            return false;
        }
    }
    if (!AppendLifted(
            out.cs, sampler_cs,
            out.sampler, why)) {
        return false;
    }
    if (prover) {
        AppendWitness(
            out.cs, sampler_cs, sampler_columns,
            out.sampler, out.columns);
    }
    std::vector<uint32_t> sampler_base;
    for (uint32_t column = 0;
         column < aq::kRcSamplerBaseCols; ++column) {
        sampler_base.push_back(column);
    }
    AddBaseMapping(
        out.sampler, sampler_base,
        out.base_columns);

    AirCS mix_cs;
    if (!BuildMixCs(
            sampler_cs.n_rows, mix_cs, why) ||
        !AppendLifted(
            out.cs, mix_cs, out.mix, why)) {
        return false;
    }
    if (prover) {
        AppendWitness(
            out.cs, mix_cs, mix_columns,
            out.mix, out.columns);
    }
    std::vector<uint32_t> mix_base(
        mix_cs.n_columns);
    std::iota(
        mix_base.begin(), mix_base.end(), 0);
    AddBaseMapping(
        out.mix, mix_base,
        out.base_columns);

    const auto& final_rows = prover
        ? hash_prover.final_output_rows
        : hash_verifier.final_output_rows;
    if (final_rows.size() !=
        statement.chacha_blocks * 16U) {
        return Fail(why, "hash_final_rows");
    }
    out.aliases.reserve(
        uint64_t{statement.candidate_rows} * 8U);
    for (uint32_t candidate = 0;
         candidate < statement.candidate_rows;
         ++candidate) {
        const uint32_t source_block = candidate / 128U;
        const uint32_t in_block = candidate % 128U;
        const uint32_t byte = in_block / 2U;
        const uint32_t word = byte / 4U;
        const uint32_t bit_base =
            (byte % 4U) * 8U +
            (candidate & 1U) * 4U;
        if (source_block >= statement.chacha_blocks) {
            return Fail(why, "candidate_source_range");
        }
        const uint32_t source_row =
            final_rows[source_block * 16U + word];
        // Canonical ChaCha final addresses are Add32 instructions.  The
        // fixed-program witness stores every Add32 output in word slot 2;
        // slots 0 and 1 are the two addends.
        constexpr uint32_t CHACHA_OUTPUT_WORD_SLOT = 2;
        for (uint32_t bit = 0; bit < 4; ++bit) {
            out.aliases.push_back({
                {out.hash.base +
                     ha::BitColumn(
                         CHACHA_OUTPUT_WORD_SLOT,
                         bit_base + bit),
                 source_row},
                {out.sampler.base +
                     aq::kColKb0 + bit,
                 candidate}});
        }
        for (const auto [sampler_column, mix_column] :
             std::array<std::pair<uint32_t, uint32_t>, 4>{
                 {{aq::kColUMix,
                   kRCStage3ExtractMixU},
                  {aq::kColGoldQ,
                   kRCStage3ExtractMixQ},
                  {aq::kColGoldV,
                   kRCStage3ExtractMixV},
                  {aq::kColH,
                   kRCStage3ExtractMixH}}}) {
            out.aliases.push_back({
                {out.sampler.base +
                     sampler_column,
                 candidate},
                {out.mix.base + mix_column,
                 candidate}});
        }
    }
    if (!AppendAliases(
            out.cs, out.aliases,
            prover ? &out.columns : nullptr,
            &out.base_columns, why)) {
        return false;
    }
    // Preprocessed columns are verifier-owned constants, but the row-FRI
    // prover still commits their evaluations as ordinary trace columns.  The
    // composition helpers above attach the verifier metadata; materialize
    // the same values in the prover trace so the OOD pin checks the intended
    // constants instead of an accidentally zero-initialized selector/table
    // column.
    if (prover &&
        !MaterializeVerifierOwnedPreprocessedV1(
            out.cs, out.columns, why)) {
        return false;
    }
    std::sort(
        out.base_columns.begin(),
        out.base_columns.end());
    out.base_columns.erase(
        std::unique(
            out.base_columns.begin(),
            out.base_columns.end()),
        out.base_columns.end());
    for (uint32_t i = 0; i < 32; ++i) {
        out.outputs[i] = {
            out.sampler.base + aq::kColOut, i};
    }
    out.positions.resize(statement.candidate_rows);
    out.input_bits.resize(statement.candidate_rows);
    for (uint32_t candidate = 0;
         candidate < statement.candidate_rows;
         ++candidate) {
        out.positions[candidate] = {
            out.sampler.base + aq::kColPos,
            candidate};
        for (uint32_t bit = 0; bit < 32; ++bit) {
            out.input_bits[candidate][bit] = {
                out.mix.base +
                    kRCStage3ExtractMixYLoBits + bit,
                candidate};
            out.input_bits[candidate][32 + bit] = {
                out.mix.base +
                    kRCStage3ExtractMixYHiBits + bit,
                candidate};
        }
    }
    return true;
}

TileStatementV1 BaseStatement(
    const uint256& statement_commitment,
    const uint256& public_fs_seed,
    const uint256& prf_key,
    uint32_t row, uint32_t block,
    uint32_t chacha_blocks,
    uint32_t candidate_rows)
{
    TileStatementV1 out;
    out.statement_commitment = statement_commitment;
    out.public_fs_seed = public_fs_seed;
    out.prf_key = prf_key;
    out.row = row;
    out.block = block;
    out.chacha_blocks = chacha_blocks;
    out.candidate_rows = candidate_rows;
    out.scale_e =
        lt::DeriveMatExpandMxScale(
            prf_key, row, block);
    uint32_t scheduled = 1;
    while (scheduled < chacha_blocks) scheduled <<= 1;
    if (scheduled < 2) scheduled = 2;
    out.trace_rows = LANE_ROWS * scheduled;
    return out;
}

} // namespace

bool MaterializeVerifierOwnedPreprocessedV1(
    const aq::AirConstraintSystem<Fp3>& cs,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    const auto fail = [&](const char* detail) {
        if (why != nullptr) {
            *why =
                std::string{
                    "stage3:extract_chacha_sampler_child:"} +
                detail;
        }
        return false;
    };
    if (columns.size() != cs.n_columns) {
        return fail("preprocessed_materialize_shape");
    }
    std::vector<uint8_t> seen(cs.n_columns, 0);
    for (const auto& [column, values] :
         cs.preprocessed) {
        if (column >= cs.n_columns ||
            values.size() != cs.n_rows) {
            return fail("preprocessed_materialize_entry");
        }
        if (seen[column]) {
            bool same =
                columns[column].size() == values.size();
            for (uint32_t row = 0;
                 same && row < values.size(); ++row) {
                same = gf::Eq(
                    columns[column][row], values[row]);
            }
            if (!same) {
                return fail(
                    "preprocessed_materialize_conflict");
            }
        }
        columns[column] = values;
        seen[column] = 1;
    }
    return true;
}

std::array<Fp3, 2> DeriveChallengePairForAuditV1(
    const TileStatementV1& statement)
{
    return ChildChallenges(statement, statement.r0_root);
}

uint256 ComputeRetainedNodeCommitmentV1(
    const TileStatementV1& statement)
{
    if (statement.version != kVersionV1 ||
        statement.statement_commitment.IsNull() ||
        statement.public_fs_seed.IsNull() ||
        statement.prf_key.IsNull() ||
        statement.chacha_blocks == 0 ||
        statement.chacha_blocks > 4 ||
        statement.candidate_rows == 0 ||
        statement.candidate_rows >
            statement.chacha_blocks * 128U ||
        statement.candidate_rows <=
            (statement.chacha_blocks - 1U) * 128U ||
        statement.trace_rows < 2048 ||
        statement.public_boundary_statement.IsNull() ||
        statement.r0_root.IsNull() ||
        statement.position_cells.size() !=
            statement.candidate_rows ||
        statement.input_bit_cells.size() !=
            statement.candidate_rows) {
        return {};
    }
    HashWriter hash;
    hash << std::string{
        "BTX_RC_STAGE3_EXTRACT_CHACHA_SAMPLER_RETAINED_NODE_V1"}
         << statement.version
         << statement.statement_commitment
         << statement.public_fs_seed
         << statement.prf_key
         << statement.row << statement.block
         << statement.chacha_blocks
         << statement.candidate_rows
         << statement.trace_rows
         << statement.scale_e
         << statement.public_boundary_statement
         << statement.r0_root;
    for (const auto& cell : statement.output_cells) {
        hash << cell.column << cell.row;
    }
    for (uint32_t i = 0;
         i < statement.position_cells.size(); ++i) {
        hash << statement.position_cells[i].column
             << statement.position_cells[i].row;
        for (const auto& bit :
             statement.input_bit_cells[i]) {
            hash << bit.column << bit.row;
        }
    }
    return hash.GetHash();
}

bool ProveTileV1(
    const uint256& statement_commitment,
    const uint256& public_fs_seed,
    const uint256& prf_key,
    uint32_t row, uint32_t block,
    const std::array<int64_t, 32>& input,
    TileProofV1& out,
    std::string* why)
{
    out = {};
    if (statement_commitment.IsNull() ||
        public_fs_seed.IsNull() ||
        prf_key.IsNull()) {
        return Fail(why, "prove_public_shape");
    }
    const ga::TileWitness witness =
        ga::TraceTile({prf_key, row, block}, input);
    if (witness.cands.empty() ||
        witness.chacha_blocks == 0 ||
        witness.chacha_blocks > 4 ||
        witness.cands.size() >
            std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "prove_native_witness");
    }
    TileStatementV1 statement = BaseStatement(
        statement_commitment, public_fs_seed,
        prf_key, row, block,
        witness.chacha_blocks,
        static_cast<uint32_t>(witness.cands.size()));

    // First pass commits only challenge-independent columns. Both the hash
    // internal-SSA LogUp and RcSampler membership challenges are then rebuilt
    // from this one complete R0 row root.
    Built preliminary;
    const uint256 dummy_root =
        ChildChallengeDigest(
            public_fs_seed, statement_commitment,
            "r0_prepass", statement);
    if (!BuildComposition(
            statement, dummy_root,
            &witness, true, preliminary, why)) {
        return false;
    }
    const auto pre_r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            preliminary.cs, preliminary.columns,
            preliminary.base_columns);
    if (!pre_r0.valid ||
        pre_r0.base_row_commitment.IsNull()) {
        return Fail(
            why, "prove_pre_r0:" +
                pre_r0.note);
    }
    statement.r0_root = pre_r0.base_row_commitment;

    Built final;
    if (!BuildComposition(
            statement, statement.r0_root,
            &witness, false, final, why) ||
        final.public_boundary_statement.IsNull()) {
        return false;
    }
    const auto retained_r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            final.cs, final.columns,
            final.base_columns);
    if (!retained_r0.valid ||
        retained_r0.base_row_commitment !=
            statement.r0_root) {
        return Fail(
            why, "prove_r0_fixed_point:" +
                retained_r0.note);
    }
    statement.public_boundary_statement =
        final.public_boundary_statement;
    statement.output_cells = final.outputs;
    statement.position_cells =
        std::move(final.positions);
    statement.input_bit_cells =
        std::move(final.input_bits);
    statement.retained_node_commitment =
        ComputeRetainedNodeCommitmentV1(statement);
    if (statement.retained_node_commitment.IsNull()) {
        return Fail(why, "prove_retained_node");
    }
    uint32_t first_bad_row = 0;
    std::string first_bad_constraint;
    const uint32_t witness_violations =
        air_recurse::CountWitnessViolationsOnH(
            final.cs, final.columns,
            &first_bad_row, &first_bad_constraint);
    if (witness_violations != 0) {
        return Fail(
            why,
            "prove_witness_violation:" +
                first_bad_constraint +
                ":row=" +
                std::to_string(first_bad_row) +
                ":count=" +
                std::to_string(witness_violations));
    }
    const auto proved =
        aq::AirQuotientProveRowsSplitRapSafeV2(
            final.cs, final.columns,
            final.base_columns,
            ProofSeed(statement), {}, &retained_r0);
    if (!proved.ok || !proved.division_exact ||
        proved.proof.batch.groups.size() != 3 ||
        Fri3AlgDigestToUint256(
            proved.proof.batch.groups[0]
                .row_commit.root) != statement.r0_root) {
        return Fail(
            why, "prove_split_rap:" +
                proved.note);
    }
    out.statement = std::move(statement);
    out.quotient = proved.proof;
    out.native_verified = true;
    out.normalized_parent_consumed = false;
    if (!VerifyTileV1(out, why)) {
        out = {};
        return false;
    }
    return true;
}

bool VerifyTileV1(
    const TileProofV1& proof,
    std::string* why)
{
    const auto& statement = proof.statement;
    if (proof.version != kVersionV1 ||
        !proof.native_verified ||
        proof.normalized_parent_consumed ||
        statement.retained_node_commitment !=
            ComputeRetainedNodeCommitmentV1(statement) ||
        proof.quotient.version !=
            aq::kAirQuotientSplitRapRowsSafeProofVersionV2 ||
        proof.quotient.trace_rows !=
            statement.trace_rows ||
        proof.quotient.batch.groups.size() != 3 ||
        Fri3AlgDigestToUint256(
            proof.quotient.batch.groups[0]
                .row_commit.root) !=
            statement.r0_root) {
        return Fail(why, "verify_shape");
    }
    Built rebuilt;
    if (!BuildComposition(
            statement, statement.r0_root,
            nullptr, false, rebuilt, why) ||
        rebuilt.public_boundary_statement !=
            statement.public_boundary_statement ||
        rebuilt.outputs != statement.output_cells ||
        rebuilt.positions != statement.position_cells ||
        rebuilt.input_bits !=
            statement.input_bit_cells ||
        rebuilt.base_columns !=
            proof.quotient.base_column_indices) {
        return Fail(why, "verify_rebuild");
    }
    std::string proof_why;
    if (!aq::AirQuotientVerifyRowsSplitRapSafeV2(
            rebuilt.cs, proof.quotient,
            rebuilt.base_columns,
            ProofSeed(statement), &proof_why)) {
        return Fail(
            why, "verify_split_rap:" +
                proof_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:extract_chacha_sampler_child:"
            "native_chacha_to_sampler_to_output_verified;"
            "normalized_parent_consumption_open";
    }
    return true;
}

} // namespace matmul::v4::rc::extract_chacha_sampler_child
