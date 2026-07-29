// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_registry_membership_air.h>

#include <algorithm>
#include <array>
#include <functional>
#include <limits>

namespace matmul::v4::rc::stage3_registry_membership_air {
namespace {

using gf::Fp;
using gf::Fp3;

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

bool DigestEqual(
    const alg_hash::Digest& a,
    const alg_hash::Digest& b)
{
    for (uint32_t i = 0; i < a.size(); ++i) {
        if (gf::Canonical(a[i]) !=
            gf::Canonical(b[i])) {
            return false;
        }
    }
    return true;
}

bool DigestZero(const alg_hash::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](Fp value) {
            return gf::Canonical(value) == 0;
        });
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    uint32_t out = 2;
    while (out < value) {
        if (out >
            std::numeric_limits<uint32_t>::max() / 2) {
            return 0;
        }
        out <<= 1;
    }
    return out;
}

std::array<Fp3, kRegistryFamilyFieldsV1>
EntryFields(
    const ut::ProductionFamilyProgramEntryV1& entry)
{
    std::array<Fp3, kRegistryFamilyFieldsV1> out{};
    out[0] = U(entry.family_index);
    out[1] = U(static_cast<uint16_t>(entry.kind));
    out[2] = U(static_cast<uint16_t>(entry.role));
    for (uint32_t limb = 0; limb < 4; ++limb) {
        out[3 + limb] =
            Fp3::FromFp(
                gf::Canonical(
                    entry.program
                        .recursive_alg_hash[limb]));
        out[7 + limb] =
            Fp3::FromFp(
                gf::Canonical(
                    entry.public_input_schema
                        .recursive_alg_hash[limb]));
    }
    out[11] =
        entry.semantic_relation_complete
        ? Fp3::One()
        : Fp3::Zero();
    return out;
}

std::array<Fp3, kRegistryFamilyFieldsV1>
SelectedFields(const SelectedFamilyV1& selected)
{
    std::array<Fp3, kRegistryFamilyFieldsV1> out{};
    out[0] = U(selected.family_index);
    out[1] = U(static_cast<uint16_t>(selected.kind));
    out[2] = U(static_cast<uint16_t>(selected.role));
    for (uint32_t limb = 0; limb < 4; ++limb) {
        out[3 + limb] =
            Fp3::FromFp(
                gf::Canonical(
                    selected.program_alg_hash[limb]));
        out[7 + limb] =
            Fp3::FromFp(
                gf::Canonical(
                    selected.schema_alg_hash[limb]));
    }
    out[11] =
        selected.semantic_relation_complete
        ? Fp3::One()
        : Fp3::Zero();
    return out;
}

bool ExactProductionOrder(
    const ut::ProductionProgramRegistryV1& registry)
{
    const auto manifest =
        soundness_scenarios::
            BuildProductionProofSiteManifest(
                soundness_scenarios::
                    SelectedProductionProofSitePolicy());
    if (registry.version !=
            ut::kProductionProgramRegistryVersionV1 ||
        registry.families.size() !=
            ut::kProductionProgramFamilyCountV1 ||
        manifest.entries.size() !=
            registry.families.size()) {
        return false;
    }
    for (uint32_t row = 0;
         row < registry.families.size();
         ++row) {
        const auto& entry =
            registry.families[row];
        const auto& expected =
            manifest.entries[row];
        if (entry.family_index != row ||
            entry.kind != expected.kind ||
            entry.role != expected.role ||
            DigestZero(
                entry.program.recursive_alg_hash) ||
            DigestZero(
                entry.public_input_schema
                    .recursive_alg_hash)) {
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
    aq::AirConstraint<Fp3> c;
    c.name = name;
    c.kind = kind;
    c.alg_degree = degree;
    c.eval = std::move(eval);
    cs.constraints.push_back(std::move(c));
}

bool ConstraintActive(
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
    uint64_t violations = 0;
    std::vector<Fp3> current(cs.n_columns);
    std::vector<Fp3> next(cs.n_columns);
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
            if (ConstraintActive(
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
    const StatementV1& statement,
    aq::AirConstraintSystem<Fp3>& cs)
{
    cs.constraints =
        pa::BuildFixedConstraints(
            layout.poseidon);

    // Every canonical registry preimage lane is a u32-packed byte word (the
    // two framing lengths are also below 2^32 for this fixed registry).
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashRate;
         ++lane) {
        for (uint32_t bit = 0;
             bit < kRegistryAbsorbBitsV1;
             ++bit) {
            AddConstraint(
                cs,
                "stage3.registry.absorb_bit_boolean",
                aq::AirKind::kEverywhere, 2,
                [column =
                     layout.AbsorbBit(lane, bit)](
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
            "stage3.registry.absorb_u32_recompose",
            aq::AirKind::kEverywhere, 1,
            [layout, lane](
                const auto& cur,
                const auto&) {
                Fp3 recomposed =
                    Fp3::Zero();
                Fp3 power = Fp3::One();
                for (uint32_t bit = 0;
                     bit <
                         kRegistryAbsorbBitsV1;
                     ++bit) {
                    recomposed =
                        gf::Add(
                            recomposed,
                            gf::Mul(
                                power,
                                cur[
                                    layout.AbsorbBit(
                                        lane, bit)]));
                    power =
                        gf::Add(power, power);
                }
                return gf::Sub(
                    cur[layout.Absorb(lane)],
                    recomposed);
            });
    }

    // First sponge block starts at zero then add-absorbs the public rate row.
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashT;
         ++lane) {
        AddConstraint(
            cs,
            "stage3.registry.sponge_first_input",
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
            "stage3.registry.sponge_state_transition",
            aq::AirKind::kTransition, 1,
            [layout, lane](
                const auto& cur,
                const auto& next) {
                Fp3 expected =
                    air_recurse::PermOutputLane(
                        layout.poseidon.perm,
                        cur, lane);
                if (lane <
                    alg_hash::kAlgHashRate) {
                    expected =
                        gf::Add(
                            expected,
                            next[
                                layout.Absorb(
                                    lane)]);
                }
                return gf::Sub(
                    next[
                        layout.poseidon.perm
                            .InputCol(lane)],
                    expected);
            });
    }

    // The public digest is a trace export, constant across the trace and
    // captured at exactly the final real sponge block.
    for (uint32_t limb = 0;
         limb < alg_hash::kAlgHashDigestLen;
         ++limb) {
        const Fp3 expected =
            Fp3::FromFp(
                gf::Canonical(
                    statement.registry_alg_root[
                        limb]));
        AddConstraint(
            cs,
            "stage3.registry.digest_claim_first",
            aq::AirKind::kFirstRow, 1,
            [column =
                 layout.DigestClaim(limb),
             expected](
                const auto& cur,
                const auto&) {
                return gf::Sub(
                    cur[column], expected);
            });
        AddConstraint(
            cs,
            "stage3.registry.digest_claim_constant",
            aq::AirKind::kTransition, 1,
            [column =
                 layout.DigestClaim(limb)](
                const auto& cur,
                const auto& next) {
                return gf::Sub(
                    next[column], cur[column]);
            });
        AddConstraint(
            cs,
            "stage3.registry.digest_capture",
            aq::AirKind::kEverywhere, 2,
            [layout, limb](
                const auto& cur,
                const auto&) {
                return gf::Mul(
                    cur[layout.digest_selector],
                    gf::Sub(
                        air_recurse::
                            PermOutputLane(
                                layout.poseidon.perm,
                                cur, limb),
                        cur[
                            layout.DigestClaim(
                                limb)]));
            });
    }

    // Dynamic one-hot selector and exact selected-family tuple.
    AddConstraint(
        cs,
        "stage3.registry.selector_boolean",
        aq::AirKind::kEverywhere, 2,
        [column = layout.selector](
            const auto& cur,
            const auto&) {
            return gf::Mul(
                cur[column],
                gf::Sub(
                    cur[column],
                    Fp3::One()));
        });
    AddConstraint(
        cs,
        "stage3.registry.selector_family_range",
        aq::AirKind::kEverywhere, 2,
        [layout](
            const auto& cur,
            const auto&) {
            return gf::Mul(
                cur[layout.selector],
                gf::Sub(
                    Fp3::One(),
                    cur[
                        layout.family_active]));
        });
    AddConstraint(
        cs,
        "stage3.registry.selector_prefix_first",
        aq::AirKind::kFirstRow, 1,
        [column = layout.selector_prefix](
            const auto& cur,
            const auto&) {
            return cur[column];
        });
    AddConstraint(
        cs,
        "stage3.registry.selector_prefix_transition",
        aq::AirKind::kTransition, 1,
        [layout](
            const auto& cur,
            const auto& next) {
            return gf::Sub(
                next[
                    layout.selector_prefix],
                gf::Add(
                    cur[
                        layout.selector_prefix],
                    cur[layout.selector]));
        });
    AddConstraint(
        cs,
        "stage3.registry.selector_exactly_one",
        aq::AirKind::kLastRow, 1,
        [layout](
            const auto& cur,
            const auto&) {
            return gf::Sub(
                gf::Add(
                    cur[
                        layout.selector_prefix],
                    cur[layout.selector]),
                Fp3::One());
        });

    const auto selected =
        SelectedFields(statement.selected);
    for (uint32_t field = 0;
         field < kRegistryFamilyFieldsV1;
         ++field) {
        AddConstraint(
            cs,
            "stage3.registry.selected_claim_first",
            aq::AirKind::kFirstRow, 1,
            [column =
                 layout.SelectedField(field),
             expected = selected[field]](
                const auto& cur,
                const auto&) {
                return gf::Sub(
                    cur[column], expected);
            });
        AddConstraint(
            cs,
            "stage3.registry.selected_claim_constant",
            aq::AirKind::kTransition, 1,
            [column =
                 layout.SelectedField(field)](
                const auto& cur,
                const auto& next) {
                return gf::Sub(
                    next[column], cur[column]);
            });
        AddConstraint(
            cs,
            "stage3.registry.selected_table_match",
            aq::AirKind::kEverywhere, 2,
            [layout, field](
                const auto& cur,
                const auto&) {
                return gf::Mul(
                    cur[layout.selector],
                    gf::Sub(
                        cur[
                            layout.FamilyField(
                                field)],
                        cur[
                            layout.SelectedField(
                                field)]));
            });
    }
}

} // namespace

StatementV1 BuildStatementV1(
    const ut::ProductionProgramRegistryV1& registry,
    uint32_t family_index)
{
    StatementV1 out;
    out.registry_alg_root =
        registry.recursive_registry_commitment;
    out.selected.family_index = family_index;
    if (family_index >=
        registry.families.size()) {
        return out;
    }
    const auto& entry =
        registry.families[family_index];
    out.selected.kind = entry.kind;
    out.selected.role = entry.role;
    out.selected.program_alg_hash =
        entry.program.recursive_alg_hash;
    out.selected.schema_alg_hash =
        entry.public_input_schema
            .recursive_alg_hash;
    out.selected.semantic_relation_complete =
        entry.semantic_relation_complete;
    return out;
}

LayoutV1 CanonicalLayoutV1()
{
    LayoutV1 out;
    out.poseidon = pa::CanonicalLayout(0);
    uint32_t cursor = out.poseidon.End();
    out.absorb_base = cursor;
    cursor += alg_hash::kAlgHashRate;
    out.absorb_bit_base = cursor;
    cursor +=
        alg_hash::kAlgHashRate *
        kRegistryAbsorbBitsV1;
    out.digest_selector = cursor++;
    out.family_active = cursor++;
    out.family_field_base = cursor;
    cursor += kRegistryFamilyFieldsV1;
    out.selector = cursor++;
    out.selector_prefix = cursor++;
    out.selected_field_base = cursor;
    cursor += kRegistryFamilyFieldsV1;
    out.digest_claim_base = cursor;
    cursor += alg_hash::kAlgHashDigestLen;
    out.n_columns = cursor;
    return out;
}

ProductV1 BuildProductV1(
    const ut::ProductionProgramRegistryV1& registry,
    const StatementV1& statement)
{
    ProductV1 out;
    out.layout = CanonicalLayoutV1();
    out.statement = statement;
    out.exact_28_entry_order =
        ExactProductionOrder(registry);

    const auto preimage =
        ut::BuildProductionProgramRegistryAlgHashPreimageV1(
            registry);
    if (statement.version !=
            kRegistryMembershipAirVersionV1 ||
        registry.families.size() !=
            ut::kProductionProgramFamilyCountV1 ||
        preimage.empty() ||
        preimage.size() >
            std::numeric_limits<uint32_t>::max()) {
        out.note =
            "stage3:registry_membership:"
            "statement_shape";
        return out;
    }
    for (Fp value : preimage) {
        if (gf::Canonical(value) >
            std::numeric_limits<uint32_t>::max()) {
            out.note =
                "stage3:registry_membership:"
                "non_u32_preimage";
            return out;
        }
    }
    out.preimage_lanes =
        static_cast<uint32_t>(
            preimage.size());
    std::vector<Fp> padded;
    padded.reserve(
        preimage.size() +
        alg_hash::kAlgHashRate);
    for (Fp value : preimage) {
        padded.push_back(
            gf::Canonical(value));
    }
    padded.push_back(1);
    while (padded.size() %
               alg_hash::kAlgHashRate !=
           0) {
        padded.push_back(0);
    }
    out.sponge_blocks =
        static_cast<uint32_t>(
            padded.size() /
            alg_hash::kAlgHashRate);
    out.trace_rows =
        NextPowerOfTwo(
            std::max<uint32_t>({
                2,
                out.sponge_blocks,
                ut::kProductionProgramFamilyCountV1}));
    if (out.trace_rows == 0) {
        out.note =
            "stage3:registry_membership:"
            "trace_rows";
        return out;
    }

    out.cs.n_rows = out.trace_rows;
    out.cs.n_columns =
        out.layout.n_columns;
    BuildConstraints(
        out.layout, statement, out.cs);
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

    out.columns.assign(
        out.layout.n_columns,
        std::vector<Fp3>(
            out.trace_rows,
            Fp3::Zero()));
    auto set = [&out](
                   uint32_t column,
                   uint32_t row,
                   const Fp3& value) {
        out.columns[column][row] =
            value;
    };

    std::vector<uint32_t>
        selected_rows;
    for (uint32_t row = 0;
         row < registry.families.size();
         ++row) {
        if (registry.families[row]
                .family_index ==
            statement.selected.family_index) {
            selected_rows.push_back(row);
        }
    }
    const uint32_t selected_row =
        selected_rows.size() == 1
        ? selected_rows.front()
        : std::numeric_limits<uint32_t>::max();
    uint32_t prefix = 0;
    const auto selected_claim =
        SelectedFields(statement.selected);
    alg_hash::State state{};
    alg_hash::Digest captured{};
    for (uint32_t row = 0;
         row < out.trace_rows;
         ++row) {
        for (uint32_t lane = 0;
             lane < alg_hash::kAlgHashRate;
             ++lane) {
            const uint64_t word =
                row < out.sponge_blocks
                ? gf::Canonical(
                      padded[
                          uint64_t{row} *
                              alg_hash::
                                  kAlgHashRate +
                          lane])
                : 0;
            set(
                out.layout.Absorb(lane),
                row, U(word));
            for (uint32_t bit = 0;
                 bit <
                     kRegistryAbsorbBitsV1;
                 ++bit) {
                set(
                    out.layout.AbsorbBit(
                        lane, bit),
                    row,
                    ((word >> bit) & 1U) != 0
                    ? Fp3::One()
                    : Fp3::Zero());
            }
            state[lane] =
                gf::Add(
                    state[lane],
                    gf::FromU64(word));
        }
        const auto poseidon =
            pa::BuildWitness(
                out.layout.poseidon,
                state);
        for (uint32_t column = 0;
             column <
                 out.layout.poseidon.End();
             ++column) {
            set(
                column, row,
                poseidon.row[column]);
        }
        state = poseidon.output;
        if (row + 1 ==
            out.sponge_blocks) {
            set(
                out.layout.digest_selector,
                row, Fp3::One());
            for (uint32_t limb = 0;
                 limb <
                     alg_hash::
                         kAlgHashDigestLen;
                 ++limb) {
                captured[limb] =
                    state[limb];
            }
        }

        if (row <
            registry.families.size()) {
            set(
                out.layout.family_active,
                row, Fp3::One());
            const auto fields =
                EntryFields(
                    registry.families[row]);
            for (uint32_t field = 0;
                 field <
                     kRegistryFamilyFieldsV1;
                 ++field) {
                set(
                    out.layout.FamilyField(
                        field),
                    row, fields[field]);
            }
        }
        set(
            out.layout.selector_prefix,
            row, U(prefix));
        if (row == selected_row) {
            set(
                out.layout.selector,
                row, Fp3::One());
            ++prefix;
        }
        for (uint32_t field = 0;
             field <
                 kRegistryFamilyFieldsV1;
             ++field) {
            set(
                out.layout.SelectedField(
                    field),
                row,
                selected_claim[field]);
        }
        for (uint32_t limb = 0;
             limb <
                 alg_hash::kAlgHashDigestLen;
             ++limb) {
            set(
                out.layout.DigestClaim(limb),
                row,
                Fp3::FromFp(
                    gf::Canonical(
                        statement
                            .registry_alg_root[
                                limb])));
        }
    }

    // R0 is exactly the ordered immutable registry tape/table. It excludes
    // every selector, claim, prefix, bit and Poseidon witness cell.
    for (uint32_t lane = 0;
         lane < alg_hash::kAlgHashRate;
         ++lane) {
        out.preprocessed_base_columns.push_back(
            out.layout.Absorb(lane));
    }
    out.preprocessed_base_columns.push_back(
        out.layout.digest_selector);
    out.preprocessed_base_columns.push_back(
        out.layout.family_active);
    for (uint32_t field = 0;
         field < kRegistryFamilyFieldsV1;
         ++field) {
        out.preprocessed_base_columns.push_back(
            out.layout.FamilyField(field));
    }
    for (uint32_t column :
         out.preprocessed_base_columns) {
        out.cs.preprocessed.emplace_back(
            column, out.columns[column]);
    }
    out.cs.preprocessed_pin_ood = true;
    const auto base_session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            out.cs, out.columns,
            out.preprocessed_base_columns);
    if (!base_session.valid ||
        base_session.base_row_commitment.IsNull()) {
        out.note =
            "stage3:registry_membership:"
            "preprocessed_root:" +
            base_session.note;
        return out;
    }
    out.preprocessed_row_group_root =
        base_session.base_row_commitment;
    out.cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role =
            aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns =
            out.preprocessed_base_columns,
        .root =
            out.preprocessed_row_group_root,
    });

    const auto native =
        alg_hash::SpongeHashFp(preimage);
    out.exact_registry_alg_hash_replayed =
        DigestEqual(native, captured) &&
        DigestEqual(
            native,
            statement.registry_alg_root) &&
        DigestEqual(
            native,
            registry.recursive_registry_commitment);
    out.preprocessed_values_root_pinned = true;
    out.dynamic_one_hot_selection_constrained =
        true;
    out.selected_tuple_constrained = true;
    out.u32_absorb_encoding_constrained = true;
    out.quadratic_poseidon =
        out.max_constraint_degree <= 2;
    out.recursive_parent_consumes_exports =
        false;
    out.production_authority_ready = false;
    out.violations =
        CountViolations(out.cs, out.columns);
    out.valid =
        out.exact_28_entry_order &&
        out.exact_registry_alg_hash_replayed &&
        out.preprocessed_values_root_pinned &&
        out.dynamic_one_hot_selection_constrained &&
        out.selected_tuple_constrained &&
        out.u32_absorb_encoding_constrained &&
        out.quadratic_poseidon &&
        out.violations == 0 &&
        !out.recursive_parent_consumes_exports &&
        !out.production_authority_ready;
    out.note = out.valid
        ? "stage3:registry_membership:"
          "exact_alg_hash_and_one_hot_selection;"
          "same_parent_consumption_pending"
        : "stage3:registry_membership:"
          "constraint_or_statement_failure";
    return out;
}

ProveResultV1 ProveV1(
    const ut::ProductionProgramRegistryV1& registry,
    const StatementV1& statement,
    const uint256& public_fs_seed)
{
    ProveResultV1 out;
    out.statement = statement;
    const auto product =
        BuildProductV1(registry, statement);
    out.trace_rows = product.trace_rows;
    out.trace_columns =
        product.layout.n_columns;
    out.preprocessed_row_group_root =
        product.preprocessed_row_group_root;
    if (!product.valid ||
        public_fs_seed.IsNull()) {
        out.note =
            "stage3:registry_membership:"
            "prove:" + product.note;
        return out;
    }
    const auto proved =
        aq::AirQuotientProveRowsSplitRap(
            product.cs, product.columns,
            product.preprocessed_base_columns,
            public_fs_seed);
    if (!proved.ok ||
        !proved.division_exact ||
        proved.proof.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            proved.proof.batch.groups[0]
                .row_commit.root) !=
            product.preprocessed_row_group_root) {
        out.note =
            "stage3:registry_membership:"
            "prove:" + proved.note;
        return out;
    }
    out.proof = proved.proof;
    out.ok = true;
    out.note =
        "stage3:registry_membership:"
        "prove:split_rap_q192";
    return out;
}

VerificationAuditV1 VerifyV1(
    const ut::ProductionProgramRegistryV1& registry,
    const StatementV1& statement,
    const aq::AirQuotientSplitRapRowsProof& proof,
    const uint256& public_fs_seed)
{
    VerificationAuditV1 out;
    const auto product =
        BuildProductV1(registry, statement);
    out.trace_rows = product.trace_rows;
    out.trace_columns =
        product.layout.n_columns;
    out.constraints = product.constraints;
    out.max_constraint_degree =
        product.max_constraint_degree;
    out.preprocessed_row_group_root =
        product.preprocessed_row_group_root;
    const auto fail =
        [&](const std::string& detail) {
            out.valid = false;
            out.production_authority_ready =
                false;
            out.note =
                "stage3:registry_membership:"
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
            product.preprocessed_base_columns,
            public_fs_seed, &why)) {
        return fail(why);
    }
    if (proof.batch.groups.empty() ||
        Fri3AlgDigestToUint256(
            proof.batch.groups[0]
                .row_commit.root) !=
            product.preprocessed_row_group_root) {
        return fail("preprocessed_row_group_root");
    }
    out.exact_registry_alg_hash_replayed =
        product.exact_registry_alg_hash_replayed;
    out.exact_ordered_preprocessed_root =
        product.preprocessed_values_root_pinned;
    out.dynamic_one_hot_selection_verified =
        product.dynamic_one_hot_selection_constrained;
    out.family_index_kind_role_bound =
        product.selected_tuple_constrained;
    out.program_and_schema_alg_hash_bound =
        product.selected_tuple_constrained;
    out.semantic_completeness_bound =
        product.selected_tuple_constrained;
    out.canonical_u32_absorb_encoding_verified =
        product.u32_absorb_encoding_constrained;
    out.split_rap_quotient_fri_verified = true;
    out.recursive_parent_consumes_exports =
        false;
    out.production_authority_ready = false;
    out.valid =
        out.exact_registry_alg_hash_replayed &&
        out.exact_ordered_preprocessed_root &&
        out.dynamic_one_hot_selection_verified &&
        out.family_index_kind_role_bound &&
        out.program_and_schema_alg_hash_bound &&
        out.semantic_completeness_bound &&
        out.canonical_u32_absorb_encoding_verified &&
        out.split_rap_quotient_fri_verified &&
        !out.recursive_parent_consumes_exports &&
        !out.production_authority_ready;
    out.note = out.valid
        ? "stage3:registry_membership:"
          "verify:exact_registry_member;"
          "same_parent_consumption_pending"
        : "stage3:registry_membership:"
          "verify:invariant";
    return out;
}

} // namespace matmul::v4::rc::stage3_registry_membership_air
