// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_temporal_induction.h>

#include <hash.h>

#include <algorithm>
#include <functional>
#include <limits>
#include <utility>

namespace matmul::v4::rc::stage3_temporal {
namespace {

constexpr char kTemporalInductionDomainV1[] =
    "BTX_RC_STAGE3_TEMPORAL_INDUCTION_V1";

bool Fail(std::string* why, const char* message)
{
    if (why) *why = message;
    return false;
}

gf::Fp3 U32(uint32_t value)
{
    return gf::Fp3::FromFp(static_cast<gf::Fp>(value));
}

void HashRoot(HashWriter& hash, const TemporalRootU32V1& root)
{
    for (const uint32_t word : root.words) hash << word;
}

bool IsPowerOfTwo(uint32_t value)
{
    return value >= 2 && (value & (value - 1)) == 0;
}

void AddConstraint(
    aq::AirConstraintSystem<gf::Fp3>& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<gf::Fp3(
        const std::vector<gf::Fp3>&,
        const std::vector<gf::Fp3>&)> eval)
{
    aq::AirConstraint<gf::Fp3> constraint;
    constraint.name = name;
    constraint.kind = kind;
    constraint.alg_degree = degree;
    constraint.eval = std::move(eval);
    cs.constraints.push_back(std::move(constraint));
}

void InstallConstraints(
    aq::AirConstraintSystem<gf::Fp3>& cs,
    const TemporalInductionLayoutV1& layout,
    const TemporalInductionManifestV1& manifest)
{
    const gf::Fp3 zero = gf::Fp3::Zero();
    const gf::Fp3 one = gf::Fp3::One();

    // The verifier owns every semantic cell through a preprocessed mirror.
    // These equalities reject omitted/reordered/duplicated/spliced rows even
    // when a locally valid replacement transition exists.
    for (uint32_t field = 0;
         field < TemporalInductionLayoutV1::kSemanticFields;
         ++field) {
        AddConstraint(
            cs,
            "temporal.verifier_owned_row",
            aq::AirKind::kEverywhere,
            1,
            [layout, field](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Sub(
                    current[layout.Witness(field)],
                    current[layout.Expected(field)]);
            });
    }

    for (const uint32_t selector : {
             layout.Active(),
             layout.Padding(),
             layout.BaseSelector(),
             layout.FinalSelector()}) {
        AddConstraint(
            cs,
            "temporal.selector_boolean",
            aq::AirKind::kEverywhere,
            2,
            [selector, one](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    current[selector],
                    gf::Sub(current[selector], one));
            });
    }
    AddConstraint(
        cs,
        "temporal.active_padding_partition",
        aq::AirKind::kEverywhere,
        1,
        [layout, one](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(
                gf::Add(
                    current[layout.Active()],
                    current[layout.Padding()]),
                one);
        });
    AddConstraint(
        cs,
        "temporal.base_is_active",
        aq::AirKind::kEverywhere,
        2,
        [layout, one](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>&) {
            return gf::Mul(
                current[layout.BaseSelector()],
                gf::Sub(current[layout.Active()], one));
        });
    AddConstraint(
        cs,
        "temporal.final_is_active",
        aq::AirKind::kEverywhere,
        2,
        [layout, one](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>&) {
            return gf::Mul(
                current[layout.FinalSelector()],
                gf::Sub(current[layout.Active()], one));
        });

    AddConstraint(
        cs,
        "temporal.first_row_active",
        aq::AirKind::kFirstRow,
        1,
        [layout, one](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(current[layout.Active()], one);
        });
    AddConstraint(
        cs,
        "temporal.first_row_base",
        aq::AirKind::kFirstRow,
        1,
        [layout, one](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(
                current[layout.BaseSelector()], one);
        });
    AddConstraint(
        cs,
        "temporal.first_round_zero",
        aq::AirKind::kFirstRow,
        1,
        [layout](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>&) {
            return current[layout.Round()];
        });

    for (uint32_t word = 0;
         word < kTemporalRootWordsV1;
         ++word) {
        const gf::Fp3 expected =
            U32(manifest.base_root.words[word]);
        AddConstraint(
            cs,
            "temporal.base_anchor",
            aq::AirKind::kEverywhere,
            2,
            [layout, word, expected](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    current[layout.BaseSelector()],
                    gf::Sub(
                        current[layout.Input(word)],
                        expected));
            });
    }

    const gf::Fp3 final_round =
        U32(manifest.expected_rounds - 1);
    AddConstraint(
        cs,
        "temporal.final_round",
        aq::AirKind::kEverywhere,
        2,
        [layout, final_round](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>&) {
            return gf::Mul(
                current[layout.FinalSelector()],
                gf::Sub(
                    current[layout.Round()],
                    final_round));
        });
    for (uint32_t word = 0;
         word < kTemporalRootWordsV1;
         ++word) {
        const gf::Fp3 expected =
            U32(manifest.final_root.words[word]);
        AddConstraint(
            cs,
            "temporal.final_anchor",
            aq::AirKind::kEverywhere,
            2,
            [layout, word, expected](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    current[layout.FinalSelector()],
                    gf::Sub(
                        current[layout.Output(word)],
                        expected));
            });
    }

    // ACTIVE - FINAL is the continuation selector.  Since FINAL is a boolean
    // subset of ACTIVE, this stays degree one and avoids a cubic transition
    // gate.
    AddConstraint(
        cs,
        "temporal.next_row_active",
        aq::AirKind::kTransition,
        2,
        [layout, one](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>& next) {
            const gf::Fp3 continuation =
                gf::Sub(
                    current[layout.Active()],
                    current[layout.FinalSelector()]);
            return gf::Mul(
                continuation,
                gf::Sub(next[layout.Active()], one));
        });
    AddConstraint(
        cs,
        "temporal.strict_round_increment",
        aq::AirKind::kTransition,
        2,
        [layout, one](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>& next) {
            const gf::Fp3 continuation =
                gf::Sub(
                    current[layout.Active()],
                    current[layout.FinalSelector()]);
            const gf::Fp3 delta =
                gf::Sub(
                    gf::Sub(
                        next[layout.Round()],
                        current[layout.Round()]),
                    one);
            return gf::Mul(continuation, delta);
        });
    for (uint32_t word = 0;
         word < kTemporalRootWordsV1;
         ++word) {
        AddConstraint(
            cs,
            "temporal.output_to_next_input",
            aq::AirKind::kTransition,
            2,
            [layout, word](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>& next) {
                const gf::Fp3 continuation =
                    gf::Sub(
                        current[layout.Active()],
                        current[layout.FinalSelector()]);
                return gf::Mul(
                    continuation,
                    gf::Sub(
                        current[layout.Output(word)],
                        next[layout.Input(word)]));
            });
    }

    AddConstraint(
        cs,
        "temporal.final_to_padding",
        aq::AirKind::kTransition,
        2,
        [layout, one](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>& next) {
            return gf::Mul(
                current[layout.FinalSelector()],
                gf::Sub(next[layout.Padding()], one));
        });
    AddConstraint(
        cs,
        "temporal_padding_is_monotone",
        aq::AirKind::kTransition,
        2,
        [layout](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>& next) {
            return gf::Mul(
                current[layout.Padding()],
                next[layout.Active()]);
        });
    AddConstraint(
        cs,
        "temporal.last_row_padding",
        aq::AirKind::kLastRow,
        1,
        [layout, one](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(current[layout.Padding()], one);
        });

    AddConstraint(
        cs,
        "temporal.padding_round_zero",
        aq::AirKind::kEverywhere,
        2,
        [layout](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>&) {
            return gf::Mul(
                current[layout.Padding()],
                current[layout.Round()]);
        });
    for (uint32_t word = 0;
         word < kTemporalRootWordsV1;
         ++word) {
        AddConstraint(
            cs,
            "temporal.padding_input_zero",
            aq::AirKind::kEverywhere,
            2,
            [layout, word](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    current[layout.Padding()],
                    current[layout.Input(word)]);
            });
        AddConstraint(
            cs,
            "temporal.padding_output_zero",
            aq::AirKind::kEverywhere,
            2,
            [layout, word](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Mul(
                    current[layout.Padding()],
                    current[layout.Output(word)]);
            });
    }

    (void)zero;
}

bool InstallColumns(
    aq::AirConstraintSystem<gf::Fp3>& cs,
    std::vector<std::vector<gf::Fp3>>& columns,
    const TemporalInductionLayoutV1& layout,
    const TemporalInductionManifestV1& manifest,
    std::string* why)
{
    if (cs.n_rows != manifest.n_rows ||
        columns.size() != layout.base) {
        return Fail(why, "temporal:parent_shape");
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return Fail(why, "temporal:parent_column_rows");
        }
    }

    columns.resize(
        layout.End(),
        std::vector<gf::Fp3>(
            cs.n_rows, gf::Fp3::Zero()));
    cs.n_columns = layout.End();

    for (uint32_t row = 0;
         row < cs.n_rows;
         ++row) {
        std::array<gf::Fp3,
                   TemporalInductionLayoutV1::kSemanticFields>
            semantic{};
        for (auto& value : semantic) value = gf::Fp3::Zero();

        if (row < manifest.expected_rounds) {
            const TemporalTransitionV1& transition =
                manifest.transitions[row];
            semantic[TemporalInductionLayoutV1::kActiveField] =
                gf::Fp3::One();
            semantic[TemporalInductionLayoutV1::kBaseField] =
                row == 0 ? gf::Fp3::One() : gf::Fp3::Zero();
            semantic[TemporalInductionLayoutV1::kFinalField] =
                row + 1 == manifest.expected_rounds
                    ? gf::Fp3::One()
                    : gf::Fp3::Zero();
            semantic[TemporalInductionLayoutV1::kRoundField] =
                U32(transition.round);
            for (uint32_t word = 0;
                 word < kTemporalRootWordsV1;
                 ++word) {
                semantic[
                    TemporalInductionLayoutV1::kInputField +
                    word] =
                    U32(transition.input_root.words[word]);
                semantic[
                    TemporalInductionLayoutV1::kOutputField +
                    word] =
                    U32(transition.output_root.words[word]);
            }
        } else {
            semantic[TemporalInductionLayoutV1::kPaddingField] =
                gf::Fp3::One();
        }

        for (uint32_t field = 0;
             field < TemporalInductionLayoutV1::kSemanticFields;
             ++field) {
            columns[layout.Witness(field)][row] =
                semantic[field];
            columns[layout.Expected(field)][row] =
                semantic[field];
        }
    }

    for (uint32_t field = 0;
         field < TemporalInductionLayoutV1::kSemanticFields;
         ++field) {
        cs.preprocessed.emplace_back(
            layout.Expected(field),
            columns[layout.Expected(field)]);
    }
    return true;
}

} // namespace

TemporalRootU32V1 EncodeTemporalRootU32V1(
    const uint256& root)
{
    TemporalRootU32V1 out;
    for (uint32_t pair = 0; pair < 4; ++pair) {
        const uint64_t value =
            root.GetUint64(static_cast<int>(pair));
        out.words[2 * pair] =
            static_cast<uint32_t>(value);
        out.words[2 * pair + 1] =
            static_cast<uint32_t>(value >> 32);
    }
    return out;
}

uint256 DecodeTemporalRootU32V1(
    const TemporalRootU32V1& root)
{
    uint256 out;
    for (uint32_t pair = 0; pair < 4; ++pair) {
        const uint64_t value =
            static_cast<uint64_t>(
                root.words[2 * pair]) |
            (static_cast<uint64_t>(
                 root.words[2 * pair + 1])
             << 32);
        WriteLE64(
            out.data() + 8 * pair,
            value);
    }
    return out;
}

bool DecodeCanonicalTemporalRootU32V1(
    const std::array<gf::Fp3, kTemporalRootWordsV1>& lanes,
    TemporalRootU32V1& out,
    std::string* why)
{
    out = {};
    for (uint32_t word = 0;
         word < kTemporalRootWordsV1;
         ++word) {
        const gf::Fp3& lane = lanes[word];
        if (lane.c0 != gf::Canonical(lane.c0) ||
            lane.c1 != 0 ||
            lane.c2 != 0 ||
            lane.c0 >
                std::numeric_limits<uint32_t>::max()) {
            out = {};
            return Fail(
                why,
                "temporal:root_lane_not_canonical_u32");
        }
        out.words[word] =
            static_cast<uint32_t>(lane.c0);
    }
    return true;
}

uint32_t CanonicalTemporalTraceRowsV1(
    uint32_t expected_rounds)
{
    if (expected_rounds == 0 ||
        expected_rounds >
            kTemporalInductionMaxRoundsV1) {
        return 0;
    }
    uint64_t rows = 2;
    const uint64_t required =
        static_cast<uint64_t>(expected_rounds) + 1;
    while (rows < required) rows <<= 1;
    if (rows >
        std::numeric_limits<uint32_t>::max()) {
        return 0;
    }
    return static_cast<uint32_t>(rows);
}

uint256 ComputeTemporalInductionCommitmentV1(
    const TemporalInductionManifestV1& manifest)
{
    HashWriter hash;
    hash << kTemporalInductionDomainV1;
    hash << manifest.version;
    hash << manifest.expected_rounds;
    hash << manifest.n_rows;
    HashRoot(hash, manifest.base_root);
    HashRoot(hash, manifest.final_root);
    hash << static_cast<uint32_t>(
        manifest.transitions.size());
    for (const auto& transition :
         manifest.transitions) {
        hash << transition.round;
        HashRoot(hash, transition.input_root);
        HashRoot(hash, transition.output_root);
    }
    return hash.GetHash();
}

bool ValidateTemporalInductionManifestV1(
    const TemporalInductionManifestV1& manifest,
    std::string* why)
{
    if (manifest.version !=
        kTemporalInductionVersionV1) {
        return Fail(why, "temporal:version");
    }
    const uint32_t canonical_rows =
        CanonicalTemporalTraceRowsV1(
            manifest.expected_rounds);
    if (canonical_rows == 0 ||
        !IsPowerOfTwo(manifest.n_rows) ||
        manifest.n_rows != canonical_rows) {
        return Fail(why, "temporal:trace_rows");
    }
    if (manifest.transitions.size() !=
        manifest.expected_rounds) {
        return Fail(why, "temporal:round_count");
    }
    for (uint32_t round = 0;
         round < manifest.expected_rounds;
         ++round) {
        const auto& transition =
            manifest.transitions[round];
        if (transition.round != round) {
            return Fail(why, "temporal:round_order");
        }
        if (round == 0 &&
            transition.input_root !=
                manifest.base_root) {
            return Fail(why, "temporal:base_anchor");
        }
        if (round > 0 &&
            manifest.transitions[round - 1].
                    output_root !=
                transition.input_root) {
            return Fail(
                why,
                "temporal:transition_discontinuity");
        }
    }
    if (manifest.transitions.back().
            output_root != manifest.final_root) {
        return Fail(why, "temporal:final_anchor");
    }
    const uint256 expected =
        ComputeTemporalInductionCommitmentV1(
            manifest);
    if (manifest.commitment.IsNull() ||
        manifest.commitment != expected) {
        return Fail(why, "temporal:commitment");
    }
    if (why) *why = "temporal:manifest_ok";
    return true;
}

bool BuildTemporalInductionManifestV1(
    uint32_t expected_rounds,
    const TemporalRootU32V1& expected_base_root,
    const TemporalRootU32V1& expected_final_root,
    const std::vector<TemporalTransitionV1>& transitions,
    TemporalInductionManifestV1& out,
    std::string* why)
{
    out = {};
    out.version = kTemporalInductionVersionV1;
    out.expected_rounds = expected_rounds;
    out.n_rows =
        CanonicalTemporalTraceRowsV1(
            expected_rounds);
    out.base_root = expected_base_root;
    out.final_root = expected_final_root;
    out.transitions = transitions;
    if (out.n_rows == 0) {
        out = {};
        return Fail(why, "temporal:round_budget");
    }
    out.commitment =
        ComputeTemporalInductionCommitmentV1(out);
    if (!ValidateTemporalInductionManifestV1(
            out, why)) {
        out = {};
        return false;
    }
    return true;
}

uint32_t CountTemporalInductionViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns,
    uint32_t* first_row,
    std::string* first_constraint)
{
    if (cs.n_rows < 2 ||
        columns.size() != cs.n_columns) {
        return 1;
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) return 1;
    }

    std::vector<gf::Fp3> current(
        cs.n_columns, gf::Fp3::Zero());
    std::vector<gf::Fp3> next(
        cs.n_columns, gf::Fp3::Zero());
    uint32_t violations = 0;
    for (uint32_t row = 0;
         row < cs.n_rows;
         ++row) {
        for (uint32_t column = 0;
             column < cs.n_columns;
             ++column) {
            current[column] = columns[column][row];
            next[column] =
                columns[column][
                    (row + 1) % cs.n_rows];
        }
        for (const auto& constraint :
             cs.constraints) {
            bool applies = true;
            if (constraint.kind ==
                aq::AirKind::kTransition) {
                applies = row + 1 < cs.n_rows;
            } else if (
                constraint.kind ==
                aq::AirKind::kFirstRow) {
                applies = row == 0;
            } else if (
                constraint.kind ==
                aq::AirKind::kLastRow) {
                applies = row + 1 == cs.n_rows;
            }
            if (!applies) continue;
            if (!gf::IsZero(
                    constraint.eval(
                        current, next))) {
                if (violations == 0) {
                    if (first_row) *first_row = row;
                    if (first_constraint) {
                        *first_constraint =
                            constraint.name
                            ? constraint.name
                            : "";
                    }
                }
                ++violations;
            }
        }
    }
    return violations;
}

TemporalInductionAirV1 BuildTemporalInductionAirV1(
    const TemporalInductionManifestV1& verifier_manifest)
{
    TemporalInductionAirV1 out;
    std::string why;
    if (!ValidateTemporalInductionManifestV1(
            verifier_manifest, &why)) {
        out.note = why;
        return out;
    }

    out.layout = TemporalInductionLayoutV1(0);
    out.cs.n_rows = verifier_manifest.n_rows;
    out.cs.n_columns = 0;
    // Standalone temporal proofs use the verifier-time OOD pin.  The parent
    // appender below deliberately preserves an existing parent's policy:
    // appending a relation must not silently weaken its pre-existing exact
    // root-regeneration pins or switch its verifier cost model.
    out.cs.preprocessed_pin_ood = true;
    if (!InstallColumns(
            out.cs,
            out.columns,
            out.layout,
            verifier_manifest,
            &why)) {
        out.note = why;
        return out;
    }
    InstallConstraints(
        out.cs, out.layout, verifier_manifest);
    out.manifest_commitment =
        verifier_manifest.commitment;
    out.violations =
        CountTemporalInductionViolationsV1(
            out.cs, out.columns);
    out.verifier_owned_preprocessed_rows =
        out.cs.preprocessed.size() ==
            TemporalInductionLayoutV1::
                kSemanticFields &&
        out.cs.preprocessed_pin_ood;
    out.base_anchor_constrained = true;
    out.strict_round_increment_constrained = true;
    out.transition_continuity_constrained = true;
    out.final_anchor_constrained = true;
    out.active_padding_constrained = true;
    out.valid =
        out.violations == 0 &&
        out.verifier_owned_preprocessed_rows;
    out.note = out.valid
        ? "stage3:temporal_induction:"
          "air_foundation_complete:"
          "endpoint_aliases_and_recursive_consumption_open"
        : "stage3:temporal_induction:violations";
    return out;
}

TemporalInductionAttachmentV1
AppendTemporalInductionToParentV1(
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    const TemporalInductionManifestV1& verifier_manifest)
{
    TemporalInductionAttachmentV1 out;
    out.layout =
        TemporalInductionLayoutV1(
            parent_cs.n_columns);
    out.constraint_base =
        static_cast<uint32_t>(
            parent_cs.constraints.size());
    std::string why;
    if (!ValidateTemporalInductionManifestV1(
            verifier_manifest, &why) ||
        parent_cs.n_rows !=
            verifier_manifest.n_rows ||
        parent_columns.size() !=
            parent_cs.n_columns) {
        out.note =
            why.empty()
            ? "stage3:temporal_induction:"
              "parent_shape"
            : why;
        return out;
    }

    if (!InstallColumns(
            parent_cs,
            parent_columns,
            out.layout,
            verifier_manifest,
            &why)) {
        out.note = why;
        return out;
    }
    InstallConstraints(
        parent_cs, out.layout, verifier_manifest);

    out.constraints_added =
        static_cast<uint32_t>(
            parent_cs.constraints.size()) -
        out.constraint_base;
    out.columns_added =
        TemporalInductionLayoutV1::kColumns;
    out.violations =
        CountTemporalInductionViolationsV1(
            parent_cs, parent_columns);
    out.verifier_owned_preprocessed_rows = true;
    out.base_anchor_constrained = true;
    out.strict_round_increment_constrained = true;
    out.transition_continuity_constrained = true;
    out.final_anchor_constrained = true;
    out.active_padding_constrained = true;
    out.valid = out.violations == 0;
    out.note = out.valid
        ? "stage3:temporal_induction:"
          "normalized_parent_append_complete:"
          "endpoint_aliases_and_recursive_consumption_open"
        : "stage3:temporal_induction:"
          "normalized_parent_violations";
    return out;
}

} // namespace matmul::v4::rc::stage3_temporal
