// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_splitrap_ctl_coordinator.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>

#include <algorithm>
#include <limits>
#include <utility>

namespace matmul::v4::rc::splitrap_ctl {
namespace {

namespace gf = gkr_field;
namespace fp = recursive_fixedpoint;

using CS = aq::AirConstraintSystem<Fp3>;
using Constraint = aq::AirConstraint<Fp3>;

constexpr uint32_t kTupleNamespace = 0x43324232U;
constexpr uint32_t kTupleStage = 28;

enum ParentColumn : uint32_t {
    P_ACTIVE = 0,
    P_TERMINAL1,
    P_TERMINAL2,
    P_RUNNING1,
    P_RUNNING2,
    P_NUM_COLUMNS,
};

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:splitrap_ctl_coordinator:" + detail;
    }
    return false;
}

bool Canonical(const Fp3& value)
{
    return value.c0 < gf::kP &&
        value.c1 < gf::kP &&
        value.c2 < gf::kP;
}

void WriteFp3(HashWriter& hash, const Fp3& value)
{
    hash << gf::Canonical(value.c0);
    hash << gf::Canonical(value.c1);
    hash << gf::Canonical(value.c2);
}

RCStage3CtlSchedule BuildSchedule(
    uint32_t rows, int8_t multiplicity)
{
    RCStage3CtlSchedule out;
    out.events.reserve(rows);
    for (uint32_t row = 0; row < rows; ++row) {
        out.events.push_back({
            kTupleNamespace,
            kTupleStage,
            1 + row,
            multiplicity,
        });
    }
    return out;
}

RCStage3CtlParticipantSpec Participant(
    RCStage3RelationRole role,
    const RCStage3CtlSchedule& schedule)
{
    RCStage3CtlParticipantSpec out;
    out.role = role;
    out.event_count = schedule.events.size();
    for (const auto& event : schedule.events) {
        out.send_count += event.multiplicity == 1 ? 1 : 0;
        out.receive_count += event.multiplicity == -1 ? 1 : 0;
    }
    out.schedule_commitment =
        CommitRCStage3CtlSchedule(schedule);
    return out;
}

uint256 TranscriptSeed(
    const RCStage3CoupledBankDequantPin& source_pin,
    const uint256& public_seed)
{
    if (source_pin.pin_commitment.IsNull() ||
        public_seed.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << "BTX_RC_STAGE3_SPLITRAP_CTL_COORDINATOR_TRANSCRIPT_V1";
    hash << source_pin.pin_commitment;
    hash << public_seed;
    return hash.GetHash();
}

void CopyConstraintFamily(
    const CS& source,
    uint32_t offset,
    CS& destination)
{
    for (const auto& source_constraint :
         source.constraints) {
        Constraint copied;
        copied.name = source_constraint.name;
        copied.kind = source_constraint.kind;
        copied.alg_degree =
            source_constraint.alg_degree;
        const uint32_t width =
            source.n_columns;
        const auto eval =
            source_constraint.eval;
        copied.eval =
            [offset, width, eval](
                const std::vector<Fp3>& current,
                const std::vector<Fp3>& next) {
                std::vector<Fp3> local_current(
                    current.begin() + offset,
                    current.begin() + offset + width);
                std::vector<Fp3> local_next(
                    next.begin() + offset,
                    next.begin() + offset + width);
                return eval(
                    local_current, local_next);
            };
        destination.constraints.push_back(
            std::move(copied));
    }
    for (const auto& [column, values] :
         source.preprocessed) {
        destination.preprocessed.push_back(
            {offset + column, values});
    }
    for (const auto& [column, root] :
         source.preprocessed_roots) {
        destination.preprocessed_roots.push_back(
            {offset + column, root});
    }
}

struct AliasLayout {
    uint32_t relation_columns{0};
    uint32_t ctl_base{0};
    uint32_t value_column{0};
    std::vector<uint32_t> base_indices;
};

bool BuildDegree2AliasSystem(
    const CS& relation_cs,
    const RCStage3CtlDegree2AirSpec& ctl_spec,
    uint32_t source_column,
    CS& out,
    AliasLayout& layout,
    std::string* why)
{
    using namespace stage3_ctl_degree2_col;
    out = {};
    layout = {};
    if (relation_cs.n_rows < 2 ||
        (relation_cs.n_rows &
         (relation_cs.n_rows - 1)) != 0 ||
        relation_cs.n_columns == 0 ||
        source_column >=
            relation_cs.n_columns ||
        relation_cs.constraints.empty()) {
        return Fail(why, "alias_relation_shape");
    }
    const CS ctl_cs =
        BuildRCStage3CtlDegree2ConstraintSystem(
            ctl_spec);
    if (ctl_cs.n_rows !=
            relation_cs.n_rows ||
        ctl_cs.n_columns != NUM_COLUMNS ||
        ctl_cs.constraints.empty() ||
        relation_cs.n_columns >
            std::numeric_limits<uint32_t>::max() -
                NUM_COLUMNS) {
        return Fail(why, "alias_ctl_shape");
    }
    out.n_rows = relation_cs.n_rows;
    out.n_columns =
        relation_cs.n_columns + NUM_COLUMNS;
    out.preprocessed_pin_ood =
        relation_cs.preprocessed_pin_ood ||
        ctl_cs.preprocessed_pin_ood;
    CopyConstraintFamily(
        relation_cs, 0, out);
    CopyConstraintFamily(
        ctl_cs, relation_cs.n_columns, out);

    const uint32_t ctl_value =
        relation_cs.n_columns + VALUE;
    out.constraints.push_back({
        "stage3.splitrap_ctl.direct_value_alias",
        aq::AirKind::kEverywhere,
        1,
        [source_column, ctl_value](
            const std::vector<Fp3>& current,
            const std::vector<Fp3>&) {
            return gf::Sub(
                current[source_column],
                current[ctl_value]);
        },
    });
    layout.relation_columns =
        relation_cs.n_columns;
    layout.ctl_base =
        relation_cs.n_columns;
    layout.value_column = ctl_value;
    layout.base_indices.reserve(
        relation_cs.n_columns + 5);
    for (uint32_t column = 0;
         column < relation_cs.n_columns;
         ++column) {
        layout.base_indices.push_back(column);
    }
    for (uint32_t column = NAMESPACE;
         column <= MULTIPLICITY;
         ++column) {
        layout.base_indices.push_back(
            layout.ctl_base + column);
    }
    return true;
}

bool BuildAliasColumns(
    const AliasLayout& layout,
    const std::vector<std::vector<Fp3>>&
        relation_columns,
    const RCStage3CtlDegree2Witness& ctl,
    std::vector<std::vector<Fp3>>& out,
    std::string* why)
{
    using namespace stage3_ctl_degree2_col;
    out.clear();
    if (layout.relation_columns == 0 ||
        relation_columns.size() !=
            layout.relation_columns ||
        !ctl.ok ||
        ctl.columns.size() != NUM_COLUMNS) {
        return Fail(why, "alias_witness_shape");
    }
    const size_t rows =
        relation_columns.front().size();
    for (const auto& column :
         relation_columns) {
        if (column.size() != rows) {
            return Fail(
                why,
                "alias_relation_rows");
        }
    }
    for (const auto& column :
         ctl.columns) {
        if (column.size() != rows) {
            return Fail(why, "alias_ctl_rows");
        }
    }
    out = relation_columns;
    out.insert(
        out.end(),
        ctl.columns.begin(),
        ctl.columns.end());
    return true;
}

bool AliasValuesMatch(
    const AliasLayout& layout,
    uint32_t source_column,
    const std::vector<std::vector<Fp3>>&
        relation_columns,
    const RCStage3CtlDegree2Witness& ctl,
    std::string* why)
{
    if (source_column >= relation_columns.size() ||
        ctl.columns.size() !=
            stage3_ctl_degree2_col::NUM_COLUMNS) {
        return Fail(why, "alias_match_shape");
    }
    const auto& values =
        ctl.columns[
            stage3_ctl_degree2_col::VALUE];
    if (relation_columns[source_column].size() !=
            values.size()) {
        return Fail(why, "alias_match_rows");
    }
    for (size_t row = 0;
         row < values.size(); ++row) {
        if (!gf::Eq(
                relation_columns[
                    source_column][row],
                values[row])) {
            return Fail(why, "alias_value_mismatch");
        }
    }
    return layout.value_column ==
            layout.ctl_base +
                stage3_ctl_degree2_col::VALUE ||
        Fail(why, "alias_layout");
}

std::vector<std::vector<Fp3>>
BuildPrechallengeColumns(
    const AliasLayout& layout,
    const std::vector<std::vector<Fp3>>&
        relation_columns,
    uint32_t source_column,
    const RCStage3CtlSchedule& schedule)
{
    using namespace stage3_ctl_degree2_col;
    const uint32_t rows =
        relation_columns.front().size();
    std::vector<std::vector<Fp3>> out =
        relation_columns;
    out.resize(
        layout.relation_columns + NUM_COLUMNS,
        std::vector<Fp3>(
            rows, Fp3::Zero()));
    for (uint32_t row = 0;
         row < rows; ++row) {
        const auto& event =
            schedule.events[row];
        out[layout.ctl_base + NAMESPACE][row] =
            gf::FromU64_3(event.namespace_id);
        out[layout.ctl_base + STAGE][row] =
            gf::FromU64_3(event.stage);
        out[layout.ctl_base + ADDRESS][row] =
            gf::FromU64_3(event.address);
        out[layout.ctl_base + VALUE][row] =
            relation_columns[source_column][row];
        out[layout.ctl_base + MULTIPLICITY][row] =
            gf::FromSigned3(event.multiplicity);
    }
    return out;
}

CS ProjectionRelationSystem(uint32_t rows)
{
    CS out;
    out.n_rows = rows;
    out.n_columns = 2;
    out.constraints.push_back({
        "stage3.splitrap_ctl.projection_copy",
        aq::AirKind::kEverywhere,
        1,
        [](const std::vector<Fp3>& current,
           const std::vector<Fp3>&) {
            return gf::Sub(
                current[0], current[1]);
        },
    });
    return out;
}

uint256 ChildSeed(
    const RCStage3CtlManifest& manifest,
    const std::array<RCStage3CtlChildPin, 2>& pins,
    const RCStage3CtlChallenges& challenges,
    uint32_t ordinal,
    const uint256& public_seed)
{
    if (ordinal >= pins.size() ||
        public_seed.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_SPLITRAP_CTL_CHILD_SEED_V1";
    hash << public_seed;
    hash << manifest.bus_id;
    hash << manifest.transcript_seed;
    for (const auto& participant :
         manifest.participants) {
        hash <<
            static_cast<uint16_t>(
                participant.role);
        hash << participant.event_count;
        hash << participant.send_count;
        hash << participant.receive_count;
        hash << participant.schedule_commitment;
    }
    for (const auto& pin : pins) {
        hash << static_cast<uint16_t>(pin.role);
        hash << pin.schedule_commitment;
        hash << pin.trace_commitment;
    }
    hash << CommitRCStage3CtlChallenges(
        challenges);
    hash << ordinal;
    return hash.GetHash();
}

uint256 ProofCommitment(
    const aq::AirQuotientSplitRapRowsProof& proof)
{
    std::vector<unsigned char> bytes;
    if (aq::SerializeAirQuotientSplitRapRowsProof(
            proof, bytes) == 0) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_SPLITRAP_CTL_CHILD_PROOF_V1";
    hash << bytes;
    return hash.GetHash();
}

uint256 PaddingCommitment(uint32_t slot)
{
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_SPLITRAP_CTL_PADDING_V1";
    hash << slot;
    return hash.GetHash();
}

CS ParentSystem(
    const std::array<Arity4TerminalSlotV1, 4>&
        slots)
{
    CS out;
    out.n_rows = 4;
    out.n_columns = P_NUM_COLUMNS;
    out.preprocessed_pin_ood = true;
    std::vector<Fp3> active(
        4, Fp3::Zero());
    std::vector<Fp3> terminal1(
        4, Fp3::Zero());
    std::vector<Fp3> terminal2(
        4, Fp3::Zero());
    for (uint32_t row = 0;
         row < 4; ++row) {
        active[row] =
            slots[row].active
            ? Fp3::One()
            : Fp3::Zero();
        terminal1[row] =
            slots[row].terminal.alpha1_sum;
        terminal2[row] =
            slots[row].terminal.alpha2_sum;
    }
    out.preprocessed = {
        {P_ACTIVE, active},
        {P_TERMINAL1, terminal1},
        {P_TERMINAL2, terminal2},
    };
    out.constraints.push_back({
        "stage3.splitrap_ctl.parent.active_boolean",
        aq::AirKind::kEverywhere,
        2,
        [](const std::vector<Fp3>& current,
           const std::vector<Fp3>&) {
            return gf::Mul(
                current[P_ACTIVE],
                gf::Sub(
                    current[P_ACTIVE],
                    Fp3::One()));
        },
    });
    out.constraints.push_back({
        "stage3.splitrap_ctl.parent.padding_terminal1_zero",
        aq::AirKind::kEverywhere,
        2,
        [](const std::vector<Fp3>& current,
           const std::vector<Fp3>&) {
            return gf::Mul(
                gf::Sub(
                    Fp3::One(),
                    current[P_ACTIVE]),
                current[P_TERMINAL1]);
        },
    });
    out.constraints.push_back({
        "stage3.splitrap_ctl.parent.padding_terminal2_zero",
        aq::AirKind::kEverywhere,
        2,
        [](const std::vector<Fp3>& current,
           const std::vector<Fp3>&) {
            return gf::Mul(
                gf::Sub(
                    Fp3::One(),
                    current[P_ACTIVE]),
                current[P_TERMINAL2]);
        },
    });
    out.constraints.push_back({
        "stage3.splitrap_ctl.parent.running1_first",
        aq::AirKind::kFirstRow,
        1,
        [](const std::vector<Fp3>& current,
           const std::vector<Fp3>&) {
            return current[P_RUNNING1];
        },
    });
    out.constraints.push_back({
        "stage3.splitrap_ctl.parent.running2_first",
        aq::AirKind::kFirstRow,
        1,
        [](const std::vector<Fp3>& current,
           const std::vector<Fp3>&) {
            return current[P_RUNNING2];
        },
    });
    out.constraints.push_back({
        "stage3.splitrap_ctl.parent.running1_transition",
        aq::AirKind::kTransition,
        1,
        [](const std::vector<Fp3>& current,
           const std::vector<Fp3>& next) {
            return gf::Sub(
                next[P_RUNNING1],
                gf::Add(
                    current[P_RUNNING1],
                    current[P_TERMINAL1]));
        },
    });
    out.constraints.push_back({
        "stage3.splitrap_ctl.parent.running2_transition",
        aq::AirKind::kTransition,
        1,
        [](const std::vector<Fp3>& current,
           const std::vector<Fp3>& next) {
            return gf::Sub(
                next[P_RUNNING2],
                gf::Add(
                    current[P_RUNNING2],
                    current[P_TERMINAL2]));
        },
    });
    out.constraints.push_back({
        "stage3.splitrap_ctl.parent.running1_last",
        aq::AirKind::kLastRow,
        1,
        [](const std::vector<Fp3>& current,
           const std::vector<Fp3>&) {
            return gf::Add(
                current[P_RUNNING1],
                current[P_TERMINAL1]);
        },
    });
    out.constraints.push_back({
        "stage3.splitrap_ctl.parent.running2_last",
        aq::AirKind::kLastRow,
        1,
        [](const std::vector<Fp3>& current,
           const std::vector<Fp3>&) {
            return gf::Add(
                current[P_RUNNING2],
                current[P_TERMINAL2]);
        },
    });
    return out;
}

std::vector<std::vector<Fp3>> ParentColumns(
    const std::array<Arity4TerminalSlotV1, 4>&
        slots)
{
    std::vector<std::vector<Fp3>> out(
        P_NUM_COLUMNS,
        std::vector<Fp3>(
            4, Fp3::Zero()));
    Fp3 running1 = Fp3::Zero();
    Fp3 running2 = Fp3::Zero();
    for (uint32_t row = 0;
         row < 4; ++row) {
        out[P_ACTIVE][row] =
            slots[row].active
            ? Fp3::One()
            : Fp3::Zero();
        out[P_TERMINAL1][row] =
            slots[row].terminal.alpha1_sum;
        out[P_TERMINAL2][row] =
            slots[row].terminal.alpha2_sum;
        out[P_RUNNING1][row] = running1;
        out[P_RUNNING2][row] = running2;
        running1 = gf::Add(
            running1,
            out[P_TERMINAL1][row]);
        running2 = gf::Add(
            running2,
            out[P_TERMINAL2][row]);
    }
    return out;
}

uint256 ParentSeed(
    const RCStage3CtlManifest& manifest,
    const RCStage3CtlChallenges& challenges,
    const std::array<
        Arity4TerminalSlotV1, 4>& slots,
    const uint256& public_seed)
{
    if (public_seed.IsNull()) return {};
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_SPLITRAP_CTL_ARITY4_PARENT_SEED_V1";
    hash << public_seed;
    hash << manifest.bus_id;
    hash << manifest.transcript_seed;
    hash << CommitRCStage3CtlChallenges(challenges);
    for (uint32_t slot = 0;
         slot < slots.size(); ++slot) {
        hash << slot;
        hash << slots[slot].active;
        hash << slots[slot].child_proof_commitment;
        WriteFp3(
            hash,
            slots[slot].terminal.alpha1_sum);
        WriteFp3(
            hash,
            slots[slot].terminal.alpha2_sum);
    }
    return hash.GetHash();
}

uint256 ReceiptCommitment(
    const CoupledBankEqualityReceiptV1& receipt)
{
    if (receipt.parent_seed.IsNull() ||
        receipt.parent_proof.trace_commit.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_SPLITRAP_CTL_RECEIPT_V1";
    hash << receipt.version;
    hash << receipt.parent_seed;
    hash << receipt.parent_proof.trace_commit;
    for (const auto& child :
         receipt.children) {
        hash << child.proof_commitment;
    }
    return hash.GetHash();
}

bool CanonicalManifest(
    const RCStage3CoupledBankDequantPin& source_pin,
    const uint256& public_seed,
    const CoupledBankEqualityReceiptV1& receipt)
{
    if (receipt.manifest.bus_id !=
            kCoupledBankEqualityBusId ||
        receipt.manifest.transcript_seed !=
            TranscriptSeed(
                source_pin, public_seed) ||
        receipt.manifest.participants.size() != 2 ||
        receipt.schedules[0] !=
            BuildSchedule(
                source_pin.n_rows, 1) ||
        receipt.schedules[1] !=
            BuildSchedule(
                source_pin.n_rows, -1)) {
        return false;
    }
    return
        receipt.manifest.participants[0] ==
            Participant(
                RCStage3RelationRole::CoupledBank,
                receipt.schedules[0]) &&
        receipt.manifest.participants[1] ==
            Participant(
                RCStage3RelationRole::CompositionLink,
                receipt.schedules[1]);
}

bool CanonicalSlots(
    const CoupledBankEqualityReceiptV1& receipt)
{
    if (!receipt.terminal_slots[0].active ||
        !receipt.terminal_slots[1].active ||
        receipt.terminal_slots[2].active ||
        receipt.terminal_slots[3].active) {
        return false;
    }
    for (uint32_t slot = 0;
         slot < 2; ++slot) {
        if (receipt.terminal_slots[slot]
                .child_proof_commitment !=
                receipt.children[slot]
                    .proof_commitment ||
            !(receipt.terminal_slots[slot]
                  .terminal ==
              receipt.children[slot]
                  .pin.terminal)) {
            return false;
        }
    }
    for (uint32_t slot = 2;
         slot < 4; ++slot) {
        if (receipt.terminal_slots[slot]
                .child_proof_commitment !=
                PaddingCommitment(slot) ||
            !gf::IsZero(
                receipt.terminal_slots[slot]
                    .terminal.alpha1_sum) ||
            !gf::IsZero(
                receipt.terminal_slots[slot]
                    .terminal.alpha2_sum)) {
            return false;
        }
    }
    return true;
}

} // namespace

bool ProveCoupledBankEqualityReceiptV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const std::vector<std::vector<Fp3>>&
        relation_columns,
    const uint256& public_seed,
    CoupledBankEqualityReceiptV1& out,
    std::string* why)
{
    out = {};
    if (public_seed.IsNull() ||
        source_pin.pin_commitment.IsNull() ||
        source_pin.pin_commitment !=
            ComputeRCStage3CoupledBankDequantPinCommitment(
                source_pin) ||
        source_pin.logical_rows !=
            source_pin.n_rows ||
        source_pin.n_rows < 2 ||
        (source_pin.n_rows &
         (source_pin.n_rows - 1)) != 0 ||
        source_pin.n_coeffs !=
            source_pin.n_rows ||
        relation_columns.size() !=
            kRCStage3CoupledBankDequantColumns) {
        return Fail(why, "prove_shape");
    }
    for (const auto& column :
         relation_columns) {
        if (column.size() !=
                source_pin.n_rows) {
            return Fail(why, "prove_rows");
        }
        for (const auto& value : column) {
            if (!Canonical(value)) {
                return Fail(
                    why,
                    "prove_noncanonical");
            }
        }
    }
    out.schedules = {
        BuildSchedule(
            source_pin.n_rows, 1),
        BuildSchedule(
            source_pin.n_rows, -1),
    };
    out.manifest.bus_id =
        kCoupledBankEqualityBusId;
    out.manifest.transcript_seed =
        TranscriptSeed(source_pin, public_seed);
    out.manifest.participants = {
        Participant(
            RCStage3RelationRole::CoupledBank,
            out.schedules[0]),
        Participant(
            RCStage3RelationRole::CompositionLink,
            out.schedules[1]),
    };
    if (out.manifest.transcript_seed.IsNull()) {
        return Fail(why, "prove_manifest");
    }

    CS producer_relation;
    if (!fp::BuildNormalizedCoupledBankConstraintSystem(
            source_pin, producer_relation, why)) {
        return false;
    }
    // The production dequant relation now carries one canonical Split-RAP
    // auxiliary-zero column after its six semantic columns. The receipt API
    // intentionally accepts only those six semantic columns; materialize the
    // protocol-owned auxiliary column here instead of making callers forge a
    // seventh endpoint value.
    std::vector<std::vector<Fp3>>
        producer_columns = relation_columns;
    producer_columns.resize(
        producer_relation.n_columns,
        std::vector<Fp3>(
            source_pin.n_rows,
            Fp3::Zero()));
    const std::vector<Fp3>& values =
        relation_columns[
            kRCStage3CoupledBankOutput];
    const CS receiver_relation =
        ProjectionRelationSystem(
            source_pin.n_rows);
    const std::vector<std::vector<Fp3>>
        receiver_columns{values, values};

    const RCStage3CtlChallenges placeholder{
        gf::FromU64_3(2),
        gf::FromU64_3(3),
        gf::FromU64_3(5),
        gf::FromU64_3(7),
    };
    const RCStage3CtlTerminal zero_terminal{};
    std::array<CS, 2> placeholder_cs;
    std::array<AliasLayout, 2> layouts;
    if (!BuildDegree2AliasSystem(
            producer_relation,
            {kRCStage3CtlDegree2Version,
             out.schedules[0], placeholder,
             zero_terminal},
            kRCStage3CoupledBankOutput,
            placeholder_cs[0],
            layouts[0], why) ||
        !BuildDegree2AliasSystem(
            receiver_relation,
            {kRCStage3CtlDegree2Version,
             out.schedules[1], placeholder,
             zero_terminal},
            0,
            placeholder_cs[1],
            layouts[1], why)) {
        return false;
    }
    std::array<
        aq::AirQuotientTwoEpochBaseRowSession,
        2> r0_sessions;
    const auto producer_phase0 =
        BuildPrechallengeColumns(
            layouts[0], producer_columns,
            kRCStage3CoupledBankOutput,
            out.schedules[0]);
    const auto receiver_phase0 =
        BuildPrechallengeColumns(
            layouts[1], receiver_columns,
            0,
            out.schedules[1]);
    r0_sessions[0] =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            placeholder_cs[0],
            producer_phase0,
            layouts[0].base_indices);
    r0_sessions[1] =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            placeholder_cs[1],
            receiver_phase0,
            layouts[1].base_indices);
    if (!r0_sessions[0].valid ||
        !r0_sessions[1].valid) {
        return Fail(why, "prove_phase0");
    }

    std::array<RCStage3CtlChildPin, 2>
        prechallenge_pins;
    for (uint32_t child = 0;
         child < 2; ++child) {
        const auto& participant =
            out.manifest.participants[child];
        auto& pin =
            prechallenge_pins[child];
        pin.role = participant.role;
        pin.bus_id =
            out.manifest.bus_id;
        pin.event_count =
            participant.event_count;
        pin.send_count =
            participant.send_count;
        pin.receive_count =
            participant.receive_count;
        pin.schedule_commitment =
            participant.schedule_commitment;
        pin.trace_commitment =
            r0_sessions[child]
                .base_row_commitment;
    }
    std::vector<RCStage3CtlChildPin>
        challenge_pins(
            prechallenge_pins.begin(),
            prechallenge_pins.end());
    if (!DeriveRCStage3CtlChallenges(
            out.manifest, challenge_pins,
            out.challenges, why)) {
        return false;
    }
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(
            out.challenges);
    if (challenge_commitment.IsNull()) {
        return Fail(
            why,
            "prove_challenge_commitment");
    }

    const auto producer_ctl =
        BuildRCStage3CtlDegree2Witness(
            out.schedules[0], values,
            out.challenges);
    const auto receiver_ctl =
        BuildRCStage3CtlDegree2Witness(
            out.schedules[1], values,
            out.challenges);
    if (!producer_ctl.ok ||
        !receiver_ctl.ok) {
        return Fail(why, "prove_ctl_witness");
    }
    const std::array<
        RCStage3CtlDegree2Witness, 2>
        ctl_witnesses{
            producer_ctl, receiver_ctl};
    std::array<CS, 2> final_cs;
    const std::array<const CS*, 2>
        relation_systems{
            &producer_relation,
            &receiver_relation};
    const std::array<
        const std::vector<
            std::vector<Fp3>>*, 2>
        relation_witnesses{
            &producer_columns,
            &receiver_columns};
    const std::array<uint32_t, 2>
        source_columns{
            kRCStage3CoupledBankOutput, 0};
    std::array<std::vector<
        std::vector<Fp3>>, 2>
        combined_columns;
    std::array<RCStage3CtlChildPin, 2>
        final_pins =
            prechallenge_pins;
    for (uint32_t child = 0;
         child < 2; ++child) {
        final_pins[child].challenge_commitment =
            challenge_commitment;
        final_pins[child].terminal =
            ctl_witnesses[child].terminal;
        if (!BuildDegree2AliasSystem(
                *relation_systems[child],
                {kRCStage3CtlDegree2Version,
                 out.schedules[child],
                 out.challenges,
                 ctl_witnesses[child]
                     .terminal},
                source_columns[child],
                final_cs[child],
                layouts[child], why) ||
            !AliasValuesMatch(
                layouts[child],
                source_columns[child],
                *relation_witnesses[child],
                ctl_witnesses[child],
                why) ||
            !BuildAliasColumns(
                layouts[child],
                *relation_witnesses[child],
                ctl_witnesses[child],
                combined_columns[child],
                why)) {
            return false;
        }
    }
    for (uint32_t child = 0;
         child < 2; ++child) {
        const uint256 seed =
            ChildSeed(
                out.manifest,
                final_pins,
                out.challenges,
                child, public_seed);
        const auto proved =
            aq::AirQuotientProveRowsSplitRap(
                final_cs[child],
                combined_columns[child],
                layouts[child].base_indices,
                seed, {},
                &r0_sessions[child]);
        if (!proved.ok ||
            !proved.division_exact) {
            return Fail(
                why,
                "prove_child_" +
                    std::to_string(child) +
                    ":" + proved.note);
        }
        out.children[child].proof =
            proved.proof;
        out.children[child].proof_commitment =
            ProofCommitment(
                out.children[child].proof);
        final_pins[child].auxiliary_commitment =
            out.children[child]
                .proof_commitment;
        out.children[child].pin =
            final_pins[child];
        if (out.children[child]
                .proof_commitment.IsNull()) {
            return Fail(
                why,
                "prove_child_codec");
        }
    }
    std::vector<RCStage3CtlChildPin>
        final_pin_vector{
            final_pins.begin(),
            final_pins.end()};
    if (!VerifyRCStage3CtlPublicPinComposition(
            out.manifest,
            final_pin_vector, why)) {
        return false;
    }

    for (uint32_t slot = 0;
         slot < 2; ++slot) {
        out.terminal_slots[slot].active =
            true;
        out.terminal_slots[slot]
            .child_proof_commitment =
            out.children[slot]
                .proof_commitment;
        out.terminal_slots[slot].terminal =
            out.children[slot].pin.terminal;
    }
    for (uint32_t slot = 2;
         slot < 4; ++slot) {
        out.terminal_slots[slot].active =
            false;
        out.terminal_slots[slot]
            .child_proof_commitment =
            PaddingCommitment(slot);
    }
    out.parent_seed =
        ParentSeed(
            out.manifest, out.challenges,
            out.terminal_slots, public_seed);
    const CS parent_cs =
        ParentSystem(out.terminal_slots);
    const auto parent_columns =
        ParentColumns(out.terminal_slots);
    const auto parent_proved =
        aq::AirQuotientProveRows(
            parent_cs, parent_columns,
            out.parent_seed, {});
    if (!parent_proved.ok ||
        !parent_proved.division_exact) {
        return Fail(
            why,
            "prove_parent:" +
                parent_proved.note);
    }
    out.parent_proof =
        parent_proved.proof;
    out.receipt_commitment =
        ReceiptCommitment(out);
    if (out.receipt_commitment.IsNull()) {
        return Fail(
            why,
            "prove_receipt_commitment");
    }
    if (why != nullptr) {
        *why =
            "stage3:splitrap_ctl_coordinator:"
            "one_role_receipt_proved";
    }
    return true;
}

CoupledBankEqualityAuditV1
VerifyCoupledBankEqualityReceiptV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const CoupledBankEqualityReceiptV1& receipt,
    const uint256& public_seed)
{
    CoupledBankEqualityAuditV1 out;
    out.rows = source_pin.n_rows;
    const auto fail =
        [&](const std::string& detail) {
            out.note =
                "stage3:splitrap_ctl_coordinator:" +
                detail;
            return out;
        };
    if (receipt.version !=
            kCoupledBankEqualityReceiptVersion ||
        public_seed.IsNull() ||
        source_pin.pin_commitment.IsNull() ||
        source_pin.pin_commitment !=
            ComputeRCStage3CoupledBankDequantPinCommitment(
                source_pin) ||
        source_pin.logical_rows !=
            source_pin.n_rows ||
        source_pin.n_rows < 2 ||
        (source_pin.n_rows &
         (source_pin.n_rows - 1)) != 0 ||
        !CanonicalManifest(
            source_pin, public_seed,
            receipt) ||
        !CanonicalSlots(receipt)) {
        return fail("shape_manifest_or_slots");
    }
    std::vector<RCStage3CtlChildPin>
        prechallenge_pins{
            receipt.children[0].pin,
            receipt.children[1].pin};
    RCStage3CtlChallenges expected_challenges;
    std::string why;
    if (!DeriveRCStage3CtlChallenges(
            receipt.manifest,
            prechallenge_pins,
            expected_challenges,
            &why) ||
        !(expected_challenges ==
          receipt.challenges)) {
        return fail(
            "challenge_replay:" + why);
    }
    out.ordered_phase0_roots = true;
    out.challenges_after_all_phase0_roots =
        true;
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(
            receipt.challenges);
    for (const auto& child :
         receipt.children) {
        if (child.pin.challenge_commitment !=
                challenge_commitment ||
            child.pin.auxiliary_commitment !=
                child.proof_commitment ||
            child.proof_commitment !=
                ProofCommitment(child.proof) ||
            child.proof.batch.groups.size() != 3 ||
            Fri3AlgDigestToUint256(
                child.proof.batch.groups[0]
                    .row_commit.root) !=
                child.pin.trace_commitment) {
            return fail("child_public_binding");
        }
    }

    CS producer_relation;
    if (!fp::BuildNormalizedCoupledBankConstraintSystem(
            source_pin, producer_relation,
            &why)) {
        return fail("producer_relation:" + why);
    }
    const CS receiver_relation =
        ProjectionRelationSystem(
            source_pin.n_rows);
    const std::array<const CS*, 2>
        relation_systems{
            &producer_relation,
            &receiver_relation};
    const std::array<uint32_t, 2>
        source_columns{
            kRCStage3CoupledBankOutput, 0};
    std::array<AliasLayout, 2> layouts;
    for (uint32_t child = 0;
         child < 2; ++child) {
        CS child_cs;
        if (!BuildDegree2AliasSystem(
                *relation_systems[child],
                {kRCStage3CtlDegree2Version,
                 receipt.schedules[child],
                 receipt.challenges,
                 receipt.children[child]
                     .pin.terminal},
                source_columns[child],
                child_cs,
                layouts[child], &why)) {
            return fail(
                "child_cs_" +
                std::to_string(child) +
                ":" + why);
        }
        const std::array<
            RCStage3CtlChildPin, 2>
            pins{
                receipt.children[0].pin,
                receipt.children[1].pin};
        const uint256 seed =
            ChildSeed(
                receipt.manifest, pins,
                receipt.challenges,
                child, public_seed);
        if (!aq::AirQuotientVerifyRowsSplitRap(
                child_cs,
                receipt.children[child]
                    .proof,
                layouts[child].base_indices,
                seed, &why)) {
            return fail(
                "child_verify_" +
                std::to_string(child) +
                ":" + why);
        }
    }
    out.producer_relation_output_same_trace =
        layouts[0].value_column ==
            layouts[0].ctl_base +
                stage3_ctl_degree2_col::VALUE;
    out.receiver_projection_same_trace =
        layouts[1].value_column ==
            layouts[1].ctl_base +
                stage3_ctl_degree2_col::VALUE;
    out.producer_split_rap_verified = true;
    out.receiver_split_rap_verified = true;
    out.dependent_columns_are_exact_ctl_suffix =
        receipt.children[0].proof
                .base_column_indices.size() ==
            producer_relation.n_columns + 5 &&
        receipt.children[1].proof
                .base_column_indices.size() ==
            receiver_relation.n_columns + 5;
    out.proof_owned_terminals = true;
    if (!VerifyRCStage3CtlPublicPinComposition(
            receipt.manifest,
            prechallenge_pins,
            &why)) {
        return fail(
            "terminal_composition:" + why);
    }
    out.dual_lane_public_composition_zero =
        true;

    const uint256 expected_parent_seed =
        ParentSeed(
            receipt.manifest,
            receipt.challenges,
            receipt.terminal_slots,
            public_seed);
    if (receipt.parent_seed !=
            expected_parent_seed ||
        expected_parent_seed.IsNull()) {
        return fail("parent_seed");
    }
    out.child_commitments_bound_in_parent_seed =
        true;
    const CS parent_cs =
        ParentSystem(
            receipt.terminal_slots);
    if (!aq::AirQuotientVerifyRows(
            parent_cs,
            receipt.parent_proof,
            receipt.parent_seed,
            &why)) {
        return fail("parent_proof:" + why);
    }
    out.arity4_parent_air_verified = true;
    if (receipt.receipt_commitment !=
            ReceiptCommitment(receipt) ||
        receipt.receipt_commitment.IsNull()) {
        return fail("receipt_commitment");
    }

    // These remain explicit gates. The executable receipt closes the
    // commit/challenge/terminal plumbing, not production provenance or the
    // self-similar verifier-in-AIR fixed point.
    out.producer_registered_column_roots_bound =
        false;
    out.registered_receiver_semantics_bound =
        false;
    out.child_verifiers_execute_in_parent_air =
        false;
    out.recursive_fixed_point = false;
    out.production_authority = false;
    out.valid =
        out.ordered_phase0_roots &&
        out.challenges_after_all_phase0_roots &&
        out.producer_relation_output_same_trace &&
        out.receiver_projection_same_trace &&
        out.producer_split_rap_verified &&
        out.receiver_split_rap_verified &&
        out.dependent_columns_are_exact_ctl_suffix &&
        out.proof_owned_terminals &&
        out.dual_lane_public_composition_zero &&
        out.arity4_parent_air_verified &&
        out.child_commitments_bound_in_parent_seed &&
        !out.producer_registered_column_roots_bound &&
        !out.registered_receiver_semantics_bound &&
        !out.child_verifiers_execute_in_parent_air &&
        !out.recursive_fixed_point &&
        !out.production_authority;
    out.note = out.valid
        ? "stage3:splitrap_ctl_coordinator:"
          "one_role_exact_native_receipt;"
          "recursive_fixed_point_no_go"
        : "stage3:splitrap_ctl_coordinator:"
          "audit_incomplete";
    return out;
}

CoupledBankEqualityReceiptCellMapV1
BuildCoupledBankEqualityReceiptCellMapV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const CoupledBankEqualityReceiptV1& receipt,
    const uint256& public_seed)
{
    namespace ah = alg_hash;
    CoupledBankEqualityReceiptCellMapV1 out;
    const auto push_u32 =
        [](std::vector<gf::Fp>& values,
           uint32_t value) {
            values.push_back(gf::FromU64(value));
        };
    const auto push_u64 =
        [&push_u32](
            std::vector<gf::Fp>& values,
            uint64_t value) {
            push_u32(
                values,
                static_cast<uint32_t>(value));
            push_u32(
                values,
                static_cast<uint32_t>(
                    value >> 32));
        };
    const auto push_digest =
        [&push_u32](
            std::vector<gf::Fp>& values,
            const uint256& digest) {
            for (uint32_t limb = 0;
                 limb < 8; ++limb) {
                const unsigned char* bytes =
                    digest.data() + 4 * limb;
                push_u32(
                    values,
                    uint32_t{bytes[0]} |
                    (uint32_t{bytes[1]} << 8) |
                    (uint32_t{bytes[2]} << 16) |
                    (uint32_t{bytes[3]} << 24));
            }
        };
    const auto push_fp3 =
        [](std::vector<gf::Fp>& values,
           const Fp3& value) {
            values.push_back(
                gf::Canonical(value.c0));
            values.push_back(
                gf::Canonical(value.c1));
            values.push_back(
                gf::Canonical(value.c2));
        };
    const auto words =
        [&push_u32](
            const std::vector<unsigned char>& bytes,
            std::vector<gf::Fp>& values) {
            const uint32_t word_count =
                static_cast<uint32_t>(
                    (bytes.size() + 3) / 4);
            push_u32(
                values,
                static_cast<uint32_t>(
                    bytes.size()));
            push_u32(values, word_count);
            for (uint32_t word = 0;
                 word < word_count; ++word) {
                uint32_t packed = 0;
                for (uint32_t byte = 0;
                     byte < 4; ++byte) {
                    const size_t offset =
                        size_t{4} * word + byte;
                    if (offset < bytes.size()) {
                        packed |=
                            uint32_t{bytes[offset]}
                            << (8 * byte);
                    }
                }
                push_u32(values, packed);
            }
            return word_count;
        };
    const auto add_span =
        [&out, &push_u32](
            ReceiptCellSectionV1 section,
            uint32_t item,
            const std::vector<gf::Fp>& payload) {
            if (out.cells.size() >
                    std::numeric_limits<uint32_t>::max() ||
                payload.size() >
                    std::numeric_limits<uint32_t>::max() ||
                out.cells.size() + payload.size() + 3 >
                    std::numeric_limits<uint32_t>::max()) {
                return false;
            }
            ReceiptCellSpanV1 span;
            span.section = section;
            span.item = item;
            span.begin =
                static_cast<uint32_t>(
                    out.cells.size());
            push_u32(
                out.cells,
                static_cast<uint8_t>(section));
            push_u32(out.cells, item);
            push_u32(
                out.cells,
                static_cast<uint32_t>(
                    payload.size()));
            out.cells.insert(
                out.cells.end(),
                payload.begin(), payload.end());
            span.count =
                static_cast<uint32_t>(
                    payload.size() + 3);
            out.spans.push_back(span);
            return true;
        };

    if (source_pin.pin_commitment.IsNull() ||
        public_seed.IsNull() ||
        receipt.version !=
            kCoupledBankEqualityReceiptVersion ||
        receipt.receipt_commitment.IsNull()) {
        out.note =
            "stage3:splitrap_ctl_coordinator:"
            "receipt_cell_map_shape";
        return out;
    }

    // Collision-free field domain: two 56-bit ASCII chunks plus a version.
    std::vector<gf::Fp> header{
        UINT64_C(0x314c4c4543544252), // "RBT CELL1"
        UINT64_C(0x315650414d4c5443),
        gf::FromU64(
            kCoupledBankEqualityReceiptCellMapVersion),
    };
    push_u32(header, receipt.version);
    push_digest(header, public_seed);
    push_digest(header, receipt.receipt_commitment);
    push_digest(header, receipt.parent_seed);
    push_u32(header, source_pin.version);
    push_digest(header, source_pin.statement_commitment);
    push_digest(header, source_pin.shape_commitment);
    push_digest(header, source_pin.sigma);
    push_u32(header, source_pin.page_index);
    push_u32(header, source_pin.logical_rows);
    push_u32(header, source_pin.n_rows);
    push_u32(header, source_pin.n_coeffs);
    push_digest(
        header, source_pin.r0_row_group_root);
    push_digest(header, source_pin.pin_commitment);
    if (!add_span(
            ReceiptCellSectionV1::HeaderAndSourcePin,
            0, header)) {
        out.note =
            "stage3:splitrap_ctl_coordinator:"
            "receipt_cell_map_overflow";
        return out;
    }

    std::vector<gf::Fp> manifest;
    push_u32(manifest, receipt.manifest.bus_id);
    push_digest(
        manifest,
        receipt.manifest.transcript_seed);
    push_u32(
        manifest,
        static_cast<uint32_t>(
            receipt.manifest.participants.size()));
    for (const auto& participant :
         receipt.manifest.participants) {
        push_u32(
            manifest,
            static_cast<uint16_t>(
                participant.role));
        push_u64(manifest, participant.event_count);
        push_u64(manifest, participant.send_count);
        push_u64(
            manifest,
            participant.receive_count);
        push_digest(
            manifest,
            participant.schedule_commitment);
    }
    if (!add_span(
            ReceiptCellSectionV1::Manifest,
            0, manifest)) {
        return out;
    }

    for (uint32_t schedule_index = 0;
         schedule_index <
             receipt.schedules.size();
         ++schedule_index) {
        std::vector<gf::Fp> schedule;
        push_u32(
            schedule,
            static_cast<uint32_t>(
                receipt.schedules[schedule_index]
                    .events.size()));
        for (const auto& event :
             receipt.schedules[schedule_index]
                 .events) {
            push_u32(
                schedule,
                event.namespace_id);
            push_u32(schedule, event.stage);
            push_u32(schedule, event.address);
            push_u32(
                schedule,
                static_cast<uint32_t>(
                    static_cast<int32_t>(
                        event.multiplicity)));
        }
        if (!add_span(
                ReceiptCellSectionV1::Schedules,
                schedule_index, schedule)) {
            return out;
        }
    }

    std::vector<gf::Fp> challenges;
    push_fp3(challenges, receipt.challenges.gamma1);
    push_fp3(challenges, receipt.challenges.gamma2);
    push_fp3(challenges, receipt.challenges.alpha1);
    push_fp3(challenges, receipt.challenges.alpha2);
    if (!add_span(
            ReceiptCellSectionV1::Challenges,
            0, challenges)) {
        return out;
    }

    for (uint32_t child = 0;
         child < receipt.children.size();
         ++child) {
        const auto& pin =
            receipt.children[child].pin;
        std::vector<gf::Fp> pin_values;
        push_u32(pin_values, pin.magic);
        push_u32(pin_values, pin.version);
        push_u32(
            pin_values,
            static_cast<uint16_t>(pin.role));
        push_u32(pin_values, pin.bus_id);
        push_u64(pin_values, pin.event_count);
        push_u64(pin_values, pin.send_count);
        push_u64(pin_values, pin.receive_count);
        push_digest(
            pin_values,
            pin.schedule_commitment);
        push_digest(
            pin_values,
            pin.trace_commitment);
        push_digest(
            pin_values,
            pin.auxiliary_commitment);
        push_digest(
            pin_values,
            pin.challenge_commitment);
        push_fp3(pin_values, pin.terminal.alpha1_sum);
        push_fp3(pin_values, pin.terminal.alpha2_sum);
        push_digest(
            pin_values,
            receipt.children[child]
                .proof_commitment);
        if (!add_span(
                ReceiptCellSectionV1::ChildPins,
                child, pin_values)) {
            return out;
        }
    }

    for (uint32_t slot = 0;
         slot < receipt.terminal_slots.size();
         ++slot) {
        std::vector<gf::Fp> terminal;
        push_u32(
            terminal,
            receipt.terminal_slots[slot].active
                ? 1 : 0);
        push_digest(
            terminal,
            receipt.terminal_slots[slot]
                .child_proof_commitment);
        push_fp3(
            terminal,
            receipt.terminal_slots[slot]
                .terminal.alpha1_sum);
        push_fp3(
            terminal,
            receipt.terminal_slots[slot]
                .terminal.alpha2_sum);
        if (!add_span(
                ReceiptCellSectionV1::TerminalSlots,
                slot, terminal)) {
            return out;
        }
    }

    out.child_codecs_canonical = true;
    for (uint32_t child = 0;
         child < receipt.children.size();
         ++child) {
        std::vector<unsigned char> codec;
        if (aq::SerializeAirQuotientSplitRapRowsProof(
                receipt.children[child].proof,
                codec) == 0 ||
            codec.size() >
                std::numeric_limits<uint32_t>::max()) {
            out.note =
                "stage3:splitrap_ctl_coordinator:"
                "receipt_cell_map_child_codec";
            return out;
        }
        const auto decoded =
            aq::DeserializeAirQuotientSplitRapRowsProof(
                codec);
        std::vector<unsigned char> canonical;
        if (!decoded.has_value() ||
            aq::SerializeAirQuotientSplitRapRowsProof(
                *decoded, canonical) !=
                codec.size() ||
            canonical != codec) {
            out.child_codecs_canonical = false;
            out.note =
                "stage3:splitrap_ctl_coordinator:"
                "receipt_cell_map_child_noncanonical";
            return out;
        }
        std::vector<gf::Fp> payload;
        out.child_codec_words[child] =
            words(codec, payload);
        out.child_codec_bytes[child] =
            static_cast<uint32_t>(
                codec.size());
        if (!add_span(
                ReceiptCellSectionV1::
                    ChildSplitRapCodec,
                child, payload)) {
            return out;
        }
    }

    std::vector<unsigned char> parent_batch;
    if (SerializeFri3AlgBatchProof(
            receipt.parent_proof.batch,
            parent_batch) == 0 ||
        parent_batch.size() >
            std::numeric_limits<uint32_t>::max()) {
        out.note =
            "stage3:splitrap_ctl_coordinator:"
            "receipt_cell_map_parent_batch";
        return out;
    }
    const auto decoded_parent =
        DeserializeFri3AlgBatchProof(parent_batch);
    std::vector<unsigned char> canonical_parent;
    if (!decoded_parent.has_value() ||
        SerializeFri3AlgBatchProof(
            *decoded_parent,
            canonical_parent) !=
            parent_batch.size() ||
        canonical_parent != parent_batch) {
        out.note =
            "stage3:splitrap_ctl_coordinator:"
            "receipt_cell_map_parent_noncanonical";
        return out;
    }
    out.parent_batch_codec_canonical = true;
    out.parent_batch_codec_bytes =
        static_cast<uint32_t>(
            parent_batch.size());
    std::vector<gf::Fp> parent;
    out.parent_batch_codec_words =
        words(parent_batch, parent);
    const size_t supplemental_begin =
        parent.size();
    push_digest(
        parent,
        receipt.parent_proof.trace_commit);
    push_u32(
        parent,
        static_cast<uint32_t>(
            receipt.parent_proof
                .next_openings.size()));
    for (const auto& query :
         receipt.parent_proof.next_openings) {
        push_u32(
            parent,
            static_cast<uint32_t>(
                query.size()));
        for (const auto& path : query) {
            push_u32(parent, path.index);
            push_u32(
                parent,
                static_cast<uint32_t>(
                    path.values.size()));
            for (const auto& value :
                 path.values) {
                push_fp3(parent, value);
            }
            push_u32(
                parent,
                static_cast<uint32_t>(
                    path.siblings.size()));
            for (const auto& sibling :
                 path.siblings) {
                for (const auto limb : sibling) {
                    parent.push_back(
                        gf::Canonical(limb));
                }
            }
        }
    }
    if (parent.size() - supplemental_begin >
            std::numeric_limits<uint32_t>::max() ||
        !add_span(
            ReceiptCellSectionV1::ParentRowsProof,
            0, parent)) {
        return out;
    }
    out.parent_supplemental_fields =
        static_cast<uint32_t>(
            parent.size() - supplemental_begin);

    out.all_values_canonical =
        std::all_of(
            out.cells.begin(), out.cells.end(),
            [](gf::Fp value) {
                return value < gf::kP;
            });
    if (!out.all_values_canonical ||
        out.cells.empty() ||
        out.spans.size() != 14) {
        out.note =
            "stage3:splitrap_ctl_coordinator:"
            "receipt_cell_map_cells";
        return out;
    }
    out.transport_commitment =
        aq::AirFriBackendAlg<Fp3>::PackDigest(
            ah::SpongeHashFp(out.cells));
    out.valid =
        out.child_codecs_canonical &&
        out.parent_batch_codec_canonical &&
        out.all_values_canonical &&
        !out.transport_commitment.IsNull();
    out.note = out.valid
        ? "stage3:splitrap_ctl_coordinator:"
          "receipt_cell_map_complete_transport_only"
        : "stage3:splitrap_ctl_coordinator:"
          "receipt_cell_map_invalid";
    return out;
}

bool ValidateCoupledBankEqualityReceiptCellMapV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const CoupledBankEqualityReceiptV1& receipt,
    const uint256& public_seed,
    const CoupledBankEqualityReceiptCellMapV1& map,
    std::string* why)
{
    const auto expected =
        BuildCoupledBankEqualityReceiptCellMapV1(
            source_pin, receipt, public_seed);
    const auto fail =
        [&](const char* detail) {
            return Fail(why, detail);
        };
    if (!expected.valid || !map.valid ||
        map.version !=
            kCoupledBankEqualityReceiptCellMapVersion ||
        map.cells != expected.cells ||
        map.spans != expected.spans ||
        map.child_codec_bytes !=
            expected.child_codec_bytes ||
        map.child_codec_words !=
            expected.child_codec_words ||
        map.parent_batch_codec_bytes !=
            expected.parent_batch_codec_bytes ||
        map.parent_batch_codec_words !=
            expected.parent_batch_codec_words ||
        map.parent_supplemental_fields !=
            expected.parent_supplemental_fields ||
        map.transport_commitment !=
            expected.transport_commitment ||
        map.child_codecs_canonical !=
            expected.child_codecs_canonical ||
        map.parent_batch_codec_canonical !=
            expected.parent_batch_codec_canonical ||
        map.all_values_canonical !=
            expected.all_values_canonical ||
        map.note != expected.note) {
        return fail("receipt_cell_map_substitution");
    }
    return true;
}

CoupledBankEqualityChildVerifierV1
BuildCoupledBankEqualityChildVerifierV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const CoupledBankEqualityReceiptV1& receipt,
    const uint256& public_seed,
    uint32_t child_index)
{
    namespace va = stage3_verifier_air;
    CoupledBankEqualityChildVerifierV1 out;
    out.child_index = child_index;
    if (child_index >= receipt.children.size() ||
        !VerifyCoupledBankEqualityReceiptV1(
             source_pin, receipt, public_seed)
             .valid) {
        out.note =
            "stage3:splitrap_ctl_coordinator:"
            "child_verifier_input";
        return out;
    }

    CS producer_relation;
    if (!fp::BuildNormalizedCoupledBankConstraintSystem(
            source_pin, producer_relation, nullptr)) {
        out.note =
            "stage3:splitrap_ctl_coordinator:"
            "child_verifier_producer_relation";
        return out;
    }
    const CS receiver_relation =
        ProjectionRelationSystem(source_pin.n_rows);
    const CS& relation =
        child_index == 0
        ? producer_relation
        : receiver_relation;
    const uint32_t source_column =
        child_index == 0
        ? kRCStage3CoupledBankOutput
        : 0;

    AliasLayout layout;
    if (!BuildDegree2AliasSystem(
            relation,
            {kRCStage3CtlDegree2Version,
             receipt.schedules[child_index],
             receipt.challenges,
             receipt.children[child_index]
                 .pin.terminal},
            source_column,
            out.child_relation,
            layout, nullptr)) {
        out.note =
            "stage3:splitrap_ctl_coordinator:"
            "child_verifier_alias_relation";
        return out;
    }
    out.program =
        va::BuildCanonicalMultiRowV2SplitRapProgramV1(
            out.child_relation,
            layout.base_indices);
    std::string why;
    if (!out.program.valid ||
        !va::ValidateCanonicalMultiRowV2SplitRapProgramV1(
            out.child_relation,
            out.program, &why)) {
        out.note =
            "stage3:splitrap_ctl_coordinator:"
            "child_verifier_program:" + why;
        return out;
    }
    const std::array<RCStage3CtlChildPin, 2> pins{
        receipt.children[0].pin,
        receipt.children[1].pin};
    const uint256 seed =
        ChildSeed(
            receipt.manifest, pins,
            receipt.challenges,
            child_index, public_seed);
    out.witness =
        va::BuildMultiRowV2SplitRapVerifierWitnessV1(
            out.child_relation,
            out.program,
            receipt.children[child_index].proof,
            seed);
    if (!out.witness.valid ||
        !va::VerifyMultiRowV2SplitRapVerifierWitnessV1(
            out.child_relation,
            out.program,
            receipt.children[child_index].proof,
            seed, out.witness, &why)) {
        out.note =
            "stage3:splitrap_ctl_coordinator:"
            "child_verifier_witness:" + why;
        return out;
    }
    out.valid = true;
    out.note =
        "stage3:splitrap_ctl_coordinator:"
        "canonical_child_verifier_relation";
    return out;
}

CoupledBankEqualityChildVerifierV1
BuildCoupledBankEqualityChildVerifierFromProgramV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const CoupledBankEqualityReceiptV1& receipt,
    const uint256& public_seed,
    uint32_t child_index,
    const constraint_bytecode::ProgramTable& program)
{
    namespace cb = constraint_bytecode;
    namespace va = stage3_verifier_air;
    CoupledBankEqualityChildVerifierV1 out;
    out.child_index = child_index;
    if (child_index != 0 ||
        !VerifyCoupledBankEqualityReceiptV1(
             source_pin, receipt, public_seed)
             .valid ||
        !cb::ValidateProgramTable(program) ||
        program.role !=
            RCStage3RelationRole::CoupledBank ||
        program.current_width !=
            kRCStage3CoupledBankDequantColumns ||
        program.next_width !=
            kRCStage3CoupledBankDequantColumns) {
        out.note =
            "stage3:splitrap_ctl_coordinator:"
            "program_child_verifier_input";
        return out;
    }

    CS registry_relation;
    if (!cb::BuildAirConstraintSystemFromProgramTable(
            program, source_pin.n_rows,
            registry_relation, nullptr)) {
        out.note =
            "stage3:splitrap_ctl_coordinator:"
            "program_child_verifier_interpreter";
        return out;
    }
    const uint32_t splitrap_aux =
        registry_relation.n_columns;
    registry_relation.n_columns += 1;
    Constraint aux_zero;
    aux_zero.name =
        "coupled.bank.splitrap_aux_zero";
    aux_zero.kind = aq::AirKind::kEverywhere;
    aux_zero.alg_degree = 1;
    aux_zero.eval =
        [splitrap_aux](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return row[splitrap_aux];
        };
    registry_relation.constraints.push_back(
        std::move(aux_zero));
    // The bytecode table is the semantic relation source of truth, but the
    // Split-RAP partition is also statement data. Reattach the exact
    // proof-owned R0 row-group pin used by the production dequant relation;
    // omitting it changes the three-group proof statement even when all
    // bytecode residuals are identical.
    registry_relation.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role = aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns = {0, 1, 2, 3, 4, 5},
        .root = source_pin.r0_row_group_root,
    });
    AliasLayout layout;
    if (!BuildDegree2AliasSystem(
            registry_relation,
            {kRCStage3CtlDegree2Version,
             receipt.schedules[child_index],
             receipt.challenges,
             receipt.children[child_index]
                 .pin.terminal},
            kRCStage3CoupledBankOutput,
            out.child_relation,
            layout, nullptr)) {
        out.note =
            "stage3:splitrap_ctl_coordinator:"
            "program_child_verifier_alias";
        return out;
    }
    out.program =
        va::BuildCanonicalMultiRowV2SplitRapProgramV1(
            out.child_relation,
            layout.base_indices);
    std::string why;
    if (!out.program.valid ||
        !va::ValidateCanonicalMultiRowV2SplitRapProgramV1(
            out.child_relation,
            out.program, &why)) {
        out.note =
            "stage3:splitrap_ctl_coordinator:"
            "program_child_verifier_schedule:" +
            why;
        return out;
    }
    const std::array<RCStage3CtlChildPin, 2> pins{
        receipt.children[0].pin,
        receipt.children[1].pin};
    const uint256 seed =
        ChildSeed(
            receipt.manifest, pins,
            receipt.challenges,
            child_index, public_seed);
    out.witness =
        va::BuildMultiRowV2SplitRapVerifierWitnessV1(
            out.child_relation,
            out.program,
            receipt.children[child_index].proof,
            seed);
    if (!out.witness.valid ||
        !va::VerifyMultiRowV2SplitRapVerifierWitnessV1(
            out.child_relation,
            out.program,
            receipt.children[child_index].proof,
            seed, out.witness, &why)) {
        out.note =
            "stage3:splitrap_ctl_coordinator:"
            "program_child_verifier_witness:" +
            why;
        return out;
    }
    out.valid = true;
    out.note =
        "stage3:splitrap_ctl_coordinator:"
        "registry_program_interpreter_child_verifier";
    return out;
}

CoupledBankEqualityRecursiveConsumptionAuditV1
AssessCoupledBankEqualityRecursiveConsumptionV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const CoupledBankEqualityReceiptV1& receipt,
    const uint256& public_seed)
{
    namespace va = stage3_verifier_air;
    CoupledBankEqualityRecursiveConsumptionAuditV1 out;
    const auto native =
        VerifyCoupledBankEqualityReceiptV1(
            source_pin, receipt, public_seed);
    out.native_receipt_verified = native.valid;
    const auto cell_map =
        BuildCoupledBankEqualityReceiptCellMapV1(
            source_pin, receipt, public_seed);
    out.canonical_cell_map_verified =
        cell_map.valid &&
        ValidateCoupledBankEqualityReceiptCellMapV1(
            source_pin, receipt, public_seed,
            cell_map, nullptr);
    if (!out.native_receipt_verified ||
        !out.canonical_cell_map_verified ||
        cell_map.cells.size() >
            std::numeric_limits<uint32_t>::max()) {
        out.note =
            "stage3:splitrap_ctl_coordinator:"
            "recursive_consumption_input";
        return out;
    }
    out.receipt_cells =
        static_cast<uint32_t>(
            cell_map.cells.size());
    out.parent_proof_verified_natively =
        native.arity4_parent_air_verified;

    CS producer_relation;
    if (!fp::BuildNormalizedCoupledBankConstraintSystem(
            source_pin, producer_relation, nullptr)) {
        out.note =
            "stage3:splitrap_ctl_coordinator:"
            "recursive_consumption_producer_cs";
        return out;
    }
    const CS receiver_relation =
        ProjectionRelationSystem(source_pin.n_rows);
    const std::array<const CS*, 2>
        relation_systems{
            &producer_relation,
            &receiver_relation};
    const std::array<uint32_t, 2>
        source_columns{
            kRCStage3CoupledBankOutput, 0};
    const std::array<
        RCStage3CtlChildPin, 2>
        pins{
            receipt.children[0].pin,
            receipt.children[1].pin};
    for (uint32_t child = 0;
         child < 2; ++child) {
        CS child_cs;
        AliasLayout layout;
        if (!BuildDegree2AliasSystem(
                *relation_systems[child],
                {kRCStage3CtlDegree2Version,
                 receipt.schedules[child],
                 receipt.challenges,
                 receipt.children[child]
                     .pin.terminal},
                source_columns[child],
                child_cs, layout, nullptr)) {
            out.note =
                "stage3:splitrap_ctl_coordinator:"
                "recursive_consumption_child_cs";
            return out;
        }
        const auto program =
            va::BuildCanonicalMultiRowV2SplitRapProgramV1(
                child_cs,
                layout.base_indices);
        std::string why;
        if (!program.valid ||
            !va::ValidateCanonicalMultiRowV2SplitRapProgramV1(
                child_cs, program, &why)) {
            out.note =
                "stage3:splitrap_ctl_coordinator:"
                "recursive_consumption_program:" +
                why;
            return out;
        }
        const uint256 seed =
            ChildSeed(
                receipt.manifest, pins,
                receipt.challenges,
                child, public_seed);
        const auto witness =
            va::BuildMultiRowV2SplitRapVerifierWitnessV1(
                child_cs, program,
                receipt.children[child].proof,
                seed);
        if (!witness.valid ||
            !va::VerifyMultiRowV2SplitRapVerifierWitnessV1(
                child_cs, program,
                receipt.children[child].proof,
                seed, witness, &why)) {
            out.note =
                "stage3:splitrap_ctl_coordinator:"
                "recursive_consumption_local_witness:" +
                why;
            return out;
        }
        out.local_child_verifier_rows +=
            witness.checked_rows;
        out.local_child_verifier_constraints +=
            static_cast<uint32_t>(
                witness.constraint_system
                    .constraints.size());
        out.local_child_verifier_output_cells +=
            static_cast<uint32_t>(
                3 * witness.outputs.size());
        out.poseidon_permutations +=
            witness.poseidon_alias_plan
                .permutation_count;
        out.poseidon_semantic_alias_cells +=
            uint64_t{
                witness.poseidon_alias_plan
                    .layout_input_alias_cells} +
            witness.poseidon_alias_plan
                .layout_output_alias_cells;
        out.sha256d_calls +=
            witness.transcript_sha_plan
                .sha256d_calls;
        out.sha256_compressions +=
            witness.transcript_sha_plan
                .unique_total_compressions;
        out.sha_shards +=
            witness.transcript_sha_plan
                .parent_shards;
        out.sha_recursive_nodes +=
            static_cast<uint32_t>(
                witness.transcript_sha_plan
                    .recursive_nodes.size());
    }
    out.both_child_programs_canonical = true;
    out.both_local_verifier_relations_execute = true;

    uint64_t parent_cells = 0;
    for (const auto& span : cell_map.spans) {
        if (span.section ==
            ReceiptCellSectionV1::ParentRowsProof) {
            parent_cells += span.count;
        }
    }
    out.gaps = {
        {
            "complete_receipt_proof_cell_equality_bus",
            "Fp cells",
            out.receipt_cells, 0, true,
            "the canonical cell map is host-built; no normalized-parent "
            "columns source these cells from authenticated verifier chips",
        },
        {
            "splitrap_multirow_v2_verifier_relation",
            "scheduled check rows",
            out.local_child_verifier_rows, 0, true,
            "both 16-column local mirrors execute, but their replay cells "
            "are preprocessed pins and neither mirror is recursively proved",
        },
        {
            "alg_hash_proof_row_semantic_aliases",
            "input/output alias cells",
            out.poseidon_semantic_alias_cells, 0, true,
            "Poseidon permutations are constrained locally; proof-cell "
            "producer/consumer aliases into the parent remain absent",
        },
        {
            "sha256d_fiat_shamir_compressions",
            "SHA-256 compression calls",
            out.sha256_compressions, 0, true,
            "the exact shared-prefix transcript schedule exists but no "
            "SHA AIR shards execute in the normalized parent",
        },
        {
            "sha_transcript_recursive_shards",
            "shards plus arity-four nodes",
            uint64_t{out.sha_shards} +
                out.sha_recursive_nodes,
            0, true,
            "all shard/node statements are scheduled; child proof "
            "verification and recursive aggregation remain absent",
        },
        {
            "arity4_parent_rows_proof_verifier",
            "canonical parent-proof transport cells",
            parent_cells, 0, true,
            "the cancellation AIR proof verifies natively, not through a "
            "self-similar verifier relation in its parent",
        },
        {
            "normalized_proof_and_terminal_root_bus",
            "u32 digest lanes",
            out.normalized_proof_terminal_lanes,
            0, true,
            "eight receipt-proof and eight CTL-terminal lanes have no "
            "proof-authenticated normalized semantic-root source",
        },
        {
            "endpoint28_registered_producer_receiver_provenance",
            "registered endpoint equality links",
            2, 0, true,
            "the receipt proves OUTPUT-to-mirror equality only; production "
            "column roots and the registered endpoint-29 consumer are open",
        },
    };
    out.receipt_cells_mapped_in_parent = 0;
    out.normalized_proof_terminal_lanes_mapped = 0;
    out.proof_cells_equality_mapped_in_parent = false;
    out.child_fiat_shamir_replayed_in_parent = false;
    out.child_hash_chips_execute_in_parent = false;
    out.parent_proof_verifier_executes_in_parent = false;
    out.terminal_bus_mapped_to_normalized_root = false;
    out.producer_registered_roots_bound =
        native.producer_registered_column_roots_bound;
    out.registered_receiver_semantics_bound =
        native.registered_receiver_semantics_bound;
    out.recursively_consumed_endpoints = 0;
    out.recursively_consumed_roles = 0;
    out.recursive_fixed_point = false;
    out.authority = false;
    out.valid =
        out.native_receipt_verified &&
        out.canonical_cell_map_verified &&
        out.both_child_programs_canonical &&
        out.both_local_verifier_relations_execute &&
        out.parent_proof_verified_natively &&
        out.receipt_cells != 0 &&
        out.local_child_verifier_rows != 0 &&
        out.local_child_verifier_constraints != 0 &&
        out.local_child_verifier_output_cells != 0 &&
        out.poseidon_permutations != 0 &&
        out.poseidon_semantic_alias_cells != 0 &&
        out.sha256d_calls != 0 &&
        out.sha256_compressions != 0 &&
        out.sha_shards != 0 &&
        !out.proof_cells_equality_mapped_in_parent &&
        !out.child_fiat_shamir_replayed_in_parent &&
        !out.child_hash_chips_execute_in_parent &&
        !out.parent_proof_verifier_executes_in_parent &&
        !out.terminal_bus_mapped_to_normalized_root &&
        !out.producer_registered_roots_bound &&
        !out.registered_receiver_semantics_bound &&
        out.recursively_consumed_endpoints == 0 &&
        out.recursively_consumed_roles == 0 &&
        !out.recursive_fixed_point &&
        !out.authority &&
        out.gaps.size() == 8;
    out.note = out.valid
        ? "stage3:splitrap_ctl_coordinator:"
          "normalized_receipt_cell_map_and_local_verifier_mirror_ok;"
          "recursive_proof_cell_sha_parent_and_provenance_gates_open;"
          "recursive_counters_0"
        : "stage3:splitrap_ctl_coordinator:"
          "normalized_receipt_consumption_audit_invalid";
    return out;
}

bool ValidateCoupledBankEqualityRecursiveConsumptionV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const CoupledBankEqualityReceiptV1& receipt,
    const uint256& public_seed,
    const CoupledBankEqualityRecursiveConsumptionAuditV1& audit,
    std::string* why)
{
    const auto expected =
        AssessCoupledBankEqualityRecursiveConsumptionV1(
            source_pin, receipt, public_seed);
    if (!expected.valid || !audit.valid ||
        audit != expected) {
        return Fail(
            why,
            "recursive_consumption_audit_substitution");
    }
    if (audit.receipt_cells_mapped_in_parent != 0 ||
        audit.normalized_proof_terminal_lanes_mapped != 0 ||
        audit.recursively_consumed_endpoints != 0 ||
        audit.recursively_consumed_roles != 0 ||
        audit.recursive_fixed_point ||
        audit.authority) {
        return Fail(
            why,
            "recursive_consumption_counter_promotion");
    }
    return true;
}

} // namespace matmul::v4::rc::splitrap_ctl
