// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_bank_hash_bridge.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <hash.h>

#include <algorithm>
#include <array>
#include <limits>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace ha = stage3_hash_air;
using gf::Fp3;

constexpr uint32_t SHA_LANE_ROWS = 1024;
constexpr uint32_t PRODUCER_NAMESPACE = 0x42545828U;
constexpr uint32_t BANK_BYTE_STAGE = 29;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:coupled_bank_hash_bridge:" + detail;
    }
    return false;
}

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

void Add(
    aq::AirConstraintSystem<Fp3>& cs,
    const char* name,
    aq::AirKind kind,
    uint32_t degree,
    std::function<Fp3(
        const std::vector<Fp3>&,
        const std::vector<Fp3>&)> eval)
{
    cs.constraints.push_back(
        {name, kind, degree, std::move(eval)});
}

bool ValidPin(
    const RCStage3CoupledBankDequantPin& pin)
{
    return
        pin.version ==
            kRCStage3CoupledBankProductVersion &&
        pin.logical_rows >= 2 &&
        pin.logical_rows == pin.n_rows &&
        pin.n_rows == pin.n_coeffs &&
        (pin.n_rows & (pin.n_rows - 1)) == 0 &&
        !pin.r0_row_group_root.IsNull() &&
        pin.pin_commitment ==
            ComputeRCStage3CoupledBankDequantPinCommitment(
                pin) &&
        !pin.pin_commitment.IsNull();
}

bool SignedByte(
    const Fp3& value,
    uint8_t& out)
{
    if (gf::Canonical(value.c1) != 0 ||
        gf::Canonical(value.c2) != 0) {
        return false;
    }
    for (int32_t signed_value = -128;
         signed_value <= 127;
         ++signed_value) {
        if (gf::Eq(
                value,
                gf::FromSigned3(signed_value))) {
            out = static_cast<uint8_t>(
                static_cast<int8_t>(signed_value));
            return true;
        }
    }
    return false;
}

RCStage3CtlSchedule ProducerSchedule(uint32_t count)
{
    RCStage3CtlSchedule out;
    out.events.reserve(count);
    for (uint32_t address = 0;
         address < count;
         ++address) {
        out.events.push_back({
            PRODUCER_NAMESPACE,
            BANK_BYTE_STAGE,
            address,
            1,
        });
    }
    return out;
}

RCStage3CtlSchedule ConsumerSchedule(uint32_t count)
{
    RCStage3CtlSchedule out;
    out.events.reserve(count);
    for (uint32_t address = 0;
         address < count;
         ++address) {
        out.events.push_back({
            PRODUCER_NAMESPACE,
            BANK_BYTE_STAGE,
            address,
            -1,
        });
    }
    return out;
}

RCStage3CtlParticipantSpec Participant(
    RCStage3RelationRole role,
    const RCStage3CtlSchedule& schedule,
    bool producer)
{
    return {
        role,
        schedule.events.size(),
        producer ? schedule.events.size() : 0,
        producer ? 0 : schedule.events.size(),
        CommitRCStage3CtlSchedule(schedule),
    };
}

uint256 TranscriptSeed(
    const RCStage3CoupledBankDequantPin& pin,
    const std::vector<uint8_t>& prefix,
    const uint256& fs_seed)
{
    if (!ValidPin(pin) || prefix.empty() ||
        fs_seed.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_BANK_28_TO_29_CTL_TRANSCRIPT_V1";
    hash << fs_seed;
    hash << pin.pin_commitment;
    hash << pin.statement_commitment;
    hash << pin.shape_commitment;
    hash << pin.page_index;
    hash << pin.logical_rows;
    hash << prefix;
    return hash.GetHash();
}

uint256 ChildSeed(
    const char* domain,
    const uint256& fs_seed,
    const RCStage3CoupledBankHashBridgeProofV1& proof)
{
    if (fs_seed.IsNull() ||
        proof.bank_byte_alg_hash_root.IsNull() ||
        proof.sha_r0_root.IsNull() ||
        proof.sha_public_statement.IsNull() ||
        proof.pins.size() != 2) {
        return {};
    }
    HashWriter hash;
    hash << domain;
    hash << fs_seed;
    hash << proof.source_pin_commitment;
    hash << proof.bank_byte_count;
    hash << proof.first_pass_blocks;
    hash << proof.sha_public_statement;
    hash << proof.bank_byte_alg_hash_root;
    hash << proof.sha_r0_root;
    // PRECHALLENGE receipt only. In particular, never absorb either child
    // proof/auxiliary commitment here: doing so would create a proof-seed
    // cycle and would make the prover and verifier use different seeds.
    hash << proof.manifest.bus_id;
    hash << proof.manifest.transcript_seed;
    hash << static_cast<uint32_t>(
        proof.manifest.participants.size());
    for (const auto& participant :
         proof.manifest.participants) {
        hash << static_cast<uint16_t>(
            participant.role);
        hash << participant.event_count;
        hash << participant.send_count;
        hash << participant.receive_count;
        hash << participant.schedule_commitment;
    }
    hash << static_cast<uint32_t>(
        proof.pins.size());
    for (const auto& pin : proof.pins) {
        hash << static_cast<uint16_t>(
            pin.role);
        hash << pin.bus_id;
        hash << pin.event_count;
        hash << pin.send_count;
        hash << pin.receive_count;
        hash << pin.schedule_commitment;
        hash << pin.trace_commitment;
        hash << pin.challenge_commitment;
        hash << gf::Canonical(
            pin.terminal.alpha1_sum.c0);
        hash << gf::Canonical(
            pin.terminal.alpha1_sum.c1);
        hash << gf::Canonical(
            pin.terminal.alpha1_sum.c2);
        hash << gf::Canonical(
            pin.terminal.alpha2_sum.c0);
        hash << gf::Canonical(
            pin.terminal.alpha2_sum.c1);
        hash << gf::Canonical(
            pin.terminal.alpha2_sum.c2);
    }
    return hash.GetHash();
}

uint256 ProofCodecCommitment(
    const char* domain,
    const aq::AirQuotientSplitRapRowsProof& proof)
{
    std::vector<unsigned char> bytes;
    if (aq::SerializeAirQuotientSplitRapRowsProof(
            proof, bytes) == 0) {
        return {};
    }
    HashWriter hash;
    hash << domain;
    hash << bytes;
    return hash.GetHash();
}

uint256 CommitBridge(
    const RCStage3CoupledBankHashBridgeProofV1& proof)
{
    const uint256 composition =
        CommitRCStage3CtlComposition(
            proof.manifest, proof.pins);
    if (proof.version !=
            kRCStage3CoupledBankHashBridgeVersion ||
        proof.bank_byte_count < 2 ||
        proof.first_pass_blocks == 0 ||
        proof.source_pin_commitment.IsNull() ||
        proof.sha_public_statement.IsNull() ||
        proof.bank_byte_alg_hash_root.IsNull() ||
        proof.sha_r0_root.IsNull() ||
        proof.producer_proof_commitment.IsNull() ||
        proof.sha_proof_commitment.IsNull() ||
        composition.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_BANK_28_TO_29_BRIDGE_PROOF_V1";
    hash << proof.version;
    hash << proof.bank_byte_count;
    hash << proof.first_pass_blocks;
    hash << proof.source_pin_commitment;
    hash << proof.sha_public_statement;
    hash << proof.bank_byte_alg_hash_root;
    hash << proof.sha_r0_root;
    hash << composition;
    hash << proof.producer_proof_commitment;
    hash << proof.sha_proof_commitment;
    return hash.GetHash();
}

uint256 CommitTerminalBus(
    const RCStage3CoupledBankHashBridgeProofV1& proof)
{
    if (proof.proof_commitment.IsNull()) return {};
    const uint256 composition =
        CommitRCStage3CtlComposition(
            proof.manifest, proof.pins);
    if (composition.IsNull()) return {};
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_BANK_28_TO_29_TERMINAL_BUS_V1";
    hash << proof.proof_commitment;
    hash << composition;
    return hash.GetHash();
}

struct ProducerLayout {
    uint32_t byte{0};
    uint32_t bit_base{0};
    uint32_t address{0};
    uint32_t inverse1{0};
    uint32_t inverse2{0};
    uint32_t running1{0};
    uint32_t running2{0};
    uint32_t columns{0};
    std::vector<uint32_t> base_indices;
};

ProducerLayout CanonicalProducerLayout()
{
    ProducerLayout out;
    out.byte =
        kRCStage3CoupledBankDequantColumns;
    out.bit_base = out.byte + 1;
    out.address = out.bit_base + 8;
    out.inverse1 = out.address + 1;
    out.inverse2 = out.inverse1 + 1;
    out.running1 = out.inverse2 + 1;
    out.running2 = out.running1 + 1;
    out.columns = out.running2 + 1;
    for (uint32_t column = 0;
         column <
             kRCStage3CoupledBankDequantColumns;
         ++column) {
        out.base_indices.push_back(column);
    }
    return out;
}

Fp3 CompressProducer(
    const std::vector<Fp3>& row,
    const ProducerLayout& layout,
    const Fp3& gamma)
{
    const Fp3 gamma2 = gf::Mul(gamma, gamma);
    const Fp3 gamma3 = gf::Mul(gamma2, gamma);
    return gf::Add(
        U(PRODUCER_NAMESPACE),
        gf::Add(
            gf::Mul(gamma, U(BANK_BYTE_STAGE)),
            gf::Add(
                gf::Mul(
                    gamma2, row[layout.address]),
                gf::Mul(
                    gamma3, row[layout.byte]))));
}

bool BuildProducerCs(
    const RCStage3CoupledBankDequantPin& pin,
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal,
    const uint256& r0_root,
    aq::AirConstraintSystem<Fp3>& cs,
    ProducerLayout& layout,
    std::string* why)
{
    if (!BuildRCStage3CoupledBankDequantConstraintSystem(
            pin, cs, why)) {
        return false;
    }
    // The legacy proof commits one independent root per column. Split-RAP is
    // row-wise and rejects those pins by construction. This bridge replaces
    // them with one exact ordered R0 row-group root below; it does not claim
    // that the new root is derivable from the legacy roots.
    cs.preprocessed_roots.clear();
    layout = CanonicalProducerLayout();
    cs.n_columns = layout.columns;
    cs.preprocessed_pin_ood = true;
    std::vector<Fp3> addresses(
        pin.n_rows, Fp3::Zero());
    for (uint32_t row = 0;
         row < pin.n_rows;
         ++row) {
        addresses[row] = U(row);
    }
    cs.preprocessed.emplace_back(
        layout.address, addresses);

    constraint_bytecode::ProgramTable bridge_table;
    if (!BuildRCStage3CoupledBankByteBridgeProgramTable(
            bridge_table, why) ||
        bridge_table.current_width !=
            layout.address + 1) {
        return Fail(why, "producer_byte_bridge_bytecode");
    }
    for (const auto& program : bridge_table.programs) {
        aq::AirConstraint<Fp3> constraint;
        constraint.name =
            "stage3.bank_bridge.byte_bridge_bytecode";
        constraint.kind = program.kind;
        constraint.alg_degree =
            program.declared_degree;
        constraint.eval =
            [program](const std::vector<Fp3>& cur,
                      const std::vector<Fp3>& next) {
                if (cur.size() < program.current_width ||
                    next.size() < program.next_width) {
                    return Fp3::One();
                }
                const std::vector<Fp3> local_cur(
                    cur.begin(),
                    cur.begin() + program.current_width);
                const std::vector<Fp3> local_next(
                    next.begin(),
                    next.begin() + program.next_width);
                Fp3 result = Fp3::Zero();
                if (!constraint_bytecode::EvaluateProgram(
                        program, local_cur, local_next,
                        result)) {
                    return Fp3::One();
                }
                return result;
            };
        cs.constraints.push_back(
            std::move(constraint));
    }
    Add(
        cs, "stage3.bank_bridge.producer_inverse1",
        aq::AirKind::kEverywhere, 2,
        [layout, challenges](
            const auto& cur, const auto&) {
            return gf::Sub(
                gf::Mul(
                    cur[layout.inverse1],
                    gf::Sub(
                        challenges.alpha1,
                        CompressProducer(
                            cur, layout,
                            challenges.gamma1))),
                Fp3::One());
        });
    Add(
        cs, "stage3.bank_bridge.producer_inverse2",
        aq::AirKind::kEverywhere, 2,
        [layout, challenges](
            const auto& cur, const auto&) {
            return gf::Sub(
                gf::Mul(
                    cur[layout.inverse2],
                    gf::Sub(
                        challenges.alpha2,
                        CompressProducer(
                            cur, layout,
                            challenges.gamma2))),
                Fp3::One());
        });
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const uint32_t inverse =
            lane == 0
            ? layout.inverse1
            : layout.inverse2;
        const uint32_t running =
            lane == 0
            ? layout.running1
            : layout.running2;
        const Fp3 expected =
            lane == 0
            ? terminal.alpha1_sum
            : terminal.alpha2_sum;
        Add(
            cs, "stage3.bank_bridge.producer_running_first",
            aq::AirKind::kFirstRow, 1,
            [running](
                const auto& cur, const auto&) {
                return cur[running];
            });
        Add(
            cs, "stage3.bank_bridge.producer_running_transition",
            aq::AirKind::kTransition, 1,
            [inverse, running](
                const auto& cur, const auto& next) {
                return gf::Sub(
                    next[running],
                    gf::Add(
                        cur[running],
                        cur[inverse]));
            });
        Add(
            cs, "stage3.bank_bridge.producer_running_last",
            aq::AirKind::kLastRow, 1,
            [inverse, running, expected](
                const auto& cur, const auto&) {
                return gf::Sub(
                    gf::Add(
                        cur[running],
                        cur[inverse]),
                    expected);
            });
    }
    if (!r0_root.IsNull()) {
        cs.preprocessed_row_group_roots.push_back({
            .version = 1,
            .role =
                aq::AirPreprocessedRowGroupRole::kR0,
            .ordered_columns = layout.base_indices,
            .root = r0_root,
        });
    }
    return true;
}

bool BuildProducerColumns(
    const RCStage3CoupledBankDequantPin& pin,
    const std::vector<std::vector<Fp3>>& relation,
    const RCStage3CtlChallenges& challenges,
    std::vector<std::vector<Fp3>>& columns,
    RCStage3CtlTerminal& terminal,
    std::vector<uint8_t>* bytes_out,
    std::string* why)
{
    const ProducerLayout layout =
        CanonicalProducerLayout();
    if (relation.size() !=
            kRCStage3CoupledBankDequantColumns) {
        return Fail(why, "producer_columns_shape");
    }
    for (const auto& column : relation) {
        if (column.size() != pin.n_rows) {
            return Fail(
                why, "producer_columns_rows");
        }
    }
    columns = relation;
    columns.resize(
        layout.columns,
        std::vector<Fp3>(
            pin.n_rows, Fp3::Zero()));
    std::vector<uint8_t> local_bytes;
    local_bytes.resize(pin.n_rows);
    Fp3 running1 = Fp3::Zero();
    Fp3 running2 = Fp3::Zero();
    for (uint32_t row = 0;
         row < pin.n_rows;
         ++row) {
        uint8_t byte{0};
        if (!SignedByte(
                relation[
                    kRCStage3CoupledBankOutput][row],
                byte)) {
            return Fail(
                why, "producer_signed_range");
        }
        local_bytes[row] = byte;
        columns[layout.byte][row] = U(byte);
        for (uint32_t bit = 0;
             bit < 8;
             ++bit) {
            columns[
                layout.bit_base + bit][row] =
                U((byte >> bit) & 1U);
        }
        columns[layout.address][row] = U(row);
        columns[layout.running1][row] =
            running1;
        columns[layout.running2][row] =
            running2;
        const auto& current =
            [&]() -> const std::vector<Fp3>& {
                static thread_local
                    std::vector<Fp3> row_values;
                row_values.resize(layout.columns);
                for (uint32_t column = 0;
                     column < layout.columns;
                     ++column) {
                    row_values[column] =
                        columns[column][row];
                }
                return row_values;
            }();
        const Fp3 denominator1 = gf::Sub(
            challenges.alpha1,
            CompressProducer(
                current, layout,
                challenges.gamma1));
        const Fp3 denominator2 = gf::Sub(
            challenges.alpha2,
            CompressProducer(
                current, layout,
                challenges.gamma2));
        if (gf::IsZero(denominator1) ||
            gf::IsZero(denominator2)) {
            return Fail(
                why, "producer_ctl_pole");
        }
        const Fp3 inverse1 =
            gf::Inv(denominator1);
        const Fp3 inverse2 =
            gf::Inv(denominator2);
        columns[layout.inverse1][row] =
            inverse1;
        columns[layout.inverse2][row] =
            inverse2;
        running1 = gf::Add(
            running1, inverse1);
        running2 = gf::Add(
            running2, inverse2);
    }
    terminal = {running1, running2};
    if (bytes_out != nullptr) {
        *bytes_out = std::move(local_bytes);
    }
    return true;
}

struct ShaPublicShape {
    ha::ShaManifest dummy_manifest;
    std::vector<ha::FixedProgramBoundaryInstance>
        dummy_boundaries;
    std::vector<std::vector<uint8_t>>
        public_masks;
    std::vector<ha::FixedProgramWitnessBoundaryLink>
        links;
    uint32_t first_pass_blocks{0};
};

bool BuildShaPublicShape(
    const std::vector<uint8_t>& prefix,
    uint32_t bank_bytes,
    ShaPublicShape& out,
    std::string* why)
{
    out = {};
    if (prefix.empty() || bank_bytes < 2 ||
        prefix.size() >
            std::numeric_limits<size_t>::max() -
                bank_bytes) {
        return Fail(why, "sha_public_shape");
    }
    std::vector<uint8_t> dummy(prefix);
    dummy.resize(prefix.size() + bank_bytes, 0);
    if (!ha::BuildShaManifest(
            dummy, ha::ShaMode::Double,
            out.dummy_manifest, why) ||
        !ha::BuildShaManifestBoundaryInstances(
            out.dummy_manifest,
            out.dummy_boundaries, why)) {
        return false;
    }
    out.first_pass_blocks =
        out.dummy_manifest.first.padded_blocks.size();
    if (out.first_pass_blocks == 0 ||
        out.dummy_boundaries.size() !=
            out.first_pass_blocks + 1 ||
        out.dummy_boundaries.size() >
            ha::kFixedProgramVerticalSemanticInstances) {
        return Fail(
            why, "sha_vertical_bound");
    }
    const auto program =
        ha::BuildCanonicalProgram(
            ha::ProgramKind::Sha256Compression);
    out.public_masks.assign(
        out.dummy_boundaries.size(),
        std::vector<uint8_t>(
            program.external_address_count, 1));
    const uint64_t bank_begin = prefix.size();
    const uint64_t bank_end =
        bank_begin + bank_bytes;
    for (uint32_t instance = 0;
         instance < out.first_pass_blocks;
         ++instance) {
        for (uint32_t word = 0;
             word < 16;
             ++word) {
            const uint64_t word_begin =
                uint64_t{instance} * 64 +
                uint64_t{word} * 4;
            const uint64_t word_end =
                word_begin + 4;
            if (word_begin < bank_end &&
                word_end > bank_begin) {
                out.public_masks[instance][word] = 0;
            }
        }
        if (instance != 0) {
            for (uint32_t word = 0;
                 word < 8;
                 ++word) {
                out.public_masks[instance][16 + word] = 0;
                out.links.push_back({
                    .source_instance = instance - 1,
                    .source_final_word = word,
                    .target_instance = instance,
                    .target_external_address =
                        17 + word,
                });
            }
        }
    }
    const uint32_t second =
        out.first_pass_blocks;
    for (uint32_t word = 0;
         word < 8;
         ++word) {
        out.public_masks[second][word] = 0;
        out.links.push_back({
            .source_instance =
                out.first_pass_blocks - 1,
            .source_final_word = word,
            .target_instance = second,
            .target_external_address =
                1 + word,
        });
    }
    return true;
}

bool BuildHonestShaBoundaries(
    const std::vector<uint8_t>& prefix,
    const std::vector<uint8_t>& bank_bytes,
    std::vector<ha::FixedProgramBoundaryInstance>&
        boundaries,
    std::string* why)
{
    std::vector<uint8_t> preimage(prefix);
    preimage.insert(
        preimage.end(),
        bank_bytes.begin(),
        bank_bytes.end());
    ha::ShaManifest manifest;
    return
        ha::BuildShaManifest(
            preimage, ha::ShaMode::Double,
            manifest, why) &&
        ha::BuildShaManifestBoundaryInstances(
            manifest, boundaries, why);
}

struct ConsumerLayout {
    uint32_t mask_base{0};
    uint32_t expected_base{0};
    uint32_t inverse1_base{0};
    uint32_t inverse2_base{0};
    uint32_t running1{0};
    uint32_t running2{0};
    uint32_t columns{0};
};

ConsumerLayout CanonicalConsumerLayout(
    uint32_t sha_columns)
{
    ConsumerLayout out;
    out.mask_base = sha_columns;
    out.expected_base = out.mask_base + 4;
    out.inverse1_base =
        out.expected_base + 4;
    out.inverse2_base =
        out.inverse1_base + 4;
    out.running1 =
        out.inverse2_base + 4;
    out.running2 = out.running1 + 1;
    out.columns = out.running2 + 1;
    return out;
}

bool FindShaMessageRows(
    const ha::FixedProgram& program,
    std::array<uint32_t, 16>& rows,
    std::string* why)
{
    rows.fill(UINT32_MAX);
    for (uint32_t row = 0;
         row < program.rows.size();
         ++row) {
        for (uint32_t input = 0;
             input <
                 program.rows[row].input_count;
             ++input) {
            const uint32_t address =
                program.rows[row].
                    input_address[input];
            if (address >= 1 &&
                address <= 16 &&
                rows[address - 1] ==
                    UINT32_MAX) {
                rows[address - 1] = row;
            }
        }
    }
    if (std::any_of(
            rows.begin(), rows.end(),
            [](uint32_t row) {
                return row == UINT32_MAX;
            })) {
        return Fail(
            why, "sha_message_rows");
    }
    return true;
}

struct ConsumerPublicColumns {
    std::array<std::vector<Fp3>, 4> mask;
    std::array<std::vector<Fp3>, 4> expected;
};

bool BuildConsumerPublicColumns(
    const ShaPublicShape& shape,
    const std::vector<uint8_t>& prefix,
    uint32_t bank_bytes,
    uint32_t n_rows,
    ConsumerPublicColumns& out,
    std::string* why)
{
    const auto program =
        ha::BuildCanonicalProgram(
            ha::ProgramKind::Sha256Compression);
    std::array<uint32_t, 16> message_rows;
    if (!FindShaMessageRows(
            program, message_rows, why)) {
        return false;
    }
    for (auto& column : out.mask) {
        column.assign(
            n_rows, Fp3::Zero());
    }
    for (auto& column : out.expected) {
        column.assign(
            n_rows, Fp3::Zero());
    }
    const uint64_t bank_begin = prefix.size();
    const uint64_t bank_end =
        bank_begin + bank_bytes;
    for (uint32_t instance = 0;
         instance < shape.first_pass_blocks;
         ++instance) {
        const auto& block =
            shape.dummy_manifest.first
                .padded_blocks[instance];
        for (uint32_t word = 0;
             word < 16;
             ++word) {
            const uint32_t row =
                instance * SHA_LANE_ROWS +
                message_rows[word];
            if (row >= n_rows) {
                return Fail(
                    why, "sha_public_row");
            }
            for (uint32_t lane = 0;
                 lane < 4;
                 ++lane) {
                const uint64_t offset =
                    uint64_t{instance} * 64 +
                    uint64_t{word} * 4 +
                    lane;
                const bool bank =
                    offset >= bank_begin &&
                    offset < bank_end;
                out.mask[lane][row] =
                    bank
                    ? Fp3::One()
                    : Fp3::Zero();
                out.expected[lane][row] =
                    U(block[word * 4 + lane]);
            }
        }
    }
    return true;
}

Fp3 CompressConsumer(
    const std::vector<Fp3>& row,
    uint32_t input_address_column,
    uint32_t input_byte_column,
    uint32_t lane,
    uint32_t prefix_size,
    const Fp3& gamma)
{
    const Fp3 gamma2 =
        gf::Mul(gamma, gamma);
    const Fp3 gamma3 =
        gf::Mul(gamma2, gamma);
    const Fp3 address =
        gf::Sub(
            gf::Add(
                gf::Mul(
                    U(4),
                    row[input_address_column]),
                U(lane)),
            U(prefix_size));
    return gf::Add(
        U(PRODUCER_NAMESPACE),
        gf::Add(
            gf::Mul(
                gamma, U(BANK_BYTE_STAGE)),
            gf::Add(
                gf::Mul(gamma2, address),
                gf::Mul(
                    gamma3,
                    row[input_byte_column]))));
}

bool AppendConsumerCs(
    const ShaPublicShape& shape,
    const std::vector<uint8_t>& prefix,
    uint32_t bank_bytes,
    uint32_t input_byte_base,
    uint32_t input_active_column,
    uint32_t input_address_column,
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal,
    aq::AirConstraintSystem<Fp3>& cs,
    ConsumerLayout& layout,
    ConsumerPublicColumns* public_columns,
    std::string* why)
{
    layout = CanonicalConsumerLayout(
        cs.n_columns);
    ConsumerPublicColumns fixed;
    if (!BuildConsumerPublicColumns(
            shape, prefix, bank_bytes,
            cs.n_rows, fixed, why)) {
        return false;
    }
    cs.n_columns = layout.columns;
    cs.preprocessed_pin_ood = true;
    for (uint32_t lane = 0;
         lane < 4;
         ++lane) {
        cs.preprocessed.emplace_back(
            layout.mask_base + lane,
            fixed.mask[lane]);
        cs.preprocessed.emplace_back(
            layout.expected_base + lane,
            fixed.expected[lane]);
        const uint32_t mask =
            layout.mask_base + lane;
        const uint32_t expected =
            layout.expected_base + lane;
        const uint32_t value =
            input_byte_base + lane;
        Add(
            cs, "stage3.bank_bridge.sha_mask_boolean",
            aq::AirKind::kEverywhere, 2,
            [mask](
                const auto& cur, const auto&) {
                return gf::Mul(
                    cur[mask],
                    gf::Sub(
                        cur[mask],
                        Fp3::One()));
            });
        Add(
            cs, "stage3.bank_bridge.sha_mask_active",
            aq::AirKind::kEverywhere, 2,
            [mask, input_active_column](
                const auto& cur, const auto&) {
                return gf::Mul(
                    cur[mask],
                    gf::Sub(
                        cur[input_active_column],
                        Fp3::One()));
            });
        Add(
            cs, "stage3.bank_bridge.sha_public_byte_pin",
            aq::AirKind::kEverywhere, 2,
            [mask, expected, value,
             input_active_column](
                const auto& cur, const auto&) {
                return gf::Mul(
                    gf::Sub(
                        cur[input_active_column],
                        cur[mask]),
                    gf::Sub(
                        cur[value],
                        cur[expected]));
            });
        for (uint32_t ctl_lane = 0;
             ctl_lane < 2;
             ++ctl_lane) {
            const uint32_t inverse =
                (ctl_lane == 0
                 ? layout.inverse1_base
                 : layout.inverse2_base) +
                lane;
            const Fp3 gamma =
                ctl_lane == 0
                ? challenges.gamma1
                : challenges.gamma2;
            const Fp3 alpha =
                ctl_lane == 0
                ? challenges.alpha1
                : challenges.alpha2;
            Add(
                cs, "stage3.bank_bridge.sha_sparse_inverse",
                aq::AirKind::kEverywhere, 2,
                [=](
                    const auto& cur, const auto&) {
                    return gf::Sub(
                        gf::Mul(
                            cur[inverse],
                            gf::Sub(
                                alpha,
                                CompressConsumer(
                                    cur,
                                    input_address_column,
                                    value, lane,
                                    prefix.size(),
                                    gamma))),
                        cur[mask]);
                });
            Add(
                cs, "stage3.bank_bridge.sha_sparse_inverse_inactive",
                aq::AirKind::kEverywhere, 2,
                [inverse, mask](
                    const auto& cur, const auto&) {
                    return gf::Mul(
                        gf::Sub(
                            Fp3::One(),
                            cur[mask]),
                        cur[inverse]);
                });
        }
    }
    for (uint32_t ctl_lane = 0;
         ctl_lane < 2;
         ++ctl_lane) {
        const uint32_t inverse_base =
            ctl_lane == 0
            ? layout.inverse1_base
            : layout.inverse2_base;
        const uint32_t running =
            ctl_lane == 0
            ? layout.running1
            : layout.running2;
        const Fp3 expected =
            ctl_lane == 0
            ? terminal.alpha1_sum
            : terminal.alpha2_sum;
        Add(
            cs, "stage3.bank_bridge.sha_running_first",
            aq::AirKind::kFirstRow, 1,
            [running](
                const auto& cur, const auto&) {
                return cur[running];
            });
        Add(
            cs, "stage3.bank_bridge.sha_running_transition",
            aq::AirKind::kTransition, 1,
            [inverse_base, running](
                const auto& cur, const auto& next) {
                Fp3 sum = Fp3::Zero();
                for (uint32_t lane = 0;
                     lane < 4;
                     ++lane) {
                    sum = gf::Add(
                        sum,
                        cur[inverse_base + lane]);
                }
                return gf::Sub(
                    next[running],
                    gf::Sub(
                        cur[running], sum));
            });
        Add(
            cs, "stage3.bank_bridge.sha_running_last",
            aq::AirKind::kLastRow, 1,
            [inverse_base, running, expected](
                const auto& cur, const auto&) {
                Fp3 sum = Fp3::Zero();
                for (uint32_t lane = 0;
                     lane < 4;
                     ++lane) {
                    sum = gf::Add(
                        sum,
                        cur[inverse_base + lane]);
                }
                return gf::Sub(
                    gf::Sub(
                        cur[running], sum),
                    expected);
            });
    }
    if (public_columns != nullptr) {
        *public_columns = std::move(fixed);
    }
    return true;
}

bool AppendConsumerColumns(
    const std::vector<uint8_t>& prefix,
    uint32_t bank_bytes,
    uint32_t input_byte_base,
    uint32_t input_address_column,
    const ConsumerLayout& layout,
    const ConsumerPublicColumns& fixed,
    const RCStage3CtlChallenges& challenges,
    std::vector<std::vector<Fp3>>& columns,
    RCStage3CtlTerminal& terminal,
    std::string* why)
{
    const uint32_t n_rows =
        columns.empty()
        ? 0
        : columns.front().size();
    if (n_rows < 2 ||
        fixed.mask[0].size() != n_rows) {
        return Fail(
            why, "sha_columns_shape");
    }
    columns.resize(
        layout.columns,
        std::vector<Fp3>(
            n_rows, Fp3::Zero()));
    for (uint32_t lane = 0;
         lane < 4;
         ++lane) {
        columns[layout.mask_base + lane] =
            fixed.mask[lane];
        columns[layout.expected_base + lane] =
            fixed.expected[lane];
    }
    Fp3 running1 = Fp3::Zero();
    Fp3 running2 = Fp3::Zero();
    uint64_t active_count = 0;
    for (uint32_t row = 0;
         row < n_rows;
         ++row) {
        columns[layout.running1][row] =
            running1;
        columns[layout.running2][row] =
            running2;
        for (uint32_t lane = 0;
             lane < 4;
             ++lane) {
            if (gf::IsZero(
                    fixed.mask[lane][row])) {
                continue;
            }
            ++active_count;
            std::vector<Fp3> current(
                layout.columns,
                Fp3::Zero());
            for (uint32_t column = 0;
                 column < layout.columns;
                 ++column) {
                current[column] =
                    columns[column][row];
            }
            const uint32_t value =
                input_byte_base + lane;
            const Fp3 denominator1 =
                gf::Sub(
                    challenges.alpha1,
                    CompressConsumer(
                        current,
                        input_address_column,
                        value, lane,
                        prefix.size(),
                        challenges.gamma1));
            const Fp3 denominator2 =
                gf::Sub(
                    challenges.alpha2,
                    CompressConsumer(
                        current,
                        input_address_column,
                        value, lane,
                        prefix.size(),
                        challenges.gamma2));
            if (gf::IsZero(denominator1) ||
                gf::IsZero(denominator2)) {
                return Fail(
                    why, "sha_ctl_pole");
            }
            const Fp3 inverse1 =
                gf::Inv(denominator1);
            const Fp3 inverse2 =
                gf::Inv(denominator2);
            columns[
                layout.inverse1_base +
                lane][row] = inverse1;
            columns[
                layout.inverse2_base +
                lane][row] = inverse2;
            running1 = gf::Sub(
                running1, inverse1);
            running2 = gf::Sub(
                running2, inverse2);
        }
    }
    if (active_count != bank_bytes) {
        return Fail(
            why, "sha_ctl_coverage");
    }
    terminal = {running1, running2};
    return true;
}

bool CanonicalManifestAndPins(
    const RCStage3CoupledBankDequantPin& pin,
    const std::vector<uint8_t>& prefix,
    const uint256& fs_seed,
    const RCStage3CoupledBankHashBridgeProofV1& proof)
{
    const auto producer =
        ProducerSchedule(pin.logical_rows);
    const auto consumer =
        ConsumerSchedule(pin.logical_rows);
    const uint256 transcript =
        TranscriptSeed(pin, prefix, fs_seed);
    if (proof.manifest.bus_id !=
            kRCStage3CoupledBankHashBridgeBusId ||
        proof.manifest.transcript_seed !=
            transcript ||
        proof.manifest.participants.size() != 2 ||
        proof.manifest.participants[0] !=
            Participant(
                RCStage3RelationRole::CoupledBank,
                producer, true) ||
        proof.manifest.participants[1] !=
            Participant(
                RCStage3RelationRole::CompositionLink,
                consumer, false) ||
        proof.pins.size() != 2) {
        return false;
    }
    return
        proof.pins[0].role ==
            RCStage3RelationRole::CoupledBank &&
        proof.pins[1].role ==
            RCStage3RelationRole::CompositionLink &&
        proof.pins[0].bus_id ==
            proof.manifest.bus_id &&
        proof.pins[1].bus_id ==
            proof.manifest.bus_id &&
        proof.pins[0].event_count ==
            pin.logical_rows &&
        proof.pins[1].event_count ==
            pin.logical_rows &&
        proof.pins[0].send_count ==
            pin.logical_rows &&
        proof.pins[0].receive_count == 0 &&
        proof.pins[1].send_count == 0 &&
        proof.pins[1].receive_count ==
            pin.logical_rows &&
        proof.pins[0].schedule_commitment ==
            CommitRCStage3CtlSchedule(producer) &&
        proof.pins[1].schedule_commitment ==
            CommitRCStage3CtlSchedule(consumer) &&
        proof.pins[0].trace_commitment ==
            proof.bank_byte_alg_hash_root &&
        proof.pins[1].trace_commitment ==
            proof.sha_r0_root;
}

} // namespace

bool ProveRCStage3CoupledBankHashBridgeV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const std::vector<std::vector<Fp3>>&
        relation_columns,
    const std::vector<uint8_t>& public_prefix,
    const uint256& fs_seed,
    RCStage3CoupledBankHashBridgeProofV1& out,
    std::string* why)
{
    out = {};
    if (!ValidPin(source_pin) ||
        public_prefix.empty() ||
        fs_seed.IsNull()) {
        return Fail(why, "prove_shape");
    }
    out.bank_byte_count =
        source_pin.logical_rows;
    out.source_pin_commitment =
        source_pin.pin_commitment;

    const RCStage3CtlChallenges placeholder{
        gf::FromU64_3(2),
        gf::FromU64_3(3),
        gf::FromU64_3(5),
        gf::FromU64_3(7),
    };
    std::vector<std::vector<Fp3>>
        producer_placeholder_columns;
    RCStage3CtlTerminal ignored_terminal;
    std::vector<uint8_t> bank_bytes;
    if (!BuildProducerColumns(
            source_pin, relation_columns,
            placeholder,
            producer_placeholder_columns,
            ignored_terminal, &bank_bytes, why)) {
        return false;
    }
    aq::AirConstraintSystem<Fp3>
        producer_placeholder_cs;
    ProducerLayout producer_layout;
    if (!BuildProducerCs(
            source_pin, placeholder,
            ignored_terminal, {},
            producer_placeholder_cs,
            producer_layout, why)) {
        return false;
    }
    const auto producer_r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            producer_placeholder_cs,
            producer_placeholder_columns,
            producer_layout.base_indices);
    if (!producer_r0.valid ||
        producer_r0.base_row_commitment.IsNull()) {
        return Fail(
            why, "producer_r0:" +
                     producer_r0.note);
    }
    if (producer_r0.base_row_commitment !=
        source_pin.r0_row_group_root) {
        return Fail(
            why, "producer_r0_source_substitution");
    }
    out.bank_byte_alg_hash_root =
        source_pin.r0_row_group_root;

    ShaPublicShape sha_shape;
    std::vector<ha::FixedProgramBoundaryInstance>
        honest_boundaries;
    if (!BuildShaPublicShape(
            public_prefix,
            source_pin.logical_rows,
            sha_shape, why) ||
        !BuildHonestShaBoundaries(
            public_prefix, bank_bytes,
            honest_boundaries, why) ||
        honest_boundaries.size() !=
            sha_shape.dummy_boundaries.size()) {
        return Fail(why, "sha_shape");
    }
    out.first_pass_blocks =
        sha_shape.first_pass_blocks;
    const auto program =
        ha::BuildCanonicalProgram(
            ha::ProgramKind::Sha256Compression);
    HashWriter sha_seed_writer;
    sha_seed_writer <<
        "BTX_RC_STAGE3_BANK_28_TO_29_SHA_R0_V1";
    sha_seed_writer << fs_seed;
    sha_seed_writer << source_pin.pin_commitment;
    sha_seed_writer << public_prefix;
    sha_seed_writer << source_pin.logical_rows;
    const uint256 sha_seed =
        sha_seed_writer.GetHash();
    auto sha_instance =
        ha::BuildFixedProgramVerticalWitnessBoundaryInstance(
            program, honest_boundaries,
            sha_shape.public_masks,
            sha_shape.links, sha_seed);
    if (!sha_instance.valid ||
        sha_instance.base_row_commitment.IsNull() ||
        !sha_instance.base_row_tree_cache) {
        return Fail(
            why, "sha_instance:" +
                     sha_instance.note);
    }
    out.sha_public_statement =
        sha_instance.public_statement;
    out.sha_r0_root =
        sha_instance.base_row_commitment;

    out.manifest.bus_id =
        kRCStage3CoupledBankHashBridgeBusId;
    out.manifest.transcript_seed =
        TranscriptSeed(
            source_pin, public_prefix, fs_seed);
    const auto producer_schedule =
        ProducerSchedule(
            source_pin.logical_rows);
    const auto consumer_schedule =
        ConsumerSchedule(
            source_pin.logical_rows);
    out.manifest.participants = {
        Participant(
            RCStage3RelationRole::CoupledBank,
            producer_schedule, true),
        Participant(
            RCStage3RelationRole::CompositionLink,
            consumer_schedule, false),
    };
    out.pins.resize(2);
    for (uint32_t index = 0;
         index < 2;
         ++index) {
        const auto& participant =
            out.manifest.participants[index];
        auto& pin = out.pins[index];
        pin.role = participant.role;
        pin.bus_id = out.manifest.bus_id;
        pin.event_count =
            participant.event_count;
        pin.send_count =
            participant.send_count;
        pin.receive_count =
            participant.receive_count;
        pin.schedule_commitment =
            participant.schedule_commitment;
    }
    out.pins[0].trace_commitment =
        out.bank_byte_alg_hash_root;
    out.pins[1].trace_commitment =
        out.sha_r0_root;

    RCStage3CtlChallenges challenges;
    if (!DeriveRCStage3CtlChallenges(
            out.manifest, out.pins,
            challenges, why)) {
        return false;
    }

    std::vector<std::vector<Fp3>>
        producer_columns;
    RCStage3CtlTerminal producer_terminal;
    if (!BuildProducerColumns(
            source_pin, relation_columns,
            challenges, producer_columns,
            producer_terminal, nullptr, why)) {
        return false;
    }
    aq::AirConstraintSystem<Fp3> producer_cs;
    if (!BuildProducerCs(
            source_pin, challenges,
            producer_terminal,
            out.bank_byte_alg_hash_root,
            producer_cs, producer_layout, why)) {
        return false;
    }

    aq::AirConstraintSystem<Fp3> sha_cs =
        sha_instance.cs;
    std::vector<std::vector<Fp3>> sha_columns =
        sha_instance.columns;
    ConsumerLayout consumer_layout;
    ConsumerPublicColumns fixed;
    RCStage3CtlTerminal zero_terminal;
    if (!AppendConsumerCs(
            sha_shape, public_prefix,
            source_pin.logical_rows,
            sha_instance.input_byte_base,
            sha_instance.input_active_column,
            sha_instance.input_address_column,
            challenges, zero_terminal,
            sha_cs, consumer_layout,
            &fixed, why)) {
        return false;
    }
    RCStage3CtlTerminal consumer_terminal;
    if (!AppendConsumerColumns(
            public_prefix,
            source_pin.logical_rows,
            sha_instance.input_byte_base,
            sha_instance.input_address_column,
            consumer_layout, fixed,
            challenges, sha_columns,
            consumer_terminal, why)) {
        return false;
    }
    // Last-row terminal constraints depend on the completed witness.
    sha_cs = sha_instance.cs;
    if (!AppendConsumerCs(
            sha_shape, public_prefix,
            source_pin.logical_rows,
            sha_instance.input_byte_base,
            sha_instance.input_active_column,
            sha_instance.input_address_column,
            challenges, consumer_terminal,
            sha_cs, consumer_layout,
            nullptr, why)) {
        return false;
    }

    out.pins[0].terminal =
        producer_terminal;
    out.pins[1].terminal =
        consumer_terminal;
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);
    out.pins[0].challenge_commitment =
        challenge_commitment;
    out.pins[1].challenge_commitment =
        challenge_commitment;
    RCStage3CoupledBankHashBridgeProofV1
        seed_view = out;
    const uint256 producer_seed =
        ChildSeed(
            "BTX_RC_STAGE3_BANK_28_TO_29_PRODUCER_AIR_V1",
            fs_seed, seed_view);
    const auto producer_proved =
        aq::AirQuotientProveRowsSplitRap(
            producer_cs, producer_columns,
            producer_layout.base_indices,
            producer_seed, {}, &producer_r0);
    if (!producer_proved.ok ||
        !producer_proved.division_exact) {
        return Fail(
            why, "producer_proof:" +
                     producer_proved.note);
    }
    out.producer_proof =
        producer_proved.proof;
    out.producer_proof_commitment =
        ProofCodecCommitment(
            "BTX_RC_STAGE3_BANK_28_TO_29_PRODUCER_CODEC_V1",
            out.producer_proof);
    out.pins[0].auxiliary_commitment =
        out.producer_proof_commitment;

    // Rebuild the retained SHA R0 cache after adding only Rdep bridge
    // columns. The ordered base set and root remain byte-identical.
    const auto sha_r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            sha_cs, sha_columns,
            sha_instance.base_column_indices);
    if (!sha_r0.valid ||
        sha_r0.base_row_commitment !=
            out.sha_r0_root) {
        return Fail(
            why, "sha_r0_reuse:" +
                     sha_r0.note);
    }
    const uint256 sha_proof_seed =
        ChildSeed(
            "BTX_RC_STAGE3_BANK_28_TO_29_SHA_AIR_V1",
            fs_seed, seed_view);
    const auto sha_proved =
        aq::AirQuotientProveRowsSplitRap(
            sha_cs, sha_columns,
            sha_instance.base_column_indices,
            sha_proof_seed, {}, &sha_r0);
    if (!sha_proved.ok ||
        !sha_proved.division_exact) {
        return Fail(
            why, "sha_proof:" +
                     sha_proved.note);
    }
    out.sha_proof = sha_proved.proof;
    out.sha_proof_commitment =
        ProofCodecCommitment(
            "BTX_RC_STAGE3_BANK_28_TO_29_SHA_CODEC_V1",
            out.sha_proof);
    out.pins[1].auxiliary_commitment =
        out.sha_proof_commitment;
    if (!VerifyRCStage3CtlPublicPinComposition(
            out.manifest, out.pins, why)) {
        return false;
    }
    out.proof_commitment =
        CommitBridge(out);
    out.terminal_bus_commitment =
        CommitTerminalBus(out);
    if (out.proof_commitment.IsNull() ||
        out.terminal_bus_commitment.IsNull()) {
        return Fail(
            why, "proof_commitment");
    }
    if (why != nullptr) {
        *why =
            "stage3:coupled_bank_hash_bridge:"
            "proof_complete";
    }
    return true;
}

RCStage3CoupledBankHashBridgeAuditV1
VerifyRCStage3CoupledBankHashBridgeV1(
    const RCStage3CoupledBankDequantPin& source_pin,
    const std::vector<uint8_t>& public_prefix,
    const uint256& fs_seed,
    const RCStage3CoupledBankHashBridgeProofV1& proof)
{
    RCStage3CoupledBankHashBridgeAuditV1 out;
    out.bank_byte_count =
        proof.bank_byte_count;
    out.first_pass_blocks =
        proof.first_pass_blocks;
    const auto fail =
        [&](const std::string& detail) {
            out.note =
                "stage3:coupled_bank_hash_bridge:" +
                detail;
            return out;
        };
    if (!ValidPin(source_pin) ||
        public_prefix.empty() ||
        fs_seed.IsNull() ||
        proof.version !=
            kRCStage3CoupledBankHashBridgeVersion ||
        proof.bank_byte_count !=
            source_pin.logical_rows ||
        proof.source_pin_commitment !=
            source_pin.pin_commitment ||
        !CanonicalManifestAndPins(
            source_pin, public_prefix,
            fs_seed, proof)) {
        return fail("shape_manifest_or_pins");
    }
    out.producer_sends =
        proof.pins[0].send_count;
    out.sha_receives =
        proof.pins[1].receive_count;

    RCStage3CtlChallenges challenges;
    std::string why;
    if (!DeriveRCStage3CtlChallenges(
            proof.manifest, proof.pins,
            challenges, &why) ||
        proof.pins[0].challenge_commitment !=
            CommitRCStage3CtlChallenges(
                challenges) ||
        proof.pins[1].challenge_commitment !=
            CommitRCStage3CtlChallenges(
                challenges)) {
        return fail(
            "challenge:" + why);
    }
    out.shared_post_r0_challenges = true;

    ProducerLayout producer_layout;
    aq::AirConstraintSystem<Fp3> producer_cs;
    if (!BuildProducerCs(
            source_pin, challenges,
            proof.pins[0].terminal,
            proof.bank_byte_alg_hash_root,
            producer_cs, producer_layout,
            &why) ||
        proof.producer_proof.
            base_column_indices !=
            producer_layout.base_indices ||
        proof.producer_proof.batch.groups.size() !=
            3 ||
        Fri3AlgDigestToUint256(
            proof.producer_proof.batch
                .groups[0].row_commit.root) !=
            proof.bank_byte_alg_hash_root) {
        return fail(
            "producer_r0:" + why);
    }
    const uint256 producer_seed =
        ChildSeed(
            "BTX_RC_STAGE3_BANK_28_TO_29_PRODUCER_AIR_V1",
            fs_seed, proof);
    if (!aq::AirQuotientVerifyRowsSplitRap(
            producer_cs,
            proof.producer_proof,
            producer_layout.base_indices,
            producer_seed, &why)) {
        return fail(
            "producer_verify:" + why);
    }
    out.signed_output_range_and_u8_same_trace =
        true;
    out.producer_ctl_value_same_trace = true;
    out.bank_byte_alg_hash_root_verified = true;
    out.producer_split_rap_verified = true;

    ShaPublicShape sha_shape;
    if (!BuildShaPublicShape(
            public_prefix,
            source_pin.logical_rows,
            sha_shape, &why) ||
        proof.first_pass_blocks !=
            sha_shape.first_pass_blocks) {
        return fail(
            "sha_public_shape:" + why);
    }
    const auto program =
        ha::BuildCanonicalProgram(
            ha::ProgramKind::Sha256Compression);
    HashWriter sha_seed_writer;
    sha_seed_writer <<
        "BTX_RC_STAGE3_BANK_28_TO_29_SHA_R0_V1";
    sha_seed_writer << fs_seed;
    sha_seed_writer << source_pin.pin_commitment;
    sha_seed_writer << public_prefix;
    sha_seed_writer << source_pin.logical_rows;
    const uint256 sha_seed =
        sha_seed_writer.GetHash();
    const auto sha_verifier =
        ha::BuildFixedProgramVerticalWitnessBoundaryVerifierInstance(
            program,
            sha_shape.dummy_boundaries,
            sha_shape.public_masks,
            sha_shape.links, sha_seed,
            proof.sha_r0_root);
    if (!sha_verifier.valid ||
        sha_verifier.public_statement !=
            proof.sha_public_statement ||
        sha_verifier.base_row_commitment !=
            proof.sha_r0_root) {
        return fail(
            "sha_verifier_cs:" +
            sha_verifier.note);
    }
    aq::AirConstraintSystem<Fp3> sha_cs =
        sha_verifier.cs;
    ConsumerLayout consumer_layout;
    if (!AppendConsumerCs(
            sha_shape, public_prefix,
            source_pin.logical_rows,
            sha_verifier.input_byte_base,
            sha_verifier.input_active_column,
            sha_verifier.input_address_column,
            challenges,
            proof.pins[1].terminal,
            sha_cs, consumer_layout,
            nullptr, &why) ||
        proof.sha_proof.
            base_column_indices !=
            sha_verifier.base_column_indices ||
        proof.sha_proof.batch.groups.size() != 3 ||
        Fri3AlgDigestToUint256(
            proof.sha_proof.batch.groups[0]
                .row_commit.root) !=
            proof.sha_r0_root) {
        return fail(
            "sha_r0:" + why);
    }
    const uint256 sha_proof_seed =
        ChildSeed(
            "BTX_RC_STAGE3_BANK_28_TO_29_SHA_AIR_V1",
            fs_seed, proof);
    if (!aq::AirQuotientVerifyRowsSplitRap(
            sha_cs, proof.sha_proof,
            sha_verifier.base_column_indices,
            sha_proof_seed, &why)) {
        return fail(
            "sha_verify:" + why);
    }
    out.sha_first_pass_bytes_epoch_r0 = true;
    out.sha_nonbank_bytes_pinned = true;
    out.sha_ctl_value_same_trace = true;
    out.sha_split_rap_verified = true;

    if (!VerifyRCStage3CtlPublicPinComposition(
            proof.manifest, proof.pins,
            &why)) {
        return fail(
            "terminal:" + why);
    }
    out.dual_lane_terminal_equality = true;

    const uint256 expected_producer_codec =
        ProofCodecCommitment(
            "BTX_RC_STAGE3_BANK_28_TO_29_PRODUCER_CODEC_V1",
            proof.producer_proof);
    const uint256 expected_sha_codec =
        ProofCodecCommitment(
            "BTX_RC_STAGE3_BANK_28_TO_29_SHA_CODEC_V1",
            proof.sha_proof);
    if (proof.producer_proof_commitment !=
            expected_producer_codec ||
        proof.sha_proof_commitment !=
            expected_sha_codec ||
        proof.pins[0].auxiliary_commitment !=
            expected_producer_codec ||
        proof.pins[1].auxiliary_commitment !=
            expected_sha_codec ||
        proof.proof_commitment !=
            CommitBridge(proof) ||
        proof.terminal_bus_commitment !=
            CommitTerminalBus(proof)) {
        return fail("proof_commitments");
    }
    out.local_bridge_executable = true;
    out.endpoint28_producer_root_bound = true;
    out.normalized_child_verifiers_execute =
        false;
    out.recursively_consumed = false;
    out.authority = false;
    out.residuals = {
        "producer_and_sha_split_rap_verifiers_not_yet_executed_inside_the_normalized_parent_air",
    };
    out.valid =
        out.signed_output_range_and_u8_same_trace &&
        out.producer_ctl_value_same_trace &&
        out.bank_byte_alg_hash_root_verified &&
        out.sha_first_pass_bytes_epoch_r0 &&
        out.sha_nonbank_bytes_pinned &&
        out.sha_ctl_value_same_trace &&
        out.shared_post_r0_challenges &&
        out.producer_split_rap_verified &&
        out.sha_split_rap_verified &&
        out.dual_lane_terminal_equality &&
        out.local_bridge_executable &&
        out.endpoint28_producer_root_bound &&
        !out.normalized_child_verifiers_execute &&
        !out.recursively_consumed &&
        !out.authority &&
        out.residuals.size() == 1;
    out.note =
        out.valid
        ? "stage3:coupled_bank_hash_bridge:"
          "local_proof_owned_bridge_complete;"
          "recursive_authority_gated"
        : "stage3:coupled_bank_hash_bridge:"
          "audit_invalid";
    return out;
}

} // namespace matmul::v4::rc
