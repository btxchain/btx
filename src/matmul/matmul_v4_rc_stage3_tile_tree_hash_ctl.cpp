// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_tile_tree_hash_ctl.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <hash.h>

#include <algorithm>
#include <array>
#include <functional>
#include <limits>
#include <numeric>
#include <optional>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace ha = stage3_hash_air;
using gf::Fp3;
using AirCS = aq::AirConstraintSystem<Fp3>;
namespace cb = constraint_bytecode;

constexpr uint32_t LANE_ROWS = 1024;
constexpr uint32_t EDGE_NAMESPACE = 0x54454831U; // "TEH1"
constexpr uint32_t EDGE_STAGE = 20;
constexpr char TRANSCRIPT_DOMAIN[] =
    "BTX_RC_STAGE3_TILE_TREE_HASH_EDGE_CTL_TRANSCRIPT_V1";
constexpr char CHILD_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_TILE_TREE_HASH_EDGE_CTL_CHILD_V1";
constexpr char PROOF_DOMAIN[] =
    "BTX_RC_STAGE3_TILE_TREE_HASH_EDGE_CTL_PROOF_V1";
constexpr char COLLECTION_DOMAIN[] =
    "BTX_RC_STAGE3_TILE_TREE_HASH_CTL_COLLECTION_V1";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:tile_tree_hash_ctl:" + detail;
    }
    return false;
}

Fp3 U(uint64_t value)
{
    return Fp3::FromFp(gf::FromU64(value));
}

void Add(
    AirCS& cs,
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

struct NodeShape {
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    std::vector<std::vector<uint8_t>> public_masks;
    std::vector<ha::FixedProgramWitnessBoundaryLink> links;
    uint256 seed{};
    uint256 public_statement{};
};

struct RootByteShape {
    AirCS cs;
    std::vector<std::vector<Fp3>> columns;
    std::vector<uint32_t> base_column_indices;
    uint256 seed{};
    uint256 public_statement{};
};

Fp3 SignedByte(uint8_t byte)
{
    return U(
        byte < 128
            ? byte
            : gf::Sub(gf::kP, 256U - byte));
}

bool BuildRootByteShape(
    const uint256& statement_commitment,
    const uint256& tree_commitment,
    uint32_t round_index,
    const uint256& root,
    bool witness,
    RootByteShape& out,
    std::string* why)
{
    out = {};
    cb::ProgramTable table;
    if (statement_commitment.IsNull() ||
        tree_commitment.IsNull() ||
        root.IsNull() ||
        !BuildRCStage3EpisodeTileTreeByteBridgeProgramTable(
            table, why) ||
        !cb::BuildAirConstraintSystemFromProgramTable(
            table, 32, out.cs, why)) {
        return Fail(why, "root_byte_shape_program");
    }
    std::vector<Fp3> active(32, Fp3::One());
    std::vector<Fp3> address(32, Fp3::Zero());
    std::vector<Fp3> expected(32, Fp3::Zero());
    for (uint32_t row = 0; row < 32; ++row) {
        address[row] = U(row);
        expected[row] = SignedByte(root.begin()[row]);
    }
    out.cs.preprocessed.emplace_back(
        kRCStage3EpisodeTileBridgeActive, active);
    out.cs.preprocessed.emplace_back(
        kRCStage3EpisodeTileBridgeAddress, address);
    out.cs.preprocessed.emplace_back(
        kRCStage3EpisodeTileBridgeExpected, expected);
    out.base_column_indices.resize(out.cs.n_columns);
    std::iota(
        out.base_column_indices.begin(),
        out.base_column_indices.end(), 0U);
    if (witness) {
        out.columns.assign(
            out.cs.n_columns,
            std::vector<Fp3>(32, Fp3::Zero()));
        for (const auto& [column, values] :
             out.cs.preprocessed) {
            out.columns[column] = values;
        }
        for (uint32_t row = 0; row < 32; ++row) {
            const uint8_t byte = root.begin()[row];
            const Fp3 value = SignedByte(byte);
            out.columns[
                kRCStage3EpisodeTileBridgeValue][row] =
                value;
            out.columns[
                kRCStage3EpisodeTileBridgeExport][row] =
                value;
            out.columns[
                kRCStage3EpisodeTileBridgeByte][row] =
                U(byte);
            out.columns[
                kRCStage3EpisodeTileBridgeSign][row] =
                U(byte >> 7);
            for (uint32_t bit = 0; bit < 8; ++bit) {
                out.columns[
                    kRCStage3EpisodeTileBridgeBitBase +
                    bit][row] =
                    U((byte >> bit) & 1U);
            }
        }
    }
    HashWriter seed;
    seed << "BTX_RC_STAGE3_TILE_TREE_ROOT_BYTE_R0_V1";
    seed << statement_commitment;
    seed << tree_commitment;
    seed << round_index;
    seed << root;
    seed << cb::CommitProgramTable(table);
    out.seed = seed.GetHash();
    HashWriter statement;
    statement
        << "BTX_RC_STAGE3_TILE_TREE_ROOT_BYTE_STATEMENT_V1";
    statement << out.seed;
    statement << out.cs.n_rows;
    statement << out.cs.n_columns;
    out.public_statement = statement.GetHash();
    return !out.seed.IsNull() &&
        !out.public_statement.IsNull();
}

bool BuildNodeShape(
    const uint256& statement_commitment,
    const uint256& tree_commitment,
    uint32_t round_index,
    uint32_t node_ordinal,
    const ha::TileTreeHashNode& node,
    NodeShape& out,
    std::string* why)
{
    out = {};
    if (statement_commitment.IsNull() ||
        tree_commitment.IsNull() ||
        node.sha256d.mode != ha::ShaMode::Double ||
        !ha::BuildShaManifestBoundaryInstances(
            node.sha256d, out.boundaries, why) ||
        out.boundaries.size() < 2 ||
        out.boundaries.size() > 64) {
        return Fail(why, "node_shape_boundaries");
    }
    out.public_masks.resize(
        out.boundaries.size(),
        std::vector<uint8_t>(88, 1));
    const uint32_t first_blocks =
        node.sha256d.first.padded_blocks.size();
    if (first_blocks == 0 ||
        out.boundaries.size() !=
            first_blocks +
                node.sha256d.second.padded_blocks.size()) {
        return Fail(why, "node_shape_passes");
    }
    uint64_t link_id = 1;
    const auto add_word_links =
        [&](uint32_t source, uint32_t target,
            uint32_t target_address_begin) {
            for (uint32_t word = 0; word < 8; ++word) {
                ha::FixedProgramWitnessBoundaryLink link;
                link.source_instance = source;
                link.source_final_word = word;
                link.target_instance = target;
                link.target_external_address =
                    target_address_begin + word;
                link.link_id =
                    (uint64_t{round_index + 1} << 48) |
                    (uint64_t{node_ordinal + 1} << 24) |
                    link_id++;
                out.public_masks[target][
                    link.target_external_address - 1] = 0;
                out.links.push_back(link);
            }
        };
    for (uint32_t block = 1;
         block < first_blocks; ++block) {
        add_word_links(block - 1, block, 17);
    }
    add_word_links(
        first_blocks - 1, first_blocks, 1);
    if (out.links.empty()) {
        return Fail(why, "node_shape_links");
    }
    HashWriter seed;
    seed << "BTX_RC_STAGE3_TILE_TREE_NODE_SHA_R0_V1";
    seed << statement_commitment;
    seed << tree_commitment;
    seed << round_index;
    seed << node_ordinal;
    seed << node.sha256d.commitment;
    out.seed = seed.GetHash();
    const auto program = ha::BuildCanonicalProgram(
        ha::ProgramKind::Sha256Compression);
    out.public_statement =
        ha::CommitFixedProgramVerticalWitnessBoundaryStatement(
            program, out.boundaries,
            out.public_masks, out.links);
    return !out.seed.IsNull() &&
        !out.public_statement.IsNull();
}

std::array<uint32_t, 16> FirstMessageRows(
    const ha::FixedProgram& program)
{
    std::array<uint32_t, 16> out;
    out.fill(UINT32_MAX);
    for (uint32_t row = 0;
         row < program.rows.size(); ++row) {
        for (uint32_t slot = 0;
             slot < program.rows[row].input_count; ++slot) {
            const uint32_t address =
                program.rows[row].input_address[slot];
            if (address >= 1 && address <= 16 &&
                out[address - 1] == UINT32_MAX) {
                out[address - 1] = row;
            }
        }
    }
    return out;
}

RCStage3CtlSchedule EdgeSchedule(int8_t multiplicity)
{
    RCStage3CtlSchedule out;
    out.events.reserve(32);
    for (uint32_t byte = 0; byte < 32; ++byte) {
        out.events.push_back({
            EDGE_NAMESPACE, EDGE_STAGE, byte, multiplicity});
    }
    return out;
}

RCStage3CtlParticipantSpec Participant(
    RCStage3RelationRole role,
    const RCStage3CtlSchedule& schedule,
    bool sends)
{
    RCStage3CtlParticipantSpec out;
    out.role = role;
    out.event_count = schedule.events.size();
    out.send_count = sends ? out.event_count : 0;
    out.receive_count = sends ? 0 : out.event_count;
    out.schedule_commitment = CommitRCStage3CtlSchedule(schedule);
    return out;
}

uint256 TranscriptSeed(
    const RCStage3TileTreeHashEdgeCtlProof& proof)
{
    HashWriter hash;
    hash << TRANSCRIPT_DOMAIN;
    hash << proof.version;
    hash << proof.statement_commitment;
    hash << proof.tree_manifest_commitment;
    hash << proof.round_index;
    hash << proof.producer_node_ordinal;
    hash << proof.consumer_node_ordinal;
    hash << proof.consumer_preimage_offset;
    hash << static_cast<uint16_t>(proof.producer_endpoint);
    hash << static_cast<uint16_t>(proof.consumer_endpoint);
    hash << proof.producer_public_statement;
    hash << proof.consumer_public_statement;
    return hash.GetHash();
}

uint256 ChildSeed(
    const char* side,
    const RCStage3TileTreeHashEdgeCtlProof& proof)
{
    HashWriter hash;
    hash << CHILD_SEED_DOMAIN;
    hash << side;
    hash << TranscriptSeed(proof);
    hash << (proof.pins.empty()
                 ? uint256{}
                 : proof.pins.front().challenge_commitment);
    for (const auto& pin : proof.pins) {
        hash << gf::Canonical(pin.terminal.alpha1_sum.c0);
        hash << gf::Canonical(pin.terminal.alpha1_sum.c1);
        hash << gf::Canonical(pin.terminal.alpha1_sum.c2);
        hash << gf::Canonical(pin.terminal.alpha2_sum.c0);
        hash << gf::Canonical(pin.terminal.alpha2_sum.c1);
        hash << gf::Canonical(pin.terminal.alpha2_sum.c2);
    }
    return hash.GetHash();
}

uint256 ProofCodec(
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

uint256 CommitEdge(
    const RCStage3TileTreeHashEdgeCtlProof& proof)
{
    const uint256 composition =
        CommitRCStage3CtlComposition(
            proof.manifest, proof.pins);
    if (composition.IsNull() ||
        proof.producer_proof_commitment.IsNull() ||
        proof.consumer_proof_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << PROOF_DOMAIN;
    hash << TranscriptSeed(proof);
    hash << proof.producer_r0_root;
    hash << proof.consumer_r0_root;
    hash << composition;
    hash << proof.producer_proof_commitment;
    hash << proof.consumer_proof_commitment;
    return hash.GetHash();
}

Fp3 Tuple(
    uint32_t address,
    const Fp3& value,
    const Fp3& gamma)
{
    return CompressRCStage3CtlTuple(
        {EDGE_NAMESPACE, EDGE_STAGE, address, 1},
        value, gamma);
}

Fp3 TupleField(
    const Fp3& address,
    const Fp3& value,
    const Fp3& gamma)
{
    const Fp3 gamma2 = gf::Mul(gamma, gamma);
    const Fp3 gamma3 = gf::Mul(gamma2, gamma);
    return gf::Add(
        U(EDGE_NAMESPACE),
        gf::Add(
            gf::Mul(gamma, U(EDGE_STAGE)),
            gf::Add(
                gf::Mul(gamma2, address),
                gf::Mul(gamma3, value))));
}

struct ProducerLayout {
    uint32_t inverse1_base{0};
    uint32_t inverse2_base{0};
    uint32_t running1{0};
    uint32_t running2{0};
    uint32_t columns{0};
};

ProducerLayout ProducerColumns(uint32_t base)
{
    ProducerLayout out;
    out.inverse1_base = base;
    out.inverse2_base = base + 32;
    out.running1 = base + 64;
    out.running2 = base + 65;
    out.columns = base + 66;
    return out;
}

bool AppendProducer(
    uint32_t output_byte_base,
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal,
    AirCS& cs,
    std::vector<std::vector<Fp3>>* columns,
    ProducerLayout& layout,
    std::string* why)
{
    const uint32_t original = cs.n_columns;
    layout = ProducerColumns(original);
    cs.n_columns = layout.columns;
    const uint32_t n_rows = cs.n_rows;
    if (n_rows < 2) return Fail(why, "producer_rows");
    for (uint32_t byte = 0; byte < 32; ++byte) {
        for (uint32_t lane = 0; lane < 2; ++lane) {
            const uint32_t inverse =
                (lane == 0
                 ? layout.inverse1_base
                 : layout.inverse2_base) + byte;
            const Fp3 gamma =
                lane == 0
                ? challenges.gamma1 : challenges.gamma2;
            const Fp3 alpha =
                lane == 0
                ? challenges.alpha1 : challenges.alpha2;
            Add(
                cs, "stage3.tile_tree.output_byte_inverse",
                aq::AirKind::kFirstRow, 2,
                [=](const auto& cur, const auto&) {
                    return gf::Sub(
                        gf::Mul(
                            cur[inverse],
                            gf::Sub(
                                alpha,
                                Tuple(
                                    byte,
                                    cur[output_byte_base + byte],
                                    gamma))),
                        Fp3::One());
                });
            Add(
                cs, "stage3.tile_tree.output_byte_inverse_padding",
                aq::AirKind::kTransition, 1,
                [inverse](const auto&, const auto& next) {
                    return next[inverse];
                });
        }
    }
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const uint32_t inverse_base =
            lane == 0
            ? layout.inverse1_base
            : layout.inverse2_base;
        const uint32_t running =
            lane == 0 ? layout.running1 : layout.running2;
        const Fp3 expected =
            lane == 0
            ? terminal.alpha1_sum : terminal.alpha2_sum;
        Add(cs, "stage3.tile_tree.output_running_first",
            aq::AirKind::kFirstRow, 1,
            [running](const auto& cur, const auto&) {
                return cur[running];
            });
        Add(cs, "stage3.tile_tree.output_running_transition",
            aq::AirKind::kTransition, 1,
            [=](const auto& cur, const auto& next) {
                Fp3 contribution = Fp3::Zero();
                for (uint32_t byte = 0; byte < 32; ++byte) {
                    contribution = gf::Add(
                        contribution,
                        cur[inverse_base + byte]);
                }
                return gf::Sub(
                    next[running],
                    gf::Add(cur[running], contribution));
            });
        Add(cs, "stage3.tile_tree.output_running_last",
            aq::AirKind::kLastRow, 1,
            [=](const auto& cur, const auto&) {
                Fp3 contribution = Fp3::Zero();
                for (uint32_t byte = 0; byte < 32; ++byte) {
                    contribution = gf::Add(
                        contribution,
                        cur[inverse_base + byte]);
                }
                return gf::Sub(
                    gf::Add(cur[running], contribution),
                    expected);
            });
    }
    if (columns == nullptr) return true;
    columns->resize(
        layout.columns,
        std::vector<Fp3>(n_rows, Fp3::Zero()));
    Fp3 terminal1 = Fp3::Zero();
    Fp3 terminal2 = Fp3::Zero();
    for (uint32_t byte = 0; byte < 32; ++byte) {
        const Fp3 value =
            (*columns)[output_byte_base + byte][0];
        const Fp3 d1 = gf::Sub(
            challenges.alpha1,
            Tuple(byte, value, challenges.gamma1));
        const Fp3 d2 = gf::Sub(
            challenges.alpha2,
            Tuple(byte, value, challenges.gamma2));
        if (gf::IsZero(d1) || gf::IsZero(d2)) {
            return Fail(why, "producer_pole");
        }
        const Fp3 i1 = gf::Inv(d1);
        const Fp3 i2 = gf::Inv(d2);
        (*columns)[layout.inverse1_base + byte][0] = i1;
        (*columns)[layout.inverse2_base + byte][0] = i2;
        terminal1 = gf::Add(terminal1, i1);
        terminal2 = gf::Add(terminal2, i2);
    }
    for (uint32_t row = 1; row < n_rows; ++row) {
        (*columns)[layout.running1][row] = terminal1;
        (*columns)[layout.running2][row] = terminal2;
    }
    if (!gf::Eq(terminal1, terminal.alpha1_sum) ||
        !gf::Eq(terminal2, terminal.alpha2_sum)) {
        return Fail(why, "producer_terminal");
    }
    return true;
}

struct ConsumerLayout {
    uint32_t mask_base{0};
    uint32_t inverse1_base{0};
    uint32_t inverse2_base{0};
    uint32_t running1{0};
    uint32_t running2{0};
    uint32_t columns{0};
};

ConsumerLayout ConsumerColumns(uint32_t base)
{
    ConsumerLayout out;
    out.mask_base = base;
    out.inverse1_base = base + 4;
    out.inverse2_base = base + 8;
    out.running1 = base + 12;
    out.running2 = base + 13;
    out.columns = base + 14;
    return out;
}

bool BuildConsumerMasks(
    const ha::FixedProgram& program,
    uint32_t n_rows,
    uint32_t first_pass_blocks,
    uint32_t preimage_offset,
    std::array<std::vector<Fp3>, 4>& masks,
    std::array<std::vector<uint32_t>, 4>& addresses,
    std::string* why)
{
    for (auto& lane : masks) {
        lane.assign(n_rows, Fp3::Zero());
    }
    for (auto& lane : addresses) {
        lane.assign(n_rows, UINT32_MAX);
    }
    const auto rows = FirstMessageRows(program);
    if (std::any_of(
            rows.begin(), rows.end(),
            [](uint32_t row) { return row == UINT32_MAX; })) {
        return Fail(why, "consumer_message_rows");
    }
    uint32_t count = 0;
    for (uint32_t instance = 0;
         instance < first_pass_blocks; ++instance) {
        for (uint32_t word = 0; word < 16; ++word) {
            const uint32_t row =
                instance * LANE_ROWS + rows[word];
            if (row >= n_rows) {
                return Fail(why, "consumer_row_range");
            }
            for (uint32_t lane = 0; lane < 4; ++lane) {
                const uint32_t offset =
                    instance * 64 + word * 4 + lane;
                if (offset >= preimage_offset &&
                    offset < preimage_offset + 32) {
                    masks[lane][row] = Fp3::One();
                    addresses[lane][row] =
                        offset - preimage_offset;
                    ++count;
                }
            }
        }
    }
    return count == 32 ||
        Fail(why, "consumer_byte_coverage");
}

bool AppendConsumer(
    const ha::FixedProgram& program,
    uint32_t first_pass_blocks,
    uint32_t preimage_offset,
    uint32_t input_byte_base,
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal,
    AirCS& cs,
    std::vector<std::vector<Fp3>>* columns,
    ConsumerLayout& layout,
    std::string* why)
{
    const uint32_t original = cs.n_columns;
    layout = ConsumerColumns(original);
    std::array<std::vector<Fp3>, 4> masks;
    std::array<std::vector<uint32_t>, 4> addresses;
    if (!BuildConsumerMasks(
            program, cs.n_rows, first_pass_blocks,
            preimage_offset, masks, addresses, why)) {
        return false;
    }
    cs.n_columns = layout.columns;
    for (uint32_t byte_lane = 0;
         byte_lane < 4; ++byte_lane) {
        cs.preprocessed.emplace_back(
            layout.mask_base + byte_lane,
            masks[byte_lane]);
        for (uint32_t ctl_lane = 0;
             ctl_lane < 2; ++ctl_lane) {
            const uint32_t inverse =
                (ctl_lane == 0
                 ? layout.inverse1_base
                 : layout.inverse2_base) + byte_lane;
            Add(
                cs, "stage3.tile_tree.input_byte_inverse",
                aq::AirKind::kEverywhere, 2,
                [=](const auto& cur, const auto&) {
                    const Fp3 mask =
                        cur[layout.mask_base + byte_lane];
                    return gf::Mul(
                        gf::Sub(Fp3::One(), mask),
                        cur[inverse]);
                });
        }
    }
    // The sparse semantic address needs one preprocessed column per byte
    // lane because the four bytes on one SHA message row are simultaneous.
    const uint32_t address_base = cs.n_columns;
    cs.n_columns += 4;
    for (uint32_t lane = 0; lane < 4; ++lane) {
        std::vector<Fp3> field(
            cs.n_rows, Fp3::Zero());
        for (uint32_t row = 0; row < cs.n_rows; ++row) {
            if (addresses[lane][row] != UINT32_MAX) {
                field[row] = U(addresses[lane][row]);
            }
        }
        cs.preprocessed.emplace_back(
            address_base + lane, field);
        for (uint32_t ctl_lane = 0;
             ctl_lane < 2; ++ctl_lane) {
            const uint32_t inverse =
                (ctl_lane == 0
                 ? layout.inverse1_base
                 : layout.inverse2_base) + lane;
            const Fp3 gamma =
                ctl_lane == 0
                ? challenges.gamma1 : challenges.gamma2;
            const Fp3 alpha =
                ctl_lane == 0
                ? challenges.alpha1 : challenges.alpha2;
            Add(
                cs, "stage3.tile_tree.input_byte_active_inverse",
                aq::AirKind::kEverywhere, 2,
                [=](const auto& cur, const auto&) {
                    const Fp3 mask =
                        cur[layout.mask_base + lane];
                    return gf::Sub(
                        gf::Mul(
                            cur[inverse],
                            gf::Sub(
                                alpha,
                                TupleField(
                                    cur[address_base + lane],
                                    cur[input_byte_base + lane],
                                    gamma))),
                        mask);
                });
        }
    }
    layout.columns = cs.n_columns;
    for (uint32_t ctl_lane = 0;
         ctl_lane < 2; ++ctl_lane) {
        const uint32_t inverse_base =
            ctl_lane == 0
            ? layout.inverse1_base : layout.inverse2_base;
        const uint32_t running =
            ctl_lane == 0 ? layout.running1 : layout.running2;
        const Fp3 expected =
            ctl_lane == 0
            ? terminal.alpha1_sum : terminal.alpha2_sum;
        Add(cs, "stage3.tile_tree.input_running_first",
            aq::AirKind::kFirstRow, 1,
            [running](const auto& cur, const auto&) {
                return cur[running];
            });
        Add(cs, "stage3.tile_tree.input_running_transition",
            aq::AirKind::kTransition, 1,
            [=](const auto& cur, const auto& next) {
                Fp3 contribution = Fp3::Zero();
                for (uint32_t lane = 0; lane < 4; ++lane) {
                    contribution = gf::Sub(
                        contribution,
                        cur[inverse_base + lane]);
                }
                return gf::Sub(
                    next[running],
                    gf::Add(cur[running], contribution));
            });
        Add(cs, "stage3.tile_tree.input_running_last",
            aq::AirKind::kLastRow, 1,
            [=](const auto& cur, const auto&) {
                Fp3 contribution = Fp3::Zero();
                for (uint32_t lane = 0; lane < 4; ++lane) {
                    contribution = gf::Sub(
                        contribution,
                        cur[inverse_base + lane]);
                }
                return gf::Sub(
                    gf::Add(cur[running], contribution),
                    expected);
            });
    }
    if (columns == nullptr) return true;
    columns->resize(
        cs.n_columns,
        std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    for (uint32_t lane = 0; lane < 4; ++lane) {
        (*columns)[layout.mask_base + lane] = masks[lane];
        for (uint32_t row = 0; row < cs.n_rows; ++row) {
            if (addresses[lane][row] != UINT32_MAX) {
                (*columns)[address_base + lane][row] =
                    U(addresses[lane][row]);
            }
        }
    }
    Fp3 running1 = Fp3::Zero();
    Fp3 running2 = Fp3::Zero();
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        (*columns)[layout.running1][row] = running1;
        (*columns)[layout.running2][row] = running2;
        for (uint32_t lane = 0; lane < 4; ++lane) {
            if (addresses[lane][row] == UINT32_MAX) continue;
            const uint32_t address = addresses[lane][row];
            const Fp3 value =
                (*columns)[input_byte_base + lane][row];
            const Fp3 d1 = gf::Sub(
                challenges.alpha1,
                Tuple(address, value, challenges.gamma1));
            const Fp3 d2 = gf::Sub(
                challenges.alpha2,
                Tuple(address, value, challenges.gamma2));
            if (gf::IsZero(d1) || gf::IsZero(d2)) {
                return Fail(why, "consumer_pole");
            }
            const Fp3 i1 = gf::Inv(d1);
            const Fp3 i2 = gf::Inv(d2);
            (*columns)[layout.inverse1_base + lane][row] = i1;
            (*columns)[layout.inverse2_base + lane][row] = i2;
            running1 = gf::Sub(running1, i1);
            running2 = gf::Sub(running2, i2);
        }
    }
    if (!gf::Eq(running1, terminal.alpha1_sum) ||
        !gf::Eq(running2, terminal.alpha2_sum)) {
        return Fail(why, "consumer_terminal");
    }
    return true;
}

struct RootConsumerLayout {
    uint32_t inverse1{0};
    uint32_t inverse2{0};
    uint32_t running1{0};
    uint32_t running2{0};
    uint32_t columns{0};
};

bool AppendRootConsumer(
    uint32_t byte_column,
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal,
    AirCS& cs,
    std::vector<std::vector<Fp3>>* columns,
    RootConsumerLayout& layout,
    std::string* why)
{
    if (cs.n_rows != 32 ||
        byte_column >= cs.n_columns) {
        return Fail(why, "root_consumer_shape");
    }
    layout.inverse1 = cs.n_columns;
    layout.inverse2 = cs.n_columns + 1;
    layout.running1 = cs.n_columns + 2;
    layout.running2 = cs.n_columns + 3;
    layout.columns = cs.n_columns + 4;
    cs.n_columns = layout.columns;
    for (uint32_t ctl_lane = 0;
         ctl_lane < 2; ++ctl_lane) {
        const uint32_t inverse =
            ctl_lane == 0
            ? layout.inverse1 : layout.inverse2;
        const uint32_t running =
            ctl_lane == 0
            ? layout.running1 : layout.running2;
        const Fp3 gamma =
            ctl_lane == 0
            ? challenges.gamma1 : challenges.gamma2;
        const Fp3 alpha =
            ctl_lane == 0
            ? challenges.alpha1 : challenges.alpha2;
        const Fp3 expected =
            ctl_lane == 0
            ? terminal.alpha1_sum : terminal.alpha2_sum;
        Add(
            cs, "stage3.tile_tree.root_byte_inverse",
            aq::AirKind::kEverywhere, 2,
            [=](const auto& cur, const auto&) {
                return gf::Sub(
                    gf::Mul(
                        cur[inverse],
                        gf::Sub(
                            alpha,
                            TupleField(
                                cur[
                                    kRCStage3EpisodeTileBridgeAddress],
                                cur[byte_column],
                                gamma))),
                    Fp3::One());
            });
        Add(
            cs, "stage3.tile_tree.root_running_first",
            aq::AirKind::kFirstRow, 1,
            [running](const auto& cur, const auto&) {
                return cur[running];
            });
        Add(
            cs, "stage3.tile_tree.root_running_transition",
            aq::AirKind::kTransition, 1,
            [=](const auto& cur, const auto& next) {
                return gf::Sub(
                    next[running],
                    gf::Sub(cur[running], cur[inverse]));
            });
        Add(
            cs, "stage3.tile_tree.root_running_last",
            aq::AirKind::kLastRow, 1,
            [=](const auto& cur, const auto&) {
                return gf::Sub(
                    gf::Sub(cur[running], cur[inverse]),
                    expected);
            });
    }
    if (columns == nullptr) return true;
    columns->resize(
        cs.n_columns,
        std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    Fp3 running1 = Fp3::Zero();
    Fp3 running2 = Fp3::Zero();
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        (*columns)[layout.running1][row] = running1;
        (*columns)[layout.running2][row] = running2;
        const Fp3 value = (*columns)[byte_column][row];
        const Fp3 d1 = gf::Sub(
            challenges.alpha1,
            Tuple(row, value, challenges.gamma1));
        const Fp3 d2 = gf::Sub(
            challenges.alpha2,
            Tuple(row, value, challenges.gamma2));
        if (gf::IsZero(d1) || gf::IsZero(d2)) {
            return Fail(why, "root_consumer_pole");
        }
        const Fp3 i1 = gf::Inv(d1);
        const Fp3 i2 = gf::Inv(d2);
        (*columns)[layout.inverse1][row] = i1;
        (*columns)[layout.inverse2][row] = i2;
        running1 = gf::Sub(running1, i1);
        running2 = gf::Sub(running2, i2);
    }
    if (!gf::Eq(running1, terminal.alpha1_sum) ||
        !gf::Eq(running2, terminal.alpha2_sum)) {
        return Fail(why, "root_consumer_terminal");
    }
    return true;
}

RCStage3CtlTerminal TerminalForDigest(
    const std::array<uint8_t, 32>& digest,
    const RCStage3CtlChallenges& challenges,
    bool sends,
    std::string* why)
{
    RCStage3CtlTerminal out;
    for (uint32_t byte = 0; byte < 32; ++byte) {
        const Fp3 value = U(digest[byte]);
        const Fp3 d1 = gf::Sub(
            challenges.alpha1,
            Tuple(byte, value, challenges.gamma1));
        const Fp3 d2 = gf::Sub(
            challenges.alpha2,
            Tuple(byte, value, challenges.gamma2));
        if (gf::IsZero(d1) || gf::IsZero(d2)) {
            Fail(why, "terminal_pole");
            return {};
        }
        const Fp3 i1 = gf::Inv(d1);
        const Fp3 i2 = gf::Inv(d2);
        out.alpha1_sum = sends
            ? gf::Add(out.alpha1_sum, i1)
            : gf::Sub(out.alpha1_sum, i1);
        out.alpha2_sum = sends
            ? gf::Add(out.alpha2_sum, i2)
            : gf::Sub(out.alpha2_sum, i2);
    }
    return out;
}

struct EdgeSpec {
    uint32_t producer{0};
    uint32_t consumer{0};
    uint32_t offset{0};
    RCStage3RelationEndpoint producer_endpoint{};
    bool root_sink{false};
};

bool BuildEdgeSpecs(
    const ha::TileTreeManifest& tree,
    std::vector<EdgeSpec>& out,
    std::string* why)
{
    out.clear();
    const auto find_internal =
        [&tree](uint32_t level, uint64_t index)
            -> std::optional<uint32_t> {
            for (uint32_t ordinal = 0;
                 ordinal < tree.hash_nodes.size(); ++ordinal) {
                const auto& node = tree.hash_nodes[ordinal];
                if (node.kind ==
                        ha::TileTreeNodeKind::Internal &&
                    node.level == level &&
                    node.index == index) {
                    return ordinal;
                }
            }
            return std::nullopt;
        };
    const auto leaf_ordinal =
        [&tree](uint64_t index)
            -> std::optional<uint32_t> {
            if (index < tree.logical_leaf_count) {
                if (index >= tree.hash_nodes.size() ||
                    tree.hash_nodes[index].kind !=
                        ha::TileTreeNodeKind::Leaf) {
                    return std::nullopt;
                }
                return static_cast<uint32_t>(index);
            }
            for (uint32_t ordinal = 0;
                 ordinal < tree.hash_nodes.size(); ++ordinal) {
                if (tree.hash_nodes[ordinal].kind ==
                        ha::TileTreeNodeKind::PadLeaf) {
                    return ordinal;
                }
            }
            return std::nullopt;
        };
    for (uint32_t consumer = 0;
         consumer < tree.hash_nodes.size(); ++consumer) {
        const auto& node = tree.hash_nodes[consumer];
        if (node.kind !=
            ha::TileTreeNodeKind::Internal) {
            continue;
        }
        for (uint32_t side = 0; side < 2; ++side) {
            const uint64_t child =
                2 * node.index + side;
            const auto producer =
                node.level == 1
                ? leaf_ordinal(child)
                : find_internal(node.level - 1, child);
            if (!producer.has_value()) {
                return Fail(why, "edge_source_inventory");
            }
            out.push_back({
                *producer,
                consumer,
                side == 0 ? 1U : 33U,
                node.level == 1
                    ? RCStage3RelationEndpoint::
                          EpisodeTileTreeLeafHash
                    : RCStage3RelationEndpoint::
                          EpisodeTileTreeInternalHash,
                false,
            });
        }
    }
    std::optional<uint32_t> root_producer;
    for (uint32_t ordinal = 0;
         ordinal < tree.hash_nodes.size(); ++ordinal) {
        const auto& node = tree.hash_nodes[ordinal];
        if (node.digest == tree.root &&
            (node.kind ==
                 ha::TileTreeNodeKind::Internal ||
             tree.padded_leaf_count == 1)) {
            root_producer = ordinal;
        }
    }
    if (!root_producer.has_value()) {
        return Fail(why, "edge_root_source");
    }
    out.push_back({
        *root_producer,
        UINT32_MAX,
        0,
        tree.padded_leaf_count == 1
            ? RCStage3RelationEndpoint::
                  EpisodeTileTreeLeafHash
            : RCStage3RelationEndpoint::
                  EpisodeTileTreeInternalHash,
        true,
    });
    return true;
}

bool FillPublicIdentity(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    uint32_t round_index,
    const EdgeSpec& spec,
    RCStage3TileTreeHashEdgeCtlProof& out,
    NodeShape& producer_shape,
    NodeShape& consumer_shape,
    std::string* why)
{
    out = {};
    if (round_index >= tile_stream.rounds.size()) {
        return Fail(why, "edge_round");
    }
    const auto& tree =
        tile_stream.rounds[round_index]
            .tree.tree_manifest;
    if (spec.producer >= tree.hash_nodes.size() ||
        (!spec.root_sink &&
         (spec.consumer >= tree.hash_nodes.size() ||
          spec.offset + 32 >
              tree.hash_nodes[spec.consumer]
                  .sha256d.preimage.size()))) {
        return Fail(why, "edge_spec_range");
    }
    out.round_index = round_index;
    out.producer_node_ordinal = spec.producer;
    out.consumer_node_ordinal = spec.consumer;
    out.consumer_preimage_offset = spec.offset;
    out.producer_endpoint = spec.producer_endpoint;
    out.consumer_endpoint = spec.root_sink
        ? RCStage3RelationEndpoint::
              EpisodeTileTreeRoot
        : RCStage3RelationEndpoint::
              EpisodeTileTreeInternalHash;
    out.statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    out.tree_manifest_commitment = tree.commitment;
    if (!BuildNodeShape(
            out.statement_commitment, tree.commitment,
            round_index, spec.producer,
            tree.hash_nodes[spec.producer],
            producer_shape, why)) {
        return false;
    }
    if (!spec.root_sink &&
        !BuildNodeShape(
            out.statement_commitment, tree.commitment,
            round_index, spec.consumer,
            tree.hash_nodes[spec.consumer],
            consumer_shape, why)) {
        return false;
    }
    out.producer_public_statement =
        producer_shape.public_statement;
    if (spec.root_sink) {
        RootByteShape root_shape;
        if (!BuildRootByteShape(
                out.statement_commitment, tree.commitment,
                round_index, tree.root, false,
                root_shape, why)) {
            return false;
        }
        out.consumer_public_statement =
            root_shape.public_statement;
    } else {
        out.consumer_public_statement =
            consumer_shape.public_statement;
    }
    return true;
}

bool ProveEdge(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    uint32_t round_index,
    const EdgeSpec& spec,
    RCStage3TileTreeHashEdgeCtlProof& out,
    std::string* why)
{
    NodeShape producer_shape;
    NodeShape consumer_shape;
    if (!FillPublicIdentity(
            statement, tile_stream, round_index, spec,
            out, producer_shape, consumer_shape, why)) {
        return false;
    }
    const auto program = ha::BuildCanonicalProgram(
        ha::ProgramKind::Sha256Compression);
    auto producer =
        ha::BuildFixedProgramVerticalWitnessBoundaryInstance(
            program, producer_shape.boundaries,
            producer_shape.public_masks,
            producer_shape.links, producer_shape.seed);
    if (!producer.valid) {
        return Fail(
            why, "edge_sha_producer:" +
                producer.note);
    }
    AirCS consumer_cs;
    std::vector<std::vector<Fp3>> consumer_columns;
    std::vector<uint32_t> consumer_base_indices;
    uint32_t consumer_input_byte_base{0};
    if (spec.root_sink) {
        RootByteShape root_shape;
        const auto& tree =
            tile_stream.rounds[round_index]
                .tree.tree_manifest;
        if (!BuildRootByteShape(
                out.statement_commitment, tree.commitment,
                round_index, tree.root, true,
                root_shape, why)) {
            return false;
        }
        consumer_cs = std::move(root_shape.cs);
        consumer_columns =
            std::move(root_shape.columns);
        consumer_base_indices =
            std::move(root_shape.base_column_indices);
    } else {
        auto consumer =
            ha::BuildFixedProgramVerticalWitnessBoundaryInstance(
                program, consumer_shape.boundaries,
                consumer_shape.public_masks,
                consumer_shape.links, consumer_shape.seed);
        if (!consumer.valid) {
            return Fail(
                why, "edge_sha_consumer:" +
                    consumer.note);
        }
        consumer_cs = std::move(consumer.cs);
        consumer_columns =
            std::move(consumer.columns);
        consumer_base_indices =
            std::move(consumer.base_column_indices);
        consumer_input_byte_base =
            consumer.input_byte_base;
    }
    out.producer_r0_root =
        producer.base_row_commitment;
    const auto consumer_r0_initial =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            consumer_cs, consumer_columns,
            consumer_base_indices);
    if (!consumer_r0_initial.valid) {
        return Fail(why, "edge_consumer_r0_initial");
    }
    out.consumer_r0_root =
        consumer_r0_initial.base_row_commitment;
    out.manifest.bus_id =
        kRCStage3TileTreeHashCtlBusId;
    out.manifest.transcript_seed =
        TranscriptSeed(out);
    const auto sends = EdgeSchedule(1);
    const auto receives = EdgeSchedule(-1);
    out.manifest.participants = {
        Participant(
            RCStage3RelationRole::EpisodeTileTree,
            sends, true),
        Participant(
            RCStage3RelationRole::CompositionLink,
            receives, false),
    };
    out.pins.resize(2);
    for (size_t i = 0; i < 2; ++i) {
        const auto& participant =
            out.manifest.participants[i];
        auto& pin = out.pins[i];
        pin.role = participant.role;
        pin.bus_id = out.manifest.bus_id;
        pin.event_count = participant.event_count;
        pin.send_count = participant.send_count;
        pin.receive_count = participant.receive_count;
        pin.schedule_commitment =
            participant.schedule_commitment;
    }
    out.pins[0].trace_commitment =
        out.producer_r0_root;
    out.pins[1].trace_commitment =
        out.consumer_r0_root;
    RCStage3CtlChallenges challenges;
    if (!DeriveRCStage3CtlChallenges(
            out.manifest, out.pins,
            challenges, why)) {
        return false;
    }
    const auto& producer_node =
        tile_stream.rounds[round_index]
            .tree.tree_manifest
            .hash_nodes[spec.producer];
    out.pins[0].terminal =
        TerminalForDigest(
            producer_node.sha256d.digest,
            challenges, true, why);
    out.pins[1].terminal =
        TerminalForDigest(
            producer_node.sha256d.digest,
            challenges, false, why);
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);
    for (auto& pin : out.pins) {
        pin.challenge_commitment =
            challenge_commitment;
    }
    ProducerLayout producer_layout;
    ConsumerLayout consumer_layout;
    RootConsumerLayout root_consumer_layout;
    if (!AppendProducer(
            producer.output_byte_base,
            challenges, out.pins[0].terminal,
            producer.cs, &producer.columns,
            producer_layout, why)) {
        return false;
    }
    if (spec.root_sink
            ? !AppendRootConsumer(
                  kRCStage3EpisodeTileBridgeByte,
                  challenges, out.pins[1].terminal,
                  consumer_cs, &consumer_columns,
                  root_consumer_layout, why)
            : !AppendConsumer(
                  program,
                  tile_stream.rounds[round_index]
                      .tree.tree_manifest
                      .hash_nodes[spec.consumer]
                      .sha256d.first.padded_blocks.size(),
                  spec.offset,
                  consumer_input_byte_base,
                  challenges, out.pins[1].terminal,
                  consumer_cs, &consumer_columns,
                  consumer_layout, why)) {
        return false;
    }
    const auto producer_r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            producer.cs, producer.columns,
            producer.base_column_indices);
    const auto consumer_r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            consumer_cs, consumer_columns,
            consumer_base_indices);
    if (!producer_r0.valid || !consumer_r0.valid ||
        producer_r0.base_row_commitment !=
            out.producer_r0_root ||
        consumer_r0.base_row_commitment !=
            out.consumer_r0_root) {
        return Fail(why, "edge_r0_reuse");
    }
    const auto producer_proved =
        aq::AirQuotientProveRowsSplitRap(
            producer.cs, producer.columns,
            producer.base_column_indices,
            ChildSeed("producer", out), {},
            &producer_r0);
    const auto consumer_proved =
        aq::AirQuotientProveRowsSplitRap(
            consumer_cs, consumer_columns,
            consumer_base_indices,
            ChildSeed("consumer", out), {},
            &consumer_r0);
    if (!producer_proved.ok ||
        !producer_proved.division_exact ||
        !consumer_proved.ok ||
        !consumer_proved.division_exact) {
        return Fail(
            why, "edge_prove:" +
                producer_proved.note + ";" +
                consumer_proved.note);
    }
    out.producer_proof = producer_proved.proof;
    out.consumer_proof = consumer_proved.proof;
    out.producer_proof_commitment =
        ProofCodec(
            "BTX_RC_STAGE3_TILE_TREE_EDGE_PRODUCER_CODEC_V1",
            out.producer_proof);
    out.consumer_proof_commitment =
        ProofCodec(
            "BTX_RC_STAGE3_TILE_TREE_EDGE_CONSUMER_CODEC_V1",
            out.consumer_proof);
    out.pins[0].auxiliary_commitment =
        out.producer_proof_commitment;
    out.pins[1].auxiliary_commitment =
        out.consumer_proof_commitment;
    if (!VerifyRCStage3CtlPublicPinComposition(
            out.manifest, out.pins, why)) {
        return false;
    }
    out.proof_commitment = CommitEdge(out);
    return !out.proof_commitment.IsNull() ||
        Fail(why, "edge_commitment");
}

bool VerifyEdge(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    uint32_t round_index,
    const EdgeSpec& spec,
    const RCStage3TileTreeHashEdgeCtlProof& proof,
    std::string* why)
{
    RCStage3TileTreeHashEdgeCtlProof expected;
    NodeShape producer_shape;
    NodeShape consumer_shape;
    if (!FillPublicIdentity(
            statement, tile_stream, round_index, spec,
            expected, producer_shape, consumer_shape, why) ||
        proof.version != expected.version ||
        proof.round_index != expected.round_index ||
        proof.producer_node_ordinal !=
            expected.producer_node_ordinal ||
        proof.consumer_node_ordinal !=
            expected.consumer_node_ordinal ||
        proof.consumer_preimage_offset !=
            expected.consumer_preimage_offset ||
        proof.producer_endpoint !=
            expected.producer_endpoint ||
        proof.consumer_endpoint !=
            expected.consumer_endpoint ||
        proof.statement_commitment !=
            expected.statement_commitment ||
        proof.tree_manifest_commitment !=
            expected.tree_manifest_commitment ||
        proof.producer_public_statement !=
            expected.producer_public_statement ||
        proof.consumer_public_statement !=
            expected.consumer_public_statement ||
        proof.pins.size() != 2) {
        return Fail(why, "edge_identity");
    }
    expected.producer_r0_root =
        proof.producer_r0_root;
    expected.consumer_r0_root =
        proof.consumer_r0_root;
    expected.manifest.bus_id =
        kRCStage3TileTreeHashCtlBusId;
    expected.manifest.transcript_seed =
        TranscriptSeed(expected);
    const auto sends = EdgeSchedule(1);
    const auto receives = EdgeSchedule(-1);
    expected.manifest.participants = {
        Participant(
            RCStage3RelationRole::EpisodeTileTree,
            sends, true),
        Participant(
            RCStage3RelationRole::CompositionLink,
            receives, false),
    };
    if (proof.manifest != expected.manifest) {
        return Fail(why, "edge_manifest");
    }
    for (size_t i = 0; i < 2; ++i) {
        const auto& participant =
            expected.manifest.participants[i];
        const auto& pin = proof.pins[i];
        if (pin.role != participant.role ||
            pin.bus_id != expected.manifest.bus_id ||
            pin.event_count != participant.event_count ||
            pin.send_count != participant.send_count ||
            pin.receive_count != participant.receive_count ||
            pin.schedule_commitment !=
                participant.schedule_commitment ||
            pin.trace_commitment !=
                (i == 0
                     ? proof.producer_r0_root
                     : proof.consumer_r0_root)) {
            return Fail(why, "edge_pin");
        }
    }
    RCStage3CtlChallenges challenges;
    if (!DeriveRCStage3CtlChallenges(
            proof.manifest, proof.pins,
            challenges, why)) {
        return false;
    }
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);
    const auto& producer_node =
        tile_stream.rounds[round_index]
            .tree.tree_manifest
            .hash_nodes[spec.producer];
    const auto send_terminal =
        TerminalForDigest(
            producer_node.sha256d.digest,
            challenges, true, why);
    const auto receive_terminal =
        TerminalForDigest(
            producer_node.sha256d.digest,
            challenges, false, why);
    if (proof.pins[0].challenge_commitment !=
            challenge_commitment ||
        proof.pins[1].challenge_commitment !=
            challenge_commitment ||
        !(proof.pins[0].terminal == send_terminal) ||
        !(proof.pins[1].terminal == receive_terminal)) {
        return Fail(why, "edge_challenge_or_terminal");
    }
    const auto program = ha::BuildCanonicalProgram(
        ha::ProgramKind::Sha256Compression);
    auto producer =
        ha::BuildFixedProgramVerticalWitnessBoundaryVerifierInstance(
            program, producer_shape.boundaries,
            producer_shape.public_masks,
            producer_shape.links, producer_shape.seed,
            proof.producer_r0_root);
    if (!producer.valid ||
        producer.public_statement !=
            proof.producer_public_statement) {
        return Fail(why, "edge_verifier_producer_sha");
    }
    AirCS consumer_cs;
    std::vector<uint32_t> consumer_base_indices;
    uint32_t consumer_input_byte_base{0};
    if (spec.root_sink) {
        RootByteShape root_shape;
        const auto& tree =
            tile_stream.rounds[round_index]
                .tree.tree_manifest;
        if (!BuildRootByteShape(
                expected.statement_commitment,
                tree.commitment, round_index,
                tree.root, false, root_shape, why) ||
            root_shape.public_statement !=
                proof.consumer_public_statement) {
            return Fail(why, "edge_verifier_root_bytes");
        }
        consumer_cs = std::move(root_shape.cs);
        consumer_base_indices =
            std::move(root_shape.base_column_indices);
    } else {
        auto consumer =
            ha::BuildFixedProgramVerticalWitnessBoundaryVerifierInstance(
                program, consumer_shape.boundaries,
                consumer_shape.public_masks,
                consumer_shape.links, consumer_shape.seed,
                proof.consumer_r0_root);
        if (!consumer.valid ||
            consumer.public_statement !=
                proof.consumer_public_statement) {
            return Fail(why, "edge_verifier_consumer_sha");
        }
        consumer_cs = std::move(consumer.cs);
        consumer_base_indices =
            std::move(consumer.base_column_indices);
        consumer_input_byte_base =
            consumer.input_byte_base;
    }
    ProducerLayout producer_layout;
    ConsumerLayout consumer_layout;
    RootConsumerLayout root_consumer_layout;
    if (!AppendProducer(
            producer.output_byte_base,
            challenges, proof.pins[0].terminal,
            producer.cs, nullptr,
            producer_layout, why)) {
        return Fail(why, "edge_verifier_producer_cs");
    }
    if (spec.root_sink
            ? !AppendRootConsumer(
                  kRCStage3EpisodeTileBridgeByte,
                  challenges, proof.pins[1].terminal,
                  consumer_cs, nullptr,
                  root_consumer_layout, why)
            : !AppendConsumer(
                  program,
                  tile_stream.rounds[round_index]
                      .tree.tree_manifest
                      .hash_nodes[spec.consumer]
                      .sha256d.first.padded_blocks.size(),
                  spec.offset,
                  consumer_input_byte_base,
                  challenges, proof.pins[1].terminal,
                  consumer_cs, nullptr,
                  consumer_layout, why)) {
        return Fail(why, "edge_verifier_consumer_cs");
    }
    if (proof.producer_proof.base_column_indices !=
            producer.base_column_indices ||
        proof.consumer_proof.base_column_indices !=
            consumer_base_indices ||
        proof.producer_proof.batch.groups.size() != 3 ||
        proof.consumer_proof.batch.groups.size() != 3 ||
        Fri3AlgDigestToUint256(
            proof.producer_proof.batch
                .groups[0].row_commit.root) !=
            proof.producer_r0_root ||
        Fri3AlgDigestToUint256(
            proof.consumer_proof.batch
                .groups[0].row_commit.root) !=
            proof.consumer_r0_root) {
        return Fail(why, "edge_verifier_cs");
    }
    expected.manifest = proof.manifest;
    expected.pins = proof.pins;
    if (!aq::AirQuotientVerifyRowsSplitRap(
            producer.cs, proof.producer_proof,
            producer.base_column_indices,
            ChildSeed("producer", expected), why) ||
        !aq::AirQuotientVerifyRowsSplitRap(
            consumer_cs, proof.consumer_proof,
            consumer_base_indices,
            ChildSeed("consumer", expected), why)) {
        return Fail(why, "edge_quotient");
    }
    const uint256 producer_codec =
        ProofCodec(
            "BTX_RC_STAGE3_TILE_TREE_EDGE_PRODUCER_CODEC_V1",
            proof.producer_proof);
    const uint256 consumer_codec =
        ProofCodec(
            "BTX_RC_STAGE3_TILE_TREE_EDGE_CONSUMER_CODEC_V1",
            proof.consumer_proof);
    if (producer_codec.IsNull() ||
        consumer_codec.IsNull() ||
        proof.producer_proof_commitment !=
            producer_codec ||
        proof.consumer_proof_commitment !=
            consumer_codec ||
        proof.pins[0].auxiliary_commitment !=
            producer_codec ||
        proof.pins[1].auxiliary_commitment !=
            consumer_codec ||
        proof.proof_commitment != CommitEdge(proof) ||
        !VerifyRCStage3CtlPublicPinComposition(
            proof.manifest, proof.pins, why)) {
        return Fail(why, "edge_commitment");
    }
    return true;
}

} // namespace

static_assert(EDGE_NAMESPACE == kRCStage3TileTreeCtlEdgeNamespace);
static_assert(EDGE_STAGE == kRCStage3TileTreeCtlEdgeStage);

aq::AirConstraintSystem<Fp3>
BuildRCStage3TileTreeProducerConstraintSystem(
    uint32_t output_byte_base,
    uint32_t n_rows,
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal)
{
    AirCS cs;
    cs.n_rows = n_rows;
    cs.n_columns = output_byte_base + 32;
    ProducerLayout layout;
    if (!AppendProducer(
            output_byte_base, challenges, terminal, cs,
            /*columns=*/nullptr, layout, nullptr)) {
        return AirCS{};
    }
    return cs;
}

bool ProveRCStage3TileTreeHashCtl(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    RCStage3TileTreeHashCtlProof& out,
    std::string* why)
{
    out = {};
    if (!VerifyRCStage3EpisodeTileStreamProduct(
            statement, manifest, tile_stream, why)) {
        return Fail(why, "prove_source_product");
    }
    out.statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    out.tile_stream_collection_commitment =
        tile_stream.collection_commitment;
    for (uint32_t round = 0;
         round < tile_stream.rounds.size(); ++round) {
        std::vector<EdgeSpec> specs;
        if (!BuildEdgeSpecs(
                tile_stream.rounds[round]
                    .tree.tree_manifest,
                specs, why)) {
            return false;
        }
        for (const auto& spec : specs) {
            RCStage3TileTreeHashEdgeCtlProof edge;
            if (!ProveEdge(
                    statement, tile_stream,
                    round, spec, edge, why)) {
                return false;
            }
            out.edges.push_back(std::move(edge));
        }
    }
    if (out.edges.empty()) {
        return Fail(why, "prove_empty");
    }
    HashWriter hash;
    hash << COLLECTION_DOMAIN;
    hash << out.version;
    hash << out.statement_commitment;
    hash << out.tile_stream_collection_commitment;
    hash << static_cast<uint32_t>(out.edges.size());
    for (const auto& edge : out.edges) {
        hash << edge.proof_commitment;
    }
    out.collection_commitment = hash.GetHash();
    return !out.collection_commitment.IsNull();
}

bool VerifyRCStage3TileTreeHashCtl(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    const RCStage3TileTreeHashCtlProof& proof,
    std::string* why)
{
    if (proof.version !=
            kRCStage3TileTreeHashCtlVersion ||
        proof.statement_commitment !=
            RCStage3EpisodeStatementCommitment(statement) ||
        proof.tile_stream_collection_commitment !=
            tile_stream.collection_commitment ||
        !VerifyRCStage3EpisodeTileStreamProduct(
            statement, manifest, tile_stream, why)) {
        return Fail(why, "verify_source_product");
    }
    size_t edge_index = 0;
    for (uint32_t round = 0;
         round < tile_stream.rounds.size(); ++round) {
        std::vector<EdgeSpec> specs;
        if (!BuildEdgeSpecs(
                tile_stream.rounds[round]
                    .tree.tree_manifest,
                specs, why)) {
            return false;
        }
        for (const auto& spec : specs) {
            if (edge_index >= proof.edges.size() ||
                !VerifyEdge(
                    statement, tile_stream, round,
                    spec, proof.edges[edge_index++], why)) {
                return false;
            }
        }
    }
    if (edge_index != proof.edges.size()) {
        return Fail(why, "verify_trailing_edge");
    }
    HashWriter hash;
    hash << COLLECTION_DOMAIN;
    hash << proof.version;
    hash << proof.statement_commitment;
    hash << proof.tile_stream_collection_commitment;
    hash << static_cast<uint32_t>(proof.edges.size());
    for (const auto& edge : proof.edges) {
        hash << edge.proof_commitment;
    }
    if (proof.collection_commitment !=
            hash.GetHash()) {
        return Fail(why, "verify_collection");
    }
    return true;
}

} // namespace matmul::v4::rc
