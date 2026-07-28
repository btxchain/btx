// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_relation_product.h>

#include <hash.h>

#include <algorithm>
#include <functional>
#include <limits>
#include <numeric>

namespace matmul::v4::rc {
namespace {

using Fp3 = gkr_field::Fp3;

constexpr char VECTOR_ROOT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_WIRING_VECTOR_ROOT_V1";
constexpr char EDGE_PRODUCT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_WIRING_EDGE_PRODUCT_V1";
constexpr char CLOSURE_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_WIRING_CLOSURE_V1";
constexpr char PRODUCER_SCHEDULE_DOMAIN[] =
    "BTX_RC_STAGE3_PRODUCER_BUS_SCHEDULE_V1";
constexpr char PRODUCER_PROOF_DOMAIN[] =
    "BTX_RC_STAGE3_PRODUCER_BUS_PROOF_V1";
constexpr char PRODUCER_RECEIPT_DOMAIN[] =
    "BTX_RC_STAGE3_PRODUCER_BUS_RECEIPT_V1";
constexpr char PRODUCER_BASE_DOMAIN[] =
    "BTX_RC_STAGE3_PRODUCER_BUS_BASE_V1";
constexpr char PRODUCER_CHALLENGE_DOMAIN[] =
    "BTX_RC_STAGE3_PRODUCER_BUS_CHALLENGE_V1";
constexpr char PRODUCER_CHALLENGE_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_PRODUCER_BUS_CHALLENGE_SEED_V1";
constexpr char COPY_RECEIVER_RELATION_DOMAIN[] =
    "BTX_RC_STAGE3_WIRING_COPY_RECEIVER_RELATION_V1";
constexpr char COPY_RECEIVER_FS_DOMAIN[] =
    "BTX_RC_STAGE3_WIRING_COPY_RECEIVER_FS_V1";

enum CopyReceiverColumn : uint32_t {
    kCopySource = 0,
    kCopyDestination,
    kCopyActive,
    kCopyEndpoint,
    kCopySemanticRole,
    kCopyAddress,
    kCopyRemaining,
    kCopyInverse1,
    kCopyInverse2,
    kCopyTerm1,
    kCopyTerm2,
    kCopyRunning1,
    kCopyRunning2,
    kCopyReceiverColumns,
};

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) {
        *why = "stage3:episode_relation_product:" + message;
    }
    return false;
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    uint32_t out = 2;
    while (out < value) out <<= 1;
    return out;
}

bool CheckedMul(uint64_t a, uint64_t b, uint64_t& out)
{
    if (a != 0 && b > std::numeric_limits<uint64_t>::max() / a) {
        return false;
    }
    out = a * b;
    return true;
}

bool CanonicalFp3(const Fp3& value)
{
    return value.c0 < gkr_field::kP &&
           value.c1 < gkr_field::kP &&
           value.c2 < gkr_field::kP;
}

void WriteFp3(HashWriter& hash, const Fp3& value)
{
    hash << gkr_field::Canonical(value.c0);
    hash << gkr_field::Canonical(value.c1);
    hash << gkr_field::Canonical(value.c2);
}

bool PowerOfTwo(uint32_t value)
{
    return value >= 2 &&
           (value & (value - 1)) == 0;
}

uint256 ProducerProofCommitment(
    const std::vector<unsigned char>& bytes)
{
    if (bytes.empty()) return {};
    HashWriter hash;
    hash << PRODUCER_PROOF_DOMAIN
         << kRCStage3ProducerBusReceiptVersionV1
         << static_cast<uint64_t>(bytes.size())
         << bytes;
    return hash.GetHash();
}

void AppendU32(
    std::vector<unsigned char>& out,
    uint32_t value)
{
    for (uint32_t byte = 0; byte < 4; ++byte) {
        out.push_back(
            static_cast<unsigned char>(
                value >> (8 * byte)));
    }
}

void AppendU64(
    std::vector<unsigned char>& out,
    uint64_t value)
{
    for (uint32_t byte = 0; byte < 8; ++byte) {
        out.push_back(
            static_cast<unsigned char>(
                value >> (8 * byte)));
    }
}

bool SerializeProducerProof(
    const air_quotient::AirQuotientProof<Fp3>& proof,
    std::vector<unsigned char>& out)
{
    out.clear();
    std::vector<unsigned char> batch;
    if (SerializeFri3BatchProof(
            proof.batch, batch) == 0 ||
        batch.empty() ||
        batch.size() > kRCFriMaxProofBytesHard ||
        proof.next_openings.size() >
            kRCFriMaxQueriesHard) {
        return false;
    }
    AppendU32(out, 0x31524250U);
    AppendU32(out, 1);
    AppendU32(
        out, static_cast<uint32_t>(
            batch.size()));
    out.insert(
        out.end(), batch.begin(), batch.end());
    out.insert(
        out.end(), proof.trace_commit.begin(),
        proof.trace_commit.end());
    AppendU32(
        out, static_cast<uint32_t>(
            proof.next_openings.size()));
    for (const auto& paths :
         proof.next_openings) {
        if (paths.size() >
            kRCFriBatchMaxColumns) {
            out.clear();
            return false;
        }
        AppendU32(
            out, static_cast<uint32_t>(
                paths.size()));
        for (const auto& path : paths) {
            if (path.siblings.size() >
                kRCFriMaxFoldLayersHard) {
                out.clear();
                return false;
            }
            AppendU32(out, path.index);
            AppendU64(
                out, gkr_field::Canonical(
                    path.leaf.c0));
            AppendU64(
                out, gkr_field::Canonical(
                    path.leaf.c1));
            AppendU64(
                out, gkr_field::Canonical(
                    path.leaf.c2));
            AppendU32(
                out, static_cast<uint32_t>(
                    path.siblings.size()));
            for (const auto& sibling :
                 path.siblings) {
                out.insert(
                    out.end(), sibling.begin(),
                    sibling.end());
            }
        }
    }
    return !out.empty() &&
           out.size() <=
               kAirQuotientCodecMaxBytes;
}

bool SampleFp3(
    const uint256& public_seed,
    const char* label,
    Fp3& out)
{
    std::array<uint64_t, 3> limbs{};
    for (uint32_t limb = 0;
         limb < limbs.size(); ++limb) {
        bool accepted = false;
        for (uint32_t counter = 0;
             counter < 16; ++counter) {
            HashWriter hash;
            hash << PRODUCER_CHALLENGE_DOMAIN
                 << kRCStage3ProducerBusReceiptVersionV1
                 << public_seed
                 << std::string{label}
                 << limb << counter;
            const uint256 candidate =
                hash.GetHash();
            uint64_t word{0};
            for (uint32_t byte = 0;
                 byte < sizeof(word); ++byte) {
                word |= static_cast<uint64_t>(
                    candidate.data()[byte])
                    << (8 * byte);
            }
            if (word < gkr_field::kP) {
                limbs[limb] = word;
                accepted = true;
                break;
            }
        }
        if (!accepted) return false;
    }
    out = Fp3{limbs[0], limbs[1], limbs[2]};
    return true;
}

uint64_t EdgeAddressBegin(uint32_t first_column)
{
    // Λ currently uses far fewer than 2^24 committed columns.  Reserving
    // 32 address bits for the row keeps every <=2^28 tensor vector disjoint.
    return kRCStage3EpisodeRelationProductAddressBase |
           (static_cast<uint64_t>(first_column) << 32);
}

uint256 RegisteredRoot(
    const RCStage3GemmExtractLayerManifest& layer,
    RCStage3EpisodeWiringOperandSlot slot)
{
    return slot == RCStage3EpisodeWiringOperandSlot::A
        ? layer.bindings.operand_a_root
        : layer.bindings.operand_b_root;
}

bool SameScheduleIdentity(
    const RCStage3EpisodeWiringCopyScheduleEntry& a,
    const RCStage3EpisodeWiringCopyScheduleEntry& b)
{
    return a == b;
}

std::optional<RCStage3ProducerBusScheduleV1>
CopyReceiverSchedule(
    const RCStage3EpisodeWiringCopyScheduleEntry& edge,
    const RCStage3EpisodeWiringCopyAirShard& shard)
{
    if (edge.value_count == 0 ||
        shard.pin.logical_rows == 0 ||
        shard.pin.logical_rows > shard.pin.n_rows ||
        shard.value_begin > edge.value_count ||
        shard.pin.logical_rows >
            edge.value_count - shard.value_begin ||
        edge.address_begin >
            std::numeric_limits<uint64_t>::max() -
                shard.value_begin ||
        edge.schedule_index >
            (std::numeric_limits<uint32_t>::max() -
             0x42540000U) / 4096U ||
        shard.shard_index >= 4096U) {
        return std::nullopt;
    }
    RCStage3ProducerBusScheduleV1 schedule;
    schedule.bus_id =
        0x42540000U +
        edge.schedule_index * 4096U +
        shard.shard_index;
    schedule.logical_rows =
        shard.pin.logical_rows;
    schedule.events.resize(shard.pin.n_rows);
    for (uint32_t row = 0;
         row < shard.pin.n_rows; ++row) {
        auto& event = schedule.events[row];
        if (row >= shard.pin.logical_rows) continue;
        const uint64_t ordinal =
            shard.value_begin + row;
        event.active = true;
        event.endpoint =
            RCStage3RelationEndpoint::
                EpisodeBuilderTrace;
        event.semantic_role =
            RCStage3RelationRole::
                EpisodeDeterministicBuilder;
        event.address =
            edge.address_begin + ordinal;
        event.remaining =
            edge.value_count - ordinal;
        event.multiplicity = -1;
    }
    schedule.schedule_commitment =
        ComputeRCStage3ProducerBusScheduleCommitmentV1(
            schedule);
    return schedule.schedule_commitment.IsNull()
        ? std::nullopt
        : std::optional{std::move(schedule)};
}

Fp3 CompressCopyReceiverTuple(
    const std::vector<Fp3>& row,
    const RCStage3CtlChallenges& challenges,
    bool second_lane)
{
    const Fp3& gamma = second_lane
        ? challenges.gamma2
        : challenges.gamma1;
    const Fp3 gamma2 = gkr_field::Mul(gamma, gamma);
    const Fp3 gamma3 = gkr_field::Mul(gamma2, gamma);
    const Fp3 gamma4 = gkr_field::Mul(gamma3, gamma);
    return gkr_field::Add(
        row[kCopyEndpoint],
        gkr_field::Add(
            gkr_field::Mul(
                gamma, row[kCopySemanticRole]),
            gkr_field::Add(
                gkr_field::Mul(
                    gamma2, row[kCopyAddress]),
                gkr_field::Add(
                    gkr_field::Mul(
                        gamma3,
                        row[kCopyRemaining]),
                    gkr_field::Mul(
                        gamma4,
                        row[kCopySource])))));
}

air_quotient::AirConstraintSystem<Fp3>
BuildCopyReceiverConstraintSystem(
    const RCStage3ProducerBusScheduleV1& schedule,
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal)
{
    using CS =
        air_quotient::AirConstraintSystem<Fp3>;
    CS cs;
    if (schedule.schedule_commitment !=
            ComputeRCStage3ProducerBusScheduleCommitmentV1(
                schedule)) {
        return cs;
    }
    cs.n_rows = schedule.events.size();
    cs.n_columns = kCopyReceiverColumns;
    cs.preprocessed_pin_ood = true;
    std::array<std::vector<Fp3>, 5> fixed;
    for (auto& column : fixed) {
        column.assign(cs.n_rows, Fp3::Zero());
    }
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        const auto& event = schedule.events[row];
        fixed[0][row] =
            gkr_field::FromU64_3(
                event.active ? 1 : 0);
        fixed[1][row] =
            gkr_field::FromU64_3(
                static_cast<uint16_t>(
                    event.endpoint));
        fixed[2][row] =
            gkr_field::FromU64_3(
                static_cast<uint16_t>(
                    event.semantic_role));
        fixed[3][row] =
            gkr_field::FromU64_3(event.address);
        fixed[4][row] =
            gkr_field::FromU64_3(event.remaining);
    }
    for (uint32_t i = 0; i < fixed.size(); ++i) {
        cs.preprocessed.push_back(
            {kCopyActive + i,
             std::move(fixed[i])});
    }
    const auto add = [&cs](
        const char* name,
        air_quotient::AirKind kind,
        uint32_t degree,
        std::function<Fp3(
            const std::vector<Fp3>&,
            const std::vector<Fp3>&)> eval) {
        cs.constraints.push_back(
            {name, kind, degree,
             std::move(eval)});
    };
    add(
        "stage3.wiring.copy_receiver.equal",
        air_quotient::AirKind::kEverywhere,
        1,
        [](const auto& row, const auto&) {
            return gkr_field::Sub(
                row[kCopySource],
                row[kCopyDestination]);
        });
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const uint32_t inverse =
            lane == 0
                ? kCopyInverse1
                : kCopyInverse2;
        const uint32_t term =
            lane == 0
                ? kCopyTerm1
                : kCopyTerm2;
        const uint32_t running =
            lane == 0
                ? kCopyRunning1
                : kCopyRunning2;
        const Fp3 alpha =
            lane == 0
                ? challenges.alpha1
                : challenges.alpha2;
        const Fp3 expected =
            lane == 0
                ? terminal.alpha1_sum
                : terminal.alpha2_sum;
        add(
            "stage3.wiring.copy_receiver.inverse",
            air_quotient::AirKind::kEverywhere,
            2,
            [inverse, alpha, challenges, lane](
                const auto& row, const auto&) {
                return gkr_field::Sub(
                    gkr_field::Mul(
                        row[inverse],
                        gkr_field::Sub(
                            alpha,
                            CompressCopyReceiverTuple(
                                row, challenges,
                                lane != 0))),
                    Fp3::One());
            });
        add(
            "stage3.wiring.copy_receiver.term",
            air_quotient::AirKind::kEverywhere,
            2,
            [inverse, term](
                const auto& row, const auto&) {
                return gkr_field::Sub(
                    row[term],
                    gkr_field::Neg(
                        gkr_field::Mul(
                            row[kCopyActive],
                            row[inverse])));
            });
        add(
            "stage3.wiring.copy_receiver.running.first",
            air_quotient::AirKind::kFirstRow,
            1,
            [running](
                const auto& row, const auto&) {
                return row[running];
            });
        add(
            "stage3.wiring.copy_receiver.running.transition",
            air_quotient::AirKind::kTransition,
            1,
            [running, term](
                const auto& row, const auto& next) {
                return gkr_field::Sub(
                    next[running],
                    gkr_field::Add(
                        row[running], row[term]));
            });
        add(
            "stage3.wiring.copy_receiver.running.last",
            air_quotient::AirKind::kLastRow,
            1,
            [running, term, expected](
                const auto& row, const auto&) {
                return gkr_field::Sub(
                    gkr_field::Add(
                        row[running], row[term]),
                    expected);
            });
    }
    return cs.QuotientLen() <= cs.n_rows
        ? cs : CS{};
}

uint256 CopyReceiverRelationCommitment(
    const RCStage3EpisodeWiringCopyEdgeProduct& product,
    const RCStage3EpisodeWiringCopyAirShard& shard)
{
    const uint256 pin_commitment =
        ComputeRCStage3EpisodeAirPinCommitment(shard.pin);
    if (product.product_commitment.IsNull() ||
        pin_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << COPY_RECEIVER_RELATION_DOMAIN
         << kRCStage3ProducerBusReceiptVersionV1
         << product.product_commitment
         << shard.shard_index
         << shard.value_begin
         << pin_commitment;
    return hash.GetHash();
}

uint256 CopyReceiverFsSeed(
    const RCStage3ProducerBusReceiptV1& receipt)
{
    if (receipt.statement_commitment.IsNull() ||
        receipt.relation_commitment.IsNull() ||
        receipt.schedule.schedule_commitment.IsNull() ||
        receipt.base_row_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << COPY_RECEIVER_FS_DOMAIN
         << receipt.version
         << receipt.statement_commitment
         << receipt.relation_commitment
         << receipt.schedule.schedule_commitment
         << receipt.base_row_commitment
         << CommitRCStage3CtlChallenges(
                receipt.challenges);
    return hash.GetHash();
}

uint256 LocalProofCommitment(
    const RCStage3EpisodeWiringCopyAirShard& shard)
{
    if (shard.proof.batch.columns.size() != 3) return {};
    HashWriter hash;
    hash << "BTX_RC_STAGE3_EPISODE_WIRING_LOCAL_PROOF_V1";
    hash << shard.shard_index;
    hash << shard.value_begin;
    hash << ComputeRCStage3EpisodeAirPinCommitment(shard.pin);
    hash << shard.proof.batch.n_coeffs;
    hash << shard.proof.batch.pow_grind_nonce;
    for (const auto& column : shard.proof.batch.columns) {
        hash << column.root;
    }
    hash << shard.proof.trace_commit;
    return hash.GetHash();
}

bool ValidateStatementAndManifest(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifestBinding(
            statement, manifest, why)) {
        return false;
    }
    if (manifest.statement_commitment !=
        RCStage3EpisodeStatementCommitment(statement)) {
        return Fail(why, "statement_commitment");
    }
    return true;
}

} // namespace

uint256 ComputeRCStage3ProducerBusScheduleCommitmentV1(
    const RCStage3ProducerBusScheduleV1& schedule)
{
    if (schedule.version !=
            kRCStage3ProducerBusReceiptVersionV1 ||
        schedule.bus_id == 0 ||
        schedule.logical_rows == 0 ||
        schedule.events.size() < 2 ||
        schedule.events.size() >
            std::numeric_limits<uint32_t>::max() ||
        schedule.logical_rows >
            schedule.events.size() ||
        !PowerOfTwo(static_cast<uint32_t>(
            schedule.events.size()))) {
        return {};
    }
    HashWriter hash;
    hash << PRODUCER_SCHEDULE_DOMAIN
         << schedule.version
         << schedule.bus_id
         << schedule.logical_rows
         << static_cast<uint32_t>(
                schedule.events.size());
    for (uint32_t row = 0;
         row < schedule.events.size(); ++row) {
        const auto& event = schedule.events[row];
        const bool expected_active =
            row < schedule.logical_rows;
        if (event.active != expected_active ||
            (expected_active &&
             event.multiplicity != 1 &&
             event.multiplicity != -1) ||
            (!expected_active &&
             (event.multiplicity != 0 ||
              event.address != 0 ||
              event.remaining != 0)) ||
            event.address >= gkr_field::kP ||
            event.remaining >= gkr_field::kP) {
            return {};
        }
        hash << event.active
             << static_cast<uint16_t>(
                    event.endpoint)
             << static_cast<uint16_t>(
                    event.semantic_role)
             << event.address
             << event.remaining
             << static_cast<int32_t>(
                    event.multiplicity);
    }
    return hash.GetHash();
}

uint256 ComputeRCStage3ProducerBusBaseCommitmentV1(
    const RCStage3ProducerBusScheduleV1& schedule,
    const std::vector<uint32_t>& base_column_indices,
    const std::vector<uint256>&
        prechallenge_column_roots)
{
    if (schedule.schedule_commitment.IsNull() ||
        schedule.schedule_commitment !=
            ComputeRCStage3ProducerBusScheduleCommitmentV1(
                schedule) ||
        base_column_indices.empty() ||
        base_column_indices.size() !=
            prechallenge_column_roots.size()) {
        return {};
    }
    HashWriter hash;
    hash << PRODUCER_BASE_DOMAIN
         << kRCStage3ProducerBusReceiptVersionV1
         << schedule.schedule_commitment
         << static_cast<uint32_t>(
                base_column_indices.size());
    uint32_t previous = 0;
    for (uint32_t i = 0;
         i < base_column_indices.size(); ++i) {
        if ((i != 0 &&
             base_column_indices[i] <= previous) ||
            prechallenge_column_roots[i].IsNull()) {
            return {};
        }
        previous = base_column_indices[i];
        hash << base_column_indices[i]
             << prechallenge_column_roots[i];
    }
    return hash.GetHash();
}

uint256 ComputeRCStage3ProducerBusProofCommitmentV1(
    const std::vector<unsigned char>& canonical_proof_bytes)
{
    return ProducerProofCommitment(
        canonical_proof_bytes);
}

uint256 ComputeRCStage3ProducerBusChallengeSeedV1(
    const uint256& statement_commitment,
    uint32_t bus_id,
    const std::vector<RCStage3ProducerBusEpochPinV1>&
        ordered_participants)
{
    if (statement_commitment.IsNull() ||
        bus_id == 0 ||
        ordered_participants.size() < 2) {
        return {};
    }
    HashWriter hash;
    hash << PRODUCER_CHALLENGE_SEED_DOMAIN
         << kRCStage3ProducerBusReceiptVersionV1
         << statement_commitment
         << bus_id
         << static_cast<uint32_t>(
                ordered_participants.size());
    for (const auto& participant :
         ordered_participants) {
        if (participant.schedule_commitment.IsNull() ||
            participant.base_row_commitment.IsNull()) {
            return {};
        }
        hash << static_cast<uint16_t>(
                    participant.relation_role)
             << participant.schedule_commitment
             << participant.base_row_commitment;
    }
    return hash.GetHash();
}

bool SerializeRCStage3ProducerBusProofV1(
    const air_quotient::AirQuotientProof<Fp3>& proof,
    std::vector<unsigned char>& out,
    std::string* why)
{
    if (!SerializeProducerProof(proof, out)) {
        out.clear();
        return Fail(
            why, "producer_bus:proof_codec");
    }
    return true;
}

bool DeriveRCStage3ProducerBusChallengesV1(
    const uint256& public_challenge_seed,
    const RCStage3ProducerBusScheduleV1& schedule,
    const uint256& base_row_commitment,
    RCStage3CtlChallenges& out,
    std::string* why)
{
    out = {};
    if (public_challenge_seed.IsNull() ||
        base_row_commitment.IsNull() ||
        schedule.schedule_commitment.IsNull() ||
        schedule.schedule_commitment !=
            ComputeRCStage3ProducerBusScheduleCommitmentV1(
                schedule) ||
        !SampleFp3(
            public_challenge_seed,
            "gamma1", out.gamma1) ||
        !SampleFp3(
            public_challenge_seed,
            "gamma2", out.gamma2) ||
        !SampleFp3(
            public_challenge_seed,
            "alpha1", out.alpha1) ||
        !SampleFp3(
            public_challenge_seed,
            "alpha2", out.alpha2) ||
        gkr_field::IsZero(out.gamma1) ||
        gkr_field::IsZero(out.gamma2) ||
        gkr_field::IsZero(out.alpha1) ||
        gkr_field::IsZero(out.alpha2) ||
        gkr_field::Eq(out.gamma1, out.gamma2) ||
        gkr_field::Eq(out.alpha1, out.alpha2)) {
        out = {};
        return Fail(
            why, "producer_bus:challenge_derivation");
    }
    return true;
}

uint256 ComputeRCStage3ProducerBusReceiptCommitmentV1(
    const RCStage3ProducerBusReceiptV1& receipt)
{
    if (receipt.magic !=
            kRCStage3ProducerBusReceiptMagicV1 ||
        receipt.version !=
            kRCStage3ProducerBusReceiptVersionV1 ||
        receipt.statement_commitment.IsNull() ||
        receipt.relation_commitment.IsNull() ||
        receipt.schedule.schedule_commitment.IsNull() ||
        receipt.schedule.schedule_commitment !=
            ComputeRCStage3ProducerBusScheduleCommitmentV1(
                receipt.schedule) ||
        receipt.logical_rows == 0 ||
        receipt.logical_rows > receipt.n_rows ||
        receipt.logical_rows !=
            receipt.schedule.logical_rows ||
        receipt.n_rows != receipt.schedule.events.size() ||
        !PowerOfTwo(receipt.n_rows) ||
        receipt.relation_value_column_root.IsNull() ||
        receipt.base_row_commitment.IsNull() ||
        receipt.base_column_indices.empty() ||
        receipt.base_column_indices.size() !=
            receipt.prechallenge_column_roots.size() ||
        receipt.base_row_commitment !=
            ComputeRCStage3ProducerBusBaseCommitmentV1(
                receipt.schedule,
                receipt.base_column_indices,
                receipt.prechallenge_column_roots) ||
        receipt.public_challenge_seed.IsNull() ||
        receipt.public_fs_seed.IsNull() ||
        receipt.terminal_running_column_roots[0].IsNull() ||
        receipt.terminal_running_column_roots[1].IsNull() ||
        receipt.terminal_term_column_roots[0].IsNull() ||
        receipt.terminal_term_column_roots[1].IsNull() ||
        receipt.canonical_proof_bytes.empty() ||
        receipt.proof_commitment !=
            ProducerProofCommitment(
                receipt.canonical_proof_bytes) ||
        !CanonicalFp3(receipt.challenges.gamma1) ||
        !CanonicalFp3(receipt.challenges.gamma2) ||
        !CanonicalFp3(receipt.challenges.alpha1) ||
        !CanonicalFp3(receipt.challenges.alpha2) ||
        !CanonicalFp3(receipt.terminal.alpha1_sum) ||
        !CanonicalFp3(receipt.terminal.alpha2_sum)) {
        return {};
    }
    HashWriter hash;
    hash << PRODUCER_RECEIPT_DOMAIN
         << receipt.magic << receipt.version
         << static_cast<uint16_t>(
                receipt.relation_role)
         << receipt.statement_commitment
         << receipt.relation_commitment
         << receipt.schedule.schedule_commitment
         << receipt.logical_rows << receipt.n_rows
         << receipt.relation_value_column
         << receipt.relation_value_column_root
         << receipt.base_row_commitment
         << static_cast<uint32_t>(
                receipt.base_column_indices.size());
    for (uint32_t i = 0;
         i < receipt.base_column_indices.size();
         ++i) {
        hash << receipt.base_column_indices[i]
             << receipt.prechallenge_column_roots[i];
    }
    hash << receipt.terminal_running_columns[0]
         << receipt.terminal_running_columns[1]
         << receipt.terminal_term_columns[0]
         << receipt.terminal_term_columns[1]
         << receipt.terminal_running_column_roots[0]
         << receipt.terminal_running_column_roots[1]
         << receipt.terminal_term_column_roots[0]
         << receipt.terminal_term_column_roots[1];
    WriteFp3(hash, receipt.challenges.gamma1);
    WriteFp3(hash, receipt.challenges.gamma2);
    WriteFp3(hash, receipt.challenges.alpha1);
    WriteFp3(hash, receipt.challenges.alpha2);
    WriteFp3(hash, receipt.terminal.alpha1_sum);
    WriteFp3(hash, receipt.terminal.alpha2_sum);
    hash << receipt.public_challenge_seed
         << receipt.public_fs_seed
         << receipt.proof_commitment;
    return hash.GetHash();
}

bool VerifyRCStage3ProducerBusReceiptV1(
    const RCStage3ProducerBusReceiptV1& receipt,
    const RCStage3ProducerBusVerificationInputV1& input,
    std::string* why)
{
    std::vector<unsigned char> canonical;
    RCStage3CtlChallenges expected_challenges;
    if (!input.valid ||
        input.expected_statement_commitment.IsNull() ||
        input.expected_relation_commitment.IsNull() ||
        input.expected_public_fs_seed.IsNull() ||
        input.expected_public_challenge_seed.IsNull() ||
        input.expected_cs.n_rows == 0 ||
        input.expected_cs.n_columns == 0 ||
        receipt.magic !=
            kRCStage3ProducerBusReceiptMagicV1 ||
        receipt.version !=
            kRCStage3ProducerBusReceiptVersionV1 ||
        receipt.relation_role !=
            input.expected_relation_role ||
        receipt.statement_commitment !=
            input.expected_statement_commitment ||
        receipt.relation_commitment !=
            input.expected_relation_commitment ||
        !(receipt.schedule ==
          input.expected_schedule) ||
        receipt.logical_rows !=
            input.expected_logical_rows ||
        receipt.n_rows != input.expected_n_rows ||
        receipt.n_rows != input.expected_cs.n_rows ||
        receipt.relation_value_column !=
            input.expected_relation_value_column ||
        receipt.relation_value_column >=
            input.expected_cs.n_columns ||
        receipt.proof.batch.columns.size() !=
            input.expected_cs.n_columns + 1 ||
        receipt.proof.batch.column_len.size() !=
            input.expected_cs.n_columns + 1 ||
        receipt.terminal_running_columns[0] >=
            input.expected_cs.n_columns ||
        receipt.terminal_running_columns[1] >=
            input.expected_cs.n_columns ||
        receipt.terminal_term_columns[0] >=
            input.expected_cs.n_columns ||
        receipt.terminal_term_columns[1] >=
            input.expected_cs.n_columns ||
        receipt.terminal_running_columns[0] ==
            receipt.terminal_running_columns[1] ||
        receipt.terminal_term_columns[0] ==
            receipt.terminal_term_columns[1] ||
        receipt.terminal_running_column_roots[0] !=
            receipt.proof.batch.columns[
                receipt.terminal_running_columns[0]].root ||
        receipt.terminal_running_column_roots[1] !=
            receipt.proof.batch.columns[
                receipt.terminal_running_columns[1]].root ||
        receipt.terminal_term_column_roots[0] !=
            receipt.proof.batch.columns[
                receipt.terminal_term_columns[0]].root ||
        receipt.terminal_term_column_roots[1] !=
            receipt.proof.batch.columns[
                receipt.terminal_term_columns[1]].root ||
        receipt.base_column_indices !=
            input.expected_base_column_indices ||
        receipt.terminal_running_columns !=
            input.expected_terminal_running_columns ||
        receipt.terminal_term_columns !=
            input.expected_terminal_term_columns ||
        receipt.public_challenge_seed !=
            input.expected_public_challenge_seed ||
        receipt.public_fs_seed !=
            input.expected_public_fs_seed ||
        receipt.relation_value_column_root !=
            receipt.proof.batch.columns[
                receipt.relation_value_column].root ||
        receipt.base_column_indices.size() !=
            receipt.prechallenge_column_roots.size() ||
        !std::equal(
            receipt.base_column_indices.begin(),
            receipt.base_column_indices.end(),
            receipt.prechallenge_column_roots.begin(),
            [&receipt](uint32_t column,
                       const uint256& root) {
                return column <
                           receipt.proof.batch.columns.size() &&
                       receipt.proof.batch.columns[
                           column].root == root;
            }) ||
        receipt.base_row_commitment !=
            ComputeRCStage3ProducerBusBaseCommitmentV1(
                receipt.schedule,
                receipt.base_column_indices,
                receipt.prechallenge_column_roots) ||
        !DeriveRCStage3ProducerBusChallengesV1(
            receipt.public_challenge_seed,
            receipt.schedule,
            receipt.base_row_commitment,
            expected_challenges, why) ||
        !(receipt.challenges ==
          expected_challenges) ||
        !SerializeProducerProof(
            receipt.proof, canonical) ||
        canonical != receipt.canonical_proof_bytes ||
        receipt.proof_commitment !=
            ProducerProofCommitment(canonical) ||
        receipt.receipt_commitment !=
            ComputeRCStage3ProducerBusReceiptCommitmentV1(
                receipt)) {
        return Fail(why, "producer_bus:binding");
    }
    std::string proof_why;
    if (!air_quotient::
            AirQuotientVerify<Fp3>(
                input.expected_cs, receipt.proof,
                input.expected_public_fs_seed,
                &proof_why)) {
        return Fail(
            why, "producer_bus:proof:" +
                proof_why);
    }
    return true;
}

bool VerifyRCStage3ProducerBusTerminalPairV1(
    const RCStage3ProducerBusReceiptV1& producer,
    const RCStage3ProducerBusVerificationInputV1& producer_input,
    const RCStage3ProducerBusReceiptV1& receiver,
    const RCStage3ProducerBusVerificationInputV1& receiver_input,
    const uint256& expected_public_challenge_seed,
    std::string* why)
{
    if (expected_public_challenge_seed.IsNull() ||
        producer.public_challenge_seed !=
            expected_public_challenge_seed ||
        receiver.public_challenge_seed !=
            expected_public_challenge_seed ||
        !(producer.challenges ==
          receiver.challenges) ||
        producer.schedule.bus_id !=
            receiver.schedule.bus_id ||
        producer.schedule.logical_rows !=
            receiver.schedule.logical_rows ||
        producer.schedule.events.size() !=
            receiver.schedule.events.size() ||
        producer.schedule.events.empty()) {
        return Fail(
            why, "producer_bus:pair_binding");
    }
    for (uint32_t row = 0;
         row < producer.schedule.events.size();
         ++row) {
        const auto& send =
            producer.schedule.events[row];
        const auto& receive =
            receiver.schedule.events[row];
        if (send.active != receive.active ||
            send.endpoint != receive.endpoint ||
            send.semantic_role !=
                receive.semantic_role ||
            send.address != receive.address ||
            send.remaining != receive.remaining ||
            send.multiplicity !=
                -receive.multiplicity) {
            return Fail(
                why, "producer_bus:pair_schedule");
        }
    }
    if (!VerifyRCStage3ProducerBusReceiptV1(
            producer, producer_input, why) ||
        !VerifyRCStage3ProducerBusReceiptV1(
            receiver, receiver_input, why) ||
        !gkr_field::IsZero(gkr_field::Add(
            producer.terminal.alpha1_sum,
            receiver.terminal.alpha1_sum)) ||
        !gkr_field::IsZero(gkr_field::Add(
            producer.terminal.alpha2_sum,
            receiver.terminal.alpha2_sum))) {
        return Fail(
            why, "producer_bus:pair_terminal");
    }
    return true;
}

std::optional<std::vector<RCStage3EpisodeWiringCopyScheduleEntry>>
BuildRCStage3EpisodeWiringCopySchedule(
    const RCStage3GemmExtractManifest& manifest,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why)) {
        return std::nullopt;
    }
    const RCGkrLayout layout = RCGkrTraceLayout(manifest.params);
    if (layout.layers.size() != manifest.layers.size()) {
        Fail(why, "schedule:layout_size");
        return std::nullopt;
    }

    std::vector<RCStage3EpisodeWiringCopyScheduleEntry> out;
    out.reserve(layout.layers.size() * 2);
    for (uint32_t layer_ordinal = 0;
         layer_ordinal < layout.layers.size(); ++layer_ordinal) {
        const auto& layer = layout.layers[layer_ordinal];
        const auto& registered = manifest.layers[layer_ordinal];
        const auto append =
            [&](RCStage3EpisodeWiringOperandSlot slot,
                const RCGkrOperandRef& ref,
                uint64_t rows,
                uint64_t cols) -> bool {
            if (ref.transpose) return true;
            uint64_t count{0};
            if (!CheckedMul(rows, cols, count) || count == 0 ||
                ref.n_chunks == 0 || ref.first_column >= (1U << 24) ||
                count > (uint64_t{1} << 32)) {
                return false;
            }
            RCStage3EpisodeWiringCopyScheduleEntry entry;
            entry.schedule_index = out.size();
            entry.layer_ordinal = layer_ordinal;
            entry.slot = slot;
            entry.first_column = ref.first_column;
            entry.n_chunks = ref.n_chunks;
            entry.value_count = count;
            entry.address_begin = EdgeAddressBegin(ref.first_column);
            entry.registered_vector_root =
                RegisteredRoot(registered, slot);
            if (entry.registered_vector_root.IsNull()) return false;
            out.push_back(std::move(entry));
            return true;
        };
        if (!append(
                RCStage3EpisodeWiringOperandSlot::A,
                layer.a, layer.m, layer.k) ||
            !append(
                RCStage3EpisodeWiringOperandSlot::B,
                layer.b, layer.k, layer.n)) {
            Fail(why, "schedule:edge_shape");
            return std::nullopt;
        }
    }
    if (out.empty()) {
        Fail(why, "schedule:empty");
        return std::nullopt;
    }
    return out;
}

uint256 ComputeRCStage3EpisodeWiringVectorRoot(
    const uint256& statement_commitment,
    uint32_t first_column,
    uint32_t n_chunks,
    uint64_t value_count,
    const std::vector<uint256>& ordered_shard_roots)
{
    if (statement_commitment.IsNull() || n_chunks == 0 ||
        value_count == 0 || first_column >= (1U << 24)) {
        return {};
    }
    const uint64_t expected_shards =
        (value_count + kRCStage3EpisodeSemanticMaxRows - 1) /
        kRCStage3EpisodeSemanticMaxRows;
    if (ordered_shard_roots.size() != expected_shards ||
        std::any_of(
            ordered_shard_roots.begin(), ordered_shard_roots.end(),
            [](const uint256& root) { return root.IsNull(); })) {
        return {};
    }
    HashWriter hash;
    hash << VECTOR_ROOT_DOMAIN;
    hash << kRCStage3EpisodeRelationProductVersion;
    hash << statement_commitment;
    hash << first_column;
    hash << n_chunks;
    hash << value_count;
    hash << static_cast<uint32_t>(ordered_shard_roots.size());
    for (const auto& root : ordered_shard_roots) hash << root;
    return hash.GetHash();
}

std::optional<uint256>
ComputeRCStage3EpisodeWiringVectorRootFromValues(
    const uint256& statement_commitment,
    uint32_t first_column,
    uint32_t n_chunks,
    const std::vector<Fp3>& values,
    std::string* why)
{
    if (values.empty()) {
        Fail(why, "vector_root:empty");
        return std::nullopt;
    }
    std::vector<uint256> roots;
    for (uint64_t begin = 0; begin < values.size();
         begin += kRCStage3EpisodeSemanticMaxRows) {
        const uint32_t rows = static_cast<uint32_t>(
            std::min<uint64_t>(
                kRCStage3EpisodeSemanticMaxRows,
                values.size() - begin));
        std::vector<Fp3> shard(
            values.begin() + begin, values.begin() + begin + rows);
        const auto root = ComputeRCStage3EpisodeSemanticValueRoot(
            shard, rows, NextPowerOfTwo(rows), why);
        if (!root.has_value()) return std::nullopt;
        roots.push_back(*root);
    }
    const uint256 root = ComputeRCStage3EpisodeWiringVectorRoot(
        statement_commitment, first_column, n_chunks,
        values.size(), roots);
    if (root.IsNull()) {
        Fail(why, "vector_root:commitment");
        return std::nullopt;
    }
    return root;
}

uint256 ComputeRCStage3EpisodeWiringCopyEdgeProductCommitment(
    const RCStage3EpisodeWiringCopyEdgeProduct& product)
{
    if (product.magic != kRCStage3EpisodeRelationProductMagic ||
        product.version != kRCStage3EpisodeRelationProductVersion ||
        product.relation_shards.empty() ||
        product.source_memory.bundle_commitment.IsNull() ||
        product.destination_memory.bundle_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << EDGE_PRODUCT_DOMAIN;
    hash << product.magic;
    hash << product.version;
    hash << product.schedule.schedule_index;
    hash << product.schedule.layer_ordinal;
    hash << static_cast<uint8_t>(product.schedule.slot);
    hash << product.schedule.first_column;
    hash << product.schedule.n_chunks;
    hash << product.schedule.value_count;
    hash << product.schedule.address_begin;
    hash << product.schedule.registered_vector_root;
    hash << static_cast<uint32_t>(product.relation_shards.size());
    for (const auto& shard : product.relation_shards) {
        const uint256 local = LocalProofCommitment(shard);
        if (local.IsNull()) return {};
        hash << local;
    }
    hash << product.source_memory.bundle_commitment;
    hash << product.destination_memory.bundle_commitment;
    return hash.GetHash();
}

uint256 ComputeRCStage3EpisodeWiringCopyClosureCommitment(
    const RCStage3EpisodeWiringCopyClosure& closure)
{
    if (closure.magic != kRCStage3EpisodeRelationProductMagic ||
        closure.version != kRCStage3EpisodeRelationProductVersion ||
        closure.statement_commitment.IsNull() ||
        closure.manifest_commitment.IsNull() ||
        closure.edges.empty()) {
        return {};
    }
    HashWriter hash;
    hash << CLOSURE_DOMAIN;
    hash << closure.magic;
    hash << closure.version;
    hash << closure.statement_commitment;
    hash << closure.manifest_commitment;
    hash << static_cast<uint32_t>(closure.edges.size());
    for (const auto& edge : closure.edges) {
        if (edge.product_commitment.IsNull()) return {};
        hash << edge.product_commitment;
    }
    return hash.GetHash();
}

bool ProveRCStage3EpisodeWiringCopyEdgeProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeWiringCopyScheduleEntry& expected,
    const std::vector<Fp3>& source,
    const std::vector<Fp3>& destination,
    RCStage3EpisodeWiringCopyEdgeProduct& out,
    std::string* why)
{
    out = {};
    if (!ValidateStatementAndManifest(statement, manifest, why)) {
        return false;
    }
    const auto schedule =
        BuildRCStage3EpisodeWiringCopySchedule(manifest, why);
    if (!schedule.has_value() ||
        expected.schedule_index >= schedule->size() ||
        !SameScheduleIdentity(
            expected, (*schedule)[expected.schedule_index])) {
        return Fail(why, "prove:schedule");
    }
    if (source.size() != expected.value_count ||
        destination.size() != expected.value_count) {
        return Fail(why, "prove:value_count");
    }

    const auto source_root =
        ComputeRCStage3EpisodeWiringVectorRootFromValues(
            manifest.statement_commitment, expected.first_column,
            expected.n_chunks, source, why);
    const auto destination_root =
        ComputeRCStage3EpisodeWiringVectorRootFromValues(
            manifest.statement_commitment, expected.first_column,
            expected.n_chunks, destination, why);
    if (!source_root.has_value() || !destination_root.has_value() ||
        *source_root != expected.registered_vector_root ||
        *destination_root != expected.registered_vector_root) {
        return Fail(why, "prove:registered_root");
    }

    out.magic = kRCStage3EpisodeRelationProductMagic;
    out.version = kRCStage3EpisodeRelationProductVersion;
    out.schedule = expected;
    const uint32_t shard_count = static_cast<uint32_t>(
        (expected.value_count +
         kRCStage3EpisodeSemanticMaxRows - 1) /
        kRCStage3EpisodeSemanticMaxRows);
    out.relation_shards.reserve(shard_count);
    for (uint32_t shard_index = 0;
         shard_index < shard_count; ++shard_index) {
        const uint64_t begin =
            static_cast<uint64_t>(shard_index) *
            kRCStage3EpisodeSemanticMaxRows;
        const uint32_t logical_rows = static_cast<uint32_t>(
            std::min<uint64_t>(
                kRCStage3EpisodeSemanticMaxRows,
                expected.value_count - begin));
        const uint32_t n_rows = NextPowerOfTwo(logical_rows);
        std::vector<std::vector<Fp3>> columns(
            2, std::vector<Fp3>(n_rows, Fp3::Zero()));
        std::copy_n(
            source.begin() + begin, logical_rows, columns[0].begin());
        std::copy_n(
            destination.begin() + begin, logical_rows,
            columns[1].begin());

        RCStage3EpisodeWiringCopyAirShard shard;
        shard.shard_index = shard_index;
        shard.value_begin = begin;
        auto& pin = shard.pin;
        pin.role = RCStage3RelationRole::EpisodeWiring;
        pin.family =
            RCStage3EpisodeAirFamily::WiringEqualityFp3V1;
        pin.statement_commitment = manifest.statement_commitment;
        pin.shard_index = shard_index;
        pin.shard_count = shard_count;
        pin.logical_rows = logical_rows;
        pin.n_rows = n_rows;
        pin.n_coeffs = n_rows;
        for (uint32_t column = 0; column < 2; ++column) {
            pin.column_roots.push_back(
                {column,
                 air_quotient::AirCommittedValuesRoot<Fp3>(
                     columns[column], n_rows)});
        }

        air_quotient::AirConstraintSystem<Fp3> cs;
        if (!ResolveRCStage3EpisodeAirConstraintSystem(
                statement, pin, cs, why)) {
            return false;
        }
        const auto proved =
            air_quotient::AirQuotientProve<Fp3>(
                cs, columns,
                ComputeRCStage3EpisodeAirSeed(statement, pin));
        if (!proved.ok || !proved.division_exact) {
            return Fail(why, "prove:local_air:" + proved.note);
        }
        shard.proof = proved.proof;
        out.relation_shards.push_back(std::move(shard));
    }

    if (!ProveRCStage3EpisodeSemanticMemoryBundle(
            RCStage3RelationEndpoint::EpisodeWiringCopy,
            manifest.statement_commitment, expected.address_begin, 1,
            source, out.source_memory, why) ||
        !ProveRCStage3EpisodeSemanticMemoryBundle(
            RCStage3RelationEndpoint::EpisodeWiringCopy,
            manifest.statement_commitment, expected.address_begin, 1,
            destination, out.destination_memory, why)) {
        out = {};
        return false;
    }
    out.product_commitment =
        ComputeRCStage3EpisodeWiringCopyEdgeProductCommitment(out);
    if (out.product_commitment.IsNull()) {
        out = {};
        return Fail(why, "prove:product_commitment");
    }
    return true;
}

bool VerifyRCStage3EpisodeWiringCopyEdgeProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeWiringCopyScheduleEntry& expected,
    const RCStage3EpisodeWiringCopyEdgeProduct& product,
    std::string* why)
{
    if (!ValidateStatementAndManifest(statement, manifest, why)) {
        return false;
    }
    if (product.magic != kRCStage3EpisodeRelationProductMagic ||
        product.version != kRCStage3EpisodeRelationProductVersion ||
        !SameScheduleIdentity(product.schedule, expected)) {
        return Fail(why, "verify:public_shape");
    }
    const uint32_t shard_count = static_cast<uint32_t>(
        (expected.value_count +
         kRCStage3EpisodeSemanticMaxRows - 1) /
        kRCStage3EpisodeSemanticMaxRows);
    if (product.relation_shards.size() != shard_count) {
        return Fail(why, "verify:shard_count");
    }

    std::vector<uint256> source_roots;
    std::vector<uint256> destination_roots;
    source_roots.reserve(shard_count);
    destination_roots.reserve(shard_count);
    for (uint32_t shard_index = 0;
         shard_index < shard_count; ++shard_index) {
        const auto& shard = product.relation_shards[shard_index];
        const uint64_t begin =
            static_cast<uint64_t>(shard_index) *
            kRCStage3EpisodeSemanticMaxRows;
        const uint32_t logical_rows = static_cast<uint32_t>(
            std::min<uint64_t>(
                kRCStage3EpisodeSemanticMaxRows,
                expected.value_count - begin));
        const uint32_t n_rows = NextPowerOfTwo(logical_rows);
        const auto& pin = shard.pin;
        if (shard.shard_index != shard_index ||
            shard.value_begin != begin ||
            pin.role != RCStage3RelationRole::EpisodeWiring ||
            pin.family !=
                RCStage3EpisodeAirFamily::WiringEqualityFp3V1 ||
            pin.statement_commitment != manifest.statement_commitment ||
            pin.shard_index != shard_index ||
            pin.shard_count != shard_count ||
            pin.logical_rows != logical_rows ||
            pin.n_rows != n_rows || pin.n_coeffs != n_rows ||
            pin.extract_scale_e != 0 ||
            pin.column_roots.size() != 2 ||
            pin.column_roots[0].column != 0 ||
            pin.column_roots[1].column != 1) {
            return Fail(why, "verify:canonical_shard");
        }
        if (!VerifyRCStage3EpisodeAirShard(
                statement, pin, shard.proof, why)) {
            return false;
        }
        source_roots.push_back(pin.column_roots[0].root);
        destination_roots.push_back(pin.column_roots[1].root);
    }

    if (!VerifyRCStage3EpisodeSemanticMemoryBundle(
            RCStage3RelationEndpoint::EpisodeWiringCopy,
            manifest.statement_commitment, expected.value_count,
            expected.address_begin, 1, source_roots,
            product.source_memory, why) ||
        !VerifyRCStage3EpisodeSemanticMemoryBundle(
            RCStage3RelationEndpoint::EpisodeWiringCopy,
            manifest.statement_commitment, expected.value_count,
            expected.address_begin, 1, destination_roots,
            product.destination_memory, why)) {
        return false;
    }

    const uint256 source_root =
        ComputeRCStage3EpisodeWiringVectorRoot(
            manifest.statement_commitment, expected.first_column,
            expected.n_chunks, expected.value_count, source_roots);
    const uint256 destination_root =
        ComputeRCStage3EpisodeWiringVectorRoot(
            manifest.statement_commitment, expected.first_column,
            expected.n_chunks, expected.value_count,
            destination_roots);
    if (source_root != expected.registered_vector_root ||
        destination_root != expected.registered_vector_root) {
        return Fail(why, "verify:registered_root");
    }
    if (product.product_commitment !=
        ComputeRCStage3EpisodeWiringCopyEdgeProductCommitment(
            product)) {
        return Fail(why, "verify:product_commitment");
    }
    return true;
}

bool VerifyRCStage3EpisodeWiringCopyClosure(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeWiringCopyClosure& closure,
    std::string* why)
{
    if (!ValidateStatementAndManifest(statement, manifest, why)) {
        return false;
    }
    const uint256 manifest_commitment =
        ComputeRCStage3GemmExtractManifestCommitment(manifest);
    if (closure.magic != kRCStage3EpisodeRelationProductMagic ||
        closure.version != kRCStage3EpisodeRelationProductVersion ||
        closure.statement_commitment != manifest.statement_commitment ||
        closure.manifest_commitment != manifest_commitment) {
        return Fail(why, "closure:public_shape");
    }
    const auto schedule =
        BuildRCStage3EpisodeWiringCopySchedule(manifest, why);
    if (!schedule.has_value() ||
        closure.edges.size() != schedule->size()) {
        return Fail(why, "closure:edge_count");
    }
    for (uint32_t index = 0; index < schedule->size(); ++index) {
        if (!VerifyRCStage3EpisodeWiringCopyEdgeProduct(
                statement, manifest, (*schedule)[index],
                closure.edges[index], why)) {
            return false;
        }
    }
    if (closure.closure_commitment !=
        ComputeRCStage3EpisodeWiringCopyClosureCommitment(closure)) {
        return Fail(why, "closure:commitment");
    }
    return true;
}

bool ProveRCStage3EpisodeWiringCopyReceiverBusReceiptV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeWiringCopyScheduleEntry& expected,
    const RCStage3EpisodeWiringCopyEdgeProduct& product,
    const std::vector<Fp3>& source_values,
    uint32_t shard_index,
    const uint256& public_challenge_seed,
    RCStage3ProducerBusReceiptV1& out,
    std::string* why)
{
    out = {};
    if (public_challenge_seed.IsNull() ||
        source_values.size() != expected.value_count ||
        !VerifyRCStage3EpisodeWiringCopyEdgeProduct(
            statement, manifest, expected, product, why) ||
        shard_index >= product.relation_shards.size()) {
        return Fail(why, "copy_receiver:public_input");
    }
    const auto& shard = product.relation_shards[shard_index];
    const auto canonical_schedule =
        CopyReceiverSchedule(expected, shard);
    if (!canonical_schedule.has_value() ||
        shard.value_begin > source_values.size() ||
        shard.pin.logical_rows >
            source_values.size() - shard.value_begin ||
        shard.pin.column_roots.size() != 2) {
        return Fail(why, "copy_receiver:schedule");
    }

    std::vector<std::vector<Fp3>> columns(
        kCopyReceiverColumns,
        std::vector<Fp3>(
            shard.pin.n_rows, Fp3::Zero()));
    std::copy_n(
        source_values.begin() + shard.value_begin,
        shard.pin.logical_rows,
        columns[kCopySource].begin());
    std::copy_n(
        source_values.begin() + shard.value_begin,
        shard.pin.logical_rows,
        columns[kCopyDestination].begin());
    for (uint32_t row = 0; row < shard.pin.n_rows; ++row) {
        const auto& event =
            canonical_schedule->events[row];
        columns[kCopyActive][row] =
            gkr_field::FromU64_3(
                event.active ? 1 : 0);
        columns[kCopyEndpoint][row] =
            gkr_field::FromU64_3(
                static_cast<uint16_t>(
                    event.endpoint));
        columns[kCopySemanticRole][row] =
            gkr_field::FromU64_3(
                static_cast<uint16_t>(
                    event.semantic_role));
        columns[kCopyAddress][row] =
            gkr_field::FromU64_3(event.address);
        columns[kCopyRemaining][row] =
            gkr_field::FromU64_3(event.remaining);
    }

    out.relation_role =
        RCStage3RelationRole::EpisodeWiring;
    out.statement_commitment =
        manifest.statement_commitment;
    out.relation_commitment =
        CopyReceiverRelationCommitment(product, shard);
    out.schedule = *canonical_schedule;
    out.logical_rows = shard.pin.logical_rows;
    out.n_rows = shard.pin.n_rows;
    out.relation_value_column = kCopySource;
    out.base_column_indices.resize(
        kCopyRemaining + 1);
    std::iota(
        out.base_column_indices.begin(),
        out.base_column_indices.end(), 0);
    out.prechallenge_column_roots.reserve(
        out.base_column_indices.size());
    for (uint32_t column :
         out.base_column_indices) {
        out.prechallenge_column_roots.push_back(
            air_quotient::AirCommittedValuesRoot<Fp3>(
                columns[column], shard.pin.n_rows));
    }
    out.relation_value_column_root =
        out.prechallenge_column_roots[
            kCopySource];
    if (out.relation_value_column_root !=
            shard.pin.column_roots[0].root ||
        out.prechallenge_column_roots[
            kCopyDestination] !=
            shard.pin.column_roots[1].root) {
        out = {};
        return Fail(
            why, "copy_receiver:value_root_alias");
    }
    out.base_row_commitment =
        ComputeRCStage3ProducerBusBaseCommitmentV1(
            out.schedule,
            out.base_column_indices,
            out.prechallenge_column_roots);
    out.public_challenge_seed =
        public_challenge_seed;
    if (out.relation_commitment.IsNull() ||
        out.base_row_commitment.IsNull() ||
        !DeriveRCStage3ProducerBusChallengesV1(
            public_challenge_seed, out.schedule,
            out.base_row_commitment,
            out.challenges, why)) {
        out = {};
        return false;
    }

    Fp3 running1 = Fp3::Zero();
    Fp3 running2 = Fp3::Zero();
    for (uint32_t row = 0;
         row < shard.pin.n_rows; ++row) {
        std::vector<Fp3> row_values(
            kCopyReceiverColumns,
            Fp3::Zero());
        for (uint32_t column = 0;
             column < kCopyReceiverColumns;
             ++column) {
            row_values[column] =
                columns[column][row];
        }
        const Fp3 denominator1 =
            gkr_field::Sub(
                out.challenges.alpha1,
                CompressCopyReceiverTuple(
                    row_values,
                    out.challenges, false));
        const Fp3 denominator2 =
            gkr_field::Sub(
                out.challenges.alpha2,
                CompressCopyReceiverTuple(
                    row_values,
                    out.challenges, true));
        if (gkr_field::IsZero(denominator1) ||
            gkr_field::IsZero(denominator2)) {
            out = {};
            return Fail(
                why,
                "copy_receiver:challenge_collision");
        }
        const Fp3 inverse1 =
            gkr_field::Inv(denominator1);
        const Fp3 inverse2 =
            gkr_field::Inv(denominator2);
        const Fp3 active =
            columns[kCopyActive][row];
        const Fp3 term1 =
            gkr_field::Neg(gkr_field::Mul(
                active, inverse1));
        const Fp3 term2 =
            gkr_field::Neg(gkr_field::Mul(
                active, inverse2));
        columns[kCopyInverse1][row] = inverse1;
        columns[kCopyInverse2][row] = inverse2;
        columns[kCopyTerm1][row] = term1;
        columns[kCopyTerm2][row] = term2;
        columns[kCopyRunning1][row] = running1;
        columns[kCopyRunning2][row] = running2;
        running1 =
            gkr_field::Add(running1, term1);
        running2 =
            gkr_field::Add(running2, term2);
    }
    out.terminal = {running1, running2};
    out.terminal_running_columns = {
        kCopyRunning1, kCopyRunning2};
    out.terminal_term_columns = {
        kCopyTerm1, kCopyTerm2};
    out.public_fs_seed = CopyReceiverFsSeed(out);
    const auto cs =
        BuildCopyReceiverConstraintSystem(
            out.schedule, out.challenges,
            out.terminal);
    if (out.public_fs_seed.IsNull() ||
        cs.n_columns != kCopyReceiverColumns ||
        cs.QuotientLen() > shard.pin.n_rows) {
        out = {};
        return Fail(
            why, "copy_receiver:constraint_system");
    }
    const auto proved =
        air_quotient::AirQuotientProve<Fp3>(
            cs, columns, out.public_fs_seed, {});
    if (!proved.ok || !proved.division_exact) {
        out = {};
        return Fail(
            why, "copy_receiver:prove:" +
                proved.note);
    }
    out.proof = proved.proof;
    out.terminal_running_column_roots = {
        out.proof.batch.columns[
            kCopyRunning1].root,
        out.proof.batch.columns[
            kCopyRunning2].root};
    out.terminal_term_column_roots = {
        out.proof.batch.columns[
            kCopyTerm1].root,
        out.proof.batch.columns[
            kCopyTerm2].root};
    if (!SerializeRCStage3ProducerBusProofV1(
            out.proof,
            out.canonical_proof_bytes, why)) {
        out = {};
        return false;
    }
    out.proof_commitment =
        ComputeRCStage3ProducerBusProofCommitmentV1(
            out.canonical_proof_bytes);
    out.receipt_commitment =
        ComputeRCStage3ProducerBusReceiptCommitmentV1(
            out);
    if (out.receipt_commitment.IsNull() ||
        !VerifyRCStage3EpisodeWiringCopyReceiverBusReceiptV1(
            expected, product, shard_index,
            public_challenge_seed, out, why)) {
        out = {};
        return false;
    }
    return true;
}

RCStage3ProducerBusVerificationInputV1
BuildRCStage3EpisodeWiringCopyReceiverBusVerificationInputV1(
    const RCStage3EpisodeWiringCopyScheduleEntry& expected,
    const RCStage3EpisodeWiringCopyEdgeProduct& product,
    uint32_t shard_index,
    const uint256& expected_public_challenge_seed,
    const RCStage3ProducerBusReceiptV1& receipt)
{
    RCStage3ProducerBusVerificationInputV1 out;
    if (!SameScheduleIdentity(
            product.schedule, expected) ||
        shard_index >= product.relation_shards.size()) {
        out.note =
            "stage3:episode_relation_product:"
            "copy_receiver_input_identity";
        return out;
    }
    const auto& shard =
        product.relation_shards[shard_index];
    const auto canonical_schedule =
        CopyReceiverSchedule(expected, shard);
    if (!canonical_schedule.has_value()) {
        out.note =
            "stage3:episode_relation_product:"
            "copy_receiver_input_schedule";
        return out;
    }
    out.expected_relation_role =
        RCStage3RelationRole::EpisodeWiring;
    out.expected_statement_commitment =
        shard.pin.statement_commitment;
    out.expected_relation_commitment =
        CopyReceiverRelationCommitment(
            product, shard);
    out.expected_schedule =
        *canonical_schedule;
    out.expected_logical_rows =
        shard.pin.logical_rows;
    out.expected_n_rows =
        shard.pin.n_rows;
    out.expected_relation_value_column =
        kCopySource;
    out.expected_terminal_running_columns = {
        kCopyRunning1, kCopyRunning2};
    out.expected_terminal_term_columns = {
        kCopyTerm1, kCopyTerm2};
    out.expected_cs =
        BuildCopyReceiverConstraintSystem(
            out.expected_schedule,
            receipt.challenges,
            receipt.terminal);
    out.expected_base_column_indices.resize(
        kCopyRemaining + 1);
    std::iota(
        out.expected_base_column_indices.begin(),
        out.expected_base_column_indices.end(), 0);
    out.expected_public_challenge_seed =
        expected_public_challenge_seed;
    out.expected_public_fs_seed =
        CopyReceiverFsSeed(receipt);
    out.valid =
        !out.expected_statement_commitment.IsNull() &&
        !out.expected_relation_commitment.IsNull() &&
        out.expected_schedule.schedule_commitment ==
            ComputeRCStage3ProducerBusScheduleCommitmentV1(
                out.expected_schedule) &&
        out.expected_cs.n_columns ==
            kCopyReceiverColumns &&
        !out.expected_public_challenge_seed.IsNull() &&
        !out.expected_public_fs_seed.IsNull();
    out.note = out.valid
        ? "stage3:episode_relation_product:"
          "copy_receiver_input_ok"
        : "stage3:episode_relation_product:"
          "copy_receiver_input_invalid";
    return out;
}

bool VerifyRCStage3EpisodeWiringCopyReceiverBusReceiptV1(
    const RCStage3EpisodeWiringCopyScheduleEntry& expected,
    const RCStage3EpisodeWiringCopyEdgeProduct& product,
    uint32_t shard_index,
    const uint256& expected_public_challenge_seed,
    const RCStage3ProducerBusReceiptV1& receipt,
    std::string* why)
{
    const auto input =
        BuildRCStage3EpisodeWiringCopyReceiverBusVerificationInputV1(
            expected, product, shard_index,
            expected_public_challenge_seed,
            receipt);
    if (!input.valid ||
        shard_index >= product.relation_shards.size()) {
        return Fail(
            why, "copy_receiver:verify_input");
    }
    const auto& shard =
        product.relation_shards[shard_index];
    if (shard.pin.column_roots.size() != 2 ||
        receipt.relation_value_column_root !=
            shard.pin.column_roots[0].root ||
        receipt.proof.batch.columns.size() <=
            kCopyDestination ||
        receipt.proof.batch.columns[
            kCopyDestination].root !=
            shard.pin.column_roots[1].root) {
        return Fail(
            why, "copy_receiver:verify_root_alias");
    }
    return VerifyRCStage3ProducerBusReceiptV1(
        receipt, input, why);
}

std::vector<RCStage3EpisodeRelationProductEndpointStatus>
CurrentRCStage3EpisodeRelationProductEndpointStatus()
{
    using E = RCStage3RelationEndpoint;
    return {
        {E::EpisodeGemmOperandA, true, true, false, false, false, false,
         "the local A column is only the sumcheck chain-end opening; "
         "full matrix A openings and the executed sumcheck are not joined"},
        {E::EpisodeGemmOperandB, true, true, false, false, false, false,
         "the local B column is only the sumcheck chain-end opening; "
         "full matrix B openings and the executed sumcheck are not joined"},
        {E::EpisodeGemmOutputY, true, true, false, false, false, false,
         "gf=a*b does not prove Y=A*B; the manifest-wide sumcheck and "
         "claim-to-Y opening remain"},
        {E::EpisodeExtractSampler, true, true, false, false, false, false,
         "RcSampler proves one fixed-program tile; segmented all-tile "
         "boundaries and degree-aligned flat-memory aliases remain"},
        {E::EpisodeExtractOutput, true, true, false, false, false, false,
         "the sampler output column is local; every tile output is not yet "
         "aggregated into each manifest extract-output root"},
        {E::EpisodeWiringCopy, true, true, true, true, false, false,
         "the complete local equality product executes, but the manifest "
         "operand root still needs equality to the executed producer/root "
         "graph before strict semantic closure"},
    };
}

} // namespace matmul::v4::rc
