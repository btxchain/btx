// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_tiletree_digest_terminal.h>

#include <hash.h>

#include <array>
#include <limits>
#include <numeric>
#include <utility>
#include <vector>

namespace matmul::v4::rc::episode_tiletree_digest_terminal {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
using gf::Fp3;

constexpr char kProducerRelationDomain[] =
    "BTX_RC_STAGE3_TILETREE_DIGEST_PRODUCER_RELATION_V1";
constexpr char kConsumerRelationDomain[] =
    "BTX_RC_STAGE3_TILETREE_DIGEST_CONSUMER_RELATION_V1";
constexpr char kFsDomain[] =
    "BTX_RC_STAGE3_TILETREE_DIGEST_RECEIPT_FS_V1";
constexpr char kProductDomain[] =
    "BTX_RC_STAGE3_TILETREE_DIGEST_TERMINAL_PRODUCT_V1";
constexpr uint64_t kAddressBegin =
    UINT64_C(0x5452444700000000);

enum Column : uint32_t {
    VALUE = 0,
    EXPECTED,
    ACTIVE,
    ENDPOINT,
    SEMANTIC_ROLE,
    ADDRESS,
    REMAINING,
    INVERSE1,
    INVERSE2,
    TERM1,
    TERM2,
    RUNNING1,
    RUNNING2,
    COLUMNS,
};

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:episode_tiletree_digest_terminal:" +
            detail;
    }
    return false;
}

void HashFp3(HashWriter& hash, const Fp3& value)
{
    hash << gf::Canonical(value.c0);
    hash << gf::Canonical(value.c1);
    hash << gf::Canonical(value.c2);
}

bool IsEpisodeStatement(const RCStage3SuccinctProof& statement)
{
    return statement.statement ==
               RCStage3StatementKind::Episode ||
        statement.statement ==
               RCStage3StatementKind::Composed;
}

std::vector<uint8_t> ProducerRootBytes(
    const RCStage3EpisodeRoundRootProducerProduct& product)
{
    std::vector<uint8_t> out;
    if (product.rounds.size() != kProductionRoundsV1) {
        return out;
    }
    out.reserve(kProductionLogicalRowsV1);
    for (uint32_t round = 0;
         round < product.rounds.size(); ++round) {
        const auto& item = product.rounds[round];
        if (item.round_index != round ||
            item.tree_manifest.root.IsNull()) {
            out.clear();
            return out;
        }
        out.insert(
            out.end(),
            item.tree_manifest.root.begin(),
            item.tree_manifest.root.end());
    }
    return out;
}

std::vector<uint8_t> ConsumerRootBytes(
    const digest::ProductV1& product)
{
    std::vector<uint8_t> out;
    if (product.manifest.round_roots.size() !=
            kProductionRoundsV1) {
        return out;
    }
    out.reserve(kProductionLogicalRowsV1);
    for (const auto& root :
         product.manifest.round_roots) {
        if (root.IsNull()) {
            out.clear();
            return out;
        }
        out.insert(
            out.end(), root.begin(), root.end());
    }
    return out;
}

uint256 ProducerRelationCommitment(
    const RCStage3EpisodeRoundRootProducerProduct& product)
{
    if (product.expected_rounds != kProductionRoundsV1 ||
        product.rounds.size() != kProductionRoundsV1 ||
        product.collection_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << kProducerRelationDomain << kVersionV1;
    hash << product.statement_commitment;
    hash << product.digest_manifest_commitment;
    hash << product.collection_commitment;
    hash << product.expected_rounds;
    for (const auto& round : product.rounds) {
        hash << round.round_index;
        hash << round.tree_manifest.commitment;
        hash << round.tree_manifest.root;
        hash << round.hash_binding.memory_manifest.
            manifest_commitment;
    }
    return hash.GetHash();
}

uint256 ConsumerRelationCommitment(
    const digest::ProductV1& product)
{
    if (product.product_commitment.IsNull() ||
        product.manifest.commitment.IsNull() ||
        product.endpoint_binding_root.IsNull() ||
        product.manifest.round_roots.size() !=
            kProductionRoundsV1) {
        return {};
    }
    HashWriter hash;
    hash << kConsumerRelationDomain << kVersionV1;
    hash << product.statement_commitment;
    hash << product.product_commitment;
    hash << product.manifest.commitment;
    hash << product.endpoint_binding_root;
    hash << static_cast<uint32_t>(
        product.manifest.round_roots.size());
    return hash.GetHash();
}

RCStage3ProducerBusScheduleV1 Schedule(int8_t multiplicity)
{
    RCStage3ProducerBusScheduleV1 out;
    out.bus_id = kBusIdV1;
    out.logical_rows = kProductionLogicalRowsV1;
    out.events.resize(kProductionLogicalRowsV1);
    for (uint32_t row = 0;
         row < kProductionLogicalRowsV1; ++row) {
        auto& event = out.events[row];
        event.active = true;
        event.endpoint =
            RCStage3RelationEndpoint::
                EpisodeDigestRoundRoots;
        event.semantic_role =
            RCStage3RelationRole::EpisodeTileTree;
        event.address = kAddressBegin + row;
        event.remaining =
            kProductionLogicalRowsV1 - row;
        event.multiplicity = multiplicity;
    }
    out.schedule_commitment =
        ComputeRCStage3ProducerBusScheduleCommitmentV1(
            out);
    return out;
}

Fp3 Compress(
    const std::vector<Fp3>& row,
    const RCStage3CtlChallenges& challenges,
    bool second_lane)
{
    const Fp3& gamma = second_lane
        ? challenges.gamma2
        : challenges.gamma1;
    const Fp3 gamma2 = gf::Mul(gamma, gamma);
    const Fp3 gamma3 = gf::Mul(gamma2, gamma);
    const Fp3 gamma4 = gf::Mul(gamma3, gamma);
    return gf::Add(
        row[ENDPOINT],
        gf::Add(
            gf::Mul(gamma, row[SEMANTIC_ROLE]),
            gf::Add(
                gf::Mul(gamma2, row[ADDRESS]),
                gf::Add(
                    gf::Mul(gamma3, row[REMAINING]),
                    gf::Mul(gamma4, row[VALUE])))));
}

aq::AirConstraintSystem<Fp3> BuildConstraintSystem(
    const std::vector<uint8_t>& expected,
    const RCStage3ProducerBusScheduleV1& schedule,
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal,
    int8_t multiplicity)
{
    aq::AirConstraintSystem<Fp3> cs;
    if (expected.size() != kProductionLogicalRowsV1 ||
        schedule.logical_rows !=
            kProductionLogicalRowsV1 ||
        schedule.events.size() !=
            kProductionLogicalRowsV1 ||
        schedule.schedule_commitment !=
            ComputeRCStage3ProducerBusScheduleCommitmentV1(
                schedule) ||
        (multiplicity != 1 && multiplicity != -1)) {
        return cs;
    }
    cs.n_rows = kProductionLogicalRowsV1;
    cs.n_columns = COLUMNS;
    cs.preprocessed_pin_ood = true;
    std::array<std::vector<Fp3>, 6> fixed;
    for (auto& column : fixed) {
        column.assign(cs.n_rows, Fp3::Zero());
    }
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        const auto& event = schedule.events[row];
        if (!event.active ||
            event.multiplicity != multiplicity) {
            return {};
        }
        fixed[0][row] = gf::FromU64_3(expected[row]);
        fixed[1][row] = Fp3::One();
        fixed[2][row] = gf::FromU64_3(
            static_cast<uint16_t>(event.endpoint));
        fixed[3][row] = gf::FromU64_3(
            static_cast<uint16_t>(
                event.semantic_role));
        fixed[4][row] = gf::FromU64_3(event.address);
        fixed[5][row] = gf::FromU64_3(event.remaining);
    }
    for (uint32_t i = 0; i < fixed.size(); ++i) {
        cs.preprocessed.push_back(
            {EXPECTED + i, std::move(fixed[i])});
    }
    const auto add = [&cs](
        const char* name, aq::AirKind kind,
        uint32_t degree,
        std::function<Fp3(
            const std::vector<Fp3>&,
            const std::vector<Fp3>&)> eval) {
        cs.constraints.push_back(
            {name, kind, degree, std::move(eval)});
    };
    add(
        "stage3.tiletree_digest.value_expected",
        aq::AirKind::kEverywhere, 1,
        [](const auto& row, const auto&) {
            return gf::Sub(
                row[VALUE], row[EXPECTED]);
        });
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const uint32_t inverse =
            lane == 0 ? INVERSE1 : INVERSE2;
        const uint32_t term =
            lane == 0 ? TERM1 : TERM2;
        const uint32_t running =
            lane == 0 ? RUNNING1 : RUNNING2;
        const Fp3 alpha =
            lane == 0
                ? challenges.alpha1
                : challenges.alpha2;
        const Fp3 terminal_value =
            lane == 0
                ? terminal.alpha1_sum
                : terminal.alpha2_sum;
        add(
            "stage3.tiletree_digest.inverse",
            aq::AirKind::kEverywhere, 2,
            [inverse, alpha, challenges, lane](
                const auto& row, const auto&) {
                return gf::Sub(
                    gf::Mul(
                        row[inverse],
                        gf::Sub(
                            alpha,
                            Compress(
                                row, challenges,
                                lane != 0))),
                    Fp3::One());
            });
        add(
            "stage3.tiletree_digest.term",
            aq::AirKind::kEverywhere, 2,
            [inverse, term, multiplicity](
                const auto& row, const auto&) {
                const Fp3 value = gf::Mul(
                    row[ACTIVE], row[inverse]);
                return gf::Sub(
                    row[term],
                    multiplicity == 1
                        ? value
                        : gf::Neg(value));
            });
        add(
            "stage3.tiletree_digest.running_first",
            aq::AirKind::kFirstRow, 1,
            [running](const auto& row, const auto&) {
                return row[running];
            });
        add(
            "stage3.tiletree_digest.running_transition",
            aq::AirKind::kTransition, 1,
            [running, term](
                const auto& row, const auto& next) {
                return gf::Sub(
                    next[running],
                    gf::Add(row[running], row[term]));
            });
        add(
            "stage3.tiletree_digest.running_last",
            aq::AirKind::kLastRow, 1,
            [running, term, terminal_value](
                const auto& row, const auto&) {
                return gf::Sub(
                    gf::Add(row[running], row[term]),
                    terminal_value);
            });
    }
    if (cs.QuotientLen() > cs.n_rows) return {};
    return cs;
}

struct PreparedReceipt {
    RCStage3RelationRole relation_role{};
    uint256 statement_commitment{};
    uint256 relation_commitment{};
    RCStage3ProducerBusScheduleV1 schedule;
    std::vector<uint8_t> expected;
    std::vector<std::vector<Fp3>> columns;
    std::vector<uint32_t> base_column_indices;
    std::vector<uint256> prechallenge_column_roots;
    uint256 base_row_commitment{};
    int8_t multiplicity{0};
};

bool PrepareReceipt(
    RCStage3RelationRole relation_role,
    const uint256& statement_commitment,
    const uint256& relation_commitment,
    std::vector<uint8_t> expected,
    int8_t multiplicity,
    PreparedReceipt& out,
    std::string* why)
{
    out = {};
    if (statement_commitment.IsNull() ||
        relation_commitment.IsNull() ||
        expected.size() != kProductionLogicalRowsV1 ||
        (multiplicity != 1 && multiplicity != -1)) {
        return Fail(why, "prepare_shape");
    }
    out.relation_role = relation_role;
    out.statement_commitment = statement_commitment;
    out.relation_commitment = relation_commitment;
    out.schedule = Schedule(multiplicity);
    out.expected = std::move(expected);
    out.multiplicity = multiplicity;
    out.columns.assign(
        COLUMNS,
        std::vector<Fp3>(
            kProductionLogicalRowsV1,
            Fp3::Zero()));
    for (uint32_t row = 0;
         row < kProductionLogicalRowsV1; ++row) {
        const auto& event = out.schedule.events[row];
        out.columns[VALUE][row] =
            gf::FromU64_3(out.expected[row]);
        out.columns[EXPECTED][row] =
            gf::FromU64_3(out.expected[row]);
        out.columns[ACTIVE][row] = Fp3::One();
        out.columns[ENDPOINT][row] =
            gf::FromU64_3(
                static_cast<uint16_t>(event.endpoint));
        out.columns[SEMANTIC_ROLE][row] =
            gf::FromU64_3(
                static_cast<uint16_t>(
                    event.semantic_role));
        out.columns[ADDRESS][row] =
            gf::FromU64_3(event.address);
        out.columns[REMAINING][row] =
            gf::FromU64_3(event.remaining);
    }
    out.base_column_indices.resize(REMAINING + 1);
    std::iota(
        out.base_column_indices.begin(),
        out.base_column_indices.end(), 0);
    out.prechallenge_column_roots.reserve(
        out.base_column_indices.size());
    for (uint32_t column :
         out.base_column_indices) {
        out.prechallenge_column_roots.push_back(
            aq::AirCommittedValuesRoot<Fp3>(
                out.columns[column],
                kProductionLogicalRowsV1));
    }
    out.base_row_commitment =
        ComputeRCStage3ProducerBusBaseCommitmentV1(
            out.schedule,
            out.base_column_indices,
            out.prechallenge_column_roots);
    return (!out.schedule.schedule_commitment.IsNull() &&
            !out.base_row_commitment.IsNull()) ||
        Fail(why, "prepare_commitment");
}

uint256 ReceiptFsSeed(
    const PreparedReceipt& prepared,
    const uint256& challenge_seed,
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal)
{
    if (prepared.statement_commitment.IsNull() ||
        prepared.relation_commitment.IsNull() ||
        prepared.schedule.schedule_commitment.IsNull() ||
        prepared.base_row_commitment.IsNull() ||
        challenge_seed.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << kFsDomain << kVersionV1;
    hash << static_cast<uint16_t>(
        prepared.relation_role);
    hash << prepared.statement_commitment;
    hash << prepared.relation_commitment;
    hash << prepared.schedule.schedule_commitment;
    hash << prepared.base_row_commitment;
    hash << challenge_seed;
    HashFp3(hash, challenges.gamma1);
    HashFp3(hash, challenges.gamma2);
    HashFp3(hash, challenges.alpha1);
    HashFp3(hash, challenges.alpha2);
    HashFp3(hash, terminal.alpha1_sum);
    HashFp3(hash, terminal.alpha2_sum);
    return hash.GetHash();
}

bool ProveReceipt(
    PreparedReceipt prepared,
    const uint256& challenge_seed,
    RCStage3ProducerBusReceiptV1& out,
    std::string* why)
{
    out = {};
    RCStage3CtlChallenges challenges;
    if (!DeriveRCStage3ProducerBusChallengesV1(
            challenge_seed, prepared.schedule,
            prepared.base_row_commitment,
            challenges, why)) {
        return false;
    }
    Fp3 running1 = Fp3::Zero();
    Fp3 running2 = Fp3::Zero();
    for (uint32_t row = 0;
         row < kProductionLogicalRowsV1; ++row) {
        const Fp3 denominator1 = gf::Sub(
            challenges.alpha1,
            Compress(
                std::vector<Fp3>{
                    prepared.columns[0][row],
                    prepared.columns[1][row],
                    prepared.columns[2][row],
                    prepared.columns[3][row],
                    prepared.columns[4][row],
                    prepared.columns[5][row],
                    prepared.columns[6][row],
                },
                challenges, false));
        const Fp3 denominator2 = gf::Sub(
            challenges.alpha2,
            Compress(
                std::vector<Fp3>{
                    prepared.columns[0][row],
                    prepared.columns[1][row],
                    prepared.columns[2][row],
                    prepared.columns[3][row],
                    prepared.columns[4][row],
                    prepared.columns[5][row],
                    prepared.columns[6][row],
                },
                challenges, true));
        if (gf::IsZero(denominator1) ||
            gf::IsZero(denominator2)) {
            return Fail(why, "challenge_collision");
        }
        const Fp3 inverse1 = gf::Inv(denominator1);
        const Fp3 inverse2 = gf::Inv(denominator2);
        const Fp3 term1 = prepared.multiplicity == 1
            ? inverse1 : gf::Neg(inverse1);
        const Fp3 term2 = prepared.multiplicity == 1
            ? inverse2 : gf::Neg(inverse2);
        prepared.columns[INVERSE1][row] = inverse1;
        prepared.columns[INVERSE2][row] = inverse2;
        prepared.columns[TERM1][row] = term1;
        prepared.columns[TERM2][row] = term2;
        prepared.columns[RUNNING1][row] = running1;
        prepared.columns[RUNNING2][row] = running2;
        running1 = gf::Add(running1, term1);
        running2 = gf::Add(running2, term2);
    }
    const RCStage3CtlTerminal terminal{
        running1, running2};
    const uint256 fs_seed = ReceiptFsSeed(
        prepared, challenge_seed,
        challenges, terminal);
    const auto cs = BuildConstraintSystem(
        prepared.expected, prepared.schedule,
        challenges, terminal,
        prepared.multiplicity);
    if (fs_seed.IsNull() ||
        cs.n_columns != COLUMNS ||
        cs.n_rows != kProductionLogicalRowsV1) {
        return Fail(why, "receipt_constraint_system");
    }
    const auto proved = aq::AirQuotientProve<Fp3>(
        cs, prepared.columns, fs_seed, {});
    if (!proved.ok || !proved.division_exact) {
        return Fail(
            why, "receipt_prove:" + proved.note);
    }
    out.relation_role = prepared.relation_role;
    out.statement_commitment =
        prepared.statement_commitment;
    out.relation_commitment =
        prepared.relation_commitment;
    out.schedule = prepared.schedule;
    out.challenges = challenges;
    out.terminal = terminal;
    out.logical_rows = kProductionLogicalRowsV1;
    out.n_rows = kProductionLogicalRowsV1;
    out.relation_value_column = VALUE;
    out.relation_value_column_root =
        proved.proof.batch.columns[VALUE].root;
    out.base_row_commitment =
        prepared.base_row_commitment;
    out.base_column_indices =
        prepared.base_column_indices;
    out.prechallenge_column_roots =
        prepared.prechallenge_column_roots;
    out.terminal_running_columns = {
        RUNNING1, RUNNING2};
    out.terminal_term_columns = {TERM1, TERM2};
    out.terminal_running_column_roots = {
        proved.proof.batch.columns[RUNNING1].root,
        proved.proof.batch.columns[RUNNING2].root};
    out.terminal_term_column_roots = {
        proved.proof.batch.columns[TERM1].root,
        proved.proof.batch.columns[TERM2].root};
    out.public_challenge_seed = challenge_seed;
    out.public_fs_seed = fs_seed;
    out.proof = proved.proof;
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
    return !out.receipt_commitment.IsNull() ||
        Fail(why, "receipt_commitment");
}

RCStage3ProducerBusVerificationInputV1 VerificationInput(
    const PreparedReceipt& prepared,
    const uint256& challenge_seed,
    const RCStage3ProducerBusReceiptV1& receipt)
{
    RCStage3ProducerBusVerificationInputV1 out;
    out.expected_relation_role =
        prepared.relation_role;
    out.expected_statement_commitment =
        prepared.statement_commitment;
    out.expected_relation_commitment =
        prepared.relation_commitment;
    out.expected_schedule = prepared.schedule;
    out.expected_logical_rows =
        kProductionLogicalRowsV1;
    out.expected_n_rows =
        kProductionLogicalRowsV1;
    out.expected_relation_value_column = VALUE;
    out.expected_terminal_running_columns = {
        RUNNING1, RUNNING2};
    out.expected_terminal_term_columns = {
        TERM1, TERM2};
    out.expected_cs = BuildConstraintSystem(
        prepared.expected, prepared.schedule,
        receipt.challenges, receipt.terminal,
        prepared.multiplicity);
    out.expected_base_column_indices =
        prepared.base_column_indices;
    out.expected_public_challenge_seed =
        challenge_seed;
    out.expected_public_fs_seed =
        ReceiptFsSeed(
            prepared, challenge_seed,
            receipt.challenges, receipt.terminal);
    out.valid =
        out.expected_cs.n_columns == COLUMNS &&
        out.expected_cs.n_rows ==
            kProductionLogicalRowsV1 &&
        !out.expected_public_challenge_seed.IsNull() &&
        !out.expected_public_fs_seed.IsNull();
    out.note = out.valid
        ? "stage3:episode_tiletree_digest_terminal:"
          "verification_input_ok"
        : "stage3:episode_tiletree_digest_terminal:"
          "verification_input_invalid";
    return out;
}

uint256 JointChallengeSeed(
    const uint256& statement_commitment,
    const PreparedReceipt& producer,
    const PreparedReceipt& consumer)
{
    return ComputeRCStage3ProducerBusChallengeSeedV1(
        statement_commitment, kBusIdV1,
        {
            {producer.relation_role,
             producer.schedule.schedule_commitment,
             producer.base_row_commitment},
            {consumer.relation_role,
             consumer.schedule.schedule_commitment,
             consumer.base_row_commitment},
        });
}

bool VerifyOwners(
    const RCStage3SuccinctProof& statement,
    const digest::TapeChallengeContextV1& tape_context,
    const RCStage3EpisodeRoundRootProducerProduct& tiletree_product,
    const digest::ProductV1& digest_product,
    std::string* why)
{
    if (!IsEpisodeStatement(statement) ||
        tiletree_product.expected_rounds !=
            kProductionRoundsV1 ||
        tiletree_product.rounds.size() !=
            kProductionRoundsV1 ||
        digest_product.manifest.round_roots.size() !=
            kProductionRoundsV1 ||
        tiletree_product.digest_manifest_commitment !=
            digest_product.manifest.commitment ||
        digest_product.endpoint_root_chain.manifest !=
            digest_product.manifest ||
        !digest::VerifyProductV1(
            statement, tape_context,
            digest_product, why) ||
        !VerifyRCStage3EpisodeRoundRootProducerProduct(
            statement, kProductionRoundsV1,
            digest_product.manifest,
            digest_product.endpoint_root_chain.
                round_roots_pin,
            digest_product.endpoint_root_chain.
                round_roots_proof,
            tiletree_product, why)) {
        return Fail(why, "owning_products");
    }
    return true;
}

} // namespace

uint256 CommitProductV1(const ProductV1& product)
{
    if (product.version != kVersionV1 ||
        product.statement_commitment.IsNull() ||
        product.tiletree_collection_commitment.IsNull() ||
        product.digest_product_commitment.IsNull() ||
        product.round_count != kProductionRoundsV1 ||
        product.logical_rows !=
            kProductionLogicalRowsV1 ||
        product.public_challenge_seed.IsNull() ||
        product.producer.receipt_commitment.IsNull() ||
        product.consumer.receipt_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << kProductDomain << product.version;
    hash << product.statement_commitment;
    hash << product.tiletree_collection_commitment;
    hash << product.digest_product_commitment;
    hash << product.round_count;
    hash << product.logical_rows;
    hash << product.public_challenge_seed;
    hash << product.producer.receipt_commitment;
    hash << product.consumer.receipt_commitment;
    hash << product.exact_all_round_inventory;
    hash << product.proof_owned_terminal_pair;
    hash << product.normalized_recursive_consumed;
    hash << product.production_authority;
    return hash.GetHash();
}

bool ProveProductV1(
    const RCStage3SuccinctProof& statement,
    const digest::TapeChallengeContextV1& tape_context,
    const RCStage3EpisodeRoundRootProducerProduct& tiletree_product,
    const digest::ProductV1& digest_product,
    ProductV1& out,
    std::string* why)
{
    out = {};
    if (!VerifyOwners(
            statement, tape_context,
            tiletree_product, digest_product, why)) {
        return false;
    }
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    PreparedReceipt producer;
    PreparedReceipt consumer;
    if (!PrepareReceipt(
            RCStage3RelationRole::EpisodeTileTree,
            statement_commitment,
            ProducerRelationCommitment(tiletree_product),
            ProducerRootBytes(tiletree_product), 1,
            producer, why) ||
        !PrepareReceipt(
            RCStage3RelationRole::EpisodeDigest,
            statement_commitment,
            ConsumerRelationCommitment(digest_product),
            ConsumerRootBytes(digest_product), -1,
            consumer, why)) {
        return false;
    }
    const uint256 challenge_seed =
        JointChallengeSeed(
            statement_commitment, producer, consumer);
    if (challenge_seed.IsNull() ||
        !ProveReceipt(
            std::move(producer), challenge_seed,
            out.producer, why) ||
        !ProveReceipt(
            std::move(consumer), challenge_seed,
            out.consumer, why)) {
        out = {};
        return Fail(why, "prove_receipts");
    }
    out.statement_commitment = statement_commitment;
    out.tiletree_collection_commitment =
        tiletree_product.collection_commitment;
    out.digest_product_commitment =
        digest_product.product_commitment;
    out.round_count = kProductionRoundsV1;
    out.logical_rows = kProductionLogicalRowsV1;
    out.public_challenge_seed = challenge_seed;
    out.exact_all_round_inventory = true;
    out.proof_owned_terminal_pair = true;
    out.normalized_recursive_consumed = false;
    out.production_authority = false;
    out.note =
        "stage3:episode_tiletree_digest_terminal:"
        "all_8_round_roots_cancel_in_dual_fp3;"
        "normalized_parent_consumption_open";
    out.product_commitment = CommitProductV1(out);
    if (out.product_commitment.IsNull() ||
        !VerifyProductV1(
            statement, tape_context,
            tiletree_product, digest_product,
            out, why)) {
        out = {};
        return Fail(why, "prove_self_verify");
    }
    return true;
}

bool VerifyProductV1(
    const RCStage3SuccinctProof& statement,
    const digest::TapeChallengeContextV1& tape_context,
    const RCStage3EpisodeRoundRootProducerProduct& tiletree_product,
    const digest::ProductV1& digest_product,
    const ProductV1& product,
    std::string* why)
{
    if (product.version != kVersionV1 ||
        !product.exact_all_round_inventory ||
        !product.proof_owned_terminal_pair ||
        product.normalized_recursive_consumed ||
        product.production_authority ||
        !VerifyOwners(
            statement, tape_context,
            tiletree_product, digest_product, why)) {
        return Fail(why, "product_or_owners");
    }
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    PreparedReceipt producer;
    PreparedReceipt consumer;
    if (!PrepareReceipt(
            RCStage3RelationRole::EpisodeTileTree,
            statement_commitment,
            ProducerRelationCommitment(tiletree_product),
            ProducerRootBytes(tiletree_product), 1,
            producer, why) ||
        !PrepareReceipt(
            RCStage3RelationRole::EpisodeDigest,
            statement_commitment,
            ConsumerRelationCommitment(digest_product),
            ConsumerRootBytes(digest_product), -1,
            consumer, why)) {
        return false;
    }
    const uint256 challenge_seed =
        JointChallengeSeed(
            statement_commitment, producer, consumer);
    const auto producer_input =
        VerificationInput(
            producer, challenge_seed,
            product.producer);
    const auto consumer_input =
        VerificationInput(
            consumer, challenge_seed,
            product.consumer);
    if (product.statement_commitment !=
            statement_commitment ||
        product.tiletree_collection_commitment !=
            tiletree_product.collection_commitment ||
        product.digest_product_commitment !=
            digest_product.product_commitment ||
        product.round_count != kProductionRoundsV1 ||
        product.logical_rows !=
            kProductionLogicalRowsV1 ||
        product.public_challenge_seed !=
            challenge_seed ||
        !producer_input.valid ||
        !consumer_input.valid ||
        !VerifyRCStage3ProducerBusTerminalPairV1(
            product.producer, producer_input,
            product.consumer, consumer_input,
            challenge_seed, why) ||
        product.product_commitment.IsNull() ||
        product.product_commitment !=
            CommitProductV1(product)) {
        return Fail(why, "terminal_pair_or_commitment");
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_tiletree_digest_terminal:"
            "proof_owned_8_round_terminal_pair_verified;"
            "recursive_parent_open";
    }
    return true;
}

} // namespace matmul::v4::rc::episode_tiletree_digest_terminal
