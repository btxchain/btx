// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paymesh.h>

#include <modelnet/swarm_codec.h>
#include <crypto/sha256.h>
#include <pqkey.h>
#include <script/pqm.h>
#include <script/script.h>
#include <span.h>
#include <util/strencodings.h>

#include <algorithm>
#include <string_view>

namespace modelnet {
namespace {

bool DigitsOnly(std::string_view text)
{
    if (text.empty()) return false;
    for (unsigned char c : text) {
        if (c < '0' || c > '9') return false;
    }
    return true;
}

bool CanonicalText(std::string_view text)
{
    for (unsigned char c : text) {
        if (c < 0x20 || c == '"' || c == '\\') return false;
    }
    return true;
}

bool ObjectiveKnown(std::string_view objective)
{
    return objective == "model-improvement" || objective == "specialist-training" || objective == "inference-service" ||
           objective == "evaluation" || objective == "application";
}

std::string BasePoolId(const SwarmSepManifest& manifest)
{
    return SwarmDigest("BTX/SwarmPool/1", SwarmCanonical({
        {"chain", manifest.network},
        {"lineage", manifest.lineage_id},
        {"nonce", manifest.nonce},
        {"objective", manifest.objective_type},
        {"policy", manifest.policy_id},
    }));
}

std::string EpochPoolId(const std::string& pool_id, int epoch)
{
    return SwarmDigest("BTX/SwarmPoolEpoch/1", SwarmCanonical({
        {"epoch", std::to_string(epoch)},
        {"pool", pool_id},
    }));
}

CTxIn PlaceholderInput()
{
    uint256 prev_hash;
    std::fill(prev_hash.begin(), prev_hash.end(), static_cast<unsigned char>(0x11));
    return CTxIn(COutPoint(Txid::FromUint256(prev_hash), 0));
}

std::string Sha256Hex(const std::vector<unsigned char>& bytes)
{
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(hash);
    return HexStr(Span<const unsigned char>(hash, CSHA256::OUTPUT_SIZE));
}

} // namespace

bool SwarmValidateManifest(const SwarmSepManifest& manifest, std::string& err)
{
    if (manifest.protocol != SWARM_SEP_PROTOCOL) {
        err = "PROTOCOL";
        return false;
    }
    if (manifest.wallet_key_custody != SWARM_WALLET_KEY_CUSTODY) {
        err = "CUSTODY";
        return false;
    }
    if (manifest.automatic_spend_atoms != SWARM_AUTOMATIC_SPEND_ATOMS) {
        err = "AUTOMATIC_SPEND";
        return false;
    }
    if (!ObjectiveKnown(manifest.objective_type)) {
        err = "OBJECTIVE";
        return false;
    }
    if (!SwarmFixedId(manifest.lineage_id) || !SwarmFixedId(manifest.checkpoint_id) || !SwarmFixedId(manifest.recipe_id) ||
        !SwarmFixedId(manifest.policy_id) || (!manifest.parent_pool.empty() && !SwarmFixedId(manifest.parent_pool))) {
        err = "ID";
        return false;
    }
    if (manifest.policy_epoch < 1) {
        err = "EPOCH";
        return false;
    }
    if (!DigitsOnly(manifest.gross_budget_atoms)) {
        err = "BUDGET";
        return false;
    }
    if (manifest.network.empty() || !CanonicalText(manifest.network) || !CanonicalText(manifest.nonce)) {
        err = "CANONICAL";
        return false;
    }
    if (BasePoolId(manifest).empty()) {
        err = "POOL_ID";
        return false;
    }
    err.clear();
    return true;
}

std::string SwarmManifestPoolId(const SwarmSepManifest& manifest, std::string& err)
{
    if (!SwarmValidateManifest(manifest, err)) return {};
    const std::string id = BasePoolId(manifest);
    if (id.empty()) {
        err = "POOL_ID";
        return {};
    }
    err.clear();
    return id;
}

std::string SwarmNextEpoch(const SwarmSepManifest& old_manifest, const SwarmSepManifest& new_manifest, std::string& err)
{
    if (!SwarmValidateManifest(old_manifest, err) || !SwarmValidateManifest(new_manifest, err)) return {};
    if (new_manifest.policy_epoch < old_manifest.policy_epoch) {
        err = "EPOCH";
        return {};
    }
    const std::string base = BasePoolId(new_manifest);
    if (base.empty()) {
        err = "POOL_ID";
        return {};
    }
    if (new_manifest.policy_epoch == old_manifest.policy_epoch) {
        err.clear();
        return base;
    }
    const std::string next = EpochPoolId(base, new_manifest.policy_epoch);
    if (next.empty() || next == base) {
        err = "POOL_ID";
        return {};
    }
    err.clear();
    return next;
}

bool SwarmObligationBook::Add(const std::string& pool, const std::string& work_id, int64_t atoms, std::string& err)
{
    if (pool.empty() || work_id.empty() || atoms <= 0) {
        err = "OBLIGATION";
        return false;
    }
    auto& row = m_atoms[pool];
    if (row.count(work_id)) {
        err = "DUPLICATE_WORK";
        return false;
    }
    row.emplace(work_id, atoms);
    err.clear();
    return true;
}

int64_t SwarmObligationBook::Atoms(const std::string& pool, const std::string& work_id) const
{
    const auto pool_it = m_atoms.find(pool);
    if (pool_it == m_atoms.end()) return 0;
    const auto work_it = pool_it->second.find(work_id);
    if (work_it == pool_it->second.end()) return 0;
    return work_it->second;
}

bool SwarmValidateSplit(const SwarmRewardSplit& split, std::string& err)
{
    const int64_t parts[] = {split.rollout_ppm, split.negative_ppm, split.reproduction_ppm,
                             split.evaluation_ppm, split.challenger_ppm, split.milestone_ppm};
    int64_t sum = 0;
    for (int64_t ppm : parts) {
        if (ppm < 0 || ppm > SWARM_PPM_TOTAL) {
            err = "PPM";
            return false;
        }
        sum += ppm;
    }
    if (sum != SWARM_PPM_TOTAL) {
        err = "PPM";
        return false;
    }
    err.clear();
    return true;
}

int64_t SwarmPayShare(int64_t gross, int64_t ppm)
{
    if (gross < 0 || ppm < 0) return 0;
    return static_cast<int64_t>((static_cast<__int128>(gross) * static_cast<__int128>(ppm)) / SWARM_PPM_TOTAL);
}

bool SwarmWinnerTakeAll(const SwarmRewardSplit& split)
{
    return split.milestone_ppm == SWARM_PPM_TOTAL && split.rollout_ppm == 0 && split.negative_ppm == 0 &&
           split.reproduction_ppm == 0 && split.evaluation_ppm == 0 && split.challenger_ppm == 0;
}

bool SwarmWorkCycle(bool published, bool funded, bool leased, bool paid, bool frontier, bool graduated, std::string& err)
{
    if (!published) {
        err = "PUBLISHED";
        return false;
    }
    if (!funded) {
        err = "FUNDING";
        return false;
    }
    if (!leased) {
        err = "LEASE";
        return false;
    }
    if (!paid) {
        err = "PAID";
        return false;
    }
    if (!frontier) {
        err = "FRONTIER";
        return false;
    }
    if (!graduated) {
        err = "GRADUATED";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmBuildRefund(SwarmChannelTx& tx, std::string& err)
{
    if (tx.sponsor_pubkey.size() != MLDSA44_PUBKEY_SIZE) {
        err = "PUBKEY";
        return false;
    }
    if (tx.refund_height < 1) {
        err = "REFUND_HEIGHT";
        return false;
    }
    if (tx.fee_reserve < 0 || tx.capacity <= tx.fee_reserve) {
        err = "CAPACITY";
        return false;
    }
    const std::vector<unsigned char> leaf =
        BuildP2MRRefundLeaf(tx.refund_height, PQAlgorithm::ML_DSA_44, tx.sponsor_pubkey);
    if (leaf.empty()) {
        err = "REFUND_SCRIPT";
        return false;
    }
    CMutableTransaction built;
    built.vin.push_back(PlaceholderInput());
    built.vout.emplace_back(static_cast<CAmount>(tx.capacity), CScript(leaf.begin(), leaf.end()));
    tx.refund = std::move(built);
    tx.refund_signed = true;
    err.clear();
    return true;
}

bool SwarmNoteChannelFunding(SwarmChannelTx& tx, std::string& err)
{
    if (!tx.refund_signed) {
        err = "REFUND_NOT_SIGNED";
        return false;
    }
    tx.funded = true;
    err.clear();
    return true;
}

bool SwarmBuildPayout(SwarmChannelTx& tx, int64_t cumulative, int height, int refund_height, std::string& err)
{
    if (!tx.funded) {
        err = "CHANNEL_UNFUNDED";
        return false;
    }
    if (refund_height != tx.refund_height) {
        err = "EXPIRY_CHANGE";
        return false;
    }
    if (cumulative < tx.cumulative) {
        err = "DECREASING_PAYMENT";
        return false;
    }
    if (cumulative < 0 || tx.fee_reserve < 0 || tx.capacity < 0 ||
        static_cast<__int128>(cumulative) + tx.fee_reserve > tx.capacity) {
        err = "CHANNEL_CAPACITY";
        return false;
    }
    if (static_cast<int64_t>(height) + SWARM_CLOSE_MARGIN >= refund_height) {
        err = "CHANNEL_DRAINING";
        return false;
    }
    if (tx.worker_pubkey.size() != MLDSA44_PUBKEY_SIZE || tx.sponsor_pubkey.size() != MLDSA44_PUBKEY_SIZE) {
        err = "PUBKEY";
        return false;
    }
    const CAmount worker_value = static_cast<CAmount>(cumulative);
    const CAmount sponsor_value = static_cast<CAmount>(tx.capacity - cumulative - tx.fee_reserve);
    CMutableTransaction built;
    built.vout.emplace_back(worker_value, CScript(tx.worker_pubkey.begin(), tx.worker_pubkey.end()));
    built.vout.emplace_back(sponsor_value, CScript(tx.sponsor_pubkey.begin(), tx.sponsor_pubkey.end()));
    tx.payout = std::move(built);
    tx.cumulative = cumulative;
    tx.sequence += 1;
    err.clear();
    return true;
}

bool SwarmClaimBeforeRefund(int height, int refund_height)
{
    return static_cast<int64_t>(height) + SWARM_CLOSE_MARGIN < refund_height;
}

SwarmRevocation SwarmNewRevocation(int sequence, unsigned char fill)
{
    SwarmRevocation rev;
    rev.sequence = sequence;
    rev.secret.assign(32, fill);
    rev.hash_hex = Sha256Hex(rev.secret);
    rev.released = false;
    return rev;
}

bool SwarmSupersede(SwarmRevocation& prior, const SwarmRevocation& next, std::string& err)
{
    if (next.sequence <= prior.sequence) {
        err = "SEQUENCE";
        return false;
    }
    prior.released = true;
    err.clear();
    return true;
}

std::vector<unsigned char> SwarmRemedyScript(const std::vector<unsigned char>& secret_hash,
                                             const std::vector<unsigned char>& counterparty_pubkey)
{
    if (secret_hash.size() != 32 || counterparty_pubkey.size() != MLDSA44_PUBKEY_SIZE) return {};
    return BuildP2MRHTLCSha256Leaf(secret_hash, PQAlgorithm::ML_DSA_44, counterparty_pubkey);
}

SwarmRemedyReport SwarmWatchState(int observed_sequence, int latest_sequence, int height, int refund_height, int margin,
                                  const SwarmRevocation& prior)
{
    SwarmRemedyReport report;
    report.secp_penalty = false;
    if (observed_sequence < latest_sequence) {
        report.hashlock_remedy = prior.released;
        report.action = prior.released ? "HASHLOCK_REMEDY" : "STALE_STATE_ALERT";
        return report;
    }
    if (static_cast<int64_t>(height) + margin >= refund_height) {
        report.action = "DRAIN_AND_NOTIFY";
        return report;
    }
    report.action = "OBSERVE";
    return report;
}

bool SwarmBindPreimage(const SwarmInvoice& invoice, const std::vector<unsigned char>& preimage32, std::string& err)
{
    if (preimage32.size() != 32 || Sha256Hex(preimage32) != invoice.preimage_hash) {
        err = "PREIMAGE";
        return false;
    }
    if (invoice.amount <= 0) {
        err = "AMOUNT";
        return false;
    }
    if (invoice.beneficiary.empty() || invoice.objective.empty() || invoice.route_id.empty()) {
        err = "INVOICE";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmReusePreimage(std::set<std::string>& seen, const std::string& hash, std::string& err)
{
    if (!seen.insert(hash).second) {
        err = "REPLAY";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmRouteMargin(int incoming_expiry, int outgoing_expiry, int margin, std::string& err)
{
    if (static_cast<int64_t>(incoming_expiry) < static_cast<int64_t>(outgoing_expiry) + margin) {
        err = "MARGIN";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmForwardAllowed(bool incoming_committed, int64_t liquidity, int64_t amount, int incoming_expiry, int height, int margin,
                         std::string& err)
{
    if (!incoming_committed) {
        err = "COMMITMENT";
        return false;
    }
    if (amount <= 0 || liquidity < amount) {
        err = "LIQUIDITY";
        return false;
    }
    if (static_cast<int64_t>(incoming_expiry) < static_cast<int64_t>(height) + margin) {
        err = "EXPIRY";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmStopNewWork(int height, int refund_height, int margin)
{
    return static_cast<int64_t>(height) + margin >= refund_height;
}

std::string SwarmCollateralBook::FirstPool(const std::string& outpoint) const
{
    const auto it = m_first_pool.find(outpoint);
    if (it == m_first_pool.end()) return {};
    return it->second;
}

bool SwarmSameCollateral(SwarmCollateralBook& book, const std::string& pool_a, const std::string& pool_b,
                         const std::string& outpoint, std::string& err)
{
    if (pool_a.empty() || pool_b.empty() || outpoint.empty()) {
        err = "COLLATERAL";
        return false;
    }
    const auto it = book.m_first_pool.find(outpoint);
    if (it == book.m_first_pool.end()) {
        book.m_first_pool.emplace(outpoint, pool_a);
    } else if (it->second != pool_a) {
        err = "COLLATERAL_REUSE";
        return false;
    }
    if (pool_a != pool_b) {
        err = "COLLATERAL_REUSE";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmRecordFiat(SwarmFiatRecord& record, std::string& err)
{
    record.usd_is_balance = false;
    if (!record.converted || record.btx_atoms.empty()) {
        err = "FIAT_NOT_FUNDED";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmAcceptInstrument(const std::string& kind, std::string& err)
{
    if (kind == "work-payment") {
        err.clear();
        return true;
    }
    err = "PASSIVE_INSTRUMENT";
    return false;
}

bool SwarmTaxOpenInference(bool open_license, bool local_execution, std::string& err)
{
    if (open_license && local_execution) {
        err = "NOT_TAXABLE";
        return false;
    }
    err.clear();
    return true;
}

int64_t SwarmMassExit(int64_t closes, int64_t bytes_per_close, int64_t block_bytes)
{
    if (closes < 0 || bytes_per_close < 0 || block_bytes <= 0) return 0;
    const __int128 bytes = static_cast<__int128>(closes) * static_cast<__int128>(bytes_per_close);
    return static_cast<int64_t>((bytes + block_bytes - 1) / block_bytes);
}

SwarmMiningDisplacementResult SwarmMiningDisplacement(const SwarmMiningNote& note)
{
    SwarmMiningDisplacementResult result;
    result.advantage = note.swarm_atoms_per_hour - note.mining_atoms_per_hour;
    result.security_increased = false;
    return result;
}

bool SwarmCoordinatorLost(const SwarmRecoverySnapshot& in, SwarmRecoverySnapshot& out, std::string& err)
{
    out = in;
    if (!in.checkpoint_present) {
        err = "RETAIN_CHECKPOINT";
        return false;
    }
    if (!in.payment_plane_present) {
        err = "PAYMENT_PLANE";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmObsoleteSettlement(int64_t offered_cumulative, int64_t best_cumulative, std::string& err)
{
    if (offered_cumulative < best_cumulative) {
        err = "STALE_SETTLEMENT";
        return false;
    }
    err.clear();
    return true;
}

int64_t SwarmWorkerDisconnected(int64_t earned_atoms)
{
    return earned_atoms;
}

bool SwarmConflictingValidators(bool& accepted, std::string& err)
{
    accepted = false;
    err = "CONFLICT";
    return false;
}

bool SwarmExpiryPressure(int height, int expiry, int margin)
{
    return static_cast<int64_t>(height) + margin >= expiry;
}

SwarmRecoverySnapshot SwarmReorgExit(SwarmRecoverySnapshot snapshot)
{
    snapshot.frozen = true;
    return snapshot;
}

} // namespace modelnet
