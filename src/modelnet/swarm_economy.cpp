// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_economy.h>

#include <modelnet/swarm_codec.h>

#include <algorithm>

namespace modelnet {
namespace {

std::string Atoms(int64_t n)
{
    return std::to_string(std::max<int64_t>(n, 0));
}

} // namespace

std::string SwarmPoolId(const SwarmPoolCommit& commit)
{
    return SwarmDigest("BTX/SwarmPool/1", SwarmCanonical({
        {"chain", commit.chain},
        {"lineage", commit.lineage},
        {"nonce", commit.nonce},
        {"objective", commit.objective},
        {"policy", commit.policy},
    }));
}

bool SwarmAcceptFiat(const SwarmFiatQuote& quote, std::string& atoms, std::string& err)
{
    if (!quote.converted || quote.btx_atoms.empty() || quote.btx_atoms == "0") {
        err = "FIAT_NOT_FUNDED";
        atoms.clear();
        return false;
    }
    for (unsigned char c : quote.btx_atoms) {
        if (c < '0' || c > '9') {
            err = "AMOUNT";
            return false;
        }
    }
    atoms = quote.btx_atoms;
    err.clear();
    return true;
}

SwarmRank SwarmRankOpportunity(const SwarmOpportunity& offer)
{
    SwarmRank rank;
    if (!offer.verified_backing || !offer.demonstrated_payment || !offer.signed_terms) {
        rank.code = "ADVERTISEMENT_UNTRUSTED";
        return rank;
    }
    if (offer.accept_ppm < 0 || offer.accept_ppm > 1000000 || offer.reward_per_hour < 0 || offer.expense_per_hour < 0) {
        rank.code = "RANGE";
        return rank;
    }
    const int64_t expected = (offer.reward_per_hour * offer.accept_ppm) / 1000000 - offer.expense_per_hour;
    rank.advantage = expected - offer.mining_alternative;
    rank.ok = true;
    rank.code = "RANKED";
    return rank;
}

std::string SwarmLedger::CreatePool(const SwarmPoolCommit& commit, std::string& err)
{
    const std::string id = SwarmPoolId(commit);
    if (id.empty()) {
        err = "POOL_ID";
        return {};
    }
    if (!m_status.count(id)) m_status[id] = "UNFUNDED";
    err.clear();
    return id;
}

bool SwarmLedger::ObserveBacking(const std::string& pool, const std::string& outpoint, int64_t amount, int64_t fee_reserve,
                                 const std::string& script, int64_t now_ms, std::string& err)
{
    (void)now_ms;
    if (!m_status.count(pool) || outpoint.empty() || script.empty() || amount <= 0 || fee_reserve < 0 || fee_reserve >= amount) {
        err = "BACKING";
        return false;
    }
    const auto existing = m_backing.find(outpoint);
    if (existing != m_backing.end()) {
        if (existing->second.pool != pool) {
            err = "BACKING_ALREADY_ALLOCATED";
            return false;
        }
        if (existing->second.amount != amount || existing->second.script != script || existing->second.fee_reserve != fee_reserve) {
            err = "BACKING_MUTATION";
            return false;
        }
        if (existing->second.state == "OBSERVED_UNSPENT") {
            err.clear();
            return true;
        }
    }
    Backing row;
    row.pool = pool;
    row.outpoint = outpoint;
    row.amount = amount;
    row.fee_reserve = fee_reserve;
    row.script = script;
    m_backing[outpoint] = row;
    if (m_status[pool] != "FROZEN") m_status[pool] = "ACCOUNTING_ONLY";
    err.clear();
    return true;
}

bool SwarmLedger::PledgeChannel(const std::string& pool, const std::string& outpoint, std::string& err)
{
    const auto it = m_backing.find(outpoint);
    if (it == m_backing.end() || it->second.pool != pool || it->second.state != "OBSERVED_UNSPENT") {
        err = "BACKING";
        return false;
    }
    it->second.channel_collateral = true;
    it->second.channel_funded = false;
    err.clear();
    return true;
}

bool SwarmLedger::FundChannel(const std::string& pool, const std::string& outpoint, bool refund_signed, std::string& err)
{
    const auto it = m_backing.find(outpoint);
    if (it == m_backing.end() || it->second.pool != pool || !it->second.channel_collateral) {
        err = "CHANNEL_COLLATERAL";
        return false;
    }
    if (!refund_signed) {
        err = "REFUND_NOT_SIGNED";
        return false;
    }
    it->second.channel_funded = true;
    err.clear();
    return true;
}

bool SwarmLedger::Invalidate(const std::string& outpoint, const std::string& reason, std::string& err)
{
    if (reason != "SPENT" && reason != "REORG" && reason != "STALE") {
        err = "BACKING_STATE";
        return false;
    }
    const auto it = m_backing.find(outpoint);
    if (it == m_backing.end()) {
        err = "BACKING_NOT_FOUND";
        return false;
    }
    it->second.state = reason;
    it->second.channel_funded = false;
    m_status[it->second.pool] = "FROZEN";
    err.clear();
    return true;
}

std::string SwarmLedger::GrantMandate(const std::string& pool, const std::string& actor, int64_t amount, int64_t expires_ms,
                                      const std::vector<std::string>& recipients, const std::string& nonce, std::string& err)
{
    if (!m_status.count(pool) || amount <= 0 || recipients.empty() || !SwarmFixedId(actor)) {
        err = "MANDATE";
        return {};
    }
    std::string recipient_body;
    std::vector<std::string> unique = recipients;
    std::sort(unique.begin(), unique.end());
    unique.erase(std::unique(unique.begin(), unique.end()), unique.end());
    for (const std::string& peer : unique) {
        if (!SwarmFixedId(peer)) {
            err = "ID";
            return {};
        }
        if (!recipient_body.empty()) recipient_body += ',';
        recipient_body += peer;
    }
    const std::string id = SwarmDigest("BTX/LocalPaymentMandate/1", SwarmCanonical({
        {"actor", actor},
        {"atoms", std::to_string(amount)},
        {"expires_ms", std::to_string(expires_ms)},
        {"nonce", nonce},
        {"pool", pool},
        {"recipients", recipient_body},
    }));
    if (!m_mandates.count(id)) {
        Mandate mandate;
        mandate.id = id;
        mandate.pool = pool;
        mandate.actor = actor;
        mandate.amount = amount;
        mandate.expires_ms = expires_ms;
        mandate.recipients = unique;
        m_mandates[id] = mandate;
    }
    err.clear();
    return id;
}

bool SwarmLedger::Reserve(const std::string& mandate, const std::string& actor, const std::string& work, const std::string& worker,
                          int64_t amount, const std::string& terms, bool accept_unsecured, std::string& reservation, std::string& err)
{
    const auto mit = m_mandates.find(mandate);
    if (mit == m_mandates.end() || mit->second.actor != actor || mit->second.revoked || amount <= 0 || !SwarmFixedId(worker)) {
        err = "MANDATE_AUTH";
        return false;
    }
    if (m_status[mit->second.pool] == "FROZEN") {
        err = "POOL_FROZEN";
        return false;
    }
    if (std::find(mit->second.recipients.begin(), mit->second.recipients.end(), worker) == mit->second.recipients.end()) {
        err = "RECIPIENT_AUTH";
        return false;
    }
    for (const auto& [id, row] : m_obligations) {
        if (row.pool == mit->second.pool && row.work == work) {
            if (row.worker != worker || row.amount != amount || row.mandate != mandate || row.terms != terms) {
                err = "OBLIGATION_CONFLICT";
                return false;
            }
            reservation = id;
            err.clear();
            return true;
        }
    }
    const SwarmBalances balances = Balances(mit->second.pool);
    const int64_t available = std::stoll(balances.available_reward_budget_atoms);
    if (amount > available && !accept_unsecured) {
        err = "INSUFFICIENT_UNRESERVED_BACKING";
        return false;
    }
    if (mit->second.used + amount > mit->second.amount) {
        err = "MANDATE_EXHAUSTED";
        return false;
    }
    reservation = SwarmDigest("BTX/WorkReservation/1", SwarmCanonical({
        {"atoms", std::to_string(amount)},
        {"pool", mit->second.pool},
        {"terms", terms},
        {"work", work},
        {"worker", worker},
    }));
    Obligation row;
    row.id = reservation;
    row.pool = mit->second.pool;
    row.work = work;
    row.worker = worker;
    row.mandate = mandate;
    row.terms = terms;
    row.amount = amount;
    row.state = amount > available ? "RESERVED_UNSECURED" : "RESERVED";
    m_obligations[reservation] = row;
    mit->second.used += amount;
    err.clear();
    return true;
}

bool SwarmLedger::AcceptWork(const std::string& reservation, const std::string& receipt, std::string& err)
{
    const auto it = m_obligations.find(reservation);
    if (it == m_obligations.end()) {
        err = "RESERVATION";
        return false;
    }
    if (it->second.state != "RESERVED" && it->second.state != "RESERVED_UNSECURED" && it->second.state != "EARNED") {
        err = "OBLIGATION_STATE";
        return false;
    }
    if (!it->second.receipt.empty() && it->second.receipt != receipt) {
        err = "RECEIPT_CONFLICT";
        return false;
    }
    if (!SwarmFixedId(receipt)) {
        err = "ID";
        return false;
    }
    it->second.receipt = receipt;
    it->second.state = "EARNED";
    err.clear();
    return true;
}

bool SwarmLedger::Cancel(const std::string& reservation, std::string& err)
{
    const auto it = m_obligations.find(reservation);
    if (it == m_obligations.end()) {
        err = "RESERVATION";
        return false;
    }
    if (it->second.state == "CANCELLED") {
        err.clear();
        return true;
    }
    if (it->second.state == "EARNED") {
        err = "EARNED_OBLIGATION_CANNOT_BE_CANCELLED";
        return false;
    }
    if (it->second.state != "RESERVED" && it->second.state != "RESERVED_UNSECURED") {
        err = "OBLIGATION_STATE";
        return false;
    }
    auto mandate = m_mandates.find(it->second.mandate);
    if (mandate != m_mandates.end()) mandate->second.used -= it->second.amount;
    it->second.state = "CANCELLED";
    err.clear();
    return true;
}

SwarmBalances SwarmLedger::Balances(const std::string& pool) const
{
    SwarmBalances out;
    const auto status = m_status.find(pool);
    if (status == m_status.end()) return out;
    out.status = status->second;
    int64_t backing = 0;
    int64_t reserve = 0;
    int64_t payable = 0;
    for (const auto& [id, row] : m_backing) {
        (void)id;
        if (row.pool != pool || row.state != "OBSERVED_UNSPENT") continue;
        if (row.channel_collateral) {
            if (row.channel_funded) payable += row.amount - row.fee_reserve;
            continue;
        }
        backing += row.amount;
        reserve += row.fee_reserve;
    }
    int64_t pending = 0;
    int64_t earned = 0;
    for (const auto& [id, row] : m_obligations) {
        (void)id;
        if (row.pool != pool) continue;
        if (row.state == "RESERVED" || row.state == "RESERVED_UNSECURED") pending += row.amount;
        if (row.state == "EARNED") earned += row.amount;
    }
    const int64_t available = std::max<int64_t>(0, backing - reserve - pending - earned);
    out.confirmed_backing_atoms = Atoms(backing);
    out.available_reward_budget_atoms = Atoms(available);
    out.immediately_payable_l2_atoms = Atoms(payable);
    out.pending_or_earned_atoms = Atoms(pending + earned);
    out.holds_money = backing > 0 || payable > 0;
    if (out.status == "UNFUNDED") out.holds_money = false;
    return out;
}

bool SwarmLedger::Conserved(const std::string& pool) const
{
    const SwarmBalances balances = Balances(pool);
    int64_t gross = 0;
    int64_t collateral = 0;
    int64_t reserve = 0;
    for (const auto& [id, row] : m_backing) {
        (void)id;
        if (row.pool != pool || row.state != "OBSERVED_UNSPENT") continue;
        gross += row.amount;
        if (row.channel_collateral) collateral += row.amount;
        else reserve += row.fee_reserve;
    }
    int64_t liability = 0;
    for (const auto& [id, row] : m_obligations) {
        (void)id;
        if (row.pool != pool) continue;
        if (row.state == "RESERVED" || row.state == "RESERVED_UNSECURED" || row.state == "EARNED") liability += row.amount;
    }
    const int64_t confirmed = std::stoll(balances.confirmed_backing_atoms);
    const int64_t available = std::stoll(balances.available_reward_budget_atoms);
    const int64_t deficit = std::max<int64_t>(0, reserve + liability - confirmed);
    return confirmed + collateral == gross && available + reserve + liability == confirmed + deficit;
}

bool SwarmLedger::EarnedSurvives(const std::string& pool, const std::string& reservation) const
{
    const auto it = m_obligations.find(reservation);
    return it != m_obligations.end() && it->second.pool == pool && it->second.state == "EARNED";
}

} // namespace modelnet
