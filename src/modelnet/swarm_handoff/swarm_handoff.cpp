// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_handoff/swarm_handoff.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmHandoff::Intent(const std::string& id, const std::string& payload, std::string& err)
{
    if (id.empty() || payload.empty()) {
        err = kSwarmHandoffIntent;
        return false;
    }
    const auto it = m_intents.find(id);
    if (it == m_intents.end()) {
        IntentRecord record;
        record.payload = payload;
        record.attempt = kSwarmHandoffFirstAttempt;
        m_intents.emplace(id, record);
        err.clear();
        return true;
    }
    if (it->second.payload == payload) {
        err = kSwarmHandoffReplay;
        return false;
    }
    err = kSwarmHandoffConflict;
    return false;
}

bool SwarmHandoff::Lease(const std::string& worker, int64_t until_ms, int64_t now_ms, std::string& err)
{
    if (worker.empty()) {
        err = kSwarmHandoffWorker;
        return false;
    }
    // Equality is expired. A bound below 1 cannot admit now_ms == until_ms - 1.
    if (until_ms < 1 || now_ms >= until_ms) {
        err = kSwarmHandoffExpired;
        return false;
    }
    LeaseRecord record;
    record.until_ms = until_ms;
    m_leases[worker] = record;
    err.clear();
    return true;
}

bool SwarmHandoff::Begin(const std::string& intent_id, const std::string& destination, int64_t until_ms, int64_t now_ms, std::string& err)
{
    if (m_intents.find(intent_id) == m_intents.end()) {
        err = kSwarmHandoffIntent;
        return false;
    }
    const auto existing = m_handoffs.find(intent_id);
    if (existing != m_handoffs.end()) {
        if (existing->second.phase == Phase::Ambiguous) {
            err = kSwarmHandoffAmbiguous;
            return false;
        }
        if (existing->second.destination != destination) {
            err = kSwarmHandoffConflict;
            return false;
        }
        err = kSwarmHandoffReplay;
        return false;
    }
    // The destination's cohort lease and the new authority share one rule:
    // now_ms >= until_ms is not admitted, including equality.
    if (!live(destination, now_ms) || until_ms < 1 || now_ms >= until_ms) {
        err = kSwarmHandoffExpired;
        return false;
    }

    HandoffRecord handoff;
    handoff.phase = Phase::Open;
    handoff.destination = destination;
    handoff.source_owner = kSwarmHandoffSource;
    handoff.owner = kSwarmHandoffSource;
    handoff.authority_until_ms = until_ms;
    handoff.authority_generation = m_next_authority;
    ++m_next_authority;
    handoff.effects = 0;
    handoff.scoped = true;
    m_handoffs.emplace(intent_id, handoff);
    m_current = intent_id;
    err.clear();
    return true;
}

bool SwarmHandoff::Fence(const std::string& intent_id, bool destination_accepts, std::string& err)
{
    const auto it = m_handoffs.find(intent_id);
    if (it == m_handoffs.end()) {
        err = kSwarmHandoffHandoff;
        return false;
    }
    HandoffRecord& handoff = it->second;
    if (handoff.phase == Phase::Ambiguous) {
        // The external effect is unknown. Do not apply it again.
        err = kSwarmHandoffAmbiguous;
        return false;
    }
    if (handoff.phase != Phase::Open) {
        err = kSwarmHandoffReplay;
        return false;
    }
    m_current = intent_id;
    handoff.effects = 1;
    if (!destination_accepts) {
        handoff.phase = Phase::Ambiguous;
        handoff.owner.clear();
        handoff.source_owner.clear();
        err = kSwarmHandoffAmbiguous;
        return false;
    }
    handoff.phase = Phase::Committed;
    handoff.source_owner.clear();
    handoff.owner = handoff.destination;
    err.clear();
    return true;
}

const std::string& SwarmHandoff::payload(const std::string& id) const
{
    const auto it = m_intents.find(id);
    if (it == m_intents.end()) return m_blank;
    return it->second.payload;
}

int SwarmHandoff::attempt(const std::string& id) const
{
    const auto it = m_intents.find(id);
    if (it == m_intents.end()) return 0;
    return it->second.attempt;
}

bool SwarmHandoff::leased(const std::string& worker) const
{
    return m_leases.find(worker) != m_leases.end();
}

int64_t SwarmHandoff::lease_until(const std::string& worker) const
{
    const auto it = m_leases.find(worker);
    if (it == m_leases.end()) return 0;
    return it->second.until_ms;
}

bool SwarmHandoff::live(const std::string& worker, int64_t now_ms) const
{
    const auto it = m_leases.find(worker);
    if (it == m_leases.end()) return false;
    return now_ms < it->second.until_ms;
}

bool SwarmHandoff::open(const std::string& intent_id) const
{
    const auto it = m_handoffs.find(intent_id);
    if (it == m_handoffs.end()) return false;
    return it->second.phase == Phase::Open;
}

bool SwarmHandoff::ambiguous(const std::string& intent_id) const
{
    const auto it = m_handoffs.find(intent_id);
    if (it == m_handoffs.end()) return false;
    return it->second.phase == Phase::Ambiguous;
}

bool SwarmHandoff::committed(const std::string& intent_id) const
{
    const auto it = m_handoffs.find(intent_id);
    if (it == m_handoffs.end()) return false;
    return it->second.phase == Phase::Committed;
}

bool SwarmHandoff::atomic(const std::string& intent_id) const
{
    return committed(intent_id);
}

const SwarmHandoff::HandoffRecord* SwarmHandoff::Current() const
{
    if (m_current.empty()) return nullptr;
    const auto it = m_handoffs.find(m_current);
    if (it == m_handoffs.end()) return nullptr;
    return &it->second;
}

const std::string& SwarmHandoff::OwnerOf(const HandoffRecord* handoff) const
{
    if (handoff == nullptr) return m_blank;
    return handoff->owner;
}

const std::string& SwarmHandoff::owner() const
{
    return OwnerOf(Current());
}

const std::string& SwarmHandoff::owner_of(const std::string& intent_id) const
{
    const auto it = m_handoffs.find(intent_id);
    if (it == m_handoffs.end()) return m_blank;
    return it->second.owner;
}

const std::string& SwarmHandoff::source_owner() const
{
    const HandoffRecord* handoff = Current();
    if (handoff == nullptr) return m_blank;
    return handoff->source_owner;
}

bool SwarmHandoff::scoped() const
{
    const HandoffRecord* handoff = Current();
    if (handoff == nullptr) return false;
    return handoff->scoped && !handoff->destination.empty() && handoff->authority_generation != 0;
}

const std::string& SwarmHandoff::authority_destination() const
{
    const HandoffRecord* handoff = Current();
    if (handoff == nullptr || !handoff->scoped) return m_blank;
    return handoff->destination;
}

uint64_t SwarmHandoff::authority_generation() const
{
    const HandoffRecord* handoff = Current();
    if (handoff == nullptr) return 0;
    return handoff->authority_generation;
}

int SwarmHandoff::effects() const
{
    const HandoffRecord* handoff = Current();
    if (handoff == nullptr) return 0;
    return handoff->effects;
}

bool SwarmHandoff::spend_key_moved() const
{
    return false;
}

bool SwarmHandoff::launched() const
{
    return false;
}

bool SwarmHandoff::gpu() const
{
    return false;
}

bool SwarmHandoff::broadcast() const
{
    return false;
}

bool SwarmHandoff::connected() const
{
    return false;
}

std::string SwarmHandoff::automatic_spend() const
{
    return std::string{kSwarmHandoffAutomaticSpend};
}

int64_t SwarmHandoff::atoms_moved() const
{
    return kSwarmHandoffAtomsMoved;
}

} // namespace modelnet
