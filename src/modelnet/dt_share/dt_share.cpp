// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_share/dt_share.h>

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <limits>
#include <string>

namespace modelnet {
namespace {

bool AddInt(std::int64_t left, std::int64_t right, std::int64_t& next)
{
    const __int128 sum = static_cast<__int128>(left) + static_cast<__int128>(right);
    if (sum > static_cast<__int128>(std::numeric_limits<std::int64_t>::max()) ||
        sum < static_cast<__int128>(std::numeric_limits<std::int64_t>::min())) {
        return false;
    }
    next = static_cast<std::int64_t>(sum);
    return true;
}

} // namespace

DtShare::Owner* DtShare::FindOwner(const std::string& owner)
{
    const auto it = m_owners.find(owner);
    if (it == m_owners.end()) return nullptr;
    return &it->second;
}

const DtShare::Owner* DtShare::FindOwner(const std::string& owner) const
{
    const auto it = m_owners.find(owner);
    if (it == m_owners.end()) return nullptr;
    return &it->second;
}

bool DtShare::Fold(Owner& row, std::int64_t amount, std::string& err)
{
    std::int64_t next = static_cast<std::int64_t>(0);
    if (!AddInt(row.weight, amount, next)) {
        err = DT_SHARE_UNCHANGED;
        return false;
    }
    row.weight = next;
    row.pending = static_cast<std::int64_t>(0);
    row.pending_open = false;
    if (!row.detached) row.cache_open = false;
    err.clear();
    return true;
}

bool DtShare::Bind(const std::string& owner, const std::string& consumer, std::string& err)
{
    if (owner.empty()) {
        err = DT_SHARE_OWNER;
        return false;
    }
    if (consumer.empty()) {
        err = DT_SHARE_CONSUMER;
        return false;
    }
    if (owner == consumer) {
        err = DT_SHARE_SELF;
        return false;
    }
    if (m_consumers.count(consumer) != 0) {
        err = NIFDT_REPLAY;
        return false;
    }
    Consumer row;
    row.owner = owner;
    m_consumers.emplace(consumer, row);
    Owner& slot = m_owners[owner];
    slot.consumers += 1;
    err.clear();
    return true;
}

bool DtShare::Grad(const std::string& owner, const std::string& consumer, std::int64_t value, std::string& err)
{
    if (owner.empty()) {
        err = DT_SHARE_OWNER;
        return false;
    }
    if (consumer.empty()) {
        err = DT_SHARE_CONSUMER;
        return false;
    }
    const auto it = m_consumers.find(consumer);
    if (it == m_consumers.end() || it->second.owner != owner) {
        err = DT_SHARE_CONSUMER;
        return false;
    }
    if (it->second.used) {
        err = NIFDT_REPLAY;
        return false;
    }
    Owner* slot = FindOwner(owner);
    if (slot == nullptr) {
        err = DT_SHARE_OWNER;
        return false;
    }
    std::int64_t next = static_cast<std::int64_t>(0);
    if (!AddInt(slot->pending, value, next)) {
        err = DT_SHARE_UNCHANGED;
        return false;
    }
    slot->pending = next;
    slot->pending_open = true;
    if (!slot->detached) {
        slot->cache = slot->pending;
        slot->cache_open = true;
    }
    it->second.used = true;
    err.clear();
    return true;
}

bool DtShare::Apply(const std::string& owner, std::string& err)
{
    Owner* slot = FindOwner(owner);
    if (owner.empty() || slot == nullptr) {
        err = DT_SHARE_OWNER;
        return false;
    }
    if (!slot->pending_open) {
        err = DT_SHARE_UNCHANGED;
        return false;
    }
    return Fold(*slot, slot->pending, err);
}

bool DtShare::Detach(const std::string& owner, std::string& err)
{
    Owner* slot = FindOwner(owner);
    if (owner.empty() || slot == nullptr) {
        err = DT_SHARE_OWNER;
        return false;
    }
    if (slot->detached) {
        err = NIFDT_REPLAY;
        return false;
    }
    slot->detached = true;
    err.clear();
    return true;
}

bool DtShare::CacheGrad(const std::string& owner, std::string& err)
{
    Owner* slot = FindOwner(owner);
    if (owner.empty() || slot == nullptr) {
        err = DT_SHARE_OWNER;
        return false;
    }
    if (slot->detached) {
        err = DT_SHARE_DETACHED;
        return false;
    }
    if (!slot->cache_open) {
        err = DT_SHARE_UNCHANGED;
        return false;
    }
    return Fold(*slot, slot->cache, err);
}

bool DtShare::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

int DtShare::optimizer_owners(const std::string& owner) const
{
    if (FindOwner(owner) == nullptr) return 0;
    return 1;
}

int DtShare::consumer_count(const std::string& owner) const
{
    const Owner* slot = FindOwner(owner);
    if (slot == nullptr) return 0;
    return slot->consumers;
}

std::int64_t DtShare::weight(const std::string& owner) const
{
    const Owner* slot = FindOwner(owner);
    if (slot == nullptr) return static_cast<std::int64_t>(0);
    return slot->weight;
}

std::int64_t DtShare::pending(const std::string& owner) const
{
    const Owner* slot = FindOwner(owner);
    if (slot == nullptr) return static_cast<std::int64_t>(0);
    return slot->pending;
}

bool DtShare::detached(const std::string& owner) const
{
    const Owner* slot = FindOwner(owner);
    if (slot == nullptr) return false;
    return slot->detached;
}

std::string DtShare::owner_of(const std::string& consumer) const
{
    const auto it = m_consumers.find(consumer);
    if (it == m_consumers.end()) return std::string();
    return it->second.owner;
}

} // namespace modelnet
