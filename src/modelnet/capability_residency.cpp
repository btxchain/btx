// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/capability.h>

#include <algorithm>
#include <limits>
#include <mutex>

namespace modelnet {
namespace {

HostResourceBroker g_broker;
LeaseTable g_leases;

bool ExceedsCap(uint64_t used, uint64_t add, uint64_t cap)
{
    if (cap == 0) return false;
    if (add > cap) return true;
    return used > cap - add;
}

uint64_t SatAdd(uint64_t a, uint64_t b)
{
    if (a > std::numeric_limits<uint64_t>::max() - b) return std::numeric_limits<uint64_t>::max();
    return a + b;
}

uint64_t UmaPhysical(uint64_t host, uint64_t device)
{
    return std::max(host, device);
}

bool LegalTransition(LeaseLife from, LeaseLife to)
{
    if (from == to) return true;
    switch (from) {
    case LeaseLife::RESERVED:
        return to == LeaseLife::ALLOCATED || to == LeaseLife::RETIRING || to == LeaseLife::QUARANTINED;
    case LeaseLife::ALLOCATED:
        return to == LeaseLife::POPULATING || to == LeaseLife::RETIRING || to == LeaseLife::QUARANTINED;
    case LeaseLife::POPULATING:
        return to == LeaseLife::VERIFIED || to == LeaseLife::RETIRING || to == LeaseLife::QUARANTINED;
    case LeaseLife::VERIFIED:
        return to == LeaseLife::ACTIVE || to == LeaseLife::RETIRING;
    case LeaseLife::ACTIVE:
        return to == LeaseLife::RETIRING;
    case LeaseLife::RETIRING:
        return to == LeaseLife::QUIESCENT || to == LeaseLife::QUARANTINED;
    case LeaseLife::QUIESCENT:
        return to == LeaseLife::RELEASED;
    case LeaseLife::QUARANTINED:
        return to == LeaseLife::RETIRING || to == LeaseLife::QUIESCENT;
    case LeaseLife::RELEASED:
        return false;
    }
    return false;
}

} // namespace

HostResourceBroker& GlobalCapabilityBroker()
{
    return g_broker;
}

LeaseTable& GlobalCapabilityLeases()
{
    return g_leases;
}

bool HostResourceBroker::Configure(const MemoryLimits& lim, std::string& err)
{
    std::lock_guard<std::mutex> lock(*m_mu);
    if (lim.host_pinned_bytes > lim.host_physical_bytes && lim.host_physical_bytes) {
        err = "pinned exceeds host";
        return false;
    }
    m_host = lim.host_physical_bytes;
    m_pinned = lim.host_pinned_bytes;
    m_device = lim.device_bytes;
    m_speculative = lim.speculative_bytes;
    if (m_speculative == 0 && m_host) m_speculative = (m_host * PREFETCH_BUDGET_PERCENT) / 100;
    m_uma = lim.uma;
    m_host_used = m_pinned_used = m_device_used = m_speculative_used = m_retired_awaiting = 0;
    m_prefetch_jobs = 0;
    return true;
}

bool HostResourceBroker::Reserve(uint64_t host, uint64_t pinned, uint64_t device, bool speculative, std::string& err)
{
    std::lock_guard<std::mutex> lock(*m_mu);
    const uint64_t h = host;
    const uint64_t d = device;
    const uint64_t phys = m_uma ? UmaPhysical(h, d) : h;
    const uint64_t spec_add = m_uma ? phys : SatAdd(h, d);
    const uint64_t host_charged = SatAdd(m_host_used, m_retired_awaiting);

    if (m_uma) {
        if (ExceedsCap(host_charged, phys, m_host)) {
            err = "UMA budget";
            return false;
        }
        if (ExceedsCap(m_pinned_used, pinned, m_pinned)) {
            err = "pinned budget";
            return false;
        }
        if (speculative && ExceedsCap(m_speculative_used, spec_add, m_speculative)) {
            err = "speculative budget";
            return false;
        }
        m_host_used = SatAdd(m_host_used, phys);
        m_pinned_used = SatAdd(m_pinned_used, pinned);
        m_device_used = SatAdd(m_device_used, d);
        if (speculative) m_speculative_used = SatAdd(m_speculative_used, spec_add);
        return true;
    }
    if (ExceedsCap(host_charged, h, m_host)) {
        err = "host budget";
        return false;
    }
    if (ExceedsCap(m_pinned_used, pinned, m_pinned)) {
        err = "pinned budget";
        return false;
    }
    if (ExceedsCap(m_device_used, d, m_device)) {
        err = "device budget";
        return false;
    }
    if (speculative && ExceedsCap(m_speculative_used, spec_add, m_speculative)) {
        err = "speculative budget";
        return false;
    }
    m_host_used = SatAdd(m_host_used, h);
    m_pinned_used = SatAdd(m_pinned_used, pinned);
    m_device_used = SatAdd(m_device_used, d);
    if (speculative) m_speculative_used = SatAdd(m_speculative_used, spec_add);
    return true;
}

void HostResourceBroker::Release(uint64_t host, uint64_t pinned, uint64_t device, bool speculative)
{
    std::lock_guard<std::mutex> lock(*m_mu);
    const uint64_t phys = m_uma ? UmaPhysical(host, device) : host;
    if (m_host_used >= phys) m_host_used -= phys;
    else m_host_used = 0;
    if (m_pinned_used >= pinned) m_pinned_used -= pinned;
    else m_pinned_used = 0;
    if (m_device_used >= device) m_device_used -= device;
    else m_device_used = 0;
    if (speculative) {
        const uint64_t spec_add = m_uma ? phys : SatAdd(host, device);
        if (m_speculative_used >= spec_add) m_speculative_used -= spec_add;
        else m_speculative_used = 0;
    }
}

void HostResourceBroker::NoteRetiredAwaiting(uint64_t bytes)
{
    std::lock_guard<std::mutex> lock(*m_mu);
    m_retired_awaiting = SatAdd(m_retired_awaiting, bytes);
}

void HostResourceBroker::ClearRetired(uint64_t bytes)
{
    std::lock_guard<std::mutex> lock(*m_mu);
    if (m_retired_awaiting >= bytes) m_retired_awaiting -= bytes;
    else m_retired_awaiting = 0;
}

UniValue HostResourceBroker::StatusJson() const
{
    std::lock_guard<std::mutex> lock(*m_mu);
    UniValue o(UniValue::VOBJ);
    o.pushKV("host_used", std::to_string(m_host_used));
    o.pushKV("pinned_used", std::to_string(m_pinned_used));
    o.pushKV("device_used", std::to_string(m_device_used));
    o.pushKV("speculative_used", std::to_string(m_speculative_used));
    o.pushKV("retired_awaiting_fence", std::to_string(m_retired_awaiting));
    o.pushKV("uma", m_uma);
    o.pushKV("prefetch_jobs", m_prefetch_jobs);
    o.pushKV("automatic_spend_atoms", 0);
    return o;
}

bool HostResourceBroker::AdmitPrefetch(std::string& err)
{
    std::lock_guard<std::mutex> lock(*m_mu);
    if (m_prefetch_jobs >= PREFETCH_JOB_MAX) {
        err = "prefetch jobs";
        return false;
    }
    ++m_prefetch_jobs;
    return true;
}

void HostResourceBroker::FinishPrefetch()
{
    std::lock_guard<std::mutex> lock(*m_mu);
    if (m_prefetch_jobs > 0) --m_prefetch_jobs;
}

bool PerRankFeasible(const std::vector<uint64_t>& rank_free_bytes, uint64_t need_per_rank, std::string& err)
{
    if (rank_free_bytes.empty()) {
        err = "no ranks";
        return false;
    }
    uint64_t sum = 0;
    for (uint64_t b : rank_free_bytes) {
        if (b < need_per_rank) {
            err = "per-rank capacity";
            return false;
        }
        if (sum + b < sum) {
            err = "overflow";
            return false;
        }
        sum += b;
    }
    (void)sum;
    return true;
}

LeaseRecord& LeaseTable::Create(LeaseClass cls, const std::string& owner, uint64_t bytes, Generation16 gen)
{
    std::lock_guard<std::mutex> lock(*m_mu);
    LeaseRecord r;
    r.lease_id = GenerationHex(NewGeneration());
    r.generation = gen;
    r.cls = cls;
    r.life = LeaseLife::RESERVED;
    r.bytes = bytes;
    r.owner = owner;
    m_leases.push_back(std::move(r));
    return m_leases.back();
}

LeaseRecord* LeaseTable::FindUnlocked(const std::string& lease_id)
{
    for (auto& l : m_leases) {
        if (l.lease_id == lease_id) return &l;
    }
    return nullptr;
}

LeaseRecord* LeaseTable::Find(const std::string& lease_id)
{
    std::lock_guard<std::mutex> lock(*m_mu);
    return FindUnlocked(lease_id);
}

bool LeaseTable::Transition(const std::string& lease_id, LeaseLife next, std::string& err_code, std::string& err)
{
    std::lock_guard<std::mutex> lock(*m_mu);
    LeaseRecord* l = FindUnlocked(lease_id);
    if (!l) {
        err_code = "INVALID_PARAMETER";
        err = "unknown lease";
        return false;
    }
    if (!LegalTransition(l->life, next)) {
        err_code = "LEASE_TRANSITION";
        err = std::string(LeaseLifeName(l->life)) + "->" + LeaseLifeName(next);
        return false;
    }
    l->life = next;
    return true;
}

PhysicalDisposition LeaseTable::Cancel(const std::string& lease_id, bool still_inflight)
{
    std::lock_guard<std::mutex> lock(*m_mu);
    LeaseRecord* l = FindUnlocked(lease_id);
    if (!l) return PhysicalDisposition::NOT_DISPATCHED;
    if (l->life == LeaseLife::RELEASED) return PhysicalDisposition::NOT_DISPATCHED;
    if (l->life == LeaseLife::QUIESCENT) return PhysicalDisposition::STOPPED_QUIESCENT;
    if (still_inflight) {
        l->life = LeaseLife::QUARANTINED;
        return PhysicalDisposition::STILL_IN_FLIGHT;
    }
    if (l->life == LeaseLife::RESERVED || l->life == LeaseLife::ALLOCATED) {
        l->life = LeaseLife::RETIRING;
        return PhysicalDisposition::NOT_DISPATCHED;
    }
    l->life = LeaseLife::QUIESCENT;
    return PhysicalDisposition::STOPPED_QUIESCENT;
}

bool LeaseTable::ReleaseIfQuiescent(const std::string& lease_id, std::string& err)
{
    std::lock_guard<std::mutex> lock(*m_mu);
    LeaseRecord* l = FindUnlocked(lease_id);
    if (!l) {
        err = "unknown lease";
        return false;
    }
    if (l->life != LeaseLife::QUIESCENT) {
        err = "not quiescent";
        return false;
    }
    l->life = LeaseLife::RELEASED;
    return true;
}

bool LeaseTable::StaleCompletion(const std::string& operation_id, const Generation16& gen, std::string& err)
{
    std::lock_guard<std::mutex> lock(*m_mu);
    if (operation_id.empty()) {
        err = "unknown operation";
        return false;
    }
    bool found = false;
    bool stale = false;
    for (auto& l : m_leases) {
        if (l.operation_id != operation_id) continue;
        found = true;
        if (l.generation != gen) {
            stale = true;
            continue;
        }
        if (l.life == LeaseLife::QUARANTINED || l.life == LeaseLife::RETIRING) {
            l.life = LeaseLife::QUIESCENT;
        }
    }
    if (!found) {
        err = "unknown operation";
        return false;
    }
    if (stale) {
        err = "stale generation";
        return true;
    }
    err.clear();
    return true;
}

UniValue LeaseTable::Json(const std::string& lease_id) const
{
    std::lock_guard<std::mutex> lock(*m_mu);
    UniValue o(UniValue::VOBJ);
    for (const auto& l : m_leases) {
        if (l.lease_id != lease_id) continue;
        o.pushKV("lease_id", l.lease_id);
        o.pushKV("generation", GenerationHex(l.generation));
        o.pushKV("life", LeaseLifeName(l.life));
        o.pushKV("bytes", std::to_string(l.bytes));
        o.pushKV("owner", l.owner);
        o.pushKV("automatic_spend_atoms", 0);
        return o;
    }
    o.pushKV("error", "unknown lease");
    return o;
}

} // namespace modelnet
