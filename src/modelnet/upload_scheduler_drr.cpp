// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/upload_scheduler_drr.h>

#include <vector>

namespace modelnet {

const char* HostAccountingClassName(HostAccountingClass c)
{
    switch (c) {
    case HostAccountingClass::NATIVE_P2P: return "NATIVE_P2P";
    case HostAccountingClass::RELAY_TRANSIT: return "RELAY_TRANSIT";
    case HostAccountingClass::PROVIDER_PAYLOAD: return "PROVIDER_PAYLOAD";
    case HostAccountingClass::CLOUD_PROXIED: return "CLOUD_PROXIED";
    case HostAccountingClass::TORRENT_REVERSE: return "TORRENT_REVERSE";
    }
    return "NATIVE_P2P";
}

bool HostAccountingClassFromName(const std::string& name, HostAccountingClass& out)
{
    if (name == "NATIVE_P2P") {
        out = HostAccountingClass::NATIVE_P2P;
        return true;
    }
    if (name == "RELAY_TRANSIT") {
        out = HostAccountingClass::RELAY_TRANSIT;
        return true;
    }
    if (name == "PROVIDER_PAYLOAD") {
        out = HostAccountingClass::PROVIDER_PAYLOAD;
        return true;
    }
    if (name == "CLOUD_PROXIED") {
        out = HostAccountingClass::CLOUD_PROXIED;
        return true;
    }
    if (name == "TORRENT_REVERSE") {
        out = HostAccountingClass::TORRENT_REVERSE;
        return true;
    }
    return false;
}

UploadClass DrrScheduleClass(UploadClass c)
{
    switch (c) {
    case UploadClass::NEWCOMER:
    case UploadClass::NORMAL:
    case UploadClass::RARE:
    case UploadClass::EXPLORATORY:
        return c;
    default:
        return UploadClass::NORMAL;
    }
}

uint32_t DrrClassWeight(UploadClass schedule, uint32_t rare_weight)
{
    if (rare_weight < 1) rare_weight = 1;
    if (rare_weight > kDrrRareWeightMax) rare_weight = kDrrRareWeightMax;
    if (DrrScheduleClass(schedule) == UploadClass::RARE) return rare_weight;
    return 1;
}

int UploadSchedulerDrr::ScheduleIndex(UploadClass c)
{
    switch (DrrScheduleClass(c)) {
    case UploadClass::NEWCOMER: return 0;
    case UploadClass::NORMAL: return 1;
    case UploadClass::RARE: return 2;
    case UploadClass::EXPLORATORY: return 3;
    default: return 1;
    }
}

int UploadSchedulerDrr::AccountingIndex(HostAccountingClass c)
{
    const int i = static_cast<int>(c);
    if (i < 0 || i >= kHostAccountingClassCount) return 0;
    return i;
}

uint64_t UploadSchedulerDrr::AddDeficit(uint64_t cur, uint64_t add) const
{
    const uint64_t cap = m_cfg.max_deficit_bytes ? m_cfg.max_deficit_bytes : kDrrMaxDeficitBytes;
    if (add > cap) add = cap;
    if (cur >= cap) return cap;
    if (cap - cur < add) return cap;
    return cur + add;
}

UploadSchedulerDrr::UploadSchedulerDrr(DrrConfig cfg) : m_cfg(cfg)
{
    if (m_cfg.admission.slots < 1) m_cfg.admission.slots = 1;
    if (m_cfg.admission.max_slots < m_cfg.admission.slots) m_cfg.admission.max_slots = m_cfg.admission.slots;
    if (m_cfg.admission.per_identity < 1) m_cfg.admission.per_identity = 1;
    if (m_cfg.admission.per_netgroup < 1) m_cfg.admission.per_netgroup = 1;
    if (m_cfg.quantum_bytes == 0) m_cfg.quantum_bytes = kDrrQuantumBytes;
    if (m_cfg.max_deficit_bytes == 0) m_cfg.max_deficit_bytes = kDrrMaxDeficitBytes;
    if (m_cfg.rare_weight < 1) m_cfg.rare_weight = 1;
    if (m_cfg.rare_weight > kDrrRareWeightMax) m_cfg.rare_weight = kDrrRareWeightMax;
    if (m_cfg.rare_lane_slots < 1) m_cfg.rare_lane_slots = kDrrRareLaneSlots;
}

bool UploadSchedulerDrr::Enqueue(const DrrUploadRequest& req, uint64_t& request_id, std::string& err)
{
    request_id = 0;
    if (req.bytes == 0) {
        err = "empty";
        return false;
    }
    const int ai = static_cast<int>(req.accounting);
    if (ai < 0 || ai >= kHostAccountingClassCount) {
        err = "accounting class";
        return false;
    }
    Queued q;
    q.id = m_next_id++;
    q.req = req;
    q.req.schedule = DrrScheduleClass(req.schedule);
    q.active = false;
    request_id = q.id;
    m_q.push_back(q);
    return true;
}

void UploadSchedulerDrr::RunEpoch()
{
    const uint64_t q = m_cfg.quantum_bytes;
    for (int i = 0; i < 4; ++i) {
        UploadClass c = UploadClass::NORMAL;
        if (i == 0) c = UploadClass::NEWCOMER;
        else if (i == 2) c = UploadClass::RARE;
        else if (i == 3) c = UploadClass::EXPLORATORY;
        m_class_deficit[i] = AddDeficit(m_class_deficit[i], q * DrrClassWeight(c, m_cfg.rare_weight));
    }
    std::map<std::string, bool> ids;
    std::map<std::string, bool> ngs;
    for (const auto& item : m_q) {
        if (item.active) continue;
        if (!item.req.identity.empty()) ids[item.req.identity] = true;
        if (!item.req.netgroup.empty()) ngs[item.req.netgroup] = true;
    }
    for (const auto& kv : ids) {
        m_id_deficit[kv.first] = AddDeficit(m_id_deficit[kv.first], q);
    }
    for (const auto& kv : ngs) {
        m_ng_deficit[kv.first] = AddDeficit(m_ng_deficit[kv.first], q);
    }
    m_served_fair_this_epoch = false;
    m_exploratory_used_this_epoch = false;
}

bool UploadSchedulerDrr::Eligible(const Queued& q, bool enforce_rare_lane, std::string& why) const
{
    if (q.active) {
        why = "already active";
        return false;
    }
    if (!q.req.receiver_writable) {
        why = "receiver not writable";
        return false;
    }
    if (!q.req.storage_credit_reserved) {
        why = "storage wait";
        return false;
    }
    if (!q.req.origin_credit_reserved) {
        why = "origin credit";
        return false;
    }
    if (!q.req.identity.empty()) {
        auto it = m_id_active.find(q.req.identity);
        const int n = it == m_id_active.end() ? 0 : it->second;
        if (n >= m_cfg.admission.per_identity) {
            why = "per-identity";
            return false;
        }
        auto d = m_id_deficit.find(q.req.identity);
        const uint64_t def = d == m_id_deficit.end() ? 0 : d->second;
        if (def < m_cfg.quantum_bytes) {
            why = "identity deficit";
            return false;
        }
    }
    if (!q.req.netgroup.empty()) {
        auto it = m_ng_active.find(q.req.netgroup);
        const int n = it == m_ng_active.end() ? 0 : it->second;
        if (n >= m_cfg.admission.per_netgroup) {
            why = "per-netgroup";
            return false;
        }
        auto d = m_ng_deficit.find(q.req.netgroup);
        const uint64_t def = d == m_ng_deficit.end() ? 0 : d->second;
        if (def < m_cfg.quantum_bytes) {
            why = "netgroup deficit";
            return false;
        }
    }
    const int si = ScheduleIndex(q.req.schedule);
    if (m_class_deficit[si] < m_cfg.quantum_bytes) {
        why = "class deficit";
        return false;
    }
    if (q.req.schedule == UploadClass::RARE && enforce_rare_lane &&
        m_active_rare >= m_cfg.rare_lane_slots) {
        why = "rare lane";
        return false;
    }
    if (q.req.schedule == UploadClass::EXPLORATORY && m_active_exploratory >= 1) {
        why = "exploratory slot";
        return false;
    }
    return true;
}

void UploadSchedulerDrr::Activate(Queued& q, DrrSelection& out)
{
    q.active = true;
    out.selected = true;
    out.request_id = q.id;
    out.slot = m_active;
    out.schedule = q.req.schedule;
    out.accounting = q.req.accounting;
    out.identity = q.req.identity;
    out.netgroup = q.req.netgroup;
    out.bytes = q.req.bytes;
    out.reason.clear();
    ++m_active;
    if (!q.req.identity.empty()) ++m_id_active[q.req.identity];
    if (!q.req.netgroup.empty()) ++m_ng_active[q.req.netgroup];
    if (q.req.schedule == UploadClass::RARE) ++m_active_rare;
    if (q.req.schedule == UploadClass::EXPLORATORY) {
        ++m_active_exploratory;
        m_exploratory_used_this_epoch = true;
    }
    if (q.req.schedule == UploadClass::NEWCOMER || q.req.schedule == UploadClass::NORMAL) {
        m_served_fair_this_epoch = true;
    }
}

bool UploadSchedulerDrr::Select(DrrSelection& out)
{
    out = {};
    if (m_active >= m_cfg.admission.slots) {
        out.reason = "slots full";
        return false;
    }

    auto collect = [&](bool enforce_rare) {
        std::vector<size_t> cand;
        std::string why;
        for (size_t i = 0; i < m_q.size(); ++i) {
            if (Eligible(m_q[i], enforce_rare, why)) cand.push_back(i);
            else if (out.reason.empty() && !m_q[i].active) out.reason = why;
        }
        return cand;
    };

    auto cand = collect(true);
    if (cand.empty()) cand = collect(false);
    if (cand.empty()) {
        if (out.reason.empty()) out.reason = "none eligible";
        return false;
    }

    auto first_of = [&](UploadClass c) -> int {
        for (size_t i : cand) {
            if (m_q[i].req.schedule == c) return static_cast<int>(i);
        }
        return -1;
    };

    int pick = -1;
    if (m_cfg.reserve_newcomer_normal && !m_served_fair_this_epoch) {
        pick = first_of(UploadClass::NEWCOMER);
        if (pick < 0) pick = first_of(UploadClass::NORMAL);
    }
    if (pick < 0 && !m_exploratory_used_this_epoch) {
        pick = first_of(UploadClass::EXPLORATORY);
    }
    if (pick < 0) {
        size_t best = cand[0];
        for (size_t i : cand) {
            const int sa = ScheduleIndex(m_q[i].req.schedule);
            const int sb = ScheduleIndex(m_q[best].req.schedule);
            if (m_class_deficit[sa] > m_class_deficit[sb]) best = i;
        }
        pick = static_cast<int>(best);
    }
    Activate(m_q[static_cast<size_t>(pick)], out);
    return true;
}

bool UploadSchedulerDrr::NoteAcceptedWork(uint64_t request_id, uint64_t bytes, std::string& err)
{
    for (auto& q : m_q) {
        if (q.id != request_id) continue;
        if (!q.active) {
            err = "not active";
            return false;
        }
        auto sub = [&](uint64_t& d) {
            if (bytes >= d) d = 0;
            else d -= bytes;
        };
        sub(m_class_deficit[ScheduleIndex(q.req.schedule)]);
        if (!q.req.identity.empty()) sub(m_id_deficit[q.req.identity]);
        if (!q.req.netgroup.empty()) sub(m_ng_deficit[q.req.netgroup]);
        const int ai = AccountingIndex(q.req.accounting);
        m_acct_bytes[ai] += bytes;
        ++m_acct_count[ai];
        return true;
    }
    err = "unknown request";
    return false;
}

void UploadSchedulerDrr::Release(uint64_t request_id)
{
    for (auto it = m_q.begin(); it != m_q.end(); ++it) {
        if (it->id != request_id) continue;
        if (it->active) {
            if (m_active > 0) --m_active;
            if (!it->req.identity.empty()) {
                auto idit = m_id_active.find(it->req.identity);
                if (idit != m_id_active.end() && idit->second > 0) --idit->second;
            }
            if (!it->req.netgroup.empty()) {
                auto ngit = m_ng_active.find(it->req.netgroup);
                if (ngit != m_ng_active.end() && ngit->second > 0) --ngit->second;
            }
            if (it->req.schedule == UploadClass::RARE && m_active_rare > 0) --m_active_rare;
            if (it->req.schedule == UploadClass::EXPLORATORY && m_active_exploratory > 0) --m_active_exploratory;
        }
        m_q.erase(it);
        return;
    }
}

bool UploadSchedulerDrr::SetReceiverWritable(uint64_t request_id, bool writable)
{
    for (auto& q : m_q) {
        if (q.id == request_id) {
            q.req.receiver_writable = writable;
            return true;
        }
    }
    return false;
}

bool UploadSchedulerDrr::SetStorageReady(uint64_t request_id, bool ready)
{
    for (auto& q : m_q) {
        if (q.id == request_id) {
            q.req.storage_credit_reserved = ready;
            return true;
        }
    }
    return false;
}

bool UploadSchedulerDrr::SetOriginCreditReserved(uint64_t request_id, bool reserved)
{
    for (auto& q : m_q) {
        if (q.id == request_id) {
            q.req.origin_credit_reserved = reserved;
            return true;
        }
    }
    return false;
}

size_t UploadSchedulerDrr::Ready() const
{
    size_t n = 0;
    for (const auto& q : m_q) {
        if (!q.active) ++n;
    }
    return n;
}

int UploadSchedulerDrr::IdentityActive(const std::string& identity) const
{
    auto it = m_id_active.find(identity);
    return it == m_id_active.end() ? 0 : it->second;
}

int UploadSchedulerDrr::NetgroupActive(const std::string& netgroup) const
{
    auto it = m_ng_active.find(netgroup);
    return it == m_ng_active.end() ? 0 : it->second;
}

uint64_t UploadSchedulerDrr::ClassDeficit(UploadClass schedule) const
{
    return m_class_deficit[ScheduleIndex(schedule)];
}

uint64_t UploadSchedulerDrr::IdentityDeficit(const std::string& identity) const
{
    auto it = m_id_deficit.find(identity);
    return it == m_id_deficit.end() ? 0 : it->second;
}

uint64_t UploadSchedulerDrr::NetgroupDeficit(const std::string& netgroup) const
{
    auto it = m_ng_deficit.find(netgroup);
    return it == m_ng_deficit.end() ? 0 : it->second;
}

uint64_t UploadSchedulerDrr::AccountedBytes(HostAccountingClass c) const
{
    return m_acct_bytes[AccountingIndex(c)];
}

uint64_t UploadSchedulerDrr::AccountedCount(HostAccountingClass c) const
{
    return m_acct_count[AccountingIndex(c)];
}

} // namespace modelnet
