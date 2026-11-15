// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_island/nif_island.h>

namespace modelnet {

NifIsland::Member* NifIsland::Find(const std::string& member)
{
    for (Member& row : m_members) {
        if (row.name == member) return &row;
    }
    return nullptr;
}

const NifIsland::Member* NifIsland::Find(const std::string& member) const
{
    for (const Member& row : m_members) {
        if (row.name == member) return &row;
    }
    return nullptr;
}

bool NifIsland::Admit(const std::string& member, int64_t rtt_us, bool qualified_hardware, std::string& err)
{
    if (member.empty()) {
        err = "MEMBER";
        return false;
    }
    if (Find(member) != nullptr) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (!qualified_hardware) {
        err = "HARDWARE";
        return false;
    }
    if (rtt_us < 0) {
        err = "RTT";
        return false;
    }
    Member row;
    row.name = member;
    row.rtt_us = rtt_us;
    m_members.push_back(std::move(row));
    err.clear();
    return true;
}

bool NifIsland::Place(const std::string& member, const std::string& phase, std::string& err)
{
    if (member.empty() || Find(member) == nullptr) {
        err = "MEMBER";
        return false;
    }
    if (phase == "prefill") {
        m_prefill = member;
    } else if (phase == "decode") {
        m_decode = member;
    } else {
        err = "PHASE";
        return false;
    }
    err.clear();
    return true;
}

bool NifIsland::Push(const std::string& member, int64_t bytes, std::string& err)
{
    Member* row = Find(member);
    if (member.empty() || row == nullptr) {
        err = "MEMBER";
        return false;
    }
    if (bytes <= 0) {
        err = "BYTES";
        return false;
    }
    if (bytes > kQueueCap - row->queued) {
        err = "BACKPRESSURE";
        return false;
    }
    row->queued += bytes;
    err.clear();
    return true;
}

bool NifIsland::Collective(const std::string& member, int64_t rtt_us, std::string& err)
{
    // Above 1000 microseconds there is no local collective route.
    // The measured rtt_us is left as passed; a lower value is not substituted.
    if (rtt_us > 1000) {
        err = NIFDT_NO_ROUTE;
        return false;
    }
    if (member.empty() || Find(member) == nullptr) {
        err = "MEMBER";
        return false;
    }
    if (rtt_us < 0) {
        err = "RTT";
        return false;
    }
    m_last_local_rtt_us = rtt_us;
    m_local_collectives += 1;
    err.clear();
    return true;
}

bool NifIsland::admitted(const std::string& member) const
{
    return Find(member) != nullptr;
}

int64_t NifIsland::rtt_us(const std::string& member) const
{
    const Member* row = Find(member);
    if (row == nullptr) return 0;
    return row->rtt_us;
}

int64_t NifIsland::queued() const
{
    int64_t total = 0;
    for (const Member& row : m_members) {
        total += row.queued;
    }
    return total;
}

int64_t NifIsland::queued(const std::string& member) const
{
    const Member* row = Find(member);
    if (row == nullptr) return 0;
    return row->queued;
}

std::string NifIsland::placed(const std::string& phase) const
{
    if (phase == "prefill") return m_prefill;
    if (phase == "decode") return m_decode;
    return {};
}

} // namespace modelnet
