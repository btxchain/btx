// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/research_views/research_views.h>
#include <modelnet/nifdt_contract/contract.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

bool ResearchViews::Known(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return true;
    }
    return false;
}

std::vector<ResearchViews::Row> ResearchViews::Select(const std::string& topic, bool public_only, bool reproduced_only) const
{
    std::vector<Row> kept;
    for (const Row& row : m_rows) {
        if (row.topic != topic) continue;
        if (public_only && row.is_private) continue;
        if (reproduced_only && !row.reproduced) continue;
        kept.push_back(row);
    }
    return kept;
}

std::vector<std::string> ResearchViews::IdsByTime(std::vector<Row> rows) const
{
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
        if (a.now_ms != b.now_ms) return a.now_ms > b.now_ms;
        return a.seq > b.seq;
    });
    std::vector<std::string> ids;
    ids.reserve(rows.size());
    for (const Row& row : rows) ids.push_back(row.id);
    return ids;
}

std::vector<std::string> ResearchViews::Topics(const std::string& topic, bool neglected) const
{
    std::vector<std::string> seen;
    for (const Row& row : m_rows) {
        if (row.is_private) continue;
        if (!topic.empty() && row.topic != topic) continue;
        bool found = false;
        for (const std::string& name : seen) {
            if (name == row.topic) {
                found = true;
                break;
            }
        }
        if (!found) seen.push_back(row.topic);
    }
    std::vector<std::string> out;
    for (const std::string& name : seen) {
        bool any_negative = false;
        bool any_non_negative = false;
        for (const Row& row : m_rows) {
            if (row.is_private || row.topic != name) continue;
            if (row.negative) any_negative = true;
            else any_non_negative = true;
        }
        if (neglected) {
            if (any_negative && !any_non_negative) out.push_back(name);
        } else if (any_negative && any_non_negative) {
            out.push_back(name);
        }
    }
    return out;
}

bool ResearchViews::Put(const std::string& id, const std::string& topic, const std::string& summary, bool negative,
                        bool reproduced, int64_t now_ms, bool is_private, std::string& err)
{
    if (id.empty() || topic.empty()) {
        err = "FIELD";
        return false;
    }
    if (Known(id)) {
        err = NIFDT_REPLAY;
        return false;
    }
    Row row;
    row.id = id;
    row.topic = topic;
    row.summary = summary;
    row.negative = negative;
    row.reproduced = reproduced;
    row.now_ms = now_ms;
    row.is_private = is_private;
    row.seq = m_seq;
    m_seq = static_cast<int64_t>(m_seq + static_cast<int64_t>(1));
    m_rows.push_back(row);
    err.clear();
    return true;
}

std::vector<std::string> ResearchViews::View(const std::string& name, const std::string& topic, std::string& err) const
{
    if (name != "LEADING" && name != "CONTESTED" && name != "NEGLECTED" && name != "RECENT" && name != "REPRODUCED") {
        err = "VIEW";
        return {};
    }
    err.clear();
    if (name == "RECENT") return IdsByTime(Select(topic, false, false));
    if (name == "REPRODUCED") return IdsByTime(Select(topic, true, true));
    if (name == "LEADING") {
        const std::vector<std::string> ids = IdsByTime(Select(topic, true, false));
        for (const std::string& id : ids) {
            for (const Row& row : m_rows) {
                if (row.id == id && !row.negative) return {id};
            }
        }
        return {};
    }
    if (name == "NEGLECTED") return Topics(topic, true);
    return Topics(topic, false);
}

std::vector<std::string> ResearchViews::Public(const std::string& topic) const
{
    std::vector<std::string> ids;
    for (const Row& row : m_rows) {
        if (row.topic == topic && !row.is_private) ids.push_back(row.id);
    }
    return ids;
}

bool ResearchViews::Assign(const std::string& author, std::string& err)
{
    (void)author;
    err = "AUTHORITY";
    return false;
}

bool ResearchViews::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool ResearchViews::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool ResearchViews::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool ResearchViews::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
