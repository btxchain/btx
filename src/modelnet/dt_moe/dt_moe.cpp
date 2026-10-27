// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_moe/dt_moe.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

bool DtMoe::Known(int expert) const
{
    return m_configured && expert >= 0 && expert < m_experts;
}

bool DtMoe::InSelection(int expert) const
{
    for (const int id : m_selected) {
        if (id == expert) return true;
    }
    return false;
}

bool DtMoe::Configure(int experts, int top_k, std::string& err)
{
    if (experts < 1 || top_k < 1 || top_k > experts) {
        err = DT_MOE_SHAPE;
        return false;
    }
    std::vector<Expert> table(static_cast<std::size_t>(experts));
    m_table.swap(table);
    m_selected.clear();
    m_experts = experts;
    m_top_k = top_k;
    m_configured = true;
    m_route_open = false;
    m_token_count = static_cast<int64_t>(0);
    m_last_token = static_cast<int64_t>(0);
    err.clear();
    return true;
}

bool DtMoe::Route(int64_t token, const std::vector<int64_t>& scores, std::string& err)
{
    if (!m_configured || scores.size() != static_cast<std::size_t>(m_experts)) {
        err = DT_MOE_SHAPE;
        return false;
    }

    std::vector<int> picked;
    picked.reserve(static_cast<std::size_t>(m_top_k));
    std::vector<unsigned char> used(static_cast<std::size_t>(m_experts), 0);
    for (int slot = 0; slot < m_top_k; ++slot) {
        int best = -1;
        int ties = 0;
        for (int i = 0; i < m_experts; ++i) {
            if (used[static_cast<std::size_t>(i)] != 0) continue;
            const int64_t score = scores[static_cast<std::size_t>(i)];
            if (best < 0 || score > scores[static_cast<std::size_t>(best)]) {
                best = i;
                ties = 1;
            } else if (score == scores[static_cast<std::size_t>(best)]) {
                ++ties;
            }
        }
        if (best < 0) {
            err = DT_MOE_SHAPE;
            return false;
        }
        // top_k > 1 and a shared winning score: the next unmasked argmax
        // returns the same expert. Store nothing.
        if (ties > 1 && m_top_k > 1) {
            err = DT_MOE_DUPLICATE;
            return false;
        }
        picked.push_back(best);
        used[static_cast<std::size_t>(best)] = 1;
    }

    for (Expert& row : m_table) {
        row.gradient = static_cast<int64_t>(0);
        row.contributions = 0;
        row.replicas.clear();
    }
    m_selected.swap(picked);
    m_last_token = token;
    m_token_count += static_cast<int64_t>(1);
    m_route_open = true;
    err.clear();
    return true;
}

bool DtMoe::Contribute(int expert, int replica, int64_t gradient, std::string& err)
{
    if (!Known(expert)) {
        err = DT_MOE_SHAPE;
        return false;
    }
    if (m_selected.empty()) {
        err = DT_MOE_MISSING;
        return false;
    }
    if (!InSelection(expert)) {
        err = DT_MOE_SHAPE;
        return false;
    }
    Expert& row = m_table[static_cast<std::size_t>(expert)];
    if (row.contributions != 0) {
        err = DT_MOE_DUPLICATE;
        return false;
    }
    row.contributions = 1;
    row.gradient = gradient;
    row.replicas.push_back(replica);
    err.clear();
    return true;
}

bool DtMoe::Apply(std::string& err)
{
    if (!m_route_open || m_selected.empty()) {
        err = DT_MOE_MISSING;
        return false;
    }
    for (const int id : m_selected) {
        if (m_table[static_cast<std::size_t>(id)].contributions != 1) {
            err = DT_MOE_MISSING;
            return false;
        }
    }
    for (const int id : m_selected) {
        Expert& row = m_table[static_cast<std::size_t>(id)];
        row.weight += row.gradient;
    }
    m_route_open = false;
    err.clear();
    return true;
}

bool DtMoe::Rematerialize(std::string& err)
{
    err.clear();
    return true;
}

bool DtMoe::GpuDispatch(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

int DtMoe::optimizer_owners(int expert) const
{
    if (!Known(expert)) return 0;
    return 1;
}

int64_t DtMoe::weight(int expert) const
{
    if (!Known(expert)) return static_cast<int64_t>(0);
    return m_table[static_cast<std::size_t>(expert)].weight;
}

int64_t DtMoe::contribution(int expert) const
{
    if (!Known(expert)) return static_cast<int64_t>(0);
    return m_table[static_cast<std::size_t>(expert)].gradient;
}

bool DtMoe::contributed(int expert) const
{
    if (!Known(expert)) return false;
    return m_table[static_cast<std::size_t>(expert)].contributions == 1;
}

const std::vector<int>& DtMoe::replicas(int expert) const
{
    if (!Known(expert)) return m_no_replicas;
    return m_table[static_cast<std::size_t>(expert)].replicas;
}

} // namespace modelnet
