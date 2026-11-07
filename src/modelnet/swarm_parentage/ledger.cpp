// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_parentage/ledger.h>

#include <modelnet/swarm_parentage/bind.h>
#include <modelnet/swarm_parentage/codes.h>
#include <modelnet/swarm_parentage/record.h>

#include <map>
#include <string>
#include <utility>

namespace modelnet {

const SwarmParentageBinding* SwarmParentageLedger::Find(const std::string& checkpoint) const
{
    const auto it = m_rows.find(checkpoint);
    if (it == m_rows.end()) {
        return nullptr;
    }
    return &it->second;
}

bool SwarmParentageLedger::Bind(const std::string& checkpoint,
                                const std::string& parent,
                                const std::string& recipe,
                                const std::string& dataset,
                                const std::string& license,
                                std::string& err)
{
    const SwarmParentageBinding* existing = Find(checkpoint);
    SwarmParentageBinding created;
    if (!SwarmParentageDecideBind(existing, checkpoint, parent, recipe, dataset, license, created, err)) {
        return false;
    }
    // A row already stored for this checkpoint stays. The new row is dropped.
    if (existing != nullptr || m_rows.find(checkpoint) != m_rows.end()) {
        err = SWARM_PARENTAGE_CONFLICT;
        return false;
    }
    if (!SwarmParentageBindingComplete(created)) {
        err = SWARM_PARENTAGE_LINEAGE;
        return false;
    }
    m_rows.emplace(checkpoint, std::move(created));
    err.clear();
    return true;
}

bool SwarmParentageLedger::bound(const std::string& checkpoint) const
{
    return Find(checkpoint) != nullptr;
}

std::string SwarmParentageLedger::parent_of(const std::string& checkpoint) const
{
    const SwarmParentageBinding* row = Find(checkpoint);
    if (row == nullptr) {
        return std::string();
    }
    return row->parent;
}

std::string SwarmParentageLedger::recipe_of(const std::string& checkpoint) const
{
    const SwarmParentageBinding* row = Find(checkpoint);
    if (row == nullptr) {
        return std::string();
    }
    return row->recipe;
}

std::string SwarmParentageLedger::dataset_of(const std::string& checkpoint) const
{
    const SwarmParentageBinding* row = Find(checkpoint);
    if (row == nullptr) {
        return std::string();
    }
    return row->dataset;
}

std::string SwarmParentageLedger::license_of(const std::string& checkpoint) const
{
    const SwarmParentageBinding* row = Find(checkpoint);
    if (row == nullptr) {
        return std::string();
    }
    return row->license;
}

} // namespace modelnet
