// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_provbind.h>

#include <string>
#include <utility>

namespace modelnet {

bool SwarmProvBind::Bind(const std::string& checkpoint, const std::string& base, const std::string& recipe, bool dataset_authorized, bool withdrawn, const std::string& digest, std::string& err)
{
    if (checkpoint.empty() || base.empty() || recipe.empty() || digest.empty()) {
        err = "PROVENANCE";
        return false;
    }
    if (withdrawn || !dataset_authorized) {
        err = "DATASET";
        return false;
    }
    if (m_rows.find(checkpoint) != m_rows.end()) {
        err = "REPLAY";
        return false;
    }
    Row row;
    row.base = base;
    row.recipe = recipe;
    row.digest = digest;
    m_rows.emplace(checkpoint, std::move(row));
    err.clear();
    return true;
}

bool SwarmProvBind::Bound(const std::string& checkpoint, std::string& base, std::string& digest) const
{
    const auto it = m_rows.find(checkpoint);
    if (it == m_rows.end()) {
        return false;
    }
    base = it->second.base;
    digest = it->second.digest;
    return true;
}

} // namespace modelnet
