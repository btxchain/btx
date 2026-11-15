// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evalengine/validation.h>

namespace modelnet {

bool SwarmEvaluationValidationBook::validated(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end()) {
        return false;
    }
    return it->second.validated && it->second.independent;
}

bool SwarmEvaluationValidationBook::any() const
{
    for (const auto& item : m_rows) {
        if (item.second.validated && item.second.independent) {
            return true;
        }
    }
    return false;
}

std::size_t SwarmEvaluationValidationBook::size() const
{
    return m_rows.size();
}

bool SwarmEvaluationValidationBook::mark(const std::string& id)
{
    if (id.empty() || validated(id)) {
        return false;
    }
    SwarmEvaluationValidation validation;
    validation.id = id;
    validation.independent = true;
    validation.validated = true;
    m_rows.emplace(id, validation);
    return true;
}

} // namespace modelnet
