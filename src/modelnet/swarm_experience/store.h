// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXPERIENCE_STORE_H
#define BITCOIN_MODELNET_SWARM_EXPERIENCE_STORE_H

#include <modelnet/swarm_experience/row.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Insertion-ordered trajectory store.
 * An empty id is TRAJECTORY and is not stored.
 * A kind other than public_trajectory or synthetic_trajectory is
 * PRIVATE_DATA and is not stored.
 * A duplicate id is REPLAY and keeps the first outcome.
 * outcome_ppm outside 0..1000000 is RANGE and is not stored.
 */
class ExperienceStore {
public:
    bool Insert(const std::string& id, const std::string& kind, int64_t outcome_ppm, std::string& err);

    ExperienceRow* Find(const std::string& id);
    const ExperienceRow* Find(const std::string& id) const;

    const std::vector<ExperienceRow>& rows() const { return m_rows; }
    std::size_t size() const { return m_rows.size(); }

    /** True only when a stored row has a kind this plane refuses. */
    bool private_stored() const;

private:
    std::vector<ExperienceRow> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXPERIENCE_STORE_H
