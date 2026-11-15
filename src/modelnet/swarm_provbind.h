// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PROVBIND_H
#define BTX_MODELNET_SWARM_PROVBIND_H

#include <map>
#include <string>

namespace modelnet {

/**
 * Binds one checkpoint to the base, recipe, and digest it was produced from.
 *
 * Bind order, first match wins: an empty checkpoint, base, recipe, or
 * digest is PROVENANCE and stores nothing. withdrawn, or a dataset that
 * is not authorized, is DATASET and stores nothing. A duplicate checkpoint
 * is REPLAY and keeps the first row. Otherwise the row is stored, err is
 * cleared, and Bind returns true.
 * Bound returns false when the checkpoint is unknown. Otherwise it fills
 * base and digest and returns true.
 */
class SwarmProvBind {
public:
    bool Bind(const std::string& checkpoint, const std::string& base, const std::string& recipe, bool dataset_authorized, bool withdrawn, const std::string& digest, std::string& err);
    bool Bound(const std::string& checkpoint, std::string& base, std::string& digest) const;

private:
    struct Row {
        std::string base;
        std::string recipe;
        std::string digest;
    };

    std::map<std::string, Row> m_rows;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PROVBIND_H
