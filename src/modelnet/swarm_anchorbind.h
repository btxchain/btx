// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ANCHORBIND_H
#define BTX_MODELNET_SWARM_ANCHORBIND_H

#include <map>
#include <string>

namespace modelnet {

/**
 * Binds one checkpoint to one base and one digest.
 *
 * A checkpoint binds to one base. A different base does not replace it.
 * An empty checkpoint, base, or digest is ANCHOR and stores nothing. A
 * duplicate checkpoint with the same base and digest returns true and
 * clears err. A duplicate checkpoint with a different base or digest is
 * CONFLICT and keeps the first row. Otherwise the checkpoint, base, and
 * digest are stored, err is cleared, and Bind returns true.
 *
 * This record does not broadcast, spend, spawn a child process, open a
 * network connection, or record a hostname or IP.
 */
class SwarmAnchorBind {
public:
    bool Bind(const std::string& checkpoint, const std::string& base, const std::string& digest, std::string& err);

    /**
     * False when the checkpoint is unknown; base and digest are left
     * unchanged. Otherwise fills base and digest and returns true.
     */
    bool Bound(const std::string& checkpoint, std::string& base, std::string& digest) const;

private:
    struct Row {
        std::string base;
        std::string digest;
    };

    std::map<std::string, Row> m_rows;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ANCHORBIND_H
