// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_MANIFESTOK_H
#define BTX_MODELNET_SWARM_MANIFESTOK_H

#include <set>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Local manifest admission.
 *
 * A root is usable only when every child digest is verified. Bind builds
 * one child manifest per digest and admits the root only when that check
 * succeeds. An empty root id is MANIFEST and stores nothing. A root id
 * already stored is REPLAY and leaves the first admission. A refused
 * check stores nothing. On success the root id is stored, err is cleared,
 * and Bind returns true.
 *
 * usable is true only for a stored root id. bytes_streamed stays false.
 *
 * This record does not broadcast, spend, spawn a child process, open a
 * network connection, or record a hostname or IP.
 */
class SwarmManifestOk {
public:
    bool Bind(const std::string& root_id, const std::vector<std::string>& children, const std::vector<std::string>& verified, std::string& err);
    bool usable(const std::string& root_id) const;
    bool bytes_streamed() const;

private:
    std::set<std::string> m_roots;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_MANIFESTOK_H
