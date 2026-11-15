// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PIECEPIPE_STORE_H
#define BITCOIN_MODELNET_SWARM_PIECEPIPE_STORE_H

#include <cstddef>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-memory piece bytes keyed by id.
 * Accept refuses an empty body, a body over the 32 MiB limit, a second copy,
 * and a new id whose SHA-384 does not match. A stored body is never replaced.
 */
class SwarmPiecePipeStore {
public:
    bool Accept(const std::string& id, const std::vector<unsigned char>& body, std::string& err);
    bool contains(const std::string& id) const;
    bool same(const std::string& id, const std::vector<unsigned char>& body) const;
    std::size_t count() const;
    void InsertNew(const std::string& id, std::vector<unsigned char> body);
    bool erase(const std::string& id);

private:
    std::map<std::string, std::vector<unsigned char>> m_pieces;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PIECEPIPE_STORE_H
