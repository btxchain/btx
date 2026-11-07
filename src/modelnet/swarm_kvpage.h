// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_KVPAGE_H
#define BTX_MODELNET_SWARM_KVPAGE_H

#include <set>
#include <string>

namespace modelnet {

/** KV page ids shared across compatible tensor families. Sharing moves no bytes. */
class SwarmKvPageRegistry {
public:
    bool Share(const std::string& page, const std::string& family_a, const std::string& family_b, bool compatible, std::string& err);
    bool shared(const std::string& page) const;
    bool bytes_moved() const;

private:
    std::set<std::string> pages;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_KVPAGE_H
