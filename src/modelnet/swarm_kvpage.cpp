// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvpage.h>

namespace modelnet {

bool SwarmKvPageRegistry::Share(const std::string& page, const std::string& family_a, const std::string& family_b, bool compatible, std::string& err)
{
    if (page.empty() || family_a.empty() || family_b.empty()) {
        err = "PAGE";
        return false;
    }
    if (pages.count(page) != 0) {
        err = "REPLAY";
        return false;
    }
    if (family_a == family_b || !compatible) {
        err = "NOT_COMPAT";
        return false;
    }
    pages.insert(page);
    err.clear();
    return true;
}

bool SwarmKvPageRegistry::shared(const std::string& page) const
{
    return pages.count(page) != 0;
}

bool SwarmKvPageRegistry::bytes_moved() const
{
    return false;
}

} // namespace modelnet
