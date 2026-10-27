// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvmove/bytes.h>

#include <cstring>
#include <vector>

namespace modelnet {

std::vector<unsigned char> SwarmKvMoveCopyBytes(const std::vector<unsigned char>& src)
{
    std::vector<unsigned char> out(src.size());
    if (!src.empty()) {
        std::memcpy(out.data(), src.data(), src.size());
    }
    return out;
}

} // namespace modelnet
