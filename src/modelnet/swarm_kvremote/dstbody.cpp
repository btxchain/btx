// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvremote/dstbody.h>

#include <vector>

namespace modelnet {

std::vector<unsigned char> SwarmKvRemoteDifferentByte(const std::vector<unsigned char>& body)
{
    constexpr unsigned char byte = 0x01;
    if (body.size() == 1 && body[0] == byte) {
        return {static_cast<unsigned char>(0x02)};
    }
    return {byte};
}

} // namespace modelnet
