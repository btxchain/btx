// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piecepipe/digest.h>

#include <crypto/sha384.h>
#include <span.h>
#include <util/strencodings.h>

#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {

static_assert(CSHA384::OUTPUT_SIZE == 48, "piece ids are the hex of a 48-byte SHA-384 digest");

std::string SwarmPiecePipeDigest(const unsigned char* data, std::size_t size)
{
    CSHA384 hasher;
    if (data != nullptr && size != 0) {
        hasher.Write(data, size);
    }
    unsigned char out[CSHA384::OUTPUT_SIZE];
    hasher.Finalize(out);
    return HexStr(Span<const unsigned char>(out, CSHA384::OUTPUT_SIZE));
}

std::string SwarmPiecePipeDigest(const std::vector<unsigned char>& body)
{
    if (body.empty()) {
        return SwarmPiecePipeDigest(nullptr, 0);
    }
    return SwarmPiecePipeDigest(body.data(), body.size());
}

} // namespace modelnet
