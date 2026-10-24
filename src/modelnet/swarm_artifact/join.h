// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ARTIFACT_JOIN_H
#define BITCOIN_MODELNET_SWARM_ARTIFACT_JOIN_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Local reassembly of offered pieces.
 * Join requires a capture, split indexes exactly 0..n-1, every non-last
 * piece 32 bytes, a last piece of 1..32 bytes, and JoinModelPieces reproducing
 * the captured bytes. Otherwise the error is GAP, SHORT, or MISMATCH and
 * joined() stays false. The resulting string is not a transfer.
 */
class ArtifactJoin {
public:
    bool Join(const std::string& captured,
              const std::vector<std::string>& pieces,
              const std::map<int64_t, std::string>& offers,
              std::string& err);

    bool joined() const { return m_joined; }
    const std::string& reassembly() const { return m_reassembly; }

private:
    bool m_joined{false};
    std::string m_reassembly;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ARTIFACT_JOIN_H
