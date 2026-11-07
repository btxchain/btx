// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_OUTPUT_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_OUTPUT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Generated output for this plane.
 * text() stays empty. tokens() stays 0.
 * A stored prompt is not this text. There is no method that fills either field.
 */
class SwarmTokenGateOutput {
public:
    const std::string& text() const;
    int64_t tokens() const;

private:
    std::string m_text;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_OUTPUT_H
