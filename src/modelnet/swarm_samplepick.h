// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SAMPLEPICK_H
#define BTX_MODELNET_SWARM_SAMPLEPICK_H

#include <string>
#include <vector>

namespace modelnet {

/**
 * Stored trajectory samples. An empty sample is SAMPLE. A kind other than
 * "public_trajectory" or "synthetic_trajectory" is PRIVATE_DATA and stores
 * nothing. A sample already stored is REPLAY. Otherwise the sample is
 * appended in order. Private prompts are not selected. This picker does not
 * broadcast, spend, spawn a child process, open a network connection, or
 * record a hostname or address.
 */
class SwarmSamplePick {
public:
    /**
     * Order: an empty sample is SAMPLE. A kind other than "public_trajectory"
     * or "synthetic_trajectory" is PRIVATE_DATA and stores nothing. A duplicate
     * sample is REPLAY. Otherwise the sample is appended. Success clears err.
     */
    bool Select(const std::string& sample, const std::string& kind, std::string& err);

    /** Selected samples in selection order. */
    const std::vector<std::string>& Selected() const;

private:
    std::vector<std::string> m_selected;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SAMPLEPICK_H
