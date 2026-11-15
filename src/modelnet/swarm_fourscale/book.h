// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FOURSCALE_BOOK_H
#define BITCOIN_MODELNET_SWARM_FOURSCALE_BOOK_H

#include <modelnet/swarm_fourscale/limits.h>
#include <modelnet/swarm_fourscale/record.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * The four improvement scales, each with its own step.
 * open plants online, daily, weekly, and generational at step 0.
 * A second open is refused and does not write.
 * advance adds 1 to the named scale. The other three stay.
 * Before open, nothing is stored: size is 0 and every read is 0.
 */
class SwarmFourScaleBook {
public:
    bool opened() const;
    std::size_t size() const;
    bool holds(const std::string& scale) const;
    int64_t steps(const std::string& scale) const;

    /** Plant the four scales at step 0. Refuses when already open. */
    bool open();

    /**
     * Add 1 to one stored scale.
     * A closed book, an empty scale, and an unknown scale are refused
     * and leave every counter where it is.
     */
    bool advance(const std::string& scale);

private:
    bool m_opened{false};
    std::array<SwarmFourScaleRecord, kSwarmFourScaleCount> m_steps{};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FOURSCALE_BOOK_H
