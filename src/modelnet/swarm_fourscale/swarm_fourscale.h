// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FOURSCALE_H
#define BITCOIN_MODELNET_SWARM_FOURSCALE_H

#include <modelnet/swarm_fourscale/book.h>
#include <modelnet/swarm_fourscale/quiet.h>
#include <modelnet/swarm_fourscale/realm.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Four-timescale plane.
 * online, daily, weekly, and generational each keep their own step.
 * They are not averaged and they do not graduate.
 *
 * Open plants those four scales at step 0 and returns true.
 * A second Open is REPLAY and leaves every step where it is.
 *
 * Step before Open is SCALE and stores nothing.
 * An unknown scale, including empty, is SCALE and stores nothing.
 * A known scale increments only that scale by 1 and returns true.
 *
 * Average always returns false with NOT_AVERAGED and does not change any step.
 * Graduate always returns false with REALM. graduated() stays false.
 * The steps stay.
 *
 * bytes_moved() stays 0. gpu() stays false.
 */
class SwarmFourScale {
public:
    bool Open(std::string& err);
    bool Step(const std::string& scale, std::string& err);
    bool Average(std::string& err) const;
    bool Graduate(std::string& err) const;

    /** True after the first Open has planted the four scales. */
    bool opened() const;

    /** True when scale is one of the four and Open has planted it. */
    bool holds(const std::string& scale) const;

    /** 0 before Open. 4 after Open. Unknown names are not added. */
    std::size_t scale_count() const;

    /**
     * Step stored for scale.
     * A closed plane and an unknown scale read as 0.
     */
    int64_t steps(const std::string& scale) const;

    /** Stays false. Graduate does not set it. */
    bool graduated() const;

    /** Stays 0. */
    int64_t bytes_moved() const;

    /** Stays false. */
    bool gpu() const;

private:
    SwarmFourScaleBook m_book;
    SwarmFourScaleQuiet m_quiet;
    SwarmFourScaleRealm m_realm;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FOURSCALE_H
