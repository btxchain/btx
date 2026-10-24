// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WATCHHOLD_H
#define BITCOIN_MODELNET_SWARM_WATCHHOLD_H

#include <modelnet/swarm_watchhold/cursor.h>
#include <modelnet/swarm_watchhold/note.h>
#include <modelnet/swarm_watchhold/secret.h>
#include <modelnet/swarm_watchhold/silence.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Watched-sequence plane.
 * A watched sequence never releases a secret by itself. Nothing is broadcast.
 *
 * Observe stores a greater sequence as latest. sequence below 1 is SEQUENCE
 * and stores nothing. sequence below latest is STALE and does not change
 * latest. sequence equal to latest is REPLAY. secret_released() stays false
 * after every Observe.
 *
 * Release always returns HELD. secret_released() stays false. No secret
 * bytes are stored.
 *
 * Refund while a sequence has been observed returns HELD and does not
 * broadcast. The close margin is 160. refund_height below height + 160 is
 * MARGIN and nothing is stored. Refund before any sequence is SEQUENCE and
 * stores nothing. Equality with height + 160 meets the margin.
 *
 * broadcast() stays false. bytes_moved() stays 0. mined() stays false.
 */
class SwarmWatchHold {
public:
    bool Observe(int64_t sequence, std::string& err);
    bool Release(std::string& err);
    bool Refund(int64_t height, int64_t refund_height, std::string& err);

    int64_t latest() const;
    bool observed() const;
    bool secret_released() const;
    std::size_t secret_bytes() const;
    bool broadcast() const;
    bool mined() const;
    int64_t bytes_moved() const;
    bool refund_noted() const;
    bool refund_built() const;
    int64_t noted_height() const;
    int64_t noted_refund_height() const;

private:
    SwarmWatchHoldCursor m_cursor;
    SwarmWatchHoldSecret m_secret;
    SwarmWatchHoldSilence m_silence;
    SwarmWatchHoldNote m_note;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WATCHHOLD_H
