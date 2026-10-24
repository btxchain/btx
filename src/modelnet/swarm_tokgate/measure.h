// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_MEASURE_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_MEASURE_H

#include <modelnet/swarm_tokgate/book.h>
#include <modelnet/swarm_tokgate/latency.h>

#include <string>

namespace modelnet {

/**
 * Refuse to record a latency.
 * An unknown session is SESSION.
 * Every open session is NOT_MEASURED.
 * ttft_ms, p50_ms, and p95_ms stay -1. measured stays false.
 * Reading those sentinels does not mark them measured.
 */
bool SwarmTokenGateMeasureRefuse(const SwarmTokenGateBook& book,
                                 const SwarmTokenGateLatency& latency,
                                 const std::string& session,
                                 std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_MEASURE_H
