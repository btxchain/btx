// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_ACT_KIND_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_ACT_KIND_H

#include <modelnet/swarm_sandboxgate/book.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * How one Act attempt relates to the stored grants.
 * Allow is the only result that may be recorded. The book is not modified.
 */
enum class SwarmSandboxGateActKind {
    Allow,
    NotGranted,
    Expired,
    Denied,
    PrivateData,
    Capability,
    NotActed,
};

/**
 * Classify one Act attempt.
 * An unknown worker is NotGranted.
 * When every matching grant has now_ms >= until_ms the result is Expired.
 * A path with no strict prefix match is Denied.
 * A path that begins with "private/" is PrivateData even when that prefix
 * was granted.
 * An empty capability is Capability.
 * A capability missing from every live match is NotActed.
 * A live match that lists the capability is Allow.
 */
SwarmSandboxGateActKind SwarmSandboxGateClassifyAct(const SwarmSandboxGateBook& book,
                                                    const std::string& worker,
                                                    const std::string& path,
                                                    const std::string& capability,
                                                    int64_t now_ms);

/**
 * Refusal code for a non-allow kind, or nullptr for Allow.
 */
const char* SwarmSandboxGateActKindCode(SwarmSandboxGateActKind kind);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_ACT_KIND_H
