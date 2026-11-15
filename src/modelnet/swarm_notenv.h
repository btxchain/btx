// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTENV_H
#define BTX_MODELNET_SWARM_NOTENV_H

#include <string>

namespace modelnet {

/**
 * A local note about one feature. env_required asks for a manual environment
 * variable. want_enable asks for a feature switch.
 *
 * Normal use must not require a manual environment variable or feature switch.
 * enabled stays false on every path. required_env stays false on every path.
 */
struct SwarmNotEnv {
    std::string feature_id;
    bool env_required{false};
    bool want_enable{false};
};

/**
 * Outcome of noting an environment request. enabled stays false on every path.
 * required_env stays false on every path.
 * Normal use must not require a manual environment variable or feature switch.
 */
struct SwarmNotEnvResult {
    std::string code;
    bool enabled{false};
    bool required_env{false};
};

/**
 * Note an environment request without requiring a manual environment variable
 * or feature switch.
 * Order, first match wins: an empty feature_id is FEATURE.
 * env_required or want_enable is NO_SWITCH.
 * Otherwise the note is NOTED and err is clear.
 * enabled stays false on every path. required_env stays false on every path.
 * Normal use must not require a manual environment variable or feature switch.
 */
SwarmNotEnvResult SwarmNoteNotEnv(const SwarmNotEnv& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTENV_H
