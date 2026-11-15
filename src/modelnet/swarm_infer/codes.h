// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_INFER_CODES_H
#define BTX_MODELNET_SWARM_INFER_CODES_H

namespace modelnet {

/** Result codes for the inference control plane. None of these is a measurement. */
struct SwarmInferCode {
    static constexpr const char* engine = "ENGINE";
    static constexpr const char* engine_absent = "ENGINE_ABSENT";
    static constexpr const char* installed = "INSTALLED";
    static constexpr const char* unqualified = "UNQUALIFIED";
    static constexpr const char* text = "TEXT";
    static constexpr const char* stored = "STORED";
    static constexpr const char* conflict = "CONFLICT";
    static constexpr const char* replay = "REPLAY";
    static constexpr const char* held = "HELD";
    static constexpr const char* closed = "CLOSED";
    static constexpr const char* not_started = "NOT_STARTED";
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_INFER_CODES_H
