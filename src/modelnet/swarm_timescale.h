// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_TIMESCALE_H
#define BTX_MODELNET_SWARM_TIMESCALE_H

#include <util/fs.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Append one record to the matching timescale array. The four arrays stay
 * separate. A prompt is refused and is not written.
 */
bool SwarmRecordTimescale(const fs::path& modeldir, const std::string& scale, const std::string& kind,
                          const std::string& body, const std::string& checkpoint_id, const std::string& recipe,
                          std::string& err);

/** Return a stored public finding. A missing finding is NOT_FOUND, not a prompt. */
bool SwarmReuseFinding(const fs::path& modeldir, const std::string& query, std::string& found, std::string& err);

/** Refuse work that would pass the host memory cap. */
bool SwarmWithinMemory(int64_t used_bytes, int64_t cap_bytes, std::string& err);

} // namespace modelnet

#endif
