// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_MODEL_ADMISSION_H
#define BITCOIN_MODELNET_MODEL_ADMISSION_H

#include <modelnet/training_evidence.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

enum class Assurance {
    PUBLIC_STRICT,
    REALM_STRICT,
    RESEARCH_ONLY,
};

/** Admission outcome. A byte-hash match is not admission and cannot be served. */
struct AdmissionResult {
    bool admitted{false};
    bool research_execution_permit{false};
    std::string code;
    bool ServeAllowed() const;
};

struct ServeResult {
    bool allowed{false};
    std::string code;
};

/**
 * Strict modes admit only with a hash match, two distinct non-empty independent
 * roots, and FullReplayCoverage. Fewer than two roots with a hash match fails
 * BTX035_REPLAY. RESEARCH_ONLY plus owner_authorized yields a research execution
 * permit; ServeAllowed() on that result is false.
 * A root id evidenced only by publisher_only ancestry does not count.
 */
AdmissionResult Admit(Assurance assurance,
                      bool byte_hash_matches,
                      const std::vector<Interval>& intervals,
                      uint64_t total,
                      const std::string& start_state,
                      const std::string& final_state,
                      const std::vector<std::string>& independent_roots,
                      bool owner_authorized);

void Quarantine(const std::string& legacy_id);

/** Quarantine fails BTX035_QUARANTINE even when byte_hash_matches is true. */
ServeResult Serve(const std::string& legacy_id, bool byte_hash_matches);

} // namespace modelnet

#endif // BITCOIN_MODELNET_MODEL_ADMISSION_H
