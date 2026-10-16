// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ADMISSION_ROUTES_H
#define BITCOIN_MODELNET_ADMISSION_ROUTES_H

#include <modelnet/model_admission.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Evidence passed to Admit() on a later serve or generate, except the
 * per-call byte hash. RESEARCH_ONLY never makes ServeAllowed() true.
 */
struct StrictAdmissionRecord {
    Assurance assurance{Assurance::PUBLIC_STRICT};
    std::vector<Interval> intervals;
    uint64_t total{0};
    std::string start_state;
    std::string final_state;
    std::vector<std::string> independent_roots;
    bool owner_authorized{false};
};

void RegisterStrictModel(const std::string& model_id, StrictAdmissionRecord record);

/**
 * Quarantine fails BTX035_QUARANTINE even when byte_hash_matches is true.
 * A RegisterStrictModel record is allowed only when Admit() is ServeAllowed();
 * a hash match alone is not enough. No record and no quarantine returns true
 * so existing 0.34 call sites keep their current behavior.
 * On failure, admission is the Admit() code, or BTX035_QUARANTINE.
 * On success, admission is empty.
 */
bool RouteMayServe(const std::string& model_id, bool byte_hash_matches, std::string& admission);
bool RouteMayGenerate(const std::string& model_id, bool byte_hash_matches, std::string& admission);

/**
 * Live host, seed, publish, load, and generate paths call this before they
 * activate a model. An unregistered id with no quarantine stays allowed.
 * `code` is empty on success and a BTX035_* code on refusal.
 */
bool LivePathAllowed(const std::string& model_id, bool generate, std::string& code);

} // namespace modelnet

#endif // BITCOIN_MODELNET_ADMISSION_ROUTES_H
