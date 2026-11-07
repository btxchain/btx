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
    /** Exact byte digest this strict model must match. Empty when the caller did not name one. */
    std::string digest;
};

void RegisterStrictModel(const std::string& model_id, StrictAdmissionRecord record);

/** An explicit legacy id keeps the historical allow path. Quarantine still denies it. */
void RegisterLegacyModel(const std::string& model_id);

/**
 * Durable admission for one model id and digest. `decision` is ADMITTED or a
 * refusal such as REVOKED. An admission for one id does not cover another.
 */
bool RecordModelAdmission(const std::string& model_id, const std::string& digest, const std::string& decision, std::string& err);

/** Revocation denies serving even when an older record says ADMITTED. */
void RevokeModel(const std::string& model_id);

/** Drop process memory of the registry. The durable file is left in place. */
void ClearAdmissionMemory();

/** Remember a quarantine id and write it into the registry file when a lab directory is set. */
void RememberQuarantine(const std::string& model_id);

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
 * activate a model. Reloads the durable registry under the lab directory.
 * A strict id is denied until an admission names that id and digest and says
 * ADMITTED. Explicit legacy ids stay allowed. Quarantine and revocation deny.
 * An id with neither a strict nor a legacy record stays on the allow path.
 * `code` is empty on success and a BTX035_* code on refusal.
 */
bool LivePathAllowed(const std::string& model_id, bool generate, std::string& code);

} // namespace modelnet

#endif // BITCOIN_MODELNET_ADMISSION_ROUTES_H
