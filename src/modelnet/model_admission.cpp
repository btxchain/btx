// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/model_admission.h>

#include <cstddef>
#include <unordered_map>
#include <unordered_set>

namespace modelnet {
namespace {

std::unordered_set<std::string>& QuarantineSet()
{
    static std::unordered_set<std::string> ids;
    return ids;
}

bool Strict(Assurance assurance)
{
    return assurance == Assurance::PUBLIC_STRICT || assurance == Assurance::REALM_STRICT;
}

/**
 * Distinct non-empty root ids. Ancestry that appears only on publisher-only
 * intervals is the producer's own coverage and is not an independent root.
 */
size_t CountIndependentRoots(const std::vector<std::string>& independent_roots,
                             const std::vector<Interval>& intervals)
{
    std::unordered_map<std::string, bool> ancestry_is_independent;
    for (const Interval& interval : intervals) {
        if (interval.ancestry.empty()) continue;
        if (Independent(interval)) {
            ancestry_is_independent[interval.ancestry] = true;
        } else {
            ancestry_is_independent.emplace(interval.ancestry, false);
        }
    }

    std::unordered_set<std::string> counted;
    for (const std::string& root_id : independent_roots) {
        if (root_id.empty()) continue;
        const auto it = ancestry_is_independent.find(root_id);
        if (it != ancestry_is_independent.end() && !it->second) continue;
        counted.insert(root_id);
    }
    return counted.size();
}

AdmissionResult Deny(const char* code)
{
    AdmissionResult result;
    result.code = code;
    return result;
}

} // namespace

bool AdmissionResult::ServeAllowed() const
{
    return admitted && code.empty() && !research_execution_permit;
}

AdmissionResult Admit(Assurance assurance,
                      bool byte_hash_matches,
                      const std::vector<Interval>& intervals,
                      uint64_t total,
                      const std::string& start_state,
                      const std::string& final_state,
                      const std::vector<std::string>& independent_roots,
                      bool owner_authorized)
{
    if (assurance == Assurance::RESEARCH_ONLY) {
        AdmissionResult result;
        if (!owner_authorized) return Deny("BTX035_SCOPE_DENIED");
        result.research_execution_permit = true;
        return result;
    }

    if (!Strict(assurance)) return Deny("BTX035_ADMISSION_DENIED");

    // Matching bytes are a prerequisite, never a substitute for replay roots.
    if (!byte_hash_matches) return Deny("BTX035_BYTE_HASH_MISMATCH");

    if (CountIndependentRoots(independent_roots, intervals) < 2) return Deny("BTX035_REPLAY");

    if (!FullReplayCoverage(total, start_state, final_state, intervals)) return Deny("BTX035_GAP");

    AdmissionResult result;
    result.admitted = true;
    return result;
}

void Quarantine(const std::string& legacy_id)
{
    QuarantineSet().insert(legacy_id);
}

ServeResult Serve(const std::string& legacy_id, bool byte_hash_matches)
{
    ServeResult result;
    if (QuarantineSet().count(legacy_id) != 0) {
        result.code = "BTX035_QUARANTINE";
        return result;
    }
    // A hash match does not admit or serve a legacy id.
    result.code = byte_hash_matches ? "BTX035_ADMISSION_REQUIRED" : "BTX035_BYTE_HASH_MISMATCH";
    return result;
}

} // namespace modelnet
