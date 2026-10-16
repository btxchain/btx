// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/admission_routes.h>

#include <mutex>
#include <unordered_map>
#include <utility>

namespace modelnet {
namespace {

std::mutex& StrictMu()
{
    static std::mutex mu;
    return mu;
}

std::unordered_map<std::string, StrictAdmissionRecord>& StrictModels()
{
    static std::unordered_map<std::string, StrictAdmissionRecord> models;
    return models;
}

bool RouteDecision(const std::string& model_id, bool byte_hash_matches, std::string& admission)
{
    // Quarantine wins over a hash match and over a record that would serve.
    if (Serve(model_id, true).code == "BTX035_QUARANTINE") {
        admission = "BTX035_QUARANTINE";
        return false;
    }

    StrictAdmissionRecord record;
    {
        std::lock_guard<std::mutex> lock(StrictMu());
        const auto it = StrictModels().find(model_id);
        if (it == StrictModels().end()) {
            admission.clear();
            return true;
        }
        record = it->second;
    }

    const AdmissionResult result = Admit(record.assurance, byte_hash_matches, record.intervals, record.total,
                                         record.start_state, record.final_state, record.independent_roots,
                                         record.owner_authorized);
    if (!result.ServeAllowed()) {
        admission = result.code;
        return false;
    }
    admission.clear();
    return true;
}

} // namespace

void RegisterStrictModel(const std::string& model_id, StrictAdmissionRecord record)
{
    std::lock_guard<std::mutex> lock(StrictMu());
    StrictModels()[model_id] = std::move(record);
}

bool RouteMayServe(const std::string& model_id, bool byte_hash_matches, std::string& admission)
{
    return RouteDecision(model_id, byte_hash_matches, admission);
}

bool RouteMayGenerate(const std::string& model_id, bool byte_hash_matches, std::string& admission)
{
    return RouteDecision(model_id, byte_hash_matches, admission);
}

bool LivePathAllowed(const std::string& model_id, bool generate, std::string& code)
{
    std::string admission;
    const bool ok = generate ? RouteMayGenerate(model_id, true, admission) : RouteMayServe(model_id, true, admission);
    if (!ok) {
        code = admission.empty() ? "BTX035_ADMISSION" : admission;
        return false;
    }
    code.clear();
    return true;
}

} // namespace modelnet
