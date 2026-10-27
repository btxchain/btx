// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/prf03/prf03.h>
#include <modelnet/admission_routes.h>
#include <modelnet/lab_disk.h>
#include <modelnet/model_admission.h>
#include <modelnet/nifdt_contract/contract.h>
#include <util/fs.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

const char* const kId = "prf03-strict";
const char* const kOther = "prf03-other";
const char* const kDigest = "prf03-digest";
const char* const kOtherDigest = "prf03-other-digest";

struct AdmissionClear {
    ~AdmissionClear() { ClearAdmissionMemory(); }
};

bool Fail(std::string& err, const std::string& code)
{
    err = code;
    return false;
}

StrictAdmissionRecord Strict(const std::string& digest)
{
    StrictAdmissionRecord record;
    record.assurance = Assurance::PUBLIC_STRICT;
    record.digest = digest;
    record.owner_authorized = false;
    return record;
}

bool RegistryPresent(std::string& err)
{
    const fs::path path = LabDiskDirectory() / "admission-registry.json";
    try {
        if (!fs::is_regular_file(path)) return Fail(err, "BTX035_RECOVERY_REQUIRED");
    } catch (const std::filesystem::filesystem_error&) {
        return Fail(err, "BTX035_RECOVERY_REQUIRED");
    }
    return true;
}

bool ExpectDenied(const std::string& model_id, bool generate, const char* want, std::string& err)
{
    std::string code = "stale";
    if (LivePathAllowed(model_id, generate, code)) return Fail(err, want);
    if (code != want) return Fail(err, code);
    return true;
}

bool ExpectDeniedBoth(const std::string& model_id, const char* want, std::string& err)
{
    if (!ExpectDenied(model_id, false, want, err)) return false;
    return ExpectDenied(model_id, true, want, err);
}

bool ExpectAllowed(const std::string& model_id, bool generate, std::string& err)
{
    std::string code = "stale";
    if (!LivePathAllowed(model_id, generate, code) || !code.empty()) {
        return Fail(err, code.empty() ? std::string("BTX035_ADMISSION") : code);
    }
    return true;
}

bool ExpectAllowedBoth(const std::string& model_id, std::string& err)
{
    if (!ExpectAllowed(model_id, false, err)) return false;
    return ExpectAllowed(model_id, true, err);
}

} // namespace

bool Prf03::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    if (LabDiskDirectory().empty()) return Fail(err, "BTX035_RECOVERY_REQUIRED");

    AdmissionClear clear;
    ClearAdmissionMemory();

    RegisterStrictModel(kId, Strict(kDigest));
    if (!RegistryPresent(err)) return false;
    if (!ExpectDeniedBoth(kId, "BTX035_ADMISSION", err)) return false;

    // Same digest, different id. Admission of the first must not cover it.
    RegisterStrictModel(kOther, Strict(kDigest));
    if (!ExpectDeniedBoth(kOther, "BTX035_ADMISSION", err)) return false;

    if (!RecordModelAdmission(kId, kOtherDigest, "ADMITTED", err)) return false;
    if (!ExpectDeniedBoth(kId, "BTX035_ADMISSION", err)) return false;
    if (!ExpectDeniedBoth(kOther, "BTX035_ADMISSION", err)) return false;

    if (!RecordModelAdmission(kId, kDigest, "ADMITTED", err)) return false;
    if (!ExpectAllowedBoth(kId, err)) return false;
    if (!ExpectDeniedBoth(kOther, "BTX035_ADMISSION", err)) return false;

    Quarantine(kId);
    if (!ExpectDeniedBoth(kId, "BTX035_QUARANTINE", err)) return false;
    if (!ExpectDeniedBoth(kOther, "BTX035_ADMISSION", err)) return false;

    m_done = true;
    err.clear();
    return true;
}

bool Prf03::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Prf03::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Prf03::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Prf03::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Prf03::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
