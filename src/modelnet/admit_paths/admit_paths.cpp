// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/admit_paths/admit_paths.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

bool KnownPath(const std::string& path)
{
    static const char* const kPaths[] = {
        "hostmodel",
        "importmodel",
        "seedmodel",
        "watched",
        "demand-seed",
        "peer-follow",
        "cloud-mirror",
        "encrypted-release",
        "bundle-import",
        "package-install",
        "hosted-gateway",
        "direct-api",
        "capability",
        "local-generate",
        "model-rollout",
    };
    for (const char* row : kPaths) {
        if (path == row) return true;
    }
    return false;
}

bool Contains(const std::vector<std::string>& rows, const std::string& path)
{
    for (const std::string& row : rows) {
        if (row == path) return true;
    }
    return false;
}

} // namespace

bool AdmitPaths::noted(const std::string& path) const
{
    return Contains(m_noted, path);
}

bool AdmitPaths::quarantined(const std::string& path) const
{
    return Contains(m_quarantine, path);
}

bool AdmitPaths::Note(const std::string& path, std::string& err)
{
    if (path.empty() || !KnownPath(path)) {
        err = "PATH";
        return false;
    }
    if (noted(path)) {
        err = NIFDT_REPLAY;
        return false;
    }
    m_noted.push_back(path);
    err.clear();
    return true;
}

bool AdmitPaths::Wired(const std::string& path) const
{
    if (noted(path)) return false;
    if (quarantined(path)) return false;
    if (KnownPath(path)) return false;
    return false;
}

bool AdmitPaths::Serve(const std::string& path, std::string& err)
{
    if (quarantined(path)) {
        err = "QUARANTINE";
        return false;
    }
    err = "UNWIRED";
    return false;
}

bool AdmitPaths::Quarantine(const std::string& path, std::string& err)
{
    if (path.empty() || !KnownPath(path)) {
        err = "PATH";
        return false;
    }
    if (quarantined(path)) {
        err = NIFDT_REPLAY;
        return false;
    }
    m_quarantine.push_back(path);
    err.clear();
    return true;
}

bool AdmitPaths::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool AdmitPaths::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool AdmitPaths::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool AdmitPaths::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
