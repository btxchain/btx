// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/git_attestation/git_attestation.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

bool LowerHex64(const std::string& s)
{
    if (s.size() != 64) return false;
    for (unsigned char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

bool ExactEngine(const std::string& text)
{
    return text == "vllm" || text == "sglang" || text == "lmcache" ||
           text == "nixl" || text == "mooncake" || text == "rdma" ||
           text == "deepinfer" || text == "dualpipe" || text == "fp8" ||
           text == "fp4";
}

} // namespace

bool GitAttestation::stored() const
{
    return m_have;
}

std::string GitAttestation::subject() const
{
    return m_have ? m_subject : std::string();
}

std::string GitAttestation::digest() const
{
    return m_have ? m_digest : std::string();
}

bool GitAttestation::Attest(const std::string& subject, const std::string& digest, std::string& err)
{
    if (subject.empty() || digest.empty()) {
        err = "FIELD";
        return false;
    }
    if (subject == "account") {
        err = "ATTEST";
        return false;
    }
    if (!LowerHex64(digest)) {
        err = "DIGEST";
        return false;
    }
    if (subject.find("private") != std::string::npos || digest.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (ExactEngine(subject) || ExactEngine(digest)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (m_have) {
        if (m_subject == subject && m_digest == digest) {
            err = NIFDT_REPLAY;
            return false;
        }
        err = "UNCHANGED";
        return false;
    }
    m_subject = subject;
    m_digest = digest;
    m_have = true;
    err.clear();
    return true;
}

bool GitAttestation::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool GitAttestation::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool GitAttestation::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool GitAttestation::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool GitAttestation::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
