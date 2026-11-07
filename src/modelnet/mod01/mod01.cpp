// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/mod01/mod01.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

const char* const kKnown[] = {
    "git_origin",
    "git_attestation",
    "agent_lineage",
    "agent_guard",
    "incident",
    "realm_promotion",
    "fleet_rollout",
    "git_remote",
    "slice_source",
    "slice_views",
    "slice_replay",
    "slice_admit",
    "slice_guard",
    "slice_wan",
    "slice_qualify",
};

bool Known(const std::string& id)
{
    for (const char* row : kKnown) {
        if (id == row) return true;
    }
    return false;
}

bool ExactAbsentEngine(const std::string& text)
{
    return text == "vllm" || text == "sglang" || text == "lmcache" ||
           text == "nixl" || text == "mooncake" || text == "rdma" ||
           text == "deepinfer" || text == "dualpipe" || text == "fp8" ||
           text == "fp4";
}

bool JourneyId(const std::string& id)
{
    return id == "slice_source" || id == "slice_views" || id == "slice_replay" ||
           id == "slice_admit" || id == "slice_guard" || id == "slice_wan";
}

} // namespace

bool Mod01::stored(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return true;
    }
    return false;
}

std::string Mod01::text(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return row.text;
    }
    return std::string();
}

std::string Mod01::classification() const
{
    return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
}

bool Mod01::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
{
    if (id.empty() || !Known(id)) {
        err = "ID";
        return false;
    }
    if (text.empty()) {
        err = "FIELD";
        return false;
    }
    if (aux < static_cast<int64_t>(0)) {
        err = "BOUND";
        return false;
    }
    if (aux > static_cast<int64_t>(100)) {
        err = "CAP";
        return false;
    }
    if (!flag) {
        err = "ABSENT";
        return false;
    }
    if (ExactAbsentEngine(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (id == "slice_qualify" && (text == "windows" || text == "macos" || text == "gpu")) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (JourneyId(id) || id == "slice_qualify") {
        err = "JOURNEY";
        return false;
    }
    if (id == "git_origin" && text == "sha1") {
        err = "DIGEST";
        return false;
    }
    if (id == "git_attestation" && text == "account") {
        err = "ATTEST";
        return false;
    }
    if (id == "agent_lineage" && text == "inherit") {
        err = "GRANT";
        return false;
    }
    if (id == "agent_guard" && text == "inprocess") {
        err = "PROCESS";
        return false;
    }
    if (id == "incident" && text == "blocklist") {
        err = "SCOPE";
        return false;
    }
    if (id == "realm_promotion" && text == "one") {
        err = "QUORUM";
        return false;
    }
    if (id == "fleet_rollout" && text == "complete") {
        err = "STATE";
        return false;
    }
    if (id == "git_remote" && text == "shell") {
        err = "HELPER";
        return false;
    }
    for (const Row& row : m_rows) {
        if (row.id != id) continue;
        if (row.text == text) {
            err = NIFDT_REPLAY;
            return false;
        }
        err = "UNCHANGED";
        return false;
    }
    m_rows.push_back(Row{id, text});
    err.clear();
    return true;
}

bool Mod01::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Mod01::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Mod01::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Mod01::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Mod01::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
