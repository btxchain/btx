// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/proc07/proc07.h>

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_discover/swarm_discover.h>

#include <cstdint>
#include <string>

namespace modelnet {

namespace {

const char* const kPeer = "local-worker";
const char* const kScope = "lan";
const char* const kEndpoint = "local";
const char* const kTask = "task-1";
const int64_t kUntilMs = 100;
const int64_t kNowMs = 0;

static_assert(2 * 3 + 1 == 7, "local inference value");

} // namespace

bool Proc07::DiscoverLocal(std::string& err)
{
    if (!m_discover.Offer(kPeer, kScope, kEndpoint, kUntilMs, kNowMs, err)) {
        return false;
    }
    if (!m_discover.Grant(kPeer, kScope, err)) {
        return false;
    }
    if (!m_discover.Use(kPeer, err)) {
        return false;
    }
    m_discovery_ok = true;
    return true;
}

bool Proc07::AssignTask(const std::string& task_id, std::string& err)
{
    if (task_id.empty()) {
        err = "FIELD";
        return false;
    }
    m_task_id = task_id;
    m_assignment_ok = true;
    return true;
}

bool Proc07::RunLocal(bool cloud_enabled, std::string& err)
{
    if (cloud_enabled) {
        err = "CLOUD";
        return false;
    }
    if (m_local) {
        err.clear();
        return true;
    }
    if (!DiscoverLocal(err)) {
        return false;
    }
    if (!AssignTask(kTask, err)) {
        return false;
    }
    m_output = static_cast<int64_t>(2) * static_cast<int64_t>(3) + static_cast<int64_t>(1);
    m_inference_ok = true;
    m_cloud_used = false;
    m_local = true;
    err.clear();
    return true;
}

bool Proc07::AskCloud(const std::string& provider, std::string& err)
{
    if (provider.empty()) {
        err = "FIELD";
        return false;
    }
    err = "ABSENT";
    return false;
}

} // namespace modelnet
