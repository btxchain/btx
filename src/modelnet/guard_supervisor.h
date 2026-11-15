// Copyright (c) 2026 The BTX developers. MIT license. See COPYING.
#ifndef BITCOIN_MODELNET_GUARD_SUPERVISOR_H
#define BITCOIN_MODELNET_GUARD_SUPERVISOR_H
#include <util/fs.h>
#include <cstdint>
#include <memory>
#include <string>
class UniValue;
namespace modelnet {
struct GuardProcessStatus {
    bool enabled{false};
    bool ready{false};
    int64_t pid{-1};
    unsigned restart_count{0};
    std::string error;
};
/** Locate only the sibling shipped binary. Never search the working directory
 * or an untrusted PATH. Missing helper is an observable degraded condition. */
fs::path FindPackagedGuardd();
/** Owns one --stdio guard via private inherited IPC; no TCP listener. Calls are
 * serialized and each exchange is bounded. EOF shutdown, reaping and retry
 * backoff are independent of the monetary node. A guard permit receipt is
 * only PERMIT_CONSUMED / NOT_DISPATCHED, never evidence of model execution. */
class GuardSupervisor {
public:
    GuardSupervisor();
    ~GuardSupervisor();
    GuardSupervisor(const GuardSupervisor&) = delete;
    GuardSupervisor& operator=(const GuardSupervisor&) = delete;
    bool Start(const fs::path& executable, std::string& error);
    bool Start(const fs::path& executable, const fs::path& security_directory, std::string& error);
    bool SecurityExchange(const UniValue& request, UniValue& response, std::string& error);
    void Tick();
    void Stop();
    bool Exchange(const std::string& line, std::string& reply, std::string& error);
    GuardProcessStatus Snapshot() const;
private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};
} // namespace modelnet
#endif
