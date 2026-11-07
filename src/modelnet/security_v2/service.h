// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BITCOIN_MODELNET_SECURITY_V2_SERVICE_H
#define BITCOIN_MODELNET_SECURITY_V2_SERVICE_H
#include <modelnet/security_v2/broker.h>
#include <modelnet/security_v2/lifecycle.h>
#include <modelnet/security_v2/peer.h>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <memory>
#include <thread>
namespace modelnet::security {
/** Owned by btx-guardd. All calls are local authenticated owner/control IPC.
 * Peer network ingress is a separate, narrower function in peer.h. */
class Service {
    struct Impl;
    std::unique_ptr<Impl> m;
public:
    explicit Service(fs::path root);
    ~Service();
    Service(const Service&)=delete;
    Service& operator=(const Service&)=delete;
    Json Handle(const Json& request);
};
/** Bounded streaming framing for the existing 4096-byte private guard pipe.
 * No JSON is placed on the legacy effect-string protocol. */
class GuardProtocol {
    Service& m_service;
    std::string m_input_id,m_input,m_output_id,m_output;
    uint64_t m_expected{0},m_deadline{0};
public:
    explicit GuardProtocol(Service& service):m_service(service){}
    std::string Handle(std::string_view line);
};
} // namespace modelnet::security
#endif
