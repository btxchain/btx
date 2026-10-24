// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying file COPYING.
#ifndef BITCOIN_MODELNET_NATIVE_DISCOVERY_H
#define BITCOIN_MODELNET_NATIVE_DISCOVERY_H

#include <array>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace modelnet {

/** A link-scoped hint only. A beacon cannot authorize work, storage, or a spend. */
struct LanBeacon {
    std::string network;
    uint16_t port{0};
    std::array<unsigned char, 16> instance{};
};

inline constexpr uint16_t MODEL_LAN_DISCOVERY_PORT = 29448;
inline constexpr size_t MODEL_LAN_BEACON_SIZE = 48;
inline constexpr int64_t MODEL_LAN_HINT_TTL_MS = 30000;
inline constexpr size_t MODEL_LAN_MAX_HINTS = 64;

bool EncodeLanBeacon(const LanBeacon&, std::array<unsigned char, MODEL_LAN_BEACON_SIZE>&);
bool DecodeLanBeacon(const unsigned char*, size_t, const std::string& network, LanBeacon&);
bool LanHintSourceAllowed(const std::string& numeric_ipv4);

/** Bounded, expiring hints. No address is admitted to monetary AddrMan. */
class LanHintBook {
public:
    bool Observe(const std::string& source, const LanBeacon&, int64_t now_ms);
    std::vector<std::string> Endpoints(int64_t now_ms);
    void Clear();
private:
    std::mutex m_mutex;
    std::map<std::string, int64_t> m_seen;
};

/**
 * Native IPv4 multicast discovery. Called by the existing model helper loop.
 * Packets contain a chain name, model transport port, and per-start nonce only.
 * The dial address is always recvfrom's source; no packet-supplied hostname/IP.
 * Every candidate still has to complete strict PQ1 and transport pin checks.
 */
class NativeLanDiscovery {
public:
    NativeLanDiscovery() = default;
    ~NativeLanDiscovery();
    NativeLanDiscovery(const NativeLanDiscovery&) = delete;
    NativeLanDiscovery& operator=(const NativeLanDiscovery&) = delete;
    bool Open(const std::string& network, const std::string& bind_host, uint16_t model_port, std::string& err);
    void Tick();
    void Close();
    std::vector<std::string> Endpoints();
    bool IsOpen() const { return m_fd != -1; }
private:
    intptr_t m_fd{-1};
    LanBeacon m_self;
    std::vector<uint32_t> m_interfaces;
    LanHintBook m_hints;
    int64_t m_last_announce{-1};
};

} // namespace modelnet
#endif
