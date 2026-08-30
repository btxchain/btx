// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_NODE_DISCOVERY_RELAY_H
#define BTX_NODE_DISCOVERY_RELAY_H

#include <netaddress.h>
#include <protocol.h>
#include <sync.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <vector>

namespace node::discovery_relay {

//! How far a connected peer's VERSION height may sit from the
//! recent-network watermark and still count as "on the recent
//! GPU-reported network." This is introduction policy, not fork choice
//! and not HasQuorum. 72 matches the emergency local-finality depth.
//! The watermark may be raised by public miners or archives; it is not
//! an archive-only oracle.
inline constexpr int32_t RECENT_HEIGHT_LAG{72};

//! Serving GPU attestors advertise both independent ExactReplay and
//! GETMMATTEST serve. Public DNS/relays must not gossip those IPs
//! (live GPU attestors). Public miners advertise CONSENSUS without ARCHIVE.
[[nodiscard]] inline bool ServicesLookLikeServingGpuAttestor(uint64_t services)
{
    return (services & NODE_MATMUL_CONSENSUS) &&
           (services & NODE_MATMUL_ATTESTATION_ARCHIVE);
}

//! Addresses a discovery relay may return in GETADDR / addr gossip.
//! Hides serving GPU attestors. Allows IBD sources, archives, public
//! miners, and other discovery relays.
[[nodiscard]] inline bool MayAdvertiseAddress(uint64_t services)
{
    if (ServicesLookLikeServingGpuAttestor(services)) return false;
    return (services & NODE_NETWORK) ||
           (services & NODE_NETWORK_LIMITED) ||
           (services & NODE_MATMUL_CONSENSUS) ||
           (services & NODE_MATMUL_TRUSTED_MIRROR) ||
           (services & NODE_MATMUL_ATTESTATION_ARCHIVE) ||
           (services & NODE_MATMUL_DISCOVERY);
}

inline Mutex& HiddenAddrMutex()
{
    static Mutex mutex;
    return mutex;
}

inline std::vector<CNetAddr>& HiddenAddrs()
{
    static std::vector<CNetAddr> addrs;
    return addrs;
}

inline void ResetHiddenNetAddrs()
{
    LOCK(HiddenAddrMutex());
    HiddenAddrs().clear();
}

inline void AddHiddenNetAddr(const CNetAddr& addr)
{
    if (!addr.IsValid()) return;
    LOCK(HiddenAddrMutex());
    auto& addrs{HiddenAddrs()};
    if (std::find(addrs.begin(), addrs.end(), addr) == addrs.end()) {
        addrs.push_back(addr);
    }
}

[[nodiscard]] inline bool IsHiddenNetAddr(const CNetAddr& addr)
{
    LOCK(HiddenAddrMutex());
    const auto& addrs{HiddenAddrs()};
    return std::find(addrs.begin(), addrs.end(), addr) != addrs.end();
}

//! Services plus the operator hide list. Used at ADDR ingest, GETADDR,
//! connected-peer push, and getnodeaddresses.
[[nodiscard]] inline bool MayAdvertiseEndpoint(uint64_t services,
                                               const CNetAddr& addr)
{
    return MayAdvertiseAddress(services) && !IsHiddenNetAddr(addr);
}

//! Relays must not fill AddrMan from random inbound ADDR (cheap Sybil).
//! Learn from outbound, addnode/manual, or DNS addr-fetch only — the
//! channel archives use after they followed the GPU pin.
//!
//! This is INGEST of gossip, not "may we remember the peer we are
//! already TCP-connected to." Mixing the two was why 45 tip-class
//! inbounds were connected and missing from addrman: GETADDR extra-push
//! reused this helper and skipped every inbound.
[[nodiscard]] inline bool MayLearnAddressFromPeer(bool inbound,
                                                  bool manual,
                                                  bool addr_fetch)
{
    if (manual || addr_fetch) return true;
    return !inbound;
}

//! Third-highest NODE_NETWORK VERSION height among currently connected
//! peers. Max is one inbound Sybil at INT_MAX; median of a 185109-heavy
//! inbound set is the stale cohort. Third-highest survives two fakes
//! and still tracks the live cluster (measured: 65 tip-class inbounds).
[[nodiscard]] inline int32_t RobustConnectedWatermark(
    std::vector<int32_t> network_peer_heights)
{
    if (network_peer_heights.empty()) return -1;
    std::sort(network_peer_heights.begin(), network_peer_heights.end(),
              [](int32_t a, int32_t b) { return a > b; });
    const size_t idx{std::min(network_peer_heights.size() - 1, size_t{2})};
    return network_peer_heights[idx];
}

[[nodiscard]] inline int32_t EffectiveIntroductionWatermark(
    int32_t archive_reported_height,
    const std::vector<int32_t>& network_peer_heights)
{
    const int32_t connected{RobustConnectedWatermark(network_peer_heights)};
    if (archive_reported_height < 0) return connected;
    if (connected < 0) return archive_reported_height;
    return std::max(archive_reported_height, connected);
}

//! ADDR_FETCH (-seednode / DNS) currently requires NODE_NETWORK via
//! GetDesirableServiceFlags. Relays advertise NODE_MATMUL_DISCOVERY
//! without NODE_NETWORK, so the handshake must keep that one exception.
//! Do not add DISCOVERY to GetDesirableServiceFlags: that would make
//! relays outbound full-node candidates.
[[nodiscard]] inline bool AddrFetchMayKeepDiscoveryPeer(uint64_t services)
{
    return (services & NODE_MATMUL_DISCOVERY) == NODE_MATMUL_DISCOVERY;
}

//! Keep a DISCOVERY-only hop we already connected to, so GETADDR can
//! run. DNS uses ADDR_FETCH. Compiled seeds are stamped NETWORK by
//! ConvertSeeds, then VERSION reveals DISCOVERY; without this keep the
//! full-outbound hop is dropped before GETADDR (fresh-datadir
//! dnsseed=0: both compiled IPs, 200000908 vs 00000009).
//! addr_fetch is accepted for call-site compatibility; DISCOVERY-only
//! is enough. Inbound still uses GetDesirableServiceFlags because
//! ExpectServicesFromConn is false there.
[[nodiscard]] inline bool HandshakeKeepsDiscoveryPeer(bool addr_fetch,
                                                      uint64_t services)
{
    (void)addr_fetch;
    return AddrFetchMayKeepDiscoveryPeer(services);
}

//! Discovery-only: DISCOVERY without NODE_NETWORK / NODE_NETWORK_LIMITED.
//! Full nodes that also set DISCOVERY are not this class.
[[nodiscard]] inline bool ServicesAreDiscoveryOnly(uint64_t services)
{
    if ((services & NODE_MATMUL_DISCOVERY) != NODE_MATMUL_DISCOVERY) {
        return false;
    }
    return (services & (NODE_NETWORK | NODE_NETWORK_LIMITED)) == 0;
}

//! Inbound discovery-only eclipse cap. Manual/addnode and outbound
//! ADDR_FETCH are unlimited here. Default 4 so a Sybil ring cannot fill
//! every inbound slot with NODE_MATMUL_DISCOVERY relays.
inline constexpr int MAX_INBOUND_DISCOVERY_ONLY{4};

[[nodiscard]] inline bool MayAcceptInboundDiscoveryPeer(
    bool inbound,
    bool manual,
    uint64_t services,
    int inbound_discovery_only_count,
    int cap = MAX_INBOUND_DISCOVERY_ONLY)
{
    if (!inbound || manual) return true;
    if (!ServicesAreDiscoveryOnly(services)) return true;
    if (cap < 0) return false;
    return inbound_discovery_only_count < cap;
}

//! 5.2 Discovery-slot slowloris: occupy inbound discovery-only slots
//! without completing VERACK (VERSION may already have set services so
//! the peer counts against the eclipse cap). Key on connection age, not
//! never-received — drip-fed bytes must not hold the slot for 20min.
//! Handshake-complete idle stays stock TIMEOUT_INTERVAL.
[[nodiscard]] inline bool DiscoverySlowlorisShouldRelease(
    bool inbound,
    bool discovery_only,
    bool handshake_complete,
    std::chrono::seconds connected_age,
    std::chrono::seconds incomplete_timeout = std::chrono::seconds{15})
{
    if (!inbound || !discovery_only) return false;
    if (handshake_complete) return false;
    return connected_age >= incomplete_timeout;
}

//! Only outbound/manual NODE_NETWORK peers that participate in the
//! chain (public miners, archives, trusted mirrors) may raise the
//! "recent network" watermark. Their VERSION height is introduction
//! policy, not fork choice and not HasQuorum. Random inbound heights
//! are Sybil. After the first sample, later raises must stay within
//! RECENT_HEIGHT_LAG so one peer cannot CAS INT_MAX and freeze GETADDR.
//! Public miners (CONSENSUS without ARCHIVE) count: the relay must not
//! depend on CPU archives as the only recent-network oracle.
[[nodiscard]] inline bool MayRaiseArchiveReportedHeight(
    bool inbound,
    bool manual,
    uint64_t services,
    int32_t starting_height,
    int32_t current_watermark = -1)
{
    if (starting_height < 0) return false;
    if (inbound && !manual) return false;
    if (!(services & NODE_NETWORK)) return false;
    const bool recent_source{
        (services & NODE_MATMUL_CONSENSUS) ||
        (services & NODE_MATMUL_ATTESTATION_ARCHIVE) ||
        (services & NODE_MATMUL_TRUSTED_MIRROR)};
    if (!recent_source) return false;
    if (current_watermark < 0) return true;
    if (starting_height <= current_watermark) return false;
    return (starting_height - current_watermark) <= RECENT_HEIGHT_LAG;
}

//! Connected peer is on the recent GPU-reported network if its VERSION
//! height is within RECENT_HEIGHT_LAG of the watermark. No GETMMATTEST.
//! No pin. No FindMostWorkChain.
//!
//! Watermark < 0 means no miner/archive sample yet. Passing every
//! versioned peer in that case made seed GETADDR introduction vacuous
//! (measured: discovery_archive_reported_height=-1, every inbound
//! classified "recent"). Fail closed; callers that have connected
//! NODE_NETWORK peers must pass EffectiveIntroductionWatermark first
//! (addnode'd miners bootstrap from that, not from this -1 hatch).
[[nodiscard]] inline bool PeerLooksOnRecentNetwork(int32_t peer_starting_height,
                                                   int32_t archive_reported_height,
                                                   int32_t max_lag = RECENT_HEIGHT_LAG)
{
    if (peer_starting_height < 0) return false;
    if (archive_reported_height < 0) return false;
    if (max_lag < 0) return false;
    const int64_t delta{
        static_cast<int64_t>(peer_starting_height) -
        static_cast<int64_t>(archive_reported_height)};
    return delta <= max_lag && delta >= -static_cast<int64_t>(max_lag);
}

//! Advertise a currently-connected peer's own endpoint on GETADDR.
//! Distinct from MayLearnAddressFromPeer. Discovery-only peers are not
//! IBD sources; do not hand them to a bootstrapping consensus node.
[[nodiscard]] inline bool MayAdvertiseConnectedPeer(uint64_t services,
                                                    int32_t starting_height,
                                                    int32_t effective_watermark)
{
    if (!MayAdvertiseAddress(services)) return false;
    if (ServicesAreDiscoveryOnly(services)) return false;
    return PeerLooksOnRecentNetwork(starting_height, effective_watermark);
}

//! Mark an inbound handshake as eligible to remember a listen endpoint.
//! This must NOT persist the accepted TCP socket: that address is the
//! peer's ephemeral SOURCE port, not the port they listen on. Gossiping
//! source ports made reachable listeners undialable network-wide.
//! Persist only a later same-IP self-ADDR
//! (MayRetainInboundSelfAnnouncement).
[[nodiscard]] inline bool MayRetainInboundHandshake(bool inbound,
                                                    bool routable,
                                                    uint64_t services,
                                                    int32_t starting_height,
                                                    int32_t effective_watermark)
{
    if (!inbound || !routable) return false;
    return MayAdvertiseConnectedPeer(services, starting_height,
                                     effective_watermark);
}

//! Persist an inbound peer's self-advertised listen endpoint. Never the
//! TCP source port of the accepted socket. Eligibility is VERSION-time
//! (MayRetainInboundHandshake). Same-IP binds the announcement to the
//! peer we already have a handshake with — not their ADDR gossip of
//! third parties (Sybil). CGNAT/hairpin (announced IP ≠ source IP) is
//! not retained: better than poisoning addrman with a dead source port.
//! Do not reject advertised_port == source_port: a listener can reuse
//! its listen port as the outbound source (SO_REUSEADDR).
[[nodiscard]] inline bool MayRetainInboundSelfAnnouncement(
    bool inbound,
    bool retain_eligible,
    bool advertised_routable,
    bool same_ip,
    bool may_advertise_endpoint)
{
    if (!inbound || !retain_eligible) return false;
    if (!advertised_routable || !same_ip) return false;
    return may_advertise_endpoint;
}

//! RB-15 (all nodes): drop an inbound peer's self-ADDR that carries the
//! ACCEPTED SOURCE port -- the ephemeral, undialable endpoint of the accepted
//! socket. The peer's real listen endpoint arrives on a different port, so
//! this loses nothing while keeping addrman/gossip free of unreachable entries.
[[nodiscard]] inline bool IsInboundSourcePortSelfAnnouncement(
    bool inbound,
    bool same_netaddr,
    bool same_port)
{
    return inbound && same_netaddr && same_port;
}

//! GETADDR extra-push of a currently-connected peer's socket address.
//! Outbound/manual endpoints are the address we dialed (listen port).
//! Inbound socket addresses are ephemeral source ports and must never
//! be gossiped — extra-push their self-advertised listen endpoint
//! instead, once ADDR has supplied it.
[[nodiscard]] inline bool MayPushConnectedPeerSocketAddress(bool inbound)
{
    return !inbound;
}

} // namespace node::discovery_relay

#endif // BTX_NODE_DISCOVERY_RELAY_H
