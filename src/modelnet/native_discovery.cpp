// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying file COPYING.
#include <modelnet/native_discovery.h>

#include <modelnet/model_nat.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <limits>
#include <random>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <mswsock.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#ifdef __APPLE__
#include <net/if_dl.h>
#endif
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace modelnet {
namespace {
constexpr unsigned char MAGIC[8] = {'B','T','X','L','A','N',1,0};
constexpr char GROUP[] = "239.192.0.35";
int64_t Now()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
bool ValidNetwork(const std::string& s)
{
    return !s.empty() && s.size() < 16 && std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
    });
}
bool ValidPort(uint16_t port)
{
    // Never turn a multicast hint into a dial to a wallet/control/metadata port.
    if (port < 1024 || port == MODEL_LAN_DISCOVERY_PORT || IsForbiddenControlPort(port)) return false;
    for (uint16_t p : {29442, 29443, 29444, 29445, 29446}) {
        if (port == p) return false;
    }
    return true;
}
void CloseSocket(intptr_t fd)
{
#ifdef _WIN32
    closesocket(static_cast<SOCKET>(fd));
#else
    close(static_cast<int>(fd));
#endif
}
bool SocketOption(intptr_t fd, int level, int option, const void* data, size_t size)
{
    return setsockopt(
#ifdef _WIN32
        static_cast<SOCKET>(fd), level, option, static_cast<const char*>(data), static_cast<int>(size)
#else
        static_cast<int>(fd), level, option, data, static_cast<socklen_t>(size)
#endif
    ) == 0;
}
struct LanInterface {
    uint32_t address;
    uint32_t netmask;
    unsigned int index;
};
std::vector<LanInterface> Interfaces(const std::string& bind_host)
{
    std::vector<LanInterface> out;
    auto add = [&](const sockaddr* addr, uint32_t netmask, unsigned int index) {
        if (!addr || addr->sa_family != AF_INET) return;
        const uint32_t inverse = ~ntohl(netmask);
        if (!index || !netmask || (inverse & (inverse + 1)) != 0) return;
        const auto* a = reinterpret_cast<const sockaddr_in*>(addr);
        char ip[INET_ADDRSTRLEN]{};
        if (!inet_ntop(AF_INET, &a->sin_addr, ip, sizeof(ip)) || !LanHintSourceAllowed(ip)) return;
        if (!bind_host.empty() && bind_host != "0.0.0.0" && bind_host != ip) return;
        if (std::none_of(out.begin(), out.end(), [&](const auto& entry) {
            return entry.address == a->sin_addr.s_addr && entry.index == index;
        })) out.push_back({a->sin_addr.s_addr, netmask, index});
    };
#ifdef _WIN32
    ULONG size = 16384;
    std::vector<unsigned char> storage(size);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
    ULONG code = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER, nullptr, adapters, &size);
    if (code == ERROR_BUFFER_OVERFLOW && size <= 1024 * 1024) {
        storage.resize(size);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
        code = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
            GAA_FLAG_SKIP_DNS_SERVER, nullptr, adapters, &size);
    }
    if (code == NO_ERROR) for (auto* a = adapters; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            const unsigned int prefix = u->OnLinkPrefixLength;
            if (prefix == 0 || prefix > 32) continue;
            add(u->Address.lpSockaddr, htonl(0xffffffffU << (32 - prefix)), a->IfIndex);
        }
    }
#else
    ifaddrs* list = nullptr;
    if (getifaddrs(&list) == 0) {
        for (auto* a = list; a; a = a->ifa_next) {
            if (!(a->ifa_flags & IFF_UP) || !(a->ifa_flags & IFF_MULTICAST) || (a->ifa_flags & IFF_LOOPBACK)) continue;
            if (!a->ifa_netmask || a->ifa_netmask->sa_family != AF_INET) continue;
            add(a->ifa_addr, reinterpret_cast<const sockaddr_in*>(a->ifa_netmask)->sin_addr.s_addr,
                if_nametoindex(a->ifa_name));
        }
        freeifaddrs(list);
    }
#endif
    return out;
}

bool EnableReceiveInterface(intptr_t fd)
{
    int enabled = 1;
#if defined(__APPLE__)
    return SocketOption(fd, IPPROTO_IP, IP_RECVIF, &enabled, sizeof(enabled)) &&
        SocketOption(fd, IPPROTO_IP, IP_RECVDSTADDR, &enabled, sizeof(enabled));
#elif defined(_WIN32) || defined(__linux__)
    return SocketOption(fd, IPPROTO_IP, IP_PKTINFO, &enabled, sizeof(enabled));
#else
    return false;
#endif
}

// Missing/truncated ancillary data never becomes an implicit discovery hint.
// The socket still accepts unicast, but only to its selected interface address.
int ReceiveBeacon(intptr_t fd, unsigned char* wire, size_t size, sockaddr_in& from,
                  unsigned int& index, uint32_t& destination)
{
    index = 0;
    destination = 0;
#ifdef _WIN32
    GUID id = WSAID_WSARECVMSG;
    LPFN_WSARECVMSG receive = nullptr;
    DWORD returned = 0;
    if (WSAIoctl(static_cast<SOCKET>(fd), SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &id, sizeof(id), &receive, sizeof(receive), &returned, nullptr, nullptr) != 0 || !receive) return -1;
    WSABUF data{static_cast<ULONG>(size), reinterpret_cast<char*>(wire)};
    union { WSACMSGHDR align; char bytes[WSA_CMSG_SPACE(sizeof(IN_PKTINFO))]; } control{};
    WSAMSG msg{};
    msg.name = reinterpret_cast<sockaddr*>(&from);
    msg.namelen = sizeof(from);
    msg.lpBuffers = &data;
    msg.dwBufferCount = 1;
    msg.Control = {sizeof(control.bytes), control.bytes};
    DWORD got = 0;
    if (receive(static_cast<SOCKET>(fd), &msg, &got, nullptr, nullptr) != 0)
        return WSAGetLastError() == WSAEMSGSIZE ? 0 : -1;
    if (msg.namelen != sizeof(from) || (msg.dwFlags & (MSG_TRUNC | MSG_CTRUNC))) return 0;
    for (auto* c = WSA_CMSG_FIRSTHDR(&msg); c; c = WSA_CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO &&
            c->cmsg_len >= WSA_CMSG_LEN(sizeof(IN_PKTINFO))) {
            IN_PKTINFO packet{};
            std::memcpy(&packet, WSA_CMSG_DATA(c), sizeof(packet));
            index = packet.ipi_ifindex;
            destination = packet.ipi_addr.s_addr;
        }
    }
    return static_cast<int>(got);
#elif defined(__APPLE__) || defined(__linux__)
    iovec data{wire, size};
    union { cmsghdr align; unsigned char bytes[256]; } control{};
    msghdr msg{};
    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov = &data;
    msg.msg_iovlen = 1;
    msg.msg_control = control.bytes;
    msg.msg_controllen = sizeof(control.bytes);
    const auto got = recvmsg(static_cast<int>(fd), &msg, 0);
    if (got < 0) return -1;
    if (msg.msg_namelen != sizeof(from) || (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) return 0;
    for (auto* c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level != IPPROTO_IP) continue;
#ifdef __APPLE__
        if (c->cmsg_type == IP_RECVIF && c->cmsg_len >= CMSG_LEN(offsetof(sockaddr_dl, sdl_data))) {
            sockaddr_dl link{};
            std::memcpy(&link, CMSG_DATA(c), std::min(c->cmsg_len - CMSG_LEN(0), sizeof(link)));
            if (link.sdl_family == AF_LINK) index = link.sdl_index;
        }
        if (c->cmsg_type == IP_RECVDSTADDR && c->cmsg_len >= CMSG_LEN(sizeof(in_addr))) {
            in_addr address{};
            std::memcpy(&address, CMSG_DATA(c), sizeof(address));
            destination = address.s_addr;
        }
#else
        if (c->cmsg_type == IP_PKTINFO && c->cmsg_len >= CMSG_LEN(sizeof(in_pktinfo))) {
            in_pktinfo packet{};
            std::memcpy(&packet, CMSG_DATA(c), sizeof(packet));
            if (packet.ipi_ifindex > 0) index = static_cast<unsigned int>(packet.ipi_ifindex);
            destination = packet.ipi_addr.s_addr;
        }
#endif
    }
    return static_cast<int>(got);
#else
    return -1;
#endif
}
} // namespace

bool EncodeLanBeacon(const LanBeacon& value, std::array<unsigned char, MODEL_LAN_BEACON_SIZE>& bytes)
{
    if (!ValidNetwork(value.network) || !ValidPort(value.port) ||
        std::all_of(value.instance.begin(), value.instance.end(), [](unsigned char c) { return c == 0; })) return false;
    bytes.fill(0);
    std::copy(std::begin(MAGIC), std::end(MAGIC), bytes.begin());
    std::copy(value.network.begin(), value.network.end(), bytes.begin() + 8);
    bytes[24] = static_cast<unsigned char>(value.port >> 8);
    bytes[25] = static_cast<unsigned char>(value.port);
    std::copy(value.instance.begin(), value.instance.end(), bytes.begin() + 32);
    return true;
}

bool DecodeLanBeacon(const unsigned char* data, size_t size, const std::string& network, LanBeacon& out)
{
    if (!data || size != MODEL_LAN_BEACON_SIZE || !ValidNetwork(network) ||
        !std::equal(std::begin(MAGIC), std::end(MAGIC), data)) return false;
    size_t end = 8;
    while (end < 24 && data[end]) ++end;
    if (end == 24 || std::string(reinterpret_cast<const char*>(data + 8), end - 8) != network) return false;
    for (size_t i = end; i < 24; ++i) if (data[i] != 0) return false;
    for (size_t i = 26; i < 32; ++i) if (data[i] != 0) return false;
    LanBeacon value;
    value.network = network;
    value.port = static_cast<uint16_t>((uint16_t(data[24]) << 8) | data[25]);
    std::copy(data + 32, data + 48, value.instance.begin());
    std::array<unsigned char, MODEL_LAN_BEACON_SIZE> encoded{};
    if (!EncodeLanBeacon(value, encoded)) return false;
    out = value;
    return true;
}

bool LanHintSourceAllowed(const std::string& ip)
{
    in_addr addr{};
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) return false;
    const uint32_t a = ntohl(addr.s_addr);
    // Link-local includes cloud metadata services; never dial it from a hint.
    return (a & 0xff000000U) == 0x0a000000U ||
        (a & 0xfff00000U) == 0xac100000U || (a & 0xffff0000U) == 0xc0a80000U;
}

bool LanHintBook::Observe(const std::string& source, const LanBeacon& beacon, int64_t now_ms)
{
    std::array<unsigned char, MODEL_LAN_BEACON_SIZE> encoded{};
    if (now_ms < 0 || !LanHintSourceAllowed(source) || !EncodeLanBeacon(beacon, encoded)) return false;
    const auto endpoint = source + ":" + std::to_string(beacon.port);
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto it = m_seen.begin(); it != m_seen.end();) {
        if (now_ms < it->second || now_ms - it->second >= MODEL_LAN_HINT_TTL_MS) it = m_seen.erase(it);
        else ++it;
    }
    if (!m_seen.count(endpoint)) {
        if (m_seen.size() >= MODEL_LAN_MAX_HINTS) return false;
        size_t per_source = 0;
        for (const auto& entry : m_seen) if (entry.first.rfind(source + ":", 0) == 0) ++per_source;
        if (per_source >= 4) return false;
    }
    m_seen[endpoint] = now_ms;
    return true;
}

std::vector<std::string> LanHintBook::Endpoints(int64_t now_ms)
{
    std::vector<std::string> out;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto it = m_seen.begin(); it != m_seen.end();) {
        if (now_ms < it->second || now_ms - it->second >= MODEL_LAN_HINT_TTL_MS) it = m_seen.erase(it);
        else { out.push_back(it->first); ++it; }
    }
    return out;
}
void LanHintBook::Clear() { std::lock_guard<std::mutex> lock(m_mutex); m_seen.clear(); }

NativeLanDiscovery::~NativeLanDiscovery() { Close(); }
void NativeLanDiscovery::Close()
{
    if (m_fd != -1) CloseSocket(m_fd);
    m_fd = -1;
    m_hints.Clear();
    m_interfaces.clear();
    m_last_announce = -1;
}
bool NativeLanDiscovery::Open(const std::string& network, const std::string& bind_host,
                              uint16_t model_port, std::string& err)
{
    Close();
    if (!ValidNetwork(network) || !ValidPort(model_port)) { err = "LAN_CONFIG"; return false; }
    for (const auto& iface : Interfaces(bind_host)) m_interfaces.push_back({iface.address, iface.index});
    if (m_interfaces.empty()) { err = "LAN_NO_PRIVATE_INTERFACE"; return false; }
    m_self.network = network;
    m_self.port = model_port;
    try {
        std::random_device rng;
        for (auto& c : m_self.instance) c = static_cast<unsigned char>(rng());
    } catch (...) { err = "LAN_ENTROPY"; return false; }
    std::array<unsigned char, MODEL_LAN_BEACON_SIZE> encoded{};
    if (!EncodeLanBeacon(m_self, encoded)) { err = "LAN_ENTROPY"; return false; }
    m_fd = static_cast<intptr_t>(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
    if (m_fd == -1) { err = "LAN_SOCKET"; return false; }
    auto fail = [&](const char* reason) { Close(); err = reason; return false; };
    if (!EnableReceiveInterface(m_fd)) return fail("LAN_RECEIVE_SCOPE");
    int reuse = 1;
    if (!SocketOption(m_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) return fail("LAN_REUSE");
#if defined(__APPLE__) && defined(SO_REUSEPORT)
    if (!SocketOption(m_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse))) return fail("LAN_REUSE");
#endif
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(MODEL_LAN_DISCOVERY_PORT);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(m_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) return fail("LAN_BIND");
#ifdef _WIN32
    DWORD ttl = 1, loop = 1;
#else
    unsigned char ttl = 1, loop = 1;
#endif
    if (!SocketOption(m_fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) ||
        !SocketOption(m_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop))) return fail("LAN_SCOPE");
    std::vector<Interface> joined;
    for (const auto& iface : m_interfaces) {
        group_req membership{};
        membership.gr_interface = iface.index;
        auto* group = reinterpret_cast<sockaddr_in*>(&membership.gr_group);
        group->sin_family = AF_INET;
#ifdef __APPLE__
        group->sin_len = sizeof(*group);
#endif
        inet_pton(AF_INET, GROUP, &group->sin_addr);
        if (SocketOption(m_fd, IPPROTO_IP, MCAST_JOIN_GROUP, &membership, sizeof(membership))) joined.push_back(iface);
    }
    m_interfaces = std::move(joined);
    if (m_interfaces.empty()) return fail("LAN_JOIN");
#ifdef _WIN32
    u_long nonblocking = 1;
    if (ioctlsocket(static_cast<SOCKET>(m_fd), FIONBIO, &nonblocking)) return fail("LAN_NONBLOCK");
#else
    if (fcntl(m_fd, F_SETFL, fcntl(m_fd, F_GETFL, 0) | O_NONBLOCK) < 0 ||
        fcntl(m_fd, F_SETFD, FD_CLOEXEC) < 0) return fail("LAN_NONBLOCK");
#endif
    err.clear();
    return true;
}
void NativeLanDiscovery::Tick()
{
    if (m_fd == -1) return;
    const int64_t now = Now();
    if (m_last_announce < 0 || now < m_last_announce || now - m_last_announce >= 3000) {
        std::array<unsigned char, MODEL_LAN_BEACON_SIZE> wire{};
        if (EncodeLanBeacon(m_self, wire)) {
            sockaddr_in group{};
            group.sin_family = AF_INET;
            group.sin_port = htons(MODEL_LAN_DISCOVERY_PORT);
            inet_pton(AF_INET, GROUP, &group.sin_addr);
            for (const auto& iface : m_interfaces) {
                in_addr local{}; local.s_addr = iface.address;
                if (!SocketOption(m_fd, IPPROTO_IP, IP_MULTICAST_IF, &local, sizeof(local))) continue;
                (void)sendto(m_fd, reinterpret_cast<const char*>(wire.data()), wire.size(), 0,
                    reinterpret_cast<sockaddr*>(&group), sizeof(group));
            }
        }
        m_last_announce = now;
    }
    std::vector<LanInterface> current_interfaces;
    in_addr group{};
    inet_pton(AF_INET, GROUP, &group);
    bool have_interfaces = false;
    for (int i = 0; i < 32; ++i) {
        unsigned char wire[MODEL_LAN_BEACON_SIZE + 1]{};
        sockaddr_in from{};
        unsigned int index = 0;
        uint32_t destination = 0;
        const int got = ReceiveBeacon(m_fd, wire, sizeof(wire), from, index, destination);
        if (got < 0) break;
        if (!index || !destination || from.sin_family != AF_INET) continue;
        LanBeacon beacon;
        if (!DecodeLanBeacon(wire, static_cast<size_t>(got), m_self.network, beacon) || beacon.instance == m_self.instance) continue;
        if (!have_interfaces) {
            current_interfaces = Interfaces({});
            have_interfaces = true;
        }
        const bool on_link = std::any_of(current_interfaces.begin(), current_interfaces.end(), [&](const auto& iface) {
            return iface.index == index &&
                std::any_of(m_interfaces.begin(), m_interfaces.end(), [&](const auto& joined) {
                    return joined.address == iface.address && joined.index == index;
                }) &&
                (destination == group.s_addr || destination == iface.address) &&
                (from.sin_addr.s_addr & iface.netmask) == (iface.address & iface.netmask);
        });
        if (!on_link) continue;
        char ip[INET_ADDRSTRLEN]{};
        if (inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip))) m_hints.Observe(ip, beacon, now);
    }
}
std::vector<std::string> NativeLanDiscovery::Endpoints() { return m_hints.Endpoints(Now()); }

} // namespace modelnet
