// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_lanwire/swarm_lanwire.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <string>
#include <vector>

namespace {

/** One UDP descriptor. Close is idempotent and runs on every exit path. */
class DatagramFd {
public:
    DatagramFd() = default;
    ~DatagramFd() { Close(); }

    DatagramFd(const DatagramFd&) = delete;
    DatagramFd& operator=(const DatagramFd&) = delete;

    bool Open()
    {
        m_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        return m_fd >= 0;
    }

    int fd() const { return m_fd; }

    bool Close()
    {
        if (m_fd < 0) {
            return true;
        }
        const int fd = m_fd;
        m_fd = -1;
        for (;;) {
            if (::close(fd) == 0) {
                return true;
            }
            if (errno != EINTR) {
                return false;
            }
        }
    }

private:
    int m_fd{-1};
};

bool LoopbackAddress(in_addr& out)
{
    return ::inet_pton(AF_INET, "127.0.0.1", &out) == 1;
}

} // namespace

namespace modelnet {

bool SwarmLanWire::Exchange(const std::vector<unsigned char>& payload, std::string& err)
{
    if (payload.empty()) {
        err = kSwarmLanWirePayload;
        return false;
    }

    DatagramFd held;
    if (!held.Open()) {
        err = kSwarmLanWireSocket;
        return false;
    }

    in_addr loopback{};
    if (!LoopbackAddress(loopback)) {
        held.Close();
        err = kSwarmLanWireNoRoute;
        return false;
    }

    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(0);
    local.sin_addr = loopback;
    if (::bind(held.fd(), reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
        held.Close();
        err = kSwarmLanWireBind;
        return false;
    }

    sockaddr_in bound{};
    socklen_t bound_len = sizeof(bound);
    if (::getsockname(held.fd(), reinterpret_cast<sockaddr*>(&bound), &bound_len) != 0 ||
        bound_len < sizeof(sockaddr_in) || bound.sin_family != AF_INET ||
        bound.sin_addr.s_addr != loopback.s_addr || bound.sin_port == 0) {
        held.Close();
        err = kSwarmLanWirePort;
        return false;
    }

    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = static_cast<decltype(tv.tv_usec)>(kSwarmLanWireRecvTimeoutMs * 1000);
    if (::setsockopt(held.fd(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
        held.Close();
        err = kSwarmLanWireSocket;
        return false;
    }

    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = bound.sin_port;
    dest.sin_addr = loopback;
    const ssize_t sent = ::sendto(held.fd(), payload.data(), payload.size(), 0, reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
    if (sent < 0 || static_cast<size_t>(sent) != payload.size()) {
        held.Close();
        err = kSwarmLanWireSend;
        return false;
    }

    std::vector<unsigned char> got(payload.size());
    sockaddr_in from{};
    socklen_t from_len = sizeof(from);
    const ssize_t n = ::recvfrom(held.fd(), got.data(), got.size(), 0, reinterpret_cast<sockaddr*>(&from), &from_len);
    if (n < 0 || static_cast<size_t>(n) != payload.size() || from_len < sizeof(sockaddr_in) ||
        from.sin_family != AF_INET || from.sin_addr.s_addr != loopback.s_addr) {
        held.Close();
        err = kSwarmLanWireRecv;
        return false;
    }
    if (got != payload) {
        held.Close();
        err = kSwarmLanWireBytes;
        return false;
    }

    if (!held.Close()) {
        err = kSwarmLanWireSocket;
        return false;
    }

    m_received = got;
    m_packets = kSwarmLanWirePacketsOne;
    m_local_received = true;
    m_bytes_moved = static_cast<int64_t>(m_received.size());
    err.clear();
    return true;
}

bool SwarmLanWire::Wan(std::string& err)
{
    err = kSwarmLanWireNoRoute;
    return false;
}

bool SwarmLanWire::Scan(const std::string& /*prefix*/, std::string& err)
{
    err = kSwarmLanWireNotScan;
    return false;
}

const std::vector<unsigned char>& SwarmLanWire::received() const
{
    return m_received;
}

int64_t SwarmLanWire::packets() const
{
    return m_packets;
}

bool SwarmLanWire::local_received() const
{
    return m_local_received;
}

bool SwarmLanWire::wan_received() const
{
    return kSwarmLanWireWanReceived;
}

bool SwarmLanWire::connected() const
{
    return kSwarmLanWireConnected;
}

bool SwarmLanWire::launched() const
{
    return kSwarmLanWireLaunched;
}

bool SwarmLanWire::gpu() const
{
    return kSwarmLanWireGpu;
}

bool SwarmLanWire::broadcast() const
{
    return kSwarmLanWireBroadcast;
}

std::string SwarmLanWire::automatic_spend() const
{
    return std::string{kSwarmLanWireAutomaticSpend};
}

int64_t SwarmLanWire::bytes_moved() const
{
    return m_bytes_moved;
}

} // namespace modelnet
