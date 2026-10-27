// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvwire/pair.h>

#include <modelnet/swarm_kvwire/codes.h>

#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <string>
#include <vector>

namespace modelnet {
namespace {

class FdPair {
public:
    int write_fd{-1};
    int read_fd{-1};

    FdPair() = default;
    ~FdPair() { Close(); }
    FdPair(const FdPair&) = delete;
    FdPair& operator=(const FdPair&) = delete;

    void Close()
    {
        if (write_fd >= 0) {
            ::close(write_fd);
            write_fd = -1;
        }
        if (read_fd >= 0) {
            ::close(read_fd);
            read_fd = -1;
        }
    }
};

bool WriteFull(int fd, const unsigned char* data, std::size_t len, std::string& err)
{
    std::size_t off = 0;
    while (off < len) {
        const ssize_t n = ::write(fd, data + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            err = kSwarmKvWireIo;
            return false;
        }
        if (n == 0) {
            err = kSwarmKvWireIo;
            return false;
        }
        off += static_cast<std::size_t>(n);
    }
    return true;
}

bool ReadFull(int fd, unsigned char* data, std::size_t len, std::string& err)
{
    std::size_t off = 0;
    while (off < len) {
        const ssize_t n = ::read(fd, data + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            err = kSwarmKvWireIo;
            return false;
        }
        if (n == 0) {
            err = kSwarmKvWireIo;
            return false;
        }
        off += static_cast<std::size_t>(n);
    }
    return true;
}

} // namespace

bool SwarmKvWireCarry(const std::vector<unsigned char>& body, std::vector<unsigned char>& out, std::string& err)
{
    if (body.empty()) {
        err = kSwarmKvWirePage;
        return false;
    }

    int fds[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        err = kSwarmKvWireIo;
        return false;
    }
    FdPair open;
    open.write_fd = fds[0];
    open.read_fd = fds[1];

    // The full body is written to one end. Each chunk is small enough to
    // sit in an empty stream buffer, then the other end is read until those
    // bytes arrive. A short write or a short read continues until every
    // byte of the body has moved or the call fails.
    constexpr std::size_t kChunk = 4096;
    std::vector<unsigned char> got(body.size());
    std::size_t sent = 0;
    while (sent < body.size()) {
        const std::size_t want = body.size() - sent < kChunk ? body.size() - sent : kChunk;
        if (!WriteFull(open.write_fd, body.data() + sent, want, err)) {
            return false;
        }
        if (!ReadFull(open.read_fd, got.data() + sent, want, err)) {
            return false;
        }
        sent += want;
    }

    open.Close();
    if (got != body) {
        err = kSwarmKvWireIo;
        return false;
    }
    out = std::move(got);
    err.clear();
    return true;
}

} // namespace modelnet
