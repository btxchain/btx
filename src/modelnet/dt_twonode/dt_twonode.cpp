// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_twonode/dt_twonode.h>

#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <utility>

namespace modelnet {
namespace {

class Ends {
public:
    Ends() = default;
    Ends(const Ends&) = delete;
    Ends& operator=(const Ends&) = delete;
    ~Ends() { Close(); }
    bool Open(std::string& err)
    {
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, m_fd) != 0) {
            err = "SOCKET";
            return false;
        }
        m_open = true;
        return true;
    }
    void Close()
    {
        if (!m_open) return;
        ::close(m_fd[0]);
        ::close(m_fd[1]);
        m_open = false;
    }
    int operator[](int i) const { return m_fd[i]; }

private:
    int m_fd[2]{-1, -1};
    bool m_open{false};
};

bool WriteFull(int fd, const unsigned char* data, size_t n)
{
    size_t off = 0;
    while (off < n) {
        const ssize_t w = ::write(fd, data + off, n - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (w == 0) return false;
        off += static_cast<size_t>(w);
    }
    return true;
}

bool ReadFull(int fd, unsigned char* data, size_t n)
{
    size_t off = 0;
    while (off < n) {
        const ssize_t r = ::read(fd, data + off, n - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (r == 0) return false;
        off += static_cast<size_t>(r);
    }
    return true;
}

} // namespace

bool DtTwoNode::Exchange(const std::vector<unsigned char>& from_a, const std::vector<unsigned char>& from_b, std::string& err)
{
    if (from_a.empty() || from_b.empty()) {
        err = "PAYLOAD";
        return false;
    }
    Ends ends;
    if (!ends.Open(err)) return false;
    const int64_t before = m_bytes;
    if (!WriteFull(ends[0], from_a.data(), from_a.size()) || !WriteFull(ends[1], from_b.data(), from_b.size())) {
        err = "SOCKET";
        return false;
    }
    std::vector<unsigned char> got_b(from_a.size());
    std::vector<unsigned char> got_a(from_b.size());
    if (!ReadFull(ends[1], got_b.data(), got_b.size()) || !ReadFull(ends[0], got_a.data(), got_a.size())) {
        err = "SOCKET";
        return false;
    }
    m_b = std::move(got_b);
    m_a = std::move(got_a);
    m_bytes = before + static_cast<int64_t>(from_a.size() + from_b.size());
    err.clear();
    return true;
}

bool DtTwoNode::GpuRank(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
