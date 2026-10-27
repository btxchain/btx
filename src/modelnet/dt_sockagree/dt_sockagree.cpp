// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_sockagree/dt_sockagree.h>
#include <modelnet/nifdt_contract/contract.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {
namespace {

class Pair {
public:
    Pair() = default;
    Pair(const Pair&) = delete;
    Pair& operator=(const Pair&) = delete;
    ~Pair() { Close(); }

    bool Open(std::string& err)
    {
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, m_fd) != 0) {
            err = DT_SOCKAGREE_IO;
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
        m_fd[0] = -1;
        m_fd[1] = -1;
        m_open = false;
    }

    int WriteEnd() const { return m_fd[0]; }
    int ReadEnd() const { return m_fd[1]; }

private:
    int m_fd[2]{-1, -1};
    bool m_open{false};
};

void StoreLe(unsigned char* out, int64_t value)
{
    std::uint64_t bits = static_cast<std::uint64_t>(value);
    for (int i = 0; i < 8; ++i) {
        out[i] = static_cast<unsigned char>(bits & 0xffu);
        bits >>= 8;
    }
}

int64_t LoadLe(const unsigned char* in)
{
    std::uint64_t bits = 0;
    for (int i = 0; i < 8; ++i) {
        bits |= static_cast<std::uint64_t>(in[i]) << (8 * i);
    }
    return static_cast<int64_t>(bits);
}

bool WriteFull(int fd, const unsigned char* data, size_t n)
{
    size_t off = 0;
    while (off < n) {
        const ssize_t wrote = ::write(fd, data + off, n - off);
        if (wrote < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (wrote == 0) return false;
        off += static_cast<size_t>(wrote);
    }
    return true;
}

size_t ReadUpTo(int fd, unsigned char* data, size_t n)
{
    size_t off = 0;
    while (off < n) {
        const ssize_t got = ::read(fd, data + off, n - off);
        if (got < 0) {
            if (errno == EINTR) continue;
            return off;
        }
        if (got == 0) return off;
        off += static_cast<size_t>(got);
    }
    return off;
}

} // namespace

bool DtSockAgree::Compare(int64_t left, int64_t right, std::string& err)
{
    if (m_agreed) {
        err = NIFDT_REPLAY;
        return false;
    }

    unsigned char raw[16];
    unsigned char got[16];
    size_t nread = 0;
    bool wrote = false;
    {
        Pair pair;
        if (!pair.Open(err)) return false;
        StoreLe(raw, left);
        StoreLe(raw + 8, right);
        wrote = WriteFull(pair.WriteEnd(), raw, sizeof raw);
        if (wrote) nread = ReadUpTo(pair.ReadEnd(), got, sizeof raw);
        pair.Close();
    }

    if (!wrote || nread != sizeof raw) {
        err = DT_SOCKAGREE_IO;
        return false;
    }
    if (LoadLe(got) != left || LoadLe(got + 8) != right) {
        err = DT_SOCKAGREE_IO;
        return false;
    }
    for (size_t i = 0; i < sizeof raw; ++i) {
        if (raw[i] != got[i]) {
            err = DT_SOCKAGREE_IO;
            return false;
        }
    }

    m_bytes = static_cast<int64_t>(16);
    if (left != right) {
        err = DT_SOCKAGREE_DISAGREE;
        return false;
    }
    m_agreed = true;
    err.clear();
    return true;
}

bool DtSockAgree::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
