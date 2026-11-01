// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include "socket_io.h"
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

int main(int argc, char** argv)
{
    using namespace rc_prover;
    Network network;
    if (!network.Ok() || argc != 3) return 2;
    const unsigned long port{std::stoul(argv[1])};
    const std::string mode{argv[2]};
    OwnedSocket s{socket(AF_INET, SOCK_STREAM, 0)};
    sockaddr_in addr{}; addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); addr.sin_port = htons(static_cast<uint16_t>(port));
    if (!s.Valid() || connect(s.Get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) return 3;
    std::string reply;
    if (mode == "write_timeout") {
        const auto start{std::chrono::steady_clock::now()};
        const bool sent{WriteAll(s.Get(), std::string(32u << 20, 'x'), std::chrono::milliseconds(150))};
        const auto elapsed{std::chrono::steady_clock::now() - start};
        return !sent && elapsed < std::chrono::seconds(3) ? 0 : 4;
    }
    if (!WriteAll(s.Get(), "{\"nonce64\":18446744073709551615}\n", std::chrono::seconds(2))) return 5;
    const auto start{std::chrono::steady_clock::now()};
    const bool ok{ReadLine(s.Get(), reply, std::chrono::milliseconds(150), 128)};
    const auto elapsed{std::chrono::steady_clock::now() - start};
    if (mode == "echo") return ok && reply == "{\"nonce64\":18446744073709551615}" ? 0 : 6;
    if (mode == "crlf") return ok && reply == "ok\r" ? 0 : 7;
    if (mode == "timeout" || mode == "slow" || mode == "eof" || mode == "oversize") return !ok && elapsed < std::chrono::seconds(3) ? 0 : 8;
    return 9;
}
