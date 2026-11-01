// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include "request_listener.h"
#include <cstdio>

int main()
{
    try {
        rc_prover::Network network;
        if (!network.Ok()) return 1;
#ifdef _WIN32
        if (!rc_prover::RecoverableAcceptError(WSAECONNRESET) ||
            !rc_prover::RecoverableAcceptError(WSAEMFILE) ||
            !rc_prover::RecoverableAcceptError(WSAENOBUFS) ||
            rc_prover::RecoverableAcceptError(WSAENOTSOCK) ||
            rc_prover::AcceptNeedsBackoff(WSAECONNRESET) || !rc_prover::AcceptNeedsBackoff(WSAENOBUFS)) return 2;
#else
        if (!rc_prover::RecoverableAcceptError(ECONNABORTED) ||
            !rc_prover::RecoverableAcceptError(EMFILE) ||
            !rc_prover::RecoverableAcceptError(ENOBUFS) ||
            rc_prover::RecoverableAcceptError(EBADF) ||
            rc_prover::AcceptNeedsBackoff(ECONNABORTED) || !rc_prover::AcceptNeedsBackoff(EMFILE)) return 2;
#endif
        rc_prover::RequestListener listener{0};
        std::printf("%u\n", listener.Port());
        std::fflush(stdout);
        for (;;) {
            auto request{listener.Next()};
            if (request.line == "quit") return 0;
            if (request.line == "sleep") std::this_thread::sleep_for(std::chrono::milliseconds(2500));
            if (!rc_prover::WriteAll(request.socket->Get(), "ok\n", std::chrono::seconds(1))) continue;
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "%s\n", e.what());
        return 3;
    }
}
