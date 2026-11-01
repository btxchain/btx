// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include "token_file.h"
#include <cstdio>

int main(int argc, char** argv)
{
    if (argc != 3) return 2;
    const bool expected{std::string(argv[2]) == "accept"};
    try {
        const auto token{rc_prover::LoadPrivateToken(argv[1])};
        if (!expected || token.size() < 32 || token.size() > 4096) return 3;
    } catch (const std::exception&) {
        if (expected) return 4;
    }
    return 0;
}
