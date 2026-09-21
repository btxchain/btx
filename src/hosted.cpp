// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/hcp.h>
#include <util/translation.h>

#include <csignal>
#include <iostream>
#include <string>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

int main(int argc, char* argv[])
{
    std::signal(SIGPIPE, SIG_IGN);
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i) args.emplace_back(argv[i]);
    std::string out, err;
    const int rc = modelnet::RunHostedCli(args, out, err);
    if (!out.empty()) std::cout << out;
    if (!err.empty()) std::cerr << err;
    return rc;
}
