// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/capability.h>
#include <util/fs.h>
#include <util/translation.h>

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>

const TranslateFn G_TRANSLATION_FUN{nullptr};

static std::atomic<bool> g_stop{false};

static void OnSignal(int)
{
    g_stop.store(true);
}

static void Usage()
{
    std::cerr <<
        "btx-capabilityd — owner-local BTX capability service (0.34.8-dev)\n"
        "\n"
        "Local resolve/plan/ensure/load lifecycle only. Not public HTTP.\n"
        "Not a remote inference marketplace. automatic_spend_atoms stays 0.\n"
        "If this process exits, monetary BTX and btx-modeld continue independently.\n"
        "\n"
        "  -modeldir=<dir>              catalog directory (never wallet/chainstate)\n"
        "  -capabilitysocket=<path>    unix JSON-RPC socket\n"
        "  -version                    print version and exit\n"
        "  -help                       print this message\n";
}

int main(int argc, char* argv[])
{
    fs::path modeldir;
    fs::path sock;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "-help" || a == "-h" || a == "--help") {
            Usage();
            return 0;
        }
        if (a == "-version" || a == "--version") {
            std::cout << "btx-capabilityd 0.34.8-dev\n";
            return 0;
        }
        if (a.rfind("-modeldir=", 0) == 0) modeldir = fs::PathFromString(a.substr(std::string("-modeldir=").size()));
        else if (a.rfind("-capabilitysocket=", 0) == 0) sock = fs::PathFromString(a.substr(std::string("-capabilitysocket=").size()));
        else {
            std::cerr << "unknown argument: " << a << "\n";
            Usage();
            return 1;
        }
    }
    if (modeldir.empty()) modeldir = fs::PathFromString("modelnet-data");
    std::signal(SIGINT, OnSignal);
    std::signal(SIGTERM, OnSignal);
    std::signal(SIGPIPE, SIG_IGN);
    return modelnet::RunCapabilityDaemon(modeldir, sock, &g_stop);
}
