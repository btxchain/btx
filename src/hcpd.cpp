// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/hcp.h>
#include <util/fs.h>
#include <util/translation.h>

#include <atomic>
#include <csignal>
#include <iostream>
#include <string>

const TranslateFn G_TRANSLATION_FUN{nullptr};

static std::atomic<bool> g_stop{false};
static void OnSignal(int) { g_stop.store(true); }

int main(int argc, char* argv[])
{
    std::signal(SIGINT, OnSignal);
    std::signal(SIGTERM, OnSignal);
    std::signal(SIGPIPE, SIG_IGN);
    bool finance = false;
    bool cr12_flag = false;
    bool cr12_set = false;
    std::string bind = "127.0.0.1:8780";
    fs::path datadir;
    std::string instance;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "-help" || a == "--help") {
            std::cerr <<
                "btx-hcpd — Hosted Control Plane gateway (0.34.8-dev)\n"
                "Loopback HTTP only. Not consensus. Not a wallet proxy.\n"
                "  -bind=127.0.0.1:port\n"
                "  -walletless (default)\n"
                "  -finance=0|1  (FUNDING profile; lab only)\n"
                "  -cr12=0|1     (Cognitive Reserve Layer v1.2; walletless analytics OK)\n"
                "  -datadir=<dir>\n"
                "  -instance=<id>\n"
                "automatic_spend_atoms stays 0.\n";
            return 0;
        }
        if (a == "-version") {
            std::cout << "btx-hcpd 0.34.8-dev HCP/1+CR11+CR12\n";
            return 0;
        }
        if (a.rfind("-bind=", 0) == 0) bind = a.substr(6);
        else if (a.rfind("-datadir=", 0) == 0) datadir = fs::PathFromString(a.substr(9));
        else if (a == "-finance=1") finance = true;
        else if (a == "-finance=0" || a == "-walletless" || a == "-walletless=1") finance = false;
        else if (a == "-cr12=1") {
            cr12_flag = true;
            cr12_set = true;
        } else if (a == "-cr12=0") {
            cr12_flag = false;
            cr12_set = true;
        } else if (a.rfind("-instance=", 0) == 0) instance = a.substr(10);
    }
    modelnet::HcpConfig cfg = finance ? modelnet::HcpFundingLabPreset() : modelnet::HcpWalletlessPreset();
    if (cr12_set) cfg.cr12_enabled = cr12_flag;
    if (!datadir.empty()) cfg.persist_dir = datadir;
    if (!instance.empty()) cfg.instance_id = instance;
    cfg.automatic_spend_atoms = 0;
    fs::path sock;
    return modelnet::RunHcpDaemon(cfg, bind, sock, &g_stop);
}
