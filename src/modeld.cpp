// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/auto_storage.h>
#include <modelnet/helper.h>
#include <modelnet/policy.h>
#include <modelnet/resource_uri.h>
#include <modelnet/transport_pq.h>
#include <util/translation.h>

#include <openssl/crypto.h>

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
        "btx-modeld — BTX Native Model Network helper (0.34.7)\n"
        "\n"
        "Inference is local after a model is acquired. This process is not a remote\n"
        "inference marketplace and has no monetary consensus authority.\n"
        "If this process exits, monetary BTX continues independently.\n"
        "\n"
        "BTX MUST NOT autonomously retrieve arbitrary advertised models. Once the\n"
        "operator allocates a storage budget and a user retrieves a qualified public\n"
        "model, the default policy retains and re-advertises it (demand propagation).\n"
        "Configured -modelpeer catalogs are followed automatically (quota-limited).\n"
        "Arbitrary advertised models are not fetched. Rare-network fetches still\n"
        "require -modelpreserverare=1.\n"
        "\n"
        "  -decode=<uri>          decode a btx:// resource and exit\n"
        "  -modeldir=<dir>        catalog/store directory (never wallet/chainstate)\n"
        "  -modelstorage=<size>  payload quota: auto (default), 0, 80GiB. Alias: -modelcache\n"
        "  -modelcache=<size>   alias of -modelstorage; packaged default auto\n"
        "  -modelstorageautocap=<size>  AUTO hard cap (default 512GiB)\n"
        "  -modelfreespacereserve=<size>  AUTO free-space reserve override\n"
        "  -modelseed=auto|manual|off  default auto (demand-seed after import/getmodel)\n"
        "  -modelseedupondownload=0|1  B0 alias of -modelseed=off|auto; not a second opt-in\n"
        "  -modelpreserverare     fetch qualified under-replicated models into spare quota\n"
        "  -modelfollowpeers=0|1  follow FREE catalogs of -modelpeer / PEX contacts (default 1)\n"
        "  -modeluploadlimit=<bps>  aggregate serving cap (0 = connection ceilings only)\n"
        "  -modelallowencrypted   allow preserve-rare of unqualified ciphertext\n"
        "  -modelbind=<ip:port>  PQ1 TLS listen address (empty = unix RPC only)\n"
        "  -modelrpcsocket=<path> unix JSON-RPC socket\n"
        "  -modeltransport=pq1  only accepted value; anything else fail-closes\n"
        "  -modeltlscert=<file>  self-signed ML-DSA certificate\n"
        "  -modeltlskey=<file>   matching private key\n"
        "  -modelpeer=<host:port>  model-plane bootstrap contact (repeatable)\n"
        "  -modelseednode=<host:port>  alias of -modelpeer\n"
        "  -modelrelay            CPU-only discovery relay (no GPU, no wallet)\n"
        "  -modelhost             serve seeded artifacts over PQ1\n"
        "  -version              print helper and OpenSSL versions and exit\n"
        "  -help                 print this message\n";
}

int main(int argc, char* argv[])
{
    modelnet::HelperConfig cfg;
    std::string decode;
    std::string transport = "pq1";
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto take = [&](const char* key) -> std::string {
            const std::string k = std::string(key) + "=";
            if (a.rfind(k, 0) == 0) return a.substr(k.size());
            return {};
        };
        if (a == "-help" || a == "-h" || a == "--help") {
            Usage();
            return 0;
        }
        if (a == "-version" || a == "--version") {
            std::cout << "btx-modeld 0.34.7\n" << OpenSSL_version(OPENSSL_VERSION) << "\n";
            return 0;
        }
        if (a == "-modelrelay") cfg.relay = true;
        else if (a == "-modelhost") cfg.host = true;
        else if (a == "-modelpreserverare") cfg.preserve_rare = true;
        else if (a == "-modelfollowpeers") cfg.follow_peers = true;
        else if (a == "-modelallowencrypted") cfg.allow_encrypted = true;
        else if (a.rfind("-decode=", 0) == 0) decode = a.substr(8);
        else if (a == "-decode" && i + 1 < argc) decode = argv[++i];
        else if (auto v = take("-modeldir"); !v.empty()) cfg.modeldir = v.c_str();
        else if (auto v = take("-modelstorage"); !v.empty()) {
            std::string err;
            if (!modelnet::ParseModelStorage(v, cfg.storage_mode, cfg.quota_bytes, err)) {
                std::cerr << err << "\n";
                return 1;
            }
        } else if (auto v = take("-modelcache"); !v.empty()) {
            std::string err;
            if (!modelnet::ParseModelStorage(v, cfg.storage_mode, cfg.quota_bytes, err)) {
                std::cerr << err << "\n";
                return 1;
            }
        } else if (auto v = take("-modelstorageautocap"); !v.empty()) {
            std::string err;
            if (!modelnet::ParseModelBytes(v, cfg.auto_cap_bytes, err)) {
                std::cerr << err << "\n";
                return 1;
            }
        } else if (auto v = take("-modelfreespacereserve"); !v.empty()) {
            std::string err;
            if (!modelnet::ParseModelBytes(v, cfg.free_space_reserve_bytes, err)) {
                std::cerr << err << "\n";
                return 1;
            }
        } else if (auto v = take("-modelseedupondownload"); !v.empty()) {
            modelnet::SeedMode mode;
            if (!modelnet::SeedModeFromName(v, mode)) {
                std::cerr << "invalid -modelseedupondownload\n";
                return 1;
            }
            cfg.seed = modelnet::SeedModeName(mode);
        } else if (auto v = take("-modelseednode"); !v.empty()) cfg.peers.push_back(v);
        else if (auto v = take("-modelseed"); !v.empty()) cfg.seed = v;
        else if (auto v = take("-modelpreserverare"); !v.empty()) {
            cfg.preserve_rare = !(v == "0" || v == "false" || v == "off");
        } else if (auto v = take("-modelfollowpeers"); !v.empty()) {
            cfg.follow_peers = !(v == "0" || v == "false" || v == "off");
        } else if (auto v = take("-modeluploadlimit"); !v.empty()) {
            std::string err;
            if (!modelnet::ParseModelBytes(v, cfg.upload_bps, err)) {
                std::cerr << err << "\n";
                return 1;
            }
        } else if (auto v = take("-modelbind"); !v.empty()) cfg.bind = v;
        else if (auto v = take("-modelrpcsocket"); !v.empty()) cfg.rpc_socket = v.c_str();
        else if (auto v = take("-modeltransport"); !v.empty()) transport = v;
        else if (auto v = take("-modeltlscert"); !v.empty()) cfg.tls_cert = v.c_str();
        else if (auto v = take("-modeltlskey"); !v.empty()) cfg.tls_key = v.c_str();
        else if (auto v = take("-modelpeer"); !v.empty()) cfg.peers.push_back(v);
        else {
            std::cerr << "unknown argument: " << a << "\n";
            Usage();
            return 1;
        }
    }
    if (!decode.empty()) {
        modelnet::Resource r;
        std::string err;
        if (!modelnet::DecodeResource(decode, r, err)) {
            std::cerr << err << "\n";
            return 1;
        }
        std::cout << r.Uri() << " " << modelnet::ResourceKindName(r.kind) << " " << r.digest.Hex() << "\n";
        return 0;
    }
    if (transport != "pq1") {
        std::cerr << "model subsystem fail-closed: -modeltransport must be pq1\n";
        return 2;
    }
    modelnet::SeedMode seed_mode;
    if (!modelnet::SeedModeFromName(cfg.seed, seed_mode)) {
        std::cerr << "-modelseed must be auto, manual, or off\n";
        return 1;
    }
    if (cfg.modeldir.empty()) cfg.modeldir = "modelnet-data";
    if (cfg.host && cfg.bind.empty()) cfg.bind = "127.0.0.1:29447";

    std::signal(SIGINT, OnSignal);
    std::signal(SIGTERM, OnSignal);
    // Peer RST during retrieve must not kill the helper (DISC-05).
    std::signal(SIGPIPE, SIG_IGN);
    return modelnet::RunModelDaemon(cfg, &g_stop);
}
