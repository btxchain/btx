// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/prf01/prf01.h>

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_observer.h>

#include <chainparams.h>
#include <common/args.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool Prf01::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }

    // Missing catalog. This path is not created. The reader succeeds with an
    // empty result when catalog.json is absent. No socket and no process.
    SwarmCatalog entries;
    if (!SwarmReadCatalog(fs::path{"/prf01/missing-catalog"}, entries, err)) return false;
    if (!entries.empty() || !err.empty()) {
        err = "CATALOG";
        return false;
    }

    // Fresh chain params. Model DNS seeds are read and must be empty.
    // Nothing is added and nothing is dialed.
    const ArgsManager args;
    for (const ChainType chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST}) {
        const auto params = CreateChainParams(args, chain);
        if (!params || !params->ModelDNSSeeds().empty()) {
            err = "SEEDS";
            return false;
        }
    }

    m_done = true;
    err.clear();
    return true;
}

bool Prf01::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Prf01::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Prf01::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Prf01::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Prf01::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
