// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_EXEC_NIF_EXEC_H
#define BITCOIN_MODELNET_NIF_EXEC_NIF_EXEC_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_decode/swarm_decode_run.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace modelnet {

/** Bounded queue, same-scope batch, streaming pull, cancellation that keeps the held byte. */
class NifExec {
public:
    bool Enqueue(const std::string& id, NifPrivacy privacy, const std::string& prompt, const std::string& engine, std::string& err);
    bool Tick(std::string& err);
    bool Cancel(const std::string& id, std::string& err);

    std::string held(const std::string& id) const;
    int64_t accepted_bytes() const { return m_accepted; }
    bool buffer_released_early() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Item {
        std::string id;
        NifPrivacy privacy{NifPrivacy::LocalOnly};
        std::string prompt;
        std::string engine;
        std::unique_ptr<SwarmDecodeRun> decode;
        bool opened{false};
        bool cancelled{false};
        std::string held;
        bool absent{false};
    };
    Item* Find(const std::string& id);
    const Item* Find(const std::string& id) const;
    std::vector<Item> m_items;
    int64_t m_accepted{0};
};

} // namespace modelnet

#endif
