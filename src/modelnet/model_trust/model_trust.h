// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_MODEL_TRUST_MODEL_TRUST_H
#define BITCOIN_MODELNET_MODEL_TRUST_MODEL_TRUST_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-memory channel attestation. One sequence and one digest per channel.
 *
 * Attest: an empty channel or digest returns FIELD and stores nothing.
 * sequence < 1 returns SEQUENCE and stores nothing. The first attest for a
 * channel stores that sequence and digest. A lower sequence returns ROLLBACK
 * and keeps the stored sequence. An equal sequence with a different digest
 * returns MISMATCH and keeps the first digest. The same sequence and digest
 * returns NIFDT_REPLAY. A higher sequence stores the new sequence and digest.
 *
 * Release returns NIFDT_UNQUALIFIED. Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * Spend returns NIFDT_AUTOMATIC_SPEND. monetary_store() stays false.
 * qualified(), release_qualified(), hardware_qualified(), launched(), gpu(),
 * and broadcast() stay false. hosts() and physical_hosts() stay 1.
 * bytes_moved() stays 0.
 * This class opens no file, socket, or process, and it does not broadcast.
 * It does not link a monetary attestor store.
 */
class ModelTrust {
public:
    bool Attest(const std::string& channel, int64_t sequence, const std::string& digest, std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Vendor(std::string& err);
    bool Spend(std::string& err);

    bool attested(const std::string& channel) const;
    int64_t sequence(const std::string& channel) const;
    std::string digest(const std::string& channel) const;

    bool monetary_store() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool advertised() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Row {
        std::string channel;
        int64_t sequence{0};
        std::string digest;
    };
    std::vector<Row> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_MODEL_TRUST_MODEL_TRUST_H
