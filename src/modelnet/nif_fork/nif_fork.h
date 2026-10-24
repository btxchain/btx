// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_FORK_NIF_FORK_H
#define BITCOIN_MODELNET_NIF_FORK_NIF_FORK_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Reviewed source pin. pin() returns this string. */
inline constexpr char NIF_FORK_PIN[] = "774ce244b87cc0eb8d4b94ab9f5de2ab22049f01";

/**
 * Byte ledger for one device. Capacity is 100. This is not a DeepSeek V4.1
 * hardware port. vendor_qualified() stays false.
 *
 * Reserve stores a hold. An empty id is REQUEST. bytes below 1 is BYTES.
 * now_ms >= until_ms is EXPIRED, including equality, and stores nothing.
 * A second Reserve of the same id is NIFDT_REPLAY and keeps the first hold.
 * bytes that would make used() exceed 100 are CAPACITY and store nothing.
 * A successful reserve increases used() by bytes.
 *
 * Pin records one outstanding device fence for a reserved id. An unknown id
 * is REQUEST. A second fence while one is outstanding is PINNED and the
 * first fence stays.
 *
 * Release while that fence is outstanding is PINNED and does not decrease
 * used(). Complete clears the fence when the id is reserved and the fence
 * matches. Any other Complete leaves the hold unchanged. Release after
 * Complete decreases used() by the reserved bytes and forgets the id.
 *
 * Eligible: a device count other than 1 is HARDWARE. minimum_devices greater
 * than devices is HARDWARE. now_ms >= qualified_until_ms is EXPIRED.
 * Otherwise true. This engine has one device. physical_hosts() is 1.
 *
 * ExecuteVendor returns false with NIFDT_ENGINE_ABSENT.
 * NifDtEngineLinked("deepinfer") is false. bytes_moved() stays 0.
 * launched(), gpu(), and broadcast() stay false. automatic_spend() is
 * NIFDT_AUTOMATIC_SPEND.
 */
class NifFork {
public:
    bool Reserve(const std::string& id, int64_t bytes, int64_t now_ms, int64_t until_ms, std::string& err);
    bool Pin(const std::string& id, int64_t fence, std::string& err);
    bool Release(const std::string& id, std::string& err);
    bool Complete(const std::string& id, int64_t fence, std::string& err);
    bool Eligible(int64_t devices, int64_t minimum_devices, int64_t qualified_until_ms, int64_t now_ms, std::string& err);
    bool ExecuteVendor(std::string& err);

    int64_t used() const;
    std::string pin() const { return NIF_FORK_PIN; }
    bool vendor_qualified() const { return false; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }

private:
    struct Reservation {
        std::string id;
        int64_t bytes{0};
        bool fence_open{false};
        int64_t fence{0};
    };

    Reservation* Find(const std::string& id);
    const Reservation* Find(const std::string& id) const;
    void Erase(const std::string& id);

    static constexpr int64_t kCapacity = 100;

    std::vector<Reservation> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_FORK_NIF_FORK_H
