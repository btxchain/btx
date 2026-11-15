// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DOC_CLAIM_DOC_CLAIM_H
#define BITCOIN_MODELNET_DOC_CLAIM_DOC_CLAIM_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** surface is not one of the five document surfaces. Nothing is stored. */
inline constexpr char DOC_CLAIM_SURFACE[] = "SURFACE";

/** text is empty. Nothing is stored. */
inline constexpr char DOC_CLAIM_TEXT[] = "TEXT";

/** text contains a qualification sentence. Nothing is stored. */
inline constexpr char DOC_CLAIM_CLAIM[] = "CLAIM";

/**
 * Document claim gate. Five surfaces may each store one honest sentence.
 * This class opens no file, socket, or process.
 *
 * Claim(surface, text, err) checks the arguments in that order. surface
 * must be readme, rpc, build, recovery, or operator. Any other surface is
 * SURFACE and stores nothing. Empty text is TEXT and stores nothing. Text
 * containing "release qualified", "production ready", "gpu passed", or
 * "windows passed" is CLAIM and stores nothing. Any other text stores that
 * surface once. A second store of the same surface is NIFDT_REPLAY and
 * keeps the first text.
 *
 * Release returns NIFDT_UNQUALIFIED even after all five surfaces are stored.
 * qualified(), release_qualified(), hardware_qualified(), advertised(),
 * launched(), gpu(), and broadcast() stay false. windows_passed() and
 * gpu_passed() stay false. hosts() and physical_hosts() stay 1.
 * bytes_moved() stays 0. Spend returns NIFDT_AUTOMATIC_SPEND. Vendor and
 * Gpu return NIFDT_ENGINE_ABSENT. automatic_spend() is "0".
 */
class DocClaim {
public:
    bool Claim(const std::string& surface, const std::string& text, std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);

    bool stored(const std::string& surface) const;
    std::string text(const std::string& surface) const;

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool advertised() const { return false; }
    bool windows_passed() const { return false; }
    bool gpu_passed() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Sentence {
        std::string surface;
        std::string text;
    };
    std::vector<Sentence> m_stored;
};

} // namespace modelnet

#endif
