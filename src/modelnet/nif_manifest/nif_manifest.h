// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_MANIFEST_NIF_MANIFEST_H
#define BITCOIN_MODELNET_NIF_MANIFEST_NIF_MANIFEST_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Open refused an empty id. Nothing is stored. */
inline constexpr char NIF_MANIFEST_MANIFEST[] = "MANIFEST";

/** Open refused pieces below 1, or Accept saw an index outside [0, pieces). Nothing is stored. */
inline constexpr char NIF_MANIFEST_PIECE[] = "PIECE";

/** Open refused now_ms greater than or equal to until_ms. Nothing is stored. */
inline constexpr char NIF_MANIFEST_EXPIRED[] = "EXPIRED";

/** Accept saw an index before the next missing index. Nothing is stored. */
inline constexpr char NIF_MANIFEST_ORDER[] = "ORDER";

/** Accept saw a digest that differs from the digest already stored at that index. The first digest stays. */
inline constexpr char NIF_MANIFEST_ALTERED[] = "ALTERED";

/** Seal saw a manifest that is still missing an index. sealed() stays false. */
inline constexpr char NIF_MANIFEST_INCOMPLETE[] = "INCOMPLETE";

/** Claim with producer_claim true is not a compute proof. compute_proof() stays false. */
inline constexpr char NIF_MANIFEST_CLAIM[] = "CLAIM";

/**
 * Ordered piece manifest.
 *
 * Open stores one id. An empty id is MANIFEST. pieces below 1 is PIECE.
 * now_ms greater than or equal to until_ms is EXPIRED, including equality.
 * Each of those stores nothing. A second Open of the same id is
 * NIFDT_REPLAY and keeps the first piece count.
 *
 * Accept stores a digest at index. index must be in [0, pieces). An index
 * outside that range is PIECE and stores nothing. Indexes arrive in order:
 * index 1 before index 0 is ORDER and stores nothing. A duplicate index
 * with the same digest is NIFDT_REPLAY and does not count twice. A digest
 * that differs from the first digest stored for that index is ALTERED and
 * does not replace it.
 *
 * Seal returns true only when every index has been accepted once. Otherwise
 * INCOMPLETE and sealed() stays false. A later Seal of an already complete
 * manifest stays true.
 *
 * Claim(id, err) is a producer claim: producer_claim true. It returns
 * false with CLAIM and does not set compute_proof(). compute_proof() stays
 * false even after Seal. Claim(id, false, err) does not set
 * compute_proof() either.
 *
 * Remote for an engine NifDtEngineLinked rejects, including nixl, mooncake,
 * and rdma, returns false with NIFDT_ENGINE_ABSENT. bytes_moved() stays 0.
 * A linked name is ENGINE and also moves nothing.
 *
 * launched(), gpu(), and broadcast() stay false. automatic_spend() is
 * NIFDT_AUTOMATIC_SPEND ("0"). physical_hosts() is 1. No socket is opened.
 */
class NifManifest {
public:
    bool Open(const std::string& id, int64_t pieces, int64_t now_ms, int64_t until_ms, std::string& err);
    bool Accept(const std::string& id, int64_t index, const std::string& digest, std::string& err);
    bool Seal(const std::string& id, std::string& err);
    bool Claim(const std::string& id, std::string& err);
    bool Claim(const std::string& id, bool producer_claim, std::string& err);
    bool Remote(const std::string& engine, std::string& err);

    bool stored(const std::string& id) const;
    int64_t count() const { return static_cast<int64_t>(m_rows.size()); }
    int64_t pieces(const std::string& id) const;
    int64_t accepted(const std::string& id) const;
    std::string digest(const std::string& id, int64_t index) const;
    bool sealed(const std::string& id) const;
    bool sealed() const;
    bool compute_proof() const { return false; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }

private:
    struct Row {
        std::string id;
        int64_t pieces{0};
        bool sealed{false};
        std::vector<std::string> digests;
    };

    Row* Find(const std::string& id);
    const Row* Find(const std::string& id) const;

    std::vector<Row> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_MANIFEST_NIF_MANIFEST_H
