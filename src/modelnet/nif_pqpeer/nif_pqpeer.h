// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_PQPEER_NIF_PQPEER_H
#define BITCOIN_MODELNET_NIF_PQPEER_NIF_PQPEER_H

#include <modelnet/identity.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** ML-DSA-44 public key length. Matches MLDSA44_PK. */
inline constexpr size_t kNifPqPeerPubkeyBytes = 1312;
/** ML-DSA-44 signature length. Matches MLDSA44_SIG. */
inline constexpr size_t kNifPqPeerSignatureBytes = 2420;
static_assert(kNifPqPeerPubkeyBytes == MLDSA44_PK);
static_assert(kNifPqPeerSignatureBytes == MLDSA44_SIG);

/** An empty peer. Nothing is stored. */
inline constexpr char kNifPqPeerPeer[] = "PEER";

/** Public key or signature length is wrong. Nothing is stored. */
inline constexpr char kNifPqPeerKey[] = "KEY";

/** A multicast signature is a hint, not authority. */
inline constexpr char kNifPqPeerHint[] = "HINT";

/** Verification failed, or the peer is unknown or not authenticated. */
inline constexpr char kNifPqPeerAuth[] = "AUTH";

/**
 * One-host PQ peer admission. NIF-LAN-003. No socket is opened.
 *
 * Admit checks, in order:
 * An empty peer is PEER and stores nothing.
 * A pubkey whose size is not 1312, or a signature whose size is not 2420,
 * is KEY and stores nothing.
 * A peer already stored is NIFDT_REPLAY and the first result stays.
 * multicast true stores that peer as a hint only and returns HINT.
 * hint_only() becomes true. authenticated() stays false. authority()
 * stays false. The signature is not authority on that path.
 * VerifyMlDsa44 failure is AUTH and stores nothing.
 * A successful non-multicast verify stores that peer once.
 * authenticated() becomes true. authority() becomes true.
 *
 * A second distinct authenticated peer is stored. ranks() is the number
 * of authenticated peers. hosts() and physical_hosts() stay 1.
 *
 * Connect opens no socket. An unknown or unauthenticated peer is AUTH.
 * An authenticated peer connects once. A second Connect of that peer is
 * NIFDT_REPLAY. connected() counts successful connects.
 *
 * Wan is NIFDT_NO_ROUTE. Scan is NIFDT_NOT_SCAN. bytes_moved() stays 0.
 * launched(), gpu(), and broadcast() stay false. automatic_spend() is
 * NIFDT_AUTOMATIC_SPEND. qualified() stays false.
 */
class NifPqPeer {
public:
    bool Admit(const std::string& peer, Span<const unsigned char> pubkey, Span<const unsigned char> message, Span<const unsigned char> signature, bool multicast, std::string& err);
    bool Connect(const std::string& peer, std::string& err);
    bool Wan(std::string& err);
    bool Scan(std::string& err);

    bool hint_only() const;
    bool authenticated() const;
    bool authority() const;
    int64_t ranks() const;
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t connected() const;
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    bool qualified() const { return false; }

private:
    struct Peer {
        std::string name;
        bool hint{false};
        bool authenticated{false};
        bool connected{false};
    };

    Peer* Find(const std::string& peer);
    const Peer* Find(const std::string& peer) const;

    std::vector<Peer> m_peers;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_PQPEER_NIF_PQPEER_H
