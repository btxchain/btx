// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PQ_DELEGATION_H
#define BITCOIN_MODELNET_PQ_DELEGATION_H

#include <modelnet/types.h>
#include <span.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

/** Per-epoch key id: D384("BTX/035/IdentityKey/v1.1", raw ML-DSA-44 public key).
 *  The logical root id is ResearchIdentityId and does not change on rotation. */
Digest48 IdentityKeyId(Span<const unsigned char> pubkey);

/** UTF-8 possession message: "BTX/035/NewKeyProof/v1.1\n" || lowercase root hex || "\n" || decimal epoch. */
std::string NewKeyProofMessage(const Digest48& root_id, uint64_t new_epoch);

/** Revocation view is fresh when now_ms <= revocation_ms + max_age_ms.
 *  Fails closed on negative inputs or overflow. */
bool AcceptFresh(int64_t revocation_ms, int64_t now_ms, int64_t max_age_ms);

/** Child capability. Authority may only narrow. */
struct CapabilityWindow {
    int64_t not_before_ms{0};
    int64_t not_after_ms{0};
    uint32_t remaining_depth{0};
    std::vector<std::string> audience_ids;
    std::vector<std::string> permissions;
    std::vector<std::pair<std::string, uint64_t>> limits;
};

/** True only when child is a strict attenuation of parent. Failure sets "BTX035_ATTENUATE". */
bool Attenuate(const CapabilityWindow& parent, const CapabilityWindow& child, std::string& err);

/** Cryptographic check only. A true result is not resource ownership or spend authority. */
bool SignatureValid(Span<const unsigned char> pk, Span<const unsigned char> msg, Span<const unsigned char> sig, std::string& err);

/** True only when both ids are the same 96-character lowercase hex string. */
bool ResourceOwner(const std::string& resource_owner_id, const std::string& signer_id);

/** Research and service keys cannot authorize a wallet spend. */
bool ResearchMaySpendWallet();

/** In-memory research-root epochs. Fail closed. Does not spend, and a valid signature is not ownership. */
class IdentityChain {
    struct KeyRow {
        Digest48 key_id;
        std::vector<unsigned char> pubkey;
        uint64_t epoch{0};
    };
    struct Revocation {
        Digest48 key_id;
        int64_t revoked_ms{0};
    };
    struct RecoveryRow {
        bool pending{false};
        std::vector<unsigned char> pubkey;
        Digest48 key_id;
        int64_t not_before_ms{0};
    };
    struct RootRow {
        Digest48 root_id;
        uint64_t epoch{0};
        std::vector<KeyRow> keys;
        std::vector<Revocation> revocations;
        RecoveryRow recovery;
    };

    std::vector<RootRow> m_roots;

    RootRow* Find(const Digest48& root_id);
    const RootRow* Find(const Digest48& root_id) const;
    static bool IsRevoked(const RootRow& row, const Digest48& key_id);
    static bool SeenPubkey(const RootRow& row, Span<const unsigned char> pubkey);

public:
    /** Epoch 0, the 1312-byte public key, and ResearchIdentityId. A second create of that id fails. */
    bool CreateRoot(Span<const unsigned char> pubkey, Digest48& root_id, std::string& err);

    /** Successor epoch. Possession proof is VerifyMlDsa44(new_pk, NewKeyProofMessage, sig).
     *  Refuses a revoked current key with "BTX035_REVOKED". */
    bool AdvanceEpoch(const Digest48& root, Span<const unsigned char> new_pk, uint64_t new_epoch,
                      Span<const unsigned char> possession_sig, std::string& err);

    /** Marks key_id revoked at revoked_ms. Unknown ids are remembered so they cannot be installed later. */
    bool RevokeKey(const Digest48& root, const Digest48& key_id, int64_t revoked_ms, std::string& err);

    /** Local receipt time plus delay. The pending key cannot become current before that deadline. */
    bool BeginRecovery(const Digest48& root, Span<const unsigned char> new_pk, int64_t now_ms, int64_t delay_ms, std::string& err);

    /** Before the deadline: "BTX035_RECOVERY_WAIT". At or after it: epoch+1, new key, pending cleared. */
    bool ActivateRecovery(const Digest48& root, int64_t now_ms, std::string& err);

    /** Verify msg under the current key. Revoked current key yields "BTX035_REVOKED". Not an ownership check. */
    bool SignCheck(const Digest48& root, Span<const unsigned char> msg, Span<const unsigned char> sig, std::string& err) const;

    bool CurrentEpoch(const Digest48& root, uint64_t& epoch, std::string& err) const;
    bool CurrentPublicKey(const Digest48& root, std::vector<unsigned char>& pubkey, std::string& err) const;
    bool KeyRevoked(const Digest48& root, const Digest48& key_id, bool& revoked, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_PQ_DELEGATION_H
