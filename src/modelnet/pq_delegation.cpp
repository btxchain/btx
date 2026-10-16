// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/pq_delegation.h>

#include <modelnet/crypto.h>
#include <modelnet/identity.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

namespace {

Span<const unsigned char> AsBytes(const std::string& s)
{
    return Span<const unsigned char>{reinterpret_cast<const unsigned char*>(s.data()), s.size()};
}

bool SumMs(int64_t now_ms, int64_t delay_ms, int64_t& deadline, std::string& err)
{
    if (now_ms < 0 || delay_ms < 0) {
        err = "BTX035_INVALID_SCHEMA";
        return false;
    }
    if (delay_ms > std::numeric_limits<int64_t>::max() - now_ms) {
        err = "BTX035_LIMIT_EXCEEDED";
        return false;
    }
    deadline = now_ms + delay_ms;
    return true;
}

bool WindowOk(const CapabilityWindow& w)
{
    return w.not_before_ms >= 0 && w.not_after_ms >= w.not_before_ms;
}

bool IsSubset(const std::vector<std::string>& child, const std::vector<std::string>& parent)
{
    for (const std::string& item : child) {
        if (std::find(parent.begin(), parent.end(), item) == parent.end()) return false;
    }
    return true;
}

bool LimitsNarrow(const std::vector<std::pair<std::string, uint64_t>>& parent,
                  const std::vector<std::pair<std::string, uint64_t>>& child)
{
    for (const auto& plim : parent) {
        bool found = false;
        for (const auto& clim : child) {
            if (clim.first != plim.first) continue;
            found = true;
            if (clim.second > plim.second) return false;
        }
        if (!found) return false;
    }
    return true;
}

bool LowerHex96(const std::string& s)
{
    if (s.size() != 96) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

} // namespace

Digest48 IdentityKeyId(Span<const unsigned char> pubkey)
{
    return DomainHash("BTX/035/IdentityKey/v1.1", pubkey);
}

std::string NewKeyProofMessage(const Digest48& root_id, uint64_t new_epoch)
{
    return std::string("BTX/035/NewKeyProof/v1.1\n") + root_id.Hex() + "\n" + std::to_string(new_epoch);
}

bool AcceptFresh(int64_t revocation_ms, int64_t now_ms, int64_t max_age_ms)
{
    if (revocation_ms < 0 || now_ms < 0 || max_age_ms < 0) return false;
    if (max_age_ms > std::numeric_limits<int64_t>::max() - revocation_ms) return false;
    return now_ms <= revocation_ms + max_age_ms;
}

bool Attenuate(const CapabilityWindow& parent, const CapabilityWindow& child, std::string& err)
{
    if (!WindowOk(parent) || !WindowOk(child) ||
        child.not_before_ms < parent.not_before_ms ||
        child.not_after_ms > parent.not_after_ms ||
        !(child.remaining_depth < parent.remaining_depth) ||
        !IsSubset(child.audience_ids, parent.audience_ids) ||
        !IsSubset(child.permissions, parent.permissions) ||
        !LimitsNarrow(parent.limits, child.limits)) {
        err = "BTX035_ATTENUATE";
        return false;
    }
    return true;
}

bool SignatureValid(Span<const unsigned char> pk, Span<const unsigned char> msg, Span<const unsigned char> sig, std::string& err)
{
    if (pk.size() != MLDSA44_PK || sig.size() != MLDSA44_SIG) {
        err = "BTX035_KEY_LENGTH";
        return false;
    }
    if (!VerifyMlDsa44(pk, msg, sig)) {
        err = "BTX035_SIGNATURE_INVALID";
        return false;
    }
    return true;
}

bool ResourceOwner(const std::string& resource_owner_id, const std::string& signer_id)
{
    if (!LowerHex96(resource_owner_id) || !LowerHex96(signer_id)) return false;
    return resource_owner_id == signer_id;
}

bool ResearchMaySpendWallet()
{
    return ServiceKeyMayAuthorizeWalletSpend();
}

IdentityChain::RootRow* IdentityChain::Find(const Digest48& root_id)
{
    for (RootRow& row : m_roots) {
        if (row.root_id == root_id) return &row;
    }
    return nullptr;
}

const IdentityChain::RootRow* IdentityChain::Find(const Digest48& root_id) const
{
    for (const RootRow& row : m_roots) {
        if (row.root_id == root_id) return &row;
    }
    return nullptr;
}

bool IdentityChain::IsRevoked(const RootRow& row, const Digest48& key_id)
{
    for (const Revocation& rev : row.revocations) {
        if (rev.key_id == key_id) return true;
    }
    return false;
}

bool IdentityChain::SeenPubkey(const RootRow& row, Span<const unsigned char> pubkey)
{
    for (const KeyRow& key : row.keys) {
        if (key.pubkey.size() == pubkey.size() &&
            std::equal(pubkey.begin(), pubkey.end(), key.pubkey.begin())) {
            return true;
        }
    }
    return false;
}

bool IdentityChain::CreateRoot(Span<const unsigned char> pubkey, Digest48& root_id, std::string& err)
{
    if (pubkey.size() != MLDSA44_PK) {
        err = "BTX035_KEY_LENGTH";
        return false;
    }
    const Digest48 id = ResearchIdentityId(pubkey);
    if (Find(id) != nullptr) {
        err = "BTX035_IDENTITY_CONFLICT";
        return false;
    }
    RootRow row;
    row.root_id = id;
    row.epoch = 0;
    KeyRow key;
    key.key_id = IdentityKeyId(pubkey);
    key.pubkey.assign(pubkey.begin(), pubkey.end());
    key.epoch = 0;
    row.keys.push_back(std::move(key));
    m_roots.push_back(std::move(row));
    root_id = id;
    return true;
}

bool IdentityChain::AdvanceEpoch(const Digest48& root, Span<const unsigned char> new_pk, uint64_t new_epoch,
                                 Span<const unsigned char> possession_sig, std::string& err)
{
    RootRow* row = Find(root);
    if (row == nullptr || row->keys.empty()) {
        err = "BTX035_IDENTITY_UNKNOWN";
        return false;
    }
    if (new_pk.size() != MLDSA44_PK || possession_sig.size() != MLDSA44_SIG) {
        err = "BTX035_KEY_LENGTH";
        return false;
    }
    const KeyRow& current = row->keys.back();
    if (IsRevoked(*row, current.key_id)) {
        err = "BTX035_REVOKED";
        return false;
    }
    if (row->epoch == std::numeric_limits<uint64_t>::max() || new_epoch != row->epoch + 1) {
        err = "BTX035_STATE_CONFLICT";
        return false;
    }
    if (SeenPubkey(*row, new_pk)) {
        err = "BTX035_CONFLICT";
        return false;
    }
    const Digest48 new_id = IdentityKeyId(new_pk);
    if (IsRevoked(*row, new_id)) {
        err = "BTX035_REVOKED";
        return false;
    }
    const std::string message = NewKeyProofMessage(row->root_id, new_epoch);
    if (!VerifyMlDsa44(new_pk, AsBytes(message), possession_sig)) {
        err = "BTX035_SIGNATURE_INVALID";
        return false;
    }
    KeyRow key;
    key.key_id = new_id;
    key.pubkey.assign(new_pk.begin(), new_pk.end());
    key.epoch = new_epoch;
    row->epoch = new_epoch;
    row->keys.push_back(std::move(key));
    row->recovery = RecoveryRow{};
    return true;
}

bool IdentityChain::RevokeKey(const Digest48& root, const Digest48& key_id, int64_t revoked_ms, std::string& err)
{
    RootRow* row = Find(root);
    if (row == nullptr) {
        err = "BTX035_IDENTITY_UNKNOWN";
        return false;
    }
    if (revoked_ms < 0) {
        err = "BTX035_INVALID_SCHEMA";
        return false;
    }
    if (IsRevoked(*row, key_id)) return true;
    Revocation rev;
    rev.key_id = key_id;
    rev.revoked_ms = revoked_ms;
    row->revocations.push_back(rev);
    return true;
}

bool IdentityChain::BeginRecovery(const Digest48& root, Span<const unsigned char> new_pk, int64_t now_ms, int64_t delay_ms, std::string& err)
{
    RootRow* row = Find(root);
    if (row == nullptr || row->keys.empty()) {
        err = "BTX035_IDENTITY_UNKNOWN";
        return false;
    }
    if (new_pk.size() != MLDSA44_PK) {
        err = "BTX035_KEY_LENGTH";
        return false;
    }
    int64_t deadline = 0;
    if (!SumMs(now_ms, delay_ms, deadline, err)) return false;
    if (row->recovery.pending) {
        err = "BTX035_IDENTITY_CONFLICT";
        return false;
    }
    if (SeenPubkey(*row, new_pk)) {
        err = "BTX035_CONFLICT";
        return false;
    }
    const Digest48 new_id = IdentityKeyId(new_pk);
    if (IsRevoked(*row, new_id)) {
        err = "BTX035_REVOKED";
        return false;
    }
    row->recovery.pending = true;
    row->recovery.pubkey.assign(new_pk.begin(), new_pk.end());
    row->recovery.key_id = new_id;
    row->recovery.not_before_ms = deadline;
    return true;
}

bool IdentityChain::ActivateRecovery(const Digest48& root, int64_t now_ms, std::string& err)
{
    RootRow* row = Find(root);
    if (row == nullptr || row->keys.empty()) {
        err = "BTX035_IDENTITY_UNKNOWN";
        return false;
    }
    if (!row->recovery.pending) {
        err = "BTX035_RECOVERY_REQUIRED";
        return false;
    }
    if (now_ms < 0) {
        err = "BTX035_INVALID_SCHEMA";
        return false;
    }
    if (now_ms < row->recovery.not_before_ms) {
        err = "BTX035_RECOVERY_WAIT";
        return false;
    }
    if (IsRevoked(*row, row->recovery.key_id)) {
        err = "BTX035_REVOKED";
        return false;
    }
    if (row->epoch == std::numeric_limits<uint64_t>::max()) {
        err = "BTX035_LIMIT_EXCEEDED";
        return false;
    }
    KeyRow key;
    key.key_id = row->recovery.key_id;
    key.pubkey = row->recovery.pubkey;
    key.epoch = row->epoch + 1;
    row->epoch = key.epoch;
    row->keys.push_back(std::move(key));
    row->recovery = RecoveryRow{};
    return true;
}

bool IdentityChain::SignCheck(const Digest48& root, Span<const unsigned char> msg, Span<const unsigned char> sig, std::string& err) const
{
    const RootRow* row = Find(root);
    if (row == nullptr || row->keys.empty()) {
        err = "BTX035_IDENTITY_UNKNOWN";
        return false;
    }
    if (sig.size() != MLDSA44_SIG) {
        err = "BTX035_KEY_LENGTH";
        return false;
    }
    const KeyRow& current = row->keys.back();
    if (IsRevoked(*row, current.key_id)) {
        err = "BTX035_REVOKED";
        return false;
    }
    if (!VerifyMlDsa44(current.pubkey, msg, sig)) {
        err = "BTX035_SIGNATURE_INVALID";
        return false;
    }
    return true;
}

bool IdentityChain::CurrentEpoch(const Digest48& root, uint64_t& epoch, std::string& err) const
{
    const RootRow* row = Find(root);
    if (row == nullptr) {
        err = "BTX035_IDENTITY_UNKNOWN";
        return false;
    }
    epoch = row->epoch;
    return true;
}

bool IdentityChain::CurrentPublicKey(const Digest48& root, std::vector<unsigned char>& pubkey, std::string& err) const
{
    const RootRow* row = Find(root);
    if (row == nullptr || row->keys.empty()) {
        err = "BTX035_IDENTITY_UNKNOWN";
        return false;
    }
    pubkey = row->keys.back().pubkey;
    return true;
}

bool IdentityChain::KeyRevoked(const Digest48& root, const Digest48& key_id, bool& revoked, std::string& err) const
{
    const RootRow* row = Find(root);
    if (row == nullptr) {
        err = "BTX035_IDENTITY_UNKNOWN";
        return false;
    }
    revoked = IsRevoked(*row, key_id);
    return true;
}

} // namespace modelnet
