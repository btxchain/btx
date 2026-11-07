// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_pqpeer/nif_pqpeer.h>

#include <modelnet/identity.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

NifPqPeer::Peer* NifPqPeer::Find(const std::string& peer)
{
    for (Peer& row : m_peers) {
        if (row.name == peer) {
            return &row;
        }
    }
    return nullptr;
}

const NifPqPeer::Peer* NifPqPeer::Find(const std::string& peer) const
{
    for (const Peer& row : m_peers) {
        if (row.name == peer) {
            return &row;
        }
    }
    return nullptr;
}

bool NifPqPeer::Admit(const std::string& peer, Span<const unsigned char> pubkey, Span<const unsigned char> message, Span<const unsigned char> signature, bool multicast, std::string& err)
{
    if (peer.empty()) {
        err = kNifPqPeerPeer;
        return false;
    }
    if (pubkey.size() != kNifPqPeerPubkeyBytes || signature.size() != kNifPqPeerSignatureBytes) {
        err = kNifPqPeerKey;
        return false;
    }
    if (Find(peer) != nullptr) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (multicast) {
        Peer row;
        row.name = peer;
        row.hint = true;
        m_peers.push_back(std::move(row));
        err = kNifPqPeerHint;
        return false;
    }
    if (!VerifyMlDsa44(pubkey, message, signature)) {
        err = kNifPqPeerAuth;
        return false;
    }
    Peer row;
    row.name = peer;
    row.authenticated = true;
    m_peers.push_back(std::move(row));
    err.clear();
    return true;
}

bool NifPqPeer::Connect(const std::string& peer, std::string& err)
{
    Peer* row = Find(peer);
    if (row == nullptr || !row->authenticated) {
        err = kNifPqPeerAuth;
        return false;
    }
    if (row->connected) {
        err = NIFDT_REPLAY;
        return false;
    }
    row->connected = true;
    err.clear();
    return true;
}

bool NifPqPeer::Wan(std::string& err)
{
    err = NIFDT_NO_ROUTE;
    return false;
}

bool NifPqPeer::Scan(std::string& err)
{
    err = NIFDT_NOT_SCAN;
    return false;
}

bool NifPqPeer::hint_only() const
{
    bool any_hint = false;
    for (const Peer& row : m_peers) {
        if (row.authenticated) {
            return false;
        }
        if (row.hint) {
            any_hint = true;
        }
    }
    return any_hint;
}

bool NifPqPeer::authenticated() const
{
    for (const Peer& row : m_peers) {
        if (row.authenticated) {
            return true;
        }
    }
    return false;
}

bool NifPqPeer::authority() const
{
    for (const Peer& row : m_peers) {
        if (row.authenticated) {
            return true;
        }
    }
    return false;
}

int64_t NifPqPeer::ranks() const
{
    int64_t count = static_cast<int64_t>(0);
    for (const Peer& row : m_peers) {
        if (row.authenticated) {
            count += static_cast<int64_t>(1);
        }
    }
    return count;
}

int64_t NifPqPeer::connected() const
{
    int64_t count = static_cast<int64_t>(0);
    for (const Peer& row : m_peers) {
        if (row.connected) {
            count += static_cast<int64_t>(1);
        }
    }
    return count;
}

} // namespace modelnet
