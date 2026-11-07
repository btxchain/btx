// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_discover/nif_discover.h>

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

NifDiscover::Peer* NifDiscover::Find(const std::string& peer)
{
    for (Peer& row : m_peers) {
        if (row.name == peer) return &row;
    }
    return nullptr;
}

const NifDiscover::Peer* NifDiscover::Find(const std::string& peer) const
{
    for (const Peer& row : m_peers) {
        if (row.name == peer) return &row;
    }
    return nullptr;
}

bool NifDiscover::IsAuthoritative(const Peer& row)
{
    return row.authenticated && !row.via_multicast;
}

bool NifDiscover::Hint(const std::string& peer, bool via_multicast, bool authenticated, std::string& err)
{
    if (peer.empty()) {
        err = kNifDiscoverPeer;
        return false;
    }
    if (Find(peer) != nullptr) {
        err = NIFDT_REPLAY;
        return false;
    }
    Peer row;
    row.name = peer;
    row.via_multicast = via_multicast;
    row.authenticated = authenticated;
    m_peers.push_back(std::move(row));
    if (!authenticated) {
        err = kNifDiscoverAuth;
        return false;
    }
    if (via_multicast) {
        err.clear();
        return true;
    }
    err.clear();
    return true;
}

bool NifDiscover::Connect(const std::string& peer, std::string& err)
{
    if (peer.empty()) {
        err = kNifDiscoverPeer;
        return false;
    }
    Peer* row = Find(peer);
    if (row == nullptr) {
        err = kNifDiscoverPeer;
        return false;
    }
    if (row->via_multicast) {
        err = kNifDiscoverHint;
        return false;
    }
    if (!IsAuthoritative(*row)) {
        err = kNifDiscoverAuth;
        return false;
    }
    row->connected = true;
    err.clear();
    return true;
}

bool NifDiscover::Wan(std::string& err)
{
    err = NIFDT_NO_ROUTE;
    return false;
}

bool NifDiscover::Scan(std::string& err)
{
    err = NIFDT_NOT_SCAN;
    return false;
}

bool NifDiscover::hint_only() const
{
    for (const Peer& row : m_peers) {
        if (IsAuthoritative(row)) return false;
    }
    return true;
}

bool NifDiscover::authority() const
{
    for (const Peer& row : m_peers) {
        if (IsAuthoritative(row)) return true;
    }
    return false;
}

bool NifDiscover::authority(const std::string& peer) const
{
    const Peer* row = Find(peer);
    if (row == nullptr) return false;
    return IsAuthoritative(*row);
}

bool NifDiscover::hinted(const std::string& peer) const
{
    return Find(peer) != nullptr;
}

bool NifDiscover::peer_authenticated(const std::string& peer) const
{
    const Peer* row = Find(peer);
    if (row == nullptr) return false;
    return row->authenticated;
}

bool NifDiscover::peer_multicast(const std::string& peer) const
{
    const Peer* row = Find(peer);
    if (row == nullptr) return false;
    return row->via_multicast;
}

int64_t NifDiscover::connected() const
{
    int64_t count = 0;
    for (const Peer& row : m_peers) {
        if (row.connected) count += static_cast<int64_t>(1);
    }
    return count;
}

} // namespace modelnet
