// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_invoice.h>

#include <crypto/sha256.h>

namespace modelnet {
namespace {

/** Single SHA-256 of the preimage, in the byte order CSHA256 writes. */
uint256 PreimageHash(const std::vector<unsigned char>& preimage)
{
    uint256 hash;
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(hash.begin());
    return hash;
}

} // namespace

bool SwarmInvoiceBook::Open(std::string& err)
{
    if (m_open) {
        err = "REOPEN";
        return false;
    }
    m_open = true;
    err.clear();
    return true;
}

bool SwarmInvoiceBook::Create(const std::string& invoice_id, const std::string& beneficiary, const std::string& objective, int64_t atoms, const uint256& hashlock, std::string& err)
{
    if (invoice_id.empty() || beneficiary.empty() || objective.empty() || atoms <= 0) {
        err = "INVOICE";
        return false;
    }
    if (!m_open) {
        err = "NOT_OPEN";
        return false;
    }
    if (m_rows.find(invoice_id) != m_rows.end()) {
        err = "REPLAY";
        return false;
    }
    Row row;
    row.beneficiary = beneficiary;
    row.objective = objective;
    row.atoms = atoms;
    row.hashlock = hashlock;
    row.settled = false;
    m_rows.emplace(invoice_id, row);
    err.clear();
    return true;
}

bool SwarmInvoiceBook::Reserve(const std::string& invoice_id, const std::string& liquidity_id, std::string& err)
{
    if (!m_open) {
        err = "NOT_OPEN";
        return false;
    }
    const auto it = m_rows.find(invoice_id);
    if (it == m_rows.end()) {
        err = "INVOICE";
        return false;
    }
    if (liquidity_id.empty()) {
        err = "LIQUIDITY";
        return false;
    }
    if (it->second.liquidity_ids.count(liquidity_id) != 0) {
        err.clear();
        return true;
    }
    if (m_liquidity_owner.find(liquidity_id) != m_liquidity_owner.end()) {
        err = "DOUBLE_RESERVE";
        return false;
    }
    it->second.liquidity_ids.insert(liquidity_id);
    m_liquidity_owner.emplace(liquidity_id, invoice_id);
    err.clear();
    return true;
}

bool SwarmInvoiceBook::Reveal(const std::string& invoice_id, const std::vector<unsigned char>& preimage, std::string& err)
{
    if (preimage.size() != 32) {
        err = "PREIMAGE";
        return false;
    }
    if (!m_open) {
        err = "NOT_OPEN";
        return false;
    }
    const auto it = m_rows.find(invoice_id);
    if (it == m_rows.end()) {
        err = "INVOICE";
        return false;
    }
    // uint256::operator== compares the raw digest bytes.
    if (PreimageHash(preimage) != it->second.hashlock) {
        err = "HASHLOCK";
        return false;
    }
    if (it->second.settled) {
        err = "REPLAY";
        return false;
    }
    it->second.settled = true;
    err.clear();
    return true;
}

bool SwarmInvoiceBook::MultiHopQualified() const
{
    // A hashlock is not a qualified multi-hop network.
    return false;
}

} // namespace modelnet
