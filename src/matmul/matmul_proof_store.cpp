// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_proof_store.h>

#include <sync.h>

#include <utility>

namespace matmul {

void MatMulProofStore::Put(const uint256& block_hash, std::vector<unsigned char> sketch_bytes)
{
    LOCK(m_mutex);
    m_proofs[block_hash] = std::move(sketch_bytes);
}

bool MatMulProofStore::Get(const uint256& block_hash, std::vector<unsigned char>& out) const
{
    LOCK(m_mutex);
    const auto it = m_proofs.find(block_hash);
    if (it == m_proofs.end()) return false;
    out = it->second;
    return true;
}

bool MatMulProofStore::Have(const uint256& block_hash) const
{
    LOCK(m_mutex);
    return m_proofs.count(block_hash) != 0;
}

void MatMulProofStore::Erase(const uint256& block_hash)
{
    LOCK(m_mutex);
    m_proofs.erase(block_hash);
}

size_t MatMulProofStore::Size() const
{
    LOCK(m_mutex);
    return m_proofs.size();
}

void MatMulProofStore::Clear()
{
    LOCK(m_mutex);
    m_proofs.clear();
}

MatMulProofStore& GetLocalMatMulProofStore()
{
    // Function-local static: one process-wide store, constructed on first use
    // and never destroyed before shutdown (Meyers singleton; thread-safe init).
    static MatMulProofStore g_store;
    return g_store;
}

void PutMatMulProof(const uint256& block_hash, std::vector<unsigned char> sketch_bytes)
{
    GetLocalMatMulProofStore().Put(block_hash, std::move(sketch_bytes));
}

bool GetMatMulProof(const uint256& block_hash, std::vector<unsigned char>& out)
{
    return GetLocalMatMulProofStore().Get(block_hash, out);
}

bool HaveMatMulProof(const uint256& block_hash)
{
    return GetLocalMatMulProofStore().Have(block_hash);
}

} // namespace matmul
