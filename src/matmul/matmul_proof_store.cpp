// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_proof_store.h>

#include <dbwrapper.h>
#include <logging.h>
#include <sync.h>

#include <memory>
#include <utility>

namespace matmul {

namespace {
//! leveldb key prefix for a proof record: ('p', block_hash) -> raw sketch bytes.
//! A single-byte prefix keeps the table self-describing and lets a future record
//! type (e.g. metadata) coexist without a schema migration.
constexpr uint8_t DB_PROOF{'p'};
using ProofKey = std::pair<uint8_t, uint256>;
} // namespace

MatMulProofStore::MatMulProofStore() = default;
MatMulProofStore::~MatMulProofStore() = default;

void MatMulProofStore::OpenDiskBacking(const fs::path& dir, size_t cache_bytes, bool archive, bool wipe)
{
    LOCK(m_mutex);
    // Portable path join (fs::path) — no platform-specific separators. The
    // leveldb wrapper owns all file I/O; nothing POSIX-specific here.
    DBParams params{
        .path = dir,
        .cache_bytes = cache_bytes,
        .memory_only = false,
        .wipe_data = wipe,
        .obfuscate = false,
    };
    m_db = std::make_unique<CDBWrapper>(params);
    m_archive = archive;

    // Rebuild the resident key index from disk WITHOUT reading any 32 MiB blob:
    // iterate keys only. This bounds startup RAM regardless of archive size.
    m_mem.clear();
    m_keys.clear();
    std::unique_ptr<CDBIterator> it{m_db->NewIterator()};
    for (it->Seek(ProofKey{DB_PROOF, uint256()}); it->Valid(); it->Next()) {
        ProofKey key;
        if (!it->GetKey(key) || key.first != DB_PROOF) break;
        m_keys.insert(key.second);
    }
    LogPrintf("MatMul proof store: opened persistent backing at %s (%s, %u proofs resident)\n",
              fs::PathToString(dir), archive ? "ARCHIVE" : "pruned", m_keys.size());
}

void MatMulProofStore::CloseDiskBacking()
{
    LOCK(m_mutex);
    m_db.reset();
    m_keys.clear();
    m_mem.clear();
    m_archive = false;
}

bool MatMulProofStore::IsArchive() const
{
    LOCK(m_mutex);
    return m_archive;
}

bool MatMulProofStore::IsDiskBacked() const
{
    LOCK(m_mutex);
    return m_db != nullptr;
}

void MatMulProofStore::Put(const uint256& block_hash, std::vector<unsigned char> sketch_bytes)
{
    LOCK(m_mutex);
    m_keys.insert(block_hash);
    if (m_db) {
        // fSync=false: fast path. A crash may lose the most recent unsynced proof,
        // but the sketch is redundant-after-verify and re-fetchable from a peer, so
        // durability is not required for correctness (leveldb never corrupts the
        // table). Get-after-Put within the process reads the memtable, so validation
        // sees the proof immediately.
        m_db->Write(ProofKey{DB_PROOF, block_hash}, sketch_bytes, /*fSync=*/false);
    } else {
        m_mem[block_hash] = std::move(sketch_bytes);
    }
}

bool MatMulProofStore::Get(const uint256& block_hash, std::vector<unsigned char>& out) const
{
    LOCK(m_mutex);
    if (m_keys.count(block_hash) == 0) return false;
    if (m_db) {
        return m_db->Read(ProofKey{DB_PROOF, block_hash}, out);
    }
    const auto it = m_mem.find(block_hash);
    if (it == m_mem.end()) return false;
    out = it->second;
    return true;
}

bool MatMulProofStore::Have(const uint256& block_hash) const
{
    LOCK(m_mutex);
    return m_keys.count(block_hash) != 0;
}

void MatMulProofStore::Erase(const uint256& block_hash)
{
    LOCK(m_mutex);
    m_keys.erase(block_hash);
    if (m_db) {
        m_db->Erase(ProofKey{DB_PROOF, block_hash}, /*fSync=*/false);
    } else {
        m_mem.erase(block_hash);
    }
}

size_t MatMulProofStore::Size() const
{
    LOCK(m_mutex);
    return m_keys.size();
}

void MatMulProofStore::Clear()
{
    LOCK(m_mutex);
    if (m_db) {
        CDBBatch batch{*m_db};
        for (const uint256& h : m_keys) batch.Erase(ProofKey{DB_PROOF, h});
        m_db->WriteBatch(batch, /*fSync=*/true);
    }
    m_keys.clear();
    m_mem.clear();
}

std::vector<uint256> MatMulProofStore::Keys() const
{
    LOCK(m_mutex);
    return std::vector<uint256>(m_keys.begin(), m_keys.end());
}

MatMulProofStore& GetLocalMatMulProofStore()
{
    // Function-local static: one process-wide store, constructed on first use
    // and never destroyed before shutdown (Meyers singleton; thread-safe init).
    // init.cpp calls CloseDiskBacking() during Shutdown so the leveldb handle is
    // released before the static-destructor phase (after logging is torn down).
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
