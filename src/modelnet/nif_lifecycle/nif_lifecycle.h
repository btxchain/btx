// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_LIFECYCLE_NIF_LIFECYCLE_H
#define BITCOIN_MODELNET_NIF_LIFECYCLE_NIF_LIFECYCLE_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/nif_lifecycle/codes.h>
#include <modelnet/nif_lifecycle/journal.h>
#include <modelnet/swarm_decode/swarm_decode_run.h>

#include <util/fs.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Durable inference request.
 *
 * Admit stores a NifRequestRecord in memory and writes it under the
 * caller-supplied directory. An empty attempt is ATTEMPT and stores nothing.
 * A second Admit of the same attempt is REPLAY and keeps the first.
 * authority_from_receipt true is RECEIPT and stores nothing.
 * authority_from_receipt() stays false. A historic receipt does not become
 * authority.
 *
 * Reload reads that file and reconstructs principal, receiver, realm,
 * generation, runtime_image, commitment, attempt, epoch, ceiling_bytes,
 * lease_until_ms, cancelled, output_ceiling, accepted_output, and
 * economic_contract. A missing file is JOURNAL and leaves that in-memory
 * record empty.
 *
 * ReleaseChunk on an unknown attempt is ATTEMPT. If revoked is true, it
 * returns false with NIFDT_REVOKED and does not call Pull. Otherwise it
 * Opens the memory engine, Prompts the public text stored as commitment,
 * and Pulls once. That byte is appended to accepted_output.
 *
 * NoteCrash sets available() false and does not change validation_affected(),
 * which stays false. automatic_spend() returns NIFDT_AUTOMATIC_SPEND.
 * launched(), gpu(), and broadcast() stay false. bytes_moved() stays 0.
 * This class opens no socket, starts no child process, and holds no spend key.
 */
class NifLifecycle {
public:
    bool Admit(const fs::path& journal_dir, const NifRequestRecord& request, bool authority_from_receipt, std::string& err);
    bool Reload(const fs::path& journal_dir, const std::string& attempt, std::string& err);
    bool ReleaseChunk(const std::string& attempt, bool revoked, std::string& err);
    void NoteCrash();

    const NifRequestRecord* Find(const std::string& attempt) const;
    bool authority_from_receipt() const;
    bool available() const;
    bool validation_affected() const;
    std::string automatic_spend() const;
    bool launched() const;
    bool gpu() const;
    bool broadcast() const;
    int64_t bytes_moved() const;

private:
    struct Slot {
        NifRequestRecord record;
        fs::path file;
    };

    bool PromptAndPull(SwarmDecodeRun& run, const std::string& attempt, const std::string& commitment, char& byte, std::string& err);

    std::map<std::string, Slot> m_slots;
    std::map<std::string, SwarmDecodeRun> m_runs;
    bool m_available{true};
    bool m_validation_affected{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_LIFECYCLE_NIF_LIFECYCLE_H
