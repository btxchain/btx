// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_lifecycle/nif_lifecycle.h>

#include <modelnet/nif_lifecycle/codes.h>
#include <modelnet/nif_lifecycle/journal.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_decode/swarm_decode_run.h>

#include <util/fs.h>

#include <cstdint>
#include <map>
#include <string>
#include <utility>

namespace modelnet {
namespace {

constexpr char kMemoryEngine[] = "memory";

bool OpenedMemory(SwarmDecodeRun& run, const std::string& attempt, std::string& err)
{
    if (run.Open(attempt, kMemoryEngine, err)) {
        return true;
    }
    return err == NIFDT_REPLAY && run.engine_of(attempt) == kMemoryEngine;
}

bool PromptedPublic(SwarmDecodeRun& run, const std::string& attempt, const std::string& text, std::string& err)
{
    const bool is_private = false;
    if (run.Prompt(attempt, text, is_private, err)) {
        return true;
    }
    return err == NIFDT_REPLAY;
}

} // namespace

bool NifLifecycle::PromptAndPull(SwarmDecodeRun& run, const std::string& attempt, const std::string& commitment, char& byte, std::string& err)
{
    if (!OpenedMemory(run, attempt, err)) {
        return false;
    }
    if (!PromptedPublic(run, attempt, commitment, err)) {
        return false;
    }
    const std::size_t before = run.text().size();
    if (!run.Pull(attempt, err)) {
        return false;
    }
    const std::string& text = run.text();
    if (text.size() != before + 1 || text.empty()) {
        err = kNifLifecycleAttempt;
        return false;
    }
    byte = text.back();
    return true;
}

bool NifLifecycle::Admit(const fs::path& journal_dir, const NifRequestRecord& request, bool authority_from_receipt, std::string& err)
{
    if (authority_from_receipt) {
        err = kNifLifecycleReceipt;
        return false;
    }
    if (request.attempt.empty()) {
        err = kNifLifecycleAttempt;
        return false;
    }
    if (m_slots.find(request.attempt) != m_slots.end()) {
        err = NIFDT_REPLAY;
        return false;
    }
    const fs::path path = NifLifecycleJournalPath(journal_dir, request.attempt);
    if (fs::exists(path)) {
        NifRequestRecord existing;
        if (!NifLifecycleJournalRead(path, existing, err)) {
            return false;
        }
        if (existing.attempt != request.attempt) {
            err = kNifLifecycleJournal;
            return false;
        }
        m_slots.emplace(request.attempt, Slot{std::move(existing), path});
        err = NIFDT_REPLAY;
        return false;
    }
    if (!NifLifecycleJournalWrite(path, request, err)) {
        return false;
    }
    m_slots.emplace(request.attempt, Slot{request, path});
    err.clear();
    return true;
}

bool NifLifecycle::Reload(const fs::path& journal_dir, const std::string& attempt, std::string& err)
{
    if (attempt.empty()) {
        err = kNifLifecycleAttempt;
        return false;
    }
    const fs::path path = NifLifecycleJournalPath(journal_dir, attempt);
    if (!fs::exists(path)) {
        m_slots.erase(attempt);
        m_runs.erase(attempt);
        err = kNifLifecycleJournal;
        return false;
    }
    NifRequestRecord loaded;
    if (!NifLifecycleJournalRead(path, loaded, err)) {
        return false;
    }
    if (loaded.attempt != attempt) {
        err = kNifLifecycleJournal;
        return false;
    }
    m_slots[attempt] = Slot{std::move(loaded), path};
    err.clear();
    return true;
}

bool NifLifecycle::ReleaseChunk(const std::string& attempt, bool revoked, std::string& err)
{
    auto it = m_slots.find(attempt);
    if (it == m_slots.end()) {
        err = kNifLifecycleAttempt;
        return false;
    }
    if (revoked) {
        err = NIFDT_REVOKED;
        return false;
    }
    SwarmDecodeRun& run = m_runs[attempt];
    const std::string commitment = it->second.record.commitment;
    char byte = 0;
    if (!PromptAndPull(run, attempt, commitment, byte, err)) {
        return false;
    }
    NifRequestRecord next = it->second.record;
    next.accepted_output.push_back(byte);
    if (!NifLifecycleJournalWrite(it->second.file, next, err)) {
        return false;
    }
    it->second.record = std::move(next);
    err.clear();
    return true;
}

void NifLifecycle::NoteCrash()
{
    m_available = false;
}

const NifRequestRecord* NifLifecycle::Find(const std::string& attempt) const
{
    const auto it = m_slots.find(attempt);
    if (it == m_slots.end()) {
        return nullptr;
    }
    return &it->second.record;
}

bool NifLifecycle::authority_from_receipt() const
{
    return false;
}

bool NifLifecycle::available() const
{
    return m_available;
}

bool NifLifecycle::validation_affected() const
{
    return m_validation_affected;
}

std::string NifLifecycle::automatic_spend() const
{
    return NIFDT_AUTOMATIC_SPEND;
}

bool NifLifecycle::launched() const
{
    return false;
}

bool NifLifecycle::gpu() const
{
    return false;
}

bool NifLifecycle::broadcast() const
{
    return false;
}

int64_t NifLifecycle::bytes_moved() const
{
    return static_cast<int64_t>(0);
}

} // namespace modelnet
