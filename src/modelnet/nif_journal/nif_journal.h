// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_JOURNAL_NIF_JOURNAL_H
#define BITCOIN_MODELNET_NIF_JOURNAL_NIF_JOURNAL_H

#include <modelnet/nifdt_contract/contract.h>
#include <util/fs.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Accept refused an empty directory. Nothing is written. */
inline constexpr char NIF_JOURNAL_DIR[] = "DIR";

/** Accept refused an empty principal, receiver, generation, or attempt. Nothing is written. */
inline constexpr char NIF_JOURNAL_REQUEST[] = "REQUEST";

/** Accept refused an empty outbox. Nothing is written. */
inline constexpr char NIF_JOURNAL_OUTBOX[] = "OUTBOX";

/** The journal refused this accept. Nothing is written. */
inline constexpr char NIF_JOURNAL_JOURNAL[] = "JOURNAL";

/** Journal file stored under the directory passed to Accept. */
inline constexpr char NIF_JOURNAL_FILE[] = "outbox.journal";

/**
 * NIF-NAT-003. One accepted request and its outbox, written by rename.
 *
 * Accept(dir, record, outbox, journal_ok, err) persists principal,
 * receiver, generation, attempt, and outbox. An empty dir is DIR. An empty
 * principal, receiver, generation, or attempt is REQUEST. An empty outbox
 * is OUTBOX. journal_ok false is JOURNAL. Each of those writes nothing,
 * creates no directory, and leaves any previous outbox.journal in place.
 *
 * A successful accept writes one file, dir/outbox.journal. The body is
 * principal, receiver, generation, attempt, and outbox, each followed by
 * a newline. The write goes to a temp file and then fs::rename onto
 * outbox.journal. A failed rename removes the temp and leaves any previous
 * final file unchanged.
 *
 * A second Accept of the same attempt is NIFDT_REPLAY and does not replace
 * that file. A different attempt replaces the file only after the rename
 * succeeds.
 *
 * bytes_moved() stays 0. launched(), gpu(), broadcast(), and qualified()
 * stay false. automatic_spend() is NIFDT_AUTOMATIC_SPEND ("0"). hosts()
 * stays 1. This class opens no socket and starts no process.
 */
class NifJournal {
public:
    bool Accept(const fs::path& dir, const NifRequestRecord& record, const std::string& outbox, bool journal_ok, std::string& err);

    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool m_have{false};
    std::string m_attempt;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_JOURNAL_NIF_JOURNAL_H
