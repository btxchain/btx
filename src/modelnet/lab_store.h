// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_LAB_STORE_H
#define BITCOIN_MODELNET_LAB_STORE_H

#include <util/fs.h>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace modelnet {

/**
 * Private-development on-disk lab store. Not release qualified.
 * Does not spend a wallet. automatic_spend is out of scope.
 *
 * The directory is caller-supplied. Open creates it when missing and reloads
 * lab.store on a later Open of the same path. Durable writes are a temp file
 * in that directory, fsync, rename, then directory fsync.
 */

struct LabRecord {
    std::string record_id;
    std::string type;
    std::string principal;
    std::string realm;
    std::string bytes_ref;
    std::string accepted_at;
    std::string auth_state;
    /** Omitted from PublicExport. Still stored and returned by GetRecord. */
    bool is_private{false};
};

struct LabRef {
    std::string repository;
    std::string name_space; //!< refs.namespace
    std::string name;
    std::string sequence;
    std::string update_id;
    std::string target;
    bool is_private{false};
};

struct LabIdentityEpoch {
    std::string root;
    std::string epoch;
    std::string transition;
    std::string key;
    std::string status;
    bool is_private{false};
};

struct LabRevocation {
    std::string issuer;
    std::string epoch;
    std::string target;
    bool is_private{false};
};

/** Identity of one mutable target. Token bytes bind all four fields. */
struct LabStateKey {
    std::string realm_id;
    std::string owner_scope;
    std::string target_kind;
    std::string target_key;
};

/**
 * Fields hashed into the state token.
 * A disengaged value_id is null and is encoded as a zero-length string.
 */
struct LabStateFields {
    std::string realm_id;
    std::string owner_scope;
    std::string target_kind;
    std::string target_key;
    std::string generation;
    std::optional<std::string> value_id;
    std::string policy_epoch;
};

/** lab.state_get descriptor. state_token is null when the target is absent. */
struct LabStateView {
    bool exists{false};
    std::string generation{"0"};
    std::optional<std::string> value_id;
    std::string policy_epoch{"0"};
    std::optional<std::string> state_token;
};

/** Idempotency scope. The key is caller-scoped, not global. */
struct LabIdempotency {
    std::string caller;
    std::string realm;
    std::string method;
    std::string key;
};

/**
 * SHA-384 hex of ASCII "BTX/035/StateToken/v1.1", one NUL, then the canonical
 * field encoding documented on the definition in lab_store.cpp.
 */
std::string StateToken(const LabStateFields& fields);

/**
 * On-disk projections for records, refs, identity epochs, revocations,
 * idempotency, and state descriptors.
 *
 * Failures return false and set err to a BTX035_* code. Success clears err.
 * max_records counts every persisted row. max_bytes counts every stored string.
 * Crossing either limit returns BTX035_LIMIT_EXCEEDED and does not change
 * signature-required or backend-ready.
 */
class LabStore {
public:
    explicit LabStore(fs::path directory);

    const fs::path& Directory() const { return m_dir; }

    bool Open(std::string& err);

    bool SignatureRequired() const { return m_snap.signature_required; }
    bool BackendReady() const { return m_snap.backend_ready; }
    bool RequiresWallet() const { return false; }

    /** Operator caps. Zero rejects the next new row or any new byte. */
    bool SetLimits(uint64_t max_records, uint64_t max_bytes, std::string& err);
    /**
     * Marks the backend ready only when at least one row exists and the
     * signature-required flag is still set. An empty store stays not ready.
     */
    bool MarkBackendReady(std::string& err);

    bool InsertRecord(const LabRecord& row, std::string& err);
    bool InsertRef(const LabRef& row, std::string& err);
    bool InsertIdentityEpoch(const LabIdentityEpoch& row, std::string& err);
    bool InsertRevocation(const LabRevocation& row, std::string& err);

    bool GetRecord(const std::string& record_id, LabRecord& out, std::string& err) const;
    bool GetRef(const std::string& repository, const std::string& name_space, const std::string& name,
                const std::string& sequence, LabRef& out, std::string& err) const;
    bool GetIdentityEpoch(const std::string& root, const std::string& epoch, LabIdentityEpoch& out, std::string& err) const;
    bool GetRevocation(const std::string& issuer, const std::string& epoch, const std::string& target,
                       LabRevocation& out, std::string& err) const;

    bool PutState(const LabStateFields& fields, std::string& err);
    bool StateGet(const LabStateKey& key, LabStateView& out, std::string& err) const;

    /**
     * Reserve idempotency and check expected_state before any result is committed.
     * Empty expected_state matches only an absent target. A committed row with the
     * same canonical request returns the original response in `response` and sets
     * replayed, including after this object is destroyed and Open is called again.
     * The same key with a different request returns BTX035_IDEMPOTENCY and leaves
     * the stored body in place. A state mismatch returns BTX035_STATE and writes
     * nothing when no reservation exists yet.
     */
    bool Reserve(const LabIdempotency& scope, const std::string& canonical_request,
                 const std::string& expected_state, const LabStateKey& target, bool& replayed, std::string& response,
                 std::string& err);

    /**
     * Commit the reserved response. Re-checks the state token first. A mismatch
     * returns BTX035_STATE and does not store or replace the response body.
     */
    bool Commit(const LabIdempotency& scope, const std::string& canonical_request, const std::string& response_body,
                std::string& err);

    /** Public rows only. A private row is never included. */
    bool PublicExport(std::string& out, std::string& err) const;

private:
    struct IdemRow {
        std::string canonical_request;
        std::string expected_state;
        LabStateKey target;
        bool committed{false};
        std::string result;
    };

    using RefKey = std::tuple<std::string, std::string, std::string, std::string>;
    using EpochKey = std::tuple<std::string, std::string>;
    using RevKey = std::tuple<std::string, std::string, std::string>;
    using IdemKey = std::tuple<std::string, std::string, std::string, std::string>;
    using StateMapKey = std::tuple<std::string, std::string, std::string, std::string>;

    struct Snapshot {
        bool signature_required{true};
        bool backend_ready{false};
        uint64_t max_records{UINT64_MAX};
        uint64_t max_bytes{UINT64_MAX};
        std::map<std::string, LabRecord> records;
        std::map<RefKey, LabRef> refs;
        std::map<EpochKey, LabIdentityEpoch> epochs;
        std::map<RevKey, LabRevocation> revocations;
        std::map<IdemKey, IdemRow> idempotency;
        std::map<StateMapKey, LabStateFields> states;
    };

    bool Persist(Snapshot next, std::string& err);
    bool EnsureOpen(std::string& err) const;
    std::string TokenFor(const LabStateKey& key) const;
    bool StateMatches(const LabStateKey& key, const std::string& expected_state, std::string& err) const;

    static RefKey RefOf(const LabRef& row);
    static EpochKey EpochOf(const LabIdentityEpoch& row);
    static RevKey RevOf(const LabRevocation& row);
    static IdemKey IdemOf(const LabIdempotency& scope);
    static StateMapKey StateOf(const LabStateKey& key);
    static StateMapKey StateOf(const LabStateFields& fields);
    static uint64_t EffectiveRows(const Snapshot& snap);
    static uint64_t EffectiveBytes(const Snapshot& snap);
    static bool PayloadBytes(const Snapshot& snap, uint64_t& out);
    static uint64_t RowCount(const Snapshot& snap);
    static bool WithinLimits(const Snapshot& snap, std::string& err);
    static bool Encode(const Snapshot& snap, std::vector<unsigned char>& out, std::string& err);
    static bool Decode(const std::vector<unsigned char>& bytes, Snapshot& snap);
    static bool Save(const fs::path& dir, const Snapshot& snap, std::string& err);

    fs::path m_dir;
    bool m_open{false};
    Snapshot m_snap;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_LAB_STORE_H
