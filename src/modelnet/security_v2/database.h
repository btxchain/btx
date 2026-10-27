// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BITCOIN_MODELNET_SECURITY_V2_DATABASE_H
#define BITCOIN_MODELNET_SECURITY_V2_DATABASE_H
#include <modelnet/security_v2/common.h>
#include <mutex>
#include <sqlite3.h>
namespace modelnet::security {
using Rows = std::vector<std::vector<std::string>>;
/** SQLite is part of the packaged native dependency image, not a server.
 * One connection per Database; a transaction holds the connection mutex.
 * WAL + synchronous=FULL, defensive mode, no extensions, and prepared binds. */
class Database {
    sqlite3* m_db{nullptr};
    std::recursive_mutex m_mutex;
    fs::path m_root;
public:
    explicit Database(fs::path root);
    ~Database();
    Database(const Database&)=delete;
    Database& operator=(const Database&)=delete;
    const fs::path& Root() const { return m_root; }
    Rows Query(std::string_view sql, const std::vector<std::string>& args = {});
    void Exec(std::string_view sql, const std::vector<std::string>& args = {});
    class Transaction {
        Database& m_db;
        std::unique_lock<std::recursive_mutex> m_lock;
        bool m_done{false};
    public:
        explicit Transaction(Database& db);
        ~Transaction();
        void Commit();
    };
    std::string Meta(const std::string& key, const std::string& fallback = {});
    void SetMeta(const std::string& key, const std::string& value);
    void CheckClock(int64_t now);
    std::string Put(const Json& envelope, std::string_view visibility = "private");
    Json Get(const std::string& id);
    bool Has(const std::string& id);
    std::vector<std::string> List(std::string_view kind, size_t limit = 128, std::string_view after = {});
    void Event(std::string_view kind, std::string_view subject, const Json& public_metadata);
    bool VerifyJournal();
    bool Revoked(std::string_view subject, int64_t now);
    void Revoke(std::string_view subject, std::string_view notice, uint64_t epoch, int64_t now);
    void LinkParent(std::string_view child, std::string_view parent);
    bool AncestryRevoked(std::string_view child, int64_t now);
};
uint64_t ParseUInt(std::string_view value);
} // namespace modelnet::security
#endif
