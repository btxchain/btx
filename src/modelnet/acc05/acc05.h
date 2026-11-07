// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ACC05_ACC05_H
#define BITCOIN_MODELNET_ACC05_ACC05_H

#include <modelnet/action_authority.h>
#include <modelnet/grp17/grp17.h>
#include <modelnet/grp18/grp18.h>
#include <modelnet/grp19/grp19.h>
#include <modelnet/grp20/grp20.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Acc05 enforces DS-NAT-001 through DS-DATA-006.
 * Qualification accessors stay false. hosts() stays 1.
 * Spend stays NIFDT_AUTOMATIC_SPEND. This class opens no file, socket, or process.
 */
class Acc05 {
public:
    bool Apply(const std::string& id, const std::string& op, const std::string& text,
               const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err);
    // Journal caller from Jrn05. Separate from the DS/1 pass.
    bool Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err);
    bool Pass(std::string& err);
    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Vendor(std::string& err);
    bool Spend(std::string& err);

    int64_t stored(const std::string& id) const;
    std::string text_of(const std::string& id) const;
    bool bit_of(const std::string& id) const;
    std::string classification() const;

    std::string observer_text() const { return m_observer; }
    std::string enroll_text() const { return m_enroll; }
    bool enrolled() const { return m_enroll_set; }
    std::string case_state() const { return m_case; }
    std::string pending() const { return m_pending; }
    bool journaled() const { return m_journal_armed; }
    bool published() const { return m_published; }
    int64_t contribution_workers() const { return m_workers; }
    bool wan_refused() const { return m_wan_refused; }
    std::string scope_text() const { return m_scope; }
    bool purpose_granted(const std::string& purpose) const;
    std::string provenance() const { return m_prov; }
    int provenance_count() const;
    std::string purpose_query() const { return m_purpose; }
    int64_t query_time() const { return m_query_time; }
    std::string exported_body() const { return m_exported; }
    std::string grant_text() const { return m_grant; }
    bool gap_reported(const std::string& kind) const;

    bool passed() const { return false; }
    bool gpu() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool advertised() const { return false; }
    bool launched() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    int64_t atoms_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool Nat003(const std::string& op, const std::string& text, bool flag, std::string& err);
    bool Nat005(const std::string& op, const std::string& text, const std::string& extra, bool flag, std::string& err);
    bool Nat006(const std::string& text, bool flag, std::string& err);
    bool Hire001(const std::string& text, std::string& err);
    bool Auth001(const std::string& text, const std::string& extra, bool flag, std::string& err);
    bool Auth003(const std::string& text, int64_t now_ms, int64_t aux, bool flag, std::string& err);
    bool Auth004(const std::string& op, const std::string& text, const std::string& extra, std::string& err);
    bool Auth005(const std::string& text, std::string& err);
    bool Auth006(const std::string& op, const std::string& text, const std::string& extra, int64_t now_ms, std::string& err);
    bool Data001(const std::string& text, const std::string& extra, std::string& err);
    bool Data003(const std::string& text, const std::string& extra, int64_t now_ms, int64_t aux, std::string& err);
    bool Data004(const std::string& op, const std::string& text, const std::string& extra, std::string& err);
    bool Data006(const std::string& op, const std::string& text, std::string& err);

    Grp20 m_nat;
    Grp17 m_auth;
    Grp18 m_hire;
    Grp19 m_family;
    ActionGate m_gate;
    bool m_revoked{false};

    bool m_observer_set{false};
    std::string m_observer;
    bool m_enroll_set{false};
    std::string m_enroll;

    bool m_journal_armed{false};
    std::string m_journal_case;
    std::string m_journal_pending;
    std::string m_case;
    std::string m_pending;

    bool m_published{false};
    int64_t m_workers{0};
    bool m_wan_refused{false};

    std::string m_fingerprint;
    bool m_fingerprint_set{false};

    bool m_sev_set{false};
    std::string m_severity;
    std::string m_scope;

    bool m_grant_read{false};
    bool m_grant_effect{false};
    bool m_grant_release{false};
    bool m_grant_spend{false};

    bool m_lease_set{false};
    std::string m_lease_text;
    int64_t m_lease_aux{0};

    bool m_bytes_set{false};
    std::string m_bytes;
    std::string m_prov;
    std::vector<std::string> m_prov_more;

    bool m_query_set{false};
    std::string m_asset;
    std::string m_purpose;
    int64_t m_query_time{0};
    int64_t m_query_bytes{0};

    bool m_local_set{false};
    std::string m_local;
    bool m_grant_set{false};
    std::string m_grant;
    bool m_did_export{false};
    std::string m_exported;

    bool m_gap_clock{false};
    bool m_gap_loss{false};
    bool m_gap_duplicate{false};
    bool m_gap_missing{false};
    std::map<std::string, std::string> m_journal;
};

} // namespace modelnet

#endif
