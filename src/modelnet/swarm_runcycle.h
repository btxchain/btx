// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_RUNCYCLE_H
#define BTX_MODELNET_SWARM_RUNCYCLE_H

#include <modelnet/swarm_invoice.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * One in-process evolutionary cycle. It admits work under the sandbox caps,
 * stores an experience row, requires an independent measurement, graduates
 * quality without promoting a realm, adopts a compatible candidate, and pays
 * through the invoice book. It does not broadcast, spend automatically, mine,
 * or claim a GPU ran.
 */
class SwarmRunCycle {
public:
    bool Form(const std::string& node_id, bool modelnet_on, std::string& err);
    bool Admit(const std::string& job_id, int64_t threads, int64_t memory_mib, bool sandbox_present, std::string& err);
    bool Experience(const std::string& job_id, const std::string& kind, std::string& err);
    /** One INTEGER_LINEAR step. The state hash is not a quality score and not a GPU result. */
    bool TrainJob(const std::string& job_id, std::string& err);
    bool Measure(const std::string& job_id, bool author_is_evaluator, bool independent, int64_t score_ppm, std::string& err);
    bool GraduateJob(const std::string& job_id, bool safety_regression, bool broad_regression, std::string& err);
    bool AdoptJob(const std::string& job_id, bool local_compatible, std::string& err);
    bool PayJob(const std::string& job_id, const std::string& beneficiary, int64_t atoms, const uint256& hashlock, const std::vector<unsigned char>& preimage, std::string& err);
    bool ContinueFrom(const std::string& parent_id, const std::string& child_id, std::string& err);
    bool Recover(std::string& err);

    bool formed() const { return m_formed; }
    int64_t earned_atoms() const { return m_earned; }
    const std::string& active_model() const { return m_active; }
    bool job_paid(const std::string& job_id) const;
    uint64_t job_steps(const std::string& job_id) const;
    const std::string& job_state_hash(const std::string& job_id) const;

private:
    struct Job {
        bool admitted{false};
        bool experienced{false};
        bool trained{false};
        uint64_t steps{0};
        std::string state_hash;
        bool measured{false};
        bool graduated{false};
        bool adopted{false};
        bool paid{false};
        int64_t score_ppm{0};
        int64_t atoms{0};
    };

    bool m_formed{false};
    bool m_book_open{false};
    std::string m_node_id;
    std::string m_active{"base"};
    int64_t m_earned{0};
    SwarmInvoiceBook m_book;
    std::map<std::string, Job> m_jobs;

    Job* Find(const std::string& job_id);
    bool EnsureBook(std::string& err);
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_RUNCYCLE_H
