// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp26/grp26.h>

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_decode/swarm_decode_run.h>
#include <modelnet/training_integer.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

bool Grp26::Echo(const std::string& session, const std::string& prompt, std::string& err)
{
    return Echo(session, prompt, false, err);
}

bool Grp26::Echo(const std::string& session, const std::string& prompt, bool is_private, std::string& err)
{
    if (!m_decode.Open(session, "memory", err)) {
        return false;
    }
    if (!m_decode.Prompt(session, prompt, is_private, err)) {
        if (is_private) {
            err = NIFDT_PRIVATE_DATA;
        }
        return false;
    }
    while (m_decode.Pull(session, err)) {
    }
    if (err == "DONE") {
        return m_decode.text().size() <= static_cast<std::size_t>(8);
    }
    return false;
}

bool Grp26::Step(std::string& err)
{
    return m_trainer.Step(err);
}

const std::string& Grp26::text() const
{
    return m_decode.text();
}

int64_t Grp26::tokens() const
{
    return m_decode.tokens();
}

std::string Grp26::engine_of(const std::string& session) const
{
    return m_decode.engine_of(session);
}

const IntegerState& Grp26::State() const
{
    return m_trainer.State();
}

int64_t Grp26::pairs() const
{
    return static_cast<int64_t>(IntegerDataset().size());
}

bool Grp26::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp26::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp26::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp26::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
