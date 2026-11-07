// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp25/grp25.h>

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_decode/swarm_decode_run.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool Grp25::Open(const std::string& session, const std::string& engine, std::string& err)
{
    return m_decode.Open(session, engine, err);
}

bool Grp25::Prompt(const std::string& session, const std::string& text, bool is_private, std::string& err)
{
    return m_decode.Prompt(session, text, is_private, err);
}

bool Grp25::Pull(const std::string& session, std::string& err)
{
    return m_decode.Pull(session, err);
}

const std::string& Grp25::text() const
{
    return m_decode.text();
}

int64_t Grp25::tokens() const
{
    return m_decode.tokens();
}

std::string Grp25::engine_of(const std::string& session) const
{
    return m_decode.engine_of(session);
}

bool Grp25::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp25::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp25::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp25::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
