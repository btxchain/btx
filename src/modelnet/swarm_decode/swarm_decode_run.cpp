// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_decode/swarm_decode_run.h>

#include <modelnet/swarm_decode/book.h>
#include <modelnet/swarm_decode/open.h>
#include <modelnet/swarm_decode/output.h>
#include <modelnet/swarm_decode/prompt.h>
#include <modelnet/swarm_decode/pull.h>
#include <modelnet/swarm_decode/status.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmDecodeRun::Open(const std::string& session, const std::string& engine, std::string& err)
{
    return SwarmDecodeOpenApply(m_book, session, engine, err);
}

bool SwarmDecodeRun::Prompt(const std::string& session, const std::string& text, bool is_private, std::string& err)
{
    return SwarmDecodePromptApply(m_book, session, text, is_private, err);
}

bool SwarmDecodeRun::Pull(const std::string& session, std::string& err)
{
    return SwarmDecodePullApply(m_book, m_output, session, err);
}

std::string SwarmDecodeRun::engine_of(const std::string& session) const
{
    return m_book.engine_of(session);
}

const std::string& SwarmDecodeRun::text() const
{
    return m_output.text();
}

int64_t SwarmDecodeRun::tokens() const
{
    return m_output.tokens();
}

bool SwarmDecodeRun::measured() const
{
    return m_status.measured();
}

bool SwarmDecodeRun::launched() const
{
    return m_status.launched();
}

bool SwarmDecodeRun::gpu() const
{
    return m_status.gpu();
}

int64_t SwarmDecodeRun::bytes_moved() const
{
    return m_status.bytes_moved();
}

} // namespace modelnet
