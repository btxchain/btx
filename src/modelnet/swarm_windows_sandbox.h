// Copyright (c) 2026 The BTX developers. MIT license. See COPYING.
#ifndef BITCOIN_MODELNET_SWARM_WINDOWS_SANDBOX_H
#define BITCOIN_MODELNET_SWARM_WINDOWS_SANDBOX_H
#include <modelnet/swarm_confine.h>
#ifdef _WIN32
namespace modelnet {
/** Windows 8+ AppContainer backend. Zero capabilities prohibit networking.
 * Inputs are copied into an ephemeral private low-integrity profile; the
 * owner tree receives only newly created verified output files. Original
 * inputs must remain unchanged. No owner-tree ACLs are modified. */
SwarmConfineResult SwarmRunWindowsAppContainer(const SwarmConfineRequest&,std::string&);
bool WindowsOwnerOnlyFile(const fs::path&);
bool WriteWindowsReleaseExclusive(const fs::path&,const std::string&,std::string&);
}
#endif
#endif
