# Resource-governor reference audit

Study only. Not BTX runtime dependencies. Do not vendor. Do not copy GPL
qBittorrent source.

Recorded 2026-09-15 under `~/Documents/btx-reference-sources/`.

| Project | SHA | What we studied | BTX-native design | Differences | License note |
|---|---|---|---|---|---|
| BOINC | `55a5644402767961451bf5ff08dd30645f3b642d` | Idle CPU/GPU, suspend reasons, battery, hysteresis, preference hierarchy (`client/hostinfo*.cpp`, `client/cpu_sched.cpp`) | Independent resource dimensions + pause reasons | No BOINC project fetch; no credit; local policy only | LGPL — do not link |
| Folding@home fah-client-bastet | `d85c21a88d0fcca138783cb16b9684e960e0fe04` | Slot pause/resume, GPU slots, headless vs desktop | Permit model per job class | No scientific WU protocol | GPL — study only |
| libtorrent 2.1 | `0608fecaea9f46dd4df62957fe6b839ca68109fa` | Rate limits, active seeds, disk I/O queues, choking | Token-bucket + hysteresis ceilings; swarm still picks pieces | No libtorrent dependency | BSD |
| libtorrent master | `485467b33ebbe34d3876ebce0904226b6b75c490` | Same, newer session | Same | Same | BSD |
| Transmission | `48835c6660a7a3730b5a122bb7b88909997addbe` | Lightweight daemon speed schedule, alt speeds | AUTO vs PERFORMANCE vs ECO modes | No session JSON copy | GPL/MIT mix — study only |
| qBittorrent | `8d3997ac784e42c452a1226287b6b06639b04358` | Alt speed UI, GUI vs backend prefs | First-run checkboxes + advanced RPC | **Never copy GPL source** | GPL |

Deferred after revisit (do not blindly add):

- BOINC per-app GPU exclusion lists
- FAH fold-at-idle screensaver coupling
- libtorrent mixed-mode choking fairness beyond our swarm lanes
- Transmission blocklist UX
- qBittorrent scheduler calendar (use PERFORMANCE/ECO instead)

Sleep/wake: helper and btxd already restart-safe; permit file is rewritten
every 2s after Observe. Full sleep/wake E2E is NOT_RUN until executed on
Apple Silicon.
