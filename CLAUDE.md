# CLAUDE.md

If you are an AI coding assistant in this tree, read [AGENTS.md](AGENTS.md)
first. Humans: [HUMANS.md](HUMANS.md). Product overview: [README.md](README.md).

## Two planes (plus hosted)

- Monetary: `btxd` — consensus, wallet, ExactReplay, BanMan, AddrMan. Modelnet defaults on. This process starts `btx-modeld` and the swarm observer.
- Model: `btx-modeld` — the helper `btxd` supervises: search, feed, retrieve, checkout, load, local generate, release coordination, bounties.
- Hosted: `btx-hcpd` / `btx-hosted` — walletless catalogue; not a fifth consensus plane.

Map: [doc/modelnet/swarm/00_THIS_TREE.md](doc/modelnet/swarm/00_THIS_TREE.md).

Never mix search, feed, or bounty popularity into consensus, fork choice,
issuance, BanMan, or AddrMan.

## Session

Do not compile (`cmake`, `ninja`, `cmake --build`) unless the operator asked.
Do not commit or push unless asked. Default posture is read-only.

This tree is **0.35.0rc1** (`CLIENT_VERSION_IS_RELEASE` true, `CLIENT_VERSION_RC` 1).
The last shipping tag remains **v0.34.15**. Full agent rules: AGENTS.md.
