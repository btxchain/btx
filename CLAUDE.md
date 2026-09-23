# CLAUDE.md

If you are an AI coding assistant in this tree, read [AGENTS.md](AGENTS.md)
first. Humans: [HUMANS.md](HUMANS.md). Product overview: [README.md](README.md).

## Two planes (plus hosted)

- Monetary: `btxd` — consensus, wallet, ExactReplay, BanMan, AddrMan.
- Model: `btx-modeld` — search, feed, retrieve, checkout, load, local generate, release coordination, bounties.
- Hosted: `btx-hcpd` / `btx-hosted` — walletless catalogue; not a fifth consensus plane.

Never mix search, feed, or bounty popularity into consensus, fork choice,
issuance, BanMan, or AddrMan.

## Session

Do not compile (`cmake`, `ninja`, `cmake --build`) unless the operator asked.
Do not commit or push unless asked. Default posture is read-only.

`CLIENT_VERSION_IS_RELEASE` is **false** for **0.34.9-dev**. Last shipping
tag is **v0.34.8**. Full agent rules: AGENTS.md.
