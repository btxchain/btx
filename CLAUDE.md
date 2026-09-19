# CLAUDE.md

If you are an AI coding assistant in this tree, read [AGENTS.md](AGENTS.md)
first. Humans: [HUMANS.md](HUMANS.md). Product overview: [README.md](README.md).

## Two planes

- Monetary: `btxd` — consensus, wallet, ExactReplay, BanMan, AddrMan.
- Model: `btx-modeld` — search, feed, retrieve, release coordination, bounties.

Never mix search, feed, or bounty popularity into consensus, fork choice,
issuance, BanMan, or AddrMan.

## Session

Do not compile (`cmake`, `ninja`, `cmake --build`) unless the operator asked.
Do not commit or push unless asked. Default posture is read-only.

`CLIENT_VERSION_IS_RELEASE` is **false** for **0.34.8rc3**. Full agent rules: AGENTS.md.
