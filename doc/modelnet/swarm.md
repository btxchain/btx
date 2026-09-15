# Swarm (BitTorrent-inspired, BTX-native)

Piece selection, endgame, PEX, and partial serving for model artifacts.
libtorrent/qBittorrent were studied as parts bins and **not** vendored.
qBittorrent is GPL — UX only, never copied.

See [libtorrent-parts-bin-audit.md](libtorrent-parts-bin-audit.md),
[piece-selection.md](piece-selection.md), [provider-exchange.md](provider-exchange.md),
[nat-traversal.md](nat-traversal.md).

Verified SHA-384 pieces are the unit of sharing. A node may demand-seed
incomplete artifacts and serve committed pieces before `index.json` is
complete. Seed-off still 404s piece GET.

Rarest-first with identity/netgroup diversity. Endgame duplicates are
capped. Snubbed peers are skipped. The swarm scheduler is independent of
monetary AddrMan.
