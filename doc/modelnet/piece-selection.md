# Piece selection

`src/modelnet/piece_picker.cpp` implements:

- rarity with identity / netgroup / endpoint diversity (one host is not
  ten independent sources)
- rarest-first after a short random-first bootstrap window
- endgame duplicate cap (max 2)
- adaptive request window
- SNUBBED vs FAILED
- endangered / currently-unavailable summaries

Fine-grained availability is learned over PQ1 after connect. Routing
records only carry a compact complete/ranges summary.
