# Refund rebroadcast after rollback

**Before: the original refund is skipped. After: the same signed refund returns to the mempool and confirms without funding again.**

Base: release-0.34.17 `1e2f8b5f12295002334d3390c12cac0bb4ae2aff`. Product change: only UTXODriver.has_transaction; historical lookup, Ethereum and journaled bytes unchanged. Tested source is identified by file hashes in MANIFEST.json; the final commit also contains this evidence and the maintained regression.

## Maintained regression

From the repository root, with the existing SwapNet Python dependencies installed:

    PYTHONPATH=contrib/swapnet python3 -m unittest discover -s contrib/swapnet/tests -p test_transaction_presence.py -v

The nine methods passed on the candidate. The identical file against the base has 14 failing assertions/subtests across nine methods. The local invocation used the same file with an isolated PYTHONPATH, not an integrated full test suite. Both outputs are retained.

## Native result

macOS ARM64, Bitcoin Core32.1.0, saved binary SHA256 `58f9e3b5b8cf0cecd268cc6bf02993f3244e1a93fe8d67949ced6b52c2fdd9fb`. Reused one already funded regtest HTLC: amount100,000sat, refund lock height105, fee2,000sat.

Invalidating block105 returns tip to104, keeping funding intact but removing the now-nonfinal refund from mempool. Restart Core and reopen SQLite Journal. At105, testmempoolaccept allows the same refund. Base Journal retry makes zero send calls; another block has no refund, and direct submission of the original bytes is the healthy diagnostic control. Candidate Journal retry makes one send, enters mempool and confirms at106:98,000sat to the original refund script, original funding outpoint consumed. No new signing or funding.

Confirmed and mempool originals suppress duplicate submissions. Candidate's premature-refund submission is refused by the native node and its probe operation stays prepared. Raw transaction identity, Core results and payout observations are in before.json/after.json. saved-after-assertions.json records explicit checks against the saved automatic-recovery output; these checks were strengthened during review without repeating the native run.

The native experiment used a retained local regtest fixture, equivalent before/after rollback states and separate journals. The checkpoint is not included here, so these JSON receipts are observed evidence, not a self-contained fresh-chain reproduction script. The maintained regression above is runnable from the branch.

## Limits

Native execution covers production UTXODriver/Journal/Store on Bitcoin Core, not the full native btxd coordinator or bilateral swap. BTX offline-refund caller controls use simulated RPC. Additional actual native BTX wallet/presence controls are described below; full native HTLC/coordinator/default-profile qualification remains untested. No native Linux/Windows, EVM, full suite or release qualification. Existing Bitcoin fixture and terminal-recovery tests were reused; no consensus, authority, signature, fee or budget policy changed. Prepared with Codex; bounded code/evidence review is not an independent native-platform run.


## Additional native BTX wallet controls

Saved Mac ARM64 package source949a98e34222cc4cdb5b1d5bd650aa3b7bcbff72, artifact14147748488; current PR777 external UTXODriver/Journal. Archive and daemon hashes are pinned in native-btx-receipt.json. Reused documented CPU wallet test flags: autoshieldcoinbase=0; regtestmatmulbindingheight/productdigestheight/v4height=2147483647; regtestmatmulrequireproductpayload=0. These postpone MatMul activation for this regtest fixture; they do not qualify default ExactReplay/MatMul.

Candidate controls passed: native confirmed/mempool recognition and duplicate suppression; wallet-known dropped transaction absent after rollback and restart; premature native non-final refusal with probe remaining prepared; exactly one original-byte rebroadcast after maturity; one confirmation, unchanged native decoded outputs/raw and consumed original inputs; zero new fund operations during recovery. The node stopped and the1.25GiB storage reserve remained intact. No rebuild.

This was an ordinary native timelocked P2MR wallet spend, **not an HTLC refund**; journal kind refund is a fixture label. These are candidate-only BTX compatibility controls, not a native BTX before/after claim. The matched real HTLC-refund before/after remains the separate Bitcoin result above. No full native btxd coordinator, bilateral swap, current native1e2build, full suites or release qualification.

native-btx-result.json retains the observed control results (RPC help text omitted). native-btx-harness.py is the unchanged locally executed audit harness: it depends on the retained artifact/runtime layout and current candidate Python directory and is **not a turnkey fresh-checkout command**. Use the maintained regression command above for the branch's directly runnable test. The native checkpoint/wallet data are not published.
