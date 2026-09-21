# Extra High review R5 — neutrality

Tree: `/home/administrator/btx-0.34.7-private`

## Verdict

`Crl12BrandDispatch` rejects known brand substrings on `/layer/` POSTs. Roles are the nine generic names. Walletless `btx-hcpd` does not enable finance unless `-finance=1`. `-cr12=1` enables the layer without custody. No global provider directory is required.

## Findings

### R5-01 NOTE — brand list is a denylist, not a proof of all brands

**File:** `hcp_crl12.cpp` `Crl12BrandDispatch`. Native `cr12_neutral_01` and process J01 (`Goldman Sachs` → `BRAND_DISPATCH`) cover the listed names. Unknown brands are allowed, which is the intended generic-entrant rule.

### R5-02 COMPLETE — no default financial host on walletless

`HcpWalletlessPreset` has `finance_enabled=false`, `cr12_enabled=false` unless `-cr12=1`. Process J20 asserts walletless health plus v1.2 discovery.

### R5-03 NOTE — attribution vs operational brand

Research register and licenses remain. Operational JSON with listed brands fails `/layer/` POST. Do not delete license brand strings.
