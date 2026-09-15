# Model access policy (ACL)

Normative: root addendum §8 (D07). Not BanMan. Not CSV PASS.

v1.1 D07: model allow/deny is **separate state** from monetary peer policy.

MUST NOT translate community trust, seeding, or preservation circles into:

- `NoBan` / BanMan
- `ForceRelay`
- fee discounts
- preferred block-download slots
- earlier block delivery

Genuine cross-plane abuse (e.g. using model sockets to stall validation)
may still be treated as abuse of this node. That is not “they denied a
model, so disconnect their blocks.”

`AffectsMonetaryBan()` on the model ACL is false. Unit:
`acl_does_not_ban_monetary`.
