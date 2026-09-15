# Bootstrap

Bootstrap peers are **introduction only**.

After the routing table has other healthy model contacts, losing every
configured bootstrap node must not destroy discovery. New providers can
still be found through remaining contacts and signed provider records.

Sources (none is authoritative):

- compiled defaults where present
- operator `-modelpeer` / helper peers
- previously validated cached contacts
- optional DNS convenience (DNS failure must not kill model networking)
- trusted community router records as hints

`getmodelnetworkinfo.bootstrap_dependency` is true only while the node
still has no independent routing contacts.

Mandatory idea (CONN-BOOT): join via A/B → populate table → shut A/B →
provider C announces → client still finds C.
