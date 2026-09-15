# Power, thermal, battery

Thermal states: UNKNOWN, NORMAL, WARM, HOT, CRITICAL.

- NORMAL: opportunistic work
- WARM: mining intensity capped at 50%
- HOT: pause mining; reduce preservation
- CRITICAL: stop optional background jobs

Desktop/server on AC: normal AUTO.

Laptop on battery: background mining off (`-backgroundonbattery=0`).
Preservation strongly reduced. User-requested downloads still allowed.

Metered networks: `-backgroundonmetered=0` pauses preservation and
strongly reduces seeding.

PERFORMANCE/MANUAL: server operators may run continuously without
desktop-idle heuristics.
