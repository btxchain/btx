# Platform backends

| Platform | CPU | Memory | Power | Thermal | GPU util | Notes |
|---|---|---|---|---|---|---|
| Linux | `/proc/loadavg` | `/proc/meminfo` | `/sys/class/power_supply` | via GPU sample if present | NVML optional, else UNKNOWN | Never shells out to nvidia-smi in the hot path |
| NVIDIA | — | NVML mem if present | NVML power optional | NVML temp | NVML | Conservative if NVML missing |
| AMD | — | UNKNOWN unless ROCm SMI present | UNKNOWN | UNKNOWN | UNKNOWN | Do not block release |
| Apple | load | memory pressure | IOKit power (when wired) | OS thermal state when public | often UNKNOWN | No private APIs in release |
| Windows | documented NOT_SUPPORTED in this tree unless a backend is added | | | | | Do not fake parity |

Unsupported metrics are UNKNOWN. Policy stays conservative. Tests inject
`SystemSignals`.
