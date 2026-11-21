# Shared P2P service core: ModelNet and SwapNet

The authoritative service core is instantiated in `btxd`, keyed by the exact native network genesis. SwapNet uses direct typed calls. A supervised ModelNet helper delegates through a private local IPC broker. Merely compiling the same header into two executables is not treated as shared state.

The core owns bounded service sessions, service-scoped byte admission, public-record mirrors, route alternatives and metrics. Persistent discovery mirrors are separate by service and network. Existing monetary AddrMan/block relay and ModelNet's verified piece-transfer implementation are not replaced by a second invented networking stack. The existing authenticated transport adapters remain responsible for their protocols; common admission and route state is shared rather than duplicated.

ModelNet handshake processing retains TLS 1.3, MLKEM768, AES-256-GCM-SHA384 and ML-DSA44 requirements. Its native adapter delegates admission only after inspecting the real negotiated session and extracting the transport pin. The private IPC token authenticates the trusted local helper to the parent; it is not remote cryptographic proof of PQ1. A malicious same-user helper is inside that local trust boundary. No wallet functions, signing keys, monetary principal objects or arbitrary RPC names cross this bridge.

The broker's fixed ModelNet operations admit/close service sessions, charge bytes, mirror already verified public records, and learn/query bounded routes. A request cannot select SwapNet's service namespace. Parent-created credentials are private, never exposed in a peer link, and never placed in a peer payload. Stale socket recovery must refuse a live listener or a differently owned path. Shutdown stops the helper/core path deliberately; new activity fails closed when its parent is unavailable.

Both services retain their own semantic verification and persistence. ModelNet signatures and content hashes determine model-record validity. SwapNet signatures, owner mandates and independently verified chain contracts determine market validity. Shared routing does not make a ModelNet participant a maker or let a provider modify a model's provenance.

Bulk traffic must be charged without starving financial-control frames; per-service limits and existing ModelNet transfer pacing remain distinct. Service-core tests, real two-process broker tests, PQ1-negative tests, helper restarts and complete native builds are required evidence. A standalone header test is not proof that every production call path is attached.
