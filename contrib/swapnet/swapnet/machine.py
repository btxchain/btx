"""Pure swap decision engine. Only locally verified observations enter this API.

A secret is considered exposed as soon as a signed claim is handed to any
broadcasting component, not when mined. Reorgs NEVER make a secret private again.
"""
from dataclasses import dataclass, asdict
from .canonical import hex32, integer
from .policy import ChainClock, Deadline, SafetyPolicy
from .errors import require, SwapError

@dataclass(frozen=True)
class LegObservation:
    present: bool = False
    exact_terms: bool = False
    canonical: bool = False
    confirmations: int = 0
    finalized: bool = False
    claimed: bool = False
    refunded: bool = False
    conflicting: bool = False
    observed_at: int = 0

    def __post_init__(self):
        for name in ('present','exact_terms','canonical','finalized','claimed','refunded','conflicting'):
            require(type(getattr(self,name)) is bool,'OBSERVATION','Boolean observation required')
        integer(self.confirmations); integer(self.observed_at)
        require(not(self.claimed and self.refunded),'OBSERVATION','A leg cannot be both claimed and refunded')

    def settled(self,family,policy,now):
        return (0 <= now-self.observed_at <= policy.max_observation_age_seconds and self.present
                and self.exact_terms and self.canonical and not self.conflicting
                and self.confirmations >= policy.confirmations(family)
                and (family!='evm' or not policy.require_evm_finalized or self.finalized))

@dataclass
class Session:
    id: str
    role: str
    phase: str = 'awaiting_authorization'
    authorized: bool = False
    secret_exposed: bool = False
    funding_prepared: bool = False
    funding_broadcast: bool = False
    recovery_ready: bool = False
    last_action: str = 'none'
    def __post_init__(self):
        hex32(self.id)
        require(self.role in {'initiator','responder'},'ROLE','Invalid swap role')
        for name in ('authorized','secret_exposed','funding_prepared','funding_broadcast','recovery_ready'):
            require(type(getattr(self,name)) is bool,'SESSION','Invalid session flag')

    def authorize(self): self.authorized=True; self.phase='authorized'
    def mark_exposed(self): self.secret_exposed=True; self.phase='secret_exposed'
    def export(self): return asdict(self)


def decide(s:Session,a:LegObservation,b:LegObservation,clock_a:ChainClock,clock_b:ChainClock,
           long:Deadline,short:Deadline,policy:SafetyPolicy,now:int):
    """Return one bounded action. No network calls; journal action before execution.

    A: initiator funds long leg, responder claims. B: responder funds short leg,
    initiator claims. All branch decisions use chain-qualified, fresh observations.
    """
    policy.check_clocks(now,clock_a,clock_b)
    for obs in (a,b):
        require(0 <= now-obs.observed_at <= policy.max_observation_age_seconds,'STALE_OBSERVATION','Leg observation stale')
    a_ok=a.settled(clock_a.family,policy,now)
    b_ok=b.settled(clock_b.family,policy,now)
    local=a if s.role=='initiator' else b
    local_clock=clock_a if s.role=='initiator' else clock_b
    local_deadline=long if s.role=='initiator' else short
    if a.conflicting or b.conflicting: return 'freeze_and_reconcile'
    if a.claimed and b.claimed and a_ok and b_ok: return 'complete'
    if local.refunded and local.settled(local_clock.family,policy,now): return 'refunded'
    # After exposure continue recovery/claim, including after chain reorganization.
    if s.secret_exposed:
        if s.role=='responder' and a_ok and not a.claimed and not a.refunded:
            return 'claim_long_leg'
        if s.role=='initiator' and b_ok and not b.claimed and not b.refunded:
            return 'rebroadcast_short_claim'
    if local.present and not local.claimed and not local.refunded:
        expired=(local_clock.height >= local_deadline.value if local_deadline.domain=='height'
                 else local_clock.timestamp >= local_deadline.value)
        if expired: return 'refund_local_leg'
    if s.role=='initiator' and a_ok and b_ok and not a.claimed and not b.claimed and not a.refunded and not b.refunded:
        try: policy.validate_deadlines(long,short,clock_a,clock_b,now)
        except SwapError: return 'wait_or_refund_without_revealing'
        if s.secret_exposed: return 'rebroadcast_short_claim'
        require(s.recovery_ready,'RECOVERY_MISSING','Recovery must be durable before secret release')
        return 'persist_secret_exposure_then_claim_short_leg'
    if not s.authorized: return 'await_authorization'
    if s.funding_broadcast: return 'reconcile_existing_funding'
    if s.role=='initiator' and not a.present:
        policy.validate_deadlines(long,short,clock_a,clock_b,now)
        return 'broadcast_prepared_long_funding' if s.funding_prepared and s.recovery_ready else 'prepare_long_funding_and_recovery'
    if s.role=='responder' and a_ok and not a.claimed and not a.refunded and not b.present:
        policy.validate_deadlines(long,short,clock_a,clock_b,now)
        return 'broadcast_prepared_short_funding' if s.funding_prepared and s.recovery_ready else 'prepare_short_funding_and_recovery'
    return 'wait_for_chain'
