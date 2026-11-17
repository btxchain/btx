"""Persistent participation policy. Modes are never wallet authority."""
from __future__ import annotations
from .errors import require

MODES=frozenset({'observe','taker','maker','recovery'})

class Participation:
    def __init__(self,journal,startup_mode=None):
        self.journal=journal
        require(startup_mode is None or startup_mode in MODES,'MODE','Unknown startup mode')
        saved=journal.setting('market.participation','observe')
        require(saved in MODES,'MODE','Invalid persisted participation mode')
        self.override=startup_mode
        self.mode=startup_mode if startup_mode is not None else saved
    def set(self,mode):
        require(mode in MODES,'MODE','Choose observe, taker, maker, or recovery')
        require(self.override!='recovery' or mode=='recovery','MODE_LOCKED',
                'This process was explicitly started recovery-only; restart to enable new activity')
        self.journal.set_setting('market.participation',mode)
        self.mode=mode
        return self.info()
    def may_trade(self):return self.mode in {'taker','maker'}
    def may_make(self):return self.mode=='maker'
    def require_trade(self):
        require(self.may_trade(),'MODE_DISABLED','Enable taker or maker mode before new trading')
    def require_make(self):
        require(self.may_make(),'MODE_DISABLED','Enable maker mode before publishing liquidity')
    def info(self):
        return {'mode':self.mode,'discovery_enabled':self.mode!='recovery',
                'new_trades_enabled':self.may_trade(),'making_enabled':self.may_make(),
                'existing_obligations_recovery_enabled':True,'automatic_spend_atoms':'0',
                'startup_recovery_lock':self.override=='recovery'}
