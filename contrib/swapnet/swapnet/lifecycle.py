"""Persisted admission mode, independent of the obligation recovery scheduler."""
from .market_controls import require
MODES=frozenset({'observe','trade','maker','recovery'})

class ModeControl:
    def __init__(self,journal,initial='observe'):
        require(initial in MODES,'MODE','Unknown startup mode')
        self.journal,self.initial=journal,initial
        saved=journal.setting('liquidity_mode',None)
        require(saved is None or saved in MODES,'MODE_STATE','Invalid saved mode; refusing new activity')
    @property
    def mode(self):return self.journal.setting('liquidity_mode',self.initial)
    def set(self,mode):
        require(mode in MODES,'MODE','Expected observe, trade, maker or recovery')
        self.journal.set_setting('liquidity_mode',mode)
        return self.status()
    def permit_new_taker(self):require(self.mode in {'trade','maker'},'TRADING_PAUSED','New trades are disabled; existing obligations continue')
    def permit_new_maker(self):require(self.mode=='maker','MAKING_PAUSED','New maker obligations are disabled')
    def status(self):
        return {'mode':self.mode,'new_taker_allowed':self.mode in {'trade','maker'},
                'new_maker_allowed':self.mode=='maker','recovery_enabled':True,
                'automatic_spend_atoms':'0','mode_is_not_spending_authority':True}
