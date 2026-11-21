"""Persist operator settings before live use: real SQLite, simulated adapters."""
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
import json,sqlite3
import pytest
from test_runtime_recovery_v2 import apps
from test_execution_v2 import A,B,Driver
from swapnet.authorization import Principal
from swapnet.embedded import Host
from swapnet.errors import SwapError
from swapnet.journal import Journal
from swapnet.store import Store

OWNER=Principal('alice',True)
WALLET='fixture-wallet-a'
OTHER='fixture-wallet-b'

@contextmanager
def reject(app,key):
    assert key in {'asset_policies','native_wallet'}
    app.store.db.execute("CREATE TEMP TRIGGER reject_setting BEFORE INSERT ON sn_settings WHEN NEW.k='"+key+"' BEGIN SELECT RAISE(ABORT, 'injected setting save rejection'); END")
    try:yield
    finally:app.store.db.execute('DROP TRIGGER reject_setting')

def reopen(app,key,default=None):
    path=app.store.db.execute('PRAGMA database_list').fetchone()[2]
    store=Store(path)
    try:return Journal(store).setting(key,default)
    finally:store.close()

def settings(app):return {k:json.loads(v) for k,v in app.store.db.execute('SELECT k,body FROM sn_settings')}
def budgets(app):return (app.store.db.execute('SELECT id,held,used FROM mandates').fetchall(),app.store.db.execute('SELECT * FROM reservations').fetchall())
def policy(rate):return {'asset':B,'rpc_url':'http://127.0.0.1:18443','fee_rate':rate}
def asset(app,p,ctx=OWNER):return app.rpc(ctx,'setswapassetpolicy',{'policy':p})

def factory(app,ledger):
    calls=[]
    def build(p):
        calls.append(deepcopy(p));driver=Driver(ledger,'alice');driver.policy=deepcopy(p)
        if p.get('fee_rate')==99:
            def refuse():raise SwapError('CHAIN_SYNC','fixture verifier not ready')
            driver.ready=refuse
        return driver
    app.configure_asset=build
    return calls

def host(app,mode):
    h=SimpleNamespace(_wallet='',journal=app.journal,app=app,loaded=[WALLET] if mode=='automatic' else [WALLET,OTHER],calls=0)
    def native(method,*args):
        assert method=='listwallets'
        h.calls+=1;return h.loaded
    h.native=native;return h

def bind(h,mode,wallet=WALLET,owner=True):
    if mode=='automatic':return Host.selected_wallet(h)
    reply=json.loads(Host.rpc(h,'alice',owner,wallet,'getswapwalletinfo','{}'))
    if 'error' in reply:raise SwapError(reply['error']['code'],reply['error']['message'])
    assert 'result' in reply
    return h._wallet

@pytest.mark.parametrize('failures',[1,2])
def test_asset_failed_save_preserves_live_then_retry_reopens(apps,failures):
    nodes,time,ledgers,wire,*_=apps;app=nodes['alice'];factory(app,ledgers[B]);asset(app,policy(1));old=app.drivers[B]
    before=settings(app);balance=budgets(app);sent=len(wire)
    with reject(app,'asset_policies'):
        for _ in range(failures):
            with pytest.raises(sqlite3.IntegrityError,match='injected setting'):asset(app,policy(2))
            assert app.drivers[B] is old and app.coordinator._driver(B) is old
            assert settings(app)==before and reopen(app,'asset_policies')[B]==policy(1)
            assert budgets(app)==balance and len(wire)==sent
    cleared=[]
    app.clear_startup_error=cleared.append
    assert asset(app,policy(2))['ready']
    assert cleared==[B]
    assert app.drivers[B] is not old and app.coordinator._driver(B).policy==policy(2)
    assert reopen(app,'asset_policies')[B]==policy(2) and budgets(app)==balance
    assert not ledgers[A].records and not ledgers[B].records

@pytest.mark.parametrize('mode',['explicit','automatic'])
@pytest.mark.parametrize('failures',[1,2])
def test_wallet_failed_save_remains_unbound_then_retry_reopens(apps,mode,failures):
    nodes,time,ledgers,wire,*_=apps;app=nodes['alice'];h=host(app,mode)
    before=settings(app);balance=budgets(app);sent=len(wire)
    with reject(app,'native_wallet'):
        for _ in range(failures):
            with pytest.raises(sqlite3.IntegrityError,match='injected setting'):bind(h,mode)
            assert h._wallet=='' and settings(app)==before and reopen(app,'native_wallet','')==''
            assert budgets(app)==balance and len(wire)==sent
    assert bind(h,mode)==WALLET and h._wallet==WALLET
    assert reopen(app,'native_wallet')==WALLET
    assert budgets(app)==balance and not ledgers[A].records and not ledgers[B].records
    with pytest.raises(SwapError,match='WALLET_SCOPE'):bind(h,'explicit',OTHER)
    assert h._wallet==WALLET and reopen(app,'native_wallet')==WALLET

@pytest.mark.parametrize('guard',['owner','active_swap','not_ready'])
def test_asset_guards_preserve_old_driver_and_policy(apps,guard):
    nodes,time,ledgers,wire,*_=apps;app=nodes['alice'];calls=factory(app,ledgers[B]);asset(app,policy(1));old=app.drivers[B]
    if guard=='active_swap':
        app.journal.save('77'*32,{'principal':'alice','peer':'bob','stage':'committed','agreement':{'long_leg':{'asset':A},'short_leg':{'asset':B}}})
    before=settings(app);count=len(calls)
    with pytest.raises(SwapError,match={'owner':'OWNER_REQUIRED','active_swap':'ASSET_BUSY','not_ready':'CHAIN_SYNC'}[guard]):
        asset(app,policy(99 if guard=='not_ready' else 2),Principal('alice') if guard=='owner' else OWNER)
    assert app.drivers[B] is old and settings(app)==before
    assert len(calls)==count+(guard=='not_ready')

@pytest.mark.parametrize('guard',['owner','unloaded','other_bound','none_loaded','ambiguous','bad_list','bound_unloaded'])
def test_wallet_guards_do_not_change_binding(apps,guard):
    nodes,*_=apps;app=nodes['alice'];automatic=guard in {'none_loaded','ambiguous','bad_list','bound_unloaded'}
    mode='automatic' if automatic else 'explicit';h=host(app,mode);owner=True;wallet=WALLET
    if guard=='owner':owner=False
    if guard=='unloaded':h.loaded=[OTHER]
    if guard=='none_loaded':h.loaded=[]
    if guard=='ambiguous':h.loaded=[WALLET,OTHER]
    if guard=='bad_list':h.loaded={'wallet':WALLET}
    if guard in {'other_bound','bound_unloaded'}:
        h._wallet=WALLET;app.journal.set_setting('native_wallet',WALLET)
        if guard=='other_bound':wallet=OTHER
        else:h.loaded=[OTHER]
    before=settings(app);binding=h._wallet
    code={'owner':'OWNER_REQUIRED','unloaded':'WALLET_UNLOADED','other_bound':'WALLET_SCOPE','none_loaded':'WALLET_SELECTION','ambiguous':'WALLET_SELECTION','bad_list':'WALLET_STATE','bound_unloaded':'WALLET_UNLOADED'}[guard]
    with pytest.raises(SwapError,match=code):bind(h,mode,wallet,owner)
    assert h._wallet==binding and settings(app)==before
    if guard=='owner':assert h.calls==0

@pytest.mark.parametrize('mode',['explicit','automatic'])
def test_existing_durable_binding_does_not_resave(apps,mode):
    nodes,*_=apps;app=nodes['alice'];h=host(app,mode)
    app.journal.set_setting('native_wallet',WALLET);h._wallet=WALLET;before=settings(app)
    with reject(app,'native_wallet'):assert bind(h,mode)==WALLET
    assert settings(app)==before and reopen(app,'native_wallet')==WALLET
