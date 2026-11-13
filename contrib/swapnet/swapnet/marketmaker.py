"""Maker-side fixed-rational quotes with durable inventory reservations.

Inventory snapshots must come from the maker's own independently verified client.
Reservations are local risk controls, NOT public proof of reserves or exclusivity.
"""
from dataclasses import dataclass
from .canonical import atoms,integer,digest,dumps,loads,hex32,exact_fields
from .assets import Asset
from .quote import Quote,SignedQuote
from .errors import require

@dataclass(frozen=True)
class Market:
    sell_asset:str
    buy_asset:str
    numerator:str
    denominator:str
    maker_fee_atoms:str
    max_receive_network_fee_atoms:str
    max_input_atoms:str
    expires_at:int
    def __post_init__(self):
        Asset.parse(self.sell_asset);Asset.parse(self.buy_asset)
        atoms(self.numerator,positive=True);atoms(self.denominator,positive=True)
        atoms(self.maker_fee_atoms);atoms(self.max_receive_network_fee_atoms)
        atoms(self.max_input_atoms,positive=True);integer(self.expires_at,lo=1)
    def output(self,sell):
        n=atoms(sell,positive=True)
        require(n<=atoms(self.max_input_atoms),'MARKET_SIZE','Trade exceeds maker limit')
        return n*atoms(self.numerator)//atoms(self.denominator)

class Maker:
    def __init__(self,store,network,identity,sign,verify):
        self.store=store;self.network=hex32(network);self.identity=identity;self.sign=sign;self.verify=verify
        with store.transaction() as db:
            db.execute('CREATE TABLE IF NOT EXISTS maker_inventory(asset TEXT PRIMARY KEY,amount TEXT NOT NULL,observed INTEGER NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS maker_quotes(rfq TEXT PRIMARY KEY,asset TEXT NOT NULL,amount TEXT NOT NULL,expires INTEGER NOT NULL,body BLOB NOT NULL,signature TEXT)')
            db.execute("INSERT OR IGNORE INTO metadata VALUES('maker_sequence','0')")
    def set_verified_inventory(self,asset,amount_atoms,observed_at):
        Asset.parse(asset);atoms(amount_atoms);integer(observed_at)
        with self.store.transaction() as db:
            db.execute('INSERT INTO maker_inventory VALUES(?,?,?) ON CONFLICT(asset) DO UPDATE SET amount=excluded.amount,observed=excluded.observed',(asset,amount_atoms,observed_at))
    def quote(self,rfq,market,now):
        exact_fields(rfq,{'network','requester','sell_asset','buy_asset','sell_atoms','nonce','issued_at','expires_at'})
        require(rfq['network']==self.network and rfq['issued_at']<=now<rfq['expires_at']<=rfq['issued_at']+120,'RFQ','Invalid RFQ lifetime/network')
        require((rfq['sell_asset'],rfq['buy_asset'])==(market.sell_asset,market.buy_asset) and now<market.expires_at,'MARKET','Market unavailable')
        amount=market.output(rfq['sell_atoms']);expires=min(now+60,rfq['expires_at'],market.expires_at)
        rid=digest('BTX/SWAPNET/RFQ/1',rfq)
        with self.store.transaction() as db:
            db.execute('DELETE FROM maker_quotes WHERE expires<=?',(now,))
            old=db.execute('SELECT body,signature FROM maker_quotes WHERE rfq=?',(rid,)).fetchone()
            if old:q=Quote.parse(loads(old[0]));sig=old[1]
            else:
                require(db.execute('SELECT COUNT(*) FROM maker_quotes').fetchone()[0]<256,'MAKER_LIMIT','Too many reserved quotes')
                row=db.execute('SELECT amount,observed FROM maker_inventory WHERE asset=?',(market.buy_asset,)).fetchone()
                require(row is not None and 0<=now-row[1]<=30,'INVENTORY_STALE','Fresh local inventory required')
                held=sum(atoms(r[0]) for r in db.execute('SELECT amount FROM maker_quotes WHERE asset=?',(market.buy_asset,)))
                # Conservative: reserve gross receive size, not size net of maker fee.
                require(held+amount<=atoms(row[0]),'INSUFFICIENT_LIQUIDITY','Maker inventory already reserved')
                sequence=int(db.execute("SELECT v FROM metadata WHERE k='maker_sequence'").fetchone()[0])+1
                q=Quote(self.network,self.identity,rfq['requester'],digest('BTX/SWAPNET/MAKER-NONCE/1',{'rfq':rid,'sequence':sequence}),sequence,
                        market.sell_asset,market.buy_asset,rfq['sell_atoms'],str(amount),market.maker_fee_atoms,market.max_receive_network_fee_atoms,now,expires)
                from dataclasses import asdict
                db.execute('INSERT INTO maker_quotes VALUES(?,?,?,?,?,NULL)',(rid,market.buy_asset,str(amount),expires,dumps(asdict(q))))
                db.execute("UPDATE metadata SET v=? WHERE k='maker_sequence'",(str(sequence),));sig=None
        # Signing is never done under the SQL lock. A crash keeps inventory
        # reserved until expiry; a retry signs the same quote ID, not new terms.
        if sig is None:
            sig=self.sign(self.identity,q.signing_message)
            require(self.verify(self.identity,sig,q.signing_message) is True,'BAD_SIGNATURE','Maker signer returned an invalid signature')
            with self.store.transaction() as db:db.execute('UPDATE maker_quotes SET signature=? WHERE rfq=?',(sig,rid))
        require(q.live(now),'QUOTE_EXPIRED','Quote expired while signing')
        return SignedQuote(q,sig)
