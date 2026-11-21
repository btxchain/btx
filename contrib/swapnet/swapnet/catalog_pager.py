"""Bounded, backpressure-aware continuation using legacy-compatible swprov frames.
A swget begins a stream of already signed advertisements, not a new wire protocol.
"""
from collections import OrderedDict
from .market_controls import require
class CatalogPager:
 def __init__(self,clock,max_peers=128,per_peer=8,total=32):
  self.now=clock;self.max_peers=max_peers;self.per_peer=per_peer;self.total=total;self.streams=OrderedDict();self.expired_streams=0
 def request(self,peer,after,limit):
  require(type(after) is str and len(after)<=256,'CURSOR','Invalid provider cursor')
  require(type(limit) is int and 1<=limit<=32,'LIMIT','Invalid page size')
  self.expire()
  if peer in self.streams:return False
  if len(self.streams)>=self.max_peers:return False
  self.streams[peer]={'after':after,'limit':min(limit,self.per_peer),'expires':self.now()+600};return True
 def expire(self):
  for p,s in list(self.streams.items()):
   if s['expires']<=self.now():self.streams.pop(p,None);self.expired_streams+=1
 def close(self,peer):self.streams.pop(peer,None)
 def pump(self,fetch,send):
  self.expire();budget=self.total
  for peer in list(self.streams):
   if budget<=0:break
   s=self.streams[peer];count=min(s['limit'],budget)
   result=fetch(s['after'],count)
   records=result['providers'];require(len(records)<=count,'CATALOG','Catalog exceeded page bound')
   complete=True
   for record in records:
    if not send(peer,record):complete=False;break
    s['after']=record['body']['identity'];budget-=1
   if complete and result.get('next_cursor') is None:self.streams.pop(peer,None)
   elif peer in self.streams:self.streams.move_to_end(peer)
  return self.total-budget
