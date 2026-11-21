import test from 'node:test';
import assert from 'node:assert/strict';
import {atomString,parseInvitation,offerRows,prepareReviewed,INVITE_PREFIX} from '../web/core/swapnet-market.js';
test('asset atoms retain full precision and reject noncanonical numbers',()=>{
 assert.equal(atomString('9007199254740993'),'9007199254740993');
 for(const x of [1,'1.0','01','-1','1e8',' 1',''])assert.throws(()=>atomString(x));
 assert.throws(()=>atomString('0',{positive:true}));
});
test('opening an invitation is inert and bounded',()=>{
 const parsed=parseInvitation(INVITE_PREFIX+'abc_DEF-123');
 assert.equal(parsed.spendingAuthority,false);assert.equal(parsed.connectionStarted,false);
 assert.throws(()=>parseInvitation('https://example.com'));assert.throws(()=>parseInvitation(INVITE_PREFIX+'A'.repeat(32768)));
});
test('firm and indicative prices are not mislabeled as guaranteed balances',()=>{
 const record={body:{provider:'key',offer_id:'a'.repeat(64),sequence:1,expires_at:200,kind:'firm',sell_asset:'a',buy_asset:'b',withdrawn:false,
 tiers:[{sell_atoms:'1',buy_atoms:'9007199254740999',maker_fee_atoms:'1',max_receive_network_fee_atoms:'2',slots:1}]}};
 const rows=offerRows({offers:[record]},100);assert.equal(rows[0].minimumReceiveAtoms,'9007199254740996');assert.match(rows[0].assurance,/on-chain/);
 assert.equal(offerRows({offers:[record]},201).length,0);
});
test('native preparation sends one request object and does not execute',async()=>{
 const calls=[];const bridge={mode:'native',prepare:async(...args)=>{calls.push(args);return {id:'review'};},execute:()=>{throw Error('must not execute');}};
 await prepareReviewed(bridge,'connectswapinvite',{uri:'inert'},'wallet');
 assert.deepEqual(calls,[['connectswapinvite',[{uri:'inert'}],'wallet']]);
 await assert.rejects(()=>prepareReviewed({mode:'demo'},'confirmswap',{}));
});
