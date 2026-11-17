import test from 'node:test';
import assert from 'node:assert/strict';
import {twoSidedPolicies} from '../web/core/swapnet-maker.js';
const policy=()=>({mandate_id:'a'.repeat(64),numerator:'20',denominator:'3',max_input_atoms:'123456789123456789',maker_fee_atoms:'0',max_receive_network_fee_atoms:'1',max_local_fee_atoms:'20',refund_fee_atoms:'10',claim_fee_atoms:'10'});
const input=()=>({base_asset:`btx:${'1'.repeat(64)}:0:native`,quote_asset:`btc:${'2'.repeat(64)}:0:native`,buy_base:policy(),sell_base:policy(),ttl_seconds:'3600'});
test('two sides retain exact distinct orientation and independent prices',()=>{const x=input();x.sell_base.numerator='7';const rows=twoSidedPolicies(x,1000);assert.equal(rows.length,2);assert.equal(rows[0].market.buy_asset,x.quote_asset);assert.equal(rows[1].market.buy_asset,x.base_asset);assert.equal(rows[1].market.numerator,'7');assert.equal(rows[0].market.max_input_atoms,'123456789123456789');assert.equal(rows[0].market.expires_at,4600);});
test('reject noncanonical money and out-of-budget recovery',()=>{for(const bad of ['1e2','-1','01','1.0']){const x=input();x.buy_base.numerator=bad;assert.throws(()=>twoSidedPolicies(x));}const x=input();x.sell_base.refund_fee_atoms='21';assert.throws(()=>twoSidedPolicies(x));});
