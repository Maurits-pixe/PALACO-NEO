import test from 'node:test';
import assert from 'node:assert/strict';
import {appendAudit,verifyAudit,verifyCheckpoint,GENESIS_HASH} from '../src/audit.mjs';
const event = (id='neo-002-1') => ({requestId:id,decision:'DENY',reason:'GO13_HOLD'});
test('empty genesis has defined head',()=>assert.deepEqual(verifyAudit([]),{ok:true,reason:'STRUCTURALLY_VALID',head:GENESIS_HASH,count:0}));
test('append produces a verifiable chain without mutating input',()=>{
 const input=[];const a=appendAudit(input,event());const b=appendAudit([a],event('neo-002-2'));
 assert.equal(input.length,0);assert.equal(Object.isFrozen(a),true);
 assert.deepEqual(verifyAudit([a,b]),{ok:true,reason:'STRUCTURALLY_VALID',head:b.hash,count:2});
});
test('edited record denied',()=>{const a=appendAudit([],event());assert.equal(verifyAudit([{...a,reason:'CHANGED'}]).reason,'BROKEN_CHAIN');});
test('missing or reordered entries denied',()=>{const a=appendAudit([],event());const b=appendAudit([a],event('neo-002-2'));assert.equal(verifyAudit([b]).ok,false);assert.equal(verifyAudit([b,a]).ok,false);});
test('trusted external head detects valid-looking rollback',()=>{const a=appendAudit([],event());const b=appendAudit([a],event('neo-002-2'));assert.equal(verifyAudit([a],b.hash).reason,'CHECKPOINT_MISMATCH');});
test('checkpoint count protects against truncated chain',()=>{const a=appendAudit([],event());assert.deepEqual(verifyCheckpoint([a],{head:a.hash,count:1}),{ok:true,reason:'MATCH'});assert.equal(verifyCheckpoint([],{head:a.hash,count:1}).ok,false);});
test('malformed input and unknown decisions denied',()=>{assert.throws(()=>appendAudit([], {...event(),decision:'ALLOW'}),/INVALID_EVENT/);assert.equal(verifyAudit([{}]).ok,false);assert.equal(verifyCheckpoint([],{head:'x',count:0}).ok,false);});
test('untrusted prior chain rejected',()=>assert.throws(()=>appendAudit([{}],event()),/UNTRUSTED_CHAIN/));
