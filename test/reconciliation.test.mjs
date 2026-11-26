import test from 'node:test';
import assert from 'node:assert/strict';
import {INITIAL_ANCHOR,proposeCheckpoint} from '../src/checkpoint.mjs';
import {classifyUncertainCommit} from '../src/reconciliation.mjs';

const event = id => ({requestId:id,decision:'DENY',reason:'GO13_HOLD'});
const first = proposeCheckpoint([],INITIAL_ANCHOR,event('neo-005-a')).candidate;
const second = proposeCheckpoint(first.records,first.anchor,event('neo-005-b')).candidate;
test('old durable state means no commit',()=>{
 assert.deepEqual(classifyUncertainCommit([],INITIAL_ANCHOR,first.anchor),{
   status:'NOT_COMMITTED',reason:'MATCHES_PREVIOUS_ANCHOR',authorized:false});
});
test('proposed durable state is classifiable but never authorized',()=>{
 assert.deepEqual(classifyUncertainCommit(first.records,INITIAL_ANCHOR,first.anchor),{
   status:'COMMITTED',reason:'MATCHES_PROPOSED_ANCHOR',authorized:false});
});
test('unexpected valid chain is held',()=>{
 assert.equal(classifyUncertainCommit(second.records,INITIAL_ANCHOR,first.anchor).status,'HOLD');
});
test('tampered chain is held',()=>{
 const tampered=[{...first.records[0],reason:'TAMPERED'}];
 assert.equal(classifyUncertainCommit(tampered,INITIAL_ANCHOR,first.anchor).reason,'CORRUPT_CHAIN');
});
test('truncated intermediate prefix is held',()=>{
 assert.equal(classifyUncertainCommit([],first.anchor,second.anchor).status,'HOLD');
});
test('candidate must be exactly one append',()=>{
 assert.equal(classifyUncertainCommit(first.records,INITIAL_ANCHOR,{...first.anchor,count:3}).reason,'INVALID_TRANSITION');
});
test('unlinked but internally consistent proposal is held',()=>{
 assert.equal(classifyUncertainCommit(first.records,
   {count:0,head:'1'.repeat(64)},first.anchor).reason,'UNLINKED_PROPOSAL');
});
test('untrusted or invalid anchors fail closed',()=>{
 for(const b of [null,undefined,{count:0,head:42},{count:-1,head:INITIAL_ANCHOR.head}])
   assert.equal(classifyUncertainCommit([],b,first.anchor).status,'HOLD');
});
