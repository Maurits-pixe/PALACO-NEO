import test from 'node:test';
import assert from 'node:assert/strict';
import {INITIAL_ANCHOR,recoverCheckpoint,proposeCheckpoint,reconcileCheckpoint} from '../src/checkpoint.mjs';

const event = id => ({requestId:id,decision:'DENY',reason:'GO13_HOLD'});
test('genesis is recoverable only against trusted genesis anchor',()=>{
 assert.equal(recoverCheckpoint([],INITIAL_ANCHOR).ok,true);
 assert.equal(recoverCheckpoint([],{count:1,head:INITIAL_ANCHOR.head}).ok,false);
});
test('proposal never mutates origin or grants execution',()=>{
 const source=[];const r=proposeCheckpoint(source,INITIAL_ANCHOR,event('neo-003-a'));
 assert.equal(r.ok,true);assert.equal(r.reason,'PROPOSAL_ONLY_NO_AUTHORITY');
 assert.equal(source.length,0);assert.equal(r.candidate.records.length,1);
 assert.equal(Object.isFrozen(r.candidate.records),true);
 assert.equal(recoverCheckpoint(r.candidate.records,r.candidate.anchor).ok,true);
});
test('stale anchor refuses advancing chain',()=>{
 const a=proposeCheckpoint([],INITIAL_ANCHOR,event('neo-003-a'));
 assert.equal(proposeCheckpoint(a.candidate.records,INITIAL_ANCHOR,event('neo-003-b')).reason,'RECOVERY_REFUSED');
});
test('tampering is rejected during recovery',()=>{
 const a=proposeCheckpoint([],INITIAL_ANCHOR,event('neo-003-a'));
 assert.equal(recoverCheckpoint([{...a.candidate.records[0],reason:'TAMPERED'}],a.candidate.anchor).ok,false);
});
test('missing anchor and malformed hashes fail closed without exceptions',()=>{
 assert.equal(recoverCheckpoint([],undefined).reason,'INVALID_TRUSTED_ANCHOR');
 assert.equal(recoverCheckpoint([],{count:0,head:1}).ok,false);
 assert.equal(recoverCheckpoint([], {count:0,head:null}).ok,false);
});
test('commit reconciliation rejects conflicting trusted anchors',()=>{
 const a=proposeCheckpoint([],INITIAL_ANCHOR,event('neo-003-a'));
 assert.equal(reconcileCheckpoint(a.candidate.records,a.candidate.anchor,a.candidate.anchor).ok,true);
 assert.equal(reconcileCheckpoint(a.candidate.records,a.candidate.anchor,INITIAL_ANCHOR).reason,'ANCHOR_CONFLICT');
});
test('replay and malformed event never create checkpoint proposal',()=>{
 assert.equal(proposeCheckpoint([],INITIAL_ANCHOR,{...event('neo-003-a'),decision:'ALLOW'}).ok,false);
 const a=proposeCheckpoint([],INITIAL_ANCHOR,event('neo-003-a'));
 assert.equal(proposeCheckpoint(a.candidate.records,a.candidate.anchor,{...event('neo-003-b'),reason:''}).ok,false);
});
