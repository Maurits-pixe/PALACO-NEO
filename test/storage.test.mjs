import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {commitLocalCheckpoint,inspectLocalCheckpoint} from '../src/storage.mjs';
import {INITIAL_ANCHOR} from '../src/checkpoint.mjs';

const event = id => ({requestId:id,decision:'DENY',reason:'GO13_HOLD'});
async function sandbox(fn) {
  const dir=await mkdtemp(join(tmpdir(),'palaco-neo004-'));
  try { await fn(dir); } finally { await rm(dir,{recursive:true,force:true}); }
}
test('durable local commit requires a matching independently supplied starting anchor',async()=>sandbox(async dir=>{
 const saved=await commitLocalCheckpoint(dir,INITIAL_ANCHOR,event('neo-004-a'));
 assert.equal(saved.ok,true);
 assert.equal((await inspectLocalCheckpoint(dir,saved.checkpoint)).ok,true);
 assert.equal((await inspectLocalCheckpoint(dir,INITIAL_ANCHOR)).reason,'TRUSTED_CHECKPOINT_MISMATCH');
}));
test('stale caller checkpoint fails closed without rewriting file',async()=>sandbox(async dir=>{
 const first=await commitLocalCheckpoint(dir,INITIAL_ANCHOR,event('neo-004-a'));
 const before=await readFile(join(dir,'checkpoint.json'),'utf8');
 assert.equal((await commitLocalCheckpoint(dir,INITIAL_ANCHOR,event('neo-004-b'))).ok,false);
 assert.equal(await readFile(join(dir,'checkpoint.json'),'utf8'),before);
 assert.equal((await commitLocalCheckpoint(dir,first.checkpoint,event('neo-004-b'))).ok,true);
}));
test('preexisting lock is never automatically stolen',async()=>sandbox(async dir=>{
 await mkdir(join(dir,'.checkpoint.lock'));
 assert.equal((await commitLocalCheckpoint(dir,INITIAL_ANCHOR,event('neo-004-a'))).reason,'LOCKED');
}));
test('corrupt storage is rejected rather than reset to genesis',async()=>sandbox(async dir=>{
 await writeFile(join(dir,'checkpoint.json'),'{broken','utf8');
 assert.equal((await commitLocalCheckpoint(dir,INITIAL_ANCHOR,event('neo-004-a'))).reason,'CORRUPT_OR_UNREADABLE_STATE');
 assert.equal((await inspectLocalCheckpoint(dir,INITIAL_ANCHOR)).ok,false);
}));
test('unrelated temporary artifact does not substitute for committed state',async()=>sandbox(async dir=>{
 await writeFile(join(dir,'.checkpoint-orphan.tmp'),'interrupted');
 assert.equal((await inspectLocalCheckpoint(dir,INITIAL_ANCHOR)).ok,true);
 assert.equal((await commitLocalCheckpoint(dir,INITIAL_ANCHOR,event('neo-004-a'))).ok,true);
}));
test('invalid event refuses to persist',async()=>sandbox(async dir=>{
 assert.equal((await commitLocalCheckpoint(dir,INITIAL_ANCHOR,{...event('neo-004-a'),decision:'ALLOW'})).ok,false);
 assert.equal((await inspectLocalCheckpoint(dir,INITIAL_ANCHOR)).ok,true);
}));
