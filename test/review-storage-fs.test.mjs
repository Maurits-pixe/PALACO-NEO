import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,writeFile,symlink,link,mkdir,readFile,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {inspectReviewStore,commitReviewProposal,INITIAL_REVIEW_STORE_POSITION as genesis} from '../src/review-storage.mjs';

async function sandbox(fn) {
 const dir=await mkdtemp(join(tmpdir(),'palaco-neo014-'));
 try {await fn(dir);} finally {await rm(dir,{recursive:true,force:true});}
}
test('symlink state file rejected even when target contains valid genesis',()=>sandbox(async dir=>{
 const target=join(dir,'target.json');
 await writeFile(target,JSON.stringify({schema:'NEO-012-v1',entries:[]}));
 await symlink(target,join(dir,'review-ledger.json'));
 assert.equal((await inspectReviewStore(dir,genesis)).reason,'CORRUPT_STORE');
 assert.equal((await commitReviewProposal(dir,genesis,null)).reason,'CORRUPT_STORE');
}));
test('hardlinked state file rejected',()=>sandbox(async dir=>{
 const target=join(dir,'target.json');
 await writeFile(target,JSON.stringify({schema:'NEO-012-v1',entries:[]}));
 await link(target,join(dir,'review-ledger.json'));
 assert.equal((await inspectReviewStore(dir,genesis)).reason,'CORRUPT_STORE');
}));
test('directory symlink rejected',()=>sandbox(async dir=>{
 const alias=join(dir,'alias');
 await symlink(dir,alias,'dir');
 assert.equal((await inspectReviewStore(alias,genesis)).ok,false);
}));
test('non-empty lock cannot be removed by failed operation',()=>sandbox(async dir=>{
 const lock=join(dir,'.review-ledger.lock');
 await mkdir(lock);
 await writeFile(join(lock,'keep.txt'),'preserve');
 assert.equal((await commitReviewProposal(dir,genesis,null)).reason,'LOCKED');
 assert.equal(await readFile(join(lock,'keep.txt'),'utf8'),'preserve');
}));
test('invalid stored JSON is fail-closed',()=>sandbox(async dir=>{
 await writeFile(join(dir,'review-ledger.json'),'{bad');
 assert.equal((await inspectReviewStore(dir,genesis)).reason,'CORRUPT_STORE');
}));
test('oversized state refuses reads',()=>sandbox(async dir=>{
 await writeFile(join(dir,'review-ledger.json'),'a'.repeat(4_000_001));
 assert.equal((await inspectReviewStore(dir,genesis)).reason,'CORRUPT_STORE');
}));
test('invalid evidence does not leave lock behind',()=>sandbox(async dir=>{
 const response=await commitReviewProposal(dir,genesis,{});
 assert.equal(response.ok,false);
 assert.equal((await readdir(dir)).includes('.review-ledger.lock'),false);
}));
