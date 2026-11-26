import {mkdir,open,rename,rm,rmdir,lstat} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {recoveryChallengeDigest,proposeChallengeConsumption} from './recovery-challenge.mjs';

/**
 * NEO-019: local cooperative single-host replay register.
 * The expected digest must be pinned in separate trusted custody.
 * No issuance, no automatic retry, no hostile-writer safety, no authority.
 */
const FILE='recovery-challenges.json',LOCK='.recovery-challenges.lock';
const hex=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const deny=reason=>Object.freeze({ok:false,reason,authorized:false,digest:null});
async function directoryId(dir) {
 if(typeof dir!=='string'||!dir.length||dir.includes('\0'))return null;
 try {const s=await lstat(dir);return s.isDirectory()&&!s.isSymbolicLink()
   ?{dev:s.dev,ino:s.ino}:null;} catch{return null;}
}
async function sameDirectory(dir,identity){
 const s=await directoryId(dir);
 return !!s&&!!identity&&s.dev===identity.dev&&s.ino===identity.ino;
}
async function readRegister(dir) {
 let h;
 try {
  h=await open(join(dir,FILE),constants.O_RDONLY|constants.O_NOFOLLOW);
  const s=await h.stat();
  if(!s.isFile()||s.nlink!==1||s.size>2_000_000)return null;
  const raw=await h.readFile('utf8');
  if(Buffer.byteLength(raw,'utf8')>2_000_000)return null;
  const value=JSON.parse(raw);
  recoveryChallengeDigest(value);
  return value;
 }catch{return null;}finally{if(h)await h.close().catch(()=>{});}
}
async function syncDir(dir){
 const h=await open(dir,'r');
 try{await h.sync();}finally{await h.close();}
}
export async function inspectChallengeRegister(dir,expectedDigest){
 if(!hex(expectedDigest))return deny('INVALID_TRUST_INPUT');
 const id=await directoryId(dir);
 if(!id)return deny('UNTRUSTED_DIRECTORY');
 const reg=await readRegister(dir);
 if(!reg)return deny('MISSING_OR_CORRUPT_REGISTER');
 if(!await sameDirectory(dir,id))return deny('DIRECTORY_CHANGED');
 const digest=recoveryChallengeDigest(reg);
 return digest===expectedDigest
  ? Object.freeze({ok:true,reason:'MATCHES_EXTERNAL_DIGEST',authorized:false,digest})
  : deny('TRUSTED_REGISTER_MISMATCH');
}
export async function consumeRecoveryChallenge(dir,expectedDigest,envelope,trust){
 if(!hex(expectedDigest))return deny('INVALID_TRUST_INPUT');
 const directory=await directoryId(dir);
 if(!directory)return deny('UNTRUSTED_DIRECTORY');
 const lockPath=join(dir,LOCK);
 let locked=false,identity=null,temp=null,renamed=false;
 try{
  try {
   await mkdir(lockPath,{mode:0o700});locked=true;
   identity=await lstat(lockPath);
   if(!identity.isDirectory()||identity.isSymbolicLink())return deny('LOCK_INTEGRITY_FAILURE');
  }catch(e){return deny(e.code==='EEXIST'?'LOCKED':'LOCK_ERROR');}
  if(!await sameDirectory(dir,directory))return deny('DIRECTORY_CHANGED');
  const reg=await readRegister(dir);
  if(!reg)return deny('MISSING_OR_CORRUPT_REGISTER');
  if(!await sameDirectory(dir,directory))return deny('DIRECTORY_CHANGED');
  const proposal=proposeChallengeConsumption(reg,expectedDigest,envelope,trust);
  if(!proposal.ok)return deny(proposal.reason);
  temp=join(dir,`.recovery-challenges-${randomUUID()}.tmp`);
  const h=await open(temp,'wx',0o600);
  try{await h.writeFile(JSON.stringify(proposal.candidate.registry)+'\n','utf8');await h.sync();}
  finally{await h.close();}
  if(!await sameDirectory(dir,directory))return deny('DIRECTORY_CHANGED');
  await rename(temp,join(dir,FILE));renamed=true;temp=null;
  await syncDir(dir);
  if(!await sameDirectory(dir,directory))return deny('UNCERTAIN_COMMIT_RECONCILE_REQUIRED');
  return Object.freeze({ok:true,reason:'LOCALLY_CONSUMED_NOT_INDEPENDENTLY_TRUSTED',
    authorized:false,digest:proposal.candidate.digest});
 }catch{return deny(renamed?'UNCERTAIN_COMMIT_RECONCILE_REQUIRED':'IO_FAILURE');}
 finally {
  if(temp)await rm(temp,{force:true}).catch(()=>{});
  if(locked&&identity)try{
   const s=await lstat(lockPath);
   if(s.isDirectory()&&!s.isSymbolicLink()&&s.dev===identity.dev&&s.ino===identity.ino)
     await rmdir(lockPath);
  }catch{/* no lock stealing */}
 }
}
