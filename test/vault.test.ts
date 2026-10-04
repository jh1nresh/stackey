import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test, type TestContext } from 'node:test';
import { validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { agentContext, runOrders, session, resourceRequest } from '../src/agent-client.js';
import { connect } from '../src/client.js';
import { AppError, digest } from '../src/contracts.js';
import { loadIdentity, writePrivateJson } from '../src/identity.js';
import { startNode } from '../src/node.js';
import { ACTION } from '../src/orders.js';
import { issueInvitation } from '../src/pairing.js';
import { seconds } from '../src/policy.js';
import { Store } from '../src/store.js';
import { backupVault, initializeVault, openVault, recovery, restoreVault, VAULT_REQUESTS_CAP } from '../src/vault.js';
import { vaultRequest } from '../src/vault-client.js';
import { unlockVault } from '../src/vault-session.js';
const cli=resolve('dist/src/cli.js');
function local(...args:string[]){const child=spawnSync(process.execPath,[cli,...args],{encoding:'utf8'});return {code:child.status,stdout:child.stdout,body:JSON.parse(child.stdout) as any};}
async function remote(...args:string[]){const child=spawn(process.execPath,[cli,...args]);let stdout='';child.stdout.on('data',chunk=>stdout+=chunk);const [code]=await once(child,'exit');return {code,stdout,body:JSON.parse(stdout) as any};}
async function fixture(t:TestContext){
  const root=mkdtempSync(join(tmpdir(),'stackey-vault-test-'));const vaultDir=join(root,'vault');const recoveryFile=join(root,'recovery.json');const nodeDir=join(root,'node');
  await initializeVault(vaultDir,recoveryFile);const identity=await loadIdentity(nodeDir,'node',true);const store=new Store(nodeDir);const node=await startNode(nodeDir,0);
  const vault=await unlockVault(vaultDir,recoveryFile,nodeDir);t.after(async()=>{await vault.close();await node.close();store.close();rmSync(root,{recursive:true});});
  const ownerArgs={_node_dir:resolve(nodeDir)};
  await vaultRequest(vaultDir,'node.bind',ownerArgs);await vaultRequest(vaultDir,'demo.init',ownerArgs);
  await vaultRequest(vaultDir,'connection.add',{wallet_id:'wallet_demo',name:'Synthetic Store',provider:'demo',config:{}});
  return {root,vaultDir,recoveryFile,nodeDir,identity,store,node,vault,ownerArgs};
}
test('real CLI initializes a 24-word encrypted vault; secrets and signing material are absent from results and disk ciphertext',async t=>{
  const root=mkdtempSync(join(tmpdir(),'stackey-vault-init-'));t.after(()=>rmSync(root,{recursive:true}));
  const dir=join(root,'vault');const file=join(root,'recovery.json');const result=local('vault','init','--vault-dir',dir,'--recovery-out',file);
  assert.equal(result.code,0);const mnemonic=await recovery(file);assert.equal(mnemonic.split(' ').length,24);assert.ok(validateMnemonic(mnemonic,wordlist));assert.ok(!result.stdout.includes(mnemonic));
  const opened=await openVault(dir,mnemonic);const owner=opened.owner.id;const key=opened.owner.privateJwk.d!;
  opened.data.credentials.push({id:'credential_'+randomUUID(),wallet_id:'wallet_demo',name:'Password',kind:'password',value:'fixture-private-value'});opened.save(opened.data);opened.close();
  const raw=readFileSync(join(dir,'vault.json'),'utf8');assert.ok(!raw.includes(mnemonic));assert.ok(!raw.includes(key));assert.ok(!raw.includes('fixture-private-value'));assert.ok(!raw.includes('Password'));
  const reopened=await openVault(dir,mnemonic);assert.equal(reopened.owner.id,owner);assert.equal(reopened.data.credentials[0]!.value,'fixture-private-value');reopened.close();
  assert.equal(local('vault','status','--vault-dir',dir).body.data.status,'locked');assert.equal(local('vault','init','--vault-dir',dir,'--recovery-out',file).code,2);
});
test('seed plus authenticated backup restores wallets and secrets without importing Node grants or replacing existing vaults',async t=>{
  const f=await fixture(t);await vaultRequest(f.vaultDir,'credential.import',{wallet_id:'wallet_demo',name:'API token',kind:'api_key',value:'fixture-only-token'});
  const backup=join(f.root,'backup.json');backupVault(f.vaultDir,backup);
  const restored=join(f.root,'restored');const result=await restoreVault(restored,backup,await recovery(f.recoveryFile));assert.equal(result.grants_restored,false);
  const original=await openVault(f.vaultDir,await recovery(f.recoveryFile));const recovered=await openVault(restored,await recovery(f.recoveryFile));
  assert.equal(recovered.owner.id,original.owner.id);assert.deepEqual(recovered.data,original.data);original.close();recovered.close();
  await assert.rejects(restoreVault(restored,backup,await recovery(f.recoveryFile)),error=>error instanceof AppError&&error.code==='output_exists');
  assert.equal(existsSync(join(restored,'pairings.sqlite')),false);assert.equal(existsSync(join(restored,'session.json')),false);
});
test('wrong seed, changed header/ciphertext and unsupported format fail closed without writing a restore target',async t=>{
  const f=await fixture(t);const otherRecovery=join(f.root,'other-recovery.json');await initializeVault(join(f.root,'other'),otherRecovery);
  await assert.rejects(openVault(f.vaultDir,await recovery(otherRecovery)));
  const raw=JSON.parse(readFileSync(join(f.vaultDir,'vault.json'),'utf8'));
  for(const change of [{version:2},{owner:raw.owner.slice(0,-1)+'a'},{salt:Buffer.alloc(32).toString('base64url')},{data:{...raw.data,tag:Buffer.alloc(16).toString('base64url')}}]){
    const backup=join(f.root,randomUUID()+'.json');writePrivateJson(backup,{...raw,...change});const target=join(f.root,randomUUID());
    await assert.rejects(restoreVault(target,backup,await recovery(f.recoveryFile)));assert.equal(existsSync(join(target,'vault.json')),false);
  }
  chmodSync(f.recoveryFile,0o644);await assert.rejects(recovery(f.recoveryFile));chmodSync(f.recoveryFile,0o600);
});
test('unlocked owner commands expose only metadata, persist multiple wallets, and never provide an export or arbitrary signing endpoint',async t=>{
  const f=await fixture(t);const created=await remote('wallet','create','--name','Research','--vault-dir',f.vaultDir);assert.equal(created.code,0);const id=created.body.data.id;
  const secret=join(f.root,'secret.json');writePrivateJson(secret,{value:'fixture-secret-key'});
  const imported=await remote('credential','import','--wallet',id,'--name','Research API','--kind','api_key','--secret-file',secret,'--vault-dir',f.vaultDir);assert.equal(imported.code,0);
  const listed=await remote('credential','list','--wallet',id,'--vault-dir',f.vaultDir);assert.equal(listed.body.data.credentials.length,1);assert.ok(!listed.stdout.includes('fixture-secret-key'));assert.ok(!imported.stdout.includes('fixture-secret-key'));
  assert.equal((await vaultRequest(f.vaultDir,'credential.list',{wallet_id:'wallet_demo'})).credentials.length,0);
  await assert.rejects(vaultRequest(f.vaultDir,'credential.export',{credential_id:imported.body.data.id}));await assert.rejects(vaultRequest(f.vaultDir,'sign',{payload:'arbitrary'}));
  assert.equal((await remote('credential','remove',imported.body.data.id,'--vault-dir',f.vaultDir)).code,0);
  assert.equal((await vaultRequest(f.vaultDir,'wallet.list')).wallets.length,2);
  const reopened=await openVault(f.vaultDir,await recovery(f.recoveryFile));assert.equal(reopened.data.wallets.length,2);reopened.close();
});
test('seed-backed owner binds a selected wallet grant; locking refuses existing and new agent sessions',async t=>{
  const f=await fixture(t);const other=await vaultRequest(f.vaultDir,'wallet.create',{name:'Second Wallet'});
  await vaultRequest(f.vaultDir,'connection.add',{wallet_id:other.id,name:'Store',provider:'demo',config:{}});
  const dir=join(f.root,'agent');await connect(await issueInvitation(f.store,f.identity,300),dir,'Test Agent');const context=await agentContext(dir);
  const approved=await remote('node','approve',context.pairingId,'--principal',context.identity.id,'--action',ACTION,'--wallet',other.id,'--vault-dir',f.vaultDir,'--data-dir',f.nodeDir);
  assert.equal(approved.code,0);assert.equal(approved.body.data.wallet_id,other.id);const token=await session(context);
  assert.equal(((await resourceRequest(context,token,'GET','/v1/capabilities')).data as any).wallet_id,other.id);
  assert.equal((await runOrders(dir,ACTION,{from:'2026-09-26',to:'2026-10-02'})).status,'ok');
  await f.vault.close();await assert.rejects(session(context),error=>error instanceof AppError&&error.code==='node_locked');
  await assert.rejects(resourceRequest(context,token,'GET','/v1/capabilities'),error=>error instanceof AppError&&error.code==='node_locked');
  assert.equal(f.store.db.prepare("SELECT value FROM settings WHERE key='vault_unlocked'").get()!.value,'0');
});
test('owner binding refuses replacing legacy identity or approving against a different Node directory',async t=>{
  const f=await fixture(t);await assert.rejects(vaultRequest(f.vaultDir,'node.bind',{_node_dir:join(f.root,'another')}),error=>error instanceof AppError&&error.code==='node_mismatch');
  const legacy=await loadIdentity(join(f.root,'legacy-owner'),'owner',true);
  f.store.db.prepare("UPDATE settings SET value=? WHERE key='owner_public_jwk'").run(JSON.stringify(legacy.publicJwk));
  await assert.rejects(vaultRequest(f.vaultDir,'node.bind',f.ownerArgs),error=>error instanceof AppError&&error.code==='owner_mismatch');
});
test('duplicate unlock and expired unlock sessions cannot create another writer or use owner commands',async t=>{
  const f=await fixture(t);await assert.rejects(unlockVault(f.vaultDir,f.recoveryFile,f.nodeDir),error=>error instanceof AppError&&error.code==='session_exists');
  await f.vault.close();let now=Math.floor(Date.now()/1000);const vault=await unlockVault(f.vaultDir,f.recoveryFile,f.nodeDir,60,()=>now);t.after(()=>vault.close());
  now+=60;await assert.rejects(vaultRequest(f.vaultDir,'wallet.create',{name:'Expired'}),error=>error instanceof AppError&&error.code==='node_locked');
});
test('nonprivate import files and invalid parameters are rejected; CLI errors never echo a supplied secret',async t=>{
  const f=await fixture(t);const file=join(f.root,'exposed.json');writeFileSync(file,JSON.stringify({value:'should-not-print'}),{mode:0o644});
  const result=await remote('credential','import','--wallet','wallet_demo','--name','Test','--kind','api_key','--secret-file',file,'--vault-dir',f.vaultDir);
  assert.equal(result.code,2);assert.ok(!result.stdout.includes('should-not-print'));
  await assert.rejects(vaultRequest(f.vaultDir,'credential.import',{wallet_id:'wallet_demo',name:'Test',kind:'anything',value:'should-not-print'}));
  assert.equal((await vaultRequest(f.vaultDir,'credential.list',{wallet_id:'wallet_demo'})).credentials.length,0);
});
test('wallet lists paginate without truncation and refuse foreign cursors',async t=>{
  const f=await fixture(t);
  for(let index=0;index<104;index++)await vaultRequest(f.vaultDir,'wallet.create',{name:'Wallet '+index});
  const first=await vaultRequest(f.vaultDir,'wallet.list');assert.equal(first.wallets.length,100);assert.equal(first.complete,false);
  const second=await vaultRequest(f.vaultDir,'wallet.list',{after:first.next_cursor});assert.equal(second.wallets.length,5);assert.equal(second.complete,true);assert.equal(second.next_cursor,null);
  assert.equal(new Set([...first.wallets,...second.wallets].map(w=>w.id)).size,105);
  await assert.rejects(vaultRequest(f.vaultDir,'credential.list',{wallet_id:'wallet_demo',after:first.next_cursor}),error=>error instanceof AppError&&error.code==='invalid_cursor');
});
test('foreground CLI unlock accepts owner CLI commands and lock exits with session files removed',async t=>{
  const root=mkdtempSync(join(tmpdir(),'stackey-unlock-cli-'));t.after(()=>rmSync(root,{recursive:true}));const dir=join(root,'vault');const file=join(root,'recovery.json');
  await initializeVault(dir,file);await loadIdentity(join(root,'node'),'node',true);
  const child=spawn(process.execPath,[cli,'vault','unlock','--vault-dir',dir,'--recovery-file',file,'--data-dir',join(root,'node')]);
  t.after(()=>{if(child.exitCode===null)child.kill('SIGTERM');});
  let output='';await new Promise<void>((resolve,reject)=>{child.stdout.on('data',chunk=>{output+=chunk;if(output.includes('\n'))resolve();});child.once('error',reject);child.once('exit',code=>{if(!output)reject(new Error('Unlock exited '+code));});});
  assert.equal(JSON.parse(output.trim()).data.status,'unlocked');assert.ok(!output.includes(await recovery(file)));
  const exit=once(child,'exit');const locked=await remote('vault','lock','--vault-dir',dir);assert.equal(locked.code,0);assert.equal(locked.body.data.status,'locked');assert.equal((await exit)[0],0);assert.equal(existsSync(join(dir,'session.json')),false);
});
test('binding a restored backup to the previous Node invalidates old grants instead of resurrecting authority',async t=>{
  const f=await fixture(t);const dir=join(f.root,'agent');await connect(await issueInvitation(f.store,f.identity,300),dir,'Agent');const context=await agentContext(dir);
  const grant=await vaultRequest(f.vaultDir,'grant.approve',{...f.ownerArgs,pairing_id:context.pairingId,principal:context.identity.id,action:ACTION,ttl:900,wallet_id:'wallet_demo'});
  const token=await session(context);const backup=join(f.root,'backup.json');backupVault(f.vaultDir,backup);const restoredDir=join(f.root,'restored');
  const restored=await restoreVault(restoredDir,backup,await recovery(f.recoveryFile));assert.notEqual(restored.vault_id,restored.source_vault_id);
  const sessionOwner=await unlockVault(restoredDir,f.recoveryFile,f.nodeDir);t.after(()=>sessionOwner.close());
  const bound=await vaultRequest(restoredDir,'node.bind',f.ownerArgs);assert.equal(bound.invalidated_grants,1);
  assert.ok(f.store.db.prepare('SELECT revoked_at FROM grants WHERE grant_id=?').get(grant.grant_id)!.revoked_at);
  await assert.rejects(resourceRequest(context,token,'GET','/v1/capabilities'),error=>error instanceof AppError&&error.code==='grant_revoked');
});
test('after a second vault binds, the older unlocked session cannot approve grants against the Node',async t=>{
  const f=await fixture(t);const dir=join(f.root,'agent');await connect(await issueInvitation(f.store,f.identity,300),dir,'Agent');const context=await agentContext(dir);
  const backup=join(f.root,'backup.json');backupVault(f.vaultDir,backup);const restoredDir=join(f.root,'restored');
  await restoreVault(restoredDir,backup,await recovery(f.recoveryFile));
  const newer=await unlockVault(restoredDir,f.recoveryFile,f.nodeDir);t.after(()=>newer.close());
  await vaultRequest(restoredDir,'node.bind',f.ownerArgs);
  await assert.rejects(vaultRequest(f.vaultDir,'grant.approve',{...f.ownerArgs,pairing_id:context.pairingId,principal:context.identity.id,action:ACTION,ttl:900,wallet_id:'wallet_demo'}),error=>error instanceof AppError&&error.code==='node_locked');
  const grant=await vaultRequest(restoredDir,'grant.approve',{...f.ownerArgs,pairing_id:context.pairingId,principal:context.identity.id,action:ACTION,ttl:900,wallet_id:'wallet_demo'});
  assert.ok(grant.grant_id);assert.equal(f.store.db.prepare('SELECT value FROM settings WHERE key=\'bound_vault_id\'').get()!.value,newer.vaultId);
});
test('re-unlocking a bound vault restores Node access without repeating owner-init',async t=>{
  const f=await fixture(t);const dir=join(f.root,'agent');await connect(await issueInvitation(f.store,f.identity,300),dir,'Agent');const context=await agentContext(dir);
  await vaultRequest(f.vaultDir,'grant.approve',{...f.ownerArgs,pairing_id:context.pairingId,principal:context.identity.id,action:ACTION,ttl:900,wallet_id:'wallet_demo'});
  assert.equal((await runOrders(dir,ACTION,{from:'2026-09-26',to:'2026-10-02'})).status,'ok');
  await f.vault.close();
  await assert.rejects(session(context),error=>error instanceof AppError&&error.code==='node_locked');
  const again=await unlockVault(f.vaultDir,f.recoveryFile,f.nodeDir);t.after(()=>again.close());
  assert.equal(f.store.db.prepare("SELECT value FROM settings WHERE key='vault_unlocked'").get()!.value,'1');
  assert.equal((await runOrders(dir,ACTION,{from:'2026-09-26',to:'2026-10-02'})).status,'ok');
});
test('timed-out owner mutations return result_unknown and the same request_id does not create a duplicate',async t=>{
  const f=await fixture(t);await f.vault.close();
  let release!:()=>void;const hold=new Promise<void>(resolve=>{release=resolve;});let waiting=0;
  const vault=await unlockVault(f.vaultDir,f.recoveryFile,f.nodeDir,900,seconds,async()=>{waiting++;if(waiting===1)await hold;});
  t.after(()=>vault.close());
  const id=randomUUID();
  const pending=vaultRequest(f.vaultDir,'wallet.create',{name:'Research',request_id:id},30);
  await new Promise<void>(resolve=>{const timer=setInterval(()=>{if(waiting>0){clearInterval(timer);resolve();}},5);});
  await assert.rejects(pending,error=>error instanceof AppError&&error.code==='result_unknown'&&error.status==='result_unknown'&&error.exitCode===4);
  release();
  const replay=await vaultRequest(f.vaultDir,'wallet.create',{name:'Research',request_id:id});
  assert.equal(replay.name,'Research');
  const listed=await vaultRequest(f.vaultDir,'wallet.list');
  assert.equal(listed.wallets.filter((wallet:{name:string})=>wallet.name==='Research').length,1);
  await assert.rejects(vaultRequest(f.vaultDir,'wallet.create',{name:'Other',request_id:id}),error=>error instanceof AppError&&error.code==='operation_conflict');
});
test('request_id replay for wallet, credential and connection survives lock and re-unlock',async t=>{
  const f=await fixture(t);
  const walletId=randomUUID();const credentialId=randomUUID();const connectionId=randomUUID();
  const wallet=await vaultRequest(f.vaultDir,'wallet.create',{name:'Research',request_id:walletId});
  const credential=await vaultRequest(f.vaultDir,'credential.import',{wallet_id:wallet.id,name:'API',kind:'api_key',value:'fixture-token',request_id:credentialId});
  const connection=await vaultRequest(f.vaultDir,'connection.add',{wallet_id:wallet.id,name:'Store',provider:'demo',config:{},request_id:connectionId});
  await f.vault.close();
  const again=await unlockVault(f.vaultDir,f.recoveryFile,f.nodeDir);t.after(()=>again.close());
  assert.equal((await vaultRequest(f.vaultDir,'wallet.create',{name:'Research',request_id:walletId})).id,wallet.id);
  assert.equal((await vaultRequest(f.vaultDir,'credential.import',{wallet_id:wallet.id,name:'API',kind:'api_key',value:'fixture-token',request_id:credentialId})).id,credential.id);
  assert.equal((await vaultRequest(f.vaultDir,'connection.add',{wallet_id:wallet.id,name:'Store',provider:'demo',config:{},request_id:connectionId})).id,connection.id);
  assert.equal((await vaultRequest(f.vaultDir,'wallet.list')).wallets.filter((row:{name:string})=>row.name==='Research').length,1);
  assert.equal((await vaultRequest(f.vaultDir,'credential.list',{wallet_id:wallet.id})).credentials.length,1);
  assert.equal((await vaultRequest(f.vaultDir,'connection.list',{wallet_id:wallet.id})).connections.length,1);
  await assert.rejects(vaultRequest(f.vaultDir,'wallet.create',{name:'Other',request_id:walletId}),error=>error instanceof AppError&&error.code==='operation_conflict');
  await assert.rejects(vaultRequest(f.vaultDir,'credential.import',{wallet_id:wallet.id,name:'Other',kind:'api_key',value:'fixture-token',request_id:credentialId}),error=>error instanceof AppError&&error.code==='operation_conflict');
  await assert.rejects(vaultRequest(f.vaultDir,'connection.add',{wallet_id:wallet.id,name:'Other',provider:'demo',config:{},request_id:connectionId}),error=>error instanceof AppError&&error.code==='operation_conflict');
});
test('request replay evicts the oldest record once the vault cap is full',async t=>{
  const f=await fixture(t);
  const oldest=randomUUID();
  const first=await vaultRequest(f.vaultDir,'wallet.create',{name:'Oldest',request_id:oldest});
  await f.vault.close();
  const opened=await openVault(f.vaultDir,await recovery(f.recoveryFile));
  assert.equal(opened.data.requests[0]!.request_id,oldest);
  while(opened.data.requests.length<VAULT_REQUESTS_CAP){
    opened.data.requests.push({request_id:randomUUID(),fingerprint:digest(`pad-${opened.data.requests.length}`),result:{id:'wallet_'+randomUUID()}});
  }
  opened.save(opened.data);opened.close();
  const again=await unlockVault(f.vaultDir,f.recoveryFile,f.nodeDir);t.after(()=>again.close());
  const newer=randomUUID();
  const created=await vaultRequest(f.vaultDir,'wallet.create',{name:'AfterCap',request_id:newer});
  assert.equal(created.name,'AfterCap');assert.notEqual(created.id,first.id);
  assert.equal((await vaultRequest(f.vaultDir,'wallet.list')).wallets.filter((row:{name:string})=>row.name==='AfterCap').length,1);
  const persisted=await openVault(f.vaultDir,await recovery(f.recoveryFile));
  assert.equal(persisted.data.requests.length,VAULT_REQUESTS_CAP);
  assert.equal(persisted.data.requests.some(row=>row.request_id===oldest),false);
  assert.equal(persisted.data.requests.some(row=>row.request_id===newer),true);
  persisted.close();
});
test('an unavailable vault session is still node_locked, not result_unknown',async t=>{
  const f=await fixture(t);await f.vault.close();
  await assert.rejects(vaultRequest(f.vaultDir,'wallet.create',{name:'Research'}),error=>error instanceof AppError&&error.code==='node_locked');
});
