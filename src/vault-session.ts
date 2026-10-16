import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { chmodSync, existsSync, mkdtempSync, rmdirSync, unlinkSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { AppError, digest, displayName, publicError, record, textField, vaultReply } from './contracts.js';
import { loadIdentity, readPrivateJson, writePrivateJson } from './identity.js';
import { initializeDemo } from './orders.js';
import { approvePairing, initializeOwner, requireGrant, revokeGrant, seconds, verifyGrant } from './policy.js';
import { Store } from './store.js';
import { readBackupState, updateBackupState, withBackupStatus } from './backup-state.js';
import { keychainFor, loadVaultKey, storeVaultKey } from './keychain.js';
import { openVault, peekVaultId, recovery, VAULT_REQUESTS_CAP, type Connection, type Credential, type VaultRequest } from './vault.js';
import { connectionConfig, executeProvider, integer, providerParams, supports } from './providers.js';
import { payMpp, type PaymentContinuation } from './mpp-payment.js';
import { sessionPath } from './vault-client.js';
import {
  addCredentialOrigin, createWebsiteSession, originAllowed, revokeWebsiteSessions, websiteSessionTtl, writeAudit,
  type AuditResult,
} from './website-sessions.js';
import { CREDENTIAL_GET_ACTION, credentialGetOrigin, credentialHandoff } from './credential-get.js';
import { executeWebsiteLogin, refuseWebsiteLogin, WEBSITE_LOGIN_ACTION, websiteOrigin, type WebsiteLoginExecutor } from './website-login.js';

export interface RunningVault { server:Server;vaultId:string;owner:string;expiresAt:number;close():Promise<void> }
export function requireBoundVault(store:Store,token:string,vaultId:string):void {
  const session=store.db.prepare("SELECT value FROM settings WHERE key='vault_session'").get();
  const boundId=store.db.prepare("SELECT value FROM settings WHERE key='bound_vault_id'").get();
  const current=typeof session?.value==='string'?session.value:'';
  if(current.length!==token.length||boundId?.value!==vaultId||!timingSafeEqual(Buffer.from(current),Buffer.from(token))) {
    throw new AppError('node_locked','This vault session is no longer bound to the Node.',403,3,'node_locked');
  }
}
async function rememberKey(dir:string,vaultId:string,mnemonic:string):Promise<void> {
  if(await storeVaultKey(dir,vaultId,mnemonic)) {
    try { updateBackupState(dir,{keychain_unlock:true}); } catch { /* nudge sidecar is best-effort */ }
  }
}
export async function resolveUnlockMnemonic(dir:string,recoveryFile?:string):Promise<string> {
  if(recoveryFile) {
    const mnemonic=await recovery(recoveryFile);
    await rememberKey(dir,peekVaultId(dir),mnemonic);
    return mnemonic;
  }
  const vaultId=peekVaultId(dir);
  try { return await loadVaultKey(dir,vaultId,keychainFor(dir)); }
  catch (error) {
    const state=readBackupState(dir);
    if(state?.plaintext_recovery && state.recovery_file && existsSync(state.recovery_file)) {
      const mnemonic=await recovery(state.recovery_file);
      await rememberKey(dir,vaultId,mnemonic);
      return mnemonic;
    }
    throw error;
  }
}
export async function unlockVault(dir:string,recoveryFile:string|undefined,nodeDir:string,ttl=900,clock=seconds,beforeExecute?:()=>Promise<void>,websiteLogin:WebsiteLoginExecutor=refuseWebsiteLogin):Promise<RunningVault> {
  if(!Number.isInteger(ttl)||ttl<60||ttl>3600)throw new AppError('invalid_ttl','Vault unlock lifetime must be 60–3600 seconds.');
  const vault=await openVault(dir,await resolveUnlockMnemonic(dir,recoveryFile));
  const pointer=sessionPath(dir);
  if(existsSync(pointer)){vault.close();throw new AppError('session_exists','A vault session or stale session file exists. Lock the active session or use vault recover-session.');}
  const socketDir=mkdtempSync(join(tmpdir(),'stackey-vault-'));chmodSync(socketDir,0o700);
  const socket=join(socketDir,'owner.sock');const token=randomBytes(32).toString('base64url');const expiresAt=clock()+ttl;
  let bound=false;let closing:Promise<void>|undefined;let queue=Promise.resolve();
  const configuredNodeDir=resolve(nodeDir);
  const requestFingerprint=(command:string,args:Record<string,unknown>)=>{
    const rest={...args};delete rest.request_id;
    return digest(JSON.stringify({command,args:Object.fromEntries(Object.entries(rest).sort(([a],[b])=>a.localeCompare(b)))}));
  };
  const requestId=(args:Record<string,unknown>)=>{
    if(args.request_id===undefined)return;
    const id=textField(args.request_id,36);
    if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id))throw new AppError('invalid_request_id','Use a UUID request_id.');
    return id;
  };
  const replayed=(command:string,args:Record<string,unknown>)=>{
    const id=requestId(args);if(!id)return;
    const prior=vault.data.requests.find(row=>row.request_id===id);if(!prior)return;
    if(prior.fingerprint!==requestFingerprint(command,args))throw new AppError('operation_conflict','request_id belongs to different parameters.');
    return prior.result;
  };
  const remember=(command:string,args:Record<string,unknown>,result:Record<string,unknown>)=>{
    const id=requestId(args);if(!id)return [];
    vault.data.requests.push({request_id:id,fingerprint:requestFingerprint(command,args),result});
    return vault.data.requests.splice(0,Math.max(0,vault.data.requests.length-VAULT_REQUESTS_CAP));
  };
  const forget=(args:Record<string,unknown>,evicted:VaultRequest[]=[])=>{
    const id=requestId(args);if(id){const index=vault.data.requests.findIndex(row=>row.request_id===id);if(index>=0)vault.data.requests.splice(index,1);}
    if(evicted.length)vault.data.requests.unshift(...evicted);
  };
  const guard=(store:Store)=>requireBoundVault(store,token,vault.vaultId);
  const setPolicy=(unlocked:boolean)=> {
    if(!bound)return;
    const store=new Store(configuredNodeDir);
    try {store.transaction(()=> {
      const row=store.db.prepare("SELECT value FROM settings WHERE key='vault_session'").get();
      if(row?.value!==token)return;
      for(const [key,value] of [['vault_unlocked',unlocked?'1':'0'],['vault_unlock_until',String(expiresAt)]] as const)store.db.prepare('INSERT INTO settings VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key,value);
    });} finally{store.close();}
  };
  const wallet=(id:unknown)=>{const found=vault.data.wallets.find(w=>w.id===id);if(!found)throw new AppError('wallet_not_found','Select an existing wallet.');return found;};
  const save=()=>vault.save(vault.data);
  async function execute(command:string,args:Record<string,unknown>) {
    if(beforeExecute)await beforeExecute();
    if(closing || clock()>=expiresAt)throw new AppError('node_locked','Vault unlock expired.',403,3,'node_locked');
    if (['node.bind','grant.approve','grant.revoke','demo.init','provider.execute','credential.revoke','credential.origin.add'].includes(command)) {
      if(args._node_dir!==configuredNodeDir) throw new AppError('node_mismatch','CLI Node directory differs from the unlocked vault session.');
      args={...args};delete args._node_dir;
    }
    const exact=(keys:string[], optional:string[]=[])=>{if(keys.some(key=>!(key in args)) || Object.keys(args).some(key=>!keys.includes(key)&&!optional.includes(key)))throw new AppError('invalid_parameters','Unexpected vault parameters.');};
    if(command==='status'){exact([]);return withBackupStatus(dir,{status:'unlocked',vault_id:vault.vaultId,owner:vault.owner.id,expires_at:expiresAt});}
    if(command==='lock'){exact([]);setPolicy(false);setImmediate(()=>{void close();});return {status:'locked'};}
    const page=<T extends {id:string}>(rows:T[])=> {
      const after=args.after;let offset=0;
      if(after!==undefined){const index=rows.findIndex(row=>row.id===textField(after,64));if(index<0)throw new AppError('invalid_cursor','Cursor does not belong to this list.');offset=index+1;}
      const values=rows.slice(offset,offset+100);const complete=offset+values.length>=rows.length;
      return {values,next_cursor:complete?null:values.at(-1)!.id,complete};
    };
    if(command==='wallet.list'){exact([],['after']);const result=page(vault.data.wallets);return {wallets:result.values.map(w=>({...w,address:`stackey:${vault.owner.id}/${w.id}`})),next_cursor:result.next_cursor,complete:result.complete};}
    if(command==='wallet.create'){
      exact(['name'],['request_id']);const replay=replayed(command,args);if(replay)return replay;
      const value={id:'wallet_'+randomUUID(),name:displayName(args.name),connections:[]};
      const result={...value,address:`stackey:${vault.owner.id}/${value.id}`};
      vault.data.wallets.push(value);const evicted=remember(command,args,result);
      try{save();}catch(error){vault.data.wallets.pop();forget(args,evicted);throw error;}
      return result;
    }
    if(command==='credential.list'){exact(['wallet_id'],['after']);const w=wallet(args.wallet_id);const result=page(vault.data.credentials.filter(c=>c.wallet_id===w.id));return {credentials:result.values.map(({value,...metadata})=>metadata),next_cursor:result.next_cursor,complete:result.complete};}
    if(command==='credential.import') {
      exact(['wallet_id','name','kind','value'],['request_id']);const replay=replayed(command,args);if(replay)return replay;
      const w=wallet(args.wallet_id);
      if(!['password','api_key','private_key','website_login'].includes(String(args.kind)))throw new AppError('invalid_kind','Use password, api_key, private_key or website_login.');
      const value:Credential={id:'credential_'+randomUUID(),wallet_id:w.id,name:displayName(args.name),kind:args.kind as Credential['kind'],value:textField(args.value,16384)};
      const metadata={id:value.id,wallet_id:value.wallet_id,name:value.name,kind:value.kind};
      vault.data.credentials.push(value);const evicted=remember(command,args,metadata);
      try{save();}catch(error){vault.data.credentials.pop();forget(args,evicted);throw error;}
      return metadata;
    }
    if(command==='credential.remove'){
      exact(['credential_id']);const id=textField(args.credential_id,64);const index=vault.data.credentials.findIndex(c=>c.id===id);
      if(index<0)throw new AppError('credential_not_found','Credential was not found.');
      if(vault.data.credentials[index]!.kind==='website_login')throw new AppError('invalid_kind','Use credential revoke for website login credentials.');
      const old=vault.data.credentials.splice(index,1)[0]!;try{save();}catch(error){vault.data.credentials.splice(index,0,old);throw error;}return {credential_id:id,removed:true};
    }
    if(command==='credential.origin.add') {
      exact(['credential_id','origin']);
      const id=textField(args.credential_id,64);
      const credential=vault.data.credentials.find(c=>c.id===id);
      if(!credential)throw new AppError('credential_not_found','Select a credential.');
      const origin=websiteOrigin(args.origin);
      const store=new Store(configuredNodeDir);
      try { addCredentialOrigin(store,id,origin); return { credential_id:id, origin, allowlisted:true }; }
      finally { store.close(); }
    }
    if(command==='credential.revoke') {
      exact(['credential_id']);
      if(!bound)throw new AppError('owner_not_initialized','Bind this vault first.');
      const id=textField(args.credential_id,64);
      const index=vault.data.credentials.findIndex(c=>c.id===id);
      if(index<0)throw new AppError('credential_not_found','Credential was not found.');
      if(vault.data.credentials[index]!.kind!=='website_login')throw new AppError('invalid_kind','Only website login credentials can be revoked this way.');
      const node=await loadIdentity(configuredNodeDir,'node');
      const store=new Store(configuredNodeDir);
      try {
        const now=clock();
        const removed=vault.data.credentials.splice(index,1)[0]!;
        const jars=vault.data.session_jars.filter(j=>j.credential_id===id);
        vault.data.session_jars=vault.data.session_jars.filter(j=>j.credential_id!==id);
        const connections=vault.data.connections.filter(c=>c.config.credential_id===id).map(c=>c.id);
        try { save(); }
        catch(error){ vault.data.credentials.splice(index,0,removed); vault.data.session_jars.push(...jars); throw error; }
        removed.value='';
        for(const jar of jars)jar.value='';
        const revokedSessions=revokeWebsiteSessions(store,id,now);
        writeAudit(store,{credential_id:id,agent_id:vault.owner.id,origin:'-',started_at:now,result:'revoked'});
        let invalidated=0;
        if(connections.length){
          const grants=store.db.prepare(`SELECT grant_id FROM grants WHERE revoked_at IS NULL AND connection_id IN (${connections.map(()=>'?').join(',')})`).all(...connections);
          for(const row of grants){ await revokeGrant(store,node,vault.owner,String(row.grant_id),clock,guard); invalidated++; }
        }
        return { credential_id:id, revoked:true, ciphertext_deleted:true, revoked_sessions:revokedSessions, invalidated_grants:invalidated };
      } finally { store.close(); }
    }
    if(command==='connection.list'){exact(['wallet_id'],['after']);const w=wallet(args.wallet_id);const result=page(vault.data.connections.filter(c=>c.wallet_id===w.id));return {connections:result.values.map(({config,...metadata})=>metadata),next_cursor:result.next_cursor,complete:result.complete};}
    if(command==='connection.add') {
      exact(['wallet_id','name','provider','config'],['request_id']);const replay=replayed(command,args);if(replay)return replay;
      const w=wallet(args.wallet_id);
      if(!['demo','supabase','vercel','stripe','website','credential'].includes(String(args.provider)))throw new AppError('invalid_provider','Use a supported provider.');
      const value:Connection={id:'connection_'+randomUUID(),wallet_id:w.id,name:displayName(args.name),provider:args.provider as Connection['provider'],config:connectionConfig(args.provider as Connection['provider'],args.config,vault.data,w.id)};
      const metadata={id:value.id,wallet_id:value.wallet_id,name:value.name,provider:value.provider};
      vault.data.connections.push(value);w.connections.push(value.id);const evicted=remember(command,args,metadata);
      try{
        if(value.provider==='website'||value.provider==='credential'){
          const origins=new Store(configuredNodeDir);
          try { addCredentialOrigin(origins,String(value.config.credential_id),websiteOrigin(value.config.origin)); }
          finally { origins.close(); }
        }
        save();
      }catch(error){vault.data.connections.pop();w.connections.pop();forget(args,evicted);throw error;}
      return metadata;
    }
    if(command==='provider.execute') {
      exact(['grant_id','principal','action','params','operation_id'],['previous']);
      if(!bound)throw new AppError('owner_not_initialized','Bind this vault first.');
      const store=new Store(configuredNodeDir);
      try {
        const node=await loadIdentity(configuredNodeDir,'node');
        const grant=requireGrant(store,textField(args.grant_id,36),textField(args.principal,64),clock());
        await verifyGrant(store,node,grant,clock());
        const check=()=>{
          store.transaction(()=> {
            if(closing||clock()>=expiresAt)throw new AppError('node_locked','Vault is locked.',403,3,'node_locked');
            requireBoundVault(store,token,vault.vaultId);
            const current=requireGrant(store,grant.grant_id,grant.principal,clock());
            const accepted=store.db.prepare('SELECT * FROM provider_operations WHERE operation_id=?').get(textField(args.operation_id,36));
            if(current.version!==grant.version||current.signed_grant!==grant.signed_grant||current.action!==args.action||!accepted||accepted.grant_id!==grant.grant_id||accepted.state!=='executing')throw new AppError('permission_denied','Operation no longer matches its grant.',403,3,'permission_denied');
          });
        };
        check();
        const connection=vault.data.connections.find(c=>c.id===grant.connection_id&&c.wallet_id===grant.wallet_id&&supports(c,grant.action));
        if(!connection)throw new AppError('connection_unavailable','Granted connection is unavailable.');
        const credential=vault.data.credentials.find(c=>c.id===connection.config.credential_id&&c.wallet_id===grant.wallet_id);
        if((grant.action===WEBSITE_LOGIN_ACTION||grant.action===CREDENTIAL_GET_ACTION) && (!credential||!credential.value))
          throw new AppError(grant.action===WEBSITE_LOGIN_ACTION?'credential_revoked':'credential_not_found',
            grant.action===WEBSITE_LOGIN_ACTION?'This website login credential has been revoked.':'Select a credential in this wallet.',403,3,'permission_denied');
        connectionConfig(connection.provider,connection.config,vault.data,grant.wallet_id);
        if(!credential||!credential.value)throw new AppError('credential_not_found','Select a credential in this wallet.');
        const params=providerParams(grant.action,args.params);
        const secret=credential.value;
        try {
          if(grant.action===CREDENTIAL_GET_ACTION) {
            const origin=credentialGetOrigin(connection);
            const credentialId=String(connection.config.credential_id);
            const started=clock();
            const audit=(result:AuditResult)=>{ writeAudit(store,{credential_id:credentialId,agent_id:grant.principal,origin,started_at:started,result}); };
            try {
              if(!originAllowed(store,credentialId,origin))throw new AppError('origin_not_allowed','Website origin is not on this credential allowlist.',403,3,'permission_denied');
              check();
              const outcome=credentialHandoff(secret);
              audit('issued');
              return outcome;
            } catch (error) {
              const safe=publicError(error, secret);
              const refused=['origin_not_allowed','credential_revoked','credential_not_found'].includes(safe.body.error.code);
              audit(refused?'refused':'failed');
              throw new AppError(safe.body.error.code, safe.body.error.message, refused?403:safe.httpStatus, refused?3:safe.exitCode, refused?'permission_denied':safe.body.status);
            }
          }
          if(grant.action===WEBSITE_LOGIN_ACTION) {
            const origin=websiteOrigin(connection.config.origin);
            const credentialId=String(connection.config.credential_id);
            const started=clock();
            const audit=(result:AuditResult,handle?:string)=>{ writeAudit(store,{credential_id:credentialId,agent_id:grant.principal,origin,started_at:started,result,...(handle?{session_handle_id:handle}:{})}); };
            try {
              if(!originAllowed(store,credentialId,origin))throw new AppError('origin_not_allowed','Website origin is not on this credential allowlist.',403,3,'permission_denied');
              const outcome=await executeWebsiteLogin(connection,secret,params,check,websiteLogin);
              let handle:string|undefined;
              if(outcome.result.outcome==='authenticated') {
                const ttl=websiteSessionTtl(store,connection.config.session_ttl);
                const session=createWebsiteSession(store,{credential_id:credentialId,agent_id:grant.principal,origin,now:clock(),ttl});
                vault.data.session_jars.push({handle_id:session.handle_id,credential_id:credentialId,value:'[]'});
                try { save(); }
                catch(error){ vault.data.session_jars.pop(); throw error; }
                (outcome.result as Record<string,unknown>).session_handle=session.handle_id;
                (outcome.result as Record<string,unknown>).expires_at=session.expires_at;
                handle=session.handle_id;
              }
              audit(outcome.result.outcome,handle);
              return vaultReply(outcome, secret) as typeof outcome;
            } catch (error) {
              const safe=publicError(error, secret);
              const refused=['executor_unavailable','origin_not_allowed','credential_revoked'].includes(safe.body.error.code);
              audit(safe.body.error.code==='executor_failed'||safe.body.error.code==='secret_leak_blocked'?'failed':'refused');
              throw new AppError(safe.body.error.code, safe.body.error.message, refused?403:safe.httpStatus, refused?3:safe.exitCode, refused?'permission_denied':safe.body.status);
            }
          }
          const outcome=grant.action==='stripe.mpp.pay'?await payMpp(connection,secret,textField(args.operation_id,36),grant.max_amount_minor,check,args.previous as PaymentContinuation|undefined)
            :await (async()=>{check();const result=await executeProvider(connection,grant.action,params,secret);check();return {state:'completed' as const,result};})();
          return vaultReply(outcome, secret) as typeof outcome;
        } catch (error) {
          const safe=publicError(error, secret);
          throw new AppError(safe.body.error.code, safe.body.error.message, safe.httpStatus, safe.exitCode, safe.body.status);
        }
      } finally {store.close();}
    }
    if(command==='node.bind') {
      exact([]);const node=await loadIdentity(configuredNodeDir,'node');const store=new Store(configuredNodeDir);
      try {await initializeOwner(store,vault.owner);
        const previous=store.db.prepare("SELECT value FROM settings WHERE key='bound_vault_id'").get();
        let invalidated=0;
        if(previous && previous.value!==vault.vaultId){
          const grants=store.db.prepare('SELECT grant_id FROM grants WHERE revoked_at IS NULL').all();
          for(const row of grants){await revokeGrant(store,node,vault.owner,String(row.grant_id),clock);invalidated++;}
        }
        store.transaction(()=> {
        for(const [key,value] of [['bound_vault_id',vault.vaultId],['vault_dir',resolve(dir)],['vault_session',token],['vault_unlocked','1'],['vault_unlock_until',String(expiresAt)]] as const)store.db.prepare('INSERT INTO settings VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key,value);
      });bound=true;return {node_id:node.id,owner:vault.owner.id,vault_id:vault.vaultId,invalidated_grants:invalidated};}finally{store.close();}
    }
    if(command==='grant.approve'||command==='grant.revoke'||command==='demo.init') {
      if(!bound)throw new AppError('owner_not_initialized','Bind this vault with node owner-init --vault-dir first.');
      const node=await loadIdentity(configuredNodeDir,'node');const store=new Store(configuredNodeDir);
      try {
        if(command==='demo.init'){exact([]);initializeDemo(store,guard);return {source:'local_synthetic',rows:21};}
        if(command==='grant.revoke'){exact(['grant_id']);return await revokeGrant(store,node,vault.owner,textField(args.grant_id,36),clock,guard);}
        exact(['pairing_id','principal','action','ttl','wallet_id'],['connection_id','max_calls','max_amount_minor']);const w=wallet(args.wallet_id);
        if(args.action!=='demo.orders.read'){
          const connection=vault.data.connections.find(c=>c.id===args.connection_id&&c.wallet_id===w.id&&supports(c,String(args.action)));
          if(!connection)throw new AppError('connection_unavailable','Select a matching connection in this wallet.');
          connectionConfig(connection.provider,connection.config,vault.data,w.id);
          const singleUseGrant=args.action===WEBSITE_LOGIN_ACTION||args.action===CREDENTIAL_GET_ACTION;
          return await approvePairing(store,node,vault.owner,textField(args.pairing_id,36),textField(args.principal,64),textField(args.action,64),Number(args.ttl),clock,w.id,{connection_id:connection.id,max_calls:integer(args.max_calls??1,1,singleUseGrant?1:100),max_amount_minor:integer(args.max_amount_minor??0,0,singleUseGrant?0:10000)},guard);
        }
        if(!vault.data.connections.some(c=>c.wallet_id===w.id&&c.provider==='demo'))throw new AppError('connection_unavailable','Connect a demo resource to this wallet first.');
        return await approvePairing(store,node,vault.owner,textField(args.pairing_id,36),textField(args.principal,64),textField(args.action,64),Number(args.ttl),clock,w.id,undefined,guard);
      } finally{store.close();}
    }
    throw new AppError('command_not_available','Vault command is not available.');
  }
  const server=createServer((request,response)=> {
    response.setHeader('content-type','application/json');response.setHeader('cache-control','no-store');
    let raw='';let size=0;
    request.on('data',chunk=>{size+=chunk.length;if(size>65536)request.destroy();else raw+=chunk.toString();});
    request.on('end',()=> {
      const handle=async()=> {
        try {
          const auth=request.headers.authorization;
          if(request.method!=='POST'||request.url!=='/owner'||request.headers['content-type']!=='application/json'||typeof auth!=='string'||Buffer.byteLength(auth)!==Buffer.byteLength('Bearer '+token)||!timingSafeEqual(Buffer.from(auth),Buffer.from('Bearer '+token)))throw new AppError('permission_denied','Private owner session required.',403,3,'permission_denied');
          const input=record(JSON.parse(raw));if(Object.keys(input).sort().join(',')!=='args,command')throw new AppError('invalid_request','Use command and args.');
          const data=await execute(textField(input.command,64),record(input.args));response.end(JSON.stringify({status:'ok',data:vaultReply(data)}));
        }catch(error){const safe=publicError(error);response.writeHead(safe.httpStatus);response.end(JSON.stringify({...safe.body,exit_code:safe.exitCode}));}
      };
      let provider=false;try{provider=record(JSON.parse(raw)).command==='provider.execute';}catch{}
      if(provider)void handle();else queue=queue.then(handle);
    });
  });
  server.requestTimeout=5000;server.headersTimeout=5000;server.keepAliveTimeout=500;
  let timer:ReturnType<typeof setTimeout>|undefined;
  async function close() {
    closing??=(async()=>{if(timer)clearTimeout(timer);await queue;setPolicy(false);await new Promise<void>((resolve,reject)=>{server.close(error=>error?reject(error):resolve());server.closeIdleConnections();});vault.close();if(existsSync(pointer)&&record(readPrivateJson(pointer)).token===token)unlinkSync(pointer);if(existsSync(socket))unlinkSync(socket);rmdirSync(socketDir);})();return closing;
  }
  try {
    writePrivateJson(pointer,{socket,token,pid:process.pid,vault_id:vault.vaultId,expires_at:expiresAt});
    await new Promise<void>((resolve,reject)=>{server.once('error',reject);server.listen(socket,()=>{server.off('error',reject);resolve();});});chmodSync(socket,0o600);
    const store=new Store(configuredNodeDir);
    try {
      store.transaction(()=> {
        const current=store.db.prepare("SELECT value FROM settings WHERE key='bound_vault_id'").get();
        if(current?.value!==vault.vaultId)return;
        for(const [key,value] of [['vault_session',token],['vault_dir',resolve(dir)],['vault_unlocked','1'],['vault_unlock_until',String(expiresAt)]] as const)
          store.db.prepare('INSERT INTO settings VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key,value);
        bound=true;
      });
    } finally {store.close();}
    timer=setTimeout(()=>{void close();},ttl*1000);timer.unref();
  }catch(error){server.close();vault.close();if(existsSync(pointer)&&record(readPrivateJson(pointer)).token===token)unlinkSync(pointer);if(existsSync(socket))unlinkSync(socket);rmdirSync(socketDir);throw error;}
  return {server,vaultId:vault.vaultId,owner:vault.owner.id,expiresAt,close};
}
