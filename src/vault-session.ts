import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { chmodSync, existsSync, mkdtempSync, rmdirSync, unlinkSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { AppError, digest, displayName, publicError, record, textField } from './contracts.js';
import { loadIdentity, readPrivateJson, writePrivateJson } from './identity.js';
import { initializeDemo } from './orders.js';
import { approvePairing, initializeOwner, requireGrant, revokeGrant, seconds, verifyGrant } from './policy.js';
import { Store } from './store.js';
import { openVault, recovery, type Connection, type Credential } from './vault.js';
import { connectionConfig, executeProvider, integer, providerParams, supports } from './providers.js';
import { payMpp, type PaymentContinuation } from './mpp-payment.js';
import { sessionPath } from './vault-client.js';

export interface RunningVault { server:Server;vaultId:string;owner:string;expiresAt:number;close():Promise<void> }
export function requireBoundVault(store:Store,token:string,vaultId:string):void {
  const session=store.db.prepare("SELECT value FROM settings WHERE key='vault_session'").get();
  const boundId=store.db.prepare("SELECT value FROM settings WHERE key='bound_vault_id'").get();
  const current=typeof session?.value==='string'?session.value:'';
  if(current.length!==token.length||boundId?.value!==vaultId||!timingSafeEqual(Buffer.from(current),Buffer.from(token))) {
    throw new AppError('node_locked','This vault session is no longer bound to the Node.',403,3,'node_locked');
  }
}
export async function unlockVault(dir:string,recoveryFile:string,nodeDir:string,ttl=900,clock=seconds,beforeExecute?:()=>Promise<void>):Promise<RunningVault> {
  if(!Number.isInteger(ttl)||ttl<60||ttl>3600)throw new AppError('invalid_ttl','Vault unlock lifetime must be 60–3600 seconds.');
  const vault=await openVault(dir,await recovery(recoveryFile));
  const pointer=sessionPath(dir);
  if(existsSync(pointer)){vault.close();throw new AppError('session_exists','A vault session or stale session file exists. Lock the active session or use vault recover-session.');}
  const socketDir=mkdtempSync(join(tmpdir(),'stackey-vault-'));chmodSync(socketDir,0o700);
  const socket=join(socketDir,'owner.sock');const token=randomBytes(32).toString('base64url');const expiresAt=clock()+ttl;
  let bound=false;let closing:Promise<void>|undefined;let queue=Promise.resolve();
  const configuredNodeDir=resolve(nodeDir);
  const requests=new Map<string,{fingerprint:string,result:unknown}>();
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
    const prior=requests.get(id);if(!prior)return;
    if(prior.fingerprint!==requestFingerprint(command,args))throw new AppError('operation_conflict','request_id belongs to different parameters.');
    return prior.result;
  };
  const remember=(command:string,args:Record<string,unknown>,result:unknown)=>{
    const id=requestId(args);if(id)requests.set(id,{fingerprint:requestFingerprint(command,args),result});
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
    if (['node.bind','grant.approve','grant.revoke','demo.init','provider.execute'].includes(command)) {
      if(args._node_dir!==configuredNodeDir) throw new AppError('node_mismatch','CLI Node directory differs from the unlocked vault session.');
      args={...args};delete args._node_dir;
    }
    const exact=(keys:string[], optional:string[]=[])=>{if(keys.some(key=>!(key in args)) || Object.keys(args).some(key=>!keys.includes(key)&&!optional.includes(key)))throw new AppError('invalid_parameters','Unexpected vault parameters.');};
    if(command==='status'){exact([]);return {status:'unlocked',vault_id:vault.vaultId,owner:vault.owner.id,expires_at:expiresAt};}
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
      const value={id:'wallet_'+randomUUID(),name:displayName(args.name),connections:[]};vault.data.wallets.push(value);
      try{save();}catch(error){vault.data.wallets.pop();throw error;}
      const result={...value,address:`stackey:${vault.owner.id}/${value.id}`};remember(command,args,result);return result;
    }
    if(command==='credential.list'){exact(['wallet_id'],['after']);const w=wallet(args.wallet_id);const result=page(vault.data.credentials.filter(c=>c.wallet_id===w.id));return {credentials:result.values.map(({value,...metadata})=>metadata),next_cursor:result.next_cursor,complete:result.complete};}
    if(command==='credential.import') {
      exact(['wallet_id','name','kind','value'],['request_id']);const replay=replayed(command,args);if(replay)return replay;
      const w=wallet(args.wallet_id);
      if(!['password','api_key','private_key'].includes(String(args.kind)))throw new AppError('invalid_kind','Use password, api_key or private_key.');
      const value:Credential={id:'credential_'+randomUUID(),wallet_id:w.id,name:displayName(args.name),kind:args.kind as Credential['kind'],value:textField(args.value,16384)};
      vault.data.credentials.push(value);try{save();}catch(error){vault.data.credentials.pop();throw error;}
      const metadata={id:value.id,wallet_id:value.wallet_id,name:value.name,kind:value.kind};remember(command,args,metadata);return metadata;
    }
    if(command==='credential.remove'){exact(['credential_id']);const id=textField(args.credential_id,64);const index=vault.data.credentials.findIndex(c=>c.id===id);if(index<0)throw new AppError('credential_not_found','Credential was not found.');const old=vault.data.credentials.splice(index,1)[0]!;try{save();}catch(error){vault.data.credentials.splice(index,0,old);throw error;}return {credential_id:id,removed:true};}
    if(command==='connection.list'){exact(['wallet_id'],['after']);const w=wallet(args.wallet_id);const result=page(vault.data.connections.filter(c=>c.wallet_id===w.id));return {connections:result.values.map(({config,...metadata})=>metadata),next_cursor:result.next_cursor,complete:result.complete};}
    if(command==='connection.add') {
      exact(['wallet_id','name','provider','config'],['request_id']);const replay=replayed(command,args);if(replay)return replay;
      const w=wallet(args.wallet_id);
      if(!['demo','supabase','vercel','stripe'].includes(String(args.provider)))throw new AppError('invalid_provider','Use a supported provider.');
      const value:Connection={id:'connection_'+randomUUID(),wallet_id:w.id,name:displayName(args.name),provider:args.provider as Connection['provider'],config:connectionConfig(args.provider as Connection['provider'],args.config,vault.data,w.id)};
      vault.data.connections.push(value);w.connections.push(value.id);try{save();}catch(error){vault.data.connections.pop();w.connections.pop();throw error;}
      const metadata={id:value.id,wallet_id:value.wallet_id,name:value.name,provider:value.provider};remember(command,args,metadata);return metadata;
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
        connectionConfig(connection.provider,connection.config,vault.data,grant.wallet_id);
        const credential=vault.data.credentials.find(c=>c.id===connection.config.credential_id&&c.wallet_id===grant.wallet_id)!;
        const params=providerParams(grant.action,args.params);
        if(grant.action==='stripe.mpp.pay')return await payMpp(connection,credential.value,textField(args.operation_id,36),grant.max_amount_minor,check,args.previous as PaymentContinuation|undefined);
        check();const result=await executeProvider(connection,grant.action,params,credential.value);check();
        return {state:'completed',result};
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
          return await approvePairing(store,node,vault.owner,textField(args.pairing_id,36),textField(args.principal,64),textField(args.action,64),Number(args.ttl),clock,w.id,{connection_id:connection.id,max_calls:integer(args.max_calls??1,1,100),max_amount_minor:integer(args.max_amount_minor??0,0,10000)},guard);
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
          const data=await execute(textField(input.command,64),record(input.args));response.end(JSON.stringify({status:'ok',data}));
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
