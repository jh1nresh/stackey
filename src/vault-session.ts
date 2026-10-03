import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { chmodSync, existsSync, mkdtempSync, rmdirSync, unlinkSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { AppError, displayName, publicError, record, textField } from './contracts.js';
import { loadIdentity, readPrivateJson, writePrivateJson } from './identity.js';
import { initializeDemo } from './orders.js';
import { approvePairing, initializeOwner, revokeGrant, seconds } from './policy.js';
import { Store } from './store.js';
import { openVault, recovery, type Connection, type Credential } from './vault.js';
import { sessionPath } from './vault-client.js';

export interface RunningVault { server:Server;vaultId:string;owner:string;expiresAt:number;close():Promise<void> }
export async function unlockVault(dir:string,recoveryFile:string,nodeDir:string,ttl=900,clock=seconds):Promise<RunningVault> {
  if(!Number.isInteger(ttl)||ttl<60||ttl>3600)throw new AppError('invalid_ttl','Vault unlock lifetime must be 60–3600 seconds.');
  const vault=await openVault(dir,await recovery(recoveryFile));
  const pointer=sessionPath(dir);
  if(existsSync(pointer)){vault.close();throw new AppError('session_exists','A vault session or stale session file exists. Lock the active session or use vault recover-session.');}
  const socketDir=mkdtempSync(join(tmpdir(),'stackey-vault-'));chmodSync(socketDir,0o700);
  const socket=join(socketDir,'owner.sock');const token=randomBytes(32).toString('base64url');const expiresAt=clock()+ttl;
  let bound=false;let closing:Promise<void>|undefined;let queue=Promise.resolve();
  const configuredNodeDir=resolve(nodeDir);
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
    if(closing || clock()>=expiresAt)throw new AppError('node_locked','Vault unlock expired.',403,3,'node_locked');
    if (['node.bind','grant.approve','grant.revoke','demo.init'].includes(command)) {
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
    if(command==='wallet.create'){exact(['name']);const value={id:'wallet_'+randomUUID(),name:displayName(args.name),connections:[]};vault.data.wallets.push(value);try{save();}catch(error){vault.data.wallets.pop();throw error;}return {...value,address:`stackey:${vault.owner.id}/${value.id}`};}
    if(command==='credential.list'){exact(['wallet_id'],['after']);const w=wallet(args.wallet_id);const result=page(vault.data.credentials.filter(c=>c.wallet_id===w.id));return {credentials:result.values.map(({value,...metadata})=>metadata),next_cursor:result.next_cursor,complete:result.complete};}
    if(command==='credential.import') {
      exact(['wallet_id','name','kind','value']);const w=wallet(args.wallet_id);
      if(!['password','api_key','private_key'].includes(String(args.kind)))throw new AppError('invalid_kind','Use password, api_key or private_key.');
      const value:Credential={id:'credential_'+randomUUID(),wallet_id:w.id,name:displayName(args.name),kind:args.kind as Credential['kind'],value:textField(args.value,16384)};
      vault.data.credentials.push(value);try{save();}catch(error){vault.data.credentials.pop();throw error;}const {value:secret,...metadata}=value;return metadata;
    }
    if(command==='credential.remove'){exact(['credential_id']);const id=textField(args.credential_id,64);const index=vault.data.credentials.findIndex(c=>c.id===id);if(index<0)throw new AppError('credential_not_found','Credential was not found.');const old=vault.data.credentials.splice(index,1)[0]!;try{save();}catch(error){vault.data.credentials.splice(index,0,old);throw error;}return {credential_id:id,removed:true};}
    if(command==='connection.list'){exact(['wallet_id'],['after']);const w=wallet(args.wallet_id);const result=page(vault.data.connections.filter(c=>c.wallet_id===w.id));return {connections:result.values.map(({config,...metadata})=>metadata),next_cursor:result.next_cursor,complete:result.complete};}
    if(command==='connection.add') {
      exact(['wallet_id','name','provider','config']);const w=wallet(args.wallet_id);
      if(!['demo','supabase','vercel','stripe'].includes(String(args.provider)))throw new AppError('invalid_provider','Use a supported provider.');
      const value:Connection={id:'connection_'+randomUUID(),wallet_id:w.id,name:displayName(args.name),provider:args.provider as Connection['provider'],config:record(args.config)};
      vault.data.connections.push(value);w.connections.push(value.id);try{save();}catch(error){vault.data.connections.pop();w.connections.pop();throw error;}
      const {config,...metadata}=value;return metadata;
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
        if(command==='demo.init'){exact([]);initializeDemo(store);return {source:'local_synthetic',rows:21};}
        if(command==='grant.revoke'){exact(['grant_id']);return await revokeGrant(store,node,vault.owner,textField(args.grant_id,36),clock);}
        exact(['pairing_id','principal','action','ttl','wallet_id']);const w=wallet(args.wallet_id);
        if(!vault.data.connections.some(c=>c.wallet_id===w.id&&c.provider==='demo'))throw new AppError('connection_unavailable','Connect a demo resource to this wallet first.');
        return await approvePairing(store,node,vault.owner,textField(args.pairing_id,36),textField(args.principal,64),textField(args.action,64),Number(args.ttl),clock,w.id);
      } finally{store.close();}
    }
    throw new AppError('command_not_available','Vault command is not available.');
  }
  const server=createServer((request,response)=> {
    response.setHeader('content-type','application/json');response.setHeader('cache-control','no-store');
    let raw='';let size=0;
    request.on('data',chunk=>{size+=chunk.length;if(size>65536)request.destroy();else raw+=chunk.toString();});
    request.on('end',()=> {
      queue=queue.then(async()=> {
        try {
          const auth=request.headers.authorization;
          if(request.method!=='POST'||request.url!=='/owner'||request.headers['content-type']!=='application/json'||typeof auth!=='string'||Buffer.byteLength(auth)!==Buffer.byteLength('Bearer '+token)||!timingSafeEqual(Buffer.from(auth),Buffer.from('Bearer '+token)))throw new AppError('permission_denied','Private owner session required.',403,3,'permission_denied');
          const input=record(JSON.parse(raw));if(Object.keys(input).sort().join(',')!=='args,command')throw new AppError('invalid_request','Use command and args.');
          const data=await execute(textField(input.command,64),record(input.args));response.end(JSON.stringify({status:'ok',data}));
        }catch(error){const safe=publicError(error);response.writeHead(safe.httpStatus);response.end(JSON.stringify({...safe.body,exit_code:safe.exitCode}));}
      });
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
    timer=setTimeout(()=>{void close();},ttl*1000);timer.unref();
  }catch(error){server.close();vault.close();if(existsSync(pointer)&&record(readPrivateJson(pointer)).token===token)unlinkSync(pointer);if(existsSync(socket))unlinkSync(socket);rmdirSync(socketDir);throw error;}
  return {server,vaultId:vault.vaultId,owner:vault.owner.id,expiresAt,close};
}
