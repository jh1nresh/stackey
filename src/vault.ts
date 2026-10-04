import { createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, hkdfSync, randomBytes, randomUUID } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, lstatSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { calculateJwkThumbprint, type JWK } from 'jose';
import { generateMnemonic, mnemonicToSeed, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { AppError, displayName, record, textField } from './contracts.js';
import { privateDirectory, readPrivateJson, writePrivateJson, type Identity } from './identity.js';

export interface Wallet { id: string; name: string; connections: string[] }
export interface Credential { id: string; wallet_id: string; name: string; kind: 'password' | 'api_key' | 'private_key' | 'website_login'; value: string }
export interface Connection { id: string; wallet_id: string; provider: 'demo' | 'supabase' | 'vercel' | 'stripe' | 'website'; name: string; config: Record<string, unknown> }
export interface VaultRequest { request_id: string; fingerprint: string; result: Record<string, unknown> }
export interface VaultData { wallets: Wallet[]; credentials: Credential[]; connections: Connection[]; requests: VaultRequest[] }
export const VAULT_REQUESTS_CAP = 3000;
interface Box { iv: string; ciphertext: string; tag: string }
interface Header { format: 'stackey-vault'; version: 1; vault_id: string; owner: string; salt: string; cipher: 'AES-256-GCM' }
interface File extends Header { wrapped_key: Box; data: Box }
const maxBytes = 4 * 1024 * 1024;
function fail(): never { throw new AppError('invalid_vault', 'Vault format, recovery material or integrity check failed.', 403, 3, 'permission_denied'); }
const derive = (seed: Uint8Array, salt: Uint8Array, purpose: string) => Buffer.from(hkdfSync('sha256', seed, salt, purpose, 32));
function bytes(raw: unknown, size?: number): Buffer {
  const text = textField(raw, maxBytes); const value = Buffer.from(text, 'base64url');
  if (value.toString('base64url') !== text || (size !== undefined && value.length !== size)) fail();
  return value;
}
function exact(value: Record<string, unknown>, fields: string[]) {
  if (Object.keys(value).sort().join(',') !== fields.sort().join(',')) fail();
}
function box(raw: unknown): Box {
  const value = record(raw); exact(value, ['iv','ciphertext','tag']);
  bytes(value.iv, 12); bytes(value.tag, 16); bytes(value.ciphertext);
  return { iv: value.iv as string, ciphertext: value.ciphertext as string, tag: value.tag as string };
}
function parse(raw: unknown): File {
  const value = record(raw); exact(value, ['format','version','vault_id','owner','salt','cipher','wrapped_key','data']);
  if (value.format !== 'stackey-vault' || value.version !== 1 || value.cipher !== 'AES-256-GCM' ||
    !/^[0-9a-f-]{36}$/.test(textField(value.vault_id,36)) || !/^[A-Za-z0-9_-]{43}$/.test(textField(value.owner,43))) fail();
  bytes(value.salt,32);
  return { format: 'stackey-vault', version: 1, vault_id: value.vault_id as string, owner: value.owner as string,
    salt: value.salt as string, cipher: 'AES-256-GCM', wrapped_key: box(value.wrapped_key), data: box(value.data) };
}
function read(path: string) {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 ||
      stat.uid !== process.getuid?.() || stat.size > maxBytes) throw new AppError('unsafe_vault_file','Use a private regular vault file.');
  try { return parse(JSON.parse(readFileSync(path,'utf8'))); } catch { fail(); }
}
function header(file: File): Header {
  return { format: file.format, version: file.version, vault_id: file.vault_id, owner: file.owner, salt: file.salt, cipher: file.cipher };
}
function seal(key: Buffer, plain: Buffer, aad: unknown): Box {
  const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm',key,iv);
  cipher.setAAD(Buffer.from(JSON.stringify(aad)));
  const encrypted = Buffer.concat([cipher.update(plain),cipher.final()]);
  return { iv: iv.toString('base64url'), ciphertext: encrypted.toString('base64url'), tag: cipher.getAuthTag().toString('base64url') };
}
function unseal(key: Buffer, value: Box, aad: unknown) {
  const cipher = createDecipheriv('aes-256-gcm',key,bytes(value.iv,12));
  cipher.setAAD(Buffer.from(JSON.stringify(aad))); cipher.setAuthTag(bytes(value.tag,16));
  return Buffer.concat([cipher.update(bytes(value.ciphertext)),cipher.final()]);
}
function validateData(raw: unknown): VaultData {
  const value = record(raw);
  const keys = Object.keys(value).sort().join(',');
  if (keys !== 'connections,credentials,wallets' && keys !== 'connections,credentials,requests,wallets') fail();
  if (!Array.isArray(value.wallets) || !Array.isArray(value.credentials) || !Array.isArray(value.connections) ||
      value.wallets.length > 1000 || value.credentials.length > 1000 || value.connections.length > 1000) fail();
  const id = (raw: unknown) => { const text=textField(raw,64); if (!/^(?:wallet_demo|(?:wallet|credential|connection)_[0-9a-f-]{36})$/.test(text)) fail(); return text; };
  const wallets = value.wallets.map(raw => {
    const w=record(raw); exact(w,['id','name','connections']); if (!Array.isArray(w.connections)) fail();
    return { id:id(w.id),name:displayName(w.name),connections:w.connections.map(id) };
  });
  const credentials = value.credentials.map(raw => {
    const c=record(raw); exact(c,['id','wallet_id','name','kind','value']);
    if (!['password','api_key','private_key','website_login'].includes(String(c.kind))) fail();
    return { id:id(c.id),wallet_id:id(c.wallet_id),name:displayName(c.name),kind:c.kind as Credential['kind'],value:textField(c.value,16384) };
  });
  const connections = value.connections.map(raw => {
    const c=record(raw); exact(c,['id','wallet_id','provider','name','config']);
    if (!['demo','supabase','vercel','stripe','website'].includes(String(c.provider))) fail();
    return { id:id(c.id),wallet_id:id(c.wallet_id),provider:c.provider as Connection['provider'],name:displayName(c.name),config:record(c.config) };
  });
  const requests = value.requests===undefined ? [] : (() => {
    if (!Array.isArray(value.requests) || value.requests.length > VAULT_REQUESTS_CAP) fail();
    return value.requests.map(raw => {
      const r=record(raw); exact(r,['fingerprint','request_id','result']);
      const request_id=textField(r.request_id,36);
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(request_id)) fail();
      const fingerprint=textField(r.fingerprint,43);
      if (!/^[A-Za-z0-9_-]{43}$/.test(fingerprint)) fail();
      return { request_id, fingerprint, result: record(r.result) };
    });
  })();
  if (new Set(wallets.map(w=>w.id)).size !== wallets.length || new Set(credentials.map(c=>c.id)).size !== credentials.length ||
      new Set(connections.map(c=>c.id)).size !== connections.length || new Set(requests.map(r=>r.request_id)).size !== requests.length ||
      [...credentials,...connections].some(c=>!wallets.some(w=>w.id===c.wallet_id)) ||
      wallets.some(w=>new Set(w.connections).size!==w.connections.length || w.connections.some(id=>!connections.some(c=>c.id===id && c.wallet_id===w.id)))) fail();
  return { wallets,credentials,connections,requests };
}
export async function recovery(file: string) {
  const raw=record(readPrivateJson(resolve(file))); exact(raw,['format','version','mnemonic']);
  const mnemonic=textField(raw.mnemonic,512);
  if (raw.format !== 'stackey-recovery' || raw.version !== 1 || !validateMnemonic(mnemonic,wordlist)) fail();
  return mnemonic;
}
async function keys(mnemonic: string, salt: Buffer) {
  if (!validateMnemonic(mnemonic,wordlist)) fail();
  const seed=await mnemonicToSeed(mnemonic);
  const signing=derive(seed,Buffer.from('stackey-owner-v1'),'stackey/owner-signing/v1');
  const wrapping=derive(seed,salt,'stackey/vault-wrapping/v1'); seed.fill(0);
  try {
    const key=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),signing]),format:'der',type:'pkcs8'});
    const publicJwk=createPublicKey(key).export({format:'jwk'}) as JWK;
    const privateJwk=key.export({format:'jwk'}) as JWK;
    return { wrapping,owner:{id:await calculateJwkThumbprint(publicJwk),publicJwk,privateJwk} satisfies Identity };
  } finally { signing.fill(0); }
}
function persist(path: string, file: File, create=false) {
  const text=JSON.stringify(file)+'\n'; if (Buffer.byteLength(text)>maxBytes) throw new AppError('vault_full','Vault is limited to 4 MiB.');
  if (create) {
    const fd=openSync(path,'wx',0o600);try{writeFileSync(fd,text);fsyncSync(fd);}finally{closeSync(fd);}return;
  }
  read(path); // Revalidate before replacing a private file; the daemon is the sole writer.
  const temporary=join(dirname(path),'.vault-'+randomUUID());
  const fd=openSync(temporary,'wx',0o600);
  try { writeFileSync(fd,text); fsyncSync(fd); } finally { closeSync(fd); }
  try { renameSync(temporary,path); } catch(error) { unlinkSync(temporary); throw error; }
}
export function vaultPath(dir: string) { return join(privateDirectory(dir),'vault.json'); }
export async function initializeVault(dir: string, recoveryOut: string) {
  const path=vaultPath(dir); const output=resolve(recoveryOut); privateDirectory(dirname(output));
  if (existsSync(path) || existsSync(output)) throw new AppError('output_exists','Vault and recovery output must both be new files.');
  const mnemonic=generateMnemonic(wordlist,256); const salt=randomBytes(32); const derived=await keys(mnemonic,salt);
  const master=randomBytes(32);
  try {
    const h:Header={format:'stackey-vault',version:1,vault_id:randomUUID(),owner:derived.owner.id,salt:salt.toString('base64url'),cipher:'AES-256-GCM'};
    const wrapped_key=seal(derived.wrapping,master,{...h,purpose:'master-key'});
    const data:VaultData={wallets:[{id:'wallet_demo',name:'Demo Wallet',connections:[]}],credentials:[],connections:[],requests:[]};
    const encrypted=seal(master,Buffer.from(JSON.stringify(data)),{...h,wrapped_key,purpose:'vault-data'});
    // Recovery file is committed first; a partial init never leaves an unrecoverable vault.
    writePrivateJson(output,{format:'stackey-recovery',version:1,mnemonic});
    const recoveryFd=openSync(output,'r');try{fsyncSync(recoveryFd);}finally{closeSync(recoveryFd);}
    persist(path,{...h,wrapped_key,data:encrypted},true);
    return {vault_id:h.vault_id,owner:h.owner,vault_file:path,recovery_file:output,status:'locked'};
  } finally { derived.wrapping.fill(0); master.fill(0); }
}
export async function openVault(dir: string, mnemonic: string) {
  const path=vaultPath(dir); const file=read(path); const h=header(file);
  const derived=await keys(mnemonic,bytes(file.salt,32)); let master:Buffer|undefined;
  try {
    if (derived.owner.id!==file.owner) fail();
    master=unseal(derived.wrapping,file.wrapped_key,{...h,purpose:'master-key'});
    if (master.length!==32) fail();
    const plaintext=unseal(master,file.data,{...h,wrapped_key:file.wrapped_key,purpose:'vault-data'});
    let data:VaultData;
    try { data=validateData(JSON.parse(plaintext.toString('utf8'))); } finally { plaintext.fill(0); }
    const dataKey=master;
    return {data,owner:derived.owner,vaultId:file.vault_id,path,save(next:VaultData) {
      const valid=validateData(next);
      persist(path,{...h,wrapped_key:file.wrapped_key,data:seal(dataKey,Buffer.from(JSON.stringify(valid)),{...h,wrapped_key:file.wrapped_key,purpose:'vault-data'})});
      this.data=valid;
    },close() { dataKey.fill(0); this.owner.privateJwk.d='';for(const credential of this.data.credentials)credential.value='';for(const connection of this.data.connections)connection.config={}; }};
  } catch { master?.fill(0); fail(); }
  finally { derived.wrapping.fill(0); }
}
export function backupVault(dir: string, output: string) {
  const file=read(vaultPath(dir)); const target=resolve(output); privateDirectory(dirname(target));
  persist(target,file,true); return {backup_file:target,vault_id:file.vault_id,encrypted:true};
}
export async function restoreVault(dir: string, backup: string, mnemonic: string) {
  const target=vaultPath(dir); if(existsSync(target)) throw new AppError('output_exists','Restore requires a new vault directory.');
  const source=read(resolve(backup));
  // Validate recovery and authenticated data before writing anything to the destination.
  const derived=await keys(mnemonic,bytes(source.salt,32)); let master:Buffer|undefined;
  try {
    if(derived.owner.id!==source.owner) fail();
    master=unseal(derived.wrapping,source.wrapped_key,{...header(source),purpose:'master-key'});
    const plain=unseal(master,source.data,{...header(source),wrapped_key:source.wrapped_key,purpose:'vault-data'});
    try {
      validateData(JSON.parse(plain.toString('utf8')));
      const restored={...header(source),vault_id:randomUUID()};
      const wrapped_key=seal(derived.wrapping,master,{...restored,purpose:'master-key'});
      persist(target,{...restored,wrapped_key,data:seal(master,plain,{...restored,wrapped_key,purpose:'vault-data'})},true);
      return {vault_id:restored.vault_id,source_vault_id:source.vault_id,owner:source.owner,status:'locked',restored_file:target,grants_restored:false};
    } finally { plain.fill(0); }
  } catch { fail(); } finally {master?.fill(0);derived.wrapping.fill(0);}
}
