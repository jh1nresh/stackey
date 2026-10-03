import { request } from 'node:http';
import { join } from 'node:path';
import { lstatSync } from 'node:fs';
import { AppError, record, textField } from './contracts.js';
import { readPrivateJson } from './identity.js';

export const sessionPath = (dir: string) => join(dir,'session.json');
export async function vaultRequest(dir: string, command: string, args: Record<string,unknown> = {}) {
  let state:Record<string,unknown>;
  try { state=record(readPrivateJson(sessionPath(dir))); }
  catch { throw new AppError('node_locked','Unlock the vault first.',403,3,'node_locked'); }
  const socket=textField(state.socket,100); const token=textField(state.token,64);
  let stat;try{stat=lstatSync(socket);}catch{throw new AppError('node_locked','Vault session is unavailable.',403,3,'node_locked');}
  if(!stat.isSocket() || stat.uid!==process.getuid?.() || (stat.mode&0o077)!==0) throw new AppError('unsafe_session','Vault session socket must be private.');
  const payload=JSON.stringify({command,args});
  if(Buffer.byteLength(payload)>65536) throw new AppError('request_too_large','Vault request exceeds 64 KiB.');
  return new Promise<any>((resolve,reject)=> {
    const pending=request({socketPath:socket,path:'/owner',method:'POST',headers:{authorization:'Bearer '+token,'content-type':'application/json','content-length':Buffer.byteLength(payload)}},response=> {
      const chunks:Buffer[]=[];let size=0;
      response.on('data',chunk=> {size+=chunk.length;if(size>131072){pending.destroy();reject(new AppError('invalid_response','Vault response exceeded its limit.'));}else chunks.push(chunk);});
      response.on('end',()=> {
        try {
          const body=record(JSON.parse(Buffer.concat(chunks).toString()));
          if((response.statusCode??500)>=400){const error=record(body.error);reject(new AppError(textField(error.code,64),textField(error.message,512),response.statusCode,Number(body.exit_code??3),String(body.status??'permission_denied')));}
          else resolve(body.data);
        }catch{reject(new AppError('invalid_response','Vault returned an invalid response.'));}
      });
    });
    pending.setTimeout(2000,()=>pending.destroy());
    pending.on('error',()=>reject(new AppError('node_locked','Vault session is unavailable. Unlock it again.',403,3,'node_locked')));
    pending.end(payload);
  });
}
