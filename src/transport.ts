import { lookup } from 'node:dns/promises';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';
import { AppError, endpoint } from './contracts.js';

export function publicAddress(address: string): boolean {
  if (isIP(address) === 4) {
    const [a,b,c] = address.split('.').map(Number) as [number,number,number,number];
    return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113));
  }
  if (isIP(address) !== 6) return false;
  const [first,second] = address.toLowerCase().split(':');
  const a = parseInt(first!,16), b = parseInt(second || '0',16);
  return a >= 0x2000 && a <= 0x3fff && a !== 0x2002 &&
    !(a === 0x2001 && (b <= 0x1ff || b === 0xdb8)) && !(a === 0x3fff && b <= 0xfff);
}

// HTTPS requests resolve once, reject private/reserved addresses and pin the
// selected address while retaining ordinary hostname/certificate verification.
// Redirects are never followed. No proxy or forwarding headers are trusted.
export async function nodeFetch(input: string | URL, init: {method?: string;headers?: NonNullable<ConstructorParameters<typeof Headers>[0]>;body?: string} = {}): Promise<Response> {
  const url = new URL(input);
  endpoint(url.origin);
  if (url.username || url.password || url.hash) throw new AppError('invalid_endpoint','Invalid request URL.');
  if (url.protocol === 'http:') return fetch(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(10000) });
  let dnsTimer: ReturnType<typeof setTimeout> | undefined;
  const addresses = await Promise.race([lookup(url.hostname, {all:true}), new Promise<never>((_, reject) => { dnsTimer = setTimeout(() => reject(new Error('DNS timeout')), 10000); })]).finally(() => clearTimeout(dnsTimer));
  if (!addresses.length || addresses.some(a => !publicAddress(a.address))) throw new AppError('unsafe_endpoint','Remote Node must resolve only to public addresses.');
  const selected = addresses[0]!;
  return new Promise<Response>((resolve,reject) => {
    const headers = Object.fromEntries(new Headers(init.headers));
    const req = httpsRequest(url, {method:init.method ?? 'GET',headers,family:selected.family,
      lookup: (_name,_options,callback) => callback(null,selected.address,selected.family)}, res => {
      const chunks:Buffer[]=[]; let size=0;
      res.on('data',chunk=> {size+=chunk.length;
        if(size>131072){req.destroy(new AppError('invalid_node_response','Response exceeds its limit.'));}else chunks.push(Buffer.from(chunk));
      });
      res.on('error',reject);
      res.on('end',()=> {
        if ((res.statusCode ?? 500)>=300 && (res.statusCode ?? 500)<400) {reject(new AppError('redirect_denied','Node redirects are not allowed.'));return;}
        const responseHeaders = new Headers();
        for(const [name,value] of Object.entries(res.headers)) if(value!==undefined) responseHeaders.set(name,Array.isArray(value)?value.join(', '):value);
        resolve(new Response(Buffer.concat(chunks),{status:res.statusCode ?? 500,headers:responseHeaders}));
      });
    });
    const timer = setTimeout(()=>req.destroy(new Error('Node timeout')),10000);
    req.once('close',()=>clearTimeout(timer));
    req.on('error',reject); req.end(init.body);
  });
}
