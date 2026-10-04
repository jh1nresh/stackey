import { nodeFetch } from './transport.js';
import { randomUUID, type webcrypto } from 'node:crypto';
import { join } from 'node:path';
import { importJWK, jwtVerify, SignJWT } from 'jose';
import * as oauth from 'oauth4webapi';
import { BOOTSTRAP_TYPE, issuer, isUuid, RESPONSE_TYPE } from './agent-protocol.js';
import { AppError, digest, endpoint, record, textField } from './contracts.js';
import { loadIdentity, publicKey, readPrivateJson, type Identity } from './identity.js';
import { providerAction, providerParams } from './provider-contracts.js';
import { ACTION, orderParams } from './orders.js';

export async function agentContext(dir: string) {
  const identity = await loadIdentity(dir, 'agent');
  const saved = record(readPrivateJson(join(dir, 'pairing.json')));
  if (saved.principal !== identity.id) throw new AppError('invalid_state', 'Pairing does not match this agent identity.');
  const node = publicKey(saved.node_public_jwk, 'EdDSA');
  return { identity, node, nodeId: textField(saved.node_id, 64),
    pairingId: textField(saved.pairing_id, 36), origin: endpoint(saved.endpoint) };
}
export type AgentContext = Awaited<ReturnType<typeof agentContext>>;

async function readResponse(response: Response) {
  if (!response.body) throw new Error('Empty response');
  const reader = response.body.getReader();
  let size = 0; const chunks: Uint8Array[] = [];
  while (true) {
    const chunk = await reader.read();
    if (chunk.done) break;
    size += chunk.value.length;
    if (size > 131_072) { await reader.cancel(); throw new Error('Oversized response'); }
    chunks.push(chunk.value);
  }
  return record(JSON.parse(Buffer.concat(chunks).toString()));
}

export async function verifiedResponse(context: AgentContext, response: Response, requestHash: string) {
  let body: Record<string, unknown>;
  try {
    const outer = await readResponse(response);
    const { payload } = await jwtVerify(textField(record(outer.data).receipt, 131_072), await importJWK(context.node, 'EdDSA'), {
      algorithms: ['EdDSA'], typ: RESPONSE_TYPE, issuer: context.nodeId, audience: 'stackey-cli',
      requiredClaims: ['iat', 'exp'],
    });
    if (payload.request_hash !== requestHash) throw new Error('Response binding');
    body = record(payload.body);
    if (body.schema_version !== 1 || typeof body.status !== 'string') throw new Error('Response format');
  } catch { throw new AppError('invalid_node_response', 'Node response could not be verified.', 502, 4, 'result_unknown'); }
  if (!response.ok) {
    const error = record(body.error);
    const status = textField(body.status, 64);
    throw new AppError(textField(error.code, 64), textField(error.message, 512), response.status,
      status === 'permission_denied' || status === 'grant_expired' || status === 'grant_revoked' ? 3 :
        status === 'rate_limited' ? 4 : 2, status);
  }
  return body;
}

async function plain(context: AgentContext, path: string, body: string, headers: Record<string, string> = {}) {
  try {
    return await nodeFetch(context.origin + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers },
      body });
  } catch { throw new AppError('node_unreachable', 'Node did not confirm the request.', 503, 4, 'node_unreachable'); }
}

export async function challenge(context: AgentContext): Promise<string> {
  const body = JSON.stringify({ request_id: randomUUID() });
  const response = await verifiedResponse(context, await plain(context, '/v1/challenges', body), digest(body));
  return textField(record(response.data).nonce, 64);
}

export async function bootstrapProof(context: AgentContext, nonce: string, method: string, path: string, body: string) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ purpose: 'agent-bootstrap', nonce, htm: method,
    htu: context.origin + path, body_hash: digest(body) })
    .setProtectedHeader({ alg: 'ES256', typ: BOOTSTRAP_TYPE, jwk: context.identity.publicJwk })
    .setIssuer(context.identity.id).setAudience(context.nodeId).setJti(randomUUID())
    .setIssuedAt(now).setExpirationTime(now + 30).sign(await importJWK(context.identity.privateJwk, 'ES256'));
}

export async function bootstrapRequest(context: AgentContext, method: string, path: string, body = '') {
  const proof = await bootstrapProof(context, await challenge(context), method, path, body);
  let response: Response;
  if (method === 'POST') response = await plain(context, path, body, { 'x-stackey-proof': proof });
  else {
    try { response = await nodeFetch(context.origin + path, { headers: { 'x-stackey-proof': proof } }); }
    catch { throw new AppError('node_unreachable', 'Node did not confirm the request.', 503, 4, 'node_unreachable'); }
  }
  return verifiedResponse(context, response, digest(proof));
}

export async function session(context: AgentContext): Promise<string> {
  const result = await bootstrapRequest(context, 'POST', '/v1/sessions', JSON.stringify({ pairing_id: context.pairingId }));
  const token = textField(record(result.data).access_token, 8192);
  try {
    const { payload } = await jwtVerify(token, await importJWK(context.node, 'EdDSA'), {
      algorithms: ['EdDSA'], typ: 'at+jwt', issuer: issuer(context.nodeId), audience: context.nodeId,
      subject: context.identity.id, requiredClaims: ['iat', 'exp', 'jti'],
    });
    if (record(payload.cnf).jkt !== context.identity.id) throw new Error('Key binding');
  } catch { throw new AppError('invalid_session', 'Node session could not be verified.', 502, 4, 'result_unknown'); }
  return token;
}

export async function resourceRequest(context: AgentContext, token: string, method: string, path: string, body = '', signer: Identity = context.identity) {
  const nonce = await challenge(context);
  const keyPair = { publicKey: await importJWK(signer.publicJwk, 'ES256') as webcrypto.CryptoKey,
    privateKey: await importJWK(signer.privateJwk, 'ES256') as webcrypto.CryptoKey };
  let proof = '';
  const handle = oauth.DPoP({}, keyPair, { [oauth.modifyAssertion]: (_header, payload) => {
    payload.nonce = nonce; payload.exp = (payload.iat as number) + 30;
    payload.stackey_body_hash = digest(body);
  } });
  let response: Response;
  try {
    response = await oauth.protectedResourceRequest(token, method, new URL(context.origin + path),
      new Headers({ 'content-type': 'application/json' }), method === 'POST' ? body : undefined,
      { DPoP: handle, [oauth.allowInsecureRequests]: true,
        [oauth.customFetch]: async (url, options) => {
          proof = new Headers(options.headers).get('dpop')!;
          return nodeFetch(url, { method: options.method, headers: options.headers,
            ...(method === 'POST' ? { body } : {}) });
        } });
  } catch { throw new AppError('node_unreachable', 'Node did not confirm the request.', 503, 4, 'node_unreachable'); }
  return verifiedResponse(context, response, digest(proof));
}

export async function liveStatus(dir: string) {
  const context = await agentContext(dir);
  return bootstrapRequest(context, 'GET', '/v1/pairings/' + context.pairingId);
}
export async function capabilities(dir: string) {
  const context = await agentContext(dir);
  return resourceRequest(context, await session(context), 'GET', '/v1/capabilities');
}
export async function runOrders(dir: string, action: string, input: unknown, operationId: string = randomUUID()) {
  if (action !== ACTION && !providerAction(action)) throw new AppError('action_not_available', 'Unsupported action.');
  if (!isUuid(operationId)) throw new AppError('invalid_operation_id', 'Use a UUID operation ID.');
  const params = action === ACTION ? orderParams(input) : providerParams(action, input);
  const context = await agentContext(dir);
  const token = await session(context);
  try {
    return await resourceRequest(context, token, 'POST', '/v1/operations',
      JSON.stringify({ operation_id: operationId, action, params }));
  } catch (error) {
    if (error instanceof AppError && error.exitCode === 4) {
      throw new AppError('operation_result_unknown', `Operation result could not be confirmed. Use operation ${operationId} to check this same request.`, 503, 4, 'result_unknown');
    }
    throw error;
  }
}
export async function operation(dir: string, id: string) {
  if (!isUuid(id)) throw new AppError('invalid_operation_id', 'Use a UUID operation ID.');
  const context = await agentContext(dir);
  return resourceRequest(context, await session(context), 'GET', '/v1/operations/' + id);
}
