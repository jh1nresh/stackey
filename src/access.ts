import { vaultRequest } from './vault-client.js';
import { randomUUID } from 'node:crypto';
import { calculateJwkThumbprint, decodeJwt, decodeProtectedHeader, importJWK, jwtVerify, SignJWT, type JWTPayload } from 'jose';
import * as oauth from 'oauth4webapi';
import { AppError, digest, envelope, record, textField } from './contracts.js';
import { publicKey, type Identity } from './identity.js';
import { ACTION, ORDER_SCHEMA, orderParams, readOrders, requireDemo } from './orders.js';
import { consumeProof, denied, event, grantForPairing, proofTime, requireGrant, verifyGrant,
  type Grant, type ProofTime } from './policy.js';
import { dispatchProviderOperation } from './provider-operations.js';
import type { Store } from './store.js';

export const BOOTSTRAP_TYPE = 'stackey-request+jwt';
export const RESPONSE_TYPE = 'stackey-response+jwt';
export const issuer = (nodeId: string) => `urn:stackey:node:${nodeId}`;
export const isUuid = (value: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);

export async function signedResponse(node: Identity, body: unknown, requestHash: string, now: number) {
  return new SignJWT({ body, request_hash: requestHash })
    .setProtectedHeader({ alg: 'EdDSA', typ: RESPONSE_TYPE }).setIssuer(node.id).setAudience('stackey-cli')
    .setIssuedAt(now).setExpirationTime(now + 30).sign(await importJWK(node.privateJwk, 'EdDSA'));
}

interface VerifiedRequest { principal: string; proof: ProofTime; grant?: Grant; session?: JWTPayload }
export interface AgentRequest { method: string; path: string; rawBody: string; proof: string; authorization?: string }

async function bootstrap(store: Store, node: Identity, origin: string, request: AgentRequest, now: number): Promise<VerifiedRequest> {
  try {
    const header = decodeProtectedHeader(request.proof);
    if (header.alg !== 'ES256') throw new Error('Wrong algorithm');
    const key = publicKey(header.jwk, 'ES256');
    const principal = await calculateJwkThumbprint(key);
    const { payload } = await jwtVerify(request.proof, await importJWK(key, 'ES256'), {
      algorithms: ['ES256'], typ: BOOTSTRAP_TYPE, issuer: principal, audience: node.id,
      currentDate: new Date(now * 1000), requiredClaims: ['iat', 'exp', 'jti'],
    });
    if (payload.htm !== request.method || payload.htu !== origin + request.path ||
        payload.body_hash !== digest(request.rawBody) || payload.purpose !== 'agent-bootstrap') throw new Error('Binding');
    const pairing = store.db.prepare('SELECT 1 FROM pairings WHERE principal = ?').get(principal);
    if (!pairing) throw new Error('Unpaired');
    return { principal, proof: proofTime(payload, now) };
  } catch { denied('invalid_proof', 'Registered agent key and a valid request proof are required.'); }
}

async function resource(store: Store, node: Identity, origin: string, request: AgentRequest, now: number): Promise<VerifiedRequest> {
  let claims: oauth.JWTAccessTokenClaims;
  let proof: ProofTime;
  try {
    const header = decodeProtectedHeader(request.proof);
    if (header.alg !== 'ES256') throw new Error('Wrong proof algorithm');
    publicKey(header.jwk, 'ES256');
    claims = await oauth.validateJwtAccessToken(
      { issuer: issuer(node.id), jwks_uri: 'https://stackey.invalid/jwks' },
      new Request(origin + request.path, { method: request.method,
        headers: { authorization: request.authorization ?? '', dpop: request.proof } }), node.id,
      { requireDPoP: true, signingAlgorithms: ['EdDSA', 'ES256'],
        [oauth.clockTolerance]: 0, [oauth.clockSkew]: now - Math.floor(Date.now() / 1000),
        // Pinned local Node key. This does not fetch a URL or caller-supplied JWKS.
        [oauth.customFetch]: async () => new Response(JSON.stringify({ keys: [node.publicJwk] }),
          { headers: { 'content-type': 'application/json' } }),
      });
    const payload = decodeJwt(request.proof); // Signature already verified by oauth4webapi.
    if (payload.stackey_body_hash !== digest(request.rawBody) ||
        payload.htu !== origin + request.path || claims.client_id !== claims.sub ||
        record(claims.cnf).jkt !== claims.sub) throw new Error('Binding');
    proof = proofTime(payload, now);
  } catch { denied('invalid_session_proof', 'A valid Node session and matching DPoP proof are required.'); }
  const grant = requireGrant(store, textField(claims.grant_id, 64), claims.sub, now);
  await verifyGrant(store, node, grant, now);
  if (claims.grant_version !== grant.version) denied('grant_revoked', 'Session policy version is no longer current.');
  return { principal: claims.sub, proof, grant, session: claims };
}

function checkSession(store: Store, input: VerifiedRequest, now: number): Grant {
  const session = input.session!;
  const grant = requireGrant(store, input.grant!.grant_id, input.principal, now);
  const row = store.db.prepare('SELECT * FROM sessions WHERE session_id = ?').get(textField(session.jti, 64));
  if (!row || row.grant_id !== grant.grant_id || row.principal !== input.principal ||
      row.version !== grant.version || (row.expires_at as number) <= now ||
      (session.exp as number) <= now || session.grant_version !== grant.version ||
      grant.signed_grant !== input.grant!.signed_grant) denied('invalid_session', 'Session is expired or no longer authorized.');
  if (grant.action === ACTION) requireDemo(store);
  return grant;
}

export async function agentAction(store: Store, node: Identity, origin: string, request: AgentRequest, clock: () => number) {
  const now = clock();
  if (request.path === '/v1/challenges' && request.method === 'POST') {
    const input = record(JSON.parse(request.rawBody));
    if (Object.keys(input).join(',') !== 'request_id' || !isUuid(textField(input.request_id, 36))) {
      throw new AppError('invalid_challenge', 'Expected one UUID request_id.');
    }
    const nonce = randomUUID();
    store.db.prepare('INSERT INTO challenges VALUES (?, ?, NULL)').run(nonce, now + 30);
    return envelope('ok', { nonce, expires_at: now + 30 });
  }
  if ((request.path === '/v1/sessions' && request.method === 'POST') ||
      (/^\/v1\/pairings\/[0-9a-f-]{36}$/.test(request.path) && request.method === 'GET')) {
    const input = await bootstrap(store, node, origin, request, now);
    const body = request.method === 'POST' ? record(JSON.parse(request.rawBody)) : undefined;
    const pairingId = request.method === 'POST' ? textField(body!.pairing_id, 36) : request.path.split('/').at(-1)!;
    if (!isUuid(pairingId) || (body && Object.keys(body).join(',') !== 'pairing_id')) throw new AppError('invalid_request', 'Expected one pairing ID.');
    const pairing = store.db.prepare('SELECT * FROM pairings WHERE pairing_id = ? AND principal = ?').get(pairingId, input.principal);
    if (!pairing) denied('permission_denied', 'This pairing does not belong to the requesting key.');
    const grant = grantForPairing(store, pairingId);
    if (request.method === 'GET') {
      if (grant && grant.revoked_at === null && grant.expires_at > now) await verifyGrant(store, node, grant, now);
      return store.transaction(() => {
        consumeProof(store, input.proof, clock());
        const current = grantForPairing(store, pairingId);
        const status = !current ? 'approval_required' : current.revoked_at !== null ? 'grant_revoked' :
          current.expires_at <= clock() ? 'grant_expired' : 'active';
        if (status === 'active' && (!grant || current!.signed_grant !== grant.signed_grant || current!.version !== grant.version)) {
          denied('policy_changed', 'Policy changed during verification; request current status again.');
        }
        return envelope(status, { pairing_id: pairingId, principal: input.principal,
          grant_id: current?.grant_id ?? null, expires_at: current?.expires_at ?? null,
          granted_actions: status === 'active' ? [current!.action] : [], source: 'live_node' });
      });
    }
    if (!grant) denied('permission_denied', 'Owner approval is required before requesting a session.');
    const vault = store.db.prepare("SELECT value FROM settings WHERE key='vault_dir'").get();
    if (vault) await vaultRequest(String(vault.value), 'status');
    requireGrant(store, grant.grant_id, input.principal, now);
    await verifyGrant(store, node, grant, now);
    if (grant.action === ACTION) requireDemo(store);
    const sessionId = randomUUID();
    const expires = Math.min(now + 60, grant.expires_at);
    const token = await new SignJWT({ client_id: input.principal, cnf: { jkt: input.principal },
      grant_id: grant.grant_id, grant_version: grant.version })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'at+jwt' }).setIssuer(issuer(node.id))
      .setAudience(node.id).setSubject(input.principal).setJti(sessionId).setIssuedAt(now).setExpirationTime(expires)
      .sign(await importJWK(node.privateJwk, 'EdDSA'));
    return store.transaction(() => {
      const current = clock();
      consumeProof(store, input.proof, current);
      const active = requireGrant(store, grant.grant_id, input.principal, current);
      if (expires <= current || active.version !== grant.version || active.signed_grant !== grant.signed_grant) {
        denied('invalid_session', 'Policy changed or the session expired before acceptance.');
      }
      store.db.prepare('INSERT INTO sessions VALUES (?, ?, ?, ?, ?)')
        .run(sessionId, grant.grant_id, input.principal, expires, grant.version);
      return envelope('ok', { access_token: token, token_type: 'DPoP', expires_at: expires });
    });
  }
  const route = request.path === '/v1/capabilities' && request.method === 'GET' ? 'capabilities' :
    request.path === '/v1/operations' && request.method === 'POST' ? 'run' :
    /^\/v1\/operations\/[0-9a-f-]{36}$/.test(request.path) && request.method === 'GET' ? 'operation' : undefined;
  if (!route) throw new AppError('route_not_available', 'Route is not available.', 404);
  const vault = store.db.prepare("SELECT value FROM settings WHERE key='vault_dir'").get();
  if (vault) await vaultRequest(String(vault.value), 'status');
  const input = await resource(store, node, origin, request, now);
  if (input.grant!.action !== ACTION) {
    return dispatchProviderOperation(store, node, request, input.principal, input.proof, () => checkSession(store, input, clock()), clock);
  }
  let operationId = ''; let inputHash = ''; let params;
  if (route === 'run') {
    const body = record(JSON.parse(request.rawBody));
    if (Object.keys(body).sort().join(',') !== 'action,operation_id,params' || body.action !== ACTION) {
      denied('action_not_allowed', 'Only the approved demo.orders.read action is allowed.');
    }
    operationId = textField(body.operation_id, 36);
    if (!isUuid(operationId)) throw new AppError('invalid_operation_id', 'Use a UUID operation ID.');
    params = orderParams(body.params);
    inputHash = digest(JSON.stringify({ action: ACTION, params }));
  }
  return store.transaction(() => {
    const current = clock();
    consumeProof(store, input.proof, current);
    const grant = checkSession(store, input, current);
    if (route === 'capabilities') return envelope('ok', { grant_id: grant.grant_id, wallet_id: grant.wallet_id, capabilities: [ORDER_SCHEMA] });
    if (route === 'operation') operationId = request.path.split('/').at(-1)!;
    const previous = store.db.prepare('SELECT * FROM operations WHERE operation_id = ?').get(operationId);
    if (previous) {
      if (previous.principal !== input.principal || previous.grant_id !== grant.grant_id) denied('permission_denied', 'Operation belongs to another grant.');
      if (route === 'run' && previous.input_hash !== inputHash) throw new AppError('operation_conflict', 'Operation ID already belongs to different parameters.', 409);
      return envelope('ok', { operation_id: operationId, result: JSON.parse(previous.result_json as string), replayed: true });
    }
    if (route === 'operation') throw new AppError('operation_not_found', 'Operation was not found.', 404);
    // Synchronous local adapter and result are inside the same policy transaction.
    const result = readOrders(store, params!);
    store.db.prepare('INSERT INTO operations VALUES (?, ?, ?, ?, ?, ?)')
      .run(operationId, grant.grant_id, input.principal, inputHash, current, JSON.stringify(result));
    event(store, 'operation_completed', input.principal, operationId, current);
    return envelope('ok', { operation_id: operationId, result, replayed: false });
  });
}
