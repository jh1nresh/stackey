import { randomUUID } from 'node:crypto';
import { calculateJwkThumbprint, decodeProtectedHeader, importJWK, jwtVerify, SignJWT } from 'jose';
import { AppError, digest, displayName, endpoint, INVITE_TYPE, PROOF_TYPE, RECEIPT_TYPE, record, textField } from './contracts.js';
import { publicKey, type Identity } from './identity.js';
import { Store, type Pairing } from './store.js';

export interface Invitation {
  endpoint: string;
  node: Identity['publicJwk'];
  token: string;
}

const nowSeconds = () => Math.floor(Date.now() / 1000);

export async function issueInvitation(store: Store, identity: Identity, ttl: number, now = nowSeconds()): Promise<string> {
  if (!Number.isInteger(ttl) || ttl < 30 || ttl > 900) {
    throw new AppError('invalid_ttl', 'Invitation lifetime must be 30–900 seconds.');
  }
  const origin = endpoint(store.getEndpoint());
  const id = randomUUID();
  const token = await new SignJWT({ purpose: 'pairing-only', endpoint: origin })
    .setProtectedHeader({ alg: 'EdDSA', typ: INVITE_TYPE })
    .setIssuer(identity.id).setAudience(identity.id).setJti(id)
    .setIssuedAt(now).setExpirationTime(now + ttl)
    .sign(await importJWK(identity.privateJwk, 'EdDSA'));
  store.addInvite(id, digest(token), now + ttl);
  const invite: Invitation = { endpoint: origin, node: identity.publicJwk, token };
  return 'stackey-invite-v1.' + Buffer.from(JSON.stringify(invite)).toString('base64url');
}

export async function parseInvitation(input: string, now = nowSeconds()) {
  textField(input, 8192);
  if (!/^stackey-invite-v1\.[A-Za-z0-9_-]+$/.test(input)) {
    throw new AppError('invalid_invitation', 'Invalid invitation format.');
  }
  let decoded: unknown;
  try { decoded = JSON.parse(Buffer.from(input.slice('stackey-invite-v1.'.length), 'base64url').toString()); }
  catch { throw new AppError('invalid_invitation', 'Invalid invitation format.'); }
  const value = record(decoded);
  const origin = endpoint(value.endpoint);
  const node = publicKey(value.node, 'EdDSA');
  const token = textField(value.token);
  const nodeId = await calculateJwkThumbprint(node);
  let verified;
  try {
    verified = await jwtVerify(token, await importJWK(node, 'EdDSA'), {
      algorithms: ['EdDSA'], typ: INVITE_TYPE, issuer: nodeId, audience: nodeId,
      requiredClaims: ['iat', 'exp', 'jti'], currentDate: new Date(now * 1000),
    });
  } catch { throw new AppError('invalid_invitation', 'Invitation signature or expiry is invalid.', 403, 3, 'permission_denied'); }
  if (verified.payload.purpose !== 'pairing-only' || verified.payload.endpoint !== origin ||
      typeof verified.payload.iat !== 'number' || typeof verified.payload.exp !== 'number' ||
      verified.payload.iat > now || verified.payload.exp - verified.payload.iat > 900) {
    throw new AppError('invalid_invitation', 'Invitation binding is invalid.', 403, 3, 'permission_denied');
  }
  return { endpoint: origin, node, token, nodeId, invitationId: textField(verified.payload.jti, 64) };
}

export async function makePairingProof(invite: Awaited<ReturnType<typeof parseInvitation>>, agent: Identity, name: string, now = nowSeconds()) {
  const jti = randomUUID();
  const proof = await new SignJWT({
    purpose: 'pairing-request', invitation_hash: digest(invite.token),
    invitation_id: invite.invitationId, display_name: displayName(name),
    method: 'POST', uri: invite.endpoint + '/v1/pairings',
  }).setProtectedHeader({ alg: 'ES256', typ: PROOF_TYPE, jwk: agent.publicJwk })
    .setIssuer(agent.id).setAudience(invite.nodeId).setJti(jti)
    .setIssuedAt(now).setExpirationTime(now + 30)
    .sign(await importJWK(agent.privateJwk, 'ES256'));
  return { proof, jti };
}

export async function acceptPairing(store: Store, node: Identity, origin: string, input: unknown, clock = nowSeconds) {
  const now = clock();
  const body = record(input);
  if (Object.keys(body).sort().join(',') !== 'invitation,proof') {
    throw new AppError('invalid_request', 'Expected invitation and proof only.');
  }
  const token = textField(body.invitation);
  const proof = textField(body.proof, 8192);
  let invitePayload;
  try {
    invitePayload = (await jwtVerify(token, await importJWK(node.publicJwk, 'EdDSA'), {
      algorithms: ['EdDSA'], typ: INVITE_TYPE, issuer: node.id, audience: node.id,
      requiredClaims: ['iat', 'exp', 'jti'], currentDate: new Date(now * 1000),
    })).payload;
  } catch { throw new AppError('invalid_invitation', 'Invitation is invalid or expired.', 403, 3, 'permission_denied'); }
  if (invitePayload.purpose !== 'pairing-only' || invitePayload.endpoint !== origin) {
    throw new AppError('invalid_invitation', 'Invitation is not valid for this Node endpoint.', 403, 3, 'permission_denied');
  }
  let publicJwk;
  let principal;
  let claims;
  try {
    const header = decodeProtectedHeader(proof);
    publicJwk = publicKey(header.jwk, 'ES256');
    principal = await calculateJwkThumbprint(publicJwk);
    claims = (await jwtVerify(proof, await importJWK(publicJwk, 'ES256'), {
      algorithms: ['ES256'], typ: PROOF_TYPE, issuer: principal, audience: node.id,
      requiredClaims: ['iat', 'exp', 'jti'], currentDate: new Date(now * 1000),
    })).payload;
    if (claims.purpose !== 'pairing-request' || claims.invitation_hash !== digest(token) ||
        claims.invitation_id !== invitePayload.jti || claims.method !== 'POST' ||
        claims.uri !== origin + '/v1/pairings' ||
        typeof claims.iat !== 'number' || !Number.isInteger(claims.iat) ||
        typeof claims.exp !== 'number' || !Number.isInteger(claims.exp) ||
        claims.iat > now || now - claims.iat > 30 || claims.exp - claims.iat > 30) {
      throw new Error('Invalid proof binding');
    }
  } catch { throw new AppError('invalid_proof', 'Pairing proof is invalid.', 403, 3, 'permission_denied'); }
  const pairing: Pairing = {
    pairing_id: randomUUID(), principal, public_jwk: JSON.stringify(publicJwk),
    display_name: displayName(claims.display_name), created_at: now, status: 'approval_required',
  };
  const proofJti = textField(claims.jti, 64);
  const acceptedAt = store.consumeInvite(
    textField(invitePayload.jti, 64), digest(token),
    { jti: proofJti, issuedAt: claims.iat as number, expiresAt: claims.exp as number }, pairing, clock,
  );
  return new SignJWT({
    purpose: 'pairing-receipt', pairing_id: pairing.pairing_id,
    principal, display_name: pairing.display_name, status: pairing.status,
    proof_jti: proofJti, created_at: acceptedAt,
  }).setProtectedHeader({ alg: 'EdDSA', typ: RECEIPT_TYPE })
    .setIssuer(node.id).setAudience(principal).setIssuedAt(acceptedAt).setExpirationTime(acceptedAt + 30)
    .sign(await importJWK(node.privateJwk, 'EdDSA'));
}
