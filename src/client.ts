import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { importJWK, jwtVerify } from 'jose';
import { AppError, envelope, RECEIPT_TYPE, record, textField } from './contracts.js';
import { loadIdentity, privateDirectory, readPrivateJson, writePrivateJson } from './identity.js';
import { makePairingProof, parseInvitation } from './pairing.js';

export async function connect(invitation: string, dir: string, name: string) {
  // Verify the trusted invitation, including its endpoint, before any network request.
  const invite = await parseInvitation(invitation);
  const safeDir = privateDirectory(dir);
  const receiptPath = join(safeDir, 'pairing.json');
  if (existsSync(receiptPath)) throw new AppError('already_paired', 'This state directory already has a pairing; use status or a separate environment.');
  const identity = await loadIdentity(safeDir, 'agent', true);
  const { proof, jti } = await makePairingProof(invite, identity, name);
  let response: Response;
  try {
    response = await fetch(invite.endpoint + '/v1/pairings', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ invitation: invite.token, proof }),
      redirect: 'error', signal: AbortSignal.timeout(5000),
    });
  } catch {
    throw new AppError('pairing_result_unknown', 'Pairing could not be confirmed. Check the Node pairing list before attempting another invitation.', 503, 4, 'result_unknown');
  }
  let body;
  try {
    if (!response.body) throw new Error('Empty body');
    const reader = response.body.getReader();
    let size = 0;
    const chunks: Uint8Array[] = [];
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.length;
      if (size > 16_384) { await reader.cancel(); throw new Error('Oversized response'); }
      chunks.push(chunk.value);
    }
    body = record(JSON.parse(Buffer.concat(chunks).toString()));
  } catch { throw new AppError('invalid_node_response', 'Unable to verify Node response; check its pairing list.', 502, 4, 'result_unknown'); }
  if (!response.ok) {
    // Unverified response messages are never reflected into agent output.
    throw new AppError('pairing_rejected', 'Node rejected the pairing request; no service access was granted.', response.status, 3, 'permission_denied');
  }
  let claims;
  try {
    const data = record(body.data);
    const receipt = textField(data.receipt, 8192);
    claims = (await jwtVerify(receipt, await importJWK(invite.node, 'EdDSA'), {
      algorithms: ['EdDSA'], typ: RECEIPT_TYPE, issuer: invite.nodeId, audience: identity.id,
      requiredClaims: ['iat', 'exp'],
    })).payload;
    if (claims.purpose !== 'pairing-receipt' || claims.status !== 'approval_required' ||
        claims.proof_jti !== jti || claims.principal !== identity.id ||
        claims.display_name !== name || typeof claims.created_at !== 'number') {
      throw new Error('Invalid receipt');
    }
    textField(claims.pairing_id, 64);
  } catch { throw new AppError('invalid_node_receipt', 'Node identity or pairing receipt could not be verified; check its pairing list.', 502, 4, 'result_unknown'); }
  const pairing = {
    node_id: invite.nodeId, node_public_jwk: invite.node, endpoint: invite.endpoint,
    principal: identity.id, pairing_id: claims.pairing_id, display_name: name,
    created_at: claims.created_at, status: 'approval_required',
  };
  try { writePrivateJson(receiptPath, pairing); }
  catch { throw new AppError('receipt_not_saved', 'Node accepted the pairing, but local state could not be saved. Check its pairing list.', 500, 4, 'result_unknown'); }
  return envelope('approval_required', {
    ...pairing, granted_actions: [], next_step: 'Ask the owner to approve this full public-key fingerprint; use status --live to check the current grant.',
  });
}

export async function localStatus(dir: string) {
  const safeDir = privateDirectory(dir);
  const path = join(safeDir, 'pairing.json');
  if (!existsSync(path)) return envelope('unpaired', { granted_actions: [] });
  const value = record(readPrivateJson(path));
  const identity = await loadIdentity(safeDir, 'agent');
  if (value.principal !== identity.id || value.status !== 'approval_required') {
    throw new AppError('invalid_state', 'Pairing state does not match this local identity.');
  }
  return envelope('approval_required', {
    pairing_id: textField(value.pairing_id, 64), principal: identity.id,
    node_id: textField(value.node_id, 64), display_name: textField(value.display_name, 64),
    granted_actions: [], source: 'local_pairing_receipt',
    next_step: 'This is a local pairing receipt. Use status --live to check current owner approval and service access.',
  });
}
