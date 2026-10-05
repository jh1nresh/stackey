import type { AgentRequest } from './access.js';
import { AppError, digest, envelope, publicError, record, textField } from './contracts.js';
import type { Identity } from './identity.js';
import { consumeProof, event, type Grant, type ProofTime } from './policy.js';
import { providerParams, providerSchema } from './providers.js';
import type { Store } from './store.js';
import { vaultRequest } from './vault-client.js';

const inFlight = new Set<string>();
const pending = new Map<string, Promise<void>>();
export async function drainProviderOperations(nodeId: string) { await Promise.all([...pending].filter(([key])=>key.startsWith(nodeId+'/')).map(([,promise])=>promise)); }
export function operationState(store: Store, id: string) { return store.db.prepare('SELECT * FROM provider_operations WHERE operation_id=?').get(id); }
export async function dispatchProviderOperation(store: Store, node: Identity, request: AgentRequest, principal: string, proof: ProofTime, check: () => Grant, clock: () => number) {
  const route = request.path === '/v1/capabilities' ? 'capabilities' : request.method === 'POST' ? 'run' : 'operation';
  const grant = check(); let operationId = request.path.split('/').at(-1)!; let inputHash = ''; let params: Record<string, unknown> = {};
  if (route === 'run') {
    const body = record(JSON.parse(request.rawBody));
    if (Object.keys(body).sort().join(',') !== 'action,operation_id,params' || body.action !== grant.action) throw new AppError('action_not_allowed', 'Use the action approved in this grant.', 403, 3, 'permission_denied');
    operationId = textField(body.operation_id, 36);
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(operationId)) throw new AppError('invalid_operation_id', 'Use a UUID operation ID.');
    params = providerParams(grant.action, body.params); inputHash = digest(JSON.stringify({ action: grant.action, params }));
  }
  const key = node.id + '/' + operationId;
  let start = false; let previous: unknown;
  const accepted = store.transaction(() => {
    consumeProof(store, proof, clock()); const current = check();
    if (route === 'capabilities') return envelope('ok', { grant_id: current.grant_id, wallet_id: current.wallet_id, connection_id: current.connection_id, capabilities: [providerSchema(current.action)], max_calls: current.max_calls, max_amount_minor: current.max_amount_minor, currency: 'USD' });
    const existing = operationState(store, operationId);
    if (existing) {
      if (existing.principal !== principal || existing.grant_id !== current.grant_id) throw new AppError('permission_denied', 'Operation belongs to another grant.', 403, 3, 'permission_denied');
      if (existing.state === 'failed') {
        const payload = existing.result_json ? record(JSON.parse(String(existing.result_json))) : {};
        const err = payload.error ? record(payload.error) : {};
        throw new AppError(typeof err.code === 'string' ? err.code : 'permission_denied',
          typeof err.message === 'string' ? err.message : 'Website login is not enabled.', 403, 3, 'permission_denied');
      }
      if (route === 'run' && existing.input_hash !== inputHash) throw new AppError('operation_conflict', 'Operation ID belongs to different parameters.', 409);
      if (route === 'run' && existing.state === 'approval_required') {
        previous = JSON.parse(String(existing.result_json));
        store.db.prepare("UPDATE provider_operations SET state='executing' WHERE operation_id=?").run(operationId); start = true;
      } else {
        const state = existing.state === 'executing' ? inFlight.has(key) ? 'operation_pending' : 'result_unknown' : String(existing.state);
        return envelope(state === 'completed' ? 'ok' : state, { operation_id: operationId, state, replayed: true, result: existing.result_json ? JSON.parse(String(existing.result_json)) : null });
      }
    } else {
      if (route === 'operation') throw new AppError('operation_not_found', 'Operation was not found.', 404);
      // Reserve the full per-purchase budget before dispatch. Unknown, failed and
      // pending operations retain their reservation; no automatic refund or retry.
      const usage = store.db.prepare("SELECT COUNT(*) AS calls, COALESCE(SUM(reserved_minor),0) AS amount FROM provider_operations WHERE grant_id=? AND state!='failed'").get(current.grant_id)!;
      const reservation = current.action === 'stripe.mpp.pay' ? current.max_amount_minor : 0;
      if (Number(usage.calls) >= current.max_calls || Number(usage.amount) + reservation > current.max_amount_minor) throw new AppError('budget_exceeded', 'Grant call or payment budget is exhausted.', 403, 3, 'permission_denied');
      store.db.prepare('INSERT INTO provider_operations VALUES (?,?,?,?,?,?,?,?,NULL)').run(operationId, current.grant_id, principal, inputHash, current.action, clock(), 'executing', reservation);
      event(store, 'operation_dispatched', principal, operationId, clock()); start = true;
    }
    return envelope('operation_pending', { operation_id: operationId, state: 'operation_pending', replayed: false, next_step: `Use operation ${operationId} to check the result.` });
  });
  if (start) {
    inFlight.add(key);
    const dir = store.db.prepare("SELECT value FROM settings WHERE key='vault_dir'").get();
    // The vault owns every provider secret. The Node gets only a sanitized result.
    const task = (async () => {
      try {
        if (!dir) throw new AppError('node_locked', 'Provider operations require a bound unlocked vault.');
        const response = record(await vaultRequest(String(dir.value), 'provider.execute', { _node_dir: store.directory,
          grant_id: grant.grant_id, principal, action: grant.action, params, operation_id: operationId,
          ...(previous ? { previous } : {}) }));
        if (!['completed', 'approval_required'].includes(String(response.state))) throw new AppError('invalid_provider_response', 'Invalid provider state.');
        store.transaction(() => {
          // Record an already-dispatched outcome even after revoke/lock. Agent
          // reads still require its current grant, so no result leaks after revoke.
          store.db.prepare('UPDATE provider_operations SET state=?,result_json=? WHERE operation_id=?').run(String(response.state), JSON.stringify(response.result), operationId);
          event(store, response.state === 'completed' ? 'operation_completed' : 'payment_approval_required', principal, operationId, clock());
        });
      } catch (error) {
        const safe = publicError(error);
        const refused = grant.action === 'website.session.login' && safe.body.error.code === 'executor_unavailable';
        store.transaction(() => {
          store.db.prepare('UPDATE provider_operations SET state=?,result_json=? WHERE operation_id=?')
            .run(refused ? 'failed' : 'result_unknown', JSON.stringify({ error: safe.body.error }), operationId);
          event(store, refused ? 'operation_failed' : 'operation_result_unknown', principal, operationId, clock());
        });
      } finally { inFlight.delete(key); pending.delete(key); }
    })();
    pending.set(key,task);
  }
  return accepted;
}
