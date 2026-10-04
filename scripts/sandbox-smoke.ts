import { strict as assert } from 'node:assert';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { agentContext, operation, resourceRequest, runOrders, session } from '../src/agent-client.js';
import { connect } from '../src/client.js';
import { AppError, record, textField } from '../src/contracts.js';
import { loadIdentity, readPrivateJson } from '../src/identity.js';
import { startNode } from '../src/node.js';
import { issueInvitation } from '../src/pairing.js';
import { drainProviderOperations } from '../src/provider-operations.js';
import { Store } from '../src/store.js';
import { initializeVault } from '../src/vault.js';
import { vaultRequest } from '../src/vault-client.js';
import { unlockVault } from '../src/vault-session.js';

async function main() {
  const { values } = parseArgs({ options: { provider: { type: 'string' }, 'secret-file': { type: 'string' }, 'project-ref': { type: 'string' }, model: { type: 'string' } }, strict: true });
  const provider = textField(values.provider, 20); if (!['supabase','vercel','stripe'].includes(provider)) throw new AppError('invalid_provider','Use supabase, vercel or stripe.');
  const secret = textField(record(readPrivateJson(resolve(textField(values['secret-file'])))).value, 16384);
  const root = mkdtempSync(join(tmpdir(),'stackey-sandbox-smoke-')); const nodeDir=join(root,'node'); const dir=join(root,'vault'); const seed=join(root,'recovery.json');
  await initializeVault(dir,seed);const identity=await loadIdentity(nodeDir,'node',true);const store=new Store(nodeDir);const node=await startNode(nodeDir,0);const vault=await unlockVault(dir,seed,nodeDir);
  try {
    const owner={_node_dir:resolve(nodeDir)};await vaultRequest(dir,'node.bind',owner);
    const key=await vaultRequest(dir,'credential.import',{wallet_id:'wallet_demo',name:'Sandbox only',kind:'api_key',value:secret});
    const config=provider==='supabase'?{project_ref:textField(values['project-ref'],20),credential_id:key.id}:provider==='vercel'?{model:textField(values.model,120),credential_id:key.id}:{mode:'payments',credential_id:key.id};
    const connection=await vaultRequest(dir,'connection.add',{wallet_id:'wallet_demo',name:'Sandbox',provider,config});
    const agent=join(root,'agent');const invite=await issueInvitation(store,identity,300);const pairing=record((await connect(invite,agent,'Sandbox Agent')).data);
    const action=provider==='supabase'?'supabase.orders.read':provider==='vercel'?'vercel.ai.generate':'stripe.payments.read';
    const grant=await vaultRequest(dir,'grant.approve',{...owner,pairing_id:pairing.pairing_id,principal:pairing.principal,action,ttl:900,wallet_id:'wallet_demo',connection_id:connection.id,max_calls:1,max_amount_minor:0});
    const context=await agentContext(agent);const token=await session(context);const id=randomUUID();
    const params=provider==='supabase'?{from:'2026-09-26',to:'2026-10-02'}:provider==='vercel'?{prompt:'Summarize this synthetic store in one sentence: 21 orders, 14 paid, 7 failed; paid totals USD 91 and TWD 2310. No customer data.'}:{};
    await runOrders(agent,action,params,id);await drainProviderOperations(node.nodeId);const result=await operation(agent,id);
    assert.equal(result.status,'ok',JSON.stringify(result));const output=record(record(result.data).result);
    if(provider==='supabase') {assert.equal((output.rows as unknown[]).length,21);assert.equal(output.complete,true);}
    await vaultRequest(dir,'grant.revoke',{...owner,grant_id:grant.grant_id});
    await assert.rejects(resourceRequest(context,token,'GET','/v1/capabilities'),error=>error instanceof AppError&&error.code==='grant_revoked');
    console.log(JSON.stringify({status:'passed',provider,operation_id:id,source:output.source,rows:Array.isArray(output.rows)?output.rows.length:undefined,usage:output.usage,summary:output.text,revocation:'existing_session_denied',secrets_exported:false}));
  } finally {await node.close();await vault.close();store.close();rmSync(root,{recursive:true});}
}
main().catch(error=>{console.error(error instanceof AppError?JSON.stringify({status:error.status,error:error.code}):JSON.stringify({status:'failed',error:'sandbox_verification_failed'}));process.exitCode=1;});
