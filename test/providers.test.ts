import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test, type TestContext } from 'node:test';
import Stripe from 'stripe';
import { Challenge, Credential } from 'mppx';
import { agentContext, operation, resourceRequest, runOrders, session } from '../src/agent-client.js';
import { connect } from '../src/client.js';
import { AppError } from '../src/contracts.js';
import { loadIdentity } from '../src/identity.js';
import { createMerchant } from '../src/mpp-merchant.js';
import { payMpp, type LinkCall, type PaymentContinuation } from '../src/mpp-payment.js';
import { assertLinkSpendRequestArgs } from './link-cli-schema.js';
import { startNode } from '../src/node.js';
import { issueInvitation } from '../src/pairing.js';
import { drainProviderOperations } from '../src/provider-operations.js';
import { connectionConfig, executeProvider, providerParams, type ProviderFetch } from '../src/providers.js';
import { Store } from '../src/store.js';
import { initializeVault, type Connection, type VaultData } from '../src/vault.js';
import { vaultRequest } from '../src/vault-client.js';
import { unlockVault } from '../src/vault-session.js';

const wallet='wallet_demo'; const credential='credential_'+randomUUID();
const data:VaultData={wallets:[{id:wallet,name:'Test',connections:[]}],credentials:[{id:credential,wallet_id:wallet,name:'Test API',kind:'api_key',value:'sk_test_fixture'}],connections:[],requests:[]};
const schemaLink=(handler:LinkCall):LinkCall=>async(token,args)=>{assertLinkSpendRequestArgs(args);return handler(token,args);};
const connection=(provider:Connection['provider'],config:Record<string,unknown>):Connection=>({id:'connection_'+randomUUID(),wallet_id:wallet,provider,name:'Fixture',config});
const supabase=connection('supabase',{project_ref:'abcdefghijklmnopqrst',credential_id:credential});
const payment=connection('stripe',{mode:'mpp',endpoint:'https://stackey-sandbox.vercel.app/api/paid-report',network_id:'profile_test_fixture',credential_id:credential,payment_method_id:'pm_fixture',amount_minor:50});

test('Link spend-request mock rejects flags outside the 0.25.1 CLI schema',()=>{
  assert.doesNotThrow(()=>assertLinkSpendRequestArgs(['spend-request','request-approval','sr_fixture']));
  assert.doesNotThrow(()=>assertLinkSpendRequestArgs(['spend-request','retrieve','sr_fixture','--include','shared_payment_token','--interval','0','--max-attempts','1']));
  assert.throws(()=>assertLinkSpendRequestArgs(['spend-request','request-approval','sr_fixture','--interval','0','--max-attempts','1']));
  assert.throws(()=>assertLinkSpendRequestArgs(['spend-request','create','--interval','0']));
});
test('provider configurations reject arbitrary destinations, cross-wallet credentials, extra config and live Stripe mode',()=>{
  assert.deepEqual(connectionConfig('supabase',supabase.config,data,wallet),supabase.config);
  for(const config of [{...supabase.config,url:'http://127.0.0.1'},{...supabase.config,project_ref:'../bad'},supabase.config]){
    assert.throws(()=>connectionConfig('supabase',config,data,config===supabase.config?'wallet_'+randomUUID():wallet));
  }
  for(const endpoint of ['http://127.0.0.1/api/paid-report','https://evil.com/api/paid-report','https://foo.vercel.app/api/paid-report?key=x','https://foo.vercel.app:444/api/paid-report'])assert.throws(()=>connectionConfig('stripe',{...payment.config,endpoint},data,wallet));
  assert.throws(()=>connectionConfig('stripe',{...payment.config,amount_minor:51},data,wallet));
  assert.throws(()=>connectionConfig('stripe',{...payment.config,amount_minor:1000},data,wallet));
  assert.throws(()=>connectionConfig('stripe',{mode:'payments',credential_id:credential},{...data,credentials:[{...data.credentials[0]!,value:'sk_live_fixture'}]},wallet));
  assert.throws(()=>providerParams('stripe.mpp.pay',{amount:1}));assert.throws(()=>providerParams('vercel.ai.generate',{prompt:'x',model:'other/model'}));
});
test('Supabase REST adapter uses fixed columns, bounded keyset pagination and rejects filter injection',async()=>{
  let requests=0;
  const transport:ProviderFetch=async(input,init)=>{
    requests++;const url=new URL(String(input));assert.equal(url.origin,'https://abcdefghijklmnopqrst.supabase.co');assert.equal(url.pathname,'/rest/v1/stackey_demo_orders');
    assert.equal(url.searchParams.get('select'),'id,created_at,currency,amount_minor,payment_status');assert.equal(init!.redirect,'error');assert.equal(new Headers(init!.headers).get('apikey'),'fixture-secret');
    return Response.json(Array.from({length:101},(_,i)=>({id:'order_'+String(i).padStart(3,'0'),created_at:'2026-10-01T12:00:00+00:00',currency:'USD',amount_minor:100,payment_status:'paid'})));
  };
  const result=await executeProvider(supabase,'supabase.orders.read',{from:'2026-10-01',to:'2026-10-01'},'fixture-secret',transport) as any;
  assert.equal(result.rows.length,100);assert.equal(result.complete,false);assert.equal(result.next_cursor,'2026-10-01T12:00:00.000Z|order_099');
  await executeProvider(supabase,'supabase.orders.read',{from:'2026-10-01',to:'2026-10-01',cursor:result.next_cursor},'fixture-secret',transport);
  await assert.rejects(executeProvider(supabase,'supabase.orders.read',{from:'2026-10-01',to:'2026-10-01',cursor:'bad),id.gt.secret'},'fixture-secret',transport));assert.equal(requests,2);
});
test('Vercel adapter runs the real AI SDK Gateway transport with a fixed model, bounded tokens and no retries',async()=>{
  const gateway=connection('vercel',{credential_id:credential,model:'openai/gpt-4.1-mini'});let requests=0;
  const transport:ProviderFetch=async(input,init)=>{
    requests++;assert.ok(String(input).startsWith('https://ai-gateway.vercel.sh/'));assert.equal(new Headers(init!.headers).get('authorization'),'Bearer fixture-gateway-secret');
    const body=JSON.parse(String(init!.body));assert.equal(body.maxOutputTokens,1024);
    return Response.json({content:[{type:'text',text:'Fixture analysis'}],finishReason:{unified:'stop',raw:'stop'},usage:{inputTokens:{total:10,noCache:10,cacheRead:0,cacheWrite:0},outputTokens:{total:5,text:5,reasoning:0}},warnings:[]});
  };
  const result=await executeProvider(gateway,'vercel.ai.generate',{prompt:'Summarize synthetic orders.'},'fixture-gateway-secret',transport) as any;
  assert.equal(requests,1);assert.equal(result.text,'Fixture analysis');assert.equal(result.usage.input_tokens,10);assert.ok(!JSON.stringify(result).includes('fixture-gateway-secret'));
  const failing:ProviderFetch=async()=>{requests++;return Response.json({error:{message:'provider failed'}},{status:503});};
  await assert.rejects(executeProvider(gateway,'vercel.ai.generate',{prompt:'x'},'fixture-gateway-secret',failing));assert.equal(requests,2);
});
test('Stripe read adapter strips customer, metadata and payment credentials, and refuses live data',async()=>{
  const stripe=connection('stripe',{mode:'payments',credential_id:credential});
  const transport:ProviderFetch=async(input)=>{assert.equal(new URL(String(input)).hostname,'api.stripe.com');return Response.json({object:'list',has_more:false,data:[{id:'pi_fixture',livemode:false,created:1790812800,currency:'usd',amount:50,status:'requires_payment_method',customer:'private-customer',metadata:{secret:'private'},last_payment_error:{code:'card_declined',message:'private'}}]});};
  const result=await executeProvider(stripe,'stripe.payments.read',{},'sk_test_fixture',transport) as any;assert.equal(result.rows[0].failure_code,'card_declined');assert.ok(!JSON.stringify(result).includes('private'));
  await assert.rejects(executeProvider(stripe,'stripe.payments.read',{},'sk_live_fixture',transport));
  const live:ProviderFetch=async()=>Response.json({object:'list',data:[{id:'pi_live',livemode:true}],has_more:false});await assert.rejects(executeProvider(stripe,'stripe.payments.read',{},'sk_test_fixture',live));
});

async function merchantFixture(){
  let charges=0;const requests=new Map<string,unknown>();
  const client=new Stripe('sk_test_fixture');
  client.paymentIntents.create=(async(_params:unknown,options:Record<string,unknown>)=>{const key=String(options.idempotencyKey);if(!requests.has(key)){requests.set(key,true);charges++;}return {id:'pi_fixture',status:'succeeded',lastResponse:{headers:{}}};}) as any;
  const handler=createMerchant('sk_test_fixture','profile_test_fixture',client);
  const transport:ProviderFetch=async(input,init)=>handler(new Request(String(input),init));
  return {handler,transport,charges:()=>charges};
}
test('real mppx challenge -> Link approval continuation -> SPT payment returns a bound receipt without exposing credentials',async()=>{
  const merchant=await merchantFixture();const operationId=randomUUID();let creates=0;let requested=0;
  const link=schemaLink(async(token,args)=>{assert.equal(token,'fixture-link-token');if(args[1]==='create'){creates++;assert.ok(args.includes('--test'));assert.ok(!args.includes('--request-approval'));assert.equal(args[args.indexOf('--amount')+1],'50');return {id:'sr_fixture',status:'created'};}
    if(args[1]==='request-approval'){requested++;assert.deepEqual(args,['spend-request','request-approval','sr_fixture']);return {id:'sr_fixture',status:'pending_approval',approval_url:'https://app.link.com/approve/fixture'};}
    return {id:'sr_fixture',status:'approved',amount:50,currency:'usd',network_id:'profile_test_fixture',credential_type:'shared_payment_token',test:true,shared_payment_token:{id:'spt_fixture_secret'}};
  });
  const waiting=await payMpp(payment,'fixture-link-token',operationId,50,()=>{},undefined,merchant.transport,link);assert.equal(waiting.state,'approval_required');assert.equal(merchant.charges(),0);assert.equal(creates,1);assert.equal(requested,1);
  const completed=await payMpp(payment,'fixture-link-token',operationId,50,()=>{},waiting.result as unknown as PaymentContinuation,merchant.transport,link);
  assert.equal(completed.state,'completed');assert.equal(merchant.charges(),1);assert.equal(creates,1);assert.equal((completed.result.receipt as any).externalId,operationId);assert.ok(!JSON.stringify(completed).includes('spt_fixture_secret'));
  await payMpp(payment,'fixture-link-token',operationId,50,()=>{},waiting.result as unknown as PaymentContinuation,merchant.transport,link);assert.equal(merchant.charges(),1);
});
test('MPP create stays approval_required even when Link already reports approved',async()=>{
  const merchant=await merchantFixture();const operationId=randomUUID();let retrieve=0;
  const approved={id:'sr_fixture',status:'approved',amount:50,currency:'usd',network_id:'profile_test_fixture',credential_type:'shared_payment_token',test:true,shared_payment_token:{id:'spt_should_not_use'}};
  const link=schemaLink(async(_token,args)=>{if(args[1]==='retrieve'){retrieve++;return approved;}return approved;});
  const waiting=await payMpp(payment,'fixture-link-token',operationId,50,()=>{},undefined,merchant.transport,link);
  assert.equal(waiting.state,'approval_required');assert.equal(merchant.charges(),0);assert.equal(retrieve,0);assert.ok(!JSON.stringify(waiting).includes('spt_should_not_use'));
});
test('MPP rejects price/profile/task tampering and revocation before terminal payment; merchant refuses live keys',async()=>{
  assert.throws(()=>createMerchant('sk_live_fixture','profile_test_fixture'));
  let linkCalls=0;const link:LinkCall=async()=>{linkCalls++;throw new Error('must not call');};
  for(const [field,value] of [['amount','100'],['currency','eur'],['externalId',randomUUID()]] as const){
    const op=randomUUID();const challenge=Challenge.from({id:'fixture',realm:'stackey-sandbox.vercel.app',method:'stripe',intent:'charge',expires:new Date(Date.now()+600000).toISOString(),request:{amount:'50',currency:'usd',externalId:op,methodDetails:{networkId:'profile_test_fixture'},[field]:value}});
    const transport:ProviderFetch=async()=>new Response('',{status:402,headers:{'www-authenticate':Challenge.serialize(challenge)}});
    await assert.rejects(payMpp(payment,'fixture',op,50,()=>{},undefined,transport,link));
  }
  assert.equal(linkCalls,0);
  const merchant=await merchantFixture();const op=randomUUID();  const waiting=await payMpp(payment,'fixture',op,50,()=>{},undefined,merchant.transport,schemaLink(async()=>({id:'sr_fixture',status:'pending_approval'})));
  let checks=0;await assert.rejects(payMpp(payment,'fixture',op,50,()=>{if(++checks===2)throw new AppError('grant_revoked','revoked');},waiting.result as unknown as PaymentContinuation,merchant.transport,schemaLink(async()=>({status:'approved',amount:50,currency:'usd',network_id:'profile_test_fixture',credential_type:'shared_payment_token',test:true,shared_payment_token:{id:'spt_fixture'}}))));
  assert.equal(merchant.charges(),0);
  const probe=await merchant.handler(new Request(String(payment.config.endpoint),{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({operation_id:op})}));const challenge=Challenge.fromResponse(probe);
  const altered={...challenge,request:{...challenge.request,amount:'1'}};
  const response=await merchant.handler(new Request(String(payment.config.endpoint),{method:'POST',headers:{'content-type':'application/json',authorization:Credential.serialize({challenge:altered,payload:{spt:'spt_bad',externalId:op}})},body:JSON.stringify({operation_id:op})}));assert.equal(response.status,402);assert.equal(merchant.charges(),0);
});

async function runtime(t:TestContext,transport:ProviderFetch){
  const root=mkdtempSync(join(tmpdir(),'stackey-providers-'));const dir=join(root,'vault');const nodeDir=join(root,'node');const recovery=join(root,'seed.json');
  const original=globalThis.fetch;globalThis.fetch=(async(input,init)=>new URL(String(input)).hostname.endsWith('.supabase.co')?transport(input,init):original(input,init)) as ProviderFetch;
  await initializeVault(dir,recovery);const identity=await loadIdentity(nodeDir,'node',true);const node=await startNode(nodeDir,0);const store=new Store(nodeDir);const vault=await unlockVault(dir,recovery,nodeDir);
  t.after(async()=>{await node.close();await vault.close();store.close();globalThis.fetch=original;rmSync(root,{recursive:true});});
  const owner={_node_dir:resolve(nodeDir)};await vaultRequest(dir,'node.bind',owner);
  const imported=await vaultRequest(dir,'credential.import',{wallet_id:wallet,name:'Fixture',kind:'api_key',value:'fixture-secret'});
  const connected=await vaultRequest(dir,'connection.add',{wallet_id:wallet,name:'Orders',provider:'supabase',config:{...supabase.config,credential_id:imported.id}});
  const agent=join(root,'agent');const invitation=await issueInvitation(store,identity,300);const pairing=(await connect(invitation,agent,'Fixture Agent')).data as any;
  const grant=await vaultRequest(dir,'grant.approve',{...owner,pairing_id:pairing.pairing_id,principal:pairing.principal,action:'supabase.orders.read',ttl:900,wallet_id:wallet,connection_id:connected.id,max_calls:1,max_amount_minor:0});
  return {dir,node,store,agent,grant,owner,context:await agentContext(agent)};
}
test('DPoP provider flow reserves before dispatch, persists result, enforces one call and revokes existing sessions',async t=>{
  let reads=0;const f=await runtime(t,async()=>{reads++;return Response.json([{id:'order_1',created_at:'2026-10-01T12:00:00Z',currency:'USD',amount_minor:100,payment_status:'paid'}]);});
  const id=randomUUID();const pending=await runOrders(f.agent,'supabase.orders.read',{from:'2026-10-01',to:'2026-10-01'},id);assert.equal(pending.status,'operation_pending');await drainProviderOperations(f.node.nodeId);
  assert.equal((await operation(f.agent,id)).status,'ok');assert.equal(reads,1);
  await runOrders(f.agent,'supabase.orders.read',{from:'2026-10-01',to:'2026-10-01'},id);assert.equal(reads,1);
  await assert.rejects(runOrders(f.agent,'supabase.orders.read',{from:'2026-10-02',to:'2026-10-02'},id));
  await assert.rejects(runOrders(f.agent,'supabase.orders.read',{from:'2026-10-01',to:'2026-10-01'}),e=>e instanceof AppError&&e.code==='budget_exceeded');
  const token=await session(f.context);await vaultRequest(f.dir,'grant.revoke',{...f.owner,grant_id:f.grant.grant_id});await assert.rejects(resourceRequest(f.context,token,'GET','/v1/capabilities'));
  assert.equal(reads,1);assert.ok(!JSON.stringify(f.store.db.prepare('SELECT * FROM provider_operations').all()).includes('fixture-secret'));
});
test('uncertain provider outcome retains reservation and is never dispatched again automatically',async t=>{
  let reads=0;const f=await runtime(t,async()=>{reads++;throw new Error('fixture service key must not leak');});const id=randomUUID();
  await runOrders(f.agent,'supabase.orders.read',{from:'2026-10-01',to:'2026-10-01'},id);await drainProviderOperations(f.node.nodeId);
  const result=await operation(f.agent,id);assert.equal(result.status,'result_unknown');assert.ok(!JSON.stringify(result).includes('must not leak'));
  await runOrders(f.agent,'supabase.orders.read',{from:'2026-10-01',to:'2026-10-01'},id);assert.equal(reads,1);
});
test('merchant rejects oversized input and credentials bound to another operation before charging', async()=>{
  const merchant=await merchantFixture();const op=randomUUID();const headers={'content-type':'application/json'};
  const oversized=await merchant.handler(new Request(String(payment.config.endpoint),{method:'POST',headers,body:'x'.repeat(1025)}));assert.equal(oversized.status,413);
  const probe=await merchant.handler(new Request(String(payment.config.endpoint),{method:'POST',headers,body:JSON.stringify({operation_id:op})}));
  const challenge=Challenge.fromResponse(probe);
  const other=await merchant.handler(new Request(String(payment.config.endpoint),{method:'POST',headers:{...headers,authorization:Credential.serialize({challenge,payload:{spt:'spt_fixture',externalId:op}})},body:JSON.stringify({operation_id:randomUUID()})}));
  assert.equal(other.status,402);assert.equal(merchant.charges(),0);
});
test('owner revocation does not wait for provider IO and blocks in-flight result delivery',async t=>{
  let release!:()=>void;let entered!:()=>void;const gate=new Promise<void>(resolve=>{release=resolve;});const started=new Promise<void>(resolve=>{entered=resolve;});
  const f=await runtime(t,async()=>{entered();await gate;return Response.json([{id:'order_1',created_at:'2026-10-01T12:00:00Z',currency:'USD',amount_minor:100,payment_status:'paid'}]);});
  t.after(()=>release());const id=randomUUID();await runOrders(f.agent,'supabase.orders.read',{from:'2026-10-01',to:'2026-10-01'},id);await started;
  await vaultRequest(f.dir,'grant.revoke',{...f.owner,grant_id:f.grant.grant_id});release();await drainProviderOperations(f.node.nodeId);
  await assert.rejects(operation(f.agent,id),e=>e instanceof AppError&&e.code==='grant_revoked');
  const saved=f.store.db.prepare('SELECT state,result_json FROM provider_operations WHERE operation_id=?').get(id)!;assert.equal(saved.state,'result_unknown');assert.ok(!String(saved.result_json).includes('order_1'));
});
test('orphaned dispatch records after restart keep their reservation and never auto-retry',async t=>{
  let reads=0;const f=await runtime(t,async()=>{reads++;return Response.json([]);});const id=randomUUID();
  await runOrders(f.agent,'supabase.orders.read',{from:'2026-10-01',to:'2026-10-01'},id);await drainProviderOperations(f.node.nodeId);assert.equal(reads,1);
  // Durable shape left by a crashed process: an executing record with no live
  // dispatch owner. The request path must reconcile rather than send it again.
  f.store.db.prepare("UPDATE provider_operations SET state='executing',result_json=NULL WHERE operation_id=?").run(id);
  assert.equal((await operation(f.agent,id)).status,'result_unknown');
  assert.equal((await runOrders(f.agent,'supabase.orders.read',{from:'2026-10-01',to:'2026-10-01'},id)).status,'result_unknown');assert.equal(reads,1);
  await assert.rejects(runOrders(f.agent,'supabase.orders.read',{from:'2026-10-01',to:'2026-10-01'}),e=>e instanceof AppError&&e.code==='budget_exceeded');
});
