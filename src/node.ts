import { createServer, type IncomingMessage, type Server } from 'node:http';
import { AppError, digest, envelope, MAX_BODY, publicError, textField } from './contracts.js';
import { agentAction, signedResponse } from './access.js';
import { loadIdentity } from './identity.js';
import { acceptPairing } from './pairing.js';
import { Store } from './store.js';

export interface RunningNode {
  server: Server;
  endpoint: string;
  nodeId: string;
  close(): Promise<void>;
}

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.from(chunk);
    size += buffer.length;
    if (size > MAX_BODY) throw new AppError('request_too_large', 'Request exceeds 16 KiB.', 413);
    chunks.push(buffer);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  try { JSON.parse(text); }
  catch { throw new AppError('invalid_json', 'Request body must be JSON.'); }
  return text;
}

export async function startNode(dir: string, port = 45820, clock = () => Math.floor(Date.now() / 1000)): Promise<RunningNode> {
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new AppError('invalid_port', 'Invalid Node port.');
  const identity = await loadIdentity(dir, 'node');
  const store = new Store(dir);
  let origin = '';
  let windowStart = clock();
  let requests = 0;
  let agentRequests = 0;
  const server = createServer(async (request, response) => {
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    let signedReply = false;
    let requestHash = digest('');
    try {
      if (request.headers.origin !== undefined) {
        throw new AppError('browser_request_denied', 'Browser-origin requests are not supported.', 403, 3, 'permission_denied');
      }
      const pairing = request.method === 'POST' && request.url === '/v1/pairings';
      const agentRoute = (request.method === 'POST' && ['/v1/challenges', '/v1/sessions', '/v1/operations'].includes(request.url ?? '')) ||
        (request.method === 'GET' && (request.url === '/v1/capabilities' || /^\/v1\/(pairings|operations)\/[0-9a-f-]{36}$/.test(request.url ?? '')));
      if (!pairing && !agentRoute) {
        throw new AppError('route_not_available', 'Route is not available.', 404);
      }
      signedReply = !pairing;
      const now = clock();
      if (now - windowStart >= 60) { windowStart = now; requests = 0; agentRequests = 0; }
      const rateLimited = pairing ? ++requests > 30 : ++agentRequests > 120;
      const rawProof = request.headers['x-stackey-proof'] ?? request.headers.dpop;
      const proof = !signedReply || rawProof === undefined ? '' : textField(rawProof, 8192);
      if (signedReply) requestHash = digest(proof);
      if (request.method === 'POST' && request.headers['content-type'] !== 'application/json') {
        throw new AppError('invalid_content_type', 'Use application/json.', 415);
      }
      const rawBody = request.method === 'POST' ? await readBody(request) : '';
      if (request.url === '/v1/challenges') requestHash = digest(rawBody);
      // Count at arrival, but bind even known rejections to the bounded request.
      // No proof verification, nonce insertion or operation occurs when limited.
      if (rateLimited) throw new AppError('rate_limited', 'Request limit reached; retry later.', 429, 4, 'rate_limited');
      if (pairing) {
        const result = await acceptPairing(store, identity, origin, JSON.parse(rawBody), clock);
        response.writeHead(201);
        response.end(JSON.stringify(envelope('approval_required', { receipt: result })));
      } else {
        const authorization = request.headers.authorization;
        const result = await agentAction(store, identity, origin, {
          method: request.method!, path: request.url!, rawBody, proof,
          ...(authorization === undefined ? {} : { authorization }),
        }, clock);
        const receipt = await signedResponse(identity, result, requestHash, clock());
        response.writeHead(200);
        response.end(JSON.stringify(envelope(result.status, { receipt })));
      }
    } catch (error) {
      const safe = publicError(error);
      if (!response.destroyed) {
        response.writeHead(safe.httpStatus);
        if (signedReply) {
          try { response.end(JSON.stringify(envelope(safe.body.status, { receipt: await signedResponse(identity, safe.body, requestHash, clock()) }))); }
          catch { response.end(JSON.stringify(publicError(new Error()).body)); }
        } else response.end(JSON.stringify(safe.body));
      }
    }
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 1000;
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, '127.0.0.1', () => { server.off('error', reject); resolve(); });
    });
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Missing address');
    origin = 'http://127.0.0.1:' + address.port;
    store.setEndpoint(origin);
  } catch (error) {
    server.close(); store.close(); throw error;
  }
  let closing: Promise<void> | undefined;
  return { server, endpoint: origin, nodeId: identity.id,
    close() {
      closing ??= new Promise<void>((resolve, reject) => {
        server.close(error => { store.close(); error ? reject(error) : resolve(); });
        server.closeIdleConnections();
      });
      return closing;
    },
  };
}
