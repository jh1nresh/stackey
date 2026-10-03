import { createServer, type IncomingMessage, type Server } from 'node:http';
import { AppError, envelope, MAX_BODY, publicError } from './contracts.js';
import { loadIdentity } from './identity.js';
import { acceptPairing } from './pairing.js';
import { Store } from './store.js';

export interface RunningNode {
  server: Server;
  endpoint: string;
  nodeId: string;
  close(): Promise<void>;
}

async function readBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.from(chunk);
    size += buffer.length;
    if (size > MAX_BODY) throw new AppError('request_too_large', 'Request exceeds 16 KiB.', 413);
    chunks.push(buffer);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw new AppError('invalid_json', 'Request body must be JSON.'); }
}

export async function startNode(dir: string, port = 45820, clock = () => Math.floor(Date.now() / 1000)): Promise<RunningNode> {
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new AppError('invalid_port', 'Invalid Node port.');
  const identity = await loadIdentity(dir, 'node');
  const store = new Store(dir);
  let origin = '';
  let windowStart = clock();
  let requests = 0;
  const server = createServer(async (request, response) => {
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    try {
      if (request.headers.origin !== undefined) {
        throw new AppError('browser_request_denied', 'Browser-origin requests are not supported.', 403, 3, 'permission_denied');
      }
      if (request.method !== 'POST' || request.url !== '/v1/pairings') {
        throw new AppError('route_not_available', 'Only pending pairing requests are available.', 404);
      }
      const now = clock();
      if (now - windowStart >= 60) { windowStart = now; requests = 0; }
      if (++requests > 30) throw new AppError('rate_limited', 'Pairing request limit reached; retry later.', 429, 4, 'rate_limited');
      if (request.headers['content-type'] !== 'application/json') {
        throw new AppError('invalid_content_type', 'Use application/json.', 415);
      }
      const input = await readBody(request);
      const result = await acceptPairing(store, identity, origin, input, clock);
      response.writeHead(201);
      response.end(JSON.stringify(envelope('approval_required', { receipt: result })));
    } catch (error) {
      const safe = publicError(error);
      if (!response.destroyed) {
        response.writeHead(safe.httpStatus);
        response.end(JSON.stringify(safe.body));
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
