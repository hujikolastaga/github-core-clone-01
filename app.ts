import http, { type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { handleGitHttp } from './git-http.ts';
import { handleGraphQL } from './graphql.ts';
import { handleMcp } from './mcp.ts';
import { handleRestApi, type ReplySender } from './rest.ts';
import { ForgeStore } from './store.ts';

export interface AppOptions {
  readonly token?: string;
}

export interface AppInstance {
  readonly server: Server;
  readonly store: ForgeStore;
}

const MAX_BODY_BYTES = 64 * 1024 * 1024;
const EMPTY_BUF = Buffer.alloc(0);
const HEALTHZ_BUF = Buffer.from('{"ok":true}', 'utf8');
const ERR_AUTH_BUF = Buffer.from('{"message":"Requires authentication"}', 'utf8');
const ERR_NOT_FOUND_BUF = Buffer.from('{"message":"Not Found"}', 'utf8');
const ERR_INTERNAL_BUF = Buffer.from('{"message":"Internal Server Error"}', 'utf8');
const ERR_TOO_LARGE_BUF = Buffer.from('{"message":"Payload Too Large"}', 'utf8');

function extractAuthMatch(authHeader: string | undefined, expectedToken: string): boolean {
  if (!expectedToken || !authHeader) return false;
  const trimmed = authHeader.trim();
  const spaceIdx = trimmed.indexOf(' ');
  if (spaceIdx <= 0) return false;
  const scheme = trimmed.slice(0, spaceIdx).toLowerCase();
  const cred = trimmed.slice(spaceIdx + 1).trim();
  if (scheme === 'bearer' || scheme === 'token') {
    return cred === expectedToken;
  }
  if (scheme === 'basic') {
    const decoded = Buffer.from(cred, 'base64').toString('utf8');
    const colon = decoded.indexOf(':');
    if (colon < 0) return decoded === expectedToken;
    const user = decoded.slice(0, colon);
    const pass = decoded.slice(colon + 1);
    return pass === expectedToken || (pass === '' && user === expectedToken);
  }
  return false;
}

export function createApp(options?: AppOptions): AppInstance {
  const store = new ForgeStore();
  const configuredToken = options?.token;
  let cachedToken = (configuredToken ?? process.env.MAKEFUN_SHOP_TOKEN ?? '').trim();
  let cachedBearer = cachedToken ? `Bearer ${cachedToken}` : '';
  let reqSeq = 0;

  const isRequestAuthorized = (authHeader: string | undefined): boolean => {
    if (!authHeader) return false;
    if (cachedBearer && authHeader === cachedBearer) return true;
    if (configuredToken === undefined) {
      const envToken = (process.env.MAKEFUN_SHOP_TOKEN ?? '').trim();
      if (envToken !== cachedToken) {
        cachedToken = envToken;
        cachedBearer = cachedToken ? `Bearer ${cachedToken}` : '';
        if (cachedBearer && authHeader === cachedBearer) return true;
      }
    }
    return extractAuthMatch(authHeader, cachedToken);
  };

  const reply: ReplySender = {
    sendRawJson(
      res: ServerResponse,
      status: number,
      buf: Buffer,
      extraHeaders?: Record<string, string>,
    ): void {
      const reqId = `req-${++reqSeq}`;
      const headers: Record<string, string | number> = extraHeaders
        ? {
            'content-type': 'application/json; charset=utf-8',
            'content-length': buf.length,
            'x-github-request-id': reqId,
            ...extraHeaders,
          }
        : {
            'content-type': 'application/json; charset=utf-8',
            'content-length': buf.length,
            'x-github-request-id': reqId,
          };
      res.writeHead(status, headers);
      res.end(buf);
    },

    sendJson(
      res: ServerResponse,
      status: number,
      body: unknown,
      extraHeaders?: Record<string, string>,
    ): void {
      const buf = Buffer.from(JSON.stringify(body), 'utf8');
      reply.sendRawJson(res, status, buf, extraHeaders);
    },

    sendEmpty(res: ServerResponse, status: number): void {
      res.writeHead(status, {
        'content-length': 0,
        'x-github-request-id': `req-${++reqSeq}`,
      });
      res.end();
    },
  };

  const sendJsonError = (res: ServerResponse, status: number, message: string): void => {
    reply.sendJson(res, status, { message });
  };

  const dispatch = (req: IncomingMessage, res: ServerResponse, body: Buffer): void => {
    try {
      const method = req.method ?? 'GET';
      const rawUrl = req.url ?? '/';
      const qIdx = rawUrl.indexOf('?');
      const pathname = qIdx < 0 ? rawUrl : rawUrl.slice(0, qIdx);
      const queryStr = qIdx < 0 ? '' : rawUrl.slice(qIdx + 1);

      if (pathname === '/healthz' && (method === 'GET' || method === 'HEAD')) {
        res.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'content-length': HEALTHZ_BUF.length,
          'x-github-request-id': `req-${++reqSeq}`,
        });
        res.end(method === 'HEAD' ? EMPTY_BUF : HEALTHZ_BUF);
        return;
      }

      if (!isRequestAuthorized(req.headers.authorization)) {
        const extra = pathname.includes('.git/')
          ? { 'www-authenticate': 'Basic realm="GitHub Forge"' }
          : undefined;
        reply.sendRawJson(res, 401, ERR_AUTH_BUF, extra);
        return;
      }

      if (pathname === '/mcp') {
        handleMcp(store, res, method, body, reply);
        return;
      }

      if (pathname === '/api/graphql') {
        handleGraphQL(store, res, method, body, reply);
        return;
      }

      if (pathname === '/api/v3' || pathname.startsWith('/api/v3/')) {
        handleRestApi(store, req, res, method, pathname, queryStr, body, reply);
        return;
      }

      res.setHeader('x-github-request-id', `req-${++reqSeq}`);
      if (handleGitHttp(store, req, res, method, pathname, queryStr, body, sendJsonError)) {
        return;
      }

      reply.sendRawJson(res, 404, ERR_NOT_FOUND_BUF);
    } catch {
      if (!res.headersSent) {
        reply.sendRawJson(res, 500, ERR_INTERNAL_BUF);
      } else {
        res.destroy();
      }
    }
  };

  const server = http.createServer((req, res) => {
    const method = req.method ?? 'GET';
    const cl = req.headers['content-length'];
    const te = req.headers['transfer-encoding'];
    const noBody = (cl === undefined || cl === '0') && te === undefined;

    if (noBody && (method === 'GET' || method === 'HEAD' || method === 'DELETE')) {
      req.resume();
      dispatch(req, res, EMPTY_BUF);
      return;
    }

    const chunks: Buffer[] = [];
    let totalBytes = 0;
    let finished = false;

    req.on('data', (chunk: Buffer) => {
      if (finished) return;
      totalBytes += chunk.length;
      if (totalBytes > MAX_BODY_BYTES) {
        finished = true;
        reply.sendRawJson(res, 413, ERR_TOO_LARGE_BUF);
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (finished) return;
      finished = true;
      const body =
        chunks.length === 0 ? EMPTY_BUF : chunks.length === 1 ? chunks[0]! : Buffer.concat(chunks, totalBytes);
      dispatch(req, res, body);
    });

    req.on('error', () => {
      finished = true;
      if (!res.headersSent) {
        res.writeHead(400, { 'content-length': 0 });
        res.end();
      }
    });
  });

  server.keepAliveTimeout = 60_000;
  server.headersTimeout = 65_000;
  server.requestTimeout = 120_000;
  server.maxRequestsPerSocket = 0;

  server.on('connection', (socket) => {
    socket.setNoDelay(true);
  });

  return { server, store };
}
