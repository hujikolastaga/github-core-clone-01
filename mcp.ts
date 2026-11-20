import type { ServerResponse } from 'node:http';
import {
  serializeIssueObject,
  serializePull,
  serializeRepo,
  type ReplySender,
} from './rest.ts';
import { ForgeStore } from './store.ts';

interface McpToolDef {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
}

const TOOLS: readonly McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a new Git repository under the authenticated user account.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Fetch metadata for an existing Git repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create a new issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body text' },
        labels: { type: 'array', items: { type: 'string' }, description: 'Issue label names' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository filtered by state.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', enum: ['open', 'closed', 'all'], description: 'Issue state filter' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a new pull request from a head branch to a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        head: { type: 'string', description: 'Source branch name' },
        base: { type: 'string', description: 'Target branch name' },
        body: { type: 'string', description: 'Pull request body text' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge an open pull request into its base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'number', description: 'Pull request number' },
        commit_title: { type: 'string', description: 'Optional merge commit title' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

const SERVER_INFO = {
  name: 'makefun-forge',
  version: '1.0.0',
};

const TOOLS_RESULT_SUFFIX = Buffer.from(
  `,"result":${JSON.stringify({ tools: TOOLS })}}`,
  'utf8',
);

function nonEmptyString(val: unknown): string | undefined {
  return typeof val === 'string' && val.trim().length > 0 ? val : undefined;
}

function parsePositiveIntArg(val: unknown): number | undefined {
  if (typeof val === 'number') {
    return Number.isInteger(val) && val > 0 ? val : undefined;
  }
  if (typeof val === 'string' && /^\d+$/.test(val.trim())) {
    const n = Number.parseInt(val.trim(), 10);
    return Number.isInteger(n) && n > 0 ? n : undefined;
  }
  return undefined;
}

function sendRpcError(
  reply: ReplySender,
  res: ServerResponse,
  httpStatus: number,
  id: unknown,
  code: number,
  message: string,
): void {
  reply.sendJson(res, httpStatus, {
    jsonrpc: '2.0',
    id: id ?? null,
    error: { code, message },
  });
}

function sendToolResult(
  reply: ReplySender,
  res: ServerResponse,
  id: unknown,
  payload: unknown,
): void {
  const result: Record<string, unknown> = {
    content: [{ type: 'text', text: JSON.stringify(payload) }],
  };
  if (typeof payload === 'object' && payload !== null && !Array.isArray(payload)) {
    result.structuredContent = payload;
  } else if (Array.isArray(payload)) {
    result.structuredContent = { items: payload, count: payload.length };
  }
  reply.sendJson(res, 200, {
    jsonrpc: '2.0',
    id,
    result,
  });
}

function sendToolFailure(
  reply: ReplySender,
  res: ServerResponse,
  id: unknown,
  message: string,
): void {
  reply.sendJson(res, 200, {
    jsonrpc: '2.0',
    id,
    result: {
      content: [{ type: 'text', text: JSON.stringify({ message }) }],
      isError: true,
    },
  });
}

function invokeTool(
  store: ForgeStore,
  reply: ReplySender,
  res: ServerResponse,
  id: unknown,
  toolName: string,
  args: Record<string, unknown>,
): void {
  switch (toolName) {
    case 'create_repo': {
      const name = nonEmptyString(args.name);
      if (!name) {
        sendRpcError(reply, res, 200, id, -32602, 'Invalid params: name is required');
        return;
      }
      const owner = nonEmptyString(args.owner) ?? store.viewer.login;
      if (owner !== store.viewer.login) {
        sendToolFailure(reply, res, id, 'Cannot create repository for another owner');
        return;
      }
      const created = store.createRepo(owner, name, {
        description: typeof args.description === 'string' ? args.description : '',
        isPrivate: typeof args.private === 'boolean' ? args.private : false,
      });
      if (!created.ok) {
        sendToolFailure(reply, res, id, created.message);
        return;
      }
      sendToolResult(reply, res, id, serializeRepo(created.repo));
      return;
    }

    case 'get_repo': {
      const owner = nonEmptyString(args.owner);
      const repoName = nonEmptyString(args.repo) ?? nonEmptyString(args.name);
      if (!owner || !repoName) {
        sendRpcError(reply, res, 200, id, -32602, 'Invalid params: owner and repo are required');
        return;
      }
      const repo = owner === store.viewer.login ? store.getRepo(owner, repoName) : undefined;
      if (!repo) {
        sendToolFailure(reply, res, id, 'Not Found');
        return;
      }
      sendToolResult(reply, res, id, serializeRepo(repo));
      return;
    }

    case 'create_issue': {
      const owner = nonEmptyString(args.owner);
      const repoName = nonEmptyString(args.repo) ?? nonEmptyString(args.name);
      const title = nonEmptyString(args.title);
      if (!owner || !repoName || !title) {
        sendRpcError(reply, res, 200, id, -32602, 'Invalid params: owner, repo, and title are required');
        return;
      }
      const repo = owner === store.viewer.login ? store.getRepo(owner, repoName) : undefined;
      if (!repo) {
        sendToolFailure(reply, res, id, 'Not Found');
        return;
      }
      const rawLabels = Array.isArray(args.labels)
        ? args.labels.filter((x): x is string => typeof x === 'string')
        : undefined;
      const created = store.createIssue(repo, {
        title,
        body: typeof args.body === 'string' ? args.body : '',
        labels: rawLabels,
      });
      if (!created.ok) {
        sendToolFailure(reply, res, id, created.message);
        return;
      }
      sendToolResult(reply, res, id, serializeIssueObject(created.issue));
      return;
    }

    case 'list_issues': {
      const owner = nonEmptyString(args.owner);
      const repoName = nonEmptyString(args.repo) ?? nonEmptyString(args.name);
      if (!owner || !repoName) {
        sendRpcError(reply, res, 200, id, -32602, 'Invalid params: owner and repo are required');
        return;
      }
      const repo = owner === store.viewer.login ? store.getRepo(owner, repoName) : undefined;
      if (!repo) {
        sendToolFailure(reply, res, id, 'Not Found');
        return;
      }
      const stateFilter = typeof args.state === 'string' ? args.state : 'open';
      if (stateFilter !== 'open' && stateFilter !== 'closed' && stateFilter !== 'all') {
        sendRpcError(reply, res, 200, id, -32602, 'Invalid params: state must be open, closed, or all');
        return;
      }
      const items = repo.issueOrder
        .filter((i) => stateFilter === 'all' || i.state === stateFilter)
        .sort((a, b) => b.createdSeq - a.createdSeq || b.number - a.number)
        .map(serializeIssueObject);
      sendToolResult(reply, res, id, items);
      return;
    }

    case 'create_pull_request': {
      const owner = nonEmptyString(args.owner);
      const repoName = nonEmptyString(args.repo) ?? nonEmptyString(args.name);
      const title = nonEmptyString(args.title);
      const head = nonEmptyString(args.head);
      const base = nonEmptyString(args.base);
      if (!owner || !repoName || !title || !head || !base) {
        sendRpcError(
          reply,
          res,
          200,
          id,
          -32602,
          'Invalid params: owner, repo, title, head, and base are required',
        );
        return;
      }
      const repo = owner === store.viewer.login ? store.getRepo(owner, repoName) : undefined;
      if (!repo) {
        sendToolFailure(reply, res, id, 'Not Found');
        return;
      }
      const created = store.createPull(repo, {
        title,
        body: typeof args.body === 'string' ? args.body : '',
        head,
        base,
      });
      if (!created.ok) {
        sendToolFailure(reply, res, id, created.message);
        return;
      }
      sendToolResult(reply, res, id, serializePull(repo, created.pull));
      return;
    }

    case 'merge_pull_request': {
      const owner = nonEmptyString(args.owner);
      const repoName = nonEmptyString(args.repo) ?? nonEmptyString(args.name);
      const pullNumber = parsePositiveIntArg(args.pull_number);
      if (!owner || !repoName || pullNumber === undefined) {
        sendRpcError(
          reply,
          res,
          200,
          id,
          -32602,
          'Invalid params: owner, repo, and positive integer pull_number are required',
        );
        return;
      }
      const repo = owner === store.viewer.login ? store.getRepo(owner, repoName) : undefined;
      if (!repo) {
        sendToolFailure(reply, res, id, 'Not Found');
        return;
      }
      const commitTitle = typeof args.commit_title === 'string' ? args.commit_title : undefined;
      const merged = store.mergePull(repo, pullNumber, commitTitle);
      if (!merged.ok) {
        sendToolFailure(reply, res, id, merged.message);
        return;
      }
      sendToolResult(reply, res, id, {
        sha: merged.sha,
        merged: true,
        message: 'Pull Request successfully merged',
        pull_number: merged.pull.number,
      });
      return;
    }

    default:
      sendRpcError(reply, res, 200, id, -32601, `Unknown tool: ${toolName}`);
  }
}

/** Handle JSON-RPC requests on `/mcp` supporting MCP 2026-07-28 discovery and 2025-11-25 initialize. */
export function handleMcp(
  store: ForgeStore,
  res: ServerResponse,
  method: string,
  body: Buffer,
  reply: ReplySender,
): void {
  if (method === 'DELETE') {
    reply.sendEmpty(res, 204);
    return;
  }
  if (method !== 'POST') {
    reply.sendJson(res, 405, { message: 'Method Not Allowed' });
    return;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString('utf8')) as unknown;
  } catch {
    sendRpcError(reply, res, 400, null, -32700, 'Parse error');
    return;
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    sendRpcError(reply, res, 400, null, -32600, 'Invalid Request');
    return;
  }

  const msg = parsed as Record<string, unknown>;
  const id = msg.id;
  const rpcMethod = msg.method;
  if (typeof rpcMethod !== 'string') {
    sendRpcError(reply, res, 400, id ?? null, -32600, 'Invalid Request: method must be a string');
    return;
  }

  if (id === undefined && rpcMethod.startsWith('notifications/')) {
    reply.sendEmpty(res, 202);
    return;
  }

  const rpcId = id === undefined ? null : id;

  if (rpcMethod === 'server/discover') {
    reply.sendJson(res, 200, {
      jsonrpc: '2.0',
      id: rpcId,
      result: {
        supportedVersions: ['2026-07-28', '2025-11-25'],
        serverInfo: SERVER_INFO,
        capabilities: { tools: {} },
        _meta: {
          'io.modelcontextprotocol/serverInfo': SERVER_INFO,
        },
      },
    });
    return;
  }

  if (rpcMethod === 'initialize') {
    reply.sendJson(res, 200, {
      jsonrpc: '2.0',
      id: rpcId,
      result: {
        protocolVersion: '2025-11-25',
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO,
      },
    });
    return;
  }

  if (rpcMethod === 'ping') {
    reply.sendJson(res, 200, { jsonrpc: '2.0', id: rpcId, result: {} });
    return;
  }

  if (rpcMethod === 'tools/list') {
    const prefix = Buffer.from(`{"jsonrpc":"2.0","id":${JSON.stringify(rpcId)}`, 'utf8');
    reply.sendRawJson(res, 200, Buffer.concat([prefix, TOOLS_RESULT_SUFFIX]));
    return;
  }

  if (rpcMethod === 'tools/call') {
    const params = msg.params;
    if (typeof params !== 'object' || params === null || Array.isArray(params)) {
      sendRpcError(reply, res, 200, rpcId, -32602, 'Invalid params');
      return;
    }
    const p = params as Record<string, unknown>;
    if (typeof p.name !== 'string' || p.name.length === 0) {
      sendRpcError(reply, res, 200, rpcId, -32602, 'Invalid params: tool name is required');
      return;
    }
    const rawArgs = p.arguments === undefined ? {} : p.arguments;
    if (typeof rawArgs !== 'object' || rawArgs === null || Array.isArray(rawArgs)) {
      sendRpcError(reply, res, 200, rpcId, -32602, 'Invalid params: arguments must be an object');
      return;
    }
    invokeTool(store, reply, res, rpcId, p.name, rawArgs as Record<string, unknown>);
    return;
  }

  sendRpcError(reply, res, 200, rpcId, -32601, `Method not found: ${rpcMethod}`);
}
