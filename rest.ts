import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  ForgeStore,
  type CommentRecord,
  type IssueRecord,
  type PullRecord,
  type RepoRecord,
} from './store.ts';

export function serializeRepo(repo: RepoRecord): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: repo.nodeId,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    private: repo.private,
    owner: { login: repo.owner, id: 1000, type: 'User' },
    description: repo.description,
    default_branch: repo.defaultBranch,
    has_issues: true,
    created_at: repo.createdAt,
    updated_at: repo.updatedAt,
  };
}

export function serializeIssueObject(issue: IssueRecord): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: issue.nodeId,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((l) => ({
      id: l.id,
      node_id: l.nodeId,
      name: l.name,
      color: l.color,
      description: l.description,
    })),
    user: { login: issue.user.login, id: issue.user.id, type: 'User' },
    comments: issue.comments.length,
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.closedAt,
  };
}

export function getIssueJsonBuffer(issue: IssueRecord): Buffer {
  if (issue.jsonCache === undefined) {
    issue.jsonCache = Buffer.from(JSON.stringify(serializeIssueObject(issue)), 'utf8');
  }
  return issue.jsonCache;
}

export function serializeComment(c: CommentRecord): Record<string, unknown> {
  return {
    id: c.id,
    node_id: c.nodeId,
    body: c.body,
    user: { login: c.user.login, id: c.user.id, type: 'User' },
    created_at: c.createdAt,
    updated_at: c.updatedAt,
  };
}

export function serializePull(repo: RepoRecord, pr: PullRecord): Record<string, unknown> {
  const headTip = repo.refs.get(`refs/heads/${pr.headRef}`) ?? pr.headSha;
  const baseTip = repo.refs.get(`refs/heads/${pr.baseRef}`) ?? pr.baseSha;
  return {
    id: pr.id,
    node_id: pr.nodeId,
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state,
    merged: pr.merged,
    merged_at: pr.mergedAt,
    merge_commit_sha: pr.mergeCommitSha,
    head: {
      label: `${repo.owner}:${pr.headRef}`,
      ref: pr.headRef,
      sha: headTip,
    },
    base: {
      label: `${repo.owner}:${pr.baseRef}`,
      ref: pr.baseRef,
      sha: baseTip,
    },
    user: { login: pr.user.login, id: pr.user.id, type: 'User' },
    created_at: pr.createdAt,
    updated_at: pr.updatedAt,
  };
}

function parseJsonBody(body: Buffer): { ok: true; value: Record<string, unknown> } | { ok: false } {
  if (body.length === 0) return { ok: true, value: {} };
  try {
    const parsed = JSON.parse(body.toString('utf8')) as unknown;
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return { ok: false };
    return { ok: true, value: parsed as Record<string, unknown> };
  } catch {
    return { ok: false };
  }
}

export interface ReplySender {
  sendJson: (res: ServerResponse, status: number, body: unknown, extraHeaders?: Record<string, string>) => void;
  sendRawJson: (res: ServerResponse, status: number, buf: Buffer, extraHeaders?: Record<string, string>) => void;
  sendEmpty: (res: ServerResponse, status: number) => void;
}

function originOf(req: IncomingMessage): string {
  const host = req.headers.host;
  return host && host !== '' ? `http://${host}` : 'http://127.0.0.1';
}

function parsePositiveInt(raw: string | null, fallback: number): number {
  if (!raw) return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const API_ROOT_BUF = Buffer.from(
  JSON.stringify({
    current_user_url: '/api/v3/user',
    user_repositories_url: '/api/v3/user/repos',
    repository_url: '/api/v3/repos/{owner}/{repo}',
    rate_limit_url: '/api/v3/rate_limit',
  }),
  'utf8',
);

const API_META_BUF = Buffer.from(
  JSON.stringify({
    installed_version: '3.14.0',
    verifiable_password_authentication: false,
  }),
  'utf8',
);

function fastDecode(seg: string): string {
  return seg.includes('%') ? decodeURIComponent(seg) : seg;
}

function parseAsciiPositiveInt(s: string): number {
  if (s.length === 0) return -1;
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i) - 48;
    if (c < 0 || c > 9) return -1;
    n = n * 10 + c;
  }
  return n > 0 ? n : -1;
}

/** Handle all `/api/v3` routes. Assumes Bearer auth has already been verified. */
export function handleRestApi(
  store: ForgeStore,
  req: IncomingMessage,
  res: ServerResponse,
  method: string,
  pathname: string,
  queryStr: string,
  body: Buffer,
  reply: ReplySender,
): void {
  const sub = pathname.slice('/api/v3'.length);

  // Hot path 1: GET /api/v3/repos/{owner}/{repo}/issues/{number}
  if (method === 'GET' && sub.startsWith('/repos/')) {
    const s1 = sub.indexOf('/', 7);
    if (s1 > 7) {
      const s2 = sub.indexOf('/', s1 + 1);
      if (s2 > s1 + 1 && sub.startsWith('/issues/', s2)) {
        const num = parseAsciiPositiveInt(sub.slice(s2 + 8));
        if (num > 0) {
          const owner = fastDecode(sub.slice(7, s1));
          const repoName = fastDecode(sub.slice(s1 + 1, s2));
          const repo = owner === store.viewer.login ? store.getRepo(owner, repoName) : undefined;
          const issue = repo?.issues.get(num);
          if (!issue) {
            reply.sendJson(res, 404, { message: 'Not Found' });
          } else {
            reply.sendRawJson(res, 200, getIssueJsonBuffer(issue));
          }
          return;
        }
      }
    }
  }

  // Hot path 2: POST /api/v3/repos/{owner}/{repo}/issues
  if (method === 'POST' && sub.startsWith('/repos/') && sub.endsWith('/issues')) {
    const middleEnd = sub.length - 7;
    const s1 = sub.indexOf('/', 7);
    if (s1 > 7 && s1 + 1 < middleEnd && sub.indexOf('/', s1 + 1) === middleEnd) {
      const owner = fastDecode(sub.slice(7, s1));
      const repoName = fastDecode(sub.slice(s1 + 1, middleEnd));
      const repo = owner === store.viewer.login ? store.getRepo(owner, repoName) : undefined;
      if (!repo) {
        reply.sendJson(res, 404, { message: 'Not Found' });
        return;
      }
      const parsed = parseJsonBody(body);
      if (!parsed.ok) {
        reply.sendJson(res, 400, { message: 'Problems parsing JSON' });
        return;
      }
      const title = parsed.value.title;
      if (typeof title !== 'string') {
        reply.sendJson(res, 422, { message: 'Validation Failed: title is required' });
        return;
      }
      const issueBody = typeof parsed.value.body === 'string' ? parsed.value.body : '';
      const rawLabels = Array.isArray(parsed.value.labels)
        ? parsed.value.labels.filter((x): x is string => typeof x === 'string')
        : undefined;
      const created = store.createIssue(repo, { title, body: issueBody, labels: rawLabels });
      if (!created.ok) {
        reply.sendJson(res, created.status, { message: created.message });
        return;
      }
      reply.sendRawJson(res, 201, getIssueJsonBuffer(created.issue));
      return;
    }
  }

  if (method === 'GET' && (sub === '' || sub === '/')) {
    reply.sendRawJson(res, 200, API_ROOT_BUF, { 'x-oauth-scopes': 'repo, read:org' });
    return;
  }

  if (method === 'GET' && sub === '/meta') {
    reply.sendRawJson(res, 200, API_META_BUF);
    return;
  }

  if (method === 'GET' && sub === '/user') {
    reply.sendJson(res, 200, {
      id: store.viewer.id,
      node_id: store.viewer.nodeId,
      login: store.viewer.login,
      name: store.viewer.name,
      email: store.viewer.email,
      type: 'User',
    });
    return;
  }

  if (sub === '/user/repos') {
    if (method === 'GET') {
      const qs = new URLSearchParams(queryStr);
      const perPage = Math.min(100, parsePositiveInt(qs.get('per_page'), 30));
      const page = parsePositiveInt(qs.get('page'), 1);
      const all = store.listOwnerRepos(store.viewer.login);
      const start = (page - 1) * perPage;
      const slice = all.slice(start, start + perPage).map(serializeRepo);
      const extra: Record<string, string> = {};
      if (start + perPage < all.length) {
        const nextUrl = `${originOf(req)}/api/v3/user/repos?per_page=${perPage}&page=${page + 1}`;
        extra.link = `<${nextUrl}>; rel="next"`;
      }
      reply.sendJson(res, 200, slice, extra);
      return;
    }
    if (method === 'POST') {
      const parsed = parseJsonBody(body);
      if (!parsed.ok) {
        reply.sendJson(res, 400, { message: 'Problems parsing JSON' });
        return;
      }
      const name = parsed.value.name;
      if (typeof name !== 'string' || name.trim() === '') {
        reply.sendJson(res, 422, { message: 'Validation Failed: name is required' });
        return;
      }
      const description = typeof parsed.value.description === 'string' ? parsed.value.description : '';
      const isPrivate = typeof parsed.value.private === 'boolean' ? parsed.value.private : false;
      const created = store.createRepo(store.viewer.login, name, { description, isPrivate });
      if (!created.ok) {
        reply.sendJson(res, created.status, { message: created.message });
        return;
      }
      reply.sendJson(res, 201, serializeRepo(created.repo));
      return;
    }
  }

  if (!sub.startsWith('/repos/')) {
    reply.sendJson(res, 404, { message: 'Not Found' });
    return;
  }

  const repoTail = sub.slice('/repos/'.length);
  const slash1 = repoTail.indexOf('/');
  if (slash1 <= 0) {
    reply.sendJson(res, 404, { message: 'Not Found' });
    return;
  }
  const slash2 = repoTail.indexOf('/', slash1 + 1);
  const owner = decodeURIComponent(repoTail.slice(0, slash1));
  const repoName = decodeURIComponent(slash2 < 0 ? repoTail.slice(slash1 + 1) : repoTail.slice(slash1 + 1, slash2));
  const resource = slash2 < 0 ? '' : repoTail.slice(slash2);

  const repo = owner === store.viewer.login ? store.getRepo(owner, repoName) : undefined;
  if (!repo) {
    reply.sendJson(res, 404, { message: 'Not Found' });
    return;
  }

  // /repos/{owner}/{repo}
  if (resource === '') {
    if (method === 'GET') {
      reply.sendJson(res, 200, serializeRepo(repo));
      return;
    }
    if (method === 'PATCH') {
      const parsed = parseJsonBody(body);
      if (!parsed.ok) {
        reply.sendJson(res, 400, { message: 'Problems parsing JSON' });
        return;
      }
      store.updateRepo(repo, {
        description: typeof parsed.value.description === 'string' ? parsed.value.description : undefined,
        private: typeof parsed.value.private === 'boolean' ? parsed.value.private : undefined,
      });
      reply.sendJson(res, 200, serializeRepo(repo));
      return;
    }
    if (method === 'DELETE') {
      store.deleteRepo(owner, repoName);
      reply.sendEmpty(res, 204);
      return;
    }
  }

  // /branches and /branches/{branch}
  if (method === 'GET' && resource === '/branches') {
    const list: Array<Record<string, unknown>> = [];
    for (const [ref, oid] of repo.refs) {
      if (ref.startsWith('refs/heads/')) {
        list.push({ name: ref.slice('refs/heads/'.length), commit: { sha: oid }, protected: false });
      }
    }
    reply.sendJson(res, 200, list);
    return;
  }
  if (method === 'GET' && resource.startsWith('/branches/')) {
    const branchName = decodeURIComponent(resource.slice('/branches/'.length));
    const oid = repo.refs.get(`refs/heads/${branchName}`);
    if (!oid) {
      reply.sendJson(res, 404, { message: 'Branch not found' });
    } else {
      reply.sendJson(res, 200, { name: branchName, commit: { sha: oid }, protected: false });
    }
    return;
  }

  // /git/refs and /git/refs/...
  if (method === 'POST' && resource === '/git/refs') {
    const parsed = parseJsonBody(body);
    if (!parsed.ok) {
      reply.sendJson(res, 400, { message: 'Problems parsing JSON' });
      return;
    }
    const ref = typeof parsed.value.ref === 'string' ? parsed.value.ref : '';
    const sha = typeof parsed.value.sha === 'string' ? parsed.value.sha : '';
    const created = store.createGitRef(repo, ref, sha);
    if (!created.ok) {
      reply.sendJson(res, created.status, { message: created.message });
      return;
    }
    reply.sendJson(res, 201, {
      ref: created.ref,
      object: { type: 'commit', sha: created.sha },
    });
    return;
  }
  if (method === 'GET' && resource.startsWith('/git/refs/')) {
    const refName = `refs/${decodeURIComponent(resource.slice('/git/refs/'.length))}`;
    const oid = repo.refs.get(refName);
    if (!oid) {
      reply.sendJson(res, 404, { message: 'Not Found' });
    } else {
      reply.sendJson(res, 200, { ref: refName, object: { type: 'commit', sha: oid } });
    }
    return;
  }

  // /commits
  if (method === 'GET' && resource === '/commits') {
    const qs = new URLSearchParams(queryStr);
    const shaParam = qs.get('sha') ?? undefined;
    const commits = store.listCommits(repo, shaParam).map((c) => ({
      sha: c.sha,
      commit: {
        message: c.message,
        author: { name: store.viewer.name, email: store.viewer.email, date: repo.createdAt },
        committer: { name: store.viewer.name, email: store.viewer.email, date: repo.createdAt },
      },
      parents: c.parents.map((p) => ({ sha: p })),
    }));
    reply.sendJson(res, 200, commits);
    return;
  }

  // /contents/{path...}
  if (resource === '/contents' || resource.startsWith('/contents/')) {
    const rawRel = resource.length <= '/contents'.length ? '' : resource.slice('/contents/'.length);
    const relPath = rawRel.split('/').map(decodeURIComponent).join('/');
    if (method === 'GET') {
      const qs = new URLSearchParams(queryStr);
      const ref = qs.get('ref') ?? undefined;
      const got = store.readContents(repo, relPath, ref);
      if (!got) {
        reply.sendJson(res, 404, { message: 'Not Found' });
        return;
      }
      if (got.kind === 'dir') {
        reply.sendJson(res, 200, got.entries);
      } else {
        reply.sendJson(res, 200, {
          type: 'file',
          encoding: 'base64',
          name: got.name,
          path: got.path,
          sha: got.sha,
          size: got.size,
          content: got.contentBase64,
        });
      }
      return;
    }
    if (method === 'PUT') {
      const parsed = parseJsonBody(body);
      if (!parsed.ok) {
        reply.sendJson(res, 400, { message: 'Problems parsing JSON' });
        return;
      }
      const content = parsed.value.content;
      const message = parsed.value.message;
      if (typeof content !== 'string' || typeof message !== 'string') {
        reply.sendJson(res, 422, { message: 'Validation Failed: content and message are required' });
        return;
      }
      const branch = typeof parsed.value.branch === 'string' ? parsed.value.branch : undefined;
      const sha = typeof parsed.value.sha === 'string' ? parsed.value.sha : undefined;
      const put = store.putContentFile(repo, relPath, { contentBase64: content, message, branch, sha });
      if (!put.ok) {
        reply.sendJson(res, put.status, { message: put.message });
        return;
      }
      const cleanPath = relPath.replace(/^\/+|\/+$/g, '');
      const name = cleanPath.slice(cleanPath.lastIndexOf('/') + 1);
      reply.sendJson(res, put.created ? 201 : 200, {
        content: {
          name,
          path: cleanPath,
          sha: put.contentSha,
          size: put.size,
          type: 'file',
          encoding: 'base64',
          content,
        },
        commit: {
          sha: put.commitSha,
          message,
        },
      });
      return;
    }
    if (method === 'DELETE') {
      const parsed = parseJsonBody(body);
      if (!parsed.ok) {
        reply.sendJson(res, 400, { message: 'Problems parsing JSON' });
        return;
      }
      const sha = typeof parsed.value.sha === 'string' ? parsed.value.sha : '';
      const message = typeof parsed.value.message === 'string' ? parsed.value.message : 'Delete file';
      const branch = typeof parsed.value.branch === 'string' ? parsed.value.branch : undefined;
      const del = store.deleteContentFile(repo, relPath, { message, sha, branch });
      if (!del.ok) {
        reply.sendJson(res, del.status, { message: del.message });
        return;
      }
      reply.sendJson(res, 200, { content: null, commit: { sha: del.commitSha } });
      return;
    }
  }

  // /labels
  if (resource === '/labels') {
    if (method === 'GET') {
      reply.sendJson(res, 200, [...repo.labels.values()].map((l) => ({
        id: l.id,
        node_id: l.nodeId,
        name: l.name,
        color: l.color,
        description: l.description,
      })));
      return;
    }
    if (method === 'POST') {
      const parsed = parseJsonBody(body);
      if (!parsed.ok) {
        reply.sendJson(res, 400, { message: 'Problems parsing JSON' });
        return;
      }
      const name = parsed.value.name;
      if (typeof name !== 'string' || name.trim() === '') {
        reply.sendJson(res, 422, { message: 'Validation Failed: label name is required' });
        return;
      }
      const color = typeof parsed.value.color === 'string' ? parsed.value.color : 'ededed';
      const description = typeof parsed.value.description === 'string' ? parsed.value.description : '';
      const label = store.createLabel(repo, name, color, description);
      reply.sendJson(res, 201, {
        id: label.id,
        node_id: label.nodeId,
        name: label.name,
        color: label.color,
        description: label.description,
      });
      return;
    }
  }

  // GET /issues (list)
  if (method === 'GET' && resource === '/issues') {
    const qs = new URLSearchParams(queryStr);
    const state = qs.get('state') ?? 'open';
    const direction = qs.get('direction') ?? 'desc';
    const perPage = Math.min(100, parsePositiveInt(qs.get('per_page'), 30));
    const page = parsePositiveInt(qs.get('page'), 1);

    let items = repo.issueOrder.filter((i) => state === 'all' || i.state === state);
    if (direction === 'asc') {
      items = [...items].sort((a, b) => a.createdSeq - b.createdSeq || a.number - b.number);
    } else {
      items = [...items].sort((a, b) => b.createdSeq - a.createdSeq || b.number - a.number);
    }
    const start = (page - 1) * perPage;
    const paged = items.slice(start, start + perPage).map(serializeIssueObject);
    reply.sendJson(res, 200, paged);
    return;
  }

  // /issues/{number} and /issues/{number}/comments
  if (resource.startsWith('/issues/')) {
    const tail = resource.slice('/issues/'.length);
    const slash = tail.indexOf('/');
    const numStr = slash < 0 ? tail : tail.slice(0, slash);
    const num = Number(numStr);
    const subRes = slash < 0 ? '' : tail.slice(slash);
    if (!Number.isInteger(num) || num <= 0) {
      reply.sendJson(res, 404, { message: 'Not Found' });
      return;
    }
    const issue = repo.issues.get(num);
    if (!issue) {
      reply.sendJson(res, 404, { message: 'Not Found' });
      return;
    }

    if (subRes === '' && method === 'PATCH') {
      const parsed = parseJsonBody(body);
      if (!parsed.ok) {
        reply.sendJson(res, 400, { message: 'Problems parsing JSON' });
        return;
      }
      const stateVal = parsed.value.state;
      if (stateVal !== undefined && stateVal !== 'open' && stateVal !== 'closed') {
        reply.sendJson(res, 422, { message: 'Validation Failed: invalid state' });
        return;
      }
      store.updateIssue(issue, {
        title: typeof parsed.value.title === 'string' ? parsed.value.title : undefined,
        body: typeof parsed.value.body === 'string' ? parsed.value.body : undefined,
        state: stateVal,
      });
      reply.sendRawJson(res, 200, getIssueJsonBuffer(issue));
      return;
    }

    if (subRes === '/comments') {
      if (method === 'GET') {
        reply.sendJson(res, 200, issue.comments.map(serializeComment));
        return;
      }
      if (method === 'POST') {
        const parsed = parseJsonBody(body);
        if (!parsed.ok) {
          reply.sendJson(res, 400, { message: 'Problems parsing JSON' });
          return;
        }
        const commentBody = parsed.value.body;
        if (typeof commentBody !== 'string') {
          reply.sendJson(res, 422, { message: 'Validation Failed: comment body is required' });
          return;
        }
        const comment = store.addComment(repo, issue, commentBody);
        reply.sendJson(res, 201, serializeComment(comment));
        return;
      }
    }
  }

  // /pulls
  if (resource === '/pulls') {
    if (method === 'GET') {
      const qs = new URLSearchParams(queryStr);
      const state = qs.get('state') ?? 'open';
      const perPage = Math.min(100, parsePositiveInt(qs.get('per_page'), 30));
      const page = parsePositiveInt(qs.get('page'), 1);
      const filtered = repo.pullOrder
        .filter((p) => state === 'all' || p.state === state)
        .sort((a, b) => b.createdSeq - a.createdSeq);
      const start = (page - 1) * perPage;
      reply.sendJson(res, 200, filtered.slice(start, start + perPage).map((p) => serializePull(repo, p)));
      return;
    }
    if (method === 'POST') {
      const parsed = parseJsonBody(body);
      if (!parsed.ok) {
        reply.sendJson(res, 400, { message: 'Problems parsing JSON' });
        return;
      }
      const title = parsed.value.title;
      const head = parsed.value.head;
      const base = parsed.value.base;
      if (typeof title !== 'string' || typeof head !== 'string' || typeof base !== 'string') {
        reply.sendJson(res, 422, { message: 'Validation Failed: title, head, and base are required' });
        return;
      }
      const prBody = typeof parsed.value.body === 'string' ? parsed.value.body : '';
      const created = store.createPull(repo, { title, body: prBody, head, base });
      if (!created.ok) {
        reply.sendJson(res, created.status, { message: created.message });
        return;
      }
      reply.sendJson(res, 201, serializePull(repo, created.pull));
      return;
    }
  }

  // /pulls/{number}, /pulls/{number}/files, /pulls/{number}/merge
  if (resource.startsWith('/pulls/')) {
    const tail = resource.slice('/pulls/'.length);
    const slash = tail.indexOf('/');
    const numStr = slash < 0 ? tail : tail.slice(0, slash);
    const num = Number(numStr);
    const subRes = slash < 0 ? '' : tail.slice(slash);
    if (!Number.isInteger(num) || num <= 0) {
      reply.sendJson(res, 404, { message: 'Not Found' });
      return;
    }
    const pr = repo.pulls.get(num);
    if (!pr) {
      reply.sendJson(res, 404, { message: 'Not Found' });
      return;
    }
    if (subRes === '' && method === 'GET') {
      reply.sendJson(res, 200, serializePull(repo, pr));
      return;
    }
    if (subRes === '/files' && method === 'GET') {
      const files = store.computeChangedFiles(repo, pr.baseSha, pr.headSha);
      reply.sendJson(res, 200, files);
      return;
    }
    if (subRes === '/merge' && method === 'PUT') {
      const parsed = parseJsonBody(body);
      if (!parsed.ok) {
        reply.sendJson(res, 400, { message: 'Problems parsing JSON' });
        return;
      }
      const commitTitle = typeof parsed.value.commit_title === 'string' ? parsed.value.commit_title : undefined;
      const merged = store.mergePull(repo, num, commitTitle);
      if (!merged.ok) {
        reply.sendJson(res, merged.status, { message: merged.message });
        return;
      }
      reply.sendJson(res, 200, {
        sha: merged.sha,
        merged: true,
        message: 'Pull Request successfully merged',
      });
      return;
    }
  }

  reply.sendJson(res, 404, { message: 'Not Found' });
}
