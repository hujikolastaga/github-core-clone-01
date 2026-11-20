import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  ForgeStore,
  HEX40_RE,
  ZERO_OID,
  decodePackfile,
  encodePackfile,
  hashGitObject,
  type RepoRecord,
  type StoredGitObject,
} from './store.ts';

const EMPTY_PACK = encodePackfile([]);
const MAX_SIDEBAND_CHUNK = 65500;

function pktLine(textOrBuf: string | Buffer): Buffer {
  const payload = typeof textOrBuf === 'string' ? Buffer.from(textOrBuf, 'utf8') : textOrBuf;
  const lenHex = (payload.length + 4).toString(16).padStart(4, '0');
  const out = Buffer.allocUnsafe(4 + payload.length);
  out.write(lenHex, 0, 4, 'ascii');
  payload.copy(out, 4);
  return out;
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

function encodePktStream(items: readonly (string | Buffer)[]): Buffer {
  return Buffer.concat(items.map((item) => (typeof item === 'string' ? pktLine(item) : item)));
}

function wrapSideband64k(packBytes: Buffer): Buffer[] {
  const packets: Buffer[] = [];
  if (packBytes.length === 0) return packets;
  let offset = 0;
  while (offset < packBytes.length) {
    const end = Math.min(packBytes.length, offset + MAX_SIDEBAND_CHUNK);
    const sliceLen = end - offset;
    const pkt = Buffer.allocUnsafe(4 + 1 + sliceLen);
    pkt.write((sliceLen + 5).toString(16).padStart(4, '0'), 0, 4, 'ascii');
    pkt[4] = 0x01;
    packBytes.copy(pkt, 5, offset, end);
    packets.push(pkt);
    offset = end;
  }
  return packets;
}

function parsePktStream(buf: Buffer): { lines: string[]; rest: Buffer } {
  const lines: string[] = [];
  let pos = 0;
  while (pos < buf.length) {
    if (pos + 4 > buf.length) throw new Error('Truncated pkt-line header');
    const hex = buf.subarray(pos, pos + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error(`Invalid pkt-line length ${hex}`);
    const len = Number.parseInt(hex, 16);
    pos += 4;
    if (len === 0) {
      lines.push('__FLUSH__');
      if (pos < buf.length && buf.subarray(pos, pos + 4).toString('ascii') === 'PACK') {
        return { lines, rest: buf.subarray(pos) };
      }
      continue;
    }
    if (len === 1) {
      lines.push('__DELIM__');
      continue;
    }
    if (len === 2) continue;
    if (len < 4 || pos + (len - 4) > buf.length) throw new Error('Truncated pkt-line payload');
    lines.push(buf.subarray(pos, pos + len - 4).toString('utf8'));
    pos += len - 4;
  }
  return { lines, rest: Buffer.alloc(0) };
}

function sortedRefEntries(repo: RepoRecord): Array<[string, string]> {
  return [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
}

function buildUploadV2Advertisement(repo: RepoRecord): Buffer {
  if (repo.uploadV2AdvCache !== undefined) return repo.uploadV2AdvCache;
  const buf = encodePktStream([
    'version 2\n',
    'agent=makefun-forge/1.0\n',
    'ls-refs=unborn\n',
    'fetch=shallow wait-for-done\n',
    'object-format=sha1\n',
    PKT_FLUSH,
  ]);
  repo.uploadV2AdvCache = buf;
  return buf;
}

function buildUploadV0Advertisement(store: ForgeStore, repo: RepoRecord): Buffer {
  if (repo.uploadV0AdvCache !== undefined) return repo.uploadV0AdvCache;
  const headRef = `refs/heads/${repo.defaultBranch}`;
  const caps = `multi_ack_detailed side-band-64k thin-pack ofs-delta shallow no-progress include-tag symref=HEAD:${headRef} agent=makefun-forge/1.0`;
  const parts: Array<string | Buffer> = ['# service=git-upload-pack\n', PKT_FLUSH];
  const entries = sortedRefEntries(repo);

  if (entries.length === 0) {
    parts.push(`${ZERO_OID} capabilities^{}\0${caps}\n`, PKT_FLUSH);
  } else {
    const headTip = repo.refs.get(headRef) ?? entries[0]![1];
    let first = true;
    const emit = (oid: string, name: string): void => {
      if (first) {
        parts.push(`${oid} ${name}\0${caps}\n`);
        first = false;
      } else {
        parts.push(`${oid} ${name}\n`);
      }
    };
    emit(headTip, 'HEAD');
    for (const [name, oid] of entries) {
      emit(oid, name);
      const peeled = store.peelTag(repo, oid);
      if (peeled) parts.push(`${peeled} ${name}^{}\n`);
    }
    parts.push(PKT_FLUSH);
  }

  const buf = encodePktStream(parts);
  repo.uploadV0AdvCache = buf;
  return buf;
}

function buildReceiveV0Advertisement(repo: RepoRecord): Buffer {
  if (repo.receiveV0AdvCache !== undefined) return repo.receiveV0AdvCache;
  const caps = 'report-status report-status-v2 side-band-64k delete-refs ofs-delta atomic agent=makefun-forge/1.0';
  const parts: Array<string | Buffer> = ['# service=git-receive-pack\n', PKT_FLUSH];
  const entries = sortedRefEntries(repo);

  if (entries.length === 0) {
    parts.push(`${ZERO_OID} capabilities^{}\0${caps}\n`, PKT_FLUSH);
  } else {
    let first = true;
    for (const [name, oid] of entries) {
      if (first) {
        parts.push(`${oid} ${name}\0${caps}\n`);
        first = false;
      } else {
        parts.push(`${oid} ${name}\n`);
      }
    }
    parts.push(PKT_FLUSH);
  }

  const buf = encodePktStream(parts);
  repo.receiveV0AdvCache = buf;
  return buf;
}

interface FetchPlan {
  shallow: string[];
  unshallow: string[];
  pack: Buffer;
}

function collectTreeAndBlobs(
  repo: RepoRecord,
  treeOid: string,
  excluded: ReadonlySet<string>,
  out: Map<string, StoredGitObject>,
): void {
  if (excluded.has(treeOid) || out.has(treeOid)) return;
  const treeObj = repo.objects.get(treeOid);
  if (!treeObj || treeObj.type !== 'tree') return;
  out.set(treeOid, treeObj);

  const data = treeObj.data;
  let pos = 0;
  while (pos < data.length) {
    const sp = data.indexOf(0x20, pos);
    if (sp < 0) break;
    const nul = data.indexOf(0x00, sp + 1);
    if (nul < 0 || nul + 21 > data.length) break;
    const mode = data.subarray(pos, sp).toString('ascii');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    pos = nul + 21;
    if (mode === '40000' || mode === '040000') {
      collectTreeAndBlobs(repo, oid, excluded, out);
    } else if (!excluded.has(oid) && !out.has(oid)) {
      const blob = repo.objects.get(oid);
      if (blob) out.set(oid, blob);
    }
  }
}

function computeFetchPlan(
  store: ForgeStore,
  repo: RepoRecord,
  opts: {
    wants: readonly string[];
    haves: readonly string[];
    shallows: readonly string[];
    depth?: number;
  },
): FetchPlan {
  const clientShallows = new Set(opts.shallows);
  const haveSet = new Set(opts.haves);
  const excludedObjects = new Set<string>();

  // Walk haves to mark objects the client already owns, stopping at any client shallow cut.
  const haveQueue: string[] = [...opts.haves];
  const visitedHaveCommits = new Set<string>();
  const dummyMap = new Map<string, StoredGitObject>();
  while (haveQueue.length > 0) {
    const oid = haveQueue.pop()!;
    if (visitedHaveCommits.has(oid)) continue;
    visitedHaveCommits.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    if (obj.type === 'tag') {
      excludedObjects.add(oid);
      if (obj.tagTarget) haveQueue.push(obj.tagTarget);
      continue;
    }
    if (obj.type === 'commit') {
      excludedObjects.add(oid);
      if (obj.treeOid) {
        dummyMap.clear();
        collectTreeAndBlobs(repo, obj.treeOid, excludedObjects, dummyMap);
        for (const k of dummyMap.keys()) excludedObjects.add(k);
      }
      if (!clientShallows.has(oid) && obj.parents) {
        for (const p of obj.parents) {
          if (!visitedHaveCommits.has(p)) haveQueue.push(p);
        }
      }
    }
  }

  const objectsToSend = new Map<string, StoredGitObject>();
  const commitTips: string[] = [];

  for (const w of opts.wants) {
    let cur = w;
    for (let hop = 0; hop < 8; hop += 1) {
      const obj = repo.objects.get(cur);
      if (!obj) break;
      if (obj.type === 'tag') {
        if (!excludedObjects.has(cur)) objectsToSend.set(cur, obj);
        if (!obj.tagTarget) break;
        cur = obj.tagTarget;
      } else {
        if (obj.type === 'commit') commitTips.push(cur);
        else if (!excludedObjects.has(cur)) objectsToSend.set(cur, obj);
        break;
      }
    }
  }

  const shallowOut: string[] = [];
  const unshallowOut: string[] = [];
  const includedCommits: string[] = [];

  if (opts.depth !== undefined && opts.depth >= 1) {
    const maxDepth = opts.depth;
    const minDepth = new Map<string, number>();
    const queue: Array<{ oid: string; d: number }> = [];
    for (const tip of commitTips) {
      if (!minDepth.has(tip)) {
        minDepth.set(tip, 1);
        queue.push({ oid: tip, d: 1 });
      }
    }
    const shallowMarks = new Set<string>();
    const unshallowMarks = new Set<string>();

    while (queue.length > 0) {
      const { oid, d } = queue.shift()!;
      const obj = repo.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      if (!haveSet.has(oid) && !excludedObjects.has(oid)) {
        includedCommits.push(oid);
      }
      const parents = obj.parents ?? [];
      if (d >= maxDepth) {
        if (parents.length > 0) shallowMarks.add(oid);
        continue;
      }
      if (clientShallows.has(oid) && parents.length > 0) {
        unshallowMarks.add(oid);
      }
      for (const p of parents) {
        const prev = minDepth.get(p);
        if (prev === undefined || d + 1 < prev) {
          minDepth.set(p, d + 1);
          queue.push({ oid: p, d: d + 1 });
        }
      }
    }
    shallowOut.push(...shallowMarks);
    unshallowOut.push(...unshallowMarks);
  } else {
    const visited = new Set<string>();
    const stack = [...commitTips];
    while (stack.length > 0) {
      const oid = stack.pop()!;
      if (visited.has(oid) || excludedObjects.has(oid)) continue;
      visited.add(oid);
      const obj = repo.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      includedCommits.push(oid);
      if (clientShallows.has(oid)) continue;
      for (const p of obj.parents ?? []) {
        if (!visited.has(p) && !excludedObjects.has(p)) stack.push(p);
      }
    }
  }

  for (const cOid of includedCommits) {
    const cObj = repo.objects.get(cOid);
    if (!cObj) continue;
    objectsToSend.set(cOid, cObj);
    if (cObj.treeOid) {
      collectTreeAndBlobs(repo, cObj.treeOid, excludedObjects, objectsToSend);
    }
  }

  const pack = objectsToSend.size === 0 ? EMPTY_PACK : encodePackfile([...objectsToSend.values()]);
  return { shallow: shallowOut, unshallow: unshallowOut, pack };
}

function handleLsRefs(store: ForgeStore, repo: RepoRecord, rawLines: readonly string[]): Buffer {
  let wantPeel = false;
  let wantSymrefs = false;
  let wantUnborn = false;
  const prefixes: string[] = [];

  for (const raw of rawLines) {
    const line = raw.endsWith('\n') ? raw.slice(0, -1) : raw;
    if (line === '__DELIM__' || line === '__FLUSH__' || line === '' || line.startsWith('command=') || line.startsWith('agent=') || line.startsWith('object-format=')) {
      continue;
    }
    if (line === 'peel') wantPeel = true;
    else if (line === 'symrefs') wantSymrefs = true;
    else if (line === 'unborn') wantUnborn = true;
    else if (line.startsWith('ref-prefix ')) prefixes.push(line.slice(11));
  }

  const matchesPrefix = (name: string): boolean =>
    prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));

  const out: Array<string | Buffer> = [];
  const headTarget = `refs/heads/${repo.defaultBranch}`;
  if (matchesPrefix('HEAD')) {
    const tip = repo.refs.get(headTarget);
    if (tip !== undefined) {
      out.push(`${tip} HEAD${wantSymrefs ? ` symref-target:${headTarget}` : ''}\n`);
    } else if (wantUnborn) {
      out.push(`unborn HEAD${wantSymrefs ? ` symref-target:${headTarget}` : ''}\n`);
    }
  }

  for (const [name, oid] of sortedRefEntries(repo)) {
    if (!matchesPrefix(name)) continue;
    const peeled = wantPeel ? store.peelTag(repo, oid) : undefined;
    out.push(`${oid} ${name}${peeled ? ` peeled:${peeled}` : ''}\n`);
  }
  out.push(PKT_FLUSH);
  return encodePktStream(out);
}

function handleFetchV2(store: ForgeStore, repo: RepoRecord, rawLines: readonly string[], cacheKey: string): Buffer {
  const cached = repo.fetchResponseCache.get(cacheKey);
  if (cached !== undefined) return cached;

  const wants: string[] = [];
  const haves: string[] = [];
  const shallows: string[] = [];
  let depth: number | undefined;
  let done = false;

  for (const raw of rawLines) {
    const line = raw.endsWith('\n') ? raw.slice(0, -1) : raw;
    if (line.startsWith('want ')) wants.push(line.slice(5).trim());
    else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) shallows.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) depth = Number.parseInt(line.slice(7).trim(), 10);
    else if (line === 'done') done = true;
  }

  if (!done) {
    return encodePktStream(['acknowledgments\n', 'NAK\n', PKT_FLUSH]);
  }

  const plan = computeFetchPlan(store, repo, { wants, haves, shallows, depth });
  const parts: Array<string | Buffer> = [];

  if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
    parts.push('shallow-info\n');
    for (const s of plan.shallow) parts.push(`shallow ${s}\n`);
    for (const u of plan.unshallow) parts.push(`unshallow ${u}\n`);
    parts.push(PKT_DELIM);
  }

  parts.push('packfile\n');
  parts.push(...wrapSideband64k(plan.pack));
  parts.push(PKT_FLUSH);

  const responseBuf = encodePktStream(parts);
  if (repo.fetchResponseCache.size < 64) {
    repo.fetchResponseCache.set(cacheKey, responseBuf);
  }
  return responseBuf;
}

function handleFetchV0(store: ForgeStore, repo: RepoRecord, rawLines: readonly string[]): Buffer {
  const wants: string[] = [];
  const haves: string[] = [];
  const shallows: string[] = [];
  let depth: number | undefined;
  let useSideband = false;

  for (const raw of rawLines) {
    const line = raw.endsWith('\n') ? raw.slice(0, -1) : raw;
    if (line.startsWith('want ')) {
      const tokens = line.slice(5).trim().split(' ');
      if (tokens[0]) wants.push(tokens[0]);
      if (tokens.includes('side-band-64k') || tokens.includes('side-band')) useSideband = true;
    } else if (line.startsWith('have ')) {
      haves.push(line.slice(5).trim());
    } else if (line.startsWith('shallow ')) {
      shallows.push(line.slice(8).trim());
    } else if (line.startsWith('deepen ')) {
      depth = Number.parseInt(line.slice(7).trim(), 10);
    }
  }

  const plan = computeFetchPlan(store, repo, { wants, haves, shallows, depth });
  const parts: Array<string | Buffer> = [];
  for (const s of plan.shallow) parts.push(`shallow ${s}\n`);
  for (const u of plan.unshallow) parts.push(`unshallow ${u}\n`);
  parts.push('NAK\n');
  if (useSideband) {
    parts.push(...wrapSideband64k(plan.pack));
    parts.push(PKT_FLUSH);
  } else {
    parts.push(plan.pack);
  }
  return encodePktStream(parts);
}

function handleReceivePack(store: ForgeStore, repo: RepoRecord, body: Buffer): Buffer {
  const { lines, rest } = parsePktStream(body);
  const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  let useSideband = false;

  for (const raw of lines) {
    if (raw === '__FLUSH__' || raw === '__DELIM__' || raw === '') continue;
    const nul = raw.indexOf('\0');
    const mainPart = (nul >= 0 ? raw.slice(0, nul) : raw).replace(/\n$/, '');
    if (nul >= 0) {
      const capStr = raw.slice(nul + 1).trim();
      if (capStr.split(' ').includes('side-band-64k')) useSideband = true;
    }
    const parts = mainPart.split(' ');
    if (parts.length !== 3 || !HEX40_RE.test(parts[0]!) || !HEX40_RE.test(parts[1]!)) {
      throw new Error('Malformed receive-pack command line');
    }
    commands.push({ oldOid: parts[0]!.toLowerCase(), newOid: parts[1]!.toLowerCase(), ref: parts[2]! });
  }

  let unpackOk = true;
  let unpackError = '';
  if (rest.length > 0) {
    try {
      const unpacked = decodePackfile(rest, (oid) => repo.objects.get(oid));
      for (const [oid, obj] of unpacked) {
        if (hashGitObject(obj.type, obj.data) !== oid) {
          throw new Error(`Hash mismatch for object ${oid}`);
        }
        store.putStoredObject(repo, oid, obj);
      }
    } catch (err) {
      unpackOk = false;
      unpackError = err instanceof Error ? err.message : String(err);
    }
  }

  const reportParts: Array<string | Buffer> = [];
  if (!unpackOk) {
    reportParts.push(`unpack error ${unpackError}\n`);
    for (const cmd of commands) reportParts.push(`ng ${cmd.ref} unpack failed\n`);
  } else {
    reportParts.push('unpack ok\n');
    const outcomes = store.applyPushCommands(repo, commands);
    for (const item of outcomes) {
      reportParts.push(item.ok ? `ok ${item.ref}\n` : `ng ${item.ref} ${item.reason ?? 'rejected'}\n`);
    }
  }
  reportParts.push(PKT_FLUSH);
  const reportBytes = encodePktStream(reportParts);
  if (!useSideband) return reportBytes;
  return Buffer.concat([...wrapSideband64k(reportBytes), PKT_FLUSH]);
}

function sendGitBytes(res: ServerResponse, status: number, contentType: string, body: Buffer): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': body.length,
    'cache-control': 'no-cache',
  });
  res.end(body);
}

/** Dispatch `/{owner}/{repo}.git/...` requests; returns true when route matched. */
export function handleGitHttp(
  store: ForgeStore,
  req: IncomingMessage,
  res: ServerResponse,
  method: string,
  pathname: string,
  queryStr: string,
  body: Buffer,
  sendJsonError: (res: ServerResponse, status: number, msg: string) => void,
): boolean {
  const gitIdx = pathname.indexOf('.git/');
  if (gitIdx <= 1) return false;
  const repoSegment = pathname.slice(1, gitIdx);
  const slash = repoSegment.indexOf('/');
  if (slash <= 0 || repoSegment.indexOf('/', slash + 1) >= 0) return false;

  const owner = decodeURIComponent(repoSegment.slice(0, slash));
  const repoName = decodeURIComponent(repoSegment.slice(slash + 1));
  const subPath = pathname.slice(gitIdx + 4);

  const repo = owner === store.viewer.login ? store.getRepo(owner, repoName) : undefined;
  if (!repo) {
    sendJsonError(res, 404, 'Not Found');
    return true;
  }

  if (method === 'GET' && subPath === '/info/refs') {
    const params = new URLSearchParams(queryStr);
    const service = params.get('service');
    if (service === 'git-upload-pack') {
      const proto = String(req.headers['git-protocol'] ?? '');
      const payload = proto.includes('version=2')
        ? buildUploadV2Advertisement(repo)
        : buildUploadV0Advertisement(store, repo);
      sendGitBytes(res, 200, 'application/x-git-upload-pack-advertisement', payload);
      return true;
    }
    if (service === 'git-receive-pack') {
      const payload = buildReceiveV0Advertisement(repo);
      sendGitBytes(res, 200, 'application/x-git-receive-pack-advertisement', payload);
      return true;
    }
    sendJsonError(res, 400, 'Unsupported git service');
    return true;
  }

  if (method === 'POST' && subPath === '/git-upload-pack') {
    const cacheKey = body.toString('latin1');
    const cached = repo.fetchResponseCache.get(cacheKey);
    if (cached !== undefined) {
      sendGitBytes(res, 200, 'application/x-git-upload-pack-result', cached);
      return true;
    }

    let parsed: { lines: string[] };
    try {
      parsed = parsePktStream(body);
    } catch (err) {
      sendJsonError(res, 400, err instanceof Error ? err.message : 'Invalid pkt-line');
      return true;
    }
    const cmdLine = parsed.lines.find((l) => l.startsWith('command='));
    let reply: Buffer;
    if (cmdLine === 'command=ls-refs\n' || cmdLine === 'command=ls-refs') {
      reply = handleLsRefs(store, repo, parsed.lines);
    } else if (cmdLine === 'command=fetch\n' || cmdLine === 'command=fetch') {
      reply = handleFetchV2(store, repo, parsed.lines, cacheKey);
    } else {
      reply = handleFetchV0(store, repo, parsed.lines);
    }
    if (repo.fetchResponseCache.size < 64 && !repo.fetchResponseCache.has(cacheKey)) {
      repo.fetchResponseCache.set(cacheKey, reply);
    }
    sendGitBytes(res, 200, 'application/x-git-upload-pack-result', reply);
    return true;
  }

  if (method === 'POST' && subPath === '/git-receive-pack') {
    try {
      const reply = handleReceivePack(store, repo, body);
      sendGitBytes(res, 200, 'application/x-git-receive-pack-result', reply);
    } catch (err) {
      sendJsonError(res, 400, err instanceof Error ? err.message : 'Invalid receive-pack body');
    }
    return true;
  }

  sendJsonError(res, 404, 'Not Found');
  return true;
}
