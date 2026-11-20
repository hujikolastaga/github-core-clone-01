import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

export type GitObjectKind = 'commit' | 'tree' | 'blob' | 'tag';

export const ZERO_OID = '0'.repeat(40);
export const HEX40_RE = /^[0-9a-f]{40}$/i;
const EPOCH_BASE_SEC = 1_735_689_600;

export interface ViewerInfo {
  readonly id: number;
  readonly nodeId: string;
  readonly login: string;
  readonly name: string;
  readonly email: string;
}

export const DEFAULT_VIEWER: ViewerInfo = {
  id: 1000,
  nodeId: 'U_adaiversen',
  login: 'adaiversen',
  name: 'ada iversen',
  email: 'adaiversen@example.invalid',
};

export interface StoredGitObject {
  readonly type: GitObjectKind;
  readonly data: Buffer;
  readonly treeOid?: string;
  readonly parents?: readonly string[];
  readonly tagTarget?: string;
  readonly tagTargetType?: GitObjectKind;
  compressed?: Buffer;
}

export interface TreeItem {
  readonly mode: string;
  readonly name: string;
  readonly oid: string;
}

export interface FlatFileEntry {
  readonly mode: string;
  readonly oid: string;
  readonly data: Buffer;
}

export interface LabelRecord {
  readonly id: number;
  readonly nodeId: string;
  readonly name: string;
  readonly color: string;
  readonly description: string;
}

export interface CommentRecord {
  readonly id: number;
  readonly nodeId: string;
  readonly body: string;
  readonly user: { readonly login: string; readonly id: number };
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface IssueRecord {
  readonly id: number;
  readonly nodeId: string;
  readonly number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: LabelRecord[];
  readonly user: { readonly login: string; readonly id: number };
  readonly createdSeq: number;
  readonly createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  readonly comments: CommentRecord[];
  jsonCache?: Buffer;
}

export interface PullFileChange {
  readonly filename: string;
  readonly status: 'added' | 'modified' | 'removed';
  readonly additions: number;
  readonly deletions: number;
  readonly changes: number;
}

export interface PullRecord {
  readonly id: number;
  readonly nodeId: string;
  readonly number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  readonly headRef: string;
  readonly baseRef: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  readonly user: { readonly login: string; readonly id: number };
  readonly createdSeq: number;
  readonly createdAt: string;
  updatedAt: string;
}

export interface RepoRecord {
  readonly id: number;
  readonly nodeId: string;
  readonly owner: string;
  name: string;
  description: string;
  private: boolean;
  defaultBranch: string;
  readonly createdAt: string;
  updatedAt: string;
  readonly objects: Map<string, StoredGitObject>;
  readonly refs: Map<string, string>;
  readonly labels: Map<string, LabelRecord>;
  readonly issues: Map<number, IssueRecord>;
  readonly pulls: Map<number, PullRecord>;
  readonly issueOrder: IssueRecord[];
  readonly pullOrder: PullRecord[];
  nextNumber: number;
  version: number;
  uploadV2AdvCache?: Buffer;
  uploadV0AdvCache?: Buffer;
  receiveV0AdvCache?: Buffer;
  fetchResponseCache: Map<string, Buffer>;
}

export type NodeTarget =
  | { readonly kind: 'Repository'; readonly repo: RepoRecord }
  | { readonly kind: 'Issue'; readonly repo: RepoRecord; readonly issue: IssueRecord }
  | { readonly kind: 'PullRequest'; readonly repo: RepoRecord; readonly pull: PullRecord }
  | { readonly kind: 'IssueComment'; readonly repo: RepoRecord; readonly comment: CommentRecord };

const KIND_TO_PACK_CODE: Record<GitObjectKind, number> = {
  commit: 1,
  tree: 2,
  blob: 3,
  tag: 4,
};

const PACK_CODE_TO_KIND: Record<number, GitObjectKind> = {
  1: 'commit',
  2: 'tree',
  3: 'blob',
  4: 'tag',
};

/** Compute standard Git SHA-1 object ID for a type and payload buffer. */
export function hashGitObject(type: GitObjectKind, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return createHash('sha1').update(header).update(data).digest('hex');
}

/** Extract commit tree OID, parent OIDs, message, and headers quickly. */
export function parseCommitHeader(data: Buffer): {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
} {
  const sep = data.indexOf('\n\n');
  const head = (sep < 0 ? data : data.subarray(0, sep)).toString('utf8');
  const message = sep < 0 ? '' : data.subarray(sep + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5);
    else if (line.startsWith('parent ')) parents.push(line.slice(7));
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

/** Parse an annotated tag payload into its target OID and type. */
export function parseTagHeader(data: Buffer): { object: string; type: GitObjectKind; tag: string } {
  const sep = data.indexOf('\n\n');
  const head = (sep < 0 ? data : data.subarray(0, sep)).toString('utf8');
  let object = '';
  let type: GitObjectKind = 'commit';
  let tag = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7);
    else if (line.startsWith('type ')) type = line.slice(5) as GitObjectKind;
    else if (line.startsWith('tag ')) tag = line.slice(4);
  }
  return { object, type, tag };
}

/** Parse raw binary Git tree entries. */
export function parseTreeEntries(data: Buffer): TreeItem[] {
  const items: TreeItem[] = [];
  let pos = 0;
  while (pos < data.length) {
    const sp = data.indexOf(0x20, pos);
    if (sp < 0) throw new Error('Malformed tree entry: missing mode separator');
    const nul = data.indexOf(0x00, sp + 1);
    if (nul < 0 || nul + 21 > data.length) throw new Error('Malformed tree entry: truncated');
    const mode = data.subarray(pos, sp).toString('ascii');
    const name = data.subarray(sp + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    items.push({ mode, name, oid });
    pos = nul + 21;
  }
  return items;
}

/** Encode sorted tree entries into a canonical Git tree buffer. */
export function encodeTreeBytes(items: readonly TreeItem[]): Buffer {
  const sorted = [...items].sort((a, b) => {
    const aKey = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
    const bKey = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
    return Buffer.compare(aKey, bKey);
  });
  const chunks: Buffer[] = [];
  for (const item of sorted) {
    chunks.push(Buffer.from(`${item.mode} ${item.name}\0`, 'utf8'));
    chunks.push(Buffer.from(item.oid, 'hex'));
  }
  return Buffer.concat(chunks);
}

/** Encode a Git commit buffer from tree, parents, identity, epoch, and message. */
export function encodeCommitBytes(opts: {
  tree: string;
  parents: readonly string[];
  author: string;
  timestampSec: number;
  message: string;
}): Buffer {
  const lines = [`tree ${opts.tree}`];
  for (const p of opts.parents) lines.push(`parent ${p}`);
  lines.push(`author ${opts.author} ${opts.timestampSec} +0000`);
  lines.push(`committer ${opts.author} ${opts.timestampSec} +0000`);
  const msg = opts.message.endsWith('\n') ? opts.message : `${opts.message}\n`;
  lines.push('', msg);
  return Buffer.from(lines.join('\n'), 'utf8');
}

function encodePackObjHeader(typeCode: number, size: number): Buffer {
  const out: number[] = [];
  let byte = ((typeCode & 7) << 4) | (size & 0x0f);
  let rem = size >>> 4;
  while (rem > 0) {
    out.push(byte | 0x80);
    byte = rem & 0x7f;
    rem >>>= 7;
  }
  out.push(byte);
  return Buffer.from(out);
}

/** Build a Git packfile v2 from full objects (reusing cached deflated payloads when present). */
export function encodePackfile(objects: readonly StoredGitObject[]): Buffer {
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);

  const parts: Buffer[] = [header];
  for (const obj of objects) {
    const code = KIND_TO_PACK_CODE[obj.type];
    parts.push(encodePackObjHeader(code, obj.data.length));
    let comp = obj.compressed;
    if (comp === undefined) {
      comp = deflateSync(obj.data, { level: 0 });
      obj.compressed = comp;
    }
    parts.push(comp);
  }
  const body = Buffer.concat(parts);
  const sha = createHash('sha1').update(body).digest();
  return Buffer.concat([body, sha]);
}

function readVarSize(buf: Buffer, offset: number): { value: number; next: number } {
  let b = buf[offset++];
  let value = b & 0x7f;
  let shift = 7;
  while (b & 0x80) {
    if (offset >= buf.length) throw new Error('Truncated varint in delta');
    b = buf[offset++];
    value |= (b & 0x7f) << shift;
    shift += 7;
  }
  return { value, next: offset };
}

function applyGitDelta(base: Buffer, delta: Buffer): Buffer {
  const srcInfo = readVarSize(delta, 0);
  if (srcInfo.value !== base.length) {
    throw new Error(`Delta base length mismatch: expected ${srcInfo.value}, got ${base.length}`);
  }
  const dstInfo = readVarSize(delta, srcInfo.next);
  const targetLen = dstInfo.value;
  let pos = dstInfo.next;
  const out = Buffer.allocUnsafe(targetLen);
  let outPos = 0;

  while (pos < delta.length) {
    const cmd = delta[pos++];
    if (cmd & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      if (cmd & 0x01) copyOffset |= delta[pos++];
      if (cmd & 0x02) copyOffset |= delta[pos++] << 8;
      if (cmd & 0x04) copyOffset |= delta[pos++] << 16;
      if (cmd & 0x08) copyOffset |= delta[pos++] << 24;
      if (cmd & 0x10) copySize |= delta[pos++];
      if (cmd & 0x20) copySize |= delta[pos++] << 8;
      if (cmd & 0x40) copySize |= delta[pos++] << 16;
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, outPos, copyOffset >>> 0, (copyOffset >>> 0) + copySize);
      outPos += copySize;
    } else if (cmd > 0) {
      delta.copy(out, outPos, pos, pos + cmd);
      pos += cmd;
      outPos += cmd;
    } else {
      throw new Error('Invalid delta instruction opcode 0');
    }
  }
  if (outPos !== targetLen) {
    throw new Error(`Delta target length mismatch: wrote ${outPos}, expected ${targetLen}`);
  }
  return out;
}

function inflateFromOffset(buf: Buffer, offset: number): { inflated: Buffer; bytesRead: number } {
  // Node zlib.inflateSync doesn't report consumed bytes directly unless info: true is passed.
  const res = (inflateSync as unknown as (data: Buffer, opts: { info: true }) => { buffer: Buffer; engine: { bytesWritten: number } })(
    buf.subarray(offset),
    { info: true },
  );
  return { inflated: res.buffer, bytesRead: res.engine.bytesWritten };
}

/** Decode a Git packfile v2/v3 (including OFS_DELTA and REF_DELTA) and validate SHA-1 trailer. */
export function decodePackfile(
  pack: Buffer,
  resolveExternal?: (oid: string) => StoredGitObject | undefined,
): Map<string, StoredGitObject> {
  if (pack.length < 32) throw new Error('Packfile too short');
  if (pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('Missing PACK magic');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`Unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);

  const payload = pack.subarray(0, pack.length - 20);
  const expectedTrailer = pack.subarray(pack.length - 20);
  const actualTrailer = createHash('sha1').update(payload).digest();
  if (!expectedTrailer.equals(actualTrailer)) throw new Error('Packfile checksum mismatch');

  interface RawEntry {
    offset: number;
    typeCode: number;
    baseOffset?: number;
    baseOid?: string;
    data: Buffer;
  }

  const entries: RawEntry[] = [];
  const byOffset = new Map<number, StoredGitObject>();
  const byOid = new Map<string, StoredGitObject>();
  let pos = 12;

  for (let i = 0; i < count; i += 1) {
    if (pos >= payload.length) throw new Error('Packfile truncated before declared object count');
    const entryOffset = pos;
    let b = payload[pos++];
    const typeCode = (b >> 4) & 7;
    while (b & 0x80) {
      if (pos >= payload.length) throw new Error('Truncated object header in packfile');
      b = payload[pos++];
    }
    let baseOffset: number | undefined;
    let baseOid: string | undefined;
    if (typeCode === 6) {
      let c = payload[pos++];
      let back = c & 0x7f;
      while (c & 0x80) {
        c = payload[pos++];
        back = ((back + 1) << 7) | (c & 0x7f);
      }
      baseOffset = entryOffset - back;
    } else if (typeCode === 7) {
      if (pos + 20 > payload.length) throw new Error('Truncated REF_DELTA base OID');
      baseOid = payload.subarray(pos, pos + 20).toString('hex');
      pos += 20;
    } else if (typeCode < 1 || typeCode > 4) {
      throw new Error(`Unsupported pack object type ${typeCode}`);
    }

    const { inflated, bytesRead } = inflateFromOffset(payload, pos);
    pos += bytesRead;
    entries.push({ offset: entryOffset, typeCode, baseOffset, baseOid, data: inflated });
  }

  const resolve = (entry: RawEntry): StoredGitObject => {
    const existing = byOffset.get(entry.offset);
    if (existing !== undefined) return existing;
    let type: GitObjectKind;
    let data: Buffer;
    if (entry.typeCode >= 1 && entry.typeCode <= 4) {
      type = PACK_CODE_TO_KIND[entry.typeCode]!;
      data = entry.data;
    } else {
      let baseObj: StoredGitObject | undefined;
      if (entry.typeCode === 6 && entry.baseOffset !== undefined) {
        baseObj = byOffset.get(entry.baseOffset);
      } else if (entry.typeCode === 7 && entry.baseOid !== undefined) {
        baseObj = byOid.get(entry.baseOid) ?? resolveExternal?.(entry.baseOid);
      }
      if (baseObj === undefined) throw new Error('Missing delta base object in packfile');
      type = baseObj.type;
      data = applyGitDelta(baseObj.data, entry.data);
    }
    const obj = createStoredObject(type, data);
    const oid = hashGitObject(type, data);
    byOffset.set(entry.offset, obj);
    byOid.set(oid, obj);
    return obj;
  };

  for (const entry of entries) resolve(entry);
  return byOid;
}

/** Construct a StoredGitObject with parsed commit/tag metadata pre-indexed. */
export function createStoredObject(type: GitObjectKind, data: Buffer): StoredGitObject {
  if (type === 'commit') {
    const meta = parseCommitHeader(data);
    return { type, data, treeOid: meta.tree, parents: meta.parents };
  }
  if (type === 'tag') {
    const meta = parseTagHeader(data);
    return { type, data, tagTarget: meta.object, tagTargetType: meta.type };
  }
  return { type, data };
}

/** Deterministic central forge state shared by REST, GraphQL, Git smart HTTP, and MCP. */
export class ForgeStore {
  readonly viewer: ViewerInfo = DEFAULT_VIEWER;
  readonly reposByOwner = new Map<string, Map<string, RepoRecord>>();
  readonly allViewerRepos: RepoRecord[] = [];
  readonly nodesById = new Map<string, NodeTarget>();
  private nextEntityId = 10_000;
  private seq = 1;

  constructor() {
    this.reposByOwner.set(this.viewer.login, new Map());
  }

  private nextStamp(): { seq: number; iso: string; epochSec: number } {
    const seq = this.seq++;
    const epochSec = EPOCH_BASE_SEC + seq;
    const iso = new Date(epochSec * 1000).toISOString();
    return { seq, iso, epochSec };
  }

  private allocId(): number {
    return this.nextEntityId++;
  }

  private invalidateRepoCaches(repo: RepoRecord): void {
    repo.version += 1;
    repo.uploadV2AdvCache = undefined;
    repo.uploadV0AdvCache = undefined;
    repo.receiveV0AdvCache = undefined;
    if (repo.fetchResponseCache.size > 0) repo.fetchResponseCache.clear();
  }

  createRepo(
    owner: string,
    name: string,
    opts: { description?: string; isPrivate?: boolean } = {},
  ): { ok: true; repo: RepoRecord } | { ok: false; status: number; message: string } {
    if (!name || typeof name !== 'string') {
      return { ok: false, status: 422, message: 'Repository name is required' };
    }
    let map = this.reposByOwner.get(owner);
    if (map === undefined) {
      map = new Map();
      this.reposByOwner.set(owner, map);
    }
    if (map.has(name)) {
      return { ok: false, status: 422, message: 'Repository creation failed: name already exists on this account' };
    }
    const stamp = this.nextStamp();
    const id = this.allocId();
    const nodeId = `R_${id}`;
    const repo: RepoRecord = {
      id,
      nodeId,
      owner,
      name,
      description: opts.description ?? '',
      private: Boolean(opts.isPrivate),
      defaultBranch: 'main',
      createdAt: stamp.iso,
      updatedAt: stamp.iso,
      objects: new Map(),
      refs: new Map(),
      labels: new Map(),
      issues: new Map(),
      pulls: new Map(),
      issueOrder: [],
      pullOrder: [],
      nextNumber: 1,
      version: 1,
      fetchResponseCache: new Map(),
    };
    map.set(name, repo);
    if (owner === this.viewer.login) this.allViewerRepos.push(repo);
    this.nodesById.set(nodeId, { kind: 'Repository', repo });
    return { ok: true, repo };
  }

  getRepo(owner: string, name: string): RepoRecord | undefined {
    return this.reposByOwner.get(owner)?.get(name);
  }

  updateRepo(repo: RepoRecord, patch: { description?: string; private?: boolean }): RepoRecord {
    const stamp = this.nextStamp();
    if (patch.description !== undefined) repo.description = patch.description;
    if (patch.private !== undefined) repo.private = patch.private;
    repo.updatedAt = stamp.iso;
    return repo;
  }

  deleteRepo(owner: string, name: string): boolean {
    const map = this.reposByOwner.get(owner);
    const repo = map?.get(name);
    if (repo === undefined) return false;
    map!.delete(name);
    this.nodesById.delete(repo.nodeId);
    for (const issue of repo.issues.values()) {
      this.nodesById.delete(issue.nodeId);
      for (const c of issue.comments) this.nodesById.delete(c.nodeId);
    }
    for (const pull of repo.pulls.values()) this.nodesById.delete(pull.nodeId);
    if (owner === this.viewer.login) {
      const idx = this.allViewerRepos.indexOf(repo);
      if (idx >= 0) this.allViewerRepos.splice(idx, 1);
    }
    return true;
  }

  listOwnerRepos(owner: string): RepoRecord[] {
    if (owner === this.viewer.login) return this.allViewerRepos;
    const map = this.reposByOwner.get(owner);
    return map ? [...map.values()] : [];
  }

  putObject(repo: RepoRecord, type: GitObjectKind, data: Buffer): string {
    const oid = hashGitObject(type, data);
    if (!repo.objects.has(oid)) {
      repo.objects.set(oid, createStoredObject(type, data));
    }
    return oid;
  }

  putStoredObject(repo: RepoRecord, oid: string, obj: StoredGitObject): void {
    if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
  }

  /** Peel an annotated tag OID down to its target commit/tree/blob OID. */
  peelTag(repo: RepoRecord, oid: string): string | undefined {
    let cur = oid;
    for (let hop = 0; hop < 8; hop += 1) {
      const obj = repo.objects.get(cur);
      if (!obj || obj.type !== 'tag' || !obj.tagTarget) return hop === 0 ? undefined : cur;
      cur = obj.tagTarget;
    }
    return cur;
  }

  /** Return true if `ancestorOid` is reachable from `descendantOid` (O(1) fast path on direct parent). */
  isAncestor(repo: RepoRecord, ancestorOid: string, descendantOid: string): boolean {
    if (ancestorOid === descendantOid) return true;
    const tipObj = repo.objects.get(descendantOid);
    if (!tipObj || tipObj.type !== 'commit') return false;
    if (tipObj.parents?.includes(ancestorOid)) return true;

    const visited = new Set<string>([descendantOid]);
    const queue: string[] = [...(tipObj.parents ?? [])];
    while (queue.length > 0) {
      const cur = queue.pop()!;
      if (cur === ancestorOid) return true;
      if (visited.has(cur)) continue;
      visited.add(cur);
      const obj = repo.objects.get(cur);
      if (obj?.parents) {
        for (const p of obj.parents) {
          if (!visited.has(p)) queue.push(p);
        }
      }
    }
    return false;
  }

  /** Apply a set of validated smart-HTTP ref updates atomically per ref. */
  applyPushCommands(
    repo: RepoRecord,
    commands: readonly { oldOid: string; newOid: string; ref: string }[],
  ): Array<{ ref: string; ok: boolean; reason?: string }> {
    const results: Array<{ ref: string; ok: boolean; reason?: string }> = [];
    let mutated = false;

    for (const cmd of commands) {
      const currentOid = repo.refs.get(cmd.ref) ?? ZERO_OID;
      if (cmd.newOid === ZERO_OID) {
        if (currentOid === ZERO_OID || (cmd.oldOid !== ZERO_OID && currentOid !== cmd.oldOid)) {
          results.push({ ref: cmd.ref, ok: false, reason: 'stale old oid' });
          continue;
        }
        repo.refs.delete(cmd.ref);
        mutated = true;
        results.push({ ref: cmd.ref, ok: true });
        continue;
      }

      if (!repo.objects.has(cmd.newOid)) {
        results.push({ ref: cmd.ref, ok: false, reason: 'missing object' });
        continue;
      }

      if (currentOid === ZERO_OID) {
        if (cmd.oldOid !== ZERO_OID) {
          results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
          continue;
        }
        repo.refs.set(cmd.ref, cmd.newOid);
        mutated = true;
        results.push({ ref: cmd.ref, ok: true });
        continue;
      }

      if (cmd.oldOid !== ZERO_OID && cmd.oldOid !== currentOid) {
        results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
        continue;
      }

      const target = repo.objects.get(cmd.newOid);
      if (target?.type === 'commit' && !this.isAncestor(repo, currentOid, cmd.newOid)) {
        results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
        continue;
      }

      repo.refs.set(cmd.ref, cmd.newOid);
      mutated = true;
      results.push({ ref: cmd.ref, ok: true });
    }

    if (mutated) this.invalidateRepoCaches(repo);
    return results;
  }

  /** Flatten a commit or tree OID into path -> { mode, oid, data }. */
  flattenTree(repo: RepoRecord, treeOrCommitOid: string): Map<string, FlatFileEntry> {
    const out = new Map<string, FlatFileEntry>();
    let rootTreeOid = treeOrCommitOid;
    const obj = repo.objects.get(treeOrCommitOid);
    if (!obj) return out;
    if (obj.type === 'commit' && obj.treeOid) rootTreeOid = obj.treeOid;

    const walk = (treeOid: string, prefix: string): void => {
      const treeObj = repo.objects.get(treeOid);
      if (!treeObj || treeObj.type !== 'tree') return;
      for (const entry of parseTreeEntries(treeObj.data)) {
        const full = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
        if (entry.mode === '40000' || entry.mode === '040000') {
          walk(entry.oid, full);
        } else {
          const blob = repo.objects.get(entry.oid);
          if (blob) out.set(full, { mode: entry.mode, oid: entry.oid, data: blob.data });
        }
      }
    };
    walk(rootTreeOid, '');
    return out;
  }

  /** Build nested Git trees in `repo` from a flat map of path -> { mode, oid, data }. */
  writeTreeFromFlat(repo: RepoRecord, files: ReadonlyMap<string, FlatFileEntry>): string {
    interface DirNode {
      files: Map<string, { mode: string; oid: string }>;
      dirs: Map<string, DirNode>;
    }
    const mk = (): DirNode => ({ files: new Map(), dirs: new Map() });
    const root = mk();
    for (const [filePath, entry] of files) {
      const segs = filePath.split('/').filter(Boolean);
      if (segs.length === 0) continue;
      let cur = root;
      for (let i = 0; i < segs.length - 1; i += 1) {
        let next = cur.dirs.get(segs[i]!);
        if (!next) {
          next = mk();
          cur.dirs.set(segs[i]!, next);
        }
        cur = next;
      }
      cur.files.set(segs[segs.length - 1]!, { mode: entry.mode, oid: entry.oid });
    }
    const build = (node: DirNode): string => {
      const items: TreeItem[] = [];
      for (const [name, f] of node.files) items.push({ mode: f.mode, name, oid: f.oid });
      for (const [name, d] of node.dirs) items.push({ mode: '40000', name, oid: build(d) });
      return this.putObject(repo, 'tree', encodeTreeBytes(items));
    };
    return build(root);
  }

  resolveRefOid(repo: RepoRecord, refOrSha?: string): string | undefined {
    const target = refOrSha && refOrSha !== '' ? refOrSha : repo.defaultBranch;
    if (HEX40_RE.test(target) && repo.objects.has(target.toLowerCase())) {
      return target.toLowerCase();
    }
    if (target.startsWith('refs/')) return repo.refs.get(target);
    return repo.refs.get(`refs/heads/${target}`) ?? repo.refs.get(`refs/tags/${target}`);
  }

  /** Read directory entries or a single file at `relPath` on a ref. */
  readContents(
    repo: RepoRecord,
    relPath: string,
    ref?: string,
  ):
    | { kind: 'file'; name: string; path: string; sha: string; size: number; contentBase64: string }
    | { kind: 'dir'; entries: Array<{ type: 'file' | 'dir'; name: string; path: string; sha: string; size: number }> }
    | null {
    const commitOid = this.resolveRefOid(repo, ref);
    if (!commitOid) return null;
    const commitObj = repo.objects.get(commitOid);
    if (!commitObj || commitObj.type !== 'commit' || !commitObj.treeOid) return null;

    const clean = relPath.replace(/^\/+|\/+$/g, '');
    const segments = clean === '' ? [] : clean.split('/').filter(Boolean);
    let curOid = commitObj.treeOid;

    for (let i = 0; i < segments.length; i += 1) {
      const treeObj = repo.objects.get(curOid);
      if (!treeObj || treeObj.type !== 'tree') return null;
      const seg = segments[i]!;
      const item = parseTreeEntries(treeObj.data).find((e) => e.name === seg);
      if (!item) return null;
      if (i === segments.length - 1) {
        if (item.mode === '40000' || item.mode === '040000') {
          curOid = item.oid;
          break;
        }
        const blob = repo.objects.get(item.oid);
        if (!blob || blob.type !== 'blob') return null;
        return {
          kind: 'file',
          name: item.name,
          path: clean,
          sha: item.oid,
          size: blob.data.length,
          contentBase64: blob.data.toString('base64'),
        };
      }
      if (item.mode !== '40000' && item.mode !== '040000') return null;
      curOid = item.oid;
    }

    const dirObj = repo.objects.get(curOid);
    if (!dirObj || dirObj.type !== 'tree') return null;
    const entries = parseTreeEntries(dirObj.data).map((item) => {
      const isDir = item.mode === '40000' || item.mode === '040000';
      const blob = isDir ? undefined : repo.objects.get(item.oid);
      return {
        type: (isDir ? 'dir' : 'file') as 'file' | 'dir',
        name: item.name,
        path: clean === '' ? item.name : `${clean}/${item.name}`,
        sha: item.oid,
        size: blob ? blob.data.length : 0,
      };
    });
    return { kind: 'dir', entries };
  }

  /** Create/update a file via Contents API, creating a real Git commit on the target branch. */
  putContentFile(
    repo: RepoRecord,
    relPath: string,
    opts: { contentBase64: string; message: string; branch?: string; sha?: string },
  ):
    | { ok: true; created: boolean; contentSha: string; commitSha: string; size: number }
    | { ok: false; status: number; message: string } {
    const clean = relPath.replace(/^\/+|\/+$/g, '');
    if (clean === '') return { ok: false, status: 422, message: 'Invalid path' };

    const branch = opts.branch && opts.branch !== '' ? opts.branch : repo.defaultBranch;
    const fullRef = `refs/heads/${branch}`;
    let baseTip = repo.refs.get(fullRef);
    if (baseTip === undefined && branch !== repo.defaultBranch) {
      baseTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
    }

    const files = baseTip ? this.flattenTree(repo, baseTip) : new Map<string, FlatFileEntry>();
    const existing = files.get(clean);

    if (opts.sha !== undefined) {
      if (!existing || existing.oid.toLowerCase() !== opts.sha.toLowerCase()) {
        return { ok: false, status: 409, message: `${clean} does not match ${opts.sha}` };
      }
    } else if (existing !== undefined) {
      return { ok: false, status: 422, message: `Invalid request: sha wasn't supplied for existing file ${clean}` };
    }

    const rawBytes = Buffer.from(opts.contentBase64.replace(/\s+/g, ''), 'base64');
    const contentSha = this.putObject(repo, 'blob', rawBytes);
    files.set(clean, { mode: '100644', oid: contentSha, data: rawBytes });

    const treeOid = this.writeTreeFromFlat(repo, files);
    const stamp = this.nextStamp();
    const commitBytes = encodeCommitBytes({
      tree: treeOid,
      parents: baseTip ? [baseTip] : [],
      author: `${this.viewer.name} <${this.viewer.email}>`,
      timestampSec: stamp.epochSec,
      message: opts.message || `Update ${clean}`,
    });
    const commitSha = this.putObject(repo, 'commit', commitBytes);
    repo.refs.set(fullRef, commitSha);
    repo.updatedAt = stamp.iso;
    this.invalidateRepoCaches(repo);

    return { ok: true, created: existing === undefined, contentSha, commitSha, size: rawBytes.length };
  }

  /** Delete a file via Contents API, creating a real Git commit on the target branch. */
  deleteContentFile(
    repo: RepoRecord,
    relPath: string,
    opts: { message: string; sha: string; branch?: string },
  ): { ok: true; commitSha: string } | { ok: false; status: number; message: string } {
    const clean = relPath.replace(/^\/+|\/+$/g, '');
    const branch = opts.branch && opts.branch !== '' ? opts.branch : repo.defaultBranch;
    const fullRef = `refs/heads/${branch}`;
    const baseTip = repo.refs.get(fullRef);
    if (!baseTip) return { ok: false, status: 404, message: 'Not Found' };

    const files = this.flattenTree(repo, baseTip);
    const existing = files.get(clean);
    if (!existing) return { ok: false, status: 404, message: 'Not Found' };
    if (existing.oid.toLowerCase() !== opts.sha.toLowerCase()) {
      return { ok: false, status: 409, message: `${clean} does not match ${opts.sha}` };
    }
    files.delete(clean);
    const treeOid = this.writeTreeFromFlat(repo, files);
    const stamp = this.nextStamp();
    const commitBytes = encodeCommitBytes({
      tree: treeOid,
      parents: [baseTip],
      author: `${this.viewer.name} <${this.viewer.email}>`,
      timestampSec: stamp.epochSec,
      message: opts.message || `Delete ${clean}`,
    });
    const commitSha = this.putObject(repo, 'commit', commitBytes);
    repo.refs.set(fullRef, commitSha);
    repo.updatedAt = stamp.iso;
    this.invalidateRepoCaches(repo);
    return { ok: true, commitSha };
  }

  /** Create a ref in `repo.refs`. */
  createGitRef(
    repo: RepoRecord,
    ref: string,
    sha: string,
  ): { ok: true; ref: string; sha: string } | { ok: false; status: number; message: string } {
    if (!ref.startsWith('refs/') || !HEX40_RE.test(sha) || !repo.objects.has(sha.toLowerCase())) {
      return { ok: false, status: 422, message: 'Reference update failed: invalid ref or unknown sha' };
    }
    if (repo.refs.has(ref)) {
      return { ok: false, status: 422, message: 'Reference already exists' };
    }
    repo.refs.set(ref, sha.toLowerCase());
    this.invalidateRepoCaches(repo);
    return { ok: true, ref, sha: sha.toLowerCase() };
  }

  /** List commits reachable from a ref or sha in reverse-chronological/topological order. */
  listCommits(repo: RepoRecord, refOrSha?: string): Array<{ sha: string; message: string; author: string; parents: string[] }> {
    const tip = this.resolveRefOid(repo, refOrSha);
    if (!tip) return [];
    const seen = new Set<string>();
    const out: Array<{ sha: string; message: string; author: string; parents: string[] }> = [];
    const queue: string[] = [tip];
    while (queue.length > 0 && out.length < 100) {
      const oid = queue.shift()!;
      if (seen.has(oid)) continue;
      seen.add(oid);
      const obj = repo.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      const parsed = parseCommitHeader(obj.data);
      out.push({ sha: oid, message: parsed.message.replace(/\n$/, ''), author: parsed.author, parents: parsed.parents });
      for (const p of parsed.parents) {
        if (!seen.has(p)) queue.push(p);
      }
    }
    return out;
  }

  /** Find lowest common ancestor commit between two commit OIDs. */
  findMergeBase(repo: RepoRecord, commitA: string, commitB: string): string | null {
    const ancestorsA = new Set<string>();
    const qA = [commitA];
    while (qA.length > 0) {
      const c = qA.pop()!;
      if (ancestorsA.has(c)) continue;
      ancestorsA.add(c);
      const obj = repo.objects.get(c);
      if (obj?.parents) qA.push(...obj.parents);
    }
    const visitedB = new Set<string>();
    const qB = [commitB];
    while (qB.length > 0) {
      const c = qB.shift()!;
      if (ancestorsA.has(c)) return c;
      if (visitedB.has(c)) continue;
      visitedB.add(c);
      const obj = repo.objects.get(c);
      if (obj?.parents) qB.push(...obj.parents);
    }
    return null;
  }

  /** Compute changed files between two commit/tree snapshots. */
  computeChangedFiles(repo: RepoRecord, baseOid: string, headOid: string): PullFileChange[] {
    const mergeBase = this.findMergeBase(repo, baseOid, headOid);
    const compareFrom = mergeBase ?? baseOid;
    const baseFiles = this.flattenTree(repo, compareFrom);
    const headFiles = this.flattenTree(repo, headOid);
    const paths = new Set<string>([...baseFiles.keys(), ...headFiles.keys()]);
    const changes: PullFileChange[] = [];

    const lineCount = (buf: Buffer): number => {
      if (buf.length === 0) return 0;
      const lines = buf.toString('utf8').split('\n');
      return lines[lines.length - 1] === '' ? Math.max(1, lines.length - 1) : lines.length;
    };

    for (const p of [...paths].sort()) {
      const b = baseFiles.get(p);
      const h = headFiles.get(p);
      if (!b && h) {
        const adds = Math.max(1, lineCount(h.data));
        changes.push({ filename: p, status: 'added', additions: adds, deletions: 0, changes: adds });
      } else if (b && !h) {
        const dels = Math.max(1, lineCount(b.data));
        changes.push({ filename: p, status: 'removed', additions: 0, deletions: dels, changes: dels });
      } else if (b && h && b.oid !== h.oid) {
        const bLines = b.data.toString('utf8').split('\n');
        const hLines = h.data.toString('utf8').split('\n');
        const adds = Math.max(1, hLines.length);
        const dels = Math.max(1, bLines.length);
        changes.push({ filename: p, status: 'modified', additions: adds, deletions: dels, changes: adds + dels });
      }
    }
    return changes;
  }

  /** Perform a 3-way squash merge check/execution; returns conflict when both sides edited the same path differently. */
  private computeThreeWayMerge(
    repo: RepoRecord,
    baseTip: string,
    headTip: string,
  ): { ok: true; mergedTree: Map<string, FlatFileEntry> } | { ok: false } {
    const lca = this.findMergeBase(repo, baseTip, headTip);
    const lcaFiles = lca ? this.flattenTree(repo, lca) : new Map<string, FlatFileEntry>();
    const baseFiles = this.flattenTree(repo, baseTip);
    const headFiles = this.flattenTree(repo, headTip);
    const merged = new Map<string, FlatFileEntry>();
    const allPaths = new Set<string>([...lcaFiles.keys(), ...baseFiles.keys(), ...headFiles.keys()]);

    for (const p of allPaths) {
      const a = lcaFiles.get(p);
      const b = baseFiles.get(p);
      const h = headFiles.get(p);

      const same = (x?: FlatFileEntry, y?: FlatFileEntry): boolean =>
        (!x && !y) || Boolean(x && y && x.oid === y.oid && x.mode === y.mode);

      if (same(b, h)) {
        if (b) merged.set(p, b);
      } else if (same(a, b)) {
        if (h) merged.set(p, h);
      } else if (same(a, h)) {
        if (b) merged.set(p, b);
      } else {
        return { ok: false };
      }
    }
    return { ok: true, mergedTree: merged };
  }

  createLabel(repo: RepoRecord, name: string, color = 'ededed', description = ''): LabelRecord {
    const existing = repo.labels.get(name);
    if (existing) return existing;
    const id = this.allocId();
    const label: LabelRecord = { id, nodeId: `LA_${id}`, name, color, description };
    repo.labels.set(name, label);
    return label;
  }

  createIssue(
    repo: RepoRecord,
    input: { title: string; body?: string; labels?: readonly string[] },
  ): { ok: true; issue: IssueRecord } | { ok: false; status: number; message: string } {
    const resolvedLabels: LabelRecord[] = [];
    if (input.labels !== undefined) {
      for (const name of input.labels) {
        const lbl = repo.labels.get(name);
        if (!lbl) {
          return { ok: false, status: 422, message: `Validation Failed: unknown label ${name}` };
        }
        resolvedLabels.push(lbl);
      }
    }
    const stamp = this.nextStamp();
    const id = this.allocId();
    const number = repo.nextNumber++;
    const nodeId = `I_${id}`;
    const issue: IssueRecord = {
      id,
      nodeId,
      number,
      title: input.title,
      body: input.body ?? '',
      state: 'open',
      labels: resolvedLabels,
      user: { login: this.viewer.login, id: this.viewer.id },
      createdSeq: stamp.seq,
      createdAt: stamp.iso,
      updatedAt: stamp.iso,
      closedAt: null,
      comments: [],
    };
    repo.issues.set(number, issue);
    repo.issueOrder.push(issue);
    this.nodesById.set(nodeId, { kind: 'Issue', repo, issue });
    return { ok: true, issue };
  }

  updateIssue(
    issue: IssueRecord,
    patch: { title?: string; body?: string; state?: 'open' | 'closed' },
  ): IssueRecord {
    const stamp = this.nextStamp();
    if (patch.title !== undefined) issue.title = patch.title;
    if (patch.body !== undefined) issue.body = patch.body;
    if (patch.state !== undefined && patch.state !== issue.state) {
      issue.state = patch.state;
      issue.closedAt = patch.state === 'closed' ? stamp.iso : null;
    }
    issue.updatedAt = stamp.iso;
    issue.jsonCache = undefined;
    return issue;
  }

  addComment(repo: RepoRecord, issue: IssueRecord, body: string): CommentRecord {
    const stamp = this.nextStamp();
    const id = this.allocId();
    const nodeId = `IC_${id}`;
    const comment: CommentRecord = {
      id,
      nodeId,
      body,
      user: { login: this.viewer.login, id: this.viewer.id },
      createdAt: stamp.iso,
      updatedAt: stamp.iso,
    };
    issue.comments.push(comment);
    this.nodesById.set(nodeId, { kind: 'IssueComment', repo, comment });
    return comment;
  }

  createPull(
    repo: RepoRecord,
    input: { title: string; body?: string; head: string; base: string },
  ): { ok: true; pull: PullRecord } | { ok: false; status: number; message: string } {
    const headSha = this.resolveRefOid(repo, input.head);
    const baseSha = this.resolveRefOid(repo, input.base);
    if (!headSha || !baseSha) {
      return { ok: false, status: 422, message: 'Validation Failed: head or base branch not found' };
    }
    for (const existing of repo.pullOrder) {
      if (existing.state === 'open' && existing.headRef === input.head && existing.baseRef === input.base) {
        return { ok: false, status: 422, message: `A pull request already exists for ${repo.owner}:${input.head}` };
      }
    }
    const stamp = this.nextStamp();
    const id = this.allocId();
    const number = repo.nextNumber++;
    const nodeId = `PR_${id}`;
    const pull: PullRecord = {
      id,
      nodeId,
      number,
      title: input.title,
      body: input.body ?? '',
      state: 'open',
      headRef: input.head,
      baseRef: input.base,
      headSha,
      baseSha,
      merged: false,
      mergedAt: null,
      mergeCommitSha: null,
      user: { login: this.viewer.login, id: this.viewer.id },
      createdSeq: stamp.seq,
      createdAt: stamp.iso,
      updatedAt: stamp.iso,
    };
    repo.pulls.set(number, pull);
    repo.pullOrder.push(pull);
    this.nodesById.set(nodeId, { kind: 'PullRequest', repo, pull });
    return { ok: true, pull };
  }

  isPullMergeable(repo: RepoRecord, pull: PullRecord): 'MERGEABLE' | 'CONFLICTING' {
    if (pull.merged) return 'MERGEABLE';
    const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`) ?? pull.baseSha;
    const headTip = repo.refs.get(`refs/heads/${pull.headRef}`) ?? pull.headSha;
    return this.computeThreeWayMerge(repo, baseTip, headTip).ok ? 'MERGEABLE' : 'CONFLICTING';
  }

  mergePull(
    repo: RepoRecord,
    number: number,
    commitTitle?: string,
  ): { ok: true; pull: PullRecord; sha: string } | { ok: false; status: number; message: string } {
    const pull = repo.pulls.get(number);
    if (!pull) return { ok: false, status: 404, message: 'Not Found' };
    if (pull.state !== 'open' || pull.merged) {
      return { ok: false, status: 405, message: 'Pull Request is not mergeable' };
    }
    const baseFullRef = `refs/heads/${pull.baseRef}`;
    const baseTip = repo.refs.get(baseFullRef) ?? pull.baseSha;
    const headTip = repo.refs.get(`refs/heads/${pull.headRef}`) ?? pull.headSha;

    const merged = this.computeThreeWayMerge(repo, baseTip, headTip);
    if (!merged.ok) {
      return { ok: false, status: 405, message: 'Pull Request is not mergeable: merge conflict' };
    }

    const treeOid = this.writeTreeFromFlat(repo, merged.mergedTree);
    const stamp = this.nextStamp();
    const commitBytes = encodeCommitBytes({
      tree: treeOid,
      parents: [baseTip],
      author: `${this.viewer.name} <${this.viewer.email}>`,
      timestampSec: stamp.epochSec,
      message: commitTitle ?? `${pull.title} (#${pull.number})`,
    });
    const mergeSha = this.putObject(repo, 'commit', commitBytes);
    repo.refs.set(baseFullRef, mergeSha);
    this.invalidateRepoCaches(repo);

    pull.state = 'closed';
    pull.merged = true;
    pull.mergedAt = stamp.iso;
    pull.mergeCommitSha = mergeSha;
    pull.updatedAt = stamp.iso;

    return { ok: true, pull, sha: mergeSha };
  }
}
