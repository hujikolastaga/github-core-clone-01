import type { ServerResponse } from 'node:http';
import type { ReplySender } from './rest.ts';
import {
  ForgeStore,
  type CommentRecord,
  type IssueRecord,
  type PullRecord,
  type RepoRecord,
} from './store.ts';

type TokenKind = 'name' | 'int' | 'float' | 'string' | 'punct' | 'eof';

interface Token {
  readonly kind: TokenKind;
  readonly value: string;
}

interface SelectionNode {
  readonly kind: 'field' | 'inlineFragment' | 'fragmentSpread';
  readonly name: string;
  readonly alias?: string;
  readonly typeCondition?: string;
  readonly args?: Record<string, unknown>;
  readonly selections?: SelectionNode[];
}

interface OperationDef {
  readonly opType: 'query' | 'mutation';
  readonly name?: string;
  readonly defaults: Record<string, unknown>;
  readonly selections: SelectionNode[];
}

interface DocumentAst {
  readonly operations: OperationDef[];
  readonly fragments: Map<string, { typeCondition: string; selections: SelectionNode[] }>;
}

const KNOWN_FIELDS: Record<string, ReadonlySet<string>> = {
  Query: new Set(['viewer', 'repository', 'node', '__type', '__typename']),
  Mutation: new Set(['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment', '__typename']),
  User: new Set(['login', 'id', 'name', '__typename']),
  Repository: new Set([
    'id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef',
    'viewerPermission', 'hasIssuesEnabled', 'isPrivate', 'description',
    'issue', 'issues', 'pullRequests', 'pullRequest', '__typename',
  ]),
  Ref: new Set(['name', 'prefix', '__typename']),
  Issue: new Set(['id', 'number', 'title', 'state', 'body', 'createdAt', 'updatedAt', 'closedAt', '__typename']),
  PullRequest: new Set([
    'id', 'number', 'title', 'body', 'headRefName', 'baseRefName',
    'mergeable', 'state', 'merged', 'mergedAt', 'files', '__typename',
  ]),
  IssueConnection: new Set(['nodes', 'edges', 'pageInfo', 'totalCount', '__typename']),
  PullRequestConnection: new Set(['nodes', 'edges', 'pageInfo', 'totalCount', '__typename']),
  PullRequestFileConnection: new Set(['nodes', 'pageInfo', 'totalCount', '__typename']),
  PullRequestFile: new Set(['path', 'additions', 'deletions', 'changeType', '__typename']),
  PageInfo: new Set(['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor', '__typename']),
  CreateIssuePayload: new Set(['issue', 'clientMutationId', '__typename']),
  CloseIssuePayload: new Set(['issue', 'clientMutationId', '__typename']),
  CreatePullRequestPayload: new Set(['pullRequest', 'clientMutationId', '__typename']),
  MergePullRequestPayload: new Set(['pullRequest', 'clientMutationId', '__typename']),
  AddCommentPayload: new Set(['commentEdge', 'clientMutationId', '__typename']),
  CommentEdge: new Set(['node', '__typename']),
  Comment: new Set(['id', 'body', 'createdAt', '__typename']),
  __Type: new Set(['name', 'kind', 'fields', 'enumValues', '__typename']),
  __Field: new Set(['name', 'isDeprecated', '__typename']),
  __EnumValue: new Set(['name', 'isDeprecated', '__typename']),
};

const INTROSPECTION_TYPES: Record<string, { kind: string; fields?: string[]; enumValues?: string[] }> = {
  Issue: {
    kind: 'OBJECT',
    fields: ['id', 'number', 'title', 'state', 'body', 'createdAt', 'updatedAt', 'closedAt'],
  },
  PullRequest: {
    kind: 'OBJECT',
    fields: ['id', 'number', 'title', 'body', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files'],
  },
  Repository: {
    kind: 'OBJECT',
    fields: [
      'id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef',
      'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest',
    ],
  },
  SearchType: {
    kind: 'ENUM',
    enumValues: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION'],
  },
};

function tokenizeGraphQL(src: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  const n = src.length;
  const puncts = new Set(['{', '}', '(', ')', '[', ']', ':', '=', '@', '$', '!']);

  while (i < n) {
    const ch = src[i]!;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < n && src[i] !== '\n') i += 1;
      continue;
    }
    if (src.startsWith('...', i)) {
      tokens.push({ kind: 'punct', value: '...' });
      i += 3;
      continue;
    }
    if (puncts.has(ch)) {
      tokens.push({ kind: 'punct', value: ch });
      i += 1;
      continue;
    }
    if (ch === '"') {
      i += 1;
      if (src.startsWith('""', i)) {
        i += 2;
        const end = src.indexOf('"""', i);
        const val = end < 0 ? src.slice(i) : src.slice(i, end);
        i = end < 0 ? n : end + 3;
        tokens.push({ kind: 'string', value: val });
        continue;
      }
      let val = '';
      while (i < n && src[i] !== '"') {
        if (src[i] === '\\' && i + 1 < n) {
          const esc = src[i + 1]!;
          if (esc === 'n') val += '\n';
          else if (esc === 'r') val += '\r';
          else if (esc === 't') val += '\t';
          else val += esc;
          i += 2;
        } else {
          val += src[i]!;
          i += 1;
        }
      }
      if (i < n) i += 1;
      tokens.push({ kind: 'string', value: val });
      continue;
    }
    if ((ch >= '0' && ch <= '9') || ch === '-') {
      const start = i;
      i += 1;
      let isFloat = false;
      while (i < n && ((src[i]! >= '0' && src[i]! <= '9') || src[i] === '.' || src[i] === 'e' || src[i] === 'E' || src[i] === '+' || src[i] === '-')) {
        if (src[i] === '.' || src[i] === 'e' || src[i] === 'E') isFloat = true;
        i += 1;
      }
      tokens.push({ kind: isFloat ? 'float' : 'int', value: src.slice(start, i) });
      continue;
    }
    if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch === '_') {
      const start = i;
      i += 1;
      while (i < n && ((src[i]! >= 'A' && src[i]! <= 'Z') || (src[i]! >= 'a' && src[i]! <= 'z') || (src[i]! >= '0' && src[i]! <= '9') || src[i] === '_')) {
        i += 1;
      }
      tokens.push({ kind: 'name', value: src.slice(start, i) });
      continue;
    }
    throw new Error(`Unexpected GraphQL token character '${ch}'`);
  }
  tokens.push({ kind: 'eof', value: '' });
  return tokens;
}

class GraphQLParser {
  private pos = 0;
  private readonly tokens: Token[];
  constructor(tokens: Token[]) {
    this.tokens = tokens;
  }

  private peek(): Token {
    return this.tokens[this.pos] ?? { kind: 'eof', value: '' };
  }

  private next(): Token {
    const t = this.peek();
    if (t.kind !== 'eof') this.pos += 1;
    return t;
  }

  private expect(val: string): void {
    const t = this.next();
    if (t.value !== val) throw new Error(`Expected '${val}', got '${t.value}'`);
  }

  private skipTypeRef(): void {
    if (this.peek().value === '[') {
      this.next();
      this.skipTypeRef();
      this.expect(']');
    } else {
      this.next();
    }
    if (this.peek().value === '!') this.next();
  }

  private parseValue(): unknown {
    const t = this.peek();
    if (t.value === '$') {
      this.next();
      return { __gqlVar: this.next().value };
    }
    if (t.kind === 'int') {
      this.next();
      return Number.parseInt(t.value, 10);
    }
    if (t.kind === 'float') {
      this.next();
      return Number.parseFloat(t.value);
    }
    if (t.kind === 'string') {
      this.next();
      return t.value;
    }
    if (t.kind === 'name') {
      this.next();
      if (t.value === 'true') return true;
      if (t.value === 'false') return false;
      if (t.value === 'null') return null;
      return t.value;
    }
    if (t.value === '[') {
      this.next();
      const arr: unknown[] = [];
      while (this.peek().value !== ']' && this.peek().kind !== 'eof') {
        arr.push(this.parseValue());
      }
      this.expect(']');
      return arr;
    }
    if (t.value === '{') {
      this.next();
      const obj: Record<string, unknown> = {};
      while (this.peek().value !== '}' && this.peek().kind !== 'eof') {
        const key = this.next().value;
        this.expect(':');
        obj[key] = this.parseValue();
      }
      this.expect('}');
      return obj;
    }
    throw new Error(`Unexpected value token '${t.value}'`);
  }

  private parseArguments(): Record<string, unknown> {
    const args: Record<string, unknown> = {};
    if (this.peek().value !== '(') return args;
    this.next();
    while (this.peek().value !== ')' && this.peek().kind !== 'eof') {
      const name = this.next().value;
      this.expect(':');
      args[name] = this.parseValue();
    }
    this.expect(')');
    return args;
  }

  private skipDirectives(): void {
    while (this.peek().value === '@') {
      this.next();
      this.next();
      if (this.peek().value === '(') this.parseArguments();
    }
  }

  private parseSelectionSet(): SelectionNode[] {
    this.expect('{');
    const sels: SelectionNode[] = [];
    while (this.peek().value !== '}' && this.peek().kind !== 'eof') {
      if (this.peek().value === '...') {
        this.next();
        if (this.peek().value === 'on') {
          this.next();
          const typeCondition = this.next().value;
          this.skipDirectives();
          sels.push({
            kind: 'inlineFragment',
            name: typeCondition,
            typeCondition,
            selections: this.parseSelectionSet(),
          });
        } else if (this.peek().value === '{') {
          sels.push({
            kind: 'inlineFragment',
            name: '',
            selections: this.parseSelectionSet(),
          });
        } else {
          const fragName = this.next().value;
          this.skipDirectives();
          sels.push({ kind: 'fragmentSpread', name: fragName });
        }
      } else {
        const first = this.next().value;
        let alias: string | undefined;
        let name = first;
        if (this.peek().value === ':') {
          this.next();
          alias = first;
          name = this.next().value;
        }
        const args = this.peek().value === '(' ? this.parseArguments() : undefined;
        this.skipDirectives();
        const selections = this.peek().value === '{' ? this.parseSelectionSet() : undefined;
        sels.push({ kind: 'field', name, alias, args, selections });
      }
    }
    this.expect('}');
    return sels;
  }

  parseDocument(): DocumentAst {
    const operations: OperationDef[] = [];
    const fragments = new Map<string, { typeCondition: string; selections: SelectionNode[] }>();

    while (this.peek().kind !== 'eof') {
      const t = this.peek();
      if (t.value === '{') {
        operations.push({ opType: 'query', defaults: {}, selections: this.parseSelectionSet() });
        continue;
      }
      if (t.value === 'fragment') {
        this.next();
        const fragName = this.next().value;
        this.expect('on');
        const typeCondition = this.next().value;
        this.skipDirectives();
        fragments.set(fragName, { typeCondition, selections: this.parseSelectionSet() });
        continue;
      }
      if (t.value === 'query' || t.value === 'mutation') {
        const opType = this.next().value as 'query' | 'mutation';
        let name: string | undefined;
        if (this.peek().kind === 'name') name = this.next().value;
        const defaults: Record<string, unknown> = {};
        if (this.peek().value === '(') {
          this.next();
          while (this.peek().value !== ')' && this.peek().kind !== 'eof') {
            this.expect('$');
            const varName = this.next().value;
            this.expect(':');
            this.skipTypeRef();
            if (this.peek().value === '=') {
              this.next();
              defaults[varName] = this.parseValue();
            }
            this.skipDirectives();
          }
          this.expect(')');
        }
        this.skipDirectives();
        operations.push({ opType, name, defaults, selections: this.parseSelectionSet() });
        continue;
      }
      throw new Error(`Unexpected top-level token '${t.value}'`);
    }
    return { operations, fragments };
  }
}

function substituteVars(val: unknown, vars: Record<string, unknown>): unknown {
  if (val === null || typeof val !== 'object') return val;
  if (Array.isArray(val)) return val.map((x) => substituteVars(x, vars));
  const rec = val as Record<string, unknown>;
  if (typeof rec.__gqlVar === 'string') {
    return vars[rec.__gqlVar];
  }
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(rec)) {
    out[k] = substituteVars(v, vars);
  }
  return out;
}

function encodeCursor(issueNumber: number): string {
  return Buffer.from(`issue:${issueNumber}`, 'utf8').toString('base64url');
}

function decodeCursor(cursor: unknown): number | null {
  if (typeof cursor !== 'string' || cursor === '') return null;
  try {
    const raw = Buffer.from(cursor, 'base64url').toString('utf8');
    if (!raw.startsWith('issue:')) return null;
    const n = Number.parseInt(raw.slice(6), 10);
    return Number.isInteger(n) && n > 0 ? n : null;
  } catch {
    return null;
  }
}

interface ExecError {
  message: string;
  path?: Array<string | number>;
}

function executeGraphQLOp(
  store: ForgeStore,
  queryStr: string,
  variables: Record<string, unknown>,
  operationName?: string,
): { data: Record<string, unknown> | null; errors?: ExecError[] } {
  let doc: DocumentAst;
  try {
    doc = new GraphQLParser(tokenizeGraphQL(queryStr)).parseDocument();
  } catch (err) {
    return {
      data: null,
      errors: [{ message: err instanceof Error ? err.message : String(err) }],
    };
  }

  const op =
    (operationName ? doc.operations.find((o) => o.name === operationName) : doc.operations[0]) ??
    doc.operations[0];
  if (!op) {
    return { data: null, errors: [{ message: 'No operation found in GraphQL document' }] };
  }

  const resolvedVars: Record<string, unknown> = { ...op.defaults, ...variables };
  const errors: ExecError[] = [];

  const flattenSelections = (
    sels: readonly SelectionNode[],
    runtimeType: string,
  ): SelectionNode[] => {
    const out: SelectionNode[] = [];
    for (const s of sels) {
      if (s.kind === 'field') {
        out.push(s);
      } else if (s.kind === 'inlineFragment') {
        if (!s.typeCondition || s.typeCondition === runtimeType) {
          out.push(...flattenSelections(s.selections ?? [], runtimeType));
        }
      } else if (s.kind === 'fragmentSpread') {
        const frag = doc.fragments.get(s.name);
        if (frag && frag.typeCondition === runtimeType) {
          out.push(...flattenSelections(frag.selections, runtimeType));
        }
      }
    }
    return out;
  };

  const resolveSelectionSet = (
    obj: Record<string, unknown>,
    typeName: string,
    sels: readonly SelectionNode[],
    path: Array<string | number>,
  ): Record<string, unknown> => {
    const out: Record<string, unknown> = {};
    const flat = flattenSelections(sels, typeName);
    const allowed = KNOWN_FIELDS[typeName];

    for (const sel of flat) {
      const outKey = sel.alias ?? sel.name;
      if (sel.name === '__typename') {
        out[outKey] = typeName;
        continue;
      }
      if (allowed && !allowed.has(sel.name)) {
        errors.push({
          message: `Field '${sel.name}' doesn't exist on type '${typeName}'`,
          path: [...path, outKey],
        });
        continue;
      }
      const args = sel.args ? (substituteVars(sel.args, resolvedVars) as Record<string, unknown>) : {};
      const val = resolveField(obj, typeName, sel.name, args, sel.selections, [...path, outKey]);
      out[outKey] = val;
    }
    return out;
  };

  const resolveRepoObj = (repo: RepoRecord): Record<string, unknown> => ({
    __type: 'Repository',
    __record: repo,
  });

  const resolveIssueObj = (repo: RepoRecord, issue: IssueRecord): Record<string, unknown> => ({
    __type: 'Issue',
    __repo: repo,
    __record: issue,
  });

  const resolvePullObj = (repo: RepoRecord, pull: PullRecord): Record<string, unknown> => ({
    __type: 'PullRequest',
    __repo: repo,
    __record: pull,
  });

  const resolveCommentObj = (comment: CommentRecord): Record<string, unknown> => ({
    __type: 'Comment',
    __record: comment,
  });

  const resolveValue = (
    raw: unknown,
    expectedType: string | undefined,
    sels: readonly SelectionNode[] | undefined,
    path: Array<string | number>,
  ): unknown => {
    if (raw === null || raw === undefined) return null;
    if (Array.isArray(raw)) {
      return raw.map((item, idx) => resolveValue(item, expectedType, sels, [...path, idx]));
    }
    if (sels && typeof raw === 'object') {
      const rec = raw as Record<string, unknown>;
      const t = (typeof rec.__type === 'string' ? rec.__type : expectedType) ?? 'Unknown';
      return resolveSelectionSet(rec, t, sels, path);
    }
    return raw;
  };

  const resolveField = (
    parent: Record<string, unknown>,
    typeName: string,
    fieldName: string,
    args: Record<string, unknown>,
    sels: readonly SelectionNode[] | undefined,
    path: Array<string | number>,
  ): unknown => {
    if (typeName === 'Query') {
      if (fieldName === 'viewer') {
        return resolveValue(
          { __type: 'User', login: store.viewer.login, id: store.viewer.nodeId, name: store.viewer.name },
          'User',
          sels,
          path,
        );
      }
      if (fieldName === 'repository') {
        const owner = typeof args.owner === 'string' ? args.owner : '';
        const name = typeof args.name === 'string' ? args.name : '';
        const repo = owner === store.viewer.login ? store.getRepo(owner, name) : undefined;
        return repo ? resolveValue(resolveRepoObj(repo), 'Repository', sels, path) : null;
      }
      if (fieldName === 'node') {
        const id = typeof args.id === 'string' ? args.id : '';
        const target = store.nodesById.get(id);
        if (!target) return null;
        if (target.kind === 'Repository') return resolveValue(resolveRepoObj(target.repo), 'Repository', sels, path);
        if (target.kind === 'Issue') return resolveValue(resolveIssueObj(target.repo, target.issue), 'Issue', sels, path);
        if (target.kind === 'PullRequest') return resolveValue(resolvePullObj(target.repo, target.pull), 'PullRequest', sels, path);
        return resolveValue(resolveCommentObj(target.comment), 'Comment', sels, path);
      }
      if (fieldName === '__type') {
        const name = typeof args.name === 'string' ? args.name : '';
        const spec = INTROSPECTION_TYPES[name];
        if (!spec) return null;
        return resolveValue(
          {
            __type: '__Type',
            name,
            kind: spec.kind,
            fields: (spec.fields ?? []).map((f) => ({ name: f, isDeprecated: false })),
            enumValues: (spec.enumValues ?? []).map((e) => ({ name: e, isDeprecated: false })),
          },
          '__Type',
          sels,
          path,
        );
      }
    }

    if (typeName === 'Mutation') {
      const input = (typeof args.input === 'object' && args.input !== null ? args.input : {}) as Record<string, unknown>;
      if (fieldName === 'createIssue') {
        const repoId = typeof input.repositoryId === 'string' ? input.repositoryId : '';
        const target = store.nodesById.get(repoId);
        if (!target || target.kind !== 'Repository') {
          errors.push({ message: 'Repository not found', path });
          return null;
        }
        const title = typeof input.title === 'string' ? input.title : '';
        const body = typeof input.body === 'string' ? input.body : '';
        const created = store.createIssue(target.repo, { title, body });
        if (!created.ok) {
          errors.push({ message: created.message, path });
          return null;
        }
        return resolveValue(
          { __type: 'CreateIssuePayload', issue: resolveIssueObj(target.repo, created.issue) },
          'CreateIssuePayload',
          sels,
          path,
        );
      }
      if (fieldName === 'closeIssue') {
        const issueId = typeof input.issueId === 'string' ? input.issueId : '';
        const target = store.nodesById.get(issueId);
        if (!target || target.kind !== 'Issue') {
          errors.push({ message: 'Issue not found', path });
          return null;
        }
        store.updateIssue(target.issue, { state: 'closed' });
        return resolveValue(
          { __type: 'CloseIssuePayload', issue: resolveIssueObj(target.repo, target.issue) },
          'CloseIssuePayload',
          sels,
          path,
        );
      }
      if (fieldName === 'createPullRequest') {
        const repoId = typeof input.repositoryId === 'string' ? input.repositoryId : '';
        const target = store.nodesById.get(repoId);
        if (!target || target.kind !== 'Repository') {
          errors.push({ message: 'Repository not found', path });
          return null;
        }
        const created = store.createPull(target.repo, {
          title: typeof input.title === 'string' ? input.title : '',
          body: typeof input.body === 'string' ? input.body : '',
          head: typeof input.headRefName === 'string' ? input.headRefName : '',
          base: typeof input.baseRefName === 'string' ? input.baseRefName : '',
        });
        if (!created.ok) {
          errors.push({ message: created.message, path });
          return null;
        }
        return resolveValue(
          { __type: 'CreatePullRequestPayload', pullRequest: resolvePullObj(target.repo, created.pull) },
          'CreatePullRequestPayload',
          sels,
          path,
        );
      }
      if (fieldName === 'mergePullRequest') {
        const prId = typeof input.pullRequestId === 'string' ? input.pullRequestId : '';
        const target = store.nodesById.get(prId);
        if (!target || target.kind !== 'PullRequest') {
          errors.push({ message: 'Pull request not found', path });
          return null;
        }
        const merged = store.mergePull(target.repo, target.pull.number);
        if (!merged.ok) {
          errors.push({ message: merged.message, path });
          return null;
        }
        return resolveValue(
          { __type: 'MergePullRequestPayload', pullRequest: resolvePullObj(target.repo, merged.pull) },
          'MergePullRequestPayload',
          sels,
          path,
        );
      }
      if (fieldName === 'addComment') {
        const subjectId = typeof input.subjectId === 'string' ? input.subjectId : '';
        const target = store.nodesById.get(subjectId);
        if (!target || target.kind !== 'Issue') {
          errors.push({ message: 'Subject not found', path });
          return null;
        }
        const bodyText = typeof input.body === 'string' ? input.body : '';
        const comment = store.addComment(target.repo, target.issue, bodyText);
        return resolveValue(
          {
            __type: 'AddCommentPayload',
            commentEdge: { __type: 'CommentEdge', node: resolveCommentObj(comment) },
          },
          'AddCommentPayload',
          sels,
          path,
        );
      }
    }

    if (typeName === 'Repository') {
      const repo = parent.__record as RepoRecord;
      if (fieldName === 'id') return repo.nodeId;
      if (fieldName === 'databaseId') return repo.id;
      if (fieldName === 'name') return repo.name;
      if (fieldName === 'nameWithOwner') return `${repo.owner}/${repo.name}`;
      if (fieldName === 'owner') {
        return resolveValue({ __type: 'User', login: repo.owner, id: store.viewer.nodeId }, 'User', sels, path);
      }
      if (fieldName === 'defaultBranchRef') {
        return repo.refs.has(`refs/heads/${repo.defaultBranch}`)
          ? resolveValue({ __type: 'Ref', name: repo.defaultBranch, prefix: 'refs/heads/' }, 'Ref', sels, path)
          : null;
      }
      if (fieldName === 'viewerPermission') return 'ADMIN';
      if (fieldName === 'hasIssuesEnabled') return true;
      if (fieldName === 'isPrivate') return repo.private;
      if (fieldName === 'description') return repo.description;
      if (fieldName === 'issue') {
        const num = typeof args.number === 'number' ? args.number : -1;
        const issue = repo.issues.get(num);
        return issue ? resolveValue(resolveIssueObj(repo, issue), 'Issue', sels, path) : null;
      }
      if (fieldName === 'issues') {
        const states = Array.isArray(args.states) ? new Set(args.states.map((s) => String(s).toLowerCase())) : null;
        const orderBy = (typeof args.orderBy === 'object' && args.orderBy !== null ? args.orderBy : {}) as Record<string, unknown>;
        const direction = typeof orderBy.direction === 'string' ? orderBy.direction.toUpperCase() : 'ASC';

        let items = repo.issueOrder.filter((i) => !states || states.has(i.state));
        if (direction === 'DESC') {
          items = [...items].sort((a, b) => b.createdSeq - a.createdSeq || b.number - a.number);
        } else {
          items = [...items].sort((a, b) => a.createdSeq - b.createdSeq || a.number - b.number);
        }

        const afterNum = decodeCursor(args.after);
        let startIdx = 0;
        if (afterNum !== null) {
          const found = items.findIndex((i) => i.number === afterNum);
          if (found >= 0) startIdx = found + 1;
        }
        const first = typeof args.first === 'number' && args.first >= 0 ? args.first : 30;
        const slice = items.slice(startIdx, startIdx + first);
        const hasNextPage = startIdx + slice.length < items.length;
        const endCursor = slice.length > 0 ? encodeCursor(slice[slice.length - 1]!.number) : null;

        return resolveValue(
          {
            __type: 'IssueConnection',
            nodes: slice.map((i) => resolveIssueObj(repo, i)),
            edges: slice.map((i) => ({ node: resolveIssueObj(repo, i), cursor: encodeCursor(i.number) })),
            totalCount: items.length,
            pageInfo: {
              __type: 'PageInfo',
              hasNextPage,
              hasPreviousPage: startIdx > 0,
              startCursor: slice.length > 0 ? encodeCursor(slice[0]!.number) : null,
              endCursor,
            },
          },
          'IssueConnection',
          sels,
          path,
        );
      }
      if (fieldName === 'pullRequests') {
        const states = Array.isArray(args.states) ? new Set(args.states.map((s) => String(s).toUpperCase())) : null;
        const items = repo.pullOrder
          .filter((pr) => {
            if (!states) return true;
            const gState = pr.merged ? 'MERGED' : pr.state.toUpperCase();
            return states.has(gState);
          })
          .sort((a, b) => b.createdSeq - a.createdSeq);
        const first = typeof args.first === 'number' && args.first >= 0 ? args.first : 30;
        const slice = items.slice(0, first);
        return resolveValue(
          {
            __type: 'PullRequestConnection',
            nodes: slice.map((pr) => resolvePullObj(repo, pr)),
            totalCount: items.length,
            pageInfo: { __type: 'PageInfo', hasNextPage: slice.length < items.length, endCursor: null },
          },
          'PullRequestConnection',
          sels,
          path,
        );
      }
      if (fieldName === 'pullRequest') {
        const num = typeof args.number === 'number' ? args.number : -1;
        const pr = repo.pulls.get(num);
        return pr ? resolveValue(resolvePullObj(repo, pr), 'PullRequest', sels, path) : null;
      }
    }

    if (typeName === 'Issue') {
      const issue = parent.__record as IssueRecord;
      if (fieldName === 'id') return issue.nodeId;
      if (fieldName === 'number') return issue.number;
      if (fieldName === 'title') return issue.title;
      if (fieldName === 'body') return issue.body;
      if (fieldName === 'state') return issue.state.toUpperCase();
      if (fieldName === 'createdAt') return issue.createdAt;
      if (fieldName === 'updatedAt') return issue.updatedAt;
      if (fieldName === 'closedAt') return issue.closedAt;
    }

    if (typeName === 'PullRequest') {
      const repo = parent.__repo as RepoRecord;
      const pr = parent.__record as PullRecord;
      if (fieldName === 'id') return pr.nodeId;
      if (fieldName === 'number') return pr.number;
      if (fieldName === 'title') return pr.title;
      if (fieldName === 'body') return pr.body;
      if (fieldName === 'headRefName') return pr.headRef;
      if (fieldName === 'baseRefName') return pr.baseRef;
      if (fieldName === 'state') return pr.merged ? 'MERGED' : pr.state.toUpperCase();
      if (fieldName === 'merged') return pr.merged;
      if (fieldName === 'mergedAt') return pr.mergedAt;
      if (fieldName === 'mergeable') return store.isPullMergeable(repo, pr);
      if (fieldName === 'files') {
        const first = typeof args.first === 'number' && args.first >= 0 ? args.first : 30;
        const changed = store.computeChangedFiles(repo, pr.baseSha, pr.headSha).slice(0, first);
        return resolveValue(
          {
            __type: 'PullRequestFileConnection',
            nodes: changed.map((c) => ({
              __type: 'PullRequestFile',
              path: c.filename,
              additions: c.additions,
              deletions: c.deletions,
              changeType: c.status.toUpperCase(),
            })),
            totalCount: changed.length,
          },
          'PullRequestFileConnection',
          sels,
          path,
        );
      }
    }

    if (typeName === 'Comment') {
      const c = parent.__record as CommentRecord;
      if (fieldName === 'id') return c.nodeId;
      if (fieldName === 'body') return c.body;
      if (fieldName === 'createdAt') return c.createdAt;
    }

    if (fieldName in parent) {
      return resolveValue(parent[fieldName], undefined, sels, path);
    }
    return null;
  };

  const rootType = op.opType === 'mutation' ? 'Mutation' : 'Query';
  const data = resolveSelectionSet({}, rootType, op.selections, []);
  return errors.length > 0 ? { data, errors } : { data };
}

/** Handle `POST /api/graphql` (single or batched operations). */
export function handleGraphQL(
  store: ForgeStore,
  res: ServerResponse,
  method: string,
  body: Buffer,
  reply: ReplySender,
): void {
  if (method !== 'POST') {
    reply.sendJson(res, 405, { message: 'Method Not Allowed' });
    return;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString('utf8')) as unknown;
  } catch {
    reply.sendJson(res, 400, { message: 'Problems parsing JSON' });
    return;
  }

  const runOne = (item: unknown): { data: Record<string, unknown> | null; errors?: ExecError[] } => {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) {
      return { data: null, errors: [{ message: 'Invalid GraphQL operation body' }] };
    }
    const rec = item as Record<string, unknown>;
    const queryStr = typeof rec.query === 'string' ? rec.query : '';
    const vars =
      typeof rec.variables === 'object' && rec.variables !== null && !Array.isArray(rec.variables)
        ? (rec.variables as Record<string, unknown>)
        : {};
    const opName = typeof rec.operationName === 'string' ? rec.operationName : undefined;
    return executeGraphQLOp(store, queryStr, vars, opName);
  };

  if (Array.isArray(parsed)) {
    reply.sendJson(res, 200, parsed.map(runOne));
    return;
  }
  reply.sendJson(res, 200, runOne(parsed));
}
