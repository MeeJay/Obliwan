// ============================================================================
// ObliWAN — Fleet Query (K5): the DSL
// ============================================================================
//
// Lexer + parser (Chevrotain, ARCHITECTURE.md §6.1) + validation against the
// zod-derived whitelist of `@obliwan/shared/query`. This file produces an AST
// and NOTHING ELSE: it never sees a database handle, never builds a SQL string,
// and never learns a tenant id. `compiler.ts` does that, from the AST.
//
// ┌─ THE SHAPE OF THE LANGUAGE, AND WHY ──────────────────────────────────────┐
// │                                                                           │
// │   firewallRule[chain = "input" and match.srcAddress has "any"]            │
// │   └── resource ──┘└──────── one element of the collection ───────────┘    │
// │                                                                           │
// │ The bracket is the whole design. `firewallRule[a and b]` asks for ONE rule │
// │ satisfying both; `firewallRule[a] and firewallRule[b]` asks for two rules  │
// │ that may be different. A flat `firewallRules.chain = "input" and           │
// │ firewallRules.action = "accept"` cannot express the difference, and would  │
// │ have reported a router as wide open because it has an accept rule          │
// │ somewhere and an input rule somewhere else. That is not a nuance; on the   │
// │ query this milestone exists to answer it is the difference between a       │
// │ finding and a lie.                                                         │
// │                                                                           │
// │ It also happens to be exactly `jsonb @>`: a containment fragment merges    │
// │ every constraint of a conjunction into ONE array element. The syntax is    │
// │ the index.                                                                 │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ┌─ NO USER-SUPPLIED REGEX. ANYWHERE. ───────────────────────────────────────┐
// │ There is no `matches` / `~` / glob operator in this grammar, and there is  │
// │ not going to be one: it would run an attacker-authored automaton on the    │
// │ event loop that serves every tenant. `contains` / `startswith` / `endswith`│
// │ compile to `LIKE` with `%`, `_` and `\` escaped INSIDE the bound           │
// │ parameter — linear, interruptible by `statement_timeout`, and executed by  │
// │ Postgres rather than by Node.                                              │
// │                                                                           │
// │ The lexer's own patterns are audited for the same property: the string     │
// │ literal is `"[^"]{0,512}"`, a flat negated class with a bounded            │
// │ repetition. The usual `"(?:[^"\\]|\\.)*"` — nested quantifiers — is        │
// │ exactly the shape that backtracks catastrophically on an unterminated      │
// │ literal, so escapes are not supported and a value containing a double      │
// │ quote is written between single quotes.                                    │
// └───────────────────────────────────────────────────────────────────────────┘

// ┌─ CHEVROTAIN IS PINNED TO ^10, AND §6.1 SAYS ^11 ──────────────────────────┐
// │ chevrotain 11 is ESM-ONLY (`"type": "module"`, and `@chevrotain/utils`    │
// │ publishes an `exports` map with an `import` condition and no `require`    │
// │ one). The server builds CJS. Plain `node dist/…` survives it on Node 24   │
// │ thanks to `require(esm)`, but `npm run dev` — `tsx watch src/index.ts` —  │
// │ transpiles to CJS and dies at resolution with                             │
// │ ERR_PACKAGE_PATH_NOT_EXPORTED. A milestone that boots in production and   │
// │ not on a developer's machine is not a milestone.                          │
// │                                                                          │
// │ §6.1 already makes exactly this call once, for exactly this reason —      │
// │ `p-limit` is pinned to **^3** with the note "v7 est ESM-only et casserait │
// │ le build CJS du serveur". This is that decision, applied to the second    │
// │ package where it bites. The grammar API used here is identical in 10 and  │
// │ 11; the day the server moves to ESM, bumping is a one-line change.        │
// └───────────────────────────────────────────────────────────────────────────┘
import { createToken, EmbeddedActionsParser, Lexer, type IToken, type TokenType } from 'chevrotain';
import {
  NCM_RESOURCE_KINDS, RESOURCE_KIND_TO_COLLECTION, type NcmResourceKind,
} from '@obliwan/shared';
import {
  QUERY_LIMITS, QUERY_CATALOG, isQueryScope, lookupField, operatorsFor,
  type ParsedQuery, type QueryExpr, type QueryFieldNode, type QueryLiteral,
  type QueryOperator, type QueryScope, type ResourceExpr,
} from '@obliwan/shared/dist/query';

/** A user error, always. Carries the offset so the editor can underline. */
export class QueryParseError extends Error {
  readonly offset: number | null;

  readonly length: number | null;

  constructor(message: string, offset: number | null = null, length: number | null = null) {
    super(message);
    this.name = 'QueryParseError';
    this.offset = offset;
    this.length = length;
  }
}

// ============================================================================
// Tokens
// ============================================================================

/** Dotted path. One token, so `match.srcAddress` cannot be mistaken for a
 *  member access on something the grammar would then have to resolve. */
const Identifier = createToken({
  name: 'Identifier',
  pattern: /[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){0,4}/,
});

/** Keywords are Identifier-shaped, so every one of them declares `longer_alt`
 *  and is listed BEFORE Identifier: without it, `notes` would lex as `not`
 *  followed by `es`, and `internal` would start with `in`. */
function keyword(name: string, pattern: RegExp): TokenType {
  return createToken({ name, pattern, longer_alt: Identifier });
}

const And = keyword('And', /and/i);
const Or = keyword('Or', /or/i);
const Not = keyword('Not', /not/i);
const Has = keyword('Has', /has/i);
const In = keyword('In', /in/i);
const Contains = keyword('Contains', /contains/i);
const StartsWith = keyword('StartsWith', /startswith/i);
const EndsWith = keyword('EndsWith', /endswith/i);
const Is = keyword('Is', /is/i);
const NullKw = keyword('Null', /null/i);
const True = keyword('True', /true/i);
const False = keyword('False', /false/i);
const Count = keyword('Count', /count/i);

// Flat negated character classes with a bounded repetition — no nesting, no
// alternation, no backtracking. See the header.
const StringLiteral = createToken({
  name: 'StringLiteral',
  pattern: /"[^"\n]{0,512}"|'[^'\n]{0,512}'/,
});
const NumberLiteral = createToken({
  name: 'NumberLiteral',
  pattern: /-?\d{1,15}(?:\.\d{1,6})?/,
});

const Gte = createToken({ name: 'Gte', pattern: />=/ });
const Lte = createToken({ name: 'Lte', pattern: /<=/ });
const Neq = createToken({ name: 'Neq', pattern: /!=|<>/ });
const Eq = createToken({ name: 'Eq', pattern: /==|=/ });
const Gt = createToken({ name: 'Gt', pattern: />/ });
const Lt = createToken({ name: 'Lt', pattern: /</ });

const LParen = createToken({ name: 'LParen', pattern: /\(/ });
const RParen = createToken({ name: 'RParen', pattern: /\)/ });
const LSquare = createToken({ name: 'LSquare', pattern: /\[/ });
const RSquare = createToken({ name: 'RSquare', pattern: /\]/ });
const Comma = createToken({ name: 'Comma', pattern: /,/ });

const WhiteSpace = createToken({
  name: 'WhiteSpace',
  pattern: /[ \t\r\n]+/,
  group: Lexer.SKIPPED,
});

/** ORDER IS THE GRAMMAR. Keywords before Identifier; `>=` before `>`. */
const ALL_TOKENS: TokenType[] = [
  WhiteSpace,
  StringLiteral, NumberLiteral,
  And, Or, Not, Has, In, Contains, StartsWith, EndsWith, Is, NullKw, True, False, Count,
  Identifier,
  Gte, Lte, Neq, Eq, Gt, Lt,
  LParen, RParen, LSquare, RSquare, Comma,
];

const lexer = new Lexer(ALL_TOKENS, { positionTracking: 'onlyOffset' });

// ============================================================================
// Parser
// ============================================================================

/** Raw predicate tail, before the field is resolved and the operator checked. */
interface Tail {
  op: QueryOperator;
  values: QueryLiteral[];
  token: IToken;
}

class FleetQueryParser extends EmbeddedActionsParser {
  constructor() {
    super(ALL_TOKENS, { maxLookahead: 2 });
    this.performSelfAnalysis();
  }

  public query = this.RULE('query', (): QueryExpr => this.SUBRULE(this.orExpr));

  private orExpr = this.RULE('orExpr', (): QueryExpr => {
    const nodes: QueryExpr[] = [];
    nodes.push(this.SUBRULE(this.andExpr));
    this.MANY(() => {
      this.CONSUME(Or);
      nodes.push(this.SUBRULE2(this.andExpr));
    });
    return nodes.length === 1 ? nodes[0] : { t: 'or', nodes };
  });

  private andExpr = this.RULE('andExpr', (): QueryExpr => {
    const nodes: QueryExpr[] = [];
    nodes.push(this.SUBRULE(this.unaryExpr));
    this.MANY(() => {
      this.CONSUME(And);
      nodes.push(this.SUBRULE2(this.unaryExpr));
    });
    return nodes.length === 1 ? nodes[0] : { t: 'and', nodes };
  });

  private unaryExpr = this.RULE('unaryExpr', (): QueryExpr => this.OR([
    {
      ALT: () => {
        this.CONSUME(Not);
        const node = this.SUBRULE(this.unaryExpr);
        return { t: 'not', node } as QueryExpr;
      },
    },
    { ALT: () => this.SUBRULE(this.atom) },
  ]));

  private atom = this.RULE('atom', (): QueryExpr => this.OR([
    {
      ALT: () => {
        this.CONSUME(LParen);
        const inner = this.SUBRULE(this.orExpr);
        this.CONSUME(RParen);
        return inner;
      },
    },
    { ALT: () => this.SUBRULE(this.countExpr) },
    { ALT: () => this.SUBRULE(this.scopedExpr) },
  ]));

  /** `count(firewallRule[…]) >= 3` — the one place a cardinality is asked for
   *  rather than an existence. It always falls back to element expansion; a
   *  containment cannot count. */
  private countExpr = this.RULE('countExpr', (): QueryExpr => {
    this.CONSUME(Count);
    this.CONSUME(LParen);
    const kindTok = this.CONSUME(Identifier);
    let expr: ResourceExpr | null = null;
    this.OPTION(() => {
      this.CONSUME(LSquare);
      expr = this.SUBRULE(this.resOr);
      this.CONSUME(RSquare);
    });
    this.CONSUME(RParen);
    const opTok = this.SUBRULE(this.compareOp);
    const numTok = this.CONSUME(NumberLiteral);
    return this.ACTION((): QueryExpr => ({
      t: 'count',
      kind: resolveKind(kindTok),
      expr,
      op: OP_BY_TOKEN[opTok.tokenType.name] ?? 'eq',
      value: Number(numTok.image),
    }));
  });

  /** `<scope>[…]` or `<scope>.<field> <op> <value>`. One rule, so the two never
   *  need a backtracking decision. */
  private scopedExpr = this.RULE('scopedExpr', (): QueryExpr => {
    const head = this.CONSUME(Identifier);
    return this.OR([
      {
        ALT: () => {
          this.CONSUME(LSquare);
          const expr = this.SUBRULE(this.resOr);
          this.CONSUME(RSquare);
          return this.ACTION((): QueryExpr => ({ t: 'resource', kind: resolveKind(head), expr }));
        },
      },
      {
        ALT: () => {
          const tail = this.SUBRULE(this.predicateTail);
          return this.ACTION((): QueryExpr => buildTopLevelField(head, tail));
        },
      },
    ]);
  });

  // ── inside the bracket ────────────────────────────────────────────────────

  private resOr = this.RULE('resOr', (): ResourceExpr => {
    const nodes: ResourceExpr[] = [];
    nodes.push(this.SUBRULE(this.resAnd));
    this.MANY(() => {
      this.CONSUME(Or);
      nodes.push(this.SUBRULE2(this.resAnd));
    });
    return nodes.length === 1 ? nodes[0] : { t: 'or', nodes };
  });

  private resAnd = this.RULE('resAnd', (): ResourceExpr => {
    const nodes: ResourceExpr[] = [];
    nodes.push(this.SUBRULE(this.resUnary));
    this.MANY(() => {
      this.CONSUME(And);
      nodes.push(this.SUBRULE2(this.resUnary));
    });
    return nodes.length === 1 ? nodes[0] : { t: 'and', nodes };
  });

  private resUnary = this.RULE('resUnary', (): ResourceExpr => this.OR([
    {
      ALT: () => {
        this.CONSUME(Not);
        const node = this.SUBRULE(this.resUnary);
        return { t: 'not', node } as ResourceExpr;
      },
    },
    {
      ALT: () => {
        this.CONSUME(LParen);
        const inner = this.SUBRULE(this.resOr);
        this.CONSUME(RParen);
        return inner;
      },
    },
    {
      ALT: () => {
        const head = this.CONSUME(Identifier);
        const tail = this.SUBRULE(this.predicateTail);
        // The scope is filled in by the enclosing resource bracket during
        // validation; the parser does not know it here and does not guess.
        return this.ACTION((): ResourceExpr => ({
          t: 'field',
          scope: 'device',
          field: head.image,
          op: tail.op,
          values: tail.values,
        }));
      },
    },
  ]));

  // ── shared tails ──────────────────────────────────────────────────────────

  private predicateTail = this.RULE('predicateTail', (): Tail => this.OR([
    {
      ALT: () => {
        const opTok = this.SUBRULE(this.compareOp);
        const v = this.SUBRULE(this.literal);
        return this.ACTION((): Tail => ({
          op: OP_BY_TOKEN[opTok.tokenType.name] ?? 'eq',
          values: [v],
          token: opTok,
        }));
      },
    },
    {
      ALT: () => {
        const t = this.CONSUME(Has);
        const v = this.SUBRULE2(this.literal);
        return this.ACTION((): Tail => ({ op: 'has', values: [v], token: t }));
      },
    },
    {
      ALT: () => {
        const t = this.CONSUME(Contains);
        const v = this.SUBRULE3(this.literal);
        return this.ACTION((): Tail => ({ op: 'contains', values: [v], token: t }));
      },
    },
    {
      ALT: () => {
        const t = this.CONSUME(StartsWith);
        const v = this.SUBRULE4(this.literal);
        return this.ACTION((): Tail => ({ op: 'startsWith', values: [v], token: t }));
      },
    },
    {
      ALT: () => {
        const t = this.CONSUME(EndsWith);
        const v = this.SUBRULE5(this.literal);
        return this.ACTION((): Tail => ({ op: 'endsWith', values: [v], token: t }));
      },
    },
    {
      ALT: () => {
        const t = this.CONSUME(In);
        this.CONSUME(LParen);
        const values: QueryLiteral[] = [];
        values.push(this.SUBRULE6(this.literal));
        this.MANY(() => {
          this.CONSUME(Comma);
          values.push(this.SUBRULE7(this.literal));
        });
        this.CONSUME(RParen);
        return this.ACTION((): Tail => ({ op: 'in', values, token: t }));
      },
    },
    {
      ALT: () => {
        const t = this.CONSUME(Is);
        let negated = false;
        this.OPTION(() => {
          this.CONSUME2(Not);
          negated = true;
        });
        this.CONSUME(NullKw);
        return this.ACTION((): Tail => ({
          op: negated ? 'isNotNull' : 'isNull',
          values: [],
          token: t,
        }));
      },
    },
  ]));

  private compareOp = this.RULE('compareOp', (): IToken => this.OR([
    { ALT: () => this.CONSUME(Gte) },
    { ALT: () => this.CONSUME(Lte) },
    { ALT: () => this.CONSUME(Neq) },
    { ALT: () => this.CONSUME(Eq) },
    { ALT: () => this.CONSUME(Gt) },
    { ALT: () => this.CONSUME(Lt) },
  ]));

  private literal = this.RULE('literal', (): QueryLiteral => this.OR([
    {
      ALT: () => {
        const t = this.CONSUME(StringLiteral);
        return this.ACTION((): QueryLiteral => t.image.slice(1, -1));
      },
    },
    {
      ALT: () => {
        const t = this.CONSUME(NumberLiteral);
        return this.ACTION((): QueryLiteral => Number(t.image));
      },
    },
    { ALT: () => { this.CONSUME(True); return this.ACTION((): QueryLiteral => true); } },
    { ALT: () => { this.CONSUME(False); return this.ACTION((): QueryLiteral => false); } },
    { ALT: () => { this.CONSUME(NullKw); return this.ACTION((): QueryLiteral => null); } },
  ]));
}

const OP_BY_TOKEN: Readonly<Record<string, QueryOperator>> = {
  Eq: 'eq', Neq: 'neq', Gt: 'gt', Gte: 'gte', Lt: 'lt', Lte: 'lte',
};

/** Plural collection name -> resource kind, so both `firewallRule[…]` and
 *  `firewallRules[…]` work and neither is a special case in the grammar. */
const KIND_BY_ALIAS: ReadonlyMap<string, NcmResourceKind> = (() => {
  const m = new Map<string, NcmResourceKind>();
  for (const k of NCM_RESOURCE_KINDS) {
    m.set(k, k);
    m.set(RESOURCE_KIND_TO_COLLECTION[k], k);
  }
  return m;
})();

function resolveKind(tok: IToken): NcmResourceKind {
  const kind = KIND_BY_ALIAS.get(tok.image);
  if (!kind) {
    throw new QueryParseError(
      `Unknown resource '${tok.image}'. Known resources: ${NCM_RESOURCE_KINDS.join(', ')}.`,
      tok.startOffset,
      tok.image.length,
    );
  }
  return kind;
}

/** `device.brand = "mikrotik"` -> scope `device`, field `brand`. */
function buildTopLevelField(head: IToken, tail: Tail): QueryFieldNode {
  const dot = head.image.indexOf('.');
  const scopeName = dot === -1 ? head.image : head.image.slice(0, dot);
  if (!isQueryScope(scopeName) || scopeName === 'device' || scopeName === 'snapshot') {
    if (dot === -1) {
      throw new QueryParseError(
        `'${head.image}' is not a predicate. Write '${head.image}[…]' for a resource, `
          + "or 'device.<field>' / 'snapshot.<field>' for a device attribute.",
        head.startOffset,
        head.image.length,
      );
    }
    if (!isQueryScope(scopeName)) {
      throw new QueryParseError(
        `Unknown scope '${scopeName}'. Use 'device', 'snapshot', or a resource in brackets.`,
        head.startOffset,
        scopeName.length,
      );
    }
    return {
      t: 'field',
      scope: scopeName,
      field: head.image.slice(dot + 1),
      op: tail.op,
      values: tail.values,
    };
  }
  // A resource kind used without a bracket: `firewallRule.chain = "input"` is
  // the flat form the header explains we refuse, and refusing it with the fix
  // spelled out is worth more than accepting a query that means the wrong thing.
  throw new QueryParseError(
    `'${scopeName}' is a resource: write ${scopeName}[${head.image.slice(dot + 1)} …] `
      + 'so the constraints apply to the SAME record.',
    head.startOffset,
    head.image.length,
  );
}

const parser = new FleetQueryParser();

// ============================================================================
// Validation — the whitelist, the operators, the literals, the size
// ============================================================================

function countNodes(node: QueryExpr | ResourceExpr): number {
  switch (node.t) {
    case 'and':
    case 'or':
      return 1 + (node.nodes as (QueryExpr | ResourceExpr)[])
        .reduce((n, c) => n + countNodes(c), 0);
    case 'not':
      return 1 + countNodes(node.node as QueryExpr | ResourceExpr);
    case 'resource':
    case 'count':
      return 1 + (node.expr ? countNodes(node.expr) : 0);
    default:
      return 1;
  }
}

function depthOf(node: QueryExpr | ResourceExpr): number {
  switch (node.t) {
    case 'and':
    case 'or':
      return 1 + Math.max(
        ...(node.nodes as (QueryExpr | ResourceExpr)[]).map(depthOf),
      );
    case 'not':
      return 1 + depthOf(node.node as QueryExpr | ResourceExpr);
    case 'resource':
    case 'count':
      return 1 + (node.expr ? depthOf(node.expr) : 0);
    default:
      return 1;
  }
}

/**
 * Resolves one leaf against the whitelist and checks its operator and its
 * literals. Mutates `scope` on the node — this is where a predicate written
 * inside `firewallRule[…]` learns which schema it belongs to.
 *
 * A rejection here is a 400 with the field named. It is a CORRECTNESS guard:
 * the statement is safe whatever this function decides, because the compiler
 * binds every literal and never interpolates one.
 */
function validateField(node: QueryFieldNode, scope: QueryScope, scopes: Set<QueryScope>): void {
  node.scope = scope;
  scopes.add(scope);

  const field = lookupField(scope, node.field);
  if (!field) {
    const known = [...(QUERY_CATALOG.get(scope)?.fields.keys() ?? [])].sort();
    const near = known.filter((k) => k.toLowerCase().startsWith(node.field.slice(0, 3).toLowerCase()));
    const hint = near.length > 0 ? ` Did you mean: ${near.slice(0, 5).join(', ')}?` : '';
    throw new QueryParseError(
      `'${node.field}' is not a queryable field of '${scope}'.${hint}`,
    );
  }

  const allowed = operatorsFor(field);
  if (!allowed.includes(node.op)) {
    const why = field.cardinality === 'set'
      ? ` '${field.path}' is a list: use 'has' to test membership.`
      : '';
    throw new QueryParseError(
      `Operator '${node.op}' is not allowed on '${scope}.${field.path}'.${why} `
        + `Allowed: ${allowed.join(', ')}.`,
    );
  }

  if (node.values.length > QUERY_LIMITS.maxInListValues) {
    throw new QueryParseError(
      `'in (…)' accepts at most ${QUERY_LIMITS.maxInListValues} values.`,
    );
  }

  for (const v of node.values) {
    if (v === null) {
      throw new QueryParseError(
        `Use 'is null' rather than comparing '${field.path}' to the null literal.`,
      );
    }
    if (field.type === 'number') {
      if (typeof v !== 'number' || !Number.isFinite(v)) {
        throw new QueryParseError(`'${scope}.${field.path}' is numeric; '${String(v)}' is not.`);
      }
      continue;
    }
    if (field.type === 'boolean') {
      if (typeof v !== 'boolean') {
        throw new QueryParseError(
          `'${scope}.${field.path}' is a boolean; write true or false, not '${String(v)}'.`,
        );
      }
      continue;
    }
    // string / timestamp
    if (typeof v !== 'string') {
      throw new QueryParseError(
        `'${scope}.${field.path}' is textual; quote the value ('"${String(v)}"').`,
      );
    }
    if (v.length > QUERY_LIMITS.maxLiteralLength) {
      throw new QueryParseError(
        `Literal too long (${v.length} > ${QUERY_LIMITS.maxLiteralLength}).`,
      );
    }
    if (field.maxLength !== null && v.length > field.maxLength) {
      throw new QueryParseError(
        `'${scope}.${field.path}' holds at most ${field.maxLength} characters; `
          + `no record can ever equal a ${v.length}-character value.`,
      );
    }
    // A closed domain is checked EXACTLY, and the error lists it. Silently
    // returning zero devices for `chain = "imput"` is the failure mode that
    // makes a query tool untrustworthy: it looks like an answer.
    if (field.values !== null && !field.values.includes(v)
        && !TEXT_MATCH_LENIENT.has(node.op)) {
      throw new QueryParseError(
        `'${v}' is not a valid ${scope}.${field.path}. One of: ${field.values.join(', ')}.`,
      );
    }
  }
}

/** `contains`/`startswith`/`endswith` on a closed domain are still substring
 *  tests, so the value is not required to BE a member of the domain. */
const TEXT_MATCH_LENIENT: ReadonlySet<QueryOperator> = new Set<QueryOperator>([
  'contains', 'startsWith', 'endsWith',
]);

function validateResourceExpr(
  node: ResourceExpr,
  scope: NcmResourceKind,
  scopes: Set<QueryScope>,
): void {
  switch (node.t) {
    case 'and':
    case 'or':
      for (const c of node.nodes) validateResourceExpr(c, scope, scopes);
      return;
    case 'not':
      validateResourceExpr(node.node, scope, scopes);
      return;
    default:
      validateField(node, scope, scopes);
  }
}

function validateExpr(node: QueryExpr, scopes: Set<QueryScope>): void {
  switch (node.t) {
    case 'and':
    case 'or':
      for (const c of node.nodes) validateExpr(c, scopes);
      return;
    case 'not':
      validateExpr(node.node, scopes);
      return;
    case 'resource':
      scopes.add(node.kind);
      if (node.expr) validateResourceExpr(node.expr, node.kind, scopes);
      return;
    case 'count':
      scopes.add(node.kind);
      if (!Number.isInteger(node.value) || node.value < 0 || node.value > 100000) {
        throw new QueryParseError('count(…) compares against a non-negative integer.');
      }
      if (node.expr) validateResourceExpr(node.expr, node.kind, scopes);
      return;
    default:
      if (node.scope !== 'device' && node.scope !== 'snapshot') {
        throw new QueryParseError(`Predicate on '${node.scope}' must sit inside brackets.`);
      }
      validateField(node, node.scope, scopes);
  }
}

// ============================================================================
// The entry point
// ============================================================================

/**
 * Text -> validated AST. Throws `QueryParseError` and nothing else for any
 * input a user can type.
 *
 * The whole call is timed and compared against `QUERY_LIMITS.maxParseMs`. The
 * grammar is LL(2) and the lexer's patterns are backtracking-free, so the
 * budget should never be reached — which is precisely why reaching it is worth
 * a hard failure rather than a log line.
 */
export function parseQuery(text: string): ParsedQuery {
  const started = Date.now();

  if (typeof text !== 'string' || text.trim().length === 0) {
    throw new QueryParseError('Empty query.');
  }
  if (text.length > QUERY_LIMITS.maxQueryLength) {
    throw new QueryParseError(
      `Query too long (${text.length} > ${QUERY_LIMITS.maxQueryLength} characters).`,
    );
  }

  // Bracket nesting is checked on the RAW TEXT, before the parser sees it.
  // `depthOf()` below measures the AST, where `((((x))))` collapses to a single
  // node — but the recursive-descent parser still burns five stack frames per
  // level on the way in, and 4096 characters of `(` is a few thousand frames of
  // orExpr -> andExpr -> unaryExpr -> atom -> orExpr. A RangeError thrown out of
  // Chevrotain is a 500; this is a 400 with a sentence in it.
  let depth = 0;
  for (let i = 0; i < text.length; i += 1) {
    const c = text.charCodeAt(i);
    if (c === 40 /* ( */ || c === 91 /* [ */) {
      depth += 1;
      if (depth > QUERY_LIMITS.maxDepth) {
        throw new QueryParseError(
          `Query nested too deeply (more than ${QUERY_LIMITS.maxDepth} levels).`,
          i,
          1,
        );
      }
    } else if (c === 41 /* ) */ || c === 93 /* ] */) {
      depth -= 1;
    }
  }

  const lexed = lexer.tokenize(text);
  if (lexed.errors.length > 0) {
    const e = lexed.errors[0];
    throw new QueryParseError(
      `Unexpected character at offset ${e.offset}: ${e.message}`,
      e.offset,
      e.length,
    );
  }
  if (lexed.tokens.length > QUERY_LIMITS.maxTokens) {
    throw new QueryParseError(
      `Query too complex (${lexed.tokens.length} tokens > ${QUERY_LIMITS.maxTokens}).`,
    );
  }

  parser.input = lexed.tokens;
  const ast = parser.query();

  if (parser.errors.length > 0) {
    const e = parser.errors[0];
    const tok = e.token as IToken | undefined;
    throw new QueryParseError(
      e.message,
      tok && typeof tok.startOffset === 'number' ? tok.startOffset : null,
      tok && typeof tok.image === 'string' ? tok.image.length : null,
    );
  }
  if (!ast) throw new QueryParseError('Query did not parse to an expression.');

  const nodeCount = countNodes(ast);
  if (nodeCount > QUERY_LIMITS.maxAstNodes) {
    throw new QueryParseError(
      `Query too complex (${nodeCount} nodes > ${QUERY_LIMITS.maxAstNodes}).`,
    );
  }
  const astDepth = depthOf(ast);
  if (astDepth > QUERY_LIMITS.maxDepth) {
    throw new QueryParseError(`Query nested too deeply (${astDepth} > ${QUERY_LIMITS.maxDepth}).`);
  }

  const scopes = new Set<QueryScope>();
  validateExpr(ast, scopes);

  const parseMs = Date.now() - started;
  if (parseMs > QUERY_LIMITS.maxParseMs) {
    throw new QueryParseError(`Query took too long to parse (${parseMs} ms).`);
  }

  return { ast, scopes: [...scopes], nodeCount, parseMs };
}
