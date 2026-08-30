// ============================================================================
// template.schema.ts — the M5 API boundary (templates, revisions, variables)
// ============================================================================
//
// Everything the outside world can say about a template, a revision, a partial,
// an assignment or a variable passes through this file first.
//
// Two of these schemas are not "input validation" in the ordinary sense — they
// are part of the mitigation of risk R6 (RCE through Nunjucks on the server
// that holds every customer's admin credentials), and they must not be relaxed
// for convenience:
//
//   • `variableKey` — lowercase snake_case, letter-initial. This is what makes
//     `__proto__`, `constructor` and `prototype` UNREPRESENTABLE as variable
//     names, so a render context cannot be handed a polluted prototype. The
//     same regex is re-checked at write time and again at read time in
//     `variableResolver.service.ts`; three checks for one rule, because the
//     cost of the rule failing is an attacker-controlled prototype inside the
//     template sandbox.
//   • `renderPreviewSchema` — has NO `mode` field on purpose. The API can only
//     ever ask for the REDACTED render. The plaintext-secret context (§8.2)
//     exists solely on the in-memory path vault -> equipment and is reachable
//     only from `variableResolver.buildRenderContext(..., { mode: 'secrets' })`
//     inside the apply path. If a future endpoint needs it, that is an
//     arbitration, not a patch.
//
// Capability note (ARCHITECTURE.md §6.3, R6): every route fed by this file is
// `TEMPLATE_WRITE`, except the read-only listings which are `TEMPLATE_READ`.
// The schemas below do not enforce that — `requireCapability` does — but a
// reviewer reading this file should know that a template body is executable
// input and is gated accordingly.
// ============================================================================

import { z } from 'zod';
import { DEVICE_BRANDS } from '@obliwan/shared';

// ============================================================================
// Shared atoms
// ============================================================================

/**
 * The canonical variable-name rule. Defined HERE rather than in the service so
 * the API boundary owns it and nothing has to import a module that opens a
 * database connection just to validate a form field;
 * `variableResolver.service.ts` re-exports it so there is exactly one regex in
 * the codebase.
 *
 * It is byte-for-byte migration 008's `config_variables_key_chk`
 * (`^[a-z][a-zA-Z0-9_]{0,119}$`) ON PURPOSE. A stricter application rule would
 * reject rows the database happily accepts from any other writer, and a render
 * would fail on a variable an operator can see in the table.
 *
 * ⚠ What this regex does NOT do — and 008's header claims it does: it refuses
 * `__proto__` (leading underscore), but `constructor` and `prototype` MATCH it.
 * They are stopped by `FORBIDDEN_KEYS` in the resolver and by the explicit list
 * below, at write time, at read time and again before the context crosses into
 * the worker. Do not remove either check on the strength of the other.
 */
export const VARIABLE_KEY_RE = /^[a-z][a-zA-Z0-9_]{0,119}$/;

/** Names that are legal per the regex but must never become context keys. */
export const FORBIDDEN_VARIABLE_KEYS = ['__proto__', 'constructor', 'prototype'] as const;

/** The four inheritance levels, narrowest last. */
export const VARIABLE_SCOPES = ['global', 'tenant', 'group', 'device'] as const;

export const variableKey = z
  .string()
  .regex(
    VARIABLE_KEY_RE,
    'variable name must start with a lowercase letter and contain only letters, digits and _ (max 120 characters)',
  )
  .refine((k) => !(FORBIDDEN_VARIABLE_KEYS as readonly string[]).includes(k), {
    message: 'this name would collide with a JavaScript prototype member',
  });

const scopeEnum = z.enum(VARIABLE_SCOPES);
const brandEnum = z.enum(DEVICE_BRANDS as unknown as [string, ...string[]]);

/**
 * A JSON value, bounded.
 *
 * The depth cap matters: the value ends up in a Nunjucks context, and an
 * arbitrarily deep structure is a cheap way to make the serializer between the
 * main thread and the render worker do unbounded work. 12 levels is far more
 * than any real template variable (a list of VLANs, a map of site codes) and
 * far less than a problem.
 *
 * `z.record` here rejects nothing by key name — that is `variableKey`'s job at
 * the top level. Nested keys never become context identifiers; they are only
 * reachable as `{{ obj.field }}`, and `variableResolver.assertJsonPure()`
 * refuses `__proto__` at every depth before anything crosses into the worker.
 */
export type JsonInput = z.infer<typeof jsonValue>;
const jsonLiteral = z.union([z.string().max(8192), z.number().finite(), z.boolean(), z.null()]);
const jsonValue: z.ZodType<unknown> = z.lazy(() =>
  z.union([jsonLiteral, z.array(jsonValue).max(512), z.record(jsonValue)]),
);

/** Depth guard — zod cannot express it, so it is a refinement. */
function depthOf(v: unknown, d = 0): number {
  if (d > 16 || v === null || typeof v !== 'object') return d;
  const children = Array.isArray(v) ? v : Object.values(v as Record<string, unknown>);
  let max = d;
  for (const c of children) max = Math.max(max, depthOf(c, d + 1));
  return max;
}

export const variableValue = jsonValue.refine((v) => depthOf(v) <= 12, {
  message: 'variable value is nested more than 12 levels deep',
});

// ============================================================================
// Variables — `config_variables`
// ============================================================================

/**
 * `scope_id` is NULL for 'global' and 'tenant' (their identity is carried by
 * `tenant_id`, exactly as in `settings`) and REQUIRED for 'group' and 'device'.
 * Expressing it here means the controller never has to guess, and the two
 * PARTIAL unique indexes on `config_variables` are never asked to constrain a
 * row that sits outside both of them.
 */
const scopeTarget = z
  .object({
    scope: scopeEnum,
    scopeId: z.number().int().positive().nullable().optional(),
  })
  .superRefine((v, ctx) => {
    const needsId = v.scope === 'group' || v.scope === 'device';
    const hasId = v.scopeId !== null && v.scopeId !== undefined;
    if (needsId && !hasId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['scopeId'],
        message: `scope "${v.scope}" requires a scopeId`,
      });
    }
    if (!needsId && hasId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['scopeId'],
        message: `scope "${v.scope}" must not carry a scopeId — it is identified by the tenant`,
      });
    }
  });

/**
 * Setting one variable.
 *
 * `isSecret: true` means the value goes to the vault and comes back redacted
 * everywhere but the in-memory push path (§8.2). It therefore MUST be a string:
 * the vault encrypts strings, and "a secret that is an object" has no meaning
 * on a router. A non-empty one, because an empty secret is almost always a form
 * that was submitted before the operator pasted the value, and storing it would
 * silently push an empty password.
 */
export const setVariableSchema = z
  .object({
    key: variableKey,
    value: variableValue,
    isSecret: z.boolean().optional().default(false),
  })
  .superRefine((v, ctx) => {
    if (!v.isSecret) return;
    if (typeof v.value !== 'string') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['value'],
        message: 'a secret variable must be a string',
      });
      return;
    }
    if (v.value.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['value'],
        message: 'a secret variable must not be empty',
      });
    }
    if (v.value.length > 4096) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['value'],
        message: 'a secret variable must be at most 4096 characters',
      });
    }
  });

export const setVariablesBulkSchema = z.object({
  entries: z.array(setVariableSchema).min(1).max(200),
});

export const variableScopeParamsSchema = scopeTarget;

// ============================================================================
// `var_schema` — the JSON Schema a revision carries
// ============================================================================

/**
 * A shallow structural check only. The real verdict is `ajv.compile()` in
 * `variableResolver.compileVarSchema()`, which is the same compiler that will
 * run at render time — validating a schema with anything else would let a
 * revision be published with a schema that only fails on the first device it is
 * applied to.
 *
 * What is enforced here is what ajv does NOT check and what matters to us:
 *  - the document is an object schema with named properties (a template's
 *    inputs are named, never positional);
 *  - every property name is a legal variable name, so `var_schema` cannot
 *    declare `__proto__`;
 *  - every `required` entry is actually declared, so an operator cannot publish
 *    a revision that is unsatisfiable by construction;
 *  - a property marked `x-obliwan-secret` carries no `default` — a default for
 *    a secret is a plaintext credential in the revision body, which is exactly
 *    what the vault exists to prevent (§8.2).
 */
export const varSchemaSchema = z
  .object({
    type: z.literal('object').optional(),
    properties: z.record(z.record(z.unknown())).default({}),
    required: z.array(z.string()).max(200).optional(),
    additionalProperties: z.boolean().optional(),
  })
  .passthrough()
  .superRefine((s, ctx) => {
    const props = s.properties ?? {};
    const names = Object.keys(props);
    if (names.length > 200) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['properties'],
        message: 'a template may declare at most 200 variables',
      });
    }
    for (const name of names) {
      if (!VARIABLE_KEY_RE.test(name)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['properties', name],
          message: `"${name}" is not a legal variable name (lowercase snake_case)`,
        });
      }
      const p = props[name] as Record<string, unknown>;
      const secret = p['x-obliwan-secret'] === true;
      if (secret && 'default' in p) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['properties', name, 'default'],
          message:
            'a secret variable must not carry a default — that would put a plaintext ' +
            'credential in the revision body (ARCHITECTURE.md §8.2)',
        });
      }
      const level = p['x-obliwan-level'];
      if (
        level !== undefined &&
        !(typeof level === 'string' && (VARIABLE_SCOPES as readonly string[]).includes(level))
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['properties', name, 'x-obliwan-level'],
          message: `x-obliwan-level must be one of ${VARIABLE_SCOPES.join(', ')}`,
        });
      }
    }
    for (const r of s.required ?? []) {
      if (!(r in props)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['required'],
          message: `"${r}" is required but is not declared in properties`,
        });
      }
    }
  });

// ============================================================================
// Templates and revisions
// ============================================================================

/**
 * A template body is EXECUTABLE INPUT. The cap is not politeness: the body is
 * parsed and rendered inside the worker whose `resourceLimits` and 5 s timeout
 * are the R6 mitigation, and a multi-megabyte body is a cheap way to spend that
 * budget before the template does anything. 512 KB is roughly 8 000 lines of
 * RouterOS — an order of magnitude more than a full site configuration.
 */
const templateBody = z.string().min(1).max(512 * 1024);

/**
 * RouterOS is not strictly semver: `7`, `7.14`, `7.14.3`, `6.49.10`, `7.15rc2`
 * and `7.16beta4` are all versions MikroTik actually ships. This is migration
 * 008's `VERSION_SHAPE`, so a value accepted here cannot be rejected by the
 * column check; the real ordering is `semver.coerce` in `assignment.service`.
 */
const osVersion = z
  .string()
  .min(1)
  .max(32)
  .regex(/^[0-9]+(\.[0-9]+){0,2}[A-Za-z0-9.+-]*$/, 'expected a version like 7.14.3 or 7.15rc2');

export const createTemplateSchema = z.object({
  name: z.string().min(1).max(120),
  description: z.string().max(2000).nullable().optional(),
  brand: brandEnum,
  /**
   * A POSIX regular expression matched case-insensitively against
   * `devices.model` (migration 008). It is operator-supplied and evaluated once
   * per candidate device, so it is length-capped and must COMPILE here — a
   * pattern that only fails inside the assignment resolver would surface as
   * "no devices matched", which is indistinguishable from a correct empty
   * result and is the worst possible failure mode for a rollout selector.
   */
  modelPattern: z
    .string()
    .max(120)
    .refine(
      (p) => {
        try {
          new RegExp(p);
          return true;
        } catch {
          return false;
        }
      },
      { message: 'model pattern is not a valid regular expression' },
    )
    .nullable()
    .optional(),
  status: z.enum(['active', 'archived']).optional(),
});

export const updateTemplateSchema = createTemplateSchema.partial();

/**
 * The sandbox knobs frozen WITH the body (migration 008): a published revision
 * whose `autoescape` could be flipped afterwards is a published revision whose
 * escaping is not published.
 *
 * `throwOnUndefined` is not offered as `false`. Nunjucks' default is to render
 * an undefined expression as the empty string, which produces exactly the
 * silent hole this milestone's variable resolver refuses to produce; allowing
 * a revision to opt back into it would route around the check.
 */
const renderOptions = z
  .object({
    throwOnUndefined: z.literal(true).optional(),
    trimBlocks: z.boolean().optional(),
    lstripBlocks: z.boolean().optional(),
    autoescape: z.boolean().optional(),
  })
  .strict();

export const createRevisionSchema = z.object({
  body: templateBody,
  varSchema: varSchemaSchema.optional(),
  /** `path -> severity`, consumed by the drift engine to weight a finding
   *  produced by this section of the template. */
  sectionSeverity: z.record(z.enum(['info', 'low', 'medium', 'high', 'critical'])).optional(),
  /** Per-REVISION OS window — a revision that starts using `/interface/wifi`
   *  is RouterOS 7 only while its predecessor was not. */
  osMin: osVersion.nullable().optional(),
  osMax: osVersion.nullable().optional(),
  renderOptions: renderOptions.optional(),
  notes: z.string().max(4000).nullable().optional(),
});

/**
 * Publishing is the moment a revision becomes immutable and its partial
 * dependencies are PINNED (§3.4). There is deliberately no `body` here: you
 * publish a draft that already exists, you do not publish new content in one
 * shot. That is what makes "editing a partial does not change the render of a
 * published revision" true rather than aspirational.
 */
export const publishRevisionSchema = z.object({
  /** Optional operator note, stored with the publication event. */
  note: z.string().max(1000).nullable().optional(),
});

export const revisionStatusSchema = z.object({
  status: z.enum(['quarantined', 'deprecated']),
  reason: z.string().min(1).max(1000),
});

// ============================================================================
// Partials
// ============================================================================

/**
 * A partial is addressed by name from `{% include %}` / `{% import %}`, so its
 * name is a loader key and must not be able to escape the DB loader into the
 * filesystem. This is migration 008's `PARTIAL_NAME_SHAPE`: slash-separated
 * segments, each starting with a letter or a digit — which structurally
 * excludes a leading slash, a `..` segment, a leading dot and a `C:` drive
 * letter. Backslashes are excluded by not being in the character class.
 */
export const PARTIAL_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*(\/[A-Za-z0-9][A-Za-z0-9_.-]*)*$/;

export const partialNameSchema = z
  .string()
  .min(1)
  .max(120)
  .regex(PARTIAL_NAME_RE, 'partial name must be slash-separated segments of letters, digits, _ . -')
  // `..` cannot appear as a whole segment given the regex, but a segment such
  // as `..foo` is legal and a future loader that concatenated names would be
  // one join away from a traversal. Refuse the substring outright.
  .refine((n) => !n.includes('..'), { message: 'partial name must not contain ".."' });

export const createPartialSchema = z.object({
  name: partialNameSchema,
  description: z.string().max(2000).nullable().optional(),
  brand: brandEnum.nullable().optional(),
});

export const createPartialRevisionSchema = z.object({
  body: templateBody,
  changelog: z.string().max(4000).nullable().optional(),
});

// ============================================================================
// Assignments
// ============================================================================

/**
 * `revisionId: null` means "follow the latest published revision"; a number
 * pins the assignment to one revision forever. `pinMode` says which of the two
 * the operator MEANT, so a null that arrived by accident is distinguishable
 * from a null that was chosen.
 *
 * `priority` breaks ties WITHIN a scope level only. Precedence BETWEEN levels
 * (device > group > tenant > global) is decided by the level itself and is not
 * configurable — migration 008 says so, and it is right: a priority that could
 * invert the levels would make the resolution unexplainable in the UI.
 */
export const createAssignmentSchema = scopeTarget.and(
  z.object({
    templateId: z.number().int().positive(),
    revisionId: z.number().int().positive().nullable().optional(),
    pinMode: z.enum(['latest_published', 'pinned']).default('latest_published'),
    priority: z.number().int().min(0).max(10000).default(100),
    enabled: z.boolean().default(true),
  }),
).superRefine((v, ctx) => {
  if (v.pinMode === 'pinned' && (v.revisionId === null || v.revisionId === undefined)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['revisionId'],
      message: 'pinMode "pinned" requires a revisionId',
    });
  }
  if (v.pinMode === 'latest_published' && v.revisionId) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['revisionId'],
      message:
        'pinMode "latest_published" must not carry a revisionId — pick "pinned" if you meant to freeze it',
    });
  }
});

export const updateAssignmentSchema = z.object({
  priority: z.number().int().min(0).max(10000).optional(),
  enabled: z.boolean().optional(),
  revisionId: z.number().int().positive().nullable().optional(),
  pinMode: z.enum(['latest_published', 'pinned']).optional(),
});

// ============================================================================
// Render preview
// ============================================================================

/**
 * Preview a revision against a witness device.
 *
 * NOTE THE ABSENCE OF A `mode` FIELD. The API renders the REDACTED form and
 * nothing else: secrets exist in plaintext only in memory, on the path
 * vault -> equipment (§8.2). There is no query parameter, no header and no
 * admin flag that turns this endpoint into a credential reader.
 *
 * `overrides` lets an operator try a value without writing it — the same typed
 * validation applies, and a secret cannot be overridden this way (that would be
 * a plaintext credential in an HTTP body).
 */
export const renderPreviewSchema = z.object({
  deviceId: z.number().int().positive(),
  overrides: z
    .array(
      z.object({
        key: variableKey,
        value: variableValue,
      }),
    )
    .max(50)
    .optional(),
});

// ============================================================================
// Inferred types — what the controllers receive
// ============================================================================

export type SetVariableInput = z.infer<typeof setVariableSchema>;
export type SetVariablesBulkInput = z.infer<typeof setVariablesBulkSchema>;
export type VariableScopeInput = z.infer<typeof variableScopeParamsSchema>;
export type VarSchemaInput = z.infer<typeof varSchemaSchema>;
export type CreateTemplateInput = z.infer<typeof createTemplateSchema>;
export type UpdateTemplateInput = z.infer<typeof updateTemplateSchema>;
export type CreateRevisionInput = z.infer<typeof createRevisionSchema>;
export type PublishRevisionInput = z.infer<typeof publishRevisionSchema>;
export type CreatePartialInput = z.infer<typeof createPartialSchema>;
export type CreatePartialRevisionInput = z.infer<typeof createPartialRevisionSchema>;
export type CreateAssignmentInput = z.infer<typeof createAssignmentSchema>;
export type UpdateAssignmentInput = z.infer<typeof updateAssignmentSchema>;
export type RenderPreviewInput = z.infer<typeof renderPreviewSchema>;
