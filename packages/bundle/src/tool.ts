import { realpath, stat } from 'node:fs/promises'
import { isAbsolute, relative, resolve, sep } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-sandbox-policy'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { createEslintSastResult } from './agent-result.js'
import type { ResolvedConfig } from './config.js'
import { runEslintSecurity } from './executor.js'
import type { EslintSecurityScanInput } from './types.js'

function isInside(root: string, candidate: string): boolean {
  const relativePath = relative(root, candidate)
  return relativePath === ''
    || (relativePath !== '..' && !relativePath.startsWith(`..${sep}`) && !isAbsolute(relativePath))
}

async function resolveTargets(workspaceRoot: string, paths: readonly string[]): Promise<string[]> {
  const canonicalRoot = await realpath(workspaceRoot)
  const resolved = await Promise.all(paths.map(async (requestedPath, index) => {
    if (requestedPath.trim() === '') {
      throw new Error(`eslint_security_scan: paths[${index}] must be a non-empty workspace-relative path`)
    }
    if (isAbsolute(requestedPath)) {
      throw new Error(`eslint_security_scan: paths[${index}] must be relative to the workspace`)
    }

    const lexicalTarget = resolve(canonicalRoot, requestedPath)
    if (!isInside(canonicalRoot, lexicalTarget)) {
      throw new Error(`eslint_security_scan: paths[${index}] escapes the workspace`)
    }
    const canonicalTarget = await realpath(lexicalTarget)
    if (!isInside(canonicalRoot, canonicalTarget)) {
      throw new Error(`eslint_security_scan: paths[${index}] resolves outside the workspace`)
    }
    const targetInfo = await stat(canonicalTarget)
    if (!targetInfo.isFile() && !targetInfo.isDirectory()) {
      throw new Error(`eslint_security_scan: paths[${index}] must identify a file or directory`)
    }

    const relativeTarget = relative(canonicalRoot, canonicalTarget)
    return relativeTarget === '' ? '.' : relativeTarget
  }))
  return [...new Set(resolved)]
}

function renderResult(result: unknown): string {
  return JSON.stringify(result)
}

const locationSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    path: { type: 'string', required: true },
    startLine: { type: 'integer', required: true },
    startColumn: { type: 'integer', required: true },
    endLine: { type: 'integer', required: true },
    endColumn: { type: 'integer', required: true },
  },
} as const

const ruleSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    id: { type: 'string', required: true },
    name: { type: 'string' },
    severity: { type: 'string', enum: ['info', 'warning', 'error'], required: true },
    cwe: { type: 'array', items: { type: 'string' } },
    owasp: { type: 'array', items: { type: 'string' } },
    references: { type: 'array', items: { type: 'string' } },
  },
} as const

const evidenceSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    type: { type: 'string', required: true },
    description: { type: 'string' },
    locations: { type: 'array', items: locationSchema },
    data: { type: 'object', additionalProperties: true },
  },
} as const

const findingSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    id: { type: 'string', required: true },
    scanner: { type: 'string', required: true },
    rule: { ...ruleSchema, required: true },
    message: { type: 'string', required: true },
    location: { ...locationSchema, required: true },
    fingerprint: { type: 'string' },
    evidence: { type: 'array', items: evidenceSchema, required: true },
  },
} as const

const diagnosticSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    level: { type: 'string', enum: ['error', 'warning', 'info'], required: true },
    type: { type: 'string', required: true },
    message: { type: 'string', required: true },
    code: { oneOf: [{ type: 'integer' }, { type: 'string' }] },
    location: locationSchema,
  },
} as const

/** Build the model-facing ESLint Security tool. */
export function createEslintSecurityScanTool(ctx: Context, config: ResolvedConfig) {
  return defineTool({
    name: 'eslint_security_scan',
    description: 'Run a read-only ESLint Security hotspot scan over workspace-relative JavaScript and TypeScript files or directories. '
      + 'Uses a fixed scanner-owned configuration and never loads the target repository ESLint config, inline disables, or suppressions. '
      + 'Results are rule-based review candidates; inspect source context and relevant data flow before classifying a vulnerability. '
      + 'Returns the versioned ssc-sast/v1 normalized result contract.',
    parameters: {
      paths: {
        type: 'array',
        items: { type: 'string' },
        description: 'Workspace-relative JavaScript or TypeScript files and directories. Defaults to the workspace root.',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          schemaVersion: { type: 'string', const: 'ssc-sast/v1', required: true },
          status: { type: 'string', enum: ['completed', 'partial'], required: true },
          scanner: {
            type: 'object',
            additionalProperties: false,
            required: true,
            properties: {
              name: { type: 'string', required: true },
              version: { type: 'string', required: true },
              components: { type: 'object', additionalProperties: true },
              configuration: { type: 'string' },
            },
          },
          scannedPaths: { type: 'array', items: { type: 'string' }, required: true },
          findings: { type: 'array', items: findingSchema, required: true },
          diagnostics: { type: 'array', items: diagnosticSchema, required: true },
          summary: {
            type: 'object',
            additionalProperties: false,
            required: true,
            properties: {
              scannedFiles: { type: 'integer' },
              totalFindings: { type: 'integer', required: true },
              returnedFindings: { type: 'integer', required: true },
              truncated: { type: 'boolean', required: true },
              durationMs: { type: 'number', required: true },
            },
          },
        },
      },
      render: (_args, result) => [{ type: 'text', text: renderResult(result) }],
    },
    async execute(args: EslintSecurityScanInput, exec) {
      const workspaceRoot = exec.agent?.session.header.cwd
      if (workspaceRoot === undefined) {
        throw new Error('eslint_security_scan: the calling session does not define a workspace')
      }
      if (args.paths !== undefined && args.paths.length === 0) {
        throw new Error('eslint_security_scan: paths must not be an empty array')
      }

      const targets = await resolveTargets(workspaceRoot, args.paths ?? ['.'])
      exec.signal.throwIfAborted()
      const sandboxPolicy = ctx.sandboxPolicy.resolve(
        exec.agent === undefined ? {} : { session: exec.agent.session },
      )
      const scan = await runEslintSecurity(ctx, {
        cwd: workspaceRoot,
        targets,
        config,
        sandboxPolicy,
        signal: exec.signal,
      })
      return createEslintSastResult(scan, targets)
    },
  })
}

export { resolveTargets }
