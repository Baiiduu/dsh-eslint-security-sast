import { realpath, stat } from 'node:fs/promises'
import { isAbsolute, relative, resolve, sep } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-sandbox-policy'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ResolvedConfig } from './config.js'
import { runEslintSecurity } from './executor.js'
import type {
  EslintSecurityDiagnostic,
  EslintSecurityFinding,
  EslintSecurityScanInput,
  EslintSecurityScanResult,
} from './types.js'

const SEVERITY_ORDER: Readonly<Record<EslintSecurityFinding['severity'], number>> = {
  error: 0,
  warning: 1,
}

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

function compareFindings(left: EslintSecurityFinding, right: EslintSecurityFinding): number {
  return SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity]
    || left.path.localeCompare(right.path)
    || left.startLine - right.startLine
    || left.startColumn - right.startColumn
    || left.ruleId.localeCompare(right.ruleId)
}

function renderDiagnostic(diagnostic: EslintSecurityDiagnostic): string {
  const location = diagnostic.line === undefined
    ? diagnostic.path
    : `${diagnostic.path}:${diagnostic.line}:${diagnostic.column ?? 1}`
  return `- [${diagnostic.type}] ${location}: ${diagnostic.message}`
}

function renderResult(result: EslintSecurityScanResult): string {
  const lines = [
    `ESLint Security scan ${result.status}.`,
    `Engine: ESLint ${result.engine.eslintVersion}; eslint-plugin-security ${result.engine.securityPluginVersion}.`,
    `Scanned targets: ${result.scannedPaths.length}; analyzed files: ${result.scannedFiles}.`,
    `Security hotspots: ${result.totalFindings}; returned: ${result.returnedFindings}; truncated: ${String(result.truncated)}.`,
    `Duration: ${result.durationMs}ms.`,
    'Treat rule matches as review candidates, not confirmed vulnerabilities. Read the surrounding source and trace relevant data flow before drawing a conclusion.',
  ]

  if (result.findings.length > 0) {
    lines.push('', 'Security hotspots:')
    for (const finding of result.findings) {
      lines.push(
        `- [${finding.severity}] ${finding.ruleId} at ${finding.path}:${finding.startLine}:${finding.startColumn}`
        + `-${finding.endLine}:${finding.endColumn}: ${finding.message}`,
      )
    }
  }
  if (result.diagnostics.length > 0) {
    lines.push('', 'Diagnostics:', ...result.diagnostics.map(renderDiagnostic))
  }
  return lines.join('\n')
}

const findingSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    ruleId: { type: 'string', required: true },
    severity: { type: 'string', enum: ['warning', 'error'], required: true },
    message: { type: 'string', required: true },
    path: { type: 'string', required: true },
    startLine: { type: 'integer', required: true },
    startColumn: { type: 'integer', required: true },
    endLine: { type: 'integer', required: true },
    endColumn: { type: 'integer', required: true },
  },
} as const

const diagnosticSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    type: { type: 'string', enum: ['parse-error', 'lint-error'], required: true },
    message: { type: 'string', required: true },
    path: { type: 'string', required: true },
    line: { type: 'integer' },
    column: { type: 'integer' },
  },
} as const

/** Build the model-facing ESLint Security tool. */
export function createEslintSecurityScanTool(ctx: Context, config: ResolvedConfig) {
  return defineTool({
    name: 'eslint_security_scan',
    description: 'Run a read-only ESLint Security hotspot scan over workspace-relative JavaScript and TypeScript files or directories. '
      + 'Uses a fixed scanner-owned configuration and never loads the target repository ESLint config, inline disables, or suppressions. '
      + 'Results are rule-based review candidates; inspect source context and relevant data flow before classifying a vulnerability.',
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
          status: { type: 'string', enum: ['completed', 'partial'], required: true },
          engine: {
            type: 'object',
            additionalProperties: false,
            required: true,
            properties: {
              name: { type: 'string', const: 'eslint-security', required: true },
              eslintVersion: { type: 'string', required: true },
              securityPluginVersion: { type: 'string', required: true },
            },
          },
          scannedPaths: { type: 'array', items: { type: 'string' }, required: true },
          scannedFiles: { type: 'integer', required: true },
          findings: { type: 'array', items: findingSchema, required: true },
          diagnostics: { type: 'array', items: diagnosticSchema, required: true },
          totalFindings: { type: 'integer', required: true },
          returnedFindings: { type: 'integer', required: true },
          truncated: { type: 'boolean', required: true },
          durationMs: { type: 'integer', required: true },
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
      const findings = [...scan.findings].sort(compareFindings)
      const result: EslintSecurityScanResult = {
        status: scan.diagnostics.length > 0 ? 'partial' : 'completed',
        engine: {
          name: 'eslint-security',
          eslintVersion: scan.eslintVersion,
          securityPluginVersion: scan.securityPluginVersion,
        },
        scannedPaths: targets,
        scannedFiles: scan.scannedFiles,
        findings,
        diagnostics: scan.diagnostics,
        totalFindings: scan.totalFindings,
        returnedFindings: findings.length,
        truncated: scan.truncated,
        durationMs: scan.durationMs,
      }
      return result
    },
  })
}

export { resolveTargets }
