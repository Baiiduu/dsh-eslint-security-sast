import { relative, resolve, sep } from 'node:path'
import { pathToFileURL } from 'node:url'
import { ESLint, type Linter } from 'eslint'
import tsParser from '@typescript-eslint/parser'
import securityPlugin from 'eslint-plugin-security'
import type {
  EslintSecurityDiagnostic,
  EslintSecurityFinding,
} from './types.js'

interface RunnerRequest {
  targets: string[]
  maxFindings: number
}

interface RunnerResult {
  eslintVersion: string
  securityPluginVersion: string
  scannedFiles: number
  findings: EslintSecurityFinding[]
  diagnostics: EslintSecurityDiagnostic[]
  totalFindings: number
  truncated: boolean
}

interface SecurityPluginMetadata {
  meta?: { version?: string }
  configs?: { recommended?: { rules?: unknown } }
  rules?: Record<string, {
    meta?: {
      docs?: { url?: string }
    }
  }>
}

type FlatPlugin = NonNullable<Linter.Config['plugins']>[string]

const pluginMetadata = securityPlugin as unknown as SecurityPluginMetadata
const configuredRules = pluginMetadata.configs?.recommended?.rules

if (configuredRules === undefined || typeof configuredRules !== 'object' || configuredRules === null) {
  throw new Error('eslint-security-sast: eslint-plugin-security does not expose its recommended rules')
}

// The DefinitelyTyped package currently models eslint-plugin-security against
// ESLint 9. The runtime plugin implements the same flat-plugin boundary, but
// ESLint 10 owns a different nominal type graph, so narrow it once here.
const flatSecurityPlugin = securityPlugin as unknown as FlatPlugin
const recommendedRules = configuredRules as Linter.RulesRecord
const SOURCE_SNIPPET_MAX_LINES = 12
const SOURCE_SNIPPET_MAX_CHARS = 2_000

function ruleDocumentationUrl(ruleId: string): string | undefined {
  const prefix = 'security/'
  if (!ruleId.startsWith(prefix)) return undefined
  const value = pluginMetadata.rules?.[ruleId.slice(prefix.length)]?.meta?.docs?.url
  return typeof value === 'string' && value.trim() !== '' ? value : undefined
}

function messageNodeType(message: Linter.LintMessage): string | undefined {
  const value = (message as Linter.LintMessage & { nodeType?: unknown }).nodeType
  return typeof value === 'string' && value.trim() !== '' ? value : undefined
}

function sourceSnippet(
  source: string | undefined,
  message: Linter.LintMessage,
): string | undefined {
  if (source === undefined || source === '') return undefined

  const lines = source.split(/\r?\n/u)
  const startIndex = message.line - 1
  if (startIndex < 0 || startIndex >= lines.length) return undefined

  const reportedEndLine = message.endLine ?? message.line
  const endIndex = Math.min(
    lines.length - 1,
    Math.max(startIndex, reportedEndLine - 1),
    startIndex + SOURCE_SNIPPET_MAX_LINES - 1,
  )
  const linesTruncated = endIndex < reportedEndLine - 1
  const selected = lines.slice(startIndex, endIndex + 1)
  selected[0] = selected[0]?.slice(Math.max(0, message.column - 1)) ?? ''
  if (message.endColumn !== undefined) {
    const lastIndex = selected.length - 1
    const endColumn = Math.max(0, message.endColumn - 1)
    if (lastIndex === 0) {
      selected[0] = selected[0]?.slice(0, Math.max(0, endColumn - message.column + 1)) ?? ''
    } else if (endIndex === reportedEndLine - 1) {
      selected[lastIndex] = selected[lastIndex]?.slice(0, endColumn) ?? ''
    }
  }

  const snippet = selected.join('\n') + (linesTruncated ? '\n[snippet truncated]' : '')
  if (snippet === '') return undefined
  if (snippet.length <= SOURCE_SNIPPET_MAX_CHARS) return snippet
  return `${snippet.slice(0, SOURCE_SNIPPET_MAX_CHARS)}\n[snippet truncated]`
}

function parseRequest(raw: string | undefined): RunnerRequest {
  if (raw === undefined) throw new Error('eslint-security-sast: runner request is missing')

  let value: unknown
  try {
    value = JSON.parse(raw) as unknown
  } catch (cause) {
    throw new Error('eslint-security-sast: runner request is not valid JSON', { cause })
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('eslint-security-sast: runner request must be an object')
  }

  const request = value as Record<string, unknown>
  if (!Array.isArray(request.targets)
    || request.targets.length === 0
    || !request.targets.every(target => typeof target === 'string' && target.trim() !== '')) {
    throw new Error('eslint-security-sast: runner targets must be a non-empty array of strings')
  }
  if (!Number.isInteger(request.maxFindings)
    || (request.maxFindings as number) < 1
    || (request.maxFindings as number) > 10_000) {
    throw new Error('eslint-security-sast: runner maxFindings must be an integer from 1 to 10000')
  }

  return {
    targets: request.targets as string[],
    maxFindings: request.maxFindings as number,
  }
}

function createOverrideConfig(): Linter.Config[] {
  const security = {
    plugins: { security: flatSecurityPlugin },
    rules: recommendedRules,
  }

  return [
    {
      name: 'ssc/global-ignores',
      ignores: ['**/.git/**', '**/node_modules/**'],
    },
    {
      name: 'ssc/javascript-security',
      files: ['**/*.{js,mjs,jsx}'],
      ...security,
      languageOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
        parserOptions: { ecmaFeatures: { jsx: true } },
      },
    },
    {
      name: 'ssc/commonjs-security',
      files: ['**/*.cjs'],
      ...security,
      languageOptions: {
        ecmaVersion: 'latest',
        sourceType: 'commonjs',
      },
    },
    {
      name: 'ssc/typescript-security',
      files: ['**/*.{ts,mts,tsx}'],
      ...security,
      languageOptions: {
        parser: tsParser,
        ecmaVersion: 'latest',
        sourceType: 'module',
        parserOptions: { jsDocParsingMode: 'none' },
      },
    },
    {
      name: 'ssc/typescript-commonjs-security',
      files: ['**/*.cts'],
      ...security,
      languageOptions: {
        parser: tsParser,
        ecmaVersion: 'latest',
        sourceType: 'commonjs',
        parserOptions: { jsDocParsingMode: 'none' },
      },
    },
  ]
}

function workspaceRelativePath(workspaceRoot: string, filePath: string): string {
  const candidate = relative(workspaceRoot, filePath)
  if (candidate === '..' || candidate.startsWith(`..${sep}`)) {
    throw new Error('eslint-security-sast: ESLint returned a file outside the workspace')
  }
  return candidate.replaceAll('\\', '/')
}

function compareFindings(left: EslintSecurityFinding, right: EslintSecurityFinding): number {
  return left.severity.localeCompare(right.severity)
    || left.path.localeCompare(right.path)
    || left.startLine - right.startLine
    || left.startColumn - right.startColumn
    || left.ruleId.localeCompare(right.ruleId)
}

async function run(request: RunnerRequest): Promise<RunnerResult> {
  const workspaceRoot = resolve(process.cwd())
  const eslint = new ESLint({
    cwd: workspaceRoot,
    overrideConfigFile: true,
    overrideConfig: createOverrideConfig(),
    allowInlineConfig: false,
    applySuppressions: false,
    cache: false,
    concurrency: 'off',
    errorOnUnmatchedPattern: false,
    fix: false,
    warnIgnored: false,
  })
  const lintResults = await eslint.lintFiles(request.targets)
  const findings: EslintSecurityFinding[] = []
  const diagnostics: EslintSecurityDiagnostic[] = []

  for (const lintResult of lintResults) {
    const path = workspaceRelativePath(workspaceRoot, lintResult.filePath)
    for (const message of lintResult.messages) {
      if (message.ruleId !== null && message.fatal !== true) {
        const nodeType = messageNodeType(message)
        const ruleUrl = ruleDocumentationUrl(message.ruleId)
        const source = sourceSnippet(lintResult.source, message)
        findings.push({
          ruleId: message.ruleId,
          severity: message.severity === 2 ? 'error' : 'warning',
          message: message.message,
          path,
          startLine: message.line,
          startColumn: message.column,
          endLine: message.endLine ?? message.line,
          endColumn: message.endColumn ?? message.column,
          ...(nodeType === undefined ? {} : { nodeType }),
          ...(ruleUrl === undefined ? {} : { ruleUrl }),
          ...(source === undefined ? {} : { source }),
        })
        continue
      }

      diagnostics.push({
        type: message.fatal === true ? 'parse-error' : 'lint-error',
        message: message.message,
        path,
        ...(message.line > 0 ? { line: message.line } : {}),
        ...(message.column > 0 ? { column: message.column } : {}),
      })
    }
  }

  findings.sort(compareFindings)
  const returnedFindings = findings.slice(0, request.maxFindings)
  return {
    eslintVersion: ESLint.version,
    securityPluginVersion: pluginMetadata.meta?.version ?? 'unknown',
    scannedFiles: lintResults.length,
    findings: returnedFindings,
    diagnostics,
    totalFindings: findings.length,
    truncated: returnedFindings.length < findings.length,
  }
}

async function main(): Promise<void> {
  const request = parseRequest(process.argv[2])
  const result = await run(request)
  process.stdout.write(JSON.stringify(result))
}

const invokedPath = process.argv[1]
if (invokedPath !== undefined && pathToFileURL(resolve(invokedPath)).href === import.meta.url) {
  void main().catch((cause: unknown) => {
    const message = cause instanceof Error ? cause.message : String(cause)
    process.stderr.write(`${message}\n`)
    process.exitCode = 1
  })
}

export type { RunnerRequest, RunnerResult }
export { createOverrideConfig, parseRequest, run }
