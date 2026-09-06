import { fileURLToPath } from 'node:url'
import type { Context } from '@deepseek-ai/cordis'
import type { SandboxExecutionPolicy, SandboxPolicy } from '@deepseek-ai/dsh-sandbox'
import type {} from '@deepseek-ai/dsh-subprocess'
import type { ResolvedConfig } from './config.js'
import type { RunnerRequest, RunnerResult } from './runner.js'
import type {
  EslintSecurityDiagnostic,
  EslintSecurityFinding,
} from './types.js'

const STDOUT_MAX_BYTES = 16 * 1024 * 1024
const STDERR_MAX_BYTES = 1024 * 1024
const TERMINATION_GRACE_MS = 2_000
const RUNNER_PATH = fileURLToPath(new URL('./runner.js', import.meta.url))

export interface RunEslintSecurityRequest {
  cwd: string
  targets: readonly string[]
  config: ResolvedConfig
  sandboxPolicy: SandboxExecutionPolicy
  signal?: AbortSignal
}

export interface RunEslintSecurityResult extends RunnerResult {
  durationMs: number
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`runner output ${field} must be a non-empty string`)
  }
  return value
}

function requireInteger(value: unknown, field: string, minimum: number): number {
  if (!Number.isInteger(value) || (value as number) < minimum) {
    throw new Error(`runner output ${field} must be an integer greater than or equal to ${minimum}`)
  }
  return value as number
}

function parseFinding(value: unknown, index: number): EslintSecurityFinding {
  const field = `findings[${index}]`
  if (!isRecord(value)) throw new Error(`runner output ${field} must be an object`)
  const severity = value.severity
  if (severity !== 'warning' && severity !== 'error') {
    throw new Error(`runner output ${field}.severity is invalid`)
  }

  return {
    ruleId: requireString(value.ruleId, `${field}.ruleId`),
    severity,
    message: requireString(value.message, `${field}.message`),
    path: requireString(value.path, `${field}.path`),
    startLine: requireInteger(value.startLine, `${field}.startLine`, 1),
    startColumn: requireInteger(value.startColumn, `${field}.startColumn`, 1),
    endLine: requireInteger(value.endLine, `${field}.endLine`, 1),
    endColumn: requireInteger(value.endColumn, `${field}.endColumn`, 1),
  }
}

function parseDiagnostic(value: unknown, index: number): EslintSecurityDiagnostic {
  const field = `diagnostics[${index}]`
  if (!isRecord(value)) throw new Error(`runner output ${field} must be an object`)
  const type = value.type
  if (type !== 'parse-error' && type !== 'lint-error') {
    throw new Error(`runner output ${field}.type is invalid`)
  }
  if (value.line !== undefined) requireInteger(value.line, `${field}.line`, 1)
  if (value.column !== undefined) requireInteger(value.column, `${field}.column`, 1)

  return {
    type,
    message: requireString(value.message, `${field}.message`),
    path: requireString(value.path, `${field}.path`),
    ...(value.line !== undefined ? { line: value.line as number } : {}),
    ...(value.column !== undefined ? { column: value.column as number } : {}),
  }
}

function parseRunnerOutput(text: string): RunnerResult {
  let value: unknown
  try {
    value = JSON.parse(text) as unknown
  } catch (cause) {
    throw new Error('eslint-security-sast: runner produced invalid JSON output', { cause })
  }
  if (!isRecord(value)) throw new Error('eslint-security-sast: runner output must be an object')
  if (!Array.isArray(value.findings)) {
    throw new Error('eslint-security-sast: runner output findings must be an array')
  }
  if (!Array.isArray(value.diagnostics)) {
    throw new Error('eslint-security-sast: runner output diagnostics must be an array')
  }

  const findings = value.findings.map(parseFinding)
  const diagnostics = value.diagnostics.map(parseDiagnostic)
  const totalFindings = requireInteger(value.totalFindings, 'totalFindings', 0)
  if (totalFindings < findings.length) {
    throw new Error('eslint-security-sast: runner totalFindings is smaller than returned findings')
  }
  if (typeof value.truncated !== 'boolean'
    || value.truncated !== (findings.length < totalFindings)) {
    throw new Error('eslint-security-sast: runner truncation metadata is inconsistent')
  }

  return {
    eslintVersion: requireString(value.eslintVersion, 'eslintVersion'),
    securityPluginVersion: requireString(value.securityPluginVersion, 'securityPluginVersion'),
    scannedFiles: requireInteger(value.scannedFiles, 'scannedFiles', 0),
    findings,
    diagnostics,
    totalFindings,
    truncated: value.truncated,
  }
}

function boundedDiagnostic(text: string): string {
  const trimmed = text.trim()
  if (trimmed.length <= 4_000) return trimmed
  return `${trimmed.slice(0, 4_000)}\n[diagnostic truncated]`
}

function confinedPolicy(policy: SandboxExecutionPolicy): SandboxPolicy {
  if (policy.mode === 'danger-full-access') {
    throw new Error('eslint-security-sast: danger-full-access is not a confined sandbox policy')
  }
  return { ...policy, mode: policy.mode }
}

/** Execute the bundled ESLint runner through Harness-managed process services. */
export async function runEslintSecurity(
  ctx: Context,
  request: RunEslintSecurityRequest,
): Promise<RunEslintSecurityResult> {
  if (request.targets.length === 0) {
    throw new Error('eslint-security-sast: at least one scan target is required')
  }

  const runnerRequest: RunnerRequest = {
    targets: [...request.targets],
    maxFindings: request.config.maxFindings,
  }
  const baseArgv = [process.execPath, RUNNER_PATH, JSON.stringify(runnerRequest)]
  const argv = request.sandboxPolicy.mode === 'danger-full-access'
    ? baseArgv
    : ctx.sandbox.confine(baseArgv, confinedPolicy(request.sandboxPolicy)).argv
  const timeoutSignal = AbortSignal.timeout(request.config.timeoutMs)
  const signal = request.signal === undefined
    ? timeoutSignal
    : AbortSignal.any([request.signal, timeoutSignal])
  const startedAt = Date.now()
  const processHandle = ctx.subprocess.spawn({
    argv,
    cwd: request.cwd,
    stdio: {
      stdin: 'ignore',
      stdout: { maxBytes: STDOUT_MAX_BYTES },
      stderr: { maxBytes: STDERR_MAX_BYTES },
    },
    graceMs: TERMINATION_GRACE_MS,
    signal,
  })
  const outcome = await processHandle.done
  const durationMs = Date.now() - startedAt
  const stdout = processHandle.collected.stdout?.readFrom(0)
  const stderr = processHandle.collected.stderr?.readFrom(0)

  if (request.signal?.aborted === true) throw request.signal.reason
  if (timeoutSignal.aborted) {
    throw new Error(`eslint-security-sast: scan timed out after ${request.config.timeoutMs}ms`)
  }
  if (stdout === undefined || stderr === undefined) {
    throw new Error('eslint-security-sast: subprocess did not provide collected output')
  }
  if (stdout.lossy) {
    throw new Error(`eslint-security-sast: JSON output exceeded ${STDOUT_MAX_BYTES} bytes`)
  }
  if (outcome.exitCode !== 0) {
    const diagnostic = boundedDiagnostic(stderr.text)
    throw new Error(
      `eslint-security-sast: runner exited with code ${String(outcome.exitCode)}`
      + (diagnostic === '' ? '' : `\n${diagnostic}`),
    )
  }

  return {
    ...parseRunnerOutput(stdout.text),
    durationMs,
  }
}

export { parseRunnerOutput }
