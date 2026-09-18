import {
  SAST_SCHEMA_VERSION,
  type SastDiagnostic,
  type SastEvidence,
  type SastFinding,
  type SastScanResult,
} from '@aaub-software/dsh-sast-contract'
import type { RunEslintSecurityResult } from './executor.js'
import type { EslintSecurityFinding } from './types.js'

interface EnrichedEslintSecurityFinding extends EslintSecurityFinding {
  nodeType?: string
  ruleUrl?: string
  source?: string
}

export interface EslintSourceEvidence extends SastEvidence {
  type: 'eslint.source-snippet'
  data: {
    text: string
    nodeType?: string
  }
}

export type EslintEvidence = EslintSourceEvidence

/** Public model-facing result produced by the ESLint Security adapter. */
export type EslintSastScanResult = SastScanResult<EslintEvidence>

const SEVERITY_ORDER: Readonly<Record<EslintSecurityFinding['severity'], number>> = {
  error: 0,
  warning: 1,
}

function compareFindings(
  left: EslintSecurityFinding,
  right: EslintSecurityFinding,
): number {
  return SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity]
    || left.path.localeCompare(right.path)
    || left.startLine - right.startLine
    || left.startColumn - right.startColumn
    || left.ruleId.localeCompare(right.ruleId)
}

function normalizeRuleUrl(value: string | undefined): string[] | undefined {
  if (value === undefined) return undefined
  try {
    const url = new URL(value)
    return url.protocol === 'https:' || url.protocol === 'http:' ? [value] : undefined
  } catch {
    return undefined
  }
}

function createFindingId(finding: EslintSecurityFinding): string {
  return [
    'eslint-security',
    encodeURIComponent(finding.ruleId),
    encodeURIComponent(finding.path),
    String(finding.startLine),
    String(finding.startColumn),
  ].join(':')
}

function createEvidence(finding: EnrichedEslintSecurityFinding): EslintEvidence[] {
  if (finding.source === undefined) return []
  return [{
    type: 'eslint.source-snippet',
    data: {
      text: finding.source,
      ...(finding.nodeType === undefined ? {} : { nodeType: finding.nodeType }),
    },
  }]
}

function createFinding(
  finding: EnrichedEslintSecurityFinding,
): SastFinding<EslintEvidence> {
  const references = normalizeRuleUrl(finding.ruleUrl)
  return {
    id: createFindingId(finding),
    scanner: 'eslint-security',
    rule: {
      id: finding.ruleId,
      severity: finding.severity,
      ...(references === undefined ? {} : { references }),
    },
    message: finding.message,
    location: {
      path: finding.path,
      startLine: finding.startLine,
      startColumn: finding.startColumn,
      endLine: finding.endLine,
      endColumn: finding.endColumn,
    },
    evidence: createEvidence(finding),
  }
}

function createDiagnostic(
  diagnostic: RunEslintSecurityResult['diagnostics'][number],
): SastDiagnostic {
  const line = diagnostic.line
  const column = diagnostic.column ?? 1
  return {
    level: 'error',
    type: diagnostic.type,
    message: diagnostic.message,
    ...(line === undefined
      ? {}
      : {
          location: {
            path: diagnostic.path,
            startLine: line,
            startColumn: column,
            endLine: line,
            endColumn: column,
          },
        }),
  }
}

/** Convert one validated ESLint execution result into the public SSC SAST contract. */
export function createEslintSastResult(
  scan: RunEslintSecurityResult,
  scannedPaths: readonly string[],
): EslintSastScanResult {
  const findings = [...scan.findings]
    .sort(compareFindings)
    .map(createFinding)

  return {
    schemaVersion: SAST_SCHEMA_VERSION,
    status: scan.diagnostics.length > 0 ? 'partial' : 'completed',
    scanner: {
      name: 'eslint-security',
      version: scan.eslintVersion,
      components: {
        'eslint-plugin-security': scan.securityPluginVersion,
      },
      configuration: 'eslint-plugin-security/recommended',
    },
    scannedPaths: [...scannedPaths],
    findings,
    diagnostics: scan.diagnostics.map(createDiagnostic),
    summary: {
      scannedFiles: scan.scannedFiles,
      totalFindings: scan.totalFindings,
      returnedFindings: findings.length,
      truncated: scan.truncated,
      durationMs: scan.durationMs,
    },
  }
}
