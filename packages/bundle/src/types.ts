/** Arguments accepted by the model-facing `eslint_security_scan` tool. */
export interface EslintSecurityScanInput {
  /** Workspace-relative JavaScript or TypeScript files and directories. Defaults to the workspace root. */
  paths?: string[]
}

/** One security hotspot reported by an ESLint security rule. */
export interface EslintSecurityFinding {
  ruleId: string
  severity: 'warning' | 'error'
  message: string
  path: string
  startLine: number
  startColumn: number
  endLine: number
  endColumn: number
}

/** A source file that ESLint could not analyze completely. */
export interface EslintSecurityDiagnostic {
  type: 'parse-error' | 'lint-error'
  message: string
  path: string
  line?: number
  column?: number
}

/** Scanner and rule-package versions used for a completed invocation. */
export interface EslintSecurityEngine {
  name: 'eslint-security'
  eslintVersion: string
  securityPluginVersion: string
}

/** Canonical usable result returned by the `eslint_security_scan` tool. */
export interface EslintSecurityScanResult {
  status: 'completed' | 'partial'
  engine: EslintSecurityEngine
  scannedPaths: string[]
  scannedFiles: number
  findings: EslintSecurityFinding[]
  diagnostics: EslintSecurityDiagnostic[]
  totalFindings: number
  returnedFindings: number
  truncated: boolean
  durationMs: number
}
