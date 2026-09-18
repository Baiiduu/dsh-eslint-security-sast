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
  /** ESLint-reported AST node type associated with the rule match. */
  nodeType?: string
  /** HTTP(S) documentation URL declared by the matched rule. */
  ruleUrl?: string
  /** Bounded source text covering the reported location. */
  source?: string
}

/** A source file that ESLint could not analyze completely. */
export interface EslintSecurityDiagnostic {
  type: 'parse-error' | 'lint-error'
  message: string
  path: string
  line?: number
  column?: number
}
