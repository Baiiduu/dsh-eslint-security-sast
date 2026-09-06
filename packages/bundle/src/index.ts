/**
 * Cordis entry point for the DeepSeek Harness ESLint Security SAST bundle.
 * @module @aaub-software/dsh-eslint-security-sast
 */

import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-sandbox'
import type {} from '@deepseek-ai/dsh-sandbox-policy'
import type {} from '@deepseek-ai/dsh-subprocess'
import type {} from '@deepseek-ai/dsh-tools'
import { resolveConfig, type Config as PluginConfig } from './config.js'
import { createEslintSecurityScanTool } from './tool.js'

export { Config } from './config.js'
export type { ResolvedConfig } from './config.js'
export type {
  EslintSecurityDiagnostic,
  EslintSecurityEngine,
  EslintSecurityFinding,
  EslintSecurityScanInput,
  EslintSecurityScanResult,
} from './types.js'

/** Cordis plugin name used in diagnostics. */
export const name = 'eslint-security-sast'

/** Harness services required for tool registration and controlled execution. */
export const inject = ['tools', 'subprocess', 'sandbox', 'sandboxPolicy']

/** Resolve plugin configuration and register the model-facing scanner tool. */
export function apply(ctx: Context, config: PluginConfig = {}): void {
  const resolvedConfig = resolveConfig(config)
  ctx.tools.register(createEslintSecurityScanTool(ctx, resolvedConfig))
}
