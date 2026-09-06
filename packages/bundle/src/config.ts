import z from '@deepseek-ai/schemastery'

export const DEFAULT_TIMEOUT_MS = 300_000
export const DEFAULT_MAX_FINDINGS = 200

/** User-facing configuration accepted by the Cordis plugin. */
export interface Config {
  timeoutMs?: number
  maxFindings?: number
}

/** Fully resolved configuration used by scan execution. */
export interface ResolvedConfig {
  timeoutMs: number
  maxFindings: number
}

/** Runtime schema consumed by the Cordis loader. */
export const Config: z<Config> = z.object({
  timeoutMs: z.number().step(1).min(1).max(3_600_000).default(DEFAULT_TIMEOUT_MS),
  maxFindings: z.number().step(1).min(1).max(10_000).default(DEFAULT_MAX_FINDINGS),
})

/** Apply defaults after the loader has validated configured values. */
export function resolveConfig(config: Config = {}): ResolvedConfig {
  return {
    timeoutMs: config.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    maxFindings: config.maxFindings ?? DEFAULT_MAX_FINDINGS,
  }
}
