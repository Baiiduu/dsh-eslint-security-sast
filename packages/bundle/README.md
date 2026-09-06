# DeepSeek Harness ESLint Security SAST

`@aaub-software/dsh-eslint-security-sast` is a Cordis bundle that registers the
model-facing `eslint_security_scan` tool in
[DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness).

It scans JavaScript and TypeScript source with ESLint 10 and the recommended
rules from `eslint-plugin-security`. Findings are security review candidates,
not automatically confirmed vulnerabilities.

## Install

DeepSeek Harness and Node.js 24 or newer are required. Install the prebuilt
bundle into the profile you use, for example:

```powershell
dsh plugin --profile web add @aaub-software/dsh-eslint-security-sast
```

Restart the profile after installation. The agent will then see the
`eslint_security_scan` tool.

## Supported source

- JavaScript: `.js`, `.mjs`, `.cjs`, `.jsx`
- TypeScript: `.ts`, `.mts`, `.cts`, `.tsx`

The scanner uses ESLint 10.10.0, eslint-plugin-security 4.0.1, and
@typescript-eslint/parser 8.69.0. All are installed as npm dependencies; no
separate scanner executable or Python runtime is required.

## Behavior and safety

- Accepts only workspace-relative files and directories.
- Rejects paths and resolved symlinks that escape the active workspace.
- Runs ESLint in a separate Node.js process controlled by Harness.
- Supports cancellation, timeout, process-tree termination, and bounded output.
- Does not load ESLint configuration or suppression files from the scanned
  repository.
- Ignores inline `eslint-disable` comments.
- Does not enable cache files, autofix, TypeScript project services, or the
  target repository's `tsconfig.json`.
- Does not execute target source code, project plugins, or package scripts.
- Requires no network access during normal scanning.

The tool reports parse diagnostics separately and marks incomplete coverage as
`partial`. The agent should read surrounding source and trace relevant data flow
before classifying a hotspot as a vulnerability or false positive.

## Documentation and source

See the
[repository documentation](https://github.com/Baiiduu/dsh-eslint-security-sast#readme)
for the complete English and Chinese guide, configuration details, security
boundaries, and development instructions.

Source:
[Baiiduu/dsh-eslint-security-sast](https://github.com/Baiiduu/dsh-eslint-security-sast)

