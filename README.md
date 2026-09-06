# DeepSeek Harness ESLint Security SAST

[English](#english) | [简体中文](#简体中文)

## English

`@aaub-software/dsh-eslint-security-sast` is a Cordis bundle that exposes the
model-facing `eslint_security_scan` tool in
[DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness). It scans
JavaScript and TypeScript source with the recommended rules from
`eslint-plugin-security`, then returns bounded, structured security hotspots for
the agent to review in source context.

This tool is a fast syntax- and AST-based security scanner. A rule match is a
review candidate, not a confirmed vulnerability. The agent should read the
surrounding code and trace relevant inputs and execution paths before reporting
a finding as exploitable.

### Runtime

- Node.js 24 or newer
- ESLint 10.10.0
- eslint-plugin-security 4.0.1
- @typescript-eslint/parser 8.69.0

The runtime is delivered as ordinary npm dependencies. It does not require a
separate ESLint installation, Python runtime, or external scanner executable.

### Install

Install the prebuilt bundle into the DeepSeek Harness profile you use, for
example `web`:

```powershell
dsh plugin --profile web add @aaub-software/dsh-eslint-security-sast
```

Restart that profile after installation. The agent will then see a tool named
`eslint_security_scan`.

### Supported source files

The built-in scanner configuration covers:

- JavaScript: `.js`, `.mjs`, `.cjs`, `.jsx`
- TypeScript: `.ts`, `.mts`, `.cts`, `.tsx`

`.git` and `node_modules` directories are ignored. The scanner uses the
recommended `eslint-plugin-security` rule set, including checks for dynamic
evaluation, child processes, non-literal filesystem and module operations,
unsafe regular expressions, object injection, insecure randomness, timing
comparisons, legacy Buffer APIs, and bidirectional control characters.

### Tool behavior

`eslint_security_scan` accepts one optional parameter:

| Parameter | Required | Description |
| --- | --- | --- |
| `paths` | No | Workspace-relative JavaScript or TypeScript files and directories. Defaults to the workspace root. |

Absolute paths, paths that escape the workspace, and symlinks resolving outside
the workspace are rejected.

Results contain:

- ESLint and security-plugin versions
- requested scan targets and analyzed file count
- exact rule ids, messages, paths, and source locations
- parse or lint diagnostics kept separate from security hotspots
- total and returned finding counts with an explicit truncation flag
- scan duration and `completed` or `partial` status

A `partial` result means at least one source file could not be analyzed cleanly.
It does not turn diagnostics into vulnerabilities, and findings from other files
remain available for review.

### Scanner-owned configuration

The plugin deliberately does not load `eslint.config.js`, legacy ESLint config,
or suppression files from the target repository. ESLint configuration files are
executable JavaScript; loading an untrusted repository's configuration could run
its code in the scanner process.

The scanner also disables:

- inline `eslint-disable` configuration comments
- bulk suppressions
- ESLint cache files
- autofix
- worker-thread concurrency

These choices make scans reproducible and prevent the scanned repository from
hiding security rules or changing scanner behavior.

### TypeScript analysis boundary

TypeScript files are parsed without `parserOptions.project`, project services,
or the target repository's `tsconfig.json`. The current security rules operate
on syntax and AST structure and do not require type information.

This keeps the scan independent of whether the project compiles and avoids
loading project-specific TypeScript configuration. It also means this plugin is
not a type-aware, cross-file data-flow engine. Semgrep and model-led source
review complement this scanner when deeper reachability or business-logic
reasoning is required.

### Sandbox and resource controls

- The runner executes in a separate Node.js process through Harness subprocess
  services.
- It inherits the session's current sandbox policy and does not request wider
  permissions.
- Harness cancellation and a five-minute default timeout terminate the process
  tree with a two-second grace period.
- Captured stdout is limited to 16 MiB and stderr to 1 MiB.
- Model-facing findings are capped at 200 by default and sorted
  deterministically.
- Runner JSON is validated before it reaches the model-facing result.
- Target project configuration, plugins, source code, and package scripts are
  not executed by the scanner.

The scanner requires no network access during normal execution because ESLint,
the parser, and the security rules are installed with the npm bundle.

### Configuration

The shipped bundle layer uses:

```yaml
- insert:
    - id: eslint-security-sast
      name: '@aaub-software/dsh-eslint-security-sast'
      config:
        timeoutMs: 300000
        maxFindings: 200
```

`timeoutMs` accepts 1 through 3,600,000 milliseconds. `maxFindings` accepts 1
through 10,000. Rule selection and the protections around project configuration,
suppressions, cache, and autofix are intentionally not configurable.

### Development

```powershell
pnpm install
pnpm typecheck
pnpm build
```

The repository is a pnpm workspace. The published DSH bundle is under
`packages/bundle`.

### License

Project code is released under the MIT License. ESLint and its transitive npm
dependencies retain their respective upstream licenses.

## 简体中文

`@aaub-software/dsh-eslint-security-sast` 是一个面向
[DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 的 Cordis 组合包，
向模型注册 `eslint_security_scan` 工具。它使用 `eslint-plugin-security` 推荐规则扫描
JavaScript 和 TypeScript 源码，并返回有数量限制的结构化安全热点，供 Agent 结合源码
上下文继续复核。

该工具是快速的语法与 AST 安全扫描器。规则命中只是待审查候选项，不是已确认漏洞。
Agent 应读取周围代码并追踪相关输入及执行路径，再判断问题是否真实可利用。

### 运行时

- Node.js 24 或更高版本
- ESLint 10.10.0
- eslint-plugin-security 4.0.1
- @typescript-eslint/parser 8.69.0

运行时作为普通 npm 依赖交付，不需要用户单独安装 ESLint、Python 或外部扫描器程序。

### 安装

将预构建 Bundle 安装到实际使用的 DeepSeek Harness profile，例如 `web`：

```powershell
dsh plugin --profile web add @aaub-software/dsh-eslint-security-sast
```

安装后重启该 profile，模型即可看到 `eslint_security_scan` 工具。

### 支持的源码

内置扫描配置覆盖：

- JavaScript：`.js`、`.mjs`、`.cjs`、`.jsx`
- TypeScript：`.ts`、`.mts`、`.cts`、`.tsx`

扫描时忽略 `.git` 和 `node_modules`。插件启用 `eslint-plugin-security` 推荐规则，覆盖
动态执行、子进程、非字面量文件与模块操作、不安全正则、对象注入、不安全随机数、
时序比较、旧式 Buffer API 和双向文本控制字符等安全热点。

### 工具行为

`eslint_security_scan` 接受一个可选参数：

| 参数 | 是否必需 | 说明 |
| --- | --- | --- |
| `paths` | 否 | 工作区相对 JavaScript 或 TypeScript 文件和目录；默认扫描工作区根目录。 |

插件会拒绝绝对路径、逃逸工作区的路径，以及最终解析到工作区外的符号链接。

结果包含：

- ESLint 和安全插件版本
- 请求的扫描目标与已分析文件数量
- 规则 ID、消息、路径和精确源码位置
- 与安全热点分开报告的解析或 lint 诊断
- 发现总数、返回数量和明确的截断标志
- 扫描耗时及 `completed` 或 `partial` 状态

`partial` 表示至少一个源码文件未能被完整分析。诊断不会被当作漏洞，其他成功分析文件
中的发现仍可继续复核。

### 扫描器自有配置

插件不会加载目标仓库中的 `eslint.config.js`、旧式 ESLint 配置或 suppression 文件。
ESLint 配置文件是可执行 JavaScript；加载不可信仓库的配置可能在扫描进程中执行其中的
代码。

扫描器同时关闭：

- 源码中的 `eslint-disable` 配置注释
- 批量 suppression
- ESLint cache 文件
- autofix
- worker thread 并发

这些约束使扫描结果可复现，并阻止被扫描仓库隐藏安全规则或改变扫描行为。

### TypeScript 分析边界

TypeScript 文件不会启用 `parserOptions.project`、project service，也不会读取目标仓库的
`tsconfig.json`。当前安全规则基于语法和 AST 结构，不依赖类型信息。

这样扫描不依赖项目能否成功编译，也不会加载项目特有的 TypeScript 配置。相应地，该
插件不是类型感知的跨文件数据流引擎。需要更深层的可达性或业务逻辑推理时，应结合
Semgrep 和模型主动源码审阅。

### 沙箱与资源控制

- runner 通过 Harness 子进程服务在独立 Node.js 进程内运行。
- 继承会话当前沙箱策略，不主动请求扩大权限。
- 支持 Harness 取消和默认五分钟超时，并以两秒宽限期终止进程树。
- stdout 最大 16 MiB，stderr 最大 1 MiB。
- 默认最多向模型返回 200 条发现，并按确定顺序排列。
- runner JSON 经过严格校验后才进入模型工具结果。
- 不执行目标项目配置、插件、源码或 package scripts。

正常扫描不需要网络访问，因为 ESLint、解析器和安全规则都随 npm Bundle 安装。

### 配置

Bundle 默认配置为：

```yaml
- insert:
    - id: eslint-security-sast
      name: '@aaub-software/dsh-eslint-security-sast'
      config:
        timeoutMs: 300000
        maxFindings: 200
```

`timeoutMs` 范围为 1 至 3,600,000 毫秒，`maxFindings` 范围为 1 至 10,000。规则选择、
目标项目配置、suppression、cache 和 autofix 等安全约束不开放配置。

### 开发

```powershell
pnpm install
pnpm typecheck
pnpm build
```

仓库使用 pnpm workspace，发布的 DSH Bundle 位于 `packages/bundle`。

### 许可证

项目代码使用 MIT 许可证。ESLint 及其传递 npm 依赖继续适用各自的上游许可证。
