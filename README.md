# Stackey

**Connect your services once. Give agents the access they need.**

Stackey is a resource wallet managed by people and used by agents. Users retain control of service connections, passwords, and private keys. When adding an agent, a single pairing and authorization flow gives it access to connected resources to complete tasks.

## Current Status

The local CLI supports pairing, Owner approval, short-lived DPoP sessions, capability discovery, read-only access to synthetic orders, operation queries, and revocation. Orders currently come from the local `local_synthetic` source. The CLI also supports a recovery-phrase-based vault, encrypted credentials, multiple wallets, backup and recovery, and locking. Read-only Supabase orders, Vercel AI Gateway generation, and read-only Stripe test payments are implemented and have passed real sandbox testing. The Link/MPP protocol and local tests are implemented; real MPP collection still awaits a Stripe sandbox profile, Link approval, and endpoint deployment. The wallet UI is developed separately. The repository's initial default branch is `spec`.

**The single source of truth for the current product specification is [docs/SPEC.md](docs/SPEC.md).** Most of the full product API and data model remain to be implemented. For the currently runnable functionality, see the [pairing format](docs/CLI_PAIRING.md) and [approval, execution, and revocation guide](docs/CLI_AUTHORIZATION.md).

## 60-second quickstart

Requires macOS or Linux and Node.js 22.18 or later. Local only — Stackey stores credentials and hands them to allowlisted agents. It never logs in, opens a browser, or keeps a website session.

```bash
npm ci --ignore-scripts
npm run build
node dist/src/cli.js                 # or: node dist/src/cli.js init
node dist/src/cli.js add GITHUB_TOKEN
# hidden prompt; or pass --secret-file with {"value":"..."}
node dist/src/cli.js connect
# prints one line: stackey connect ABC123
```

Paste that line into the agent (or run it in the agent’s environment):

```bash
node dist/src/cli.js connect ABC123 --state-dir .stackey/agent
node dist/src/cli.js credential get --state-dir .stackey/agent
```

On the owner side, approve the one-use request (no grant IDs):

```bash
node dist/src/cli.js approve
# Agent Codex wants GITHUB_TOKEN once — approve? [y/N]
node dist/src/cli.js status
```

`status` lists credentials, connected agents, pending requests, recent denials, and the backup reminder. The recovery phrase is saved privately; run `stackey backup` when you can — you do not write it down up front.

Allowlisting, one-use grants, TTL, revocation, audit, and encryption at rest stay in force. Advanced commands (`node invite`, `node approve --replace-grant`, fingerprints) keep working for scripts that already use them.

## 60 秒快速開始

需要 macOS 或 Linux，以及 Node.js 22.18 以上。僅限本機。Stackey 只保管憑證並交給允許清單內的 agent；不會代為登入、開啟瀏覽器或保存網站工作階段。

```bash
npm ci --ignore-scripts
npm run build
node dist/src/cli.js                 # 或 node dist/src/cli.js init
node dist/src/cli.js add GITHUB_TOKEN
# 隱藏輸入；或用 --secret-file，內容為 {"value":"..."}
node dist/src/cli.js connect
# 印出一行：stackey connect ABC123
```

把這一行貼給 agent（或在 agent 環境執行）：

```bash
node dist/src/cli.js connect ABC123 --state-dir .stackey/agent
node dist/src/cli.js credential get --state-dir .stackey/agent
```

Owner 核准一次性取用（不必查 Grant ID）：

```bash
node dist/src/cli.js approve
# Agent Codex wants GITHUB_TOKEN once — approve? [y/N]
node dist/src/cli.js status
```

`status` 會用白話列出憑證、已連線 agent、待核准請求、最近拒絕，以及備份提醒。助記詞先存在本機私有檔，之後再跑 `stackey backup`，一開始不必抄寫。

允許清單、一次性 Grant、TTL、撤銷、稽核與靜態加密仍然有效。進階命令（`node invite`、`node approve --replace-grant`、指紋）維持可用。

For API setup for the three services, agent execution, and the sandbox test evidence, see the [CLI service integration guide](docs/CLI_INTEGRATIONS.md).

For the local vault and seed-backed Owner, see the [CLI vault guide](docs/CLI_VAULT.md). The legacy pairing demo continues to use its existing Owner and does not migrate automatically.

For agent password/API-key access, use the [credential handoff walkthrough](docs/CLI_VAULT.md#讓-agent-取用同一筆帳密每次-owner-核准不用重新配對). Store a credential once, pair each agent once, and approve each retrieval. The Owner can replace a spent or expired `credential.get` grant on the same pairing; each grant still permits only one retrieval within 60–300 seconds. This hands over the credential; it does not automate website login.

## Local Setup: Step One

Requires macOS or Linux and Node.js 22.18 or later. The CLI exits with a clear error on older Node versions and does not print Node's experimental SQLite warning.

```bash
npm ci --ignore-scripts
npm run build
npm run stackey -- node init
npm run stackey -- node start
```

Keep the Node running in the foreground. Open another terminal in the same repository and run:

```bash
npm run stackey -- node invite --out .stackey/invitation.json --ttl 300
npm run stackey -- connect --invite-file .stackey/invitation.json --name "Local Agent"
npm run stackey -- status
npm run stackey -- node pairings
```

The initial connection returns a pairing ID awaiting approval and a public key fingerprint, with an empty `granted_actions` list. Continue with the [step-two guide](docs/CLI_AUTHORIZATION.md) for approval and execution. Press Ctrl+C to stop the Node. The `status` command reads the local connection receipt; it does not query live service permissions. Use a separate `--state-dir` for each runtime environment. Directories owned by the same OS user do not provide strong isolation.

`node pairings` returns up to 200 entries per page. If `data.next_cursor` in the JSON response is not `null`, run `node pairings --after <next_cursor>` to fetch the next page, continuing until it is `null`. Do not treat a truncated list as a complete result.

For raw CLI JSON output without npm's script headers, use `node dist/src/cli.js ...`. Invitation files contain single-use connection material, default to mode 0600, and cannot be overwritten. Do not commit them to git. At this stage, only `http://127.0.0.1:<port>` is supported; cloud access from the official Grok Bot has not been verified.

## Verification

```bash
npm run typecheck
npm test
```

Tests cover Owner approval, isolation between two agents, order correctness, DPoP sessions and revocation, operations and pagination, real CLI and HTTP connections, concurrent use of single-use invitations and replay after restart, invalid signatures, invitation/proof binding, expiration, Node receipt verification, redirect rejection, request limits, and ensuring private keys do not appear in CLI results.

## Product Interfaces

- **Wallet UI**: People connect services, approve agents, manage grants, view activity, and revoke access.
- **CLI**: Agents discover capabilities, execute operations, wait for approval, and retrieve results. The runtime manages identity keys.
- **Vault Node**: A user-controlled layer for storing secrets, checking permissions, and executing service operations.

## Technology Responsibilities

| Technology | Planned Role |
| --- | --- |
| Vercel + Next.js | Wallet dashboard, control-plane API, and MPP paid endpoints |
| Vercel AI Gateway + AI SDK | Controlled model-call adapter with optional paid analysis capabilities |
| Supabase | Dashboard authentication, administration metadata, activity sync, encrypted backups, and actual demo orders |
| Stripe Link + MPP | User payment sources, payment approval, and HTTP 402 paid-resource flows |
| TypeScript CLI + Vault Node | Agent pairing, capability discovery, authorized execution, secret usage, and result retrieval |

## First Demo

Create a bot in the official Grok Bot and have it request access through the Stackey CLI. The user approves read-only access to test orders in the wallet. The bot retrieves actual synthetic records from Supabase and produces a summary. Afterward, revoke access and verify that subsequent requests are rejected.

The primary demo verifies connection and task completion. Stripe MPP sandbox and AI Gateway form a second acceptance stage within the same architecture. A fake balance displayed in the UI is not a substitute for payment integration.

## Development Sequence

1. Finalize identity, authorization, encryption, and API contracts.
2. Build the Vault Node, CLI, and read-only Supabase adapter.
3. Build the trusted local wallet administration UI and Vercel dashboard.
4. Verify real Grok Bot tasks and access revocation.
5. Add Link/MPP sandbox support and an AI Gateway analysis endpoint.

Record implementation evidence against the [specification's acceptance matrix](docs/SPEC.md#13-驗收矩陣). Deployment, service provisioning, payments, and use of production data are separate follow-up scopes.
