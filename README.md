# Stackey

**Connect your services once. Give agents the access they need.**

Stackey is a resource wallet managed by people and used by agents. Users retain control of service connections, passwords, and private keys. When adding an agent, a single pairing and authorization flow gives it access to connected resources to complete tasks.

## Current Status

The local CLI supports pairing, Owner approval, short-lived DPoP sessions, capability discovery, read-only access to synthetic orders, operation queries, and revocation. Orders currently come from the local `local_synthetic` source. The CLI also supports a recovery-phrase-based vault, encrypted credentials, multiple wallets, backup and recovery, and locking. Supabase, Vercel, and Stripe service operations and the wallet UI still await acceptance testing. The repository's initial default branch is `spec`.

**The single source of truth for the current product specification is [docs/SPEC.md](docs/SPEC.md).** Most of the full product API and data model remain to be implemented. For the currently runnable functionality, see the [pairing format](docs/CLI_PAIRING.md) and [approval, execution, and revocation guide](docs/CLI_AUTHORIZATION.md).

For the local vault and seed-backed Owner, see the [CLI vault guide](docs/CLI_VAULT.md). The legacy pairing demo continues to use its existing Owner and does not migrate automatically.

## Local Setup: Step One

Requires macOS or Linux and Node.js 22.18 or later. Stackey uses Node's native SQLite support; Node 22 may print an experimental warning to stderr.

```bash
npm ci
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
