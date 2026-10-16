# Multi-user vaults (design)

Date: 2026-10-16. Status: design only. This note records how Stackey stays a **1Password for agents** when more than one Owner or a hosted Node is in play. It does not authorize a deploy, a shared vault, a login runner, or a browser session store.

Stackey stores credentials and hands a secret to an agent only after a per-agent grant. It does not log in, drive a browser, or hold website sessions as a product surface. Related contracts: [SPEC.md](SPEC.md), [CLI_VAULT.md](CLI_VAULT.md), [CLI_AUTHORIZATION.md](CLI_AUTHORIZATION.md).

## 1. Per-user vaults

Each Owner has their own mnemonic-backed vault. Ciphertext, recovery phrase, Keychain item, and optional iCloud blob are all per-user. There is no shared key, no org-wide unwrap, and no “admin can decrypt this wallet.”

- **Local (default):** vault files live on the Owner’s machine. Unlock is local (recovery file or macOS Keychain / Touch ID). The Node binds to that vault for the unlock TTL.
- **Isolation:** wallets, credentials, and connections inside a vault never mix with another Owner’s vault. Binding a different vault to a Node invalidates leftover grants.
- **Recovery:** 24-word BIP39 stays the Owner’s; a hosted operator must not see it. Restoring a vault creates a new directory, not an in-place merge.

A company with several people is several vaults, not one vault with several users.

## 2. Per-agent scoped grants

Agents never read the vault. They receive a secret only through `credential.get`, and only when every gate below holds:

| Gate | Rule |
| --- | --- |
| Pairing | The agent principal is the pairing that the Owner approved. A second agent needs its own pairing and grant. |
| Action | Grant `actions` is exactly `["credential.get"]`. |
| Connection | Grant is pinned to one `credential` connection (one credential id + one exact `https://host` origin). |
| Allowlist | `credential_origins` is an exact-origin list. No wildcards, paths, ports, or redirects. Missing origin is `origin_not_allowed` and does not consume the grant. |
| Budget | `max_calls = 1`. A second successful or uncertain operation is `budget_exceeded`. |
| Lifetime | Grant TTL is 60–300 seconds. |
| Revocation | `grant.revoke` or credential remove/revoke stops further gets immediately. |
| Audit | Append-only `audit_log` records credential, agent, origin, time, and result (`issued` / `refused` / …). No secret column. |

The Node persists `{issued:true}` for the operation. The secret exists in process memory until the first completed poll, then is dropped. Replay returns `{issued:true}` with no value. Errors and logs go through the public error table and the secret scrubber.

`stackey credential get` is the agent CLI: it polls that one-shot operation and prints `{value}` only. Everything else on stdout is an error envelope without the secret.

Local implementation update (2026-10-16): after each use, the Owner may explicitly approve the same pairing and credential connection again with `node approve ... --replace-grant CURRENT_GRANT_ID`. Replacement atomically revokes/supersedes the previous grant and creates a new single-use grant; historical grants and operations remain. Stale or cross-pairing/connection replacements fail. The agent identity and pairing persist, but access never renews automatically. This also permits an explicit Owner reapproval after expiry or revocation. Hosted/multi-user architecture remains design-only.

## 3. Hosted option (not this milestone)

A hosted Stackey would keep the same grant model. It would not become a login proxy.

- **Still per-user:** each Owner’s vault is encrypted under their mnemonic (or a wrap key they control). The host stores ciphertext and runs the Node; it must not be able to unwrap vaults at rest.
- **Still per-agent:** pairing, DPoP, exact-origin allowlist, `max_calls=1`, short TTL, revoke, and audit stay the authorization plane. Hosting does not widen a grant.
- **Unlock:** the Owner unlocks (device, Keychain, or recovery) so the host process can serve `credential.get` for the unlock window. When unlock expires, the Node fails closed (`node_locked`).
- **Out of scope here:** no multi-tenant control plane, no IdP, no deploy, no shared “org vault,” no remote Playwright, no session jars as a product.

Until a hosted design is implemented, the only supported topology is one Owner, one local vault, one loopback Node, and short-lived grants to paired agents.
