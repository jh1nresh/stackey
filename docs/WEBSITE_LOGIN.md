# Website login grants (design)

Date: 2026-10-04. Status: design plus a fail-closed local slice. This document is the contract for storing a website login in the mnemonic-backed vault and letting a paired agent request a **daemon-side** login after Owner approval. It does not authorize real browser automation, live provider calls, or handing a password to an agent.

Related contracts: [SPEC.md](SPEC.md), [CLI_VAULT.md](CLI_VAULT.md), [CLI_AUTHORIZATION.md](CLI_AUTHORIZATION.md). Reachability remains `http://127.0.0.1:<port>` only. Cloud access from an official Grok Bot is still unverified.

## 1. Goal

The Owner stores a website login (for example the Privy dashboard) in the Stackey vault. A paired agent, such as a Grok Bot, may request a one-time use of that login after explicit approval. The agent must never receive the password, never keep it, and never see it in logs. Use is scoped to that agent, short-lived, single-use, and auditable through the existing approval / DPoP session / revocation path.

This is **not** a generic “log in anywhere” proxy. SPEC already says passwords may be stored as custody items; automatic login needs a fixed adapter and is not promised for arbitrary sites.

## 2. Recommendation

**By 12 October 2026 (Colosseum): ship custody + grant + mock daemon executor only. Do not attempt a real login to `https://dashboard.privy.io` or any other live site.**

| Option | What the agent gets | Password leaves vault process? | Fits Privy-class sites? | Oct 12 |
| --- | --- | --- | --- | --- |
| **A. Daemon-side executor (this slice)** | Sanitized outcome only (`authenticated` or `human_required`) | No. Decrypted in the unlocked vault daemon, injected into an executor interface, never returned | Only after a per-site executor exists, and only for password-only forms | Mock only |
| **B. Short-lived session cookie handoff** | A website cookie or storage blob | Cookie *is* the account. Blast radius is full dashboard access, often longer than the grant TTL | High risk: replay, XSS, extension theft, agent persistence | Do not ship |
| **C. Human-in-the-loop handoff** | A wait state; Owner finishes MFA/passkey/captcha in their own browser | No | **Best default for Privy, bank, and cloud consoles** | Document; not implemented |
| **D. Official API key / OAuth adapter** | Bounded business result, as with Supabase / AI Gateway / Stripe today | No | Prefer this whenever the site has one | Already the supported pattern |

Use **A** as the control-plane primitive (store, approve, revoke, single-use, audit). Use **C** for any site that shows email OTP, passkeys, captcha, or device confirmation. Use **D** instead of a password whenever the vendor offers a scoped API credential. Do not implement **B**.

For the founder’s Grok Bot demo, a Privy **API credential or Owner-completed browser session** is safer and more likely to work than teaching an agent to type a dashboard password.

## 3. Architecture

```mermaid
sequenceDiagram
    participant Owner
    participant Vault as Vault daemon
    participant Node as Loopback Node
    participant Agent
    participant Exec as Login executor

    Owner->>Vault: credential.import website_login
    Owner->>Vault: connection.add website (pinned HTTPS origin)
    Agent->>Node: pair (no access yet)
    Owner->>Vault: grant.approve website.session.login max_calls=1
    Agent->>Node: DPoP session + POST /v1/operations
    Node->>Vault: provider.execute (grant, no secret)
    Vault->>Vault: verify grant, decrypt password
    Vault->>Exec: inject username/password (in-process)
    Exec-->>Vault: sanitized outcome only
    Vault-->>Node: { outcome, origin }
    Node-->>Agent: operation result (never password, never cookie)
    Owner->>Vault: grant.revoke (invalidates sessions)
```

Responsibilities stay where they already are:

- **Vault daemon**: only process that decrypts `website_login`. Owner socket, not the agent HTTP API.
- **Node**: pairing, DPoP, grant version, call budget, operation durability. Never reads the password.
- **Agent CLI**: capability discovery and operation polling. Stdout is a JSON envelope. No secret export.
- **Executor**: injectable function. Production default **refuses**. Tests inject a mock. No Playwright, no live navigation.

### 3.1 Where the credential is decrypted

Only inside the unlocked vault daemon, after `requireGrant` + `verifyGrant` + bound-session checks, immediately before the executor call. The Node’s `provider.execute` IPC carries `grant_id`, `principal`, `action`, `params`, and `operation_id`. It does not carry the password. Credential list, connection list, grant records, events, and operation rows store metadata only.

Locking or unlock expiry zeroes vault key material using the existing `close()` path. JS strings cannot be guaranteed wiped; this is the same residual-memory limit as other vault secrets.

### 3.2 How login is performed

This slice uses **option A**: a daemon-side executor interface.

```ts
type WebsiteLoginExecutor = (input: {
  origin: string;   // pinned from the connection, not from the agent
  username: string;
  password: string;
}) => Promise<{ state: 'completed' | 'human_required'; reason?: WebsiteHumanReason }>;
```

The executor may use the password. It must not return it. `executeWebsiteLogin` rebuilds the agent-visible result from a whitelist (`source`, `origin`, `outcome`, optional `reason`). Extra fields, cookies, headers, HTML, and DOM dumps are dropped. If the rebuilt JSON still contains the password, execution fails closed.

A future real executor (out of scope) would:

1. Open an isolated browser profile owned by the daemon, never by the agent.
2. Navigate only to the pinned origin’s login entry (per-site adapter, not an agent-supplied URL).
3. Fill the form and submit.
4. Treat cookies as daemon memory, wipe them when the operation ends or the grant is revoked.
5. Return only the sanitized outcome.

It would **not** give the agent a cookie jar, CDP port, or screenshot of a filled password field.

### 3.3 Session cookie handling and blast radius

| Material | Who may hold it | Lifetime | Blast radius if stolen |
| --- | --- | --- | --- |
| Vault `website_login` password | Unlocked vault process only | Until Owner removes it or the vault is locked | Full account, including new sessions, recovery, and often billing |
| Website session cookie | Future daemon executor only; **never the agent** | Operation TTL, then wipe | Full logged-in account until the site expires or rotates the cookie. Often survives password grant expiry |
| Stackey DPoP access token | Agent memory; not printed | `min(60s, grant.expires_at)` | Stackey operations already granted, not the website password |
| Agent-visible login result | Agent, Node operation row, events | Durable | Origin + outcome only. Must not be enough to replay the site login |

Handing a cookie to the agent (option B) turns a single-use password grant into a portable account token. Cookies are replayable, often `Secure` but present in the browser profile, and may outlive both the Stackey grant and the DPoP session. HttpOnly reduces page-script theft; it does not stop a compromised agent that received the cookie, a malicious extension, or a copied profile.

This slice therefore **does not create, persist, or return cookies**.

### 3.4 What still needs the human

The executor must stop and return `human_required` when the page is not a plain username/password success. Fixed reasons:

- `email_otp` — email or SMS one-time code
- `passkey` — WebAuthn / security key / platform authenticator
- `captcha` — bot challenge
- `device_confirmation` — “approve this login” on another device or app

The agent must not solve these. It should tell the Owner. A later HITL flow (option C) can pause the operation, let the Owner complete the challenge in a trusted browser, and resume with a daemon-held session. Solving OTP from agent mail, or clicking passkeys from an untrusted profile, is out of scope and usually a policy violation of the target site.

Privy dashboard, Vercel, Stripe, Google, and GitHub routinely show at least one of the above. A password-only mock will not log into them.

### 3.5 Single-use and TTL

Reuse existing grant fields. No new token type.

- **Grant TTL**: existing 60–900 seconds. Owner picks the window. Session tokens remain `min(60s, grant.expires_at)`.
- **`max_calls`**: forced to `1` for `website.session.login`. A second *successful or uncertain* operation ID is `budget_exceeded`.
- **`max_amount_minor`**: forced to `0` (`--max-amount-minor 0`). This is not a payment.
- **Same operation ID**: existing replay. Returns the stored sanitized result. Does not call the executor again and does not decrypt the password again for a new login.
- **Default executor refuse**: only the built-in `refuseWebsiteLogin` function is a non-consuming refusal. It always becomes a brand-new `executor_unavailable` / `permission_denied` (fixed message, never the executor's own text).
- **Executor exception**: any injected executor throw, including a spoofed `executor_unavailable` whose message contains the password, becomes `executor_failed`. That outcome is `result_unknown` and **does** consume the call.
- **Orphaned `executing` row**: existing `result_unknown` + reservation retained. No automatic retry (a retry would be a second login).
- **Revoke / lock / expiry**: existing fail-closed checks before and after the executor. In-flight results are not delivered to a revoked agent.

A “single-use key” in the founder’s wording is this grant + call budget, not a new bearer secret given to the agent.

### 3.6 Audit trail and revocation

Existing objects only:

- `grant_approved` / `grant_revoked` — subject is the principal, object is the grant ID
- `operation_dispatched` / `operation_completed` / `operation_failed` / `operation_result_unknown`
- Grant row: pairing, principal, action, connection, `max_calls`, TTL, version
- Operation row: hashes and sanitized JSON

Events still store kind, subject, object ID, and time. They must never store password, username, cookie, DPoP proof, or access token. Revocation bumps grant version, writes `stackey-revocation+jwt`, and invalidates existing DPoP sessions. It cannot un-type a password already submitted to a real site, and cannot retract a cookie already minted. That is why this slice does not mint cookies and why a real executor must wipe daemon state on revoke.

## 4. Data model (minimal slice)

New vault kinds, same storage format:

| Object | Addition | Notes |
| --- | --- | --- |
| Credential | `kind: website_login` | `value` is the password string. List/import return id, wallet, name, kind only |
| Connection | `provider: website` | `config = { origin, username, credential_id }`. Origin is a fixed HTTPS origin (no path, query, userinfo, port, or IP). List strips `config` |
| Action | `website.session.login` | Empty params. Agent cannot pass a URL |
| Grant | existing scoped grant | `max_calls = 1`, `max_amount_minor = 0`, resource `connection:<id>/website.session.login` |

`password` remains a custody-only kind. A website connection must reference `website_login`, not `password` or `api_key`. That keeps “I stored a note” separate from “I authorized a login adapter”.

## 5. Threat model

Fail closed. Default deny.

| Threat | What happens | Mitigation in this slice | Residual risk |
| --- | --- | --- | --- |
| **Compromised agent** | Agent has shell on the same OS user, or the model is jailbroken | Password never in responses, logs, or agent files. Grant is per pairing and revocable. DPoP binds requests to the agent key | Same-user agents can still read recovery files and the vault socket. SPEC already says 0600 is not Bot isolation |
| **Replayed grant / operation** | Attacker replays HTTP, DPoP, or operation ID | Nonce/jti consumption, body hash, grant version, `max_calls=1`, same-ID replay of sanitized result only | A real site login already performed cannot be undone |
| **Malicious page** | Login URL is attacker-controlled; credential posted off-origin | Agent cannot supply a URL. Origin is pinned at connection add. Default executor does not network | A future executor must pin navigation and reject redirects off origin |
| **Exfiltration through page DOM** | Script on the login page reads the typed password or a new cookie | No real page in this slice. Future executor must not return DOM/HTML and must use an isolated profile | Any real browser fill can be observed by the page itself. That is inherent to password autofill |
| **Log leakage** | Password appears in CLI JSON, Node logs, events, or thrown errors | Whitelisted result; `publicError` strips unknown errors; tests scan responses, DB rows, and stdout | Host telemetry, swap, and core dumps are out of process control |
| **Confused deputy / SSRF** | Executor fetches attacker hosts with the password | HTTPS origin allowlist; no IPs, localhost, userinfo, or ports. Default executor refuses | Per-site adapters still needed before any HTTP client is attached |
| **Owner socket theft** | Malware on the same user talks to the vault socket | Existing Unix socket + bearer session file mode 0600 | Not a cross-user boundary |

## 6. What is feasible by 12 October 2026

Feasible in this repository, locally, with Node 22.18:

- Store `website_login` in the encrypted vault
- Pin a website connection to one HTTPS origin
- Per-agent grant with Owner approval and revoke
- Single-use (`max_calls=1`) DPoP operation that invokes a daemon-side executor
- Mock executor for tests; production default refuses (no live navigation)
- Negative tests: no approval, revoked grant, reused grant, secret-leak scan

Not feasible, and not attempted:

- Real login to Privy or any other live site
- Email OTP, passkeys, captcha, or device-confirmation completion
- Returning or persisting website cookies
- Cloud / HTTPS reachability from Grok Bot
- A general browser tool (“go to any URL and sign in”)
- Claiming the agent can operate a dashboard unattended after one approval

## 7. What remains after this slice

1. Per-site adapters (explicit entry URL, selectors, success signal) — start only with a test/staging site the Owner controls.
2. Isolated browser profile, redirect allowlist, and cookie memory with wipe-on-revoke.
3. HITL continuation for `human_required` (option C), with Owner UI confirmation.
4. Prefer API-key connections for Privy/Vercel/Stripe over passwords.
5. Verified remote Node reachability if a cloud Grok Bot must call in.
6. Stronger runtime isolation than same-OS-user files (already a SPEC limit).

## 8. CLI sketch (local only)

```bash
# Owner: store a fixture login. Use a private JSON file, never a real password in chat.
# {"value":"fixture-only-password"}
stackey credential import --wallet wallet_demo --name "Privy dashboard" \
  --kind website_login --secret-file .stackey/website-secret.json \
  --vault-dir .stackey/vault

# {"origin":"https://dashboard.privy.io","username":"owner@example.com","credential_id":"credential_..."}
stackey connection add --wallet wallet_demo --name Privy \
  --provider website --config-file .stackey/website-config.json \
  --vault-dir .stackey/vault

stackey node approve PAIRING_ID --principal FULL_FINGERPRINT \
  --action website.session.login --connection CONNECTION_ID \
  --wallet wallet_demo --ttl 300 --max-calls 1 --max-amount-minor 0 \
  --vault-dir .stackey/vault --data-dir .stackey/vault-node

# Agent: empty params. Poll the operation. Expect executor_unavailable unless a test mock is injected.
stackey run website.session.login --state-dir .stackey/agents/new-agent
stackey node revoke GRANT_ID --vault-dir .stackey/vault --data-dir .stackey/vault-node
```

Never put a real password, cookie, invite, or Owner URL in command lines, tests, docs, or PRs.

## 9. Decision

Ship the control plane now. Keep the executor fail-closed. Treat dashboard password autofill as a last resort behind HITL, not as the Colosseum demo path. If the founder needs “Grok Bot used Privy once,” the safe October story is: Owner stores the login, approves a single-use grant, the daemon refuses or waits for the human, and the audit log shows approve → attempt → revoke — without the bot ever holding the password.
