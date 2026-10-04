# Cloud Agent demo

This candidate supports a cloud CLI connecting to a local Node through a temporary HTTPS tunnel. Orders are synthetic. This bundled demo CLI supports synthetic order reads and reports only; it does not expose payment, account login, credential creation or credential values. Existing provider adapters remain available separately through the main CLI. Independent security review is still pending.

## Owner

Build with `npm run build`. Unlock/bind the Vault using the existing wallet setup. Start the wallet locally, then forward **only its Agent port** to a tunnel. Never forward the Owner UI port or Unix socket.

```sh
node dist/src/cli.js wallet start --node-port 60687 --port 60688
cloudflared tunnel --url http://127.0.0.1:60687 --no-autoupdate
```

Once the public HTTPS origin is known, configure it through authenticated same-origin `POST /api/remote` with `{ "endpoint": "https://your-agent-host", "confirmed": true }`. Configure this for each new temporary tunnel; no demo hostname is committed. For a stable hostname, pass `--public-endpoint https://your-agent-host` to `wallet start` or `node start`. Restarting without that option returns to local invitations.

Open the private wallet launch URL locally. Click **Invite agent** and paste its command into the cloud Agent. The command downloads the bundled Agent CLI and dependencies using the live invitation, chooses a fresh private state directory, and connects. Node 22.18+ and curl/tar are required. The single-use invitation expires in five minutes; generate a fresh one when needed. Downloading does not consume it, pairing does.

Connecting requests approval; it grants no access. Match the fingerprint in the wallet and approve **demo.orders.read** for **15 minutes**. State is attached to the execution environment; bots sharing a computer/state directory are not isolated identities.

## Agent value demonstration

After Owner approval, run the report command shown in the invitation:

```sh
node stackey-agent/src/cloud-agent.js report --from 2026-09-26 --to 2026-10-02 --state-dir .your-agent-state
```

It reads through the actual signed, proof-bound session and prints a Markdown daily report. Paid revenue is separated by currency; failed payments are excluded. The fixture has 21 orders, seven failures (33.3%), one failed USD 12 payment per day, and highest revenue on October 2 (USD 16, TWD 360). The demo alert threshold is 20%; gateway investigation is a suggestion, not a confirmed cause.

In the wallet, revoke the Agent grant and run the same command again. The new read must return `grant_revoked` with exit code 3. Existing reports/data already read cannot be recalled or erased by revocation. Expiry and Vault locking also refuse new access.

For the narration: “A conventional integration often gives the agent a service credential. Stackey gives this agent a narrow, time-limited read grant; the owner keeps the Vault credentials and controls future access.” Other systems can also support scoped tokens; do not claim that every alternative requires a full secret.

Stop the tunnel after the demo. This is a temporary development endpoint, not a production deployment. The implementation-session test tunnel was authorized for 30 minutes; production hosting and further tunnels require separate scoped authority.

## Transport boundaries

- Canonical HTTPS remote DNS origins; reject credentials, paths, queries and fragments.
- Resolve once, reject private/reserved addresses, pin the selected public address, retain TLS hostname/certificate checks, refuse redirects, bound response size and timeout.
- Node trusts only its configured local/public Host; forwarded headers do not define proof origins.
- Signed invitations pin Node key and origin. Signed Agent receipts and DPoP bind requests to the correct key, method, URL, body and nonce. Existing local clients remain valid.
- Package download requires an unexpired, unconsumed invitation issued by this Node. Package includes only Agent runtime modules and dependencies, no Owner CLI, Vault implementation, wallet UI, identity files, recovery material or local data.
- Public listener serves no Owner/Vault endpoints. Owner approvals, revocation, reveals and remote-origin configuration remain authenticated localhost operations.
