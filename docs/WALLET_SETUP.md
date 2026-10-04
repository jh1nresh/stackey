# Wallet setup and recovery UI

Local candidate, pending independent security review. This standalone entry point keeps setup separate from the existing wallet preview and never replaces an existing setup directory.

## Run

From the repository:

```sh
npm run build
node dist/src/wallet-setup.js --dir .stackey/new-personal-wallet --port 45823
```

Open the returned `setup_url` yourself. Its fragment is an Owner capability; do not send it to an agent. The setup session lasts 30 minutes. Use a **new** `--dir` for each setup attempt; existing directories are rejected. The parent must be a private directory owned by the current user; `.stackey` is created with mode 0700 if absent.

Create flow: acknowledge recovery requirements → create draft → explicitly reveal the 24-word phrase → write it down → enter three randomly selected words → confirm → download an encrypted backup → open the new wallet. The phrase is hidden after 60 seconds, on window blur and on exit. Unconfirmed drafts expire after ten minutes; cancel or process shutdown removes their temporary recovery files. Refreshing the launch URL resumes a still-valid draft without exposing the phrase in the state response.

Restore flow: enter all 24 words → select an encrypted Stackey Vault JSON backup (maximum 4 MiB) → confirm restoration into a new directory. The existing Vault code checks the phrase, format and authenticated ciphertext before committing the restored directory. A new vault instance ID is generated. No Node, pairing, session or agent grant is restored.

After completion, **Open wallet** starts a new local Node and an unlocked Owner session on available loopback ports, then opens the existing wallet UI. It does not create demo data or grant any agent access. The setup process owns these listeners; keep it running while using that wallet. Ctrl+C stops its listeners and locks its Vault without deleting saved wallet files.

## Saved material and subsequent unlock

The new directory contains `wallet/vault/vault.json` (encrypted), `wallet/recovery.json` (plaintext recovery material, mode 0600), and, after opening, `wallet/node/`.

The recovery file is retained for compatibility with the current CLI unlock workflow. File permissions are not isolation against agents with arbitrary shell access as the same OS user. The UI discloses this before creation. Keep this directory away from such agents and keep your offline phrase separate from exported backups. This candidate does not add Keychain, a daily unlock password, or hardware-backed isolation.

A phrase alone does not recover imported passwords. Keep encrypted backups current after adding or changing credentials. The setup backup button returns the current encrypted Vault file and never returns the plaintext recovery file.

To reopen a completed wallet after the setup process exits, in one terminal:

```sh
node dist/src/cli.js vault unlock --vault-dir .stackey/new-personal-wallet/wallet/vault \
  --recovery-file .stackey/new-personal-wallet/wallet/recovery.json \
  --data-dir .stackey/new-personal-wallet/wallet/node --ttl 900
```

In another terminal (the Node must have been initialized by **Open wallet**):

```sh
node dist/src/cli.js node owner-init --vault-dir .stackey/new-personal-wallet/wallet/vault \
  --data-dir .stackey/new-personal-wallet/wallet/node
node dist/src/cli.js wallet start --vault-dir .stackey/new-personal-wallet/wallet/vault \
  --data-dir .stackey/new-personal-wallet/wallet/node
```

If setup completed but **Open wallet** was never pressed, first initialize that new Node using `node init --data-dir .stackey/new-personal-wallet/wallet/node`, then run the commands above. Do not initialize over an existing Node.

## Verification

`npm run typecheck` and `node --test dist/test/wallet-setup.test.js` after building. Tests use disposable fixtures and cover positive create/restore/open paths, confirmation challenges, secret-free status/assets, authorization and origin checks, existing destination preservation, duplicate finalization, backup tampering, draft cleanup, expiry and stalled uploads.

The UI was checked at desktop and mobile widths. Secret entry/confirmation remains an Owner action; no real user recovery phrase was read or entered during implementation.
