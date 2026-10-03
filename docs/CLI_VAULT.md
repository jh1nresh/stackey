# CLI 保險箱、錢包與憑證

此階段完成本機保險箱與 seed-backed Owner；服務 adapter 在後續整合。所有測試只用新建 fixture，既有 `.stackey/node` 和 agent 身分不自動搬移或重新核准。

## 從新目錄開始

不要以新的助記詞取代已固定的舊 Owner。本例刻意使用新的 Node／vault 目錄；舊配對 demo 可照原指南繼續使用。

```bash
npm ci
npm run build
node dist/src/cli.js node init --data-dir .stackey/vault-node
node dist/src/cli.js vault init --vault-dir .stackey/vault --recovery-out .stackey/recovery.json
node dist/src/cli.js node start --data-dir .stackey/vault-node --port 45822
```

`vault init` 產生專供 Stackey 的 24 個英文 BIP39 單字，寫入指定 0600 recovery 檔案。stdout 只顯示路徑、公鑰身分與 locked 狀態。助記詞不能放在 CLI 參數、聊天或 agent 工具結果。Recovery 檔案是明文復原材料，請保管在 agent 無法存取的位置並備份。

另一個終端機解鎖，保持前景程序執行：

```bash
node dist/src/cli.js vault unlock --vault-dir .stackey/vault \
  --recovery-file .stackey/recovery.json --data-dir .stackey/vault-node --ttl 900
```

第三個終端機執行 Owner 命令：

```bash
node dist/src/cli.js vault status
node dist/src/cli.js node owner-init --vault-dir .stackey/vault --data-dir .stackey/vault-node
node dist/src/cli.js wallet list
node dist/src/cli.js wallet create --name Research
```

解鎖期限 60–3600 秒，預設 900 秒。解鎖只在 Unix socket 程序記憶體中持有解密金鑰；不建立 HTTP 管理 API。`node owner-init --vault-dir` 將這個 Owner 綁到 unlock 時指定的 Node，拒絕替換另一個 Owner。

## 匯入與清單

先用可信 Owner 端建立一份私有 JSON 檔案，格式為 `{"value":"your-secret"}`，目錄 0700、檔案 0600。不要使用有真實值的 shell inline 指令，避免落入 shell history。

```bash
node dist/src/cli.js credential import --wallet wallet_demo --name TestAPI \
  --kind api_key --secret-file .stackey/secret-input.json
node dist/src/cli.js credential list --wallet wallet_demo
node dist/src/cli.js credential remove CREDENTIAL_ID
```

種類為 `password`、`api_key`、`private_key`。清單與匯入結果只回傳 ID、wallet、名称與種類；没有秘密匯出或通用簽章命令。輸入檔案不會自動刪除，Owner 自行管理其保管。這是保管功能，尚不代表任意網站可自動登入。

錢包、憑證和 connection 清單每頁 100 筆。當 `next_cursor` 非 null，使用 `--after NEXT_CURSOR` 取得下一頁，直到 `complete: true`。

## 連接測試資源並授權 agent

為 demo provider 準備私有 JSON config 檔案，內容 `{}`：

```bash
node dist/src/cli.js connection add --wallet wallet_demo --name DemoStore \
  --provider demo --config-file .stackey/demo-config.json
node dist/src/cli.js connection list --wallet wallet_demo
node dist/src/cli.js node demo-init --vault-dir .stackey/vault --data-dir .stackey/vault-node
node dist/src/cli.js node invite --out .stackey/vault-invite.json --data-dir .stackey/vault-node
node dist/src/cli.js connect --invite-file .stackey/vault-invite.json \
  --state-dir .stackey/agents/new-agent --name NewAgent
node dist/src/cli.js node pairings --data-dir .stackey/vault-node
node dist/src/cli.js node approve PAIRING_ID --principal FULL_FINGERPRINT \
  --action demo.orders.read --wallet wallet_demo --ttl 900 \
  --vault-dir .stackey/vault --data-dir .stackey/vault-node
node dist/src/cli.js capabilities --state-dir .stackey/agents/new-agent
node dist/src/cli.js run demo.orders.read --from 2026-09-26 --to 2026-10-02 \
  --state-dir .stackey/agents/new-agent
```

可選取 `wallet create` 回傳的另一個 wallet ID；先在該 wallet 連接 demo，再核准。Grant 的 wallet 與 Owner 簽章綁定；每個配對仍只有一個任務 Grant。Demo connections 是同一份本機合成訂單的資源引用，沒有各自的外部帳號或真實付款。

Connection 可保管 Supabase／Vercel／Stripe config，但本階段尚未執行這些 provider；它們的 key 與 config 不出現在清單中。請依後續服務指南驗收，不能把 config 入庫算作完成整合。

## 鎖定、撤銷、備份與復原

```bash
node dist/src/cli.js node revoke GRANT_ID --vault-dir .stackey/vault --data-dir .stackey/vault-node
node dist/src/cli.js vault lock
node dist/src/cli.js vault backup --out .stackey/encrypted-backup.json
node dist/src/cli.js vault restore --vault-dir .stackey/restored-vault \
  --backup-file .stackey/encrypted-backup.json --recovery-file .stackey/recovery.json
```

鎖定或解鎖到期後，bound Node 的新／既有 agent session 都不能執行操作。正常 `vault lock`／Ctrl+C 移除本次 session 檔案與 socket；程序異常退出後，先確認 `vault status` 為 locked，再用 `vault recover-session` 清除已死亡程序的私有 socket。此命令拒絕清理仍存在的程序。

備份是加密 vault 檔案，鎖定時也能產生；輸出禁止覆寫。復原需要助記詞與加密備份，不能只靠助記詞還原匯入密碼。Restore 拒絕既有目標，驗證格式／完整性後才寫入，生成新的 vault instance ID。

備份不包含 Node 的 pairing、Grant、session 或 operation 資料庫。預設用新 Node 重新配對；若 Owner 明確把 restored vault 綁回原 Node，會先撤銷所有舊 Grant，不讓舊備份復活權限。正常同一 vault 的重新解鎖不改變仍有效的 Grant。

## 格式與限制

- BIP39：鎖定 `@scure/bip39` 2.2.0；沒有額外 BIP39 passphrase 選項。[上游文件](https://github.com/paulmillr/scure-bip39)
- Owner Ed25519 seed 與 vault wrapping key 使用不同用途的 HKDF-SHA256；wrapping key 使用 32-byte 隨機 salt。
- 32-byte 隨機 vault master key，由 wrapping key 以 AES-256-GCM 包裝；資料另以 master key 加密。每次保存使用新的 12-byte IV，16-byte tag。
- AAD 綁定格式、版本、vault ID、Owner、公鑰根、salt、cipher 與用途；資料也綁定 wrapped key。拒絕未知格式、篡改與錯誤助記詞。
- v1 是單一加密 vault payload，多 wallet 為權限 context；尚未採各 wallet 獨立資料加密金鑰或支援跨 Node 同步。
- Session 在私有 Unix socket 中提供有限 Owner 命令，權限來源是同 OS 使用者與私有 session file。這不是 agent 與 Owner 的強 runtime 隔離；同使用者的任意 shell 權限仍可讀 recovery 檔案或管理 session。
- Node／agent 原有私鑰檔案未加密；新的 seed-backed Owner 私鑰不落盤。JS 記憶體中的字串不能保證全部清除；鎖定會清理引用與 key buffer，程序結束後由 OS 回收。
- 只支援 macOS／Linux、單一 writer、4 MiB vault、每類最多 1000 筆。沒有 Keychain 日常解鎖、密碼改版或防惡意舊密文 rollback 的硬體根。

驗證：`npm run typecheck`、`npm test`，包含真實 CLI init／unlock／lock、密文無秘密、錯誤 seed／篡改、備份復原、舊權限失效、多 wallet／分頁與鎖定後拒絕。
