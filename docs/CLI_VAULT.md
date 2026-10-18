# CLI 保險箱、錢包與憑證

此階段完成本機保險箱與 seed-backed Owner；三家服務 API 操作另見 [CLI 服務整合指南](CLI_INTEGRATIONS.md)。所有測試只用新建 fixture，既有 `.stackey/node` 和 agent 身分不自動搬移或重新核准。

## 從新目錄開始

不要以新的助記詞取代已固定的舊 Owner。本例刻意使用新的 Node／vault 目錄；舊配對 demo 可照原指南繼續使用。

```bash
npm ci
npm run build
node dist/src/cli.js node init --data-dir .stackey/vault-node
node dist/src/cli.js setup --vault-dir .stackey/vault
node dist/src/cli.js node start --data-dir .stackey/vault-node --port 45822
```

`stackey setup` 是 Uniswap-wallet 風格的一鍵建立：產生 24 個英文 BIP39 單字、寫入預設 0600 recovery 檔案（`.stackey/recovery.json`），**stdout 不顯示助記詞**。`vault init --recovery-out` 仍可用於指定路徑。助記詞不能放在 CLI 參數、聊天或 agent 工具結果。

建立後 sidecar `backup-state.json` 標記 `backed_up: false`。`stackey setup`、`vault status`（locked 或 unlocked）與 `stackey status` 會持續顯示 `backup_nudge`（`This vault is not backed up. Run stackey backup ...`），直到 `stackey backup` 三詞確認成功。Recovery 檔案是明文復原材料，請保管在 agent 無法存取的位置並備份。

手動備份（Uniswap 風格，助記詞只在按 Enter 後顯示在 stderr）：

```bash
node dist/src/cli.js backup --vault-dir .stackey/vault
```

確認 3 個隨機位置的單字後，會清除 nudge，並詢問是否安全覆寫後刪除明文 recovery 檔。stdout 仍是 JSON，不含助記詞。加密 vault 檔複製仍用 `vault backup`。

加密 iCloud Drive 備份（使用者備份密碼 + scrypt + AES-256-GCM；無伺服器）。macOS 寫入 `~/Library/Mobile Documents/com~apple~CloudDocs/Stackey/`；測試可用 `STACKEY_ICLOUD_DIR`。密碼只從 0600 `--password-file` `{"password":"..."}` 讀取，不進 CLI 參數：

```bash
node dist/src/cli.js backup --icloud --password-file .stackey/backup-password.json
node dist/src/cli.js restore --password-file .stackey/backup-password.json \
  --vault-dir .stackey/restored-vault
```

iCloud 檔不含明文助記詞。錯誤密碼對應 `invalid_backup_password`，不寫入目標 vault。這不會自動清除紙本 `not backed up` nudge。

另一個終端機解鎖，保持前景程序執行。macOS 預設走 Keychain／Touch ID，不必再讀明文 recovery 檔：

```bash
node dist/src/cli.js vault unlock --vault-dir .stackey/vault \
  --data-dir .stackey/vault-node --ttl 900
```

`--recovery-file` 仍可用於尚未寫入 Keychain 的裝置，或作為助記詞復原路徑。Linux 測試／開發後端是 vault 目錄下的 0600 file keychain，不是生物辨識。

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
node dist/src/cli.js credential origin-add CREDENTIAL_ID --origin https://dashboard.example.test \
  --vault-dir .stackey/vault --data-dir .stackey/vault-node
node dist/src/cli.js credential revoke CREDENTIAL_ID \
  --vault-dir .stackey/vault --data-dir .stackey/vault-node
node dist/src/cli.js audit --data-dir .stackey/vault-node
```

種類為 `password`、`api_key`、`private_key`、`website_login`。清單與匯入結果只回傳 ID、wallet、名称與種類；没有秘密匯出或通用簽章命令。輸入檔案不會自動刪除，Owner 自行管理其保管。`password` 仍是保管項目；網站自動登入是獨立的 `website` connection + `website.session.login` Grant，預設拒絕真實瀏覽器自動化。`website_login` 必須用 `credential revoke`（刪密文、清空 jar、立即作廢 website session 與對應 Grant，並寫入 append-only `audit_log`），不能用 `credential remove`。Allowlist 為精確 `https://host`，無萬用字元。`stackey audit` 讀取稽核列（憑證、agent、origin、時間、結果；不含秘密）。契約與威脅模型見 [WEBSITE_LOGIN.md](WEBSITE_LOGIN.md)。

錢包、憑證和 connection 清單每頁 100 筆。當 `next_cursor` 非 null，使用 `--after NEXT_CURSOR` 取得下一頁，直到 `complete: true`。

## 讓 Agent 取用同一筆帳密：每次 Owner 核准，不用重新配對

先完成上面的 Node、vault unlock、owner-init 及 credential import。初次試跑只用測試憑證。Owner 準備 0600 JSON config 檔案：`{"origin":"https://dashboard.example.test","credential_id":"CREDENTIAL_ID"}`，將 ID 換成匯入結果；不再複製秘密。

```bash
node dist/src/cli.js connection add --wallet wallet_demo --name Dashboard \
  --provider credential --config-file .stackey/credential-config.json --vault-dir .stackey/vault
node dist/src/cli.js node invite --out .stackey/codex-invite.json --data-dir .stackey/vault-node
node dist/src/cli.js connect --invite-file .stackey/codex-invite.json \
  --state-dir .stackey/agents/codex --name Codex
```

Owner 核對配對回傳的完整指紋、connection 與 wallet，再核准：

```bash
node dist/src/cli.js node approve PAIRING_ID --principal FULL_FINGERPRINT \
  --action credential.get --connection CONNECTION_ID --wallet wallet_demo \
  --vault-dir .stackey/vault --data-dir .stackey/vault-node
```

省略 TTL 時預設為 300 秒，允許 60–300 秒，`max_calls` 固定為 1。Agent 只需保留自己的 state directory：

```bash
node dist/src/cli.js status --live --state-dir .stackey/agents/codex
node dist/src/cli.js credential get --state-dir .stackey/agents/codex
```

成功輸出為 `{"value":"..."}`，供 Agent 的工具使用；不要把真實輸出貼進聊天或紀錄檔。此流程交付原始秘密，不執行網站登入；origin 是核准取用的條件，不能限制已交付密碼之後的用途，也不能代替 MFA。

下一次取用，由 Owner 讀取 `node grants` 或 Agent 的 `status --live`，取得當前 Grant ID，對同一 pairing／指紋／connection 再核准：

```bash
node dist/src/cli.js node approve PAIRING_ID --principal FULL_FINGERPRINT \
  --action credential.get --connection CONNECTION_ID --wallet wallet_demo \
  --replace-grant CURRENT_GRANT_ID \
  --vault-dir .stackey/vault --data-dir .stackey/vault-node
```

新舊 Grant 在同一交易內切換，回傳新的 Grant ID；舊 Grant、session 與舊 operation 不能靠新授權再次取回秘密，歷史紀錄保留。重送舊 `--replace-grant` 會拒絕，請先查當前 Grant，避免誤發另一張授權。允許 Owner 明確取代已用完、過期或撤銷的 Grant；Agent 本身不能續期，且不能藉此變更帳號／wallet／action。其他 action 不支援此旗標。

第二個 Agent 用新 invitation 與自己的 state directory 配對，再由 Owner 核准同一個 CONNECTION_ID。憑證只保存一份，各 Agent 的 Grant、取用次數與撤銷互不共用。重啟 Node／重新解鎖相同 vault 後，原 Agent state directory 仍可用；已用完的 Grant 不會因重啟恢復次數。

Agent 收到 `node_locked` 時 exit code 為 3，表示需 Owner 解鎖；不要把它當作參數錯誤而重新配對。其他拒絕使用不同的 exit code：`permission_denied` 為 5、`grant_expired` 為 6、`grant_revoked` 為 7、`budget_exceeded` 為 8。`node grants` 會區分 `spent`（已用完 `max_calls`）、`replaced`（被 `--replace-grant` 取代）、`expired` 與 Owner 撤銷的 `revoked`。`stackey audit` 會列出成功 `issued`、上述拒絕，以及 pair / approve / replace / revoke / lock / unlock 等 Owner 變更；每列含 agent id、credential id、reason 與時間，不含秘密。

`node revoke GRANT_ID` 停止該 Grant 後續取用，不會收回已交付的密碼或網站登入狀態。升級涉及 grants 表遷移，請先依 [升級步驟](CLI_AUTHORIZATION.md#本機重現) 停止舊程序並備份。

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

可選取 `wallet create` 回傳的另一個 wallet ID；先在該 wallet 連接 demo，再核准。Grant 的 wallet 與 Owner 簽章綁定；demo 每個配對仍只核發一次任務 Grant。Demo connections 是同一份本機合成訂單的資源引用，沒有各自的外部帳號或真實付款。

Connection 可連接 Supabase 訂單唯讀、Vercel AI Gateway 模型生成與 Stripe 測試付款唯讀；key 與 config 不出現在清單中。設定及實際驗收見 [CLI 服務整合指南](CLI_INTEGRATIONS.md)。MPP 的真實商家收款驗收另有帳號與部署前置條件。

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
- macOS 日常解鎖把助記詞放在 Keychain，`SecAccessControl` `.userPresence`（Touch ID 或裝置密碼）。secret 經 helper stdin，不進 argv。這仍是同一 macOS 使用者的 Keychain 項目：有裝置密碼的人可以解鎖，不是獨立硬體根，也不是 agent 隔離。Linux 檔案後端與明文 recovery 同等級。
- 只支援 macOS／Linux、單一 writer、4 MiB vault、每類最多 1000 筆。沒有密碼改版或防惡意舊密文 rollback 的硬體根。

驗證：`npm run typecheck`、`npm test`，包含真實 CLI init／unlock／lock、密文無秘密、錯誤 seed／篡改、備份復原、舊權限失效、多 wallet／分頁與鎖定後拒絕。
