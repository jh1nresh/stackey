# 第二步：本機核准、執行與撤銷

範圍：owner 用本機 CLI 簽署限時 Grant，agent 取得綁定自身 key 的 session，探索能力、讀取本機合成訂單，owner 撤銷後，舊 session 與新的 session 請求都被拒絕。資料來源明確為 `local_synthetic`，**不是 Supabase 整合驗收**。

## 本機重現

升級前停止舊 Node 與 vault unlock 程序，並備份停止寫入後的 Node 目錄；於 repo 執行 `npm ci --ignore-scripts`、`npm run build`，再啟動新版 Node 與 vault。沿用原 Node 與 agent 目錄，不需刪除或重新配對。新版首次開啟 SQLite 時會在交易內重建 grants 表，保留舊資料、簽章與外鍵，改為每個 pairing 只有一張未被取代的 Grant。完整性檢查失敗會回滾；請勿混跑舊版與新版程序或直接降版使用升級後的資料庫。回退須還原升級前完整 Node 備份。

另一個終端機準備 owner 與固定的 21 筆合成訂單：

```bash
node dist/src/cli.js node owner-init
node dist/src/cli.js node demo-init
node dist/src/cli.js node pairings
```

`owner-init` 固定 owner 公鑰；相同 signer 可重跑，拒絕替換既有 owner。`demo-init` 可重跑，不重複固定種子。測試日期為 2026-09-26 至 2026-10-02（UTC）。

把下列文字換成 `node pairings` 顯示的完整 pairing ID 與 principal 指紋：

```bash
node dist/src/cli.js node approve "PAIRING_ID" \
  --principal "FULL_PRINCIPAL_FINGERPRINT" \
  --action demo.orders.read --ttl 900
```

Owner 必須確認指紋、操作與期限；不是只看可任意填寫的 agent 名稱。此 demo.orders.read 流程每個 pairing 仍只接受一次 Grant，TTL 60–900 秒，固定 Wallet／Connection／資源，不允許再委派。僅 `credential.get` 支援 Owner 透過 `--replace-grant CURRENT_GRANT_ID` 在原 pairing 重新核准相同帳號連接；每次仍只取用一次、TTL 60–300 秒，詳見 [CLI vault 指南](CLI_VAULT.md#讓-agent-取用同一筆帳密每次-owner-核准不用重新配對)。

Agent 使用原 state directory（下面以已配對的 `.stackey/agents/codex` 為例）：

```bash
node dist/src/cli.js status --live --state-dir .stackey/agents/codex
node dist/src/cli.js capabilities --state-dir .stackey/agents/codex
node dist/src/cli.js run demo.orders.read --schema
node dist/src/cli.js run demo.orders.read \
  --from 2026-09-26 --to 2026-10-02 --state-dir .stackey/agents/codex
node dist/src/cli.js node events
node dist/src/cli.js node grants
```

預期 `status --live` 為 `active`，run 的 `data.result` 含 21 筆訂單。`source: local_synthetic`、`amount_unit: minor`、`timezone: UTC`、`complete: true`。成功付款 USD 共 9,100 最小貨幣單位；TWD 共 231,000；付款失敗 7 筆。不同幣別不可相加。

核准輸出或 `node grants` 提供 grant ID：

```bash
node dist/src/cli.js node revoke "GRANT_ID"
node dist/src/cli.js status --live --state-dir .stackey/agents/codex
node dist/src/cli.js run demo.orders.read \
  --from 2026-09-26 --to 2026-10-02 --state-dir .stackey/agents/codex
```

撤銷後 live status 為 `grant_revoked`，run exit 3。撤銷只影響該 Grant，不刪除共用 Connection，不收回先前交付的資料。

## 身分與傳輸契約

- Node 與 Owner signer 採不同 Ed25519 身分。Owner 私鑰位於指定 owner directory；SQLite 只保存 owner 公鑰、簽署後 Grant／撤銷材料。這是私有本機檔案管理通道，沒有任何 HTTP owner 管理路由。
- Owner 簽章 Grant 綁定 pairing、subject、Node audience、固定 Wallet／Connection／資源／action、期限與 policy version。每次服務請求驗證簽章與當前持久化政策。
- `POST /v1/challenges` 發出 30 秒、一次性 nonce。CLI 驗證 Node 簽署的回應；回應綁定新 request ID 的 body hash，不能把舊 challenge 回應作為新回應。
- `GET /v1/pairings/:id` 與 `POST /v1/sessions` 使用 `stackey-request+jwt`（jose ES256）。綁定 method／完整 URI／body hash、nonce、jti、Node audience、Principal。這是 Stackey bootstrap，不是 OAuth token grant endpoint。
- Session 為 Node 簽署的 `at+jwt`，最長 60 秒且不晚於 Grant 到期，綁定 `cnf.jkt`、Node issuer／audience、Principal、Grant ID 與版本。CLI 只在記憶體使用，不將 token 印到 stdout 或寫入 agent receipt。
- `GET /v1/capabilities`、`POST /v1/operations`、`GET /v1/operations/:id` 採 [oauth4webapi](https://github.com/panva/oauth4webapi) 3.8.8 生成／驗證 RFC 9449 DPoP 與 JWT access token。固定 proof ES256／token EdDSA，檢查 method、URI、ath、key binding、時間與持久化 nonce／jti。Stackey 額外用受簽章的 `stackey_body_hash` 綁定完整 body，縮小有效時間為 30 秒。
- Node 驗證 token 的 JWKS 是本機固定的 Node 公鑰，無外部 JWKS fetch。CLI 驗證 Node 簽署的業務／錯誤回應，且回應綁定當次 proof hash。
- 目前只允許 literal `http://127.0.0.1:<port>`。這是本機傳輸例外，不代表已完成標準的 HTTPS 遠端部署或完整 OAuth authorization server。

## 政策、結果與持久化

新增 SQLite `grants`、`challenges`、`request_proofs`、`sessions`、`demo_orders`、`operations` 與 `events`。核准、撤銷、nonce 消耗、session 登記與 operation 結果均持久化。驗證後，在持有 SQLite 寫入鎖時重檢時間、Grant／session 版本與撤銷；本機唯讀 adapter 與結果保存同步完成於該交易，沒有 async 外部 I/O。

同一 operation ID 與相同參數返回已保存結果，不重新讀取／新增事件。不同參數明確 conflict；不同 Principal／Grant 不可讀取結果。`stackey operation "OPERATION_ID"` 查原結果，仍需目前有效授權。`run --operation-id` 可指定 ID；未確認結果時錯誤提供原 ID，不自動盲目重送。結果在 `data.operation_id`／`data.result`，尚未沿用完整 SPEC 的所有 envelope 欄位。

唯一 operation 為 `demo.orders.read`；不接受任意 URL、SQL、header、Wallet 或 Connection。起訖日 UTC inclusive，最多 31 天，每頁 100 筆，按 created_at／id 排序；用 `--cursor` 傳入 `next_cursor` 續讀，`complete` 只在沒有剩餘頁時為 true。

Owner `node grants`／`node events` 每頁最多 200 筆，提供 `next_cursor` 與 `--after`。事件只記錄類型、subject、object ID、時間，不記錄 proof／token／私鑰。`node pairings` 與未加 `--live` 的 `status` 是原始接入／receipt，授權當前狀態請查 `node grants`／`status --live`。

## 限制與驗證

Owner／Node／agent key 仍是未加密的 0600 私有檔案。同 OS 使用者若能讀 owner／Node 目錄，就能使用本機管理能力；此版不能把有完整 shell／檔案權限的 agent 視為隔離使用者。強 runtime 隔離、OS signer、助記詞與 vault 加密仍待實作，勿用正式秘密測試。

此版沒有錢包 UI、Supabase／Vercel／Stripe／MPP、HTTPS／遠端 Grok Bot 或對外服務副作用。只有明確標示的本機合成訂單，可先完成授權流程，再換成正式 adapter。

驗證使用 `npm run typecheck`、`npm test`。包含真實 owner／agent CLI、資料 ground truth、雙 agent、舊 session 撤銷／重啟、proof replay／時間／URI／body 綁定、owner 簽章／scope、分頁、immutable operation 及 CLI 不輸出秘密的正反案例。
