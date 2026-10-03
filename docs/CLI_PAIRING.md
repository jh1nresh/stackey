# 第一步：本機 CLI 接入

日期：2026-10-03。範圍：agent 提交一個可驗證的接入請求，Node 保存為待核准。沒有服務權限或供應商憑證，不代表完整 Vault 或遠端 Grok Bot 整合完成。

## 契約與實際結構

- CLI：`src/cli.ts`，編譯後 `node dist/src/cli.js`。
- Node：`src/node.ts`，僅 bind `127.0.0.1`，僅提供 `POST /v1/pairings`。
- 身分與狀態：`src/identity.ts`、`src/store.ts`；Node Ed25519，agent P-256／ES256，指紋採 RFC 7638 JWK thumbprint。
- 配對：`src/pairing.ts`；成熟 jose 函式庫提供 JWT／JWS 及金鑰操作，沒有自製簽章演算法。
- Agent client：`src/client.ts`，驗證可信 invitation 和 Node receipt，記錄本機配對狀態。
- 驗證：`test/pairing.test.ts`，使用 task 自建、獨立的臨時目錄與程序；關閉 Node 後清理自身 fixtures。

完整重現命令見 [README](../README.md#本機執行第一步)。`node invite`／`node pairings` 是本機檔案管理操作，agent HTTP API 沒有對應管理路由。

## 接入流程

1. Owner 執行 `node init` 建立專用 Node 身分與本機資料庫，`node start` 啟動前景程序。
2. `node invite --out <private-file>` 簽發預設 300 秒、可設定 30–900 秒的邀請。資料庫只保存邀請 JWT 的 hash、ID、期限與消耗狀態。
3. Owner 經可信方式把 invitation 交給 agent。可信 invitation 是 Node 公鑰的 bootstrap 信任來源；自己簽署的假 Node 邀請也會是有效 JWT，因此不能把任意來源的 invitation 視為可信。
4. CLI 檢查邀請的簽章、用途、期限、endpoint 與 Node 指紋，再建立或載入執行環境身分。
5. CLI 提交 invitation token 與 ES256 簽署的持有證明。Proof 綁定完整邀請 hash／ID、Node audience、method／URI、display name、jti，以及 30 秒有效時間。
6. Node 在完整 body 收到後驗證 proof，並在 SQLite `BEGIN IMMEDIATE` 取得鎖後重新檢查邀請與 proof 期限，再消耗邀請、新增一筆 `approval_required` pairing。邀請與 proof jti 都有唯一性約束。
7. Node 簽署回應 receipt，綁定 principal、request proof jti、pairing ID 和待核准狀態。CLI 以 invitation 中固定的 Node 公鑰驗證 receipt，寫入本機狀態，再輸出 JSON。

Proof 型別是版本化的 Stackey bootstrap JWS／JWT，**不是 OAuth DPoP session**。後續 session 授權仍依 SPEC 採標準 DPoP，不能沿用 pending pairing 充當 access token。Receipt 是接入確認，不能用於呼叫服務。

## 結果與錯誤

成功回傳 `schema_version: 1`、`request_id`、`status: approval_required`、pairing ID、公鑰指紋與 `granted_actions: []`。`status` 明確標示資料來源為本機 receipt，不宣稱 Node 在線或權限已批准。

- 錯誤參數／格式：exit 2。
- 無效／過期 invitation 或 Node 拒絕：exit 3，沒有服務授權。
- 請求逾時、receipt 無法驗證或本機 receipt 保存失敗：exit 4、`result_unknown`。Owner 查看 `node pairings`，不自動重送或宣稱未接入。
- 非預期錯誤：固定公開訊息，exit 1；不印出 JWK、邀請或原始第三方錯誤文字。

Owner 的 `node pairings` 以建立時間及 pairing ID 穩定排序，每頁最多 200 筆，回傳 `next_cursor`。使用 `node pairings --after <next_cursor>` 繼續讀取，直到 `next_cursor: null`；未知 cursor 明確拒絕，不會悄悄回傳空頁。這也是 `result_unknown` 的完整本機查詢路徑。

邀請經 `--invite-file` 使用，避免出現在 shell history／程序參數。直接傳 invitation 的方式為介面相容性保留，僅用於受控測試。

## 持久化與限制

狀態預設位於目前 repo 的 `.stackey/node` 和 `.stackey/agent`，不讀寫既有 SSH／雲端憑證／交易錢包 keystore。

目錄 0700、檔案 0600，拒絕不安全的權限、非本人擁有的檔案、symlink 狀態目錄／檔案和硬連結狀態檔案；已有 identity／invitation／receipt 不覆寫。執行環境身分 key 目前以私有檔案保存，**未加密、未使用 OS signer**。同 OS 使用者能讀取這些檔案，因此不能宣稱模型／Bot 隔離；不要匯入正式秘密。

HTTP 只允許 literal loopback endpoint，拒絕 DNS localhost、其他 host／protocol、URL credentials、額外 path／query／fragment 和 redirect。公開 HTTPS、TLS／Node pinning 的遠端部署與官方 Grok Bot 執行尚未完成。

Node 限制 JSON body 16 KiB、最多 30 次配對路由請求／分鐘，並拒絕 browser Origin。回應禁止 cache，不開放跨來源、session、Grant、operation 或管理端點。這些只保護目前的接入切片，不能當成 production auth／vault 安全認證。

## 驗證與下一步

驗收需要 `npm run typecheck`、`npm test` 和真實 CLI 的 pending 接入；測試確認無效 proof 不消耗 invitation、併發只接受一次、重啟保留狀態、另一把 Node key 的 receipt 無法確認接入、redirect 不轉送配對材料，且未開放服務／管理路由。

下一步才是可信 Owner 核准、正式 Grant／DPoP session、撤銷與一個 Supabase adapter。密碼加密／助記詞、備份、錢包 UI、雲端服務與付款均不在本切片。
