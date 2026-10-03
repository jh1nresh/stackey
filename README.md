# Stackey

**Connect your services once. Give agents the access they need.**

Stackey 是給人管理、給 agent 使用的資源錢包。使用者保管服務連接、密碼與私鑰；新增 agent 時，透過一次配對與授權，讓它使用已連接的資源完成任務。

## 目前狀態

本機 CLI 已支援配對、Owner 核准、短期 DPoP session、能力探索、合成訂單唯讀、operation 查詢與撤銷。訂單來源明確為本機 `local_synthetic`；CLI 另已支援助記詞保險箱、加密憑證、多錢包、備份復原與鎖定；Supabase／Vercel／Stripe 服務操作與錢包 UI 仍待驗收。Repo 初始預設分支為 `spec`。

**唯一的現行產品規格：[docs/SPEC.md](docs/SPEC.md)。** 完整產品 API／資料模型大部分仍待實作；目前可執行範圍見 [配對格式](docs/CLI_PAIRING.md) 與 [核准／執行／撤銷步驟](docs/CLI_AUTHORIZATION.md)。

本機保險箱與 seed-backed Owner：見 [CLI 保險箱指南](docs/CLI_VAULT.md)。舊配對 demo 沿用原 Owner，不自動遷移。

## 本機執行第一步

需要 macOS／Linux 與 Node.js 22.18 以上。使用 Node 原生 SQLite，Node 22 可能在 stderr 顯示 experimental warning。

```bash
npm ci
npm run build
npm run stackey -- node init
npm run stackey -- node start
```

Node 保持前景執行；另開終端機，在同一 repo 執行：

```bash
npm run stackey -- node invite --out .stackey/invitation.json --ttl 300
npm run stackey -- connect --invite-file .stackey/invitation.json --name "Local Agent"
npm run stackey -- status
npm run stackey -- node pairings
```

首次接入回傳待核准的 pairing ID 與公鑰指紋，`granted_actions` 為空。核准與執行請接著使用 [第二步操作指南](docs/CLI_AUTHORIZATION.md)。使用 Ctrl+C 停止 Node。`status` 讀取本機接入 receipt，沒有查詢即時服務權限。不同執行環境使用獨立 `--state-dir`；同 OS 使用者的目錄不構成強隔離。

`node pairings` 每頁最多 200 筆；若 JSON 的 `data.next_cursor` 不為 `null`，執行 `node pairings --after <next_cursor>` 取得下一頁，直到 `null`。不會把截斷清單當成完整結果。

原始 CLI JSON 輸出可用 `node dist/src/cli.js ...`，避免 npm 自身印出的 script 標頭。Invitation 檔案含一次性接入材料，預設 0600 且禁止覆寫；不可提交至 git。這一階段只允許 `http://127.0.0.1:<port>`，尚未驗證官方 Grok Bot 的雲端接入。

## 驗證

```bash
npm run typecheck
npm test
```

測試包含 Owner 核准、雙 agent 隔離、訂單正確、DPoP session／撤銷、operation／分頁及真實 CLI／HTTP 接入、一次性邀請的併發與重啟後重放、錯誤簽章、邀請／proof 綁定、過期、Node receipt 驗證、redirect 拒絕、請求限制，以及私鑰不出現在 CLI 結果中。

## 產品入口

- **錢包介面**：人連接服務、核准 agent、管理授權、查看活動與停止存取。
- **CLI**：agent 發現能力、執行操作、等待核准與取得結果；由 runtime 管理身分金鑰。
- **Vault Node**：使用者掌控的秘密保管、權限檢查與服務操作執行層。

## 技術分工

| 技術 | 預定用途 |
| --- | --- |
| Vercel + Next.js | 錢包 dashboard、控制平面 API、MPP 付費 endpoint |
| Vercel AI Gateway + AI SDK | 受控的模型呼叫 adapter，支援可選付費分析能力 |
| Supabase | Dashboard Auth、管理 metadata、活動同步、加密備份、實際 demo 訂單 |
| Stripe Link + MPP | 使用者付款來源、付款核准、HTTP 402 付費資源流程 |
| TypeScript CLI + Vault Node | Agent 配對、能力探索、授權執行、秘密使用與結果續取 |

## 第一個 demo

在官方 Grok Bot 新增 Bot，讓它透過 Stackey CLI 提出接入請求；使用者在錢包核准測試訂單唯讀權限；Bot 從 Supabase 取得真實合成資料並完成摘要。結束後撤銷權限，再次存取被拒絕。

主 demo 驗證接入與任務完成；Stripe MPP sandbox 和 AI Gateway 是相同架構的第二段驗收，不以畫面上的假餘額代替付款整合。

## 開發順序

1. 固定身分、授權、加密與 API 契約。
2. Vault Node、CLI 與 Supabase 唯讀 adapter。
3. 可信本機錢包管理介面與 Vercel dashboard。
4. 真實 Grok Bot 任務與撤銷驗證。
5. Link／MPP sandbox、AI Gateway 分析 endpoint。

實作時依 [規格的驗收矩陣](docs/SPEC.md#13-驗收矩陣) 記錄實際證據。部署、服務開通、付款與正式資料使用是後續獨立執行範圍。
