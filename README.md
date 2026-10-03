# Stackey

**Connect your services once. Give agents the access they need.**

Stackey 是給人管理、給 agent 使用的資源錢包。使用者保管服務連接、密碼與私鑰；新增 agent 時，透過一次配對與授權，讓它使用已連接的資源完成任務。

## 目前狀態

規格階段。此 repo 包含產品需求、架構、介面契約、demo 與驗收計畫，尚無可執行 app、CLI 或付款整合。Repo 初始預設分支為 `spec`。

**唯一的現行規格：[docs/SPEC.md](docs/SPEC.md)。** 規格內的 API、指令、資料表與資料夾皆為待實作設計。

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
