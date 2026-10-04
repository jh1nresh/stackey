# CLI 服務整合與 API demo

核心流程：Owner 只匯入一次服務 key，agent 使用自己的配對私鑰提出請求。Vault 執行指定 API 操作，agent 得到限定結果；撤銷後，既有 session 也不能繼續使用。這個 API demo 不需要 Stripe business profile，也不需要部署公開服務。

## 可執行範圍

| Provider | Action | 固定操作 |
| --- | --- | --- |
| Supabase | `supabase.orders.read` | `stackey_demo_orders` 日期區間唯讀，固定五個欄位、每頁 100 筆 |
| Vercel | `vercel.ai.generate` | Owner 指定 Gateway 模型；prompt 上限 4,000 字元、最多 1,024 output tokens、無自動 retry |
| Stripe | `stripe.payments.read` | 測試模式 PaymentIntent 清單，每頁 10 筆，只回傳狀態與金額 |
| Stripe Link + MPP | `stripe.mpp.pay` | 單次指定 HTTPS endpoint、USD 固定金額、Link 核准與 SPT 支付；真實收款待驗收 |

助記詞、匯入 key、Link access token、SPT 不會提供給 agent。Node 保存 operation、公開 continuation 和限定結果。Agent 同 OS 使用者的 shell 仍不是強隔離；本階段 Node 只支援 loopback，沒有完成遠端 Grok Bot 接入。

每個 pairing 目前只有一個任務 grant。一個 grant 綁定一個 wallet、connection 和 action；同一 pairing 不能同時建立多個服務 grant。多服務 demo 可以使用三個獨立 agent state directory，後續再擴充一個任務的多權限契約。

## 1. Owner 準備

依 [保險箱指南](CLI_VAULT.md) 建立新的 Node、vault、recovery 檔案，保持 Node 與 vault unlock 在各自終端機執行，並以 `node owner-init --vault-dir ...` 綁定。既有舊 Node 不自動搬移。以下沿用 `.stackey/vault-node`、`.stackey/vault`。

```bash
npm ci --ignore-scripts
npm run build
node dist/src/cli.js wallet list --vault-dir .stackey/vault
```

`--ignore-scripts` 不執行 Link 套件的額外 binary 下載；Stackey 直接使用已鎖定的官方 npm JavaScript CLI。

Owner 在私有目錄建立 0600 JSON 檔案，內容 `{"value":"服務的測試 key"}`，分別匯入；真實 key 不要放入 shell inline 指令或 agent 對話。

```bash
node dist/src/cli.js credential import --wallet wallet_demo --name SupabaseSandbox \
  --kind api_key --secret-file .stackey/supabase-secret.json --vault-dir .stackey/vault
node dist/src/cli.js credential import --wallet wallet_demo --name GatewaySandbox \
  --kind api_key --secret-file .stackey/vercel-secret.json --vault-dir .stackey/vault
node dist/src/cli.js credential import --wallet wallet_demo --name StripeSandbox \
  --kind api_key --secret-file .stackey/stripe-secret.json --vault-dir .stackey/vault
```

保留各自回傳的 `credential_id`。輸入檔是 Owner 的明文設定材料，匯入後由 Owner 管理；正式 secret 存在加密 vault。

## 2. 建立三家 Connection

私有 config JSON 只放 ID 與固定資源，沒有 key：

```json
{"project_ref":"YOUR_20_LETTER_REF","credential_id":"credential_SUPABASE_ID"}
```

```json
{"model":"openai/gpt-4.1-mini","credential_id":"credential_GATEWAY_ID"}
```

```json
{"mode":"payments","credential_id":"credential_STRIPE_ID"}
```

各存成 `.stackey/supabase-config.json`、`vercel-config.json`、`stripe-config.json`（0600），執行：

```bash
node dist/src/cli.js connection add --wallet wallet_demo --name DemoStore \
  --provider supabase --config-file .stackey/supabase-config.json --vault-dir .stackey/vault
node dist/src/cli.js connection add --wallet wallet_demo --name Analysis \
  --provider vercel --config-file .stackey/vercel-config.json --vault-dir .stackey/vault
node dist/src/cli.js connection add --wallet wallet_demo --name TestPayments \
  --provider stripe --config-file .stackey/stripe-config.json --vault-dir .stackey/vault
```

Supabase 在專用 sandbox 套用 [合成訂單 SQL](../supabase/migrations/202610030001_stackey_demo_orders.sql)：21 筆虛構訂單、7 筆失敗；RLS 啟用、anon/authenticated 不可讀。Vault 使用 secret／service role key，固定 table、欄位和日期範圍，agent 不會取得高權限 key，也不能提出任意 SQL。Gateway 使用有供應商額度限制的 key；`max_calls` 控制呼叫次數，USD 付款預算只適用 MPP，並非模型費用精確估價。Stripe 拒絕 live key 與 live PaymentIntent，移除 customer、metadata 和付款資料。

## 3. Hire agent、核准、執行

每個 agent 使用不同私有 `--state-dir` 和一次性 invitation。以下讓第一個 agent 讀 Supabase：

```bash
node dist/src/cli.js node invite --out .stackey/invite-reader.json --data-dir .stackey/vault-node
node dist/src/cli.js connect --invite-file .stackey/invite-reader.json \
  --state-dir .stackey/agents/reader --name Reader
node dist/src/cli.js node pairings --data-dir .stackey/vault-node
node dist/src/cli.js node approve PAIRING_ID --principal FULL_FINGERPRINT \
  --action supabase.orders.read --connection SUPABASE_CONNECTION_ID --wallet wallet_demo \
  --max-calls 3 --ttl 900 --vault-dir .stackey/vault --data-dir .stackey/vault-node
node dist/src/cli.js capabilities --state-dir .stackey/agents/reader
node dist/src/cli.js run supabase.orders.read --from 2026-09-26 --to 2026-10-02 \
  --state-dir .stackey/agents/reader
node dist/src/cli.js operation OPERATION_ID --state-dir .stackey/agents/reader
```

`run` 先回傳 `operation_pending`，用同一 `operation_id` 查詢，直到 `ok`、`approval_required` 或 `result_unknown`。Supabase `complete: false` 時，帶回傳的 cursor 查下一頁；每次新 operation 使用一次 call。

第二個、第三個 agent 以相同配對流程，核准各自 connection/action，再執行：

```bash
node dist/src/cli.js run vercel.ai.generate --prompt '根據已取得的合成訂單結果，產生摘要。' \
  --state-dir .stackey/agents/analyst
node dist/src/cli.js run stripe.payments.read --state-dir .stackey/agents/payments
```

模型只收到 agent 明確傳入的 prompt；不自動將 vault 或其他服務資料送往 Gateway。三家 API 是獨立能力，目前未把 Stripe API 結果與合成訂單假裝成同一商店的關聯資料。

Owner 撤銷 `GRANT_ID`，再執行 agent 命令應被拒絕：

```bash
node dist/src/cli.js node revoke GRANT_ID --vault-dir .stackey/vault --data-dir .stackey/vault-node
```

provider operation 先持久化保留 call／付款預算再送出。相同 ID、相同參數重放不再次呼叫；改參數、換 grant 或 agent 被拒絕。未知結果保留預算，不自動重試。Node 重啟後尚未確認完成的 dispatch 回傳 `result_unknown`，需要 Owner 確認供應商結果，不以新的 ID 重付。

## 4. Link／MPP 擴充（不阻擋 API demo）

Owner 開啟 vault 後：

```bash
node dist/src/cli.js link login --wallet wallet_demo --vault-dir .stackey/vault
# 使用者在 Link 完成登入與裝置核准；agent 不能代替使用者批准。
node dist/src/cli.js link finish --wallet wallet_demo --vault-dir .stackey/vault
# 若未完成或已過期，可撤銷並清除本次登入，再開始。
node dist/src/cli.js link cancel --wallet wallet_demo --vault-dir .stackey/vault
```

`login` 只回傳驗證 URL／phrase，沒有阻塞式選單。登入期間的官方 auth 暫存檔位於私有 vault/link-onboarding 目錄，0600；`finish` 只將 access token 經 Owner IPC 匯入加密 vault，隨後刪除 auth 暫存檔。refresh token 不保留，本階段尚未支援 token 自動 refresh；過期後重新登入。`cancel` 只處理尚在暫存中的登入，不刪除已匯入的 vault credential 或既有 agent grant。不要將驗證 URL 放入公開活動記錄。

收款端程式為 `api/paid-report.ts`，使用 `STRIPE_TEST_SECRET_KEY` 和 `STRIPE_TEST_PROFILE_ID`，價格固定 US$0.50，交付明確標示的合成報告。需要另行授權部署；沒有在這個 PR 部署。Stripe 官方要求商家的 sandbox business profile（`profile_test_...`），與 Link 付款者帳號分開。[官方 MPP sandbox 文件](https://docs.stripe.com/payments/machine/mpp#test-with-a-stripe-sandbox)

MPP config：

```json
{"mode":"mpp","credential_id":"credential_LINK_ID","endpoint":"https://YOUR-PREVIEW.vercel.app/api/paid-report","network_id":"profile_test_YOUR_ID","payment_method_id":"pm_YOUR_ID","amount_minor":50}
```

只接受單一 `.vercel.app` HTTPS hostname、固定 `/api/paid-report`、test profile、USD 50 cents（商家固定價格），禁止任意目的地或 agent 改价。以 `stripe.mpp.pay` 核准 connection，`--max-calls 1 --max-amount-minor 50`。一次 grant 支援一次付款；保守保留整份付款預算，不因失敗或待核准自動釋放。

```bash
node dist/src/cli.js run stripe.mpp.pay --operation-id SAME_UUID --state-dir .stackey/agents/buyer
node dist/src/cli.js operation SAME_UUID --state-dir .stackey/agents/buyer
# 使用者在 Link 核准 approval_url 後，以相同 ID 續行。
node dist/src/cli.js run stripe.mpp.pay --operation-id SAME_UUID --state-dir .stackey/agents/buyer
node dist/src/cli.js operation SAME_UUID --state-dir .stackey/agents/buyer
```

每個階段再查授權，SPT 只在記憶體使用，challenge／receipt 綁定 operation 和商家，Stripe SDK 使用 idempotency key。Link 額外身分驗證／3DS 尚未完整包裝；未知結果停止自動執行。撤銷會阻止後續 dispatch，無法取消已經送往供應商的請求或退回已支付款項。

## 實際證據（2026-10-03）

| 實測 | 結果 |
| --- | --- |
| Supabase sandbox API | 21 筆真實資料庫內的合成訂單；撤銷既有 session 後拒絕 |
| Vercel AI Gateway / `openai/gpt-4.1-mini` | 實際摘要生成，45 input / 36 output tokens；撤銷既有 session 後拒絕 |
| Stripe test PaymentIntent API | 讀取 3 筆測試付款，只輸出限定欄位；撤銷既有 session 後拒絕 |
| MPP 協定 fixture | 使用真正 mppx challenge／credential／receipt 與 Stripe SDK，Link／Stripe 網路回應使用 fixture；不代表真實支付 |
| MPP 外部收款 | 未執行。sandbox profile API 回傳 404，Dashboard 建立按鈕停用；尚未完成 Link 核准、部署或收款 |

Supabase $100 優惠碼已兌換。Vercel $30 申請顯示 queued，入帳尚未確認；實測使用既有 Gateway credits，key 七天到期、總額 US$1，不自動重置。服務 credential 留在本機私有設定材料，未提交 Git。

驗證命令：

```bash
npm run typecheck
npm test
npm run test:sandbox -- --provider supabase --project-ref YOUR_PROJECT_REF --secret-file PRIVATE_SECRET_JSON
npm run test:sandbox -- --provider vercel --model openai/gpt-4.1-mini --secret-file PRIVATE_SECRET_JSON
npm run test:sandbox -- --provider stripe --secret-file PRIVATE_SECRET_JSON
```

`test:sandbox` 建立一次性 Node／vault／agent，真正經過配對、Owner 核准、DPoP、服務呼叫、結果續取和撤銷，最後只清除自己的 fixture。需要使用者事先指定測試專案並批准資料／付費模型呼叫；不會自行建立帳號、deploy、變更 production 或進行 MPP 付款。
