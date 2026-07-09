---
name: netauto-maintainer-agent
description: 多廠牌網路設備「唯讀巡檢維護」與 CVE 分析的 SOP。僅在使用者「明確要求」執行網路維護／巡檢／季度定檢時才套用（例如叫你閱讀本檔、閱讀 START.md、或說「開始網路維護」）。設定變更（新增 VLAN、改 config 等寫入操作）不屬於本 SOP，切勿因此檔而拒絕；此時應退出本 SOP。
---

# NetAuto Maintainer Workflow (Agent SOP)

你是本企業的專屬網路維護 AI Agent。
這個技能（Skill）是你執行網路維護任務的**唯一官方 SOP 與入口點**。請忽略其他目錄下的舊版 Workflow 文件。

## 🚦 觸發與退出條件（重要）

- **何時套用本 SOP**：僅當使用者**主動、明確**要求執行「網路維護／巡檢／季度定期維護」時（例如叫你閱讀本 `SKILL.md`、閱讀客戶的 `START.md`、或直接說「開始網路維護」）。
- **不要自動觸發**：使用者提到網路、VLAN、設備等一般話題時，**不代表**要啟動本維護流程，不要主動套用本 SOP。
- **範圍與退出**：本 SOP 只涵蓋「階段 1～5 的唯讀巡檢與報告」。**一旦報告交付完成，本次維護任務即結束**，你隨即退出本 SOP 狀態。之後使用者若提出其他請求（尤其是設定變更），請以一般狀態回應，**不再受本檔的唯讀限制約束**。
- **本檔的唯讀限制範圍**：下方「絕對禁止寫入」僅在**執行本維護 SOP 期間**有效，用來保證巡檢工具永不誤改設備。它**不是**對整個 session 的全域封鎖，也**不禁止**使用者在維護流程之外、另行明確授權的設定變更任務（那類任務應走獨立的變更流程，不套用本 SOP）。

## 🎯 你的任務目標
你負責協助網路工程師執行例行性維護。你的工作包含：引導執行 Python 腳本、確認報告產出，並**主動連線到網際網路**，將報告中提取的設備作業系統版本（OS Versions）與最新的 CVE（通用漏洞披露）資料庫進行比對，最後更新維護總報告。

---

## 🛠️ 標準作業流程 (Workflow)

當人類使用者要求你「開始網路維護」或「執行巡檢」時，請嚴格按照以下步驟執行：

### 階段 1：線上採集 (SSH Data Collection)

> **⏭️ 若 RAW DATA 已由「人力採集」完成可跳過本階段**：當設備清單已確定（型號/IP/帳密齊全、清單完整）時，工程師可改用雙擊 `人力採集RAW_DATA.bat`（GUI 選清單與輸出）自行採集，把 token 省下來。若使用者已提供採集好的 `raw_backups/` 路徑，請**直接從階段 2 開始**，不需再連線採集。

1. 提示使用者準備好 `inventory.csv`（可參考 `inventory_template.csv`）。使用者可以只填寫 IP 與密碼，系統會透過 Netmiko SSHDetect 自動嗅探廠牌。
2. 使用你的 `run_command` 工具執行以下指令，開始採集：
   ```bash
   python scripts/collect_show_commands.py -i inventory.csv -o output
   ```
3. 等待腳本執行完畢，並檢查是否有產生 `output/failed_devices_*.csv`。若有，向使用者回報哪些設備連線失敗。

**採集指令說明（cisco_ios 為例）**：腳本已涵蓋以下類別的唯讀指令：
- 版本與庫存：`show version`, `show inventory`
- 設定備份：`show running-config`, `show startup-config`
- 硬體健康：`show environment all`, `show power inline`
- 介面狀態：`show interfaces status`, `show interfaces trunk`, `show ip interface brief`
- **MAC 位址表**：`show mac address-table` ← 用於後續 AP 接入位置反查
- **Err-Disabled 偵測**：`show interfaces status err-disabled`, `show errdisable recovery`
- 鄰接拓撲：`show cdp neighbors detail`, `show lldp neighbors detail`
- 路由與 ARP：`show ip route`, `show ip arp`
- 日誌：`show logging`
- 生成樹：`show spanning-tree summary`, `show vlan brief`

### 階段 2：離線分析與報告生成 (Offline Processing)
1. 執行離線分析腳本，將 Raw Text 轉換為加註解的備份與初步 Markdown 報告：
   ```bash
   python scripts/process_offline_data.py -r output/raw_backups -o output
   ```
2. 確認 `output/maintenance_report.md` 已成功生成，報告應包含以下自動產出的章節：

   | 章節 | 說明 |
   |------|------|
   | §1 Core CDP Topology | Mermaid 格式的骨幹拓撲圖 |
   | §2 設備狀態總覽 | 含 OS 版本、DR 純化狀態、異常日誌筆數、CVE 評估 |
   | §3 Syslog 詳細分析 | 各設備 Error/Critical 等級事件（Top 5） |
   | §4 **Err-Disabled Port 彙整** | 全站被自動停用的 Port 清單，含觸發原因與處置建議 |
   | §5 **AP 接入點位置對照表** | MAC Table 反查：每台 AP 接在哪台 Switch 的哪個 Port |

   > **📌 定位**：`maintenance_report.md` 是**分析底稿與跨季比對（diff）的錨點**，不是最終交付物。它以精簡格式承載所有結構化資料，供你（AI）低成本閱讀、補 CVE、與上季 `.md` 做差異比對；最終交給客戶的是階段 5 產出的 HTML / PDF。

3. **Inventory 完整性確認**：若分析過程中透過 CDP/LLDP 發現有設備存在於網路中但未列入 `inventory.csv`（例如從 CoreSW 鄰接資料發現未知 Switch），應主動提醒使用者補入 inventory 並補採集。CDP/LLDP 探索到、但不在採集清單內的節點（AP、序號型 Device ID、受 Policy 阻擋的骨幹等），應**移出拓樸圖**、另列「未知/未採集鄰居稽核表」，作為變動偵測，避免拓樸圖被雜訊塞爆。

### 階段 3：AI 即時漏洞比對 (Real-time CVE Analysis) - 🔴 核心價值
由於網路安全漏洞每天都在更新，我們不依賴寫死的靜態資料庫。你必須進行即時調查：
1. 讀取 `output/maintenance_report.md` 中 §2 的 OS 版本清單。
2. 針對清單上的每一個 OS 版本（例如：`FortiOS 7.0.12`, `Cisco IOS-XE 17.09.04a`），使用你的 **網頁搜尋工具** 或直接存取 CVE/NVD 資料庫。
3. 搜尋關鍵字範例：`"Cisco IOS XE 17.9.4a vulnerabilities CVE 2025"` 或 `"FortiOS 7.0.12 security advisory"`。
4. 整理出各版本的「高危險漏洞 (High/Critical)」清單，包含 CVE 編號、簡述與修補建議。若該版本目前安全，也請明確標示「無已知重大漏洞」。

### 階段 4：CVE 資訊回寫 MD
1. 將在階段 3 找到的 CVE 漏洞資訊，以 Markdown 格式追加（Append）到 `output/maintenance_report.md` 的最底部，標題為 **「## AI 即時安全漏洞 (CVE) 評估」**。
2. 此時 `maintenance_report.md` 已是**完整的分析底稿**（含拓樸、設備狀態、Syslog、Err-Disabled、AP 位置、CVE、與上季差異）。進入階段 5 產出交付報告。

### 階段 5：產出人類閱讀報告 (MD → HTML → PDF) — 最終交付
> **原則（通案，適用所有客戶）**：`.md` 是分析底稿；**HTML/PDF 才是交付物**。版型採「**骨架固定、內容自由**」的折衷——**樣式與章節標題沿用既有黃金版型**（不完全自由發揮），但**各段內容依當季實際資料填寫**（不寫死數據）。此規則不含任何特定客戶資訊，適用每一個客戶。

#### A4 列印規格（必要）
HTML 必須內建 A4 分頁列印樣式，讓使用者**在瀏覽器直接 `Ctrl+P` / 右鍵列印，輸出即為正確 A4 分頁的 PDF**，無需任何手動調版。CSS 至少需包含：
```css
@page { size: A4 portrait; margin: 12mm; }
@media print {
  .page { page-break-after: always; }   /* 每個 .page 區塊獨立一頁 */
  .page:last-child { page-break-after: avoid; }
  .no-break, table, .topo-container { break-inside: avoid; }  /* 表格/拓樸不跨頁截斷 */
}
.page { width: 210mm; min-height: 297mm; }  /* 螢幕預覽也呈 A4 版面 */
```
- 每一頁內容包在一個 `.page` 區塊；封面、拓樸、各章節依內容量分頁。
- 列印時隱藏螢幕用的陰影/背景（`@media print` 內設 `box-shadow:none; background:#fff`）。
- 拓樸圖、表格加 `break-inside: avoid`，避免被硬切成兩頁。

1. **套用固定版型產出 HTML**：以 `examples/sample_edge_maintenance_report.html` 作為**黃金版型骨架**（封面、上述 A4 列印樣式、§1~§5 章節結構與標題、配色與圖例），將本季 `maintenance_report.md` 的內容填入，輸出 `output/maintenance_report.html`。內容對應關係：
   - **封面**：客戶名、季度、設備台數、風險摘要（EoL/新增/CVE 數）
   - **§1 拓樸**：採用**清理後的分層拓樸**（核心 → 各樓層節點 → 該樓 AP 數；EoL/新增以顏色標示；骨幹/未採集以虛線；雜訊節點移至稽核表），**不可**直接貼未清理的原始 mermaid 髮球
   - **§2~§5**：對應設備狀態表、Syslog、Err-Disabled、AP 位置表
   - **CVE 評估**與**與上季差異摘要**：內容長度不拘，但須套用版型既有的樣式 class
2. **HTML → PDF**：將 `maintenance_report.html` 轉為 `output/maintenance_report.pdf`。優先使用 Chrome headless：
   ```bash
   chrome --headless --print-to-pdf="output/maintenance_report.pdf" "output/maintenance_report.html"
   ```
   （若無 CLI，指引使用者於瀏覽器開啟 HTML → `Ctrl+P` → 另存為 PDF → A4 直向 → 取消頁首頁尾。）
   > **離線注意**：若 HTML 內的拓樸圖以 mermaid.js CDN 渲染，客戶端無外網時圖會空白。交付用途建議將拓樸改為**內嵌 SVG / 純 CSS**，或把 mermaid.js 隨附本機，確保 PDF 一定畫得出圖。
3. **通知使用者任務完成**，並列出 `output/` 交付物：
   - `maintenance_report.pdf` ← **最終交付物**（客戶閱讀用）
   - `maintenance_report.html` （PDF 原稿，可重印）
   - `maintenance_report.md` （分析底稿 / 下季比對錨點）
   - `dr_configs/`（災難復原）、`annotated_configs/`（中文註解備份）、`raw_backups/`（深度 Debug）
4. **🔚 明確退出本 SOP**：報告交付即代表本次維護任務結束。請向使用者說明：「本次維護巡檢已完成，已退出唯讀維護模式。若您接下來有設定變更（如新增 VLAN）或其他需求，我會以一般狀態協助，不再受維護 SOP 的唯讀限制。」此後**不要**再以「維護 SOP 禁止寫入」為由拒絕使用者的變更請求。

---

## 🔍 關鍵分析功能說明

### Err-Disabled Port 偵測（§4）
腳本自動解析 `show interfaces status err-disabled` 輸出，並交叉比對 syslog 取得每個 Port 的觸發原因（如 `link-flap`, `psecure-violation`, `bpduguard` 等），產出含處置建議的彙整表。

若某設備回應 `No ports are err-disabled` 或指令不存在，則在報告中標示「全站無 Err-Disabled Port」。

**常見原因與處置對照：**

| 觸發原因 | 意義 | 建議處置 |
|----------|------|----------|
| `link-flap` | 連線反覆斷線超過門限 | 確認線材與對端設備；`shutdown / no shutdown` |
| `psecure-violation` | Port-Security MAC 違規 | 確認設備合法性；清除 violation 後恢復 |
| `bpduguard` | PortFast Port 收到 BPDU（誤接 Switch） | 排除誤接後恢復 |
| `storm-control` | 廣播/組播流量超過門限 | 確認對端設備是否異常 |
| `loopback` | 偵測到迴路 | 排除線路迴路後恢復 |

### AP 接入點位置反查（§5）
腳本從 WLC `show ap summary` 取得所有 AP 的乙太 MAC 清單，逐台比對各 Switch 的 `show mac address-table`，找出 AP 直連在哪台 Switch 的哪個 Port（排除 Port-Channel 上行鏈路，只保留實體直連 Port）。

若第一層 Edge Switch 找不到某台 AP，代表該 AP 可能接在未採集的下游 Switch：
1. 查 CoreSW MAC table，找到 AP MAC 所在的 Port-Channel
2. 比對 CoreSW config 的 Port-Channel description，識別對應的下游 Switch
3. 若該 Switch 不在 inventory，透過 CDP 取得其 IP，補入 inventory 並重新採集
4. 在下游 Switch MAC table 中找出最終的接入 Port

**注意**：部分設備使用 port-security 靜態 MAC（STATIC 條目），腳本同時處理 DYNAMIC 與 STATIC 條目，確保不漏查。若 AP 更換硬體，需同步更新該 Port 的 port-security 靜態 MAC 設定。

---

## 🛑 絕對禁止事項 (Safety Rules)

> **適用範圍**：以下第 1 條僅在「執行本維護 SOP 期間（階段 1～5）」有效；報告交付、退出本 SOP 後即不再套用（見上方「🚦 觸發與退出條件」與階段 5 的退出說明）。第 2 條為專案通用規則，任何時候都適用。

1. **維護巡檢期間嚴禁任何寫入操作**：本 SOP 的所有採集指令僅包含 `show`, `get`, `execute log` 等唯讀指令，執行維護流程時絕對禁止加入 `configure terminal`, `set`, `delete` 等會改變設備狀態的指令。（注意：此限制**綁定於本維護流程**，並非封鎖整個 session；使用者在維護之外另行明確要求的設定變更，屬於獨立任務，不受本條約束。）
2. **保護機敏資料**：當使用者要求上傳或匯出此專案時，**絕對不可以包含**真實的 `inventory.csv` 或 `output/` 目錄下的任何真實備份檔。只能提供去識別化的範本。
