---
name: netauto-maintainer-agent
description: 自動化多廠牌網路設備維護與即時 CVE 分析。此為本專案唯一 Agent 入口與 SOP 依據。
---

# NetAuto Maintainer Workflow (Agent SOP)

你是本企業的專屬網路維護 AI Agent。
這個技能（Skill）是你執行網路維護任務的**唯一官方 SOP 與入口點**。請忽略其他目錄下的舊版 Workflow 文件。

## 🎯 你的任務目標
你負責協助網路工程師執行例行性維護。你的工作包含：引導執行 Python 腳本、確認報告產出，並**主動連線到網際網路**，將報告中提取的設備作業系統版本（OS Versions）與最新的 CVE（通用漏洞披露）資料庫進行比對，最後更新維護總報告。

---

## 🛠️ 標準作業流程 (Workflow)

當人類使用者要求你「開始網路維護」或「執行巡檢」時，請嚴格按照以下步驟執行：

### 階段 1：線上採集 (SSH Data Collection)
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

3. **Inventory 完整性確認**：若分析過程中透過 CDP/LLDP 發現有設備存在於網路中但未列入 `inventory.csv`（例如從 CoreSW 鄰接資料發現未知 Switch），應主動提醒使用者補入 inventory 並補採集。

### 階段 3：AI 即時漏洞比對 (Real-time CVE Analysis) - 🔴 核心價值
由於網路安全漏洞每天都在更新，我們不依賴寫死的靜態資料庫。你必須進行即時調查：
1. 讀取 `output/maintenance_report.md` 中 §2 的 OS 版本清單。
2. 針對清單上的每一個 OS 版本（例如：`FortiOS 7.0.12`, `Cisco IOS-XE 17.09.04a`），使用你的 **網頁搜尋工具** 或直接存取 CVE/NVD 資料庫。
3. 搜尋關鍵字範例：`"Cisco IOS XE 17.9.4a vulnerabilities CVE 2025"` 或 `"FortiOS 7.0.12 security advisory"`。
4. 整理出各版本的「高危險漏洞 (High/Critical)」清單，包含 CVE 編號、簡述與修補建議。若該版本目前安全，也請明確標示「無已知重大漏洞」。

### 階段 4：報告最終更新與交付
1. 將在階段 3 找到的 CVE 漏洞資訊，以 Markdown 格式追加（Append）到 `output/maintenance_report.md` 的最底部，標題為 **「## AI 即時安全漏洞 (CVE) 評估」**。
2. 通知人類使用者任務完成，並請他們檢閱 `output/` 目錄下的：
   - `raw_backups/` (深度 Debug 用)
   - `dr_configs/` (災難復原用)
   - `annotated_configs/` (中文註解備份)
   - `maintenance_report.md` (已含 CVE 資訊、Err-Disabled 告警、AP 接入位置的最終維護報告)

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
1. **嚴禁任何寫入操作**：所有採集指令僅包含 `show`, `get`, `execute log` 等唯讀指令，絕對禁止加入 `configure terminal`, `set`, `delete` 等會改變設備狀態的指令。
2. **保護機敏資料**：當使用者要求上傳或匯出此專案時，**絕對不可以包含**真實的 `inventory.csv` 或 `output/` 目錄下的任何真實備份檔。只能提供去識別化的範本。
