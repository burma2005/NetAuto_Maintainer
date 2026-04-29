# 設備指令集 Profile (Command Profiles)

本目錄存放各廠牌/平台的設備指令集定義檔（YAML 格式）。每個 Profile 定義了採集指令清單、型號/版本解析規則、以及該廠牌專屬的「中文註解對照表」。

## 如何新增自訂設備 Profile

1. 複製一份現有的 `.yml` 檔案作為範本（建議複製 `_template.yml`）
2. 修改以下必要欄位：

```yaml
device_type: "your_device_type"      # 必須是 Netmiko 支援的 device_type
                                       # 完整清單: https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md
display_name: "Your Device Platform"
vendor_keywords: ["your_vendor"]      # CSV Vendor 欄位的匹配關鍵字（小寫比對）
os_keywords: []                       # CSV OS_Version 欄位的匹配關鍵字
exclude_keywords: []                  # 排除比對的關鍵字

enable_mode: true                     # 是否需要進入 enable/privilege 模式

version_command: "show version"       # 用於取得版本資訊的指令
inventory_command: "show inventory"   # 用於取得硬體型號的指令

model_patterns:                       # 從 version/inventory 輸出解析型號的 regex (依序嘗試)
  - 'PID:\s*(\S+)'

version_patterns:                     # 解析 OS 版本的 regex (依序嘗試)
  - 'Version\s+(\S+)'

commands:                             # 主要採集指令集
  - "show version"
  - "show running-config"

conditional_commands: []              # 條件性指令（依設備型號觸發，可選）

# --- 解析與註解設定 ---
topology_command: "show cdp neighbors detail"  # 用於繪製拓樸圖的指令輸出 (若該廠牌不支援則留空)
command_annotations:                           # 中文註解對照表 (產生 annotated_configs 時使用)
  "show running-config": "⭐ 運行組態 (DR 來源)"
```

3. 將新的 `.yml` 檔存入本目錄即可，腳本啟動時會自動掃描載入。

## 注意事項與變更說明

- **移除 `pre_commands`**：最新版本的框架已深度整合 Netmiko，底層會在連線時自動處理關閉分頁（如 `terminal length 0` 等），因此 YAML 中不再需要定義前置指令。
- **解耦的中文註解**：在 `command_annotations` 中為該廠牌的特殊指令寫上中文註解，離線分析腳本就會在產出備份時自動帶上您的說明。
- **支援 Fallback**：若偵測到設備但沒有對應的 YAML Profile，系統將會啟動內建的「通用盲測模式」進行基礎資料採集。
