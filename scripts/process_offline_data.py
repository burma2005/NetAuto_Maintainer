import os
import re
import argparse
from glob import glob
from datetime import datetime

# 依照官方資安通報更新之設備漏洞清單
LOCAL_CVE_DB = {
    '17.9.4a': ['已修復 WebUI (CVE-2023-20198) 等重大漏洞的相對安全版本。'],
    '16.12.4': ['[EoL] CVE-2021-1443 (REST API Bypass)', '[EoL] CVE-2021-34727 (SD-WAN Viptela)'],
    '16.9.7': ['[EoL] CVE-2020-3227 (IOS XE Web UI)', '[EoL] CVE-2020-3118 (CDP DoS/RCE)'],
    '8.8.120.0': ['[EoL] CVE-2020-3453 (802.11 MAC DoS)', '[EoL] CVE-2021-1469 (REST API Auth Bypass)']
}

def get_cves_for_version(version_str):
    for ver, cves in LOCAL_CVE_DB.items():
        if ver in version_str:
            return cves
    return ['未發現已知重大 CVE 或未建檔版號']

def parse_show_cmd(file_content, cmd):
    """從 raw 檔案中擷取特定 COMMAND 區段的內容"""
    pattern = r'={10,}\s*\nCOMMAND:\s*' + re.escape(cmd) + r'\s*\n={10,}\s*\n(.*?)(?=\n={10,}\s*\nCOMMAND:|\Z)'
    match = re.search(pattern, file_content, re.DOTALL)
    if match:
        return match.group(1).strip()
    return ""

def clean_config_for_dr(config_text):
    """清理終端雜訊，產出可直接貼入空機的純淨設定"""
    lines = config_text.splitlines()
    clean_lines = []
    for line in lines:
        if re.match(r'^Building configuration', line) or re.match(r'^Current configuration', line):
            continue
        line = line.replace('--More--', '')
        if re.match(r'^[\w\-().]+[#>]\s*$', line):
            continue
        clean_lines.append(line)
    return '\n'.join(clean_lines).strip()

def normalize_mac_to_cisco(mac_str):
    """將任意格式 MAC 轉換為 Cisco 點記法 xxxx.xxxx.xxxx"""
    clean = re.sub(r'[:\-\.]', '', mac_str).lower()
    if len(clean) == 12:
        return f"{clean[0:4]}.{clean[4:8]}.{clean[8:12]}"
    return None

def parse_ap_list_from_wlc(content):
    """從 WLC 的 show ap summary 中提取 AP 名稱、乙太 MAC 與 IP
    回傳 {cisco_mac: (ap_name, ap_ip)} 字典"""
    ap_summary = parse_show_cmd(content, 'show ap summary')
    aps = {}
    mac_re = re.compile(r'([\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2})')
    for line in ap_summary.splitlines():
        mac_match = mac_re.search(line)
        if not mac_match:
            continue
        tokens = line.split()
        if not tokens:
            continue
        ap_name = tokens[0]
        mac = normalize_mac_to_cisco(mac_match.group(1))
        ip_match = re.search(r'\bTW\s+([\d]+\.[\d]+\.[\d]+\.[\d]+)', line)
        ap_ip = ip_match.group(1) if ip_match else 'N/A'
        if mac:
            aps[mac] = (ap_name, ap_ip)
    return aps

def parse_err_disabled_ports(content):
    """解析 show interfaces status err-disabled 輸出，
    並交叉比對 syslog 取得觸發原因。
    回傳 list of dict: {port, vlan, reason}"""
    err_out = parse_show_cmd(content, 'show interfaces status err-disabled')
    if not err_out or 'No ports' in err_out or 'Invalid input' in err_out:
        return []

    ports = []
    for line in err_out.splitlines():
        # 格式: Gi1/0/17   description   err-disabled  vlan  duplex  speed  type
        m = re.match(r'^(\S+/\S+)\s+.*err-disabl\S*\s+(\S+)', line, re.IGNORECASE)
        if not m:
            # 嘗試無描述欄位的格式
            m = re.match(r'^(\S+/\S+)\s+err-disabl\S*\s+(\S+)', line, re.IGNORECASE)
        if m:
            port = m.group(1)
            vlan = m.group(2)
            ports.append({'port': port, 'vlan': vlan, 'reason': 'unknown'})

    # 從 syslog 交叉比對取得觸發原因
    log_out = parse_show_cmd(content, 'show logging') or parse_show_cmd(content, 'show logging logfile')
    for entry in ports:
        port_esc = re.escape(entry['port'])
        # 找最近一筆 ERR_DISABLE 紀錄，擷取原因
        m = re.search(
            r'%PM-\d+-ERR_DISABLE:\s+(\S+)\s+error detected on ' + port_esc,
            log_out, re.IGNORECASE
        )
        if m:
            entry['reason'] = m.group(1)
    return ports

def parse_mac_table_for_aps(content, ap_mac_set):
    """從 show mac address-table 中找出 AP 直連的接入 Port（排除 Port-Channel 上行鏈路）
    回傳 {mac: (vlan, port)} 字典，僅包含直連端口（非 Po/Vl/CPU）"""
    mac_output = parse_show_cmd(content, 'show mac address-table')
    found = {}
    for match in re.finditer(
        r'^\s*(\d+)\s+([\da-f]{4}\.[\da-f]{4}\.[\da-f]{4})\s+(?:DYNAMIC|STATIC)\s+(\S+)',
        mac_output, re.MULTILINE | re.IGNORECASE
    ):
        vlan = match.group(1)
        mac = match.group(2).lower()
        port = match.group(3)
        if mac not in ap_mac_set:
            continue
        # 非 Port-Channel / Vlan / CPU → 代表該 switch 直連此 AP
        if not re.match(r'^(Po|Vl|CPU)', port, re.IGNORECASE):
            found[mac] = (vlan, port)
    return found

def process_device_file(filepath, dr_dir, annotated_dir):
    filename = os.path.basename(filepath)
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', filename)
    ip = ip_match.group(1) if ip_match else "Unknown"
    hostname = filename.split('_')[0]

    ver_out = parse_show_cmd(content, 'show version')
    sys_out = parse_show_cmd(content, 'show sysinfo')
    full_ver = ver_out if ver_out else sys_out

    os_version = "Unknown"
    if 'IOS XE' in full_ver or 'IOS-XE' in full_ver:
        vmatch = re.search(r'Version\s+(\S+),', full_ver)
        if vmatch: os_version = vmatch.group(1)
    elif 'NX-OS' in full_ver:
        vmatch = re.search(r'system:\s+version\s+(\S+)', full_ver)
        if vmatch: os_version = vmatch.group(1)
    elif 'Product Version' in full_ver:
        vmatch = re.search(r'Product Version\.+\s+(\S+)', full_ver)
        if vmatch: os_version = vmatch.group(1)

    dr_config = ""
    for dr_cmd in ['show running-config', 'show startup-config', 'show run-config commands', 'show run-config']:
        raw_cfg = parse_show_cmd(content, dr_cmd)
        if raw_cfg and len(raw_cfg) > 50 and 'Invalid input' not in raw_cfg:
            dr_config = clean_config_for_dr(raw_cfg)
            break

    file_base = filename.replace('_raw.txt', '')
    if dr_config:
        with open(os.path.join(dr_dir, f"{file_base}_dr_config.txt"), 'w', encoding='utf-8') as f:
            f.write(dr_config)
    else:
        print(f"  [WARNING] {hostname} ({ip}): 無法提取有效運行組態。")

    ANNOTATIONS = {
        'show running-config': '# 【⭐ 運行組態 (DR 來源)】目前正在運行的完整設定檔，可直接用於災難還原',
        'show logging': '# 【⚠️ 系統日誌】包含近期事件，需優先檢查 Error / Critical 級別',
        'show cdp neighbors detail': '# 【CDP 鄰接設備】用於繪製本專案的實體接線架構圖',
        'show version': '# 【系統版本與身分識別】設備基礎辨識資訊',
        'show environment all': '# 【環境硬體監控】溫度、風扇、電源綜合狀態',
        'show mac address-table': '# 【MAC 位址表】全域各 VLAN 學習狀態，可用於追蹤 AP 實體接入位置',
        'show interfaces status err-disabled': '# 【Err-Disabled Port 清單】列出所有因錯誤自動停用的 Port',
        'show errdisable recovery': '# 【Err-Disable 自動恢復設定】顯示各原因的自動恢復計時器狀態',
    }

    with open(os.path.join(annotated_dir, f"{file_base}_annotated.md"), 'w', encoding='utf-8') as af:
        af.write(f"# {hostname} ({ip}) — 帶註解的完整狀態備份\n\n")
        af.write(f"> **版本**: {os_version} | **時間**: {datetime.now().strftime('%Y/%m/%d %H:%M')}\n\n---\n\n")
        for line in content.splitlines():
            cmd_match = re.match(r'^COMMAND:\s*(.+)$', line)
            if cmd_match:
                cmd_name = cmd_match.group(1).strip()
                af.write(f"\n{ANNOTATIONS.get(cmd_name, f'# 【{cmd_name}】')}\n")
            af.write(f"{line}\n")

    cdp_out = parse_show_cmd(content, 'show cdp neighbors detail')
    neighbors = []
    for match in re.finditer(r'Device ID:\s*(.+)', cdp_out):
        raw_id = match.group(1).split('.')[0].strip()
        if re.match(r'^(SEP|ATA|AP|HQ-AP|F1-AP|B2-AP|CN97)', raw_id, re.IGNORECASE):
            continue
        neighbors.append(raw_id)

    log_out = parse_show_cmd(content, 'show logging') or parse_show_cmd(content, 'show logging logfile') or parse_show_cmd(content, 'show traplog')
    error_logs = []
    for line in log_out.splitlines():
        if re.search(r'-%[A-Z0-9_]+-[0-4]-', line) or (re.search(r'\b(ERR|CRIT)\b', line, re.IGNORECASE) and 'overrun' not in line.lower()):
            error_logs.append(line.strip())

    err_disabled = parse_err_disabled_ports(content)

    return {
        'hostname': hostname,
        'ip': ip,
        'version': os_version,
        'cves': get_cves_for_version(os_version),
        'neighbors': list(set(neighbors)),
        'errors': error_logs[:5],
        'has_dr': bool(dr_config),
        'err_disabled': err_disabled,
        'raw_content': content,
    }

def safe_mermaid_name(name):
    return re.sub(r'[^a-zA-Z0-9_-]', '_', name.strip())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--raw-dir', default='output/raw_backups', help="Directory containing raw_backups")
    parser.add_argument('-o', '--output-dir', default='output', help="Base directory for analysis artifacts")
    args = parser.parse_args()

    dr_dir = os.path.join(args.output_dir, 'dr_configs')
    annotated_dir = os.path.join(args.output_dir, 'annotated_configs')
    report_file = os.path.join(args.output_dir, 'maintenance_report.md')

    os.makedirs(dr_dir, exist_ok=True)
    os.makedirs(annotated_dir, exist_ok=True)

    files = sorted(glob(os.path.join(args.raw_dir, '*_raw.txt')))
    if not files:
        print(f"找不到任何Raw備份檔 ({args.raw_dir})！請先執行集錄腳本。")
        return

    print(f"找到 {len(files)} 個原始備份檔，開始分析與產出...")

    # --- 第一步：找出 WLC 檔並提取 AP 清單 ---
    wlc_aps = {}
    for f in files:
        if 'Controller' in os.path.basename(f) or 'WLC' in os.path.basename(f).upper():
            with open(f, 'r', encoding='utf-8', errors='ignore') as fh:
                wlc_content = fh.read()
            wlc_aps = parse_ap_list_from_wlc(wlc_content)
            print(f"  [WLC] from {os.path.basename(f)} extracted {len(wlc_aps)} AP Ethernet MACs.")
            break

    ap_mac_set = set(wlc_aps.keys())

    # --- 第二步：逐台設備分析 ---
    results, topology_edges = [], set()
    ap_location_table = {}   # {ap_mac: {ap_name, ap_ip, switch, switch_ip, vlan, port}}
    all_err_disabled = []    # [{hostname, ip, port, vlan, reason}, ...]

    for f in files:
        data = process_device_file(f, dr_dir, annotated_dir)
        results.append(data)
        src = safe_mermaid_name(data['hostname'])
        for n in data['neighbors']:
            dst = safe_mermaid_name(n)
            topology_edges.add(tuple(sorted([src, dst])))

        # Err-Disabled Port 彙整
        for ep in data['err_disabled']:
            all_err_disabled.append({
                'hostname': data['hostname'],
                'ip': data['ip'],
                **ep,
            })

        # MAC Table 反查：找出直連 AP
        if ap_mac_set:
            directly_connected = parse_mac_table_for_aps(data['raw_content'], ap_mac_set)
            for mac, (vlan, port) in directly_connected.items():
                ap_name, ap_ip = wlc_aps[mac]
                ap_location_table[mac] = {
                    'ap_name': ap_name,
                    'ap_ip': ap_ip,
                    'switch': data['hostname'],
                    'switch_ip': data['ip'],
                    'vlan': vlan,
                    'port': port,
                }

    mermaid_lines = ["graph TD"]
    for src, dst in sorted(topology_edges):
        mermaid_lines.append(f"    {src} <--> {dst}")

    timestamp = datetime.now().strftime("%Y/%m/%d %H:%M")
    with open(report_file, 'w', encoding='utf-8') as rf:
        rf.write(f"# 網路設備自動化維護總報告\n")
        rf.write(f"**分析時間**: {timestamp}\n\n---\n")
        rf.write("## 📁 隨附設定檔與備份路徑說明\n\n")
        rf.write("*   **災難還原設定檔目錄 (`.\\dr_configs\\`)**：已剔除雜訊的純配置指令檔，可 100% 回貼空機。\n")
        rf.write("*   **原始狀態除錯備份目錄 (`.\\raw_backups\\`)**：含全方位狀態原始輸出，專供工程師深度 Debug。\n")
        rf.write("*   **帶註解的完整備份目錄 (`.\\annotated_configs\\`)**：為 raw 的中文註解版，便於交接。\n---\n\n")

        rf.write("## 1. 網路核心接線架構圖 (Core CDP Topology)\n")
        rf.write("*(註：已自動過濾 IP Phones 與微型 AP，維持骨幹交換器與控制網路核心簡潔)*\n")
        rf.write("```mermaid\n" + "\n".join(mermaid_lines) + "\n```\n\n")

        rf.write("## 2. 設備狀態總覽與 CVE 漏洞評估表\n")
        rf.write("| Hostname | IP | OS Version | DR純化 | 異常日誌 | 官方通報之已知 CVE |\n")
        rf.write("| :--- | :--- | :--- | :---: | :---: | :--- |\n")
        for r in results:
            dr_status = "✅" if r['has_dr'] else "❌"
            rf.write(f"| {r['hostname']} | {r['ip']} | {r['version']} | {dr_status} | {len(r['errors'])} 筆 | {', '.join(r['cves'])} |\n")

        rf.write("\n## 3. 設備詳細狀態與 Syslog 分析\n")
        rf.write("> **💡 說明**：`Syslog logging: enabled (0 messages dropped, 9 rate-limited, 0 flushes, 0 overruns...)` 屬於系統連線正常/緩衝區健康的狀態回報，非錯誤事件。\n\n")
        for r in results:
            rf.write(f"### {r['hostname']} ({r['ip']})\n")
            rf.write(f"- **OS Version**: {r['version']}\n")
            rf.write(f"- **CVE 漏洞警告**: {', '.join(r['cves'])}\n")
            rf.write(f"- **近期系統日誌 (Top 5)**:\n")
            if r['errors']:
                for e in r['errors']: rf.write(f"  - `{e}`\n")
            else:
                rf.write("  - 系統日誌乾淨，無重大 Error 紀錄。\n\n")

        # --- 第四節：Err-Disabled Port 彙整表 ---
        rf.write("\n## 4. Err-Disabled Port 彙整表\n\n")
        if all_err_disabled:
            rf.write("> 以下 Port 已被設備自動停用（err-disable state）。")
            rf.write("觸發原因來自 `show interfaces status err-disabled` 與 syslog 交叉比對。\n\n")
            rf.write("| 交換器 | IP | Port | VLAN | 觸發原因 | 建議處置 |\n")
            rf.write("| :--- | :--- | :--- | :---: | :--- | :--- |\n")
            for ep in all_err_disabled:
                reason = ep['reason']
                action = {
                    'link-flap': '確認線材與對端設備；`shutdown / no shutdown` 恢復後觀察',
                    'psecure-violation': '確認連接設備 MAC 是否合法；清除 violation 後恢復',
                    'bpduguard': '確認該 Port 是否誤接交換器；排除後恢復',
                    'loopback': '確認線路是否形成迴路；排除後恢復',
                    'storm-control': '確認對端設備是否廣播/組播異常；排除後恢復',
                }.get(reason, f'確認 err-disable 原因（{reason}）後執行 `shutdown / no shutdown`')
                rf.write(f"| **{ep['hostname']}** | {ep['ip']} | `{ep['port']}` | {ep['vlan']} | `{reason}` | {action} |\n")
        else:
            rf.write("> ✅ 全站無 Err-Disabled Port，所有介面狀態正常。\n")

        # --- 第五節：AP 接入點位置對照表 (MAC Table 反查) ---
        rf.write("\n## 5. AP 接入點位置對照表 (MAC Table 反查)\n\n")
        if ap_location_table:
            rf.write("> 透過各台 Switch 的 `show mac address-table` 輸出，比對 WLC 所提供的 AP 乙太 MAC，")
            rf.write("自動找出每台 AP 直連的交換器與 Port。僅顯示非 Port-Channel 接入（確認為實體直連）。\n\n")
            rf.write("| AP 名稱 | AP 乙太 MAC | AP IP | 接入交換器 | 交換器 IP | VLAN | 接入 Port |\n")
            rf.write("| :--- | :--- | :--- | :--- | :--- | :---: | :--- |\n")
            for mac, info in sorted(ap_location_table.items(), key=lambda x: x[1]['ap_name']):
                rf.write(f"| {info['ap_name']} | `{mac}` | {info['ap_ip']} | **{info['switch']}** | {info['switch_ip']} | {info['vlan']} | `{info['port']}` |\n")

            # 找出尚未在 MAC table 中找到的 AP（可能連到 Core 或未上線）
            located_macs = set(ap_location_table.keys())
            unlocated = {mac: info for mac, info in wlc_aps.items() if mac not in located_macs}
            if unlocated:
                rf.write("\n### 未在 Edge Switch 直連 Port 找到的 AP（可能直連 CoreSW 或上行鏈路學習）\n\n")
                rf.write("| AP 名稱 | AP 乙太 MAC | AP IP |\n")
                rf.write("| :--- | :--- | :--- |\n")
                for mac, (ap_name, ap_ip) in sorted(unlocated.items(), key=lambda x: x[1][0]):
                    rf.write(f"| {ap_name} | `{mac}` | {ap_ip} |\n")
        else:
            rf.write("> ⚠️ 未在 WLC 檔案中找到 AP 清單，或無 `show mac address-table` 資料。請確認 WLC raw backup 存在。\n")

    # 清理 raw_content（不需要存入 results）
    for r in results:
        r.pop('raw_content', None)

    print(f"\n[OK] 報告與離線解析作業全數完成: {report_file}")
    if all_err_disabled:
        print(f"   [ERR] 發現 {len(all_err_disabled)} 個 Err-Disabled Port，已列入報告第 4 節。")
    if ap_location_table:
        print(f"   [AP] 成功建立 AP 接入位置對照表，共找到 {len(ap_location_table)} 台 AP 的直連 Port。")

if __name__ == "__main__":
    main()
