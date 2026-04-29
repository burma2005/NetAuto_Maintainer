"""
Offline Data Processor & Report Generator
==========================================
純離線解析 raw_backups 資料，產出 DR 設定檔、註解備份與維護總報告。
CVE 漏洞比對由 AI Agent 於報告生成後即時線上搜尋，本腳本僅負責版本提取。
"""
import os, re, argparse
from glob import glob
from datetime import datetime
import yaml

def load_global_annotations_and_topology(profile_dir):
    """讀取所有 YAML Profile，合併註解字典與拓樸查詢指令"""
    annotations = {
        'show version': '# 【系統版本與身分識別】設備基礎辨識資訊',
    }
    topology_cmds = ['show cdp neighbors detail', 'show lldp neighbors detail', 'show lldp neighbors']
    
    if not os.path.exists(profile_dir):
        return annotations, topology_cmds

    for fp in glob(os.path.join(profile_dir, '*.yml')):
        if '_template' in os.path.basename(fp):
            continue
        try:
            with open(fp, 'r', encoding='utf-8') as f:
                p = yaml.safe_load(f)
            # 合併中文註解
            if 'command_annotations' in p and isinstance(p['command_annotations'], dict):
                for cmd, note in p['command_annotations'].items():
                    annotations[cmd] = f"# 【{note}】"
            # 合併拓樸指令
            if 'topology_command' in p and p['topology_command']:
                if p['topology_command'] not in topology_cmds:
                    topology_cmds.append(p['topology_command'])
        except Exception as e:
            print(f"  [Warning] 無法載入 YAML 註解 ({fp}): {e}")
            
    return annotations, topology_cmds

def parse_show_cmd(content, cmd):
    pattern = r'={10,}\s*\nCOMMAND:\s*' + re.escape(cmd) + r'\s*\n={10,}\s*\n(.*?)(?=\n={10,}\s*\nCOMMAND:|\Z)'
    m = re.search(pattern, content, re.DOTALL)
    return m.group(1).strip() if m else ""

def clean_config_for_dr(config_text):
    lines = []
    for line in config_text.splitlines():
        if re.match(r'^Building configuration', line) or re.match(r'^Current configuration', line):
            continue
        line = line.replace('--More--', '')
        if re.match(r'^[\w\-().]+[#>]\s*$', line):
            continue
        lines.append(line)
    return '\n'.join(lines).strip()

def process_device_file(filepath, dr_dir, annotated_dir, annotations, topology_cmds):
    filename = os.path.basename(filepath)
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', filename)
    ip = ip_match.group(1) if ip_match else "Unknown"
    hostname = filename.split('_')[0]

    # 版本偵測（多廠牌）
    ver_out = parse_show_cmd(content, 'show version')
    sys_out = parse_show_cmd(content, 'show sysinfo')
    status_out = parse_show_cmd(content, 'get system status')
    full_ver = ver_out or sys_out or status_out

    os_version = "Unknown"
    ver_patterns = [
        (r'IOS XE|IOS-XE', r'Version\s+(\S+),'),
        (r'NX-OS', r'system:\s+version\s+(\S+)'),
        (r'Product Version', r'Product Version\.+\s+(\S+)'),
        (r'FortiGate', r'v(\S+),'),
        (r'Cisco IOS', r'Version\s+(\S+),'),   # 純 IOS Fallback (C2960 等)
    ]
    for indicator, regex in ver_patterns:
        if indicator in full_ver:
            vm = re.search(regex, full_ver)
            if vm:
                os_version = vm.group(1)
                break

    # DR 設定檔
    dr_config = ""
    for dr_cmd in ['show running-config', 'show startup-config', 'show run-config commands',
                    'show run-config', 'show full-configuration']:
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

    # 帶註解備份
    with open(os.path.join(annotated_dir, f"{file_base}_annotated.md"), 'w', encoding='utf-8') as af:
        af.write(f"# {hostname} ({ip}) — 帶註解的完整狀態備份\n\n")
        af.write(f"> **版本**: {os_version} | **時間**: {datetime.now().strftime('%Y/%m/%d %H:%M')}\n\n---\n\n")
        for line in content.splitlines():
            cmd_match = re.match(r'^COMMAND:\s*(.+)$', line)
            if cmd_match:
                cmd_name = cmd_match.group(1).strip()
                af.write(f"\n{annotations.get(cmd_name, f'# 【{cmd_name}】')}\n")
            af.write(f"{line}\n")

    # 動態拓樸解析
    neighbors = []
    for top_cmd in topology_cmds:
        top_out = parse_show_cmd(content, top_cmd)
        if not top_out: continue
        for m in re.finditer(r'(?:Device ID|System Name):\s*(.+)', top_out):
            raw_id = m.group(1).split('.')[0].strip()
            if re.match(r'^(SEP|ATA|AP\d|HQ-AP|F1-AP|B2-AP|CN97)', raw_id, re.IGNORECASE):
                continue
            neighbors.append(raw_id)

    # Syslog 錯誤
    log_out = (parse_show_cmd(content, 'show logging') or
               parse_show_cmd(content, 'show logging logfile') or
               parse_show_cmd(content, 'show traplog') or
               parse_show_cmd(content, 'execute log display'))
    errors = []
    for line in log_out.splitlines():
        if (re.search(r'-%[A-Z0-9_]+-[0-4]-', line) or
            (re.search(r'\b(ERR|CRIT)\b', line, re.IGNORECASE) and 'overrun' not in line.lower())):
            errors.append(line.strip())

    return {
        'hostname': hostname, 'ip': ip, 'version': os_version,
        'neighbors': list(set(neighbors)),
        'errors': errors[:5], 'has_dr': bool(dr_config),
    }

def safe_mermaid_name(name):
    return re.sub(r'[^a-zA-Z0-9_-]', '_', name.strip())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--raw-dir', default='output/raw_backups')
    parser.add_argument('-o', '--output-dir', default='output')
    parser.add_argument('-p', '--profile-dir', default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'command_profiles'))
    args = parser.parse_args()

    dr_dir = os.path.join(args.output_dir, 'dr_configs')
    annotated_dir = os.path.join(args.output_dir, 'annotated_configs')
    report_file = os.path.join(args.output_dir, 'maintenance_report.md')
    os.makedirs(dr_dir, exist_ok=True)
    os.makedirs(annotated_dir, exist_ok=True)

    # 讀取 YAML 註解
    annotations, topology_cmds = load_global_annotations_and_topology(args.profile_dir)

    files = sorted(glob(os.path.join(args.raw_dir, '*_raw.txt')))
    if not files:
        print(f"找不到 Raw 備份檔 ({args.raw_dir})！請先執行採集腳本。"); return

    print(f"找到 {len(files)} 個原始備份檔，開始分析...")
    results, edges = [], set()
    for f in files:
        data = process_device_file(f, dr_dir, annotated_dir, annotations, topology_cmds)
        results.append(data)
        src = safe_mermaid_name(data['hostname'])
        for n in data['neighbors']:
            edges.add(tuple(sorted([src, safe_mermaid_name(n)])))

    # 提取不重複版本清單，供 Agent 進行即時 CVE 查詢
    unique_versions = sorted(set(r['version'] for r in results if r['version'] != 'Unknown'))

    mermaid = ["graph TD"] + [f"    {s} <--> {d}" for s, d in sorted(edges)]
    ts = datetime.now().strftime("%Y/%m/%d %H:%M")

    with open(report_file, 'w', encoding='utf-8') as rf:
        rf.write(f"# 網路設備自動化維護總報告\n**分析時間**: {ts}\n\n---\n")
        rf.write("## 📁 隨附設定檔與備份路徑說明\n\n")
        rf.write("* **`dr_configs/`**：災難還原設定檔，可 100% 回貼空機。\n")
        rf.write("* **`raw_backups/`**：原始狀態輸出，供深度 Debug。\n")
        rf.write("* **`annotated_configs/`**：中文註解版備份。\n---\n\n")

        rf.write("## 1. 核心接線架構圖 (CDP/LLDP Topology)\n")
        rf.write("```mermaid\n" + "\n".join(mermaid) + "\n```\n\n")

        rf.write("## 2. 設備狀態總覽\n")
        rf.write("| Hostname | IP | OS Version | DR純化 | 異常日誌 |\n")
        rf.write("| :--- | :--- | :--- | :---: | :---: |\n")
        for r in results:
            dr = "✅" if r['has_dr'] else "❌"
            rf.write(f"| {r['hostname']} | {r['ip']} | {r['version']} | {dr} | {len(r['errors'])} 筆 |\n")

        # 版本摘要表：供 Agent 即時搜尋 CVE
        rf.write("\n## 3. 偵測到的 OS 版本清單（待 CVE 即時比對）\n")
        rf.write("> **⚠️ 注意**：以下版本清單由腳本自動提取，請 AI Agent 針對每個版本即時搜尋官方 CVE 通報並補充至報告中。\n\n")
        rf.write("| OS Version | 使用該版本的設備數量 |\n")
        rf.write("| :--- | :---: |\n")
        for ver in unique_versions:
            count = sum(1 for r in results if r['version'] == ver)
            rf.write(f"| {ver} | {count} 台 |\n")

        rf.write("\n## 4. 詳細狀態與 Syslog 分析\n")
        for r in results:
            rf.write(f"### {r['hostname']} ({r['ip']})\n")
            rf.write(f"- **OS Version**: {r['version']}\n")
            rf.write(f"- **近期系統日誌 (Top 5)**:\n")
            if r['errors']:
                for e in r['errors']: rf.write(f"  - `{e}`\n")
            else:
                rf.write("  - 系統日誌乾淨，無重大 Error 紀錄。\n\n")

    print(f"\n✅ 報告完成: {report_file}")
    if unique_versions:
        print(f"📋 偵測到 {len(unique_versions)} 個不重複 OS 版本，請 Agent 進行即時 CVE 搜尋：")
        for v in unique_versions:
            print(f"   - {v}")

if __name__ == "__main__":
    main()
