"""
Network Device Data Collector (Profile-Driven, Multi-Vendor)
============================================================
透過 YAML 設備 Profile 與 Netmiko SSHDetect 自動辨識驅動的採集工具。
全流程嚴格唯讀，禁止任何設定變更操作。
"""
import argparse, csv, os, re, sys
from datetime import datetime
from glob import glob
import concurrent.futures
import yaml
from netmiko import ConnectHandler, SSHDetect
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

# 萬用 Fallback 指令集（當找不到對應 Profile 時使用）
FALLBACK_COMMANDS = [
    "show version",
    "get system status",
    "show inventory",
    "show running-config",
    "show full-configuration",
    "show interfaces status",
    "show ip interface brief",
    "show ip route",
    "show arp",
    "get system arp",
    "show mac address-table",
    "show cdp neighbors detail",
    "show lldp neighbors detail",
    "show logging"
]

def get_default_profile_dir():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(script_dir), 'command_profiles')

def load_profiles(profile_dir):
    profiles = {}
    for fp in sorted(glob(os.path.join(profile_dir, '*.yml'))):
        if '_template' in os.path.basename(fp):
            continue
        try:
            with open(fp, 'r', encoding='utf-8') as f:
                p = yaml.safe_load(f)
            dt = p.get('device_type')
            if dt:
                profiles[dt] = p
                print(f"  ✅ Loaded: {p.get('display_name', dt)}")
        except Exception as e:
            print(f"  ⚠️ Failed: {fp}: {e}")
    return profiles

def determine_device_type_by_csv(vendor, os_version, hostname, profiles):
    """根據 CSV 提供的文字資訊猜測設備類型"""
    if not vendor and not os_version:
        return None
        
    combined = f"{(vendor or '').lower()} {(os_version or '').lower()} {(hostname or '').lower()}"
    best_match, best_score = None, -1
    for dt, p in profiles.items():
        if any(kw in combined for kw in p.get('exclude_keywords', [])):
            continue
        score = sum(10 for kw in p.get('os_keywords', []) if kw in combined)
        score += sum(5 for kw in p.get('vendor_keywords', []) if kw in combined)
        if score > best_score and score > 0:
            best_score, best_match = score, dt
    return best_match

def autodetect_device_type(ip, username, password, secret):
    """透過 Netmiko SSHDetect 即時嗅探設備類型"""
    print(f"[{ip}] 🔍 Autodetecting device type via SSH...")
    device = {
        'device_type': 'autodetect',
        'host': ip,
        'username': username,
        'password': password,
        'secret': secret if secret else password,
        'global_delay_factor': 2,
    }
    try:
        guesser = SSHDetect(**device)
        best_match = guesser.autodetect()
        if best_match:
            print(f"[{ip}] 💡 Netmiko detected: {best_match}")
            return best_match
    except Exception as e:
        print(f"[{ip}] ⚠️ Autodetect failed: {e}")
    return None

def extract_by_patterns(text, patterns):
    for pat in patterns:
        m = re.search(pat, text)
        if m and m.group(1).strip():
            return m.group(1).strip()
    return None

def extract_model(profile, ver_out, inv_out, os_hint):
    pats = profile.get('model_patterns', []) if profile else []
    model = extract_by_patterns(ver_out, pats) or extract_by_patterns(inv_out, pats)
    if not model and os_hint:
        for kw in ['C9606R','C9300','C9200','C3850','C2960']:
            if kw in os_hint:
                model = kw; break
    return re.sub(r'[<>:"/\\|?*]', '_', model or 'UnknownModel')

def process_device(dev, timestamp, raw_dir, profiles):
    ip = dev.get('IP', '').strip()
    if not ip: return
    username = dev.get('Username', '').strip()
    password = dev.get('Password', '').strip()
    secret = dev.get('Secret', '').strip()
    hostname = dev.get('Hostname', '').strip() or ip
    vendor = dev.get('Vendor', '').strip()
    os_hint = dev.get('OS_Version', '').strip()
    explicit_dt = dev.get('DeviceType', '').strip()

    # 1. 優先使用 CSV 明確指定的 DeviceType
    device_type = explicit_dt if explicit_dt else None
    
    # 2. 若無，嘗試從 CSV 的 Vendor/OS 字串猜測
    if not device_type:
        device_type = determine_device_type_by_csv(vendor, os_hint, hostname, profiles)
        
    # 3. 若仍無法判定，直接連線進行 SSHDetect
    if not device_type:
        device_type = autodetect_device_type(ip, username, password, secret)

    if not device_type:
        err = f"無法自動辨識設備類型，且未提供 Vendor 資訊"
        print(f"\n[{ip}] ❌ {err}，跳過。")
        return {'ip': ip, 'hostname': hostname, 'status': 'failed', 'error': err}

    # 判斷是否使用 Fallback 模式
    if device_type in profiles:
        profile = profiles[device_type]
        display_name = profile.get('display_name', device_type)
        cmds = list(profile.get('commands', []))
        ver_cmd = profile.get('version_command', 'show version')
        inv_cmd = profile.get('inventory_command', 'show inventory')
        enable_required = profile.get('enable_mode', False)
        print(f"\n[{ip}] Connecting to {hostname} ({display_name})...")
    else:
        profile = None
        display_name = f"Unknown ({device_type})"
        cmds = FALLBACK_COMMANDS
        ver_cmd = "show version"
        inv_cmd = "show inventory"
        enable_required = True # Fallback 預設嘗試 Enable
        print(f"\n[{ip}] ⚠️ 未找到 '{device_type}' 的專屬 Profile，啟用通用盲測模式...")

    netmiko_dev = {
        'device_type': device_type, 
        'host': ip,
        'username': username, 
        'password': password,
        'secret': secret if secret else password, 
        'global_delay_factor': 2,
    }
    
    try:
        with ConnectHandler(**netmiko_dev) as conn:
            # Enable 模式
            if enable_required:
                try: conn.enable()
                except Exception as e: print(f"[{ip}] Warn enable: {e}")
            
            # Netmiko 建立連線時已自動處理 terminal length 0，無須手動 pre_commands

            # 抓取基礎資訊供辨識型號
            try:
                ver_out = conn.send_command(ver_cmd, read_timeout=30)
                inv_out = conn.send_command(inv_cmd, read_timeout=30)
                real_host = conn.find_prompt().replace('#','').replace('>','').strip()
            except Exception as e:
                ver_out = inv_out = ""; real_host = hostname
                print(f"[{ip}] Warn facts: {e}")

            real_model = extract_model(profile, ver_out, inv_out, os_hint)
            safe_host = re.sub(r'[<>:"/\\|?*]', '_', real_host)
            file_base = f"{safe_host}_{ip}_{real_model}_{timestamp}"
            
            # 條件指令
            if profile:
                for cb in profile.get('conditional_commands', []):
                    if cb.get('condition','') in real_model:
                        cmds.extend(cb.get('commands', []))

            raw_fp = os.path.join(raw_dir, f"{file_base}_raw.txt")
            print(f"[{ip}] Fetching RAW → {file_base}_raw.txt ...")
            with open(raw_fp, 'w', encoding='utf-8') as of:
                for cmd in cmds:
                    of.write(f"{'='*58}\nCOMMAND: {cmd}\n{'='*58}\n")
                    try:
                        to = 120 if any(k in cmd for k in ['running-config','run-config','configuration']) else 30
                        out = conn.send_command(cmd, read_timeout=to)
                        # Fallback 模式下忽略報錯指令
                        if not profile and ("Invalid input" in out or "Unknown command" in out):
                            out = "Not Supported."
                        of.write(out + "\n\n")
                    except Exception as ce:
                        of.write(f"Error executing {cmd}: {ce}\n\n")
        print(f"[{ip}] ✅ Completed {real_host}.")
        return {'ip': ip, 'hostname': real_host, 'status': 'success', 'error': ''}
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"[{ip}] ❌ Connection Error: {e}")
        return {'ip': ip, 'hostname': hostname, 'status': 'failed', 'error': f"Connection Error: {e}"}
    except Exception as e:
        print(f"[{ip}] ❌ Unexpected error: {e}")
        return {'ip': ip, 'hostname': hostname, 'status': 'failed', 'error': f"Unexpected error: {e}"}

def main():
    parser = argparse.ArgumentParser(description="Multi-vendor network device data collector.")
    parser.add_argument('-i', '--inventory', default='inventory.csv')
    parser.add_argument('-o', '--output-dir', default='output')
    parser.add_argument('-t', '--threads', type=int, default=5)
    parser.add_argument('-p', '--profile-dir', default=None)
    args = parser.parse_args()

    profile_dir = args.profile_dir or get_default_profile_dir()
    if not os.path.isdir(profile_dir):
        print(f"❌ Profile dir not found: {profile_dir}"); sys.exit(1)
    print(f"📂 Loading profiles from: {profile_dir}")
    profiles = load_profiles(profile_dir)
    print(f"   {len(profiles)} custom profile(s) loaded.\n")

    raw_dir = os.path.join(args.output_dir, 'raw_backups')
    os.makedirs(raw_dir, exist_ok=True)
    if not os.path.exists(args.inventory):
        print(f"❌ Inventory '{args.inventory}' not found."); sys.exit(1)

    devices = []
    with open(args.inventory, 'r', encoding='utf-8-sig') as f:
        for row in csv.DictReader(f):
            if row.get('IP','').strip() and not row['IP'].strip().startswith('#'):
                devices.append(row)
    print(f"📋 Loaded {len(devices)} devices.\n")
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")

    results = []
    if args.threads > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = [ex.submit(process_device, d, ts, raw_dir, profiles) for d in devices]
            for f in concurrent.futures.as_completed(futures):
                if f.result(): results.append(f.result())
    else:
        for d in devices: 
            res = process_device(d, ts, raw_dir, profiles)
            if res: results.append(res)
            
    # Write failed log
    failed = [r for r in results if r['status'] == 'failed']
    if failed:
        failed_fp = os.path.join(args.output_dir, f'failed_devices_{ts}.csv')
        with open(failed_fp, 'w', encoding='utf-8-sig', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'Hostname', 'Error Reason'])
            for r in failed:
                writer.writerow([r['ip'], r['hostname'], r['error']])
        print(f"\n⚠️ 有 {len(failed)} 台設備採集失敗，清單已儲存至: {failed_fp}")
        
    print(f"\n✅ All raw backups saved to: {raw_dir}")

if __name__ == "__main__":
    main()
