import argparse
import csv
import os
import re
import glob
from datetime import datetime
import concurrent.futures
import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from netmiko.ssh_autodetect import SSHDetect

PROFILE_DIR = os.path.join(os.path.dirname(__file__), '..', 'command_profiles')


def load_profiles():
    """掃描 command_profiles/*.yml，回傳 {device_type: profile_dict}"""
    profiles = {}
    for path in sorted(glob.glob(os.path.join(PROFILE_DIR, '*.yml'))):
        if os.path.basename(path) == '_template.yml':
            continue
        with open(path, 'r', encoding='utf-8') as f:
            profile = yaml.safe_load(f)
        if profile and profile.get('device_type'):
            profiles[profile['device_type']] = profile
    return profiles


PROFILES = load_profiles()


def match_profile_by_keywords(vendor, os_version):
    """依 CSV 的 Vendor / OS_Version 欄位，比對各 Profile 的 vendor_keywords / os_keywords"""
    vendor_l = (vendor or "").lower()
    os_l = (os_version or "").lower()
    for device_type, profile in PROFILES.items():
        excludes = profile.get('exclude_keywords') or []
        if any(x in vendor_l or x in os_l for x in excludes):
            continue
        vendor_keywords = profile.get('vendor_keywords') or []
        os_keywords = profile.get('os_keywords') or []
        if any(k in vendor_l for k in vendor_keywords):
            return device_type
        if os_keywords and any(k in os_l for k in os_keywords):
            return device_type
    return None


def autodetect_device_type(ip, username, password, secret):
    """CSV 完全沒有線索時，透過 Netmiko SSHDetect 連線即時嗅探廠牌"""
    guesser = SSHDetect(
        device_type='autodetect',
        host=ip,
        username=username,
        password=password,
        secret=secret if secret else password,
    )
    best_match = guesser.autodetect()
    return best_match if best_match in PROFILES else None


def determine_device_type(ip, username, password, secret, explicit_device_type, vendor, os_version):
    """裝置類型判斷優先序：
    1. CSV 明確填寫的 DeviceType 欄位（且必須是已載入的 Profile）
    2. Vendor / OS_Version 關鍵字比對 Profile
    3. 皆空 -> 即時 SSH 自動偵測 (Netmiko SSHDetect)
    4. 以上皆無法判斷 -> 預設 cisco_ios 並提出警告
    """
    explicit_device_type = (explicit_device_type or "").strip()
    if explicit_device_type and explicit_device_type in PROFILES:
        return explicit_device_type, "CSV DeviceType 欄位指定"

    matched = match_profile_by_keywords(vendor, os_version)
    if matched:
        return matched, "Vendor/OS_Version 關鍵字比對"

    if not vendor and not os_version and not explicit_device_type:
        try:
            detected = autodetect_device_type(ip, username, password, secret)
        except Exception as e:
            detected = None
            print(f"[{ip}] SSHDetect 自動嗅探失敗: {e}")
        if detected:
            return detected, "Netmiko SSHDetect 即時嗅探"

    return 'cisco_ios', "無法判斷，已回退為預設值 cisco_ios（請確認此設備是否需要補建對應 Profile）"


def extract_model(profile, version_output, inventory_output, fallback_hint):
    model = None
    for pattern in profile.get('model_patterns', []):
        for text in (version_output, inventory_output):
            match = re.search(pattern, text or "")
            if match:
                model = match.group(1).strip()
                break
        if model:
            break
    if not model:
        model = fallback_hint or "UnknownModel"
    return re.sub(r'[<>:"/\\|?*]', '_', model)


def build_command_list(profile, model):
    cmds = list(profile.get('commands', []))
    for cond in profile.get('conditional_commands') or []:
        if cond.get('condition') and cond['condition'] in model:
            cmds.extend(cond.get('commands', []))
    return cmds


def process_device(dev, timestamp, raw_dir):
    ip = dev.get('IP', '').strip()
    if not ip:
        return

    username = dev.get('Username', '').strip()
    password = dev.get('Password', '').strip()
    secret = dev.get('Secret', '').strip()
    hostname = dev.get('Hostname', '').strip()
    vendor = dev.get('Vendor', '').strip()
    os_hint = dev.get('OS_Version', '').strip()
    explicit_device_type = dev.get('DeviceType', '').strip()

    device_type, reason = determine_device_type(
        ip, username, password, secret, explicit_device_type, vendor, os_hint
    )
    profile = PROFILES[device_type]
    print(f"\n[{ip}] Connecting to {hostname} ({device_type} - {reason})...")

    netmiko_device = {
        'device_type': device_type,
        'host': ip,
        'username': username,
        'password': password,
        'secret': secret if secret else password,
        'global_delay_factor': 2,
    }

    try:
        with ConnectHandler(**netmiko_device) as net_connect:
            if profile.get('enable_mode'):
                try:
                    net_connect.enable()
                except Exception as e:
                    print(f"[{ip}] Warning: Could not enter enable mode: {e}")

            if device_type == 'cisco_wlc':
                net_connect.send_command('config paging disable')
            else:
                net_connect.send_command('terminal length 0')

            try:
                version_out = net_connect.send_command(profile.get('version_command', 'show version'))
                inventory_out = net_connect.send_command(profile.get('inventory_command', 'show inventory'))
                real_hostname = net_connect.find_prompt().replace('#', '').replace('>', '')
            except Exception as e:
                version_out = ""
                inventory_out = ""
                real_hostname = hostname
                print(f"[{ip}] Warning: Failed to get initial facts: {e}")

            real_model = extract_model(profile, version_out, inventory_out, os_hint)
            safe_hostname = re.sub(r'[<>:"/\\|?*]', '_', real_hostname)

            file_base = f"{safe_hostname}_{ip}_{real_model}_{timestamp}"
            cmds_to_run = build_command_list(profile, real_model)

            raw_filepath = os.path.join(raw_dir, f"{file_base}_raw.txt")
            print(f"[{ip}] Fetching RAW data into {file_base}_raw.txt ...")

            with open(raw_filepath, 'w', encoding='utf-8') as out_f:
                for cmd in cmds_to_run:
                    out_f.write(f"==========================================================\n")
                    out_f.write(f"COMMAND: {cmd}\n")
                    out_f.write(f"==========================================================\n")
                    try:
                        timeout = 120 if 'running-config' in cmd or 'run-config' in cmd or 'full-configuration' in cmd else 30
                        output = net_connect.send_command(cmd, read_timeout=timeout)
                        out_f.write(output + "\n\n")
                    except Exception as cmd_e:
                        out_f.write(f"Error executing {cmd}: {cmd_e}\n\n")

        print(f"[{ip}] Successfully completed {real_hostname}.")

    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"[{ip}] Connection Error: {e}")
    except Exception as e:
        print(f"[{ip}] An unexpected error occurred: {e}")


def main():
    parser = argparse.ArgumentParser(description="Collect running-config and show commands from network devices.")
    parser.add_argument('-i', '--inventory', default='inventory.csv', help="Path to the CSV inventory file")
    parser.add_argument('-o', '--output-dir', default='output', help="Base directory for output files")
    parser.add_argument('-t', '--threads', type=int, default=5, help="Number of parallel SSH threads")
    args = parser.parse_args()

    raw_dir = os.path.join(args.output_dir, 'raw_backups')
    os.makedirs(raw_dir, exist_ok=True)

    if not os.path.exists(args.inventory):
        print(f"Error: Inventory file '{args.inventory}' not found.")
        return

    if not PROFILES:
        print(f"Error: 找不到任何 command_profiles/*.yml，請確認 {PROFILE_DIR} 目錄內容。")
        return

    devices = []
    with open(args.inventory, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get('IP') or row.get('IP', '').strip().startswith('#'):
                continue
            devices.append(row)

    print(f"Loaded {len(devices)} devices from {args.inventory}. ({len(PROFILES)} device profiles available: {', '.join(PROFILES.keys())})")
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    if args.threads > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [executor.submit(process_device, dev, timestamp, raw_dir) for dev in devices]
            concurrent.futures.wait(futures)
    else:
        for dev in devices:
            process_device(dev, timestamp, raw_dir)

    print(f"\n✅ All raw backups have been saved to: {raw_dir}")


if __name__ == "__main__":
    main()
