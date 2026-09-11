"""介面錯誤檢查 — 唯讀採集。

對 inventory.csv 內 DeviceType 為 cisco_ios 的設備執行：
  show version / show interfaces / show interfaces counters errors
僅執行 show 類指令，不做任何設定變更。輸出至 <output>/raw_interfaces/。

用法：
  python scripts/collect_show_interfaces.py -i inventory.csv -o output_interface_check
"""
import argparse
import csv
import os
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from netmiko import ConnectHandler

COMMANDS = ["show version", "show interfaces", "show interfaces counters errors"]


def process(dev, raw_dir, ts):
    ip = dev['IP'].strip()
    name = dev.get('Hostname', '').strip()
    params = {
        'device_type': 'cisco_ios',
        'host': ip,
        'username': dev['Username'].strip(),
        'password': dev['Password'].strip(),
        'secret': (dev.get('Secret') or dev['Password']).strip(),
        'global_delay_factor': 2,
    }
    try:
        with ConnectHandler(**params) as conn:
            try:
                conn.enable()
            except Exception:
                pass
            conn.send_command('terminal length 0')
            real = conn.find_prompt().rstrip('#>') or name
            safe = re.sub(r'[<>:"/\\|?*]', '_', real)
            path = os.path.join(raw_dir, f"{safe}_{ip}_{ts}_interfaces.txt")
            with open(path, 'w', encoding='utf-8') as f:
                for cmd in COMMANDS:
                    f.write("=" * 58 + f"\nCOMMAND: {cmd}\n" + "=" * 58 + "\n")
                    f.write(conn.send_command(cmd, read_timeout=240) + "\n\n")
        return ip, name, 'OK', ''
    except Exception as e:
        return ip, name, 'FAIL', str(e).splitlines()[0] if str(e) else repr(e)


def main():
    ap = argparse.ArgumentParser(description="唯讀採集 show interfaces（cisco_ios）")
    ap.add_argument('-i', '--inventory', required=True)
    ap.add_argument('-o', '--output-dir', required=True)
    ap.add_argument('-t', '--threads', type=int, default=5)
    args = ap.parse_args()

    raw_dir = os.path.join(args.output_dir, 'raw_interfaces')
    os.makedirs(raw_dir, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d-%H%M%S')

    with open(args.inventory, encoding='utf-8-sig') as f:
        rows = [r for r in csv.DictReader(f)
                if r.get('IP') and not r['IP'].strip().startswith('#')
                and r.get('DeviceType', '').strip() == 'cisco_ios']
    print(f"共 {len(rows)} 台 cisco_ios 設備，開始採集 show interfaces ...", flush=True)

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        results = list(ex.map(lambda d: process(d, raw_dir, ts), rows))

    for ip, name, st, msg in results:
        print(f"[{st}] {ip} {name} {msg}", flush=True)
    failed = [r for r in results if r[2] != 'OK']
    print(f"完成：成功 {len(results) - len(failed)} / {len(results)}", flush=True)


if __name__ == '__main__':
    main()
