import argparse
import csv
import os
import re
from datetime import datetime
import concurrent.futures
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

RAW_COMMANDS = {
    'cisco_ios': [
        'show version',
        'show inventory',
        'show running-config',
        'show environment all',
        'show environment temperature',
        'show environment power',
        'show power inline',
        'show processes cpu history',
        'show memory platform',
        'show startup-config',
        'show interfaces status',
        'show interfaces trunk',
        'show ip interface brief',
        'show etherchannel summary',
        'show ip route',
        'show ip arp',
        'show mac address-table',
        'show interfaces status err-disabled',
        'show errdisable recovery',
        'show cdp neighbors detail',
        'show lldp neighbors detail',
        'show logging',
        'show vlan brief',
        'show spanning-tree summary'
    ],
    'cisco_nxos': [
        'show version',
        'show inventory',
        'show module',
        'show running-config',
        'show environment',
        'show environment all',
        'show environment temperature',
        'show environment fan',
        'show environment power',
        'show processes cpu history',
        'show startup-config',
        'show interface status',
        'show interface brief',
        'show interface trunk',
        'show ip interface brief',
        'show port-channel summary',
        'show ip route',
        'show ip arp',
        'show mac address-table',
        'show interface status err-disabled',
        'show errdisable recovery',
        'show vpc',
        'show vpc brief',
        'show vpc peer-keepalive',
        'show cdp neighbors detail',
        'show lldp neighbors detail',
        'show logging logfile',
        'show vlan brief',
        'show spanning-tree summary'
    ],
    'cisco_wlc': [
        'show sysinfo',
        'show inventory',
        'show run-config commands',
        'show run-config',
        'show run-config no-ap',
        'show wlan summary',
        'show ap summary',
        'show ap join stats summary all',
        'show client summary',
        'show interface summary',
        'show port summary',
        'show cdp neighbors detail',
        'show traplog',
        'show msglog',
        'show 802.11a summary',
        'show 802.11b summary',
        'show advanced 802.11a summary',
        'show radius summary',
        'show acl summary',
        'show redundancy summary'
    ]
}

def determine_device_type(vendor, os_version, hostname):
    vendor = vendor.lower()
    os_version_lower = os_version.lower() if os_version else ""
    if 'nexus' in vendor or 'nx-os' in os_version_lower:
        return 'cisco_nxos'
    elif 'wlc' in vendor or 'aireos' in os_version_lower:
        return 'cisco_wlc'
    else:
        return 'cisco_ios'

def extract_model(device_type, version_output, inventory_output, os_version_hint):
    model = "UnknownModel"
    if device_type == 'cisco_wlc':
        match = re.search(r'PID:\s*(\S+)', inventory_output)
        if match:
            model = match.group(1)
        else:
            model = "AIR-CT3504-K9"
    elif device_type == 'cisco_nxos':
        match = re.search(r'Hardware:\s*(.+?)\r?\n', version_output)
        if match:
            model = match.group(1).replace(' ', '_').strip()
        else:
            match = re.search(r'PID:\s*(\S+)', inventory_output)
            if match:
                model = match.group(1)
    elif device_type == 'cisco_ios':
        match = re.search(r'Model [Nn]umber\s*:\s*(\S+)', version_output)
        if not match:
            match = re.search(r'PID:\s*(\S+)', inventory_output)
        if match:
            model = match.group(1)
        else:
            if 'C9606R' in os_version_hint: model = 'C9606R'
            elif '9300' in os_version_hint: model = 'C9300'
            elif '9200' in os_version_hint: model = 'C9200'
            elif '3850' in os_version_hint: model = 'C3850'
            elif '2960' in os_version_hint: model = 'C2960'
    return re.sub(r'[<>:"/\\|?*]', '_', model)

def process_device(dev, timestamp, raw_dir):
    ip = dev.get('IP', '').strip()
    if not ip: return
    
    username = dev.get('Username', '').strip()
    password = dev.get('Password', '').strip()
    secret = dev.get('Secret', '').strip()
    hostname = dev.get('Hostname', '').strip()
    vendor = dev.get('Vendor', '').strip()
    os_hint = dev.get('OS_Version', '').strip()
    
    device_type = determine_device_type(vendor, os_hint, hostname)
    print(f"\n[{ip}] Connecting to {hostname} ({device_type})...")
    
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
            if device_type in ('cisco_ios', 'cisco_nxos'):
                try:
                    net_connect.enable()
                except Exception as e:
                    print(f"[{ip}] Warning: Could not enter enable mode: {e}")
                
            if device_type == 'cisco_wlc':
                net_connect.send_command('config paging disable')
            else:
                net_connect.send_command('terminal length 0')
            
            try:
                version_out = net_connect.send_command('show version' if device_type != 'cisco_wlc' else 'show sysinfo')
                inventory_out = net_connect.send_command('show inventory')
                real_hostname = net_connect.find_prompt().replace('#','').replace('>','')
            except Exception as e:
                version_out = ""
                inventory_out = ""
                real_hostname = hostname
                print(f"[{ip}] Warning: Failed to get initial facts: {e}")
            
            real_model = extract_model(device_type, version_out, inventory_out, os_hint)
            safe_hostname = re.sub(r'[<>:"/\\|?*]', '_', real_hostname)
            
            file_base = f"{safe_hostname}_{ip}_{real_model}_{timestamp}"
            cmds_to_run = list(RAW_COMMANDS[device_type])
            
            if device_type == 'cisco_ios' and 'C9606R' in real_model:
                cmds_to_run.extend(['show module', 'show redundancy'])
            
            raw_filepath = os.path.join(raw_dir, f"{file_base}_raw.txt")
            print(f"[{ip}] Fetching RAW data into {file_base}_raw.txt ...")
            
            with open(raw_filepath, 'w', encoding='utf-8') as out_f:
                for cmd in cmds_to_run:
                    out_f.write(f"==========================================================\n")
                    out_f.write(f"COMMAND: {cmd}\n")
                    out_f.write(f"==========================================================\n")
                    try:
                        timeout = 120 if 'running-config' in cmd or 'run-config' in cmd else 30
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

    devices = []
    with open(args.inventory, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get('IP') or row.get('IP', '').strip().startswith('#'):
                continue
            devices.append(row)
            
    print(f"Loaded {len(devices)} devices from {args.inventory}.")
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
