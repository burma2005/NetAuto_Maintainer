"""單一 port 多 MAC 清查（找末端交換器下是否再串小 HUB / 小交換器）。

離線解析定保 raw_backups（show mac address-table / show running-config / show interfaces trunk /
show cdp neighbors detail / show lldp neighbors detail / show ip arp），列出
「扣除話機 MAC 後，同一 access port 上有 >= N 個不重複 MAC」的 port。

排除：trunk、Port-channel、CPU/VLAN 介面，以及 CDP/LLDP 對端為交換器或 AP 的 port。
話機 MAC 認定：該 port voice VLAN 內的 MAC、CDP Device ID 為 SEP<MAC>、LLDP 宣告為電話之 chassis MAC。

用法：
  python scripts/analyze_mac_per_port.py -r output/raw_backups -o output_mac_check --customer "客戶名稱" --pdf
"""
import argparse
import glob
import html
import os
import re
from collections import defaultdict

from analyze_interfaces import sections, short
from build_interface_report import CSS, natkey, to_pdf

E = html.escape
MAC_RX = re.compile(r"^\s*\*?\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(DYNAMIC|STATIC)\s+(\S+)", re.M | re.I)
SKIP_PORTS = ("Po", "CPU", "Vl", "Router", "Switch", "Drop")
VM_OUI = {"0800.27": "VirtualBox", "0015.5d": "Hyper-V", "0050.56": "VMware", "000c.29": "VMware",
          "0005.69": "VMware", "5254.00": "KVM/QEMU", "001c.42": "Parallels"}


def vm_hint(macs):
    """回傳如「VirtualBox 19」之虛擬機 MAC 提示"""
    cnt = defaultdict(int)
    for m in macs:
        if m[:7] in VM_OUI:
            cnt[VM_OUI[m[:7]]] += 1
    return "、".join(f"{k} {v}" for k, v in cnt.items())


def mac_fmt(s):
    s = re.sub(r"[^0-9a-f]", "", s.lower())
    return f"{s[0:4]}.{s[4:8]}.{s[8:12]}" if len(s) == 12 else ""


def parse_config(cfg):
    """回傳 {port: {"mode","access","voice","desc"}}"""
    ports = {}
    for m in re.finditer(r"^interface (\S+)\r?\n((?:[ \t].*\r?\n?)*)", cfg, re.M):
        body = m.group(2)
        g = lambda rx: (re.search(rx, body) or [None, ""])[1]
        ports[short(m.group(1))] = {"mode": g(r"switchport mode (\S+)"), "access": g(r"switchport access vlan (\d+)"),
                                    "voice": g(r"switchport voice vlan (\d+)"), "desc": g(r"description (.+)").strip()}
    return ports


def parse_neighbors(cdp, lldp):
    """回傳 (uplink_ports:set, phone_macs:{port:set})"""
    uplink, phones = set(), defaultdict(set)
    for blk in re.split(r"-{10,}", cdp):
        intf = re.search(r"Interface: (\S+?),", blk)
        if not intf:
            continue
        port = short(intf.group(1))
        dev = (re.search(r"Device ID: (\S+)", blk) or [None, ""])[1]
        caps = (re.search(r"Capabilities: (.+)", blk) or [None, ""])[1]
        plat = (re.search(r"Platform: ([^,]+)", blk) or [None, ""])[1]
        if "Phone" in caps or re.match(r"SEP[0-9A-Fa-f]{12}$", dev):
            if re.match(r"SEP[0-9A-Fa-f]{12}$", dev):
                phones[port].add(mac_fmt(dev[3:]))
        elif "Switch" in caps or "Trans-Bridge" in caps or "AIR-" in plat or "Router" in caps:
            uplink.add(port)
    for blk in re.split(r"-{10,}", lldp):
        intf = re.search(r"Local Intf: (\S+)", blk)
        if not intf:
            continue
        port = short(intf.group(1))
        chassis = mac_fmt((re.search(r"Chassis id: (\S+)", blk) or [None, ""])[1])
        enabled = (re.search(r"Enabled Capabilities: (.+)", blk) or [None, ""])[1]
        caps = set(re.findall(r"\b([BTWRSC])\b", enabled))
        if "T" in caps and chassis:
            phones[port].add(chassis)
        elif caps & {"B", "W", "R"}:
            uplink.add(port)
    return uplink, phones


def main():
    ap = argparse.ArgumentParser(description="單一 access port 多 MAC 清查（找串接 HUB）")
    ap.add_argument("-r", "--raw-dir", required=True, help="定保 raw_backups 目錄")
    ap.add_argument("-o", "--output-dir", required=True)
    ap.add_argument("--min-macs", type=int, default=2, help="扣除話機後之 MAC 數門檻（預設 2）")
    ap.add_argument("--customer", default="")
    ap.add_argument("--pdf", action="store_true")
    args = ap.parse_args()

    devs, arp = [], {}
    for f in sorted(glob.glob(os.path.join(args.raw_dir, "*_raw.txt"))):
        sec = sections(open(f, encoding="utf-8", errors="replace").read())
        if "show mac address-table" not in sec:
            continue
        m = re.match(r"(.+?)_(\d+\.\d+\.\d+\.\d+)_.*_(\d{8})-(\d{4})\d{2}_raw\.txt", os.path.basename(f))
        devs.append((m.groups(), sec))
        for ip_, mac in re.findall(r"Internet\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})",
                                   sec.get("show ip arp", "")):
            arp.setdefault(mac, ip_)

    results, stat = {}, defaultdict(int)
    for (host, ip, date, hm), sec in devs:
        cfg = parse_config(sec.get("show running-config", ""))
        uplink, phones = parse_neighbors(sec.get("show cdp neighbors detail", ""), sec.get("show lldp neighbors detail", ""))
        trunks = {short(l.split()[0]) for l in sec.get("show interfaces trunk", "").splitlines()
                  if re.match(r"^\S+\s+(on|auto|desirable)\b", l)}
        per_port = defaultdict(list)
        for vlan, mac, typ, port in MAC_RX.findall(sec["show mac address-table"]):
            per_port[short(port)].append((vlan, mac.lower()))
        rows = []
        for port, entries in per_port.items():
            c = cfg.get(port, {})
            if (port.startswith(SKIP_PORTS) or port in trunks or c.get("mode") == "trunk" or port in uplink):
                stat["skipped"] += 1 if len({m for _, m in entries}) >= 2 else 0
                continue
            voice = c.get("voice", "")
            phone = {m for v, m in entries if voice and v == voice} | phones.get(port, set())
            data = sorted({(v, m) for v, m in entries if m not in phone}, key=lambda x: x[1])
            data_macs = sorted({m for _, m in data})
            if len(data_macs) >= args.min_macs:
                vl = {m: sorted({v for v, mm in data if mm == m}) for m in data_macs}
                rows.append({"port": port, "vlan": c.get("access") or "/".join(sorted({v for v, _ in data})),
                             "desc": c.get("desc", ""), "phone": len(phone), "macs": data_macs, "vl": vl})
        if rows:
            results[(host, ip)] = sorted(rows, key=lambda r: natkey(r["port"]))
        stat["date"] = f"{date[:4]}/{date[4:6]}/{date[6:]} {hm[:2]}:{hm[2:]}"

    n_ports = sum(len(v) for v in results.values())
    n_macs = sum(len(r["macs"]) for v in results.values() for r in v)
    title = f"{args.customer} 單一 Port 多 MAC 清查（串接 HUB 檢查）".strip()

    body = [f"<h1>{E(title)}</h1>",
            f'<div class="meta"><b>資料來源</b> 定保採集 {stat["date"]}　<b>範圍</b> {len(devs)} 台交換器（show mac address-table）'
            f'<br><b>判定</b> access port 上扣除話機 MAC 後，仍有 ≥ {args.min_macs} 個不重複 MAC'
            f'<br><b>排除</b> trunk、Port-channel、CDP/LLDP 對端為交換器 / AP 之 port（{stat["skipped"]} 個多 MAC 之上行 port 未列）</div>',
            f'<div class="stats"><div class="stat red"><b>{n_ports}</b>個 port 疑似串接</div>'
            f'<div class="stat"><b>{len(results)}</b>台交換器</div><div class="stat"><b>{n_macs}</b>個 MAC</div></div>',
            "<table><thead><tr><th>Port</th><th>VLAN</th><th>描述</th><th>MAC 數</th><th>MAC 位址（IP）</th></tr></thead><tbody>"]
    md = [f"# {title}", "", f"- 資料來源：定保採集 {stat['date']}，{len(devs)} 台交換器",
          f"- 判定：access port 扣除話機 MAC 後 ≥ {args.min_macs} 個不重複 MAC；排除 trunk / Port-channel / CDP・LLDP 對端交換器或 AP",
          f"- 結果：{n_ports} 個 port（{len(results)} 台交換器）", "",
          "| 設備 | Port | VLAN | 描述 | MAC 數 | MAC 位址（IP） |", "|---|---|---|---|---:|---|"]
    for (host, ip), rows in sorted(results.items(), key=lambda kv: natkey(kv[0][0])):
        body.append(f'<tr class="dev"><td colspan="5">{E(host)}<span>{ip}　{len(rows)} 個 port</span></td></tr>')
        for r in rows:
            macs = "、".join(f'{m}{f"（{arp[m]}）" if m in arp else ""}' for m in r["macs"])
            vm = vm_hint(r["macs"])
            cnt = (f'{len(r["macs"])}' + (f'（另有話機 {r["phone"]}）' if r["phone"] else "")
                   + (f'（含 VM：{vm}）' if vm else ""))
            hot = ' class="hot"' if len(r["macs"]) >= 3 and not vm else ""
            body.append(f'<tr><td class="port">{E(r["port"])}</td><td class="st">{E(r["vlan"])}</td><td class="desc">{E(r["desc"])}</td>'
                        f'<td{hot} style="white-space:nowrap">{E(cnt)}</td><td style="font-family:Consolas,monospace;font-size:7.4pt">{E(macs)}</td></tr>')
            md.append(f"| {host} | {r['port']} | {r['vlan']} | {r['desc']} | {cnt} | {macs} |")
    body.append("</tbody></table>")
    body.append('<div class="note">紅字：扣除話機後 ≥ 3 個 MAC 且非虛擬機 MAC。IP 取自各交換器 ARP 表（查無則不顯示）。'
                "「含 VM」＝MAC 前綴屬 VirtualBox / Hyper-V / VMware / KVM 等虛擬化平台，多為單一主機上之虛擬機而非 HUB。"
                "USB 網卡、Docking、多網卡設備也可能產生多個 MAC，請現場確認。</div>")

    os.makedirs(args.output_dir, exist_ok=True)
    html_path = os.path.join(args.output_dir, "mac_port_check.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(f'<!DOCTYPE html>\n<html lang="zh-TW"><head><meta charset="UTF-8"><title>{E(title)}</title>'
                f"<style>{CSS}</style></head><body>\n" + "\n".join(body) + "\n</body></html>\n")
    with open(os.path.join(args.output_dir, "mac_port_check.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")
    print(f"疑似串接 port {n_ports} 個（{len(results)} 台）-> {html_path}")
    if args.pdf:
        to_pdf(html_path, os.path.join(args.output_dir, "mac_port_check.pdf"))


if __name__ == "__main__":
    main()
