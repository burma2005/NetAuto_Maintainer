"""介面錯誤檢查 — 離線解析。

1. 解析 collect_show_interfaces.py 產出的 raw_interfaces/*_interfaces.txt（本次計數）。
2. 遞迴掃描歷史定保 raw（*_raw.txt，含 show logging 者）找出 Link Flapping：
   ① 曾因 link-flap 被 err-disable（show interfaces status err-disabled / %PM-4-ERR_DISABLE）
   ② 單份 log 內同一介面 %LINK-3-UPDOWN down 次數 >= threshold
   跨次採集重複出現之同一事件以時間戳去重。

用法：
  python scripts/analyze_interfaces.py -c output_interface_check/raw_interfaces \
      -H <歷史定保根目錄> -o output_interface_check/interface_analysis.json
"""
import argparse
import glob
import json
import os
import re
from collections import defaultdict
from datetime import datetime

SHORT = [
    ("TwentyFiveGigE", "Twe"), ("HundredGigE", "Hu"), ("FortyGigabitEthernet", "Fo"),
    ("TenGigabitEthernet", "Te"), ("AppGigabitEthernet", "Ap"), ("GigabitEthernet", "Gi"),
    ("FastEthernet", "Fa"), ("Port-channel", "Po"),
]


def short(name):
    for long_, s in SHORT:
        if name.startswith(long_):
            return s + name[len(long_):]
    return name


def sections(text):
    """回傳 {command: output}"""
    parts = re.split(r"={20,}\r?\nCOMMAND: (.+?)\r?\n={20,}\r?\n", text)
    return {parts[i].strip(): parts[i + 1] for i in range(1, len(parts) - 1, 2)}


# ---------------- 1. 本次 show interfaces ----------------
INT_HDR = re.compile(r"^(\S+) is (.+?), line protocol is (\S+)(?: \((.+?)\))?\s*$", re.M)
NUM_FIELDS = {
    "input_packets": r"(\d+) packets input",
    "runts": r"(\d+) runts",
    "giants": r"(\d+) giants",
    "input_errors": r"(\d+) input errors",
    "crc": r"(\d+) CRC",
    "frame": r"(\d+) frame",
    "overrun": r"(\d+) overrun",
    "ignored": r"(\d+) ignored",
    "output_errors": r"(\d+) output errors",
    "collisions": r"(\d+) collisions",
    "resets": r"(\d+) interface resets",
    "babbles": r"(\d+) babbles",
    "late_collision": r"(\d+) late collision",
    "lost_carrier": r"(\d+) lost carrier",
    "no_carrier": r"(\d+) no carrier",
    "output_drops": r"Total output drops: (\d+)",
}
CNT_COLS = {"Align-Err": "align_err", "FCS-Err": "fcs_err", "Xmit-Err": "xmit_err", "Rcv-Err": "rcv_err",
            "UnderSize": "undersize", "OutDiscards": "out_discards", "OverSize": "oversize",
            "Single-Col": "single_col", "Multi-Col": "multi_col", "Late-Col": "late_col",
            "Excess-Col": "excess_col", "Carri-Sen": "carri_sen", "Runts": "cnt_runts"}
ALL_KEYS = list(NUM_FIELDS) + list(CNT_COLS.values())


def parse_current(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    sec = sections(text)
    m = re.match(r"(.+?)_(\d+\.\d+\.\d+\.\d+)_(\d{8}-\d{6})_", os.path.basename(path))
    host, ip, ts = m.groups()
    up = re.search(r"uptime is (.+)", sec.get("show version", ""))
    ver = re.search(r"Version (\S+),", sec.get("show version", ""))
    ifs = {}
    body = sec.get("show interfaces", "")
    hdrs = list(INT_HDR.finditer(body))
    for i, h in enumerate(hdrs):
        blk = body[h.end(): hdrs[i + 1].start() if i + 1 < len(hdrs) else len(body)]
        d = {"name": short(h.group(1)), "status": h.group(2), "proto": h.group(3),
             "state": h.group(4) or "", "desc": ""}
        dm = re.search(r"Description: (.*)", blk)
        if dm:
            d["desc"] = dm.group(1).strip()
        cm = re.search(r'Last clearing of "show interface" counters (\S+)', blk)
        d["last_clear"] = cm.group(1) if cm else ""
        for k, rx in NUM_FIELDS.items():
            mm = re.search(rx, blk)
            d[k] = int(mm.group(1)) if mm else 0
        ifs[d["name"]] = d
    cols = None
    for line in sec.get("show interfaces counters errors", "").splitlines():
        if line.startswith("Port"):
            cols = [CNT_COLS.get(c) for c in line.split()[1:]]
            continue
        parts = line.split()
        if cols and parts and len(parts) == len(cols) + 1 and parts[0] in ifs:
            for c, v in zip(cols, parts[1:]):
                if c and v.isdigit():
                    ifs[parts[0]][c] = int(v)
    for d in ifs.values():
        for k in ALL_KEYS:
            d.setdefault(k, 0)
    return {"host": host, "ip": ip, "collected": ts, "uptime": up.group(1).strip() if up else "",
            "version": ver.group(1) if ver else "", "interfaces": ifs}


# ---------------- 2. 歷史 link flapping ----------------
LINK_RX = re.compile(r"^(?:\d+:\s*)?(\*?)(\w{3}\s+\d+\s+\d{4}\s+[\d:.]+)\s*\w*:\s*"
                     r"%LINK-3-UPDOWN: Interface (\S+), changed state to (up|down)", re.M)
ERRDIS_LOG_RX = re.compile(r"^(?:\d+:\s*)?\*?(\w{3}\s+\d+\s+\d{4}\s+[\d:.]+)\s*\w*:\s*"
                           r"%PM-4-ERR_DISABLE: link-flap error detected on (\S+?),", re.M)


def to_dt(ts):
    try:
        return datetime.strptime(" ".join(ts.split()[:4]).split(".")[0], "%b %d %Y %H:%M:%S")
    except ValueError:
        return None


def max_in_window(ts_list, sec):
    t = sorted(x for x in (to_dt(s) for s in ts_list) if x)
    best, j = 0, 0
    for i in range(len(t)):
        while (t[i] - t[j]).total_seconds() > sec:
            j += 1
        best = max(best, i - j + 1)
    return best


def span_seconds(ts_list):
    t = [x for x in (to_dt(s) for s in ts_list) if x]
    return int((max(t) - min(t)).total_seconds()) if t else 0


def batch_folder(path, root):
    """raw 所屬之採集批次資料夾（跳過 raw_backups / output 等通用層）"""
    rel = os.path.relpath(os.path.dirname(path), root).split(os.sep)
    rel = [p for p in rel if p.lower() not in ("raw_backups", "output", ".")]
    return rel[0] if rel else os.path.basename(root)


def shorten_labels(names):
    """去除所有批次名稱共同的前綴 / 後綴，得到精簡標籤"""
    names = sorted(set(names))
    if len(names) < 2:
        return {n: n for n in names}
    pre = os.path.commonprefix(names)
    suf = os.path.commonprefix([n[::-1] for n in names])[::-1]
    out = {}
    for n in names:
        s = n[len(pre):len(n) - len(suf) if suf else None].strip("_- ")
        out[n] = s or n
    return out


def parse_history(root, threshold):
    files = sorted(glob.glob(os.path.join(root, "**", "*_raw.txt"), recursive=True))
    batches = {}
    flap = defaultdict(lambda: {"events": set(), "per_set": {}, "errdis_status": set(),
                                "errdis_log": set(), "unsynced": False, "host": ""})
    for f in files:
        m = re.match(r"(.+?)_(\d+\.\d+\.\d+\.\d+)_.*_(\d{8})-\d{6}_raw\.txt", os.path.basename(f))
        if not m:
            continue
        sec = sections(open(f, encoding="utf-8", errors="replace").read())
        if "show logging" not in sec:  # 非 IOS 設備（如 WLC）略過
            continue
        host, ip, date = m.groups()
        label = batch_folder(f, root)
        batches.setdefault(label, date)
        downs = defaultdict(list)
        for star, ts, ifn, st in LINK_RX.findall(sec["show logging"]):
            key = (ip, short(ifn))
            flap[key]["host"] = host
            flap[key]["events"].add((ts, st))
            if star:
                flap[key]["unsynced"] = True
            if st == "down":
                downs[short(ifn)].append(ts)
        for ifn, lst in downs.items():
            flap[(ip, ifn)]["per_set"][label] = {"downs": len(lst), "first": lst[0], "last": lst[-1],
                                                 "max_1h": max_in_window(lst, 3600), "span_s": span_seconds(lst)}
        for ts, ifn in ERRDIS_LOG_RX.findall(sec["show logging"]):
            flap[(ip, short(ifn))]["errdis_log"].add((label, ts))
            flap[(ip, short(ifn))]["host"] = host
        for line in sec.get("show interfaces status err-disabled", "").splitlines():
            p = line.split()
            if len(p) >= 3 and "link-flap" in p and "err-disabled" in p:
                flap[(ip, short(p[0]))]["errdis_status"].add(label)
                flap[(ip, short(p[0]))]["host"] = host
    short_map = shorten_labels(batches)
    out = []
    for (ip, ifn), v in flap.items():
        max_single = max([s["downs"] for s in v["per_set"].values()] or [0])
        out.append({"ip": ip, "host": v["host"], "iface": ifn,
                    "unique_downs": sum(1 for _, st in v["events"] if st == "down"),
                    "max_single_log": max_single,
                    "per_set": {short_map[k]: s for k, s in v["per_set"].items()},
                    "errdis_status": sorted(short_map[k] for k in v["errdis_status"]),
                    "errdis_log": sorted((short_map[k], t) for k, t in v["errdis_log"]),
                    "unsynced": v["unsynced"],
                    "is_flap": max_single >= threshold or bool(v["errdis_status"]) or bool(v["errdis_log"])})
    return {short_map[k]: d for k, d in batches.items()}, out


def main():
    ap = argparse.ArgumentParser(description="解析 show interfaces 與歷史 Link Flapping")
    ap.add_argument("-c", "--current-dir", required=True, help="raw_interfaces 目錄")
    ap.add_argument("-H", "--history-root", required=True, help="歷史定保根目錄（遞迴搜尋 *_raw.txt）")
    ap.add_argument("-o", "--output", required=True, help="輸出 JSON 路徑")
    ap.add_argument("--threshold", type=int, default=3, help="單份 log 內 LINK down 次數門檻（預設 3）")
    args = ap.parse_args()

    cur = [parse_current(p) for p in sorted(glob.glob(os.path.join(args.current_dir, "*_interfaces.txt")))]
    batches, hist = parse_history(args.history_root, args.threshold)
    json.dump({"current": cur, "batches": batches, "history": hist, "threshold": args.threshold},
              open(args.output, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"設備 {len(cur)} 台、歷史批次 {len(batches)} 次、flapping 介面 "
          f"{sum(1 for h in hist if h['is_flap'])} 個 -> {args.output}")


if __name__ == "__main__":
    main()
