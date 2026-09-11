"""介面錯誤檢查 — 產出「實體線路異常快速檢視」報告（HTML / MD / 選用 PDF）。

只列有實體層錯誤（CRC / FCS / Align / Collision / Late Collision / Output Err）
或歷史 Link Flapping 的 port，依設備分組、依 port 編號排序，供現場查線使用。

用法：
  python scripts/build_interface_report.py -j output_interface_check/interface_analysis.json \
      -o output_interface_check --customer "客戶名稱" --pdf
"""
import argparse
import html
import json
import os
import re
import shutil
import subprocess
import tempfile

VIRTUAL = ("Vlan", "Loopback", "Null", "Tunnel", "Po")
ERR_FIELDS = [  # (欄位, 顯示名稱)
    ("align_err", "Align"), ("collisions", "Collision"), ("late_collision", "Late Collision"),
    ("excess_col", "Excess Collision"), ("output_errors", "Output Err"), ("xmit_err", "Xmit Err"),
]
E = html.escape

CSS = """
@page { size: A4 portrait; margin: 12mm 10mm; }
* { box-sizing: border-box; }
body { font-family: "Microsoft JhengHei", "PingFang TC", "Noto Sans TC", sans-serif; font-size: 9pt;
       color: #1a1a2e; background: #fff; margin: 0 auto; max-width: 190mm; padding: 6mm 4mm; }
h1 { font-size: 15pt; color: #1a3a6b; margin: 0 0 4px; border-bottom: 3px solid #1a3a6b; padding-bottom: 6px; }
.meta { font-size: 8pt; color: #5a6a8a; margin: 4px 0 8px; line-height: 1.7; }
.meta b { color: #1a3a6b; }
.stats { display: flex; gap: 8px; margin: 6px 0 10px; flex-wrap: wrap; }
.stat { background: #f6f8fc; border-left: 4px solid #2563ae; border-radius: 0 6px 6px 0; padding: 5px 10px; font-size: 8pt; }
.stat b { font-size: 12pt; color: #1a3a6b; margin-right: 3px; }
.stat.red { border-color: #dc2626; } .stat.red b { color: #b91c1c; }
.stat.org { border-color: #d97706; } .stat.org b { color: #b45309; }
table { width: 100%; border-collapse: collapse; font-size: 8pt; }
thead { display: table-header-group; }
thead th { background: #1a3a6b; color: #fff; text-align: left; padding: 5px 6px; font-size: 7.8pt; }
td { padding: 3px 6px; border-bottom: 1px solid #e8eef8; vertical-align: top; }
tr { break-inside: avoid; }
tr.dev td { background: #e8f0fe; color: #1a3a6b; font-weight: 700; padding: 5px 6px; border-top: 1.5px solid #93c5fd; }
tr.dev span { font-weight: 400; color: #5a6a8a; margin-left: 8px; }
td.port { font-family: Consolas, "Courier New", monospace; white-space: nowrap; }
td.st { white-space: nowrap; color: #5a6a8a; }
td.st.bad { color: #b91c1c; font-weight: 700; }
td.desc { color: #5a6a8a; max-width: 28mm; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.hot { color: #b91c1c; font-weight: 700; }
.note { font-size: 7.5pt; color: #5a6a8a; margin-top: 8px; line-height: 1.6; }
@media print { body { padding: 0; max-width: none; } }
"""


def natkey(s):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]


def fmt(n):
    return f"{n:,}"


def human_span(s):
    if s < 3600:
        return f"{max(s // 60, 1)} 分鐘"
    if s < 86400:
        return f"{s // 3600} 小時"
    return f"{s // 86400} 天"


def main():
    ap = argparse.ArgumentParser(description="產出實體線路異常快速檢視報告")
    ap.add_argument("-j", "--json", required=True)
    ap.add_argument("-o", "--output-dir", required=True)
    ap.add_argument("--customer", default="", help="報告標題上的客戶名稱（選填）")
    ap.add_argument("--crc-hot", type=int, default=1000, help="CRC 標紅門檻（預設 1000）")
    ap.add_argument("--flap-hot", type=int, default=20, help="1 小時內 down 次數標紅門檻（預設 20）")
    ap.add_argument("--pdf", action="store_true", help="以 Chrome/Edge headless 另存 PDF")
    args = ap.parse_args()

    D = json.load(open(args.json, encoding="utf-8"))
    batches = sorted(D["batches"].items(), key=lambda kv: kv[1])
    hist = {(h["ip"], h["iface"]): h for h in D["history"] if h["is_flap"]}
    devs = sorted(D["current"], key=lambda d: natkey(d["host"]))
    ip2host = {d["ip"]: d["host"] for d in devs}

    rows_by_dev, n_phys, cnt = {}, 0, {"crc": 0, "col": 0, "flap": 0}
    for d in devs:
        rows = {}
        for i in d["interfaces"].values():
            if i["name"].startswith(VIRTUAL):
                continue
            n_phys += 1
            errs, hot = [], False
            crc, fcs = i["crc"], i["fcs_err"]
            if crc or fcs:
                errs.append(f"CRC/FCS {fmt(max(crc, fcs))}" if crc == fcs else f"CRC {fmt(crc)} / FCS {fmt(fcs)}")
                hot |= max(crc, fcs) >= args.crc_hot
                cnt["crc"] += 1
            for k, label in ERR_FIELDS:
                if i[k] and not (k == "output_errors" and (i["collisions"] or i["late_collision"])):
                    errs.append(f"{label} {fmt(i[k])}")
            if i["collisions"] or i["late_collision"] or i["excess_col"]:
                cnt["col"] += 1
                hot |= bool(i["late_collision"])
            if errs:
                rows[i["name"]] = {"i": i, "errs": errs, "hot": hot}
        rows_by_dev[d["ip"]] = rows
    # 歷史 flapping（含目前已不存在於本次輸出的介面）
    for (ip, ifn), h in hist.items():
        cnt["flap"] += 1
        dev = next((d for d in devs if d["ip"] == ip), None)
        r = rows_by_dev.setdefault(ip, {}).setdefault(
            ifn, {"i": dev["interfaces"].get(ifn) if dev else None, "errs": [], "hot": False})
        if h["errdis_status"] or h["errdis_log"]:
            where = "、".join(sorted(set(h["errdis_status"]) | {b for b, _ in h["errdis_log"]}))
            r["flap"] = f"link-flap err-disabled（{where}）"
            r["flap_hot"] = True
        else:
            b, s = max(h["per_set"].items(), key=lambda kv: kv[1]["downs"])
            times = sum(1 for v in h["per_set"].values() if v["downs"] >= D["threshold"])
            r["flap"] = (f"down {s['downs']} 次 / {human_span(s['span_s'])}（{b}"
                         + (f"，{times} 次採集" if times > 1 else "") + "）")
            r["flap_hot"] = s["max_1h"] >= args.flap_hot

    total_ports = sum(len(v) for v in rows_by_dev.values())
    title = f"{args.customer} 實體線路異常快速檢視".strip()
    collected = devs[0]["collected"] if devs else ""
    cdate = f"{collected[:4]}/{collected[4:6]}/{collected[6:8]} {collected[9:11]}:{collected[11:13]}" if collected else ""
    bdesc = "、".join(f"{k}({v[4:6]}/{v[6:]})" for k, v in batches)
    cleared = sorted({i["last_clear"] for d in devs for i in d["interfaces"].values() if i.get("last_clear")})

    # ---------- HTML ----------
    body = [f"<h1>{E(title)}</h1>",
            f'<div class="meta"><b>採集時間</b> {cdate}　<b>範圍</b> {len(devs)} 台交換器 / {fmt(n_phys)} 個實體 port'
            f'<br><b>錯誤計數</b> show interfaces / show interfaces counters errors（計數器 Last clearing：{E("、".join(cleared))}，為累計值）'
            f'<br><b>Link Flap</b> 比對歷史 {len(batches)} 次採集 {E(bdesc)}：曾 link-flap err-disable，或單份 log 內 down ≥ {D["threshold"]} 次</div>',
            f'<div class="stats"><div class="stat"><b>{total_ports}</b>個異常 port</div>'
            f'<div class="stat red"><b>{cnt["crc"]}</b>CRC/FCS</div><div class="stat org"><b>{cnt["col"]}</b>Collision</div>'
            f'<div class="stat org"><b>{cnt["flap"]}</b>Link Flap</div></div>',
            "<table><thead><tr><th>Port</th><th>狀態</th><th>描述</th><th>錯誤訊息</th><th>Link Flap 紀錄</th></tr></thead><tbody>"]
    md = [f"# {title}", "", f"- 採集時間：{cdate}　範圍：{len(devs)} 台 / {n_phys} 個實體 port",
          f"- Link Flap：比對 {bdesc}；link-flap err-disable 或單份 log 內 down ≥ {D['threshold']} 次",
          f"- 異常 port {total_ports} 個（CRC/FCS {cnt['crc']}、Collision {cnt['col']}、Link Flap {cnt['flap']}）", "",
          "| 設備 | Port | 狀態 | 描述 | 錯誤訊息 | Link Flap 紀錄 |", "|---|---|---|---|---|---|"]
    for ip in sorted(rows_by_dev, key=lambda x: natkey(ip2host.get(x, x))):
        rows = rows_by_dev[ip]
        if not rows:
            continue
        host = ip2host.get(ip) or next(h["host"] for (hip, _), h in hist.items() if hip == ip)
        body.append(f'<tr class="dev"><td colspan="5">{E(host)}<span>{ip}　異常 {len(rows)} 個 port</span></td></tr>')
        for name in sorted(rows, key=natkey):
            r = rows[name]
            i = r["i"]
            st = (i["state"] or i["status"]) if i else "—"
            err = "、".join(r["errs"]) or "—"
            flap = r.get("flap", "—")
            body.append(f'<tr><td class="port">{E(name)}</td><td class="st{" bad" if "err-disabled" in st else ""}">{E(st)}</td>'
                        f'<td class="desc">{E(i["desc"] if i else "")}</td><td class="{"hot" if r["hot"] else ""}">{E(err)}</td>'
                        f'<td class="{"hot" if r.get("flap_hot") else ""}">{E(flap)}</td></tr>')
            md.append(f"| {host} | {name} | {st} | {i['desc'] if i else ''} | {err} | {flap} |")
    body.append("</tbody></table>")
    body.append(f'<div class="note">紅字：CRC/FCS ≥ {fmt(args.crc_hot)}、有 Late Collision、曾 link-flap err-disable，或 1 小時內 down ≥ {args.flap_hot} 次。'
                "「N 次採集」＝歷史採集中有 N 次達 flapping 門檻。錯誤計數為設備開機以來累計；建議排除後於維護時段清除計數器，下次再比對增量。</div>")

    os.makedirs(args.output_dir, exist_ok=True)
    html_path = os.path.join(args.output_dir, "interface_quickview.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(f'<!DOCTYPE html>\n<html lang="zh-TW"><head><meta charset="UTF-8"><title>{E(title)}</title>'
                f"<style>{CSS}</style></head><body>\n" + "\n".join(body) + "\n</body></html>\n")
    with open(os.path.join(args.output_dir, "interface_quickview.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")
    print(f"異常 port {total_ports} 個 -> {html_path}")

    if args.pdf:
        to_pdf(html_path, os.path.join(args.output_dir, "interface_quickview.pdf"))


def to_pdf(html_path, pdf_path):
    """Chrome/Edge headless 轉 PDF；路徑含非 ASCII 字元時 Chrome 會靜默失敗，故經暫存目錄中轉。"""
    cands = [r"C:\Program Files\Google\Chrome\Application\chrome.exe",
             r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
             r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
             shutil.which("chrome") or "", shutil.which("google-chrome") or "", shutil.which("msedge") or ""]
    exe = next((c for c in cands if c and os.path.exists(c)), None)
    if not exe:
        print("找不到 Chrome/Edge，請以瀏覽器開啟 HTML 後 Ctrl+P 另存 PDF。")
        return
    tmp = tempfile.mkdtemp(prefix="ifrpt_")
    src, dst = os.path.join(tmp, "r.html"), os.path.join(tmp, "r.pdf")
    shutil.copy(html_path, src)
    subprocess.run([exe, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                    f"--user-data-dir={os.path.join(tmp, 'prof')}", f"--print-to-pdf={dst}",
                    "file:///" + src.replace("\\", "/")], check=False, timeout=180)
    if os.path.exists(dst):
        shutil.copy(dst, pdf_path)
        print(f"PDF -> {pdf_path}")
    else:
        print("PDF 產生失敗，請以瀏覽器開啟 HTML 後 Ctrl+P 另存 PDF。")
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
