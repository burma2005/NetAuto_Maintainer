"""
人力採集啟動器 (GUI)
====================
適用情境：設備清單已確定（型號、IP、帳密齊全，已跑過採集、清單完整）時，
不需要 AI Agent 逐步引導，直接由工程師點擊本腳本完成 RAW DATA 採集，
把 token 省下來，只讓 AI Agent 接手後續的報告分析。

流程：
  1. 跳出檔案視窗，請你選擇設備清單 inventory.csv
  2. 跳出資料夾視窗，請你選擇 RAW DATA 輸出位置（可取消，預設為清單同層的 output/）
  3. 呼叫既有的 collect_show_commands.py 進行並行 SSH 唯讀採集
  4. 完成後開啟輸出資料夾，並印出「交接給 AI Agent 做報告分析」的提示

本腳本全程唯讀，僅執行 show / get 類指令，不會變更任何設備設定。
"""

import os
import sys
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, os.pardir))
COLLECT_SCRIPT = os.path.join(SCRIPT_DIR, "collect_show_commands.py")


def check_dependencies():
    """確認 netmiko / yaml 已安裝，未安裝時給出明確指引。"""
    missing = []
    for mod in ("netmiko", "yaml"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        messagebox.showerror(
            "缺少相依套件",
            "偵測到尚未安裝必要套件：{}\n\n請先在命令列執行：\n    pip install -r requirements.txt".format(
                ", ".join(missing)
            ),
        )
        return False
    return True


def pick_inventory():
    return filedialog.askopenfilename(
        title="請選擇設備清單 inventory.csv（含 IP / 帳密）",
        initialdir=PROJECT_DIR,
        filetypes=[("CSV 設備清單", "*.csv"), ("所有檔案", "*.*")],
    )


def pick_output_dir(default_dir):
    chosen = filedialog.askdirectory(
        title="請選擇 RAW DATA 輸出資料夾（取消則用預設 output/）",
        initialdir=default_dir,
    )
    return chosen or default_dir


def open_folder(path):
    """跨平台開啟資料夾（主要供 Windows 雙擊情境）。"""
    try:
        if os.name == "nt":
            os.startfile(path)  # noqa: S606
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception:
        pass


def main():
    root = tk.Tk()
    root.withdraw()  # 只用對話框，不顯示主視窗

    if not check_dependencies():
        return

    inventory = pick_inventory()
    if not inventory:
        print("未選擇設備清單，結束。")
        return

    default_out = os.path.join(os.path.dirname(inventory), "output")
    output_dir = pick_output_dir(default_out)

    print("=" * 60)
    print("人力採集啟動")
    print("  設備清單 : {}".format(inventory))
    print("  輸出目錄 : {}".format(output_dir))
    print("=" * 60)
    print("開始並行 SSH 唯讀採集，請稍候……\n")

    cmd = [sys.executable, COLLECT_SCRIPT, "-i", inventory, "-o", output_dir]
    # 讓子行程直接輸出到本 console，工程師可即時看到每台設備進度
    result = subprocess.run(cmd)

    raw_dir = os.path.join(output_dir, "raw_backups")
    print()
    if result.returncode == 0:
        print("✅ 採集完成。RAW DATA 已存於：{}".format(raw_dir))
        # 印出交接提示，讓工程師直接複製給 AI Agent，AI 不需再花 token 採集
        handoff = (
            "\n----------- 交接給 AI Agent（複製以下提示即可）-----------\n"
            "閱讀 {skill}\n\n"
            "RAW DATA 已由人力採集完成，位於：{raw}\n"
            "請直接從『階段 2：離線分析』開始，跳過階段 1 線上採集。\n"
            "本季輸出：{out}\n\n"
            "接手後續離線分析、CVE 比對與報告產出。\n"
            "----------------------------------------------------------\n"
        ).format(
            skill=os.path.join(PROJECT_DIR, "SKILL.md"),
            raw=raw_dir,
            out=output_dir,
        )
        print(handoff)
        open_folder(output_dir)
        messagebox.showinfo(
            "採集完成",
            "RAW DATA 採集完成！\n\n輸出位置：\n{}\n\n"
            "接下來把本視窗（或命令列）印出的『交接提示』複製給 AI Agent，"
            "即可讓 AI 只做報告分析、不需重新採集。".format(raw_dir),
        )
    else:
        print("⚠️ 採集腳本回傳非零結束碼（{}），請檢視上方訊息。".format(result.returncode))
        messagebox.showwarning(
            "採集未完全成功",
            "採集過程可能有錯誤（結束碼 {}）。\n請檢視命令列視窗的訊息，"
            "並確認 output/ 內是否已產生 failed_devices 相關紀錄。".format(result.returncode),
        )


if __name__ == "__main__":
    main()
