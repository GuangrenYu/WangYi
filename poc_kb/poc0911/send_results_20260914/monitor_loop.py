"""后台监控：每 120s 快照发包进度，直到发送结束或超时（5h）。"""
import json
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

OUT = Path(__file__).parent / "monitor.log"
RESULTS = Path(__file__).parent / "send_results.json"
SEND_OUTPUT = Path(r"D:\Docker\tmp\claude\F--wangyi-0\f6b49e9a-20c8-4f6d-9cbb-29e7ef7f21e5\tasks\bjbb174p2.output")
TOTAL = 2269
INTERVAL = 120
MAX_ITER = 150  # 5 小时上限


def snapshot() -> str:
    n = 0
    dpt = h3c = hit = ok = 0
    last = ""
    if RESULTS.exists():
        try:
            d = json.loads(RESULTS.read_text(encoding="utf-8"))
            recs = d.get("records", [])
            n = len(recs)
            ok = sum(1 for r in recs if r.get("success"))
            hit = sum(1 for r in recs if r.get("hit"))
            dpt = sum(1 for r in recs if r.get("hit_dptech"))
            h3c = sum(1 for r in recs if r.get("hit_h3c"))
            if recs:
                last = recs[-1]["cve_id"]
        except Exception:
            pass
    return f"已发 {n}/{TOTAL} | 成功 {ok} | 严格命中 {hit} | 迪普 {dpt} | 华三 {h3c} | 最后 {last}"


def done() -> bool:
    txt = ""
    if SEND_OUTPUT.exists():
        try:
            txt = SEND_OUTPUT.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            pass
    return ("完成。" in txt) or ("Traceback" in txt) or ("Error" in txt and "已发" not in txt)


with OUT.open("a", encoding="utf-8") as f:
    f.write(f"=== monitor start {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
    prev_n = -1
    stall = 0
    for i in range(MAX_ITER):
        time.sleep(INTERVAL)
        line = f"[{time.strftime('%H:%M:%S')}] {snapshot()}"
        print(line, flush=True)
        f.write(line + "\n")
        f.flush()
        n = 0
        if RESULTS.exists():
            try:
                n = len(json.loads(RESULTS.read_text(encoding="utf-8")).get("records", []))
            except Exception:
                pass
        if n == prev_n:
            stall += 1
        else:
            stall = 0
        prev_n = n
        if done() and n >= TOTAL - 5:
            f.write("=== 检测到发送结束 ===\n")
            break
        if stall >= 15:  # 30 分钟无进展且未结束
            f.write("=== 停滞告警：30 分钟无进展 ===\n")
            stall = 0
    f.write(f"=== monitor exit {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
