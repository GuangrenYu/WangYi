"""并行发包监控：每 120s 汇总 6 个 shard 的进度，直到全部完成或 5h 超时。"""
import json
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

OUT = Path(__file__).parent / "monitor.log"
D = Path(__file__).parent
TOTAL = 969
N_WORKERS = 6
INTERVAL = 120
MAX_ITER = 150  # 5h


def snapshot() -> tuple[int, int, int, int, int, int, int]:
    tot = ok = hit = dpt = h3c = gen = fail = 0
    for f in sorted(D.glob("send_results_shard*.json")):
        try:
            recs = json.loads(f.read_text(encoding="utf-8")).get("records", [])
        except Exception:
            continue
        tot += len(recs)
        ok += sum(1 for r in recs if r.get("success"))
        hit += sum(1 for r in recs if r.get("hit"))
        dpt += sum(1 for r in recs if r.get("hit_dptech"))
        h3c += sum(1 for r in recs if r.get("hit_h3c"))
        gen += sum(1 for r in recs if r.get("ips_match_count") and not r.get("hit"))
        fail += sum(1 for r in recs if not r.get("success"))
    return tot, ok, hit, dpt, h3c, gen, fail


def finished() -> int:
    n = 0
    for f in sorted(D.glob("worker*.log")):
        try:
            t = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if ("完成。" in t) or ("Traceback" in t) or ("POC 总数" in t and "已发" in t and "完成。" in t):
            n += 1
    return n


with OUT.open("a", encoding="utf-8") as f:
    f.write(f"=== rerun monitor start {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
    prev_tot = -1
    stall = 0
    for _ in range(MAX_ITER):
        time.sleep(INTERVAL)
        tot, ok, hit, dpt, h3c, gen, fail = snapshot()
        line = (f"[{time.strftime('%H:%M:%S')}] {tot}/{TOTAL} | 成功{ok} | "
                f"严格命中{hit} | 迪普{dpt} | 华三{h3c} | 仅通用{gen} | 失败{fail}")
        print(line, flush=True)
        f.write(line + "\n")
        f.flush()
        if tot == prev_tot:
            stall += 1
        else:
            stall = 0
        prev_tot = tot
        if tot >= TOTAL:
            f.write("=== 全部发送完成 ===\n")
            break
        if stall >= 10:
            f.write("=== 停滞告警：20 分钟无进展 ===\n")
            stall = 0
    f.write(f"=== rerun monitor exit {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
