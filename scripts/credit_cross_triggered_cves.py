#!/usr/bin/env python3
"""跨 CVE 认领：把「别的 PoC 打出、但告警点名了本 CVE」的证据归档到本 CVE 下。

背景：迪普/H3C 的一条特征常覆盖同族的多个 CVE。例如 S2-008 的特征一条规则同时点名
`|CVE-2012-0391|CVE-2012-0392|`——只要发了 0392 的 PoC，0391 也会被点名。这种告警
对本 CVE 而言同样算「已复现」，只是触发它的那次发送挂在了兄弟 CVE 名下。

做法：对每个待认领 CVE，在 IPS 日志里找点名它的告警，再回溯到"告警入库前 4 分钟内"
的那次发送（本轮重发记录 或 output/web_runs 的历史记录），把那次发送的 PoC 与 pcap
复制到本 CVE 的归档目录，result.json 里写明 credited_by。

只读内网服务与本地文件，不调 LLM、不碰公网。
"""

from __future__ import annotations

import json
import re
import shutil
import sys
import time
from datetime import datetime
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

RESEND = ROOT / "output" / "resend_20260917"
UNVERIFIED = RESEND / "unverified_success_cves.json"
ARCHIVE = ROOT / "archives" / "successful_cve_0917"
IPS_LOGS = "http://10.20.1.240:3013/api/logs"

LOG_START = "2026-09-16 00:00:00"
LOG_END = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
# 告警入库时刻相对发送时刻允许的偏差（采集/入库有延迟，华三尤其明显）
TRIGGER_LOOKBACK = 240.0
TRIGGER_SLACK = 5.0

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
METHOD_RE = re.compile(r"^([A-Z]{3,8})\s+(\S+)")


def log(msg: str) -> None:
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with (RESEND / "credit.log").open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def load_resend_module():
    spec = spec_from_file_location("resend_failed_cves", ROOT / "scripts" / "resend_failed_cves.py")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_archive_module():
    """复用归档脚本的 README 渲染，口径保持一致。"""
    spec = spec_from_file_location(
        "archive_successful_and_update_xlsx", ROOT / "scripts" / "archive_successful_and_update_xlsx.py")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def epoch(stamp: str) -> float:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return time.mktime(time.strptime(str(stamp)[:26], fmt))
        except (ValueError, TypeError):
            continue
    return float("inf")


def request_line(raw: str) -> str:
    first = str(raw or "").replace("\r\n", "\n").split("\n", 1)[0].strip()
    m = METHOD_RE.match(first)
    return m.group(2) if m else first


# 请求行短于这个长度就没有区分度（`POST /` 之类），不足以作为同族证据
MIN_DISTINCTIVE_LINE = 16


def line_matches(sent_target: str, logged: str) -> bool:
    a = str(sent_target or "").strip()
    b = METHOD_RE.sub(lambda m: m.group(2), str(logged or "").strip())
    if not a or not b:
        return False
    short, long_ = sorted((a, b), key=len)
    return len(short) >= MIN_DISTINCTIVE_LINE and long_.startswith(short)


def fetch_alarms() -> list[dict]:
    out: list[dict] = []
    page = 1
    with httpx.Client(trust_env=False, timeout=90) as client:
        while page <= 40:
            resp = client.get(IPS_LOGS, params={
                "start_time": LOG_START, "end_time": LOG_END,
                "page": page, "page_size": 1000,
            })
            data = resp.json()
            records = data.get("data") or []
            out += records
            if len(records) < 1000 or len(out) >= int(data.get("total") or 0):
                break
            page += 1
    return out


def alarm_cves(rec: dict) -> set[str]:
    fields = rec.get("fields") if isinstance(rec.get("fields"), dict) else {}
    text = " ".join([str(rec.get("cve_list") or ""), str(fields.get("CVE") or ""),
                     str(rec.get("attack_name") or "")])
    return {m.group(0).upper() for m in CVE_RE.finditer(text)}


class Send:
    """一次发送的证据来源。"""

    def __init__(self, cve, sent_epoch, target, poc, pcap, note):
        self.cve = cve
        self.sent_epoch = sent_epoch
        self.target = target      # 告警里的请求行（用于与告警比对）
        self.poc = poc            # (文件名, 内容) 或 None
        self.pcap = pcap          # ('url', url) / ('file', Path) 或 None
        self.note = note


def collect_sends(resend) -> list[Send]:
    sends: list[Send] = []
    poc_index = resend.build_poc_index()
    nuclei_index = resend.build_nuclei_index()

    for path, modality in ((RESEND / "results.jsonl", "http"), (RESEND / "results_nuclei.jsonl", "nuclei")):
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if not rec.get("cve") or not rec.get("sent_epoch"):
                continue
            task = {"cve": rec["cve"]}
            poc = None
            if modality == "http":
                raw, label, src = resend.resolve_poc(task, poc_index)
                if raw:
                    content = resend.normalize_raw_http(raw, resend.TARGET_HOST)
                    poc = ("poc.http", content, raw, f"{label}:{src}")
            else:
                yaml_text, label, src = resend.resolve_nuclei(task, nuclei_index)
                if yaml_text:
                    poc = ("poc.yaml", yaml_text, "", f"{label}:{src}")
            sends.append(Send(
                rec["cve"], float(rec["sent_epoch"]),
                rec.get("request_target") or (poc[2] and request_line(poc[2])) or "",
                poc,
                ("url", rec["pcap_url"]) if rec.get("pcap_url") else None,
                f"本轮{modality}重发",
            ))

    for result_path in ROOT.glob("output/web_runs/*/*/result.json"):
        try:
            data = json.loads(result_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        sent = epoch(data.get("timestamp") or "")
        if sent == float("inf"):
            continue
        cve = str(data.get("cve_id") or result_path.parent.name)
        raw_http = str(data.get("poc_raw_http") or "")
        poc = None
        if raw_http:
            poc = ("poc.http", raw_http, raw_http, f"web_runs:{result_path.parent.parent.name}")
        else:
            yaml_file = result_path.parent / "poc.yaml"
            if yaml_file.exists():
                text = yaml_file.read_text(encoding="utf-8", errors="ignore")
                poc = ("poc.yaml", text, "", f"web_runs:{result_path.parent.parent.name}")
        pcap = None
        local = str(data.get("pcap_file_path") or "")
        if local and Path(local).is_file():
            pcap = ("file", Path(local))
        else:
            url = str((data.get("executor_result") or {}).get("pcap_download_url") or "")
            if url:
                pcap = ("url", url)
        sends.append(Send(cve, sent, request_line(raw_http), poc, pcap, "历史 web_runs 批次"))

    sends.sort(key=lambda s: s.sent_epoch)
    return sends


def pick_trigger(alarm: dict, sends: list[Send]) -> Send | None:
    """在告警入库时刻之前的一小段窗口里找触发它的那次发送。

    排序依据（分数越小越可信）：
    - 发送的 CVE 也在该告警的 cve_list 里 —— 说明就是这条特征覆盖的那一族，最强信号；
    - 告警的 HttpFirstLine 与发送的请求行前缀一致 —— 字节级印证；
    - 最后才看时间接近程度。
    """
    received = epoch(alarm.get("received_at") or "")
    if received == float("inf"):
        return None
    logged = str((alarm.get("fields") or {}).get("HttpFirstLine") or "")
    named = alarm_cves(alarm)
    best: tuple[float, Send] | None = None
    for send in sends:
        delta = received - send.sent_epoch
        if delta < -TRIGGER_SLACK or delta > TRIGGER_LOOKBACK:
            continue
        named_same = send.cve in named
        # 两道硬门槛：要么发送的 CVE 就在该告警的 cve_list 里，要么请求行足够长且一致。
        # 都不满足说明只是时间上凑巧，宁可判「回溯不到」也不认领错。
        if not named_same and not line_matches(send.target, logged):
            continue
        score = delta + (0.0 if named_same else 250.0)
        if not line_matches(send.target, logged):
            score += 120.0
        if best is None or score < best[0]:
            best = (score, send)
    return best[1] if best else None


def materialize(target: str, alarm: dict, trigger: Send) -> dict:
    dest = ARCHIVE / target
    dest.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}

    if trigger.poc:
        name, content, _raw, origin = trigger.poc
        (dest / name).write_text(content, encoding="utf-8")
        written["poc"] = f"{name} <- {origin}"

    pcap_name = ""
    if trigger.pcap:
        kind, value = trigger.pcap
        try:
            if kind == "file":
                shutil.copy2(value, dest / value.name)
                pcap_name = value.name
            else:
                from cve_hunter.evidence import _remote_pcap_name
                with httpx.stream("GET", value, timeout=httpx.Timeout(90, connect=10),
                                  follow_redirects=True, trust_env=False) as response:
                    response.raise_for_status()
                    pcap_name = _remote_pcap_name(
                        response.headers.get("content-disposition", ""), "", value)
                    pending = dest / (pcap_name + ".part")
                    with pending.open("wb") as handle:
                        for chunk in response.iter_bytes():
                            handle.write(chunk)
                    with pending.open("rb") as handle:
                        header = handle.read(24)
                    if len(header) < 24 or header[:4] not in {
                        b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
                        b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a",
                    }:
                        raise ValueError("下载内容不是有效的 PCAP/PCAPNG 文件头")
                    pending.replace(dest / pcap_name)
            written["pcap"] = pcap_name
        except Exception as exc:  # noqa: BLE001
            written["pcap_error"] = f"{type(exc).__name__}: {exc}"

    result = {
        "cve_id": target,
        "status": "SUCCESS",
        "success_level": "ips_cve_match",
        "credited_via": "cross_cve_trigger",
        "note": "IPS 日志点名该 CVE，但触发它的是兄弟 CVE 的 PoC（同一台设备的同一条特征）",
        "archived_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "credited_by": {
            "sent_cve": trigger.cve,
            "sent_at": datetime.fromtimestamp(trigger.sent_epoch).strftime("%Y-%m-%d %H:%M:%S"),
            "origin": trigger.note,
            "request_line": trigger.target,
        },
        "alarm": {
            "source": alarm.get("source"),
            "received_at": alarm.get("received_at"),
            "cve_list": alarm.get("cve_list"),
            "attack_name": alarm.get("attack_name"),
            "HttpFirstLine": (alarm.get("fields") or {}).get("HttpFirstLine"),
        },
        "poc": written,
    }
    (dest / "result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def main() -> int:
    resend = load_resend_module()
    if not UNVERIFIED.exists():
        log("没有 unverified_success_cves.json，先跑 archive_successful_and_update_xlsx.py")
        return 1
    targets = json.loads(UNVERIFIED.read_text(encoding="utf-8"))
    log(f"待认领 {len(targets)} 个 CVE，拉取 IPS 日志 {LOG_START} ~ {LOG_END}")

    alarms = fetch_alarms()
    log(f"日志共 {len(alarms)} 条")
    by_cve: dict[str, list[dict]] = {}
    for rec in alarms:
        for cve in alarm_cves(rec):
            by_cve.setdefault(cve, []).append(rec)

    sends = collect_sends(resend)
    log(f"候选发送记录 {len(sends)} 条（本轮重发 + 历史 web_runs）")

    credited, no_alarm, no_trigger = [], [], []
    for cve in targets:
        found = sorted(by_cve.get(cve, []), key=lambda a: epoch(a.get("received_at") or ""), reverse=True)
        if not found:
            no_alarm.append(cve)
            log(f"  {cve}: 全库无点名告警，无法认领")
            continue
        hit = None
        for alarm in found:
            trigger = pick_trigger(alarm, sends)
            if trigger:
                hit = (alarm, trigger)
                break
        if not hit:
            no_trigger.append(cve)
            log(f"  {cve}: 有 {len(found)} 条点名告警，但回溯不到对应发送")
            continue
        alarm, trigger = hit
        info = materialize(cve, alarm, trigger)
        credited.append(cve)
        log(f"  ✓ {cve} ← 由 {trigger.cve} 的发送触发（{trigger.note}，"
            f"告警 {alarm.get('received_at')} {alarm.get('source')}）poc={list(info['poc'])}")
        time.sleep(0.2)

    # 不覆盖输入清单：认领结果另存，重跑时仍按同一份待认领集合处理（幂等）。
    (RESEND / "credit_result.json").write_text(json.dumps({
        "credited": credited, "no_alarm": no_alarm, "no_trigger": no_trigger,
        "still_unverified": sorted(no_alarm + no_trigger),
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    # 同步刷新归档清单
    archive_mod = load_archive_module()
    all_cves = sorted(p.name for p in ARCHIVE.iterdir() if p.is_dir())
    archive_mod.rewrite_readme(all_cves, sorted(no_alarm + no_trigger), sorted(credited))
    log(f"README 已刷新：归档 {len(all_cves)} 个（本次认领 {len(credited)} 个）")

    log(f"认领 {len(credited)} 个；无告警 {len(no_alarm)} 个：{' '.join(no_alarm)}")
    if no_trigger:
        log(f"有告警但回溯不到触发发送：{' '.join(no_trigger)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
