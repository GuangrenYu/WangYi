
import os, subprocess, sys, time
from datetime import datetime
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'output' / 'queue'
LOG = OUT / 'watchdog_until_21.log'

def log(m):
    line=f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {m}"
    print(line, flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    with LOG.open('a', encoding='utf-8') as f:
        f.write(line+'\n')

def night_running():
    try:
        out=subprocess.check_output('ps -ef', shell=True, text=True, errors='replace')
    except Exception:
        return False
    return any('night_runner_until_21.py' in line and 'python' in line.lower() for line in out.splitlines())

def start_night():
    out = open(OUT/'night_runner_until_21.out','a',encoding='utf-8')
    p=subprocess.Popen([sys.executable, str(ROOT/'tools'/'night_runner_until_21.py')], cwd=str(ROOT), stdout=out, stderr=subprocess.STDOUT, env={**os.environ,'PYTHONIOENCODING':'utf-8','PYTHONUTF8':'1'})
    (OUT/'night_runner_until_21.pid').write_text(str(p.pid), encoding='utf-8')
    log(f'started night_runner pid={p.pid}')

log('watchdog start')
while datetime.now().hour < 21:
    if not night_running():
        log('night runner missing; restart')
        start_night()
    else:
        # progress ping
        sp=OUT/'A_full_batch_state.json'
        n=0
        if sp.exists():
            import json
            try:
                n=len(json.loads(sp.read_text(encoding='utf-8')).get('results') or {})
            except Exception:
                n=-1
        log(f'ok night alive; A_done={n}/59')
    time.sleep(120)
log('watchdog stop at >=21:00')
