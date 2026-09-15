param(
  [int]$Port = 8000,
  [switch]$Docker
)
$ErrorActionPreference = "Stop"
if ($Docker) {
  docker compose -f docker-compose.web.yml up --build
  exit $LASTEXITCODE
}
$listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($listener) {
  $existingPid = $listener.OwningProcess
  try {
    $health = Invoke-RestMethod "http://127.0.0.1:$Port/api/health" -TimeoutSec 2
    if ($health.status -eq "ok") {
      Write-Host "CVE Hunter Web 已在 http://127.0.0.1:$Port 运行 (PID $existingPid)" -ForegroundColor Green
      exit 0
    }
  } catch {
    # The port belongs to another service; report that below.
  }
  throw "端口 $Port 已被进程 $existingPid 占用。请使用 -Port <端口>，或先停止该进程。"
}
python -m uvicorn cve_hunter.web_app:app --host 127.0.0.1 --port $Port
