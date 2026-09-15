param([string]$OutputDir = "release")
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
$out = Join-Path $root $OutputDir
$stage = Join-Path $out "cve-hunter-ubuntu-minimal"
$archive = Join-Path $out "cve-hunter-ubuntu-minimal.tar.gz"
New-Item -ItemType Directory -Path $out -Force | Out-Null
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
New-Item -ItemType Directory -Path $stage | Out-Null
Copy-Item -LiteralPath (Join-Path $root "main.py"), (Join-Path $root "requirements.txt"), (Join-Path $root "README.md"), (Join-Path $root ".env.example"), (Join-Path $root "run_web.sh"), (Join-Path $root "deploy_ubuntu.sh") -Destination $stage
Copy-Item -LiteralPath (Join-Path $root "cve_hunter") -Destination $stage -Recurse
New-Item -ItemType Directory -Path (Join-Path $stage "poc_kb") | Out-Null
Copy-Item -LiteralPath (Join-Path $root "poc_kb\custom") -Destination (Join-Path $stage "poc_kb") -Recurse
Get-ChildItem -LiteralPath $stage -Recurse -Directory -Filter __pycache__ | Remove-Item -Recurse -Force
Get-ChildItem -LiteralPath $stage -Recurse -File | Where-Object { $_.Extension -in ".pyc", ".pyo" } | Remove-Item -Force
tar -czf $archive -C $out (Split-Path $stage -Leaf)
Remove-Item -LiteralPath $stage -Recurse -Force
Write-Host "Created $archive"
