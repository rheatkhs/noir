Write-Host "Noir - checking dependencies..." -ForegroundColor Cyan

$tools = @{nmap = "nmap"; curl = "curl.exe"; ffuf = "ffuf.exe" }
$missing = @()
foreach ($t in $tools.Keys) {
    if (-not (Get-Command $tools[$t] -ErrorAction SilentlyContinue)) {
        $missing += $t
    }
}

if ($missing.Count -gt 0) {
    Write-Host "missing: $($missing -join ', ')" -ForegroundColor Yellow
}

if ($missing -contains "nmap") {
    try { winget install Insecure.Nmap -h --accept-package-agreements 2>$null }
    catch { Write-Host "install nmap manually from https://nmap.org/download.html" -ForegroundColor Red }
}

if ($missing -contains "ffuf") {
    $url = "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_windows_amd64.zip"
    $zip = "$env:TEMP\ffuf.zip"
    try {
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath "$env:LOCALAPPDATA\Microsoft\WindowsApps" -Force
        Remove-Item $zip
    }
    catch { Write-Host "install ffuf manually from https://github.com/ffuf/ffuf/releases" -ForegroundColor Red }
}

pip install playwright requests mcp 2>$null
python -m playwright install chromium 2>$null

Write-Host "Noir - ready." -ForegroundColor Green
