# INSTALL-ADMIN: sets up the counter (admin) PC. Run it as admin, once; run again to update.
#   - the cafe server as a Windows service that starts with the PC
#   - a firewall rule: only PCs on the shop network may reach it
#   - AdGuard Home, the free internet filter the gaming PCs use for every web address (downloaded from its maker)
# -Uninstall: take it all off again. -Ci: unattended test run (no pop-ups).
#Requires -RunAsAdministrator
param([switch]$Uninstall, [switch]$Ci)
$ErrorActionPreference = "Stop"
$src = $PSScriptRoot
$app = "$env:ProgramFiles\ShinzxCafe\Server"
$agh = "$env:ProgramFiles\AdGuardHome"
$svc = "CafeServer"
function Say($text) {
    if ($Ci) { Write-Host $text; return }
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show($text, "Shinzx setup") | Out-Null
}
trap { Say "Setup stopped:`n$_`n`nRun it again. If it stops again, take a photo of this window and send it on Discord to the person who gave you this software."; break }

if ($Uninstall) {
    if (Get-Service $svc -ErrorAction SilentlyContinue) { Stop-Service $svc -Force; sc.exe delete $svc | Out-Null }
    if (Test-Path "$agh\AdGuardHome.exe") { Start-Process "$agh\AdGuardHome.exe" "-s uninstall" -Wait -WindowStyle Hidden }
    Remove-NetFirewallRule -Group "Shinzx counter" -ErrorAction SilentlyContinue
    Remove-Item $app, $agh -Recurse -Force -ErrorAction SilentlyContinue
    Say "The cafe server and the internet filter are off this PC. The cafe data in C:\ProgramData\Cafe is kept."
    exit 0
}

# --- the cafe server ---
if (Get-Service $svc -ErrorAction SilentlyContinue) { Stop-Service $svc -Force }
New-Item $app -ItemType Directory -Force | Out-Null   # inside Program Files: only admins can change it
Copy-Item "$src\Cafe.Server.exe" $app -Force
if (-not (Get-Service $svc -ErrorAction SilentlyContinue)) {
    New-Service -Name $svc -BinaryPathName "`"$app\Cafe.Server.exe`"" -DisplayName "Shinzx Cafe server" -StartupType Automatic | Out-Null
}
sc.exe failure $svc reset= 86400 actions= restart/2000/restart/2000/restart/2000 | Out-Null
Start-Service $svc

# --- firewall: the server and the filter answer the shop network only, never the internet ---
Remove-NetFirewallRule -Group "Shinzx counter" -ErrorAction SilentlyContinue
New-NetFirewallRule -Group "Shinzx counter" -DisplayName "Shinzx cafe server (shop network only)" -Direction Inbound -Action Allow -Profile Any `
    -Program "$app\Cafe.Server.exe" -Protocol TCP -LocalPort 5443 -RemoteAddress LocalSubnet | Out-Null
foreach ($proto in "UDP", "TCP") {
    New-NetFirewallRule -Group "Shinzx counter" -DisplayName "Shinzx internet filter $proto (shop network only)" -Direction Inbound -Action Allow -Profile Any `
        -Program "$agh\AdGuardHome.exe" -Protocol $proto -LocalPort 53 -RemoteAddress LocalSubnet | Out-Null
}

# --- AdGuard Home: a fixed version, checked against the maker's published fingerprint before it runs ---
# (GPL-3.0 program; we do not ship it, the PC downloads it from AdGuard's own release page)
$ver = "v0.107.79"
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
$sha = @{ amd64 = "e42294dc26b2c0d8f4576a91f09aa5129ffdfb7b647026fac77f0abac9acffce"; arm64 = "b7c1c16c4b3cb7a97d7a58f01d649b03244cc847fb9045a2d719cff6e7b57ccd" }[$arch]
if (-not (Test-Path "$agh\AdGuardHome.exe")) {
    $zip = Join-Path $env:TEMP "AdGuardHome.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    for ($i = 1; ; $i++) { # GitHub's download servers sometimes time out: three tries
        try { Invoke-WebRequest "https://github.com/AdguardTeam/AdGuardHome/releases/download/$ver/AdGuardHome_windows_$arch.zip" -OutFile $zip -UseBasicParsing; break }
        catch { if ($i -ge 3) { throw "Could not download the internet filter (is the internet on?): $_" }; Start-Sleep -Seconds 10 }
    }
    if ((Get-FileHash $zip -Algorithm SHA256).Hash -ne $sha) { Remove-Item $zip; throw "The internet filter download was damaged or changed. Nothing was installed." }
    Expand-Archive $zip $env:ProgramFiles -Force   # the zip holds one AdGuardHome folder
    Remove-Item $zip
    # Start-Process: AdGuard Home writes its progress to the error stream, which Windows PowerShell would treat as a failure
    $p = Start-Process "$agh\AdGuardHome.exe" "-s install" -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode) { throw "The internet filter did not install (exit $($p.ExitCode))" }
}

# --- what the gaming PCs need from here ---
$pin = "$env:ProgramData\Cafe\server.pin"
for ($i = 0; $i -lt 30 -and -not (Test-Path $pin); $i++) { Start-Sleep -Seconds 1 }
if (-not (Test-Path $pin)) { throw "The cafe server did not start. Its log is in C:\ProgramData\Cafe\logs." }
$out = Join-Path $src "for-gaming-PCs"
New-Item $out -ItemType Directory -Force | Out-Null
Copy-Item $pin $out -Force
$ip = (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp, Manual -ErrorAction SilentlyContinue | Where-Object IPAddress -notlike "169.254.*" | Select-Object -First 1).IPAddress
Say "The counter PC is ready.`n`nThis PC's address: $ip`n`nNext:`n1. Open http://127.0.0.1:3000 in the browser and finish the internet filter setup.`n   Choose 'All interfaces' and port 53 for the DNS server. Write down the password you pick.`n2. Copy the folder 'for-gaming-PCs' to each gaming PC's install folder."
