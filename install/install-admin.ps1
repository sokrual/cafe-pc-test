# INSTALL-ADMIN: sets up the counter (admin) PC. Run it as admin, once; run again to update.
#   - the cafe server as a Windows service that starts with the PC
#   - a firewall rule: only PCs on the shop network may reach it
#   - AdGuard Home, the free internet filter the gaming PCs use for every web address (downloaded from its maker)
#   - on a new install: one key file per gaming PC (PC1.token, PC2.token ...) in this folder, for INSTALL-PC
# -Uninstall: take it all off again. -Ci: unattended test run (no pop-ups; -Pcs gives the number of gaming PCs).
#Requires -RunAsAdministrator
param([switch]$Uninstall, [switch]$Ci, [int]$Pcs)
$ErrorActionPreference = "Stop"
$src = $PSScriptRoot
$app = "$env:ProgramFiles\GamingCafe\Server"
$agh = "$env:ProgramFiles\AdGuardHome"
$svc = "CafeServer"
function Say($text) {
    if ($Ci) { Write-Host $text; return }
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show($text, "Gaming Cafe setup") | Out-Null
}
trap { Say "Setup stopped:`n$_`n`nRun it again. If it stops again, take a photo of this window. Send the photo and the file install-log.txt (in this folder) on Discord to the person who gave you this software."; break }
Start-Transcript "$src\install-log.txt" -Append | Out-Null   # what happened, step by step: send this file on Discord if setup stops

if ($Uninstall) {
    if (Get-Service $svc -ErrorAction SilentlyContinue) { Stop-Service $svc -Force; sc.exe delete $svc | Out-Null }
    if (Test-Path "$agh\AdGuardHome.exe") { Start-Process "$agh\AdGuardHome.exe" "-s uninstall" -Wait -WindowStyle Hidden }
    Remove-NetFirewallRule -Group "Cafe counter" -ErrorAction SilentlyContinue
    $keep = "$env:ProgramData\Cafe\before-install.json"
    if (Test-Path $keep) { # clock settings back as they were
        foreach ($p in (Get-Content $keep -Raw | ConvertFrom-Json).PSObject.Properties) {
            $key, $name = $p.Name -split '\|'
            if ($null -eq $p.Value) { Remove-ItemProperty $key $name -ErrorAction SilentlyContinue } else { Set-ItemProperty $key $name $p.Value }
        }
        Restart-Service w32time -ErrorAction SilentlyContinue
        Remove-Item $keep
    }
    Remove-Item $app, $agh -Recurse -Force -ErrorAction SilentlyContinue
    Say "The cafe server and the internet filter are off this PC. The cafe data in C:\ProgramData\Cafe is kept."
    exit 0
}

# --- counter PC disk encryption: warn, but never enable BitLocker or stop setup ---
$bitLockerWarning = "Disk encryption (BitLocker) is off on this counter PC. If the PC or its disk is stolen, the cafe data can be read. Turn it on: see SECURITY-GUIDE.txt, part 1."
$bitLockerUnavailable = "BitLocker is not available on this counter PC (Windows Home may not include it). See SECURITY-GUIDE.txt, part 1."
$bitLockerUnknown = "Could not check BitLocker on this counter PC. Check disk encryption: see SECURITY-GUIDE.txt, part 1."
if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
    Write-Host "BitLocker status: Unavailable"
    Write-Host $bitLockerUnavailable
    Say $bitLockerUnavailable
} else {
    try {
        $systemVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        if ($null -ne $systemVolume -and "$($systemVolume.ProtectionStatus)" -eq "On") {
            Write-Host "BitLocker status: On"
        } else {
            Write-Host "BitLocker status: Off"
            Write-Host $bitLockerWarning
            Say $bitLockerWarning
        }
    } catch {
        Write-Host "BitLocker status: Unknown"
        Write-Host $bitLockerUnknown
        Say $bitLockerUnknown
    }
}

# --- the cafe server ---
if (Get-Service $svc -ErrorAction SilentlyContinue) { Stop-Service $svc -Force }
Get-Process Cafe.Server -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep -Seconds 1
New-Item $app -ItemType Directory -Force | Out-Null   # inside Program Files: only admins can change it
Copy-Item "$src\Cafe.Server.exe" $app -Force
if (-not (Get-Service $svc -ErrorAction SilentlyContinue)) {
    New-Service -Name $svc -BinaryPathName "`"$app\Cafe.Server.exe`"" -DisplayName "Gaming Cafe server" -StartupType Automatic | Out-Null
}
sc.exe failure $svc reset= 86400 actions= restart/2000/restart/2000/restart/2000 | Out-Null
# new install only (no cafe data yet): the keys for the gaming PCs, so nobody makes them one by one on the counter screen
$madeKeys = @()
if (-not (Test-Path "$env:ProgramData\Cafe\cafe.db")) {
    while (-not $Ci -and $Pcs -eq 0) {
        Add-Type -AssemblyName Microsoft.VisualBasic
        $answer = [Microsoft.VisualBasic.Interaction]::InputBox("How many gaming PCs does the cafe have? (Do not count this counter PC.)", "Gaming Cafe setup", "8")
        if (-not $answer) { break }   # Cancel: add the PCs on the counter screen later
        if ($answer.Trim() -match '^\d{1,3}$' -and [int]$answer -ge 1 -and [int]$answer -le 200) { $Pcs = [int]$answer } else { Say "Type a number from 1 to 200." }
    }
    if ($Pcs -gt 0) {
        $madeKeys = @(& "$app\Cafe.Server.exe" --add-pcs $Pcs --out $src)
        if ($LASTEXITCODE) { throw "Could not make the gaming PC keys (error $LASTEXITCODE). Run INSTALL-ADMIN again." }
    }
}
Start-Service $svc

# what this install changes outside its own folders, kept once so uninstall can put it back (admins and Windows only)
$keep = "$env:ProgramData\Cafe"   # the server's own data folder; kept at uninstall (a gaming PC uses ProgramData\GamingCafe)
New-Item $keep -ItemType Directory -Force | Out-Null
icacls $keep /inheritance:r /grant "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null
$timeKeys = @("HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters|NtpServer", "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters|Type",
    "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient|SpecialPollInterval",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|InactivityTimeoutSecs")
if (-not (Test-Path "$keep\before-install.json")) {
    $before = [ordered]@{}
    foreach ($t in $timeKeys) { $k, $n = $t -split '\|'; $before[$t] = (Get-ItemProperty $k -Name $n -ErrorAction SilentlyContinue).$n }
    $before | ConvertTo-Json | Set-Content "$keep\before-install.json" -Encoding utf8
}

# --- counter screen: Windows locks after 10 idle minutes and requires the Windows sign-in credential ---
$idleKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
New-ItemProperty $idleKey InactivityTimeoutSecs -PropertyType DWord -Value 600 -Force | Out-Null

# --- clock: synced every hour with India's official time servers (NIC and NPL), as CERT-In asks; logs need the right time ---
$w32 = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time"
Set-ItemProperty "$w32\Parameters" NtpServer "samay1.nic.in,0x9 samay2.nic.in,0x9 time.nplindia.org,0x9"
Set-ItemProperty "$w32\Parameters" Type "NTP"
Set-ItemProperty "$w32\TimeProviders\NtpClient" SpecialPollInterval 3600 -Type DWord
Set-Service w32time -StartupType Automatic; Restart-Service w32time -Force
w32tm.exe /resync /nowait | Out-Null

# --- firewall: the server and the filter answer the shop network only, never the internet ---
Remove-NetFirewallRule -Group "Cafe counter" -ErrorAction SilentlyContinue
New-NetFirewallRule -Group "Cafe counter" -DisplayName "Gaming Cafe server (shop network only)" -Direction Inbound -Action Allow -Profile Any `
    -Program "$app\Cafe.Server.exe" -Protocol TCP -LocalPort 5443 -RemoteAddress LocalSubnet | Out-Null
New-NetFirewallRule -Group "Cafe counter" -DisplayName "Gaming Cafe: gaming PCs find the counter PC (shop network only)" -Direction Inbound -Action Allow -Profile Any `
    -Program "$app\Cafe.Server.exe" -Protocol UDP -LocalPort 5442 -RemoteAddress LocalSubnet | Out-Null
foreach ($proto in "UDP", "TCP") {
    New-NetFirewallRule -Group "Cafe counter" -DisplayName "Cafe internet filter $proto (shop network only)" -Direction Inbound -Action Allow -Profile Any `
        -Program "$agh\AdGuardHome.exe" -Protocol $proto -LocalPort 53 -RemoteAddress LocalSubnet | Out-Null
}

# --- AdGuard Home: a fixed version, checked against the maker's published fingerprint before it runs ---
# (GPL-3.0 program; we do not ship it, the PC downloads it from AdGuard's own release page)
$ver = "v0.107.79"
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
$sha = @{ amd64 = "e42294dc26b2c0d8f4576a91f09aa5129ffdfb7b647026fac77f0abac9acffce"; arm64 = "b7c1c16c4b3cb7a97d7a58f01d649b03244cc847fb9045a2d719cff6e7b57ccd" }[$arch]
$local = "$src\AdGuardHome_windows_$arch.zip"   # the zip can come with this folder (no internet needed); same fingerprint check
if (-not (Test-Path "$agh\AdGuardHome.exe")) {
    $zip = Join-Path $env:TEMP "AdGuardHome.zip"
    Remove-Item $zip -ErrorAction SilentlyContinue   # never a half download from an earlier try
    if (Test-Path $local) { Copy-Item $local $zip -Force }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    for ($i = 1; -not (Test-Path $zip); $i++) { # GitHub's download servers sometimes time out: six tries over about 2 minutes
        try { Invoke-WebRequest "https://github.com/AdguardTeam/AdGuardHome/releases/download/$ver/AdGuardHome_windows_$arch.zip" -OutFile $zip -UseBasicParsing }
        catch { Remove-Item $zip -ErrorAction SilentlyContinue; if ($i -ge 6) { throw "Could not download the internet filter. Check that this PC has internet, then run INSTALL-ADMIN again. ($_)" }; Start-Sleep -Seconds 20 }
    }
    if ((Get-FileHash $zip -Algorithm SHA256).Hash -ne $sha) { Remove-Item $zip; throw "The internet filter download was damaged or changed. Nothing was installed." }
    Expand-Archive $zip $env:ProgramFiles -Force   # the zip holds one AdGuardHome folder
    Remove-Item $zip
    # Start-Process: AdGuard Home writes its progress to the error stream, which Windows PowerShell would treat as a failure
    $p = Start-Process "$agh\AdGuardHome.exe" "-s install" -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode) { throw "The internet filter did not install (error $($p.ExitCode)). Run INSTALL-ADMIN again." }
}

sc.exe failure AdGuardHome reset= 86400 actions= restart/2000/restart/2000/restart/2000 | Out-Null   # restarts if it stops: without it no PC finds any website

# --- the filter's first-start setup, done here instead of the owner clicking through its browser wizard ---
# web page on this PC only (127.0.0.1:3000), DNS for the shop network on port 53, website list kept 180 days (the law
# asks a cyber cafe for 180 days), a long random password saved where only admins can read it. Never printed: the
# install log may be sent to someone.
$filterPasswordFile = "$keep\filter-password.txt"
$filterJustSetUp = $false
if (-not (Test-Path "$agh\AdGuardHome.yaml")) {
    $wizard = "http://127.0.0.1:3000/control/install"
    for ($i = 0; $i -lt 60; $i++) { try { Invoke-WebRequest "$wizard/get_addresses" -UseBasicParsing | Out-Null; break } catch { if ($i -eq 59) { throw "The internet filter did not start. Restart the PC and run INSTALL-ADMIN again." }; Start-Sleep -Seconds 1 } }
    $bytes = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $filterPassword = [Convert]::ToBase64String($bytes) -replace '[+/=]', 'x'
    $settings = @{ web = @{ ip = "127.0.0.1"; port = 3000 }; dns = @{ ip = "0.0.0.0"; port = 53 }; username = "owner"; password = $filterPassword }
    try { Invoke-RestMethod "$wizard/configure" -Method Post -ContentType "application/json" -Body ($settings | ConvertTo-Json) | Out-Null }
    catch { throw "The internet filter could not take port 53 (another program may use it). Run INSTALL-ADMIN again. ($($_.Exception.Message))" }
    Set-Content $filterPasswordFile "Internet filter (http://127.0.0.1:3000 on the counter PC): user owner, password $filterPassword" -Encoding ascii
    $auth = @{ Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("owner:$filterPassword")) }
    for ($i = 0; $i -lt 30; $i++) { try { Invoke-RestMethod "http://127.0.0.1:3000/control/status" -Headers $auth | Out-Null; break } catch { if ($i -eq 29) { throw "The internet filter did not restart after its setup. Run INSTALL-ADMIN again." }; Start-Sleep -Seconds 1 } }
    $log = @{ enabled = $true; interval = [long]180 * 24 * 3600 * 1000; anonymize_client_ip = $false; ignored = @() }   # milliseconds
    Invoke-RestMethod "http://127.0.0.1:3000/control/querylog/config/update" -Method Put -Headers $auth -ContentType "application/json" -Body ($log | ConvertTo-Json) | Out-Null
    $filterJustSetUp = $true
}

# --- what the gaming PCs need from here ---
$pin = "$env:ProgramData\Cafe\server.pin"
for ($i = 0; $i -lt 30 -and -not (Test-Path $pin); $i++) { Start-Sleep -Seconds 1 }
if (-not (Test-Path $pin)) { throw "The cafe server did not start. Restart the PC and run INSTALL-ADMIN again. Its log is in C:\ProgramData\Cafe\logs." }
$out = Join-Path $src "for-gaming-PCs"
New-Item $out -ItemType Directory -Force | Out-Null
Copy-Item $pin $out -Force
Copy-Item $pin $src -Force   # the same folder then goes to every gaming PC as it is
# the address Windows itself uses towards the router: not a virtual adapter (WSL, Hyper-V, VirtualBox, VPN) that also has one
$ip = try { (Find-NetRoute -RemoteIPAddress "8.8.8.8" -ErrorAction Stop | Where-Object IPAddress | Select-Object -First 1).IPAddress } catch { $null }
if (-not $ip) { $ip = (Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp, Manual -ErrorAction SilentlyContinue | Where-Object IPAddress -notlike "169.254.*" | Select-Object -First 1).IPAddress }
if ($ip) { Set-Content "$src\counter-address.txt" $ip -Encoding ascii }   # INSTALL-PC reads it: nobody types the address
$keysStep = if ($madeKeys.Count) { "The keys for $($madeKeys.Count) gaming PCs ($($madeKeys[0]) to $($madeKeys[-1])) are in this folder." } else { "Then add each gaming PC under Owner security, PC keys. Save each key file into this folder." }
$filterNote = if ($filterJustSetUp) { "The internet filter is set up. You rarely need its page; its password is in $filterPasswordFile (only admins can open it).`n`n" } else { "" }
Say "The counter PC is ready.`n`nThis PC's address: $ip`n`n$($filterNote)Next:`n1. On the counter screen (https://127.0.0.1:5443/staff/), make your owner account. $keysStep`n2. Take this whole folder (for example on a pen drive) to each gaming PC and run INSTALL-PC.`n`nThe counter screen opens now."
if (-not $Ci) { Start-Process "https://127.0.0.1:5443/staff/" }   # one less address to type
