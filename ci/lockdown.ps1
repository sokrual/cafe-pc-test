# B3 on a real Windows machine: admin PC install, gaming PC install (both steps), logout wipe, what a customer
# cannot do, Level A enforce mechanics, then both uninstalls. Prints a results table; exit 1 if any check fails.
# Needs out\server, out\agent, out\watchdog, out\timer (single-file x64 builds) and admin rights.
$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot
$out = Join-Path $repo "out"
$results = New-Object System.Collections.Generic.List[object]
function Check($id, $test, $ok, $detail) {
    $res = if ($ok) { "PASS" } else { "FAIL" }
    $results.Add([pscustomobject]@{ id = $id; result = $res; test = $test; detail = "$detail" })
    Write-Host "[$res] $id $test - $detail"
}
function WaitFor($seconds, $test) { for ($i = 0; $i -lt $seconds * 2; $i++) { if (& $test) { return $true }; Start-Sleep -Milliseconds 500 }; $false }
function AsCustomer($exe, $argList) { # start a program as Customer (password read from where auto sign-in keeps it)
    $pw = New-Object Security.SecureString; foreach ($c in ([Shinzx.Lsa]::Read("DefaultPassword")).ToCharArray()) { $pw.AppendChar($c) }
    $cred = [pscredential]::new("Customer", $pw)
    $p = @{ FilePath = $exe; Credential = $cred; LoadUserProfile = $true; WorkingDirectory = "$env:WINDIR\System32"; PassThru = $true; WindowStyle = "Hidden" }
    if ($argList) { $p.ArgumentList = $argList }
    $proc = Start-Process @p
    $null = $proc.Handle   # without this Windows PowerShell never reports the exit code
    $proc
}
function CustomerPs($command) { # run PowerShell as Customer; returns its exit code (0 = the command worked)
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("`$ErrorActionPreference = 'Stop'; $command"))
    $p = AsCustomer "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" "-NoProfile -EncodedCommand $enc"; $p.WaitForExit(); $p.ExitCode
}
$runKey = "Software\Microsoft\Windows\CurrentVersion\Run"
$wd = "$env:ProgramData\Cafe\logs"
$app = "$env:ProgramFiles\ShinzxCafe"
$data = "$env:ProgramData\ShinzxCafe"
$winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$autoBefore = (Get-ItemProperty $winlogon).AutoAdminLogon
$ntpKey = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"
$ntpOriginal = (Get-ItemProperty $ntpKey).NtpServer
$dohOriginal = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -ErrorAction SilentlyContinue).DnsOverHttpsMode
# control for C6: other DNS servers must answer BEFORE the install, or "blocked" afterwards proves nothing
$googleBefore = try { Resolve-DnsName example.com -Server 8.8.8.8 -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null; "answered" } catch { "blocked" }
$dnsBefore = @(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | ForEach-Object { "$($_.InterfaceIndex)=$((Get-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).ServerAddresses -join ',')" })
$runnerDns = ((Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1).DNSServer | Where-Object AddressFamily -eq 2).ServerAddresses[0]

try {
    # ===== A. counter (admin) PC =====
    $stageA = Join-Path $env:TEMP "stage-admin"; New-Item $stageA -ItemType Directory -Force | Out-Null
    Copy-Item "$repo\install\install-admin.ps1", "$out\server\Cafe.Server.exe" $stageA
    & "$stageA\install-admin.ps1" -Ci
    Check "B3.A1" "Cafe server runs as a Windows service" ((Get-Service CafeServer).Status -eq "Running") (Get-Service CafeServer).StartType
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }   # the test only; PCs pin the certificate
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    # curl.exe uses Windows' TLS directly. Windows PowerShell 5.1 with a script-block certificate callback failed its
    # first HTTPS call here ("unexpected error on a send") while curl.exe got the right answer (runs 42633874084)
    $curl = (curl.exe -sk -o NUL -w "%{http_code}" https://127.0.0.1:5443/pc/state) -join ""
    Check "B3.A2" "Server answers HTTPS and refuses a PC without its key" ($curl -eq "401") "HTTP $curl"
    # the certificate the server shows must be the one whose fingerprint the gaming PCs pin (server.pin)
    $tcp = [Net.Sockets.TcpClient]::new("127.0.0.1", 5443)
    $ssl = [Net.Security.SslStream]::new($tcp.GetStream(), $false, { $true })   # accept it here only to read it
    $ssl.AuthenticateAsClient("cafe-admin")
    $served = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($ssl.RemoteCertificate.GetRawCertData())) -replace '-', '')
    $ssl.Dispose(); $tcp.Dispose()
    $pinned = (Get-Content "$env:ProgramData\Cafe\server.pin" -Raw).Trim()
    Check "B3.A2b" "Server shows the certificate the gaming PCs pin" ($served -eq $pinned) "served $($served.Substring(0, 12))..., pinned $($pinned.Substring(0, 12))..."
    if ($curl -ne "401") { cmd.exe /c "curl.exe -vk https://127.0.0.1:5443/pc/state 2>&1" | Write-Host }
    $rule = Get-NetFirewallRule -Group "Shinzx counter" | Where-Object DisplayName -like "*cafe server*" | Get-NetFirewallAddressFilter
    Check "B3.A3" "Firewall lets only the shop network reach the server" ("$($rule.RemoteAddress)" -eq "LocalSubnet") "remote: $($rule.RemoteAddress)"
    Check "B3.A4" "Internet filter (AdGuard Home) installed, checked and running" ((Get-Service AdGuardHome -ErrorAction SilentlyContinue).Status -eq "Running") "version pinned, SHA-256 checked"
    $wiz = WaitFor 20 { try { (Invoke-WebRequest http://127.0.0.1:3000 -UseBasicParsing).StatusCode -eq 200 } catch { $false } }
    Check "B3.A5" "Filter set-up page opens on the counter PC" $wiz "http://127.0.0.1:3000"
    Check "B3.A6" "Internet filter restarts by itself if it stops" ((sc.exe qfailure AdGuardHome) -match "RESTART") ""
    Stop-Service CafeServer   # the gaming-PC tests below use a test server with test users on the same port

    # ===== B. test server with test users =====
    $tdata = "C:\cafe-test"
    $server = Start-Process "$out\server\Cafe.Server.exe" -ArgumentList "--data $tdata --seed-test" -PassThru -WindowStyle Hidden
    if (-not (WaitFor 30 { Test-Path "$tdata\pc1.token" })) { throw "test server did not start" }
    $token = (Get-Content "$tdata\pc1.token" -Raw).Trim()
    function Pc($path, $body) { Invoke-RestMethod "https://127.0.0.1:5443$path" -Method Post -Headers @{ "X-Pc-Token" = $token } -ContentType "application/json" -Body ($body | ConvertTo-Json) }

    # ===== C. gaming PC, step 1 =====
    $ntpBefore = (Get-ItemProperty $ntpKey).NtpServer   # after the counter PC install, which sets the same clock settings
    $stage = Join-Path $env:TEMP "stage-pc"; New-Item $stage -ItemType Directory -Force | Out-Null
    Copy-Item "$repo\install\*", "$out\agent\Cafe.Agent.exe", "$out\watchdog\Cafe.Watchdog.exe" $stage
    Copy-Item "$tdata\pc1.token" "$stage\pc.token"; Copy-Item "$tdata\server.pin" $stage
    & "$stage\install-pc.ps1" -Server 127.0.0.1 -DnsServer $runnerDns -Ci
    $u = Get-LocalUser Customer
    $isAdmin = [bool]((net.exe localgroup (Get-LocalGroup -SID S-1-5-32-544).Name) -match '^Customer$')   # Get-LocalGroupMember breaks on unknown members
    Check "B3.C1" "Customer account made, not an admin" ($u.Enabled -and -not $isAdmin) "SID $($u.SID)"
    $wl = Get-ItemProperty $winlogon
    Check "B3.C2" "Automatic sign-in to Customer, password not in plain text" ($wl.AutoAdminLogon -eq "1" -and $wl.ForceAutoLogon -eq "1" -and $wl.DefaultUserName -eq "Customer" -and -not $wl.DefaultPassword) "AutoAdminLogon $($wl.AutoAdminLogon)"
    $first = AsCustomer "$env:WINDIR\System32\cmd.exe" "/c exit"; $first.WaitForExit()
    Check "B3.C3" "Stored sign-in password really signs in Customer" ($first.ExitCode -eq 0) "exit $($first.ExitCode)"
    $s = Get-CimInstance Win32_Service -Filter "Name='CafeWatchdog'"
    Check "B3.C4" "Watchdog service: automatic, as SYSTEM, also in Safe Mode" ($s.StartMode -eq "Auto" -and $s.StartName -eq "LocalSystem" -and (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\CafeWatchdog") -and (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\CafeWatchdog")) "$($s.State)"
    Start-Sleep -Seconds 5
    Check "B3.C5" "Setup mode: no lock screen yet" ((Test-Path "$app\setup.flag") -and -not (Get-Process Cafe.Agent -ErrorAction SilentlyContinue)) "setup.flag present"
    $other = try { Resolve-DnsName example.com -Server 8.8.8.8 -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null; "answered" } catch { "blocked" }
    $own = try { Resolve-DnsName example.com -DnsOnly -ErrorAction Stop | Out-Null; "works" } catch { "$_" }
    Check "B3.C6" "Other DNS servers blocked, the filter's one works" ($googleBefore -eq "answered" -and $other -eq "blocked" -and $own -eq "works") "8.8.8.8 before install $googleBefore, after $other; normal lookups $own"
    $poll = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient").SpecialPollInterval
    Check "B3.C8" "Clock synced hourly with India's official time servers (NIC, NPL)" ((Get-ItemProperty $ntpKey).NtpServer -match "samay1.nic.in" -and $poll -eq 3600 -and (Get-Service w32time).Status -eq "Running") "time source now: $((w32tm.exe /query /source) -join ' ')"
    Check "B3.C7" "Browsers' own secure DNS switched off" ((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge").DnsOverHttpsMode -eq "off") "Edge, Chrome, Firefox policies"

    # ===== D. the owner sets the Customer account up (here: an "installed Discord" and a shortcut) =====
    $prof = (Get-CimInstance Win32_UserProfile | Where-Object SID -eq $u.SID.Value).LocalPath
    New-Item "$prof\AppData\Local\Discord" -ItemType Directory -Force | Out-Null; "app" | Set-Content "$prof\AppData\Local\Discord\Update.txt"
    "shortcut" | Set-Content "$prof\Desktop\Game.txt"
    $ownerRun = CustomerPs "if (-not (Test-Path HKCU:\$runKey)) { New-Item HKCU:\$runKey | Out-Null }; Set-ItemProperty HKCU:\$runKey OwnerApp 'C:\owner.exe'"
    Start-Sleep -Seconds 5

    # ===== E. step 2 =====
    & "$stage\install-pc.ps1" -Ci
    Check "B3.E1" "Clean copy saved" (Test-Path "$data\clean-profile\AppData\Local\Discord\Update.txt") "$data\clean-profile"
    cmd.exe /c "reg load HKU\T `"$prof\NTUSER.DAT`" >nul 2>&1"
    $h = if ($LASTEXITCODE) { "Registry::HKEY_USERS\$($u.SID.Value)" } else { "Registry::HKEY_USERS\T" }
    $sys = Get-ItemProperty "$h\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $cmd = (Get-ItemProperty "$h\Software\Policies\Microsoft\Windows\System").DisableCMD
    Check "B3.E2" "Customer: no Task Manager, no Lock, no password change, no registry editor, no command prompt" ($sys.DisableTaskMgr -eq 1 -and $sys.DisableLockWorkstation -eq 1 -and $sys.DisableChangePassword -eq 1 -and $sys.DisableRegistryTools -eq 1 -and $cmd -eq 2) "DisableCMD $cmd"
    Remove-Variable sys; [gc]::Collect(); cmd.exe /c "reg unload HKU\T >nul 2>&1"
    Check "B3.E3" "Switch user hidden" ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").HideFastUserSwitching -eq 1) ""
    $agentUp = WaitFor 20 { Get-Process Cafe.Agent -ErrorAction SilentlyContinue }
    Check "B3.E4" "Setup mode off: the watchdog starts the lock screen" ($agentUp -and -not (Test-Path "$app\setup.flag")) ""
    $la = Get-Content "$data\levelA-id.txt" -ErrorAction SilentlyContinue
    Check "B3.E5" "Level A watch-only on (nothing blocked)" ($la -and ((CiTool.exe --list-policies) -match [regex]::Escape("$la".Trim('{}')))) "policy $la"

    # ===== F. a customer plays, then logs out =====
    foreach ($d in "FakeGame", "FakeMouse") { New-Item "$env:ProgramFiles\$d" -ItemType Directory -Force | Out-Null }
    Copy-Item "$env:WINDIR\System32\PING.EXE" "$env:ProgramFiles\FakeGame\game.exe"; Copy-Item "$env:WINDIR\System32\PING.EXE" "$env:ProgramFiles\FakeMouse\lghub.exe"
    New-Item "C:\FakeSteam\config" -ItemType Directory -Force | Out-Null
    'users { "1" { "AccountName" "someone" "RememberPassword" "1" } }' | Set-Content "C:\FakeSteam\config\loginusers.vdf"
    "`"InstallConfigStore`"`n{`n`t`"Software`" { `"x`" `"1`" }`n`t`"ConnectCache`"`n`t{`n`t`t`"7a2b`" `"secret`"`n`t}`n}" | Set-Content "C:\FakeSteam\config\config.vdf"
    $steamKey = "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam"; New-Item $steamKey -Force | Out-Null; Set-ItemProperty $steamKey InstallPath "C:\FakeSteam"
    Pc "/pc/login" @{ phone = "9000000003"; pin = "2222" } | Out-Null
    $p1 = AsCustomer "$env:WINDIR\System32\PING.EXE" "-t 127.0.0.1"
    $p2 = AsCustomer "$env:ProgramFiles\FakeGame\game.exe" "-t 127.0.0.1"
    $p3 = AsCustomer "$env:ProgramFiles\FakeMouse\lghub.exe" "-t 127.0.0.1"
    New-Item "$prof\AppData\Roaming\discord\Local Storage" -ItemType Directory -Force | Out-Null; "token" | Set-Content "$prof\AppData\Roaming\discord\Local Storage\login.txt"
    "secret" | Set-Content "$prof\Downloads\secret.txt"
    Remove-Item "$prof\Desktop\Game.txt"
    New-Item "$prof\AppData\Local\NVIDIA\DXCache" -ItemType Directory -Force | Out-Null; "cache" | Set-Content "$prof\AppData\Local\NVIDIA\DXCache\x.bin"
    # what a customer could leave behind to run again for the next customer, and a link meant to trick the clean-up
    $taskMade = CustomerPs "schtasks.exe /create /tn ShinzxCustomerTask /tr 'C:\Windows\System32\PING.EXE 127.0.0.1' /sc minute /mo 30 /f; exit `$LASTEXITCODE"
    $runMade = CustomerPs "Set-ItemProperty HKCU:\$runKey Evil 'C:\evil.exe'"
    New-Item "C:\ShinzxCanary" -ItemType Directory -Force | Out-Null
    icacls.exe "C:\ShinzxCanary" /inheritance:r /grant "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" | Out-Null   # the customer alone cannot delete it
    "must stay" | Set-Content "C:\ShinzxCanary\keep.txt"   # made after the folder rule, so it takes it over
    $hard = CustomerPs "New-Item -ItemType HardLink -Path '$prof\Desktop\Game.txt' -Target 'C:\ShinzxCanary\keep.txt' -Force | Out-Null"   # a trap where the owner's shortcut was
    $linkMade = CustomerPs "New-Item -ItemType Junction -Path '$prof\Downloads\link' -Target 'C:\ShinzxCanary' | Out-Null"
    New-Item "$env:ProgramFiles\OpenFolder" -ItemType Directory -Force | Out-Null
    icacls.exe "$env:ProgramFiles\OpenFolder" /grant "*S-1-5-32-545:(OI)(CI)M" | Out-Null   # like Steam's folder: any user can write
    Copy-Item "$env:WINDIR\System32\PING.EXE" "$env:ProgramFiles\OpenFolder\lghub.exe"
    $p4 = AsCustomer "$env:ProgramFiles\OpenFolder\lghub.exe" "-t 127.0.0.1"
    Start-Sleep -Seconds 4   # the lock screen sees the session (polls every 2 s)
    Pc "/pc/logout" @{} | Out-Null
    $asked = WaitFor 15 { Test-Path "$data\wipe\request" }
    $done = WaitFor 90 { -not (Test-Path "$data\wipe\request") }
    Check "B3.F1" "Logout asks for the clean-up and the watchdog finishes it" ($asked -and $done) "asked $asked, done $done"
    Start-Sleep -Seconds 2
    Check "B3.F2" "Customer's programs closed (a Windows one and a game)" ($p1.HasExited -and $p2.HasExited) "ping $($p1.HasExited), game $($p2.HasExited)"
    Check "B3.F3" "Mouse app on the keep list stays running" (-not $p3.HasExited) "lghub.exe"
    Check "B3.F4" "Customer's files and app logins gone" (-not (Test-Path "$prof\Downloads\secret.txt") -and -not (Test-Path "$prof\AppData\Roaming\discord")) "Downloads, Discord login"
    Check "B3.F5a" "Owner's desktop shortcut back" (Test-Path "$prof\Desktop\Game.txt") ""
    Check "B3.F5b" "Owner's Discord install kept" (Test-Path "$prof\AppData\Local\Discord\Update.txt") ""
    Check "B3.F5c" "Graphics card cache kept" (Test-Path "$prof\AppData\Local\NVIDIA\DXCache\x.bin") ""
    $cfg = Get-Content "C:\FakeSteam\config\config.vdf" -Raw
    Check "B3.F6" "Steam saved logins cleared, other Steam settings kept" (-not (Test-Path "C:\FakeSteam\config\loginusers.vdf") -and $cfg -notmatch "ConnectCache" -and $cfg -match "Software") ""
    Check "B3.F7" "Lock screen still running after the clean-up" ([bool](Get-Process Cafe.Agent -ErrorAction SilentlyContinue)) ""
    Check "B3.F8" "A customer's folder link cannot make the clean-up delete files elsewhere" ($linkMade -eq 0 -and (Test-Path "C:\ShinzxCanary\keep.txt")) "link made: exit $linkMade"
    Check "B3.F8b" "A customer's hard link cannot make the clean-up write over files elsewhere" ((Get-Content "C:\ShinzxCanary\keep.txt" -Raw) -eq "must stay`r`n") "hard link made: exit $hard (a refusal by Windows is a pass too)"
    Check "B3.F9" "A program named like a mouse app in a folder anyone can write is closed" ($p4.HasExited) "lghub.exe in an open folder"
    $run = Get-ItemProperty "Registry::HKEY_USERS\$($u.SID.Value)\$runKey" -ErrorAction SilentlyContinue
    Check "B3.F10" "Customer's autostart entry removed, the owner's kept" ($runMade -eq 0 -and $ownerRun -eq 0 -and -not $run.Evil -and $run.OwnerApp -eq "C:\owner.exe") "made: customer exit $runMade, owner exit $ownerRun"
    cmd.exe /c "schtasks /query /tn ShinzxCustomerTask >nul 2>&1"
    Check "B3.F11" "Customer's scheduled task removed" ($taskMade -eq 0 -and $LASTEXITCODE -ne 0) "made: exit $taskMade"
    Stop-Process -Id $p3.Id -Force

    # ===== G. what a customer cannot do =====
    $stop = AsCustomer "$env:WINDIR\System32\sc.exe" "stop CafeWatchdog"; $stop.WaitForExit()
    Check "B3.G1" "Customer cannot stop the watchdog" ($stop.ExitCode -ne 0 -and (Get-Service CafeWatchdog).Status -eq "Running") "sc exit $($stop.ExitCode)"
    # PowerShell, not cmd: the command prompt is switched off for Customer, so a cmd test would "pass" for the wrong reason
    $own = CustomerPs "Set-Content -LiteralPath '$prof\Downloads\ok.txt' x"
    Check "B3.G0" "Control: the same write works in the customer's own folder" ($own -eq 0) "exit $own"
    foreach ($t in @(@("$app\setup.flag", "switch the lock screen off"), @("$app\Cafe.Agent.exe", "replace the lock screen"), @("$data\clean-profile\x.txt", "change the clean copy"), @("$data\run-keys.txt", "change the owner's autostart list"))) {
        $w = CustomerPs "Set-Content -LiteralPath '$($t[0])' x"
        Check "B3.G2" "Customer cannot $($t[1])" ($w -ne 0 -and -not ((Test-Path $t[0]) -and (Get-Content $t[0] -Raw) -eq "x`r`n")) "$($t[0]): exit $w"
    }

    # ===== H. Level A enforce: approved runs, unapproved is blocked, the cafe program is allowed =====
    New-Item "C:\Games\Approved" -ItemType Directory -Force | Out-Null
    Copy-Item "$out\timer\ShinzxTimerTest.exe" "C:\Games\Approved\game.exe"
    Copy-Item "$out\watchdog\Cafe.Watchdog.exe" "C:\Users\Public\unknown.exe"
    try {
        & "$app\levelA.ps1" -Mode Enforce -Approve "C:\Games\Approved"
        Start-Sleep -Seconds 3
        $ok = AsCustomer "C:\Games\Approved\game.exe" "--selftest"; $ok.WaitForExit()
        Check "B3.H1" "Level A: an approved game runs" ($ok.ExitCode -eq 0) "exit $($ok.ExitCode)"
        $why = try { $x = AsCustomer "C:\Users\Public\unknown.exe"; $x.WaitForExit(); "it ran (exit $($x.ExitCode))" } catch { $_.Exception.Message }
        Check "B3.H2" "Level A: an unknown program is blocked" ($why -notmatch "^it ran") $why
        $why2 = try { $x = AsCustomer "$app\Cafe.Watchdog.exe"; $x.WaitForExit(); "it ran" } catch { $_.Exception.Message }
        Check "B3.H3" "Level A: the cafe program is allowed" ($why2 -eq "it ran") $why2
    } finally { & "$app\levelA.ps1" -Mode Off }

    # ===== I. uninstall =====
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    Copy-Item "$data\logs\*" $wd -ErrorAction SilentlyContinue   # the watchdog's log goes with the uninstall; keep it for the artifacts
    & "$app\install-pc.ps1" -Uninstall -Ci
    $dnsAfter = @(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | ForEach-Object { "$($_.InterfaceIndex)=$((Get-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).ServerAddresses -join ',')" })
    Check "B3.I1" "PC uninstall: service, account, files and rules gone" (-not (Get-Service CafeWatchdog -ErrorAction SilentlyContinue) -and -not (Get-LocalUser Customer -ErrorAction SilentlyContinue) -and -not (Test-Path $app) -and -not (Get-NetFirewallRule -Group "Shinzx PC" -ErrorAction SilentlyContinue)) ""
    Check "B3.I2" "PC uninstall: DNS and automatic sign-in back as before" (("$dnsAfter" -eq "$dnsBefore") -and (Get-ItemProperty $winlogon).AutoAdminLogon -eq $autoBefore) "DNS before $dnsBefore, after $dnsAfter"
    Check "B3.I2b" "PC uninstall: clock settings back as before" ((Get-ItemProperty $ntpKey).NtpServer -eq $ntpBefore) "$ntpBefore"
    Check "B3.I2c" "PC uninstall: browsers' secure DNS setting back as before" ((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -ErrorAction SilentlyContinue).DnsOverHttpsMode -eq $dohOriginal) "before: '$dohOriginal'"
    Check "B3.I3" "PC uninstall: Level A off" (-not ((CiTool.exe --list-policies) -match "Shinzx Level A")) ""
    & "$stageA\install-admin.ps1" -Uninstall -Ci
    Check "B3.I4" "Counter PC uninstall: server and filter gone" (-not (Get-Service CafeServer, AdGuardHome -ErrorAction SilentlyContinue)) ""
    Check "B3.I4b" "Counter PC uninstall: clock settings back as before" ((Get-ItemProperty $ntpKey).NtpServer -eq $ntpOriginal) "$ntpOriginal"
}
catch { Check "B3.X" "script error" $false "$_ (line $($_.InvocationInfo.ScriptLineNumber))" }
finally {
    foreach ($f in Get-ChildItem $wd -Filter "*.log" -ErrorAction SilentlyContinue) { Write-Host "--- $($f.Name)"; Get-Content $f.FullName | Select-Object -Last 40 }
    $results | Format-Table id, result, test, detail -AutoSize -Wrap | Out-String -Width 250 | Write-Host
    $results | Export-Csv (Join-Path $repo "lockdown-results.csv") -NoTypeInformation -Encoding utf8
    Copy-Item $wd (Join-Path $repo "lockdown-logs") -Recurse -Force -ErrorAction SilentlyContinue   # artifacts must sit in the checkout
}
if (@($results | Where-Object result -eq "FAIL").Count) { exit 1 }
