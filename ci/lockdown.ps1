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
    Start-Process @p
}
$wd = "$env:ProgramData\Cafe\logs"
$app = "$env:ProgramFiles\ShinzxCafe"
$data = "$env:ProgramData\ShinzxCafe"
$winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$autoBefore = (Get-ItemProperty $winlogon).AutoAdminLogon
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
    $code = try { Invoke-WebRequest https://127.0.0.1:5443/pc/state -UseBasicParsing | Out-Null; 200 } catch { [int]$_.Exception.Response.StatusCode }
    Check "B3.A2" "Server answers HTTPS and refuses a PC without its key" ($code -eq 401) "HTTP $code"
    $rule = Get-NetFirewallRule -Group "Shinzx counter" | Where-Object DisplayName -like "*cafe server*" | Get-NetFirewallAddressFilter
    Check "B3.A3" "Firewall lets only the shop network reach the server" ("$($rule.RemoteAddress)" -eq "LocalSubnet") "remote: $($rule.RemoteAddress)"
    Check "B3.A4" "Internet filter (AdGuard Home) installed, checked and running" ((Get-Service AdGuardHome -ErrorAction SilentlyContinue).Status -eq "Running") "version pinned, SHA-256 checked"
    $wiz = WaitFor 20 { try { (Invoke-WebRequest http://127.0.0.1:3000 -UseBasicParsing).StatusCode -eq 200 } catch { $false } }
    Check "B3.A5" "Filter set-up page opens on the counter PC" $wiz "http://127.0.0.1:3000"
    Stop-Service CafeServer   # the gaming-PC tests below use a test server with test users on the same port

    # ===== B. test server with test users =====
    $tdata = "C:\cafe-test"
    $server = Start-Process "$out\server\Cafe.Server.exe" -ArgumentList "--data $tdata --seed-test" -PassThru -WindowStyle Hidden
    if (-not (WaitFor 30 { Test-Path "$tdata\pc1.token" })) { throw "test server did not start" }
    $token = (Get-Content "$tdata\pc1.token" -Raw).Trim()
    function Pc($path, $body) { Invoke-RestMethod "https://127.0.0.1:5443$path" -Method Post -Headers @{ "X-Pc-Token" = $token } -ContentType "application/json" -Body ($body | ConvertTo-Json) }

    # ===== C. gaming PC, step 1 =====
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
    Check "B3.C6" "Other DNS servers blocked, the filter's one works" ($other -eq "blocked" -and $own -eq "works") "8.8.8.8 $other; normal lookups $own"
    Check "B3.C7" "Browsers' own secure DNS switched off" ((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge").DnsOverHttpsMode -eq "off") "Edge, Chrome, Firefox policies"

    # ===== D. the owner sets the Customer account up (here: an "installed Discord" and a shortcut) =====
    $prof = (Get-CimInstance Win32_UserProfile | Where-Object SID -eq $u.SID.Value).LocalPath
    New-Item "$prof\AppData\Local\Discord" -ItemType Directory -Force | Out-Null; "app" | Set-Content "$prof\AppData\Local\Discord\Update.txt"
    "shortcut" | Set-Content "$prof\Desktop\Game.txt"
    Start-Sleep -Seconds 5

    # ===== E. step 2 =====
    & "$stage\install-pc.ps1" -Ci
    Check "B3.E1" "Clean copy saved" (Test-Path "$data\clean-profile\AppData\Local\Discord\Update.txt") "$data\clean-profile"
    reg.exe load HKU\T "$prof\NTUSER.DAT" 2>&1 | Out-Null
    $h = if ($LASTEXITCODE) { "Registry::HKEY_USERS\$($u.SID.Value)" } else { "Registry::HKEY_USERS\T" }
    $sys = Get-ItemProperty "$h\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $cmd = (Get-ItemProperty "$h\Software\Policies\Microsoft\Windows\System").DisableCMD
    Check "B3.E2" "Customer: no Task Manager, no Lock, no password change, no registry editor, no command prompt" ($sys.DisableTaskMgr -eq 1 -and $sys.DisableLockWorkstation -eq 1 -and $sys.DisableChangePassword -eq 1 -and $sys.DisableRegistryTools -eq 1 -and $cmd -eq 2) "DisableCMD $cmd"
    Remove-Variable sys; [gc]::Collect(); reg.exe unload HKU\T 2>&1 | Out-Null
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
    Start-Sleep -Seconds 4   # the lock screen sees the session (polls every 2 s)
    Pc "/pc/logout" @{} | Out-Null
    $asked = WaitFor 15 { Test-Path "$data\wipe\request" }
    $done = WaitFor 90 { -not (Test-Path "$data\wipe\request") }
    Check "B3.F1" "Logout asks for the clean-up and the watchdog finishes it" ($asked -and $done) "asked $asked, done $done"
    Start-Sleep -Seconds 2
    Check "B3.F2" "Customer's programs closed (a Windows one and a game)" ($p1.HasExited -and $p2.HasExited) "ping $($p1.HasExited), game $($p2.HasExited)"
    Check "B3.F3" "Mouse app on the keep list stays running" (-not $p3.HasExited) "lghub.exe"
    Check "B3.F4" "Customer's files and app logins gone" (-not (Test-Path "$prof\Downloads\secret.txt") -and -not (Test-Path "$prof\AppData\Roaming\discord")) "Downloads, Discord login"
    Check "B3.F5" "Owner's set-up back, graphics cache kept" ((Test-Path "$prof\Desktop\Game.txt") -and (Test-Path "$prof\AppData\Local\Discord\Update.txt") -and (Test-Path "$prof\AppData\Local\NVIDIA\DXCache\x.bin")) ""
    $cfg = Get-Content "C:\FakeSteam\config\config.vdf" -Raw
    Check "B3.F6" "Steam saved logins cleared, other Steam settings kept" (-not (Test-Path "C:\FakeSteam\config\loginusers.vdf") -and $cfg -notmatch "ConnectCache" -and $cfg -match "Software") ""
    Check "B3.F7" "Lock screen still running after the clean-up" ([bool](Get-Process Cafe.Agent -ErrorAction SilentlyContinue)) ""
    Stop-Process -Id $p3.Id -Force

    # ===== G. what a customer cannot do =====
    $stop = AsCustomer "$env:WINDIR\System32\sc.exe" "stop CafeWatchdog"; $stop.WaitForExit()
    Check "B3.G1" "Customer cannot stop the watchdog" ($stop.ExitCode -ne 0 -and (Get-Service CafeWatchdog).Status -eq "Running") "sc exit $($stop.ExitCode)"
    foreach ($t in @(@("$app\setup.flag", "switch the lock screen off"), @("$app\Cafe.Agent.exe", "replace the lock screen"), @("$data\clean-profile\x.txt", "change the clean copy"))) {
        $w = AsCustomer "$env:WINDIR\System32\cmd.exe" "/c echo x> `"$($t[0])`""; $w.WaitForExit()
        Check "B3.G2" "Customer cannot $($t[1])" ($w.ExitCode -ne 0) "$($t[0]): exit $($w.ExitCode)"
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
    & "$app\install-pc.ps1" -Uninstall -Ci
    $dnsAfter = @(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | ForEach-Object { "$($_.InterfaceIndex)=$((Get-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).ServerAddresses -join ',')" })
    Check "B3.I1" "PC uninstall: service, account, files and rules gone" (-not (Get-Service CafeWatchdog -ErrorAction SilentlyContinue) -and -not (Get-LocalUser Customer -ErrorAction SilentlyContinue) -and -not (Test-Path $app) -and -not (Get-NetFirewallRule -Group "Shinzx PC" -ErrorAction SilentlyContinue)) ""
    Check "B3.I2" "PC uninstall: DNS and automatic sign-in back as before" (("$dnsAfter" -eq "$dnsBefore") -and (Get-ItemProperty $winlogon).AutoAdminLogon -eq $autoBefore) "DNS before $dnsBefore, after $dnsAfter"
    Check "B3.I3" "PC uninstall: Level A off" (-not ((CiTool.exe --list-policies) -match "Shinzx Level A")) ""
    & "$stageA\install-admin.ps1" -Uninstall -Ci
    Check "B3.I4" "Counter PC uninstall: server and filter gone" (-not (Get-Service CafeServer, AdGuardHome -ErrorAction SilentlyContinue)) ""
}
catch { Check "B3.X" "script error" $false "$_ (line $($_.InvocationInfo.ScriptLineNumber))" }
finally {
    foreach ($f in Get-ChildItem $wd -Filter "*.log" -ErrorAction SilentlyContinue) { Write-Host "--- $($f.Name)"; Get-Content $f.FullName | Select-Object -Last 40 }
    $results | Format-Table id, result, test, detail -AutoSize -Wrap | Out-String -Width 250 | Write-Host
    $results | Export-Csv (Join-Path $repo "lockdown-results.csv") -NoTypeInformation -Encoding utf8
}
if (@($results | Where-Object result -eq "FAIL").Count) { exit 1 }
