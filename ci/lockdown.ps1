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
function Get-QueuedActionCount($path) {
    if (-not (Test-Path -LiteralPath $path)) { return 0 }
    $items = ConvertFrom-Json -InputObject (Get-Content -LiteralPath $path -Raw)
    if ($null -eq $items) { return 0 }
    return @($items).Count
}
if (-not ("CafeDpapiProbe" -as [type])) {
    Add-Type @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class CafeDpapiProbe {
    [StructLayout(LayoutKind.Sequential)] struct DataBlob { public int Length; public IntPtr Data; }
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CryptUnprotectData(ref DataBlob input, out IntPtr description, IntPtr entropy, IntPtr reserved,
        IntPtr prompt, uint flags, out DataBlob output);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    public static byte[] Unprotect(byte[] protectedBytes) {
        var handle = GCHandle.Alloc(protectedBytes, GCHandleType.Pinned);
        try {
            var input = new DataBlob { Length = protectedBytes.Length, Data = handle.AddrOfPinnedObject() };
            IntPtr description;
            DataBlob output;
            if (!CryptUnprotectData(ref input, out description, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, out output))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (description != IntPtr.Zero) LocalFree(description);
            try { var clear = new byte[output.Length]; Marshal.Copy(output.Data, clear, 0, clear.Length); return clear; }
            finally { LocalFree(output.Data); }
        } finally { handle.Free(); }
    }
}
'@
}
if (-not ("CafeTotpProbe" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
public static class CafeTotpProbe
{
    const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    public static string Current(string secret)
    {
        var key = Decode(secret);
        long step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var msg = BitConverter.GetBytes(step);
        if (BitConverter.IsLittleEndian) Array.Reverse(msg);
        using (var hmac = new HMACSHA1(key))
        {
            var hash = hmac.ComputeHash(msg);
            int offset = hash[hash.Length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24) | (hash[offset + 1] << 16) |
                (hash[offset + 2] << 8) | hash[offset + 3];
            return (binary % 1000000).ToString("D6", CultureInfo.InvariantCulture);
        }
    }
    static byte[] Decode(string text)
    {
        var bytes = new List<byte>();
        int buffer = 0, bits = 0;
        foreach (char c in text.ToUpperInvariant().Replace(" ", "").TrimEnd('='))
        {
            int value = Alphabet.IndexOf(c);
            if (value < 0) throw new FormatException("Invalid Base32 test secret.");
            buffer = ((buffer << 5) | value) & 0xFFFF;
            bits += 5;
            if (bits >= 8) { bytes.Add((byte)(buffer >> (bits - 8))); bits -= 8; }
        }
        return bytes.ToArray();
    }
}
'@
}
function AsCustomer($exe, $argList) { # start a program as Customer (password read from where auto sign-in keeps it)
    $pw = New-Object Security.SecureString; foreach ($c in ([Cafe.Lsa]::Read("DefaultPassword")).ToCharArray()) { $pw.AppendChar($c) }
    $cred = [pscredential]::new("Customer", $pw)
    $p = @{ FilePath = $exe; Credential = $cred; LoadUserProfile = $true; WorkingDirectory = "$env:WINDIR\System32"; PassThru = $true; WindowStyle = "Hidden" }
    if ($argList) { $p.ArgumentList = $argList }
    $proc = Start-Process @p
    $null = $proc.Handle   # without this Windows PowerShell never reports the exit code
    $proc
}
if (-not ("CafeWindowProbe" -as [type])) {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class CafeWindowProbe {
    delegate bool EnumProc(IntPtr window, IntPtr state);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc callback, IntPtr state);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr window, StringBuilder text, int max);
    public static bool HasVisibleWindow(int pid) {
        bool found = false;
        EnumWindows((window, state) => {
            uint owner;
            GetWindowThreadProcessId(window, out owner);
            if (owner == (uint)pid && IsWindowVisible(window)) {
                var title = new StringBuilder(256);
                GetWindowText(window, title, title.Capacity);
                if (title.Length > 0) { found = true; return false; }
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
'@
}
function CustomerPs($command) { # run PowerShell as Customer; returns its exit code (0 = the command worked)
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("`$ErrorActionPreference = 'Stop'; $command"))
    $p = AsCustomer "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" "-NoProfile -EncodedCommand $enc"; $p.WaitForExit(); $p.ExitCode
}
$runKey = "Software\Microsoft\Windows\CurrentVersion\Run"
$wd = "$env:ProgramData\Cafe\logs"
$app = "$env:ProgramFiles\GamingCafe"
$data = "$env:ProgramData\GamingCafe"
$winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$autoBefore = (Get-ItemProperty $winlogon).AutoAdminLogon
$ntpKey = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"
$ntpOriginal = (Get-ItemProperty $ntpKey).NtpServer
$idleKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$idleOriginal = Get-ItemProperty $idleKey -ErrorAction SilentlyContinue
$enableLUAOriginal = $idleOriginal.EnableLUA
$dohOriginal = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -ErrorAction SilentlyContinue).DnsOverHttpsMode
# control for C6: other DNS servers must answer BEFORE the install, or "blocked" afterwards proves nothing
$googleBefore = try { Resolve-DnsName example.com -Server 8.8.8.8 -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null; "answered" } catch { "blocked" }
$defaultIfIndexes = @(Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -ExpandProperty InterfaceIndex -Unique)
if (-not $defaultIfIndexes) { throw "No IPv4 default route found" }
$dnsBefore = @($defaultIfIndexes | ForEach-Object { $i = $_; "$i=$((Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4).ServerAddresses -join ',')" })
$runnerDns = (Get-DnsClientServerAddress -InterfaceIndex $defaultIfIndexes[0] -AddressFamily IPv4).ServerAddresses[0]

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
    $rule = Get-NetFirewallRule -Group "Cafe counter" | Where-Object DisplayName -like "*cafe server*" | Get-NetFirewallAddressFilter
    Check "B3.A3" "Firewall lets only the shop network reach the server" ("$($rule.RemoteAddress)" -eq "LocalSubnet") "remote: $($rule.RemoteAddress)"
    Check "B3.A4" "Internet filter (AdGuard Home) installed, checked and running" ((Get-Service AdGuardHome -ErrorAction SilentlyContinue).Status -eq "Running") "version pinned, SHA-256 checked"
    $wiz = WaitFor 20 { try { (Invoke-WebRequest http://127.0.0.1:3000 -UseBasicParsing).StatusCode -eq 200 } catch { $false } }
    Check "B3.A5" "Filter set-up page opens on the counter PC" $wiz "http://127.0.0.1:3000"
    Check "B3.A6" "Internet filter restarts by itself if it stops" ((sc.exe qfailure AdGuardHome) -match "RESTART") ""
    $idle = Get-ItemProperty $idleKey
    Check "B3.A7" "Windows locks the counter PC after 10 idle minutes" ($idle.InactivityTimeoutSecs -eq 600) "InactivityTimeoutSecs $($idle.InactivityTimeoutSecs)"
    Check "B3.A7b" "Install leaves Windows UAC enabled setting unchanged" ($idle.EnableLUA -eq $enableLUAOriginal) "EnableLUA before $enableLUAOriginal, after $($idle.EnableLUA)"
    Stop-Service CafeServer   # the gaming-PC tests below use a test server with test users on the same port

    # ===== B. test server with test users =====
    $tdata = "C:\cafe-test"
    $server = Start-Process "$out\server\Cafe.Server.exe" -ArgumentList "--data $tdata --seed-test --seed-offline-secret-test" -PassThru -WindowStyle Hidden
    if (-not (WaitFor 30 { (Test-Path "$tdata\pc1.token") -and (Test-Path "$tdata\server.pin") })) { throw "test server did not start" }
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
    # the very first Customer sign-in on a fresh machine sometimes reports no exit code at all; the retry must still exit 0
    if ($null -eq $first.ExitCode) { $first = AsCustomer "$env:WINDIR\System32\cmd.exe" "/c exit"; $first.WaitForExit() }
    Check "B3.C3" "Stored sign-in password really signs in Customer" ($first.ExitCode -eq 0) "exit $($first.ExitCode)"
    $s = Get-CimInstance Win32_Service -Filter "Name='CafeWatchdog'"
    Check "B3.C4" "Watchdog service: automatic, as SYSTEM, also in Safe Mode" ($s.StartMode -eq "Auto" -and $s.StartName -eq "LocalSystem" -and (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\CafeWatchdog") -and (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\CafeWatchdog")) "$($s.State)"
    $tokenRead = CustomerPs "[IO.File]::ReadAllText('$data\keys\pc.token') | Out-Null"
    $pinRead = CustomerPs "[IO.File]::ReadAllText('$data\keys\server.pin') | Out-Null"
    Check "B3.C4b" "Customer cannot read the PC token or certificate pin" ($tokenRead -ne 0 -and $pinRead -ne 0 -and -not (Test-Path "$app\pc.token") -and -not (Test-Path "$app\server.pin") -and -not (Test-Path "$stage\pc.token") -and -not (Test-Path "$stage\server.pin")) "token read exit $tokenRead, pin read exit $pinRead; source copies removed"
    $tokenDisk = [IO.File]::ReadAllBytes("$data\keys\pc.token")
    $tokenDiskText = [Text.Encoding]::UTF8.GetString($tokenDisk).Trim()
    $tokenClear = [Text.Encoding]::UTF8.GetString([CafeDpapiProbe]::Unprotect($tokenDisk)).Trim()
    Check "B3.C4e" "PC token on disk is machine-DPAPI encrypted, not the plain token" ($tokenClear -eq $token -and $tokenDiskText -ne $token) "decrypted token matches server; disk bytes differ"
    $offlineCache = "$data\keys\offline-unlock.bin"
    for ($i = 0; $i -lt 30 -and -not (Test-Path $offlineCache); $i++) { Start-Sleep -Seconds 1 }
    $offlineCacheRead = CustomerPs "try { [IO.File]::ReadAllBytes('$offlineCache') | Out-Null; exit 0 } catch { exit 1 }"
    Check "B3.C4c" "Customer cannot read the machine-encrypted offline authenticator cache" ((Test-Path $offlineCache) -and $offlineCacheRead -ne 0) "cache exists $((Test-Path $offlineCache)); customer read exit $offlineCacheRead"
    $fixture = Get-Content "$tdata\offline-secret-fixture.json" -Raw | ConvertFrom-Json
    $clearOffline = [CafeDpapiProbe]::Unprotect([IO.File]::ReadAllBytes($offlineCache))
    $offlineState = [Text.Encoding]::UTF8.GetString($clearOffline) | ConvertFrom-Json
    $cachedSecrets = @($offlineState.Accounts | ForEach-Object { $_.Secret })
    $expectedOffline = @($fixture.ownerOffline, $fixture.staffOffline)
    $counterSecrets = @($fixture.ownerCounter, $fixture.staffCounter)
    $offlineOnly = ($cachedSecrets.Count -eq 2) -and
        (@($cachedSecrets | Where-Object { $_ -notin $expectedOffline -or $_ -in $counterSecrets }).Count -eq 0) -and
        (@($expectedOffline | Where-Object { $_ -notin $cachedSecrets }).Count -eq 0)
    Check "B3.C4d" "Offline cache contains only separate offline-unlock secrets, never counter two-step secrets" $offlineOnly "cached $($cachedSecrets.Count) offline secrets; counter secrets excluded"
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
    # CI runs without a Customer interactive session; this admin-only marker exercises the profile reset after
    # the test Customer processes exit. Installed cafe PCs never contain this file and log off the real Customer session.
    New-Item "$app\test-wipe-mode.flag" -ItemType File -Force | Out-Null
    Check "B3.E1" "Clean copy saved" (Test-Path "$data\clean-profile\AppData\Local\Discord\Update.txt") "$data\clean-profile"
    # An older install has a clean file copy but no registry-hive baseline. Require owner setup instead of
    # letting the first customer logout fail forever because the reset snapshot is missing.
    $heldHive = "$data\clean-profile-hive.migration-test"
    Move-Item "$data\clean-profile-hive" $heldHive
    & "$stage\install-pc.ps1" -Ci
    $migrationSetup = (Test-Path "$app\setup.flag") -and -not (Get-Process Cafe.Agent -ErrorAction SilentlyContinue)
    Move-Item $heldHive "$data\clean-profile-hive"
    Remove-Item "$app\setup.flag" -Force -ErrorAction SilentlyContinue
    Restart-Service CafeWatchdog -Force
    $migrationLock = WaitFor 20 {
        @(Get-Process Cafe.Agent -ErrorAction SilentlyContinue | Where-Object { [CafeWindowProbe]::HasVisibleWindow($_.Id) }).Count -gt 0
    }
    Check "B3.E1b" "An existing install without a clean hive requests owner setup and restores the lock screen after its baseline returns" ($migrationSetup -and $migrationLock) "setup requested $migrationSetup; lock screen restored $migrationLock"
    cmd.exe /c "reg load HKU\T `"$prof\NTUSER.DAT`" >nul 2>&1"
    $h = if ($LASTEXITCODE) { "Registry::HKEY_USERS\$($u.SID.Value)" } else { "Registry::HKEY_USERS\T" }
    $sys = Get-ItemProperty "$h\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $cmd = (Get-ItemProperty "$h\Software\Policies\Microsoft\Windows\System").DisableCMD
    Check "B3.E2" "Customer: no Task Manager, no Lock, no password change, no registry editor, no command prompt" ($sys.DisableTaskMgr -eq 1 -and $sys.DisableLockWorkstation -eq 1 -and $sys.DisableChangePassword -eq 1 -and $sys.DisableRegistryTools -eq 1 -and $cmd -eq 2) "DisableCMD $cmd"
    Remove-Variable sys; [gc]::Collect(); cmd.exe /c "reg unload HKU\T >nul 2>&1"
    Check "B3.E3" "Switch user hidden" ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").HideFastUserSwitching -eq 1) ""
    $hiveRead = CustomerPs "try { [IO.File]::ReadAllBytes('$data\clean-profile-hive\NTUSER.DAT') | Out-Null; if (Test-Path '$data\clean-profile-hive\UsrClass.dat') { [IO.File]::ReadAllBytes('$data\clean-profile-hive\UsrClass.dat') | Out-Null }; exit 0 } catch { exit 1 }"
    Check "B3.E6" "Owner registry hives are saved and Customer cannot read them" ((Test-Path "$data\clean-profile-hive\NTUSER.DAT") -and $hiveRead -ne 0) "NTUSER.DAT and optional UsrClass.dat are admin/SYSTEM-only; read attempt exit $hiveRead"
    # Prove that the watchdog still starts the locked UI when its protected keys are absent,
    # then restores the proxy after the 30-second retry when the keys return.
    Stop-Service CafeWatchdog -Force
    Get-Process Cafe.Agent -ErrorAction SilentlyContinue | Stop-Process -Force
    $heldKeys = Join-Path $env:TEMP ("cafe-held-keys-" + [guid]::NewGuid().ToString("N"))
    New-Item $heldKeys -ItemType Directory | Out-Null
    Move-Item "$data\keys\pc.token" "$heldKeys\pc.token"
    Move-Item "$data\keys\server.pin" "$heldKeys\server.pin"
    Start-Service CafeWatchdog
    $agentUp = WaitFor 20 { Get-Process Cafe.Agent -ErrorAction SilentlyContinue }
    $watchdogLog = Join-Path "$data\logs" "watchdog-$(Get-Date -Format yyyyMMdd).log"
    $missingKeysLogged = WaitFor 10 { (Test-Path $watchdogLog) -and (Select-String -Path $watchdogLog -Pattern "PC pipe proxy start failed" -SimpleMatch) }
    $retryLogStart = if (Test-Path $watchdogLog) { (Get-Content $watchdogLog).Count } else { 0 }
    Move-Item "$heldKeys\pc.token" "$data\keys\pc.token"
    Move-Item "$heldKeys\server.pin" "$data\keys\server.pin"
    Remove-Item $heldKeys -Force
    $proxyRetried = WaitFor 45 {
        if (-not (Test-Path $watchdogLog)) { return $false }
        $lines = @(Get-Content $watchdogLog)
        $lines.Count -gt $retryLogStart -and [bool]($lines | Select-Object -Skip $retryLogStart | Select-String -Pattern "PC pipe proxy started" -SimpleMatch)
    }
    Check "B3.E4" "Watchdog starts the lock screen without keys and retries the proxy after keys return" ($agentUp -and $missingKeysLogged -and $proxyRetried -and -not (Test-Path "$app\setup.flag")) "agent $agentUp, missing-key failure logged $missingKeysLogged, proxy retry $proxyRetried"

    # The pipe ACL admits Customer, but the process-image check must refuse a different executable.
    $probe = AsCustomer "$app\Cafe.Watchdog.exe" "--test-pipe-probe"
    $probe.WaitForExit()
    Start-Sleep -Milliseconds 300
    $pipeRefused = $probe.ExitCode
    $refusalLogged = (Test-Path $watchdogLog) -and [bool](Select-String -Path $watchdogLog -Pattern "refused named-pipe client process" -SimpleMatch)
    Check "B3.E4b" "A non-Cafe.Agent.exe process running as Customer is refused by the pipe" ($pipeRefused -eq 0 -and $refusalLogged) "probe exit $pipeRefused, refusal logged $refusalLogged"
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
    # A fresh request is handled promptly; an unchanged active-session reason is logged only once across retries.
    $watchdogLog = Join-Path "$data\logs" "watchdog-$(Get-Date -Format yyyyMMdd).log"
    $beforeDeferred = if (Test-Path $watchdogLog) { @(Select-String -Path $watchdogLog -Pattern "cleanup deferred (session active)" -SimpleMatch).Count } else { 0 }
    Set-Content "$data\wipe\request" ""
    # the arm test machine can take more than 5 s to reach the server check
    $firstDeferred = WaitFor 15 { (Test-Path $watchdogLog) -and @(Select-String -Path $watchdogLog -Pattern "cleanup deferred (session active)" -SimpleMatch).Count -gt $beforeDeferred }
    Start-Sleep -Seconds 32
    $afterDeferred = if (Test-Path $watchdogLog) { @(Select-String -Path $watchdogLog -Pattern "cleanup deferred (session active)" -SimpleMatch).Count } else { 0 }
    Check "B3.F0" "Fresh request is tried promptly and unchanged deferral is logged once" ((Test-Path "$data\wipe\request") -and $firstDeferred -and $afterDeferred -eq ($beforeDeferred + 1)) "log lines $beforeDeferred -> $afterDeferred"
    $f0RequestPath = "$data\wipe\request"
    $f0Removed = $false
    $f0RemoveError = ""
    for ($attempt = 0; $attempt -le 15; $attempt++) {
        try {
            if (Test-Path -LiteralPath $f0RequestPath) {
                Remove-Item -LiteralPath $f0RequestPath -Force -ErrorAction Stop
            }
            if (-not (Test-Path -LiteralPath $f0RequestPath)) {
                $f0Removed = $true
                break
            }
            $f0RemoveError = "request path still exists"
        } catch {
            $f0RemoveError = $_.Exception.Message
        }
        if ($attempt -lt 15) { Start-Sleep -Seconds 1 }
    }
    Check "B3.F0c" "F0 test request removed" $f0Removed $(if ($f0Removed) { "request path is gone" } else { $f0RemoveError })
    $p1 = AsCustomer "$env:WINDIR\System32\PING.EXE" "-t 127.0.0.1"
    $p2 = AsCustomer "$env:ProgramFiles\FakeGame\game.exe" "-t 127.0.0.1"
    $p3 = AsCustomer "$env:ProgramFiles\FakeMouse\lghub.exe" "-t 127.0.0.1"
    New-Item "$prof\AppData\Roaming\discord\Local Storage" -ItemType Directory -Force | Out-Null; "token" | Set-Content "$prof\AppData\Roaming\discord\Local Storage\login.txt"
    "secret" | Set-Content "$prof\Downloads\secret.txt"
    Remove-Item "$prof\Desktop\Game.txt"
    New-Item "$prof\AppData\Local\NVIDIA\DXCache" -ItemType Directory -Force | Out-Null; "cache" | Set-Content "$prof\AppData\Local\NVIDIA\DXCache\x.bin"
    # what a customer could leave behind to run again for the next customer, and a link meant to trick the clean-up
    $taskMade = CustomerPs "schtasks.exe /create /tn CafeCustomerTask /tr 'C:\Windows\System32\PING.EXE 127.0.0.1' /sc minute /mo 30 /f; exit `$LASTEXITCODE"
    $runMade = CustomerPs "Set-ItemProperty HKCU:\$runKey Evil 'C:\evil.exe'"
    New-Item "C:\CafeCanary" -ItemType Directory -Force | Out-Null
    icacls.exe "C:\CafeCanary" /inheritance:r /grant "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" | Out-Null   # the customer alone cannot delete it
    "must stay" | Set-Content "C:\CafeCanary\keep.txt"   # made after the folder rule, so it takes it over
    $hard = CustomerPs "New-Item -ItemType HardLink -Path '$prof\Desktop\Game.txt' -Target 'C:\CafeCanary\keep.txt' -Force | Out-Null"   # a trap where the owner's shortcut was
    $linkMade = CustomerPs "New-Item -ItemType Junction -Path '$prof\Downloads\link' -Target 'C:\CafeCanary' | Out-Null"
    New-Item "$env:ProgramFiles\OpenFolder" -ItemType Directory -Force | Out-Null
    icacls.exe "$env:ProgramFiles\OpenFolder" /grant "*S-1-5-32-545:(OI)(CI)M" | Out-Null   # like Steam's folder: any user can write
    Copy-Item "$env:WINDIR\System32\PING.EXE" "$env:ProgramFiles\OpenFolder\lghub.exe"
    $p4 = AsCustomer "$env:ProgramFiles\OpenFolder\lghub.exe" "-t 127.0.0.1"
    Start-Sleep -Seconds 4   # the lock screen sees the session (polls every 2 s)
    # A directory containing a junction at the request path is a request, not a reason to follow it.
    New-Item "$data\wipe\request" -ItemType Directory -Force | Out-Null
    New-Item -ItemType Junction -Path "$data\wipe\request\escape" -Target "C:\CafeCanary" | Out-Null
    $resetClock = [Diagnostics.Stopwatch]::StartNew()
    Pc "/pc/logout" @{} | Out-Null
    $asked = WaitFor 15 { Test-Path "$data\wipe\request" }
    $done = WaitFor 90 { -not (Test-Path "$data\wipe\request") }
    $resetLockReady = WaitFor 15 {
        @(Get-Process Cafe.Agent -ErrorAction SilentlyContinue | Where-Object { [CafeWindowProbe]::HasVisibleWindow($_.Id) }).Count -gt 0
    }
    $resetClock.Stop()
    $resetSeconds = [math]::Round($resetClock.Elapsed.TotalSeconds, 2)
    Check "B3.F1" "Logout request folder and its junction are removed without following the link" ($asked -and $done -and (Test-Path "C:\CafeCanary\keep.txt")) "asked $asked, done $done"
    Check "B3.M1" "Full profile reset logout-to-lock-screen-ready measurement" ($done -and $resetLockReady) "$resetSeconds seconds; request removed $done; lock screen ready $resetLockReady"
    # A junction at the request path itself is also removed without touching its target.
    New-Item -ItemType Junction -Path "$data\wipe\request" -Target "C:\CafeCanary" | Out-Null
    $linkDone = WaitFor 30 { -not (Test-Path "$data\wipe\request") }
    Check "B3.F1b" "A junction at the request path is removed without following it" ($linkDone -and (Test-Path "C:\CafeCanary\keep.txt")) "done $linkDone"
    # A hard link is still a file, but it must not make the lock screen overwrite its target.
    New-Item -ItemType HardLink -Path "$data\wipe\request" -Target "C:\CafeCanary\keep.txt" -Force | Out-Null
    $hardLinkDone = WaitFor 30 { -not (Test-Path "$data\wipe\request") }
    Check "B3.F1c" "A hard-linked request is replaced without changing its target" ($hardLinkDone -and (Get-Content "C:\CafeCanary\keep.txt" -Raw) -eq "must stay`r`n") "done $hardLinkDone"
    # A failed clean-up keeps the request and the lock screen blocked; restoring the clean copy lets the next loop retry.
    Move-Item "$data\clean-profile" "$data\clean-profile.saved"
    Set-Content "$data\wipe\request" ""
    Start-Sleep -Seconds 5
    $blocked = Test-Path "$data\wipe\request"
    Stop-Service CafeWatchdog -Force
    Move-Item "$data\clean-profile.saved" "$data\clean-profile"
    Start-Service CafeWatchdog
    $retryDone = WaitFor 45 { -not (Test-Path "$data\wipe\request") }
    Check "B3.F1d" "A failed reset stays pending and succeeds after watchdog restart" ($blocked -and $retryDone) "blocked $blocked, retry $retryDone"

    # Verify the full profile + registry hives were replaced, then exercise the account after the reset.
    $prof = (Get-CimInstance Win32_UserProfile | Where-Object SID -eq $u.SID.Value).LocalPath
    $ntUserMatch = (Test-Path "$prof\NTUSER.DAT") -and ((Get-FileHash "$prof\NTUSER.DAT").Hash -eq (Get-FileHash "$data\clean-profile-hive\NTUSER.DAT").Hash)
    $usrClassSnapshot = "$data\clean-profile-hive\UsrClass.dat"
    $usrClassPath = "$prof\AppData\Local\Microsoft\Windows\UsrClass.dat"
    $usrClassMatch = -not (Test-Path $usrClassSnapshot) -or ((Test-Path $usrClassPath) -and ((Get-FileHash $usrClassPath).Hash -eq (Get-FileHash $usrClassSnapshot).Hash))
    $hiveMatch = $ntUserMatch -and $usrClassMatch
    Check "B3.M2" "Customer profile folder and registry hives are restored from the owner's clean baseline" ((Test-Path $prof) -and (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($u.SID.Value)") -and $hiveMatch) "profile $prof; NTUSER.DAT $ntUserMatch; UsrClass.dat $usrClassMatch"
    $passwordProbe = AsCustomer "$env:WINDIR\System32\cmd.exe" "/c exit"
    $passwordOk = $passwordProbe.WaitForExit(15000) -and $passwordProbe.ExitCode -eq 0
    Check "B3.M3" "Customer password still works after a full profile reset" $passwordOk "AsCustomer exit success: $passwordOk"
    $wlAfterReset = Get-ItemProperty $winlogon
    $autoSignInOk = ($wlAfterReset.AutoAdminLogon -eq "1" -and $wlAfterReset.ForceAutoLogon -eq "1" -and
        $wlAfterReset.DefaultUserName -eq "Customer" -and $wlAfterReset.DefaultDomainName -eq $env:COMPUTERNAME -and
        -not [string]::IsNullOrWhiteSpace([Cafe.Lsa]::Read("DefaultPassword")))
    Check "B3.M4" "Automatic sign-in settings and saved password survive a full profile reset" $autoSignInOk "AutoAdminLogon, ForceAutoLogon, Customer name/domain and LSA password retained: $autoSignInOk"
    $gameProbe = AsCustomer "$env:ProgramFiles\FakeGame\game.exe" "-n 1 127.0.0.1"
    $allUsersGameOk = $gameProbe.WaitForExit(15000) -and $gameProbe.ExitCode -eq 0
    Check "B3.M5" "A game installed for all users still runs after a full profile reset" $allUsersGameOk "$env:ProgramFiles\FakeGame\game.exe exit success: $allUsersGameOk"
    # Wait for the profile service to unload Customer's live hive before inspecting the restored file.
    # Never read HKU\<SID>: Windows may unload it between a path check and a registry read.
    $customerHivePath = "Registry::HKEY_USERS\$($u.SID.Value)"
    $privateHivePath = "Registry::HKEY_USERS\CafeResetCheck"
    $privateHiveLoaded = $false
    $resetPolicies = $null
    $resetCmd = $null
    $resetRun = $null
    $settingsOk = $false
    $settingsDetail = $null
    try {
        $hiveReleased = $false
        for ($hiveWait = 0; $hiveWait -lt 60; $hiveWait++) {
            if (-not (Test-Path -LiteralPath $customerHivePath)) {
                $hiveReleased = $true
                break
            }
            Start-Sleep -Seconds 1
        }
        if (-not $hiveReleased -and -not (Test-Path -LiteralPath $customerHivePath)) {
            $hiveReleased = $true
        }

        if (-not $hiveReleased) {
            $settingsDetail = "Customer hive still loaded after 60 s"
        } else {
            reg.exe load "HKU\CafeResetCheck" "$prof\NTUSER.DAT" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Could not load the restored Customer registry hive under the private name." }
            $privateHiveLoaded = $true

            $policySystemPath = "$privateHivePath\Software\Microsoft\Windows\CurrentVersion\Policies\System"
            $policyCommandPath = "$privateHivePath\Software\Policies\Microsoft\Windows\System"
            $runRegistryPath = "$privateHivePath\$runKey"
            $resetPolicies = Get-ItemProperty -LiteralPath $policySystemPath -ErrorAction Stop
            $resetCmd = (Get-ItemProperty -LiteralPath $policyCommandPath -ErrorAction Stop).DisableCMD
            $resetRun = Get-ItemProperty -LiteralPath $runRegistryPath -ErrorAction Stop
            $settingsOk = ($resetPolicies.DisableTaskMgr -eq 1 -and $resetCmd -eq 2 -and
                $resetRun.OwnerApp -eq "C:\owner.exe" -and -not $resetRun.Evil)
            $settingsDetail = "policy and Run keys restored from NTUSER.DAT: $settingsOk"
        }
    } catch {
        $settingsOk = $false
        $settingsDetail = "could not read restored NTUSER.DAT: $($_.Exception.Message)"
    } finally {
        if ($privateHiveLoaded) {
            [gc]::Collect()
            [gc]::WaitForPendingFinalizers()
            reg.exe unload "HKU\CafeResetCheck" | Out-Null
            if ($LASTEXITCODE -ne 0) {
                $settingsOk = $false
                $settingsDetail = "could not unload the private restored Customer hive"
            }
        }
    }
    Check "B3.M7" "Customer restrictions and owner autostart settings survive the new registry hive" $settingsOk $settingsDetail
    Get-Process Cafe.Agent -ErrorAction SilentlyContinue | Stop-Process -Force
    $resetLockReady = WaitFor 20 {
        @(Get-Process Cafe.Agent -ErrorAction SilentlyContinue | Where-Object { [CafeWindowProbe]::HasVisibleWindow($_.Id) }).Count -gt 0
    }
    Check "B3.M6" "Watchdog starts the lock screen after a full profile reset" $resetLockReady "visible Cafe.Agent lock screen: $resetLockReady"
    # An unreachable counter server must also leave the request pending; reconnecting lets the next loop retry.
    Set-Content "$data\wipe\request" ""
    Stop-Process -Id $server.Id -Force
    Start-Sleep -Seconds 5
    $offlineKept = Test-Path "$data\wipe\request"
    $server = Start-Process "$out\server\Cafe.Server.exe" -ArgumentList "--data $tdata --seed-test" -PassThru -WindowStyle Hidden
    # The watchdog retry succeeding is the end-to-end proof that the server is reachable again.
    $offlineDone = WaitFor 45 { -not (Test-Path "$data\wipe\request") }
    Check "B3.F0b" "An unreachable server keeps the request pending until it reconnects" ($offlineKept -and $offlineDone) "kept $offlineKept, retry $offlineDone"
    Start-Sleep -Seconds 2
    Check "B3.F2" "Customer's programs closed by the full profile reset" ($p1.HasExited -and $p2.HasExited -and $p3.HasExited -and $p4.HasExited) "ping $($p1.HasExited), game $($p2.HasExited), mouse $($p3.HasExited), open-folder app $($p4.HasExited)"
    $mouseProbe = AsCustomer "$env:ProgramFiles\FakeMouse\lghub.exe" "-t 127.0.0.1"
    Start-Sleep -Seconds 1
    $mouseStarts = -not $mouseProbe.HasExited
    if ($mouseStarts) { Stop-Process -Id $mouseProbe.Id -Force -ErrorAction SilentlyContinue }
    Check "B3.F3" "Machine-wide mouse app can start again for Customer after reset" $mouseStarts "Program Files executable started as Customer: $mouseStarts"
    Check "B3.F4" "Customer's files and app logins gone" (-not (Test-Path "$prof\Downloads\secret.txt") -and -not (Test-Path "$prof\AppData\Roaming\discord")) "Downloads, Discord login"
    Check "B3.F5a" "Owner's desktop shortcut back" (Test-Path "$prof\Desktop\Game.txt") ""
    Check "B3.F5b" "Owner's Discord install kept" (Test-Path "$prof\AppData\Local\Discord\Update.txt") ""
    Check "B3.F5c" "Graphics card cache kept" (Test-Path "$prof\AppData\Local\NVIDIA\DXCache\x.bin") ""
    $cfg = Get-Content "C:\FakeSteam\config\config.vdf" -Raw
    Check "B3.F6" "Steam saved logins cleared, other Steam settings kept" (-not (Test-Path "C:\FakeSteam\config\loginusers.vdf") -and $cfg -notmatch "ConnectCache" -and $cfg -match "Software") ""
    Check "B3.F7" "Lock screen still running after the clean-up" ([bool](Get-Process Cafe.Agent -ErrorAction SilentlyContinue)) ""
    Check "B3.F8" "A customer's folder link cannot make the clean-up delete files elsewhere" ($linkMade -eq 0 -and (Test-Path "C:\CafeCanary\keep.txt")) "link made: exit $linkMade"
    Check "B3.F8b" "A customer's hard link cannot make the clean-up write over files elsewhere" ((Get-Content "C:\CafeCanary\keep.txt" -Raw) -eq "must stay`r`n") "hard link made: exit $hard (a refusal by Windows is a pass too)"
    Check "B3.F9" "A program named like a mouse app in a folder anyone can write is closed" ($p4.HasExited) "lghub.exe in an open folder"
    $resetOwnerRunOk = ($null -ne $resetRun -and $resetRun.OwnerApp -eq "C:\owner.exe" -and -not $resetRun.Evil)
    Check "B3.F10" "Customer's autostart entry removed, the owner's kept" ($runMade -eq 0 -and $ownerRun -eq 0 -and $resetOwnerRunOk) "made: customer exit $runMade, owner exit $ownerRun"
    cmd.exe /c "schtasks /query /tn CafeCustomerTask >nul 2>&1"
    Check "B3.F11" "Customer's scheduled task removed" ($taskMade -eq 0 -and $LASTEXITCODE -ne 0) "made: exit $taskMade"
    # Verify final server state and the bill through staff endpoints; queue-empty alone is not proof.
    $loginState = Pc "/pc/login" @{ phone = "9000000003"; pin = "2222" }
    $sessionBeforeLogout = $loginState.Session
    Stop-Process -Id $server.Id -Force
    $offlineSelfLock = AsCustomer "$app\Cafe.Agent.exe" "--test-queue-selflock"
    $selfLockQueued = $offlineSelfLock.WaitForExit(15000) -and $offlineSelfLock.ExitCode -eq 0
    $offlineLogout = AsCustomer "$app\Cafe.Agent.exe" "--test-queue-logout"
    $logoutQueued = $offlineLogout.WaitForExit(15000) -and $offlineLogout.ExitCode -eq 0
    $queuedLogoutFile = "$data\keys\pending-actions.json"
    $queuedActions = if (Test-Path $queuedLogoutFile) { @(Get-Content $queuedLogoutFile -Raw | ConvertFrom-Json) } else { @() }
    $logoutDurable = $selfLockQueued -and $logoutQueued -and $queuedActions.Count -eq 2 -and
        $queuedActions[0].Path -eq "/pc/selflock" -and $queuedActions[1].Path -eq "/pc/logout"
    # Pay-at-end has a 5-minute start grace; keep the outage beyond it so the staff bill must contain a charge.
    Start-Sleep -Seconds 310
    Get-Process Cafe.Agent -ErrorAction SilentlyContinue | Stop-Process -Force
    Restart-Service CafeWatchdog -Force
    $server = Start-Process "$out\server\Cafe.Server.exe" -ArgumentList "--data $tdata --seed-test" -PassThru -WindowStyle Hidden
    $script:f12LastHttpStatus = "not called"
    $script:f12LastCurlError = ""
    function Invoke-F12CurlJson([string[]]$curlArguments) {
        $curlOutput = & curl.exe -sSk -w "HTTPSTATUS:%{http_code}" @curlArguments 2>&1
        $curlExit = $LASTEXITCODE
        $curlText = ($curlOutput -join [char]10)
        $httpStatus = ""
        $responseBody = $curlText
        if ($curlText -match '(?s)^(.*)HTTPSTATUS:(\d{3})\s*$') {
            $responseBody = $matches[1]
            $httpStatus = $matches[2]
        }
        $script:f12LastHttpStatus = if ($httpStatus) { $httpStatus } else { "none" }
        if ($curlExit -ne 0) {
            $script:f12LastCurlError = "curl exit ${curlExit}: $curlText"
            return $null
        }
        if ($httpStatus -notmatch '^2\d\d$') {
            $script:f12LastCurlError = "HTTP $($script:f12LastHttpStatus): $responseBody"
            return $null
        }
        try {
            $script:f12LastCurlError = ""
            return (ConvertFrom-Json -InputObject $responseBody)
        } catch {
            $script:f12LastCurlError = "HTTP $httpStatus; invalid JSON: $($_.Exception.Message)"
            return $null
        }
    }
    $serverReady = WaitFor 90 {
        $probe = Invoke-F12CurlJson @("-H", "X-Pc-Token: $token", "https://127.0.0.1:5443/pc/state")
        $null -ne $probe
    }
    $staffLogin = $false
    $staffLoginError = ""
    if ($serverReady) {
        $staffCode = [CafeTotpProbe]::Current($fixture.staffCounter)
        $staffBody = @{ phone = "9000000002"; pin = "111111"; code = $staffCode } | ConvertTo-Json
        $staff = Invoke-F12CurlJson @("-X", "POST", "-H", "Content-Type: application/json", "--data-binary", $staffBody, "https://127.0.0.1:5443/staff/login")
        if ($null -ne $staff -and $staff.token) {
            $script:staffHeaders = @{ Authorization = "Bearer $($staff.token)" }
            $staffLogin = $true
        } else {
            $staffLoginError = $script:f12LastCurlError
        }
    } else {
        $staffLoginError = "readiness probe: HTTP $($script:f12LastHttpStatus); $($script:f12LastCurlError)"
    }
    $staffHeaders = $script:staffHeaders
    $script:finalStaffState = $null
    $script:finalStaffBill = $null
    $replayObserved = $staffLogin -and (WaitFor 90 {
        $state = Invoke-F12CurlJson @("-H", "Authorization: $($staffHeaders.Authorization)", "https://127.0.0.1:5443/staff/state/PC1")
        $bill = Invoke-F12CurlJson @("-H", "Authorization: $($staffHeaders.Authorization)", "https://127.0.0.1:5443/staff/bill/$sessionBeforeLogout")
        $script:finalStaffState = $state
        $script:finalStaffBill = $bill
        $pending = Get-QueuedActionCount $queuedLogoutFile
        ($null -ne $state) -and ($null -ne $bill) -and $null -eq $state.Session -and $bill.Charged -gt 0 -and $pending -eq 0
    })
    $finalStaffState = $script:finalStaffState
    $finalStaffBill = $script:finalStaffBill
    $remainingActions = Get-QueuedActionCount $queuedLogoutFile
    $logoutReplayed = [bool]($staffLogin -and $finalStaffState -and $null -eq $finalStaffState.Session -and $finalStaffBill.Charged -gt 0)
    Check "B3.F12" "Offline self-lock and logout survive lock-screen kill and watchdog restart; staff API confirms ended session and charged bill" ($sessionBeforeLogout -and $logoutDurable -and $logoutReplayed -and $remainingActions -eq 0) "session before $sessionBeforeLogout; self-lock queued $selfLockQueued; logout queued $logoutQueued; queue ordered $logoutDurable; server ready $serverReady; staff login $staffLogin ($staffLoginError); staff session $($finalStaffState.Session); bill charged $($finalStaffBill.Charged); pending actions $remainingActions; last HTTP $script:f12LastHttpStatus; curl error $script:f12LastCurlError"
    Stop-Process -Id $p3.Id -Force -ErrorAction SilentlyContinue

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
    Copy-Item "$out\timer\CafeTimerTest.exe" "C:\Games\Approved\game.exe"
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
    Remove-Item "$app\test-wipe-mode.flag" -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    Copy-Item "$data\logs\*" $wd -ErrorAction SilentlyContinue   # the watchdog's log goes with the uninstall; keep it for the artifacts
    & "$app\install-pc.ps1" -Uninstall -Ci
    $afterIfIndexes = @(Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -ExpandProperty InterfaceIndex -Unique)
    $dnsAfter = @($afterIfIndexes | ForEach-Object { $i = $_; "$i=$((Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4).ServerAddresses -join ',')" })
    Check "B3.I1" "PC uninstall: service, account, files and rules gone" (-not (Get-Service CafeWatchdog -ErrorAction SilentlyContinue) -and -not (Get-LocalUser Customer -ErrorAction SilentlyContinue) -and -not (Test-Path $app) -and -not (Get-NetFirewallRule -Group "Cafe PC" -ErrorAction SilentlyContinue)) ""
    Check "B3.I2" "PC uninstall: DNS and automatic sign-in back as before" (("$dnsAfter" -eq "$dnsBefore") -and (Get-ItemProperty $winlogon).AutoAdminLogon -eq $autoBefore) "DNS before $dnsBefore, after $dnsAfter"
    Check "B3.I2b" "PC uninstall: clock settings back as before" ((Get-ItemProperty $ntpKey).NtpServer -eq $ntpBefore) "$ntpBefore"
    Check "B3.I2c" "PC uninstall: browsers' secure DNS setting back as before" ((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -ErrorAction SilentlyContinue).DnsOverHttpsMode -eq $dohOriginal) "before: '$dohOriginal'"
    Check "B3.I3" "PC uninstall: Level A off" (-not ((CiTool.exe --list-policies) -match "Cafe Level A")) ""
    & "$stageA\install-admin.ps1" -Uninstall -Ci
    Check "B3.I4" "Counter PC uninstall: server and filter gone" (-not (Get-Service CafeServer, AdGuardHome -ErrorAction SilentlyContinue)) ""
    Check "B3.I4b" "Counter PC uninstall: clock settings back as before" ((Get-ItemProperty $ntpKey).NtpServer -eq $ntpOriginal) "$ntpOriginal"
    $idleAfter = Get-ItemProperty $idleKey -ErrorAction SilentlyContinue
    $idleBefore = if ($null -eq $idleOriginal) { $null } else { $idleOriginal.InactivityTimeoutSecs }
    $idleRestored = if ($null -eq $idleBefore) { $null -eq $idleAfter.InactivityTimeoutSecs } else { $idleAfter.InactivityTimeoutSecs -eq $idleBefore }
    Check "B3.I4c" "Counter PC uninstall: previous idle-lock setting restored" $idleRestored "before $idleBefore, after $($idleAfter.InactivityTimeoutSecs)"
}
catch { Check "B3.X" "script error" $false "$_ (line $($_.InvocationInfo.ScriptLineNumber))" }
finally {
    foreach ($f in Get-ChildItem (Join-Path $data "logs") -Filter "watchdog-*.log" -ErrorAction SilentlyContinue) {
        Copy-Item $f.FullName $wd -Force -ErrorAction SilentlyContinue
    }
    foreach ($f in Get-ChildItem $wd -Filter "*.log" -ErrorAction SilentlyContinue) { Write-Host "--- $($f.Name)"; Get-Content $f.FullName | Select-Object -Last 40 }
    $results | Format-Table id, result, test, detail -AutoSize -Wrap | Out-String -Width 250 | Write-Host
    $results | Export-Csv (Join-Path $repo "lockdown-results.csv") -NoTypeInformation -Encoding utf8
    Copy-Item $wd (Join-Path $repo "lockdown-logs") -Recurse -Force -ErrorAction SilentlyContinue   # artifacts must sit in the checkout
}
$failCount = @($results | Where-Object result -eq "FAIL").Count
if ($failCount -gt 0) { exit 1 } else { exit 0 }
