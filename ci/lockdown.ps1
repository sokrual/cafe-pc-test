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
function CounterWindows { "counter windows running: " + ((@(Get-CimInstance Win32_Process -Filter "Name='Cafe.Counter.exe'") | ForEach-Object { $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($_.ParentProcessId)"; "$($_.ProcessId) session $($_.SessionId) since $($_.CreationDate.ToString('HH:mm:ss')) from $($parent.Name) ($($parent.CommandLine)) as: $($_.CommandLine)" }) -join "; ") }
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
    [DllImport("user32.dll")] static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
    [DllImport("user32.dll")] static extern bool SetThreadDesktop(IntPtr desktop);
    [DllImport("user32.dll")] static extern bool CloseDesktop(IntPtr desktop);
    // The lock screen has its own Windows desktop, and a thread only sees the windows of the desktop it is on:
    // the look happens on a new thread moved to the desktop that has the screen.
    public static bool HasVisibleWindow(int pid) {
        bool found = false;
        IntPtr input = OpenInputDesktop(0, false, 0x10000000 /*GENERIC_ALL*/);
        var look = new System.Threading.Thread(() => {
            if (input != IntPtr.Zero) SetThreadDesktop(input);
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
        });
        look.Start(); look.Join();
        if (input != IntPtr.Zero) CloseDesktop(input);
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
$penKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
$penStorageKey = "HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
$penRestrictionsOriginal = Test-Path $penKey
$hotspotKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
$gameDvrOriginal = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -ErrorAction SilentlyContinue).AllowGameDVR
$hotspotOriginal = (Get-ItemProperty $hotspotKey -ErrorAction SilentlyContinue).NC_ShowSharedAccessUI
$writeProtectOriginal = (Get-ItemProperty $penStorageKey -ErrorAction SilentlyContinue).WriteProtect
function Get-PenDriveBlock {
    $r = Get-ItemProperty $penKey -ErrorAction SilentlyContinue
    $deny = @((Get-ItemProperty "$penKey\DenyDeviceIDs" -ErrorAction SilentlyContinue).'1')   # pendrives.ps1 writes one entry, "1"
    [pscustomobject]@{
        On = $r.DenyDeviceIDs -eq 1 -and $deny -contains "USB\Class_08" -and $r.AllowDenyLayered -eq 1 -and $r.AllowInstanceIDs -eq 1 -and $r.DenyDeviceIDsRetroactive -eq 0
        AllowCount = @((Get-Item "$penKey\AllowInstanceIDs" -ErrorAction SilentlyContinue).Property).Count
        WriteProtect = (Get-ItemProperty $penStorageKey -ErrorAction SilentlyContinue).WriteProtect
        Message = (Get-ItemProperty "$penKey\DeniedPolicy" -ErrorAction SilentlyContinue).SimpleText
        Phones = $r.DenyDeviceClasses -eq 1 -and $r.DenyDeviceClassesRetroactive -eq 0 -and (Get-ItemProperty "$penKey\DenyDeviceClasses" -ErrorAction SilentlyContinue).'1' -eq "{eec5ad98-8080-425f-922a-dabf3de3f69a}"
        NewNetwork = $r.DenyDeviceClasses -eq 1 -and $r.DenyDeviceClassesRetroactive -eq 0 -and (Get-ItemProperty "$penKey\DenyDeviceClasses" -ErrorAction SilentlyContinue).'2' -eq "{4d36e972-e325-11ce-bfc1-08002be10318}"
    }
}
Import-Module AppLocker -ErrorAction Stop
$appLockerPolicyBefore = [xml](Get-AppLockerPolicy -Local -Xml)
$appIdServiceBefore = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'"
if (-not $appIdServiceBefore) { throw "Application Identity service is missing from the Windows runner." }
# control for C6: other DNS servers must answer BEFORE the install, or "blocked" afterwards proves nothing
$googleBefore = try { Resolve-DnsName example.com -Server 8.8.8.8 -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null; "answered" } catch { "blocked" }
$defaultIfIndexes = @(Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -ExpandProperty InterfaceIndex -Unique)
if (-not $defaultIfIndexes) { throw "No IPv4 default route found" }
$dnsBefore = @($defaultIfIndexes | ForEach-Object { $i = $_; "$i=$((Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4).ServerAddresses -join ',')" })
$runnerDns = (Get-DnsClientServerAddress -InterfaceIndex $defaultIfIndexes[0] -AddressFamily IPv4).ServerAddresses[0]

try {
    # ===== A. counter (admin) PC =====
    $stageA = Join-Path $env:TEMP "stage-admin"; New-Item $stageA -ItemType Directory -Force | Out-Null
    Copy-Item "$repo\install\install-admin.ps1", "$out\server\Cafe.Server.exe", "$out\counter\Cafe.Counter.exe" $stageA
    $bitLockerExpected = try {
        if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) { "Unavailable" }
        else {
            $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
            if ($v.ProtectionStatus -eq "On") { "On" } else { "Off" }
        }
    } catch { "Unknown" }
    # a signed update in the folder, as the build makes it: INSTALL-ADMIN hands it to the gaming PCs
    Copy-Item "$repo\install\install-pc.ps1", "$repo\install\HOW-TO-INSTALL.txt" $stageA
    pwsh -NoProfile -File "$repo\ci\sign-update.ps1" -Folder $stageA -Version 3 | Out-Host
    # B5.3: a PC the software cannot run on is told so before anything changes (own folder, so the real install's log stays apart)
    $stageW = Join-Path $env:TEMP "stage-checks"; New-Item $stageW -ItemType Directory -Force | Out-Null
    Copy-Item "$repo\install\install-admin.ps1", "$repo\install\install-pc.ps1" $stageW
    $oldWindows = try { & "$stageW\install-admin.ps1" -Ci -TestBuild 19045 *>&1 | Out-String } catch { "did not stop cleanly: $_" }; $oldWindowsExit = $LASTEXITCODE
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    $noWebView2 = try { & "$stageW\install-admin.ps1" -Ci -TestNoWebView2 *>&1 | Out-String } catch { "did not stop cleanly: $_" }; $noWebView2Exit = $LASTEXITCODE
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    $untouched = -not (Test-Path "$env:ProgramFiles\GamingCafe\Server") -and -not (Get-Service CafeServer -ErrorAction SilentlyContinue)
    Check "A.W1" "INSTALL-ADMIN stops on a Windows older than Windows 11 and says so, before it changes anything" ($oldWindowsExit -eq 1 -and $oldWindows -match "needs Windows 11 Pro" -and $untouched) "exit $oldWindowsExit"
    Check "A.W2" "INSTALL-ADMIN stops when Microsoft WebView2 is missing, with Microsoft's download page as a link, before it changes anything" ($noWebView2Exit -eq 1 -and $noWebView2.Contains("https://developer.microsoft.com/microsoft-edge/webview2/") -and $untouched) "exit $noWebView2Exit"
    & "$stageA\install-admin.ps1" -Ci -Pcs 3   # a new install: keys for 3 gaming PCs
    Stop-Transcript | Out-Null   # the installer leaves its log open; on a real PC its own PowerShell ends and closes it. Read here before that, the log can lack the last message (seen on ARM, check A.K6)
    $adminInstallLog = Get-Content "$stageA\install-log.txt" -Raw
    $offBitLockerWarning = "Disk encryption (BitLocker) is off on this counter PC. If the PC or its disk is stolen, the cafe data can be read. Turn it on: see SECURITY-GUIDE.txt, part 1."
    $unavailableBitLockerWarning = "BitLocker is not available on this counter PC (Windows Home may not include it). See SECURITY-GUIDE.txt, part 1."
    $unknownBitLockerWarning = "Could not check BitLocker on this counter PC. Check disk encryption: see SECURITY-GUIDE.txt, part 1."
    $hasOffBitLockerWarning = $adminInstallLog.Contains($offBitLockerWarning)
    $hasUnavailableBitLockerWarning = $adminInstallLog.Contains($unavailableBitLockerWarning)
    $hasUnknownBitLockerWarning = $adminInstallLog.Contains($unknownBitLockerWarning)
    $bitLockerCheck = switch ($bitLockerExpected) {
        "On" { $adminInstallLog -match "BitLocker status: On" -and -not $hasOffBitLockerWarning -and -not $hasUnavailableBitLockerWarning -and -not $hasUnknownBitLockerWarning }
        "Off" { $adminInstallLog -match "BitLocker status: Off" -and $hasOffBitLockerWarning -and -not $hasUnavailableBitLockerWarning -and -not $hasUnknownBitLockerWarning }
        "Unavailable" { $adminInstallLog -match "BitLocker status: Unavailable" -and $hasUnavailableBitLockerWarning -and -not $hasOffBitLockerWarning -and -not $hasUnknownBitLockerWarning }
        default { $adminInstallLog -match "BitLocker status: Unknown" -and $hasUnknownBitLockerWarning -and -not $hasOffBitLockerWarning -and -not $hasUnavailableBitLockerWarning }
    }
    Check "B3.A8" "Counter installer warns only when BitLocker is not confirmed On" $bitLockerCheck "runner state $bitLockerExpected; install log contains matching status and warning"
    $counterApp = "$env:ProgramFiles\GamingCafe\Server"
    $counterIcons = "$env:PUBLIC\Desktop\Gaming Cafe counter.lnk", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Gaming Cafe counter.lnk"
    $shell = New-Object -ComObject WScript.Shell
    $iconsOk = @($counterIcons | Where-Object { (Test-Path $_) -and $shell.CreateShortcut($_).TargetPath -eq "$counterApp\Cafe.Counter.exe" }).Count
    $pinCopied = (Test-Path "$counterApp\server.pin") -and (Get-Content "$counterApp\server.pin" -Raw).Trim() -eq (Get-Content "$env:ProgramData\Cafe\server.pin" -Raw).Trim()
    Check "A.C1" "INSTALL-ADMIN puts the counter window on the counter PC: the program, the counter's fingerprint beside it (readable without admin), a desktop icon and a start with Windows" ((Test-Path "$counterApp\Cafe.Counter.exe") -and $pinCopied -and $iconsOk -eq 2) "icons $iconsOk of 2; fingerprint copied $pinCopied"
    $counterLog = Join-Path $env:TEMP "counter-window-log.txt"; Remove-Item $counterLog -ErrorAction SilentlyContinue
    $counterRun = try { Start-Process "$counterApp\Cafe.Counter.exe" -ArgumentList "--log `"$counterLog`"" -PassThru } catch { $null }   # as installed, against the installed counter
    $counterOpened = $counterRun -and (WaitFor 60 { (Test-Path $counterLog) -and (Get-Content $counterLog -Raw) -match "counter page opened" })
    if ($counterRun) { Stop-Process -Id $counterRun.Id -Force -ErrorAction SilentlyContinue }
    Write-Host "after A.C2: $(CounterWindows)"
    Check "A.C2" "The installed counter window opens the installed counter's page, trusting its certificate by the fingerprint" $counterOpened "$(Get-Content $counterLog -Raw -ErrorAction SilentlyContinue)"
    $addressFile = (Get-Content "$stageA\counter-address.txt" -ErrorAction SilentlyContinue | Select-Object -First 1)
    $myAddresses = @(Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object IPAddress)
    # the right one is on the network adapter that leads to the router; the runners also have a Hyper-V adapter (172.x)
    $routerSide = @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $defaultIfIndexes[0] | ForEach-Object IPAddress)
    Check "A.K3" "Counter install writes the address on the router side into the install folder for INSTALL-PC (not a virtual adapter's)" ($addressFile -and $routerSide -contains $addressFile.Trim()) "counter-address.txt '$addressFile'; router side: $($routerSide -join ', '); all: $($myAddresses -join ', ')"
    $keyNames = @(Get-ChildItem $stageA -Filter "PC*.token" -File | ForEach-Object BaseName | Sort-Object)
    $pc2Key = (Get-Content "$stageA\PC2.token" -Raw -ErrorAction SilentlyContinue)
    function KeyState { if (-not $pc2Key) { return "no key file" }; (curl.exe -sk --max-time 10 -o NUL -w "%{http_code}" -H "X-Pc-Token: $($pc2Key.Trim())" -H "X-Pc-Bind: lockdown-test-pc2-secret" https://127.0.0.1:5443/pc/state) -join "" }   # the first use ties PC2's key to this secret
    $null = WaitFor 30 { (KeyState) -eq "200" }; $pc2State = KeyState   # the service may still be starting
    Check "A.K5" "Counter install makes one key file per gaming PC, and the counter PC's server accepts them" (($keyNames -join ",") -eq "PC1,PC2,PC3" -and $pc2State -eq "200") "key files: $($keyNames -join ', '); PC2's key on the real server: HTTP $pc2State"
    # run again (an update): no new PCs; PC2 was used above (tied), so it keeps its key; PC1 and PC3 were never
    # installed, so they get new key files and the old copies stop working
    $pc3Old = (Get-Content "$stageA\PC3.token" -Raw -ErrorAction SilentlyContinue)
    & "$stageA\install-admin.ps1" -Ci -Pcs 5
    Stop-Transcript | Out-Null   # close the installer's log before reading it (see the first INSTALL-ADMIN run above)
    $adminLogAfter = Get-Content "$stageA\install-log.txt" -Raw
    Write-Host "after the update: $(CounterWindows)"
    $keyNamesAfter = @(Get-ChildItem $stageA -Filter "PC*.token" -File | ForEach-Object BaseName | Sort-Object)
    $null = WaitFor 30 { (KeyState) -eq "200" }; $pc2After = KeyState
    function KeyCode($k, $secret) { if (-not $k) { return "no key file" }; (curl.exe -sk --max-time 10 -o NUL -w "%{http_code}" -H "X-Pc-Token: $($k.Trim())" -H "X-Pc-Bind: $secret" https://127.0.0.1:5443/pc/state) -join "" }
    $pc3New = (Get-Content "$stageA\PC3.token" -Raw -ErrorAction SilentlyContinue)
    $pc3OldCode = KeyCode $pc3Old "lockdown-old-pc3-file"; $pc3NewCode = KeyCode $pc3New "lockdown-test-pc3-secret"
    Check "A.K6" "Running INSTALL-ADMIN again (an update) adds no PCs, keeps the key of the PC already used, and gives the PCs not installed yet new keys: the old copies stop working" (($keyNamesAfter -join ",") -eq "PC1,PC2,PC3" -and $pc2After -eq "200" -and $pc3Old -and $pc3New -and $pc3Old.Trim() -ne $pc3New.Trim() -and $pc3OldCode -eq "401" -and $pc3NewCode -eq "200" -and $adminLogAfter -match "New keys for the 2 gaming PCs not installed yet \(PC1, PC3\)") "key files: $($keyNamesAfter -join ', '); PC2 (used) HTTP $pc2After; PC3 old file HTTP $pc3OldCode, new file HTTP $pc3NewCode; message names PC1, PC3: $($adminLogAfter -match 'PC1, PC3')"
    $offered = "$env:ProgramData\Cafe\updates"
    $offeredList = if (Test-Path "$offered\update.json") { Get-Content "$offered\update.json" -Raw | ConvertFrom-Json } else { $null }
    $offeredFiles = @(Get-ChildItem "$offered\files" -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object Name)
    Check "A.U1" "INSTALL-ADMIN hands the signed update to the counter server: its file list, signature and only the files it lists (no key files)" ($offeredList.version -eq 3 -and (Test-Path "$offered\update.sig") -and $offeredFiles -contains "install-pc.ps1" -and -not ($offeredFiles -like "*.token") -and -not ($offeredFiles -contains "Cafe.Server.exe") -and $offeredFiles.Count -eq @($offeredList.files).Count) "version $($offeredList.version); files offered: $($offeredFiles -join ', ')"
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
    $findRule = Get-NetFirewallRule -Group "Cafe counter" | Where-Object DisplayName -like "*find the counter PC*"
    $findPort = $findRule | Get-NetFirewallPortFilter; $findFrom = $findRule | Get-NetFirewallAddressFilter
    Check "B3.A3b" "Firewall lets only the shop network ask where the counter PC is (UDP 5442)" ($findPort.Protocol -eq "UDP" -and "$($findPort.LocalPort)" -eq "5442" -and "$($findFrom.RemoteAddress)" -eq "LocalSubnet") "$($findPort.Protocol) $($findPort.LocalPort) from $($findFrom.RemoteAddress)"
    Check "B3.A4" "Internet filter (AdGuard Home) installed, checked and running" ((Get-Service AdGuardHome -ErrorAction SilentlyContinue).Status -eq "Running") "version pinned, SHA-256 checked"
    # S3: the installer did the filter's first-start setup; the owner never opens its wizard
    $filterLine = Get-Content "$env:ProgramData\Cafe\filter-password.txt" -Raw -ErrorAction SilentlyContinue
    $filterPw = if ($filterLine -match 'password (\S+)') { $Matches[1] } else { "" }
    $filterAuth = @{ Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("owner:$filterPw")) }
    $filterStatus = try { Invoke-RestMethod http://127.0.0.1:3000/control/status -Headers $filterAuth } catch { $null }
    $filterLog = try { Invoke-RestMethod http://127.0.0.1:3000/control/querylog/config -Headers $filterAuth } catch { $null }
    $noPassword = (curl.exe -s --max-time 10 -o NUL -w "%{http_code}" http://127.0.0.1:3000/control/status) -join ""
    $lanSide = $routerSide | Select-Object -First 1
    $fromLan = (curl.exe -s --max-time 5 -o NUL -w "%{http_code}" "http://${lanSide}:3000/") -join ""   # 000: nothing listens there
    $dnsOnLan = WaitFor 30 { try { [bool](Resolve-DnsName example.com -Server $lanSide -DnsOnly -QuickTimeout -ErrorAction Stop) } catch { $false } }
    Check "B3.A5" "Internet filter set up by the installer: DNS for the shop network on port 53, website list kept 180 days, its page on the counter PC only and behind a password" ($filterPw.Length -ge 24 -and $filterStatus.running -and $filterStatus.dns_port -eq 53 -and $filterLog.enabled -and [long]$filterLog.interval -eq 15552000000 -and $noPassword -in "401", "403" -and $fromLan -eq "000" -and $dnsOnLan) "password file $($filterPw.Length -ge 24); running $($filterStatus.running), DNS port $($filterStatus.dns_port); log on $($filterLog.enabled), kept $($filterLog.interval) ms; page without password HTTP $noPassword; page from $lanSide HTTP $fromLan; DNS answers on $lanSide $dnsOnLan"
    Check "B3.A5b" "The filter password is never in the install log (the owner may send that file to someone)" ($filterPw -and -not $adminInstallLog.Contains($filterPw) -and -not (Get-Content "$stageA\install-log.txt" -Raw).Contains($filterPw)) "checked both install runs' log"
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
    # the test acts as PC1 next to its installed watchdog, so it sends the secret that watchdog made (pc.bind)
    function PcBind { Add-Type -AssemblyName System.Security; [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes("$data\keys\pc.bind"), $null, "LocalMachine")) }
    function Pc($path, $body) { Invoke-RestMethod "https://127.0.0.1:5443$path" -Method Post -Headers @{ "X-Pc-Token" = $token; "X-Pc-Bind" = (PcBind) } -ContentType "application/json" -Body ($body | ConvertTo-Json) }

    # A real install starts with no accounts. The owner account is made on the counter PC itself, once.
    $freshData = Join-Path $env:TEMP "cafe-fresh-server"; Remove-Item $freshData -Recurse -Force -ErrorAction SilentlyContinue
    $fresh = Start-Process "$out\server\Cafe.Server.exe" -ArgumentList "--data $freshData --port 5544" -PassThru -WindowStyle Hidden
    # GET with curl: Windows PowerShell runs the test's trust-the-certificate callback on another thread for a GET,
    # where it fails ("no Runspace available"), so Invoke-RestMethod never got an answer
    function SetupState { $t = (curl.exe -sk --max-time 10 https://127.0.0.1:5544/setup) -join ""; try { $t | ConvertFrom-Json } catch { $null } }
    $setupBefore = $null; $setupTries = 0
    for ($i = 0; $i -lt 120 -and -not $setupBefore; $i++) { $setupTries++; $setupBefore = SetupState; if (-not $setupBefore) { Start-Sleep -Seconds 1 } }
    $lanIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } | Select-Object -First 1).IPAddress
    $ownerBody = @{ role = 0; name = "Fresh Owner"; phone = "9100000001"; pin = "135790" } | ConvertTo-Json
    function SetupOwner($hostName) { try { Invoke-RestMethod "https://${hostName}:5544/setup/owner" -Method Post -ContentType "application/json" -Body $ownerBody | Out-Null; "made" } catch { [int]$_.Exception.Response.StatusCode } }
    $fromLan = SetupOwner $lanIp
    $fromCounter = SetupOwner "127.0.0.1"
    $again = SetupOwner "127.0.0.1"
    $setupAfter = SetupState
    $freshLogin = try { [bool](Invoke-RestMethod "https://127.0.0.1:5544/staff/login" -Method Post -ContentType "application/json" -Body (@{ phone = "9100000001"; pin = "135790" } | ConvertTo-Json)).token } catch { $false }
    Stop-Process -Id $fresh.Id -Force -ErrorAction SilentlyContinue
    Get-ChildItem "$freshData\logs" -File -ErrorAction SilentlyContinue | ForEach-Object { Get-Content $_.FullName | ForEach-Object { Write-Host "A.S1 server log: $_" } }
    Check "A.S1" "A new install asks for the owner account first; only the counter PC itself can make it, only once; the owner can then sign in" ($setupBefore.needsOwner -eq $true -and $fromLan -eq 403 -and $fromCounter -eq "made" -and $again -eq 400 -and $setupAfter.needsOwner -eq $false -and $freshLogin) "asks first $($setupBefore.needsOwner) (after $setupTries tries); from another PC ($lanIp): $fromLan; from the counter PC: $fromCounter; again: $again; asks after $($setupAfter.needsOwner); sign-in $freshLogin"

    # ===== C. gaming PC, step 1 =====
    $ntpBefore = (Get-ItemProperty $ntpKey).NtpServer   # after the counter PC install, which sets the same clock settings
    $stage = Join-Path $env:TEMP "stage-pc"; New-Item $stage -ItemType Directory -Force | Out-Null
    Copy-Item "$repo\install\*", "$out\watchdog\Cafe.Watchdog.exe" $stage
    $agentRuntimeStage = Join-Path $stage "agent-runtime"
    New-Item -ItemType Directory -Path $agentRuntimeStage -Force | Out-Null
    Copy-Item "$out\agent\*" $agentRuntimeStage -Force
    # the key files as INSTALL-ADMIN leaves them. PC9 holds the test server's key; PC10 is a decoy. The PC must take
    # PC9 (lowest number), not PC10 (first by letters). PC10 then stays for the next gaming PC.
    Copy-Item "$tdata\pc1.token" "$stage\PC9.token"; Set-Content "$stage\PC10.token" "not-a-real-key" -Encoding ascii
    Copy-Item "$tdata\server.pin" $stage
    Set-Content "$stage\counter-address.txt" "127.0.0.1" -Encoding ascii   # as INSTALL-ADMIN writes it; the test server is on this machine
    $secureBootExpected = try { if (Confirm-SecureBootUEFI -ErrorAction Stop) { "On" } else { "Off" } } catch { "Unknown" }
    $oldPc = try { & "$stageW\install-pc.ps1" -Ci -TestBuild 19045 -AllowFolders "" *>&1 | Out-String } catch { "did not stop cleanly: $_" }; $oldPcExit = $LASTEXITCODE
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    Check "C.W1" "INSTALL-PC stops on a Windows older than Windows 11 and says so, before it changes anything" ($oldPcExit -eq 1 -and $oldPc -match "needs Windows 11 Pro" -and -not (Get-Service CafeWatchdog -ErrorAction SilentlyContinue) -and -not (Get-LocalUser Customer -ErrorAction SilentlyContinue)) "exit $oldPcExit"
    & "$stage\install-pc.ps1" -DnsServer $runnerDns -Ci -AllowFolders ""   # the counter address comes from counter-address.txt
    Stop-Transcript | Out-Null   # close the installer's log before reading it (see the first INSTALL-ADMIN run above)
    $pcInstallLog = Get-Content "$stage\install-log.txt" -Raw
    $offSecureBootWarning = "Secure Boot is off on this gaming PC. Turn it on: see SECURITY-GUIDE.txt, part 2."
    $unknownSecureBootWarning = "Secure Boot could not be checked on this gaming PC. Check it: see SECURITY-GUIDE.txt, part 2."
    $hasOffSecureBootWarning = $pcInstallLog.Contains($offSecureBootWarning)
    $hasUnknownSecureBootWarning = $pcInstallLog.Contains($unknownSecureBootWarning)
    $secureBootCheck = switch ($secureBootExpected) {
        "On" { $pcInstallLog -match "Secure Boot status: On" -and -not $hasOffSecureBootWarning -and -not $hasUnknownSecureBootWarning }
        "Off" { $pcInstallLog -match "Secure Boot status: Off" -and $hasOffSecureBootWarning -and -not $hasUnknownSecureBootWarning }
        default { $pcInstallLog -match "Secure Boot status: Unknown" -and $hasUnknownSecureBootWarning -and -not $hasOffSecureBootWarning }
    }
    Check "B3.C9" "Gaming PC installer warns only when Secure Boot is off or cannot be checked" $secureBootCheck "runner state $secureBootExpected; install log contains matching status and warning"
    $u = Get-LocalUser Customer
    $isAdmin = [bool]((net.exe localgroup (Get-LocalGroup -SID S-1-5-32-544).Name) -match '^Customer$')   # Get-LocalGroupMember breaks on unknown members
    Check "A.K1" "INSTALL-PC takes the lowest-numbered key file (PC9, not PC10), names the PC, saves the key protected, and removes it from the install folder" ((Test-Path "$data\keys\pc.token") -and -not (Test-Path "$stage\PC9.token") -and (Test-Path "$stage\PC10.token") -and -not (Test-Path "$stage\pc.token") -and $pcInstallLog.Contains("This PC is PC9")) "saved $(Test-Path "$data\keys\pc.token"); left in folder: PC9.token $(Test-Path "$stage\PC9.token"), PC10.token $(Test-Path "$stage\PC10.token"), pc.token $(Test-Path "$stage\pc.token"); named PC9 $($pcInstallLog.Contains("This PC is PC9"))"
    Check "A.K7" "The certificate fingerprint (server.pin) stays in the install folder for the next gaming PC" (Test-Path "$stage\server.pin") "server.pin in folder: $(Test-Path "$stage\server.pin")"
    Remove-Item "$stage\PC10.token" -ErrorAction SilentlyContinue
    $watchdogArgs = Get-Content "$env:ProgramFiles\GamingCafe\watchdog.args" -Raw -ErrorAction SilentlyContinue
    Check "A.K4" "INSTALL-PC takes the counter address from counter-address.txt, with nothing typed" ($watchdogArgs -match '--server https://127\.0\.0\.1:5443') "watchdog.args: $watchdogArgs"
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
    $filterPwRead = CustomerPs "[IO.File]::ReadAllText('$env:ProgramData\Cafe\filter-password.txt') | Out-Null"
    Check "B3.C4p" "Customer cannot read the internet filter's password" ($filterPwRead -ne 0) "read exit $filterPwRead"
    Check "B3.C4b" "Customer cannot read the PC token or certificate pin" ($tokenRead -ne 0 -and $pinRead -ne 0 -and -not (Test-Path "$app\pc.token") -and -not (Test-Path "$app\server.pin") -and -not (Test-Path "$stage\pc.token")) "token read exit $tokenRead, pin read exit $pinRead; key's source copy removed"
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
    $offlineTestCache = Join-Path $env:TEMP ("cafe-offline-refresh-" + [Guid]::NewGuid().ToString("N") + ".bin")
    Copy-Item -LiteralPath $offlineCache -Destination $offlineTestCache
    $testModeBefore = $env:CAFE_TEST_MODE
    $env:CAFE_TEST_MODE = "1"
    try {
        $oldRefresh = [DateTime]::UtcNow.AddDays(-8).ToString("o")
        & "$out\watchdog\Cafe.Watchdog.exe" --test-set-offline-refresh --test-mode --cache-file $offlineTestCache --server-time $oldRefresh
        $setRefreshExit = $LASTEXITCODE
        $expiryMessage = & "$out\watchdog\Cafe.Watchdog.exe" --test-check-offline-refresh --test-mode --cache-file $offlineTestCache
        $expiryExit = $LASTEXITCODE
        & "$out\watchdog\Cafe.Watchdog.exe" --test-set-offline-refresh --test-mode --cache-file $offlineTestCache --server-time ([DateTime]::UtcNow.AddSeconds(-1).ToString("o"))
        $restoreRefreshExit = $LASTEXITCODE
    } finally {
        Remove-Item -LiteralPath $offlineTestCache -Force -ErrorAction SilentlyContinue
        if ($null -eq $testModeBefore) { Remove-Item Env:CAFE_TEST_MODE -ErrorAction SilentlyContinue }
        else { $env:CAFE_TEST_MODE = $testModeBefore }
    }
    Check "B3.C4f" "Offline unlock refuses a cache whose last counter refresh is over seven days old" ($setRefreshExit -eq 0 -and $expiryExit -eq 0 -and ($expiryMessage -join " ") -match "this PC has not reached the counter for 7 days" -and $restoreRefreshExit -eq 0) "set $setRefreshExit; probe $expiryExit; message $($expiryMessage -join ' '); restore $restoreRefreshExit"
    Check "B3.C5" "Setup mode: no lock screen yet" ((Test-Path "$app\setup.flag") -and -not (Get-Process Cafe.Agent -ErrorAction SilentlyContinue)) "setup.flag present"
    $other = try { Resolve-DnsName example.com -Server 8.8.8.8 -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null; "answered" } catch { "blocked" }
    $own = try { Resolve-DnsName example.com -DnsOnly -ErrorAction Stop | Out-Null; "works" } catch { "$_" }
    Check "B3.C6" "Other DNS servers blocked, the filter's one works" ($googleBefore -eq "answered" -and $other -eq "blocked" -and $own -eq "works") "8.8.8.8 before install $googleBefore, after $other; normal lookups $own"
    $poll = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient").SpecialPollInterval
    Check "B3.C8" "Clock synced hourly with India's official time servers (NIC, NPL)" ((Get-ItemProperty $ntpKey).NtpServer -match "samay1.nic.in" -and $poll -eq 3600 -and (Get-Service w32time).Status -eq "Running") "time source now: $((w32tm.exe /query /source) -join ' ')"
    Check "B3.C7" "Browsers' own secure DNS switched off" ((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge").DnsOverHttpsMode -eq "off") "Edge, Chrome, Firefox policies"
    $expectedInboundBlocks = @(
        @{ Id = "B3.C10a"; Name = "Cafe: block SMB (TCP 445)"; Protocol = "TCP"; Ports = "445" },
        @{ Id = "B3.C10b"; Name = "Cafe: block NetBIOS name service (UDP 137-138)"; Protocol = "UDP"; Ports = "137-138" },
        @{ Id = "B3.C10c"; Name = "Cafe: block NetBIOS session service (TCP 139)"; Protocol = "TCP"; Ports = "139" },
        @{ Id = "B3.C10d"; Name = "Cafe: block Remote Desktop (TCP 3389)"; Protocol = "TCP"; Ports = "3389" },
        @{ Id = "B3.C10e"; Name = "Cafe: block Remote Desktop (UDP 3389)"; Protocol = "UDP"; Ports = "3389" },
        @{ Id = "B3.C10f"; Name = "Cafe: block Windows Remote Management (TCP 5985-5986)"; Protocol = "TCP"; Ports = "5985-5986" }
    )
    foreach ($expected in $expectedInboundBlocks) {
        $rules = @(Get-NetFirewallRule -DisplayName $expected.Name -ErrorAction SilentlyContinue | Where-Object Group -eq "Cafe PC")
        $valid = $rules.Count -eq 1
        $detail = "found $($rules.Count)"
        if ($valid) {
            $rule = $rules[0]
            $port = $rule | Get-NetFirewallPortFilter
            $address = $rule | Get-NetFirewallAddressFilter
            $actualPorts = @($port.LocalPort | ForEach-Object { "$_" }) -join ","
            $remoteAny = @($address.RemoteAddress | Where-Object { $_ -eq "Any" }).Count -gt 0
            $valid = ("$($rule.Enabled)" -eq "True" -and $rule.Direction -eq "Inbound" -and $rule.Action -eq "Block" -and
                $rule.Group -eq "Cafe PC" -and $port.Protocol -eq $expected.Protocol -and
                $actualPorts -eq $expected.Ports -and $remoteAny)
            $detail = "enabled $($rule.Enabled); $($rule.Direction) $($rule.Action); $($port.Protocol) $actualPorts; group $($rule.Group); remote $($address.RemoteAddress)"
        }
        Check $expected.Id "Inbound firewall rule $($expected.Name) is enabled, blocks the correct ports from any address in Cafe PC" $valid $detail
    }

    # ===== D. the owner sets the Customer account up (here: an "installed Discord" and a shortcut) =====
    $prof = (Get-CimInstance Win32_UserProfile | Where-Object SID -eq $u.SID.Value).LocalPath
    New-Item "$prof\AppData\Local\Discord" -ItemType Directory -Force | Out-Null; "app" | Set-Content "$prof\AppData\Local\Discord\Update.txt"
    "shortcut" | Set-Content "$prof\Desktop\Game.txt"
    $ownerRun = CustomerPs "if (-not (Test-Path HKCU:\$runKey)) { New-Item HKCU:\$runKey | Out-Null }; Set-ItemProperty HKCU:\$runKey OwnerApp 'C:\owner.exe'"
    Start-Sleep -Seconds 5

    # D1 diagnostics: preserve a representative Customer executable before installing AppLocker.
    $d1DiagnosticExe = "$prof\Downloads\d1-policy-diagnostic.exe"
    Copy-Item -LiteralPath "$env:WINDIR\System32\PING.EXE" -Destination $d1DiagnosticExe -Force
    $cRootAclBefore = (Get-Acl -LiteralPath "$env:SystemDrive\").Sddl
    $d1InstallStarted = Get-Date

    # ===== E. step 2, started by the Customer from the "Finish cafe setup" icon: no admin password (S4) =====
    # what the icon (finish-setup.ps1) does, minus its windows: list the networks, write the choice, start the task.
    # A file, because CustomerPs command lines must stay short.
    $s4 = "$env:PUBLIC\cafe-s4-test.ps1"
    Set-Content $s4 @'
param($Mode, $Wifi)
$o = "$env:ProgramData\GamingCafe\finish"
$f = "HKCU:\Software\GamingCafe"
function Written { (Get-Item "$o\nearby.txt" -ErrorAction SilentlyContinue).LastWriteTimeUtc }
function Wait($test) { for ($i = 0; $i -lt 900 -and -not (& $test); $i++) { Start-Sleep 1 } }
if ($Mode -eq "list") { Remove-Item $f -Recurse -Force -ErrorAction SilentlyContinue; $b = Written }
else { New-Item $f -Force | Out-Null; Set-ItemProperty $f FinishWifi $Wifi; $r = (Get-Item "$o\result.txt" -ErrorAction SilentlyContinue).LastWriteTimeUtc }
schtasks.exe /run /tn CafeFinishSetup | Out-Null
if ($LASTEXITCODE) { exit 5 }
if ($Mode -eq "list") { Wait { (Written) -ne $b } }
elseif ($Mode -eq "bad") { Wait { (Get-Item "$o\result.txt" -ErrorAction SilentlyContinue).LastWriteTimeUtc -ne $r } }
else { Wait { -not (Test-Path "$env:ProgramFiles\GamingCafe\setup.flag") } }   # setup closes this process on the way
'@
    $finishOut = "$data\finish"
    $customerSid = $u.SID.Value
    $iconThere = Test-Path "$env:PUBLIC\Desktop\Finish cafe setup.lnk"
    $finishTaskDef = Get-ScheduledTask CafeFinishSetup -ErrorAction SilentlyContinue
    $scheduler = New-Object -ComObject Schedule.Service; $scheduler.Connect()
    $taskSd = try { $scheduler.GetFolder("\").GetTask("CafeFinishSetup").GetSecurityDescriptor(4) } catch { "" }
    # Task Scheduler stores the rights in its own form: admins and Windows full; the Customer read and start (0x1200a9) only
    $aces = @([regex]::Matches($taskSd, '\(A;;([^;]+);;;([^)]+)\)') | ForEach-Object { [pscustomobject]@{ Rights = $_.Groups[1].Value; Who = $_.Groups[2].Value } })
    $taskRightsOk = $aces.Count -gt 0 -and @($aces | Where-Object { $_.Who -notin "BA", "SY", $customerSid }).Count -eq 0 -and
        ((@($aces | Where-Object { $_.Who -eq $customerSid }).Rights -join ",") -in @("0x1200a9", "GRGX")) -and $taskSd -notmatch '\(D;|\(A;[^)]*;;;(WD|AU|BU|IU)\)'
    $plant = CustomerPs "Set-Content '$finishOut\nearby.txt' planted"   # the Customer may only read the task's answers
    $listRun = CustomerPs "& '$s4' list"
    $nearbyFile = (Get-Content "$finishOut\nearby.txt" -Raw -ErrorAction SilentlyContinue)
    Check "S4.1" "Setup mode puts a 'Finish cafe setup' icon on the desktop; its task runs as SYSTEM, only admins, Windows and the Customer (start only) may touch it; the Customer cannot write the task's answers; the first start lists the Wi-Fi networks and changes nothing else" ($iconThere -and $finishTaskDef.Principal.UserId -in "SYSTEM", "S-1-5-18" -and $taskRightsOk -and $plant -ne 0 -and $listRun -eq 0 -and $nearbyFile -and $nearbyFile -notmatch "planted" -and (Test-Path "$app\setup.flag")) "icon $iconThere; runs as $($finishTaskDef.Principal.UserId); rights $taskSd; Customer write exit $plant; list run exit $listRun; list '$("$nearbyFile".Trim())'; still in setup mode $(Test-Path "$app\setup.flag")"
    $badRun = CustomerPs "& '$s4' bad 'Not-A-Cafe-Network'"
    $badResult = Get-Content "$finishOut\result.txt" -Raw -ErrorAction SilentlyContinue
    Check "S4.2" "A Wi-Fi choice that is not a network in range stops step 2, says why for the next sign-in, and leaves the PC in setup mode" ($badRun -eq 0 -and $badResult -match "not in range" -and (Test-Path "$app\setup.flag") -and -not (Test-Path "$data\clean-profile-hive\NTUSER.DAT")) "run exit $badRun; result '$("$badResult".Trim())'; setup mode $(Test-Path "$app\setup.flag")"
    $finishRun = CustomerPs "& '$s4' finish ''"   # no Wi-Fi networks for customers
    $finishStarted = Get-Date
    # 30 minutes, not 15: step 2 took 5.9 to 8.8 min in 13 x64 jobs and 14.1 and 15.1 min in 2. The folder scan in it waits for the
    # disk; why it was 2.7 times slower those two times is not known. The check below prints how long step 2 took.
    $null = WaitFor 1800 { -not (Test-Path "$app\setup.flag") -and -not (Get-ScheduledTask CafeFinishSetup -ErrorAction SilentlyContinue) }
    $finishMinutes = [math]::Round(((Get-Date) - $finishStarted).TotalMinutes, 1)
    $finishLog = Get-Content "$app\install-log.txt" -Raw -ErrorAction SilentlyContinue
    $againRun = CustomerPs "schtasks.exe /run /tn CafeFinishSetup"
    Check "S4.3" "The Customer's start finishes step 2 as SYSTEM; then the task, the icon and the sign-in check are gone, so the Customer cannot start anything again" (-not (Test-Path "$app\setup.flag") -and -not (Get-ScheduledTask CafeFinishSetup -ErrorAction SilentlyContinue) -and -not (Test-Path "$env:PUBLIC\Desktop\Finish cafe setup.lnk") -and -not (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue).CafeFinishSetup -and -not (Test-Path $finishOut) -and $finishLog -match "The finish-setup task and icon are removed" -and $againRun -ne 0) "setup mode $(Test-Path "$app\setup.flag"); task left $([bool](Get-ScheduledTask CafeFinishSetup -ErrorAction SilentlyContinue)); icon $(Test-Path "$env:PUBLIC\Desktop\Finish cafe setup.lnk"); answers folder $(Test-Path $finishOut); ran to the end $($finishLog -match 'task and icon are removed'); start again exit $againRun (Customer run exit $finishRun); took $finishMinutes min"
    if (Test-Path "$app\setup.flag") { Write-Host "S4 step 2 log:"; Write-Host $finishLog }
    else { "$finishLog" -split "`r?`n" | Where-Object { $_ -match '^\d\d:\d\d:\d\d ' } | ForEach-Object { Write-Host "S4 step 2 time: $_" } }
    Remove-Item $s4 -Force -ErrorAction SilentlyContinue

    $compiledPolicyNames = @("Exe.AppLocker", "Dll.AppLocker", "Msi.AppLocker", "Script.AppLocker", "Appx.AppLocker")
    $compiledPolicyFresh = $true
    foreach ($compiledPolicyName in $compiledPolicyNames) {
        $compiledPolicyPath = Join-Path "$env:WINDIR\System32\AppLocker" $compiledPolicyName
        $compiledItem = Get-Item -LiteralPath $compiledPolicyPath -ErrorAction SilentlyContinue
        $fresh = ($null -ne $compiledItem) -and ($compiledItem.LastWriteTimeUtc -gt $d1InstallStarted.ToUniversalTime())
        Write-Host "First-install compiled policy $compiledPolicyName fresh=$fresh"
        $compiledPolicyFresh = $compiledPolicyFresh -and $fresh
    }
    Check "D1.C1c" "All five compiled AppLocker policy files are newer than the first install" $compiledPolicyFresh "First install UTC $($d1InstallStarted.ToUniversalTime().ToString('o')); files $($compiledPolicyNames -join ', ')"

    $rootCreateProbe = "C:\CafeD1RootCreate-$([guid]::NewGuid().ToString('N'))"
    $rootCreateExit = CustomerPs "try { New-Item -Path '$rootCreateProbe' -ItemType Directory -ErrorAction Stop | Out-Null; exit 0 } catch { exit 1 }"
    Check "D1.C3b" "Customer cannot create a new folder directly under the C drive root" ($rootCreateExit -ne 0 -and -not (Test-Path -LiteralPath $rootCreateProbe)) "CustomerPs exit $rootCreateExit; folder exists $(Test-Path -LiteralPath $rootCreateProbe)"

    # D2 pen drives. There is no USB on a cloud machine: a real pen drive is checked in Phase 0 (STATUS.txt).
    $penBlock = Get-PenDriveBlock
    Check "D2.C1" "Pen drive block on after install: USB storage held back, nothing allowed, read-only by default, counter message set" ($penBlock.On -and $penBlock.AllowCount -eq 0 -and $penBlock.WriteProtect -eq 1 -and $penBlock.Message) "block $($penBlock.On); allowed $($penBlock.AllowCount); WriteProtect $($penBlock.WriteProtect); message '$($penBlock.Message)'"
    Check "D2.C4" "Phones never get file transfer: Windows' portable-devices class is not set up (charging needs no driver)" ($penBlock.Phones) "phone block $($penBlock.Phones)"
    $netUp = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq "Up").Count
    Check "D2.C5" "No USB tethering: no new network adapter is set up, and the adapters set up before still work" ($penBlock.NewNetwork -and $netUp -ge 1) "new-adapter block $($penBlock.NewNetwork); adapters up $netUp"
    # one short command each: the Windows call that starts a program as another account takes at most 1024 characters
    $penCustomerExits = @(
        (CustomerPs "try { Set-ItemProperty '$penKey' DenyDeviceIDs 0 -ErrorAction Stop; exit 0 } catch { exit 7 }"),
        (CustomerPs "try { Set-ItemProperty '$penStorageKey' WriteProtect 0 -ErrorAction Stop; exit 0 } catch { exit 7 }"),
        (CustomerPs "try { New-ItemProperty '$penKey\AllowInstanceIDs' -Name 1 -Value 'USB\VID_FFFF' -ErrorAction Stop | Out-Null; exit 0 } catch { exit 7 }"))
    $penCustomerExit = "$penCustomerExits"
    $penAfterCustomer = Get-PenDriveBlock
    Check "D2.C2" "Customer cannot switch the pen drive block off, allow a drive, or allow writing" ($penCustomerExit -eq "7 7 7" -and $penAfterCustomer.On -and $penAfterCustomer.AllowCount -eq 0 -and $penAfterCustomer.WriteProtect -eq 1) "CustomerPs exits for block, write setting, allow list: $penCustomerExit (7 = refused)"
    # D3 Wi-Fi. A cloud machine has no Wi-Fi card: the Wi-Fi filters and the router check are tested in Phase 0.
    $hotspot = (Get-ItemProperty $hotspotKey -ErrorAction SilentlyContinue).NC_ShowSharedAccessUI
    Check "D3.C1" "Mobile hotspot and internet sharing off for everyone; a PC with no Wi-Fi card gets no Wi-Fi filters" ($hotspot -eq 0 -and -not (Test-Path "$data\keys\wifi.json") -and -not (Test-Path "$data\wifi-networks.txt")) "NC_ShowSharedAccessUI $hotspot; router list $(Test-Path "$data\keys\wifi.json")"
    $hotspotCustomerExit = CustomerPs "try { Set-ItemProperty '$hotspotKey' NC_ShowSharedAccessUI 1 -ErrorAction Stop; exit 0 } catch { exit 7 }"
    Check "D3.C2" "Customer cannot switch Mobile hotspot back on" ($hotspotCustomerExit -eq 7 -and (Get-ItemProperty $hotspotKey).NC_ShowSharedAccessUI -eq 0) "CustomerPs exit $hotspotCustomerExit (7 = refused)"
    $wifiNetworks = cmd.exe /c "`"$app\Cafe.Watchdog.exe`" --wifi-networks `"$data\keys`" 2>&1"
    $wifiNetworksExit = $LASTEXITCODE
    Check "D3.W1" "Watchdog reads Wi-Fi through Windows and reports no Wi-Fi card cleanly" ($wifiNetworksExit -eq 3) "exit $wifiNetworksExit (3 = no Wi-Fi on this PC); output '$wifiNetworks'"
    Stop-Service CafeWatchdog -Force   # the service would correct the allow list during the self-test
    $penTestKeys = Join-Path $env:TEMP "cafe-pen-test-keys"; New-Item $penTestKeys -ItemType Directory -Force | Out-Null
    $env:CAFE_TEST_MODE = "1"
    $penSelfTest = cmd.exe /c "`"$app\Cafe.Watchdog.exe`" --test-pen-drive --test-mode --keys `"$penTestKeys`" 2>&1"
    $penSelfTestExit = $LASTEXITCODE
    Remove-Item Env:CAFE_TEST_MODE
    $penSelfTest | ForEach-Object { Write-Host "D2.W1 $_" }
    $penAfterSelfTest = Get-PenDriveBlock
    Start-Service CafeWatchdog
    Check "D2.W1" "Watchdog reads USB storage through Windows, gives a drive read-only, then read and write, then ends it at logout" ($penSelfTestExit -eq 0 -and $penAfterSelfTest.On -and $penAfterSelfTest.AllowCount -eq 0 -and $penAfterSelfTest.WriteProtect -eq 1) "self-test exit $penSelfTestExit (3 block off, 4 read-only, 5 read and write, 6 logout)"

    # Capture the effective policy decision, kernel/service state, and every AppLocker event since install.
    Write-Host "===== D1 enforcement diagnostics (install started $($d1InstallStarted.ToString('o'))) ====="
    Write-Host "AsCustomer launch path: Start-Process -Credential (CreateProcessWithLogonW); LOGON32_LOGON_INTERACTIVE=2; LoadUserProfile=true."
    Write-Host "AsCustomer token evaluation: Test-AppLockerPolicy below evaluates the Customer SAM account; runtime block events are correlated against Customer SID $($u.SID.Value)."
    # Query the token owner from the admin-side process table. Do not make the
    # Customer PowerShell process write a helper file into a denied user folder.
    $tokenProbe = AsCustomer "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" "-NoProfile -Command Start-Sleep -Seconds 8"
    $tokenProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$($tokenProbe.Id)" -ErrorAction SilentlyContinue
    $tokenOwner = if ($tokenProcess) { Invoke-CimMethod -InputObject $tokenProcess -MethodName GetOwnerSid -ErrorAction SilentlyContinue } else { $null }
    $d1TokenIdentity = if ($tokenOwner -and $tokenOwner.ReturnValue -eq 0) { $tokenOwner.Sid } else { "" }
    $d1TokenIdentityExit = if ($tokenProbe.WaitForExit(12000)) { $tokenProbe.ExitCode } else { Stop-Process -Id $tokenProbe.Id -Force -ErrorAction SilentlyContinue; 1 }
    Write-Host "AsCustomer actual process token SID: $d1TokenIdentity; expected Customer SID: $($u.SID.Value)"
    Check "D1.C2c" "AsCustomer process token is the Customer SID evaluated by Test-AppLockerPolicy" ($d1TokenIdentityExit -eq 0 -and $d1TokenIdentity -eq $u.SID.Value) "token SID $d1TokenIdentity; Customer SID $($u.SID.Value); exit $d1TokenIdentityExit"
    $effectivePolicyPath = Join-Path $data "applocker-effective.xml"
    try {
        $effectivePolicyXml = Get-AppLockerPolicy -Effective -Xml
        [IO.File]::WriteAllText($effectivePolicyPath, [string]$effectivePolicyXml, (New-Object Text.UTF8Encoding($false)))
        Write-Host "Effective policy saved to $effectivePolicyPath"
        $policyDecision = Test-AppLockerPolicy -XmlPolicy $effectivePolicyPath -Path $d1DiagnosticExe -User Customer
        Write-Host "Test-AppLockerPolicy effective-policy result for Customer / ${d1DiagnosticExe}:"
        $policyDecision | Format-List * | Out-String | Write-Host
    } catch { Write-Warning "Effective-policy test failed: $($_.Exception.Message)" }
    foreach ($serviceName in @("appid", "applockerfltr", "appidsvc")) {
        Write-Host "===== sc.exe query $serviceName ====="
        & "$env:WINDIR\System32\sc.exe" query $serviceName 2>&1 | Out-String | Write-Host
    }
    foreach ($channel in @("Microsoft-Windows-AppLocker/EXE and DLL", "Microsoft-Windows-AppLocker/MSI and Script")) {
        Write-Host "===== AppLocker events in $channel since install ====="
        try {
            $channelEvents = @(Get-WinEvent -FilterHashtable @{ LogName = $channel; StartTime = $d1InstallStarted } -ErrorAction Stop | Sort-Object TimeCreated)
            if ($channelEvents.Count -eq 0) { Write-Host "No events since install." }
            foreach ($event in $channelEvents) {
                Write-Host ("{0:o} ID={1} Provider={2}" -f $event.TimeCreated, $event.Id, $event.ProviderName)
                Write-Host $event.Message
            }
        } catch { Write-Warning "Could not read $channel since install: $($_.Exception.Message)" }
    }
    Write-Host "===== End D1 enforcement diagnostics ====="
    # CI runs without a Customer interactive session; this admin-only marker exercises the profile reset after
    # the test Customer processes exit. Installed cafe PCs never contain this file and log off the real Customer session.
    New-Item "$app\test-wipe-mode.flag" -ItemType File -Force | Out-Null
    Check "B3.E1" "Clean copy saved" (Test-Path "$data\clean-profile\AppData\Local\Discord\Update.txt") "$data\clean-profile"
    # An older install has a clean file copy but no registry-hive baseline. Require owner setup instead of
    # letting the first customer logout fail forever because the reset snapshot is missing.
    $heldHive = "$data\clean-profile-hive.migration-test"
    Move-Item "$data\clean-profile-hive" $heldHive
    & "$stage\install-pc.ps1" -Ci -AllowFolders ""
    $migrationSetup = (Test-Path "$app\setup.flag") -and -not (Get-Process Cafe.Agent -ErrorAction SilentlyContinue)
    $penInSetup = Get-PenDriveBlock
    $hotspotInSetup = (Get-ItemProperty $hotspotKey -ErrorAction SilentlyContinue).NC_ShowSharedAccessUI
    $penKeyInSetup = Test-Path $penKey
    Move-Item $heldHive "$data\clean-profile-hive"
    Remove-Item "$app\setup.flag" -Force -ErrorAction SilentlyContinue
    & "$app\pendrives.ps1" -Mode Install -DataPath $data   # what the owner's next INSTALL-PC run does after setup
    & "$app\wifi.ps1" -Mode Install -Ask -AppPath $app -DataPath $data
    $hotspotAfterSetup = (Get-ItemProperty $hotspotKey -ErrorAction SilentlyContinue).NC_ShowSharedAccessUI
    Check "D3.C3" "Setup mode puts Mobile hotspot back as it was for the owner, and it is off again afterwards" ($hotspotInSetup -eq $hotspotOriginal -and $hotspotAfterSetup -eq 0) "before install '$hotspotOriginal'; in setup '$hotspotInSetup'; after '$hotspotAfterSetup'"
    $penAfterSetup = Get-PenDriveBlock
    Check "D2.C3" "Setup mode switches the pen drive block off for the owner, and it comes back on afterwards" (-not $penInSetup.On -and -not $penInSetup.Phones -and -not $penInSetup.NewNetwork -and $penKeyInSetup -eq $penRestrictionsOriginal -and $penAfterSetup.On -and $penAfterSetup.Phones -and $penAfterSetup.NewNetwork -and $penAfterSetup.WriteProtect -eq 1) "in setup: block $($penInSetup.On), policy key $penKeyInSetup (before install $penRestrictionsOriginal); after: block $($penAfterSetup.On), WriteProtect $($penAfterSetup.WriteProtect)"
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

    # ===== D1. AppLocker blocks execution from Customer-writable locations =====
    $d1Policy = [xml](Get-AppLockerPolicy -Local -Xml)
    $d1Types = @("Exe", "Msi", "Script", "Dll")
    $d1CollectionsOk = $true
    $d1RuleDetails = New-Object System.Collections.Generic.List[string]
    foreach ($type in $d1Types) {
        $collection = @($d1Policy.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq $type })
        $ok = $collection.Count -eq 1 -and $collection[0].EnforcementMode -eq "Enabled"
        if ($ok) {
            $rules = @($collection[0].FilePathRule)
            $allowAll = @($rules | Where-Object { $_.Action -eq "Allow" -and $_.UserOrGroupSid -eq "S-1-1-0" -and $_.Conditions.FilePathCondition.Path -eq "*" }).Count -gt 0
            $denyPaths = @($rules | Where-Object { $_.Action -eq "Deny" -and $_.UserOrGroupSid -eq $u.SID.Value } | ForEach-Object { $_.Conditions.FilePathCondition.Path })
            $required = @("%OSDRIVE%\Users\*", "$env:WINDIR\Temp\*", "%REMOVABLE%\*", "%HOT%\*")
            $ok = $allowAll -and @($required | Where-Object { $_ -notin $denyPaths }).Count -eq 0
            $programDataDenyPaths = @($denyPaths | Where-Object { $_ -like "$env:ProgramData\*" })
            $ok = $ok -and $programDataDenyPaths.Count -gt 0
            if ($type -eq "Exe") { $d1RuleDetails.Add("ProgramData deny paths: $($programDataDenyPaths -join '; ')") }
            $d1RuleDetails.Add("$type enabled=$($collection[0].EnforcementMode), allow-all=$allowAll, customer-denies=$($denyPaths.Count)")
        }
        $d1CollectionsOk = $d1CollectionsOk -and $ok
    }
    Check "D1.C1" "AppLocker enforces Exe, Msi, Script and Dll collections with Everyone allow and Customer-only path denies" $d1CollectionsOk ($d1RuleDetails -join " | ")
    $appxCollection = @($d1Policy.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq "Appx" })
    $appxAllow = $false
    if ($appxCollection.Count -eq 1 -and $appxCollection[0].EnforcementMode -eq "Enabled") {
        $appxAllow = @($appxCollection[0].FilePublisherRule | Where-Object { $_.Action -eq "Allow" -and $_.UserOrGroupSid -eq "S-1-1-0" -and $_.Conditions.FilePublisherCondition.PublisherName -eq "*" -and $_.Conditions.FilePublisherCondition.ProductName -eq "*" -and $_.Conditions.FilePublisherCondition.BinaryName -eq "*" }).Count -gt 0
        $appxDenies = @($appxCollection[0].FilePublisherRule | Where-Object { $_.Action -eq "Deny" })
        $appxAllow = $appxAllow -and $appxDenies.Count -eq 1 -and $appxDenies[0].Conditions.FilePublisherCondition.ProductName -eq "Microsoft.XboxGamingOverlay" -and $appxDenies[0].UserOrGroupSid -eq $u.SID.Value
    }
    Check "D1.C1b" "Appx collection allows signed packaged apps; its only deny is the Xbox Game Bar, for the Customer" $appxAllow "Appx collection count $($appxCollection.Count)"
    # E3: is the Game Bar really refused to the Customer, and other packaged apps still allowed? Windows' own AppLocker test answers per package.
    $gameDvrPolicy = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -ErrorAction SilentlyContinue).AllowGameDVR
    $gameBarPackage = @(Get-AppxPackage -AllUsers -Name Microsoft.XboxGamingOverlay -ErrorAction SilentlyContinue | Select-Object -First 1)
    $otherPackage = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { -not $_.IsFramework -and $_.Name -ne "Microsoft.XboxGamingOverlay" -and $_.SignatureKind -eq "Store" } | Select-Object -First 1)
    $d1PolicyFile = Join-Path $env:TEMP "cafe-applocker-now.xml"; Get-AppLockerPolicy -Effective -Xml | Set-Content $d1PolicyFile -Encoding UTF8
    $gameBarDecision = if ($gameBarPackage) { (Test-AppLockerPolicy -XmlPolicy $d1PolicyFile -Packages $gameBarPackage -User Customer).PolicyDecision } else { "not installed on this machine" }
    $otherDecision = if ($otherPackage) { (Test-AppLockerPolicy -XmlPolicy $d1PolicyFile -Packages $otherPackage -User Customer).PolicyDecision } else { "none found" }
    Check "E3.G1" "Xbox Game Bar off: Windows' game recording policy off; AppLocker refuses the Game Bar to the Customer and still allows other packaged apps" ($gameDvrPolicy -eq 0 -and $gameBarDecision -in @("Denied", "DeniedByDefault", "not installed on this machine") -and "$otherDecision" -eq "Allowed") "AllowGameDVR $gameDvrPolicy; Game Bar: $gameBarDecision; $($otherPackage.Name): $otherDecision"
    $appIdNow = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'"
    Check "D1.C2" "Application Identity is automatic and running" ($appIdNow.StartMode -eq "Auto" -and $appIdNow.State -eq "Running") "start $($appIdNow.StartMode); state $($appIdNow.State)"
    $appLockerFilter = Get-CimInstance Win32_SystemDriver -Filter "Name='applockerfltr'" -ErrorAction SilentlyContinue
    $appLockerFilterRunning = $appLockerFilter -and $appLockerFilter.State -eq "Running"
    Check "D1.C2b" "AppLocker filter driver is running" $appLockerFilterRunning "AppLockerFltr state $($appLockerFilter.State)"
    $aclReport = "$data\customer-writable-folders.txt"
    $aclReportPresent = Test-Path -LiteralPath $aclReport
    if ($aclReportPresent) { New-Item -ItemType Directory -Path $wd -Force | Out-Null; Copy-Item -LiteralPath $aclReport -Destination $wd -Force }
    $aclReportText = if ($aclReportPresent) { Get-Content -LiteralPath $aclReport -Raw } else { "" }
    $aclRootsRecorded = $aclReportText.Contains("ACL ROOT: $env:ProgramFiles") -and $aclReportText.Contains("ACL ROOT: $($env:ProgramFiles) (x86)") -and $aclReportText.Contains("ACL ROOT: $env:ProgramData")
    $aclDetailsRecorded = $aclReportText.Contains("CUSTOMER-WRITABLE+EXECUTABLE:") -and $aclReportText.Contains("STEAM/LIBRARY FOLDERS") -and ($aclReportText.Contains("PROGRAMDATA WRITABLE:") -or $aclReportText.Contains("PROGRAMDATA CUSTOMER-WRITABLE FOLDERS: none"))
    Check "D1.C3" "Fresh-install ACL inventory records Program Files, Program Files (x86), ProgramData and every writable/executable folder before policy creation" ($aclReportPresent -and $aclRootsRecorded -and $aclDetailsRecorded) "report $aclReport; roots recorded $aclRootsRecorded; details recorded $aclDetailsRecorded"
    $wipeReported = $aclReportText.Contains("PROGRAMDATA WRITABLE: $data\wipe")
    Check "D1.C3a" "ACL inventory explicitly reports the Customer-writable ProgramData wipe folder" $wipeReported "Expected $data\wipe in customer-writable-folders.txt"

    function Get-D1BlockEvent([string]$LogName, [int]$EventId, [string]$FilePath, [string]$CustomerSid) {
        # Get-WinEvent's StartTime filter is local-time based; convert the UTC test
        # boundary explicitly, then verify each event's UTC timestamp and UserId SID.
        $startUtc = $d1StartedUtc
        $events = @(Get-WinEvent -FilterHashtable @{
            LogName = $LogName
            Id = $EventId
            StartTime = $startUtc.ToLocalTime()
        } -ErrorAction SilentlyContinue)
        foreach ($event in $events) {
            $eventUtc = $event.TimeCreated.ToUniversalTime()
            if ($eventUtc -lt $startUtc) { continue }
            $eventSid = if ($event.UserId -is [Security.Principal.SecurityIdentifier]) { $event.UserId.Value } else { "$($event.UserId)" }
            if ($eventSid -ne $CustomerSid) { continue }
            $message = "$($event.Message)"
            $expandedMessage = $message -replace "(?i)%OSDRIVE%", $env:SystemDrive
            $expandedMessage = $expandedMessage -replace "(?i)%WINDIR%", $env:WINDIR
            $expandedMessage = $expandedMessage -replace "(?i)%SYSTEM32%", (Join-Path $env:WINDIR "System32")
            if ($message.IndexOf($FilePath, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                $expandedMessage.IndexOf($FilePath, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                Write-Host ("Matched AppLocker block event {0} in '{1}'; event UTC={2:o}; UserId={3}; file={4}" -f $EventId, $LogName, $eventUtc, $eventSid, $FilePath)
                return $true
            }
        }
        return $false
    }
    function Invoke-CustomerInteractiveTaskProbe([string]$FilePath, [string]$CustomerSid) {
        $taskName = "CafeD1InteractiveProbe-" + [guid]::NewGuid().ToString("N")
        $taskFolder = $null
        $registeredTask = $null
        $agentSession = $null
        $agent = Get-Process Cafe.Agent -IncludeUserName -ErrorAction SilentlyContinue |
            Where-Object { $_.UserName -eq "$env:COMPUTERNAME\Customer" } | Select-Object -First 1
        if ($agent) { $agentSession = $agent.SessionId }
        Write-Host "Interactive Customer-session probe: Cafe.Agent session ID=$agentSession; target=$FilePath"
        try {
            $taskService = New-Object -ComObject "Schedule.Service"
            $taskService.Connect()
            $definition = $taskService.NewTask(0)
            $definition.RegistrationInfo.Description = "Temporary Cafe D1 AppLocker interactive-session diagnostic"
            $definition.Principal.UserId = "$env:COMPUTERNAME\Customer"
            $definition.Principal.LogonType = 3 # TASK_LOGON_INTERACTIVE_TOKEN: use an already logged-on Customer session
            $definition.Principal.RunLevel = 0
            $definition.Settings.Enabled = $true
            $definition.Settings.Hidden = $true
            $definition.Settings.ExecutionTimeLimit = "PT30S"
            $action = $definition.Actions.Create(0)
            $action.Path = $FilePath
            $action.Arguments = "-t 127.0.0.1"
            $taskFolder = $taskService.GetFolder("\")
            $registeredTask = $taskFolder.RegisterTaskDefinition($taskName, $definition, 6,
                "$env:COMPUTERNAME\Customer", $null, 3, $null)
            $null = $registeredTask.Run($null)

            $probe = $null
            for ($probeWait = 0; $probeWait -lt 20; $probeWait++) {
                $probe = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                    Where-Object { $_.ExecutablePath -and $_.ExecutablePath.Equals($FilePath, [StringComparison]::OrdinalIgnoreCase) } |
                    Select-Object -First 1
                if ($probe) { break }
                Start-Sleep -Milliseconds 500
            }
            $interactiveSession = $null
            $startedInInteractiveSession = $false
            if ($probe) {
                $startedInInteractiveSession = $true
                $interactiveSession = $probe.SessionId
                Stop-Process -Id $probe.ProcessId -Force -ErrorAction SilentlyContinue
            }
            Start-Sleep -Milliseconds 500
            $taskResult = $registeredTask.LastTaskResult
            $blocked = Get-D1BlockEvent "Microsoft-Windows-AppLocker/EXE and DLL" 8004 $FilePath $CustomerSid
            $sameSession = ($null -ne $agentSession -and $null -ne $interactiveSession -and $agentSession -eq $interactiveSession)
            Write-Host "Interactive Customer-session probe result: processStarted=$startedInInteractiveSession; processSessionId=$interactiveSession; Cafe.AgentSessionId=$agentSession; sameSessionAsCafeAgent=$sameSession; taskLastResult=$taskResult; event8004=$blocked"
            if (-not $agent) { Write-Host "No Customer-owned Cafe.Agent process was present to identify the lock-screen session." }
            return [pscustomobject]@{ Started = $startedInInteractiveSession; SessionId = $interactiveSession; AgentSessionId = $agentSession; SameSession = $sameSession; TaskResult = $taskResult; BlockedEvent = $blocked }
        } catch {
            Write-Host "Interactive Customer-session probe could not run: $($_.Exception.Message)"
            return [pscustomobject]@{ Started = $false; SessionId = $null; AgentSessionId = $agentSession; SameSession = $false; TaskResult = $null; BlockedEvent = $false; Error = $_.Exception.Message }
        } finally {
            if ($taskFolder -and $taskName) {
                try { $taskFolder.DeleteTask($taskName, 0) } catch { Write-Host "Could not remove temporary interactive diagnostic task: $($_.Exception.Message)" }
            }
        }
    }
    $d1StartedUtc = [DateTime]::UtcNow
    $pingSource = "$env:WINDIR\System32\PING.EXE"
    $d1Suffix = [guid]::NewGuid().ToString("N")
    $d1ExeCases = @(
        @{ Id = "D1.C4a"; Name = "Desktop"; File = "$prof\Desktop\d1-$d1Suffix.exe" },
        @{ Id = "D1.C4b"; Name = "Downloads"; File = "$prof\Downloads\d1-$d1Suffix.exe" },
        @{ Id = "D1.C4c"; Name = "AppData Local Temp"; File = "$prof\AppData\Local\Temp\d1-$d1Suffix.exe" },
        @{ Id = "D1.C4d"; Name = "C Users Public"; File = "C:\Users\Public\d1-$d1Suffix.exe" }
    )
    foreach ($case in $d1ExeCases) {
        $parent = Split-Path -Parent $case.File
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
        Copy-Item -LiteralPath $pingSource -Destination $case.File -Force
        $ran = $false
        try {
            $process = AsCustomer $case.File "-n 1 127.0.0.1"
            if ($process.WaitForExit(10000)) { $ran = ($process.ExitCode -eq 0) }
            else { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue; $ran = $true }
        } catch { $ran = $false }
        if ($case.Id -eq "D1.C4a") {
            Write-Host "D1.C4 diagnostic Customer execution result: file=$($case.File); processRan=$ran; exitCode=$($process.ExitCode)"
            $interactiveProbe = Invoke-CustomerInteractiveTaskProbe $case.File $u.SID.Value
            Write-Host "D1 comparison (same probe image): Start-Process -Credential ran=$ran; InteractiveToken task started=$($interactiveProbe.Started); same Cafe.Agent session=$($interactiveProbe.SameSession); interactive 8004=$($interactiveProbe.BlockedEvent)"
        }
        $logged = WaitFor 20 { Get-D1BlockEvent "Microsoft-Windows-AppLocker/EXE and DLL" 8004 $case.File $u.SID.Value }
        Check $case.Id "Customer cannot run PING.EXE from $($case.Name); AppLocker logs event 8004" ((-not $ran) -and $logged) "ran $ran; event 8004 $logged; $($case.File)"
    }

    # The customer account has DisableCMD=2 for normal use. Temporarily remove only that test restriction
    # while checking AppLocker script rules, then restore it before continuing.
    $customerHivePath = "Registry::HKEY_USERS\$($u.SID.Value)"
    $mountedD1Hive = $false
    if (-not (Test-Path -LiteralPath $customerHivePath)) {
        & reg.exe load "HKU\$($u.SID.Value)" "$prof\NTUSER.DAT" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not load Customer hive for the AppLocker batch-file tests." }
        $customerHivePath = "Registry::HKEY_USERS\$($u.SID.Value)"
        $mountedD1Hive = $true
    }
    $cmdPolicyKey = "$customerHivePath\Software\Policies\Microsoft\Windows\System"
    $disableCmdProperty = Get-ItemProperty -LiteralPath $cmdPolicyKey -Name DisableCMD -ErrorAction SilentlyContinue
    $hadDisableCmd = $null -ne $disableCmdProperty
    $disableCmdBefore = if ($hadDisableCmd) { $disableCmdProperty.DisableCMD } else { $null }
    try {
        Remove-ItemProperty -LiteralPath $cmdPolicyKey -Name DisableCMD -ErrorAction SilentlyContinue
        $downloadBat = "$prof\Downloads\d1-$d1Suffix.bat"
        $downloadBatMarker = Join-Path "$prof\AppData\Local\Temp" "d1-bat-download-$d1Suffix.txt"
        [IO.File]::WriteAllText($downloadBat, "@echo off`r`necho ran> `"$downloadBatMarker`"`r`nexit /b 0`r`n")
        $batRan = $false
        try {
            $batProcess = AsCustomer "$env:WINDIR\System32\cmd.exe" "/d /c `"$downloadBat`""
            if ($batProcess.WaitForExit(10000)) { $batRan = ($batProcess.ExitCode -eq 0 -and (Test-Path -LiteralPath $downloadBatMarker)) }
            else { Stop-Process -Id $batProcess.Id -Force -ErrorAction SilentlyContinue; $batRan = $true }
        } catch { $batRan = $false }
        $batLogged = WaitFor 20 { Get-D1BlockEvent "Microsoft-Windows-AppLocker/MSI and Script" 8007 $downloadBat $u.SID.Value }
        Check "D1.C5" "Customer cannot run a .bat from Downloads; AppLocker logs event 8007" ((-not $batRan) -and $batLogged) "ran $batRan; event 8007 $batLogged"

        $downloadPs1 = "$prof\Downloads\d1-$d1Suffix.ps1"
        $downloadPsResult = "$prof\Downloads\d1-ps-result-$d1Suffix.txt"
        $psScript = @"
`$mode = `$ExecutionContext.SessionState.LanguageMode
"LanguageMode=`$mode" | Set-Content -LiteralPath '$downloadPsResult'
try {
    Add-Type -TypeDefinition 'public class CafeD1ScriptProbe { public static int Value = 1; }' -ErrorAction Stop
    "Add-Type=Succeeded" | Add-Content -LiteralPath '$downloadPsResult'
    exit 11
} catch {
    "Add-Type=Failed" | Add-Content -LiteralPath '$downloadPsResult'
    if (`$mode -eq 'ConstrainedLanguage') { exit 0 }
    exit 12
}
"@
        [IO.File]::WriteAllText($downloadPs1, $psScript)
        $psExited = $false
        $psExitCode = -1
        try {
            $psProcess = AsCustomer "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" "-NoProfile -ExecutionPolicy Bypass -File `"$downloadPs1`""
            $psExited = $psProcess.WaitForExit(10000)
            if ($psExited) { $psExitCode = $psProcess.ExitCode }
            else { Stop-Process -Id $psProcess.Id -Force -ErrorAction SilentlyContinue }
        } catch { $psExited = $false }
        $psResultText = if (Test-Path -LiteralPath $downloadPsResult) { Get-Content -LiteralPath $downloadPsResult -Raw } else { "" }
        $psConstrained = $psExited -and $psExitCode -eq 0 -and
            $psResultText.Contains("LanguageMode=ConstrainedLanguage") -and $psResultText.Contains("Add-Type=Failed")
        $psLogged = WaitFor 20 { Get-D1BlockEvent "Microsoft-Windows-AppLocker/MSI and Script" 8007 $downloadPs1 $u.SID.Value }
        $psRefused = $psLogged -and -not $psConstrained
        $psOutcome = $psRefused -or $psConstrained
        $psDetail = if ($psConstrained) { "script ran in ConstrainedLanguage; Add-Type failed inside the script" }
            elseif ($psRefused) { "script was refused with AppLocker event 8007" }
            else { "no expected 8007 refusal or ConstrainedLanguage/Add-Type failure; exit $psExitCode; output $psResultText" }
        Check "D1.C6" "Customer .ps1 is refused or runs in ConstrainedLanguage with Add-Type blocked" $psOutcome $psDetail

        # Owner option B: an explicit allow list leaves the selected writable folder un-denied,
        # while another discovered writable folder remains denied.
        $ownerAllowedDir = "C:\CafeD1OwnerAllowed"
        $ownerBlockedDir = "C:\CafeD1OwnerBlocked"
        foreach ($folder in @($ownerAllowedDir, $ownerBlockedDir)) {
            New-Item -ItemType Directory -Path $folder -Force | Out-Null
            & icacls.exe $folder /grant "*$($u.SID.Value):(OI)(CI)M" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Could not grant Customer write access to $folder." }
        }
        Copy-Item -LiteralPath $pingSource -Destination "$ownerAllowedDir\allowed.exe" -Force
        Copy-Item -LiteralPath $pingSource -Destination "$ownerBlockedDir\blocked.exe" -Force
        & "$app\applocker.ps1" -Mode Install -CustomerSid $u.SID.Value -DataPath $data -AllowFolders $ownerAllowedDir
        $ownerPolicy = [xml](Get-AppLockerPolicy -Local -Xml)
        $ownerExeRules = @($ownerPolicy.AppLockerPolicy.RuleCollection | Where-Object Type -eq "Exe" | ForEach-Object { $_.FilePathRule })
        $allowedDeny = @($ownerExeRules | Where-Object { $_.Action -eq "Deny" -and $_.UserOrGroupSid -eq $u.SID.Value -and $_.Conditions.FilePathCondition.Path -eq "$ownerAllowedDir\*" }).Count -gt 0
        $blockedDeny = @($ownerExeRules | Where-Object { $_.Action -eq "Deny" -and $_.UserOrGroupSid -eq $u.SID.Value -and $_.Conditions.FilePathCondition.Path -eq "$ownerBlockedDir\*" }).Count -gt 0
        $allowedRun = $false
        try {
            $ownerAllowedProcess = AsCustomer "$ownerAllowedDir\allowed.exe" "-n 1 127.0.0.1"
            $allowedRun = $ownerAllowedProcess.WaitForExit(10000) -and $ownerAllowedProcess.ExitCode -eq 0
        } catch { $allowedRun = $false }
        $blockedRun = $false
        try {
            $ownerBlockedProcess = AsCustomer "$ownerBlockedDir\blocked.exe" "-n 1 127.0.0.1"
            if ($ownerBlockedProcess.WaitForExit(10000)) { $blockedRun = ($ownerBlockedProcess.ExitCode -eq 0) }
            else { Stop-Process -Id $ownerBlockedProcess.Id -Force -ErrorAction SilentlyContinue; $blockedRun = $true }
        } catch { $blockedRun = $false }
        $ownerBlockedLogged = WaitFor 20 { Get-D1BlockEvent "Microsoft-Windows-AppLocker/EXE and DLL" 8004 "$ownerBlockedDir\blocked.exe" $u.SID.Value }
        Check "D1.C6a" "Owner-allowed writable folder has no Customer deny rule and its executable runs" ((-not $allowedDeny) -and $allowedRun) "deny rule $allowedDeny; executable ran $allowedRun"
        Check "D1.C6b" "Discovered writable folder omitted from -AllowFolders is denied for Customer" ($blockedDeny -and (-not $blockedRun) -and $ownerBlockedLogged) "deny rule $blockedDeny; executable ran $blockedRun; event 8004 $ownerBlockedLogged"

        $programDataProbeDir = Join-Path $env:ProgramData "CafeD1CustomerFolder-$d1Suffix"
        $programDataCreateExit = CustomerPs "try { New-Item -Path '$programDataProbeDir' -ItemType Directory -ErrorAction Stop | Out-Null; exit 0 } catch { exit 1 }"
        $programDataCreated = $programDataCreateExit -eq 0 -and (Test-Path -LiteralPath $programDataProbeDir -PathType Container)
        if ($programDataCreated) {
            $programDataProbeExe = Join-Path $programDataProbeDir "blocked.exe"
            Copy-Item -LiteralPath $pingSource -Destination $programDataProbeExe -Force
            $programDataExeRan = $false
            try {
                $programDataProcess = AsCustomer $programDataProbeExe "-n 1 127.0.0.1"
                if ($programDataProcess.WaitForExit(10000)) { $programDataExeRan = ($programDataProcess.ExitCode -eq 0) }
                else { Stop-Process -Id $programDataProcess.Id -Force -ErrorAction SilentlyContinue; $programDataExeRan = $true }
            } catch { $programDataExeRan = $false }
            $programDataEvent = WaitFor 20 { Get-D1BlockEvent "Microsoft-Windows-AppLocker/EXE and DLL" 8004 $programDataProbeExe $u.SID.Value }
        } else {
            $programDataExeRan = $true
            $programDataEvent = $false
        }
        Check "D1.C6c" "Customer can create a folder in ProgramData but cannot execute an EXE from it" ($programDataCreated -and (-not $programDataExeRan) -and $programDataEvent) "folder created $programDataCreated; executable ran $programDataExeRan; event 8004 $programDataEvent"

        $fakeGameDir = "$env:ProgramFiles\CafeD1FakeGame"
        New-Item -ItemType Directory -Path $fakeGameDir -Force | Out-Null
        Copy-Item -LiteralPath "$out\timer\CafeTimerTest.exe" -Destination "$fakeGameDir\game.exe" -Force
        $gameProcess = AsCustomer "$fakeGameDir\game.exe" "--selftest"
        $gameExited = $gameProcess.WaitForExit(15000)
        if (-not $gameExited) { Stop-Process -Id $gameProcess.Id -Force -ErrorAction SilentlyContinue }
        $gameOk = $gameExited -and $gameProcess.ExitCode -eq 0
        Check "D1.C7" "A fake installed game in Program Files still runs as Customer" $gameOk "exit $($gameProcess.ExitCode)"

        $programFilesBat = "$fakeGameDir\allowed.bat"
        $programFilesBatMarker = Join-Path "$prof\AppData\Local\Temp" "d1-bat-programfiles-$d1Suffix.txt"
        [IO.File]::WriteAllText($programFilesBat, "@echo off`r`necho ran> `"$programFilesBatMarker`"`r`nexit /b 0`r`n")
        $allowedBat = AsCustomer "$env:WINDIR\System32\cmd.exe" "/d /c `"$programFilesBat`""
        $allowedBatExited = $allowedBat.WaitForExit(10000)
        if (-not $allowedBatExited) { Stop-Process -Id $allowedBat.Id -Force -ErrorAction SilentlyContinue }
        $allowedBatOk = $allowedBatExited -and $allowedBat.ExitCode -eq 0 -and (Test-Path -LiteralPath $programFilesBatMarker)
        Check "D1.C8" "A .bat in Program Files still runs as Customer" $allowedBatOk "exit $($allowedBat.ExitCode); marker $((Test-Path $programFilesBatMarker))"
    } finally {
        if ($hadDisableCmd) {
            $restoreHiveName = "CafeD1Restore_$PID"
            $restoreHiveMounted = $false
            $restoredInLiveHive = $false
            if (Test-Path -LiteralPath $customerHivePath) {
                try {
                    $restorePolicyKey = "$customerHivePath\Software\Policies\Microsoft\Windows\System"
                    if (-not (Test-Path -LiteralPath $restorePolicyKey)) {
                        New-Item -Path $restorePolicyKey -Force | Out-Null
                    }
                    Set-ItemProperty -LiteralPath $restorePolicyKey -Name DisableCMD -Value $disableCmdBefore -Type DWord
                    $restoredInLiveHive = $true
                } catch {
                    if (Test-Path -LiteralPath $customerHivePath) { throw }
                    Write-Host "Customer hive unloaded during DisableCMD restore; retrying against NTUSER.DAT."
                }
            }
            if (-not $restoredInLiveHive) {
                $restoreProfilePath = (Get-CimInstance Win32_UserProfile | Where-Object SID -eq $u.SID.Value).LocalPath
                if (-not $restoreProfilePath) { $restoreProfilePath = $prof }
                $restoreLoaded = $false
                for ($restoreAttempt = 0; $restoreAttempt -lt 10; $restoreAttempt++) {
                    & reg.exe load "HKU\$restoreHiveName" "$restoreProfilePath\NTUSER.DAT" | Out-Null
                    if ($LASTEXITCODE -eq 0) { $restoreLoaded = $true; break }
                    Start-Sleep -Seconds 1
                }
                if (-not $restoreLoaded) { throw "Customer's hive was unloaded during AsCustomer tests and could not be reloaded to restore DisableCMD." }
                $restoreHiveMounted = $true
                try {
                    $restorePolicyKey = "Registry::HKEY_USERS\$restoreHiveName\Software\Policies\Microsoft\Windows\System"
                    if (-not (Test-Path -LiteralPath $restorePolicyKey)) {
                        New-Item -Path $restorePolicyKey -Force | Out-Null
                    }
                    Set-ItemProperty -LiteralPath $restorePolicyKey -Name DisableCMD -Value $disableCmdBefore -Type DWord
                    Write-Host "Restored DisableCMD=$disableCmdBefore in the reloaded Customer NTUSER.DAT."
                } finally {
                    if ($restoreHiveMounted) {
                        [gc]::Collect()
                        [gc]::WaitForPendingFinalizers()
                        & reg.exe unload "HKU\$restoreHiveName" | Out-Null
                        if ($LASTEXITCODE -ne 0) { throw "Could not unload the temporary Customer hive after restoring DisableCMD." }
                    }
                }
            }
        }
        if ($mountedD1Hive -and (Test-Path -LiteralPath $customerHivePath)) {
            # Only unload when this test performed the reg.exe load. If the Customer profile service
            # has adopted the hive, or Windows still reports it busy, leave HKU\<SID> mounted.
            $customerProfileForHive = Get-CimInstance Win32_UserProfile | Where-Object SID -eq $u.SID.Value
            $customerProcessesForHive = @(Get-Process -IncludeUserName -ErrorAction SilentlyContinue |
                Where-Object { $_.UserName -eq "$env:COMPUTERNAME\Customer" })
            if (($customerProfileForHive -and $customerProfileForHive.Loaded) -or $customerProcessesForHive.Count -gt 0) {
                Write-Host "Customer profile/session owns HKU\$($u.SID.Value); leaving the test-loaded hive mounted and continuing to use the SID hive."
            } else {
                [gc]::Collect()
                [gc]::WaitForPendingFinalizers()
                & reg.exe unload "HKU\$($u.SID.Value)" | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning "Windows refused to unload the D1 test-loaded Customer hive (exit $LASTEXITCODE); leaving HKU\$($u.SID.Value) mounted instead of failing B3.X."
                }
            }
        }
    }

    $adminExe = "$prof\Downloads\d1-$d1Suffix.exe"
    $adminProcess = Start-Process -FilePath $adminExe -ArgumentList "-n 1 127.0.0.1" -PassThru -WindowStyle Hidden
    $adminExited = $adminProcess.WaitForExit(10000)
    if (-not $adminExited) { Stop-Process -Id $adminProcess.Id -Force -ErrorAction SilentlyContinue }
    Check "D1.C10" "The same Downloads executable remains runnable by an administrator" ($adminExited -and $adminProcess.ExitCode -eq 0) "exited $adminExited"


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
    $ownerCode = [CafeTotpProbe]::Current($fixture.ownerCounter)
    $ownerLogin = Invoke-RestMethod "https://127.0.0.1:5443/staff/login" -Method Post -ContentType "application/json" -Body (@{ phone = "9000000001"; pin = "432100"; code = $ownerCode } | ConvertTo-Json)
    $ownerHeaders = @{ Authorization = "Bearer $($ownerLogin.token)" }
    $timeLockLogStart = if (Test-Path -LiteralPath $watchdogLog) { @(Get-Content -LiteralPath $watchdogLog).Count } else { 0 }
    Invoke-RestMethod "https://127.0.0.1:5443/staff/settings/time-lock" -Method Post -Headers $ownerHeaders -ContentType "application/json" -Body (@{ enabled = $true } | ConvertTo-Json) | Out-Null
    $timeLockSettingPath = "$data\keys\time-lock-setting.json"
    $timeLockRemembered = WaitFor 15 {
        if (-not (Test-Path -LiteralPath $timeLockSettingPath)) { return $false }
        try { (Get-Content -LiteralPath $timeLockSettingPath -Raw | ConvertFrom-Json).lockWhenTimeRunsOut -eq $true } catch { $false }
    }
    $timeLockCustomerAgents = @(Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Where-Object {
        $_.ProcessName -eq "Cafe.Agent" -and $_.UserName -eq "$env:COMPUTERNAME\Customer"
    })
    $timeLockWindowLog = @()
    if (Test-Path -LiteralPath $watchdogLog) {
        $timeLockWindowLog = @(Get-Content -LiteralPath $watchdogLog | Select-Object -Skip $timeLockLogStart)
    }
    Write-Host "F4.1 Customer-owned Cafe.Agent running: $($timeLockCustomerAgents.Count -gt 0) (count $($timeLockCustomerAgents.Count))"
    if ($timeLockWindowLog.Count -eq 0) {
        Write-Host "F4.1 watchdog log in 15-second window: <no new lines>"
    } else {
        foreach ($line in $timeLockWindowLog) { Write-Host "F4.1 watchdog log in 15-second window: $line" }
    }
    Check "F4.1" "Watchdog remembers the owner's latest server time-lock setting outside Customer HKCU" $timeLockRemembered "protected file $timeLockSettingPath; expected lockWhenTimeRunsOut=true; Customer-owned Cafe.Agent running: $($timeLockCustomerAgents.Count -gt 0) (count $($timeLockCustomerAgents.Count)); watchdog log lines in 15-second window: $($timeLockWindowLog.Count)"
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
    # D2: the PC reports a held-back pen drive; it waits on the counter; the owner's answer reaches the PC
    $penDevice = "USB\VID_0781&PID_5567\CAFECI0001"
    $copyRefused = (curl.exe -sk --max-time 10 -o NUL -w "%{http_code}" -H "X-Pc-Token: $token" -H "X-Pc-Bind: a-copy-of-the-key-elsewhere" https://127.0.0.1:5443/pc/state) -join ""
    $bindRead = CustomerPs "[IO.File]::ReadAllBytes('$data\keys\pc.bind') | Out-Null"
    $bindPlain = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes("$data\keys\pc.bind")) -eq (PcBind)
    Check "B3.C4q" "A copy of this PC's key does not work from another device: the counter tied it to this PC's own secret, which the Customer cannot read and which is stored encrypted" ($copyRefused -eq "401" -and $bindRead -ne 0 -and -not $bindPlain) "copy without the secret: HTTP $copyRefused; Customer read exit $bindRead; stored as plain text $bindPlain"
    $penAsked = Pc "/pc/pen-drive" @{ device = $penDevice; name = "CI stick" }
    $penWaiting = @(Invoke-RestMethod "https://127.0.0.1:5443/staff/pen-drives" -Headers $ownerHeaders | Where-Object { $_.id -eq $penAsked.id -and $_.pc -eq "PC1" -and $_.name -eq "CI stick" })
    Invoke-RestMethod "https://127.0.0.1:5443/staff/pen-drives/$($penAsked.id)" -Method Post -Headers $ownerHeaders -ContentType "application/json" -Body (@{ access = "read" } | ConvertTo-Json) | Out-Null
    $penAnswered = Pc "/pc/pen-drive" @{ device = $penDevice; name = "CI stick" }
    $penPcAsStaff = try { Invoke-WebRequest "https://127.0.0.1:5443/staff/pen-drives" -Headers @{ "X-Pc-Token" = $token; "X-Pc-Bind" = (PcBind) } -UseBasicParsing | Out-Null; "answered" } catch { [int]$_.Exception.Response.StatusCode }
    Pc "/pc/wifi-alert" @{ network = "Cafe WiFi"; router = "a4:2b:b0:11:22:33" } | Out-Null
    $wifiAlert = @(Invoke-RestMethod "https://127.0.0.1:5443/staff/alerts" -Headers $ownerHeaders | Where-Object { $_ -like "*PC1: Wi-Fi `"Cafe WiFi`" through a router the cafe did not set up (a4:2b:b0:11:22:33)*" })
    Check "D3.F1" "A PC that disconnected an unknown Wi-Fi router shows it on the owner's alerts" ($wifiAlert.Count -eq 1) "alerts matching: $($wifiAlert.Count)"
    Check "D2.F1" "A pen drive the PC reports waits on the counter, the owner allows read-only, the PC gets that answer, and a PC key cannot answer" ($null -eq $penAsked.access -and $penWaiting.Count -eq 1 -and $penAnswered.access -eq "read" -and $penAnswered.id -eq $penAsked.id -and $penPcAsStaff -eq 401) "first answer '$($penAsked.access)'; on counter $($penWaiting.Count); after answer '$($penAnswered.access)'; PC key on staff page: $penPcAsStaff"
    # S7: the owner puts this PC into setup mode while the customer's time is running. The PC's watchdog tells the counter,
    # which pauses the time and locks the PC; out of setup mode the time runs again. Real setup mode also restarts the PC;
    # here only its flag is made and removed.
    function PcState { Invoke-RestMethod "https://127.0.0.1:5443/pc/state" -Headers @{ "X-Pc-Token" = $token; "X-Pc-Bind" = (PcBind) } }
    $beforeSetup = PcState
    New-Item "$app\setup.flag" -ItemType File -Force | Out-Null
    $setupPaused = WaitFor 30 { $setupState = PcState; $setupState.locked -and $setupState.message -like "This PC is being set up*" }
    $pausedAt = (PcState).elapsedSec; Start-Sleep -Seconds 4; $pausedLater = (PcState).elapsedSec
    Remove-Item "$app\setup.flag" -Force
    $setupResumed = WaitFor 30 { -not (PcState).locked }
    Start-Sleep -Seconds 3
    $afterSetup = PcState
    Check "S7.1" "A PC that goes into setup mode while a customer's time is running tells the counter by itself: the time is paused and the PC is locked with a message; out of setup mode the same visit runs again" ($beforeSetup.locked -eq $false -and $setupPaused -and $pausedLater -eq $pausedAt -and $setupResumed -and $afterSetup.elapsedSec -gt $pausedLater -and $afterSetup.session -eq $beforeSetup.session) "before: locked $($beforeSetup.locked), session $($beforeSetup.session); paused within 30 s $setupPaused; time while paused $pausedAt s then $pausedLater s; running again within 30 s $setupResumed; after: $($afterSetup.elapsedSec) s, session $($afterSetup.session)"
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
    $timeLockAfterReset = $false
    try { $timeLockAfterReset = (Get-Content -LiteralPath $timeLockSettingPath -Raw | ConvertFrom-Json).lockWhenTimeRunsOut -eq $true } catch { }
    Check "F4.2" "Last server time-lock setting survives a full Customer profile and hive reset" $timeLockAfterReset "protected watchdog setting after reset: $timeLockAfterReset"
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
    $customerAgentQuery = {
        @(Get-Process Cafe.Agent -IncludeUserName -ErrorAction SilentlyContinue | Where-Object {
            $_.UserName -eq "$env:COMPUTERNAME\Customer" -and $_.Path -eq "$app\Cafe.Agent.exe"
        }).Count -gt 0
    }
    $agentStarts = WaitFor 5 $customerAgentQuery
    $customerAgentProbe = $null
    if (-not $agentStarts) {
        # Hosted runners do not auto-logon to Customer; start the installed image with the same
        # interactive Customer credential path used by the D1 executable probes.
        Write-Host "No watchdog-owned Customer Cafe.Agent is present in the runner session; launching the Program Files image as Customer to verify its runtime dependencies."
        $customerAgentProbe = AsCustomer "$app\Cafe.Agent.exe" "--server https://127.0.0.1:5443 --logs $data\logs"
        $agentStarts = WaitFor 20 $customerAgentQuery
    }
    $agentProcesses = @(Get-Process Cafe.Agent -IncludeUserName -ErrorAction SilentlyContinue | Where-Object {
        $_.UserName -eq "$env:COMPUTERNAME\Customer" -and $_.Path -eq "$app\Cafe.Agent.exe"
    })
    Check "D1.C9" "Cafe.Agent from Program Files loads and runs under the Customer token" ($agentStarts -and $agentProcesses.Count -gt 0) "Customer-owned Cafe.Agent processes $($agentProcesses.Count); Program Files runtime sidecars $(@(Get-ChildItem -LiteralPath $app -Filter '*.dll' -File).Count)"
    $processAccessDenied = $false
    $processAccessDetail = "No Customer-owned Cafe.Agent process was found"
    $processTestDir = Join-Path $env:ProgramFiles "CafeProcessSecurityTest"
    if ($agentProcesses.Count -gt 0) {
        try {
            Remove-Item -LiteralPath $processTestDir -Recurse -Force -ErrorAction SilentlyContinue
            New-Item -ItemType Directory -Path $processTestDir -Force | Out-Null
            Copy-Item -LiteralPath "$app\Cafe.Watchdog.exe" -Destination "$processTestDir\Cafe.Watchdog.exe" -Force
            $processProbe = AsCustomer "$processTestDir\Cafe.Watchdog.exe" "--test-process-access $($agentProcesses[0].Id)"
            $processProbeExited = $processProbe.WaitForExit(15000)
            if (-not $processProbeExited) { Stop-Process -Id $processProbe.Id -Force -ErrorAction SilentlyContinue }
            $processAccessDenied = $processProbeExited -and $processProbe.ExitCode -eq 0
            $processAccessDetail = "Program Files test-folder probe as Customer; exit $($processProbe.ExitCode)"
        } catch { $processAccessDetail = $_.Exception.Message }
        finally { Remove-Item -LiteralPath $processTestDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    Check "F14.1" "Customer program from a Program Files test folder cannot open Cafe.Agent for VM_WRITE, CREATE_THREAD, DUP_HANDLE, WRITE_DAC, TERMINATE or VM_READ" $processAccessDenied $processAccessDetail
    if ($customerAgentProbe -and -not $customerAgentProbe.HasExited) { Stop-Process -Id $customerAgentProbe.Id -Force -ErrorAction SilentlyContinue }
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
    # E3b: the lock screen's own desktop refuses every other program of the Customer. The lock screen program, run as the
    # Customer (a standard user), makes the desktop exactly as the lock screen does, uses its own handle, then starts itself
    # once more in the same sign-in to try to open the desktop by name.
    $lockDesktop = AsCustomer "$app\Cafe.Agent.exe" "--test-lock-desktop make"
    $lockDesktopDone = $lockDesktop.WaitForExit(60000)
    Check "E3b.L1" "The lock screen's own desktop, made by the Customer, cannot be opened by another program of the Customer: not to switch the screen, read or make windows, set hooks, or read or change its rights" ($lockDesktopDone -and $lockDesktop.ExitCode -eq 0) "finished $lockDesktopDone; exit code $($lockDesktop.ExitCode) (0 = made, the maker's own handle works, the other program was refused every time; 1 = Windows refused to make the desktop; 2 = the maker's handle could not move a thread to it; 3 = the other program OPENED it; 4 = the other program did not finish; 5 = refused, but not as 'access denied')"
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
        $ErrorActionPreference = "Continue"
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
        $probe = Invoke-F12CurlJson @("-H", "X-Pc-Token: $token", "-H", "X-Pc-Bind: $(PcBind)", "https://127.0.0.1:5443/pc/state")
        $null -ne $probe
    }
    $staffLogin = $false
    $staffLoginError = ""
    if ($serverReady) {
        $staffCode = [CafeTotpProbe]::Current($fixture.staffCounter)
        $staffBody = @{ phone = "9000000002"; pin = "111111"; code = $staffCode } | ConvertTo-Json
        $staffBodyPath = Join-Path $env:TEMP ("cafe-f12-staff-" + [guid]::NewGuid().ToString("N") + ".json")
        try {
            [IO.File]::WriteAllText($staffBodyPath, $staffBody, (New-Object System.Text.UTF8Encoding($false)))
            $staff = Invoke-F12CurlJson @("-X", "POST", "-H", "Content-Type: application/json", "--data-binary", "@$staffBodyPath", "https://127.0.0.1:5443/staff/login")
        } finally {
            Remove-Item -LiteralPath $staffBodyPath -Force -ErrorAction SilentlyContinue
        }
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

    # ===== S5. the router gives the counter PC a new address; the gaming PC finds it by itself =====
    $argsFile = "$app\watchdog.args"; $argsBefore = Get-Content $argsFile -Raw
    $gone = "192.0.2.1"   # TEST-NET-1, nobody answers there: like the counter's old address after the router moved it
    function WatchdogLog { (Get-ChildItem "$data\logs" -Filter "watchdog-*.log" -ErrorAction SilentlyContinue | Get-Content -ErrorAction SilentlyContinue) -join "`n" }
    Stop-Service CafeWatchdog
    Set-Content $argsFile ($argsBefore.Trim() -replace '--server\s+https://[^\s"]+', "--server https://${gone}:5443") -Encoding ascii
    Set-Content "$data\dns-server.txt" $gone -Encoding ascii   # DNS went to the counter's old address too
    # first an impostor answers the search: another cafe server with its own certificate
    Stop-Process -Id $server.Id -Force
    $impostorData = Join-Path $env:TEMP "cafe-impostor"; Remove-Item $impostorData -Recurse -Force -ErrorAction SilentlyContinue
    $impostor = Start-Process "$out\server\Cafe.Server.exe" -ArgumentList "--data $impostorData --seed-test" -PassThru -WindowStyle Hidden
    $null = WaitFor 30 { Test-Path "$impostorData\server.pin" }
    Start-Service CafeWatchdog
    $impostorSeen = WaitFor 150 { (WatchdogLog) -match "counter search: \S+ failed the certificate" }
    $argsWithImpostor = Get-Content $argsFile -Raw
    Check "S5.1" "A server with another certificate that answers the search is not used" ($impostorSeen -and $argsWithImpostor -match [regex]::Escape($gone)) "refusal logged $impostorSeen; address kept: $($argsWithImpostor -match [regex]::Escape($gone))"
    Stop-Process -Id $impostor.Id -Force -ErrorAction SilentlyContinue
    $server = Start-Process "$out\server\Cafe.Server.exe" -ArgumentList "--data $tdata --seed-test" -PassThru -WindowStyle Hidden
    $moved = WaitFor 150 { (Get-Content $argsFile -Raw) -notmatch [regex]::Escape($gone) }
    $argsAfter = Get-Content $argsFile -Raw
    $newHost = if ($argsAfter -match '--server https://([0-9.]+):5443') { $Matches[1] } else { "" }
    function NicDns { @((Get-DnsClientServerAddress -InterfaceIndex $defaultIfIndexes[0] -AddressFamily IPv4).ServerAddresses) }
    $dnsMoved = WaitFor 180 { "$(Get-Content "$data\dns-server.txt" -Raw)".Trim() -eq $newHost -and (NicDns) -contains $newHost }
    $nicDns = NicDns
    $resolves = WaitFor 30 { try { [bool](Resolve-DnsName example.com -DnsOnly -QuickTimeout -ErrorAction Stop) } catch { $false } }   # through the filter at the new address
    Check "S5.2" "The gaming PC finds the counter at its new address by itself, checks its certificate and key, saves the address, and moves DNS there" ($moved -and $myAddresses -contains $newHost -and $argsAfter -match [regex]::Escape("`"$app\Cafe.Agent.exe`"") -and $dnsMoved -and $nicDns -contains $newHost -and $resolves -and (WatchdogLog) -match "counter PC found at $([regex]::Escape($newHost))") "moved $moved to '$newHost'; watchdog.args: $("$argsAfter".Trim()); dns-server.txt moved $dnsMoved; adapter DNS $($nicDns -join ','); a website resolves $resolves"
    if (-not $moved -or -not $dnsMoved -or $nicDns -notcontains $newHost) { (WatchdogLog) -split "`n" | Where-Object { $_ -match "counter|DNS" } | Select-Object -Last 30 | ForEach-Object { Write-Host "S5 watchdog log: $_" } }
    & "$app\dns.ps1" -DnsServer $runnerDns -DataPath $data | Out-Null   # back to the test machine's own DNS

    # ===== S6. the gaming PC updates itself from the counter: only a signed, newer update, when it is idle =====
    $updateWork = "$data\update"; New-Item $updateWork -ItemType Directory -Force | Out-Null
    Set-Content "$updateWork\ci-no-restart.flag" "CI: no restart at the end of the update" -Encoding ascii
    function WrongUpdateKey { pwsh -NoProfile -Command "[Convert]::ToBase64String([Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256).ExportPkcs8PrivateKey())" }   # a fresh key that is not the update key
    function OfferUpdate($version, [switch]$OtherKey) {   # what the build and INSTALL-ADMIN do, for the test server
        $u = Join-Path $env:TEMP "cafe-update-$version"; Remove-Item $u -Recurse -Force -ErrorAction SilentlyContinue
        Copy-Item $stage $u -Recurse
        $realKey = $env:UPDATE_SIGNING_KEY
        $env:SIGN_UPDATE_TEST_OTHER_KEY = if ($OtherKey) { "1" } else { "" }   # the test's wrong key on purpose
        if ($OtherKey) { $env:UPDATE_SIGNING_KEY = WrongUpdateKey }
        pwsh -NoProfile -File "$repo\ci\sign-update.ps1" -Folder $u -Version $version | Out-Host
        $signed = $LASTEXITCODE; $env:UPDATE_SIGNING_KEY = $realKey
        if ($signed) { throw "Could not sign the test update (exit $signed)" }
        $to = "$tdata\updates"; Remove-Item $to -Recurse -Force -ErrorAction SilentlyContinue
        foreach ($f in (Get-Content "$u\update.json" -Raw | ConvertFrom-Json).files) {
            $t = Join-Path "$to\files" $f.path; New-Item (Split-Path $t) -ItemType Directory -Force | Out-Null; Copy-Item -LiteralPath (Join-Path $u $f.path) $t
        }
        Copy-Item "$u\update.json", "$u\update.sig" $to
    }
    function InstalledVersion { if (Test-Path "$app\update.json") { (Get-Content "$app\update.json" -Raw | ConvertFrom-Json).version } else { 0 } }
    $idle = try { $st = ((curl.exe -sk --max-time 10 -H "X-Pc-Token: $token" -H "X-Pc-Bind: $(PcBind)" https://127.0.0.1:5443/pc/state) -join "") | ConvertFrom-Json; $st.locked -and $null -eq $st.session } catch { $false }   # curl: PowerShell 5.1 GETs fail with the test's certificate callback
    $versionBefore = InstalledVersion
    OfferUpdate 7 -OtherKey
    Restart-Service CafeWatchdog   # it looks 2 minutes after it starts, then every 10
    $refusedSeen = WaitFor 300 { (WatchdogLog) -match "update refused: its signature is not from the update key" }
    Check "S6.1" "An update signed with any other key is refused and nothing is installed" ($idle -and $refusedSeen -and (InstalledVersion) -eq $versionBefore -and (WatchdogLog) -notmatch "installing update version 7") "PC idle $idle; refusal logged $refusedSeen; installed version $(InstalledVersion) (was $versionBefore)"
    $lockScreenBefore = @(Get-Process Cafe.Agent -ErrorAction SilentlyContinue | ForEach-Object Id)   # "stayed up" = the same program, not one started again later
    OfferUpdate 8
    Restart-Service CafeWatchdog
    $updated = WaitFor 1200 { (InstalledVersion) -eq 8 -and "$(Get-Content "$updateWork\result.txt" -Raw -ErrorAction SilentlyContinue)" -match "^done: 8" -and (Get-Service CafeWatchdog).Status -eq "Running" }
    $lockScreenUp = [bool](Get-Process Cafe.Agent -ErrorAction SilentlyContinue | Where-Object { $lockScreenBefore -contains $_.Id })
    Check "S6.2" "A signed, newer update is installed by the gaming PC itself while idle; the watchdog runs again and the lock screen stayed up" ($updated -and $lockScreenUp -and (WatchdogLog) -match "installing update version 8") "installed version $(InstalledVersion); result '$("$(Get-Content "$updateWork\result.txt" -Raw -ErrorAction SilentlyContinue)".Trim())'; watchdog $((Get-Service CafeWatchdog).Status); the same lock screen still running $lockScreenUp"
    if (-not $updated) { Get-Content "$updateWork\new\install-log.txt" -Tail 40 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "S6 update log: $_" } }
    Restart-Service CafeWatchdog
    Start-Sleep -Seconds 170
    $installs = ([regex]::Matches((WatchdogLog), "installing update version 8")).Count
    Check "S6.3" "The same version is not installed again" ($installs -eq 1 -and (InstalledVersion) -eq 8) "installs of version 8 logged: $installs"
    # the build's own guard: with a key that is not the watchdog's it must stop, not ship an update no gaming PC accepts
    $wrongKeyFolder = Join-Path $env:TEMP "cafe-update-wrong-key"; Remove-Item $wrongKeyFolder -Recurse -Force -ErrorAction SilentlyContinue
    New-Item $wrongKeyFolder -ItemType Directory | Out-Null; Copy-Item "$repo\install\install-pc.ps1" $wrongKeyFolder
    $realKey = $env:UPDATE_SIGNING_KEY; $env:SIGN_UPDATE_TEST_OTHER_KEY = ""; $env:UPDATE_SIGNING_KEY = WrongUpdateKey
    pwsh -NoProfile -File "$repo\ci\sign-update.ps1" -Folder $wrongKeyFolder -Version 9 | Out-Host
    $wrongKeyExit = $LASTEXITCODE; $env:UPDATE_SIGNING_KEY = $realKey
    Check "S6.4" "The build refuses to sign an update with a key that is not the one built into the watchdog" ($wrongKeyExit -ne 0 -and -not (Test-Path "$wrongKeyFolder\update.json") -and -not (Test-Path "$wrongKeyFolder\update.sig")) "sign-update exit code $wrongKeyExit; update.json written $(Test-Path "$wrongKeyFolder\update.json"); update.sig written $(Test-Path "$wrongKeyFolder\update.sig")"
    Remove-Item "$updateWork\ci-no-restart.flag" -Force -ErrorAction SilentlyContinue

    # ===== I. uninstall =====
    Remove-Item "$app\test-wipe-mode.flag" -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    Copy-Item "$data\logs\*" $wd -ErrorAction SilentlyContinue   # the watchdog's log goes with the uninstall; keep it for the artifacts
    $postUninstallPassword = [Cafe.Lsa]::Read("DefaultPassword")
    $uninstallLogPath = Join-Path $env:TEMP "cafe-pc-uninstall.log"
    Remove-Item -LiteralPath $uninstallLogPath -Force -ErrorAction SilentlyContinue
    & "$app\install-pc.ps1" -Uninstall -Ci *>&1 |
        Tee-Object -FilePath $uninstallLogPath |
        ForEach-Object { Write-Host "$_" }
    $afterIfIndexes = @(Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -ExpandProperty InterfaceIndex -Unique)
    $dnsAfter = @($afterIfIndexes | ForEach-Object { $i = $_; "$i=$((Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4).ServerAddresses -join ',')" })
    Check "B3.I1" "PC uninstall: service, account, files, data and rules gone" (-not (Get-Service CafeWatchdog -ErrorAction SilentlyContinue) -and -not (Get-LocalUser Customer -ErrorAction SilentlyContinue) -and -not (Test-Path $app) -and -not (Test-Path $data) -and -not (Get-NetFirewallRule -Group "Cafe PC" -ErrorAction SilentlyContinue)) "left: $(@(Get-ChildItem $app, $data -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 5 | ForEach-Object FullName) -join ', '); $(CounterWindows)"
    $blockedNames = @("Cafe: block SMB (TCP 445)", "Cafe: block NetBIOS name service (UDP 137-138)",
        "Cafe: block NetBIOS session service (TCP 139)", "Cafe: block Remote Desktop (TCP 3389)",
        "Cafe: block Remote Desktop (UDP 3389)", "Cafe: block Windows Remote Management (TCP 5985-5986)")
    $remainingBlocks = @($blockedNames | ForEach-Object { Get-NetFirewallRule -DisplayName $_ -ErrorAction SilentlyContinue })
    Check "B3.I5" "PC uninstall removes every new inbound sharing and remote-administration block rule" ($remainingBlocks.Count -eq 0) "remaining rules $($remainingBlocks.Count)"
    Check "B3.I2" "PC uninstall: DNS and automatic sign-in back as before" (("$dnsAfter" -eq "$dnsBefore") -and (Get-ItemProperty $winlogon).AutoAdminLogon -eq $autoBefore) "DNS before $dnsBefore, after $dnsAfter"
    Check "B3.I2b" "PC uninstall: clock settings back as before" ((Get-ItemProperty $ntpKey).NtpServer -eq $ntpBefore) "$ntpBefore"
    Check "B3.I2c" "PC uninstall: browsers' secure DNS setting back as before" ((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -ErrorAction SilentlyContinue).DnsOverHttpsMode -eq $dohOriginal) "before: '$dohOriginal'"
    Check "B3.I3" "PC uninstall: Level A off" (-not ((CiTool.exe --list-policies) -match "Cafe Level A")) ""
    $writeProtectAfter = (Get-ItemProperty $penStorageKey -ErrorAction SilentlyContinue).WriteProtect
    $gameDvrAfter = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -ErrorAction SilentlyContinue).AllowGameDVR
    Check "E3.I1" "PC uninstall puts the game recording policy back as it was" ($gameDvrAfter -eq $gameDvrOriginal) "before '$gameDvrOriginal', after '$gameDvrAfter'"
    $hotspotAfter = (Get-ItemProperty $hotspotKey -ErrorAction SilentlyContinue).NC_ShowSharedAccessUI
    Check "D3.I1" "PC uninstall puts Mobile hotspot back as it was" ($hotspotAfter -eq $hotspotOriginal -and -not (Test-Path "$data\hotspot-before.txt")) "before '$hotspotOriginal', after '$hotspotAfter'"
    Check "D2.I1" "PC uninstall puts the pen drive settings back as they were" ((Test-Path $penKey) -eq $penRestrictionsOriginal -and $writeProtectAfter -eq $writeProtectOriginal) "restrictions key before $penRestrictionsOriginal, after $(Test-Path $penKey); WriteProtect before '$writeProtectOriginal', after '$writeProtectAfter'"

    $appLockerPolicyAfter = [xml](Get-AppLockerPolicy -Local -Xml)
    $policyRestored = $appLockerPolicyAfter.OuterXml -eq $appLockerPolicyBefore.OuterXml
    $d1RulesRemain = @($appLockerPolicyAfter.SelectNodes("//FilePathRule[contains(@Name, 'Cafe D1')]")).Count -gt 0
    Check "D1.I1" "PC uninstall restores the previous AppLocker policy and removes every D1 rule" ($policyRestored -and -not $d1RulesRemain) "policy restored $policyRestored; D1 rules remain $d1RulesRemain"
    $appIdServiceAfter = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'"
    $uninstallLogText = if (Test-Path -LiteralPath $uninstallLogPath) { Get-Content -LiteralPath $uninstallLogPath -Raw } else { "" }
    $appIdRestoreWarning = $uninstallLogText -match "Could not restore AppIDSvc startup mode"
    $appLockerPolicyRemoved = $policyRestored -and -not $d1RulesRemain
    $appIdStartModeRestored = $appIdServiceAfter.StartMode -eq $appIdServiceBefore.StartMode
    Check "D1.I2" "PC uninstall removes the D1 AppLocker policy and restores AppIDSvc start mode or logs the protected-service refusal" ($appLockerPolicyRemoved -and ($appIdStartModeRestored -or $appIdRestoreWarning)) "D1 policy removed $appLockerPolicyRemoved; start mode before $($appIdServiceBefore.StartMode), after $($appIdServiceAfter.StartMode); protected-service warning logged $appIdRestoreWarning"
    function Get-CRootAclMeaning([string]$Sddl) {
        $sections = @{}
        foreach ($match in [regex]::Matches($Sddl, '([OGDS]):(.*?)(?=[OGDS]:|$)', [Text.RegularExpressions.RegexOptions]::Singleline)) {
            $sections[$match.Groups[1].Value] = $match.Groups[2].Value
        }
        $daclEntries = @()
        if ($sections.ContainsKey("D")) {
            $daclEntries = @([regex]::Matches($sections["D"], '\([^)]*\)') |
                ForEach-Object { $_.Value } | Sort-Object -Unique -CaseSensitive)
        }
        $labelEntries = @()
        if ($sections.ContainsKey("S")) {
            $labelEntries = @([regex]::Matches($sections["S"], '\(ML;[^)]*\)') |
                ForEach-Object { $_.Value } | Sort-Object -Unique -CaseSensitive)
        }
        [pscustomobject]@{
            Owner = $sections["O"]
            Group = $sections["G"]
            Dacl = $daclEntries -join "`n"
            MandatoryLabel = $labelEntries -join "`n"
        }
    }
    $cRootAclAfterUninstall = (Get-Acl -LiteralPath "$env:SystemDrive\").Sddl
    $cRootAclBeforeMeaning = Get-CRootAclMeaning $cRootAclBefore
    $cRootAclAfterMeaning = Get-CRootAclMeaning $cRootAclAfterUninstall
    $cRootOwnerSame = $cRootAclBeforeMeaning.Owner -eq $cRootAclAfterMeaning.Owner
    $cRootGroupSame = $cRootAclBeforeMeaning.Group -eq $cRootAclAfterMeaning.Group
    $cRootDaclSame = $cRootAclBeforeMeaning.Dacl -ceq $cRootAclAfterMeaning.Dacl
    $cRootLabelSame = $cRootAclBeforeMeaning.MandatoryLabel -ceq $cRootAclAfterMeaning.MandatoryLabel
    $cRootAclRestored = $cRootOwnerSame -and $cRootGroupSame -and $cRootDaclSame -and $cRootLabelSame
    $cRootAclDetail = if ($cRootAclRestored) {
        "owner, group, unordered DACL ACE set, and SACL mandatory label restored"
    } else {
        "owner same $cRootOwnerSame; group same $cRootGroupSame; DACL ACE set same $cRootDaclSame; SACL mandatory label same $cRootLabelSame; original SDDL: $cRootAclBefore; after-uninstall SDDL: $cRootAclAfterUninstall"
    }
    Check "D1.I4" "PC uninstall restores the C drive root ACL meaning (owner, group, DACL ACE set, SACL label)" $cRootAclRestored $cRootAclDetail

    $postUninstallRuns = $false
    $postUninstallDetail = "Customer test account was not recreated."
    $postUninstallUser = $null
    try {
        if ([string]::IsNullOrWhiteSpace($postUninstallPassword)) { throw "The pre-uninstall Customer password was unavailable." }
        $postUninstallSecurePassword = New-Object Security.SecureString
        foreach ($passwordCharacter in $postUninstallPassword.ToCharArray()) { $postUninstallSecurePassword.AppendChar($passwordCharacter) }
        $postUninstallSecurePassword.MakeReadOnly()
        $postUninstallUser = New-LocalUser -Name "Customer" -Password $postUninstallSecurePassword -PasswordNeverExpires -AccountNeverExpires -UserMayNotChangePassword -FullName "Customer"
        Add-LocalGroupMember -SID "S-1-5-32-545" -Member $postUninstallUser
        [Cafe.Lsa]::Store("DefaultPassword", $postUninstallPassword)
        $profileProbe = AsCustomer "$env:WINDIR\System32\cmd.exe" "/c exit"
        $profileProbe.WaitForExit(10000)
        $postUninstallProfile = Get-CimInstance Win32_UserProfile | Where-Object SID -eq $postUninstallUser.SID.Value | Select-Object -First 1
        if (-not $postUninstallProfile -or -not $postUninstallProfile.LocalPath) { throw "The post-uninstall Customer profile was not created." }
        $postUninstallDownloads = Join-Path $postUninstallProfile.LocalPath "Downloads"
        New-Item -ItemType Directory -Path $postUninstallDownloads -Force | Out-Null
        $postUninstallExe = Join-Path $postUninstallDownloads "d1-after-uninstall.exe"
        Copy-Item -LiteralPath $pingSource -Destination $postUninstallExe -Force
        $postUninstallProcess = AsCustomer $postUninstallExe "-n 1 127.0.0.1"
        $postUninstallExited = $postUninstallProcess.WaitForExit(10000)
        if (-not $postUninstallExited) { Stop-Process -Id $postUninstallProcess.Id -Force -ErrorAction SilentlyContinue }
        $postUninstallRuns = $postUninstallExited -and $postUninstallProcess.ExitCode -eq 0
        $postUninstallDetail = "Customer Downloads PING.EXE exit $($postUninstallProcess.ExitCode); AppLocker policy restored $policyRestored; D1 rules remain $d1RulesRemain"
    } catch {
        $postUninstallDetail = $_.Exception.Message
    } finally {
        [Cafe.Lsa]::Store("DefaultPassword", $null)
        if ($postUninstallUser) {
            $postUninstallProfile = Get-CimInstance Win32_UserProfile | Where-Object SID -eq $postUninstallUser.SID.Value
            if ($postUninstallProfile) { $postUninstallProfile | Remove-CimInstance -ErrorAction SilentlyContinue }
            Remove-LocalUser -Name "Customer" -ErrorAction SilentlyContinue
        }
    }
    Check "D1.I3" "After uninstall, Customer can run PING.EXE from Downloads and the previous AppLocker policy is restored" ($postUninstallRuns -and $policyRestored -and -not $d1RulesRemain) $postUninstallDetail

    Write-Host "before the counter uninstall: $(CounterWindows)"
    & "$stageA\install-admin.ps1" -Uninstall -Ci
    Check "B3.I4" "Counter PC uninstall: server and filter gone" (-not (Get-Service CafeServer, AdGuardHome -ErrorAction SilentlyContinue)) ""
    Check "B3.I4d" "Counter PC uninstall: the counter window program and its two icons gone" (-not (Test-Path "$counterApp\Cafe.Counter.exe") -and -not ($counterIcons | Where-Object { Test-Path $_ })) "program left $(Test-Path "$counterApp\Cafe.Counter.exe"); icons left $(@($counterIcons | Where-Object { Test-Path $_ }).Count); $(CounterWindows)"
    Check "B3.I4b" "Counter PC uninstall: clock settings back as before" ((Get-ItemProperty $ntpKey).NtpServer -eq $ntpOriginal) "$ntpOriginal"
    $idleAfter = Get-ItemProperty $idleKey -ErrorAction SilentlyContinue
    $idleBefore = if ($null -eq $idleOriginal) { $null } else { $idleOriginal.InactivityTimeoutSecs }
    $idleRestored = if ($null -eq $idleBefore) { $null -eq $idleAfter.InactivityTimeoutSecs } else { $idleAfter.InactivityTimeoutSecs -eq $idleBefore }
    Check "B3.I4c" "Counter PC uninstall: previous idle-lock setting restored" $idleRestored "before $idleBefore, after $($idleAfter.InactivityTimeoutSecs)"
}
catch { Check "B3.X" "script error" $false "$_ (line $($_.InvocationInfo.ScriptLineNumber))" }
finally {
    if (Test-Path -LiteralPath "$data\customer-writable-folders.txt") {
        New-Item -ItemType Directory -Path $wd -Force | Out-Null
        Copy-Item -LiteralPath "$data\customer-writable-folders.txt" -Destination $wd -Force -ErrorAction SilentlyContinue
    }
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
