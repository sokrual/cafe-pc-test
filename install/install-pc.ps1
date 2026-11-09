# INSTALL-PC: sets up one gaming PC. Run it as admin, two times:
#   1st time: puts the cafe program on the PC and makes the "Customer" Windows account. After a restart the PC
#             signs in to Customer by itself, with no lock screen yet, so the owner can set that account up.
#   2nd time: saves a clean copy of the Customer account, locks the account down, and switches the lock screen on.
# -Server: the counter PC's address (asked once, kept after that). -DnsServer: the internet filter's address (normally the
# counter PC; only for tests). -Setup: open the Customer account for changes again.
# -Uninstall: take everything off this PC. -Ci: unattended test run (no pop-ups, no restart).
#Requires -RunAsAdministrator
param([string]$Server, [string]$DnsServer, [switch]$Setup, [switch]$Uninstall, [switch]$Ci)
$ErrorActionPreference = "Stop"
$src = $PSScriptRoot
$app = "$env:ProgramFiles\ShinzxCafe"     # program files: only admins can change them
$data = "$env:ProgramData\ShinzxCafe"     # clean copy and settings: only admins and Windows can open them
$flag = "$app\setup.flag"                 # while this file exists the lock screen stays off
$user = "Customer"
$svc = "CafeWatchdog"
$winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$machinePolicy = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
function Say($text) {
    if ($Ci) { Write-Host $text; return }
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show($text, "Shinzx setup") | Out-Null
}
trap { Say "Setup stopped:`n$_`n`nRun it again. If it stops again, take a photo of this window and send it on Discord to the person who gave you this software."; break }
if (-not $Uninstall) { Start-Transcript "$src\install-log.txt" -Append | Out-Null }   # what happened, step by step: send this file on Discord if setup stops

# The Windows sign-in password is kept where Windows keeps it for automatic sign-in (an LSA secret), never in a file.
Add-Type -Namespace Shinzx -Name Lsa -MemberDefinition @'
[StructLayout(LayoutKind.Sequential)] public struct U { public ushort Len, Max; public IntPtr Buf; }
[StructLayout(LayoutKind.Sequential)] public struct A { public int Len; public IntPtr Root, Name; public uint Attr; public IntPtr Sd, Qos; }
[DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(IntPtr sys, ref A attr, uint access, out IntPtr h);
[DllImport("advapi32.dll")] static extern uint LsaStorePrivateData(IntPtr h, ref U key, IntPtr data);
[DllImport("advapi32.dll")] static extern uint LsaRetrievePrivateData(IntPtr h, ref U key, out IntPtr data);
[DllImport("advapi32.dll")] static extern uint LsaFreeMemory(IntPtr p);
[DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr h);
static U Str(string s) { return new U { Len = (ushort)(s.Length * 2), Max = (ushort)(s.Length * 2 + 2), Buf = Marshal.StringToHGlobalUni(s) }; }
static IntPtr Open() { var a = new A { Len = Marshal.SizeOf(typeof(A)) }; IntPtr h; var r = LsaOpenPolicy(IntPtr.Zero, ref a, 0x000F0FFF, out h); if (r != 0) throw new Exception("LsaOpenPolicy " + r); return h; }
// value null deletes the secret
public static void Store(string key, string value) {
    var h = Open(); var k = Str(key); var v = value == null ? new U() : Str(value); var p = IntPtr.Zero;
    try {
        if (value != null) { p = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(U))); Marshal.StructureToPtr(v, p, false); }
        var r = LsaStorePrivateData(h, ref k, p);
        if (r != 0 && value != null) throw new Exception("LsaStorePrivateData " + r);
    } finally { Marshal.FreeHGlobal(k.Buf); if (v.Buf != IntPtr.Zero) Marshal.FreeHGlobal(v.Buf); if (p != IntPtr.Zero) Marshal.FreeHGlobal(p); LsaClose(h); }
}
public static string Read(string key) {
    var h = Open(); var k = Str(key); IntPtr d;
    try {
        if (LsaRetrievePrivateData(h, ref k, out d) != 0) return null;
        var u = (U)Marshal.PtrToStructure(d, typeof(U)); var s = Marshal.PtrToStringUni(u.Buf, u.Len / 2); LsaFreeMemory(d); return s;
    } finally { Marshal.FreeHGlobal(k.Buf); LsaClose(h); }
}
'@

function Customer-Profile { # folder of the Customer account, or $null before its first sign-in
    $u = Get-LocalUser $user -ErrorAction SilentlyContinue
    if ($u) { (Get-CimInstance Win32_UserProfile | Where-Object SID -eq $u.SID.Value).LocalPath }
}
function Close-Customer-Apps { Get-Process -IncludeUserName | Where-Object UserName -eq "$env:COMPUTERNAME\$user" | Stop-Process -Force -ErrorAction SilentlyContinue }
function Restore-Dns {
    foreach ($a in Get-Content "$data\dns-before.json" -Raw | ConvertFrom-Json) {
        if ($a.servers) { Set-DnsClientServerAddress -InterfaceIndex $a.index -ServerAddresses ($a.servers -split ',') -ErrorAction SilentlyContinue }
        else { Set-DnsClientServerAddress -InterfaceIndex $a.index -ResetServerAddresses -ErrorAction SilentlyContinue }   # back to automatic
    }
    Clear-DnsClientCache
}
function Key($k) { if (-not (Test-Path $k)) { New-Item $k -Force | Out-Null } }   # New-Item -Force on an existing key would wipe its values
function Restart-Now($text) { if ($Ci) { Write-Host "$text (CI: no restart)" } else { Say $text; Restart-Computer -Force } }

if ($Uninstall) {
    if (Get-Service $svc -ErrorAction SilentlyContinue) { Stop-Service $svc -Force; sc.exe delete $svc | Out-Null }
    foreach ($m in "Minimal", "Network") { Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$m\$svc" -Recurse -ErrorAction SilentlyContinue }
    Get-Process Cafe.Agent -ErrorAction SilentlyContinue | Stop-Process -Force
    if (Test-Path "$app\levelA.ps1") { & "$app\levelA.ps1" -Mode Off }
    [Shinzx.Lsa]::Store("DefaultPassword", $null)
    if (Test-Path "$data\before.json") { # put back each Windows setting exactly as it was before the first install
        $before = Get-Content "$data\before.json" -Raw | ConvertFrom-Json
        foreach ($p in $before.PSObject.Properties) {
            $key, $name = $p.Name -split '\|'
            if ($null -eq $p.Value) { Remove-ItemProperty $key $name -ErrorAction SilentlyContinue } else { Set-ItemProperty $key $name $p.Value }
        }
    }
    Remove-NetFirewallRule -Group "Shinzx PC" -ErrorAction SilentlyContinue
    if (Test-Path "$data\dns-before.json") { Restore-Dns }
    $u = Get-LocalUser $user -ErrorAction SilentlyContinue
    if ($u) {
        Close-Customer-Apps
        Get-CimInstance Win32_UserProfile | Where-Object SID -eq $u.SID.Value | Remove-CimInstance -ErrorAction SilentlyContinue
        Remove-LocalUser $user
    }
    Remove-Item $app, $data -Recurse -Force -ErrorAction SilentlyContinue
    Say "The cafe program is off this PC. The Customer account is removed."
    exit 0
}

# --- the counter PC's address and this PC's keys ---
if (-not $Server -and (Test-Path "$app\watchdog.args")) { $Server = ((Get-Content "$app\watchdog.args" -Raw) -split '--server https://')[1] -replace '(?s):5443.*', '' }
if (-not $Server -and -not $Ci) { Add-Type -AssemblyName Microsoft.VisualBasic; $Server = [Microsoft.VisualBasic.Interaction]::InputBox("Type the counter PC's address (for example 192.168.1.10):", "Shinzx setup") }
if ($Server -notmatch '^[A-Za-z0-9.-]{1,63}$') { throw "The counter PC's address '$Server' is not valid. Use its address, for example 192.168.1.10." }
foreach ($f in "pc.token", "server.pin") {
    if (-not (Test-Path "$src\$f") -and -not (Test-Path "$app\$f")) { throw "The file $f is missing. Copy it from the counter PC into this folder." }
}

# --- program files ---
if (Get-Service $svc -ErrorAction SilentlyContinue) { Stop-Service $svc -Force }
Get-Process Cafe.Watchdog, Cafe.Agent -ErrorAction SilentlyContinue | Stop-Process -Force   # a stopped service can take a moment to let go of its file
Start-Sleep -Seconds 1
New-Item $app -ItemType Directory -Force | Out-Null   # inside Program Files: customers can read and run, not change
foreach ($f in "Cafe.Agent.exe", "Cafe.Watchdog.exe", "keep-running.txt", "install-pc.ps1", "levelA.ps1", "SETUP-MODE.bat", "pc.token", "server.pin") {
    if ($src -ne $app -and (Test-Path "$src\$f")) { Copy-Item "$src\$f" $app -Force }   # SETUP-MODE runs from $app itself
}
"`"$app\Cafe.Agent.exe`" --server https://${Server}:5443" | Set-Content "$app\watchdog.args" -Encoding ascii

New-Item $data -ItemType Directory -Force | Out-Null
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in "S-1-5-32-544", "S-1-5-18") {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]$sid, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"))
}
Set-Acl $data $acl
# the one place the lock screen (running as Customer) may write: a "please clean up" note for the watchdog
New-Item "$data\wipe" -ItemType Directory -Force | Out-Null
icacls "$data\wipe" /grant "*S-1-5-32-545:(OI)(CI)(W,RD)" | Out-Null

# --- Windows settings: remember what they were, once, so uninstall can put them back ---
$edge, $chrome, $firefox = "HKLM:\SOFTWARE\Policies\Microsoft\Edge", "HKLM:\SOFTWARE\Policies\Google\Chrome", "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS"
$watched = @("$winlogon|AutoAdminLogon", "$winlogon|ForceAutoLogon", "$winlogon|DefaultUserName", "$winlogon|DefaultDomainName",
    "$machinePolicy|HideFastUserSwitching", "$edge|DnsOverHttpsMode", "$chrome|DnsOverHttpsMode", "$firefox|Enabled", "$firefox|Locked",
    "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters|NtpServer", "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters|Type",
    "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient|SpecialPollInterval")
if (-not (Test-Path "$data\before.json")) {
    $before = [ordered]@{}
    foreach ($w in $watched) { $k, $n = $w -split '\|'; $before[$w] = (Get-ItemProperty $k -Name $n -ErrorAction SilentlyContinue).$n }
    $before | ConvertTo-Json | Set-Content "$data\before.json" -Encoding utf8
}

# --- the Customer account: a normal (not admin) account with a long random password nobody needs to know ---
$rnd = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($rnd)
$pwText = [Convert]::ToBase64String($rnd) + "Aa9!"   # suffix meets Windows password rules
$pw = New-Object Security.SecureString; foreach ($c in $pwText.ToCharArray()) { $pw.AppendChar($c) }
if (Get-LocalUser $user -ErrorAction SilentlyContinue) { Set-LocalUser $user -Password $pw -PasswordNeverExpires $true }
else {
    New-LocalUser $user -Password $pw -PasswordNeverExpires -AccountNeverExpires -UserMayNotChangePassword -FullName "Customer" | Out-Null
    Add-LocalGroupMember -SID "S-1-5-32-545" -Member $user
}
Remove-LocalGroupMember -SID "S-1-5-32-544" -Member $user -ErrorAction SilentlyContinue   # never an admin
[Shinzx.Lsa]::Store("DefaultPassword", $pwText)
Remove-ItemProperty $winlogon DefaultPassword -ErrorAction SilentlyContinue   # never in plain text
Set-ItemProperty $winlogon AutoAdminLogon "1"
Set-ItemProperty $winlogon ForceAutoLogon "1"      # signs Customer in again after a sign-out too
Set-ItemProperty $winlogon DefaultUserName $user
Set-ItemProperty $winlogon DefaultDomainName $env:COMPUTERNAME
Key $machinePolicy
Set-ItemProperty $machinePolicy HideFastUserSwitching 1 -Type DWord

# --- forced DNS: every web address goes through the counter PC's internet filter (AdGuard Home), so customers
#     cannot reach blocked sites by using another DNS server. Only switched on once the filter answers. ---
if (-not $DnsServer) { $DnsServer = Get-Content "$data\dns-server.txt" -ErrorAction SilentlyContinue }
if (-not $DnsServer) { $DnsServer = $Server }
$dnsOk = $false
if ($DnsServer -as [ipaddress]) { try { Resolve-DnsName "example.com" -Server $DnsServer -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null; $dnsOk = $true } catch { } }
if ($dnsOk) {
    $nics = @(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq "Up" })
    if (-not (Test-Path "$data\dns-before.json")) {
        @($nics | ForEach-Object { # "servers" empty = the address came automatically from the router
            $static = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($_.NetAdapter.InterfaceGuid)").NameServer
            [pscustomobject]@{ index = $_.InterfaceIndex; servers = "$static" }
        }) | ConvertTo-Json | Set-Content "$data\dns-before.json" -Encoding utf8
    }
    Remove-NetFirewallRule -Group "Shinzx PC" -ErrorAction SilentlyContinue
    $DnsServer | Set-Content "$data\dns-server.txt" -Encoding ascii
    foreach ($n in $nics) { Set-DnsClientServerAddress -InterfaceIndex $n.InterfaceIndex -ServerAddresses $DnsServer }
    # block DNS (53) and private DNS (853) to every address except the filter; all of IPv6
    $b = ([ipaddress]$DnsServer).GetAddressBytes(); [array]::Reverse($b); $n = [BitConverter]::ToUInt32($b, 0)
    function Ip($v) { $x = [BitConverter]::GetBytes([uint32]$v); [array]::Reverse($x); ([ipaddress]$x).ToString() }
    $others = @("::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
    if ($n -gt 0) { $others += "0.0.0.0-$(Ip ($n - 1))" }
    if ($n -lt [uint32]::MaxValue) { $others += "$(Ip ($n + 1))-255.255.255.255" }
    New-NetFirewallRule -Group "Shinzx PC" -DisplayName "Shinzx: web addresses only through the counter PC (UDP)" -Direction Outbound -Action Block -Profile Any -Protocol UDP -RemotePort 53, 853 -RemoteAddress $others | Out-Null
    New-NetFirewallRule -Group "Shinzx PC" -DisplayName "Shinzx: web addresses only through the counter PC (TCP)" -Direction Outbound -Action Block -Profile Any -Protocol TCP -RemotePort 53, 853 -RemoteAddress $others | Out-Null
    # browsers must not go around it with their own secure DNS
    foreach ($k in $edge, $chrome) { Key $k; Set-ItemProperty $k DnsOverHttpsMode "off" }
    Key $firefox; Set-ItemProperty $firefox Enabled 0 -Type DWord; Set-ItemProperty $firefox Locked 1 -Type DWord
    Clear-DnsClientCache
} elseif (-not (Get-NetFirewallRule -Group "Shinzx PC" -ErrorAction SilentlyContinue)) {   # an existing lock stays as it is
    Say "Note: the internet filter on the counter PC ($DnsServer) did not answer, so web filtering is NOT on for this PC yet.`nFinish the filter setup on the counter PC, then run INSTALL-PC again. Everything else works."
}

# --- clock: synced every hour with India's official time servers (NIC and NPL), as CERT-In asks; logs need the right time ---
$w32 = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time"
Set-ItemProperty "$w32\Parameters" NtpServer "samay1.nic.in,0x9 samay2.nic.in,0x9 time.nplindia.org,0x9"
Set-ItemProperty "$w32\Parameters" Type "NTP"
Set-ItemProperty "$w32\TimeProviders\NtpClient" SpecialPollInterval 3600 -Type DWord
Set-Service w32time -StartupType Automatic; Restart-Service w32time -Force
w32tm.exe /resync /nowait | Out-Null

# --- the watchdog service: runs as Windows itself (SYSTEM), starts with the PC, also in Safe Mode, restarts if it stops ---
if (-not (Get-Service $svc -ErrorAction SilentlyContinue)) {
    New-Service -Name $svc -BinaryPathName "`"$app\Cafe.Watchdog.exe`"" -DisplayName "Shinzx Cafe watchdog" -StartupType Automatic | Out-Null
}
sc.exe failure $svc reset= 86400 actions= restart/2000/restart/2000/restart/2000 | Out-Null
foreach ($m in "Minimal", "Network") { New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$m\$svc" -Value "Service" -Force | Out-Null }

# --- which step is this? ---
$profilePath = Customer-Profile
if ($Setup -or (-not (Test-Path "$data\clean-profile") -and -not (Test-Path $flag))) {
    New-Item $flag -ItemType File -Force | Out-Null
    Start-Service $svc
    Restart-Now "Step 1 is done.`n`nThe PC restarts now and signs in to the Customer account by itself (no lock screen yet).`nThere: install Discord, add the game shortcuts, set up the mouse, keyboard and headset apps.`nDo NOT sign in to Discord, Steam or any other app.`n`nThen double-click INSTALL-PC again (it asks for the admin password)."
    exit 0
}
if ((Test-Path $flag) -and -not $profilePath) { Start-Service $svc; Say "Restart the PC first. It signs in to the Customer account by itself. Set it up, then run INSTALL-PC again."; exit 1 }

if (Test-Path $flag) {
    # --- step 2: save the clean copy and lock the Customer account down ---
    Close-Customer-Apps
    Start-Sleep -Seconds 2
    # caches the graphics card driver builds stay between customers (games load faster); everything else is copied
    robocopy $profilePath "$data\clean-profile" /MIR /XJ /R:0 /W:0 /NFL /NDL /NJH /NJS /NP /XF NTUSER.DAT* ntuser.* UsrClass.dat* /XD NVIDIA AMD D3DSCache | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "Could not save the clean copy of the Customer account (robocopy $LASTEXITCODE)" }

    $sid = (Get-LocalUser $user).SID.Value
    $hive = "Registry::HKEY_USERS\$sid"
    $loaded = Test-Path $hive
    if (-not $loaded) { # Windows may still be closing the account's settings file just after a sign-out: try for 20 s
        for ($i = 0; $i -lt 10; $i++) { cmd.exe /c "reg load HKU\ShinzxCustomer `"$profilePath\NTUSER.DAT`" >nul 2>&1"; if (-not $LASTEXITCODE) { break }; Start-Sleep -Seconds 2 }
        if ($LASTEXITCODE) { throw "Could not open the Customer settings (reg load $LASTEXITCODE). Restart the PC and run INSTALL-PC again." }
        $hive = "Registry::HKEY_USERS\ShinzxCustomer"
    }
    try {
        foreach ($p in @(
            # no Task Manager, no Lock (Win+L), no password change, no registry editor, no command prompt (game .bat files still run)
            @("Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableTaskMgr", 1),
            @("Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableLockWorkstation", 1),
            @("Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableChangePassword", 1),
            @("Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools", 1),
            @("Software\Policies\Microsoft\Windows\System", "DisableCMD", 2),
            # no "Let's finish setting up your PC" screens and no welcome tips
            @("Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement", "ScoobeSystemSettingEnabled", 0),
            @("Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-310093Enabled", 0))) {
            Key "$hive\$($p[0])"
            Set-ItemProperty "$hive\$($p[0])" $p[1] $p[2] -Type DWord
        }
        # the owner's autostart list (Run, RunOnce): the logout clean-up puts exactly this back and removes anything a customer added
        $runs = foreach ($k in "Run", "RunOnce") {
            $item = Get-Item "$hive\Software\Microsoft\Windows\CurrentVersion\$k" -ErrorAction SilentlyContinue
            if ($item) { foreach ($n in $item.GetValueNames()) { "$k`t$n`t$($item.GetValue($n, $null, 'DoNotExpandEnvironmentNames'))" } }
        }
        [IO.File]::WriteAllLines("$data\run-keys.txt", [string[]]@($runs))
        Remove-Variable item -ErrorAction SilentlyContinue
    } finally {
        if (-not $loaded) { [gc]::Collect(); Start-Sleep -Milliseconds 500; reg.exe unload "HKU\ShinzxCustomer" | Out-Null }
    }
    # Level A watch-only: nothing is blocked; Windows notes every program it would block, for the owner to review
    if (-not (Test-Path "$data\levelA-id.txt")) { & "$app\levelA.ps1" -Mode Audit }
    Remove-Item $flag -Force
    Start-Service $svc
    Restart-Now "All done. The PC restarts now and shows the lock screen.`n`nTo change the Customer account later (new game shortcut, Discord update): double-click SETUP-MODE in C:\Program Files\ShinzxCafe."
    exit 0
}

Start-Service $svc
Say "The cafe program on this PC is updated."
