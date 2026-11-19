# INSTALL-PC: sets up one gaming PC. Run it as admin, two times:
#   1st time: puts the cafe program on the PC and makes the "Customer" Windows account. After a restart the PC
#             signs in to Customer by itself, with no lock screen yet, so the owner can set that account up.
#   2nd time: saves a clean copy of the Customer account, locks the account down, and switches the lock screen on.
# -Server: the counter PC's address (asked once, kept after that). -DnsServer: the internet filter's address (normally the
# counter PC; only for tests). -Setup: open the Customer account for changes again.
# -Uninstall: take everything off this PC. -Ci: unattended test run (no pop-ups, no restart).
# -Auto: an update the gaming PC installs by itself (the watchdog, as SYSTEM, from the counter's signed update): no
#        windows; the lock screen stays up; the PC restarts at the end, or after a failure, so it never stays unlocked.
# -Finish: the 2nd time, started by the "Finish cafe setup" icon (finish-setup.ps1) through the scheduled task
#          CafeFinishSetup, which Windows runs as SYSTEM: no admin password. It works only in setup mode.
#Requires -RunAsAdministrator
param([string]$Server, [string]$DnsServer, [switch]$Setup, [switch]$Uninstall, [switch]$Ci, [switch]$Finish, [switch]$Detached, [switch]$Auto, [AllowEmptyString()][string]$AllowFolders)
$ErrorActionPreference = "Stop"
if ($Finish -and -not $Detached) {
    # Windows runs a scheduled task's program at background speed (CI: step 2 took 14 minutes instead of 2, even at task
    # priority 4). Start the same run as an ordinary program, same SYSTEM account and fixed arguments, and let the task end.
    $run = "`"$PSHOME\powershell.exe`" -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Finish -Detached" + $(if ($Ci) { " -Ci" } else { "" })
    $started = Invoke-CimMethod Win32_Process -MethodName Create -Arguments @{ CommandLine = $run }
    if ($started.ReturnValue) { throw "Could not start the setup (error $($started.ReturnValue))." }
    exit 0
}
$allowFoldersWasSpecified = $PSBoundParameters.ContainsKey("AllowFolders")
$src = $PSScriptRoot
$app = "$env:ProgramFiles\GamingCafe"     # program files: only admins can change them
$data = "$env:ProgramData\GamingCafe"     # clean copy and settings: only admins and Windows can open them
$flag = "$app\setup.flag"                 # while this file exists the lock screen stays off
$user = "Customer"
$svc = "CafeWatchdog"
$winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$machinePolicy = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$finishTask = "CafeFinishSetup"
$finishOut = "$data\finish"   # what the task tells the icon (Wi-Fi networks in range, the result); the Customer can only read it
$finishIcon = "$env:PUBLIC\Desktop\Finish cafe setup.lnk"
$finishCheck = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
function Say($text) {
    if ($Ci -or $Finish -or $Auto) { Write-Host $text; return }   # -Finish and -Auto run as SYSTEM: no screen to show a window on
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show($text, "Gaming Cafe setup") | Out-Null
}
trap {
    if ($Auto) { # the watchdog reads this; a restart starts the old watchdog and lock screen again (services start at boot)
        Set-Content "$data\update\result.txt" "failed: $_" -Encoding utf8 -ErrorAction SilentlyContinue
        if (-not $Ci) { Restart-Computer -Force }
    }
    if ($Finish) { # the icon cannot show it now (setup closed the Customer's apps): shown at the next sign-in, after a restart
        Set-Content "$finishOut\result.txt" "$_" -Encoding utf8 -ErrorAction SilentlyContinue
        if (-not $Ci) { Restart-Computer -Force }
    }
    Say "Setup stopped:`n$_`n`nRun it again. If it stops again, take a photo of this window. Send the photo and the file install-log.txt (in this folder) on Discord to the person who gave you this software."; break }
if (-not $Uninstall) {
    Start-Transcript "$src\install-log.txt" -Append | Out-Null   # what happened, step by step: send this file on Discord if setup stops
    # Firmware protection is the owner's job; warn only and keep the installer running.
    $secureBootWarning = "Secure Boot is off on this gaming PC. Turn it on: see SECURITY-GUIDE.txt, part 2."
    $secureBootUnknown = "Secure Boot could not be checked on this gaming PC. Check it: see SECURITY-GUIDE.txt, part 2."
    try {
        if (-not (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) {
            $secureBootState = "Unknown"
        } else {
            $secureBootState = if (Confirm-SecureBootUEFI -ErrorAction Stop) { "On" } else { "Off" }
        }
    } catch { $secureBootState = "Unknown" }
    Write-Host "Secure Boot status: $secureBootState"
    if ($secureBootState -eq "Off") {
        Write-Host $secureBootWarning
        Say $secureBootWarning
    } elseif ($secureBootState -eq "Unknown") {
        Write-Host $secureBootUnknown
        Say $secureBootUnknown
    }
}

# The Windows sign-in password is kept where Windows keeps it for automatic sign-in (an LSA secret), never in a file.
Add-Type -Namespace Cafe -Name Lsa -MemberDefinition @'
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

function Close-Customer-Apps { Get-Process -IncludeUserName | Where-Object UserName -eq "$env:COMPUTERNAME\$user" | Stop-Process -Force -ErrorAction SilentlyContinue }
function Copy-WithRetry([string]$Source, [string]$Destination) {
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        try {
            Copy-Item -LiteralPath $Source -Destination $Destination -Force -ErrorAction Stop
            return
        } catch {
            $exception = $_.Exception
            while ($exception -and $exception -isnot [System.IO.IOException]) { $exception = $exception.InnerException }
            if (-not $exception -or (($exception.HResult -band 0xFFFF) -notin @(32, 33))) { throw }
            if ($attempt -eq 10) {
                throw "Could not copy '$Source' to '$Destination' after 10 attempts because the file is in use. Close the program using it and run INSTALL-PC again. $($exception.Message)"
            }
            Start-Sleep -Seconds 1
        }
    }
}
function Restore-Dns {
    foreach ($a in Get-Content "$data\dns-before.json" -Raw | ConvertFrom-Json) {
        if ($a.servers) { Set-DnsClientServerAddress -InterfaceIndex $a.index -ServerAddresses ($a.servers -split ',') -ErrorAction SilentlyContinue }
        else { Set-DnsClientServerAddress -InterfaceIndex $a.index -ResetServerAddresses -ErrorAction SilentlyContinue }   # back to automatic
    }
    Clear-DnsClientCache
}
function Key($k) { if (-not (Test-Path $k)) { New-Item $k -Force | Out-Null } }   # New-Item -Force on an existing key would wipe its values
function Restart-Now($text) { if ($Ci) { Write-Host "$text (CI: no restart)" } else { Say $text; Restart-Computer -Force } }
function Remove-FinishIcon {
    Unregister-ScheduledTask $finishTask -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $finishIcon -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty $finishCheck CafeFinishSetup -ErrorAction SilentlyContinue
}

if ($Uninstall) {
    if (Get-Service $svc -ErrorAction SilentlyContinue) { Stop-Service $svc -Force; sc.exe delete $svc | Out-Null }
    foreach ($m in "Minimal", "Network") { Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$m\$svc" -Recurse -ErrorAction SilentlyContinue }
    Get-Process Cafe.Agent -ErrorAction SilentlyContinue | Stop-Process -Force
    if (Test-Path "$app\applocker.ps1") { & "$app\applocker.ps1" -Mode Uninstall -DataPath $data }
    if (Test-Path "$app\levelA.ps1") { & "$app\levelA.ps1" -Mode Off }
    if (Test-Path "$app\pendrives.ps1") { & "$app\pendrives.ps1" -Mode Off -DataPath $data }
    if (Test-Path "$app\wifi.ps1") { & "$app\wifi.ps1" -Mode Off -AppPath $app -DataPath $data }
    [Cafe.Lsa]::Store("DefaultPassword", $null)
    if (Test-Path "$data\before.json") { # put back each Windows setting exactly as it was before the first install
        $before = Get-Content "$data\before.json" -Raw | ConvertFrom-Json
        foreach ($p in $before.PSObject.Properties) {
            $key, $name = $p.Name -split '\|'
            if ($null -eq $p.Value) { Remove-ItemProperty $key $name -ErrorAction SilentlyContinue } else { Set-ItemProperty $key $name $p.Value }
        }
    }
    Remove-FinishIcon
    Remove-NetFirewallRule -Group "Cafe PC" -ErrorAction SilentlyContinue
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

# --- the "Finish cafe setup" icon asked for step 2 ---
$finishWifi = $null
if ($Finish) {
    if (-not (Test-Path $flag)) { Write-Host "Not in setup mode: nothing to finish."; exit 0 }
    $sid = (Get-LocalUser $user).SID.Value
    $wanted = "Registry::HKEY_USERS\$sid\Software\GamingCafe"   # the icon writes the owner's Wi-Fi choice there
    $nearby = @(& "$app\Cafe.Watchdog.exe" --wifi-networks "$data\keys")
    $noWifi = $LASTEXITCODE -eq 3
    if (-not $noWifi -and $LASTEXITCODE) { throw "Could not read the Wi-Fi networks (error $LASTEXITCODE)." }
    $choice = (Get-ItemProperty $wanted -ErrorAction SilentlyContinue).FinishWifi
    if ($null -eq $choice) { # first call: tell the icon which networks are in range, then wait for the owner's choice
        Set-Content "$finishOut\nearby.txt" $(if ($noWifi) { "NO-WIFI" } else { $nearby }) -Encoding utf8
        exit 0
    }
    Remove-Item $wanted -Recurse -Force   # not into the clean copy of the account
    $finishWifi = @($choice -split "`n" | ForEach-Object Trim | Where-Object { $_ })
    foreach ($n in $finishWifi) { if ($nearby -notcontains $n) { throw "A Wi-Fi network you chose is not in range now. Double-click Finish cafe setup again." } }   # never repeated: it came from the Customer account
    Remove-Item "$finishOut\result.txt", "$finishOut\nearby.txt" -Force -ErrorAction SilentlyContinue
}

# --- the counter PC's address and this PC's keys ---
if (-not $Server -and (Test-Path "$app\watchdog.args")) { $Server = ((Get-Content "$app\watchdog.args" -Raw) -split '--server https://')[1] -replace '(?s):5443.*', '' }
if (-not $Server -and (Test-Path "$src\counter-address.txt")) { $Server = (Get-Content "$src\counter-address.txt" -Raw).Trim() }   # written by INSTALL-ADMIN
if (-not $Server -and -not $Ci) { Add-Type -AssemblyName Microsoft.VisualBasic; $Server = [Microsoft.VisualBasic.Interaction]::InputBox("Type the counter PC's address (for example 192.168.1.10):", "Gaming Cafe setup") }
if ($Server -notmatch '^[A-Za-z0-9.-]{1,63}$') { throw "The counter PC's address '$Server' is not valid. Use its address, for example 192.168.1.10." }
$agentRuntimeSource = Join-Path $src "agent-runtime"
$agentExeSource = Join-Path $agentRuntimeSource "Cafe.Agent.exe"
if (-not (Test-Path -LiteralPath $agentExeSource)) { $agentExeSource = Join-Path $src "Cafe.Agent.exe" }
if (-not (Test-Path -LiteralPath $agentExeSource) -and -not (Test-Path -LiteralPath "$app\Cafe.Agent.exe")) {
    throw "Cafe.Agent.exe and its runtime files are missing. Copy the agent-runtime folder into this installer folder."
}
# key files are named after the PC (PC1.token, PC2.token, made by INSTALL-ADMIN or saved from the counter screen):
# this PC takes the lowest-numbered one left in the folder, so the same folder goes to every gaming PC with no question
$pcName = $null
if (-not (Test-Path "$src\pc.token") -and -not (Test-Path "$app\pc.token") -and -not (Test-Path "$data\keys\pc.token")) {
    $keyFile = Get-ChildItem $src -Filter "*.token" -File | Where-Object Name -ne "pc.token" |
        Sort-Object { $n = ($_.BaseName -replace ' \(\d+\)$', '') -replace '\D', ''; if ($n) { [double]$n } else { [double]::MaxValue } }, Name |
        Select-Object -First 1
    if ($keyFile) {
        $pcName = $keyFile.BaseName -replace ' \(\d+\)$', ''   # " (1)": the browser saved the same file twice
        Move-Item $keyFile.FullName "$src\pc.token"   # used once: removed from the folder after it is saved on this PC
        Write-Host "This PC is $pcName"
    }
}
foreach ($f in "Cafe.Watchdog.exe", "pc.token", "server.pin") {
    if (-not (Test-Path "$src\$f") -and -not (Test-Path "$app\$f") -and -not (Test-Path "$data\keys\$f")) {
        throw "The file $f is missing. Copy it from the counter PC into this folder."
    }
}

# --- program files ---
if (Get-Service $svc -ErrorAction SilentlyContinue) { Stop-Service $svc -Force }
# an update by itself keeps the lock screen running: its files are moved aside (Windows allows that for a running
# program), the new ones copied in, and the restart at the end starts the new lock screen
$stop = if ($Auto) { "Cafe.Watchdog" } else { "Cafe.Watchdog", "Cafe.Agent" }
Get-Process $stop -ErrorAction SilentlyContinue | Stop-Process -Force -PassThru | Wait-Process -Timeout 30
Get-ChildItem "$app\*.moved-aside" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue   # left by the last update
New-Item $app -ItemType Directory -Force | Out-Null   # inside Program Files: customers can read and run, not change
foreach ($f in "Cafe.Watchdog.exe", "keep-running.txt", "install-pc.ps1", "levelA.ps1", "applocker.ps1", "pendrives.ps1", "wifi.ps1", "dns.ps1", "finish-setup.ps1", "SETUP-MODE.bat", "update.json", "update.sig") {
    if ($src -ne $app -and (Test-Path "$src\$f")) { Copy-WithRetry "$src\$f" $app }   # SETUP-MODE runs from $app itself
}
if ($src -ne $app -and (Test-Path -LiteralPath $agentRuntimeSource -PathType Container)) {
    # Cafe.Agent is multi-file published: native runtime libraries stay beside the EXE in Program Files,
    # rather than being extracted by the Customer process into its AppData\Local\Temp directory.
    foreach ($agentFile in Get-ChildItem -LiteralPath $agentRuntimeSource -File) {
        $target = Join-Path $app $agentFile.Name
        if ($Auto -and (Test-Path -LiteralPath $target)) { Move-Item -LiteralPath $target "$target.$([guid]::NewGuid().ToString('N')).moved-aside" -Force }
        Copy-WithRetry $agentFile.FullName $target
    }
} elseif ($src -ne $app -and (Test-Path -LiteralPath $agentExeSource -PathType Leaf)) {
    # Backward-compatible single-file installer source.
    Copy-WithRetry $agentExeSource $app
}
"`"$app\Cafe.Agent.exe`" --server https://${Server}:5443" | Set-Content "$app\watchdog.args" -Encoding ascii

New-Item $data -ItemType Directory -Force | Out-Null
icacls $data /inheritance:r /grant "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null   # admins and Windows only
$keys = "$data\keys"
New-Item $keys -ItemType Directory -Force | Out-Null
icacls $keys /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null
Add-Type -AssemblyName System.Security
if (-not ("CafeAtomicMove" -as [type])) {
    Add-Type -TypeDefinition @'
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class CafeAtomicMove
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool MoveFileEx(string existingFileName, string newFileName, uint flags);
    public static void Replace(string source, string destination)
    {
        if (!MoveFileEx(source, destination, 0x1u | 0x8u))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }
}
'@
}
foreach ($f in "pc.token", "server.pin") {
    $source = if (Test-Path "$src\$f") { "$src\$f" } elseif (Test-Path "$app\$f") { "$app\$f" } else { $null }
    if ($source) { Copy-WithRetry $source "$keys\$f" }
    if (-not (Test-Path "$keys\$f")) { throw "The protected key file $f is missing." }
    if ($f -eq "pc.token") {
        $tokenBytes = [IO.File]::ReadAllBytes("$keys\pc.token")
        $alreadyProtected = $tokenBytes.Length -gt 8 -and $tokenBytes[0] -eq 1 -and $tokenBytes[1] -eq 0 -and
            $tokenBytes[2] -eq 0 -and $tokenBytes[3] -eq 0 -and $tokenBytes[4] -eq 0xD0 -and
            $tokenBytes[5] -eq 0x8C -and $tokenBytes[6] -eq 0x9D -and $tokenBytes[7] -eq 0xDF
        if ($alreadyProtected) {
            try { [void][Security.Cryptography.ProtectedData]::Unprotect($tokenBytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine) }
            catch { throw "The existing machine-protected PC token cannot be decrypted on this PC." }
        } else {
            $plainToken = [Text.Encoding]::UTF8.GetString($tokenBytes).Trim()
            if ([string]::IsNullOrWhiteSpace($plainToken)) { throw "The PC token is empty." }
            $protectedToken = [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($plainToken), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
            $tempToken = "$keys\pc.token.new"
            $tokenStream = [IO.File]::Open($tempToken, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $tokenStream.Write($protectedToken, 0, $protectedToken.Length); $tokenStream.Flush($true) }
            finally { $tokenStream.Dispose() }
            [CafeAtomicMove]::Replace($tempToken, "$keys\pc.token")
        }
    }
    # the key is this PC's alone: off the folder. server.pin stays: it is public (the counter's certificate fingerprint)
    # and the next gaming PC needs it from the same folder
    if ($f -eq "pc.token" -and $src -ne $app -and (Test-Path "$src\$f")) { Remove-Item "$src\$f" -Force }
    Remove-Item "$app\$f" -Force -ErrorAction SilentlyContinue
}
# the one place the lock screen (running as Customer) may write: a "please clean up" note for the watchdog
New-Item "$data\wipe" -ItemType Directory -Force | Out-Null
icacls "$data\wipe" /grant "*S-1-5-32-545:(OI)(CI)(W,RD)" | Out-Null

# --- Windows settings: remember what they were, once, so uninstall can put them back ---
$edge, $chrome, $firefox = "HKLM:\SOFTWARE\Policies\Microsoft\Edge", "HKLM:\SOFTWARE\Policies\Google\Chrome", "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS"
$gameDvr = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
$watched = @("$winlogon|AutoAdminLogon", "$winlogon|ForceAutoLogon", "$winlogon|DefaultUserName", "$winlogon|DefaultDomainName",
    "$machinePolicy|HideFastUserSwitching", "$edge|DnsOverHttpsMode", "$chrome|DnsOverHttpsMode", "$firefox|Enabled", "$firefox|Locked",
    "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters|NtpServer", "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters|Type",
    "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient|SpecialPollInterval", "$gameDvr|AllowGameDVR")
$before = [ordered]@{}
if (Test-Path "$data\before.json") { (Get-Content "$data\before.json" -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $before[$_.Name] = $_.Value } }
$added = $false
foreach ($w in $watched) { # a setting a newer version watches is remembered on its first update, before it is changed
    if ($before.Contains($w)) { continue }
    $k, $n = $w -split '\|'; $before[$w] = (Get-ItemProperty $k -Name $n -ErrorAction SilentlyContinue).$n; $added = $true
}
if ($added) { $before | ConvertTo-Json | Set-Content "$data\before.json" -Encoding utf8 }

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
[Cafe.Lsa]::Store("DefaultPassword", $pwText)
Remove-ItemProperty $winlogon DefaultPassword -ErrorAction SilentlyContinue   # never in plain text
Set-ItemProperty $winlogon AutoAdminLogon "1"
Set-ItemProperty $winlogon ForceAutoLogon "1"      # signs Customer in again after a sign-out too
Set-ItemProperty $winlogon DefaultUserName $user
Set-ItemProperty $winlogon DefaultDomainName $env:COMPUTERNAME
Key $machinePolicy
Set-ItemProperty $machinePolicy HideFastUserSwitching 1 -Type DWord
# Xbox Game Bar off (E3): Windows' policy switches off game recording and the Game Bar overlay (Win+G);
# applocker.ps1 also stops the Customer opening the Game Bar app at all
Key $gameDvr
Set-ItemProperty $gameDvr AllowGameDVR 0 -Type DWord

# --- forced DNS: every web address goes through the counter PC's internet filter (AdGuard Home), so customers
#     cannot reach blocked sites by using another DNS server. Only switched on once the filter answers. ---
if (-not $DnsServer) { $DnsServer = Get-Content "$data\dns-server.txt" -ErrorAction SilentlyContinue }
if (-not $DnsServer) { $DnsServer = $Server }
$dnsOk = $false
if ($DnsServer -as [ipaddress]) { try { Resolve-DnsName "example.com" -Server $DnsServer -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null; $dnsOk = $true } catch { } }
if ($dnsOk) {
    Remove-NetFirewallRule -Group "Cafe PC" -ErrorAction SilentlyContinue
    & "$app\dns.ps1" -DnsServer $DnsServer -DataPath $data   # the watchdog runs it again if the counter PC moves
    # browsers must not go around it with their own secure DNS
    foreach ($k in $edge, $chrome) { Key $k; Set-ItemProperty $k DnsOverHttpsMode "off" }
    Key $firefox; Set-ItemProperty $firefox Enabled 0 -Type DWord; Set-ItemProperty $firefox Locked 1 -Type DWord
    Clear-DnsClientCache
} elseif (-not (Get-NetFirewallRule -Group "Cafe PC" -ErrorAction SilentlyContinue)) {   # an existing lock stays as it is
    Say "Note: the internet filter on the counter PC ($DnsServer) did not answer. Website filtering is NOT on for this PC yet.`nCheck that the counter PC is on and INSTALL-ADMIN finished there, then run INSTALL-PC again. Everything else works."
}

# --- block inbound Windows sharing and remote administration on every gaming PC ---
$inboundBlocks = @(
    @{ DisplayName = "Cafe: block SMB (TCP 445)"; Protocol = "TCP"; Ports = @("445") },
    @{ DisplayName = "Cafe: block NetBIOS name service (UDP 137-138)"; Protocol = "UDP"; Ports = @("137-138") },
    @{ DisplayName = "Cafe: block NetBIOS session service (TCP 139)"; Protocol = "TCP"; Ports = @("139") },
    @{ DisplayName = "Cafe: block Remote Desktop (TCP 3389)"; Protocol = "TCP"; Ports = @("3389") },
    @{ DisplayName = "Cafe: block Remote Desktop (UDP 3389)"; Protocol = "UDP"; Ports = @("3389") },
    @{ DisplayName = "Cafe: block Windows Remote Management (TCP 5985-5986)"; Protocol = "TCP"; Ports = @("5985-5986") }
)
foreach ($rule in $inboundBlocks) {
    Get-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue | Where-Object Group -eq "Cafe PC" | Remove-NetFirewallRule
    New-NetFirewallRule -Group "Cafe PC" -DisplayName $rule.DisplayName -Direction Inbound -Action Block -Enabled True -Profile Any -Protocol $rule.Protocol -LocalPort $rule.Ports -RemoteAddress Any | Out-Null
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
    New-Service -Name $svc -BinaryPathName "`"$app\Cafe.Watchdog.exe`"" -DisplayName "Gaming Cafe watchdog" -StartupType Automatic | Out-Null
}
sc.exe failure $svc reset= 86400 actions= restart/2000/restart/2000/restart/2000 | Out-Null
foreach ($m in "Minimal", "Network") { New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$m\$svc" -Value "Service" -Force | Out-Null }

# --- which step is this? ---
$profilePath = (Get-CimInstance Win32_UserProfile | Where-Object SID -eq (Get-LocalUser $user).SID.Value).LocalPath   # empty before Customer's first sign-in
# Older installs have a file baseline but no clean registry-hive snapshot; run the owner's setup again before enabling resets.
if ($Setup -or (-not (Test-Path $flag) -and (-not (Test-Path "$data\clean-profile") -or -not (Test-Path "$data\clean-profile-hive\NTUSER.DAT")))) {
    New-Item $flag -ItemType File -Force | Out-Null
    # the "Finish cafe setup" icon: the Customer may start step 2 (as SYSTEM) while the PC is in setup mode, nothing else
    New-Item $finishOut -ItemType Directory -Force | Out-Null
    $customerSid = (Get-LocalUser $user).SID.Value
    icacls $finishOut /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*${customerSid}:(OI)(CI)RX" | Out-Null
    $taskArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$app\install-pc.ps1`" -Finish" + $(if ($Ci) { " -Ci" } else { "" })
    Register-ScheduledTask $finishTask -Force -Action (New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $taskArgs) `
        -Principal (New-ScheduledTaskPrincipal -UserId "S-1-5-18" -RunLevel Highest) `
        -Settings (New-ScheduledTaskSettingsSet -Priority 4 -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries) | Out-Null   # the task only starts the real run (see -Detached)
    $scheduler = New-Object -ComObject Schedule.Service; $scheduler.Connect()
    $scheduler.GetFolder("\").GetTask($finishTask).SetSecurityDescriptor("D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;GRGX;;;$customerSid)", 0)   # Customer: start it only
    $shell = New-Object -ComObject WScript.Shell; $lnk = $shell.CreateShortcut($finishIcon)
    $lnk.TargetPath = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$app\finish-setup.ps1`""
    $lnk.IconLocation = "$env:WINDIR\System32\shell32.dll,294"; $lnk.Save()
    Set-ItemProperty $finishCheck CafeFinishSetup "`"$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe`" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$app\finish-setup.ps1`" -Check"
    & "$app\pendrives.ps1" -Mode Off -DataPath $data   # the owner may need a pen drive while setting the PC up
    & "$app\wifi.ps1" -Mode Off -AppPath $app -DataPath $data   # and any Wi-Fi network
    Start-Service $svc
    $nameNote = if ($pcName) { "This PC is $pcName. Put a label with $pcName on it: the counter screen uses that name.`n`n" } else { "" }
    Restart-Now "$($nameNote)Step 1 is done.`n`nThe PC restarts now and signs in to the Customer account by itself (no lock screen yet).`nThere: install Discord, add the game shortcuts, set up the mouse, keyboard and headset apps.`nDo NOT sign in to Discord, Steam or any other app.`n`nThen double-click 'Finish cafe setup' on the desktop (no password needed)."
    exit 0
}
if ((Test-Path $flag) -and -not $profilePath) { Start-Service $svc; Say "Restart the PC first. It signs in to the Customer account by itself. Set it up, then run INSTALL-PC again."; exit 1 }

if (Test-Path $flag) {
    # --- step 2: save the clean copy and lock the Customer account down ---
    Write-Host "$(Get-Date -Format HH:mm:ss) step 2 starts"
    Close-Customer-Apps
    Start-Sleep -Seconds 2
    # caches the graphics card driver builds stay between customers (games load faster); everything else is copied
    robocopy $profilePath "$data\clean-profile" /MIR /XJ /R:0 /W:0 /NFL /NDL /NJH /NJS /NP /XF NTUSER.DAT* ntuser.* UsrClass.dat* /XD NVIDIA AMD D3DSCache | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "Could not save the clean copy of the Customer account (error $LASTEXITCODE). Restart the PC and try again." }

    $sid = (Get-LocalUser $user).SID.Value
    $hive = "Registry::HKEY_USERS\$sid"
    $loaded = Test-Path $hive
    if (-not $loaded) { # Windows may still be closing the account's settings file just after a sign-out: try for 20 s
        for ($i = 0; $i -lt 10; $i++) { cmd.exe /c "reg load HKU\CafeCustomer `"$profilePath\NTUSER.DAT`" >nul 2>&1"; if (-not $LASTEXITCODE) { break }; Start-Sleep -Seconds 2 }
        if ($LASTEXITCODE) { throw "Could not open the Customer account's settings (error $LASTEXITCODE). Restart the PC and try again." }
        $hive = "Registry::HKEY_USERS\CafeCustomer"
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
        # Save the complete owner registry hive while it is mounted; a full profile reset restores this clean baseline.
        $hiveSnapshot = "$data\clean-profile-hive"
        if (Test-Path $hiveSnapshot) { Remove-Item $hiveSnapshot -Recurse -Force }
        New-Item $hiveSnapshot -ItemType Directory -Force | Out-Null
        icacls $hiveSnapshot /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not protect the clean registry hive snapshot." }
        $hiveName = if ($loaded) { $sid } else { "CafeCustomer" }
        reg.exe save "HKU\$hiveName" "$hiveSnapshot\NTUSER.DAT" /y | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path "$hiveSnapshot\NTUSER.DAT")) { throw "Could not save the Customer registry hive." }
        $classSid = "${sid}_Classes"
        $usrClass = "$profilePath\AppData\Local\Microsoft\Windows\UsrClass.dat"
        if (Test-Path "Registry::HKEY_USERS\$classSid") {
            reg.exe save "HKU\$classSid" "$hiveSnapshot\UsrClass.dat" /y | Out-Null
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path "$hiveSnapshot\UsrClass.dat")) { throw "Could not save the Customer class registry hive." }
        } elseif (Test-Path $usrClass) {
            Copy-WithRetry $usrClass "$hiveSnapshot\UsrClass.dat"
        }
        Remove-Variable item -ErrorAction SilentlyContinue
    } finally {
        if (-not $loaded) { [gc]::Collect(); Start-Sleep -Milliseconds 500; reg.exe unload "HKU\CafeCustomer" | Out-Null }
    }
    # AppLocker blocks Customer execution only from customer-writable locations; Level A remains watch-only.
    $appLockerArgs = @{ Mode = "Install"; CustomerSid = $sid; DataPath = $data }
    if ($Ci) { $appLockerArgs.AllowFolders = "" }
    elseif ($allowFoldersWasSpecified) { $appLockerArgs.AllowFolders = $AllowFolders }
    Write-Host "$(Get-Date -Format HH:mm:ss) clean copy saved; AppLocker starts"
    & "$app\applocker.ps1" @appLockerArgs
    Write-Host "$(Get-Date -Format HH:mm:ss) AppLocker done"
    & "$app\pendrives.ps1" -Mode Install -DataPath $data   # pen drives need an OK from the counter
    if ($Finish) { & "$app\wifi.ps1" -Mode Install -Networks $finishWifi -AppPath $app -DataPath $data }   # chosen on the icon
    else { & "$app\wifi.ps1" -Mode Install -Ask -AppPath $app -DataPath $data }   # the owner picks the cafe's Wi-Fi networks
    # Level A watch-only: nothing is blocked; Windows notes every program it would block, for the owner to review
    if (-not (Test-Path "$data\levelA-id.txt")) { & "$app\levelA.ps1" -Mode Audit }
    Remove-Item $flag -Force
    Remove-Item $finishOut -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service $svc
    if (-not $Finish) { Remove-FinishIcon }
    Restart-Now "All done. The PC restarts now and shows the lock screen.`n`nTo change the Customer account later (new game shortcut, Discord update): double-click SETUP-MODE in C:\Program Files\GamingCafe."
    # last: the restart may win the race. shortcut: then the task stays; harmless, it does nothing outside setup mode
    # and the next setup mode replaces it
    Remove-FinishIcon
    Write-Host "The finish-setup task and icon are removed."
    exit 0
}

$appLockerArgs = @{ Mode = "Install"; CustomerSid = (Get-LocalUser $user).SID.Value; DataPath = $data }
if ($Ci) { $appLockerArgs.AllowFolders = "" }
elseif ($allowFoldersWasSpecified) { $appLockerArgs.AllowFolders = $AllowFolders }
& "$app\applocker.ps1" @appLockerArgs
& "$app\pendrives.ps1" -Mode Install -DataPath $data
& "$app\wifi.ps1" -Mode Install -AppPath $app -DataPath $data
if ($Auto) { Set-Content "$data\update\result.txt" "done: $((Get-Content "$app\update.json" -Raw | ConvertFrom-Json).version)" -Encoding utf8 }
if ($Auto -and -not $Ci) { Restart-Computer -Force; exit 0 }   # the new watchdog and lock screen start at boot
Start-Service $svc
Say "The cafe program on this PC is updated."
