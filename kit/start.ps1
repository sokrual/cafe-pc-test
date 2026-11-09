# START-TEST: runs every automatic Phase 0 check, then leaves quiet monitoring on for normal cafe use.
#Requires -RunAsAdministrator
# -Ci: unattended run on a test machine (no pop-ups, no restart)
param([switch]$Ci)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
function Say($text, $buttons = "OK") {
    if ($Ci) { Write-Host $text; return "No" }
    [System.Windows.Forms.MessageBox]::Show($text, "Shinzx test", $buttons)
}
trap { Say "Something went wrong:`n$_`n`nCustomers can keep using this PC - nothing is blocked for them.`n`nPlease take a photo of this window and send it on Discord to the person who gave you this test. Then double-click FINISH-TEST to undo any changes." | Out-Null; break }

$root = $PSScriptRoot
if ($root -match '\\(Downloads|Desktop|Documents|OneDrive)(\\|$)') { Say "Please move this folder to C:\ShinzxTest and run START-TEST again."; exit 1 }
$logs = Join-Path $root "logs"
Get-ChildItem $root -File | Unblock-File   # kit files only, before the transcript file is open
# Folders made in C:\ let every user change their files. Lock the kit: measure.ps1 runs as SYSTEM and
# START/FINISH as admin, so a customer who could edit them would get full control of the PC.
# Replace the whole permission list (a folder can carry its own "Authenticated Users: Modify"); files inside inherit it.
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($r in ("S-1-5-32-544", "FullControl"), ("S-1-5-18", "FullControl"), ("S-1-5-32-545", "ReadAndExecute")) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]$r[0], $r[1], "ContainerInherit, ObjectInherit", "None", "Allow"))
}
Set-Acl $root $acl
icacls "$root\*" /reset /T /Q | Out-Null   # make every file inside take exactly these permissions
if ($LASTEXITCODE) { throw "Could not lock the test files (icacls exit $LASTEXITCODE)" }
$userLogs = Join-Path $logs "users"   # the only place normal users may write: the timer's own logs
New-Item -ItemType Directory $userLogs -Force | Out-Null
icacls $userLogs /grant "*S-1-5-32-545:(OI)(CI)M" | Out-Null
Start-Transcript (Join-Path $logs "start-transcript.txt") -Append | Out-Null

$results = [System.Collections.Generic.List[object]]::new()
function Add-Result($id, $test, $ok, $detail) {
    $res = if ($null -eq $ok) { "NOT TESTED" } elseif ($ok) { "PASS" } else { "FAIL" }
    $results.Add([pscustomobject]@{ id = $id; test = $test; result = $res; detail = "$detail" })
    Write-Host "[$res] $test - $detail"
}
$start = Get-Date
$expires = $start.AddDays(3).ToString("s")   # monitoring stops itself after 3 days if FINISH-TEST is forgotten
@{ start = $start.ToString("s"); expires = $expires } | ConvertTo-Json | Out-File (Join-Path $logs "test-window.json") -Encoding utf8

$exe = Join-Path $root "ShinzxTimerTest.exe"
# --- PC details (also answers "which Windows version?") ---
$os = Get-CimInstance Win32_OperatingSystem
$cv = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
@(
    "Windows: $($os.Caption), version $($cv.DisplayVersion), build $($cv.CurrentBuild).$($cv.UBR)"
    "CPU: $((Get-CimInstance Win32_Processor | Select-Object -First 1).Name) ($([Environment]::ProcessorCount) threads)"
    "GPU: $((Get-CimInstance Win32_VideoController).Name -join ', ')"
    "RAM: {0:N0} GB" -f ((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
    "Kit: v4, timer SHA-256 $((Get-FileHash $exe).Hash)"
) | Out-File (Join-Path $logs "pc-info.txt") -Encoding utf8
Add-Result "T0.0" "Windows 11 version 25H2 or newer" ([int]$cv.CurrentBuild -ge 26200) "$($os.Caption) $($cv.DisplayVersion) build $($cv.CurrentBuild)"

# --- T0.1 self-check of the timer program ---
$st = (Start-Process $exe -ArgumentList "--selftest" -Wait -PassThru).ExitCode
Add-Result "T0.1a" "Timer program self-check" ($st -eq 0) "exit code $st"

# --- Find installed games (Steam, Epic, Riot) ---
$gameDirs = [System.Collections.Generic.List[string]]::new()
$steam = (Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Valve\Steam" -ErrorAction SilentlyContinue).InstallPath
if (-not $steam) { $steam = (Get-ItemProperty "HKCU:\Software\Valve\Steam" -ErrorAction SilentlyContinue).SteamPath -replace "/", "\" }
if ($steam -and (Test-Path "$steam\steamapps\libraryfolders.vdf")) {
    foreach ($m in [regex]::Matches((Get-Content "$steam\steamapps\libraryfolders.vdf" -Raw), '"path"\s+"([^"]+)"')) {
        $gameDirs.Add(($m.Groups[1].Value -replace '\\\\', '\') + "\steamapps\common")
    }
}
foreach ($f in Get-ChildItem "$env:ProgramData\Epic\EpicGamesLauncher\Data\Manifests\*.item" -ErrorAction SilentlyContinue) {
    try { $gameDirs.Add((Get-Content $f.FullName -Raw | ConvertFrom-Json).InstallLocation) } catch { }
}
foreach ($d in "$env:SystemDrive\Riot Games", "D:\Riot Games") { if (Test-Path $d) { $gameDirs.Add($d) } }
$gameDirs = @($gameDirs | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)
$gameExes = @($gameDirs | ForEach-Object { Get-ChildItem $_ -Recurse -Filter *.exe -File -ErrorAction SilentlyContinue })
$gameDirs | Out-File (Join-Path $logs "game-folders.txt") -Encoding utf8
$gameExes.FullName | Out-File (Join-Path $logs "game-programs.txt") -Encoding utf8
$gameExes | ForEach-Object { $_.BaseName } | Select-Object -Unique | Out-File (Join-Path $root "games.txt") -Encoding utf8
Add-Result "T0.2a" "Installed games found" ($gameExes.Count -gt 0) "$($gameExes.Count) game programs in $($gameDirs.Count) folders"

# --- Back up AppLocker + its service setting so FINISH-TEST can restore them exactly ---
$backup = Join-Path $logs "applocker-backup.xml"
if (-not (Test-Path $backup)) { Get-AppLockerPolicy -Local -Xml | Out-File $backup -Encoding utf8 }
$svcFile = Join-Path $logs "appidsvc-starttype.txt"
if (-not (Test-Path $svcFile)) { (Get-Service AppIDSvc).StartType.ToString() | Out-File $svcFile -Encoding utf8 }

function Write-Policy($file, $denySid, $denyPaths, $mode) {
    $col = foreach ($type in "Exe", "Msi", "Script") {
        $r = "<FilePathRule Id=`"$([guid]::NewGuid())`" Name=`"Allow all`" Description=`"`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`"><Conditions><FilePathCondition Path=`"*`" /></Conditions></FilePathRule>"
        foreach ($d in $denyPaths) {
            $r += "<FilePathRule Id=`"$([guid]::NewGuid())`" Name=`"Shinzx block`" Description=`"`" UserOrGroupSid=`"$denySid`" Action=`"Deny`"><Conditions><FilePathCondition Path=`"$([Security.SecurityElement]::Escape($d))`" /></Conditions></FilePathRule>"
        }
        "<RuleCollection Type=`"$type`" EnforcementMode=`"$mode`">$r</RuleCollection>"
    }
    "<AppLockerPolicy Version=`"1`">$($col -join '')</AppLockerPolicy>" | Out-File $file -Encoding utf8
}
function Risky($prof) { "$prof\Downloads\*", "$prof\Desktop\*", "$prof\Documents\*", "$prof\OneDrive\*", "$prof\AppData\Local\Temp\*" }
$shared = "$env:SystemDrive\Users\Public\*", "$env:WINDIR\Temp\*", "%REMOVABLE%\*", "%HOT%\*"

sc.exe config AppIDSvc start= auto | Out-Null
Start-Service AppIDSvc
Add-Result "T0.2g" "Windows app-control service running" ((Get-Service AppIDSvc).Status -eq "Running") "sc.exe exit $LASTEXITCODE"
# Program (exe) rules only reach Windows' blocking driver when the built-in PolicyConverter task runs, normally at
# restart. Run it now so rules apply straight away (measured on Windows 11: without it nothing is blocked or audited).
function Apply-Policy($file) {
    Set-AppLockerPolicy -XmlPolicy $file; gpupdate /target:computer /force | Out-Null
    $t = Get-ScheduledTask -TaskPath "\Microsoft\Windows\AppID\" -TaskName "PolicyConverter"
    $off = $t.State -eq "Disabled"; if ($off) { $t | Enable-ScheduledTask | Out-Null } # disabled on Windows Server only
    $t | Start-ScheduledTask; Start-Sleep -Seconds 15
    if ($off) { $t | Disable-ScheduledTask | Out-Null }
}

# --- T0.2 enforced check with a temporary standard user (removed again a minute later) ---
$user = "ShinzxTest"
$usersGroup = (Get-LocalGroup -SID "S-1-5-32-545").Name
function Remove-TestUser { # user and its profile; also clears one left by an earlier run that lost power
    $u = Get-LocalUser $user -ErrorAction SilentlyContinue
    if ($u) { Get-CimInstance Win32_UserProfile | Where-Object SID -eq $u.SID.Value | Remove-CimInstance -ErrorAction SilentlyContinue; Remove-LocalUser $user }
}
Remove-TestUser
$rnd = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($rnd)
$pw = New-Object Security.SecureString   # crypto-random; suffix meets Windows complexity rules
foreach ($c in ([Convert]::ToBase64String($rnd) + "Aa9!").ToCharArray()) { $pw.AppendChar($c) }
New-LocalUser $user -Password $pw -PasswordNeverExpires -AccountNeverExpires | Out-Null
Add-LocalGroupMember -Group $usersGroup -Member $user
$cred = [pscredential]::new($user, $pw)
$sid = (Get-LocalUser $user).SID.Value
$sys32 = "$env:WINDIR\System32"
try {
    Start-Process "$sys32\cmd.exe" -ArgumentList "/c exit" -Credential $cred -LoadUserProfile -WorkingDirectory $sys32 -Wait -WindowStyle Hidden
    $prof = (Get-CimInstance Win32_UserProfile | Where-Object SID -eq $sid).LocalPath
    if (-not $prof) { $prof = "$env:SystemDrive\Users\$user" } # rules still cover this path; folders are created below
    $testDirs = @(Risky $prof | ForEach-Object { $_.TrimEnd('*').TrimEnd('\') }) + "$env:SystemDrive\Users\Public"
    $usb = Get-Volume | Where-Object { $_.DriveType -eq "Removable" -and $_.DriveLetter } | Select-Object -First 1
    if ($usb) { $testDirs += "$($usb.DriveLetter):\" }

    $enf = Join-Path $logs "levelB-enforce-test.xml"
    Write-Policy $enf $sid ((Risky $prof) + $shared) "Enabled"
    Apply-Policy $enf

    foreach ($d in $testDirs) {
        New-Item -ItemType Directory $d -Force | Out-Null
        $copy = Join-Path $d "shinzx-blocktest.exe"
        Copy-Item "$sys32\whoami.exe" $copy -Force
        $why = try { Start-Process $copy -Credential $cred -WorkingDirectory $sys32 -WindowStyle Hidden -Wait; "it ran" } catch { $_.Exception.Message }
        $blocked = $why -match "blocked|policy"
        Remove-Item $copy -Force -ErrorAction SilentlyContinue
        Add-Result "T0.2b" "Program blocked in $($d -replace [regex]::Escape($prof), '<customer folder>')" $blocked $why
    }
    if (-not $usb) { Add-Result "T0.2b" "Program blocked on a USB drive" $null "no USB drive was plugged in" }

    $ctl = (Start-Process $exe -ArgumentList "--selftest" -Credential $cred -WorkingDirectory $root -Wait -PassThru).ExitCode
    Add-Result "T0.2c" "Normal programs still run for customers" ($ctl -eq 0) "test program from C:\ShinzxTest exit code $ctl"

    $probe = Join-Path $root "probe.txt"
    Start-Process "$sys32\cmd.exe" -ArgumentList "/c echo x> `"$probe`"" -Credential $cred -WorkingDirectory $sys32 -WindowStyle Hidden -Wait
    $wrote = Test-Path $probe; Remove-Item $probe -Force -ErrorAction SilentlyContinue
    Add-Result "T0.2h" "Customers cannot change the test files" (-not $wrote) $(if ($wrote) { "a customer account could write in the kit folder" } else { "write attempt refused" })

    if ($gameExes.Count) {
        $dec = @(Test-AppLockerPolicy -XmlPolicy $enf -Path $gameExes.FullName -User $user)
        $denied = @($dec | Where-Object { $_.PolicyDecision -notlike "Allowed*" })
        $denied | ForEach-Object { $_.FilePath } | Out-File (Join-Path $logs "games-blocked-by-rules.txt") -Encoding utf8
        Add-Result "T0.2d" "All game programs allowed by the rules" ($denied.Count -eq 0) "$($dec.Count - $denied.Count) of $($dec.Count) allowed"
    } else { Add-Result "T0.2d" "All game programs allowed by the rules" $null "no games found" }
}
finally { Remove-TestUser } # always, even if a check above failed

# --- Monitoring for normal use: same rules in AUDIT mode for every normal account (nothing is blocked,
#     Windows only notes what WOULD be blocked, so FINISH-TEST can list any game or launcher affected) ---
$profiles = Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and $_.LocalPath -like "*\Users\*" }
$audit = Join-Path $logs "levelB-audit.xml"
Write-Policy $audit "S-1-5-32-545" (@($profiles | ForEach-Object { Risky $_.LocalPath }) + $shared) "AuditOnly"
Apply-Policy $audit
Add-Result "T0.2e" "Day-long check switched on (audit only, nothing blocked)" $true "$(@($profiles).Count) user profiles watched"

# --- Level A watch-only: Windows' own App Control with Microsoft's "Windows only" example policy in AUDIT mode.
#     Nothing is blocked; every program Windows would not trust is logged (event 3076), so FINISH-TEST can list
#     them by maker for the owner to approve. ---
try {
    $ci = Join-Path $logs "levelA-audit.xml"
    Copy-Item "$env:WINDIR\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml" $ci -Force
    Set-CIPolicyIdInfo -FilePath $ci -PolicyName "Shinzx test (watch only)" -ResetPolicyID | Out-Null
    Set-RuleOption -FilePath $ci -Option 3   # 3 = audit mode; set again so this can never block anything
    $ciId = ([xml](Get-Content $ci -Raw)).SiPolicy.PolicyID
    ConvertFrom-CIPolicy -XmlFilePath $ci -BinaryFilePath (Join-Path $logs "levelA.cip") | Out-Null
    $ciId | Out-File (Join-Path $logs "levelA-policy-id.txt") -Append -Encoding utf8   # FINISH-TEST removes every id listed
    CiTool.exe --update-policy (Join-Path $logs "levelA.cip") -json | Out-Null
    if ($LASTEXITCODE) { throw "CiTool exit $LASTEXITCODE" }
    Add-Result "T0.4a" "Level A watch-only check switched on (nothing blocked)" ([bool]((CiTool.exe --list-policies) -match [regex]::Escape($ciId.Trim('{}')))) "policy $ciId"
} catch { Add-Result "T0.4a" "Level A watch-only check switched on (nothing blocked)" $false "$($_.Exception.Message) (at: $($_.InvocationInfo.Line.Trim()))" }

# --- Security scan: Microsoft Defender quick scan now; its unwanted-program check (PUA) set to log-only for the test ---
try {
    $puaFile = Join-Path $logs "pua-before.txt"
    if (-not (Test-Path $puaFile)) { "$((Get-MpPreference).PUAProtection)" | Out-File $puaFile -Encoding utf8 }
    Set-MpPreference -PUAProtection AuditMode
    Start-MpScan -ScanType QuickScan
    $mp = Get-MpComputerStatus
    Add-Result "T0.5a" "Security scan ran (Microsoft Defender)" $true "real-time protection on: $($mp.RealTimeProtectionEnabled); virus list from $($mp.AntivirusSignatureLastUpdated)"
} catch { Add-Result "T0.5a" "Security scan ran (Microsoft Defender)" $null "Defender is not working on this PC: $($_.Exception.Message)" }

# --- Scheduled tasks: timer for every user at sign-in, hidden measurer as SYSTEM at start-up ---
$set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries
$timerArgs = "--log `"$userLogs`" --games `"$root\games.txt`" --expires $expires"
Register-ScheduledTask -TaskName "ShinzxTestTimer" -Force -Action (New-ScheduledTaskAction -Execute $exe -Argument $timerArgs) `
    -Trigger (New-ScheduledTaskTrigger -AtLogOn) -Principal (New-ScheduledTaskPrincipal -GroupId $usersGroup -RunLevel Limited) -Settings $set | Out-Null
$mArgs = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$root\measure.ps1`" -Out `"$logs\measure.csv`" -Expires $expires"
Register-ScheduledTask -TaskName "ShinzxTestMeasure" -Force -Action (New-ScheduledTaskAction -Execute "powershell.exe" -Argument $mArgs) `
    -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal (New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest) -Settings $set | Out-Null
Add-Result "T0.1b" "Day-long timer monitoring installed" $true "starts after the restart"

$results | Export-Csv (Join-Path $logs "start-results.csv") -NoTypeInformation -Encoding utf8
Stop-Transcript | Out-Null
$fails = @($results | Where-Object result -eq "FAIL").Count
$msg = "Setup is done. $fails problem(s) found. They will be in the report.`n`nNext:`n1. The PC restarts now.`n2. Use it normally for one or two days. Customers can play as usual.`n   Open every game once and let it update.`n3. Then double-click FINISH-TEST.`n`nRestart now?"
if ($Ci) { Write-Host "CI run: no restart. $fails FAIL(s)."; exit 0 }
if ((Say $msg "YesNo") -eq "Yes") { Restart-Computer -Force } else { Say "OK. Restart the PC when it is free - the day-long test starts after that." | Out-Null }
