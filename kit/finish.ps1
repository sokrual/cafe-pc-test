# FINISH-TEST: stops monitoring, puts the PC back exactly as before, asks one question,
# and writes Shinzx-Test-Report-<date>.zip in this folder to send back.
# -ReportOnly rebuilds the report from an existing logs folder without touching Windows (used for testing).
# -Ci: unattended run on a test machine (no pop-ups; pass -VoiceHeard Yes/No).
param([switch]$ReportOnly, [string]$LogsDir, [string]$VoiceHeard, [switch]$Ci)
$ErrorActionPreference = "Stop"
trap {
    if (-not $ReportOnly -and -not $Ci) {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("Something went wrong:`n$_`n`nPlease take a photo of this window and send it on Discord to the person who gave you this test. Then double-click FINISH-TEST once more.", "Shinzx test") | Out-Null
    }
    break
}
$root = $PSScriptRoot
$logs = if ($LogsDir) { $LogsDir } else { Join-Path $root "logs" }
$inv = [Globalization.CultureInfo]::InvariantCulture
if (-not (Test-Path (Join-Path $logs "test-window.json"))) { Write-Host "No test found here. Run START-TEST first." -ForegroundColor Red; exit 1 }
$window = Get-Content (Join-Path $logs "test-window.json") -Raw | ConvertFrom-Json
$started = if ($window.start -is [datetime]) { $window.start } else { [datetime]::Parse($window.start, $inv) } # PowerShell 7 already converts it
$results = [System.Collections.Generic.List[object]]::new()
if (Test-Path (Join-Path $logs "start-results.csv")) { Import-Csv (Join-Path $logs "start-results.csv") | ForEach-Object { $results.Add($_) } }
function Add-Result($id, $test, $ok, $detail) {
    $res = if ($null -eq $ok) { "NOT TESTED" } elseif ($ok) { "PASS" } else { "FAIL" }
    $results.Add([pscustomobject]@{ id = $id; test = $test; result = $res; detail = "$detail" })
}
function Maker($sig) { # the company (O=) on the signing certificate
    if (-not $sig) { return "(file is gone)" }
    if (-not $sig.SignerCertificate) { return "(not signed)" }
    if ($sig.SignerCertificate.Subject -match '(?:^|, )O="?([^",]+)') { return $Matches[1] }
    $sig.SignerCertificate.GetNameInfo("SimpleName", $false)
}

if (-not $ReportOnly) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw "Run FINISH-TEST.bat (it asks for admin)." }
    Add-Type -AssemblyName System.Windows.Forms
    Start-Transcript (Join-Path $logs "finish-transcript.txt") -Append | Out-Null

    try {
        # 1. stop monitoring
        New-Item (Join-Path $logs "stop.flag") -ItemType File -Force | Out-Null
        foreach ($t in "ShinzxTestTimer", "ShinzxTestMeasure") {
            Stop-ScheduledTask $t -ErrorAction SilentlyContinue
            Unregister-ScheduledTask $t -Confirm:$false -ErrorAction SilentlyContinue
        }
        Get-Process ShinzxTimerTest -ErrorAction SilentlyContinue | Stop-Process -Force
        # temporary user left behind if the PC lost power during START-TEST
        $u = Get-LocalUser "ShinzxTest" -ErrorAction SilentlyContinue
        if ($u) { Get-CimInstance Win32_UserProfile | Where-Object SID -eq $u.SID.Value | Remove-CimInstance; Remove-LocalUser "ShinzxTest" }

        # 2. what WOULD have been blocked during normal use (audit events 8003 = exe/dll, 8006 = msi/script)
        $ev = @(foreach ($log in "Microsoft-Windows-AppLocker/EXE and DLL", "Microsoft-Windows-AppLocker/MSI and Script") {
            Get-WinEvent -FilterHashtable @{ LogName = $log; Id = 8003, 8006; StartTime = $started } -ErrorAction SilentlyContinue
        })
        $wbRows = foreach ($x in $ev) { # foreach, not a pipeline: an empty list must not run the body once with $null
            $d = ([xml]$x.ToXml()).Event.UserData.RuleAndFileData
            $who = try { ([Security.Principal.SecurityIdentifier]$d.TargetUser).Translate([Security.Principal.NTAccount]).Value } catch { "$($d.TargetUser)" }
            [pscustomobject]@{ time = $x.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"); user = $who; path = "$($d.FullFilePath)" }
        }
        "time,user,path" | Out-File (Join-Path $logs "would-be-blocked.csv") -Encoding utf8
        @($wbRows) | Where-Object { $_ } | Export-Csv (Join-Path $logs "would-be-blocked.csv") -NoTypeInformation -Encoding utf8 -Append

        # Level A: every file Windows would not have trusted (event 3076), with who signed it. Events name the disk
        # as \Device\HarddiskVolumeN, so map those back to drive letters first.
        Add-Type -Namespace Shinzx -Name Dos -MemberDefinition '[DllImport("kernel32.dll", CharSet = CharSet.Unicode)] public static extern uint QueryDosDevice(string name, System.Text.StringBuilder target, int max);'
        $dev = @{}
        foreach ($d in [IO.DriveInfo]::GetDrives()) { $sb = New-Object Text.StringBuilder 300; if ([Shinzx.Dos]::QueryDosDevice($d.Name.TrimEnd('\'), $sb, 300)) { $dev[$sb.ToString()] = $d.Name.TrimEnd('\') } }
        $files = foreach ($x in @(Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-CodeIntegrity/Operational"; Id = 3076; StartTime = $started } -ErrorAction SilentlyContinue)) {
            $f = "$((([xml]$x.ToXml()).Event.EventData.Data | Where-Object Name -eq "File Name").'#text')"
            foreach ($k in $dev.Keys) { if ($f.StartsWith("$k\", "OrdinalIgnoreCase")) { $f = $dev[$k] + $f.Substring($k.Length) } }
            $f
        }
        $aRows = foreach ($f in @($files | Where-Object { $_ } | Sort-Object -Unique)) {
            $s = if (Test-Path -LiteralPath $f) { Get-AuthenticodeSignature -LiteralPath $f }
            $maker = Maker $s
            [pscustomobject]@{ maker = $maker; path = $f }
        }
        "maker,path" | Out-File (Join-Path $logs "levelA-would-block.csv") -Encoding utf8
        @($aRows) | Where-Object { $_ } | Export-Csv (Join-Path $logs "levelA-would-block.csv") -NoTypeInformation -Encoding utf8 -Append

        # what is on this PC, for the owner to review: programs, non-Microsoft services and drivers, start-up items
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*", "Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
            Where-Object DisplayName | Select-Object DisplayName, Publisher, DisplayVersion, InstallDate, InstallLocation | Sort-Object DisplayName -Unique |
            Export-Csv (Join-Path $logs "installed-programs.csv") -NoTypeInformation -Encoding utf8
        $svc = foreach ($x in @(Get-CimInstance Win32_Service) + @(Get-CimInstance Win32_SystemDriver)) {
            $p = "$($x.PathName)" -replace '^\\\?\?\\', '' -replace '^\\SystemRoot\\', "$env:WINDIR\" -replace '^(?i)System32\\', "$env:WINDIR\System32\"
            $p = if ($p -match '^"([^"]+)"') { $Matches[1] } elseif ($p -match '^(.+?\.(exe|sys))(\s|$)') { $Matches[1] } else { $p }
            $s = if ($p -and (Test-Path -LiteralPath $p)) { Get-AuthenticodeSignature -LiteralPath $p }
            $maker = Maker $s
            if ($maker -ne "Microsoft Corporation") { [pscustomobject]@{ kind = $x.CimClass.CimClassName -replace 'Win32_System|Win32_'; name = $x.Name; state = $x.State; maker = $maker; path = $p } }
        }
        @($svc) | Where-Object { $_ } | Export-Csv (Join-Path $logs "services-and-drivers.csv") -NoTypeInformation -Encoding utf8
        Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | Export-Csv (Join-Path $logs "startup.csv") -NoTypeInformation -Encoding utf8

        # everything Microsoft Defender has found on this PC (its history, not only during the test), and its exceptions
        try {
            $names = @{}; foreach ($t in @(Get-MpThreat)) { $names[$t.ThreatID] = $t.ThreatName }
            @(Get-MpThreatDetection) | ForEach-Object { [pscustomobject]@{ time = $_.InitialDetectionTime; threat = $names[$_.ThreatID]; files = ($_.Resources -join ' ; '); program = $_.ProcessName } } |
                Export-Csv (Join-Path $logs "security-finds.csv") -NoTypeInformation -Encoding utf8
            $p = Get-MpPreference
            @($p.ExclusionPath) + @($p.ExclusionProcess) + @($p.ExclusionExtension) | Where-Object { $_ } | Out-File (Join-Path $logs "defender-exceptions.txt") -Encoding utf8
            (Get-MpComputerStatus).RealTimeProtectionEnabled | Out-File (Join-Path $logs "defender-realtime.txt") -Encoding utf8
        } catch { "Defender not working: $_" | Out-File (Join-Path $logs "defender-error.txt") -Encoding utf8 }
    }
    finally {
        # 3. ALWAYS restore AppLocker and its service exactly as they were before START-TEST, even if step 1-2 failed.
        #    First wipe our rules (an empty backup alone may not clear them), then put the old policy back.
        #    Each step has its own try so one failure cannot skip the others; T0.9a below checks the result.
        try {
            $clear = Join-Path $logs "applocker-clear.xml"
            $cols = foreach ($t in "Exe", "Msi", "Script", "Dll", "Appx") { '<RuleCollection Type="' + $t + '" EnforcementMode="NotConfigured" />' }
            ('<AppLockerPolicy Version="1">' + ($cols -join '') + '</AppLockerPolicy>') | Out-File $clear -Encoding utf8
            Set-AppLockerPolicy -XmlPolicy $clear
        } catch { Write-Host "Clearing rules failed: $_" -ForegroundColor Red }
        try {
            $bk = Join-Path $logs "applocker-backup.xml"
            if (([xml](Get-Content $bk -Raw)).SelectNodes("//RuleCollection").Count) { Set-AppLockerPolicy -XmlPolicy $bk }
        } catch { Write-Host "Restoring old rules failed: $_" -ForegroundColor Red }
        gpupdate /target:computer /force | Out-Null
        try { # push the restored rules to the blocking driver now, not at the next restart (same task START uses)
            $t = Get-ScheduledTask -TaskPath "\Microsoft\Windows\AppID\" -TaskName "PolicyConverter"
            $off = $t.State -eq "Disabled"; if ($off) { $t | Enable-ScheduledTask | Out-Null }
            $t | Start-ScheduledTask; Start-Sleep -Seconds 15
            if ($off) { $t | Disable-ScheduledTask | Out-Null }
        } catch { Write-Host "Applying the restored rules failed (they apply at the next restart): $_" -ForegroundColor Red }
        try {
            $map = @{ Automatic = "auto"; Manual = "demand"; Disabled = "disabled" }
            $old = (Get-Content (Join-Path $logs "appidsvc-starttype.txt") -Raw).Trim()
            if ($map[$old]) { sc.exe config AppIDSvc start= $($map[$old]) | Out-Null }
        } catch { Write-Host "Restoring the service setting failed: $_" -ForegroundColor Red }
        try { # remove the Level A watch-only policy (every id START-TEST added)
            foreach ($id in @(Get-Content (Join-Path $logs "levelA-policy-id.txt") -ErrorAction Stop | Where-Object { $_.Trim() })) { CiTool.exe --remove-policy $id.Trim() -json | Out-Null }
        } catch { Write-Host "Removing the Level A check failed: $_" -ForegroundColor Red }
        try { wevtutil.exe sl "Microsoft-Windows-CodeIntegrity/Operational" /ms:$((Get-Content (Join-Path $logs "levelA-logsize.txt") -Raw -ErrorAction Stop).Trim()) }
        catch { Write-Host "Putting the log size back failed: $_" -ForegroundColor Red }
        try {
            $old = (Get-Content (Join-Path $logs "pua-before.txt") -Raw -ErrorAction Stop).Trim()
            Set-MpPreference -PUAProtection (@{ "0" = "Disabled"; "1" = "Enabled"; "2" = "AuditMode" }[$old])
        } catch { Write-Host "Restoring the Defender setting failed: $_" -ForegroundColor Red }
    }
    # check the restore really worked
    $before = @(([xml](Get-Content (Join-Path $logs "applocker-backup.xml") -Raw)).SelectNodes("//*[@Action]")).Count
    $now = @(([xml](Get-AppLockerPolicy -Local -Xml)).SelectNodes("//*[@Action]")).Count
    $left = @(Get-ScheduledTask -TaskName "ShinzxTest*" -ErrorAction SilentlyContinue).Count + @(Get-LocalUser "ShinzxTest" -ErrorAction SilentlyContinue).Count
    Add-Result "T0.9a" "PC app rules restored to how they were" ($now -eq $before) "$now rules now, $before before the test"
    Add-Result "T0.9b" "Test tasks and test user removed" ($left -eq 0) "$left left"
    $ids = @(Get-Content (Join-Path $logs "levelA-policy-id.txt") -ErrorAction SilentlyContinue | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim().Trim('{}') })
    $still = @($ids | Where-Object { (CiTool.exe --list-policies) -match [regex]::Escape($_) })
    Add-Result "T0.9c" "Level A watch-only check removed" ($still.Count -eq 0) "$($still.Count) of $($ids.Count) still on"
    if (Test-Path (Join-Path $logs "levelA-logsize.txt")) {
        $want = [long](Get-Content (Join-Path $logs "levelA-logsize.txt") -Raw).Trim(); $size = (Get-WinEvent -ListLog "Microsoft-Windows-CodeIntegrity/Operational").MaximumSizeInBytes
        Add-Result "T0.9e" "Windows log size put back" ($size -eq $want) "now $size bytes, before $want"
    }
    if (Test-Path (Join-Path $logs "pua-before.txt")) {
        $want = (Get-Content (Join-Path $logs "pua-before.txt") -Raw).Trim(); $now = "$((Get-MpPreference).PUAProtection)"
        Add-Result "T0.9d" "Defender setting put back" ($now -eq $want) "now $now, before $want"
    }
}

# ---------------- build the report ----------------

# measurements (CPU/memory/GPU every 5 s)
$rows = @()
if (Test-Path (Join-Path $logs "measure.csv")) {
    $rows = @(Import-Csv (Join-Path $logs "measure.csv") | ForEach-Object {
        try { [pscustomobject]@{ t = [datetime]::ParseExact($_.time, "yyyy-MM-dd HH:mm:ss", $inv); pid = $_.pid
            cpu = [double]::Parse($_.cpu_percent, $inv); priv = [double]::Parse($_.private_mb, $inv); gpu = [double]::Parse("0$($_.gpu_percent)", $inv) } }
        catch { } }) # a damaged row must not stop the report (blank GPU = 0)
}
# timer logs: when was the timer hidden (= a game was in front)?
$events = [System.Collections.Generic.List[object]]::new()
$hidden = [System.Collections.Generic.List[object]]::new(); $openFrom = @()
foreach ($f in Get-ChildItem $logs -Filter "timer-*.log" -Recurse) { # one file per Windows user, read separately
    $from = $null
    foreach ($l in Get-Content $f.FullName | Where-Object { $_ -match "^\d{4}-" }) {
        $t, $m = $l -split "`t", 2
        $ts = [datetime]::MinValue # customers can write these files: skip bad lines instead of crashing the report
        if (-not [datetime]::TryParseExact($t, "yyyy-MM-dd HH:mm:ss", $inv, 0, [ref]$ts)) { continue }
        $e = [pscustomobject]@{ t = $ts; m = $m }
        $events.Add($e)
        if ($m -eq "HIDE") { $from = $e.t }
        elseif ($from -and $m -match "^(SHOW|STOP|START)") { $hidden.Add(@($from, $e.t)); $from = $null }
    }
    if ($from) { $openFrom += $from }
}
$lastSeen = @(@($events.t) + @($rows.t) | Sort-Object)[-1]
foreach ($o in $openFrom) { $hidden.Add(@($o, $lastSeen)) } # timer was killed while hidden: count until the last sign of life
$gameMin = 0; foreach ($h in $hidden) { $gameMin += ($h[1] - $h[0]).TotalMinutes }
function InGame($t) { foreach ($h in $hidden) { if ($t -ge $h[0] -and $t -lt $h[1]) { return $true } }; $false }

$hides  = @($events | Where-Object m -eq "HIDE").Count
$missed = @($events | Where-Object m -like "MISSED *" | ForEach-Object { $_.m.Substring(7) } | Select-Object -Unique)
$steals = @($events | Where-Object m -eq "FOCUS_STOLEN").Count
Add-Result "T0.1c" "Timer hid itself during games" ($(if ($hides) { $true } else { $null })) ("{0} times; {1:N0} minutes of play seen" -f $hides, $gameMin)
Add-Result "T0.1d" "Every game was recognised" ($(if ($events.Count) { $missed.Count -eq 0 } else { $null })) $(if ($missed) { "not recognised: $($missed -join ', ')" } else { "none missed" })
Add-Result "T0.1e" "Timer never took focus from a game" ($(if ($events.Count) { $steals -eq 0 } else { $null })) "$steals focus steals"

# judge the in-game samples (what matters); fall back to all samples if no game was played
$game = @($rows | Where-Object { InGame $_.t })
$use = if ($game.Count) { $game } else { $rows }
$scope = if ($game.Count) { "$($game.Count) samples during games" } else { "$($rows.Count) samples (no game time seen)" }
if ($use.Count) {
    $avgCpu = ($use | Measure-Object cpu -Average).Average
    $maxPriv = ($use | Measure-Object priv -Maximum).Maximum
    $avgGpu = ($use | Measure-Object gpu -Average).Average
    $longest = @($rows | Group-Object pid | Sort-Object Count -Descending | Select-Object -First 1)[0].Group
    $warm = @($longest | Where-Object { $_.t -ge $longest[0].t.AddHours(1) }) # memory always rises at start-up; judge after 1 h
    Add-Result "T0.1f" "Timer CPU under 1%" ($avgCpu -lt 1) ("average {0:N2}% ({1})" -f $avgCpu, $scope)
    Add-Result "T0.1g" "Timer memory under 50 MB" ($maxPriv -lt 50) ("peak {0:N1} MB" -f $maxPriv)
    Add-Result "T0.1h" "Timer uses no GPU" ($avgGpu -lt 0.5) ("average {0:N2}%" -f $avgGpu)
    if ($warm.Count -ge 2 -and ($warm[-1].t - $warm[0].t).TotalHours -ge 1) {
        $growth = ($warm[-1].priv / $warm[0].priv - 1) * 100
        Add-Result "T0.1i" "Timer memory does not keep growing" ($growth -lt 10) ("{0:N1} -> {1:N1} MB over {2:N1} hours (after the first hour)" -f $warm[0].priv, $warm[-1].priv, ($warm[-1].t - $warm[0].t).TotalHours)
    } else { Add-Result "T0.1i" "Timer memory does not keep growing" $null "timer ran under 2 hours in one go" }
} else { Add-Result "T0.1f" "Timer measurements" $null "no measurements found - was the PC restarted after START-TEST?" }

# voice
$vDone = @($events | Where-Object m -like "VOICE_DONE*")
if ($vDone.Count) {
    Add-Result "T0.3a" "Voice message played during games" (-not ($vDone.m -match "error=(?!none)")) "$($vDone.Count) of 3 played"
    Add-Result "T0.3b" "Game kept focus while the voice played" (-not ($vDone.m -match "same_window=False")) "checked $($vDone.Count) times"
    if (-not $ReportOnly -and -not $VoiceHeard) {
        $VoiceHeard = [System.Windows.Forms.MessageBox]::Show("One question:`n`nDuring the test, while playing a game with a headset, did you (or a customer) hear a short voice say 'Shinzx Gaming Hub test message'?", "Shinzx test", "YesNo")
    }
    Add-Result "T0.3c" "Voice was heard clearly in the headset" ($VoiceHeard -eq "Yes") "owner answered: $VoiceHeard"
} else { Add-Result "T0.3a" "Voice message played during games" $null "no game was played for 2+ minutes in a row" }

# Level B audit: did anything game-related try to run from a blocked folder?
$wb = @(); $wbFile = Join-Path $logs "would-be-blocked.csv"
if (Test-Path $wbFile) { $wb = @(Import-Csv $wbFile) } # Import-Csv stops on a missing file even with -ErrorAction
$gameWords = "steam|epic|riot|vanguard|valorant|battle\.net|blizzard|ubisoft|uplay|\bea\b|\borigin\b|rockstar|garena|faceit|easyanticheat|battleye|discord|nvidia|amd"
$gameHits = @($wb | Where-Object { $_.path -match $gameWords } | Select-Object -ExpandProperty path -Unique)
$otherHits = @($wb | Where-Object { $_.path -notmatch $gameWords } | Select-Object -ExpandProperty path -Unique)
Add-Result "T0.2f" "No game, launcher or anti-cheat would be blocked by Level B" ($gameHits.Count -eq 0) "$($gameHits.Count) game-related, $($otherHits.Count) other programs would be blocked"

# Level A: the list the owner approves from, grouped by maker; games, launchers, anti-cheats and mouse/keyboard apps marked
$la = @(); $laFile = Join-Path $logs "levelA-would-block.csv"
if (Test-Path $laFile) { $la = @(Import-Csv $laFile) }
$hwWords = "logitech|razer|corsair|steelseries|hyperx|asus|msi|redragon|cosmic byte|ant esports|zebronics|realtek|intel|nvidia|amd|advanced micro"
$makers = @($la | Group-Object maker | Sort-Object Count -Descending | ForEach-Object {
    $tag = if ("$($_.Name) $($_.Group[0].path)" -match $gameWords) { "game" } elseif ($_.Name -match $hwWords) { "hardware" } else { "check" }
    [pscustomobject]@{ maker = $_.Name; files = $_.Count; tag = $tag; example = $_.Group[0].path } })
Add-Result "T0.4b" "Level A list of programs to approve was made" (Test-Path $laFile) "$($la.Count) files from $($makers.Count) makers would need approval"

# security: anything Defender found, and any exceptions someone added to it
$finds = @(); if (Test-Path (Join-Path $logs "security-finds.csv")) { $finds = @(Import-Csv (Join-Path $logs "security-finds.csv")) }
$except = @(Get-Content (Join-Path $logs "defender-exceptions.txt") -ErrorAction SilentlyContinue | Where-Object { $_ })
if (Test-Path (Join-Path $logs "defender-error.txt")) { Add-Result "T0.5b" "No harmful or unwanted programs found" $null (Get-Content (Join-Path $logs "defender-error.txt") -Raw) }
else {
    Add-Result "T0.5b" "No harmful or unwanted programs found" ($finds.Count -eq 0) $(if ($finds) { ($finds.threat | Select-Object -Unique) -join ", " } else { "none found" })
    Add-Result "T0.5c" "No exceptions added to Microsoft Defender" ($except.Count -eq 0) $(if ($except) { "$($except.Count) exceptions - check each one" } else { "none" })
}

# write report.txt + zip
$pass = @($results | Where-Object result -eq "PASS").Count
$fail = @($results | Where-Object result -eq "FAIL").Count
$nt = @($results | Where-Object result -eq "NOT TESTED").Count
$out = @("SHINZX PHASE 0 TEST REPORT", ("Test ran from {0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm}" -f $started, (Get-Date)), "")
$out += Get-Content (Join-Path $logs "pc-info.txt") -ErrorAction SilentlyContinue
$out += "", "SUMMARY: $pass passed, $fail failed, $nt not tested", ""
$out += $results | ForEach-Object { "[{0}] {1} {2} - {3}" -f $_.result, $_.id, $_.test, $_.detail }
if ($gameHits) { $out += "", "GAME-RELATED PROGRAMS LEVEL B WOULD BLOCK (must fix before Level B goes live):"; $out += $gameHits | ForEach-Object { "  $_" } }
if ($otherHits) { $out += "", "OTHER PROGRAMS LEVEL B WOULD BLOCK (expected - downloads, USB, temp):"; $out += $otherHits | Select-Object -First 50 | ForEach-Object { "  $_" } }
if ($finds) { $out += "", "HARMFUL OR UNWANTED PROGRAMS DEFENDER FOUND (this PC may need a clean reinstall):"; $out += $finds | ForEach-Object { "  $($_.time)  $($_.threat)  $($_.files)" } }
if ($except) { $out += "", "EXCEPTIONS IN MICROSOFT DEFENDER (it does not scan these - remove any you did not add):"; $out += $except | ForEach-Object { "  $_" } }
if ($makers) {
    $out += "", "PROGRAMS LEVEL A WOULD BLOCK, BY MAKER (approve the ones you know; full list in levelA-would-block.csv):"
    $out += "  game = game, launcher or anti-cheat   hardware = mouse, keyboard, sound or graphics   check = look at it"
    $out += $makers | Select-Object -First 60 | ForEach-Object { "  [{0}] {1} ({2} files) e.g. {3}" -f $_.tag, $_.maker, $_.files, $_.example }
}
$out | Out-File (Join-Path $logs "REPORT.txt") -Encoding utf8
$out | Write-Host

if (-not $ReportOnly) {
    # zip next to START-TEST (an elevated admin's Desktop may not be the owner's Desktop), then move logs aside
    # so a later run starts clean
    $zip = Join-Path $root ("Shinzx-Test-Report-{0:yyyyMMdd-HHmm}.zip" -f (Get-Date))
    Stop-Transcript | Out-Null # release the transcript file before zipping it
    Compress-Archive -Path (Join-Path $logs "*") -DestinationPath $zip -Force
    Rename-Item $logs ("logs-done-{0:yyyyMMdd-HHmm}" -f (Get-Date))
    Write-Host "ZIP=$zip"
    if (-not $Ci) {
        [System.Windows.Forms.MessageBox]::Show("Done. The PC is back to normal.`n`nSend this file on Discord to the person who gave you this test:`n$zip`n`n($pass passed, $fail failed, $nt not tested)", "Shinzx test") | Out-Null
        Start-Process explorer.exe "/select,`"$zip`""
    }
}
