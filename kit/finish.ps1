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
        try {
            $map = @{ Automatic = "auto"; Manual = "demand"; Disabled = "disabled" }
            $old = (Get-Content (Join-Path $logs "appidsvc-starttype.txt") -Raw).Trim()
            if ($map[$old]) { sc.exe config AppIDSvc start= $($map[$old]) | Out-Null }
        } catch { Write-Host "Restoring the service setting failed: $_" -ForegroundColor Red }
    }
    # check the restore really worked
    $before = @(([xml](Get-Content (Join-Path $logs "applocker-backup.xml") -Raw)).SelectNodes("//*[@Action]")).Count
    $now = @(([xml](Get-AppLockerPolicy -Local -Xml)).SelectNodes("//*[@Action]")).Count
    $left = @(Get-ScheduledTask -TaskName "ShinzxTest*" -ErrorAction SilentlyContinue).Count + @(Get-LocalUser "ShinzxTest" -ErrorAction SilentlyContinue).Count
    Add-Result "T0.9a" "PC app rules restored to how they were" ($now -eq $before) "$now rules now, $before before the test"
    Add-Result "T0.9b" "Test tasks and test user removed" ($left -eq 0) "$left left"
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
    $growth = if ($longest[0].priv -gt 0) { ($longest[-1].priv / $longest[0].priv - 1) * 100 } else { 0 }
    Add-Result "T0.1f" "Timer CPU under 1%" ($avgCpu -lt 1) ("average {0:N2}% ({1})" -f $avgCpu, $scope)
    Add-Result "T0.1g" "Timer memory under 50 MB" ($maxPriv -lt 50) ("peak {0:N1} MB" -f $maxPriv)
    Add-Result "T0.1h" "Timer uses no GPU" ($avgGpu -lt 0.5) ("average {0:N2}%" -f $avgGpu)
    Add-Result "T0.1i" "Timer memory does not keep growing" ($growth -lt 10) ("{0:N1} -> {1:N1} MB over {2:N1} hours" -f $longest[0].priv, $longest[-1].priv, ($longest[-1].t - $longest[0].t).TotalHours)
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
$wb = @(Import-Csv (Join-Path $logs "would-be-blocked.csv") -ErrorAction SilentlyContinue)
$gameWords = "steam|epic|riot|vanguard|valorant|battle\.net|blizzard|ubisoft|uplay|\bea\b|\borigin\b|rockstar|garena|faceit|easyanticheat|battleye|discord|nvidia|amd"
$gameHits = @($wb | Where-Object { $_.path -match $gameWords } | Select-Object -ExpandProperty path -Unique)
$otherHits = @($wb | Where-Object { $_.path -notmatch $gameWords } | Select-Object -ExpandProperty path -Unique)
Add-Result "T0.2f" "No game, launcher or anti-cheat would be blocked by Level B" ($gameHits.Count -eq 0) "$($gameHits.Count) game-related, $($otherHits.Count) other programs would be blocked"

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
