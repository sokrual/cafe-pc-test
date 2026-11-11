# Stands in for "use the PC for a day": runs the two test tasks without a restart, fakes a full-screen
# game, and runs a program from Downloads so the audit log has something to report. About 3 minutes.
$ErrorActionPreference = "Stop"
$root = "C:\CafeTest"

# measurer: start the real SYSTEM task (proves the task itself works)
Start-ScheduledTask -TaskName "CafeTestMeasure"

# timer: start it with the exact program and arguments the logon task would use
$a = (Get-ScheduledTask -TaskName "CafeTestTimer").Actions[0]
Write-Host "Timer task runs: $($a.Execute) $($a.Arguments)"
$timer = Start-Process $a.Execute -ArgumentList $a.Arguments -PassThru
Start-Sleep -Seconds 15

# fake game: a borderless window covering the whole screen, run by a process the timer is told is a game
Copy-Item "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" "$root\FakeGame.exe" -Force
Add-Content "$root\games.txt" "FakeGame"
$game = @'
Add-Type -AssemblyName System.Windows.Forms
$f = New-Object System.Windows.Forms.Form
$f.FormBorderStyle = "None"; $f.WindowState = "Maximized"; $f.TopMost = $true; $f.BackColor = "Black"
$t = New-Object System.Windows.Forms.Timer; $t.Interval = 150000; $t.Add_Tick({ $f.Close() }); $t.Start()
[System.Windows.Forms.Application]::Run($f)
'@
$gameScript = "$env:TEMP\fakegame.ps1"; $game | Out-File $gameScript -Encoding utf8
# the timer read games.txt at start, so restart it to pick up FakeGame
Stop-Process -Id $timer.Id -Force
$timer = Start-Process $a.Execute -ArgumentList $a.Arguments -PassThru
Start-Sleep -Seconds 5
$g = $null
try { $g = Start-Process "$root\FakeGame.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$gameScript`"" -PassThru }
catch { Write-Host "::warning::fake game did not start: $_" }

# something Level B would block: a program started from Downloads (audit mode, so it still runs)
$dl = Join-Path $env:USERPROFILE "Downloads"
New-Item $dl -ItemType Directory -Force | Out-Null
Copy-Item "$env:WINDIR\System32\whoami.exe" "$dl\cafe-ci-download.exe" -Force
& "$dl\cafe-ci-download.exe" | Out-Null

if ($g) { $g.WaitForExit(170000) | Out-Null } else { Start-Sleep -Seconds 150 }   # 2.5 min of "play": long enough for the voice rule (2 min in a game)
Start-Sleep -Seconds 15             # a few samples after the game
Get-ChildItem "$root\logs" -Recurse | Format-Table Name, Length -AutoSize | Out-String | Write-Host
Get-Content "$root\logs\users\timer-*.log" -ErrorAction SilentlyContinue | Write-Host
