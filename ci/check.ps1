# Fails the run if anything that MUST work on any Windows PC did not work.
# Checks that depend on real games, a GPU, speakers or Windows 11 25H2 are reported as warnings only.
param([int]$Round)
$ErrorActionPreference = "Stop"
$root = "C:\ShinzxTest"
$hard = [System.Collections.Generic.List[string]]::new()
$summary = [System.Collections.Generic.List[string]]::new()

$done = Get-ChildItem $root -Directory -Filter "logs-done-*" | Sort-Object LastWriteTime | Select-Object -Last 1
if (-not $done) { throw "No logs-done folder: FINISH-TEST did not complete." }
if (Test-Path "$root\logs") { $hard.Add("logs folder still there after FINISH-TEST") }
if (-not (Get-ChildItem $root -Filter "Shinzx-Test-Report-*.zip")) { $hard.Add("no report zip") }

$lines = Get-Content (Join-Path $done.FullName "REPORT.txt")
$res = foreach ($l in $lines) { if ($l -match '^\[(PASS|FAIL|NOT TESTED)\] (\S+) (.*)$') { [pscustomobject]@{ r = $Matches[1]; id = $Matches[2]; text = $Matches[3] } } }

# must PASS on every Windows machine
$mustPass = "T0.1a", "T0.2g", "T0.2c", "T0.2h", "T0.2e", "T0.1b", "T0.1f", "T0.1h", "T0.9a", "T0.9b", "T0.4a", "T0.4b", "T0.9c"
if ($env:PROCESSOR_ARCHITECTURE -ne "ARM64") { $mustPass += "T0.1g" } # on Arm our x64 timer runs emulated and uses more memory
foreach ($id in $mustPass) {
    $hit = @($res | Where-Object id -eq $id)
    if (-not $hit) { $hard.Add("$id missing from report") }
    foreach ($h in $hit) { if ($h.r -ne "PASS") { $hard.Add("$id $($h.r): $($h.text)") } }
}
# every folder block check must PASS (USB is NOT TESTED: no USB on a cloud machine)
$blocks = @($res | Where-Object { $_.id -eq "T0.2b" -and $_.text -notmatch "USB" })
if ($blocks.Count -lt 6) { $hard.Add("only $($blocks.Count) folder block checks ran, expected 6") }
foreach ($b in $blocks) { if ($b.r -ne "PASS") { $hard.Add("T0.2b $($b.r): $($b.text)") } }

# no customer account may change the kit (measure.ps1 runs as SYSTEM, start/finish as admin)
foreach ($f in "$root\measure.ps1", "$root\start.ps1", "$root\finish.ps1", "$root\ShinzxTimerTest.exe") {
    if ((Get-Acl $f).Access | Where-Object { $_.IdentityReference -match "Authenticated Users|Everyone|\\Users$" -and $_.FileSystemRights -match "Write|Modify|FullControl" }) {
        $hard.Add("customers can change $f"); icacls $f | Write-Host
    }
}

# the PC must really be back to normal
if (Get-LocalUser "ShinzxTest" -ErrorAction SilentlyContinue) { $hard.Add("temporary user ShinzxTest still exists") }
if (Get-CimInstance Win32_UserProfile | Where-Object LocalPath -like "*\ShinzxTest*") { $hard.Add("ShinzxTest profile still exists") }
if (Get-ScheduledTask -TaskName "ShinzxTest*" -ErrorAction SilentlyContinue) { $hard.Add("test tasks still registered") }
if (Get-Process ShinzxTimerTest -ErrorAction SilentlyContinue) { $hard.Add("timer still running") }
$rules = @(([xml](Get-AppLockerPolicy -Effective -Xml)).SelectNodes("//*[@Action]")).Count
if ($rules -ne 0) { $hard.Add("$rules AppLocker rules still active (cloud machine had none before)") }
Start-Sleep -Seconds 12
if (Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match "measure\.ps1" }) { $hard.Add("measurer still running") }

# soft: expected to differ on a cloud machine, shown so a real problem is not missed
# the audit log must have caught the program run from Downloads (proves the day-long check works without a restart)
$wb = Import-Csv (Join-Path $done.FullName "would-be-blocked.csv")
$sawDownload = [bool]($wb | Where-Object path -match "shinzx-ci-download")
# Level A watch-only must have logged our own unsigned timer (proves the events are read and the paths decoded)
$la = @(Import-Csv (Join-Path $done.FullName "levelA-would-block.csv"))
$sawTimer = [bool]($la | Where-Object { $_.path -like "$root\ShinzxTimerTest.exe" })
foreach ($f in "installed-programs.csv", "services-and-drivers.csv", "startup.csv") { if (-not (Test-Path (Join-Path $done.FullName $f))) { $hard.Add("$f missing") } }
foreach ($r in $res) { $summary.Add("| $($r.r) | $($r.id) | $($r.text -replace '\|', '/') |") }

$out = @("## Round $Round on $((Get-CimInstance Win32_OperatingSystem).Caption)", "",
    "Audit log caught the Downloads program: $sawDownload", "Level A log caught the unsigned timer: $sawTimer ($($la.Count) files listed)", "",
    "| Result | ID | Check |", "|---|---|---|") + $summary + @("", "**Must-pass problems: $($hard.Count)**") + ($hard | ForEach-Object { "- $_" })
$out | Write-Host
if ($env:GITHUB_STEP_SUMMARY) { $out | Out-File $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8 }
if (-not $sawTimer) { $hard.Add("Level A watch-only did not list ShinzxTimerTest.exe"); $la | Select-Object -First 20 | Format-Table | Out-String | Write-Host }
if (-not $sawDownload) { $hard.Add("audit log did not record the program run from Downloads") }
if ($hard.Count) { exit 1 }
