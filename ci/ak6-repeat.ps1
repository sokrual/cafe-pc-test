# THROWAWAY (A.K6 measurement): one fresh PowerShell runs the real INSTALL-ADMIN update twice, as ci/lockdown.ps1 does,
# and after each run reads the install log at once. -Close: the reader first closes the log the installer left open.
param($Stage, $Label, [switch]$Close)
$ErrorActionPreference = "Stop"
$log = "$Stage\install-log.txt"; $last = "The counter screen opens now\."
foreach ($call in "first", "second") {
    Start-Sleep -Seconds 2   # let anything still on its way reach the file, so "before" is a settled count
    $before = ([regex]::Matches("$(Get-Content $log -Raw)", $last)).Count
    & "$Stage\install-admin.ps1" -Ci -Pcs 5
    if ($Close) { Stop-Transcript | Out-Null }
    $text = "$(Get-Content $log -Raw)"
    $s = [IO.File]::Open($log, "Open", "Read", "ReadWrite"); $bytes = $s.Length; $s.Dispose()
    $after = ([regex]::Matches($text, $last)).Count
    Write-Output "AK6-REPEAT|round $Label|$call run in this PowerShell|log closed first=$([bool]$Close)|last message count before=$before, read at once=$after|missed=$($after -le $before)|characters read=$($text.Length)|file bytes just after=$bytes"
}
