# THROWAWAY (A.K6 measurement): is an install log complete when a test reads it right after the installer
# returns, in the same PowerShell? Measured with the log left open (today) and closed by the installer.
param([int]$Pairs = 100, $Pair, [switch]$Close)
$ErrorActionPreference = "Stop"
if ($Pair) {   # one fresh PowerShell = one lockdown run: the installer runs twice into the same log, as ci/lockdown.ps1 does
    foreach ($call in 1, 2) {
        $round = "$(Split-Path $Pair -Leaf)-$call"
        $want = [regex]::Escape("not installed yet (PC1, PC3) round $round are in this folder")
        & "$PSScriptRoot\measure-installer.ps1" -Folder $Pair -Round $round -Close:$Close
        $t0 = Get-Date
        $text = "$(Get-Content "$Pair\install-log.txt" -Raw)"
        $found = $text -match $want
        $whole = $text -match "round $round are in this folder[\s\S]*The counter screen opens now\."
        $later = ""
        if (-not $found) {
            $later = "never in 10 s"
            for ($k = 0; $k -lt 100; $k++) {
                Start-Sleep -Milliseconds 100
                if ("$(Get-Content "$Pair\install-log.txt" -Raw)" -match $want) { $later = "$([int]((Get-Date) - $t0).TotalMilliseconds) ms"; break }
            }
        }
        $tail = $text.Substring([Math]::Max(0, $text.Length - 160)) -replace "\s+", " "
        Write-Output "RESULT|$call|$found|$whole|$later|$tail"
    }
    return
}
"Windows PowerShell $($PSVersionTable.PSVersion) on $([Environment]::OSVersion.VersionString) $env:PROCESSOR_ARCHITECTURE; $Pairs fresh PowerShells per way, 2 installer calls each"
$work = Join-Path $env:TEMP "ak6-measure"; Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
foreach ($closed in $false, $true) {
    $rows = for ($i = 1; $i -le $Pairs; $i++) {
        $folder = Join-Path $work "$closed-$i"; New-Item $folder -ItemType Directory -Force | Out-Null
        $a = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath, "-Pair", $folder); if ($closed) { $a += "-Close" }
        & powershell.exe @a | Where-Object { "$_" -like "RESULT|*" } | ForEach-Object { $p = "$_".Split("|", 6); [pscustomobject]@{ call = $p[1]; found = $p[2]; whole = $p[3]; later = $p[4]; tail = $p[5] } }
    }
    foreach ($call in "1", "2") {
        $mine = @($rows | Where-Object call -eq $call)
        $missed = @($mine | Where-Object found -ne "True")
        "MEASURED log closed by the installer=$closed, installer call $call`: $($mine.Count) reads; message missing at once: $($missed.Count); whole last message missing at once: $(@($mine | Where-Object whole -ne 'True').Count); it arrived later after: [$(($missed | ForEach-Object later | Select-Object -First 12) -join ', ')]"
        $missed | Select-Object -First 2 | ForEach-Object { "   example, end of the log as the test read it: [$($_.tail)]" }
    }
}
