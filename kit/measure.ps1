# Runs hidden as SYSTEM for the whole test. Every 5 s records CPU, memory and GPU of every running
# ShinzxTimerTest.exe into logs\measure.csv. Stops when logs\stop.flag exists or the test expires.
param([Parameter(Mandatory)][string]$Out, [Parameter(Mandatory)][string]$Expires, [int]$IntervalSec = 5)

$stopFlag = Join-Path (Split-Path $Out) "stop.flag"
$until = [datetime]::Parse($Expires, [Globalization.CultureInfo]::InvariantCulture)
$cores = [Environment]::ProcessorCount
if (-not (Test-Path $Out)) { "time,pid,cpu_percent,private_mb,working_set_mb,gpu_percent" | Out-File $Out -Encoding utf8 }
$last = @{} # pid -> @(cpuTime, wallTime)

while ((Get-Date) -lt $until -and -not (Test-Path $stopFlag)) {
    Start-Sleep -Seconds $IntervalSec
    foreach ($p in @(Get-Process -Name ShinzxTimerTest -ErrorAction SilentlyContinue)) {
        $now = Get-Date
        $prev = $last[$p.Id]
        $last[$p.Id] = @($p.TotalProcessorTime, $now)
        if (-not $prev) { continue } # first sight of this process: need two readings for CPU %
        $cpu = ($p.TotalProcessorTime - $prev[0]).TotalMilliseconds / ($now - $prev[1]).TotalMilliseconds / $cores * 100
        $gpu = 0
        try {
            $gpu = ((Get-Counter "\GPU Engine(pid_$($p.Id)_*)\Utilization Percentage" -ErrorAction Stop).CounterSamples |
                    Measure-Object CookedValue -Sum).Sum
        } catch { $gpu = 0 } # no GPU engine instances = the timer used no GPU
        # invariant culture + F formats: no thousands commas or comma decimals that would break the CSV
        [string]::Format([Globalization.CultureInfo]::InvariantCulture, "{0:yyyy-MM-dd HH:mm:ss},{1},{2:F3},{3:F1},{4:F1},{5:F3}",
            $now, $p.Id, $cpu, ($p.PrivateMemorySize64 / 1MB), ($p.WorkingSet64 / 1MB), $gpu) |
            Out-File $Out -Append -Encoding utf8
    }
}
