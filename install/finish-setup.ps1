# FINISH-SETUP: the "Finish cafe setup" icon on the desktop while a gaming PC is in setup mode. It runs as Customer and
# needs no admin password: it asks which Wi-Fi networks are the cafe's, then starts the installer's step 2 through the
# scheduled task CafeFinishSetup, which Windows runs as SYSTEM. The task does nothing outside setup mode and is removed
# when step 2 is done. -Check (at sign-in): show why the last try stopped, if it did.
param([switch]$Check)
$out = "$env:ProgramData\GamingCafe\finish"   # written by the task; this account can only read it
Add-Type -AssemblyName System.Windows.Forms, Microsoft.VisualBasic
function Say($text) { [System.Windows.Forms.MessageBox]::Show($text, "Gaming Cafe setup") | Out-Null }
$last = Get-Content "$out\result.txt" -Raw -ErrorAction SilentlyContinue
if ($Check) {
    if ($last) { Say "Finishing the cafe setup stopped last time:`n$last`n`nDouble-click 'Finish cafe setup' to try again. If it stops again, send a photo of this message on Discord to the person who gave you this software." }
    exit 0
}

function Run-Step { schtasks.exe /run /tn CafeFinishSetup | Out-Null; if ($LASTEXITCODE) { Say "Could not start the setup (error $LASTEXITCODE). Restart the PC and try again."; exit 1 } }
$wanted = "HKCU:\Software\GamingCafe"
Remove-Item $wanted -Recurse -Force -ErrorAction SilentlyContinue   # no choice yet: the task first lists the networks
function Written { (Get-Item "$out\nearby.txt" -ErrorAction SilentlyContinue).LastWriteTimeUtc }
$before = Written   # this account cannot delete the task's files: wait for a new list instead
Run-Step
for ($i = 0; $i -lt 60 -and (Written) -eq $before; $i++) { Start-Sleep -Seconds 1 }
if ((Written) -eq $before) { Say "The setup did not answer. Restart the PC and try again."; exit 1 }
$nearby = @(Get-Content "$out\nearby.txt" -Encoding UTF8 | Where-Object { $_ })

$chosen = @()
if ($nearby -and $nearby[0] -ne "NO-WIFI") {
    $list = (1..$nearby.Count | ForEach-Object { "  $_. $($nearby[$_ - 1])" }) -join "`n"
    $answer = [Microsoft.VisualBasic.Interaction]::InputBox("Wi-Fi networks this PC can see:`n$list`n`nCustomers will see only the cafe's own networks.`nType the numbers of the cafe's networks, for example 1,3 (or none):", "Gaming Cafe setup", "none")
    if (-not $answer) { exit 0 }   # Cancel
    if ($answer.Trim() -ne "none") {
        foreach ($n in $answer -split "[,\s]+" | Where-Object { $_ }) {
            if ($n -notmatch '^\d+$' -or [int]$n -lt 1 -or [int]$n -gt $nearby.Count) { Say "'$n' is not one of the numbers shown. Double-click 'Finish cafe setup' again."; exit 1 }
            $chosen += $nearby[[int]$n - 1]
        }
    }
}
New-Item $wanted -Force | Out-Null
Set-ItemProperty $wanted FinishWifi ($chosen -join "`n")
Say "The setup finishes now. The screen goes dark for 5 to 10 minutes. Do not switch the PC off. Then it restarts by itself and shows the lock screen."
Run-Step
