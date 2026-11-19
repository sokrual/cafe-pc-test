# THROWAWAY (A.K6 measurement): stands in for install-admin.ps1. Opens its log the same way and writes the same
# last message the same way. -Close also closes the log before returning (the fix being measured).
param($Folder, $Round, [switch]$Close)
$ErrorActionPreference = "Stop"
function Say($text) { Write-Host $text }
Start-Transcript "$Folder\install-log.txt" -Append | Out-Null
Write-Host "BitLocker status: Off"
cmd.exe /c "echo a program's own output, round $Round" | Out-Host
$keysStep = "New keys for the 2 gaming PCs not installed yet (PC1, PC3) round $Round are in this folder. Older key files no longer work."
Say "The counter PC is ready.`n`nThis PC's address: 10.1.0.148`n`nNext:`n1. On the counter screen (https://127.0.0.1:5443/staff/), make your owner account. $keysStep`n2. Take this whole folder (for example on a pen drive) to each gaming PC and run INSTALL-PC.`n`nThe counter screen opens now."
if ($Close) { Stop-Transcript | Out-Null }
