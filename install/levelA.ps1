# LEVEL A: only programs the owner approved may run on this PC (Windows' own App Control for Business).
#   -Mode Audit   (start here) nothing is blocked; Windows writes down every program it would block (event 3076).
#   -Mode Enforce programs outside the approved list are blocked (event 3077).
#   -Mode Off     the rules are taken off again (no restart needed).
# -Approve: folders the owner approved (game folders, launchers, mouse and keyboard apps). Every program in them is
# allowed by its maker's signature, so game updates keep working; unsigned files are allowed by their exact content
# (an update to an unsigned file needs this script run again). Windows' own programs and drivers are always allowed,
# and so is the cafe program in C:\Program Files\ShinzxCafe (a folder only admins can change).
#Requires -RunAsAdministrator
param([ValidateSet("Audit", "Enforce", "Off")][string]$Mode = "Audit", [string[]]$Approve = @())
$ErrorActionPreference = "Stop"
$data = "$env:ProgramData\ShinzxCafe"
$idFile = "$data\levelA-id.txt"
New-Item $data -ItemType Directory -Force | Out-Null   # install-pc.ps1 makes it admin-only

# take the previous rules off first (rules of ours that are not active are simply not found)
if (Test-Path $idFile) {
    foreach ($id in Get-Content $idFile) { if ($id) { CiTool.exe --remove-policy $id -json | Out-Null } }
    Remove-Item $idFile
}
if ($Mode -eq "Off") { Write-Host "Level A is off."; exit 0 }

wevtutil.exe sl "Microsoft-Windows-CodeIntegrity/Operational" /ms:67108864   # 64 MB; the 1 MB default fills fast on a gaming PC
$xml = "$data\levelA.xml"
Copy-Item "$env:WINDIR\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml" $xml -Force
$rules = @(New-CIPolicyRule -FilePathRule "$env:ProgramFiles\ShinzxCafe\*")
foreach ($dir in $Approve) {
    if (-not (Test-Path $dir)) { throw "Approved folder not found: $dir" }
    # Publisher = the maker's certificate, so new versions from the same maker still run
    $files = Get-SystemDriver -ScanPath $dir -UserPEs -NoScript -NoShadowCopy
    $rules += New-CIPolicyRule -DriverFiles $files -Level Publisher -Fallback Hash
}
Merge-CIPolicy -PolicyPaths $xml -Rules $rules -OutputFilePath $xml | Out-Null
Set-CIPolicyIdInfo -FilePath $xml -PolicyName "Shinzx Level A" -ResetPolicyID | Out-Null
Set-RuleOption -FilePath $xml -Option 16   # rules can change without a restart
if ($Mode -eq "Audit") { Set-RuleOption -FilePath $xml -Option 3 } else { Set-RuleOption -FilePath $xml -Option 3 -Delete }
$id = ([xml](Get-Content $xml -Raw)).SiPolicy.PolicyID
ConvertFrom-CIPolicy -XmlFilePath $xml -BinaryFilePath "$data\levelA.cip" | Out-Null
CiTool.exe --update-policy "$data\levelA.cip" -json | Out-Null
if ($LASTEXITCODE) { throw "Windows did not take the Level A rules (CiTool exit $LASTEXITCODE)" }
$id | Set-Content $idFile -Encoding ascii
Write-Host "Level A is on ($Mode), $($rules.Count) rules, policy $id."
