# WI-FI (D3): customers can join only the cafe's own Wi-Fi networks, through the cafe's own routers, and cannot
# share the PC's internet (Windows' Mobile hotspot is off). The owner picks the cafe's networks once; the watchdog
# records the routers it can see under those names and disconnects any other router (a renamed phone hotspot).
#   -Mode Install  switch on. -Ask: show nearby networks and ask the owner (installer step 2); otherwise keep the
#                  owner's earlier choice (updates). -Networks: the names, without asking (tests).
#   -Mode Off      put Windows back as it was before (setup mode and uninstall)
#Requires -RunAsAdministrator
param([ValidateSet("Install", "Off")][string]$Mode = "Install", [switch]$Ask, [string[]]$Networks,
    [string]$AppPath = "$env:ProgramFiles\GamingCafe", [string]$DataPath = "$env:ProgramData\GamingCafe")
$ErrorActionPreference = "Stop"
$keys = Join-Path $DataPath "keys"                    # only admins and Windows can open it
$choice = Join-Path $DataPath "wifi-networks.txt"    # the owner's choice, kept for updates
$hotspotKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
$hotspotBefore = Join-Path $DataPath "hotspot-before.txt"
$watchdog = Join-Path $AppPath "Cafe.Watchdog.exe"
[Console]::OutputEncoding = [Text.Encoding]::UTF8   # network names come back from the watchdog in UTF-8

if ($Mode -eq "Off") {
    & $watchdog --wifi-off $keys | Out-Host
    if (Test-Path $hotspotBefore) {
        $before = Get-Content $hotspotBefore -Raw
        if ($before.Trim() -eq "none") { Remove-ItemProperty $hotspotKey NC_ShowSharedAccessUI -ErrorAction SilentlyContinue }
        else { Set-ItemProperty $hotspotKey NC_ShowSharedAccessUI ([int]$before.Trim()) -Type DWord }
        Remove-Item $hotspotBefore -Force
    }
    Write-Host "Wi-Fi limits are off. Windows is as it was before."
    exit 0
}

# Mobile hotspot and internet sharing off for everyone
if (-not (Test-Path $hotspotBefore)) {
    $old = (Get-ItemProperty $hotspotKey -ErrorAction SilentlyContinue).NC_ShowSharedAccessUI
    Set-Content $hotspotBefore $(if ($null -eq $old) { "none" } else { "$old" })
}
if (-not (Test-Path $hotspotKey)) { New-Item $hotspotKey -Force | Out-Null }
Set-ItemProperty $hotspotKey NC_ShowSharedAccessUI 0 -Type DWord

$nearby = @(& $watchdog --wifi-networks $keys)
if ($LASTEXITCODE -eq 3) { Write-Host "No Wi-Fi on this PC: only Mobile hotspot is switched off."; exit 0 }
if ($LASTEXITCODE) { throw "Could not read the Wi-Fi networks (error $LASTEXITCODE)." }
if ($PSBoundParameters.ContainsKey("Networks")) { $chosen = @($Networks | Where-Object { $_ }) }
elseif ($Ask -or -not (Test-Path $choice)) {
    Write-Host ""
    Write-Host "Wi-Fi networks this PC can see now:"
    for ($i = 0; $i -lt $nearby.Count; $i++) { Write-Host "  $($i + 1). $($nearby[$i])" }
    Write-Host "Customers will see only the cafe's own networks. Join them on this PC first, so Windows knows the password."
    $answer = Read-Host "Type the numbers of the cafe's networks, for example 1,3 (or type none for no Wi-Fi)"
    $chosen = @()
    if ($answer.Trim() -ne "none") {
        foreach ($n in $answer -split "[,\s]+" | Where-Object { $_ }) {
            if ($n -notmatch '^\d+$' -or [int]$n -lt 1 -or [int]$n -gt $nearby.Count) { throw "'$n' is not one of the numbers shown. Run INSTALL-PC again." }
            $chosen += $nearby[[int]$n - 1]
        }
    }
}
else { $chosen = @(Get-Content $choice -Encoding UTF8 | Where-Object { $_ }) }
Set-Content $choice $chosen -Encoding UTF8
& $watchdog --wifi-apply $keys @chosen | Out-Host
if ($LASTEXITCODE -eq 4) { Write-Host "WARNING: a cafe network you chose has no router in range now. This PC will not stay on it. Move closer or check the router, then run INSTALL-PC again." }
elseif ($LASTEXITCODE) { throw "Could not set the Wi-Fi limits (error $LASTEXITCODE)." }
if ($chosen.Count -eq 0) { Write-Host "Wi-Fi is closed to customers on this PC." }
else { Write-Host "Customers can use only these Wi-Fi networks: $($chosen -join ', ')" }
