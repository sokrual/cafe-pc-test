# PEN DRIVES (D2): Windows sets up no USB storage device (pen drive, USB hard disk, card reader, phone in USB-drive
# mode) until staff or the owner allow it at the counter. The watchdog asks the counter and puts an allowed drive on
# Windows' own allow list; read-only uses Windows' WriteProtect setting. USB mice, keyboards, headsets and game
# controllers are not storage and keep working.
#   -Mode Install  switch the block on (the installer's second step and every update)
#   -Mode Off      put Windows back as it was before (setup mode and uninstall)
#Requires -RunAsAdministrator
param([ValidateSet("Install", "Off")][string]$Mode = "Install", [string]$DataPath = "$env:ProgramData\GamingCafe")
$ErrorActionPreference = "Stop"
$restrictions = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
$storage = "HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
$backup = Join-Path $DataPath "pendrives-before"   # only admins and Windows can open DataPath
$regKeys = @{ "restrictions.reg" = "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"; "storage.reg" = "HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies" }

# USB storage Windows already knows (plugged in before, or now): taken out, so it must be allowed at the counter next time
function Remove-KnownUsbStorage {
    foreach ($device in @(Get-PnpDevice -Class USB -ErrorAction SilentlyContinue)) {
        $service = (Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName DEVPKEY_Device_Service -ErrorAction SilentlyContinue).Data
        if ($service -notin @("USBSTOR", "UASPStor")) { continue }
        pnputil.exe /remove-device "$($device.InstanceId)" /subtree | Out-Null
        Write-Host "USB storage device taken out of Windows: $($device.FriendlyName) ($($device.InstanceId)), exit $LASTEXITCODE"
    }
    pnputil.exe /scan-devices | Out-Null
}

if ($Mode -eq "Off") {
    if (-not (Test-Path $backup)) { Write-Host "Pen drive block is already off."; exit 0 }
    foreach ($k in $regKeys.Keys) {
        $path = "Registry::" + $regKeys[$k]
        if (Test-Path $path) { Remove-Item $path -Recurse -Force }
        $file = Join-Path $backup $k
        if (Test-Path $file) { reg.exe import "$file" | Out-Null; if ($LASTEXITCODE) { throw "Could not put back $($regKeys[$k]) (error $LASTEXITCODE)." } }
    }
    Remove-Item $backup -Recurse -Force
    pnputil.exe /scan-devices | Out-Null   # drives held back so far are set up now
    Write-Host "Pen drive block is off. Windows is as it was before."
    exit 0
}

if (-not (Test-Path $backup)) { # once: what Windows had before, so Off can put exactly that back
    New-Item $backup -ItemType Directory -Force | Out-Null
    foreach ($k in $regKeys.Keys) {
        if (Test-Path ("Registry::" + $regKeys[$k])) { reg.exe export $regKeys[$k] (Join-Path $backup $k) /y | Out-Null; if ($LASTEXITCODE) { throw "Could not save $($regKeys[$k]) (error $LASTEXITCODE)." } }
    }
}
foreach ($k in $restrictions, "$restrictions\DenyDeviceIDs", "$restrictions\AllowInstanceIDs", "$restrictions\DeniedPolicy", $storage) {
    if (-not (Test-Path $k)) { New-Item $k -Force | Out-Null }
}
# "USB\Class_08" is the USB mass-storage class every USB drive reports; matching devices are not set up
Set-ItemProperty "$restrictions\DenyDeviceIDs" "1" "USB\Class_08"
Set-ItemProperty $restrictions DenyDeviceIDs 1 -Type DWord
Set-ItemProperty $restrictions DenyDeviceIDsRetroactive 0 -Type DWord   # Remove-KnownUsbStorage below does this, safely
# the one drive the counter allowed (written by the watchdog) wins over the block above
Set-ItemProperty $restrictions AllowInstanceIDs 1 -Type DWord
Set-ItemProperty $restrictions AllowDenyLayered 1 -Type DWord
Set-ItemProperty "$restrictions\DeniedPolicy" SimpleText "This pen drive needs an OK from the counter"
Set-ItemProperty "$restrictions\DeniedPolicy" DetailText "Ask at the counter. Staff can allow it to read files, or to read and write. Programs on it never run."
Set-ItemProperty $storage WriteProtect 1 -Type DWord   # read-only unless the counter allowed read and write
Remove-KnownUsbStorage
Write-Host "Pen drive block is on: USB storage needs an OK from the counter."
