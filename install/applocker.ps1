# AppLocker policy for customer-writable locations. Run only from the elevated PC installer.
#Requires -RunAsAdministrator
param(
    [ValidateSet("Install", "Uninstall")][string]$Mode,
    [string]$CustomerSid,
    [string]$DataPath = "$env:ProgramData\GamingCafe",
    [AllowEmptyString()][string]$AllowFolders
)
$ErrorActionPreference = "Stop"
$allowFoldersWasSpecified = $PSBoundParameters.ContainsKey("AllowFolders")
$policyBackup = Join-Path $DataPath "applocker-before.xml"
$serviceBackup = Join-Path $DataPath "appidsvc-before.json"
$logBackup = Join-Path $DataPath "applocker-logs-before.json"
$reportPath = Join-Path $DataPath "customer-writable-folders.txt"
$channels = @("Microsoft-Windows-AppLocker/EXE and DLL", "Microsoft-Windows-AppLocker/MSI and Script")

function Set-AppIdStartupMode([string]$Mode) {
    $scMode = switch ($Mode) {
        "Auto" { "auto" }
        "Manual" { "demand" }
        "Disabled" { "disabled" }
        "Boot" { "boot" }
        "System" { "system" }
        default { throw "Unsupported AppIDSvc startup mode '$Mode'." }
    }
    & "$env:WINDIR\System32\sc.exe" config AppIDSvc start= $scMode | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not set AppIDSvc startup mode to '$Mode' (sc.exe exit $LASTEXITCODE)." }
}

function Restore-OriginalState {
    Import-Module AppLocker -ErrorAction Stop
    if (Test-Path -LiteralPath $policyBackup) {
        Set-AppLockerPolicy -XmlPolicy $policyBackup
    }
    $rootAclBackup = Join-Path $DataPath "c-root-acl-before.sddl"
    if (Test-Path -LiteralPath $rootAclBackup) {
        $systemDriveRoot = "$env:SystemDrive\"
        $originalRootSddl = (Get-Content -LiteralPath $rootAclBackup -Raw).Trim()
        $rootAcl = Get-Acl -LiteralPath $systemDriveRoot
        $rootAcl.SetSecurityDescriptorSddlForm($originalRootSddl)
        Set-Acl -LiteralPath $systemDriveRoot -AclObject $rootAcl
        Write-Host "Restored original ACL on $systemDriveRoot from the install-time backup."
    }
    if (Test-Path -LiteralPath $logBackup) {
        foreach ($entry in (Get-Content -LiteralPath $logBackup -Raw | ConvertFrom-Json)) {
            $enabled = if ($entry.Enabled) { "true" } else { "false" }
            & wevtutil.exe sl $entry.Channel "/e:$enabled" | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Could not restore event log setting for $($entry.Channel)." }
        }
    }
    if (Test-Path -LiteralPath $serviceBackup) {
        $original = Get-Content -LiteralPath $serviceBackup -Raw | ConvertFrom-Json
        try {
            Set-AppIdStartupMode $original.StartMode
        } catch {
            Write-Warning "Could not restore AppIDSvc startup mode to '$($original.StartMode)' (the protected service refused the change); continuing uninstall because the AppLocker policy has already been restored. $($_.Exception.Message)"
        }
        if ($original.WasRunning) {
            Start-Service -Name AppIDSvc -ErrorAction Stop
        } else {
            Stop-Service -Name AppIDSvc -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host "AppLocker policy restored; Application Identity service state restoration attempted."
}

function Get-CustomerWritableDirectoryTree([string]$Root, [string[]]$PrincipalSids) {
    # Stop at the first writable folder on each branch; descendants inherit the same access.
    $found = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return @() }
    $pending = New-Object System.Collections.Generic.Stack[object]
    $pending.Push([pscustomobject]@{ Path = $Root; ParentAccess = $null })
    while ($pending.Count -gt 0) {
        $item = $pending.Pop()
        $current = $item.Path
        try {
            $acl = Get-Acl -LiteralPath $current -ErrorAction Stop
            $explicitRules = @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
            $currentOwnerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
            if ($null -ne $item.ParentAccess -and $explicitRules.Count -eq 0 -and
                $currentOwnerSid -eq $item.ParentAccess.OwnerSid) {
                $access = [pscustomobject]@{
                    Path = $current; Writable = $item.ParentAccess.Writable
                    Executable = $item.ParentAccess.Executable; OwnerSid = $currentOwnerSid; Sddl = $null
                }
            } else {
                $access = Get-CustomerDirectoryAccess $current $PrincipalSids $acl
            }
            if ($access.Writable) {
                $found.Add([pscustomobject]@{ Path = $current; Access = $access })
                continue
            }
            $children = @()
            try { $children = [IO.Directory]::GetDirectories($current) }
            catch {
                $script:scanDeniedFolders.Add($current)
                Write-Warning "Could not enumerate '$current'; not changed (scan inaccessible): $($_.Exception.Message)"
                continue
            }
            foreach ($child in $children) {
                try {
                    $attributes = [IO.File]::GetAttributes($child)
                    if (($attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
                        $pending.Push([pscustomobject]@{ Path = $child; ParentAccess = $access })
                    }
                } catch { }
            }
        } catch {
            $script:scanDeniedFolders.Add($current)
            Write-Warning "Could not inspect '$current'; not changed (scan inaccessible): $($_.Exception.Message)"
        }
    }
    return $found.ToArray()
}

function Get-CustomerDirectoryAccess([string]$Path, [string[]]$PrincipalSids, $Acl = $null) {
    try {
        if ($null -eq $Acl) { $Acl = Get-Acl -LiteralPath $Path -ErrorAction Stop }
        $acl = $Acl
        $allowMask = [int64]0
        $denyMask = [int64]0
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
            if ($PrincipalSids -contains $rule.IdentityReference.Value) {
                $mask = [int64]$rule.FileSystemRights
                if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny) {
                    $denyMask = $denyMask -bor $mask
                } else {
                    $allowMask = $allowMask -bor $mask
                }
            }
        }
        $effectiveMask = $allowMask -band (-bnot $denyMask)
        # AppendData is CreateSubdirectories on directories. It is writable exposure:
        # a Customer-created child is Customer-owned and can contain executables after installation.
        $writeMask = [int64]([int][Security.AccessControl.FileSystemRights]::WriteData -bor
            [int][Security.AccessControl.FileSystemRights]::AppendData -bor
            [int][Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
            [int][Security.AccessControl.FileSystemRights]::WriteAttributes)
        $executeMask = [int64][int][Security.AccessControl.FileSystemRights]::ExecuteFile
        $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($PrincipalSids -contains $ownerSid) {
            $effectiveMask = $effectiveMask -bor $writeMask -bor $executeMask
        }
        return [pscustomobject]@{
            Path = $Path
            Writable = (($effectiveMask -band $writeMask) -ne 0)
            Executable = (($effectiveMask -band $executeMask) -ne 0)
            OwnerSid = $ownerSid
            Sddl = $acl.Sddl
        }
    } catch {
        throw "Could not inspect Customer access on ACL path '$Path': $($_.Exception.Message)"
    }
}

function Install-CustomerPolicy {
    if ($CustomerSid -notmatch '^S-1-5-21-(\d+-){3}\d+$') {
        throw "A valid local Customer SID is required to install AppLocker rules."
    }
    Import-Module AppLocker -ErrorAction Stop
    $service = Get-CimInstance Win32_Service -Filter "Name='AppIDSvc'"
    if (-not $service) { throw "The Application Identity service (AppIDSvc) is not installed." }

    if (-not (Test-Path -LiteralPath $policyBackup)) {
        $before = Get-AppLockerPolicy -Local -Xml
        [IO.File]::WriteAllText($policyBackup, [string]$before, (New-Object Text.UTF8Encoding($false)))
    }
    if (-not (Test-Path -LiteralPath $serviceBackup)) {
        $serviceState = [pscustomobject]@{ StartMode = $service.StartMode; WasRunning = ($service.State -eq "Running") }
        $serviceState | ConvertTo-Json | Set-Content -LiteralPath $serviceBackup -Encoding UTF8
    }
    if (-not (Test-Path -LiteralPath $logBackup)) {
        $logStates = foreach ($channel in $channels) {
            $details = (& wevtutil.exe gl $channel 2>&1) -join [Environment]::NewLine
            if ($LASTEXITCODE -ne 0) { throw "Could not read AppLocker event channel $channel." }
            [pscustomobject]@{
                Channel = $channel
                Enabled = [bool]($details -match "(?im)^\s*enabled:\s*true\s*$")
            }
        }
        @($logStates) | ConvertTo-Json | Set-Content -LiteralPath $logBackup -Encoding UTF8
    }

    # Report the effective allow/deny ACEs before generating any rules. Customer is a standard local user.
    $principals = @($CustomerSid, "S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-4", "S-1-5-113")

    # Prevent creation of new, previously-uninventoried folders directly under the system-drive root.
    # Preserve the exact original descriptor once so repeated installs and uninstall remain reversible.
    $systemDriveRoot = "$env:SystemDrive\"
    $rootAclBackup = Join-Path $DataPath "c-root-acl-before.sddl"
    if (-not (Test-Path -LiteralPath $rootAclBackup)) {
        $originalRootSddl = (Get-Acl -LiteralPath $systemDriveRoot).Sddl
        [IO.File]::WriteAllText($rootAclBackup, $originalRootSddl, (New-Object Text.UTF8Encoding($false)))
    }
    $systemRootAcl = Get-Acl -LiteralPath $systemDriveRoot
    foreach ($principalSid in @("S-1-5-11", "S-1-5-32-545")) {
        $alreadyDenied = @($systemRootAcl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.IdentityReference.Value -eq $principalSid -and
                $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny -and
                (([int64]$_.FileSystemRights -band [int64][int][Security.AccessControl.FileSystemRights]::CreateDirectories) -ne 0) -and
                $_.InheritanceFlags -eq [Security.AccessControl.InheritanceFlags]::None }).Count -gt 0
        if (-not $alreadyDenied) {
            $denyCreateRootFolder = New-Object Security.AccessControl.FileSystemAccessRule(
                (New-Object Security.Principal.SecurityIdentifier($principalSid)),
                [Security.AccessControl.FileSystemRights]::CreateDirectories,
                [Security.AccessControl.AccessControlType]::Deny,
                [Security.AccessControl.InheritanceFlags]::None,
                [Security.AccessControl.PropagationFlags]::None)
            [void]$systemRootAcl.AddAccessRule($denyCreateRootFolder)
        }
    }
    Set-Acl -LiteralPath $systemDriveRoot -AclObject $systemRootAcl
    Write-Host "Removed effective CreateDirectories access for Authenticated Users and BUILTIN\\Users on $systemDriveRoot only; original ACL saved for uninstall."

    $programFiles = $env:ProgramFiles
    $programFilesX86 = $env:ProgramFiles + " (x86)"
    $programData = $env:ProgramData
    $roots = @($programFiles, $programFilesX86, $programData) | Where-Object { Test-Path -LiteralPath $_ -PathType Container }
    $report = New-Object System.Collections.Generic.List[string]
    $report.Add("D1 customer-writable folder inventory (ACL-based, before AppLocker policy installation)")
    $report.Add("Customer SID: $CustomerSid")
    $report.Add("ACL effective-access calculation includes Customer, Everyone, Authenticated Users, BUILTIN\Users, Interactive and Local account ACEs plus owner rights; deny ACE masks are subtracted from allow ACE masks.")
    $report.Add("")
    foreach ($root in $roots) {
        $rootAcl = Get-Acl -LiteralPath $root
        $report.Add("ACL ROOT: $root")
        $report.Add("SDDL: $($rootAcl.Sddl)")
    }

    $script:scanDeniedFolders = New-Object System.Collections.Generic.List[string]
    $allWritableExecute = New-Object System.Collections.Generic.List[string]
    $customerProfile = (Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $CustomerSid } | Select-Object -First 1).LocalPath
    $profileRoots = @($customerProfile, "$env:SystemDrive\Users\Public", "$env:WINDIR\Temp") | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) }
    foreach ($profileRoot in $profileRoots) {
        foreach ($entry in (Get-CustomerWritableDirectoryTree $profileRoot $principals)) {
            $folder = $entry.Path; $access = $entry.Access
            if ($access.Executable) {
                $allWritableExecute.Add($folder)
                $report.Add("CUSTOMER-WRITABLE+EXECUTABLE: $folder")
                if ($access.Sddl) { $report.Add("SDDL: $($access.Sddl)") }
            }
        }
    }

    $programDataWritable = New-Object System.Collections.Generic.List[string]
    $programDataWriteExecute = New-Object System.Collections.Generic.List[string]
    foreach ($entry in (Get-CustomerWritableDirectoryTree $programData $principals)) {
        $folder = $entry.Path; $access = $entry.Access
        $programDataWritable.Add($folder)
        $report.Add("PROGRAMDATA WRITABLE: $folder (execute=$($access.Executable))")
        if ($access.Sddl) { $report.Add("SDDL: $($access.Sddl)") }
        if ($access.Executable) {
            $programDataWriteExecute.Add($folder); $allWritableExecute.Add($folder)
            $report.Add("CUSTOMER-WRITABLE+EXECUTABLE: $folder")
        }
    }

    $programFilesWritableFolders = New-Object System.Collections.Generic.List[string]
    $programFilesWritableExecute = New-Object System.Collections.Generic.List[string]
    foreach ($root in @($programFiles, $programFilesX86)) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        $writeExecute = New-Object System.Collections.Generic.List[string]
        foreach ($entry in (Get-CustomerWritableDirectoryTree $root $principals)) {
            $folder = $entry.Path; $access = $entry.Access
            $programFilesWritableFolders.Add($folder)
            $report.Add("PROGRAM FILES CUSTOMER-WRITABLE: $folder (execute=$($access.Executable))")
            if ($access.Sddl) { $report.Add("SDDL: $($access.Sddl)") }
            if ($access.Executable) {
                $writeExecute.Add($folder); $programFilesWritableExecute.Add($folder); $allWritableExecute.Add($folder)
                $report.Add("CUSTOMER-WRITABLE+EXECUTABLE: $folder")
            }
        }
        if ($writeExecute.Count -eq 0) {
            $report.Add("PROGRAM FILES CUSTOMER-WRITABLE+EXECUTABLE: none under $root")
        } else {
            foreach ($folder in $writeExecute) { $report.Add("PROGRAM FILES CUSTOMER-WRITABLE+EXECUTABLE: $folder") }
        }
        if ($programFilesWritableFolders.Count -eq 0) { $report.Add("PROGRAM FILES CUSTOMER-WRITABLE FOLDERS: none under $root") }
    }

    $wipePath = Join-Path $DataPath "wipe"
    if (Test-Path -LiteralPath $wipePath -PathType Container) {
        $wipeAccess = Get-CustomerDirectoryAccess $wipePath $principals
        if (-not $wipeAccess.Writable) { throw "The installer-created Customer-writable folder '$wipePath' is not writable according to its ACL." }
        if (-not $programDataWritable.Contains($wipePath)) {
            $programDataWritable.Add($wipePath)
            $report.Add("PROGRAMDATA WRITABLE: $wipePath (execute=$($wipeAccess.Executable))")
            $report.Add("SDDL: $($wipeAccess.Sddl)")
        }
    }
    if ($programDataWritable.Count -eq 0) {
        $report.Add("PROGRAMDATA CUSTOMER-WRITABLE FOLDERS: none")
    }
    if ($programDataWriteExecute.Count -eq 0) {
        $report.Add("PROGRAMDATA CUSTOMER-WRITABLE+EXECUTABLE FOLDERS: none")
    }
    # Inventory all Customer-writable fixed-drive folders outside the standard deny roots.
    $unlistedWritableFolders = New-Object System.Collections.Generic.List[string]
    $unlistedWritableExecute = New-Object System.Collections.Generic.List[string]
    $systemDriveRoot = "$env:SystemDrive\"
    $coveredRoots = @($programFiles, $programFilesX86, $programData, "$env:SystemDrive\Users", $env:WINDIR)
    $fixedDrives = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue)
    foreach ($drive in $fixedDrives) {
        $driveRoot = "$($drive.DeviceID)\"
        $scanRoots = @()
        if ($driveRoot -eq $systemDriveRoot) {
            try {
                $rootAccess = Get-CustomerDirectoryAccess $driveRoot $principals
                if ($rootAccess.Writable) {
                    $unlistedWritableFolders.Add($driveRoot)
                    $report.Add("UNLISTED CUSTOMER-WRITABLE FIXED-DRIVE FOLDER: $driveRoot (execute=$($rootAccess.Executable))")
                    $report.Add("SDDL: $($rootAccess.Sddl)")
                    if ($rootAccess.Executable) { $unlistedWritableExecute.Add($driveRoot); $allWritableExecute.Add($driveRoot) }
                } else {
                    foreach ($child in [IO.Directory]::GetDirectories($driveRoot)) {
                        $isCovered = @($coveredRoots | Where-Object { $_ -and $child.TrimEnd('\') -ieq $_.TrimEnd('\') }).Count -gt 0
                        if (-not $isCovered) { $scanRoots += $child }
                    }
                }
            } catch {
                $script:scanDeniedFolders.Add($driveRoot)
                Write-Warning "Could not inspect fixed-drive root '$driveRoot'; not changed (scan inaccessible): $($_.Exception.Message)"
            }
        } else { $scanRoots = @($driveRoot) }
        foreach ($scanRoot in $scanRoots) {
            foreach ($entry in (Get-CustomerWritableDirectoryTree $scanRoot $principals)) {
                $folder = $entry.Path; $access = $entry.Access
                $unlistedWritableFolders.Add($folder)
                $report.Add("UNLISTED CUSTOMER-WRITABLE FIXED-DRIVE FOLDER: $folder (execute=$($access.Executable))")
                if ($access.Sddl) { $report.Add("SDDL: $($access.Sddl)") }
                if ($access.Executable) {
                    $unlistedWritableExecute.Add($folder); $allWritableExecute.Add($folder)
                    $report.Add("CUSTOMER-WRITABLE+EXECUTABLE: $folder")
                }
            }
        }
    }
    if ($unlistedWritableFolders.Count -eq 0) {
        $report.Add("UNLISTED CUSTOMER-WRITABLE FOLDERS ON FIXED DRIVES: none")
    }
    if ($unlistedWritableExecute.Count -eq 0) {
        $report.Add("UNLISTED CUSTOMER-WRITABLE+EXECUTABLE FOLDERS ON FIXED DRIVES: none")
    }
    $steamPaths = @(@($allWritableExecute) + @($programDataWritable) + @($programFilesWritableFolders) + @($unlistedWritableFolders) | Where-Object { $_ -match "(?i)(^|\\)SteamLibrary(\\|$)|(^|\\)steamapps(\\|$)" })
    if ($steamPaths.Count -eq 0) {
        $report.Add("CUSTOMER-WRITABLE+EXECUTABLE STEAM/LIBRARY FOLDERS: none found in scanned standard and fixed-drive scopes")
    } else {
        foreach ($folder in $steamPaths) { $report.Add("CUSTOMER-WRITABLE STEAM/GAME-LIBRARY FOLDER: $folder") }
    }
    $report.Add("")
    $report.Add("Profile and Public paths covered by %OSDRIVE%\Users\*: Customer profile (Desktop, Downloads, Documents, AppData and Temp) and C:\Users\Public.")
    $report.Add("Windows temporary path covered: $env:WINDIR\Temp\*")
    $removableDrives = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DeviceID)
    if ($removableDrives.Count -eq 0) { $report.Add("REMOVABLE DRIVES PRESENT DURING INVENTORY: none; %REMOVABLE%\* and %HOT%\* deny cover later insertions") }
    else { foreach ($drive in $removableDrives) { $report.Add("REMOVABLE DRIVE PRESENT: $drive (covered by %REMOVABLE%\*)") } }
    $report.Add("Removable paths covered: %REMOVABLE%\* (CD/DVD) and %HOT%\* (USB/removable storage).")
    foreach ($folder in @($script:scanDeniedFolders | Sort-Object -Unique)) {
        $report.Add("SCAN INACCESSIBLE (not changed): $folder")
    }
    # Owner choice: checked means Allow (default); unchecked means Block.
    $candidateFolders = @(@($programFilesWritableFolders) + @($unlistedWritableFolders) | Sort-Object -Unique)
    $allowedFolders = @()
    if ($allowFoldersWasSpecified) {
        $allowedFolders = @($AllowFolders -split ';' | ForEach-Object { $_.Trim().TrimEnd('\') } | Where-Object { $_ })
    } elseif ($candidateFolders.Count -gt 0) {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        $form = New-Object System.Windows.Forms.Form
        $form.Text = "Customer-writable folders"; $form.Width = 760; $form.Height = 520
        $form.StartPosition = "CenterScreen"; $form.TopMost = $true; $form.ControlBox = $false
        $label = New-Object System.Windows.Forms.Label
        $label.Text = "These folders are writable by Customer. Ticked = Allow (default); unticked = Block."
        $label.Left = 12; $label.Top = 12; $label.Width = 720; $label.Height = 38
        $list = New-Object System.Windows.Forms.CheckedListBox
        $list.Left = 12; $list.Top = 55; $list.Width = 720; $list.Height = 365; $list.CheckOnClick = $true
        foreach ($folder in $candidateFolders) { [void]$list.Items.Add($folder, $true) }
        $ok = New-Object System.Windows.Forms.Button
        $ok.Text = "OK"; $ok.Width = 100; $ok.Height = 32; $ok.Left = 632; $ok.Top = 430
        $ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Controls.AddRange(@($label, $list, $ok)); $form.AcceptButton = $ok
        $result = $form.ShowDialog()
        if ($result -ne [System.Windows.Forms.DialogResult]::OK) { throw "Owner folder selection was not confirmed." }
        $allowedFolders = @($list.CheckedItems | ForEach-Object { [string]$_ })
        $form.Dispose()
    }
    $allowedSet = @{}
    foreach ($folder in $allowedFolders) { $allowedSet[$folder.TrimEnd('\')] = $true }
    foreach ($folder in @($allowedFolders | Where-Object { $_ -notin $candidateFolders })) {
        $report.Add("ALLOW REQUEST NOT FOUND IN INVENTORY (not allowed): $folder")
    }
    $blockedFolders = @($candidateFolders | Where-Object { -not $allowedSet.ContainsKey($_.TrimEnd('\')) })
    foreach ($folder in $candidateFolders) {
        $decision = if ($allowedSet.ContainsKey($folder.TrimEnd('\'))) { "ALLOW" } else { "BLOCK" }
        $report.Add("OWNER DECISION: $decision : $folder")
    }
    $report.Add("OWNER ALLOW-FOLDERS ARGUMENT: $($allowedFolders -join '; ')")
    $report.Add("OWNER BLOCK-FOLDERS: $($blockedFolders -join '; ')")
    $report.Add("")
    [IO.File]::WriteAllLines($reportPath, $report.ToArray(), (New-Object Text.UTF8Encoding($false)))
    Get-Content -LiteralPath $reportPath | Write-Host

    $denyPaths = New-Object System.Collections.Generic.List[string]
    $denyPaths.Add("%OSDRIVE%\Users\*")
    $denyPaths.Add("$env:WINDIR\Temp\*")
    foreach ($folder in $programDataWritable) { $denyPaths.Add("$folder\*") }
    foreach ($folder in $blockedFolders) { $denyPaths.Add("$folder\*") }
    $denyPaths.Add("%REMOVABLE%\*")
    $denyPaths.Add("%HOT%\*")
    $denyPaths = @($denyPaths | Select-Object -Unique)

    $xml = New-Object System.Collections.Generic.List[string]
    $xml.Add('<?xml version="1.0" encoding="utf-8"?>')
    $xml.Add('<AppLockerPolicy Version="1">')
    foreach ($collection in @("Exe", "Msi", "Script", "Dll")) {
        $xml.Add('  <RuleCollection Type="' + $collection + '" EnforcementMode="Enabled">')
        $allowId = [guid]::NewGuid().ToString("D")
        $xml.Add('    <FilePathRule Id="' + $allowId + '" Name="Cafe D1 allow Everyone - ' + $collection + '" Description="Allow paths except Customer writable locations" UserOrGroupSid="S-1-1-0" Action="Allow">')
        $xml.Add('      <Conditions><FilePathCondition Path="*" /></Conditions>')
        $xml.Add('    </FilePathRule>')
        foreach ($path in $denyPaths) {
            $safePath = [Security.SecurityElement]::Escape($path)
            $denyId = [guid]::NewGuid().ToString("D")
            $xml.Add('    <FilePathRule Id="' + $denyId + '" Name="Cafe D1 deny Customer - ' + $collection + '" Description="Block Customer execution from writable folders" UserOrGroupSid="' + $CustomerSid + '" Action="Deny">')
            $xml.Add('      <Conditions><FilePathCondition Path="' + $safePath + '" /></Conditions>')
            $xml.Add('    </FilePathRule>')
        }
        $xml.Add("  </RuleCollection>")
    }
    # AppLocker requires an Appx rule collection whenever the Exe collection is enforced.
    # Keep signed packaged apps available; D1 adds no packaged-app deny rules.
    $appxId = [guid]::NewGuid().ToString("D")
    $xml.Add('  <RuleCollection Type="Appx" EnforcementMode="Enabled">')
    $xml.Add('    <FilePublisherRule Id="' + $appxId + '" Name="Cafe D1 allow Everyone - Appx" Description="Allow all signed packaged apps" UserOrGroupSid="S-1-1-0" Action="Allow">')
    $xml.Add('      <Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="0.0.0.0" HighSection="*" /></FilePublisherCondition></Conditions>')
    $xml.Add('    </FilePublisherRule>')
    $xml.Add('  </RuleCollection>')
    $xml.Add("</AppLockerPolicy>")
    $policyPath = Join-Path $DataPath "applocker-policy.xml"
    [IO.File]::WriteAllLines($policyPath, $xml.ToArray(), (New-Object Text.UTF8Encoding($false)))

    Set-AppIdStartupMode "Auto"
    Start-Service -Name AppIDSvc
    $running = Wait-ForService
    if (-not $running) { throw "Application Identity service did not start." }
    Start-AppLockerFilter
    foreach ($channel in $channels) {
        & wevtutil.exe sl $channel /e:true | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not enable AppLocker event channel $channel." }
    }
    $cacheDirectory = Join-Path $env:WINDIR "System32\AppLocker"
    $cacheNames = @("Exe.AppLocker", "Dll.AppLocker", "Msi.AppLocker", "Script.AppLocker", "Appx.AppLocker")
    function Wait-ForCompiledPolicy([datetime]$ImportStarted) {
        $deadline = (Get-Date).AddSeconds(30)
        do {
            $allFresh = $true
            foreach ($cacheName in $cacheNames) {
                $cacheFile = Join-Path $cacheDirectory $cacheName
                if (-not (Test-Path -LiteralPath $cacheFile -PathType Leaf) -or
                    (Get-Item -LiteralPath $cacheFile).LastWriteTimeUtc -lt $ImportStarted.ToUniversalTime().AddSeconds(-2)) {
                    $allFresh = $false
                    break
                }
            }
            if ($allFresh) { return $true }
            Start-Sleep -Milliseconds 500
        } while ((Get-Date) -lt $deadline)
        return $false
    }
    function Write-CompiledPolicyInventory([datetime]$ImportStarted, [string]$Attempt) {
        Write-Host "AppLocker compiled-policy inventory ($Attempt; import started $($ImportStarted.ToString('o')); captured $((Get-Date).ToString('o'))):"
        foreach ($cacheName in $cacheNames) {
            $cacheFile = Join-Path $cacheDirectory $cacheName
            if (Test-Path -LiteralPath $cacheFile -PathType Leaf) {
                $cacheItem = Get-Item -LiteralPath $cacheFile
                $fresh = $cacheItem.LastWriteTimeUtc -ge $ImportStarted.ToUniversalTime().AddSeconds(-2)
                Write-Host ("  {0}: exists=True; bytes={1}; createdUtc={2:o}; modifiedUtc={3:o}; modifiedSinceImport={4}" -f $cacheName, $cacheItem.Length, $cacheItem.CreationTimeUtc, $cacheItem.LastWriteTimeUtc, $fresh)
            } else {
                Write-Host ("  {0}: exists=False" -f $cacheName)
            }
        }
    }

    $policyInstallStarted = Get-Date
    Set-AppLockerPolicy -XmlPolicy $policyPath
    & "$env:WINDIR\System32\gpupdate.exe" /target:computer /force /wait:60 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Computer Group Policy refresh failed after applying AppLocker (gpupdate exit $LASTEXITCODE)." }
    $compiled = Wait-ForCompiledPolicy $policyInstallStarted
    Write-CompiledPolicyInventory $policyInstallStarted "first import"
    if (-not $compiled) {
        Write-Warning "AppLocker did not compile all five policy collections within 30 seconds; reapplying the policy once."
        $policyRetryStarted = Get-Date
        Set-AppLockerPolicy -XmlPolicy $policyPath
        & "$env:WINDIR\System32\gpupdate.exe" /target:computer /force /wait:60 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Computer Group Policy refresh failed after retrying AppLocker policy application (gpupdate exit $LASTEXITCODE)." }
        $compiled = Wait-ForCompiledPolicy $policyRetryStarted
        Write-CompiledPolicyInventory $policyRetryStarted "second import"
    }
    if (-not $compiled) {
        throw "AppLocker policy compilation failed: one or more of $($cacheNames -join ', ') were missing or stale after two 30-second application attempts. Installation is unsafe and has been stopped."
    }
    Write-Host "All five AppLocker policy collections were compiled after policy import."
    foreach ($channel in $channels) {
        $conversionEvents = @(Get-WinEvent -FilterHashtable @{ LogName = $channel; Id = @(8000, 8001, 8002, 8003); StartTime = $policyInstallStarted.AddSeconds(-2) } -ErrorAction SilentlyContinue)
        Write-Host "AppLocker policy-conversion/runtime events 8000-8003 in '$channel' since policy import: $($conversionEvents.Count)"
        foreach ($entry in $conversionEvents | Sort-Object TimeCreated) {
            Write-Host ("  EventId={0}; TimeCreated={1:o}; RecordId={2}; Level={3}; Message={4}" -f $entry.Id, $entry.TimeCreated, $entry.RecordId, $entry.LevelDisplayName, ($entry.Message -replace "[\r\n]+", " "))
        }
    }
    $applied = [xml](Get-AppLockerPolicy -Local -Xml)
    foreach ($type in @("Exe", "Msi", "Script", "Dll", "Appx")) {
        $collectionNode = @($applied.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq $type })
        if ($collectionNode.Count -ne 1 -or $collectionNode[0].EnforcementMode -ne "Enabled") {
            throw "AppLocker $type collection was not applied in Enforce mode."
        }
    }
    $appxCollection = @($applied.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq "Appx" })
    $appxAllow = @($appxCollection[0].FilePublisherRule | Where-Object { $_.Action -eq "Allow" -and $_.UserOrGroupSid -eq "S-1-1-0" -and $_.Conditions.FilePublisherCondition.PublisherName -eq "*" -and $_.Conditions.FilePublisherCondition.ProductName -eq "*" -and $_.Conditions.FilePublisherCondition.BinaryName -eq "*" }).Count -gt 0
    if ($appxCollection.Count -ne 1 -or -not $appxAllow) { throw "The required allow-only Appx rule collection was not applied." }
    Write-Host "AppLocker D1 enforced for Customer in Exe, Msi, Script and Dll; signed packaged apps remain allowed."
}

function Wait-ForService {
    for ($i = 0; $i -lt 20; $i++) {
        if ((Get-Service -Name AppIDSvc).Status -eq "Running") { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Start-AppLockerFilter {
    $filter = Get-CimInstance Win32_SystemDriver -Filter "Name='applockerfltr'" -ErrorAction SilentlyContinue
    if (-not $filter) { throw "The AppLocker filter driver (AppLockerFltr) is not installed." }
    if ($filter.State -ne "Running") {
        $appidtelPath = Join-Path $env:WINDIR "System32\appidtel.exe"
        if (-not (Test-Path -LiteralPath $appidtelPath)) {
            $appidtelCommand = Get-Command appidtel -ErrorAction SilentlyContinue
            if ($appidtelCommand) { $appidtelPath = $appidtelCommand.Source }
        }
        if (-not (Test-Path -LiteralPath $appidtelPath)) { throw "appidtel.exe was not found; cannot start the AppLocker filter driver." }
        & $appidtelPath start | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "appidtel start failed (exit $LASTEXITCODE)." }
    }
    for ($i = 0; $i -lt 20; $i++) {
        $filter = Get-CimInstance Win32_SystemDriver -Filter "Name='applockerfltr'" -ErrorAction SilentlyContinue
        if ($filter -and $filter.State -eq "Running") {
            Write-Host "AppLocker filter driver (AppLockerFltr) is running."
            return
        }
        Start-Sleep -Milliseconds 500
    }
    throw "AppLocker filter driver (AppLockerFltr) did not reach Running after appidtel start."
}

if ($Mode -eq "Uninstall") {
    Restore-OriginalState
    exit 0
}
Install-CustomerPolicy
