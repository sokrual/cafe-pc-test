# Experiment: which no-restart step makes AppLocker actually block a program? Prints one line per attempt.
$ErrorActionPreference = "Stop"
sc.exe config AppIDSvc start= auto | Out-Null; Start-Service AppIDSvc
$user = "ProbeUser"; $rnd = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($rnd)
$pw = New-Object Security.SecureString; foreach ($c in ([Convert]::ToBase64String($rnd) + "Aa9!").ToCharArray()) { $pw.AppendChar($c) }
New-LocalUser $user -Password $pw | Out-Null; Add-LocalGroupMember -Group (Get-LocalGroup -SID "S-1-5-32-545").Name -Member $user
$cred = [pscredential]::new($user, $pw); $sid = (Get-LocalUser $user).SID.Value; $sys32 = "$env:WINDIR\System32"
$box = "C:\ProbeBox"; New-Item $box -ItemType Directory -Force | Out-Null; Copy-Item "$sys32\whoami.exe" "$box\probe.exe" -Force
# deny for the probe user AND for everyone else in the box, so we also learn whether a direct (non-runas) start is blocked
$deny = foreach ($s in $sid, "S-1-1-0") { "<FilePathRule Id=`"$([guid]::NewGuid())`" Name=`"d`" Description=`"`" UserOrGroupSid=`"$s`" Action=`"Deny`"><Conditions><FilePathCondition Path=`"$box\*`" /></Conditions></FilePathRule>" }
$allow = "<FilePathRule Id=`"$([guid]::NewGuid())`" Name=`"a`" Description=`"`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`"><Conditions><FilePathCondition Path=`"*`" /></Conditions></FilePathRule>"
"<AppLockerPolicy Version=`"1`"><RuleCollection Type=`"Exe`" EnforcementMode=`"Enabled`">$allow$($deny -join '')</RuleCollection></AppLockerPolicy>" | Out-File "$box\p.xml" -Encoding utf8
Set-AppLockerPolicy -XmlPolicy "$box\p.xml"; gpupdate /target:computer /force | Out-Null
function Probe($label) {
    $as = try { Start-Process "$box\probe.exe" -Credential $cred -WorkingDirectory $sys32 -WindowStyle Hidden -Wait; "RAN" } catch { "BLOCKED ($($_.Exception.Message))" }
    $me = try { & "$box\probe.exe" | Out-Null; "RAN" } catch { "BLOCKED ($($_.Exception.Message))" }
    $st = foreach ($s in "appidsvc", "appid", "applockerfltr") { "$s=" + ((sc.exe query $s | Select-String "STATE") -replace '.*:\s*\d+\s*', '') }
    Write-Host "PROBE | $label | as test user: $as | as admin: $me | $($st -join ' ')"
}
Probe "1 right after Set-AppLockerPolicy + gpupdate"
Start-Sleep 30; Probe "2 after waiting 30 s"
foreach ($d in "appid", "applockerfltr") { sc.exe start $d | Out-Null }; Start-Sleep 5; Probe "3 after sc start appid + applockerfltr"
Get-ScheduledTask -TaskPath "\Microsoft\Windows\AppID\" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "task: $($_.TaskName) $($_.State)"; Start-ScheduledTask -InputObject $_ }
Start-Sleep 15; Probe "4 after running the AppID scheduled tasks"
Restart-Service AppIDSvc -Force -ErrorAction SilentlyContinue; Start-Sleep 10; Probe "5 after restarting AppIDSvc"
Get-ChildItem "$sys32\AppLocker" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "file: $($_.Name) $($_.Length) $($_.LastWriteTime)" }
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 8 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "event $($_.Id): $($_.Message)" }
