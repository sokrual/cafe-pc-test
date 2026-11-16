# DNS: every web address goes through the internet filter at -DnsServer (on the counter PC), so customers cannot reach
# blocked sites through another DNS server. Sets it on each network adapter with a route out and blocks DNS (53) and
# private DNS (853) to every other address and all of IPv6. INSTALL-PC runs it; the watchdog runs it again when the
# counter PC turns up at a new address (S5).
#Requires -RunAsAdministrator
param([Parameter(Mandatory)][string]$DnsServer, [string]$DataPath = "$env:ProgramData\GamingCafe")
$ErrorActionPreference = "Stop"
$ip = $DnsServer -as [ipaddress]
if (-not $ip -or $ip.AddressFamily -ne "InterNetwork") { throw "'$DnsServer' is not an IPv4 address." }
# Enumerate adapters individually; Get-NetIPConfiguration can fail to construct its NetAdapter CIM property
# when a Windows runner exposes multiple adapters.
$nics = @(Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
    $adapter = $_
    if (Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue) {
        [pscustomobject]@{ InterfaceIndex = $adapter.ifIndex; NetAdapter = $adapter }
    }
})
if (-not (Test-Path "$DataPath\dns-before.json")) {
    @($nics | ForEach-Object { # "servers" empty = the address came automatically from the router
        $static = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($_.NetAdapter.InterfaceGuid)").NameServer
        [pscustomobject]@{ index = $_.InterfaceIndex; servers = "$static" }
    }) | ConvertTo-Json | Set-Content "$DataPath\dns-before.json" -Encoding utf8
}
foreach ($n in $nics) { Set-DnsClientServerAddress -InterfaceIndex $n.InterfaceIndex -ServerAddresses $DnsServer }
$names = "Cafe: web addresses only through the counter PC (UDP)", "Cafe: web addresses only through the counter PC (TCP)"
Remove-NetFirewallRule -DisplayName $names -ErrorAction SilentlyContinue
$b = $ip.GetAddressBytes(); [array]::Reverse($b); $n = [BitConverter]::ToUInt32($b, 0)
function Ip($v) { $x = [BitConverter]::GetBytes([uint32]$v); [array]::Reverse($x); ([ipaddress]$x).ToString() }
$others = @("::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
if ($n -gt 0) { $others += "0.0.0.0-$(Ip ($n - 1))" }
if ($n -lt [uint32]::MaxValue) { $others += "$(Ip ($n + 1))-255.255.255.255" }
New-NetFirewallRule -Group "Cafe PC" -DisplayName $names[0] -Direction Outbound -Action Block -Profile Any -Protocol UDP -RemotePort 53, 853 -RemoteAddress $others | Out-Null
New-NetFirewallRule -Group "Cafe PC" -DisplayName $names[1] -Direction Outbound -Action Block -Profile Any -Protocol TCP -RemotePort 53, 853 -RemoteAddress $others | Out-Null
Clear-DnsClientCache
$DnsServer | Set-Content "$DataPath\dns-server.txt" -Encoding ascii   # last: it says the move is complete
Write-Host "DNS goes only to the internet filter at $DnsServer."
