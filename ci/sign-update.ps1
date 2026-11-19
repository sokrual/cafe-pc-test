# Signs a gaming-PC update (PowerShell 7). update.json lists each file the gaming PCs install, with its SHA-256, and the
# version; update.sig is the ECDSA P-256 signature of update.json, made with the private key in UPDATE_SIGNING_KEY (a
# GitHub secret; base64 PKCS#8). A gaming PC installs an update only if the signature matches the public key built into
# its watchdog (pc/Cafe.Watchdog/FindUpdate.cs) and the version is newer than the one it has.
param([Parameter(Mandatory)][string]$Folder, [Parameter(Mandatory)][long]$Version)
$ErrorActionPreference = "Stop"
if (-not $env:UPDATE_SIGNING_KEY) { throw "UPDATE_SIGNING_KEY is not set, so the update cannot be signed." }
# one root string for both: TEMP can be a short 8.3 path (RUNNER~1) that Resolve-Path keeps but file names expand
$root = (Get-Item -LiteralPath $Folder).FullName.TrimEnd('\', '/')
$counterOnly = "update.json", "update.sig", "Cafe.Server.exe", "install-log.txt", "counter-address.txt", "server.pin"
$files = @(Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object { $counterOnly -notcontains $_.Name -and $_.Extension -ne ".token" } |
    Sort-Object FullName | ForEach-Object {
        [ordered]@{ path = [IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/'); sha256 = (Get-FileHash $_.FullName SHA256).Hash.ToLowerInvariant() }
    })
$bytes = [Text.Encoding]::UTF8.GetBytes(([ordered]@{ version = $Version; files = $files } | ConvertTo-Json -Depth 4 -Compress))
# byte[] APIs (Windows CNG): PowerShell cannot pass a byte[] to the Span-taking ImportPkcs8PrivateKey
$key = [Security.Cryptography.ECDsaCng]::new([Security.Cryptography.CngKey]::Import([Convert]::FromBase64String($env:UPDATE_SIGNING_KEY), [Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob))
# the gaming PCs check against the public half built into the watchdog: refuse to sign with a key that does not match it
$mine = [Convert]::ToBase64String($key.ExportSubjectPublicKeyInfo())
$built = [regex]::Match((Get-Content "$PSScriptRoot/../pc/Cafe.Watchdog/FindUpdate.cs" -Raw), 'PublicKey = "([^"]+)"').Groups[1].Value
if ($mine -ne $built -and -not $env:SIGN_UPDATE_TEST_OTHER_KEY) { throw "UPDATE_SIGNING_KEY does not match the public key in FindUpdate.cs.`nKey's public half: $mine`nIn FindUpdate.cs:   $built" }
[IO.File]::WriteAllBytes("$root/update.json", $bytes)
[IO.File]::WriteAllText("$root/update.sig", [Convert]::ToBase64String($key.SignData($bytes, [Security.Cryptography.HashAlgorithmName]::SHA256)))
Write-Host "Signed update version ${Version}: $($files.Count) files"
