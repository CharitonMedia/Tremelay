# Prepare an extraction-only, version-pinned GUI fixture on a hosted Windows runner.
# This does not execute the installer or configure GnuPG, a keyring, or gpg-agent.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $IsWindows -or [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP) -or
    [string]::IsNullOrWhiteSpace($env:GITHUB_ENV)) {
    throw 'The pinentry fixture requires Windows runner temporary storage and GITHUB_ENV.'
}
if (-not (Test-Path -LiteralPath $env:RUNNER_TEMP -PathType Container)) {
    throw 'The Windows runner temporary directory is unavailable.'
}

# Official package and SHA-256: https://gnupg.org/download/integrity_check.html
# Release: https://lists.gnupg.org/pipermail/gnupg-announce/2026q3/000516.html
$packageName = 'gnupg-w32-2.5.24_20260923.exe'
$packageURL = 'https://gnupg.org/ftp/gcrypt/binary/gnupg-w32-2.5.24_20260923.exe'
$packageSize = 5804864
$packageSHA256 = 'ea6f9dee2cccd83287432625b8b399173805add81d27067fcaf019c0c4da1ad8'
$sevenZip = Join-Path $env:ProgramFiles '7-Zip\7z.exe'
if (-not (Test-Path -LiteralPath $sevenZip -PathType Leaf)) {
    throw 'The runner-provided 7-Zip executable is unavailable; no software is installed by this fixture.'
}

$fixtureRoot = Join-Path $env:RUNNER_TEMP ('tremelay-gui-' + [guid]::NewGuid().ToString('N'))
if ($fixtureRoot -match '[\r\n]') {
    throw 'The Windows runner temporary path cannot be exported safely.'
}
[void](New-Item -ItemType Directory -Path $fixtureRoot)
$package = Join-Path $fixtureRoot $packageName
$payload = Join-Path $fixtureRoot 'payload'
Invoke-WebRequest -Uri $packageURL -OutFile $package -MaximumRedirection 0 -TimeoutSec 120
if ((Get-Item -LiteralPath $package).Length -ne $packageSize) {
    throw 'The pinned GnuPG package size does not match.'
}
if ((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash -ine $packageSHA256) {
    throw 'The pinned GnuPG package SHA-256 does not match.'
}

# 7-Zip reads the verified NSIS payload; never invoke the installer itself.
# Keep the extracted directory layout and same-package DLLs together.
& $sevenZip x $package "-o$payload" -y | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Extraction of the verified GnuPG package failed.'
}
$bin = Join-Path $payload 'bin'
foreach ($name in @('pinentry-basic.exe', 'libassuan-9.dll', 'libgpg-error-0.dll')) {
    $file = Join-Path $bin $name
    if (-not (Test-Path -LiteralPath $file -PathType Leaf) -or
        (Get-Item -LiteralPath $file).Length -eq 0) {
        throw "The verified GnuPG payload is missing required member $name."
    }
    Write-Host "$name SHA-256: $((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash)"
}

$helper = Join-Path $bin 'pinentry-basic.exe'
$cli = Join-Path $fixtureRoot 'tremelay.exe'
[IO.File]::AppendAllLines($env:GITHUB_ENV, [string[]]@(
    "TREMELAY_TEST_WINDOWS_PINENTRY=$helper",
    "TREMELAY_TEST_WINDOWS_CLI=$cli",
    'TREMELAY_TEST_WINDOWS_GUI_REQUIRED=1'
), [Text.UTF8Encoding]::new($false))
Write-Host "Prepared $packageName using its pinned official-source SHA-256; no signature verification is claimed."
