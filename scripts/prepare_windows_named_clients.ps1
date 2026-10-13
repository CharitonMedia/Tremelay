# Inert until the ordinary Windows workflow runs. No accounts or model turns.
# The pinned setup-python action provisions exact CPython into the runner toolcache.
# No unreviewed interpreter fallback or ad-hoc installer is used.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

if (-not $IsWindows -or $env:RUNNER_ARCH -ne 'X64' -or
    [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP) -or
    [string]::IsNullOrWhiteSpace($env:RUNNER_TOOL_CACHE) -or
    [string]::IsNullOrWhiteSpace($env:GITHUB_ENV)) {
    throw 'Named-client preparation requires a hosted Windows x64 runner.'
}
$repo = Split-Path -Parent $PSScriptRoot
$python = Join-Path $env:RUNNER_TOOL_CACHE 'Python\3.14.8\x64\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw 'Preparation unavailable: exact workflow-provisioned Python 3.14.8 x64 is missing; no native runtime was tested.'
}
$root = Join-Path $env:RUNNER_TEMP ('tremelay-named-' + [guid]::NewGuid().ToString('N'))
if ($root -match '[\r\n]') { throw 'Runner temporary path cannot be exported safely.' }
[void](New-Item -ItemType Directory -Path $root)
foreach ($name in @('home', 'appdata', 'localappdata', 'tmp', 'logs', 'claude', 'hermes', 'results')) {
    [void](New-Item -ItemType Directory -Path (Join-Path $root $name))
}
$childEnvironment = @{
    SYSTEMROOT = $env:SYSTEMROOT; WINDIR = $env:SYSTEMROOT
    PATH = (Join-Path $env:SYSTEMROOT 'System32') + ';' + $env:SYSTEMROOT
    HOME = (Join-Path $root 'home'); USERPROFILE = (Join-Path $root 'home')
    APPDATA = (Join-Path $root 'appdata'); LOCALAPPDATA = (Join-Path $root 'localappdata')
    TEMP = (Join-Path $root 'tmp'); TMP = (Join-Path $root 'tmp')
    PYTHONNOUSERSITE = '1'; PYTHONDONTWRITEBYTECODE = '1'
    # pip reads this even in --isolated mode; Windows os.devnull is exactly 'nul'.
    # --isolated alone still admits global/site pip.ini files.
    PIP_CONFIG_FILE = 'nul'
}
$script:processCounter = 0

function Invoke-BoundedProcess {
    param([string]$File, [string[]]$Arguments, [int]$TimeoutSeconds = 180)
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $File
    $info.WorkingDirectory = $root
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.CreateNoWindow = $true
    $info.Environment.Clear()
    foreach ($key in $childEnvironment.Keys) { $info.Environment[$key] = $childEnvironment[$key] }
    foreach ($argument in $Arguments) { [void]$info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    $streams = @()
    $started = $false
    try {
        $started = $process.Start()
        if (-not $started) { throw 'Preparation subprocess did not start.' }
        foreach ($reader in @($process.StandardOutput, $process.StandardError)) {
            $buffer = [byte[]]::new(8192)
            $stream = $reader.BaseStream
            $streams += @{
                Stream = $stream; Buffer = $buffer; Capture = [IO.MemoryStream]::new()
                Pending = $stream.ReadAsync($buffer, 0, $buffer.Length)
            }
        }
        $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        while (-not $process.HasExited -or $null -ne $streams[0].Pending -or $null -ne $streams[1].Pending) {
            if ([DateTime]::UtcNow -gt $deadline) { throw 'Preparation subprocess exceeded its deadline.' }
            foreach ($state in $streams) {
                if ($null -eq $state.Pending -or -not $state.Pending.IsCompleted) { continue }
                $count = $state.Pending.GetAwaiter().GetResult()
                if ($count -eq 0) { $state.Pending = $null; continue }
                if ($state.Capture.Length + $count -gt 262144) { throw 'Preparation capture exceeded its bound.' }
                $state.Capture.Write($state.Buffer, 0, $count)
                $state.Pending = $state.Stream.ReadAsync($state.Buffer, 0, $state.Buffer.Length)
            }
            Start-Sleep -Milliseconds 20
        }
        $process.WaitForExit()
        $stdout = [Text.Encoding]::UTF8.GetString($streams[0].Capture.ToArray())
        $stderr = [Text.Encoding]::UTF8.GetString($streams[1].Capture.ToArray())
        $script:processCounter++
        [IO.File]::WriteAllText((Join-Path $root "logs\prepare-$script:processCounter.log"), $stdout + $stderr)
        if ($process.ExitCode -ne 0) { throw 'Preparation subprocess failed; raw preparation output remains local.' }
        return $stdout
    } finally {
        if ($started -and -not $process.HasExited) {
            $process.Kill($true)
            if (-not $process.WaitForExit(5000)) { throw 'Preparation subprocess cleanup did not finish.' }
        }
        foreach ($state in $streams) { $state.Capture.Dispose() }
        $process.Dispose()
    }
}

function Get-PinnedFile {
    param([string]$URL, [string]$Destination, [long]$Size, [string]$SHA256)
    if (Test-Path -LiteralPath $Destination) { throw 'Preparation refuses to overwrite a downloaded asset.' }
    Invoke-WebRequest -Uri $URL -OutFile $Destination -MaximumRedirection 5 -TimeoutSec 180
    if ((Get-Item -LiteralPath $Destination).Length -ne $Size -or
        (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash -ine $SHA256) {
        throw 'Official asset differs from its exact reviewed size or SHA-256.'
    }
}

[void](Invoke-BoundedProcess $python @('-I', '-c',
    'import struct,sys; assert sys.version_info[:3] == (3,14,8) and struct.calcsize("P") == 8') 30)
$tar = Join-Path $env:SYSTEMROOT 'System32\tar.exe'
if (-not (Test-Path -LiteralPath $tar -PathType Leaf)) { throw 'Runner-provided archive reader is unavailable.' }

$codex = Join-Path $root 'codex.exe'
Get-PinnedFile 'https://github.com/openai/codex/releases/download/rust-v0.159.2/codex-x86_64-pc-windows-msvc.exe' `
    $codex 324702000 '52f75c649bebb8001102a1dd129c1ea6d02b0940321e6d7e82ee0526753bd58a'

$claudeArchive = Join-Path $root 'claude-code-win32-x64-2.1.296.tgz'
Get-PinnedFile 'https://registry.npmjs.org/@anthropic-ai/claude-code-win32-x64/-/claude-code-win32-x64-2.1.296.tgz' `
    $claudeArchive 117726124 'f04bb1c18698dc6562912a573b031306225f5e202df4fe6bd2317351f5e492c5'
$expectedClaudeSHA512 = [Convert]::ToHexString([Convert]::FromBase64String(
    'g2aYBzYM5YTDio0ulAoGIGgtGRMa08WAecer4wuOUrKPwVPRfyRdmoZI01BNS8jF9yupDmQycBMuBcVui/VGNw=='))
if ((Get-FileHash -LiteralPath $claudeArchive -Algorithm SHA512).Hash -ine $expectedClaudeSHA512) {
    throw 'Claude native archive differs from official registry integrity.'
}
[void](Invoke-BoundedProcess $tar @('-xzf', $claudeArchive, '-C', (Join-Path $root 'claude')) 60)
$claude = Join-Path $root 'claude\package\claude.exe'
if (-not (Test-Path -LiteralPath $claude -PathType Leaf)) { throw 'Pinned Claude native member is missing.' }

$hermesArchive = Join-Path $root 'hermes-71d34bad.tar.gz'
Get-PinnedFile 'https://codeload.github.com/NousResearch/hermes-agent/tar.gz/71d34bad1045610252eda02ee79549436896e784' `
    $hermesArchive 81181089 'a88ae3f634a3fd45050d3418d80b30ee5af51c89b9de40ec1ea3039d3024d77a'
[void](Invoke-BoundedProcess $tar @('-xzf', $hermesArchive, '-C', (Join-Path $root 'hermes')) 120)
$hermesSource = Join-Path $root 'hermes\hermes-agent-71d34bad1045610252eda02ee79549436896e784'
if (-not (Test-Path -LiteralPath (Join-Path $hermesSource 'tools\mcp_tool.py') -PathType Leaf)) {
    throw 'Pinned Hermes source member is missing.'
}
$venv = Join-Path $root 'hermes-venv'
[void](Invoke-BoundedProcess $python @('-I', '-m', 'venv', $venv) 120)
$hermesPython = Join-Path $venv 'Scripts\python.exe'
$lock = Join-Path $PSScriptRoot 'mcp_hermes_windows_lock.txt'
# Assert the documented null-file switch actually produces an empty isolated
# configuration before any pip network operation. No configuration is printed.
# A changed pip API/version must fail preparation rather than weaken isolation.
[void](Invoke-BoundedProcess $hermesPython @('-I', '-c',
    'import os; from pip._internal.configuration import Configuration; assert os.environ.get("PIP_CONFIG_FILE") == os.devnull; config = Configuration(isolated=True); config.load(); assert not list(config.items()); print("pip configuration isolation verified")') 30)
[void](Invoke-BoundedProcess $hermesPython @('-I', '-m', 'pip', '--isolated', '--disable-pip-version-check',
    'install', '--quiet', '--no-input', '--no-cache-dir', '--only-binary=:all:', '--require-hashes',
    '--index-url', 'https://pypi.org/simple', '-r', $lock) 300)
[void](Invoke-BoundedProcess $hermesPython @('-I', '-m', 'pip', '--isolated', '--disable-pip-version-check', 'check') 30)

$results = Join-Path $root 'results'
$driver = Join-Path $PSScriptRoot 'mcp_windows_named_client.py'
$testBinary = Join-Path $root 'tremelay-command.test.exe'
$git = (Get-Command git.exe -CommandType Application).Source
$source = (Invoke-BoundedProcess $git @('-C', $repo, 'rev-parse', 'HEAD') 20).Trim()
$tree = (Invoke-BoundedProcess $git @('-C', $repo, 'rev-parse', 'HEAD^{tree}') 20).Trim()
if ($source -notmatch '^[0-9a-f]{40}$' -or $tree -notmatch '^[0-9a-f]{40}$') { throw 'Source identity unavailable.' }
$record = @{
    schema = 1; status = 'preparation-only'; source_commit = $source; source_tree = $tree
    runner_image = $env:ImageOS; runner_image_version = $env:ImageVersion
    python_version = '3.14.8'; python_sha256 = (Get-FileHash -LiteralPath $python -Algorithm SHA256).Hash.ToLowerInvariant()
    python_provenance = 'pinned setup-python v6.3.0 with official python-versions manifest; version checked; executable hash observed; no binary-to-installer equivalence claim'
    codex_version = '0.159.2'; codex_sha256 = (Get-FileHash -LiteralPath $codex -Algorithm SHA256).Hash.ToLowerInvariant()
    claude_version = '2.1.296'; claude_archive_sha256 = (Get-FileHash -LiteralPath $claudeArchive -Algorithm SHA256).Hash.ToLowerInvariant()
    hermes_commit = '71d34bad1045610252eda02ee79549436896e784'
    hermes_archive_sha256 = (Get-FileHash -LiteralPath $hermesArchive -Algorithm SHA256).Hash.ToLowerInvariant()
    windows_wheel_lock_sha256 = (Get-FileHash -LiteralPath $lock -Algorithm SHA256).Hash.ToLowerInvariant()
    pip_configuration_empty = $true
    model_turns = 0; runtime_acceptance_performed = $false
}
[IO.File]::WriteAllText((Join-Path $results 'preparation.json'), ($record | ConvertTo-Json -Depth 4) + "`n", [Text.UTF8Encoding]::new($false))
[IO.File]::AppendAllLines($env:GITHUB_ENV, [string[]]@(
    "TREMELAY_TEST_WINDOWS_PYTHON=$python",
    "TREMELAY_TEST_WINDOWS_CODEX=$codex",
    "TREMELAY_TEST_WINDOWS_CLAUDE=$claude",
    "TREMELAY_TEST_WINDOWS_HERMES_PYTHON=$hermesPython",
    "TREMELAY_TEST_WINDOWS_HERMES_SOURCE=$hermesSource",
    "TREMELAY_TEST_WINDOWS_NAMED_DRIVER=$driver",
    "TREMELAY_TEST_WINDOWS_NAMED_TEST=$testBinary",
    "TREMELAY_TEST_WINDOWS_NAMED_RESULTS=$results"
), [Text.UTF8Encoding]::new($false))
Write-Host 'Prepared pinned native clients and an isolated hashed Windows wheel closure; no runtime acceptance claim.'
