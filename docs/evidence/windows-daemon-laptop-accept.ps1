$ErrorActionPreference = 'Continue'
$d = Join-Path $env:TEMP ("trem3b-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory $d | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'tremelay.exe') $d
Set-Location $d
$exe = Join-Path $d 'tremelay.exe'
$b = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
$pass = [Convert]::ToBase64String($b)
$env:TREMELAY_PASSPHRASE = $pass
$env:TREMELAY_DAEMON_INSTANCE = 'accept3b'
[IO.File]::WriteAllText("$d\secret", 'dummy-demo-secret')
"== setup"
& $exe vault create --path "$d\v.db"
$cred = (& $exe credential put --path "$d\v.db" --label demo --type api_key --secret-file "$d\secret" 2>$null) | Select-Object -Last 1
Remove-Item "$d\secret"
$agent = (& $exe agent create --path "$d\v.db" --label claude-code --token-file "$d\cc.token" 2>$null) | Select-Object -First 1
"agent=$agent"
& $exe grant create --path "$d\v.db" --agent $agent --credential $cred --operation http_broker --resource https://httpbin.org/anything --method GET --inject bearer --expires 2027-01-01T00:00:00Z 2>&1 | Select-Object -Last 1
"== token file ACL"
(Get-Acl "$d\cc.token").Access | ForEach-Object { "$($_.IdentityReference) $($_.FileSystemRights) $($_.AccessControlType)" }
"== start daemon"
$p = Start-Process -FilePath $exe -ArgumentList @('daemon','--vault',"$d\v.db",'--idle-timeout','10m') -RedirectStandardOutput "$d\daemon.out" -RedirectStandardError "$d\daemon.err" -PassThru -WindowStyle Hidden
Start-Sleep 4
Get-Content "$d\daemon.out","$d\daemon.err"
"pipe present: " + [bool](Get-ChildItem \\.\pipe\ | Where-Object Name -like 'tremelay-*accept3b')
$env:TREMELAY_PASSPHRASE = $null
"== claude code through the daemon (no passphrase in its env)"
$cfg = @{ mcpServers = @{ tremelay = @{ command = $exe; args = @('mcp','--daemon','--token-file',"$d\cc.token"); env = @{ TREMELAY_DAEMON_INSTANCE = 'accept3b' } } } } | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText("$d\mcp.json", $cfg)
$prompt = "Use the tremelay MCP tools: call list_capabilities, then invoke_capability on the http_broker grant with a GET of https://httpbin.org/anything/windows-check. Reply in at most 4 lines: the HTTP status, the URL httpbin echoed, and the exact value of the Authorization header httpbin echoed (it should be redacted). Do not guess; if a call fails, quote the error."
$prompt | claude -p --strict-mcp-config --mcp-config "$d\mcp.json" "--allowedTools=mcp__tremelay__list_capabilities,mcp__tremelay__describe_capability,mcp__tremelay__invoke_capability"
"claude exit=$LASTEXITCODE"
"== raw MCP stdio client through the daemon (stand-in, no passphrase in env)"
$init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"accept3b","version":"0"}}}'
$note='{"jsonrpc":"2.0","method":"notifications/initialized"}'
$list='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_capabilities","arguments":{}}}'
$psi = New-Object Diagnostics.ProcessStartInfo $exe
$psi.Arguments = "mcp --daemon --token-file `"$d\cc.token`""
$psi.UseShellExecute = $false; $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
$pr = [Diagnostics.Process]::Start($psi)
function Send($line) { $pr.StandardInput.WriteLine($line); $pr.StandardInput.Flush() }
Send $init; $pr.StandardOutput.ReadLine()
Send $note; Send $list; $l2 = $pr.StandardOutput.ReadLine()
$l2.Substring(0, [Math]::Min(500, $l2.Length)) + '...'
$h = [regex]::Match($l2, '"handle":"([A-Za-z0-9+/=]{44})"').Groups[1].Value
"handle found: " + [bool]$h
$inv = @{jsonrpc='2.0';id=3;method='tools/call';params=@{name='invoke_capability';arguments=@{handle=$h;method='GET';path='/anything/windows-check'}}} | ConvertTo-Json -Depth 6 -Compress
Send $inv; $l3 = $pr.StandardOutput.ReadLine()
$l3.Substring(0, [Math]::Min(2500, $l3.Length))
$pr.StandardInput.Close(); $pr.WaitForExit(10000) | Out-Null
"mcp exit=$($pr.ExitCode) stderr=$($pr.StandardError.ReadToEnd().Trim())"
"== wrong token"
$b2 = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b2)
[IO.File]::WriteAllText("$d\bad.token", (($b2 | ForEach-Object { $_.ToString('x2') }) -join ''))
icacls "$d\bad.token" /setowner "$($env:USERNAME)" | Out-Null
icacls "$d\bad.token" /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null
'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}' | & $exe mcp --daemon --token-file "$d\bad.token"
"bad token exit=$LASTEXITCODE"
"== lock"
& $exe lock
"lock exit=$LASTEXITCODE"
Start-Sleep 2
"daemon exited: " + $p.HasExited
'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}' | & $exe mcp --daemon --token-file "$d\cc.token"
"after-lock exit=$LASTEXITCODE"
"== audit daemon_auth"
$env:TREMELAY_PASSPHRASE = $pass
& $exe audit list --path "$d\v.db" --action daemon_auth 2>$null
& $exe audit verify --path "$d\v.db" 2>$null
"== grep secret in everything"
"secret found in outputs/db: " + [bool](Select-String -Path "$d\*" -Pattern 'dummy-demo-secret' -SimpleMatch -Quiet)
$env:TREMELAY_PASSPHRASE = $null
if (-not $p.HasExited) { Stop-Process $p -Force }
Set-Location $env:TEMP
Remove-Item -Recurse -Force $d
"cleaned: " + -not (Test-Path $d)
