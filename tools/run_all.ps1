param(
    [switch]$Destructive,
    [int]$TimeoutSeconds = 120,
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\build'),
    [string]$ResultsDir = ''
)
$ErrorActionPreference = 'Stop'
if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 3600) { throw 'TimeoutSeconds must be 1..3600' }
$BuildDir = (Resolve-Path $BuildDir).Path
if (!$ResultsDir) { $ResultsDir = Join-Path $BuildDir 'results' }
New-Item -ItemType Directory -Force $ResultsDir | Out-Null
$ResultsDir = (Resolve-Path $ResultsDir).Path
# An interrupted run must not leave an earlier successful manifest authoritative.
'[]' | Set-Content -LiteralPath (Join-Path $ResultsDir 'run.json') -Encoding UTF8
$rows = @()
foreach ($exe in (Get-ChildItem -LiteralPath $BuildDir -Filter '*.exe' | Sort-Object Name)) {
    if (!$Destructive -and $exe.BaseName.StartsWith('dx_')) { continue }
    $out = Join-Path $ResultsDir ($exe.BaseName + '.txt')
    $err = Join-Path $ResultsDir ($exe.BaseName + '.stderr.txt')
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $exe.FullName -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err
    $timedOut = !$process.WaitForExit($TimeoutSeconds * 1000)
    if ($timedOut) {
        # Kill the tree, not just the harness: a timed-out CHILD must not survive.
        $killer = Start-Process -FilePath 'taskkill.exe' -ArgumentList @('/PID', $process.Id, '/T', '/F') -PassThru -NoNewWindow
        if (!$killer.WaitForExit(10000)) { $killer.Kill() }
        if (!$process.WaitForExit(5000)) { throw "Unable to terminate $($exe.Name) process tree" }
    }
    $process.Refresh()
    $clock.Stop()
    $summary = @(Get-Content -LiteralPath $out | Where-Object { $_ -match '^SUMMARY\b' })
    $cleanSummary = $false
    if ($summary.Count -eq 1 -and $summary[0] -match '^SUMMARY tests=([1-9]\d*) failed=0 skipped=(\d+) checks_pass=\d+ checks_fail=0\s*$') {
        $cleanSummary = [long]$Matches[2] -le [long]$Matches[1]
    }
    $ok = !$timedOut -and $process.ExitCode -eq 0 -and $cleanSummary
    $rows += [pscustomobject]@{ area = $exe.BaseName; exitCode = $process.ExitCode; timeout = $timedOut; seconds = [math]::Round($clock.Elapsed.TotalSeconds, 3); summary = ($summary -join ''); ok = $ok }
    Write-Host "$($exe.BaseName): exit=$($process.ExitCode) timeout=$timedOut $($summary -join '')"
}
if (!$rows.Count) { throw 'No test executables found' }
ConvertTo-Json -InputObject @($rows) -Depth 4 | Set-Content -LiteralPath (Join-Path $ResultsDir 'run.json') -Encoding UTF8
if (@($rows | Where-Object { !$_.ok }).Count) { exit 1 }
exit 0
