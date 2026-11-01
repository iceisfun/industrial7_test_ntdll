param([string]$Mode)
$ErrorActionPreference='Continue'
$src = Split-Path -Parent $MyInvocation.MyCommand.Path
$w = 'C:\i7\w'
Remove-Item -Recurse -Force $w -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$w\results" | Out-Null
Copy-Item "$src\build" "$w\build" -Recurse
$cred = $null
if ($Mode -eq 'std') {
  $pw = 'Aa1!' + [guid]::NewGuid().ToString('N').Substring(0,10)   # throwaway local account in a disposable VM; keep <=14 chars or net user prompts
  net user i7std $pw /add | Out-Null
  $sec = ConvertTo-SecureString $pw -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\i7std",$sec)
  icacls $w /grant 'Users:(OI)(CI)M' /T | Out-Null
}
function Com($s){ Write-Output $s }
Com "I7RES mode=$Mode"
if ($Mode -eq 'std') {
  $p = Start-Process -FilePath cmd.exe -ArgumentList '/c whoami /all > C:\i7\w\whoami.txt 2>&1' -Credential $cred -LoadUserProfile -WorkingDirectory $w -PassThru -WindowStyle Hidden
} else {
  $p = Start-Process -FilePath cmd.exe -ArgumentList '/c whoami /all > C:\i7\w\whoami.txt 2>&1' -WorkingDirectory $w -PassThru -WindowStyle Hidden
}
$p.WaitForExit(60000) | Out-Null
foreach($l in (Get-Content "$w\whoami.txt" -ErrorAction SilentlyContinue)){ Com "I7RES whoami $l" }
foreach($f in (Get-ChildItem "$w\build\*.exe" | Sort-Object Name)) {
  $a = $f.BaseName
  Com "I7RES start $a"
  $args2 = "/c $w\build\$a.exe > $w\results\$a.txt 2>&1"
  $sw = [Diagnostics.Stopwatch]::StartNew()
  try {
    if ($Mode -eq 'std') { $p = Start-Process -FilePath cmd.exe -ArgumentList $args2 -Credential $cred -LoadUserProfile -WorkingDirectory $w -PassThru -WindowStyle Hidden }
    else { $p = Start-Process -FilePath cmd.exe -ArgumentList $args2 -WorkingDirectory $w -PassThru -WindowStyle Hidden }
    $null = $p.Handle
    if (-not $p.WaitForExit(300000)) {
      Com "I7RES timeout $a"
      & taskkill /F /T /PID $p.Id | Out-Null
      $rc = 'TIMEOUT'
    } else { $rc = $p.ExitCode }
  } catch { $rc = "LAUNCHERR $_" }
  Com "I7RES end $a rc=$rc secs=$([int]$sw.Elapsed.TotalSeconds)"
  Com "I7RES begin $a"
  if (Test-Path "$w\results\$a.txt") { foreach($l in (Get-Content "$w\results\$a.txt")){ Com "I7RES | $l" } }
  Com "I7RES finish $a"
}
Com "I7RES done"
