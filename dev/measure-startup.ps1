param(
  [Parameter(Mandatory = $true)][string]$Exe,
  [string]$Title = "Mantel Debug",
  [int]$Runs = 5,
  [int]$IdleSeconds = 15
)
$ErrorActionPreference = "Stop"

Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class MantelWin {
  delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
  [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr lParam);
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hWnd);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int max);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
  public static bool Visible(HashSet<uint> pids, string title) {
    bool found = false;
    EnumWindows((h, l) => {
      uint pid; GetWindowThreadProcessId(h, out pid);
      if (!pids.Contains(pid) || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(256); GetWindowText(h, sb, 256);
      if (sb.ToString() == title) { found = true; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
"@

function Get-Tree([uint32]$root) {
  $all = Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId
  $tree = New-Object 'System.Collections.Generic.HashSet[uint32]'
  [void]$tree.Add($root)
  do {
    $added = $false
    foreach ($p in $all) {
      if ($tree.Contains([uint32]$p.ParentProcessId) -and $tree.Add([uint32]$p.ProcessId)) { $added = $true }
    }
  } while ($added)
  return $tree
}

function Measure-Once {
  $watch = [System.Diagnostics.Stopwatch]::StartNew()
  $proc = Start-Process -FilePath $Exe -PassThru
  $startup = $null
  $pids = New-Object 'System.Collections.Generic.HashSet[uint32]'
  [void]$pids.Add([uint32]$proc.Id)
  while ($watch.Elapsed.TotalSeconds -lt 60) {
    if ([MantelWin]::Visible($pids, $Title)) { $startup = $watch.ElapsedMilliseconds; break }
    Start-Sleep -Milliseconds 10
  }
  Start-Sleep -Seconds $IdleSeconds
  $tree = Get-Tree $proc.Id
  $procs = @(Get-Process -Id ([int[]]@($tree)) -ErrorAction SilentlyContinue)
  $ws = ($procs | Measure-Object WorkingSet64 -Sum).Sum / 1MB
  $private = ($procs | Measure-Object PrivateMemorySize64 -Sum).Sum / 1MB
  foreach ($p in $procs) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Seconds 2
  return [pscustomobject]@{ StartupMs = $startup; WorkingSetMB = [math]::Round($ws, 1); PrivateMB = [math]::Round($private, 1); Processes = $procs.Count }
}

[void](Measure-Once)  # Aufwärmen (erster Start legt Daten-/WebView-Ordner an)
$results = @(1..$Runs | ForEach-Object { Measure-Once })
$results | Format-Table -AutoSize | Out-String | Write-Output
function Median($values) { $sorted = @($values | Sort-Object); return $sorted[[int][math]::Floor(($sorted.Count - 1) / 2)] }
"Median: Start {0} ms, Working Set {1} MB, Private {2} MB, Prozesse {3}" -f (Median ($results.StartupMs)), (Median ($results.WorkingSetMB)), (Median ($results.PrivateMB)), (Median ($results.Processes))
