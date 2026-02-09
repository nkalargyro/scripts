<#
.SYNOPSIS
    Scans for common keylogger indicators on the local system.

.DESCRIPTION
    Checks for suspicious keyboard hooks, startup entries, hidden processes,
    and known keylogger signatures. Outputs a report of findings.

.PARAMETER LogPath
    Path to write the report. Defaults to ~/Organized/security-scan.txt

.EXAMPLE
    .\Detect-Keyloggers.ps1
#>
param(
    [string]$LogPath = "$env:USERPROFILE\Organized\security-scan.txt"
)

$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$findings = @()
$warningCount = 0

function Add-Finding {
    param([string]$Category, [string]$Severity, [string]$Detail)
    $script:findings += [PSCustomObject]@{
        Category = $Category
        Severity = $Severity
        Detail   = $Detail
    }
    if ($Severity -eq 'WARNING') { $script:warningCount++ }
}

Write-Host "=== Keylogger Detection Scan ===" -ForegroundColor Cyan
Write-Host "Started: $timestamp"
Write-Host ""

# -------------------------------------------------------
# 1. Check for processes using keyboard hook APIs
# -------------------------------------------------------
Write-Host "[1/6] Checking processes for keyboard hook modules..." -ForegroundColor Yellow

$suspiciousModules = @('hook', 'keylog', 'capture', 'sniff', 'monitor', 'spy', 'record')
$hookProcesses = @()

Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $proc = $_
        $proc.Modules | ForEach-Object {
            $modName = $_.ModuleName.ToLower()
            foreach ($term in $suspiciousModules) {
                if ($modName -like "*$term*") {
                    $hookProcesses += "$($proc.ProcessName) (PID $($proc.Id)) loaded $($_.ModuleName)"
                }
            }
        }
    } catch {}
}

if ($hookProcesses.Count -gt 0) {
    foreach ($hp in $hookProcesses) {
        Add-Finding 'Hook Modules' 'WARNING' $hp
        Write-Host "  ! $hp" -ForegroundColor Red
    }
} else {
    Add-Finding 'Hook Modules' 'OK' 'No suspicious hook-related modules found in running processes.'
    Write-Host "  OK - No suspicious modules detected" -ForegroundColor Green
}

# -------------------------------------------------------
# 2. Scan startup entries for unknown programs
# -------------------------------------------------------
Write-Host "[2/6] Checking startup entries..." -ForegroundColor Yellow

$startupPaths = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)

$startupEntries = @()
foreach ($path in $startupPaths) {
    if (Test-Path $path) {
        $props = Get-ItemProperty $path -ErrorAction SilentlyContinue
        $props.PSObject.Properties | Where-Object {
            $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$'
        } | ForEach-Object {
            $startupEntries += [PSCustomObject]@{
                Key   = $path
                Name  = $_.Name
                Value = $_.Value
            }
        }
    }
}

if ($startupEntries.Count -gt 0) {
    foreach ($entry in $startupEntries) {
        $shortKey = $entry.Key -replace 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\', 'HKCU\..\' `
                                -replace 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\', 'HKLM\..\'
        $line = "$shortKey -> $($entry.Name) = $($entry.Value)"
        Add-Finding 'Startup Entries' 'INFO' $line
        Write-Host "  i $($entry.Name): $($entry.Value)" -ForegroundColor Gray
    }
} else {
    Add-Finding 'Startup Entries' 'OK' 'No startup entries found.'
    Write-Host "  OK - No startup entries found" -ForegroundColor Green
}

# -------------------------------------------------------
# 3. Check for hidden or windowless processes with high uptime
# -------------------------------------------------------
Write-Host "[3/6] Checking for hidden/windowless background processes..." -ForegroundColor Yellow

$suspicious = Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $_.MainWindowHandle -eq 0 -and
    $_.SessionId -gt 0 -and
    $_.WorkingSet64 -lt 20MB -and
    $_.Path -and
    $_.Path -notmatch '\\(Windows|Microsoft|Program Files)\\' -and
    $_.Path -notmatch '\\(svchost|csrss|conhost|RuntimeBroker|dllhost|taskhostw|sihost)\.exe$'
}

if ($suspicious) {
    foreach ($proc in $suspicious) {
        $detail = "$($proc.ProcessName) (PID $($proc.Id)) - $($proc.Path)"
        Add-Finding 'Hidden Processes' 'INFO' $detail
        Write-Host "  i $($proc.ProcessName) PID:$($proc.Id) - $($proc.Path)" -ForegroundColor Gray
    }
} else {
    Add-Finding 'Hidden Processes' 'OK' 'No suspicious hidden processes found.'
    Write-Host "  OK - Nothing suspicious" -ForegroundColor Green
}

# -------------------------------------------------------
# 4. Check scheduled tasks for suspicious entries
# -------------------------------------------------------
Write-Host "[4/6] Checking scheduled tasks..." -ForegroundColor Yellow

$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.State -eq 'Ready' -or $_.State -eq 'Running'
} | ForEach-Object {
    $task = $_
    $action = ($task.Actions | Select-Object -First 1).Execute
    if ($action -and $action -notmatch '\\(Windows|Microsoft|system32)\\' -and $action -ne $null) {
        [PSCustomObject]@{
            Name   = $task.TaskName
            Path   = $task.TaskPath
            Action = $action
        }
    }
}

if ($tasks) {
    foreach ($t in $tasks) {
        $detail = "$($t.Path)$($t.Name) -> $($t.Action)"
        Add-Finding 'Scheduled Tasks' 'INFO' $detail
        Write-Host "  i $($t.Name): $($t.Action)" -ForegroundColor Gray
    }
} else {
    Add-Finding 'Scheduled Tasks' 'OK' 'No suspicious scheduled tasks found.'
    Write-Host "  OK - Nothing suspicious" -ForegroundColor Green
}

# -------------------------------------------------------
# 5. Scan common keylogger drop locations
# -------------------------------------------------------
Write-Host "[5/6] Scanning common drop locations for log files..." -ForegroundColor Yellow

$dropPaths = @(
    "$env:TEMP",
    "$env:APPDATA",
    "$env:LOCALAPPDATA\Temp"
)
$suspiciousPatterns = @('*keylog*', '*keystroke*', '*klog*', '*captured*', '*keystrokes*')
$dropFindings = @()

foreach ($dp in $dropPaths) {
    if (Test-Path $dp) {
        foreach ($pattern in $suspiciousPatterns) {
            $hits = Get-ChildItem $dp -Filter $pattern -File -ErrorAction SilentlyContinue
            foreach ($hit in $hits) {
                $dropFindings += $hit.FullName
            }
        }
    }
}

if ($dropFindings.Count -gt 0) {
    foreach ($df in $dropFindings) {
        Add-Finding 'Drop Locations' 'WARNING' $df
        Write-Host "  ! Found: $df" -ForegroundColor Red
    }
} else {
    Add-Finding 'Drop Locations' 'OK' 'No suspicious log files found in common drop locations.'
    Write-Host "  OK - No suspicious files" -ForegroundColor Green
}

# -------------------------------------------------------
# 6. Check Windows Defender threat history
# -------------------------------------------------------
Write-Host "[6/6] Checking Defender threat history..." -ForegroundColor Yellow

try {
    $threats = Get-MpThreatDetection -ErrorAction Stop | Select-Object -First 10
    if ($threats) {
        foreach ($t in $threats) {
            $detail = "ThreatID $($t.ThreatID) - $($t.ProcessName) at $($t.InitialDetectionTime)"
            Add-Finding 'Defender Threats' 'WARNING' $detail
            Write-Host "  ! $detail" -ForegroundColor Red
        }
    } else {
        Add-Finding 'Defender Threats' 'OK' 'No recent threat detections.'
        Write-Host "  OK - No recent threats" -ForegroundColor Green
    }
} catch {
    Add-Finding 'Defender Threats' 'INFO' 'Could not query Defender (may need admin privileges).'
    Write-Host "  i Could not query Defender (run as admin for full results)" -ForegroundColor Gray
}

# -------------------------------------------------------
# Report
# -------------------------------------------------------
Write-Host ""
Write-Host "=== Scan Complete ===" -ForegroundColor Cyan

if ($warningCount -gt 0) {
    Write-Host "$warningCount warning(s) found - review details above" -ForegroundColor Red
} else {
    Write-Host "No warnings. System looks clean." -ForegroundColor Green
}

# Write log
$logDir = Split-Path $LogPath -Parent
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }

$report = @()
$report += "=== Keylogger Detection Scan: $timestamp ==="
$report += ""
foreach ($f in $findings) {
    $report += "[$($f.Severity)] $($f.Category): $($f.Detail)"
}
$report += ""
$report += "Warnings: $warningCount"
$report += "========================================="
$report += ""

$report | Out-File -FilePath $LogPath -Append -Encoding UTF8
Write-Host "Report appended to $LogPath"
