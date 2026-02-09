<#
.SYNOPSIS
    Organizes files from Downloads into categorized folders.

.DESCRIPTION
    Scans the Downloads folder and sorts files into category-based subfolders
    under ~\Organized\. Runs in dry-run mode by default.

.PARAMETER Confirm
    Actually execute the moves. Without this flag, only a preview is shown.

.PARAMETER Recurse
    Scan Downloads subfolders recursively.

.EXAMPLE
    .\Organize-Files.ps1              # Dry-run preview
    .\Organize-Files.ps1 -Confirm     # Execute moves
#>
[CmdletBinding(SupportsShouldProcess = $false)]
param(
    [switch]$Confirm,
    [switch]$Recurse
)

$SourceDir = "$env:USERPROFILE\Downloads"
$DestRoot  = "$env:USERPROFILE\Organized"
$LogFile   = "$DestRoot\organize-log.txt"

# Extension-to-category mapping
$CategoryMap = @{
    '.pdf'  = 'Documents'; '.docx' = 'Documents'; '.doc'  = 'Documents'
    '.xlsx' = 'Documents'; '.xls'  = 'Documents'; '.pptx' = 'Documents'
    '.csv'  = 'Documents'; '.txt'  = 'Documents'; '.rtf'  = 'Documents'

    '.png'  = 'Images'; '.jpg'  = 'Images'; '.jpeg' = 'Images'
    '.gif'  = 'Images'; '.bmp'  = 'Images'; '.svg'  = 'Images'
    '.webp' = 'Images'; '.ico'  = 'Images'

    '.mp4'  = 'Videos'; '.avi'  = 'Videos'; '.mkv'  = 'Videos'
    '.mov'  = 'Videos'; '.wmv'  = 'Videos'

    '.exe'  = 'Installers'; '.msi' = 'Installers'

    '.zip'  = 'Archives'; '.rar' = 'Archives'; '.7z'  = 'Archives'
    '.tar'  = 'Archives'; '.gz'  = 'Archives'
}

# System files to skip
$SkipFiles = @('desktop.ini', 'thumbs.db', 'ntuser.dat', 'ntuser.ini', 'ntuser.pol')

function Get-UniqueDestPath {
    param([string]$Folder, [string]$FileName)

    $dest = Join-Path $Folder $FileName
    if (-not (Test-Path $dest)) { return $dest }

    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
    $ext      = [System.IO.Path]::GetExtension($FileName)
    $counter  = 1

    do {
        $dest = Join-Path $Folder "$baseName ($counter)$ext"
        $counter++
    } while (Test-Path $dest)

    return $dest
}

# Gather files
$gciParams = @{ Path = $SourceDir; File = $true }
if ($Recurse) { $gciParams.Recurse = $true }

$files = Get-ChildItem @gciParams | Where-Object {
    $SkipFiles -notcontains $_.Name.ToLower() -and
    -not $_.Name.ToLower().StartsWith('ntuser')
}

if ($files.Count -eq 0) {
    Write-Host "No files found in $SourceDir"
    exit
}

# Ensure log directory exists when executing
if ($Confirm) {
    if (-not (Test-Path $DestRoot)) { New-Item -Path $DestRoot -ItemType Directory -Force | Out-Null }
}

$logEntries = @()
$moveCount  = @{}

foreach ($file in $files) {
    $ext = $file.Extension.ToLower()
    $category = if ($CategoryMap.ContainsKey($ext)) { $CategoryMap[$ext] } else { 'Other' }

    $targetDir  = Join-Path $DestRoot $category
    $destPath   = Get-UniqueDestPath -Folder $targetDir -FileName $file.Name
    $destName   = [System.IO.Path]::GetFileName($destPath)
    $timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    if (-not $moveCount.ContainsKey($category)) { $moveCount[$category] = 0 }
    $moveCount[$category]++

    if ($Confirm) {
        if (-not (Test-Path $targetDir)) { New-Item -Path $targetDir -ItemType Directory -Force | Out-Null }
        Move-Item -Path $file.FullName -Destination $destPath
        $logLine = "$timestamp  MOVED  $($file.Name) -> $category\$destName"
        $logEntries += $logLine
        Write-Host "  Moved: $($file.Name) -> $category\$destName"
    } else {
        Write-Host "  [DRY RUN] $($file.Name) -> $category\$destName"
    }
}

# Summary
Write-Host ""
Write-Host "--- Summary ---"
foreach ($cat in $moveCount.Keys | Sort-Object) {
    Write-Host "  $cat : $($moveCount[$cat]) file(s)"
}
Write-Host "  Total: $($files.Count) file(s)"

if ($Confirm) {
    # Write log
    $header = "=== Organize-Files run at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="
    ($header, $logEntries, "") | Out-File -FilePath $LogFile -Append -Encoding UTF8
    Write-Host ""
    Write-Host "Log written to $LogFile"
} else {
    Write-Host ""
    Write-Host "This was a dry run. Re-run with -Confirm to execute moves."
}
