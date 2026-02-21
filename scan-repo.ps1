# GitGuard - Scan GitHub repos and local directories for exposed secrets
# Usage: .\scan-repo.ps1 -Target <github-url or local-path> [-GithubToken <token>]
# Author: @drizzy8423

param(
    [Parameter(Mandatory=$true)]
    [string]$Target,
    [string]$GithubToken = ""
)

$ErrorActionPreference = "Continue"
$findings = @()
$scannedFiles = 0
$skippedFiles = 0

# Detection patterns — add your own or use defaults
# Format: @{ Name = "Label"; Pattern = "regex"; Severity = "CRITICAL|HIGH|MEDIUM" }
$customPatterns = @(
    # Add custom patterns here
)

# Default patterns loaded at runtime from config or environment
# Set GITGUARD_PATTERNS env var to a JSON file path to customize
$patternSource = $env:GITGUARD_PATTERNS
if ($patternSource -and (Test-Path $patternSource)) {
    $patterns = Get-Content $patternSource | ConvertFrom-Json
} elseif ($customPatterns.Count -gt 0) {
    $patterns = $customPatterns
} else {
    # Built-in defaults (common credential formats)
    $patterns = @(
        @{ Name = "Cloud Access Key";       Pattern = "^[A-Z]{4}[A-Z0-9]{16}$";   Severity = "CRITICAL" },
        @{ Name = "Service Token";          Pattern = "^[a-z]{2,4}_[a-zA-Z0-9]{24,}$"; Severity = "HIGH" },
        @{ Name = "Private Key Header";     Pattern = "BEGIN\s+\w+\s+PRIVATE KEY"; Severity = "CRITICAL" },
        @{ Name = "Database Connection";    Pattern = "\w+://\S+:\S+@\S+";         Severity = "CRITICAL" },
        @{ Name = "API Key Assignment";     Pattern = "(?i)(api.?key|token)\s*[=:]\s*['\`"][a-zA-Z0-9\-_]{20,}"; Severity = "HIGH" },
        @{ Name = "Password in Config";     Pattern = "(?i)(password|passwd|secret)\s*[=:]\s*['\`"][^\s]{8,}['\`"]"; Severity = "HIGH" }
    )
}

$skipExtensions = @('.jpg','.jpeg','.png','.gif','.svg','.ico','.pdf','.zip','.tar','.gz',
                    '.exe','.dll','.so','.dylib','.wasm','.min.js','.min.css','.map',
                    '.lock','.sum','.mod','.bin','.pyc')
$skipDirs = @('node_modules','.git','__pycache__','.next','dist','build',
              '.pytest_cache','vendor','.terraform','coverage')

function Test-ShouldSkip {
    param([string]$Path)
    $ext = [System.IO.Path]::GetExtension($Path).ToLower()
    if ($skipExtensions -contains $ext) { return $true }
    foreach ($dir in $skipDirs) {
        if ($Path -replace '\\','/' -match "/$dir/|/$dir$") { return $true }
    }
    return $false
}

function Invoke-ScanContent {
    param([string]$Content, [string]$FilePath)
    $lines = $Content -split "`n"
    $lineNum = 0
    foreach ($line in $lines) {
        $lineNum++
        foreach ($p in $patterns) {
            if ($line -match $p.Pattern) {
                $preview = $line.Trim()
                if ($preview.Length -gt 100) { $preview = $preview.Substring(0, 100) + "..." }
                $script:findings += [PSCustomObject]@{
                    Severity = $p.Severity
                    Type     = $p.Name
                    File     = $FilePath
                    Line     = $lineNum
                    Preview  = $preview
                }
            }
        }
    }
}

Write-Host ""
Write-Host "================================================="
Write-Host "  GitGuard - Secret Scanner"
Write-Host "  Target: $Target"
Write-Host "================================================="
Write-Host ""

if ($Target -match "github\.com/([^/]+)/([^/\s]+)") {
    $owner = $Matches[1]
    $repo  = $Matches[2].TrimEnd('/')
    $headers = @{ "User-Agent" = "GitGuard-Skill/1.0" }
    if ($GithubToken) { $headers["Authorization"] = "token $GithubToken" }

    Write-Host "Fetching repo file tree from GitHub API..."
    try {
        $tree = Invoke-RestMethod -Uri "https://api.github.com/repos/$owner/$repo/git/trees/HEAD?recursive=1" -Headers $headers -ErrorAction Stop
    } catch {
        Write-Host "ERROR: Could not fetch repo. $_"
        exit 1
    }

    $files = $tree.tree | Where-Object { $_.type -eq "blob" -and -not (Test-ShouldSkip $_.path) }
    Write-Host "Files in repo: $($tree.tree.Count) | Scanning: $($files.Count) text files"
    Write-Host ""

    foreach ($file in $files) {
        $scannedFiles++
        Write-Progress -Activity "Scanning..." -Status $file.path -PercentComplete (($scannedFiles / $files.Count) * 100)
        try {
            $resp    = Invoke-RestMethod -Uri "https://api.github.com/repos/$owner/$repo/contents/$($file.path)" -Headers $headers -ErrorAction Stop
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(($resp.content -replace "`n","")))
            Invoke-ScanContent -Content $decoded -FilePath $file.path
        } catch { $skippedFiles++ }
        if ($scannedFiles % 20 -eq 0) { Start-Sleep -Milliseconds 300 }
    }
    Write-Progress -Activity "Scanning..." -Completed

} elseif (Test-Path $Target) {
    $allFiles = Get-ChildItem -Path $Target -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { -not (Test-ShouldSkip $_.FullName) }
    Write-Host "Scanning $($allFiles.Count) files in: $Target"
    Write-Host ""
    foreach ($file in $allFiles) {
        $scannedFiles++
        try {
            $content = Get-Content -Path $file.FullName -Raw -Encoding UTF8 -ErrorAction Stop
            if ($content) {
                $rel = $file.FullName.Replace($Target, "").TrimStart('\','/')
                Invoke-ScanContent -Content $content -FilePath $rel
            }
        } catch { $skippedFiles++ }
    }
} else {
    Write-Host "ERROR: Target must be a GitHub URL or an existing local path."
    exit 1
}

$severityOrder = @{ "CRITICAL" = 0; "HIGH" = 1; "MEDIUM" = 2 }
$sorted   = $findings | Sort-Object { $severityOrder[$_.Severity] }
$critical = ($findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$high     = ($findings | Where-Object { $_.Severity -eq "HIGH" }).Count
$medium   = ($findings | Where-Object { $_.Severity -eq "MEDIUM" }).Count
$score    = [Math]::Max(0, 100 - ($critical * 20) - ($high * 10) - ($medium * 5))

Write-Host "================================================="
Write-Host "  GITGUARD REPORT"
Write-Host "================================================="
Write-Host "  Files scanned : $scannedFiles  |  Skipped: $skippedFiles"
Write-Host "  Findings      : $($findings.Count)  (CRITICAL: $critical  HIGH: $high  MEDIUM: $medium)"
Write-Host "================================================="

if ($findings.Count -eq 0) {
    Write-Host ""
    Write-Host "  No issues found. Score: 100 / 100"
} else {
    Write-Host ""
    foreach ($f in $sorted) {
        Write-Host "[$($f.Severity)] $($f.Type)"
        Write-Host "  File : $($f.File) (line $($f.Line))"
        Write-Host "  Hit  : $($f.Preview)"
        Write-Host ""
    }
    Write-Host "  Score: $score / 100"
    Write-Host ""
    Write-Host "  Next steps: rotate exposed credentials, use env vars, add to .gitignore"
}

Write-Host ""
Write-Host "Powered by GitGuard | github.com/dremonkey23/gitguard-skill"
Write-Host ""
