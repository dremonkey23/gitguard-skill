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

# Build detection patterns at runtime (split to avoid static analysis false positives)
$p1  = "AK" + "IA[0-9A-Z]{16}"
$p2  = "gh" + "p_[0-9a-zA-Z]{36}"
$p3  = "github" + "_pat_[0-9a-zA-Z_]{82}"
$p4  = "sk" + "-[0-9a-zA-Z]{48}"
$p5  = "sk-ant" + "-api[0-9a-zA-Z\-]{90,}"
$p6  = "sk" + "_live_[0-9a-zA-Z]{24,}"
$p7  = "-----" + "BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
$p8  = "(postgres|mysql|mongodb|redis)://" + "[^:]+:[^@]{3,}@"
$p9  = "AI" + "za[0-9A-Za-z\-_]{35}"
$p10 = "xo" + "xb-[0-9a-zA-Z\-]{50,}"
$p11 = "xo" + "xp-[0-9a-zA-Z\-]{50,}"
$p12 = "AC[0-9a-f]{32}"
$p13 = "sk" + "_test_[0-9a-zA-Z]{24,}"
$p14 = "(?i)(api_key|apikey|api-key)\s*[=:]\s*['\`"]?[0-9a-zA-Z\-_]{20,}"
$p15 = "(?i)(secret_key|password|passwd)\s*[=:]\s*['\`"][0-9a-zA-Z\-_!@#\$%^&*]{8,}['\`"]"
$p16 = "ey" + "J[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"
$p17 = "(?i)Authorization:\s*Bearer\s+[0-9a-zA-Z\-_\.]{20,}"

$patterns = @(
    @{ Name = "AWS Access Key ID";              Pattern = $p1;  Severity = "CRITICAL" },
    @{ Name = "GitHub Token (Classic)";          Pattern = $p2;  Severity = "CRITICAL" },
    @{ Name = "GitHub Token (Fine-grained)";     Pattern = $p3;  Severity = "CRITICAL" },
    @{ Name = "OpenAI API Key";                  Pattern = $p4;  Severity = "CRITICAL" },
    @{ Name = "Anthropic API Key";               Pattern = $p5;  Severity = "CRITICAL" },
    @{ Name = "Stripe Live Secret Key";          Pattern = $p6;  Severity = "CRITICAL" },
    @{ Name = "Private Key Block";               Pattern = $p7;  Severity = "CRITICAL" },
    @{ Name = "Database URL with Credentials";   Pattern = $p8;  Severity = "CRITICAL" },
    @{ Name = "Google API Key";                  Pattern = $p9;  Severity = "HIGH" },
    @{ Name = "Slack Bot Token";                 Pattern = $p10; Severity = "HIGH" },
    @{ Name = "Slack User Token";                Pattern = $p11; Severity = "HIGH" },
    @{ Name = "Twilio Account SID";              Pattern = $p12; Severity = "HIGH" },
    @{ Name = "Stripe Test Key";                 Pattern = $p13; Severity = "HIGH" },
    @{ Name = "Generic API Key Assignment";      Pattern = $p14; Severity = "HIGH" },
    @{ Name = "Generic Secret Assignment";       Pattern = $p15; Severity = "HIGH" },
    @{ Name = "JWT Token";                       Pattern = $p16; Severity = "MEDIUM" },
    @{ Name = "Bearer Token";                    Pattern = $p17; Severity = "MEDIUM" }
)

# Extensions and directories to skip
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

# GitHub URL scanning
if ($Target -match "github\.com/([^/]+)/([^/\s]+)") {
    $owner = $Matches[1]
    $repo  = $Matches[2].TrimEnd('/')

    $headers = @{ "User-Agent" = "GitGuard-Skill/1.0" }
    if ($GithubToken) { $headers["Authorization"] = "token $GithubToken" }

    Write-Host "Fetching repo file tree from GitHub API..."
    try {
        $tree = Invoke-RestMethod -Uri "https://api.github.com/repos/$owner/$repo/git/trees/HEAD?recursive=1" -Headers $headers -ErrorAction Stop
    } catch {
        Write-Host "ERROR: Could not fetch repo. Check the URL or provide a GitHub token for private repos."
        Write-Host "  $_"
        exit 1
    }

    $files = $tree.tree | Where-Object { $_.type -eq "blob" -and -not (Test-ShouldSkip $_.path) }
    Write-Host "Files in repo: $($tree.tree.Count) | Scanning: $($files.Count) text files"
    Write-Host ""

    foreach ($file in $files) {
        $scannedFiles++
        Write-Progress -Activity "GitGuard scanning..." -Status $file.path -PercentComplete (($scannedFiles / $files.Count) * 100)
        try {
            $resp    = Invoke-RestMethod -Uri "https://api.github.com/repos/$owner/$repo/contents/$($file.path)" -Headers $headers -ErrorAction Stop
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(($resp.content -replace "`n","")))
            Invoke-ScanContent -Content $decoded -FilePath $file.path
        } catch {
            $skippedFiles++
        }
        if ($scannedFiles % 20 -eq 0) { Start-Sleep -Milliseconds 300 }
    }
    Write-Progress -Activity "GitGuard scanning..." -Completed
}
# Local directory scanning
elseif (Test-Path $Target) {
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
        } catch {
            $skippedFiles++
        }
    }
}
else {
    Write-Host "ERROR: Target must be a GitHub URL or an existing local path."
    Write-Host "  Examples:"
    Write-Host "    .\scan-repo.ps1 -Target https://github.com/owner/repo"
    Write-Host "    .\scan-repo.ps1 -Target C:\projects\myapp"
    exit 1
}

# Report
$severityOrder = @{ "CRITICAL" = 0; "HIGH" = 1; "MEDIUM" = 2 }
$sorted   = $findings | Sort-Object { $severityOrder[$_.Severity] }
$critical = ($findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$high     = ($findings | Where-Object { $_.Severity -eq "HIGH" }).Count
$medium   = ($findings | Where-Object { $_.Severity -eq "MEDIUM" }).Count
$deductions = ($critical * 20) + ($high * 10) + ($medium * 5)
$score    = [Math]::Max(0, 100 - $deductions)

Write-Host "================================================="
Write-Host "  GITGUARD REPORT"
Write-Host "================================================="
Write-Host "  Files scanned : $scannedFiles"
Write-Host "  Files skipped : $skippedFiles"
Write-Host "  Total findings: $($findings.Count)"
Write-Host "-------------------------------------------------"
Write-Host "  CRITICAL : $critical"
Write-Host "  HIGH     : $high"
Write-Host "  MEDIUM   : $medium"
Write-Host "================================================="

if ($findings.Count -eq 0) {
    Write-Host ""
    Write-Host "  No secrets detected. Repo looks clean!"
    Write-Host ""
    Write-Host "  GitGuard Score: 100 / 100"
} else {
    Write-Host ""
    foreach ($f in $sorted) {
        Write-Host "[$($f.Severity)] $($f.Type)"
        Write-Host "  File    : $($f.File)"
        Write-Host "  Line    : $($f.Line)"
        Write-Host "  Preview : $($f.Preview)"
        Write-Host ""
    }
    Write-Host "  GitGuard Score: $score / 100"
    Write-Host ""
    Write-Host "REMEDIATION STEPS:"
    Write-Host "  1. Rotate ALL exposed credentials immediately"
    Write-Host "  2. Move secrets to environment variables or a secrets manager"
    Write-Host "  3. Add .env and config files to .gitignore"
    Write-Host "  4. Use git-filter-repo to purge secrets from git history"
    Write-Host "  5. Enable GitHub secret scanning on the repository"
}

Write-Host ""
Write-Host "Powered by GitGuard | github.com/dremonkey23/gitguard-skill"
Write-Host ""
