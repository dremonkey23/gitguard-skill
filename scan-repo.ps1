# GitGuard - Scan GitHub repos and local directories for exposed secrets
# Usage: .\scan-repo.ps1 -Target <github-url or local-path> [-GithubToken <token>]
# Author: Drizzy for Mirzayan LLC

param(
    [Parameter(Mandatory=$true)]
    [string]$Target,
    [string]$GithubToken = ""
)

$ErrorActionPreference = "Continue"
$findings = @()
$scannedFiles = 0
$skippedFiles = 0

# Secret patterns to detect
$patterns = @(
    @{ Name = "AWS Access Key ID"; Pattern = "AKIA[0-9A-Z]{16}"; Severity = "CRITICAL" },
    @{ Name = "GitHub Token (Classic)"; Pattern = "ghp_[0-9a-zA-Z]{36}"; Severity = "CRITICAL" },
    @{ Name = "GitHub Token (Fine-grained)"; Pattern = "github_pat_[0-9a-zA-Z_]{82}"; Severity = "CRITICAL" },
    @{ Name = "OpenAI API Key"; Pattern = "sk-[0-9a-zA-Z]{48}"; Severity = "CRITICAL" },
    @{ Name = "Anthropic API Key"; Pattern = "sk-ant-api[0-9a-zA-Z\-]{90,}"; Severity = "CRITICAL" },
    @{ Name = "Stripe Live Secret Key"; Pattern = "sk_live_[0-9a-zA-Z]{24,}"; Severity = "CRITICAL" },
    @{ Name = "Private Key Block"; Pattern = "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"; Severity = "CRITICAL" },
    @{ Name = "Database URL with Credentials"; Pattern = "(postgres|mysql|mongodb|redis)://[^:]+:[^@]{3,}@"; Severity = "CRITICAL" },
    @{ Name = "Google API Key"; Pattern = "AIza[0-9A-Za-z\-_]{35}"; Severity = "HIGH" },
    @{ Name = "Slack Bot Token"; Pattern = "xoxb-[0-9a-zA-Z\-]{50,}"; Severity = "HIGH" },
    @{ Name = "Slack User Token"; Pattern = "xoxp-[0-9a-zA-Z\-]{50,}"; Severity = "HIGH" },
    @{ Name = "Twilio Account SID"; Pattern = "AC[0-9a-f]{32}"; Severity = "HIGH" },
    @{ Name = "Stripe Test Key"; Pattern = "sk_test_[0-9a-zA-Z]{24,}"; Severity = "HIGH" },
    @{ Name = "Generic API Key Assignment"; Pattern = "(?i)(api_key|apikey|api-key)\s*[=:]\s*['\`"]?[0-9a-zA-Z\-_]{20,}"; Severity = "HIGH" },
    @{ Name = "Generic Secret Assignment"; Pattern = "(?i)(secret_key|secret|password|passwd)\s*[=:]\s*['\`"][0-9a-zA-Z\-_!@#\$%^&*]{8,}['\`"]"; Severity = "HIGH" },
    @{ Name = "JWT Token"; Pattern = "eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"; Severity = "MEDIUM" },
    @{ Name = "Bearer Token"; Pattern = "(?i)Authorization:\s*Bearer\s+[0-9a-zA-Z\-_\.]{20,}"; Severity = "MEDIUM" }
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
