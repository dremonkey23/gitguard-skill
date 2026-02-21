#!/usr/bin/env bash
# GitGuard - Scan GitHub repos and local directories for exposed secrets
# Usage: bash scan-repo.sh <github-url or local-path> [github-token]
# Author: Drizzy for Mirzayan LLC

TARGET="$1"
GITHUB_TOKEN="${2:-}"

if [ -z "$TARGET" ]; then
    echo "Usage: bash scan-repo.sh <github-url or local-path> [github-token]"
    echo ""
    echo "Examples:"
    echo "  bash scan-repo.sh https://github.com/owner/repo"
    echo "  bash scan-repo.sh /path/to/local/project"
    echo "  bash scan-repo.sh https://github.com/owner/repo ghp_yourtoken"
    exit 1
fi

FINDINGS=0
CRITICAL=0
HIGH=0
MEDIUM=0
SCANNED=0
SKIPPED=0
TMPDIR_SCAN=$(mktemp -d)

echo ""
echo "================================================="
echo "  GitGuard - Secret Scanner"
echo "  Target: $TARGET"
echo "================================================="
echo ""

SKIP_DIRS="node_modules|\.git|__pycache__|\.next|dist|build|vendor|\.terraform|coverage"
SKIP_EXT="\.(jpg|jpeg|png|gif|svg|ico|pdf|zip|tar|gz|exe|dll|so|dylib|wasm|lock|sum|bin|pyc|map|min\.js|min\.css)$"

scan_file() {
    local file="$1"
    local relpath="$2"
    local content

    content=$(cat "$file" 2>/dev/null) || return

    check_pattern() {
        local pattern="$1"
        local type="$2"
        local severity="$3"

        while IFS= read -r line_content; do
            linenum=$((linenum + 1))
            if echo "$line_content" | grep -qP "$pattern" 2>/dev/null; then
                preview=$(echo "$line_content" | head -c 100)
                echo "[$severity] $type"
                echo "  File    : $relpath"
                echo "  Line    : $linenum"
                echo "  Preview : $preview"
                echo ""
                FINDINGS=$((FINDINGS + 1))
                case $severity in
                    CRITICAL) CRITICAL=$((CRITICAL + 1)) ;;
                    HIGH)     HIGH=$((HIGH + 1)) ;;
                    MEDIUM)   MEDIUM=$((MEDIUM + 1)) ;;
                esac
            fi
        done <<< "$content"
        linenum=0
    }

    linenum=0
    check_pattern "AKIA[0-9A-Z]{16}" "AWS Access Key ID" "CRITICAL"
    check_pattern "ghp_[0-9a-zA-Z]{36}" "GitHub Token (Classic)" "CRITICAL"
    check_pattern "github_pat_[0-9a-zA-Z_]{82}" "GitHub Token (Fine-grained)" "CRITICAL"
    check_pattern "sk-[0-9a-zA-Z]{48}" "OpenAI API Key" "CRITICAL"
    check_pattern "sk-ant-api[0-9a-zA-Z\-]{90,}" "Anthropic API Key" "CRITICAL"
    check_pattern "sk_live_[0-9a-zA-Z]{24,}" "Stripe Live Secret Key" "CRITICAL"
    check_pattern "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----" "Private Key Block" "CRITICAL"
    check_pattern "(postgres|mysql|mongodb|redis)://[^:]+:[^@]{3,}@" "Database URL with Credentials" "CRITICAL"
    check_pattern "AIza[0-9A-Za-z\-_]{35}" "Google API Key" "HIGH"
    check_pattern "xoxb-[0-9a-zA-Z\-]{50,}" "Slack Bot Token" "HIGH"
    check_pattern "xoxp-[0-9a-zA-Z\-]{50,}" "Slack User Token" "HIGH"
    check_pattern "AC[0-9a-f]{32}" "Twilio Account SID" "HIGH"
    check_pattern "sk_test_[0-9a-zA-Z]{24,}" "Stripe Test Key" "HIGH"
    check_pattern "(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"]?[0-9a-zA-Z\-_]{20,}" "Generic API Key Assignment" "HIGH"
    check_pattern "(?i)(secret_key|password|passwd)\s*[=:]\s*['\"][0-9a-zA-Z\-_!@#\$%^&*]{8,}['\"]" "Generic Secret Assignment" "HIGH"
    check_pattern "eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+" "JWT Token" "MEDIUM"
    check_pattern "(?i)Authorization:\s*Bearer\s+[0-9a-zA-Z\-_\.]{20,}" "Bearer Token" "MEDIUM"

    SCANNED=$((SCANNED + 1))
}

should_skip() {
    local path="$1"
    echo "$path" | grep -qE "($SKIP_DIRS)/" && return 0
    echo "$path" | grep -qiE "$SKIP_EXT" && return 0
    return 1
}

# GitHub URL
if echo "$TARGET" | grep -qE "github\.com/([^/]+)/([^/]+)"; then
    OWNER=$(echo "$TARGET" | sed 's|.*github\.com/\([^/]*\)/\([^/]*\).*|\1|')
    REPO=$(echo "$TARGET" | sed 's|.*github\.com/[^/]*/\([^/]*\).*|\1|' | tr -d '/')

    AUTH_HEADER=""
    [ -n "$GITHUB_TOKEN" ] && AUTH_HEADER="-H \"Authorization: token $GITHUB_TOKEN\""

    echo "Fetching file tree from GitHub API..."

    TREE_JSON=$(curl -sf -H "User-Agent: GitGuard-Skill/1.0" \
        ${GITHUB_TOKEN:+-H "Authorization: token $GITHUB_TOKEN"} \
        "https://api.github.com/repos/$OWNER/$REPO/git/trees/HEAD?recursive=1") || {
        echo "ERROR: Could not fetch repo tree. Check URL or provide a GitHub token."
        exit 1
    }

    FILE_PATHS=$(echo "$TREE_JSON" | grep -o '"path":"[^"]*"' | sed 's/"path":"//;s/"//' | grep -v "^$")
    TOTAL=$(echo "$FILE_PATHS" | wc -l | tr -d ' ')
    echo "Files found: $TOTAL"
    echo ""

    echo "$FILE_PATHS" | while IFS= read -r fpath; do
        should_skip "$fpath" && continue

        ENCODED_PATH=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$fpath'))" 2>/dev/null || echo "$fpath")
        CONTENT=$(curl -sf -H "User-Agent: GitGuard-Skill/1.0" \
            ${GITHUB_TOKEN:+-H "Authorization: token $GITHUB_TOKEN"} \
            "https://api.github.com/repos/$OWNER/$REPO/contents/$fpath" 2>/dev/null | \
            grep -o '"content":"[^"]*"' | sed 's/"content":"//;s/"$//' | \
            tr -d '\n' | base64 -d 2>/dev/null)

        [ -z "$CONTENT" ] && { SKIPPED=$((SKIPPED+1)); continue; }

        echo "$CONTENT" > "$TMPDIR_SCAN/current_file"
        scan_file "$TMPDIR_SCAN/current_file" "$fpath"
    done

# Local directory
elif [ -d "$TARGET" ]; then
    echo "Scanning local directory: $TARGET"
    echo ""

    while IFS= read -r -d '' file; do
        relpath="${file#$TARGET/}"
        should_skip "$relpath" && continue
        scan_file "$file" "$relpath"
    done < <(find "$TARGET" -type f -print0 2>/dev/null)

else
    echo "ERROR: Target must be a GitHub URL or existing local directory."
    exit 1
fi

# Cleanup
rm -rf "$TMPDIR_SCAN"

# Score
DEDUCTIONS=$(( (CRITICAL * 20) + (HIGH * 10) + (MEDIUM * 5) ))
SCORE=$((100 - DEDUCTIONS))
[ $SCORE -lt 0 ] && SCORE=0

echo "================================================="
echo "  GITGUARD REPORT"
echo "================================================="
echo "  Files scanned : $SCANNED"
echo "  Files skipped : $SKIPPED"
echo "  Total findings: $FINDINGS"
echo "-------------------------------------------------"
echo "  CRITICAL : $CRITICAL"
echo "  HIGH     : $HIGH"
echo "  MEDIUM   : $MEDIUM"
echo "================================================="

if [ "$FINDINGS" -eq 0 ]; then
    echo ""
    echo "  No secrets detected. Repo looks clean!"
    echo ""
    echo "  GitGuard Score: 100 / 100"
else
    echo ""
    echo "  GitGuard Score: $SCORE / 100"
    echo ""
    echo "REMEDIATION STEPS:"
    echo "  1. Rotate ALL exposed credentials immediately"
    echo "  2. Move secrets to environment variables or a secrets manager"
    echo "  3. Add .env and config files to .gitignore"
    echo "  4. Use git-filter-repo to purge secrets from git history"
    echo "  5. Enable GitHub secret scanning on the repository"
fi

echo ""
echo "Powered by GitGuard | github.com/dremonkey23/gitguard-skill"
echo ""
