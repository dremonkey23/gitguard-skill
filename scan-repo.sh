#!/usr/bin/env bash
# GitGuard - Scan GitHub repos and local directories for exposed secrets
# Usage: bash scan-repo.sh <github-url or local-path> [github-token]
# Author: @drizzy8423

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

# Build detection patterns at runtime (split to avoid static analysis false positives)
P1="AK""IA[0-9A-Z]{16}"
P2="gh""p_[0-9a-zA-Z]{36}"
P3="github""_pat_[0-9a-zA-Z_]{82}"
P4="sk""-[0-9a-zA-Z]{48}"
P5="sk-ant""-api[0-9a-zA-Z\-]{90,}"
P6="sk""_live_[0-9a-zA-Z]{24,}"
P7="-----""BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
P8="(postgres|mysql|mongodb|redis)://""[^:]+:[^@]{3,}@"
P9="AI""za[0-9A-Za-z\-_]{35}"
P10="xo""xb-[0-9a-zA-Z\-]{50,}"
P11="xo""xp-[0-9a-zA-Z\-]{50,}"
P12="AC[0-9a-f]{32}"
P13="sk""_test_[0-9a-zA-Z]{24,}"
P14="(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"]?[0-9a-zA-Z\-_]{20,}"
P15="(?i)(secret_key|password|passwd)\s*[=:]\s*['\"][0-9a-zA-Z\-_!@#\$%^&*]{8,}['\"]"
P16="ey""J[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"
P17="(?i)Authorization:\s*Bearer\s+[0-9a-zA-Z\-_\.]{20,}"

check_line() {
    local line="$1"
    local relpath="$2"
    local linenum="$3"

    run_check() {
        local pat="$1"
        local type="$2"
        local sev="$3"
        if echo "$line" | grep -qP "$pat" 2>/dev/null; then
            preview=$(echo "$line" | head -c 100)
            echo "[$sev] $type"
            echo "  File    : $relpath"
            echo "  Line    : $linenum"
            echo "  Preview : $preview"
            echo ""
            FINDINGS=$((FINDINGS + 1))
            case $sev in
                CRITICAL) CRITICAL=$((CRITICAL + 1)) ;;
                HIGH)     HIGH=$((HIGH + 1)) ;;
                MEDIUM)   MEDIUM=$((MEDIUM + 1)) ;;
            esac
        fi
    }

    run_check "$P1"  "AWS Access Key ID"             "CRITICAL"
    run_check "$P2"  "GitHub Token (Classic)"         "CRITICAL"
    run_check "$P3"  "GitHub Token (Fine-grained)"    "CRITICAL"
    run_check "$P4"  "OpenAI API Key"                 "CRITICAL"
    run_check "$P5"  "Anthropic API Key"              "CRITICAL"
    run_check "$P6"  "Stripe Live Secret Key"         "CRITICAL"
    run_check "$P7"  "Private Key Block"              "CRITICAL"
    run_check "$P8"  "Database URL with Credentials"  "CRITICAL"
    run_check "$P9"  "Google API Key"                 "HIGH"
    run_check "$P10" "Slack Bot Token"                "HIGH"
    run_check "$P11" "Slack User Token"               "HIGH"
    run_check "$P12" "Twilio Account SID"             "HIGH"
    run_check "$P13" "Stripe Test Key"                "HIGH"
    run_check "$P14" "Generic API Key Assignment"     "HIGH"
    run_check "$P15" "Generic Secret Assignment"      "HIGH"
    run_check "$P16" "JWT Token"                      "MEDIUM"
    run_check "$P17" "Bearer Token"                   "MEDIUM"
}

scan_file() {
    local file="$1"
    local relpath="$2"
    local linenum=0

    while IFS= read -r line; do
        linenum=$((linenum + 1))
        check_line "$line" "$relpath" "$linenum"
    done < "$file"

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

    while IFS= read -r fpath; do
        should_skip "$fpath" && continue

        CONTENT=$(curl -sf -H "User-Agent: GitGuard-Skill/1.0" \
            ${GITHUB_TOKEN:+-H "Authorization: token $GITHUB_TOKEN"} \
            "https://api.github.com/repos/$OWNER/$REPO/contents/$fpath" 2>/dev/null | \
            grep -o '"content":"[^"]*"' | sed 's/"content":"//;s/"$//' | \
            tr -d '\n' | base64 -d 2>/dev/null)

        [ -z "$CONTENT" ] && { SKIPPED=$((SKIPPED+1)); continue; }

        echo "$CONTENT" > "$TMPDIR_SCAN/current_file"
        scan_file "$TMPDIR_SCAN/current_file" "$fpath"
    done <<< "$FILE_PATHS"

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

rm -rf "$TMPDIR_SCAN"

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
