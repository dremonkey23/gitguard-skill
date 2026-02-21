# GitGuard

Scan GitHub repositories and local directories for exposed secrets, API keys, tokens, and credentials before attackers find them first.

## When to use this skill

- Before making a GitHub repo public
- Auditing an existing repo for accidental credential exposure
- Scanning a local codebase or project directory
- Security review of client repositories
- Pre-commit or CI/CD security checks

## Usage

### Scan a GitHub repository (Windows)
```
Run scan-repo.ps1 -Target https://github.com/owner/repo
```

### Scan a local directory (Windows)
```
Run scan-repo.ps1 -Target C:\path\to\your\project
```

### With a GitHub token (for private repos or higher rate limits)
```
Run scan-repo.ps1 -Target https://github.com/owner/repo -GithubToken ghp_yourtoken
```

### Linux / macOS
```
bash scan-repo.sh https://github.com/owner/repo
bash scan-repo.sh /path/to/local/project
```

## What it detects

- AWS Access Keys and Secret Keys
- GitHub Personal Access Tokens (classic and fine-grained)
- OpenAI and Anthropic API Keys
- Google API Keys
- Stripe Live Keys
- Slack Tokens
- Twilio Credentials
- Private SSH/TLS Keys
- Database URLs with embedded credentials (Postgres, MySQL, MongoDB, Redis)
- JWT Tokens
- Generic API keys, secrets, and passwords
- Bearer tokens

## Output

Returns a scored report (0-100) with severity breakdown:
- **CRITICAL** — Rotate immediately (AWS keys, private keys, database creds)
- **HIGH** — Rotate soon (API keys, service tokens)
- **MEDIUM** — Review and assess (JWTs, generic patterns)

## Scripts

- `scan-repo.ps1` — Windows (PowerShell)
- `scan-repo.sh` — Linux/macOS (Bash)

## Notes

- GitHub API allows 60 requests/hour unauthenticated, 5000/hour with a token
- Binary files, images, and lock files are automatically skipped
- For large repos, provide a GitHub token to avoid rate limiting
