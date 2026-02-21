# GitGuard

**Scan GitHub repositories and local directories for exposed secrets before attackers find them first.**

Built for AI agents running on OpenClaw / LarryBrain. Drop it into your workflow to audit any codebase for leaked credentials, API keys, tokens, and passwords — in seconds.

---

## What It Detects

| Type | Severity |
|------|----------|
| AWS Access Key ID | CRITICAL |
| GitHub Personal Access Tokens | CRITICAL |
| OpenAI / Anthropic API Keys | CRITICAL |
| Stripe Live Secret Keys | CRITICAL |
| Private SSH / TLS Keys | CRITICAL |
| Database URLs with credentials | CRITICAL |
| Google API Keys | HIGH |
| Slack Tokens | HIGH |
| Twilio Account SIDs | HIGH |
| Generic API key / secret assignments | HIGH |
| JWT Tokens | MEDIUM |
| Bearer Tokens | MEDIUM |

---

## Quick Start

### Scan a GitHub repo (Windows)
```powershell
.\scan-repo.ps1 -Target https://github.com/owner/repo
```

### Scan a private repo (with token)
```powershell
.\scan-repo.ps1 -Target https://github.com/owner/repo -GithubToken ghp_yourtoken
```

### Scan a local directory (Windows)
```powershell
.\scan-repo.ps1 -Target C:\projects\myapp
```

### Linux / macOS
```bash
bash scan-repo.sh https://github.com/owner/repo
bash scan-repo.sh /path/to/local/project
```

---

## Output Example

```
=================================================
  GITGUARD REPORT
=================================================
  Files scanned : 12
  Files skipped : 3
  Total findings: 3
-------------------------------------------------
  CRITICAL : 1
  HIGH     : 2
  MEDIUM   : 0
=================================================

[CRITICAL] AWS Access Key ID
  File    : config/.env
  Line    : 7
  Preview : AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE

[HIGH] Generic API Key Assignment
  File    : src/api.js
  Line    : 14
  Preview : const apiKey = "sk-AbCdEfGhIjKlMnOp..."

  GitGuard Score: 0 / 100

REMEDIATION STEPS:
  1. Rotate ALL exposed credentials immediately
  2. Move secrets to environment variables or a secrets manager
  ...
```

---

## Scoring

| Score | Status |
|-------|--------|
| 100 | Clean — no secrets found |
| 80-99 | Low risk — review medium findings |
| 60-79 | Moderate risk — rotate high-severity creds |
| 0-59 | Critical — immediate action required |

---

## Notes

- GitHub API: 60 req/hour unauthenticated, 5000/hour with token
- Binary files, images, lock files, and build dirs skipped automatically
- For large repos, always provide a GitHub token

---

Built by [@drizzy8423](https://x.com/sheeptweetZ) | Powered by [LarryBrain](https://larrybrain.com)
