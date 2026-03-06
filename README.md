# envault

> **AES-256-GCM encrypted .env file manager.** Lock your secrets, share them safely with your team.

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Security](https://img.shields.io/badge/Crypto-AES--256--GCM-blue?style=flat-square)](#)

Stop storing `.env` files in Slack DMs, emails, or unencrypted S3 buckets.
**envault** lets you encrypt secrets locally and share them as a single copy-paste string or binary file — without a secrets server.

---

## Features

- **AES-256-GCM** encryption — authenticated, tamper-proof
- **PBKDF2-SHA256** key derivation (600,000 iterations — OWASP 2023)
- **Lock / Unlock** — encrypt and decrypt `.env` files
- **View** — inspect secrets in terminal without writing to disk (masked by default)
- **Share** — generate a portable base64 string or binary `.envshare` file
- **Pull** — import a shared secret file or string
- **CI/CD ready** — `ENVAULT_PASSWORD` env var support, no interactive prompts needed
- **Zero cloud dependencies** — everything runs locally

---

## Installation

```bash
pip install envault
```

Or from source:

```bash
git clone https://github.com/alikesk222/envault
cd envault
pip install -e .
```

---

## Quick Start

### Lock your .env

```bash
envault lock .env
# Creates .env.vault — commit this to git, keep .env in .gitignore
```

### Unlock on another machine

```bash
envault unlock .env.vault
# Recreates .env
```

### View secrets without writing to disk

```bash
envault view .env.vault
# Shows masked values: DATABASE_URL = po**************03

envault view .env.vault --show-values
# Shows actual values
```

### Share with a teammate

```bash
# Generate a copy-paste string
envault share .env --string
# Output: envault:aGVsbG8gd29ybGQ...

# Or generate a binary file
envault share .env
# Creates .env.envshare
```

### Pull (import) a shared secret

```bash
# From a file
envault pull team-secrets.envshare

# From a share string (paste interactively)
envault pull --string
```

---

## Workflow Examples

### Team onboarding

```bash
# Lead developer:
envault share .env --string
# Shares "envault:..." string via password manager / secure channel

# New developer:
envault pull --string
# Pastes the string, enters the password -> .env created
```

### Git-safe secrets

```bash
# .gitignore
.env
*.envshare

# Commit the vault (safe — encrypted)
git add .env.vault
git commit -m "chore: update vault"
```

### CI/CD (no interactive prompts)

```bash
# GitHub Actions / GitLab CI
export ENVAULT_PASSWORD=${{ secrets.VAULT_PASSWORD }}
envault unlock .env.vault --overwrite
```

### Multiple environments

```bash
envault lock .env.production --output production.vault
envault lock .env.staging --output staging.vault
envault unlock production.vault --output .env
```

---

## Security Details

| Property | Value |
|----------|-------|
| Encryption | AES-256-GCM |
| Authentication | GCM tag (128-bit) — detects tampering |
| Key Derivation | PBKDF2-HMAC-SHA256 |
| KDF Iterations | 600,000 (OWASP 2023 recommendation) |
| Salt | 256-bit random (per encryption) |
| Nonce | 96-bit random (per encryption) |
| File Header | Magic bytes + version for format validation |

The encrypted output is different every time (random salt + nonce), even with the same password and plaintext.

---

## Commands

```
envault lock    [ENV_FILE]   Encrypt .env -> .env.vault
envault unlock  [VAULT_FILE] Decrypt .env.vault -> .env
envault view    [VAULT_FILE] View secrets in terminal (no disk write)
envault share   [ENV_FILE]   Generate shareable string or .envshare file
envault pull    [SOURCE]     Import from share file or --string
```

All commands accept `--password` / `-p` or `ENVAULT_PASSWORD` env var.

---

## License

MIT — See [LICENSE](LICENSE)

---

> Built by [Ali Kesik](https://github.com/alikesk222)
