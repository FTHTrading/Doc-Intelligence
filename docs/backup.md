# ⚙️ Backup & Recovery

## Overview

The backup agent creates encrypted archives of all ledger data at regular intervals. Each backup is independently verifiable and restorable.

## Configuration

| Parameter | Environment Variable | Default |
|-----------|---------------------|---------|
| Interval | `FTH_BACKUP_INTERVAL_MINUTES` | 15 |
| Encryption Key | `FTH_BACKUP_ENCRYPTION_KEY` | Required |
| Retention | `FTH_BACKUP_RETENTION_DAYS` | 30 |

## CLI Commands

```bash
# Create backup now
npx ts-node app.ts --backup-now

# Start daemon (every 15 min)
npx ts-node app.ts --backup-daemon

# List backups
npx ts-node app.ts --backup-list

# Verify integrity
npx ts-node app.ts --backup-verify <file>

# Restore (DESTRUCTIVE)
npx ts-node app.ts --backup-restore <file>

# Status
npx ts-node app.ts --backup-status
```

## Encryption

| Parameter | Value |
|-----------|-------|
| Algorithm | AES-256-GCM |
| Key Derivation | PBKDF2 |
| Iterations | 100,000 |
| Hash | SHA-512 |
| Salt | 32 bytes (random per backup) |
| IV | 16 bytes (random per backup) |
| Auth Tag | 16 bytes |

## Backup Archive Format

```
[salt:32][iv:16][authTag:16][ciphertext...]
```

Decrypted payload contains:
- **Manifest** — File inventory with individual SHA-256 hashes
- **Data** — All `.doc-engine/*.json` and `.txt` files
- **Integrity Hash** — SHA-256 of combined payload

## Backup Ledger

Every backup event is recorded in `.doc-engine/backup-ledger.json`:

| Event | Description |
|-------|-------------|
| `created` | Backup successfully created |
| `verified` | Backup integrity verified |
| `restored` | Data restored from backup |
| `pruned` | Expired backup removed |
| `failed` | Backup operation failed |

The backup ledger is itself hash-chained.

## Recovery Procedure

1. List available backups: `--backup-list`
2. Identify the target backup by timestamp
3. Verify integrity: `--backup-verify <file>`
4. Stop all services
5. Restore: `--backup-restore <file>`
6. Restart services
7. Verify ledger chain integrity across all ledgers

**Warning:** Restore is destructive — it overwrites current `.doc-engine/` data. Always verify the backup before restoring.

---

**From The Hart** · [fthtrading.com](https://fthtrading.com)
