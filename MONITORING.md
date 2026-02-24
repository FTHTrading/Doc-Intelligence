# Monitoring & Operations

## Operator Dashboard

The monitoring dashboard provides real-time visibility into all system layers from a single pane.

### Launch

```bash
npx ts-node app.ts --dashboard
```

Dashboard available at: `http://localhost:3005`

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | HTML dashboard (auto-refresh 10s) |
| `GET /dashboard` | HTML dashboard (alias) |
| `GET /api/snapshot` | JSON system snapshot |
| `GET /health` | Health check |

### Dashboard Sections

| Section | Metrics |
|---------|---------|
| **Engine** | Version, Node.js version, platform, memory usage, PID, uptime |
| **Cloudflare Tunnel** | State, connected since, route count |
| **Perimeter Security** | Total events, validation pass/fail, chain integrity, active IP blocks, recent alerts |
| **Rate Limiter** | Total checks, total blocked, block rate %, active tracked IPs |
| **Backup Agent** | Total backups, last backup time, last backup hash, daemon status |

### JSON Snapshot

```bash
npx ts-node app.ts --dashboard-snapshot
```

Returns a complete system state object suitable for programmatic monitoring.

---

## Backup Operations

### Backup Agent

The backup agent creates AES-256-GCM encrypted archives of all ledger data every 15 minutes.

| Command | Description |
|---------|-------------|
| `--backup-now` | Create backup immediately |
| `--backup-daemon` | Start automated backup daemon |
| `--backup-list` | List all available backups |
| `--backup-verify <file>` | Verify backup integrity |
| `--backup-restore <file>` | Restore from backup (destructive) |
| `--backup-status` | Show backup agent status |

### Backup Format

Each backup contains:

- **Manifest** — File inventory with individual SHA-256 hashes
- **Payload** — All `.doc-engine/*.json` and `.doc-engine/*.txt` files
- **Integrity Hash** — SHA-256 of combined payload
- **Encryption** — AES-256-GCM with PBKDF2-derived key (100k iterations)

### Backup Retention

- Default retention: **30 days**
- Configurable via `FTH_BACKUP_RETENTION_DAYS` in `.env`
- Automated pruning runs after each backup cycle

### Backup Ledger

All backup events are recorded in a hash-chained backup ledger at `.doc-engine/backup-ledger.json`. Events: `created`, `verified`, `restored`, `pruned`, `failed`.

---

## Perimeter Monitoring

### Perimeter Ledger

```bash
# Full report
npx ts-node app.ts --perimeter-ledger report

# Recent events (last 20)
npx ts-node app.ts --perimeter-ledger recent

# Filter by event type
npx ts-node app.ts --perimeter-ledger rate-limit-blocked
```

### Rate Limiter Status

```bash
npx ts-node app.ts --rate-limiter-status
```

### Chain Integrity

```bash
npx ts-node app.ts --verify-perimeter-chain
```

---

## Tunnel Monitoring

```bash
# Tunnel health
npx ts-node app.ts --tunnel-status

# Start tunnel
npx ts-node app.ts --tunnel-start

# Stop tunnel
npx ts-node app.ts --tunnel-stop
```

---

## Daily Operations Checklist

During pilot, perform these checks daily:

| # | Check | Command |
|---|-------|---------|
| 1 | Verify tunnel is connected | `--tunnel-status` |
| 2 | Check perimeter ledger chain | `--verify-perimeter-chain` |
| 3 | Review security events | `--perimeter-ledger recent` |
| 4 | Confirm backup status | `--backup-status` |
| 5 | Verify last backup integrity | `--backup-verify <latest>` |
| 6 | Check dashboard | `--dashboard` |
| 7 | Review signing sessions | `--session-status all` |
| 8 | Run determinism test | `npm run test:determinism` |

---

## Alerting

The current system does not include automated alerting. During pilot:

- **Check dashboard proactively** — do not wait for problems.
- **Review perimeter ledger daily** — look for unusual patterns.
- **Verify chain integrity** — any break indicates tampering.

Future iterations may add webhook-based alerting to Slack or email.

---

## Log Locations

| Log | Location |
|-----|----------|
| Perimeter events | `.doc-engine/perimeter-ledger.json` |
| Backup events | `.doc-engine/backup-ledger.json` |
| Access events | `.doc-engine/access-ledger.json` |
| Conversation log | `.doc-engine/conversation-ledger.json` |
| Lifecycle events | `.doc-engine/lifecycle-registry.json` |
| CID registry | `.doc-engine/cid-registry.json` |
| Signing sessions | `.doc-engine/signing-sessions.json` |

All ledgers use SHA-256 hash chaining. Integrity is verifiable.

---

**From The Hart** · [fthtrading.com](https://fthtrading.com)
