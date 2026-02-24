# Deployment Guide

## Prerequisites

- Docker Engine 24+
- Docker Compose v2
- Cloudflare account with Zero Trust enabled
- Cloudflare Tunnel token
- Telnyx account with messaging profile
- IPFS/Kubo (bundled in Docker Compose)

---

## Quick Start

```bash
# Clone repository
git clone https://github.com/FTHTrading/Doc-Intelligence.git
cd Doc-Intelligence

# Configure environment
cp .env.example .env
```

Edit `.env` with your credentials:

```env
# Telecom
TELNYX_API_KEY=KEY_xxx
TELNYX_WEBHOOK_SECRET=whsec_xxx
TELNYX_MESSAGING_PROFILE=xxx

# Cloudflare
CLOUDFLARE_TUNNEL_TOKEN=eyJ...

# Backup
FTH_BACKUP_INTERVAL_MINUTES=15
FTH_BACKUP_ENCRYPTION_KEY=<generate-strong-key>
FTH_BACKUP_RETENTION_DAYS=30

# IPFS (optional — for swarm isolation)
IPFS_SWARM_KEY=<64-hex-chars>
```

---

## Deploy

```bash
# Build and start all services
docker compose up -d

# Verify all 4 services are running
docker compose ps

# Check engine logs
docker compose logs fth-engine --tail 50

# Check tunnel connection
docker compose logs cloudflared --tail 20
```

---

## Service Architecture

```
┌─────────────────────────────────────────────────────┐
│                 Docker Compose                       │
│                                                      │
│  ┌──────────────┐  ┌──────────────┐                 │
│  │  fth-engine   │  │  ipfs-kubo   │  fth-internal  │
│  │  (ports       │  │  (RPC 5001)  │  (bridge,      │
│  │   3001-3005)  │←→│  (GW 8081)   │   internal)    │
│  └──────┬───────┘  └──────────────┘                 │
│         │                                            │
│  ┌──────┴───────┐  ┌──────────────┐                 │
│  │  cloudflared  │  │  fth-backup  │                 │
│  │  (tunnel)     │  │  (daemon)    │  fth-tunnel    │
│  └──────────────┘  └──────────────┘  (bridge)       │
└─────────────────────────────────────────────────────┘
         │
         │ Cloudflare Tunnel (encrypted)
         │
┌────────┴────────┐
│  Cloudflare     │
│  Edge Network   │
│  (Zero Trust)   │
└─────────────────┘
```

### Services

| Service | Image | Purpose | Network |
|---------|-------|---------|---------|
| `fth-engine` | Custom build | Core engine — all application servers | `fth-internal` |
| `ipfs-kubo` | `ipfs/kubo:v0.33.2` | IPFS distributed storage node | `fth-internal` |
| `cloudflared` | `cloudflare/cloudflared:latest` | Tunnel daemon — zero exposed ports | `fth-internal` + `fth-tunnel` |
| `fth-backup` | Same as engine | Encrypted backup daemon | `fth-internal` |

### Networks

| Network | Type | Purpose |
|---------|------|---------|
| `fth-internal` | Bridge (internal) | Inter-service communication. No external access. |
| `fth-tunnel` | Bridge | Cloudflared outbound to Cloudflare edge. |

### Volumes

| Volume | Purpose |
|--------|---------|
| `fth-data` | Engine working data (`.doc-engine/`) |
| `fth-backups` | Encrypted backup archives |
| `ipfs-data` | IPFS block storage |
| `ipfs-staging` | IPFS staging area |

---

## Cloudflare Tunnel Setup

### 1. Create Tunnel

```bash
cloudflared tunnel create fth-doc-intelligence
```

### 2. Configure DNS Routes

In Cloudflare Dashboard, create CNAME records:

| Hostname | Target |
|----------|--------|
| `portal.fthtrading.com` | Tunnel → `fth-engine:3001` |
| `signing.fthtrading.com` | Tunnel → `fth-engine:3002` |
| `viewer.fthtrading.com` | Tunnel → `fth-engine:3003` |
| `webhook.fthtrading.com` | Tunnel → `fth-engine:3004` |
| `ops.fthtrading.com` | Tunnel → `fth-engine:3005` |

### 3. Configure Zero Trust Access

For each hostname, create an Access Application:

- **Authentication:** Email OTP
- **Allowed emails:** Whitelist only authorized users
- **Session duration:** 1 hour
- **Device posture:** Require managed device (optional)

### 4. Set Tunnel Token

Copy the tunnel token to `.env`:

```env
CLOUDFLARE_TUNNEL_TOKEN=eyJ...
```

---

## Verification Checklist

After deployment, verify each layer:

```bash
# Engine health
curl http://localhost:3001/health

# Tunnel status
npx ts-node app.ts --tunnel-status

# Perimeter integrity
npx ts-node app.ts --perimeter-ledger report

# Backup status
npx ts-node app.ts --backup-status

# Dashboard
npx ts-node app.ts --dashboard

# Determinism
npm run test:determinism
```

---

## Resource Limits

Default Docker Compose resource allocation:

| Service | Memory | CPU |
|---------|--------|-----|
| `fth-engine` | 2 GB | 2 cores |
| `ipfs-kubo` | Default | Default |
| `cloudflared` | Default | Default |
| `fth-backup` | Default | Default |

Adjust in `docker-compose.yml` under `deploy.resources.limits`.

---

## Updating

```bash
# Pull latest
git pull origin main

# Rebuild
docker compose build --no-cache fth-engine

# Rolling restart
docker compose up -d
```

---

## Backup Recovery

In the event of data loss:

```bash
# List available backups
npx ts-node app.ts --backup-list

# Verify backup integrity
npx ts-node app.ts --backup-verify <backup-file>

# Restore (DESTRUCTIVE — overwrites current data)
npx ts-node app.ts --backup-restore <backup-file>
```

Backups are encrypted with AES-256-GCM. The encryption key in `.env` must match the key used during backup creation.

---

**From The Hart** · [fthtrading.com](https://fthtrading.com)
