# 🔴 Sovereign Comms Agent (SCA)

## Overview

The Sovereign Comms Agent handles all inbound telecommunications — SMS and voice via Telnyx. It classifies investor intent using AI, executes actions through a governed pipeline, and logs every interaction to a hash-chained conversation ledger.

## Modules

| Module | File | Purpose |
|--------|------|---------|
| Inbound Router | `telecom/inboundRouter.ts` | Webhook routing and compliance filtering |
| AI Intent Engine | `telecom/aiIntentEngine.ts` | Natural language intent classification |
| Action Engine | `telecom/actionEngine.ts` | Intent-to-action execution |
| Response Composer | `telecom/responseComposer.ts` | Contextual response generation |
| Conversation Ledger | `telecom/conversationLedger.ts` | Hash-chained conversation log |
| Telecom Registry | `telecom/telecomRegistry.ts` | Carrier and number management |

## Message Flow

```
Investor SMS
     │
     ▼
Telnyx Webhook ──→ Cloudflare Edge ──→ Tunnel ──→ Webhook Validator
                                                        │
                                        ┌───────────────┘
                                        ▼
                                  Inbound Router
                                        │
                            ┌───────────┼───────────┐
                            ▼           ▼           ▼
                       Compliance   AI Intent    Direct Route
                       Keywords     Engine       (system cmds)
                       STOP/HELP    Classify
                            │           │           │
                            ▼           ▼           ▼
                       Auto Reply   Action Eng   Handler
                            │           │           │
                            └─────┬─────┘───────────┘
                                  ▼
                          Conversation Ledger
                                  │
                                  ▼
                          Response Composer ──→ Telnyx SMS Out
```

## Supported Intents

| Intent | Keyword | Tier | Action |
|--------|---------|------|--------|
| Onboarding | `ONBOARD` | 2 | Create session, generate access link |
| Fund | `FUND <SKU>` | 2 | Prepare funding packet, queue approval |
| Status | `STATUS` | 0 | Return session/document status |
| Help | `HELP` | 0 | Return available commands |
| Stop | `STOP` | 0 | Compliance opt-out (TCPA) |

## Compliance

The SCA enforces TCPA compliance:

- `STOP` → Immediate opt-out, no further messages
- `HELP` → Information response
- All messages logged with sender, recipient, timestamp
- Opt-out status tracked per number

## Conversation Ledger

Every inbound message and outbound response is recorded:

```json
{
  "sequence": 1,
  "timestamp": "2026-02-24T14:30:00.000Z",
  "direction": "inbound",
  "from": "+1234567890",
  "to": "+18446696333",
  "body": "ONBOARD",
  "intent": "ONBOARD",
  "tier": 2,
  "threadId": "thr_abc123",
  "previousHash": "0000000000000000",
  "hash": "a3f8c1d2..."
}
```

## Webhook Security

Inbound webhooks are protected by:

1. **Telnyx IP allowlisting** — only known Telnyx IPs accepted
2. **HMAC signature verification** — webhook body verified against secret
3. **Replay prevention** — timestamp window enforcement
4. **Rate limiting** — per-IP throttling on webhook endpoint
5. **Perimeter ledger logging** — all validation events recorded

---

**From The Hart** · [fthtrading.com](https://fthtrading.com)
