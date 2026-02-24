# Perimeter Flow Diagram

## Request Validation Chain

```mermaid
flowchart TD
    A[Inbound Request] --> B[Cloudflare Edge]

    B --> C{Zero Trust Policy}
    C -->|Denied| D[403 Blocked]
    C -->|Allowed| E[Cloudflare Tunnel]

    E --> F[Rate Limiter]
    F -->|Blocked| G[429 Rate Limited]
    F -->|Allowed| H{Request Type}

    H -->|Webhook| I[Webhook Validator]
    H -->|Viewer| J[Access Token Check]
    H -->|API| K[Auth Header Check]

    I --> L{HMAC Valid?}
    L -->|No| M[401 Invalid Signature]
    L -->|Yes| N{Replay Check}
    N -->|Replay| O[409 Replay Detected]
    N -->|Fresh| P[Route to Handler]

    J --> Q{Token Valid?}
    Q -->|No| R[401 Invalid Token]
    Q -->|Yes| S[OTP Challenge]
    S -->|Fail| T[401 OTP Failed]
    S -->|Pass| P

    K --> P

    P --> U[Application Layer]

    D --> V[Perimeter Ledger]
    G --> V
    M --> V
    O --> V
    R --> V
    T --> V
    U --> V

    style A fill:#1a1a2e,stroke:#C8A951,color:#fff
    style L fill:#1a1a2e,stroke:#ff4444,color:#fff
    style Q fill:#1a1a2e,stroke:#ff4444,color:#fff
    style V fill:#1a1a2e,stroke:#C8A951,color:#fff
```

## ASCII Version

```
Inbound Request
       │
       ▼
Cloudflare Edge
       │
       ▼
┌─────────────────┐
│  Zero Trust      │
│  Access Policy   │
└───┬─────────┬───┘
    │         │
  DENY      ALLOW
    │         │
    ▼         ▼
  403    Cloudflare Tunnel
              │
              ▼
       ┌──────────────┐
       │  Rate Limiter  │
       └──┬────────┬──┘
          │        │
       BLOCKED   ALLOWED
          │        │
          ▼        ▼
        429    Request Type?
               │    │    │
            Webhook Viewer API
               │    │    │
               ▼    ▼    ▼
            HMAC  Token  Auth
            Check Check  Check
               │    │    │
          ┌────┘    │    │
          ▼         ▼    │
      Replay?    OTP?    │
       │   │    │   │    │
     REPL FRESH FAIL PASS │
       │    │    │    │   │
       ▼    └────┴────┴───┘
     409          │
                  ▼
          Application Layer
                  │
                  ▼
          Perimeter Ledger
       (all events logged)
```

## Event Types Logged

| Event | HTTP Status | Severity |
|-------|:-----------:|----------|
| Zero Trust denied | 403 | `alert` |
| Rate limit blocked | 429 | `warning` |
| Invalid HMAC | 401 | `alert` |
| Replay detected | 409 | `critical` |
| Invalid token | 401 | `warning` |
| OTP failed | 401 | `warning` |
| Validation passed | 200 | `info` |
| Request routed | — | `info` |
