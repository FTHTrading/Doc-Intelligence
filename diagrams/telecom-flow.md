# Telecom Flow Diagram

## Inbound Message Processing

```mermaid
flowchart TD
    A[Investor SMS] --> B[Telnyx Webhook]
    B --> C[Cloudflare Edge]
    C --> D[Zero Trust Check]
    D --> E[Cloudflare Tunnel]
    E --> F[Webhook Validator]

    F -->|Invalid| G[Reject + Log]
    F -->|Valid| H[Inbound Router]

    H --> I{Intent Classification}

    I -->|STOP/HELP| J[Compliance Handler]
    I -->|ONBOARD/FUND| K[AI Intent Engine]
    I -->|STATUS| L[Status Handler]

    J --> M[Auto Reply]
    K --> N[Action Engine]
    L --> O[Query Response]

    N --> P{Governance Tier}
    P -->|Tier 0| Q[Execute Immediately]
    P -->|Tier 1| R[OTP Challenge]
    P -->|Tier 2| S[Queue for Approval]

    R --> T[Verify OTP]
    T -->|Pass| Q
    T -->|Fail| U[Reject]

    S --> V[Operator Dashboard]
    V -->|Approve| Q
    V -->|Reject| U

    Q --> W[Response Composer]
    M --> W
    O --> W
    U --> W

    W --> X[Conversation Ledger]
    X --> Y[Telnyx SMS Out]

    style A fill:#1a1a2e,stroke:#C8A951,color:#fff
    style F fill:#1a1a2e,stroke:#ff4444,color:#fff
    style P fill:#1a1a2e,stroke:#C8A951,color:#fff
    style X fill:#1a1a2e,stroke:#C8A951,color:#fff
```

## ASCII Version

```
Investor SMS
     │
     ▼
Telnyx Webhook ──→ Cloudflare Edge ──→ Zero Trust ──→ Tunnel
                                                        │
                                                        ▼
                                                 Webhook Validator
                                                   │          │
                                              INVALID       VALID
                                                │              │
                                           Reject+Log    Inbound Router
                                                              │
                                              ┌───────────────┼───────────────┐
                                              ▼               ▼               ▼
                                         Compliance      AI Intent        Status
                                         STOP/HELP       ONBOARD/FUND     Query
                                              │               │               │
                                              ▼               ▼               ▼
                                         Auto Reply     Action Engine    Query Resp
                                              │               │               │
                                              │          ┌────┼────┐          │
                                              │          ▼    ▼    ▼          │
                                              │        T0   T1   T2          │
                                              │        Auto OTP  Manual      │
                                              │          │    │    │          │
                                              └──────────┴────┴────┴──────────┘
                                                              │
                                                              ▼
                                                     Response Composer
                                                              │
                                                              ▼
                                                    Conversation Ledger
                                                              │
                                                              ▼
                                                       Telnyx SMS Out
```
