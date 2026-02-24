# Signing Flow Diagram

## Multi-Signature Ceremony

```mermaid
flowchart TD
    A[Signing Request] --> B[Create Session]
    B --> C[Register Signers]
    C --> D[Set Threshold]
    D --> E[Session Active]

    E --> F[Signer Connects]
    F --> G[Identity Verification]
    G --> H[Issue OTP Challenge]
    H --> I{OTP Valid?}

    I -->|No| J[Reject + Log]
    I -->|Yes| K[Present Document]

    K --> L[Display Hash]
    L --> M[Signer Applies Signature]
    M --> N[Record Signature]

    N --> O{Threshold Met?}
    O -->|No| F
    O -->|Yes| P[Generate Certificate]

    P --> Q[ESIGN/UETA Certificate]
    Q --> R[Update Access Ledger]
    R --> S[Update Conversation Ledger]
    S --> T[Update Perimeter Ledger]
    T --> U[Distribution Engine]
    U --> V[Session Complete]

    style A fill:#1a1a2e,stroke:#C8A951,color:#fff
    style I fill:#1a1a2e,stroke:#ff4444,color:#fff
    style O fill:#1a1a2e,stroke:#C8A951,color:#fff
    style Q fill:#1a1a2e,stroke:#C8A951,color:#fff
```

## ASCII Version

```
Signing Request
       │
       ▼
┌─────────────────┐
│  Create Session  │
│  Session ID      │
│  Document Hash   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Register Signers │
│ Set Threshold    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Session Active  │◄────────────────┐
└────────┬────────┘                  │
         │                           │
         ▼                           │
┌─────────────────┐                  │
│  OTP Challenge   │                  │
└────────┬────────┘                  │
         │                           │
    ┌────┴────┐                      │
    ▼         ▼                      │
  FAIL      PASS                     │
    │         │                      │
    ▼         ▼                      │
  Reject   Sign Document             │
    │         │                      │
    │         ▼                      │
    │    Threshold Met? ──── NO ─────┘
    │         │
    │        YES
    │         │
    │         ▼
    │   ┌─────────────────┐
    │   │  Generate Cert   │
    │   │  ESIGN/UETA      │
    │   └────────┬────────┘
    │            │
    │            ▼
    │   ┌─────────────────┐
    │   │  Log to Ledgers  │
    │   │  Access           │
    │   │  Conversation     │
    │   │  Perimeter        │
    │   └────────┬────────┘
    │            │
    │            ▼
    └──→ Session Complete
```
