# System Flow Diagram

## End-to-End Document Lifecycle

```mermaid
flowchart TD
    A[Input File] --> B[Format Detector]
    B --> C{File Type}
    C -->|PDF| D[PDF Parser]
    C -->|DOCX| E[DOCX Parser]
    C -->|HTML| F[HTML Parser]
    C -->|Image| G[OCR Parser]
    C -->|TXT/MD| H[Text Parser]

    D --> I[Canonicalizer]
    E --> I
    F --> I
    G --> I
    H --> I

    I --> J[Governance Transform]
    J --> K[Compliance Transform]
    K --> L[Brand Transform]
    L --> M[Template Export]

    M --> N[Document Fingerprint]
    N --> O[Digital Signature]
    O --> P[Signature Certificate]
    P --> Q[AES-256-GCM Encryption]
    Q --> R[IPFS Push]
    R --> S[CID Registry]
    S --> T[Ledger Anchor]
    T --> U[Lifecycle Registry]

    style A fill:#1a1a2e,stroke:#C8A951,color:#fff
    style N fill:#1a1a2e,stroke:#C8A951,color:#fff
    style O fill:#1a1a2e,stroke:#C8A951,color:#fff
    style Q fill:#1a1a2e,stroke:#C8A951,color:#fff
    style U fill:#1a1a2e,stroke:#C8A951,color:#fff
```

## ASCII Version

```
Input File
    │
    ▼
Format Detector ──→ PDF Parser ──┐
                ──→ DOCX Parser ─┤
                ──→ HTML Parser ─┤
                ──→ OCR Parser  ─┤
                ──→ Text Parser ─┘
                                 │
                                 ▼
                          Canonicalizer
                                 │
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
              Governance    Compliance     Brand
              Transform     Transform    Transform
                    │            │            │
                    └────────────┼────────────┘
                                 │
                                 ▼
                          Template Export
                                 │
                                 ▼
                      Document Fingerprint
                                 │
                                 ▼
                       Digital Signature
                                 │
                                 ▼
                    Signature Certificate
                                 │
                                 ▼
                      AES-256-GCM Encrypt
                                 │
                                 ▼
                           IPFS Push
                                 │
                                 ▼
                         CID Registry
                                 │
                                 ▼
                        Ledger Anchor
                                 │
                                 ▼
                     Lifecycle Registry
```
