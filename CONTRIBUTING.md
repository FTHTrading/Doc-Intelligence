# Contributing

## Development Standards

Doc-Intelligence is institutional-grade infrastructure. Contributions must meet the same standard.

### Requirements

- TypeScript strict mode (`"strict": true`)
- ES2020 target, CommonJS modules
- No `any` types without explicit justification
- All new modules must be deterministic — identical input produces identical output
- Every ledger entry must be hash-chained

### Code Style

- 2-space indentation
- Explicit return types on all exported functions
- JSDoc comments on all public interfaces and exported functions
- No third-party dependencies without security review

### Testing

All changes must pass the determinism test suite:

```bash
npm run test:determinism
```

Results required: **10/10 tests, 20,000 hash computations, zero drift.**

### Commit Messages

Use conventional commits:

```
feat(signing): add multi-sig threshold validation
fix(perimeter): correct rate limiter window calculation
docs(security): update threat model for OTP enforcement
```

### Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Implement changes with tests
4. Run `npx tsc --noEmit` — must compile clean
5. Run `npm run test:determinism` — must pass 10/10
6. Submit PR with description of changes and security implications

### Security-Sensitive Changes

Any change touching the following modules requires explicit security review:

- `sovereign/` — Encryption, IPFS, backup
- `gateway/` — Signing, OTP
- `sdc/` — Access control, watermarking
- `perimeter/` — Rate limiting, webhook validation
- `telecom/` — Inbound routing, conversation handling

### What We Do Not Accept

- Dependencies with known CVEs
- Code that introduces non-determinism
- Changes that weaken any security control
- Marketing language in documentation

---

## Architecture Decisions

Major architectural decisions are documented inline. If your contribution changes system architecture, update [ARCHITECTURE.md](ARCHITECTURE.md) accordingly.

---

**From The Hart** · [fthtrading.com](https://fthtrading.com)
