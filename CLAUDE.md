# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
cargo build          # Build the library
cargo test           # Run all tests
cargo test <name>    # Run a specific test (e.g., cargo test test_rbac)
cargo clippy         # Lint
cargo fmt            # Format code
```

Note: Tests generate RSA keys at runtime, so they take a few seconds.

## Architecture

This is a Rust JWT authentication library (`easy-auth-sdk`) that validates RS256-signed tokens and provides RBAC checks.

### Core Design

```
EasyAuth (main struct)
    ├── from_jwks_json() / from_pem()  → Initialize with public keys
    └── validate(&token)               → Decode token → Returns Claims

Claims (JWT payload struct)
    ├── is_subject(sub)                → Check subject → Returns bool
    └── allowed_domain_roles(&[roles]) → Check roles → Returns bool
```

**Key principle**: `validate()` decodes the token once and returns `Claims`. Then `is_subject()` and `allowed_domain_roles()` operate on `Claims` directly, returning booleans for easy OR/AND logic:

```rust
// Allow if subject matches OR user has admin role
if claims.is_subject("user-123") || claims.allowed_domain_roles(&["admin"]) {
    // Access granted
}
```

### Module Structure

- `lib.rs` - `EasyAuth` struct and public API
- `claims.rs` - `Claims` struct (JWT payload: `sub`, `domain_roles`, `exp`, `iat`)
- `error.rs` - `AuthError` enum using `thiserror`
- `jwks.rs` - JWKS JSON parsing, converts JWK to `DecodingKey`

### JWT Claims Format

```json
{
  "sub": "user-uuid",
  "domain_roles": ["domain:role", "product.feature:permission"],
  "exp": 1699999999
}
```

- `domain_roles` uses exact string matching
- Hierarchical permissions encoded in strings (e.g., `product_a.feature_x:admin`)

### Error Categories

- Token errors (401): `TokenExpired`, `InvalidSignature`, `InvalidToken`, `MissingClaim`
- Config errors (500): `InvalidKey`, `JsonError`

## Coding Standards

- All code must pass `cargo fmt` and `cargo clippy -- -D warnings` (enforced by CI).
- Use conventional commit messages: `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`. See @README.md Contributing section.

## CI/CD

- CI runs on push/PR to `main`: check, clippy, fmt, test. See @.github/workflows/ci.yml.
- Releases via release-please: conventional commits → auto PR → merge triggers publish to crates.io. See @.github/workflows/release.yml.
