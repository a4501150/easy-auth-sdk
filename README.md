# easy-auth-sdk

A Rust JWT authentication library with RBAC (Role-Based Access Control) support.

## Features

- JWT token validation with RS256 algorithm
- RBAC: Check if claims contain required domain roles
- Subject matching: Verify token ownership
- Supports JWKS and PEM public key formats
- Automatic expiration validation

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
easy-auth-sdk = "0.1"
```

## JWT Claims Structure

The SDK expects JWT tokens with the following claims:

```json
{
  "sub": "295fafbb-7da3-4881-858f-e6ea5d2b65ae",
  "domain_roles": ["example:admin", "moon:user"],
  "exp": 1699999999,
  "iat": 1699990000
}
```

| Claim | Type | Description |
|-------|------|-------------|
| `sub` | string | User identifier (typically UUID) |
| `domain_roles` | string[] | Array of `domain:role` pairs (optional, defaults to empty) |
| `exp` | number | Expiration timestamp (validated automatically) |
| `iat` | number | Issued at timestamp (optional) |

## Usage

### Initialize the SDK

You can initialize the SDK from either a JWKS JSON string or a PEM public key. Fetch the key however you need (HTTP, gRPC, file, environment variable, etc.).

**From JWKS:**

```rust
use easy_auth_sdk::{EasyAuth, AuthError};

let jwks_json = r#"{
  "keys": [{
    "kty": "RSA",
    "kid": "my-key-id",
    "use": "sig",
    "alg": "RS256",
    "n": "...",
    "e": "AQAB"
  }]
}"#;

let auth = EasyAuth::from_jwks_json(jwks_json)?;
```

**From PEM:**

```rust
use easy_auth_sdk::{EasyAuth, AuthError};

let pem = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...
-----END PUBLIC KEY-----"#;

let auth = EasyAuth::from_pem(pem)?;
```

### Validate Token

Validate the token signature and expiration, then get the claims:

```rust
let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";

let claims = auth.validate(token)?;
println!("User: {}", claims.sub);
println!("Roles: {:?}", claims.domain_roles);
```

### RBAC Check

Check if the claims contain any of the allowed domain roles:

```rust
let claims = auth.validate(token)?;

// Returns true if claims have any of the allowed roles
if claims.allowed_domain_roles(&["moon:user", "moon:admin"]) {
    println!("Access granted for user: {}", claims.sub);
} else {
    println!("Access denied");
}
```

### Subject Matching

Check that the claims subject matches an expected value:

```rust
let claims = auth.validate(token)?;

// Returns true if sub matches
if claims.is_subject("295fafbb-7da3-4881-858f-e6ea5d2b65ae") {
    println!("Verified user: {}", claims.sub);
} else {
    println!("Subject mismatch");
}
```

### Combining Checks

Validate once, perform multiple checks with boolean logic:

```rust
use easy_auth_sdk::{EasyAuth, AuthError, Claims};

fn authorize_request(
    auth: &EasyAuth,
    token: &str,
    resource_owner_id: &str,
) -> Result<Claims, AuthError> {
    // Validate and decode once
    let claims = auth.validate(token)?;

    // User must have read permission AND be the resource owner
    if claims.allowed_domain_roles(&["api:read"]) && claims.is_subject(resource_owner_id) {
        Ok(claims)
    } else {
        Err(AuthError::InvalidToken("Access denied".to_string()))
    }
}
```

### Flexible Authorization Logic

The boolean return values allow flexible OR/AND combinations:

```rust
let claims = auth.validate(token)?;

// User must have admin role OR be the resource owner
if claims.allowed_domain_roles(&["example:admin"]) || claims.is_subject(resource_owner_id) {
    // Access granted
}

// User must have BOTH read AND write permissions
if claims.allowed_domain_roles(&["api:read"]) && claims.allowed_domain_roles(&["api:write"]) {
    // Full access granted
}
```

## API Reference

### EasyAuth

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `from_jwks_json` | `jwks_json: &str` | `Result<Self, AuthError>` | Create instance from JWKS JSON |
| `from_pem` | `pem: &str` | `Result<Self, AuthError>` | Create instance from PEM public key |
| `validate` | `token: &str` | `Result<Claims, AuthError>` | Validate token and return claims |

### Claims

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `is_subject` | `expected_sub: &str` | `bool` | Check if claims.sub matches |
| `allowed_domain_roles` | `allowed_roles: &[&str]` | `bool` | Check if claims have any of the roles |

### Claims Fields

| Field | Type | Description |
|-------|------|-------------|
| `sub` | `String` | User identifier |
| `domain_roles` | `Vec<String>` | Array of domain:role pairs |
| `exp` | `Option<u64>` | Expiration timestamp |
| `iat` | `Option<u64>` | Issued at timestamp |

## Error Handling

| Error | Meaning | Suggested HTTP Status |
|-------|---------|----------------------|
| `AuthError::TokenExpired` | Token has expired | 401 Unauthorized |
| `AuthError::InvalidSignature` | Signature verification failed | 401 Unauthorized |
| `AuthError::InvalidToken(_)` | Malformed token | 401 Unauthorized |
| `AuthError::MissingClaim(_)` | Required claim missing | 401 Unauthorized |
| `AuthError::InvalidKey(_)` | Bad JWKS/PEM configuration | 500 Internal Error |
| `AuthError::JsonError(_)` | JSON parsing error | 500 Internal Error |

### Example with HTTP Status Mapping

```rust
use easy_auth_sdk::{EasyAuth, AuthError};

fn check_access(auth: &EasyAuth, token: &str) -> (u16, String) {
    let claims = match auth.validate(token) {
        Ok(c) => c,
        Err(AuthError::TokenExpired) => return (401, "Token expired".to_string()),
        Err(AuthError::InvalidSignature) => return (401, "Invalid signature".to_string()),
        Err(e) => return (401, format!("Auth error: {}", e)),
    };

    if claims.allowed_domain_roles(&["api:read"]) {
        (200, format!("Welcome, {}", claims.sub))
    } else {
        (403, "Forbidden".to_string())
    }
}
```

## Domain Roles

The `domain_roles` field supports flexible permission schemes:

```
moon:user                    # Simple domain:role
example:admin                # Another domain
product_a.feature_x:editor   # Hierarchical permissions
org.billing:manage           # Nested domains
```

The SDK performs exact string matching. Define your permission semantics in your application logic.

## Notes

- **Token refresh is the caller's responsibility.** This SDK only validates tokens.
- **Algorithm support:** Only RS256 is supported.
- **Expiration validation:** Enabled by default. Expired tokens return `AuthError::TokenExpired`.
- **JWKS key selection:** If the JWT header contains a `kid`, the SDK matches it against JWKS keys. Otherwise, the first available key is used.
- **Thread safety:** `EasyAuth` is `Send + Sync` and can be shared across threads with `Arc<EasyAuth>`.

## Contributing

### Commit Messages

This project uses [conventional commits](https://www.conventionalcommits.org/) with [release-please](https://github.com/googleapis/release-please) for automated releases:

- `feat: add ES256 support` — new feature (bumps minor version)
- `fix: handle expired token edge case` — bug fix (bumps patch version)
- `feat!: redesign Claims struct` — breaking change (bumps major version)
- `chore:`, `docs:`, `refactor:` — no version bump

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE) for details.

This project also supports the [Anti-996 License](https://github.com/996icu/996.ICU/blob/master/LICENSE). We encourage fair labor practices and oppose the "996" working schedule.
