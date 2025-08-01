# Axum Firebase Middleware

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/yourusername/axum-firebase-middleware)

A production-ready Firebase JWT authentication middleware for Axum web applications. This crate provides secure token validation with automatic public key caching, comprehensive error handling, and built-in security features.

## Features

- **Secure JWT validation** with Firebase-specific claim verification
- **Automatic public key caching** with configurable expiration and key rotation
- **Production-ready error handling** with detailed, actionable error types
- **Security hardening** including token length limits, timing validation, and DoS protection
- **Retry logic with exponential backoff** for robust key fetching
- **Comprehensive logging** for monitoring and debugging
- **Zero-copy where possible** for optimal performance

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
axum-firebase-middleware = "0.1.0"
axum = "0.8"
tokio = { version = "1.0", features = ["full"] }
```

Basic usage:

```rust
use axum::{
    routing::get,
    Router,
    Extension,
    Json,
    middleware::from_fn_with_state,
};
use axum_firebase_middleware::{firebase_auth_middleware, FirebaseConfig, FirebaseClaims};
use serde_json::json;

// Your protected handler
async fn protected_handler(
    Extension(claims): Extension<FirebaseClaims>
) -> Json<serde_json::Value> {
    Json(json!({
        "message": "Successfully authenticated!",
        "user_id": claims.user_id,
        "email": claims.email,
        "email_verified": claims.email_verified
    }))
}

// Public handler (no authentication required)
async fn public_handler() -> Json<serde_json::Value> {
    Json(json!({
        "message": "This endpoint is public"
    }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    // Create Firebase configuration
    let firebase_config = FirebaseConfig::new("your-firebase-project-id".to_string())?
        .with_cache_duration(3600)? // Cache keys for 1 hour
        .with_max_token_age(std::time::Duration::from_secs(24 * 3600)); // 24 hour max token age

    // Build the application with protected and public routes
    let app = Router::new()
        .route("/public", get(public_handler))
        .nest("/api/v1", 
            Router::new()
                .route("/protected", get(protected_handler))
                .route_layer(from_fn_with_state(
                    firebase_config.clone(), 
                    firebase_auth_middleware
                ))
        )
        .with_state(firebase_config);

    // Run the server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("Server running on http://0.0.0.0:3000");
    
    axum::serve(listener, app).await?;
    Ok(())
}
```

## Usage

### 1. Get Firebase Project ID

Get your Firebase project ID from the Firebase Console:

- Go to [Firebase Console](https://console.firebase.google.com/)
- Select your project
- Click on Project Settings (gear icon)
- Copy the Project ID

### 2. Client-side Token Generation

On your client (web, mobile app), authenticate users and get ID tokens:

```javascript
// Web example using Firebase SDK
import { getAuth, signInWithEmailAndPassword, getIdToken } from 'firebase/auth';

const auth = getAuth();
const userCredential = await signInWithEmailAndPassword(auth, email, password);
const idToken = await getIdToken(userCredential.user);

// Use this token in Authorization header
fetch('/api/v1/protected', {
    headers: {
        'Authorization': `Bearer ${idToken}`
    }
});
```

### 3. Server-side Validation

The middleware automatically validates tokens and provides claims:

```rust
async fn user_profile(
    Extension(claims): Extension<FirebaseClaims>
) -> Json<serde_json::Value> {
    Json(json!({
        "user_id": claims.user_id,
        "email": claims.email,
        "email_verified": claims.email_verified,
        "auth_time": claims.auth_time,
        "sign_in_provider": claims.firebase.sign_in_provider
    }))
}
```

## Configuration Options

### Custom Cache Duration

```rust
let config = FirebaseConfig::new("project-id".to_string())?
    .with_cache_duration(1800)?; // Cache for 30 minutes
```

### Custom Token Age Limits

```rust
let config = FirebaseConfig::new("project-id".to_string())?
    .with_max_token_age(Duration::from_secs(12 * 3600)); // 12 hours max
```

## Error Handling

The middleware returns appropriate HTTP status codes:

- `401 Unauthorized`: Invalid, expired, or malformed tokens
- `503 Service Unavailable`: Firebase key service unavailable
- `429 Too Many Requests`: Rate limiting (if implemented)
- `413 Payload Too Large`: Request body too large
- `500 Internal Server Error`: Configuration errors

Custom error handling:

```rust
use axum_firebase_middleware::FirebaseAuthError;

match validate_firebase_token(&token, &config).await {
    Ok(claims) => {
        // Token is valid, use claims
        println!("User ID: {}", claims.user_id);
    }
    Err(FirebaseAuthError::InvalidTokenFormat(msg)) => {
        println!("Invalid token format: {}", msg);
    }
    Err(FirebaseAuthError::ValidationFailed(msg)) => {
        println!("Token validation failed: {}", msg);
    }
    Err(e) => {
        println!("Other error: {}", e);
    }
}
```

## Security Features

- **Token length limits** prevent DoS attacks
- **Timing validation** prevents replay attacks with old tokens
- **Algorithm validation** ensures only RS256 is accepted
- **Claim validation** verifies Firebase-specific claims
- **Public key caching** with automatic rotation
- **Request size limits** prevent large payload attacks
- **Comprehensive input validation** on all user inputs

## Performance

- Automatic public key caching reduces Firebase API calls
- Efficient JWT validation using `jsonwebtoken` crate
- Minimal memory allocations in hot paths
- Configurable cache duration for optimal performance vs security trade-offs

## Logging

The crate uses the `log` crate for structured logging:

```rust
// Initialize logging in your main function
env_logger::init();

// The middleware will log:
// - INFO: Successful key refreshes
// - WARN: Authentication failures, key fetch issues
// - DEBUG: Cache hits, successful validations
// - ERROR: Configuration issues, repeated failures
```

Log levels:

- `DEBUG`: Cache operations, successful validations
- `INFO`: Key refresh operations
- `WARN`: Authentication failures, recoverable errors
- `ERROR`: Configuration issues, persistent failures

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

1. Clone the repository
2. Run tests: `cargo test`
3. Check formatting: `cargo fmt`
4. Run clippy: `cargo clippy`

## License

This project is licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Changelog

### 0.1.0

- Initial release
- Firebase JWT validation
- Automatic key caching
- Production-ready error handling
- Comprehensive security features
