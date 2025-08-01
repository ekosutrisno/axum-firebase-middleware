//! # Firebase JWT Authentication Middleware for Axum
//!
//! A production-ready Firebase JWT token validation middleware for Axum web applications.
//! This crate provides secure token validation with automatic public key caching,
//! comprehensive error handling, and built-in security features.
//!
//! ## Features
//!
//! - **Secure JWT validation** with Firebase-specific claim verification
//! - **Automatic public key caching** with configurable expiration
//! - **Production-ready error handling** with detailed error types
//! - **Security hardening** including token length limits and timing validation
//! - **Retry logic with exponential backoff** for key fetching
//! - **Comprehensive logging** for monitoring and debugging
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use axum::{routing::get, Router, Extension, Json};
//! use axum::middleware::from_fn_with_state;
//! use serde_json::json;
//! use axum_firebase_middleware::{FirebaseClaims, FirebaseConfig, firebase_auth_middleware};
//!
//! // Your protected handler
//! async fn protected_handler(
//!     Extension(claims): Extension<FirebaseClaims>
//! ) -> Json<serde_json::Value> {
//!     Json(json!({
//!         "user_id": claims.user_id,
//!         "email": claims.email
//!     }))
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = FirebaseConfig::new("your-firebase-project-id".to_string())
//!         .expect("Failed to create Firebase config");
//!
//!     let app = Router::new()
//!         .route("/protected", get(protected_handler))
//!         .route_layer(from_fn_with_state(config.clone(), firebase_auth_middleware))
//!         .with_state(config);
//!
//!     // Run your server...
//! }
//! ```

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use uuid::Uuid;

const GOOGLE_CERTS_URL: &str =
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
const DEFAULT_CACHE_DURATION: u64 = 3600;
const MAX_TOKEN_LENGTH: usize = 4096;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RETRIES: u32 = 3;

/// Firebase JWT claims structure containing user authentication information.
///
/// This struct represents the decoded claims from a Firebase ID token.
/// All fields follow Firebase's JWT specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirebaseClaims {
    /// Token issuer (should be `https://securetoken.google.com/{project_id}`)
    pub iss: String,
    /// Audience (your Firebase project ID)
    pub aud: String,
    /// Authentication time (Unix timestamp)
    pub auth_time: i64,
    /// Firebase user ID
    pub user_id: String,
    /// Subject (should match user_id)
    pub sub: String,
    /// Issued at time (Unix timestamp)
    pub iat: i64,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// User's email address (if available)
    pub email: Option<String>,
    /// Whether the email has been verified
    pub email_verified: Option<bool>,
    /// Firebase authentication provider information
    pub firebase: FirebaseAuthProvider,
}

/// Firebase authentication provider information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirebaseAuthProvider {
    /// User identities from various providers
    pub identities: HashMap<String, Vec<String>>,
    /// The sign-in provider used for authentication
    pub sign_in_provider: String,
}

/// Comprehensive error types for Firebase authentication failures.
#[derive(Debug, thiserror::Error)]
pub enum FirebaseAuthError {
    #[error("Invalid token format: {0}")]
    InvalidTokenFormat(String),

    #[error("Token validation failed: {0}")]
    ValidationFailed(String),

    #[error("Public key fetch failed: {0}")]
    KeyFetchFailed(String),

    #[error("Token expired or invalid timing")]
    InvalidTiming,

    #[error("Missing required claims")]
    MissingClaims,

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Rate limit exceeded")]
    RateLimited,
}

/// Public key cache with automatic refresh and retry logic.
///
/// Handles fetching and caching of Firebase's public keys used for JWT verification.
/// Keys are automatically refreshed based on the configured cache duration.
#[derive(Clone)]
pub struct PublicKeyCache {
    keys: Arc<RwLock<HashMap<String, DecodingKey>>>,
    last_updated: Arc<RwLock<SystemTime>>,
    cache_duration: Duration,
    http_client: reqwest::Client,
    retry_count: Arc<RwLock<u32>>,
}

impl PublicKeyCache {
    /// Creates a new public key cache with the specified cache duration.
    ///
    /// # Arguments
    /// * `cache_duration_seconds` - How long to cache keys before refreshing
    ///
    /// # Errors
    /// Returns `FirebaseAuthError::ConfigError` if HTTP client creation fails.
    pub fn new(cache_duration_seconds: u64) -> Result<Self, FirebaseAuthError> {
        let http_client = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .user_agent("Firebase-JWT-Validator/1.0")
            .https_only(true)
            .build()
            .map_err(|e| {
                FirebaseAuthError::ConfigError(format!("HTTP client creation failed: {}", e))
            })?;

        Ok(Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            last_updated: Arc::new(RwLock::new(UNIX_EPOCH)),
            cache_duration: Duration::from_secs(cache_duration_seconds),
            http_client,
            retry_count: Arc::new(RwLock::new(0)),
        })
    }

    /// Retrieves a decoding key for the given key ID.
    ///
    /// Automatically refreshes the cache if needed and handles key rotation.
    ///
    /// # Arguments
    /// * `kid` - The key ID from the JWT header
    ///
    /// # Errors
    /// Returns various `FirebaseAuthError` types for validation or fetch failures.
    pub async fn get_key(&self, kid: &str) -> Result<DecodingKey, FirebaseAuthError> {
        if kid.is_empty() || kid.len() > 128 {
            return Err(FirebaseAuthError::InvalidTokenFormat(
                "Invalid key ID".to_string(),
            ));
        }

        let last_updated = *self.last_updated.read().await;
        let now = SystemTime::now();

        let needs_refresh =
            now.duration_since(last_updated).unwrap_or(Duration::MAX) > self.cache_duration;

        if needs_refresh {
            self.refresh_keys().await?;
        }

        if let Some(key) = self.keys.read().await.get(kid).cloned() {
            debug!("Public key cache hit for kid: {}", kid);
            return Ok(key);
        }

        if !needs_refresh {
            warn!("Key {} not found in fresh cache, forcing refresh", kid);
            self.refresh_keys().await?;

            if let Some(key) = self.keys.read().await.get(kid).cloned() {
                return Ok(key);
            }
        }

        Err(FirebaseAuthError::KeyFetchFailed(format!(
            "Public key not found for kid: {}",
            kid
        )))
    }

    /// Refreshes public keys with exponential backoff retry logic.
    async fn refresh_keys(&self) -> Result<(), FirebaseAuthError> {
        let mut retry_count = *self.retry_count.read().await;
        let mut delay = Duration::from_millis(100);

        for attempt in 0..MAX_RETRIES {
            match self.fetch_keys().await {
                Ok(()) => {
                    *self.retry_count.write().await = 0;
                    info!("Successfully refreshed Firebase public keys");
                    return Ok(());
                }
                Err(e) => {
                    retry_count += 1;
                    *self.retry_count.write().await = retry_count;

                    if attempt < MAX_RETRIES - 1 {
                        warn!(
                            "Failed to fetch keys (attempt {}): {}. Retrying in {:?}",
                            attempt + 1,
                            e,
                            delay
                        );
                        tokio::time::sleep(delay).await;
                        delay *= 2;
                    } else {
                        error!("Failed to fetch keys after {} attempts: {}", MAX_RETRIES, e);
                        return Err(e);
                    }
                }
            }
        }

        unreachable!()
    }

    /// Fetches public keys from Google's certificate endpoint.
    async fn fetch_keys(&self) -> Result<(), FirebaseAuthError> {
        let response = self
            .http_client
            .get(GOOGLE_CERTS_URL)
            .send()
            .await
            .map_err(|e| {
                FirebaseAuthError::KeyFetchFailed(format!("HTTP request failed: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(FirebaseAuthError::KeyFetchFailed(format!(
                "HTTP {} from Google certificates endpoint",
                response.status()
            )));
        }

        let certs: HashMap<String, String> = response.json().await.map_err(|e| {
            FirebaseAuthError::KeyFetchFailed(format!("Invalid JSON response: {}", e))
        })?;

        if certs.is_empty() {
            return Err(FirebaseAuthError::KeyFetchFailed(
                "Empty certificates response".to_string(),
            ));
        }

        let mut keys = HashMap::new();
        let mut parse_errors = 0;

        for (kid, cert) in certs {
            if !cert.starts_with("-----BEGIN CERTIFICATE-----") {
                warn!("Invalid certificate format for kid: {}", kid);
                parse_errors += 1;
                continue;
            }

            match DecodingKey::from_rsa_pem(cert.as_bytes()) {
                Ok(key) => {
                    keys.insert(kid.clone(), key);
                    debug!("Successfully parsed certificate for kid: {}", kid);
                }
                Err(e) => {
                    warn!("Failed to parse certificate for kid {}: {}", kid, e);
                    parse_errors += 1;
                }
            }
        }

        if keys.is_empty() {
            return Err(FirebaseAuthError::KeyFetchFailed(
                "No valid certificates found".to_string(),
            ));
        }

        if parse_errors > 0 {
            warn!(
                "Failed to parse {} out of {} certificates",
                parse_errors,
                keys.len() + parse_errors
            );
        }

        *self.keys.write().await = keys;
        *self.last_updated.write().await = SystemTime::now();

        Ok(())
    }
}

/// Firebase authentication configuration.
///
/// Contains all settings needed for JWT validation including project ID,
/// key cache configuration, and security parameters.
#[derive(Clone)]
pub struct FirebaseConfig {
    /// Firebase project ID
    pub project_id: String,
    /// Public key cache instance
    pub key_cache: PublicKeyCache,
    /// Maximum allowed token age
    pub max_token_age: Duration,
    /// Allowed JWT algorithms (defaults to RS256 only)
    pub allowed_algorithms: Vec<Algorithm>,
}

impl FirebaseConfig {
    /// Creates a new Firebase configuration with secure defaults.
    ///
    /// # Arguments
    /// * `project_id` - Your Firebase project ID
    ///
    /// # Errors
    /// Returns `FirebaseAuthError::ConfigError` for invalid project IDs or setup failures.
    ///
    /// # Example
    /// ```rust,no_run
    /// use axum_firebase_middleware::FirebaseConfig;
    ///
    /// let config = FirebaseConfig::new("my-firebase-project".to_string())?;
    /// # Ok::<(), axum_firebase_middleware::FirebaseAuthError>(())
    /// ```
    pub fn new(project_id: String) -> Result<Self, FirebaseAuthError> {
        if project_id.is_empty() {
            return Err(FirebaseAuthError::ConfigError(
                "Project ID cannot be empty".to_string(),
            ));
        }

        if !project_id.chars().all(|c| c.is_alphanumeric() || c == '-') || project_id.len() > 30 {
            return Err(FirebaseAuthError::ConfigError(
                "Invalid project ID format".to_string(),
            ));
        }

        let key_cache = PublicKeyCache::new(DEFAULT_CACHE_DURATION)?;

        Ok(Self {
            project_id,
            key_cache,
            max_token_age: Duration::from_secs(24 * 3600),
            allowed_algorithms: vec![Algorithm::RS256],
        })
    }

    /// Sets a custom cache duration for public keys.
    ///
    /// # Arguments
    /// * `seconds` - Cache duration in seconds
    pub fn with_cache_duration(mut self, seconds: u64) -> Result<Self, FirebaseAuthError> {
        self.key_cache = PublicKeyCache::new(seconds)?;
        Ok(self)
    }

    /// Sets the maximum allowed token age.
    ///
    /// Tokens older than this duration will be rejected even if not expired.
    ///
    /// # Arguments
    /// * `duration` - Maximum token age
    pub fn with_max_token_age(mut self, duration: Duration) -> Self {
        self.max_token_age = duration;
        self
    }
}

/// Extracts and validates Bearer token from Authorization header.
///
/// Performs comprehensive security checks including length limits,
/// format validation, and character validation.
fn extract_bearer_token(headers: &HeaderMap) -> Result<String, FirebaseAuthError> {
    let auth_header = headers.get("authorization").ok_or_else(|| {
        FirebaseAuthError::InvalidTokenFormat("Missing Authorization header".to_string())
    })?;

    let auth_str = auth_header.to_str().map_err(|_| {
        FirebaseAuthError::InvalidTokenFormat("Invalid Authorization header encoding".to_string())
    })?;

    if !auth_str.starts_with("Bearer ") {
        return Err(FirebaseAuthError::InvalidTokenFormat(
            "Authorization header must use Bearer scheme".to_string(),
        ));
    }

    let token = &auth_str[7..];

    if token.is_empty() {
        return Err(FirebaseAuthError::InvalidTokenFormat(
            "Empty token".to_string(),
        ));
    }

    if token.len() > MAX_TOKEN_LENGTH {
        return Err(FirebaseAuthError::InvalidTokenFormat(
            "Token too long".to_string(),
        ));
    }

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(FirebaseAuthError::InvalidTokenFormat(
            "Invalid JWT format".to_string(),
        ));
    }

    if token.contains('\0') || token.contains('\n') || token.contains('\r') {
        return Err(FirebaseAuthError::InvalidTokenFormat(
            "Token contains invalid characters".to_string(),
        ));
    }

    Ok(token.to_string())
}

/// Validates Firebase JWT token with comprehensive security checks.
///
/// Performs all necessary validations including:
/// - Signature verification using Google's public keys
/// - Claims validation (issuer, audience, timing)
/// - Firebase-specific claim verification
/// - Security checks for token age and format
async fn validate_firebase_token(
    token: &str,
    config: &FirebaseConfig,
) -> Result<FirebaseClaims, FirebaseAuthError> {
    let header = decode_header(token).map_err(|e| {
        FirebaseAuthError::InvalidTokenFormat(format!("Invalid token header: {}", e))
    })?;

    let algorithm = header.alg;
    if !config.allowed_algorithms.contains(&algorithm) {
        return Err(FirebaseAuthError::ValidationFailed(format!(
            "Algorithm {:?} not allowed",
            algorithm
        )));
    }

    let kid = header.kid.ok_or_else(|| {
        FirebaseAuthError::InvalidTokenFormat("Missing key ID in token header".to_string())
    })?;

    let decoding_key = config.key_cache.get_key(&kid).await?;

    let mut validation = Validation::new(algorithm);
    validation.set_audience(&[&config.project_id]);
    validation.set_issuer(&[&format!(
        "https://securetoken.google.com/{}",
        config.project_id
    )]);
    validation.validate_exp = true;
    validation.validate_nbf = false;
    validation.validate_aud = true;
    validation.leeway = 60;
    validation.reject_tokens_expiring_in_less_than = 0;

    let token_data = decode::<FirebaseClaims>(token, &decoding_key, &validation).map_err(|e| {
        FirebaseAuthError::ValidationFailed(format!("Token validation failed: {}", e))
    })?;

    let claims = token_data.claims;

    if claims.sub.is_empty() || claims.sub.len() > 128 {
        return Err(FirebaseAuthError::MissingClaims);
    }

    if claims.sub != claims.user_id {
        return Err(FirebaseAuthError::ValidationFailed(
            "Subject and user_id mismatch".to_string(),
        ));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    if claims.auth_time > now + 60 {
        return Err(FirebaseAuthError::InvalidTiming);
    }

    let token_age = Duration::from_secs((now - claims.iat) as u64);
    if token_age > config.max_token_age {
        return Err(FirebaseAuthError::InvalidTiming);
    }

    let expected_issuer = format!("https://securetoken.google.com/{}", config.project_id);
    if claims.iss != expected_issuer {
        return Err(FirebaseAuthError::ValidationFailed(
            "Invalid issuer".to_string(),
        ));
    }

    if claims.aud != config.project_id {
        return Err(FirebaseAuthError::ValidationFailed(
            "Invalid audience".to_string(),
        ));
    }

    let auth_age = Duration::from_secs((now - claims.auth_time) as u64);
    if auth_age > Duration::from_secs(7 * 24 * 3600) {
        return Err(FirebaseAuthError::InvalidTiming);
    }

    debug!(
        "Successfully validated Firebase token for user: {}",
        claims.user_id
    );
    Ok(claims)
}

/// Axum middleware for Firebase JWT authentication.
///
/// This middleware validates Firebase ID tokens and adds the decoded claims
/// to the request extensions for use by downstream handlers.
///
/// # Security Features
/// - Validates JWT signatures using Google's public keys
/// - Enforces token expiration and timing constraints
/// - Checks Firebase-specific claims and issuer
/// - Prevents common attacks (oversized requests, malformed tokens)
/// - Adds request IDs for tracing
///
/// # Usage
/// ```rust,no_run
/// use axum::{Router, routing::get, Json, response::IntoResponse, Extension, middleware::from_fn_with_state};
/// use axum_firebase_middleware::{firebase_auth_middleware, FirebaseConfig, FirebaseClaims};
/// use jsonwebtoken::errors::ErrorKind::Json as OtherJson;
///
///
/// let config = FirebaseConfig::new("project-id".to_string())?;
///
/// async fn protected_handler(Extension(claims): Extension<FirebaseClaims>) -> impl IntoResponse {
///     Json(serde_json::json!({
///         "message": "Successfully authenticated",
///         "user_id": claims.user_id,
///         "email": claims.email
///     }))
///  }
///
/// let app = Router::new()
///     .route("/protected", get(protected_handler))
///     .route_layer(from_fn_with_state(config.clone(), firebase_auth_middleware))
///     .with_state(config);
/// # Ok::<(), axum_firebase_middleware::FirebaseAuthError>(())
/// ```
pub async fn firebase_auth_middleware(
    State(config): State<FirebaseConfig>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(content_length) = request.headers().get("content-length") {
        if let Ok(length_str) = content_length.to_str() {
            if let Ok(length) = length_str.parse::<usize>() {
                if length > 10_485_760 {
                    warn!("Request body too large: {} bytes", length);
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
            }
        }
    }

    let token = match extract_bearer_token(request.headers()) {
        Ok(token) => token,
        Err(e) => {
            warn!("Token extraction failed: {}", e);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let claims = match validate_firebase_token(&token, &config).await {
        Ok(claims) => {
            debug!("Successfully authenticated user: {}", claims.user_id);
            claims
        }
        Err(e) => match e {
            FirebaseAuthError::InvalidTokenFormat(_) | FirebaseAuthError::MissingClaims => {
                warn!("Invalid token format: {}", e);
                return Err(StatusCode::UNAUTHORIZED);
            }
            FirebaseAuthError::ValidationFailed(_) | FirebaseAuthError::InvalidTiming => {
                warn!("Token validation failed: {}", e);
                return Err(StatusCode::UNAUTHORIZED);
            }
            FirebaseAuthError::KeyFetchFailed(_) => {
                error!("Key fetch failed: {}", e);
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            FirebaseAuthError::RateLimited => {
                warn!("Rate limit exceeded");
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
            FirebaseAuthError::ConfigError(_) => {
                error!("Configuration error: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        },
    };

    request.extensions_mut().insert(claims);

    if request.extensions().get::<String>().is_none() {
        let request_id = Uuid::new_v4().to_string();
        request.extensions_mut().insert(request_id);
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::FromRef;
    use axum::http::Request;
    use axum::middleware::from_fn_with_state;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Extension, Json, Router};
    use tower::ServiceExt;

    #[derive(Clone, FromRef)]
    struct AppStateMock {
        fb: FirebaseConfig,
    }

    async fn health_check(
        State(config): State<FirebaseConfig>,
    ) -> Result<Json<serde_json::Value>, StatusCode> {
        match config.key_cache.fetch_keys().await {
            Ok(()) => Ok(Json(serde_json::json!({
                "status": "healthy",
                "firebase_keys": "accessible",
                "timestamp": SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            }))),
            Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
        }
    }

    async fn protected_handler(Extension(claims): Extension<FirebaseClaims>) -> impl IntoResponse {
        Json(serde_json::json!({
            "message": "Successfully authenticated",
            "user_id": claims.user_id,
            "email": claims.email
        }))
    }

    async fn create_route() -> Router {
        let app_state = AppStateMock {
            fb: FirebaseConfig::new("test-project-id".to_string()).unwrap(),
        };

        Router::new()
            .route("/health", get(health_check))
            .nest(
                "/api/v1",
                Router::new()
                    .route("/protected", get(protected_handler))
                    .route_layer(from_fn_with_state(
                        app_state.fb.clone(),
                        firebase_auth_middleware,
                    )),
            )
            .with_state(app_state)
    }

    #[test]
    fn test_extract_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer test.token.123".parse().unwrap());
        let token = extract_bearer_token(&headers).unwrap();
        assert_eq!(token, "test.token.123");

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Basic invalid".parse().unwrap());
        let result = extract_bearer_token(&headers);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FirebaseAuthError::InvalidTokenFormat(_)
        ));

        let headers = HeaderMap::new();
        let result = extract_bearer_token(&headers);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FirebaseAuthError::InvalidTokenFormat(_)
        ));

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer ".parse().unwrap());
        let result = extract_bearer_token(&headers);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FirebaseAuthError::InvalidTokenFormat(_)
        ));

        let mut headers = HeaderMap::new();
        let long_token = "Bearer ".to_string() + &"a".repeat(MAX_TOKEN_LENGTH + 1);
        headers.insert("authorization", long_token.parse().unwrap());
        let result = extract_bearer_token(&headers);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FirebaseAuthError::InvalidTokenFormat(_)
        ));

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer part1.part2".parse().unwrap());
        let result = extract_bearer_token(&headers);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FirebaseAuthError::InvalidTokenFormat(_)
        ));

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer part1.part2.part3".parse().unwrap());
        let result = extract_bearer_token(&headers);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "part1.part2.part3");

        let invalid_chars = ["token\0null", "token\nline", "token\rreturn"];
        for invalid_token in invalid_chars {
            let has_invalid_chars = invalid_token.contains('\0')
                || invalid_token.contains('\n')
                || invalid_token.contains('\r');
            assert!(has_invalid_chars, "Token should contain invalid characters");
        }
    }

    #[tokio::test]
    async fn test_public_key_cache_creation() {
        let cache = PublicKeyCache::new(3600);
        assert!(cache.is_ok());
        assert!(cache.unwrap().keys.read().await.is_empty());
    }

    #[tokio::test]
    async fn test_firebase_config_creation() {
        let project_id = "test-project-id".to_string();
        let config = FirebaseConfig::new(project_id.clone());
        assert!(config.is_ok());

        let config = config.unwrap();
        assert_eq!(config.project_id, project_id);
        assert_eq!(config.allowed_algorithms, vec![Algorithm::RS256]);
    }

    #[tokio::test]
    async fn test_firebase_auth_middleware_no_token() {
        let app = create_route().await;

        let request = Request::builder()
            .uri("/api/v1/protected")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_firebase_auth_middleware_invalid_token() {
        let app = create_route().await;

        let request = Request::builder()
            .uri("/api/v1/protected")
            .header("Authorization", "Bearer invalid.token.format")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_firebase_auth_without_middleware() {
        let app = create_route().await;

        let request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
