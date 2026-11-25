use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const DEFAULT_API_BASE_URL: &str = "https://drive-api.proton.me";
// ProtonDriveApps/sdk usage guidelines require unofficial third-party clients to
// identify themselves via `external-drive-{name}@{semver}-{channel}+{suffix}`
// and an honest User-Agent rather than masquerading as an official first-party
// Proton client.
pub const DEFAULT_APP_VERSION: &str = "external-drive-neutron_drive@3.0.3-alpha+linux";
pub const DEFAULT_USER_AGENT: &str = "NeutronDrive/3.0.3 (Linux)";
pub const DEFAULT_LOCALE: &str = "en_US";
pub const PROTON_ACCEPT_HEADER: &str = "application/vnd.protonmail.v1+json";
pub const DEFAULT_MAX_RETRY_COUNT: usize = 6;
const MAX_RETRY_AFTER_SECS: u64 = 300;
const MAX_BACKOFF_EXPONENT: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateLimitFamily {
    Auth,
    Metadata,
    Children,
    Transfer,
    Events,
    Mutation,
}

#[derive(Debug, Clone, Default)]
struct FamilyRateLimitState {
    blocked_until: Option<Instant>,
    consecutive_failures: u32,
}

#[derive(Debug)]
struct RateLimitGateInner {
    families: HashMap<RateLimitFamily, FamilyRateLimitState>,
    default_retry_after: Duration,
}

#[derive(Debug)]
pub struct RateLimitGate {
    inner: Mutex<RateLimitGateInner>,
}

impl Default for RateLimitGate {
    fn default() -> Self {
        Self {
            inner: Mutex::new(RateLimitGateInner {
                families: HashMap::new(),
                default_retry_after: Duration::from_secs(2),
            }),
        }
    }
}

impl RateLimitGate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_default_retry_after(default_retry_after: Duration) -> Self {
        Self {
            inner: Mutex::new(RateLimitGateInner {
                families: HashMap::new(),
                default_retry_after,
            }),
        }
    }

    pub fn set_default_retry_after(&self, default_retry_after: Duration) {
        self.inner.lock().unwrap().default_retry_after = default_retry_after;
    }

    pub fn compute_backoff_delay(base: Duration, consecutive_failures: u32) -> Duration {
        let exp = consecutive_failures
            .saturating_sub(1)
            .min(MAX_BACKOFF_EXPONENT);
        let mult = 1u32.checked_shl(exp).unwrap_or(u32::MAX);
        base.saturating_mul(mult)
            .min(Duration::from_secs(MAX_RETRY_AFTER_SECS))
    }

    pub fn parse_retry_after_value(raw: &str) -> Option<Duration> {
        Self::parse_retry_after_value_at(raw, SystemTime::now())
    }

    pub fn parse_retry_after_value_at(raw: &str, now: SystemTime) -> Option<Duration> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        if let Ok(secs) = trimmed.parse::<u64>() {
            return Some(Duration::from_secs(secs.min(MAX_RETRY_AFTER_SECS)));
        }
        if let Ok(secs_f) = trimmed.parse::<f64>() {
            if secs_f.is_finite() && secs_f >= 0.0 {
                return Some(Duration::from_secs_f64(
                    secs_f.min(MAX_RETRY_AFTER_SECS as f64),
                ));
            }
            return None;
        }
        let target_time = parse_http_date(trimmed)?;
        let delta = target_time.duration_since(now).unwrap_or(Duration::ZERO);
        Some(delta.min(Duration::from_secs(MAX_RETRY_AFTER_SECS)))
    }

    pub fn blocked_until(&self, family: RateLimitFamily) -> Option<Instant> {
        self.inner
            .lock()
            .unwrap()
            .families
            .get(&family)
            .and_then(|s| s.blocked_until)
    }

    pub fn consecutive_failures(&self, family: RateLimitFamily) -> u32 {
        self.inner
            .lock()
            .unwrap()
            .families
            .get(&family)
            .map(|s| s.consecutive_failures)
            .unwrap_or(0)
    }

    pub fn wait_if_needed(&self, family: RateLimitFamily) {
        loop {
            let wait_dur = {
                let guard = self.inner.lock().unwrap();
                guard
                    .families
                    .get(&family)
                    .and_then(|s| s.blocked_until)
                    .and_then(|until| {
                        let now = Instant::now();
                        if until > now {
                            Some(until - now)
                        } else {
                            None
                        }
                    })
            };
            let Some(dur) = wait_dur else {
                return;
            };
            thread::sleep(dur);
        }
    }

    pub fn record_rate_limited(
        &self,
        retry_after: Option<Duration>,
        family: RateLimitFamily,
        _source: &str,
    ) {
        let mut guard = self.inner.lock().unwrap();
        let base = guard.default_retry_after;
        let state = guard.families.entry(family).or_default();
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        let delay = retry_after
            .map(|d| d.min(Duration::from_secs(MAX_RETRY_AFTER_SECS)))
            .unwrap_or_else(|| Self::compute_backoff_delay(base, state.consecutive_failures));
        let candidate = Instant::now() + delay;
        state.blocked_until = Some(match state.blocked_until {
            Some(existing) if existing > candidate => existing,
            _ => candidate,
        });
    }

    pub fn record_success(&self, family: RateLimitFamily) {
        let mut guard = self.inner.lock().unwrap();
        if let Some(state) = guard.families.get_mut(&family) {
            state.consecutive_failures = 0;
            if let Some(until) = state.blocked_until {
                if until <= Instant::now() {
                    state.blocked_until = None;
                }
            }
        }
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap().families.clear();
    }
}

fn parse_month_abbr(mon: &str) -> Option<u32> {
    match mon {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn parse_hms(hms: &str) -> Option<(u32, u32, u32)> {
    let mut parts = hms.split(':');
    let h: u32 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let s: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || h > 23 || m > 59 || s > 60 {
        return None;
    }
    Some((h, m, s))
}

/// Parses RFC 7231 HTTP-date formats (IMF-fixdate, RFC 850, and asctime) into UTC `SystemTime`.
fn parse_http_date(raw: &str) -> Option<SystemTime> {
    let s = raw.trim();
    let (year, month, day, h, m, sec) = if let Some((_, rest)) = s.split_once(',') {
        let tokens: Vec<&str> = rest.split_whitespace().collect();
        if tokens.len() == 5 && (tokens[4] == "GMT" || tokens[4] == "UTC") {
            // IMF-fixdate: "21 Oct 2015 07:28:00 GMT"
            let day: u32 = tokens[0].parse().ok()?;
            let month = parse_month_abbr(tokens[1])?;
            let year: i64 = tokens[2].parse().ok()?;
            let (h, m, sec) = parse_hms(tokens[3])?;
            (year, month, day, h, m, sec)
        } else if tokens.len() == 3 && (tokens[2] == "GMT" || tokens[2] == "UTC") {
            // RFC 850: "06-Nov-94 08:49:37 GMT"
            let mut dmy = tokens[0].split('-');
            let day: u32 = dmy.next()?.parse().ok()?;
            let month = parse_month_abbr(dmy.next()?)?;
            let yy: i64 = dmy.next()?.parse().ok()?;
            if dmy.next().is_some() {
                return None;
            }
            let year = if yy >= 70 { 1900 + yy } else { 2000 + yy };
            let (h, m, sec) = parse_hms(tokens[1])?;
            (year, month, day, h, m, sec)
        } else {
            return None;
        }
    } else {
        // asctime: "Sun Nov  6 08:49:37 1994"
        let tokens: Vec<&str> = s.split_whitespace().collect();
        if tokens.len() != 5 {
            return None;
        }
        let month = parse_month_abbr(tokens[1])?;
        let day: u32 = tokens[2].parse().ok()?;
        let (h, m, sec) = parse_hms(tokens[3])?;
        let year: i64 = tokens[4].parse().ok()?;
        (year, month, day, h, m, sec)
    };

    if !(1..=31).contains(&day) || year < 1970 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    if days < 0 {
        return None;
    }
    let total_secs = (days as u64)
        .checked_mul(86_400)?
        .checked_add(u64::from(h) * 3600 + u64::from(m) * 60 + u64::from(sec))?;
    Some(UNIX_EPOCH + Duration::from_secs(total_secs))
}

#[derive(Clone, Default)]
pub struct HttpAuthTokens {
    pub uid: String,
    pub access_token: Zeroizing<String>,
    pub refresh_token: Zeroizing<String>,
}

impl std::fmt::Debug for HttpAuthTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpAuthTokens")
            .field("uid", &self.uid)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub enum HttpError {
    Status {
        status: u16,
        code: Option<i64>,
        message: String,
    },
    Network(String),
    Decode(String),
    Unauthorized(String),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Status {
                status,
                code,
                message,
            } => write!(f, "HTTP {} (API code {:?}): {}", status, code, message),
            HttpError::Network(m) => write!(f, "Network error: {}", m),
            HttpError::Decode(m) => write!(f, "Decode error: {}", m),
            HttpError::Unauthorized(m) => write!(f, "Unauthorized: {}", m),
        }
    }
}

impl std::error::Error for HttpError {}

#[derive(Debug, Deserialize)]
struct ApiErrorEnvelope {
    #[serde(rename = "Code", alias = "code")]
    code: Option<i64>,
    #[serde(rename = "Error", alias = "error")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct RefreshRequest<'a> {
    #[serde(rename = "UID")]
    uid: &'a str,
    #[serde(rename = "RefreshToken")]
    refresh_token: &'a str,
    #[serde(rename = "ResponseType")]
    response_type: &'a str,
    #[serde(rename = "GrantType")]
    grant_type: &'a str,
    #[serde(rename = "RedirectURI")]
    redirect_uri: &'a str,
}

#[derive(Debug, Deserialize)]
struct RefreshResponse {
    #[serde(rename = "Code", alias = "code", default)]
    code: Option<i64>,
    #[serde(rename = "Error", alias = "error", default)]
    error: Option<String>,
    #[serde(rename = "UID", alias = "uid", default)]
    uid: Option<String>,
    #[serde(rename = "AccessToken", alias = "accessToken", default)]
    access_token: String,
    #[serde(rename = "RefreshToken", alias = "refreshToken", default)]
    refresh_token: String,
}

pub type TokenRefreshCallback = Arc<dyn Fn(&HttpAuthTokens) + Send + Sync>;

pub struct PdHttpClient {
    base_url: String,
    app_version: String,
    client: reqwest::Client,
    runtime: Arc<tokio::runtime::Runtime>,
    rate_limit_gate: Arc<RateLimitGate>,
    max_retry_count: usize,
    tokens: Arc<Mutex<Option<HttpAuthTokens>>>,
    refresh_lock: Mutex<()>,
    on_token_refresh: Mutex<Option<TokenRefreshCallback>>,
}

impl PdHttpClient {
    pub fn new(base_url: Option<String>, app_version: Option<String>) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .user_agent(DEFAULT_USER_AGENT)
            .timeout(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| format!("Failed to construct HTTP client: {}", e))?;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| format!("Failed to build Tokio runtime for HTTP client: {}", e))?;

        let clean_base = base_url
            .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_string())
            .trim_end_matches('/')
            .to_string();

        Ok(Self {
            base_url: clean_base,
            app_version: app_version.unwrap_or_else(|| DEFAULT_APP_VERSION.to_string()),
            client,
            runtime: Arc::new(runtime),
            rate_limit_gate: Arc::new(RateLimitGate::new()),
            max_retry_count: DEFAULT_MAX_RETRY_COUNT,
            tokens: Arc::new(Mutex::new(None)),
            refresh_lock: Mutex::new(()),
            on_token_refresh: Mutex::new(None),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn rate_limit_gate(&self) -> &Arc<RateLimitGate> {
        &self.rate_limit_gate
    }

    pub fn set_tokens(&self, tokens: Option<HttpAuthTokens>) {
        *self.tokens.lock().unwrap() = tokens;
    }

    pub fn tokens(&self) -> Option<HttpAuthTokens> {
        self.tokens.lock().unwrap().clone()
    }

    pub fn set_on_token_refresh(&self, cb: TokenRefreshCallback) {
        *self.on_token_refresh.lock().unwrap() = Some(cb);
    }

    pub fn set_max_retry_count(&mut self, max_retries: usize) {
        self.max_retry_count = max_retries.max(1);
    }

    pub fn resolve_url(
        &self,
        path_or_url: &str,
        query: &[(&str, &str)],
    ) -> Result<String, HttpError> {
        let base = if path_or_url.starts_with("http://") || path_or_url.starts_with("https://") {
            path_or_url.to_string()
        } else if path_or_url.starts_with('/') {
            format!("{}{}", self.base_url, path_or_url)
        } else {
            format!("{}/{}", self.base_url, path_or_url)
        };

        if query.is_empty() {
            return Ok(base);
        }

        let mut parsed = url::Url::parse(&base)
            .map_err(|e| HttpError::Network(format!("Invalid URL {}: {}", base, e)))?;
        {
            let mut pairs = parsed.query_pairs_mut();
            for (k, v) in query {
                pairs.append_pair(k, v);
            }
        }
        Ok(parsed.to_string())
    }

    pub fn get_json<T: DeserializeOwned>(
        &self,
        family: RateLimitFamily,
        path: &str,
        query: &[(&str, &str)],
        authenticated: bool,
    ) -> Result<T, HttpError> {
        let url = self.resolve_url(path, query)?;
        let bytes =
            self.execute_with_retries(family, Method::GET, &url, None, None, authenticated, true)?;
        serde_json::from_slice(&bytes)
            .map_err(|e| HttpError::Decode(format!("Failed decoding JSON from {}: {}", path, e)))
    }

    pub fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        family: RateLimitFamily,
        path: &str,
        body: &B,
        authenticated: bool,
    ) -> Result<T, HttpError> {
        self.post_json_with_options(family, path, body, &[], authenticated, true)
    }

    pub fn post_json_with_options<B: Serialize, T: DeserializeOwned>(
        &self,
        family: RateLimitFamily,
        path: &str,
        body: &B,
        extra_headers: &[(&str, &str)],
        authenticated: bool,
        allow_refresh: bool,
    ) -> Result<T, HttpError> {
        let url = self.resolve_url(path, &[])?;
        let payload = serde_json::to_vec(body)
            .map_err(|e| HttpError::Decode(format!("Failed encoding request JSON: {}", e)))?;
        let bytes = self.execute_with_retries_headers(
            family,
            Method::POST,
            &url,
            Some(payload),
            Some("application/json"),
            extra_headers,
            authenticated,
            allow_refresh,
        )?;
        serde_json::from_slice(&bytes)
            .map_err(|e| HttpError::Decode(format!("Failed decoding JSON from {}: {}", path, e)))
    }

    pub fn put_json<B: Serialize, T: DeserializeOwned>(
        &self,
        family: RateLimitFamily,
        path: &str,
        body: &B,
        authenticated: bool,
    ) -> Result<T, HttpError> {
        let url = self.resolve_url(path, &[])?;
        let payload = serde_json::to_vec(body)
            .map_err(|e| HttpError::Decode(format!("Failed encoding request JSON: {}", e)))?;
        let bytes = self.execute_with_retries(
            family,
            Method::PUT,
            &url,
            Some(payload),
            Some("application/json"),
            authenticated,
            true,
        )?;
        serde_json::from_slice(&bytes)
            .map_err(|e| HttpError::Decode(format!("Failed decoding JSON from {}: {}", path, e)))
    }

    pub fn delete_json<T: DeserializeOwned>(
        &self,
        family: RateLimitFamily,
        path: &str,
        authenticated: bool,
    ) -> Result<T, HttpError> {
        let url = self.resolve_url(path, &[])?;
        let bytes = self.execute_with_retries(
            family,
            Method::DELETE,
            &url,
            None,
            None,
            authenticated,
            false,
        )?;
        serde_json::from_slice(&bytes)
            .map_err(|e| HttpError::Decode(format!("Failed decoding JSON from {}: {}", path, e)))
    }

    pub fn download_bytes(
        &self,
        family: RateLimitFamily,
        url_or_path: &str,
        authenticated: bool,
    ) -> Result<Vec<u8>, HttpError> {
        self.download_bytes_with_headers(family, url_or_path, &[], authenticated)
    }

    pub fn download_bytes_with_headers(
        &self,
        family: RateLimitFamily,
        url_or_path: &str,
        extra_headers: &[(&str, &str)],
        authenticated: bool,
    ) -> Result<Vec<u8>, HttpError> {
        let url = self.resolve_url(url_or_path, &[])?;
        self.execute_with_retries_headers(
            family,
            Method::GET,
            &url,
            None,
            None,
            extra_headers,
            authenticated,
            true,
        )
    }

    pub fn upload_multipart_block(
        &self,
        family: RateLimitFamily,
        url_or_path: &str,
        block_bytes: &[u8],
        authenticated: bool,
    ) -> Result<Vec<u8>, HttpError> {
        self.upload_multipart_block_with_token(
            family,
            url_or_path,
            None,
            block_bytes,
            authenticated,
        )
    }

    pub fn upload_multipart_block_with_token(
        &self,
        family: RateLimitFamily,
        url_or_path: &str,
        storage_token: Option<&str>,
        block_bytes: &[u8],
        authenticated: bool,
    ) -> Result<Vec<u8>, HttpError> {
        let url = self.resolve_url(url_or_path, &[])?;
        let boundary = format!("neutron-drive-boundary-{:016x}", fastrand::u64(..));
        let mut body = Vec::with_capacity(block_bytes.len() + 256);
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"Block\"; filename=\"blob\"\r\n",
        );
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(block_bytes);
        body.extend_from_slice(format!("\r\n--{}--\r\n", boundary).as_bytes());

        let content_type = format!("multipart/form-data; boundary={}", boundary);
        let extra_headers: Vec<(&str, &str)> = match storage_token.filter(|t| !t.is_empty()) {
            Some(tok) => vec![("pm-storage-token", tok)],
            None => Vec::new(),
        };
        self.execute_with_retries_headers(
            family,
            Method::POST,
            &url,
            Some(body),
            Some(&content_type),
            &extra_headers,
            authenticated,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_with_retries(
        &self,
        family: RateLimitFamily,
        method: Method,
        url: &str,
        body: Option<Vec<u8>>,
        content_type: Option<&str>,
        authenticated: bool,
        allow_refresh: bool,
    ) -> Result<Vec<u8>, HttpError> {
        self.execute_with_retries_headers(
            family,
            method,
            url,
            body,
            content_type,
            &[],
            authenticated,
            allow_refresh,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_with_retries_headers(
        &self,
        family: RateLimitFamily,
        method: Method,
        url: &str,
        body: Option<Vec<u8>>,
        content_type: Option<&str>,
        extra_headers: &[(&str, &str)],
        authenticated: bool,
        allow_refresh: bool,
    ) -> Result<Vec<u8>, HttpError> {
        let mut attempts_remaining = self.max_retry_count;
        let mut refresh_attempted = false;

        loop {
            self.rate_limit_gate.wait_if_needed(family);

            let token_snapshot = self.tokens.lock().unwrap().clone();
            if authenticated && token_snapshot.is_none() {
                return Err(HttpError::Unauthorized(
                    "Missing authentication credentials".to_string(),
                ));
            }

            let resp_res = self.runtime.block_on(async {
                let mut req = self.client.request(method.clone(), url);
                req = req.header("x-pm-appversion", &self.app_version);
                req = req.header("x-pm-locale", DEFAULT_LOCALE);
                req = req.header("Accept", PROTON_ACCEPT_HEADER);
                for &(k, v) in extra_headers {
                    req = req.header(k, v);
                }
                if let Some(ref t) = token_snapshot {
                    if !t.uid.is_empty() {
                        req = req.header("x-pm-uid", &t.uid);
                    }
                    if authenticated && !t.access_token.is_empty() {
                        req = req.header(
                            "Authorization",
                            format!("Bearer {}", t.access_token.as_str()),
                        );
                    }
                }
                if let Some(ct) = content_type {
                    req = req.header("Content-Type", ct);
                }
                if let Some(ref b) = body {
                    req = req.body(b.clone());
                }
                let resp = req
                    .send()
                    .await
                    .map_err(|e| HttpError::Network(e.to_string()))?;
                let status = resp.status().as_u16();
                let retry_after = resp
                    .headers()
                    .get("Retry-After")
                    .or_else(|| resp.headers().get("retry-after"))
                    .and_then(|v| v.to_str().ok())
                    .and_then(RateLimitGate::parse_retry_after_value);
                let bytes = resp
                    .bytes()
                    .await
                    .map_err(|e| HttpError::Network(e.to_string()))?
                    .to_vec();
                Ok::<(u16, Option<Duration>, Vec<u8>), HttpError>((status, retry_after, bytes))
            });

            let (status, retry_after, bytes) = resp_res?;

            if status == 429 || (500..600).contains(&status) {
                self.rate_limit_gate
                    .record_rate_limited(retry_after, family, url);
                if attempts_remaining > 1 {
                    attempts_remaining -= 1;
                    continue;
                }
                return Err(Self::build_status_error(status, &bytes));
            }

            if status == 401 && authenticated && allow_refresh {
                if !refresh_attempted {
                    refresh_attempted = true;
                    let prev_access = token_snapshot
                        .as_ref()
                        .map(|t| t.access_token.as_str().to_string())
                        .unwrap_or_default();
                    self.try_refresh_tokens(&prev_access)?;
                    continue;
                }
                return Err(HttpError::Unauthorized(
                    "Session rejected after token refresh".to_string(),
                ));
            }

            if (200..300).contains(&status) {
                self.rate_limit_gate.record_success(family);
                return Ok(bytes);
            }

            return Err(Self::build_status_error(status, &bytes));
        }
    }

    fn build_status_error(status: u16, bytes: &[u8]) -> HttpError {
        if let Ok(env) = serde_json::from_slice::<ApiErrorEnvelope>(bytes) {
            let msg = env
                .error
                .unwrap_or_else(|| String::from_utf8_lossy(bytes).to_string());
            return HttpError::Status {
                status,
                code: env.code,
                message: msg,
            };
        }
        HttpError::Status {
            status,
            code: None,
            message: String::from_utf8_lossy(bytes).to_string(),
        }
    }

    pub fn try_refresh_tokens(
        &self,
        stale_access_token: &str,
    ) -> Result<HttpAuthTokens, HttpError> {
        let _guard = self.refresh_lock.lock().unwrap();

        let current = self
            .tokens
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| HttpError::Unauthorized("No refresh token available".to_string()))?;

        // Another concurrent caller may have already rotated the token.
        if !stale_access_token.is_empty() && current.access_token.as_str() != stale_access_token {
            return Ok(current);
        }

        if current.refresh_token.is_empty() || current.uid.is_empty() {
            return Err(HttpError::Unauthorized(
                "Missing UID or RefreshToken".to_string(),
            ));
        }

        let url = self.resolve_url("/auth/v4/refresh", &[])?;
        let req_body = RefreshRequest {
            uid: &current.uid,
            refresh_token: current.refresh_token.as_str(),
            response_type: "token",
            grant_type: "refresh_token",
            redirect_uri: "https://proton.me",
        };
        let payload = serde_json::to_vec(&req_body)
            .map_err(|e| HttpError::Decode(format!("Refresh encode error: {}", e)))?;

        let mut attempts_remaining = self.max_retry_count;
        let (status, bytes) = loop {
            self.rate_limit_gate.wait_if_needed(RateLimitFamily::Auth);
            let res = self.runtime.block_on(async {
                let resp = self
                    .client
                    .post(&url)
                    .header("x-pm-appversion", &self.app_version)
                    .header("x-pm-locale", DEFAULT_LOCALE)
                    .header("Accept", PROTON_ACCEPT_HEADER)
                    .header("x-pm-uid", &current.uid)
                    .header("Content-Type", "application/json")
                    .body(payload.clone())
                    .send()
                    .await
                    .map_err(|e| HttpError::Network(e.to_string()))?;
                let status = resp.status().as_u16();
                let retry_after = resp
                    .headers()
                    .get("Retry-After")
                    .or_else(|| resp.headers().get("retry-after"))
                    .and_then(|v| v.to_str().ok())
                    .and_then(RateLimitGate::parse_retry_after_value);
                let bytes = resp
                    .bytes()
                    .await
                    .map_err(|e| HttpError::Network(e.to_string()))?
                    .to_vec();
                Ok::<(u16, Option<Duration>, Vec<u8>), HttpError>((status, retry_after, bytes))
            })?;

            if res.0 == 429 || (500..600).contains(&res.0) {
                self.rate_limit_gate
                    .record_rate_limited(res.1, RateLimitFamily::Auth, &url);
                if attempts_remaining > 1 {
                    attempts_remaining -= 1;
                    continue;
                }
                return Err(Self::build_status_error(res.0, &res.2));
            }
            if (200..300).contains(&res.0) {
                self.rate_limit_gate.record_success(RateLimitFamily::Auth);
            }
            break (res.0, res.2);
        };

        if matches!(status, 400 | 401 | 403 | 422) {
            return Err(HttpError::Unauthorized(format!(
                "Refresh rejected: {}",
                Self::build_status_error(status, &bytes)
            )));
        }

        if !(200..300).contains(&status) {
            return Err(Self::build_status_error(status, &bytes));
        }

        let parsed: RefreshResponse = serde_json::from_slice(&bytes)
            .map_err(|e| HttpError::Decode(format!("Failed decoding refresh response: {}", e)))?;

        if let Some(code) = parsed.code {
            if code != 1000 && code != 1001 {
                return Err(HttpError::Unauthorized(format!(
                    "Refresh rejected with API code {}: {}",
                    code,
                    parsed.error.as_deref().unwrap_or("unknown error")
                )));
            }
        }
        if parsed.access_token.is_empty() || parsed.refresh_token.is_empty() {
            return Err(HttpError::Decode(
                "Refresh response missing AccessToken or RefreshToken".to_string(),
            ));
        }

        let next = HttpAuthTokens {
            uid: parsed
                .uid
                .filter(|u| !u.is_empty())
                .unwrap_or_else(|| current.uid.clone()),
            access_token: Zeroizing::new(parsed.access_token),
            refresh_token: Zeroizing::new(parsed.refresh_token),
        };

        *self.tokens.lock().unwrap() = Some(next.clone());
        if let Some(ref cb) = *self.on_token_refresh.lock().unwrap() {
            cb(&next);
        }
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_gate_parse_retry_after_numeric_and_http_date() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        assert_eq!(
            RateLimitGate::parse_retry_after_value_at("12", now),
            Some(Duration::from_secs(12))
        );
        assert_eq!(
            RateLimitGate::parse_retry_after_value_at("0", now),
            Some(Duration::ZERO)
        );
        assert_eq!(
            RateLimitGate::parse_retry_after_value_at("2.5", now),
            Some(Duration::from_secs_f64(2.5))
        );
        assert_eq!(
            RateLimitGate::parse_retry_after_value_at("9999", now),
            Some(Duration::from_secs(MAX_RETRY_AFTER_SECS))
        );
        assert_eq!(RateLimitGate::parse_retry_after_value_at("-5", now), None);
        assert_eq!(
            RateLimitGate::parse_retry_after_value_at("not-a-date", now),
            None
        );

        // 1_700_000_000 = Tue, 14 Nov 2023 22:13:20 GMT -> +30s = 22:13:50 GMT
        assert_eq!(
            RateLimitGate::parse_retry_after_value_at("Tue, 14 Nov 2023 22:13:50 GMT", now),
            Some(Duration::from_secs(30))
        );
        // Date in the past clamps to 0s
        assert_eq!(
            RateLimitGate::parse_retry_after_value_at("Tue, 14 Nov 2023 22:12:00 GMT", now),
            Some(Duration::ZERO)
        );
        // Far future clamps to MAX_RETRY_AFTER_SECS
        assert_eq!(
            RateLimitGate::parse_retry_after_value_at("Wed, 15 Nov 2023 00:00:00 GMT", now),
            Some(Duration::from_secs(MAX_RETRY_AFTER_SECS))
        );
        // RFC 850 & asctime formats
        assert_eq!(
            RateLimitGate::parse_retry_after_value_at("Tuesday, 14-Nov-23 22:13:35 GMT", now),
            Some(Duration::from_secs(15))
        );
        assert_eq!(
            RateLimitGate::parse_retry_after_value_at("Tue Nov 14 22:13:25 2023", now),
            Some(Duration::from_secs(5))
        );
    }

    #[test]
    fn test_rate_limit_gate_exponential_backoff_and_success_reset() {
        let base = Duration::from_secs(2);
        assert_eq!(
            RateLimitGate::compute_backoff_delay(base, 1),
            Duration::from_secs(2)
        );
        assert_eq!(
            RateLimitGate::compute_backoff_delay(base, 2),
            Duration::from_secs(4)
        );
        assert_eq!(
            RateLimitGate::compute_backoff_delay(base, 3),
            Duration::from_secs(8)
        );
        assert_eq!(
            RateLimitGate::compute_backoff_delay(base, 4),
            Duration::from_secs(16)
        );
        assert_eq!(
            RateLimitGate::compute_backoff_delay(base, 20),
            Duration::from_secs(MAX_RETRY_AFTER_SECS)
        );

        let gate = RateLimitGate::with_default_retry_after(Duration::from_millis(50));
        let t0 = Instant::now();
        gate.record_rate_limited(None, RateLimitFamily::Metadata, "test-1");
        assert_eq!(gate.consecutive_failures(RateLimitFamily::Metadata), 1);
        let d1 = gate
            .blocked_until(RateLimitFamily::Metadata)
            .unwrap()
            .saturating_duration_since(t0);
        assert!(d1 >= Duration::from_millis(45));

        gate.record_rate_limited(None, RateLimitFamily::Metadata, "test-2");
        assert_eq!(gate.consecutive_failures(RateLimitFamily::Metadata), 2);
        let d2 = gate
            .blocked_until(RateLimitFamily::Metadata)
            .unwrap()
            .saturating_duration_since(t0);
        assert!(d2 >= Duration::from_millis(90));

        // Other families remain unaffected
        assert_eq!(gate.consecutive_failures(RateLimitFamily::Transfer), 0);

        // Success resets the failure streak back to 0
        gate.record_success(RateLimitFamily::Metadata);
        assert_eq!(gate.consecutive_failures(RateLimitFamily::Metadata), 0);
    }
}
