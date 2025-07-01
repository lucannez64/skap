//! Security module for SKAP
//! Implements rate limiting, session management, and audit logging

use dashmap::DashMap;
use governor::{Quota, RateLimiter};
use governor::state::InMemoryState;
use log::{info, warn, error};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use uuid::Uuid;
use warp::{Filter, Rejection, Reply};

// Rate limiting configuration
const MAX_REQUESTS_PER_MINUTE: u32 = 60;
const MAX_LOGIN_ATTEMPTS_PER_HOUR: u32 = 5;
const MAX_CONCURRENT_SESSIONS_PER_USER: usize = 3;

// Session tracking
#[derive(Debug, Clone)]
pub struct UserSession {
    pub user_id: Uuid,
    pub token: String,
    pub created_at: SystemTime,
    pub last_activity: SystemTime,
    pub ip_address: Option<IpAddr>,
}

// Security manager
pub struct SecurityManager {
    // Rate limiters
    general_limiter: Arc<RateLimiter<IpAddr, dashmap::DashMap<IpAddr, InMemoryState>, governor::clock::DefaultClock>>,
    login_limiter: Arc<RateLimiter<IpAddr, dashmap::DashMap<IpAddr, InMemoryState>, governor::clock::DefaultClock>>,
    
    // Session management
    active_sessions: Arc<DashMap<String, UserSession>>, // token -> session
    user_sessions: Arc<DashMap<Uuid, Vec<String>>>, // user_id -> tokens
    
    // Audit logging
    audit_events: Arc<RwLock<Vec<AuditEvent>>>,
}

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub timestamp: SystemTime,
    pub event_type: AuditEventType,
    pub user_id: Option<Uuid>,
    pub ip_address: Option<IpAddr>,
    pub details: String,
    pub success: bool,
}

#[derive(Debug, Clone)]
pub enum AuditEventType {
    Login,
    Logout,
    PasswordAccess,
    PasswordCreate,
    PasswordShare,
    RateLimitExceeded,
    SessionLimitExceeded,
    SecurityViolation,
}

impl SecurityManager {
    pub fn new() -> Self {
        // Create rate limiters
        let general_quota = Quota::per_minute(std::num::NonZeroU32::new(MAX_REQUESTS_PER_MINUTE).unwrap());
        let login_quota = Quota::per_hour(std::num::NonZeroU32::new(MAX_LOGIN_ATTEMPTS_PER_HOUR).unwrap());
        
        let general_limiter = Arc::new(RateLimiter::dashmap(general_quota));
        let login_limiter = Arc::new(RateLimiter::dashmap(login_quota));
        
        Self {
            general_limiter,
            login_limiter,
            active_sessions: Arc::new(DashMap::new()),
            user_sessions: Arc::new(DashMap::new()),
            audit_events: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    // Rate limiting methods
    pub async fn check_general_rate_limit(&self, ip: IpAddr) -> Result<(), SecurityError> {
        match self.general_limiter.check_key(&ip) {
            Ok(_) => Ok(()),
            Err(_) => {
                self.log_audit_event(AuditEvent {
                    timestamp: SystemTime::now(),
                    event_type: AuditEventType::RateLimitExceeded,
                    user_id: None,
                    ip_address: Some(ip),
                    details: "General rate limit exceeded".to_string(),
                    success: false,
                }).await;
                Err(SecurityError::RateLimitExceeded)
            }
        }
    }
    
    pub async fn check_login_rate_limit(&self, ip: IpAddr) -> Result<(), SecurityError> {
        match self.login_limiter.check_key(&ip) {
            Ok(_) => Ok(()),
            Err(_) => {
                self.log_audit_event(AuditEvent {
                    timestamp: SystemTime::now(),
                    event_type: AuditEventType::RateLimitExceeded,
                    user_id: None,
                    ip_address: Some(ip),
                    details: "Login rate limit exceeded".to_string(),
                    success: false,
                }).await;
                Err(SecurityError::LoginRateLimitExceeded)
            }
        }
    }
    
    // Session management methods
    pub async fn create_session(&self, user_id: Uuid, token: String, ip: Option<IpAddr>) -> Result<(), SecurityError> {
        // Check concurrent session limit
        let user_session_count = self.user_sessions
            .get(&user_id)
            .map(|sessions| sessions.len())
            .unwrap_or(0);
            
        if user_session_count >= MAX_CONCURRENT_SESSIONS_PER_USER {
            self.log_audit_event(AuditEvent {
                timestamp: SystemTime::now(),
                event_type: AuditEventType::SessionLimitExceeded,
                user_id: Some(user_id),
                ip_address: ip,
                details: format!("Concurrent session limit exceeded: {}", user_session_count),
                success: false,
            }).await;
            return Err(SecurityError::SessionLimitExceeded);
        }
        
        let session = UserSession {
            user_id,
            token: token.clone(),
            created_at: SystemTime::now(),
            last_activity: SystemTime::now(),
            ip_address: ip,
        };
        
        // Add session
        self.active_sessions.insert(token.clone(), session);
        
        // Update user sessions
        self.user_sessions
            .entry(user_id)
            .or_insert_with(Vec::new)
            .push(token.clone());
            
        self.log_audit_event(AuditEvent {
            timestamp: SystemTime::now(),
            event_type: AuditEventType::Login,
            user_id: Some(user_id),
            ip_address: ip,
            details: "Session created successfully".to_string(),
            success: true,
        }).await;
        
        Ok(())
    }
    
    pub async fn remove_session(&self, token: &str) -> Result<(), SecurityError> {
        if let Some((_, session)) = self.active_sessions.remove(token) {
            // Remove from user sessions
            if let Some(mut user_sessions) = self.user_sessions.get_mut(&session.user_id) {
                user_sessions.retain(|t| t != token);
                if user_sessions.is_empty() {
                    drop(user_sessions);
                    self.user_sessions.remove(&session.user_id);
                }
            }
            
            self.log_audit_event(AuditEvent {
                timestamp: SystemTime::now(),
                event_type: AuditEventType::Logout,
                user_id: Some(session.user_id),
                ip_address: session.ip_address,
                details: "Session removed successfully".to_string(),
                success: true,
            }).await;
            
            Ok(())
        } else {
            Err(SecurityError::SessionNotFound)
        }
    }
    
    pub fn update_session_activity(&self, token: &str) -> Result<(), SecurityError> {
        if let Some(mut session) = self.active_sessions.get_mut(token) {
            session.last_activity = SystemTime::now();
            Ok(())
        } else {
            Err(SecurityError::SessionNotFound)
        }
    }
    
    pub fn get_session(&self, token: &str) -> Option<UserSession> {
        self.active_sessions.get(token).map(|s| s.clone())
    }
    
    pub async fn cleanup_expired_sessions(&self) {
        let now = SystemTime::now();
        let session_timeout = Duration::from_secs(3600); // 1 hour
        
        let mut expired_tokens = Vec::new();
        
        for entry in self.active_sessions.iter() {
            let (token, session) = entry.pair();
            if let Ok(duration) = now.duration_since(session.last_activity) {
                if duration > session_timeout {
                    expired_tokens.push(token.clone());
                }
            }
        }
        
        for token in expired_tokens {
            let _ = self.remove_session(&token).await;
        }
    }
    
    pub async fn update_user_session(&self, _user_id: Uuid, token: String) -> Result<(), SecurityError> {
        if let Some(mut session) = self.active_sessions.get_mut(&token) {
            session.last_activity = SystemTime::now();
            Ok(())
        } else {
            Err(SecurityError::SessionNotFound)
        }
    }
    
    // Audit logging methods
    pub async fn log_audit_event(&self, event: AuditEvent) {
        let mut events = self.audit_events.write().await;
        
        // Log to application logger
        match event.event_type {
            AuditEventType::Login => {
                if event.success {
                    info!("[AUDIT] Login successful - User: {:?}, IP: {:?}", event.user_id, event.ip_address);
                } else {
                    warn!("[AUDIT] Login failed - User: {:?}, IP: {:?}, Details: {}", event.user_id, event.ip_address, event.details);
                }
            },
            AuditEventType::RateLimitExceeded | AuditEventType::SessionLimitExceeded | AuditEventType::SecurityViolation => {
                warn!("[AUDIT] Security event - Type: {:?}, IP: {:?}, Details: {}", event.event_type, event.ip_address, event.details);
            },
            _ => {
                info!("[AUDIT] Event - Type: {:?}, User: {:?}, Success: {}, Details: {}", event.event_type, event.user_id, event.success, event.details);
            }
        }
        
        events.push(event);
        
        // Keep only last 10000 events to prevent memory issues
        if events.len() > 10000 {
            events.drain(0..1000);
        }
    }
    
    pub async fn get_audit_events(&self, limit: Option<usize>) -> Vec<AuditEvent> {
        let events = self.audit_events.read().await;
        let limit = limit.unwrap_or(100);
        
        events.iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
    
    // Security metrics
    pub fn get_security_metrics(&self) -> SecurityMetrics {
        SecurityMetrics {
            active_sessions: self.active_sessions.len(),
            total_users_with_sessions: self.user_sessions.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityMetrics {
    pub active_sessions: usize,
    pub total_users_with_sessions: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Login rate limit exceeded")]
    LoginRateLimitExceeded,
    #[error("Session limit exceeded")]
    SessionLimitExceeded,
    #[error("Session not found")]
    SessionNotFound,
}

// Warp filter for rate limiting
pub fn with_rate_limiting(
    security_manager: Arc<SecurityManager>,
) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    warp::addr::remote()
        .and(warp::any().map(move || security_manager.clone()))
        .and_then(|addr: Option<std::net::SocketAddr>, security_manager: Arc<SecurityManager>| async move {
            if let Some(addr) = addr {
                match security_manager.check_general_rate_limit(addr.ip()).await {
                    Ok(_) => Ok(()),
                    Err(_) => Err(warp::reject::custom(RateLimitRejection)),
                }
            } else {
                Ok(())
            }
        })
        .untuple_one()
}

// Warp filter for login rate limiting
pub fn with_login_rate_limiting(
    security_manager: Arc<SecurityManager>,
) -> impl Filter<Extract = (), Error = Rejection> + Clone {
    warp::addr::remote()
        .and(warp::any().map(move || security_manager.clone()))
        .and_then(|addr: Option<std::net::SocketAddr>, security_manager: Arc<SecurityManager>| async move {
            if let Some(addr) = addr {
                match security_manager.check_login_rate_limit(addr.ip()).await {
                    Ok(_) => Ok(()),
                    Err(_) => Err(warp::reject::custom(LoginRateLimitRejection)),
                }
            } else {
                Ok(())
            }
        })
        .untuple_one()
}

// Custom rejection types
#[derive(Debug)]
pub struct RateLimitRejection;
impl warp::reject::Reject for RateLimitRejection {}

#[derive(Debug)]
pub struct LoginRateLimitRejection;
impl warp::reject::Reject for LoginRateLimitRejection {}

// Rejection handler
pub async fn handle_rejections(err: Rejection) -> Result<impl Reply, std::convert::Infallible> {
    if err.find::<RateLimitRejection>().is_some() {
        Ok(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({
                "error": "Rate limit exceeded",
                "code": 429
            })),
            warp::http::StatusCode::TOO_MANY_REQUESTS,
        ))
    } else if err.find::<LoginRateLimitRejection>().is_some() {
        Ok(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({
                "error": "Too many login attempts",
                "code": 429
            })),
            warp::http::StatusCode::TOO_MANY_REQUESTS,
        ))
    } else {
        Ok(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({
                "error": "Internal server error",
                "code": 500
            })),
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
        ))
    }
}