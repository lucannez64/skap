use crate::postgres::PassesPostgres;
use crate::postgres::SharedPassesPostgres;
use crate::postgres::UsersPostgres;
use crate::protocol::ProtocolError;
use crate::protocol::SharedPass;
use crate::protocol::SharedByUser;
use uuid::Uuid;
use crate::protocol::Server as Server2;
use crate::protocol::CK;
use crate::protocol::EP;
use crate::redis::RedisChallenges;
use crate::redis::RedisSecrets;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use core::convert::TryInto;
use pasetors::claims::{Claims, ClaimsValidationRules};
use pasetors::keys::{Generate, SymmetricKey};
use pasetors::token::UntrustedToken;
use pasetors::{local, version4::V4, Local};
use serde::Deserialize;
use serde::Serialize;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::RwLock;
use warp::{reject, reply::Response, Filter, Rejection, Reply};


#[derive(Serialize)]
struct ErrorMessage {
    code: u16,
    message: String,
}

#[derive(Clone, Debug,Serialize, Deserialize)]
struct PasswordsExtended {
    passwords: Vec<(EP, Uuid)>,
    shared_passes: Vec<(SharedPass, Uuid, Uuid)>,
}

#[derive(Debug, Serialize)]
enum ApiError {
    BadRequest(String, bool), // message, is_json_response
    Unauthorized(String, bool), // message, is_json_response
    InternalError(String, bool), // message, is_json_response
    AuthenticationFailed(String, bool), // message, is_json_response
}

impl warp::reject::Reject for ApiError {}

impl ApiError {
    fn to_response(&self) -> Response {
        let (code, message, is_json) = match self {
            ApiError::BadRequest(msg, is_json_hint) => (400, msg, *is_json_hint),
            ApiError::Unauthorized(msg, is_json_hint) => (401, msg, *is_json_hint),
            ApiError::InternalError(msg, is_json_hint) => (500, msg, *is_json_hint),
            ApiError::AuthenticationFailed(msg, is_json_hint) => (401, msg, *is_json_hint),
        };

        if is_json {
            let json_error = ErrorMessage {
                code,
                message: message.to_string(),
            };
            warp::reply::with_status(warp::reply::json(&json_error), warp::http::StatusCode::from_u16(code).unwrap()).into_response()
        } else {
            let error_response = bincode::serialize(message).unwrap_or_default();
            warp::reply::with_status(
                warp::reply::Response::new(error_response.into()),
                warp::http::StatusCode::from_u16(code).unwrap(),
            )
            .into_response()
        }
    }
}

impl From<ApiError> for Infallible {
    fn from(_: ApiError) -> Self {
        unreachable!()
    }
}

// This From implementation is tricky. If an ApiError is converted using .into(),
// it needs to know its format. The is_json_response field now handles this.
// This means that when an ApiError is created, its is_json_response must be set correctly.
impl From<ApiError> for Response {
    fn from(error: ApiError) -> Self {
        error.to_response()
    }
}

pub type ServerArc = Arc<
    RwLock<
        Server2<RedisSecrets, PassesPostgres, RedisChallenges, UsersPostgres, SharedPassesPostgres>,
    >,
>;

// New function for core authentication logic, returning Result<(), ApiError>
async fn auth_validation_logic(
    paseto_key: Arc<RwLock<SymmetricKey<V4>>>,
    path_uuid: &str,
    token_str: Option<String>,
    is_json_response: bool,
) -> Result<(), ApiError> {
    if let Some(token) = token_str {
        let sk_guard = paseto_key.read().await;
        let validation_rules = ClaimsValidationRules::new(); // Default rules

        let untrusted_token = UntrustedToken::<Local, V4>::try_from(&token)
            .map_err(|e| {
                log::debug!("Token format error: {}", e);
                ApiError::Unauthorized("Invalid token format".to_string(), is_json_response)
            })?;

        let trusted_token = local::decrypt(&sk_guard, &untrusted_token, &validation_rules, None, Some(b"skap"))
            .map_err(|e| {
                log::debug!("Token decryption/validation failed: {}", e);
                ApiError::Unauthorized("Token validation failed".to_string(), is_json_response)
            })?;

        let claims = trusted_token.payload_claims().ok_or_else(|| {
            log::debug!("No claims in token");
            ApiError::Unauthorized("No claims in token".to_string(), is_json_response)
        })?;

        let sub = claims
            .get_claim("sub")
            .ok_or_else(|| {
                log::debug!("No subject claim in token");
                ApiError::Unauthorized("No subject claim in token".to_string(), is_json_response)
            })?
            .as_str()
            .ok_or_else(|| {
                log::debug!("Invalid subject claim format");
                ApiError::Unauthorized("Invalid subject claim format".to_string(), is_json_response)
            })?;

        // Normalize both UUIDs by removing hyphens and quotes for a safer comparison
        let normalized_path_uuid = path_uuid.replace(['-', '"'], "");
        let normalized_sub_uuid = sub.replace(['-', '"'], "");
        
        if normalized_path_uuid == normalized_sub_uuid {
            Ok(())
        } else {
            log::debug!("UUID mismatch: path_uuid='{}', token_sub='{}'", normalized_path_uuid, normalized_sub_uuid);
            Err(ApiError::Unauthorized("UUID mismatch".to_string(), is_json_response))
        }
    } else {
        log::debug!("No token provided");
        Err(ApiError::Unauthorized("No token".to_string(), is_json_response))
    }
}

// Custom rejection handler
async fn handle_rejection(rej: Rejection) -> Result<impl Reply, Infallible> {
    if let Some(api_error) = rej.find::<ApiError>() {
        // We have a custom ApiError, use its to_response method
        Ok(api_error.to_response())
    } else if rej.is_not_found() {
        // Default 404
        Ok(ApiError::BadRequest("Not Found".to_string(), true).to_response()) // true for JSON by default for 404
    } else if let Some(e) = rej.find::<warp::filters::body::BodyDeserializeError>() {
        // Handle body deserialization errors
        log::debug!("BodyDeserializeError: {:?}", e);
        // Attempt to guess if JSON was expected. This is imperfect.
        // For now, defaulting to JSON for these errors as they often occur with JSON APIs.
        Ok(ApiError::BadRequest(format!("Invalid request body: {}", e), true).to_response())
    } else if rej.find::<warp::reject::MethodNotAllowed>().is_some() {
        Ok(ApiError::BadRequest("Method Not Allowed".to_string(), true).to_response()) // true for JSON
    } else {
        // For any other errors, log them and return a generic 500 response.
        log::error!("Unhandled rejection: {:?}", rej);
        Ok(ApiError::InternalError("Internal Server Error".to_string(), true).to_response()) // true for JSON
    }
}

// New Warp filter for authentication
fn with_auth(
    paseto_key: Arc<RwLock<SymmetricKey<V4>>>,
    is_json_response: bool,
) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    warp::path::param::<String>() // Expects UUID as a path parameter
        .and(warp::filters::cookie::optional("token"))
        .and(warp::filters::header::optional("Authorization"))
        .and(warp::any().map(move || paseto_key.clone()))
        .and(warp::any().map(move || is_json_response))
        .and_then(
            |path_uuid: String,
             cookie_token: Option<String>,
             header_token: Option<String>,
             key: Arc<RwLock<SymmetricKey<V4>>>,
             is_json: bool| async move {
                let token_to_use = cookie_token.or_else(|| {
                    header_token.and_then(|h| {
                        // Standard "Bearer <token>" format
                        if h.starts_with("Bearer ") {
                            Some(h[7..].to_string())
                        } else {
                            None
                        }
                    })
                });

                match auth_validation_logic(key, &path_uuid, token_to_use, is_json).await {
                    Ok(()) => Ok(path_uuid), // Pass the UUID string if auth succeeds
                    Err(api_error) => Err(warp::reject::custom(api_error)),
                }
            },
        )
}

async fn auth_validation(
    sk: Arc<RwLock<SymmetricKey<V4>>>,
    uuid: &str,
    token: Option<String>,
    is_json: bool,
) -> Result<(), Response> {
    if let Some(token) = token {
        let sk = sk.read().await;
        let validation = ClaimsValidationRules::new();
        let untrusted_token = UntrustedToken::<Local, V4>::try_from(&token)
        .map_err(|_| ApiError::Unauthorized("Invalid token format".to_string(), is_json).to_response())?;

        let trusted_token = local::decrypt(&sk, &untrusted_token, &validation, None, Some(b"skap"))
            .map_err(|_| ApiError::Unauthorized("Token validation failed".to_string(), is_json).to_response())?;

        let claims = trusted_token
            .payload_claims()
            .ok_or_else(|| ApiError::Unauthorized("No claims in token".to_string(), is_json).to_response())?;

        let sub = claims
            .get_claim("sub")
            .ok_or_else(|| ApiError::Unauthorized("No subject claim in token".to_string(), is_json).to_response())?
            .as_str()
            .ok_or_else(|| ApiError::Unauthorized("Invalid subject claim format".to_string(), is_json).to_response())?;

        let normalized_uuid = uuid.replace('-', "").replace('"', "");
        let normalized_sub = sub.replace('-', "").replace('"', "");
        
        if normalized_uuid == normalized_sub {
            Ok(())
        } else {
            Err(ApiError::Unauthorized("UUID mismatch".to_string(), is_json).to_response())
        }
    } else {
        Err(ApiError::Unauthorized("No token".to_string(), is_json).to_response())
    }
}

fn auth_error() -> Result<Response, Infallible> {
    Ok(
        warp::reply::with_status(warp::reply(), warp::http::StatusCode::UNAUTHORIZED)
            .into_response(),
    )
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // Amélioration de la configuration des logs
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            use std::io::Write;
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
            if cfg!(debug_assertions) {
                writeln!(
                    buf,
                    "[{} {} {}:{}] {}",
                    timestamp,
                    record.level(),
                    record.file().unwrap_or("unknown"),
                    record.line().unwrap_or(0),
                    record.args()
                )
            } else {
                writeln!(
                    buf,
                    "[{} {}] {}",
                    timestamp,
                    record.level(),
                    record.args()
                )
            }
        })
        .init();

    let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");
    log::info!("Redis URL configured: {}", redis_url);

    let ca = std::env::var("CA_FILE").expect("CA must be set");
    log::info!("CA file configured: {}", ca);

    log::info!("Creating server instance...");
    let server2 = Arc::new(RwLock::new(
        match Server2::<
            RedisSecrets,
            PassesPostgres,
            RedisChallenges,
            UsersPostgres,
            SharedPassesPostgres,
        >::new_with_redis(&database_url, &redis_url, &ca)
        .await
        {
            Ok(server) => {
                log::info!("Server instance created successfully");
                server
            }
            Err(e) => {
                log::error!("Failed to create server instance: {:?}", e);
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Server initialization error: {:?}", e),
                )));
            }
        },
    ));

    let mut sk: SymmetricKey<V4>;
    if std::env::var("BASE64_KEY").is_err() {
        log::warn!("BASE64_KEY not set, generating new key");
        sk = match SymmetricKey::<V4>::generate() {
            Ok(key) => key,
            Err(e) => {
                log::error!("Failed to generate symmetric key: {:?}", e);
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Key generation error: {:?}", e),
                )));
            }
        };
        log::info!(
            "Generated BASE64_KEY: {}",
            base64::engine::general_purpose::STANDARD.encode(sk.as_bytes())
        );
    } else {
        let base64k = std::env::var("BASE64_KEY").expect("BASE64_KEY must be set");
        log::info!("Using provided BASE64_KEY (length: {})", base64k.len());
        let skbytes = match STANDARD.decode(&base64k) {
            Ok(bytes) => bytes,
            Err(e) => {
                log::error!("Failed to decode BASE64_KEY: {:?}", e);
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Key decoding error: {:?}", e),
                )));
            }
        };
        sk = match SymmetricKey::<V4>::from(&skbytes) {
            Ok(key) => key,
            Err(e) => {
                log::error!("Failed to create symmetric key from bytes: {:?}", e);
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Key creation error: {:?}", e),
                )));
            }
        };
        log::info!("Successfully loaded symmetric key from BASE64_KEY");
    }

    let mutexsk = Arc::new(RwLock::new(sk));
    let server_filter = warp::any().map(move || Arc::clone(&server2));
    let mutexsk_filter = warp::any().map(move || Arc::clone(&mutexsk));
    let cookies_filter = warp::filters::cookie::optional("token");
    let header_filter = warp::filters::header::optional("Authorization");
    let create_user_json = warp::post()
        .and(warp::path("create_user_json"))
        .and(warp::body::json())
        .and(server_filter.clone())
        .and_then(
            |ck: CK, server2: ServerArc| async move { create_user_json_map(ck, &server2).await },
        );

    let send_all =
        warp::get()
            .and(warp::path("send_all"))
            .and(warp::path::param::<String>())
            .and(server_filter.clone())
            .and(with_auth(mutexsk_filter.clone(), false)) // false for binary endpoint
            .and(server_filter.clone())
            // The handler now receives uui directly from with_auth
            .and_then(|uui: String, server2: ServerArc| async move {
                send_all_map(uui, &server2).await
            });

    let send_all_json =
        warp::get()
            .and(warp::path("send_all_json"))
            // .and(warp::path::param::<String>()) // with_auth handles param extraction
            .and(with_auth(mutexsk_filter.clone(), true)) // true for JSON endpoint
            .and(server_filter.clone())
            // The handler now receives uui directly from with_auth
            .and_then(|uui: String, server2: ServerArc| async move {
                send_all_json_map(uui, &server2).await
            });

    let create_user = warp::post()
        .and(warp::path("create_user"))
        .and(warp::body::bytes())
        .and(server_filter.clone())
        .and_then(|body: bytes::Bytes, server2: ServerArc| async move {
            create_user_map(body, &server2).await
        });

    let sync_json =
        warp::get()
            .and(warp::path("sync_json"))
            .and(warp::path::param::<String>())
            .and(server_filter.clone())
            // .and(warp::path::param::<String>()) // with_auth handles param extraction
            .and(with_auth(mutexsk_filter.clone(), true)) // true for JSON
            .and(server_filter.clone())
            .and_then(|uui: String, server2: ServerArc| async move {
                sync_json_map(uui, &server2).await
            });

    let sync =
        warp::get()
            .and(warp::path("sync"))
            // .and(warp::path::param::<String>()) // with_auth handles param extraction
            .and(with_auth(mutexsk_filter.clone(), false)) // false for binary
            .and(server_filter.clone())
            .and_then(|uui: String, server2: ServerArc| async move {
                sync_map(uui, &server2).await
            });

    let create_pass = warp::post()
        .and(warp::path("create_pass"))
        // uui is now from with_auth
        .and(with_auth(mutexsk_filter.clone(), false))
        .and(warp::body::bytes())
        .and(server_filter.clone())
        .and_then(|uui: String, pass: bytes::Bytes, server2: ServerArc| async move {
            create_pass_map(uui, pass, &server2).await
        });

    let create_pass_json = warp::post()
        .and(warp::path("create_pass_json"))
        // uui is now from with_auth
        .and(with_auth(mutexsk_filter.clone(), true))
        .and(warp::body::json())
        .and(server_filter.clone())
        .and_then(|uui: String, pass: EP, server2: ServerArc| async move {
            create_pass_json_map(uui, pass, &server2).await
        });

    let challenge_json = warp::get()
        .and(warp::path("challenge_json"))
        .and(warp::path::param::<String>())
        .and(server_filter.clone())
        .and_then(|uui: String, server2: ServerArc| async move {
            challenge_json_map(uui, &server2).await
        });

    let challenge = warp::get()
        .and(warp::path("challenge"))
        .and(warp::path::param::<String>())
        .and(server_filter.clone())
        .and_then(
            |uui: String, server2: ServerArc| async move { challenge_map(uui, &server2).await },
        );

    let verify = warp::post()
        .and(warp::path("verify"))
        .and(warp::path::param::<String>())
        .and(warp::body::bytes())
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and_then(
            |uui: String,
             body: bytes::Bytes,
             server2: ServerArc,
             mutexsk: Arc<RwLock<SymmetricKey<V4>>>| async move {
                verify_map(uui, body, &server2, &mutexsk).await
            },
        );

    let verify_json = warp::post()
        .and(warp::path("verify_json"))
        .and(warp::path::param::<String>())
        .and(warp::body::json())
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and_then(
            |uui: String,
             body: Vec<u8>,
             server2: ServerArc,
             mutexsk: Arc<RwLock<SymmetricKey<V4>>>| async move {
                verify_json_map(uui, body, &server2, &mutexsk).await
            },
        );

    let update_pass = warp::post()
        .and(warp::path("update_pass"))
            .and(warp::path("update_pass"))
            // uui (user_id) is now from with_auth
            .and(with_auth(mutexsk_filter.clone(), false)) 
            .and(warp::path::param::<String>()) // uui2 (pass_id)
        .and(warp::body::bytes())
        .and(server_filter.clone())
            .and_then(|uui_user: String, uui_pass: String, pass_bytes: bytes::Bytes, server2: ServerArc| async move {
                update_pass_map(uui_user, uui_pass, pass_bytes, &server2).await
            });

    let update_pass_json = warp::post()
        .and(warp::path("update_pass_json"))
        // uui (user_id) is now from with_auth
        .and(with_auth(mutexsk_filter.clone(), true))
        .and(warp::path::param::<String>()) // uui2 (pass_id)
        .and(warp::body::json())
        .and(server_filter.clone())
        .and_then(|uui_user: String, uui_pass: String, pass_data: EP, server2: ServerArc| async move {
            update_pass_json_map(uui_user, uui_pass, pass_data, &server2).await
        });

    let delete = warp::get()
        .and(warp::path("delete_pass"))
        // uui (user_id) is now from with_auth
        .and(with_auth(mutexsk_filter.clone(), false))
        .and(warp::path::param::<String>()) // uui2 (pass_id)
        .and(server_filter.clone())
        .and_then(|uui_user: String, uui_pass: String, server2: ServerArc| async move {
            delete_map(uui_user, uui_pass, &server2).await
        });

    let delete_json = warp::get()
        .and(warp::path("delete_pass_json"))
        // uui (user_id) is now from with_auth
        .and(with_auth(mutexsk_filter.clone(), true))
        .and(warp::path::param::<String>()) // uui2 (pass_id)
        .and(server_filter.clone())
        .and_then(|uui_user: String, uui_pass: String, server2: ServerArc| async move {
            delete_json_map(uui_user, uui_pass, &server2).await
        });

    let send = warp::get()
        .and(warp::path("send"))
        // uui (user_id) is now from with_auth
        .and(with_auth(mutexsk_filter.clone(), false))
        .and(warp::path::param::<String>()) // uui2 (pass_id)
        .and(server_filter.clone())
        .and_then(|uui_user: String, uui_pass: String, server2: ServerArc| async move {
            send_map(uui_user, uui_pass, &server2).await
        });

    let send_json = warp::get()
        .and(warp::path("send_json"))
        // uui (user_id) is now from with_auth
        .and(with_auth(mutexsk_filter.clone(), true))
        .and(warp::path::param::<String>()) // uui2 (pass_id)
        .and(server_filter.clone())
        .and_then(|uui_user: String, uui_pass: String, server2: ServerArc| async move {
            send_json_map(uui_user, uui_pass, &server2).await
        });

    let share_pass = warp::post()
        .and(warp::path("share_pass"))
        // owner (user_id) is now from with_auth
        .and(with_auth(mutexsk_filter.clone(), false)) // owner_id
        .and(warp::path::param::<String>()) // pass_id
        .and(warp::path::param::<String>()) // recipient_id
        .and(warp::body::bytes())
        .and(server_filter.clone())
        .and_then(
            |owner_str: String, pass_id_str: String, recipient_str: String, shared_pass_bytes: bytes::Bytes, server2: ServerArc| async move {
                share_pass_map(owner_str, pass_id_str, recipient_str, shared_pass_bytes, &server2).await
            },
        );

    let share_pass_json = warp::post()
        .and(warp::path("share_pass_json"))
        // owner (user_id) is now from with_auth
        .and(with_auth(mutexsk_filter.clone(), true)) // owner_id
        .and(warp::path::param::<String>()) // pass_id
        .and(warp::path::param::<String>()) // recipient_id
        .and(warp::body::json())
        .and(server_filter.clone())
        .and_then(
            |owner_str: String, pass_id_str: String, recipient_str: String, shared_pass_data: crate::protocol::SharedPass, server2: ServerArc| async move {
                share_pass_json_map(owner_str, pass_id_str, recipient_str, shared_pass_data, &server2).await
            },
        );

    let unshare_pass = warp::post()
        .and(warp::path("unshare_pass"))
        // owner (user_id) is now from with_auth
        .and(with_auth(mutexsk_filter.clone(), false)) // owner_id
        .and(warp::path::param::<String>()) // pass_id
        .and(warp::path::param::<String>()) // recipient_id
        .and(server_filter.clone())
        .and_then(
            |owner_str: String, pass_id_str: String, recipient_str: String, server2: ServerArc| async move {
                unshare_pass_map(owner_str, pass_id_str, recipient_str, &server2).await
            },
        );

    let unshare_pass_json = warp::post()
        .and(warp::path("unshare_pass_json"))
        // owner (user_id) is now from with_auth
        .and(with_auth(mutexsk_filter.clone(), true)) // owner_id
        .and(warp::path::param::<String>()) // pass_id
        .and(warp::path::param::<String>()) // recipient_id
        .and(server_filter.clone())
        .and_then(
            |owner_str: String, pass_id_str: String, recipient_str: String, server2: ServerArc| async move {
                unshare_pass_json_map(owner_str, pass_id_str, recipient_str, &server2).await
            },
        );

    let get_shared_pass = warp::get()
        .and(warp::path("get_shared_pass"))
        // recipient (user_id) is now from with_auth
        .and(with_auth(mutexsk_filter.clone(), false)) // recipient_id
        .and(warp::path::param::<String>()) // owner_id
        .and(warp::path::param::<String>()) // pass_id
        .and(server_filter.clone())
        .and_then(
            |recipient_str: String, owner_str: String, pass_id_str: String, server2: ServerArc| async move {
                get_shared_pass_map(recipient_str, owner_str, pass_id_str, &server2).await
            },
        );

    let get_shared_pass_json = warp::get()
        .and(warp::path("get_shared_pass_json"))
        // recipient (user_id) is now from with_auth
        .and(with_auth(mutexsk_filter.clone(), true)) // recipient_id
        .and(warp::path::param::<String>()) // owner_id
        .and(warp::path::param::<String>()) // pass_id
        .and(server_filter.clone())
        .and_then(
            |recipient_str: String, owner_str: String, pass_id_str: String, server2: ServerArc| async move {
                get_shared_pass_json_map(recipient_str, owner_str, pass_id_str, &server2).await
            },
        );

    let get_uuid_from_email = warp::get()
        .and(warp::path("get_uuid_from_email"))
        .and(warp::path::param::<String>())
        .and(server_filter.clone())
        .and_then(
            |email: String, server2: ServerArc| async move {
                get_uuid_from_email_map(email, &server2).await
            },
        );

    let get_public_key = warp::get()
        .and(warp::path("get_public_key"))
        .and(warp::path::param::<String>())
        .and(server_filter.clone())
        .and_then(
            |id: String, server2: ServerArc| async move {
                let id = match uuid::Uuid::parse_str(&id) {
                    Ok(uuid) => uuid,
                    Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(false)),
                };
                get_public_key_map(id, &server2).await
            },
        );

    let get_shared_by_user = warp::get()
        .and(warp::path("get_shared_by_user"))
        .and(warp::path::param::<String>())
        .and(server_filter.clone())
            .and(with_auth(mutexsk_filter.clone(), false)) // owner_id
            .and(server_filter.clone())
        .and_then(
            |owner_str: String, server2: ServerArc| async move {
                get_shared_by_user_map(owner_str, &server2).await
            },
        );

    let get_uuids_from_emails = warp::post()
        .and(warp::path("get_uuids_from_emails"))
        .and(warp::body::json())
        .and(server_filter.clone())
        .and_then(
            |emails: Vec<String>, server2: ServerArc| async move {
                get_uuids_from_emails_map(emails, &server2).await
            },
        );

    let get_emails_from_uuids = warp::post()
        .and(warp::path("get_emails_from_uuids"))
        .and(warp::body::json())
        .and(server_filter.clone())
        .and_then(
            |uuids: Vec<Uuid>, server2: ServerArc| async move {
                get_emails_from_uuids_map(uuids, &server2).await
            },
        );
    let home = warp::get().and(warp::path::end()).and_then(|| async move {
        Ok::<warp::reply::Response, Infallible>(warp::reply::Response::new("Hello, world!".into()))
    });

    let accept_shared_pass = warp::get()
        .and(warp::path("accept_shared_pass"))
        .and(warp::path::param::<String>()) // recipient id
        .and(warp::path::param::<String>()) // owner id
        .and(warp::path::param::<String>()) // pass id
        .and(server_filter.clone())
            // recipient_id is now from with_auth
            .and(with_auth(mutexsk_filter.clone(), false))
            .and(warp::path::param::<String>()) // owner_id
            .and(warp::path::param::<String>()) // pass_id
            .and(server_filter.clone())
        .and_then(
            |recipient_str: String, owner_str: String, pass_id_str: String, server2: ServerArc| async move {
                accept_shared_pass_map(recipient_str, owner_str, pass_id_str, &server2).await
            },
        );

    let accept_shared_pass_json = warp::get()
        .and(warp::path("accept_shared_pass_json"))
        // recipient_id is now from with_auth
        .and(with_auth(mutexsk_filter.clone(), true))
        .and(warp::path::param::<String>()) // owner_id
        .and(warp::path::param::<String>()) // pass_id
        .and(server_filter.clone())
        .and_then(
            |recipient_str: String, owner_str: String, pass_id_str: String, server2: ServerArc| async move {
                accept_shared_pass_json_map(recipient_str, owner_str, pass_id_str, &server2).await
            },
        );

    let reject_shared_pass = warp::get()
        .and(warp::path("reject_shared_pass"))
        // recipient_id is now from with_auth
        .and(with_auth(mutexsk_filter.clone(), false))
        .and(warp::path::param::<String>()) // owner_id
        .and(warp::path::param::<String>()) // pass_id
        .and(server_filter.clone())
        .and_then(
            |recipient_str: String, owner_str: String, pass_id_str: String, server2: ServerArc| async move {
                reject_shared_pass_map(recipient_str, owner_str, pass_id_str, &server2).await
            },
        );

    let reject_shared_pass_json = warp::get()
        .and(warp::path("reject_shared_pass_json"))
        // recipient_id is now from with_auth
        .and(with_auth(mutexsk_filter.clone(), true))
        .and(warp::path::param::<String>()) // owner_id
        .and(warp::path::param::<String>()) // pass_id
        .and(server_filter.clone())
        .and_then(
            |recipient_str: String, owner_str: String, pass_id_str: String, server2: ServerArc| async move {
                reject_shared_pass_json_map(recipient_str, owner_str, pass_id_str, &server2).await
            },
        );

    let get_shared_pass_status = warp::get()
        .and(warp::path("get_shared_pass_status"))
        // owner_id is now from with_auth
        .and(with_auth(mutexsk_filter.clone(), false))
        .and(warp::path::param::<String>()) // pass_id
        .and(warp::path::param::<String>()) // recipient_id
        .and(server_filter.clone())
        .and_then(
            |owner_str: String, pass_id_str: String, recipient_str: String, server2: ServerArc| async move {
                get_shared_pass_status_map(owner_str, pass_id_str, recipient_str, &server2).await
            },
        );
    let get_shared_pass_status_json = warp::get()
        .and(warp::path("get_shared_pass_status_json"))
        // owner_id is now from with_auth
        .and(with_auth(mutexsk_filter.clone(), true))
        .and(warp::path::param::<String>()) // pass_id
        .and(warp::path::param::<String>()) // recipient_id
        .and(server_filter.clone())
        .and_then(
            |owner_str: String, pass_id_str: String, recipient_str: String, server2: ServerArc| async move {
                get_shared_pass_status_json_map(owner_str, pass_id_str, recipient_str, &server2).await
            },
        );

    let routes = create_user
        .or(challenge)
        .or(sync)
        .or(create_pass)
        .or(send)
        .or(verify)
        .or(send_all)
        .or(update_pass)
        .or(delete)
        .or(create_user_json)
        .or(challenge_json)
        .or(sync_json)
        .or(create_pass_json)
        .or(verify_json)
        .or(send_all_json)
        .or(update_pass_json)
        .or(delete_json)
        .or(send_json)
        .or(share_pass)
        .or(share_pass_json)
        .or(unshare_pass)
        .or(unshare_pass_json)
        .or(get_shared_pass)
        .or(get_shared_pass_json)
        .or(get_uuid_from_email)
        .or(get_public_key)
        .or(get_shared_by_user)
        .or(get_uuids_from_emails)
        .or(get_emails_from_uuids)
        .or(home)
        .or(accept_shared_pass)
        .or(accept_shared_pass_json)
        .or(reject_shared_pass)
        .or(reject_shared_pass_json)
        .or(get_shared_pass_status)
        .or(get_shared_pass_status_json)
        .recover(handle_rejection); // Add rejection handler to the end of the chain

    // Ajout de logs pour les routes

    use log;
    use warp::Filter;

    // Ajout de logs pour les routes
    log::info!("Setting up server routes...");

    // Utiliser la variable d'environnement SERVER_ADDR ou 127.0.0.1:3030 par défaut
    let server_addr = std::env::var("SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:3030".to_string());
    log::info!("Starting server on {}...", server_addr);

    // Convertir la chaîne d'adresse en SocketAddr
    let socket_addr: std::net::SocketAddr = server_addr.parse().unwrap_or_else(|e| {
        log::warn!(
            "Failed to parse SERVER_ADDR '{}': {}. Using default 127.0.0.1:3030",
            server_addr,
            e
        );
        ([0, 0, 0, 0], 3030).into()
    });

    warp::serve(routes).run(socket_addr).await;
    log::info!("Server shutdown");
    Ok(())
}

async fn get_uuid_from_email_map(email: String, server2: &ServerArc) -> Result<Response, Infallible> {
    let server = server2.read().await;
    let uuid = server.get_uuid_from_email(email).await;
    if let Ok(uuid) = uuid {
        Ok(warp::reply::Response::new(uuid.to_string().into()))
    } else {
        Ok(ApiError::BadRequest("Failed to get UUID from email".to_string()).to_response(false))
    }
}

async fn get_uuids_from_emails_map(emails: Vec<String>, server2: &ServerArc) -> Result<Response, Infallible> {
    let server = server2.read().await;
    let uuids = server.get_uuids_from_emails(emails).await;
    if let Ok(uuids) = uuids {
        Ok(warp::reply::json(&uuids).into_response())
    } else {
        Ok(ApiError::BadRequest("Failed to get UUIDs from emails".to_string()).to_response(false))
    }
}

//************************************************************************************************//
// START get_shared_pass_status
//************************************************************************************************//
async fn logic_get_shared_pass_status(
    owner_id: Uuid,
    pass_id: Uuid,
    recipient_id: Uuid,
    server_arc: &ServerArc,
) -> Result<crate::protocol::SharedPassStatus, ProtocolError> {
    let server = server_arc.read().await;
    server.get_shared_pass_status(owner_id, pass_id, recipient_id).await
}

async fn get_shared_pass_status_map(
    owner_str: String,
    pass_id_str: String,
    recipient_str: String,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let owner_id = match uuid::Uuid::parse_str(&owner_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid owner UUID format".to_string()).to_response(false)),
    };
    let pass_id = match uuid::Uuid::parse_str(&pass_id_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid pass UUID format".to_string()).to_response(false)),
    };
    let recipient_id = match uuid::Uuid::parse_str(&recipient_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid recipient UUID format".to_string()).to_response(false)),
    };

    match logic_get_shared_pass_status(owner_id, pass_id, recipient_id, server2).await {
        Ok(status) => {
            match bincode::serialize(&status) {
                Ok(serialized) => Ok(warp::reply::Response::new(serialized.into())),
                Err(e) => {
                    log::error!("Failed to serialize status for get_shared_pass_status_map: {:?}", e);
                    Ok(ApiError::InternalError("Failed to serialize response".to_string()).to_response(false))
                }
            }
        }
        Err(protocol_error) => {
            log::warn!("Failed to get shared pass status (binary): {} (owner: {}, pass: {}, recipient: {})", protocol_error, owner_id, pass_id, recipient_id);
            Ok(ApiError::BadRequest(format!("Failed to get shared pass status: {}", protocol_error)).to_response(false))
        }
    }
}

async fn get_shared_pass_status_json_map(
    owner_str: String,
    pass_id_str: String,
    recipient_str: String,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let owner_id = match uuid::Uuid::parse_str(&owner_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid owner UUID format".to_string()).to_response(true)),
    };
    let pass_id = match uuid::Uuid::parse_str(&pass_id_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid pass UUID format".to_string()).to_response(true)),
    };
    let recipient_id = match uuid::Uuid::parse_str(&recipient_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid recipient UUID format".to_string()).to_response(true)),
    };

    match logic_get_shared_pass_status(owner_id, pass_id, recipient_id, server2).await {
        Ok(status) => Ok(warp::reply::json(&status).into_response()),
        Err(protocol_error) => {
            log::warn!("Failed to get shared pass status (JSON): {} (owner: {}, pass: {}, recipient: {})", protocol_error, owner_id, pass_id, recipient_id);
            Ok(ApiError::BadRequest(format!("Failed to get shared pass status: {}", protocol_error)).to_response(true))
        }
    }
}
// END get_shared_pass_status
//************************************************************************************************//

async fn get_emails_from_uuids_map(uuids: Vec<Uuid>, server2: &ServerArc) -> Result<Response, Infallible> {
    let server = server2.read().await;
    let emails = server.get_emails_from_uuids(uuids).await;
    if let Ok(emails) = emails {
        Ok(warp::reply::json(&emails).into_response())
    } else {
        Ok(ApiError::BadRequest("Failed to get emails from UUIDs".to_string()).to_response(false))
    }
}

async fn get_public_key_map(id: Uuid, server2: &ServerArc) -> Result<Response, Infallible> {
    let server = server2.read().await;
    let public_key = server.get_public_key(id).await;
    if let Ok(public_key) = public_key {
        Ok(warp::reply::json(&public_key.to_vec()).into_response())
    } else {
        Ok(ApiError::BadRequest("Failed to get public key".to_string()).to_response(false))
    }
}

async fn get_shared_by_user_map(owner: String, server2: &ServerArc) -> Result<Response, Infallible> {
    let server = server2.read().await;
    let owner = match uuid::Uuid::parse_str(&owner) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(false)),
    };
    let shared_by_user = server.get_shared_by_user(owner).await;
    if let Ok(shared_by_user) = shared_by_user {
        Ok(warp::reply::json(&shared_by_user).into_response())
    } else {
        Ok(ApiError::BadRequest("Failed to get shared by user".to_string()).to_response(false))
    }
}

async fn accept_shared_pass_map(recipient: String, owner: String, pass_id: String, server2: &ServerArc) -> Result<Response, Infallible> {
    let mut server = server2.write().await;
    let recipient = match uuid::Uuid::parse_str(&recipient) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(false)),
    };
    let owner = match uuid::Uuid::parse_str(&owner) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(false)),
    };
    let pass_id = match uuid::Uuid::parse_str(&pass_id) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(false)),
    };
    let shared_pass = server.accept_shared_pass(owner, pass_id, recipient).await;
    if let Err(e) = shared_pass {
        return Ok(ApiError::BadRequest(e.to_string()).to_response(false));
    }
    Ok(warp::reply::Response::new(bincode::serialize(&"OK").unwrap().into()))
}

async fn accept_shared_pass_json_map(recipient: String, owner: String, pass_id: String, server2: &ServerArc) -> Result<Response, Infallible> {
    let mut server = server2.write().await;
    let recipient = match uuid::Uuid::parse_str(&recipient) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(true)),
    };
    let owner = match uuid::Uuid::parse_str(&owner) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(true)),
    };
    let pass_id = match uuid::Uuid::parse_str(&pass_id) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(true)),
    };
    let shared_pass = server.accept_shared_pass(owner, pass_id, recipient).await;
    if let Err(e) = shared_pass {
        return Ok(ApiError::BadRequest(e.to_string()).to_response(true));
    }
    Ok(warp::reply::json(&"OK").into_response())
}

async fn reject_shared_pass_map(recipient: String, owner: String, pass_id: String, server2: &ServerArc) -> Result<Response, Infallible> {
    let mut server = server2.write().await;
    let recipient = match uuid::Uuid::parse_str(&recipient) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(false)),
    };
    let owner = match uuid::Uuid::parse_str(&owner) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(false)),
    };
    let pass_id = match uuid::Uuid::parse_str(&pass_id) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(false)),
    };
    let shared_pass = server.reject_shared_pass(owner, pass_id, recipient).await;
    if let Err(e) = shared_pass {
        return Ok(ApiError::BadRequest(e.to_string()).to_response(false));
    }
    Ok(warp::reply::Response::new(bincode::serialize(&"OK").unwrap().into()))
}

async fn reject_shared_pass_json_map(recipient: String, owner: String, pass_id: String, server2: &ServerArc) -> Result<Response, Infallible> {
    let mut server = server2.write().await;
    let recipient = match uuid::Uuid::parse_str(&recipient) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(true)),
    };
    let owner = match uuid::Uuid::parse_str(&owner) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(true)),
    };
    let pass_id = match uuid::Uuid::parse_str(&pass_id) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(true)),
    };
    let shared_pass = server.reject_shared_pass(owner, pass_id, recipient).await;
    if let Err(e) = shared_pass {
        return Ok(ApiError::BadRequest(e.to_string()).to_response(true));
    }
    Ok(warp::reply::json(&"OK").into_response())
}

//************************************************************************************************//
// START create_user
//************************************************************************************************//
async fn logic_create_user(mut ck: CK, server_arc: &ServerArc) -> Result<CK, ProtocolError> {
    let mut server_lock = server_arc.write().await;
    log::info!("Adding new user with email: {}", ck.email);
    // The add_user method in the server's core logic is expected to populate the ID in ck.
    let uuid = server_lock.add_user(&mut ck).await?;
    log::info!("User created successfully with uuid {} and email {}", uuid, ck.email);
    // add_user in postgres.rs ensures ck.id is set.
    Ok(ck)
}

//************************************************************************************************//
// START delete_pass
//************************************************************************************************//
async fn logic_delete_pass(user_id: Uuid, pass_id: Uuid, server_arc: &ServerArc) -> Result<(), ProtocolError> {
    let mut server = server_arc.write().await;
    server.delete_pass(user_id, pass_id).await
}

async fn delete_map(
    uui_user: String,
    uui_pass: String,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let user_id = match uuid::Uuid::parse_str(&uui_user) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid user UUID format".to_string()).to_response(false)),
    };
    let pass_id = match uuid::Uuid::parse_str(&uui_pass) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid pass UUID format".to_string()).to_response(false)),
    };

    match logic_delete_pass(user_id, pass_id, server2).await {
        Ok(()) => {
            match bincode::serialize(&"Pass deleted successfully") {
                Ok(serialized) => Ok(warp::reply::Response::new(serialized.into())),
                Err(e) => {
                    log::error!("Failed to serialize success message for delete_map: {:?}",e);
                    Ok(ApiError::InternalError("Failed to serialize response".to_string()).to_response(false))
                }
            }
        }
        Err(protocol_error) => {
            log::error!("Failed to delete pass (binary): {:?}", protocol_error);
            Ok(ApiError::InternalError(format!("Failed to delete pass: {}", protocol_error)).to_response(false))
        }
    }
}

async fn delete_json_map(
    uui_user: String,
    uui_pass: String,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let user_id = match uuid::Uuid::parse_str(&uui_user) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid user UUID format".to_string()).to_response(true)),
    };
    let pass_id = match uuid::Uuid::parse_str(&uui_pass) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid pass UUID format".to_string()).to_response(true)),
    };

    match logic_delete_pass(user_id, pass_id, server2).await {
        Ok(()) => Ok(warp::reply::json(&"Pass deleted successfully").into_response()),
        Err(protocol_error) => {
            log::error!("Failed to delete pass (JSON): {:?}", protocol_error);
            Ok(ApiError::InternalError(format!("Failed to delete pass: {}", protocol_error)).to_response(true))
        }
    }
}
// END delete_pass
//************************************************************************************************//

//************************************************************************************************//
// START challenge
//************************************************************************************************//
async fn logic_challenge(user_id: Uuid, server_arc: &ServerArc) -> Result<Vec<u8>, ProtocolError> {
    let mut server = server_arc.write().await;
    server.challenge(user_id).await
}

async fn challenge_map(uui: String, server2: &ServerArc) -> Result<Response, Infallible> {
    let user_id = match uuid::Uuid::parse_str(&uui) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(false)),
    };

    match logic_challenge(user_id, server2).await {
        Ok(challenge_data) => {
            match bincode::serialize(&challenge_data) {
                Ok(serialized) => Ok(warp::reply::Response::new(serialized.into())),
                Err(e) => {
                    log::error!("Failed to serialize challenge data for challenge_map: {:?}", e);
                    Ok(ApiError::InternalError("Failed to serialize challenge".to_string()).to_response(false))
                }
            }
        }
        Err(ProtocolError::UserNotFound) => {
            Ok(ApiError::BadRequest("User not found".to_string()).to_response(false))
        }
        Err(protocol_error) => {
            log::error!("Failed to generate challenge (binary): {:?}", protocol_error);
            Ok(ApiError::InternalError(format!("Failed to generate challenge: {}", protocol_error)).to_response(false))
        }
    }
}

async fn challenge_json_map(uui: String, server2: &ServerArc) -> Result<Response, Infallible> {
    let user_id = match uuid::Uuid::parse_str(&uui) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(true)),
    };

    match logic_challenge(user_id, server2).await {
        Ok(challenge_data) => Ok(warp::reply::json(&challenge_data).into_response()),
        Err(ProtocolError::UserNotFound) => {
            Ok(ApiError::BadRequest("User not found".to_string()).to_response(true))
        }
        Err(protocol_error) => {
            log::error!("Failed to generate challenge (JSON): {:?}", protocol_error);
            Ok(ApiError::InternalError(format!("Failed to generate challenge: {}", protocol_error)).to_response(true))
        }
    }
}
// END challenge
//************************************************************************************************//

//************************************************************************************************//
// START verify
//************************************************************************************************//
async fn logic_verify(user_id: Uuid, proof: &[u8], server_arc: &ServerArc) -> Result<(), ProtocolError> {
    let server = server_arc.read().await;
    server.verify(user_id, proof).await
}

async fn verify_map(
    uui: String,
    body_bytes: bytes::Bytes,
    server2: &ServerArc,
    mutexsk: &Arc<RwLock<SymmetricKey<V4>>>,
) -> Result<Response, Infallible> {
    let user_id = match uuid::Uuid::parse_str(&uui) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(false)),
    };

    let proof = match bincode::deserialize::<Vec<u8>>(&body_bytes) {
        Ok(p) => p,
        Err(_) => return Ok(ApiError::BadRequest("Invalid proof format".to_string()).to_response(false)),
    };

    match logic_verify(user_id, &proof, server2).await {
        Ok(()) => {
            let sk = mutexsk.read().await;
            let mut claims = match Claims::new() {
                Ok(cl) => cl,
                Err(_) => return Ok(ApiError::InternalError("Failed to create claims".to_string()).to_response(false)),
            };

            if claims.subject(&user_id.to_string()).is_err() {
                return Ok(ApiError::InternalError("Failed to set subject claim".to_string()).to_response(false));
            }

            let token = match local::encrypt(&sk, &claims, None, Some(b"skap")) {
                Ok(t) => t,
                Err(_) => return Ok(ApiError::InternalError("Failed to create token".to_string()).to_response(false)),
            };

            Ok(warp::reply::with_header(
                token.clone(), // Token is sent raw in the body
                "set-cookie",
                format!("token={}; Path=/; HttpOnly; Max-Age=3600; SameSite=Strict", token),
            ).into_response())
        }
        Err(_) => Ok(ApiError::AuthenticationFailed("Authentication failed".to_string()).to_response(false)),
    }
}

async fn verify_json_map(
    uui: String,
    body_vec: Vec<u8>, // Warp already deserialized this if it was a JSON array of numbers.
                       // If it was a base64 string in JSON, this needs custom deserialization.
                       // Assuming body_vec is the raw proof bytes.
    server2: &ServerArc,
    mutexsk: &Arc<RwLock<SymmetricKey<V4>>>,
) -> Result<Response, Infallible> {
    let user_id = match uuid::Uuid::parse_str(&uui) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(true)),
    };

    // The `body: Vec<u8>` from `warp::body::json()` implies that the JSON payload was an array of numbers.
    // If the client sends a base64 encoded string for the proof, this would need custom handling.
    // Assuming `body_vec` is the correct proof.
    match logic_verify(user_id, &body_vec, server2).await {
        Ok(()) => {
            let sk = mutexsk.read().await;
            let mut claims = match Claims::new() {
                Ok(cl) => cl,
                Err(_) => return Ok(ApiError::InternalError("Failed to create claims".to_string()).to_response(true)),
            };

            if claims.subject(&user_id.to_string()).is_err() {
                return Ok(ApiError::InternalError("Failed to set subject claim".to_string()).to_response(true));
            }

            let token = match local::encrypt(&sk, &claims, None, Some(b"skap")) {
                Ok(t) => t,
                Err(_) => return Ok(ApiError::InternalError("Failed to create token".to_string()).to_response(true)),
            };

            Ok(warp::reply::with_header(
                warp::reply::json(&token), // Token is JSON serialized in the body
                "set-cookie",
                format!("token={}; Path=/; HttpOnly; Max-Age=3600; SameSite=Strict", token),
            ).into_response())
        }
        Err(_) => Ok(ApiError::AuthenticationFailed("Authentication failed".to_string()).to_response(true)),
    }
}
// END verify
//************************************************************************************************//

//************************************************************************************************//
// START update_pass
//************************************************************************************************//
async fn logic_update_pass(user_id: Uuid, pass_id: Uuid, pass_data: EP, server_arc: &ServerArc) -> Result<(), ProtocolError> {
    let mut server = server_arc.write().await;
    server.update_pass(user_id, pass_id, pass_data).await
}

async fn update_pass_map(
    uui_user: String,
    uui_pass: String,
    pass_bytes: bytes::Bytes,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let user_id = match uuid::Uuid::parse_str(&uui_user) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid user UUID format".to_string()).to_response(false)),
    };
    let pass_id = match uuid::Uuid::parse_str(&uui_pass) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid pass UUID format".to_string()).to_response(false)),
    };
    let pass_data = match bincode::deserialize::<EP>(&pass_bytes) {
        Ok(ep) => ep,
        Err(e) => {
            log::error!("Failed to deserialize pass data for update_pass_map: {:?}", e);
            return Ok(ApiError::BadRequest("Invalid pass data format".to_string()).to_response(false));
        }
    };

    match logic_update_pass(user_id, pass_id, pass_data, server2).await {
        Ok(()) => {
            match bincode::serialize(&pass_id) { // Return the pass_id
                Ok(serialized) => Ok(warp::reply::Response::new(serialized.into())),
                Err(e) => {
                    log::error!("Failed to serialize pass_id for update_pass_map: {:?}", e);
                    Ok(ApiError::InternalError("Failed to serialize response".to_string()).to_response(false))
                }
            }
        }
        Err(protocol_error) => {
            log::error!("Failed to update pass (binary): {:?}", protocol_error);
            Ok(ApiError::InternalError(format!("Failed to update pass: {}", protocol_error)).to_response(false))
        }
    }
}

async fn update_pass_json_map(
    uui_user: String,
    uui_pass: String,
    pass_data: EP, // Already deserialized by Warp
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let user_id = match uuid::Uuid::parse_str(&uui_user) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid user UUID format".to_string()).to_response(true)),
    };
    let pass_id = match uuid::Uuid::parse_str(&uui_pass) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid pass UUID format".to_string()).to_response(true)),
    };

    match logic_update_pass(user_id, pass_id, pass_data, server2).await {
        Ok(()) => Ok(warp::reply::json(&pass_id).into_response()), // Return the pass_id
        Err(protocol_error) => {
            log::error!("Failed to update pass (JSON): {:?}", protocol_error);
            Ok(ApiError::InternalError(format!("Failed to update pass: {}", protocol_error)).to_response(true))
        }
    }
}
// END update_pass
//************************************************************************************************//

//************************************************************************************************//
// START send
//************************************************************************************************//
async fn logic_send(user_id: Uuid, pass_id: Uuid, server_arc: &ServerArc) -> Result<EP, ProtocolError> {
    let server = server_arc.read().await;
    server.send(user_id, pass_id).await
}

async fn send_map(uui_user: String, uui_pass: String, server2: &ServerArc) -> Result<Response, Infallible> {
    let user_id = match uuid::Uuid::parse_str(&uui_user) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid user UUID format".to_string()).to_response(false)),
    };
    let pass_id = match uuid::Uuid::parse_str(&uui_pass) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid pass UUID format".to_string()).to_response(false)),
    };

    match logic_send(user_id, pass_id, server2).await {
        Ok(encrypted_pass) => {
            match bincode::serialize(&encrypted_pass) {
                Ok(serialized) => Ok(warp::reply::Response::new(serialized.into())),
                Err(e) => {
                    log::error!("Failed to serialize encrypted_pass for send_map: {:?}", e);
                    Ok(ApiError::InternalError("Failed to serialize response".to_string()).to_response(false))
                }
            }
        }
        Err(ProtocolError::UserNotFound) => {
            Ok(ApiError::BadRequest("User not found".to_string()).to_response(false))
        }
        Err(ProtocolError::PassNotFound) => {
            Ok(ApiError::BadRequest("Pass not found".to_string()).to_response(false))
        }
        Err(protocol_error) => {
            log::error!("Failed to send pass (binary): {:?}", protocol_error);
            Ok(ApiError::InternalError(format!("Failed to send pass: {}", protocol_error)).to_response(false))
        }
    }
}

async fn send_json_map(
    uui_user: String,
    uui_pass: String,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let user_id = match uuid::Uuid::parse_str(&uui_user) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid user UUID format".to_string()).to_response(true)),
    };
    let pass_id = match uuid::Uuid::parse_str(&uui_pass) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid pass UUID format".to_string()).to_response(true)),
    };

    match logic_send(user_id, pass_id, server2).await {
        Ok(encrypted_pass) => Ok(warp::reply::json(&encrypted_pass).into_response()),
        Err(ProtocolError::UserNotFound) => {
            Ok(ApiError::BadRequest("User not found".to_string()).to_response(true))
        }
        Err(ProtocolError::PassNotFound) => {
            Ok(ApiError::BadRequest("Pass not found".to_string()).to_response(true))
        }
        Err(protocol_error) => {
            log::error!("Failed to send pass (JSON): {:?}", protocol_error);
            Ok(ApiError::InternalError(format!("Failed to send pass: {}", protocol_error)).to_response(true))
        }
    }
}
// END send
//************************************************************************************************//

//************************************************************************************************//
// START create_pass
//************************************************************************************************//
async fn logic_create_pass(user_id: Uuid, pass: EP, server_arc: &ServerArc) -> Result<Uuid, ProtocolError> {
    let mut server = server_arc.write().await;
    server.create_pass(user_id, pass).await // This returns Result<Uuid, ProtocolError>
}

async fn create_pass_map(
    uui: String,
    pass_bytes: bytes::Bytes,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let user_id = match uuid::Uuid::parse_str(&uui) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid user UUID format".to_string()).to_response(false)),
    };

    let pass_data = match bincode::deserialize::<EP>(&pass_bytes) {
        Ok(ep) => ep,
        Err(e) => {
            log::error!("Failed to deserialize pass data for create_pass_map: {:?}", e);
            return Ok(ApiError::BadRequest("Invalid pass data format".to_string()).to_response(false));
        }
    };

    match logic_create_pass(user_id, pass_data, server2).await {
        Ok(pass_id) => {
            match bincode::serialize(&pass_id) {
                Ok(serialized) => Ok(warp::reply::Response::new(serialized.into())),
                Err(e) => {
                    log::error!("Failed to serialize pass_id for create_pass_map: {:?}", e);
                    Ok(ApiError::InternalError("Failed to serialize response".to_string()).to_response(false))
                }
            }
        }
        Err(protocol_error) => {
            log::error!("Failed to create pass (binary): {:?}", protocol_error);
            Ok(ApiError::InternalError(format!("Failed to create pass: {}", protocol_error)).to_response(false))
        }
    }
}

async fn create_pass_json_map(
    uui: String,
    pass: EP, // Already deserialized by Warp
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let user_id = match uuid::Uuid::parse_str(&uui) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid user UUID format".to_string()).to_response(true)),
    };

    match logic_create_pass(user_id, pass, server2).await {
        Ok(pass_id) => Ok(warp::reply::json(&pass_id).into_response()),
        Err(protocol_error) => {
            log::error!("Failed to create pass (JSON): {}", protocol_error.to_string());
            Ok(ApiError::InternalError(format!("Failed to create pass: {}", protocol_error)).to_response(true))
        }
    }
}
// END create_pass
//************************************************************************************************//

//************************************************************************************************//
// START reject_shared_pass
//************************************************************************************************//
async fn logic_reject_shared_pass(
    recipient_id: Uuid,
    owner_id: Uuid,
    pass_id: Uuid,
    server_arc: &ServerArc,
) -> Result<(), ProtocolError> {
    let mut server = server_arc.write().await;
    // The server.reject_shared_pass method takes owner_id, pass_id, recipient_id
    server.reject_shared_pass(owner_id, pass_id, recipient_id).await
}

async get_public_key_map(id: Uuid, server2: &ServerArc) -> Result<Response, Infallible> {
    let mut server = server2.write().await;
    let id = uuid::Uuid::parse_str(&uui);
    if id.is_err() {
        return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).into());
    }
    match server.sync(id.unwrap()).await {
        Ok(ciphertextsync) => Ok(warp::reply::Response::new(
            bincode::serialize(&ciphertextsync.to_vec()).unwrap().into(),
        )),
        Err(_) => Ok(ApiError::InternalError("Failed to sync data".to_string()).into()),
    }
}

async fn sync_json_map(uui: String, server2: &ServerArc) -> Result<Response, Infallible> {
    let mut server = server2.write().await;

    let id = match uuid::Uuid::parse_str(&uui) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(true)),
    };

    match server.sync(id).await {
        Ok(ciphertextsync) => Ok(warp::reply::json(&ciphertextsync.to_vec()).into_response()),
        Err(_) => Ok(ApiError::InternalError("Failed to sync data".to_string()).to_response(true)),
    }
}

async fn create_user_map(body: bytes::Bytes, server2: &ServerArc) -> Result<Response, Infallible> {
    log::debug!("Attempting to deserialize user data for binary create_user, length: {}", body.len());
    let ck = match bincode::deserialize::<CK>(&body) {
        Ok(ck) => ck,
        Err(e) => {
            log::error!("Failed to deserialize user data for binary create_user: {:?}", e);
            return Ok(ApiError::BadRequest("Invalid user data format".to_string()).to_response(false));
        }
    };

    match logic_create_user(ck, server2).await {
        Ok(created_ck) => { // created_ck has the ID populated by logic_create_user
            match bincode::serialize(&created_ck) {
                Ok(serialized) => {
                    log::debug!("User data serialized successfully for binary response, length: {}", serialized.len());
                    Ok(warp::reply::Response::new(serialized.into()))
                }
                Err(e) => {
                    log::error!("Failed to serialize user data for binary response: {:?}", e);
                    Ok(ApiError::InternalError("Failed to serialize user data".to_string()).to_response(false))
                }
            }
        }
        Err(protocol_error) => {
            log::error!("Failed to create user (binary): {:?}", protocol_error);
            Ok(ApiError::InternalError(format!("Failed to create user: {}", protocol_error)).to_response(false))
        }
    }
}

async fn create_user_json_map(ck: CK, server2: &ServerArc) -> Result<Response, Infallible> {
    match logic_create_user(ck, server2).await {
        Ok(created_ck) => { // created_ck has the ID populated
            Ok(warp::reply::json(&created_ck).into_response())
        }
        Err(protocol_error) => {
            log::error!("Failed to create user (JSON): {:?}", protocol_error);
            Ok(ApiError::InternalError(format!("Failed to create user: {}", protocol_error)).to_response(true))
        }
    }
}
// END create_user
//************************************************************************************************//

//************************************************************************************************//
// START send_all
//************************************************************************************************//
async fn logic_send_all(
    user_id: Uuid,
    server_arc: &ServerArc,
) -> Result<(Vec<(EP, Uuid)>, Vec<(SharedPass, Uuid, Uuid)>), ProtocolError> {
    let server = server_arc.read().await;
    let passwords = server.send_all(user_id).await?;
    // According to the original send_all_json_map, if get_all_shared_passes fails,
    // it still proceeds with just passwords for JSON. We should decide if this is the desired behavior.
    // For now, let's assume get_all_shared_passes failing is not critical for the primary passwords part.
    // If it should be critical, this logic needs adjustment.
    let shared_passes = server.get_all_shared_passes(user_id).await.unwrap_or_else(|_| Vec::new());
    Ok((passwords, shared_passes))
}

async fn send_all_map(uui: String, server2: &ServerArc) -> Result<Response, Infallible> {
    let id = match uuid::Uuid::parse_str(&uui) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(false)),
    };

    match logic_send_all(id, server2).await {
        Ok((passwords, _)) => { // Ignore shared_passes for the binary version
            match bincode::serialize(&passwords) {
                Ok(serialized) => Ok(warp::reply::Response::new(serialized.into())),
                Err(e) => {
                    log::error!("Failed to serialize passwords for send_all_map: {:?}", e);
                    Ok(ApiError::InternalError("Failed to serialize data".to_string()).to_response(false))
                }
            }
        }
        Err(protocol_error) => {
            log::error!("Failed to send all (binary): {:?}", protocol_error);
            Ok(ApiError::InternalError(format!("Failed to retrieve data: {}", protocol_error)).to_response(false))
        }
    }
}

async fn send_all_json_map(uui: String, server2: &ServerArc) -> Result<Response, Infallible> {
    let id = match uuid::Uuid::parse_str(&uui) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(true)),
    };

    match logic_send_all(id, server2).await {
        Ok((passwords, shared_passes)) => {
            let passwords_extended = PasswordsExtended {
                passwords,
                shared_passes,
            };
            Ok(warp::reply::json(&passwords_extended).into_response())
        }
        Err(protocol_error) => {
            log::error!("Failed to send all (JSON): {:?}", protocol_error);
            // If logic_send_all returns an error, it means primary passwords failed.
            // The original code would attempt to return just passwords if shared_passes failed,
            // but logic_send_all now bundles this. If primary passwords fail, we error out.
            Ok(ApiError::InternalError(format!("Failed to retrieve data: {}", protocol_error)).to_response(true))
        }
    }
}
// END send_all
//************************************************************************************************//

//************************************************************************************************//
// START sync
//************************************************************************************************//
async fn logic_sync(user_id: Uuid, server_arc: &ServerArc) -> Result<Vec<u8>, ProtocolError> {
    let mut server = server_arc.write().await;
    server.sync(user_id).await // This returns Result<CiphertextSync, ProtocolError> (CiphertextSync is Vec<u8>)
}

// Fonction utilitaire pour parser un UUID avec gestion d'erreur
fn parse_uuid(uuid_str: &str, field_name: &str, is_json: bool) -> Result<Uuid, Response> {
    uuid::Uuid::parse_str(uuid_str).map_err(|_| {
        ApiError::BadRequest(format!("Invalid UUID format for {}", field_name)).to_response(is_json)
    })
}

//************************************************************************************************//
// START share_pass
//************************************************************************************************//
async fn logic_share_pass(
    owner_id: Uuid,
    pass_id: Uuid,
    recipient_id: Uuid,
    shared_pass_data: crate::protocol::SharedPass,
    server_arc: &ServerArc,
) -> Result<(), ProtocolError> {
    let mut server = server_arc.write().await;
    server.store_shared_pass(owner_id, pass_id, recipient_id, shared_pass_data).await
}

async fn share_pass_map(
    owner_str: String,
    pass_id_str: String,
    recipient_str: String,
    shared_pass_bytes: bytes::Bytes,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let owner_id = match parse_uuid(&owner_str, "owner ID", false) {
        Ok(uuid) => uuid,
        Err(response) => return Ok(response),
    };
    let pass_id = match parse_uuid(&pass_id_str, "pass ID", false) {
        Ok(uuid) => uuid,
        Err(response) => return Ok(response),
    };
    let recipient_id = match parse_uuid(&recipient_str, "recipient ID", false) {
        Ok(uuid) => uuid,
        Err(response) => return Ok(response),
    };

    let shared_pass_data = match bincode::deserialize::<crate::protocol::SharedPass>(&shared_pass_bytes) {
        Ok(pass) => pass,
        Err(e) => {
            log::error!("Failed to deserialize shared_pass_data for share_pass_map: {:?}", e);
            return Ok(ApiError::BadRequest("Invalid shared pass data format".to_string()).to_response(false));
        }
    };

    match logic_share_pass(owner_id, pass_id, recipient_id, shared_pass_data, server2).await {
        Ok(()) => {
            match bincode::serialize(&"Password shared successfully") {
                Ok(serialized) => Ok(warp::reply::Response::new(serialized.into())),
                Err(e) => {
                    log::error!("Failed to serialize success message for share_pass_map: {:?}", e);
                    Ok(ApiError::InternalError("Failed to serialize response".to_string()).to_response(false))
                }
            }
        }
        Err(protocol_error) => {
            log::error!("Failed to share password (binary): {:?}", protocol_error);
            Ok(ApiError::InternalError(format!("Failed to share password: {}", protocol_error)).to_response(false))
        }
    }
}

async fn share_pass_json_map(
    owner_str: String,
    pass_id_str: String,
    recipient_str: String,
    shared_pass_data: crate::protocol::SharedPass, // Already deserialized by Warp
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let owner_id = match parse_uuid(&owner_str, "owner ID", true) {
        Ok(uuid) => uuid,
        Err(response) => return Ok(response),
    };
    let pass_id = match parse_uuid(&pass_id_str, "pass ID", true) {
        Ok(uuid) => uuid,
        Err(response) => return Ok(response),
    };
    let recipient_id = match parse_uuid(&recipient_str, "recipient ID", true) {
        Ok(uuid) => uuid,
        Err(response) => return Ok(response),
    };

    match logic_share_pass(owner_id, pass_id, recipient_id, shared_pass_data, server2).await {
        Ok(()) => Ok(warp::reply::json(&"Password shared successfully").into_response()),
        Err(protocol_error) => {
            log::error!("Failed to share password (JSON): {:?}", protocol_error);
            Ok(ApiError::InternalError(format!("Failed to share password: {}", protocol_error)).to_response(true))
        }
    }
}
// END share_pass
//************************************************************************************************//

//************************************************************************************************//
// START unshare_pass
//************************************************************************************************//
async fn logic_unshare_pass(
    owner_id: Uuid,
    pass_id: Uuid,
    recipient_id: Uuid,
    server_arc: &ServerArc,
) -> Result<(), ProtocolError> {
    let mut server = server_arc.write().await;
    server.unshare_pass(owner_id, pass_id, recipient_id).await
}

async fn unshare_pass_map(
    owner_str: String,
    pass_id_str: String,
    recipient_str: String,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let owner_id = match uuid::Uuid::parse_str(&owner_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid owner UUID format".to_string()).to_response(false)),
    };
    let pass_id = match uuid::Uuid::parse_str(&pass_id_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid pass UUID format".to_string()).to_response(false)),
    };
    let recipient_id = match uuid::Uuid::parse_str(&recipient_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid recipient UUID format".to_string()).to_response(false)),
    };

    match logic_unshare_pass(owner_id, pass_id, recipient_id, server2).await {
        Ok(()) => {
            match bincode::serialize(&"Password unshared successfully") {
                Ok(serialized) => Ok(warp::reply::Response::new(serialized.into())),
                Err(e) => {
                    log::error!("Failed to serialize success message for unshare_pass_map: {:?}",e);
                    Ok(ApiError::InternalError("Failed to serialize response".to_string()).to_response(false))
                }
            }
        }
        Err(protocol_error) => {
            log::error!("Failed to unshare password (binary): {:?}", protocol_error);
            Ok(ApiError::InternalError(format!("Failed to unshare password: {}", protocol_error)).to_response(false))
        }
    }
}

async fn unshare_pass_json_map(
    owner_str: String,
    pass_id_str: String,
    recipient_str: String,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let owner_id = match uuid::Uuid::parse_str(&owner_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid owner UUID format".to_string()).to_response(true)),
    };
    let pass_id = match uuid::Uuid::parse_str(&pass_id_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid pass UUID format".to_string()).to_response(true)),
    };
    let recipient_id = match uuid::Uuid::parse_str(&recipient_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid recipient UUID format".to_string()).to_response(true)),
    };

    match logic_unshare_pass(owner_id, pass_id, recipient_id, server2).await {
        Ok(()) => Ok(warp::reply::json(&"Password unshared successfully").into_response()),
        Err(protocol_error) => {
            log::error!("Failed to unshare password (JSON): {:?}", protocol_error);
            Ok(ApiError::InternalError(format!("Failed to unshare password: {}", protocol_error)).to_response(true))
        }
    }
}
// END unshare_pass
//************************************************************************************************//

//************************************************************************************************//
// START get_shared_pass
//************************************************************************************************//
async fn logic_get_shared_pass(
    recipient_id: Uuid,
    owner_id: Uuid,
    pass_id: Uuid,
    server_arc: &ServerArc,
) -> Result<crate::protocol::SharedPass, ProtocolError> {
    let server = server_arc.read().await;
    server.get_shared_pass(recipient_id, owner_id, pass_id).await
}

async fn get_shared_pass_map(
    recipient_str: String,
    owner_str: String,
    pass_id_str: String,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let recipient_id = match uuid::Uuid::parse_str(&recipient_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid recipient UUID format".to_string()).to_response(false)),
    };
    let owner_id = match uuid::Uuid::parse_str(&owner_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid owner UUID format".to_string()).to_response(false)),
    };
    let pass_id = match uuid::Uuid::parse_str(&pass_id_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid pass UUID format".to_string()).to_response(false)),
    };

    match logic_get_shared_pass(recipient_id, owner_id, pass_id, server2).await {
        Ok(shared_pass_data) => {
            match bincode::serialize(&shared_pass_data) {
                Ok(serialized) => Ok(warp::reply::Response::new(serialized.into())),
                Err(e) => {
                    log::error!("Failed to serialize shared_pass_data for get_shared_pass_map: {:?}", e);
                    Ok(ApiError::InternalError("Failed to serialize response".to_string()).to_response(false))
                }
            }
        }
        Err(protocol_error) => {
            log::error!("Failed to get shared pass (binary): {:?}", protocol_error);
            Ok(ApiError::InternalError(format!("Failed to get shared password: {}", protocol_error)).to_response(false))
        }
    }
}

async fn get_shared_pass_json_map(
    recipient_str: String,
    owner_str: String,
    pass_id_str: String,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let recipient_id = match uuid::Uuid::parse_str(&recipient_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid recipient UUID format".to_string()).to_response(true)),
    };
    let owner_id = match uuid::Uuid::parse_str(&owner_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid owner UUID format".to_string()).to_response(true)),
    };
    let pass_id = match uuid::Uuid::parse_str(&pass_id_str) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid pass UUID format".to_string()).to_response(true)),
    };

    match logic_get_shared_pass(recipient_id, owner_id, pass_id, server2).await {
        Ok(shared_pass_data) => Ok(warp::reply::json(&shared_pass_data).into_response()),
        Err(protocol_error) => {
            log::error!("Failed to get shared pass (JSON): {:?}", protocol_error);
            Ok(ApiError::InternalError(format!("Failed to get shared password: {}", protocol_error)).to_response(true))
        }
    }
}
// END get_shared_pass
//************************************************************************************************//

//************************************************************************************************//
// START accept_shared_pass
//************************************************************************************************//
async fn logic_accept_shared_pass(
    recipient_id: Uuid,
    owner_id: Uuid,
    pass_id: Uuid,
    server_arc: &ServerArc,
) -> Result<(), ProtocolError> {
    let mut server = server_arc.write().await;
    // The server.accept_shared_pass method takes owner_id, pass_id, recipient_id
    server.accept_shared_pass(owner_id, pass_id, recipient_id).await
}
