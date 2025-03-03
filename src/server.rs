use crate::postgres::PassesPostgres;
use crate::postgres::SharedPassesPostgres;
use crate::postgres::UsersPostgres;
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
    BadRequest(String),
    Unauthorized(String),
    InternalError(String),
    AuthenticationFailed(String),
}

impl warp::reject::Reject for ApiError {}

impl ApiError {
    fn to_response(&self, is_json: bool) -> Response {
        let (code, message) = match self {
            ApiError::BadRequest(msg) => (400, msg),
            ApiError::Unauthorized(msg) => (401, msg),
            ApiError::InternalError(msg) => (500, msg),
            ApiError::AuthenticationFailed(msg) => (401, msg),
        };

        if is_json {
            self.create_json_response(code, message)
        } else {
            self.create_binary_response(code, message)
        }
    }

    // Méthodes privées pour créer des réponses spécifiques au format
    fn create_json_response(&self, code: u16, message: &str) -> Response {
        let json = warp::reply::json(&ErrorMessage {
            code,
            message: message.to_string(),
        });
        warp::reply::with_status(json, warp::http::StatusCode::from_u16(code).unwrap())
            .into_response()
    }

    fn create_binary_response(&self, code: u16, message: &str) -> Response {
        let error_response = bincode::serialize(&message).unwrap_or_default();
        warp::reply::with_status(
            warp::reply::Response::new(error_response.into()),
            warp::http::StatusCode::from_u16(code).unwrap(),
        )
        .into_response()
    }

    // Méthodes d'aide pour créer des réponses spécifiques au format
    fn to_json_response(&self) -> Response {
        self.to_response(true)
    }

    fn to_binary_response(&self) -> Response {
        self.to_response(false)
    }
}

impl From<ApiError> for Infallible {
    fn from(_: ApiError) -> Self {
        unreachable!()
    }
}

impl From<ApiError> for Response {
    fn from(error: ApiError) -> Self {
        error.to_response(false)
    }
}

pub type ServerArc = Arc<
    RwLock<
        Server2<RedisSecrets, PassesPostgres, RedisChallenges, UsersPostgres, SharedPassesPostgres>,
    >,
>;

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
        .map_err(|_| ApiError::Unauthorized("Invalid token format".to_string()).to_response(is_json))?;

        let trusted_token = local::decrypt(&sk, &untrusted_token, &validation, None, Some(b"skap"))
            .map_err(|_| ApiError::Unauthorized("Token validation failed".to_string()).to_response(is_json))?;

        let claims = trusted_token
            .payload_claims()
            .ok_or_else(|| ApiError::Unauthorized("No claims in token".to_string()).to_response(is_json))?;

        let sub = claims
            .get_claim("sub")
            .ok_or_else(|| ApiError::Unauthorized("No subject claim in token".to_string()).to_response(is_json))?
            .as_str()
            .ok_or_else(|| ApiError::Unauthorized("Invalid subject claim format".to_string()).to_response(is_json))?;

        let normalized_uuid = uuid.replace('-', "").replace('"', "");
        let normalized_sub = sub.replace('-', "").replace('"', "");
        
        if normalized_uuid == normalized_sub {
            Ok(())
        } else {
            Err(ApiError::Unauthorized("UUID mismatch".to_string()).to_response(is_json))
        }
    } else {
        Err(ApiError::Unauthorized("No token".to_string()).to_response(is_json))
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
            writeln!(
                buf,
                "[{} {} {}:{}] {}",
                timestamp,
                record.level(),
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.args()
            )
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
            .and(mutexsk_filter.clone())
            .and(cookies_filter.clone())
            .and(header_filter.clone())
            .and_then(
                |uui: String,
                 server2: ServerArc,
                 sk: Arc<RwLock<SymmetricKey<V4>>>,
                 token: Option<String>,
                 header: Option<String>| async move {
                    if let Some(token) = token {
                        if let Err(response) = auth_validation(sk, &uui, Some(token), false).await {
                            return Ok(response);
                        }
                    } else {
                        if let Err(response) = auth_validation(sk, &uui, header, false).await {
                            return Ok(response);
                        }
                    }
                    send_all_map(uui, &server2).await
                },
            );

    let send_all_json =
        warp::get()
            .and(warp::path("send_all_json"))
            .and(warp::path::param::<String>())
            .and(server_filter.clone())
            .and(mutexsk_filter.clone())
            .and(cookies_filter.clone())
            .and(header_filter.clone())
            .and_then(
                |uui: String,
                 server2: ServerArc,
                 sk: Arc<RwLock<SymmetricKey<V4>>>,
                 token: Option<String>,
                 header: Option<String>| async move {
                    if let Some(token) = token {
                        if let Err(response) = auth_validation(sk, &uui, Some(token), true).await {
                            return Ok(response);
                        }
                    } else {
                        if let Err(response) = auth_validation(sk, &uui, header, true).await {
                            return Ok(response);
                        }
                    }
                    send_all_json_map(uui, &server2).await
                },
            );

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
            .and(mutexsk_filter.clone())
            .and(cookies_filter.clone())
            .and(header_filter.clone())
            .and_then(
                |uui: String,
                 server2: ServerArc,
                 sk: Arc<RwLock<SymmetricKey<V4>>>,
                 token: Option<String>,
                 header: Option<String>| async move {
                    if let Some(token) = token {
                        if let Err(response) = auth_validation(sk, &uui, Some(token), true).await {
                            return Ok(response);
                        }
                    } else {
                        if let Err(response) = auth_validation(sk, &uui, header, true).await {
                            return Ok(response);
                        }
                    }
                    sync_json_map(uui, &server2).await
                },
            );

    let sync =
        warp::get()
            .and(warp::path("sync"))
            .and(warp::path::param::<String>())
            .and(server_filter.clone())
            .and(mutexsk_filter.clone())
            .and(cookies_filter.clone())
            .and(header_filter.clone())
            .and_then(
                |uui: String,
                 server2: ServerArc,
                 sk: Arc<RwLock<SymmetricKey<V4>>>,
                 token: Option<String>,
                 header: Option<String>| async move {
                    if let Some(token) = token {
                        if let Err(response) = auth_validation(sk, &uui, Some(token), false).await {
                            return Ok(response);
                        }
                    } else {
                        if let Err(response) = auth_validation(sk, &uui, header, false).await {
                            return Ok(response);
                        }
                    }
                    sync_map(uui, &server2).await
                },
            );

    let create_pass = warp::post()
        .and(warp::path("create_pass"))
        .and(warp::path::param::<String>())
        .and(warp::body::bytes())
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |uui: String,
             pass: bytes::Bytes,
             server2: ServerArc,
             sk: Arc<RwLock<SymmetricKey<V4>>>,
             token: Option<String>,
             header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &uui, Some(token), false).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &uui, header, false).await {
                        return Ok(response);
                    }
                }
                create_pass_map(uui, pass, &server2).await
            },
        );

    let create_pass_json = warp::post()
        .and(warp::path("create_pass_json"))
        .and(warp::path::param::<String>())
        .and(warp::body::json())
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |uui: String,
             pass: EP,
             server2: ServerArc,
             sk: Arc<RwLock<SymmetricKey<V4>>>,
             token: Option<String>,
             header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &uui, Some(token), true).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &uui, header, true).await {
                        return Ok(response);
                    }
                }
                create_pass_json_map(uui, pass, &server2).await
            },
        );

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
        .and(warp::path::param::<String>())
        .and(warp::path::param::<String>())
        .and(warp::body::bytes())
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |uui: String,
             uui2: String,
             pass: bytes::Bytes,
             server2: ServerArc,
             sk: Arc<RwLock<SymmetricKey<V4>>>,
             token: Option<String>,
             header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &uui, Some(token), false).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &uui, header, false).await {
                        return Ok(response);
                    }
                }
                update_pass_map(uui, uui2, pass, &server2).await
            },
        );

    let update_pass_json = warp::post()
        .and(warp::path("update_pass_json"))
        .and(warp::path::param::<String>())
        .and(warp::path::param::<String>())
        .and(warp::body::json())
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |uui: String,
             uui2: String,
             pass: EP,
             server2: ServerArc,
             sk: Arc<RwLock<SymmetricKey<V4>>>,
             token: Option<String>,
             header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &uui, Some(token), true).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &uui, header, true).await {
                        return Ok(response);
                    }
                }
                update_pass_json_map(uui, uui2, pass, &server2).await
            },
        );

    let delete = warp::get()
        .and(warp::path("delete_pass"))
        .and(warp::path::param::<String>())
        .and(warp::path::param::<String>())
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |uui: String,
             uui2: String,
             server2: ServerArc,
             sk: Arc<RwLock<SymmetricKey<V4>>>,
             token: Option<String>,
             header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &uui, Some(token), false).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &uui, header, false).await {
                        return Ok(response);
                    }
                }
                delete_map(uui, uui2, &server2).await
            },
        );

    let delete_json = warp::get()
        .and(warp::path("delete_pass_json"))
        .and(warp::path::param::<String>())
        .and(warp::path::param::<String>())
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |uui: String,
             uui2: String,
             server2: ServerArc,
             sk: Arc<RwLock<SymmetricKey<V4>>>,
             token: Option<String>,
             header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &uui, Some(token), true).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &uui, header, true).await {
                        return Ok(response);
                    }
                }
                delete_json_map(uui, uui2, &server2).await
            },
        );

    let send = warp::get()
        .and(warp::path("send"))
        .and(warp::path::param::<String>())
        .and(warp::path::param::<String>())
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |uui: String,
             uui2: String,
             server2: ServerArc,
             sk: Arc<RwLock<SymmetricKey<V4>>>,
             token: Option<String>,
             header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &uui, Some(token), false).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &uui, header, false).await {
                        return Ok(response);
                    }
                }
                send_map(uui, uui2, &server2).await
            },
        );

    let send_json = warp::get()
        .and(warp::path("send_json"))
        .and(warp::path::param::<String>())
        .and(warp::path::param::<String>())
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |uui: String,
             uui2: String,
             server2: ServerArc,
             sk: Arc<RwLock<SymmetricKey<V4>>>,
             token: Option<String>,
             header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &uui, Some(token), true).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &uui, header, true).await {
                        return Ok(response);
                    }
                }
                send_json_map(uui, uui2, &server2).await
            },
        );

    let share_pass = warp::post()
        .and(warp::path("share_pass"))
        .and(warp::path::param::<String>()) // owner id
        .and(warp::path::param::<String>()) // pass id
        .and(warp::path::param::<String>()) // recipient id
        .and(warp::body::bytes())
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |owner: String,
             pass_id: String,
             recipient: String,
             shared_pass: bytes::Bytes,
             server2: ServerArc,
             sk: Arc<RwLock<SymmetricKey<V4>>>,
             token: Option<String>,
             header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &owner, Some(token), false).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &owner, header, false).await {
                        return Ok(response);
                    }
                }
                share_pass_map(owner, pass_id, recipient, shared_pass, &server2).await
            },
        );

    let share_pass_json = warp::post()
        .and(warp::path("share_pass_json"))
        .and(warp::path::param::<String>()) // owner id
        .and(warp::path::param::<String>()) // pass id
        .and(warp::path::param::<String>()) // recipient id
        .and(warp::body::json())
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |owner: String,
             pass_id: String,
             recipient: String,
             shared_pass: crate::protocol::SharedPass,
             server2: ServerArc,
             sk: Arc<RwLock<SymmetricKey<V4>>>,
             token: Option<String>,
             header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &owner, Some(token), true).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &owner, header, true).await {
                        return Ok(response);
                    }
                }
                share_pass_json_map(owner, pass_id, recipient, shared_pass, &server2).await
            },
        );

    let unshare_pass = warp::post()
        .and(warp::path("unshare_pass"))
        .and(warp::path::param::<String>()) // owner id
        .and(warp::path::param::<String>()) // pass id
        .and(warp::path::param::<String>()) // recipient id
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |owner: String,
             pass_id: String,
             recipient: String,
             server2: ServerArc,
             sk: Arc<RwLock<SymmetricKey<V4>>>,
             token: Option<String>,
             header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &owner, Some(token), false).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &owner, header, false).await {
                        return Ok(response);
                    }
                }
                unshare_pass_map(owner, pass_id, recipient, &server2).await
            },
        );

    let unshare_pass_json = warp::post()
        .and(warp::path("unshare_pass_json"))
        .and(warp::path::param::<String>()) // owner id
        .and(warp::path::param::<String>()) // pass id
        .and(warp::path::param::<String>()) // recipient id
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |owner: String,
             pass_id: String,
             recipient: String,
             server2: ServerArc,
             sk: Arc<RwLock<SymmetricKey<V4>>>,
             token: Option<String>,
             header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &owner, Some(token), true).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &owner, header, true).await {
                        return Ok(response);
                    }
                }
                unshare_pass_json_map(owner, pass_id, recipient, &server2).await
            },
        );

    let get_shared_pass = warp::get()
        .and(warp::path("get_shared_pass"))
        .and(warp::path::param::<String>()) // recipient id
        .and(warp::path::param::<String>()) // owner id
        .and(warp::path::param::<String>()) // pass id
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |recipient: String,
             owner: String,
             pass_id: String,
             server2: ServerArc,
             sk: Arc<RwLock<SymmetricKey<V4>>>,
             token: Option<String>,
             header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &recipient, Some(token), false).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &recipient, header, false).await {
                        return Ok(response);
                    }
                }
                get_shared_pass_map(recipient, owner, pass_id, &server2).await
            },
        );

    let get_shared_pass_json = warp::get()
        .and(warp::path("get_shared_pass_json"))
        .and(warp::path::param::<String>()) // recipient id
        .and(warp::path::param::<String>()) // owner id
        .and(warp::path::param::<String>()) // pass id
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |recipient: String,
             owner: String,
             pass_id: String,
             server2: ServerArc,
             sk: Arc<RwLock<SymmetricKey<V4>>>,
             token: Option<String>,
             header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &recipient, Some(token), true).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &recipient, header, true).await {
                        return Ok(response);
                    }
                }
                get_shared_pass_json_map(recipient, owner, pass_id, &server2).await
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
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |owner: String, server2: ServerArc, sk: Arc<RwLock<SymmetricKey<V4>>>, token: Option<String>, header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &owner, Some(token), false).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &owner, header, false).await {
                        return Ok(response);
                    }
                }
                get_shared_by_user_map(owner, &server2).await
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
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |recipient: String, owner: String, pass_id: String, server2: ServerArc, sk: Arc<RwLock<SymmetricKey<V4>>>, token: Option<String>, header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &recipient, Some(token), false).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &recipient, header, false).await {
                        return Ok(response);
                    }
                }
                accept_shared_pass_map(recipient, owner, pass_id, &server2).await
            },
        );

    let accept_shared_pass_json = warp::get()
        .and(warp::path("accept_shared_pass_json"))
        .and(warp::path::param::<String>()) // recipient id
        .and(warp::path::param::<String>()) // owner id
        .and(warp::path::param::<String>()) // pass id
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |recipient: String, owner: String, pass_id: String, server2: ServerArc, sk: Arc<RwLock<SymmetricKey<V4>>>, token: Option<String>, header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &recipient, Some(token), true).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &recipient, header, true).await {
                        return Ok(response);
                    }
                }
                accept_shared_pass_json_map(recipient, owner, pass_id, &server2).await
            },
        );

    let reject_shared_pass = warp::get()
        .and(warp::path("reject_shared_pass"))
        .and(warp::path::param::<String>()) // recipient id
        .and(warp::path::param::<String>()) // owner id
        .and(warp::path::param::<String>()) // pass id
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |recipient: String, owner: String, pass_id: String, server2: ServerArc, sk: Arc<RwLock<SymmetricKey<V4>>>, token: Option<String>, header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &recipient, Some(token), false).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &recipient, header, false).await {
                        return Ok(response);
                    }
                }
                reject_shared_pass_map(recipient, owner, pass_id, &server2).await
            },
        );

    let reject_shared_pass_json = warp::get()
        .and(warp::path("reject_shared_pass_json"))
        .and(warp::path::param::<String>()) // recipient id
        .and(warp::path::param::<String>()) // owner id
        .and(warp::path::param::<String>()) // pass id
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |recipient: String, owner: String, pass_id: String, server2: ServerArc, sk: Arc<RwLock<SymmetricKey<V4>>>, token: Option<String>, header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &recipient, Some(token), true).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &recipient, header, true).await {
                        return Ok(response);
                    }
                }
                reject_shared_pass_json_map(recipient, owner, pass_id, &server2).await
            },
        );

    let get_shared_pass_status = warp::get()
        .and(warp::path("get_shared_pass_status"))
        .and(warp::path::param::<String>()) // owner id
        .and(warp::path::param::<String>()) // pass id
        .and(warp::path::param::<String>()) // recipient id
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |owner: String, pass_id: String, recipient: String, server2: ServerArc, sk: Arc<RwLock<SymmetricKey<V4>>>, token: Option<String>, header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &owner, Some(token), false).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &owner, header, false).await {
                        return Ok(response);
                    }
                }
                get_shared_pass_status_map(owner, pass_id, recipient, &server2).await
            },
        );
    let get_shared_pass_status_json = warp::get()
        .and(warp::path("get_shared_pass_status_json"))
        .and(warp::path::param::<String>()) // owner id
        .and(warp::path::param::<String>()) // pass id
        .and(warp::path::param::<String>()) // recipient id
        .and(server_filter.clone())
        .and(mutexsk_filter.clone())
        .and(cookies_filter.clone())
        .and(header_filter.clone())
        .and_then(
            |owner: String, pass_id: String, recipient: String, server2: ServerArc, sk: Arc<RwLock<SymmetricKey<V4>>>, token: Option<String>, header: Option<String>| async move {
                if let Some(token) = token {
                    if let Err(response) = auth_validation(sk, &owner, Some(token), true).await {
                        return Ok(response);
                    }
                } else {
                    if let Err(response) = auth_validation(sk, &owner, header, true).await {
                        return Ok(response);
                    }
                }
                get_shared_pass_status_json_map(owner, pass_id, recipient, &server2).await
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
        .or(get_shared_pass_status_json);

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

async fn get_shared_pass_status_map(owner: String, pass_id: String, recipient: String, server2: &ServerArc) -> Result<Response, Infallible> {
    let server = server2.read().await;
    let owner = match uuid::Uuid::parse_str(&owner) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(false)),
    };
    let pass_id = match uuid::Uuid::parse_str(&pass_id) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(false)),
    };
    let recipient = match uuid::Uuid::parse_str(&recipient) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(false)),
    };
    let status = server.get_shared_pass_status(owner, pass_id, recipient).await;
    if let Ok(status) = status {
        Ok(warp::reply::Response::new(bincode::serialize(&status).unwrap().into()))
    } else {
        Ok(ApiError::BadRequest("Failed to get shared pass status".to_string()).to_response(false))
    }
}

async fn get_shared_pass_status_json_map(owner: String, pass_id: String, recipient: String, server2: &ServerArc) -> Result<Response, Infallible> {
    let server = server2.read().await;
    let owner = match uuid::Uuid::parse_str(&owner) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(true)),
    };
    let pass_id = match uuid::Uuid::parse_str(&pass_id) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(true)),
    };
    let recipient = match uuid::Uuid::parse_str(&recipient) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(true)),
    };
    let status = server.get_shared_pass_status(owner, pass_id, recipient).await;
    if let Ok(status) = status {
        Ok(warp::reply::json(&status).into_response())  
    } else {
        Ok(ApiError::BadRequest("Failed to get shared pass status".to_string()).to_response(true))
    }
}







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

async fn delete_map(
    uui: String,
    uui2: String,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let mut server = server2.write().await;

    let id = match uuid::Uuid::parse_str(&uui) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(
                ApiError::BadRequest("Invalid UUID format for user ID".to_string()).to_response(false),
            )
        }
    };
    let id2 = match uuid::Uuid::parse_str(&uui2) {
        Ok(uuid2) => uuid2,
        Err(_) => {
            return Ok(
                ApiError::BadRequest("Invalid UUID format for pass ID".to_string()).to_response(false),
            )
        }
    };

    match server.delete_pass(id, id2).await {
        Ok(()) => Ok(warp::reply::Response::new(
            bincode::serialize(&"Pass deleted successfully")
                .unwrap()
                .into(),
        )),
        Err(_) => {
            Ok(ApiError::InternalError("Failed to delete pass".to_string()).to_binary_response())
        }
    }
}

async fn delete_json_map(
    uui: String,
    uui2: String,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let mut server = server2.write().await;

    let id = match uuid::Uuid::parse_str(&uui) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(
                ApiError::BadRequest("Invalid UUID format for user ID".to_string()).to_response(true),
            )
        }
    };

    let id2 = match uuid::Uuid::parse_str(&uui2) {
        Ok(uuid2) => uuid2,
        Err(_) => {
            return Ok(
                ApiError::BadRequest("Invalid UUID format for pass ID".to_string()).to_response(true),
            )
        }
    };

    match server.delete_pass(id, id2).await {
        Ok(()) => Ok(warp::reply::json(&"Pass deleted successfully").into_response()),
        Err(_) => Ok(ApiError::InternalError("Failed to delete pass".to_string()).to_response(true)),
    }
}

async fn challenge_map(uui: String, server2: &ServerArc) -> Result<Response, Infallible> {
    let mut server = server2.write().await;

    let id = match uuid::Uuid::parse_str(&uui) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(
                ApiError::BadRequest("Invalid UUID format for pass ID".to_string()).to_response(false),
            )
        }
    };

    match server.challenge(id).await {
        Ok(challenge) => match bincode::serialize(&challenge) {
            Ok(a) => return Ok(warp::reply::Response::new(a.into())),
            Err(_) => {
                return Ok(
                    ApiError::InternalError("Failed to serialize challenge".to_string())
                        .to_response(false),
                )
            }
        },
        Err(_) => {
            Ok(ApiError::InternalError("Failed to generate challenge".to_string()).to_response(false))
        }
    }
}

async fn challenge_json_map(uui: String, server2: &ServerArc) -> Result<Response, Infallible> {
    let mut server = server2.write().await;

    let id = match uuid::Uuid::parse_str(&uui) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(true)),
    };

    match server.challenge(id).await {
        Ok(challenge) => Ok(warp::reply::json(&challenge).into_response()),
        Err(_) => Ok(ApiError::InternalError("Failed to generate challenge".to_string()).to_response(true)),
    }
}

async fn verify_map(
    uui: String,
    body: bytes::Bytes,
    server2: &ServerArc,
    mutexsk: &Arc<RwLock<SymmetricKey<V4>>>,
) -> Result<Response, Infallible> {
    let server = server2.read().await;

    let id = match uuid::Uuid::parse_str(&uui) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).into()),
    };

    let proof = match bincode::deserialize::<Vec<u8>>(&body) {
        Ok(proof) => proof,
        Err(_) => return Ok(ApiError::BadRequest("Invalid proof format".to_string()).into()),
    };

    match server.verify(id.clone(), &proof).await {
        Ok(_) => {
            let sk = mutexsk.read().await;
            let mut claims = match Claims::new() {
                Ok(claims) => claims,
                Err(_) => {
                    return Ok(
                        ApiError::InternalError("Failed to create claims".to_string()).into(),
                    )
                }
            };

            if let Err(_) = claims.subject(&id.to_string()) {
                return Ok(
                    ApiError::InternalError("Failed to set subject claim".to_string()).into(),
                );
            }

            let token = match local::encrypt(&sk, &claims, None, Some(b"skap")) {
                Ok(token) => token,
                Err(_) => {
                    return Ok(ApiError::InternalError("Failed to create token".to_string()).into())
                }
            };

            Ok(warp::reply::with_header(
                token.clone(),
                "set-cookie",
                format!(
                    "token={}; Path=/; HttpOnly; Max-Age=3600; SameSite=Strict",
                    token
                ),
            )
            .into_response())
        }
        Err(_) => Ok(ApiError::AuthenticationFailed("Authentication failed".to_string()).into()),
    }
}

async fn verify_json_map(
    uui: String,
    body: Vec<u8>,
    server2: &ServerArc,
    mutexsk: &Arc<RwLock<SymmetricKey<V4>>>,
) -> Result<Response, Infallible> {
    let server = server2.read().await;

    let id = match uuid::Uuid::parse_str(&uui) {
        Ok(id) => id,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(true)),
    };

    match server.verify(id.clone(), body.as_slice()).await {
        Ok(_) => {
            let sk = mutexsk.read().await;
            let mut claims = match Claims::new() {
                Ok(claims) => claims,
                Err(_) => {
                    return Ok(
                        ApiError::InternalError("Failed to create claims".to_string())
                            .to_response(true),
                    )
                }
            };

            if let Err(_) = claims.subject(&id.to_string()) {
                return Ok(
                    ApiError::InternalError("Failed to set subject claim".to_string())
                        .to_response(true),
                );
            }

            let token = match local::encrypt(&sk, &claims, None, Some(b"skap")) {
                Ok(token) => token,
                Err(_) => {
                    return Ok(
                        ApiError::InternalError("Failed to create token".to_string()).to_response(true),
                    )
                }
            };

            Ok(warp::reply::with_header(
                warp::reply::json(&token),
                "set-cookie",
                format!(
                    "token={}; Path=/; HttpOnly; Max-Age=3600; SameSite=Strict",
                    token
                ),
            )
            .into_response())
        }
        Err(_) => {
            Ok(ApiError::AuthenticationFailed("Authentication failed".to_string()).to_response(true))
        }
    }
}

async fn update_pass_map(
    uui: String,
    uui2: String,
    pass: bytes::Bytes,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let mut server = server2.write().await;

    let id = match uuid::Uuid::parse_str(&uui) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(ApiError::BadRequest("Invalid UUID format for user ID".to_string()).into())
        }
    };

    let id2 = match uuid::Uuid::parse_str(&uui2) {
        Ok(uuid2) => uuid2,
        Err(_) => {
            return Ok(ApiError::BadRequest("Invalid UUID format for pass ID".to_string()).into())
        }
    };

    let ep = match bincode::deserialize::<EP>(&pass) {
        Ok(ep) => ep,
        Err(_) => return Ok(ApiError::BadRequest("Invalid pass data format".to_string()).into()),
    };

    match server.update_pass(id, id2, ep).await {
        Ok(()) => Ok(warp::reply::json(&id2).into_response()),
        Err(_) => Ok(ApiError::InternalError("Failed to update pass".to_string()).into()),
    }
}

async fn update_pass_json_map(
    uui: String,
    uui2: String,
    pass: EP,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let mut server = server2.write().await;

    let id = match uuid::Uuid::parse_str(&uui) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(ApiError::BadRequest("Invalid UUID format for user ID".to_string()).to_response(true))
        }
    };

    let id2 = match uuid::Uuid::parse_str(&uui2) {
        Ok(uuid2) => uuid2,
        Err(_) => {
            return Ok(ApiError::BadRequest("Invalid UUID format for pass ID".to_string()).to_response(true))
        }
    };

    match server.update_pass(id, id2, pass).await {
        Ok(()) => Ok(warp::reply::json(&id2).into_response()),
        Err(_) => Ok(ApiError::InternalError("Failed to update pass".to_string()).to_response(true)),
    }
}

async fn send_map(uui: String, uui2: String, server2: &ServerArc) -> Result<Response, Infallible> {
    let server = server2.read().await;
    let id = uuid::Uuid::parse_str(&uui);
    let id2 = uuid::Uuid::parse_str(&uui2);
    if id.is_err() || id2.is_err() {
        return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).into());
    }
    match server.send(id.unwrap(), id2.unwrap()).await {
        Ok(r) => {
            Ok(warp::reply::Response::new(bincode::serialize(&r).unwrap().into()).into_response())
        }
        Err(_) => Ok(ApiError::InternalError("Failed to send pass".to_string()).into()),
    }
}

async fn send_json_map(
    uui: String,
    uui2: String,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let server = server2.read().await;

    let id = match uuid::Uuid::parse_str(&uui) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(ApiError::BadRequest("Invalid UUID format for user ID".to_string()).to_response(true))
        }
    };

    let id2 = match uuid::Uuid::parse_str(&uui2) {
        Ok(uuid2) => uuid2,
        Err(_) => {
            return Ok(ApiError::BadRequest("Invalid UUID format for pass ID".to_string()).to_response(true))
        }
    };

    match server.send(id, id2).await {
        Ok(r) => Ok(warp::reply::json(&r).into_response()),
        Err(_) => Ok(ApiError::InternalError("Failed to send pass".to_string()).to_response(true)),
    }
}

async fn create_pass_map(
    uui: String,
    pass: bytes::Bytes,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let mut server = server2.write().await;
    let id = uuid::Uuid::parse_str(&uui);
    let ep = bincode::deserialize::<EP>(&pass);
    if id.is_err() || ep.is_err() {
        return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).into());
    }
    match server.create_pass(id.unwrap(), ep.unwrap()).await {
        Ok(id2) => Ok(
            warp::reply::Response::new(bincode::serialize(&id2).unwrap().into()).into_response(),
        ),
        Err(_) => Ok(ApiError::InternalError("Failed to create pass".to_string()).into()),
    }
}

async fn create_pass_json_map(
    uui: String,
    pass: EP,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let mut server = server2.write().await;
    let id = match uuid::Uuid::parse_str(&uui) {
        Ok(uuid) => uuid,
        Err(_) => return Ok(ApiError::BadRequest("Invalid UUID format".to_string()).to_response(true)),
    };

    match server.create_pass(id, pass).await {
        Ok(id2) => Ok(warp::reply::json(&id2).into_response()),
        Err(e) => {
            log::error!("Failed to create pass : {}", e);
            Ok(ApiError::InternalError("Failed to create pass".to_string()).to_response(true))
        }
    }
}

async fn sync_map(uui: String, server2: &ServerArc) -> Result<Response, Infallible> {
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
    log::debug!(
        "Attempting to deserialize user data, length: {}",
        body.len()
    );
    let ck = match bincode::deserialize::<CK>(&body) {
        Ok(ck) => {
            log::debug!(
                "Successfully deserialized user data with email: {}",
                ck.email
            );
            ck
        }
        Err(e) => {
            log::error!("Failed to deserialize user data: {:?}", e);
            return Ok(ApiError::BadRequest("Invalid user data format".to_string()).into());
        }
    };

    let mut server = server2.write().await;
    log::info!("Adding new user with email: {}", ck.email);
    match server.add_user(&mut ck.clone()).await {
        Ok(uuid) => {
            log::info!(
                "User created successfully with uuid {} and email {}",
                uuid,
                ck.email
            );
            match bincode::serialize(&ck) {
                Ok(serialized) => {
                    log::debug!(
                        "User data serialized successfully, length: {}",
                        serialized.len()
                    );
                    Ok(warp::reply::Response::new(serialized.into()))
                }
                Err(e) => {
                    log::error!("Failed to serialize user data: {:?}", e);
                    Ok(ApiError::InternalError("Failed to serialize user data".to_string()).into())
                }
            }
        }
        Err(e) => {
            log::error!("Failed to create user: {:?}", e);
            Ok(ApiError::InternalError("Failed to create user".to_string()).into())
        }
    }
}

async fn create_user_json_map(mut ck: CK, server2: &ServerArc) -> Result<Response, Infallible> {
    let mut server = server2.write().await;

    log::info!("Adding new user with email: {}", ck.email);
    match server.add_user(&mut ck).await {
        Ok(uuid) => {
            log::info!(
                "User created successfully with uuid {} and email {}",
                uuid,
                ck.email
            );
            ck.id = Some(uuid);
            Ok(warp::reply::json(&ck).into_response())
        }
        Err(_) => Ok(ApiError::InternalError("Failed to create user".to_string()).to_response(true)),
    }
}

async fn send_all_map(uui: String, server2: &ServerArc) -> Result<Response, Infallible> {
    let id = uuid::Uuid::parse_str(&uui);
    if id.is_err() {
        return Ok(ApiError::BadRequest("Invalid UUID format for pass ID".to_string()).into());
    }
    let server = server2.read().await;
    match server.send_all(id.unwrap()).await {
        Ok(r) => {
            Ok(warp::reply::Response::new(bincode::serialize(&r).unwrap().into()).into_response())
        }
        Err(_) => Ok(ApiError::InternalError("Failed to send pass".to_string()).into()),
    }
}

async fn send_all_json_map(uui: String, server2: &ServerArc) -> Result<Response, Infallible> {
    let id = uuid::Uuid::parse_str(&uui);
    if id.is_err() {
        return Ok(ApiError::BadRequest("Invalid UUID format for pass ID".to_string()).to_response(true));
    }
    let server = server2.read().await;
    match server.send_all(id.clone().unwrap()).await {
        Ok(r) => {
            let passwords = r;
            match server.get_all_shared_passes(id.unwrap()).await {
                Ok(shared_passes) => {
                    let pp = shared_passes;

                    let passwords_extended = PasswordsExtended {
                        passwords,
                        shared_passes: pp,
                    };
                    Ok(warp::reply::json(&passwords_extended).into_response())
                }
                Err(_) => Ok(warp::reply::json(&passwords).into_response()),
            }
        }
        Err(_) => Ok(ApiError::InternalError("Failed to send pass".to_string()).to_response(true)),
    }
}

// Fonction utilitaire pour parser un UUID avec gestion d'erreur
fn parse_uuid(uuid_str: &str, field_name: &str, is_json: bool) -> Result<Uuid, Response> {
    uuid::Uuid::parse_str(uuid_str).map_err(|_| {
        ApiError::BadRequest(format!("Invalid UUID format for {}", field_name)).to_response(is_json)
    })
}

async fn share_pass_map(
    owner: String,
    pass_id: String,
    recipient: String,
    shared_pass: bytes::Bytes,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let mut server = server2.write().await;

    let owner_id = match parse_uuid(&owner, "owner ID", false) {
        Ok(uuid) => uuid,
        Err(response) => return Ok(response),
    };

    let pass_uuid = match parse_uuid(&pass_id, "pass ID", false) {
        Ok(uuid) => uuid,
        Err(response) => return Ok(response),
    };

    let recipient_id = match parse_uuid(&recipient, "recipient ID", false) {
        Ok(uuid) => uuid,
        Err(response) => return Ok(response),
    };

    let shared_pass = match bincode::deserialize::<crate::protocol::SharedPass>(&shared_pass) {
        Ok(pass) => pass,
        Err(_) => {
            return Ok(ApiError::BadRequest("Invalid shared pass data format".to_string()).into())
        }
    };

    match server
        .store_shared_pass(owner_id, pass_uuid, recipient_id, shared_pass)
        .await
    {
        Ok(()) => Ok(warp::reply::Response::new(
            bincode::serialize(&"Password shared successfully")
                .unwrap()
                .into(),
        )),
        Err(_) => Ok(ApiError::InternalError("Failed to share password".to_string()).into()),
    }
}

async fn share_pass_json_map(
    owner: String,
    pass_id: String,
    recipient: String,
    shared_pass: crate::protocol::SharedPass,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let mut server = server2.write().await;

    let owner_id = match parse_uuid(&owner, "owner ID", true) {
        Ok(uuid) => uuid,
        Err(response) => return Ok(response),
    };

    let pass_uuid = match parse_uuid(&pass_id, "pass ID", true) {
        Ok(uuid) => uuid,
        Err(response) => return Ok(response),
    };

    let recipient_id = match parse_uuid(&recipient, "recipient ID", true) {
        Ok(uuid) => uuid,
        Err(response) => return Ok(response),
    };

    match server
        .store_shared_pass(owner_id, pass_uuid, recipient_id, shared_pass)
        .await
    {
        Ok(()) => Ok(warp::reply::json(&"Password shared successfully").into_response()),
        Err(_) => Ok(ApiError::InternalError("Failed to share password".to_string()).into()),
    }
}

async fn unshare_pass_map(
    owner: String,
    pass_id: String,
    recipient: String,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let mut server = server2.write().await;

    let owner_id = match uuid::Uuid::parse_str(&owner) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(ApiError::BadRequest("Invalid UUID format for owner ID".to_string()).into())
        }
    };

    let pass_uuid = match uuid::Uuid::parse_str(&pass_id) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(ApiError::BadRequest("Invalid UUID format for pass ID".to_string()).into())
        }
    };

    let recipient_id = match uuid::Uuid::parse_str(&recipient) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(
                ApiError::BadRequest("Invalid UUID format for recipient ID".to_string()).into(),
            )
        }
    };

    match server.unshare_pass(owner_id, pass_uuid, recipient_id).await {
        Ok(()) => Ok(warp::reply::Response::new(
            bincode::serialize(&"Password unshared successfully")
                .unwrap()
                .into(),
        )),
        Err(_) => Ok(ApiError::InternalError("Failed to unshare password".to_string()).into()),
    }
}

async fn unshare_pass_json_map(
    owner: String,
    pass_id: String,
    recipient: String,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let mut server = server2.write().await;

    let owner_id = match uuid::Uuid::parse_str(&owner) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(ApiError::BadRequest("Invalid UUID format for owner ID".to_string()).to_response(true))
        }
    };

    let pass_uuid = match uuid::Uuid::parse_str(&pass_id) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(ApiError::BadRequest("Invalid UUID format for pass ID".to_string()).to_response(true))
        }
    };

    let recipient_id = match uuid::Uuid::parse_str(&recipient) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(
                ApiError::BadRequest("Invalid UUID format for recipient ID".to_string()).to_response(true)
            )
        }
    };

    match server.unshare_pass(owner_id, pass_uuid, recipient_id).await {
        Ok(()) => Ok(warp::reply::json(&"Password unshared successfully").into_response()),
        Err(_) => Ok(ApiError::InternalError("Failed to unshare password".to_string()).into()),
    }
}

async fn get_shared_pass_map(
    recipient: String,
    owner: String,
    pass_id: String,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let server = server2.read().await;

    let recipient_id = match uuid::Uuid::parse_str(&recipient) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(
                ApiError::BadRequest("Invalid UUID format for recipient ID".to_string()).into(),
            )
        }
    };

    let owner_id = match uuid::Uuid::parse_str(&owner) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(ApiError::BadRequest("Invalid UUID format for owner ID".to_string()).into())
        }
    };

    let pass_uuid = match uuid::Uuid::parse_str(&pass_id) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(ApiError::BadRequest("Invalid UUID format for pass ID".to_string()).into())
        }
    };

    match server
        .get_shared_pass(recipient_id, owner_id, pass_uuid)
        .await
    {
        Ok(shared_pass) => Ok(warp::reply::Response::new(
            bincode::serialize(&shared_pass).unwrap().into(),
        )),
        Err(_) => Ok(ApiError::InternalError("Failed to get shared password".to_string()).into()),
    }
}

async fn get_shared_pass_json_map(
    recipient: String,
    owner: String,
    pass_id: String,
    server2: &ServerArc,
) -> Result<Response, Infallible> {
    let server = server2.read().await;

    let recipient_id = match uuid::Uuid::parse_str(&recipient) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(
                ApiError::BadRequest("Invalid UUID format for recipient ID".to_string()).to_response(true)
            )
        }
    };

    let owner_id = match uuid::Uuid::parse_str(&owner) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(ApiError::BadRequest("Invalid UUID format for owner ID".to_string()).to_response(true))
        }
    };

    let pass_uuid = match uuid::Uuid::parse_str(&pass_id) {
        Ok(uuid) => uuid,
        Err(_) => {
            return Ok(ApiError::BadRequest("Invalid UUID format for pass ID".to_string()).to_response(true))
        }
    };

    match server
        .get_shared_pass(recipient_id, owner_id, pass_uuid)
        .await
    {
        Ok(shared_pass) => Ok(warp::reply::json(&shared_pass).into_response()),
        Err(_) => Ok(ApiError::InternalError("Failed to get shared password".to_string()).into()),
    }
}
