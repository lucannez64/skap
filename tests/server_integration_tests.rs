// tests/server_integration_tests.rs

use skap::protocol::{CK, EP, PasswordsExtended, SharedPass, Server as SkapServer, ProtocolError, SharedByUser, ShareStatus, Password};
use skap::postgres::{UsersPostgres, PassesPostgres, SharedPassesPostgres};
use skap::redis::{RedisSecrets, RedisChallenges};


use bytes::Bytes;
use reqwest::cookie::Jar;
use reqwest::{Client, StatusCode, header::{HeaderValue, CONTENT_TYPE, AUTHORIZATION}};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use pasetors::keys::{SymmetricKey, Generate};
use pasetors::claims::Claims;
use pasetors::{local, version4::V4, Local, UntrustedToken, ClaimsValidationRules};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::net::SocketAddr;
use std::time::Duration;
use once_cell::sync::Lazy; 

// --- Global Static Variables for Test Server and PASETO Key ---
static TEST_PORT: u16 = 8090; // Changed port again to avoid conflict with previous run
static ref TEST_BASE_URL: String = format!("http://127.0.0.1:{}", TEST_PORT);

static ref TEST_PASETO_KEY_BYTES: Vec<u8> = SymmetricKey::<V4>::generate().expect("Failed to generate test PASETO key").as_bytes().to_vec();
static ref TEST_PASETO_BASE64_KEY: String = STANDARD.encode(&*TEST_PASETO_KEY_BYTES);


async fn start_test_server() -> String {
    let address = format!("127.0.0.1:{}", TEST_PORT);

    std::env::set_var("DATABASE_URL", "postgres://user:password@localhost:5432/testdb");
    std::env::set_var("REDIS_URL", "redis://127.0.0.1/");
    if std::fs::File::open("ca.pem").is_err() {
        if let Err(e) = std::fs::File::create("ca.pem") {
            eprintln!("Failed to create dummy ca.pem: {}", e);
        }
    }
    std::env::set_var("CA_FILE", "ca.pem");
    std::env::set_var("BASE64_KEY", TEST_PASETO_BASE64_KEY.clone());
    std::env::set_var("SERVER_ADDR", address.clone());
    std::env::set_var("RUST_LOG", "info,skap=debug"); 

    tokio::spawn(async move {
        if let Err(e) = skap::server::run().await { 
            eprintln!("Test server failed to run: {}", e);
        }
    });

    tokio::time::sleep(Duration::from_millis(2500)).await; // Increased delay further

    TEST_BASE_URL.clone()
}

fn generate_auth_token(user_uuid: &str) -> String {
    let key = SymmetricKey::<V4>::from(TEST_PASETO_KEY_BYTES.as_slice()).expect("Failed to create symmetric key from static bytes");
    
    let mut claims = Claims::new().unwrap();
    claims.subject(user_uuid).unwrap();
    let current_time = chrono::Utc::now();
    let expiration_time = current_time + chrono::Duration::hours(1);
    claims.expiration(&expiration_time.to_rfc3339()).unwrap();
    claims.issued_at(&current_time.to_rfc3339()).unwrap();

    local::encrypt(&key, &claims, None, Some(b"skap")).expect("Failed to encrypt token")
}

async fn create_test_user(client: &Client, base_url: &str, email_prefix: &str) -> (CK, String) {
    let email = format!("{}_{}@example.com", email_prefix, Uuid::new_v4().to_simple().to_string()); 
    let (ky_p_bytes, _) = libcrux_ml_kem::mlkem1024::generate_key_pair(libcrux_ml_kem::mlkem1024::generate_randomness());
    let (di_p, _) = fips204::ml_dsa_87::try_keygen().unwrap();

    let ck_req = CK {
        email: email.clone(),
        id: None,
        ky_p: skap::protocol::KyPublicKey { bytes: *ky_p_bytes.as_slice() },
        di_p: skap::protocol::DiPublicKey { bytes: di_p.into_bytes() },
    };

    let resp = client
        .post(format!("{}/create_user_json", base_url))
        .json(&ck_req)
        .send()
        .await
        .expect("Failed to send request for /create_user_json in helper");
    
    assert_eq!(resp.status(), StatusCode::OK, "Helper Create User did not return OK. Body: {:?}", resp.text().await.unwrap_or_default());
    let ck_resp: CK = resp.json().await.expect("Failed to deserialize JSON response in helper");
    let user_uuid_str = ck_resp.id.expect("User ID should be populated").to_string();
    (ck_resp, user_uuid_str)
}

async fn initial_sync_for_user(client: &Client, base_url: &str, user_uuid_str: &str, token: &str) {
    let resp_sync = client.get(format!("{}/sync_json/{}", base_url, user_uuid_str))
        .header(AUTHORIZATION, format!("Bearer {}", token))
        .send().await.unwrap();
    let status = resp_sync.status();
    let body = resp_sync.text().await.unwrap_or_default();
    assert_eq!(status, StatusCode::OK, "Initial sync failed for user {}. Body: {:?}", user_uuid_str, body);
    let _sync_data: Vec<u8> = serde_json::from_str(&body).expect("Failed to parse sync data from JSON");
}

fn get_dummy_ep_for_client_encryption() -> EP { 
    EP {
        ciphertext: vec![0u8; 40], 
        nonce: vec![0u8; 24],      
        nonce2: Some(vec![0u8;24]) 
    }
}

async fn create_test_pass(client: &Client, base_url: &str, user_uuid_str: &str, token: &str) -> Uuid {
    let pass_ep = get_dummy_ep_for_client_encryption();
    let resp_create = client.post(format!("{}/create_pass_json/{}", base_url, user_uuid_str))
        .header(AUTHORIZATION, format!("Bearer {}", token))
        .json(&pass_ep)
        .send().await.unwrap();
    assert_eq!(resp_create.status(), StatusCode::OK, "/create_pass_json failed in helper. Body: {:?}", resp_create.text().await.unwrap_or_default());
    resp_create.json().await.unwrap()
}


#[tokio::test]
async fn test_create_user_endpoints() {
    let base_url = start_test_server().await;
    let client = Client::new();

    let unique_id_json = Uuid::new_v4().to_string();
    let email_json = format!("testuser_json_{}@example.com", unique_id_json);
    let (ky_p_json_bytes, _) = libcrux_ml_kem::mlkem1024::generate_key_pair(libcrux_ml_kem::mlkem1024::generate_randomness());
    let (di_p_json, _) = fips204::ml_dsa_87::try_keygen().unwrap();

    let ck_json_req = CK {
        email: email_json.clone(),
        id: None, 
        ky_p: skap::protocol::KyPublicKey { bytes: *ky_p_json_bytes.as_slice() },
        di_p: skap::protocol::DiPublicKey { bytes: di_p_json.into_bytes() },
    };

    let resp_json = client
        .post(format!("{}/create_user_json", base_url))
        .json(&ck_json_req)
        .send()
        .await
        .expect("Failed to send request for /create_user_json");

    let resp_status_json = resp_json.status();
    let resp_text_json = resp_json.text().await.unwrap_or_default();
    assert_eq!(resp_status_json, StatusCode::OK, "JSON Create User did not return OK. Response: {}", resp_text_json);
    
    let ck_json_resp: CK = serde_json::from_str(&resp_text_json).expect("Failed to deserialize JSON response for /create_user_json");

    assert!(ck_json_resp.id.is_some(), "JSON Create User response ID is None");
    assert_eq!(ck_json_resp.email, email_json);

    let unique_id_bin = Uuid::new_v4().to_string();
    let email_bin = format!("testuser_bin_{}@example.com", unique_id_bin);
    let (ky_p_bin_bytes, _) = libcrux_ml_kem::mlkem1024::generate_key_pair(libcrux_ml_kem::mlkem1024::generate_randomness());
    let (di_p_bin, _) = fips204::ml_dsa_87::try_keygen().unwrap();
    
    let ck_bin_req = CK {
        email: email_bin.clone(),
        id: None,
        ky_p: skap::protocol::KyPublicKey { bytes: *ky_p_bin_bytes.as_slice() },
        di_p: skap::protocol::DiPublicKey { bytes: di_p_bin.into_bytes() },
    };

    let serialized_ck_bin_req = bincode::serialize(&ck_bin_req).expect("Failed to serialize for /create_user");

    let resp_bin = client
        .post(format!("{}/create_user", base_url))
        .body(serialized_ck_bin_req)
        .header(CONTENT_TYPE, "application/octet-stream")
        .send()
        .await
        .expect("Failed to send request for /create_user");
    
    let resp_status_bin = resp_bin.status();
    let body_bytes_bin = resp_bin.bytes().await.expect("Failed to get bytes from /create_user response");
    assert_eq!(resp_status_bin, StatusCode::OK, "Bincode Create User did not return OK. Response: {:?}", body_bytes_bin);

    let ck_bin_resp: CK = bincode::deserialize(&body_bytes_bin).expect("Failed to deserialize bincode response for /create_user");

    assert!(ck_bin_resp.id.is_some(), "Bincode Create User response ID is None");
    assert_eq!(ck_bin_resp.email, email_bin);
}


#[tokio::test]
async fn test_auth_and_sync_endpoints() {
    let base_url = start_test_server().await;
    let client = Client::builder().cookie_store(true).build().unwrap(); 

    let (created_user, user_uuid_str) = create_test_user(&client, &base_url, "sync_user").await;
    let valid_token = generate_auth_token(&user_uuid_str);

    initial_sync_for_user(&client, &base_url, &user_uuid_str, &valid_token).await;

    let resp_sync_json_bearer = client
        .get(format!("{}/sync_json/{}", base_url, user_uuid_str))
        .header(AUTHORIZATION, format!("Bearer {}", valid_token))
        .send()
        .await
        .expect("Request failed for /sync_json with Bearer token");
    assert_eq!(resp_sync_json_bearer.status(), StatusCode::OK, "Sync JSON with Bearer token failed. Body: {:?}", resp_sync_json_bearer.text().await.unwrap_or_default());
    let _sync_data_json: Vec<u8> = resp_sync_json_bearer.json().await.expect("Failed to parse JSON from /sync_json");
    
     let resp_sync_bin_bearer = client
        .get(format!("{}/sync/{}", base_url, user_uuid_str))
        .header(AUTHORIZATION, format!("Bearer {}", valid_token))
        .send()
        .await
        .expect("Request failed for /sync with Bearer token");
    let bin_status = resp_sync_bin_bearer.status();
    let bin_body = resp_sync_bin_bearer.bytes().await.expect("Failed to get bytes from /sync");
    assert_eq!(bin_status, StatusCode::OK, "Sync Bincode with Bearer token failed. Body: {:?}", bin_body);
    let _sync_data_bin: Vec<u8> = bincode::deserialize(&bin_body).expect("Failed to deserialize bincode from /sync");

    let resp_sync_json_invalid_token = client
        .get(format!("{}/sync_json/{}", base_url, user_uuid_str))
        .header(AUTHORIZATION, "Bearer an-invalid-token-that-is-malformed")
        .send()
        .await
        .expect("Request failed for /sync_json with invalid token");
    assert_eq!(resp_sync_json_invalid_token.status(), StatusCode::UNAUTHORIZED, "Sync JSON with invalid token did not return 401");

    let resp_sync_json_no_token = client
        .get(format!("{}/sync_json/{}", base_url, user_uuid_str))
        .send()
        .await
        .expect("Request failed for /sync_json with no token");
    assert_eq!(resp_sync_json_no_token.status(), StatusCode::UNAUTHORIZED, "Sync JSON with no token did not return 401");

    let (_user_b, user_b_uuid_str) = create_test_user(&client, &base_url, "sync_user_b").await;
    let resp_sync_json_wrong_user = client
        .get(format!("{}/sync_json/{}", base_url, user_b_uuid_str)) 
        .header(AUTHORIZATION, format!("Bearer {}", valid_token)) 
        .send()
        .await
        .expect("Request failed for /sync_json with wrong user token");
    assert_eq!(resp_sync_json_wrong_user.status(), StatusCode::UNAUTHORIZED, "Sync JSON with wrong user token did not return 401");
}


#[tokio::test]
async fn test_send_all_endpoints() {
    let base_url = start_test_server().await;
    let client = Client::new();

    let (created_user, user_uuid_str) = create_test_user(&client, &base_url, "sendall_user").await;
    let valid_token = generate_auth_token(&user_uuid_str);
    
    initial_sync_for_user(&client, &base_url, &user_uuid_str, &valid_token).await;

    let resp_json = client
        .get(format!("{}/send_all_json/{}", base_url, user_uuid_str))
        .header(AUTHORIZATION, format!("Bearer {}", valid_token))
        .send()
        .await
        .expect("Request failed for /send_all_json");
    assert_eq!(resp_json.status(), StatusCode::OK, "/send_all_json returned non-OK status. Body: {:?}", resp_json.text().await.unwrap_or_default());
    let passwords_ext: PasswordsExtended = resp_json.json().await.expect("Failed to parse PasswordsExtended from /send_all_json");
    assert!(passwords_ext.passwords.is_empty(), "Expected no passwords for a new user");
    assert!(passwords_ext.shared_passes.is_empty(), "Expected no shared passwords for a new user");

    let resp_bin = client
        .get(format!("{}/send_all/{}", base_url, user_uuid_str))
        .header(AUTHORIZATION, format!("Bearer {}", valid_token))
        .send()
        .await
        .expect("Request failed for /send_all");
    let bin_status = resp_bin.status();
    let body_bytes_bin = resp_bin.bytes().await.expect("Failed to get bytes from /send_all");
    assert_eq!(bin_status, StatusCode::OK, "/send_all returned non-OK status. Body: {:?}", body_bytes_bin);
    let passwords_bin: Vec<(EP, Uuid)> = bincode::deserialize(&body_bytes_bin).expect("Failed to deserialize Vec<(EP, Uuid)> from /send_all");
    assert!(passwords_bin.is_empty(), "Expected no passwords for a new user (binary)");
}

#[tokio::test]
async fn test_create_pass_endpoints() {
    let base_url = start_test_server().await;
    let client = Client::new();
    let (_user_ck, user_uuid_str) = create_test_user(&client, &base_url, "createpass_user").await;
    let valid_token = generate_auth_token(&user_uuid_str);

    initial_sync_for_user(&client, &base_url, &user_uuid_str, &valid_token).await;

    let pass_ep_json = get_dummy_ep_for_client_encryption();
    let resp_create_json = client.post(format!("{}/create_pass_json/{}", base_url, user_uuid_str))
        .header(AUTHORIZATION, format!("Bearer {}", valid_token))
        .json(&pass_ep_json)
        .send().await.unwrap();
    assert_eq!(resp_create_json.status(), StatusCode::OK, "/create_pass_json failed. Body: {:?}", resp_create_json.text().await.unwrap_or_default());
    let _pass_id_json: Uuid = resp_create_json.json().await.unwrap();

    let pass_ep_bin = get_dummy_ep_for_client_encryption();
    let serialized_ep_bin = bincode::serialize(&pass_ep_bin).unwrap();
    let resp_create_bin = client.post(format!("{}/create_pass/{}", base_url, user_uuid_str))
        .header(AUTHORIZATION, format!("Bearer {}", valid_token))
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(serialized_ep_bin)
        .send().await.unwrap();
    assert_eq!(resp_create_bin.status(), StatusCode::OK, "/create_pass failed. Body: {:?}", resp_create_bin.bytes().await.unwrap_or_default());
    let pass_id_bin_bytes = resp_create_bin.bytes().await.unwrap();
    let _pass_id_bin: Uuid = bincode::deserialize(&pass_id_bin_bytes).unwrap();
}

#[tokio::test]
async fn test_update_pass_endpoints() {
    let base_url = start_test_server().await;
    let client = Client::new();
    let (_user_ck, user_uuid_str) = create_test_user(&client, &base_url, "updatepass_user").await;
    let valid_token = generate_auth_token(&user_uuid_str);

    initial_sync_for_user(&client, &base_url, &user_uuid_str, &valid_token).await;

    let initial_pass_ep = get_dummy_ep_for_client_encryption();
    let pass_to_update_id = create_test_pass(&client, &base_url, &user_uuid_str, &valid_token).await;

    let updated_pass_ep_json = get_dummy_ep_for_client_encryption(); 
    let resp_update_json = client.post(format!("{}/update_pass_json/{}/{}", base_url, user_uuid_str, pass_to_update_id))
        .header(AUTHORIZATION, format!("Bearer {}", valid_token))
        .json(&updated_pass_ep_json)
        .send().await.unwrap();
    assert_eq!(resp_update_json.status(), StatusCode::OK, "/update_pass_json failed. Body: {:?}", resp_update_json.text().await.unwrap_or_default());
    let updated_pass_id_json: Uuid = resp_update_json.json().await.unwrap();
    assert_eq!(updated_pass_id_json, pass_to_update_id);

    let updated_pass_ep_bin = get_dummy_ep_for_client_encryption();
    let serialized_updated_ep_bin = bincode::serialize(&updated_pass_ep_bin).unwrap();
    let resp_update_bin = client.post(format!("{}/update_pass/{}/{}", base_url, user_uuid_str, pass_to_update_id))
        .header(AUTHORIZATION, format!("Bearer {}", valid_token))
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(serialized_updated_ep_bin)
        .send().await.unwrap();
    assert_eq!(resp_update_bin.status(), StatusCode::OK, "/update_pass failed. Body: {:?}", resp_update_bin.bytes().await.unwrap_or_default());
    let updated_pass_id_bin_bytes = resp_update_bin.bytes().await.unwrap();
    let updated_pass_id_bin: Uuid = bincode::deserialize(&updated_pass_id_bin_bytes).unwrap();
    assert_eq!(updated_pass_id_bin, pass_to_update_id);
}

#[tokio::test]
async fn test_delete_pass_endpoints() {
    let base_url = start_test_server().await;
    let client = Client::new();
    let (_user_ck, user_uuid_str) = create_test_user(&client, &base_url, "deletepass_user").await;
    let valid_token = generate_auth_token(&user_uuid_str);

    initial_sync_for_user(&client, &base_url, &user_uuid_str, &valid_token).await;
    
    let pass_id_json = create_test_pass(&client, &base_url, &user_uuid_str, &valid_token).await;
    let resp_delete_json = client.get(format!("{}/delete_pass_json/{}/{}", base_url, user_uuid_str, pass_id_json))
        .header(AUTHORIZATION, format!("Bearer {}", valid_token))
        .send().await.unwrap();
    assert_eq!(resp_delete_json.status(), StatusCode::OK, "/delete_pass_json failed. Body: {:?}", resp_delete_json.text().await.unwrap_or_default());

    let pass_id_bincode = create_test_pass(&client, &base_url, &user_uuid_str, &valid_token).await;
    let resp_delete_bincode = client.get(format!("{}/delete_pass/{}/{}", base_url, user_uuid_str, pass_id_bincode))
        .header(AUTHORIZATION, format!("Bearer {}", valid_token))
        .send().await.unwrap();
    assert_eq!(resp_delete_bincode.status(), StatusCode::OK, "/delete_pass failed. Body: {:?}", resp_delete_bincode.bytes().await.unwrap_or_default());
}

#[tokio::test]
async fn test_send_endpoints() {
    let base_url = start_test_server().await;
    let client = Client::new();
    let (user_ck, user_uuid_str) = create_test_user(&client, &base_url, "send_user").await;
    let valid_token = generate_auth_token(&user_uuid_str);
    initial_sync_for_user(&client, &base_url, &user_uuid_str, &valid_token).await;
    let pass_id = create_test_pass(&client, &base_url, &user_uuid_str, &valid_token).await;

    // JSON
    let resp_json = client.get(format!("{}/send_json/{}/{}", base_url, user_uuid_str, pass_id))
        .header(AUTHORIZATION, format!("Bearer {}", valid_token))
        .send().await.unwrap();
    assert_eq!(resp_json.status(), StatusCode::OK, "/send_json failed. Body: {:?}", resp_json.text().await.unwrap_or_default());
    let _ep_json: EP = resp_json.json().await.unwrap();

    // Bincode
    let resp_bin = client.get(format!("{}/send/{}/{}", base_url, user_uuid_str, pass_id))
        .header(AUTHORIZATION, format!("Bearer {}", valid_token))
        .send().await.unwrap();
    assert_eq!(resp_bin.status(), StatusCode::OK, "/send failed. Body: {:?}", resp_bin.bytes().await.unwrap_or_default());
    let ep_bin_bytes = resp_bin.bytes().await.unwrap();
    let _ep_bin: EP = bincode::deserialize(&ep_bin_bytes).unwrap();
}


#[tokio::test]
async fn test_share_and_get_shared_pass_endpoints() {
    let base_url = start_test_server().await;
    let client = Client::new();

    let (owner_ck, owner_uuid_str) = create_test_user(&client, &base_url, "share_owner").await;
    let owner_token = generate_auth_token(&owner_uuid_str);
    initial_sync_for_user(&client, &base_url, &owner_uuid_str, &owner_token).await;

    let (recipient_ck, recipient_uuid_str) = create_test_user(&client, &base_url, "share_recipient").await;
    let _recipient_token = generate_auth_token(&recipient_uuid_str); // Not used for sharing by owner, but good for completeness
    initial_sync_for_user(&client, &base_url, &recipient_uuid_str, &_recipient_token).await;


    let pass_id = create_test_pass(&client, &base_url, &owner_uuid_str, &owner_token).await;

    // Share pass (JSON)
    let shared_pass_data = SharedPass {
        kem_ct: vec![1;1568], // Placeholder, actual KEM CT would be generated by client
        ep: get_dummy_ep_for_client_encryption(), // Dummy EP, actual would be encrypted by client
        status: ShareStatus::Pending, // Will be set by server
    };
    let resp_share_json = client.post(format!("{}/share_pass_json/{}/{}/{}", base_url, owner_uuid_str, pass_id, recipient_uuid_str))
        .header(AUTHORIZATION, format!("Bearer {}", owner_token))
        .json(&shared_pass_data)
        .send().await.unwrap();
    assert_eq!(resp_share_json.status(), StatusCode::OK, "/share_pass_json failed. Body: {:?}", resp_share_json.text().await.unwrap_or_default());

    // Get shared pass (JSON) - by recipient
    let resp_get_shared_json = client.get(format!("{}/get_shared_pass_json/{}/{}/{}", base_url, recipient_uuid_str, owner_uuid_str, pass_id))
        .header(AUTHORIZATION, format!("Bearer {}", generate_auth_token(&recipient_uuid_str))) // Recipient's token
        .send().await.unwrap();
    assert_eq!(resp_get_shared_json.status(), StatusCode::OK, "/get_shared_pass_json failed. Body: {:?}", resp_get_shared_json.text().await.unwrap_or_default());
    let _retrieved_shared_pass: SharedPass = resp_get_shared_json.json().await.unwrap();
    // Assertions on _retrieved_shared_pass fields if needed

    // Unshare pass (JSON)
    let resp_unshare_json = client.post(format!("{}/unshare_pass_json/{}/{}/{}", base_url, owner_uuid_str, pass_id, recipient_uuid_str))
        .header(AUTHORIZATION, format!("Bearer {}", owner_token))
        .send().await.unwrap();
    assert_eq!(resp_unshare_json.status(), StatusCode::OK, "/unshare_pass_json failed. Body: {:?}", resp_unshare_json.text().await.unwrap_or_default());
}

#[tokio::test]
async fn test_utility_endpoints() {
    let base_url = start_test_server().await;
    let client = Client::new();

    let (user_ck, user_uuid_str) = create_test_user(&client, &base_url, "utility_user").await;
    let user_email = user_ck.email.clone();
    
    // /get_uuid_from_email
    let resp_get_uuid = client.get(format!("{}/get_uuid_from_email/{}", base_url, user_email))
        .send().await.unwrap();
    assert_eq!(resp_get_uuid.status(), StatusCode::OK);
    let uuid_from_email: String = resp_get_uuid.text().await.unwrap();
    assert_eq!(uuid_from_email, user_uuid_str);

    // /get_public_key
    let resp_get_pk = client.get(format!("{}/get_public_key/{}", base_url, user_uuid_str))
        .send().await.unwrap();
    assert_eq!(resp_get_pk.status(), StatusCode::OK);
    let pk_bytes: Vec<u8> = resp_get_pk.json().await.unwrap();
    assert_eq!(pk_bytes, user_ck.ky_p.bytes.to_vec());


    // /get_uuids_from_emails
    let emails_to_query = vec![user_email.clone(), "nonexistent@example.com".to_string()];
    let resp_get_uuids = client.post(format!("{}/get_uuids_from_emails", base_url))
        .json(&emails_to_query)
        .send().await.unwrap();
    assert_eq!(resp_get_uuids.status(), StatusCode::OK);
    let found_uuids: Vec<Uuid> = resp_get_uuids.json().await.unwrap();
    assert_eq!(found_uuids.len(), 1);
    assert_eq!(found_uuids[0].to_string(), user_uuid_str);

    // /get_emails_from_uuids
    let uuids_to_query = vec![Uuid::parse_str(&user_uuid_str).unwrap(), Uuid::new_v4()];
    let resp_get_emails = client.post(format!("{}/get_emails_from_uuids", base_url))
        .json(&uuids_to_query)
        .send().await.unwrap();
    assert_eq!(resp_get_emails.status(), StatusCode::OK);
    let found_emails: Vec<String> = resp_get_emails.json().await.unwrap();
    assert_eq!(found_emails.len(), 1);
    assert_eq!(found_emails[0], user_email);
}

#[tokio::test]
async fn test_shared_pass_status_management() {
    let base_url = start_test_server().await;
    let client = Client::new();

    let (owner_ck, owner_uuid_str) = create_test_user(&client, &base_url, "status_owner").await;
    let owner_token = generate_auth_token(&owner_uuid_str);
    initial_sync_for_user(&client, &base_url, &owner_uuid_str, &owner_token).await;

    let (recipient_ck, recipient_uuid_str) = create_test_user(&client, &base_url, "status_recipient").await;
    let recipient_token = generate_auth_token(&recipient_uuid_str);
    initial_sync_for_user(&client, &base_url, &recipient_uuid_str, &recipient_token).await;

    let pass_id = create_test_pass(&client, &base_url, &owner_uuid_str, &owner_token).await;

    // 1. Share the pass
    let shared_pass_data = SharedPass {
        kem_ct: vec![1;1568], 
        ep: get_dummy_ep_for_client_encryption(),
        status: ShareStatus::Pending, // Initial status is irrelevant client-side for sharing
    };
    let resp_share = client.post(format!("{}/share_pass_json/{}/{}/{}", base_url, owner_uuid_str, pass_id, recipient_uuid_str))
        .header(AUTHORIZATION, format!("Bearer {}", owner_token))
        .json(&shared_pass_data)
        .send().await.unwrap();
    assert_eq!(resp_share.status(), StatusCode::OK, "Share pass failed");

    // 2. Get status (owner) - should be Pending
    let resp_status_owner = client.get(format!("{}/get_shared_pass_status_json/{}/{}/{}", base_url, owner_uuid_str, pass_id, recipient_uuid_str))
        .header(AUTHORIZATION, format!("Bearer {}", owner_token))
        .send().await.unwrap();
    assert_eq!(resp_status_owner.status(), StatusCode::OK);
    let status_owner: ShareStatus = resp_status_owner.json().await.unwrap();
    assert!(matches!(status_owner, ShareStatus::Pending));

    // 3. Recipient accepts
    let resp_accept = client.get(format!("{}/accept_shared_pass_json/{}/{}/{}", base_url, recipient_uuid_str, owner_uuid_str, pass_id))
        .header(AUTHORIZATION, format!("Bearer {}", recipient_token))
        .send().await.unwrap();
    assert_eq!(resp_accept.status(), StatusCode::OK, "Accept shared pass failed. Body: {:?}", resp_accept.text().await.unwrap_or_default());

    // 4. Get status (owner) - should be Accepted
    let resp_status_accepted = client.get(format!("{}/get_shared_pass_status_json/{}/{}/{}", base_url, owner_uuid_str, pass_id, recipient_uuid_str))
        .header(AUTHORIZATION, format!("Bearer {}", owner_token))
        .send().await.unwrap();
    assert_eq!(resp_status_accepted.status(), StatusCode::OK);
    let status_accepted: ShareStatus = resp_status_accepted.json().await.unwrap();
    assert!(matches!(status_accepted, ShareStatus::Accepted));

    // 5. Recipient rejects (after accepting, for testing the change)
    // For this to work, server must allow changing status or we need another share.
    // Let's assume for now it is allowed to re-share or status can be changed.
    // If not, this part needs a new shared pass instance.
    // Re-share to reset to Pending (or create a new shared pass instance)
     let resp_reshare = client.post(format!("{}/share_pass_json/{}/{}/{}", base_url, owner_uuid_str, pass_id, recipient_uuid_str))
        .header(AUTHORIZATION, format!("Bearer {}", owner_token))
        .json(&shared_pass_data) // Fresh share to ensure it's Pending
        .send().await.unwrap();
    assert_eq!(resp_reshare.status(), StatusCode::OK, "Re-Share pass failed for reject test");


    let resp_reject = client.get(format!("{}/reject_shared_pass_json/{}/{}/{}", base_url, recipient_uuid_str, owner_uuid_str, pass_id))
        .header(AUTHORIZATION, format!("Bearer {}", recipient_token))
        .send().await.unwrap();
    assert_eq!(resp_reject.status(), StatusCode::OK, "Reject shared pass failed. Body: {:?}", resp_reject.text().await.unwrap_or_default());

    // 6. Get status (owner) - should be Rejected
    let resp_status_rejected = client.get(format!("{}/get_shared_pass_status_json/{}/{}/{}", base_url, owner_uuid_str, pass_id, recipient_uuid_str))
        .header(AUTHORIZATION, format!("Bearer {}", owner_token))
        .send().await.unwrap();
    assert_eq!(resp_status_rejected.status(), StatusCode::OK);
    let status_rejected: ShareStatus = resp_status_rejected.json().await.unwrap();
    assert!(matches!(status_rejected, ShareStatus::Rejected));
}

// Additional tests for binary versions of status management can be added if necessary,
// following the pattern of JSON tests but using bincode for (de)serialization.
