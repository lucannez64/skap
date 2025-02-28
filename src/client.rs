use crate::protocol::*;
use reqwest::{cookie::Jar, header::{HeaderValue, COOKIE}, Url};
use reqwest_cookie_store::RawCookie;
use uuid::Uuid;

const BASE_URL: &str = "https://127.0.0.1:3030/";

pub async fn new(client2: &reqwest::Client, email: &str) -> ResultP<(Client, CK)> {
    let client = crate::protocol::Client::new()?;
    let ck = CK::new(client.ky_p, client.di_p.clone(), email.to_string());
    
    let serialized_ck = bincode::serialize(&ck)
        .map_err(|_| ProtocolError::DataError)?;
    
    let res = client2
        .post(BASE_URL.to_string() + "create_user/")
        .body(serialized_ck)
        .send()
        .await
        .map_err(|_| ProtocolError::DataError)?;
    
    let bytes = res.bytes()
        .await
        .map_err(|_| ProtocolError::DataError)?;
    
    let deserialized_ck = bincode::deserialize::<CK>(&bytes)
        .map_err(|_| ProtocolError::DataError)?;
    
    Ok((client, deserialized_ck))
}

pub async fn auth(
    client2: &reqwest::Client,
    jar: std::sync::Arc<reqwest_cookie_store::CookieStoreRwLock>,
    uuid: Uuid,
    client: &mut Client,
) -> ResultP<()> {
    // Obtenir le challenge
    let res = client2
        .get(BASE_URL.to_string() + "challenge/" + uuid.to_string().as_str() + "/")
        .send()
        .await
        .map_err(|_| ProtocolError::DataError)?;
    
    let chall = res.bytes()
        .await
        .map_err(|_| ProtocolError::DataError)?;
    
    // Signer le challenge
    let sign = client.sign(&chall);
    
    // Vérifier la signature
    let serialized_sign = bincode::serialize(sign.as_slice())
        .map_err(|_| ProtocolError::DataError)?;
    
    let res = client2
        .post(BASE_URL.to_string() + "verify/" + uuid.to_string().as_str() + "/")
        .body(serialized_sign)
        .send()
        .await
        .map_err(|_| ProtocolError::DataError)?;
    
    // Récupérer le cookie
    let c = jar.read()
        .map_err(|_| ProtocolError::DataError)?;
    
    let cookies = c.iter_any().collect::<Vec<_>>();
    if cookies.is_empty() {
        return Err(ProtocolError::AuthError);
    }
    
    let cookie = format!("token={}", cookies[0].value().replace("\"", ""));
    
    // Synchroniser
    let syncr = client2
        .get(BASE_URL.to_string() + "sync/" + uuid.to_string().as_str() + "/")
        .header(COOKIE, HeaderValue::from_str(cookie.as_str())
            .map_err(|_| ProtocolError::DataError)?);
    
    let sync = syncr.send()
        .await
        .map_err(|_| ProtocolError::DataError)?;
    
    let d = sync.bytes()
        .await
        .map_err(|_| ProtocolError::DataError)?;
    
    let dd = bincode::deserialize::<&[u8]>(&d)
        .map_err(|_| ProtocolError::DataError)?;
    
    client.sync(dd)?;
    
    Ok(())
}

pub async fn create_pass(
    client2: &reqwest::Client,
    uuid: Uuid,
    client: &mut Client,
    pass: Password,
    jar: std::sync::Arc<reqwest_cookie_store::CookieStoreRwLock>,
) -> ResultP<Uuid> {
    let encrypted = client.encrypt(pass.clone())?;
    let eq = client.send(encrypted)?;
    
    let c = jar.read()
        .map_err(|_| ProtocolError::DataError)?;
    
    let cookies = c.iter_any().collect::<Vec<_>>();
    if cookies.is_empty() {
        return Err(ProtocolError::AuthError);
    }
    
    let cookie = format!("token={}", cookies[0].value().replace("\"", ""));
    
    let serialized_eq = bincode::serialize(&eq)
        .map_err(|_| ProtocolError::DataError)?;
    
    let res = client2
        .post(BASE_URL.to_string() + "create_pass/" + uuid.to_string().as_str() + "/")
        .header(COOKIE, HeaderValue::from_str(cookie.as_str())
            .map_err(|_| ProtocolError::DataError)?)
        .body(serialized_eq)
        .send()
        .await
        .map_err(|_| ProtocolError::DataError)?;
    
    let bytes = res.bytes()
        .await
        .map_err(|_| ProtocolError::DataError)?;
    
    bincode::deserialize::<Uuid>(&bytes)
        .map_err(|_| ProtocolError::DataError)
}

pub async fn update_pass(
    client2: &reqwest::Client,
    uuid: Uuid,
    uuid2: Uuid,
    client: &mut Client,
    pass: Password,
    jar: std::sync::Arc<reqwest_cookie_store::CookieStoreRwLock>,
) -> ResultP<Uuid> {
    let encrypted = client.encrypt(pass.clone())?;
    let eq = client.send(encrypted)?;
    
    let c = jar.read()
        .map_err(|_| ProtocolError::DataError)?;
    
    let cookies = c.iter_any().collect::<Vec<_>>();
    if cookies.is_empty() {
        return Err(ProtocolError::AuthError);
    }
    
    let cookie = format!("token={}", cookies[0].value().replace("\"", ""));
    
    let serialized_eq = bincode::serialize(&eq)
        .map_err(|_| ProtocolError::DataError)?;
    
    let res = client2
        .post(
            BASE_URL.to_string()
                + "update_pass/"
                + uuid.to_string().as_str()
                + "/"
                + uuid2.to_string().as_str()
                + "/",
        )
        .header(COOKIE, HeaderValue::from_str(cookie.as_str())
            .map_err(|_| ProtocolError::DataError)?)
        .body(serialized_eq)
        .send()
        .await
        .map_err(|_| ProtocolError::DataError)?;
    
    let bytes = res.bytes()
        .await
        .map_err(|_| ProtocolError::DataError)?;
    
    bincode::deserialize::<Uuid>(&bytes)
        .map_err(|_| ProtocolError::DataError)
}

pub async fn get_all(
    client2: &reqwest::Client,
    uuid: Uuid,
    client: &mut Client,
    jar: std::sync::Arc<reqwest_cookie_store::CookieStoreRwLock>,
) -> ResultP<(Vec<(Password, Uuid)>, Vec<(Password, Uuid, Uuid)>)> {
    let c = jar.read()
        .map_err(|_| ProtocolError::DataError)?;
    
    let cookies = c.iter_any().collect::<Vec<_>>();
    if cookies.is_empty() {
        return Err(ProtocolError::AuthError);
    }
    
    let cookie = format!("token={}", cookies[0].value().replace("\"", ""));
    let cookie_header = HeaderValue::from_str(cookie.as_str())
        .map_err(|_| ProtocolError::DataError)?;

    // Get owned passwords
    let res = client2
        .get(BASE_URL.to_string() + "send_all/" + uuid.to_string().as_str() + "/")
        .header(COOKIE, cookie_header.clone())
        .send()
        .await
        .map_err(|_| ProtocolError::DataError)?;
    
    let d = res.bytes()
        .await
        .map_err(|_| ProtocolError::DataError)?;

    let mut owned_passwords: Vec<(Password, Uuid)> = Vec::new();
    let da = bincode::deserialize::<Vec<(EP, Uuid)>>(&d)
        .map_err(|_| ProtocolError::DataError)?;
    
    for g in da.iter() {
        let p = client.receive(g.0.clone())?;
        owned_passwords.push((p, g.1));
    }

    // Get shared passwords
    let res = client2
        .get(BASE_URL.to_string() + "get_shared_pass/" + uuid.to_string().as_str() + "/")
        .header(COOKIE, cookie_header)
        .send()
        .await
        .map_err(|_| ProtocolError::DataError)?;
    
    let d = res.bytes()
        .await
        .map_err(|_| ProtocolError::DataError)?;

    let mut shared_passwords: Vec<(Password, Uuid, Uuid)> = Vec::new();
    let shared_data = bincode::deserialize::<Vec<(SharedPass, Uuid, Uuid)>>(&d)
        .map_err(|_| ProtocolError::DataError)?;
    
    for (shared_pass, owner_id, pass_id) in shared_data {
        let password = client.decrypt_shared(shared_pass)?;
        shared_passwords.push((password, owner_id, pass_id));
    }

    Ok((owned_passwords, shared_passwords))
}

pub async fn delete_pass(
    client2: &reqwest::Client,
    uuid: Uuid,
    uuid2: Uuid,
    jar: std::sync::Arc<reqwest_cookie_store::CookieStoreRwLock>
) -> ResultP<()> {
    let c = jar.read()
        .map_err(|_| ProtocolError::DataError)?;
    
    let cookies = c.iter_any().collect::<Vec<_>>();
    if cookies.is_empty() {
        return Err(ProtocolError::AuthError);
    }
    
    let cookie = format!("token={}", cookies[0].value().replace("\"", ""));
    
    let res = client2
        .get(
            BASE_URL.to_string()
                + "delete_pass/"
                + uuid.to_string().as_str()
                + "/"
                + uuid2.to_string().as_str()
                + "/",
        )
        .header(COOKIE, HeaderValue::from_str(cookie.as_str())
            .map_err(|_| ProtocolError::DataError)?)
        .send()
        .await
        .map_err(|_| ProtocolError::DataError)?;
    
    let bytes = res.bytes()
        .await
        .map_err(|_| ProtocolError::DataError)?;
    
    let response = bincode::deserialize::<String>(&bytes)
        .map_err(|_| ProtocolError::DataError)?;
    
    match response.as_str() {
        "OK" => Ok(()),
        _ => Err(ProtocolError::DataError),
    }
}

pub async fn share_pass(
    client2: &reqwest::Client,
    owner_uuid: Uuid,
    pass_uuid: Uuid,
    recipient_uuid: Uuid,
    client: &Client,
    recipient_ky_p: &KyPublicKey,
    password: &Password,
    jar: std::sync::Arc<reqwest_cookie_store::CookieStoreRwLock>,
) -> ResultP<()> {
    // Encrypt the password for sharing
    let shared_pass = client.share_encrypt(password, recipient_ky_p)?;

    let c = jar.read().unwrap();
    let cookie =
        format!("token={}", c.iter_any().collect::<Vec<_>>()[0].value().replace("\"", ""));

    let res = client2
        .post(
            BASE_URL.to_string()
                + "share_pass/"
                + owner_uuid.to_string().as_str()
                + "/"
                + pass_uuid.to_string().as_str()
                + "/"
                + recipient_uuid.to_string().as_str()
                + "/",
        )
        .header(COOKIE, HeaderValue::from_str(cookie.as_str()).unwrap())
        .body(bincode::serialize(&shared_pass).map_err(|_| ProtocolError::DataError)?)
        .send()
        .await
        .map_err(|_| ProtocolError::DataError)?;

    let response = bincode::deserialize::<String>(&res.bytes().await.map_err(|_| ProtocolError::DataError)?).map_err(|_| ProtocolError::DataError)?;
    match response.as_str() {
        "Password shared successfully" => Ok(()),
        _ => Err(ProtocolError::DataError),
    }
}

pub async fn unshare_pass(
    client2: &reqwest::Client,
    owner_uuid: Uuid,
    pass_uuid: Uuid,
    recipient_uuid: Uuid,
    jar: std::sync::Arc<reqwest_cookie_store::CookieStoreRwLock>,
) -> ResultP<()> {
    let c = jar.read().unwrap();
    let cookie =
        format!("token={}", c.iter_any().collect::<Vec<_>>()[0].value().replace("\"", ""));

    let res = client2
        .post(
            BASE_URL.to_string()
                + "unshare_pass/"
                + owner_uuid.to_string().as_str()
                + "/"
                + pass_uuid.to_string().as_str()
                + "/"
                + recipient_uuid.to_string().as_str()
                + "/",
        )
        .header(COOKIE, HeaderValue::from_str(cookie.as_str()).unwrap())
        .send()
        .await
        .map_err(|_| ProtocolError::DataError)?;

    let response = bincode::deserialize::<String>(&res.bytes().await.map_err(|_| ProtocolError::DataError)?).map_err(|_| ProtocolError::DataError)?;
    match response.as_str() {
        "Password unshared successfully" => Ok(()),
        _ => Err(ProtocolError::DataError),
    }
}

pub async fn get_shared_pass(
    client2: &reqwest::Client,
    recipient_uuid: Uuid,
    owner_uuid: Uuid,
    pass_uuid: Uuid,
    client: &Client,
    jar: std::sync::Arc<reqwest_cookie_store::CookieStoreRwLock>,
) -> ResultP<Password> {
    let c = jar.read().unwrap();
    let cookie =
        format!("token={}", c.iter_any().collect::<Vec<_>>()[0].value().replace("\"", ""));

    let res = client2
        .get(
            BASE_URL.to_string()
                + "get_shared_pass/"
                + recipient_uuid.to_string().as_str()
                + "/"
                + owner_uuid.to_string().as_str()
                + "/"
                + pass_uuid.to_string().as_str()
                + "/",
        )
        .header(COOKIE, HeaderValue::from_str(cookie.as_str()).unwrap())
        .send()
        .await
        .map_err(|_| ProtocolError::DataError)?;

    let shared_pass = bincode::deserialize::<SharedPass>(
        &res.bytes().await.map_err(|_| ProtocolError::DataError)?
    ).map_err(|_| ProtocolError::DataError)?;

    // Decrypt the shared password
    client.decrypt_shared(shared_pass)
}
