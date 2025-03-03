use base64::Engine;
use blake3::hash;
use chacha20poly1305::consts::P2;
use thiserror::Error;
use serde_repr::{Serialize_repr, Deserialize_repr};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "server")]
use crate::postgres::PassesPostgres;
#[cfg(feature = "server")]
use crate::postgres::UsersPostgres;
#[cfg(feature = "server")]
use crate::postgres::SharedPassesPostgres;

use bytes::BytesMut;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, rand_core::RngCore},
    Key, XChaCha20Poly1305, XNonce, 
};
use libcrux_ml_kem::mlkem1024::{
    self, MlKem1024Ciphertext, MlKem1024PrivateKey, MlKem1024PublicKey,
};
#[cfg(feature = "server")]
use postgres_types::{accepts, to_sql_checked, FromSql, ToSql};

#[cfg(feature = "server")]
use crate::redis::RedisChallenges;
#[cfg(feature = "server")]
use crate::redis::RedisSecrets;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::{serde_as, Bytes};
use std::fmt;
use std::io::Write;
use std::{collections::HashMap, io::Read};
use uuid::Uuid;
use fips204::ml_dsa_87;
use fips204::traits::{SerDes, Signer, Verifier};

pub const KYBER_PUBLICKEYBYTES: usize = 1568;
pub const KYBER_CIPHERTEXTBYTES: usize = 1568;
pub const KYBER_SSBYTES: usize = 32;
pub const KYBER_SECRETKEYBYTES: usize = 3168;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Cryptographic operation failed")]
    CryptoError,
    #[error("Authentication failed")]
    AuthError,
    #[error("Invalid Data")]
    DataError,
    #[error("Storage Error")]
    StorageError,
}

pub type ResultP<T> = std::result::Result<T, ProtocolError>;


#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug, Copy)]
pub struct KyPublicKey {
    #[serde_as(as = "Bytes")]
    pub bytes: [u8; KYBER_PUBLICKEYBYTES],
}

pub type KySecretKey = [u8; KYBER_SECRETKEYBYTES];

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SharedByUser {
    pub pass_id: Uuid,
    pub recipient_ids: Vec<Uuid>,
}



#[cfg(feature = "server")]
impl<'a> FromSql<'a> for KyPublicKey {
    fn from_sql(
        _ty: &postgres_types::Type,
        raw: &[u8],
    ) -> Result<KyPublicKey, Box<dyn std::error::Error + Sync + Send>> {
        let bt = postgres_protocol::types::bytea_from_sql(&raw);
        let t = MlKem1024PublicKey::try_from(bt)?;
        let t = KyPublicKey {
            bytes: *t.as_slice(),
        };
        Ok(t)
    }

    accepts!(BYTEA);
}

impl From<KyPublicKey> for MlKem1024PublicKey {
    fn from(t: KyPublicKey) -> Self {
        let k: [u8; KYBER_PUBLICKEYBYTES] = t.bytes;
        MlKem1024PublicKey::from(k)
    }
}

fn random_array<const L: usize>() -> [u8; L] {
    let mut seed = [0; L];
    OsRng.fill_bytes(&mut seed);
    seed
}

#[cfg(feature = "server")]
impl ToSql for KyPublicKey {
    fn to_sql(
        &self,
        _ty: &postgres_types::Type,
        out: &mut BytesMut,
    ) -> Result<postgres_types::IsNull, Box<dyn std::error::Error + Sync + Send>> {
        postgres_protocol::types::bytea_to_sql(&self.bytes, out);
        Ok(postgres_types::IsNull::No)
    }

    accepts!(BYTEA);
    to_sql_checked!();
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DiPublicKey {
    #[serde_as(as = "Bytes")]
    pub bytes: [u8; ml_dsa_87::PK_LEN],
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug, Copy)]
pub struct DiSecretKey {
    #[serde_as(as = "Bytes")]
    pub bytes: [u8; ml_dsa_87::SK_LEN],
}

impl Zeroize for DiSecretKey {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for DiSecretKey {}

#[cfg(feature = "server")]
impl<'a> FromSql<'a> for DiPublicKey {
    fn from_sql(
        _ty: &postgres_types::Type,
        raw: &[u8],
    ) -> Result<DiPublicKey, Box<dyn std::error::Error + Sync + Send>> {
        let bt = postgres_protocol::types::bytea_from_sql(&raw);
        let tt: [u8; ml_dsa_87::PK_LEN] = bt.try_into().unwrap();
        let t = DiPublicKey::from_di(ml_dsa_87::PublicKey::try_from_bytes(tt).unwrap());
        Ok(t)
    }

    accepts!(BYTEA);
}

#[cfg(feature = "server")]
impl ToSql for DiPublicKey {
    fn to_sql(
        &self,
        _ty: &postgres_types::Type,
        out: &mut BytesMut,
    ) -> Result<postgres_types::IsNull, Box<dyn std::error::Error + Sync + Send>> {
        let bt = self.clone().bytes;
        postgres_protocol::types::bytea_to_sql(&bt, out);
        Ok(postgres_types::IsNull::No)
    }

    accepts!(BYTEA);
    to_sql_checked!();
}

impl DiPublicKey {
    fn from_di(pb: ml_dsa_87::PublicKey) -> Self {
        DiPublicKey { bytes: pb.into_bytes() }
    }

    fn to_di(self) -> ml_dsa_87::PublicKey {
        ml_dsa_87::PublicKey::try_from_bytes(self.bytes).unwrap()
    }
}

impl DiSecretKey {
    fn from_di(pb: ml_dsa_87::PrivateKey) -> Self {
        DiSecretKey { bytes: pb.into_bytes() }
    }

    pub fn to_di(self) -> ml_dsa_87::PrivateKey {
        ml_dsa_87::PrivateKey::try_from_bytes(self.bytes).unwrap()
    }
}

#[cfg_attr(
    feature = "server",
    derive(postgres_types::ToSql, postgres_types::FromSql)
)]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CK {
    pub email: String,
    pub id: Option<Uuid>,
    pub ky_p: KyPublicKey,
    pub di_p: DiPublicKey,
}

impl CK {
    pub fn new(ky_p: KyPublicKey, di_p: DiPublicKey, email: String) -> CK {
        CK {
            email,
            id: None,
            ky_p,
            di_p,
        }
    }

    fn set_id(&mut self) {
        self.id = Some(Uuid::new_v4());
    }
}

/// Structure pour un mot de passe partagé
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedPass {
    /// Texte chiffré KEM généré avec la clé publique du destinataire
    pub kem_ct: Vec<u8>,
    /// Le mot de passe chiffré (EP) avec la clé partagée
    pub ep: EP,
    pub status: ShareStatus,
}

#[derive(Clone, Debug, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum ShareStatus {
    Pending = 0,
    Accepted = 1,
    Rejected = 2,
}

/// Collection pour stocker les mots de passe partagés
#[derive(Clone)]
pub struct SharedPasses(HashMap<(Uuid, Uuid, Uuid), Vec<u8>>);

impl SharedPasses {
    pub fn new() -> Self {
        SharedPasses(HashMap::new())
    }
}

pub struct Server<T: SecretsT, U: PassesT, D: ChallengesT, E: UsersT, F: SharedPassesT> {
    users: E,
    rng: OsRng,
    challenges: D,
    secrets: T,
    passes: U,
    shared_passes: F,
}

pub struct Secrets(HashMap<Uuid, ([u8; 32], [u8; KYBER_CIPHERTEXTBYTES])>);

pub struct Passes(HashMap<(Uuid, Uuid), Vec<u8>>);

pub struct Challenges(HashMap<Uuid, [u8; 32]>);

pub struct Users(HashMap<Uuid, CK>);

pub trait UsersT {
    async fn get_user(&self, id: Uuid) -> ResultP<CK>;
    async fn add_user(&mut self, id: Uuid, user: CK) -> ResultP<()>;
    async fn remove_user(&mut self, id: Uuid) -> ResultP<()>;
    async fn get_user_from_email(&self, email: String) -> ResultP<CK>;
    async fn get_uuids_from_emails(&self, emails: Vec<String>) -> ResultP<Vec<Uuid>>;
    async fn get_public_key(&self, id: Uuid) -> ResultP<[u8; KYBER_PUBLICKEYBYTES]>;
    async fn get_emails_from_uuids(&self, uuids: Vec<Uuid>) -> ResultP<Vec<String>>;
}

impl Users {
    pub fn new() -> Users {
        Users(HashMap::new())
    }
}
impl UsersT for Users {
    async fn get_user(&self, id: Uuid) -> ResultP<CK> {
        self.0.get(&id).cloned().ok_or(ProtocolError::StorageError)
    }

    async fn add_user(&mut self, id: Uuid, user: CK) -> ResultP<()> {
        self.0.insert(id, user);
        Ok(())
    }

    async fn remove_user(&mut self, id: Uuid) -> ResultP<()> {
        self.0
            .remove(&id)
            .ok_or(ProtocolError::StorageError)
            .map(|_| ())
    }

    async fn get_user_from_email(&self, email: String) -> ResultP<CK> {
        self.0.values().find(|user| user.email == email).cloned().ok_or(ProtocolError::StorageError)
    }

    async fn get_public_key(&self, id: Uuid) -> ResultP<[u8; KYBER_PUBLICKEYBYTES]> {
        let user = self.get_user(id).await?;
        Ok(user.ky_p.bytes)
    }

    async fn get_uuids_from_emails(&self, emails: Vec<String>) -> ResultP<Vec<Uuid>> {
        let uuids = self.0
            .values()
            .filter_map(|user| {
                if emails.contains(&user.email) {
                    user.id
                } else {
                    None
                }
            })
            .collect();
        Ok(uuids)
    }

    async fn get_emails_from_uuids(&self, uuids: Vec<Uuid>) -> ResultP<Vec<String>> {
        let emails = self.0
            .values()
            .filter_map(|user| {
                if let Some(id) = user.id {
                    if uuids.contains(&id) {
                        Some(user.email.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();
        Ok(emails)
    }
}

pub trait SecretsT {
    fn get_secret(&self, id: Uuid) -> ResultP<Option<([u8; 32], [u8; KYBER_CIPHERTEXTBYTES])>>;
    fn add_secret(&mut self, id: Uuid, secret: [u8; KYBER_SSBYTES], ciphertext: [u8; KYBER_CIPHERTEXTBYTES]);
}

pub trait ChallengesT {
    fn get_challenge(&self, id: Uuid) -> ResultP<[u8; 32]>;
    fn add_challenge(&mut self, id: Uuid, challenge: [u8; 32]);
}

impl ChallengesT for Challenges {
    fn get_challenge(&self, id: Uuid) -> ResultP<[u8; 32]> {
        self.0.get(&id).cloned().ok_or(ProtocolError::StorageError)
    }

    fn add_challenge(&mut self, id: Uuid, challenge: [u8; 32]) {
        self.0.insert(id, challenge);
    }
}

pub trait PassesT {
    async fn get_pass(&self, id: Uuid, pass_id: Uuid) -> ResultP<Vec<u8>>;
    async fn add_pass(&mut self, id: Uuid, pass_id: Uuid, pass: Vec<u8>) -> ResultP<()>;
    async fn get_all_pass(&self, id: Uuid) -> ResultP<Vec<(Vec<u8>, Uuid)>>;
    async fn remove_pass(&mut self, id: Uuid, pass_id: Uuid) -> ResultP<()>;
    async fn update_pass(&mut self, id: Uuid, pass_id: Uuid, pass: Vec<u8>) -> ResultP<()>;
}


pub trait SharedPassesT {
    async fn store_shared_pass(
        &mut self,
        owner: Uuid,
        pass_id: Uuid,
        recipient: Uuid,
        shared_pass: Vec<u8>,
    ) -> ResultP<()>;

    async fn get_shared_pass(
        &self,
        recipient: Uuid,
        owner: Uuid,
        pass_id: Uuid,
    ) -> ResultP<Vec<u8>>;

    async fn remove_shared_pass(
        &mut self,
        owner: Uuid,
        pass_id: Uuid,
        recipient: Uuid,
    ) -> ResultP<()>;

    async fn get_all_shared_passes(
        &self,
        recipient: Uuid,
    ) -> ResultP<Vec<(Vec<u8>, Uuid, Uuid)>>;

    async fn get_shared_by_user(
        &self,
        owner: Uuid
    ) -> ResultP<Vec<SharedByUser>>;

    async fn get_shared_by_user_and_pass(
        &self,
        owner: Uuid,
        pass_id: Uuid
    ) -> ResultP<Vec<Uuid>>;
    
}


impl SharedPassesT for SharedPasses {
    async fn store_shared_pass(
        &mut self,
        owner: Uuid,
        pass_id: Uuid,
        recipient: Uuid,
        shared_pass: Vec<u8>,
    ) -> ResultP<()> {
        self.0.insert((owner, pass_id, recipient), shared_pass);
        Ok(())
    }

    async fn get_shared_pass(
        &self,
        recipient: Uuid,
        owner: Uuid,
        pass_id: Uuid,
    ) -> ResultP<Vec<u8>> {
        self.0.get(&(owner, pass_id, recipient)).cloned().ok_or(ProtocolError::StorageError)
    }

    async fn remove_shared_pass(
        &mut self,
        owner: Uuid,
        pass_id: Uuid,
        recipient: Uuid,
    ) -> ResultP<()> {
        self.0.remove(&(owner, pass_id, recipient));
        Ok(())
    }

    async fn get_all_shared_passes(
        &self,
        recipient: Uuid,
    ) -> ResultP<Vec<(Vec<u8>, Uuid, Uuid)>> {
        let mut shared_passes = Vec::new();
        for ((owner, pass_id, rec), shared_pass) in &self.0 {
            if *rec == recipient {
                shared_passes.push((shared_pass.clone(), *owner, *pass_id));
            }
        }
        Ok(shared_passes)
    }

    async fn get_shared_by_user(
        &self,
        ownerr: Uuid
    ) -> ResultP<Vec<SharedByUser>> {
        // Utiliser une HashMap pour regrouper les destinataires par ID de mot de passe
        let mut shared_by_pass_id: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
        
        // Collecter tous les destinataires pour chaque mot de passe
        for ((owner, pass_id, rec), _) in &self.0 {
            if *owner == ownerr {
                shared_by_pass_id
                    .entry(*pass_id)
                    .or_insert_with(Vec::new)
                    .push(*rec);
            }
        }
        
        // Convertir la HashMap en Vec<SharedByUser>
        let shared_passes = shared_by_pass_id
            .into_iter()
            .map(|(pass_id, recipient_ids)| {
                SharedByUser { pass_id, recipient_ids }
            })
            .collect();
            
        Ok(shared_passes)
    }

    async fn get_shared_by_user_and_pass(
        &self,
        owner: Uuid,
        pass_id: Uuid
    ) -> ResultP<Vec<Uuid>> {
        let shared_passes = self.get_shared_by_user(owner).await?;
        let shared_pass = shared_passes.iter().find(|pass| pass.pass_id == pass_id);
        if let Some(shared_pass) = shared_pass {
            Ok(shared_pass.recipient_ids.clone())
        } else {
            Err(ProtocolError::StorageError)
        }
    }

}

impl PassesT for Passes {
    async fn get_pass(&self, id: Uuid, pass_id: Uuid) -> ResultP<Vec<u8>> {
        self.0
            .get(&(id, pass_id))
            .cloned()
            .ok_or(ProtocolError::StorageError)
    }

    async fn add_pass(&mut self, id: Uuid, pass_id: Uuid, pass: Vec<u8>) -> ResultP<()> {
        self.0.insert((id, pass_id), pass);
        Ok(())
    }

    async fn get_all_pass(&self, id: Uuid) -> ResultP<Vec<(Vec<u8>, Uuid)>> {
        let mut res = Vec::new();
        for (k, v) in &self.0 {
            if k.0 == id {
                res.push((v.clone(), k.1));
            }
        }
        Ok(res)
    }

    async fn remove_pass(&mut self, id: Uuid, pass_id: Uuid) -> ResultP<()> {
        self.0
            .remove(&(id, pass_id))
            .ok_or(ProtocolError::StorageError)
            .map(|_| ())
    }

    async fn update_pass(&mut self, id: Uuid, pass_id: Uuid, pass: Vec<u8>) -> ResultP<()> {
        self.remove_pass(id, pass_id).await?;
        self.add_pass(id, pass_id, pass).await?;
        Ok(())
    }
}

impl SecretsT for Secrets {
    fn get_secret(&self, id: Uuid) -> ResultP<Option<([u8; 32], [u8; KYBER_CIPHERTEXTBYTES])>> {
        let secret = self.0.get(&id).cloned();
        Ok(secret)
    }

    fn add_secret(&mut self, id: Uuid, secret: [u8; 32], ciphertext: [u8; KYBER_CIPHERTEXTBYTES]) {
        self.0.insert(id, (secret, ciphertext));
    }
}

impl Server<Secrets, Passes, Challenges, Users, SharedPasses> {
    pub fn new() -> ResultP<Self> {
        let rng = OsRng;
        Ok(Server {
            users: Users::new(),
            rng,
            challenges: Challenges(HashMap::new()),
            secrets: Secrets(HashMap::new()),
            passes: Passes(HashMap::new()),
            shared_passes: SharedPasses(HashMap::new()),
        })
    }
}
#[cfg(feature = "server")]
impl Server<Secrets, PassesPostgres, Challenges, UsersPostgres, SharedPassesPostgres> {
    pub async fn new(postgres_url: &str, file: &str) -> ResultP<Self> {
        let rng = OsRng;
        let passes = PassesPostgres::new(postgres_url, file)
            .await
            .map_err(|_| ProtocolError::StorageError)?;
        let users = UsersPostgres::new(postgres_url, file)
            .await
            .map_err(|_| ProtocolError::StorageError)?;
        let shared_passes = SharedPassesPostgres::new(postgres_url, file)
            .await
            .map_err(|_| ProtocolError::StorageError)?;
        Ok(Server {
            users,
            rng,
            challenges: Challenges(HashMap::new()),
            secrets: Secrets(HashMap::new()),
            passes,
            shared_passes,
        })
    }
}

impl<T: SecretsT, U: PassesT, D: ChallengesT, E: UsersT, F: SharedPassesT> Server<T, U, D, E, F> {
    pub async fn add_user(&mut self, ck: &mut CK) -> ResultP<Uuid> {
        ck.set_id();
        let id = ck.id.unwrap();
        self.users.add_user(id, ck.clone()).await?;
        Ok(id)
    }

    pub async fn get_uuid_from_email(&self, email: String) -> ResultP<Uuid> {
        let user = self.users.get_user_from_email(email).await?;
        if let Some(id) = user.id {
            Ok(id)
        } else {
            Err(ProtocolError::StorageError)
        }
    }

    pub async fn get_emails_from_uuids(&self, uuids: Vec<Uuid>) -> ResultP<Vec<String>> {
        self.users.get_emails_from_uuids(uuids).await
    }

    pub async fn get_uuids_from_emails(&self, emails: Vec<String>) -> ResultP<Vec<Uuid>> {
        self.users.get_uuids_from_emails(emails).await
    }

    pub async fn get_public_key(&self, id: Uuid) -> ResultP<[u8; KYBER_PUBLICKEYBYTES]> {
        self.users.get_public_key(id).await
    }

    pub async fn get_all_shared_passes(&self, recipient: Uuid) -> ResultP<Vec<(SharedPass, Uuid, Uuid)>> {
        let mut shared_passes = Vec::new();
        let shared_data = self.shared_passes.get_all_shared_passes(recipient).await?;
        
        for (data, owner_id, pass_id) in shared_data {
            let shared_pass = bincode::deserialize(&data)
                .map_err(|_| ProtocolError::DataError)?;
            shared_passes.push((shared_pass, owner_id, pass_id));
        }
        
        Ok(shared_passes)
    }

    pub async fn get_user(&self, id: Uuid) -> ResultP<CK> {
        self.users.get_user(id).await
    }

    pub async fn challenge(&mut self, id: Uuid) -> ResultP<[u8; 32]> {
        let mut challenge = [0u8; 32];
        self.rng.try_fill_bytes(&mut challenge)
            .map_err(|_| ProtocolError::CryptoError)?;
        let _ = self.get_user(id).await?;
        self.challenges.add_challenge(id, challenge);
        Ok(challenge)
    }

    pub async fn verify(&self, id: Uuid, signature: &[u8]) -> ResultP<()> {
        if signature.len() !=  ml_dsa_87::SIG_LEN {
            return Err(ProtocolError::AuthError);
        }
        let ck = self.get_user(id).await?;
        let challenge = self.challenges.get_challenge(id)?;
        let signature2 : [u8; ml_dsa_87::SIG_LEN] = signature.try_into()
            .map_err(|_| ProtocolError::AuthError)?;
        let verify = ck.di_p.to_di().verify(&challenge, &signature2, &[]);
        if verify {
            Ok(())
        } else {
            Err(ProtocolError::AuthError)
        }
    }

    pub async fn sync(&mut self, id: Uuid) -> ResultP<[u8; KYBER_CIPHERTEXTBYTES]> {
        let ck = self.get_user(id).await?;
        let option = self.secrets.get_secret(id)?;
        if let Some((secret, ciphertext)) = option {
            let ciphertext2: [u8; KYBER_CIPHERTEXTBYTES] = ciphertext.try_into()
                .map_err(|_| ProtocolError::CryptoError)?;
            return Ok(ciphertext2);
        }
        let pk = MlKem1024PublicKey::from(ck.ky_p.clone());
        let randomness = random_array();
        let (ciphertext, secret) = mlkem1024::encapsulate(&pk, randomness);
        self.secrets.add_secret(id, secret, *ciphertext.as_slice());
        Ok(*ciphertext.as_slice())
    }

    pub async fn send(&self, id: Uuid, pass_id: Uuid) -> ResultP<EP> {
        let _ck = self.get_user(id).await?;
        let option = self.secrets.get_secret(id)?;
        if let Some((secret, ciphertext)) = option {
            let hash = hash(&secret);
            let key: &Key = Key::from_slice(hash.as_bytes());
            let cipher = XChaCha20Poly1305::new(key);
            let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
            let pass = self.passes.get_pass(id, pass_id).await?;
            let passs: EP = bincode::deserialize(&pass).unwrap();
            let ciphertext = cipher
                .encrypt(&nonce, passs.ciphertext.as_slice())
                .map_err(|_| ProtocolError::CryptoError)?;
            Ok(EP {
                ciphertext,
                nonce: passs.nonce,
                nonce2: Some(nonce.to_vec()),
            })
        } else {
            Err(ProtocolError::StorageError)
        }
    }

    pub async fn send_all(&self, id: Uuid) -> ResultP<Vec<(EP, Uuid)>> {
        let _ = self.get_user(id).await?;
        let option = self.secrets.get_secret(id)?;
        if let None = option {
            return Err(ProtocolError::StorageError);
        }
        let (secret, ciphertext) = option.unwrap();
        let hash = hash(&secret);
        let key: &Key = Key::from_slice(hash.as_bytes());
        let cipher = XChaCha20Poly1305::new(key);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let passes = self.passes.get_all_pass(id).await?;
        
        let results = passes
            .into_iter()
            .map(|(pass_data, pass_id)| {
                let pass: EP = bincode::deserialize(&pass_data).unwrap();
                let ciphertext = cipher
                    .encrypt(&nonce, pass.ciphertext.as_slice())
                    .map_err(|_| ProtocolError::CryptoError);
                
                ciphertext.map(|ct| {
                    (
                        EP {
                            ciphertext: ct,
                            nonce: pass.nonce,
                            nonce2: Some(nonce.to_vec()),
                        },
                        pass_id,
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
            
        Ok(results)
    }

    pub async fn create_pass(&mut self, id: Uuid, pass: EP) -> ResultP<Uuid> {
        let _ck = self.get_user(id).await?;
        let option = self.secrets.get_secret(id)?;
        if let None = option {
            return Err(ProtocolError::StorageError);
        }
        let (secret, ciphertext) = option.unwrap();
        let id2 = Uuid::new_v4();
        let hash = hash(&secret);
        let key: &Key = Key::from_slice(hash.as_bytes());
        let cipher = XChaCha20Poly1305::new(key);
        let nonce2 = pass.nonce2.clone().ok_or(ProtocolError::DataError)?;


        let pass2 = cipher
            .decrypt(XNonce::from_slice(&nonce2), pass.ciphertext.as_slice())
            .map_err(|e| {
                println!("Error decrypting pass: {}", e.to_string());
                ProtocolError::CryptoError
            })?;
        let ep = EP {
            ciphertext: pass2,
            nonce: pass.nonce,
            nonce2: None,
        };
        let bi = bincode::serialize(&ep).map_err(|_| ProtocolError::DataError)?;
        self.passes.add_pass(id, id2, bi).await?;
        Ok(id2)
    }

    pub async fn update_pass(&mut self, id: Uuid, passid: Uuid, pass: EP) -> ResultP<()> {
        let _ck = self.get_user(id).await?;
        let option = self.secrets.get_secret(id)?;
        if let None = option {
            return Err(ProtocolError::StorageError);
        }
        let (secret, ciphertext) = option.unwrap();
        let hash = hash(&secret);
        let key: &Key = Key::from_slice(hash.as_bytes());
        let cipher = XChaCha20Poly1305::new(key);
        let nonce2 = pass.nonce2.clone().ok_or(ProtocolError::DataError)?;
        let pass2 = cipher
            .decrypt(XNonce::from_slice(&nonce2), pass.ciphertext.as_slice())
            .map_err(|_| ProtocolError::CryptoError)?;
        let ep = EP {
            ciphertext: pass2,
            nonce: pass.nonce,
            nonce2: None,
        };
        let bi = bincode::serialize(&ep).map_err(|_| ProtocolError::DataError)?;
        self.passes.update_pass(id, passid, bi).await?;
        Ok(())
    }

    pub async fn delete_pass(&mut self, id: Uuid, passid: Uuid) -> ResultP<()> {
        let _ck = self.get_user(id).await?;
        if let Ok(recipients) = self.shared_passes.get_shared_by_user_and_pass(id, passid).await {
            for recipient in recipients {
                self.shared_passes.remove_shared_pass(id, passid, recipient).await?;
            }
        }
        self.passes.remove_pass(id, passid).await?;
        Ok(())
    }

    /// Stocker un mot de passe partagé
    pub async fn store_shared_pass(
        &mut self,
        owner: Uuid,
        pass_id: Uuid,
        recipient: Uuid,
        shared_pass: SharedPass,
    ) -> ResultP<()> {
        // Sérialiser le mot de passe partagé
        let mut shared_pass2 = shared_pass.clone();
        if let Ok(a) = self.shared_passes.get_shared_pass(recipient, owner, pass_id).await {
            let shared_pass3: SharedPass = bincode::deserialize(&a).unwrap();
            shared_pass2.status = shared_pass3.status;
        } else {
            shared_pass2.status = ShareStatus::Pending;
        }
        let shared_serialized = bincode::serialize(&shared_pass2)
            .map_err(|_| ProtocolError::DataError)?;
            
        // Stocker dans la base de données
        self.shared_passes
            .store_shared_pass(owner, pass_id, recipient, shared_serialized)
            .await
    }

    /// Révoquer le partage
    pub async fn unshare_pass(
        &mut self,
        owner: Uuid,
        pass_id: Uuid,
        recipient: Uuid,
    ) -> ResultP<()> {
        self.shared_passes
            .remove_shared_pass(owner, pass_id, recipient)
            .await
    }

    /// Récupérer un mot de passe partagé
    pub async fn get_shared_pass(
        &self,
        recipient: Uuid,
        owner: Uuid,
        pass_id: Uuid,
    ) -> ResultP<SharedPass> {
        let shared_data = self.shared_passes
            .get_shared_pass(recipient, owner, pass_id)
            .await?;
        bincode::deserialize(&shared_data)
            .map_err(|_| ProtocolError::DataError)
    }

    pub async fn get_shared_by_user(
        &self,
        owner: Uuid
    ) -> ResultP<Vec<SharedByUser>> {
        let shared_by_user: Vec<SharedByUser> = self.shared_passes.get_shared_by_user(owner).await?;
        Ok(shared_by_user)
    }

    pub async fn accept_shared_pass(
        &mut self,
        owner: Uuid,
        pass_id: Uuid,
        recipient: Uuid
    ) -> ResultP<()> {
        let mut shared_pass = self.get_shared_pass(recipient, owner, pass_id).await?;
        shared_pass.status = ShareStatus::Accepted;
        let shared_serialized = bincode::serialize(&shared_pass)
            .map_err(|_| ProtocolError::DataError)?;
        self.shared_passes.store_shared_pass(owner, pass_id, recipient, shared_serialized).await?;
        Ok(())
    }

    pub async fn get_shared_pass_status(
        &self,
        owner: Uuid,
        pass_id: Uuid,
        recipient: Uuid
    ) -> ResultP<ShareStatus> {
        let shared_data = self.shared_passes
            .get_shared_pass(recipient, owner, pass_id)
            .await?;
        let shared_pass: SharedPass = bincode::deserialize(&shared_data)
            .map_err(|_| ProtocolError::DataError)?;
        Ok(shared_pass.status)
    }
    

    pub async fn reject_shared_pass(
        &mut self,
        owner: Uuid,
        pass_id: Uuid,
        recipient: Uuid
    ) -> ResultP<()> {
        let mut shared_pass = self.get_shared_pass(recipient, owner, pass_id).await?;
        shared_pass.status = ShareStatus::Rejected;
        let shared_serialized = bincode::serialize(&shared_pass)
            .map_err(|_| ProtocolError::DataError)?;
        self.shared_passes.store_shared_pass(owner, pass_id, recipient, shared_serialized).await?;
        Ok(())
    }
    
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EP {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub nonce2: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Password {
    pub password: String,
    pub app_id: Option<String>,
    pub username: String,
    pub description: Option<String>,
    pub url: Option<String>,
    pub otp: Option<String>,
}

impl Zeroize for Password {
    fn zeroize(&mut self) {
        self.password.zeroize();
        if let Some(ref mut app_id) = self.app_id {
            app_id.zeroize();
        }
        self.username.zeroize();
        if let Some(ref mut description) = self.description {
            description.zeroize();
        }
        if let Some(ref mut url) = self.url {
            url.zeroize();
        }
        if let Some(ref mut otp) = self.otp {
            otp.zeroize();
        }
    }
}

impl ZeroizeOnDrop for Password {}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Client {
    pub ky_p: KyPublicKey,
    #[serde_as(as = "Bytes")]
    pub ky_q: KySecretKey,
    pub di_p: DiPublicKey,
    pub di_q: DiSecretKey,
    pub secret: Option<[u8; KYBER_SSBYTES]>,
}

impl Zeroize for Client {
    fn zeroize(&mut self) {
        self.ky_q.zeroize();
        self.di_q.zeroize();
        if let Some(ref mut secret) = self.secret {
            secret.zeroize();
        }
    }
}

impl ZeroizeOnDrop for Client {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientEx {
    pub c: Client,
    pub id: CK,
}

impl ClientEx {
    pub fn new(c: &Client, ck: &CK) -> Self {
        ClientEx {
            c: c.clone(),
            id: ck.clone(),
        }
    }

    pub fn to_string(&self) -> String {
        let a = bincode::serialize(&self)
            .map_err(|_| ProtocolError::DataError)
            .unwrap();
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(a)
    }

    pub fn to_file(&self, file_name: String) -> ResultP<()> {
        let a = bincode::serialize(&self)
            .map_err(|_| ProtocolError::DataError)
            .unwrap();
        let mut file = std::fs::File::create(file_name)
            .map_err(|_| ProtocolError::DataError)
            .unwrap();
        file.write_all(&a)
            .map_err(|_| ProtocolError::DataError)
            .unwrap();
        Ok(())
    }

    pub fn from_file(file_name: String) -> ResultP<Self> {
        let mut file = std::fs::File::open(file_name)
            .map_err(|_| ProtocolError::DataError)
            .unwrap();
        let mut a = Vec::new();
        file.read_to_end(&mut a)
            .map_err(|_| ProtocolError::DataError)
            .unwrap();
        let c = bincode::deserialize(&a)
            .map_err(|_| ProtocolError::DataError)
            .unwrap();
        Ok(c)
    }
}

impl Client {
    pub fn new() -> ResultP<Self> {
        let randomness = random_array();
        let keypair = mlkem1024::generate_key_pair(randomness);
        let ky_p = *keypair.pk();
        let ky_q = *keypair.sk();
        let dikeypair = ml_dsa_87::try_keygen().map_err(|_| ProtocolError::CryptoError)?;
        let di_p = dikeypair.0;
        let di_q = dikeypair.1;
        Ok(Client {
            ky_p: KyPublicKey { bytes: ky_p },
            ky_q,
            di_p: DiPublicKey::from_di(di_p),
            di_q: DiSecretKey::from_di(di_q),
            secret: None,
        })
    }

    pub fn encrypt(&self, pass: Password) -> ResultP<EP> {
        let passb = bincode::serialize(&pass).map_err(|_| ProtocolError::DataError)?;
        let hash = hash(&self.ky_q);
        let key: &Key = Key::from_slice(hash.as_bytes());
        let cipher = XChaCha20Poly1305::new(key);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, passb.as_slice())
            .map_err(|_| ProtocolError::CryptoError)?;
        Ok(EP {
            ciphertext,
            nonce: nonce.to_vec(),
            nonce2: None,
        })
    }

    pub fn send(&self, ep: EP) -> ResultP<EP> {
        let secret = self.secret.clone().ok_or(ProtocolError::CryptoError)?;
        let hash = hash(&secret);
        let key: &Key = Key::from_slice(hash.as_bytes());
        let cipher = XChaCha20Poly1305::new(key);
        let nonce2 = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce2, ep.ciphertext.as_slice())
            .map_err(|_| ProtocolError::CryptoError)?;
        Ok(EP {
            ciphertext,
            nonce: ep.nonce,
            nonce2: Some(nonce2.to_vec()),
        })
    }

    pub fn receive(&self, ep: EP) -> ResultP<Password> {
        let secret = self.secret.clone().ok_or(ProtocolError::CryptoError)?;
        let hash = hash(&secret);
        let key: &Key = Key::from_slice(hash.as_bytes());
        let cipher = XChaCha20Poly1305::new(key);
        let nonce2 = ep.nonce2.clone().ok_or(ProtocolError::DataError)?;
        // NONCE 2
        // DECRYPT
        let pass = cipher
            .decrypt(XNonce::from_slice(&nonce2), ep.ciphertext.as_slice())
            .map_err(|_| ProtocolError::CryptoError)?;
        let ep = EP {
            ciphertext: pass,
            nonce: ep.nonce,
            nonce2: None,
        };
        self.decrypt(ep)
    }

    pub fn decrypt(&self, ep: EP) -> ResultP<Password> {
        let hash = hash(&self.ky_q);
        let key: Key = Key::clone_from_slice(hash.as_bytes());
        let cipher = XChaCha20Poly1305::new(&key);
        let pass = cipher
            .decrypt(XNonce::from_slice(&ep.nonce), ep.ciphertext.as_slice())
            .map_err(|_| ProtocolError::CryptoError)?;
        let pass: Password = bincode::deserialize(&pass).map_err(|_| ProtocolError::DataError)?;
        Ok(pass)
    }

    pub fn sign(&self, challenge: &[u8]) -> ResultP<[u8; ml_dsa_87::SIG_LEN]> {
        self.di_q.clone().to_di().try_sign(challenge, &[])
            .map_err(|_| ProtocolError::CryptoError)
    }

    pub fn sync(&mut self, ciphertextsync: &[u8]) -> ResultP<()> {
        let sk = MlKem1024PrivateKey::from(&self.ky_q);
        if ciphertextsync.len() != 1568 {
            return Err(ProtocolError::DataError);
        }
        let ci: &[u8; 1568] = ciphertextsync.try_into()
            .map_err(|_| ProtocolError::DataError)?;
        let cipher = MlKem1024Ciphertext::from(ci);
        let s = mlkem1024::decapsulate(&sk, &cipher);
        self.secret = Some(s);
        Ok(())
    }

    /// Chiffrer un mot de passe pour un destinataire
    pub fn share_encrypt(
        &self,
        raw_password: &Password,
        recipient_ky_p: &KyPublicKey,
    ) -> ResultP<SharedPass> {
        // Encapsuler une clé partagée avec la clé publique du destinataire
        let kem_rand = random_array();
        let recipient_pk: MlKem1024PublicKey = recipient_ky_p.clone().into();
        let (kem_ct, shared_secret) = mlkem1024::encapsulate(&recipient_pk, kem_rand);

        // Dériver une clé symétrique
        let hash = hash(&shared_secret);
        let shared_key: &Key = Key::from_slice(hash.as_bytes());
        let shared_cipher = XChaCha20Poly1305::new(shared_key);
        let shared_nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        // Chiffrer le mot de passe
        let password_ser = bincode::serialize(&raw_password)
            .map_err(|_| ProtocolError::DataError)?;
        let shared_ct = shared_cipher
            .encrypt(&shared_nonce, password_ser.as_slice())
            .map_err(|_| ProtocolError::CryptoError)?;

        Ok(SharedPass {
            kem_ct: kem_ct.as_slice().to_vec(),
            ep: EP {
                ciphertext: shared_ct,
                nonce: shared_nonce.to_vec(),
                nonce2: None,
            },
            status: ShareStatus::Pending,
        })
    }

    /// Déchiffrer un mot de passe partagé
    pub fn decrypt_shared(&self, shared_pass: SharedPass) -> ResultP<Password> {
        // Décapsuler la clé partagée
        let kem_ct = shared_pass.kem_ct.as_slice();
        if kem_ct.len() != 1568 {
            return Err(ProtocolError::DataError);
        }
        let kem_array: &[u8; 1568] = kem_ct.try_into()
            .map_err(|_| ProtocolError::DataError)?;
        let kem_cipher = MlKem1024Ciphertext::from(kem_array);
        let shared_secret = mlkem1024::decapsulate(
            &MlKem1024PrivateKey::from(&self.ky_q),
            &kem_cipher,
        );

        // Déchiffrer le mot de passe
        let hash = hash(&shared_secret);
        let shared_key: &Key = Key::from_slice(hash.as_bytes());
        let shared_cipher = XChaCha20Poly1305::new(shared_key);
        let nonce = XNonce::from_slice(&shared_pass.ep.nonce);
        let decrypted_bytes = shared_cipher
            .decrypt(nonce, shared_pass.ep.ciphertext.as_slice())
            .map_err(|_| ProtocolError::CryptoError)?;

        bincode::deserialize(&decrypted_bytes)
            .map_err(|_| ProtocolError::DataError)
    }
}


#[derive(Clone, Serialize, Deserialize)]
pub struct Shards {
    data: Vec<Vec<u8>>,
}

impl Shards {
    pub fn new(ret_num: u8, secret: &[u8]) -> ResultP<Shards> {
        let threshold = 3; // Nombre minimum de parts nécessaires pour reconstruire le secret
        let shares = sss_rs::prelude::share(&secret, threshold, ret_num, true)
            .map_err(|_| ProtocolError::CryptoError)?;
        Ok(Shards { data: shares })
    }

    pub fn recover(self) -> ResultP<Vec<u8>> {
        let secret = sss_rs::prelude::reconstruct(&self.data, true).map_err(|_| ProtocolError::CryptoError)?;
        Ok(secret)
    }
}

#[cfg(feature = "server")]
impl Server<RedisSecrets, PassesPostgres, RedisChallenges, UsersPostgres, SharedPassesPostgres> {
    pub async fn new_with_redis(postgres_url: &str, redis_url: &str, file: &str) -> ResultP<Self> {
        let rng = OsRng;
        let passes = PassesPostgres::new(postgres_url, file)
            .await
            .map_err(|_| ProtocolError::StorageError)?;
        let users = UsersPostgres::new(postgres_url, file)
            .await
            .map_err(|_| ProtocolError::StorageError)?;
        let secrets = RedisSecrets::new(redis_url)
            .map_err(|_| ProtocolError::StorageError)?;
        let challenges = RedisChallenges::new(redis_url)
            .map_err(|_| ProtocolError::StorageError)?;
        let shared_passes = SharedPassesPostgres::new(postgres_url, file)
            .await
            .map_err(|_| ProtocolError::StorageError)?;

        Ok(Server {
            users,
            rng,
            challenges,
            secrets,
            passes,
            shared_passes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = Client::new();
        assert!(client.is_ok());
        let client = client.unwrap();
        assert!(client.secret.is_none());
    }

    #[test]
    fn test_password_encryption() {
        let client = Client::new().unwrap();
        let pass = Password {
            username: "test".to_string(),
            password: "password123".to_string(),
            app_id: None,
            description: None,
            url: Some("https://example.com".to_string()),
            otp: None,
        };

        let encrypted = client.encrypt(pass.clone());
        assert!(encrypted.is_ok());
        let ep = encrypted.unwrap();
        assert!(!ep.ciphertext.is_empty());
        assert!(!ep.nonce.is_empty());
        assert!(ep.nonce2.is_none());
    }

    #[test]
    fn test_shards() {
        let secret = b"test secret";
        let shards = Shards::new(5, secret).unwrap();
        let recovered = shards.recover().unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_client_signing() {
        let client = Client::new().unwrap();
        let challenge = b"test challenge";
        let signature = client.sign(challenge);
        assert_eq!(signature.len(), ml_dsa_87::SIG_LEN);
    }
}
