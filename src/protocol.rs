use base64::Engine;
use blake3::hash;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use thiserror::Error;

#[cfg(feature = "server")]
use crate::postgres::PassesPostgres;
#[cfg(feature = "server")]
use crate::postgres::UsersPostgres;
use bytes::BytesMut;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Key, XChaCha20Poly1305, XNonce,
};
use libcrux_ml_kem::mlkem1024::{
    self, MlKem1024Ciphertext, MlKem1024PrivateKey, MlKem1024PublicKey,
};
#[cfg(feature = "server")]
use postgres_types::{accepts, to_sql_checked, FromSql, ToSql};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::{serde_as, Bytes};
use sharks::{Share, Sharks};
use std::fmt;
use std::io::Write;
use std::{collections::HashMap, io::Read};
use uuid::Uuid;
use fips204::ml_dsa_87;
use fips204::traits::{SerDes, Signer, Verifier};

const KYBER_PUBLICKEYBYTES: usize = 1568;
const KYBER_CIPHERTEXTBYTES: usize = 1568;
const KYBER_SSBYTES: usize = 32;
const KYBER_SECRETKEYBYTES: usize = 3168;

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
    let mut rng = OsRng;
    let mut seed = [0; L];
    rng.try_fill_bytes(&mut seed).unwrap();
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

#[cfg(feature = "server")]
impl<'a> FromSql<'a> for DiPublicKey {
    fn from_sql(
        _ty: &postgres_types::Type,
        raw: &[u8],
    ) -> Result<DiPublicKey, Box<dyn std::error::Error + Sync + Send>> {
        let bt = postgres_protocol::types::bytea_from_sql(&raw);
        let t = DiPublicKey::from_di(di::PublicKey::from_bytes(&bt));
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
        let bt = self.clone().to_di().bytes;
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
        ml_dsa_87::PublicKey::try_from_bytes(&self.bytes).unwrap()
    }
}

impl DiSecretKey {
    fn from_di(pb: ml_dsa_87::PrivateKey) -> Self {
        DiSecretKey { bytes: pb.into_bytes() }
    }

    pub fn to_di(self) -> ml_dsa_87::PrivateKey {
        ml_dsa_87::PrivateKey::try_from_bytes(&self.bytes).unwrap()
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

#[derive(Clone)]
pub struct Server<T: SecretsT, U: PassesT, D: ChallengesT, E: UsersT> {
    users: E,
    rng: StdRng,
    challenges: D,
    secrets: T,
    passes: U,
}

pub struct Secrets(HashMap<Uuid, [u8; 32]>);

pub struct Passes(HashMap<(Uuid, Uuid), Vec<u8>>);

pub struct Challenges(HashMap<Uuid, [u8; 32]>);

pub struct Users(HashMap<Uuid, CK>);

pub trait UsersT {
    async fn get_user(&self, id: Uuid) -> ResultP<CK>;
    async fn add_user(&mut self, id: Uuid, user: CK) -> ResultP<()>;
    async fn remove_user(&mut self, id: Uuid) -> ResultP<()>;
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
}

pub trait SecretsT {
    fn get_secret(&self, id: Uuid) -> ResultP<[u8; 32]>;
    fn add_secret(&mut self, id: Uuid, secret: [u8; KYBER_SSBYTES]);
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
    fn get_secret(&self, id: Uuid) -> ResultP<[u8; 32]> {
        self.0.get(&id).cloned().ok_or(ProtocolError::StorageError)
    }

    fn add_secret(&mut self, id: Uuid, secret: [u8; 32]) {
        self.0.insert(id, secret);
    }
}

impl Server<Secrets, Passes, Challenges, Users> {
    pub fn new() -> ResultP<Self> {
        let rng = SeedableRng::from_entropy();
        Ok(Server {
            users: Users::new(),
            rng,
            challenges: Challenges(HashMap::new()),
            secrets: Secrets(HashMap::new()),
            passes: Passes(HashMap::new()),
        })
    }
}
#[cfg(feature = "server")]
impl Server<Secrets, PassesPostgres, Challenges, UsersPostgres> {
    pub async fn new(postgres_url: &str, file: &str) -> ResultP<Self> {
        let rng = SeedableRng::from_entropy();
        let passes = PassesPostgres::new(postgres_url, file)
            .await
            .map_err(|_| ProtocolError::StorageError)?;
        let users = UsersPostgres::new(postgres_url, file)
            .await
            .map_err(|_| ProtocolError::StorageError)?;
        Ok(Server {
            users,
            rng,
            challenges: Challenges(HashMap::new()),
            secrets: Secrets(HashMap::new()),
            passes,
        })
    }
}

impl<T: SecretsT, U: PassesT, D: ChallengesT, E: UsersT> Server<T, U, D, E> {
    pub async fn add_user(&mut self, ck: &mut CK) -> ResultP<Uuid> {
        ck.set_id();
        let id = ck.id.unwrap();
        self.users.add_user(id.clone(), ck.clone()).await?;
        Ok(id)
    }

    pub async fn get_user(&self, id: Uuid) -> ResultP<CK> {
        self.users.get_user(id).await
    }

    pub async fn challenge(&mut self, id: Uuid) -> ResultP<[u8; 32]> {
        let mut challenge = [0u8; 32];
        self.rng.fill_bytes(&mut challenge);
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
        let verify = ck.di_p.to_di().verify(&challenge, &signature, &[]);
        if verify {
            Ok(())
        } else {
            Err(ProtocolError::AuthError)
        }
    }

    pub async fn sync(&mut self, id: Uuid) -> ResultP<[u8; KYBER_CIPHERTEXTBYTES]> {
        let ck = self.get_user(id).await?;
        let pk = MlKem1024PublicKey::from(ck.ky_p.clone());
        let randomness = random_array();
        let (ciphertext, secret) = mlkem1024::encapsulate(&pk, randomness);
        self.secrets.add_secret(id, secret);
        Ok(*ciphertext.as_slice())
    }

    pub async fn send(&self, id: Uuid, pass_id: Uuid) -> ResultP<EP> {
        let _ck = self.get_user(id).await?;
        let secret = self.secrets.get_secret(id)?;
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
    }

    pub async fn send_all(&self, id: Uuid) -> ResultP<Vec<(EP, Uuid)>> {
        let _ = self.get_user(id).await?;
        let secret = self.secrets.get_secret(id)?;
        let hash = hash(&secret);
        let key: &Key = Key::from_slice(hash.as_bytes());
        let cipher = XChaCha20Poly1305::new(key);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let pass = self.passes.get_all_pass(id).await?;
        let mut res = Vec::new();
        for p in pass {
            let passs: EP = bincode::deserialize(&p.0).unwrap();
            let ciphertext = cipher
                .encrypt(&nonce, passs.ciphertext.as_slice())
                .map_err(|_| ProtocolError::CryptoError)?;
            res.push((
                EP {
                    ciphertext,
                    nonce: passs.nonce,
                    nonce2: Some(nonce.to_vec()),
                },
                p.1,
            ));
        }
        Ok(res)
    }

    pub async fn create_pass(&mut self, id: Uuid, pass: EP) -> ResultP<Uuid> {
        let _ck = self.get_user(id).await?;
        let secret = self.secrets.get_secret(id)?;
        let id2 = Uuid::new_v4();
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
        self.passes.add_pass(id, id2, bi).await?;
        Ok(id2)
    }

    pub async fn update_pass(&mut self, id: Uuid, passid: Uuid, pass: EP) -> ResultP<()> {
        let _ck = self.get_user(id).await?;
        let secret = self.secrets.get_secret(id)?;
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
        self.passes.remove_pass(id, passid).await?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EP {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    nonce2: Option<Vec<u8>>,
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

    pub fn sign(&self, challenge: &[u8]) -> [u8; ml_dsa_87::SIG_LEN] {
        di::SecretKey::sign(&self.di_q.clone().to_di(), challenge)
    }

    pub fn sync(&mut self, ciphertextsync: &[u8]) -> ResultP<()> {
        let sk = MlKem1024PrivateKey::from(&self.ky_q);
        if ciphertextsync.len() != 1568 {
            return Err(ProtocolError::DataError);
        }
        let ci: &[u8; 1568] = ciphertextsync.try_into().unwrap();
        let cipher = MlKem1024Ciphertext::from(ci);
        let s = mlkem1024::decapsulate(&sk, &cipher);
        self.secret = Some(s);
        Ok(())
    }
}

#[derive(Clone)]
pub struct Shard {
    data: Share,
}

impl Serialize for Shard {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let vec: Vec<u8> = (&self.clone().data).into();
        serializer.serialize_bytes(vec.as_slice())
    }
}

impl<'de> Deserialize<'de> for Shard {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ShardVisitor;

        impl<'de> Visitor<'de> for ShardVisitor {
            type Value = Shard;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a byte array")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                // Assuming Share can be constructed from a byte slice
                //
                let data: Share =
                    Share::try_from(v).map_err(|_| de::Error::invalid_length(v.len(), &self))?;
                Ok(Shard { data })
            }
        }

        deserializer.deserialize_bytes(ShardVisitor)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Shards {
    data: Vec<Shard>,
}

impl Shards {
    pub fn new(ret_num: u8, secret: &[u8]) -> Shards {
        let shards = Sharks(3);
        let dealer = shards.dealer(secret);
        let data = dealer
            .take(ret_num.into())
            .map(|x| Shard { data: x })
            .collect();
        Shards { data }
    }

    pub fn recover(self) -> ResultP<Vec<u8>> {
        let shards = Sharks(3);
        let slice: Vec<Share> = self.data.iter().map(|x| x.data.clone()).collect();
        let secret = shards
            .recover(&slice)
            .map_err(|_| ProtocolError::CryptoError);
        secret
    }
}
