use crate::protocol::{ChallengesT, ProtocolError, ResultP, SecretsT, KYBER_CIPHERTEXTBYTES};
use redis::{Client, Commands, RedisError};
use std::time::Duration;
use uuid::Uuid;

// Constantes pour les préfixes de clés
const SECRET_KEY_PREFIX: &str = "secret:";
const CHALLENGE_KEY_PREFIX: &str = "challenge:";

// Constantes pour les durées d'expiration
const SECRET_EXPIRATION_SECS: u64 = 3600; // 1 heure
const CHALLENGE_EXPIRATION_SECS: u64 = 20; // 20 secondes

// Macro pour gérer les erreurs Redis de manière cohérente
macro_rules! handle_redis_error {
    ($result:expr) => {
        $result.map_err(|e| {
            eprintln!("Redis error: {}", e);
            ProtocolError::StorageError
        })
    };
}

// Fonction utilitaire pour convertir Vec<u8> en [u8; 32]
fn vec_to_array(vec: Vec<u8>) -> ResultP<[u8; 32]> {
    if vec.len() != 32 {
        eprintln!("Invalid data length: expected 32, got {}", vec.len());
        return Err(ProtocolError::StorageError);
    }

    let mut array = [0u8; 32];
    array.copy_from_slice(&vec);
    Ok(array)
}

pub struct RedisSecrets {
    client: Client,
}

pub struct RedisChallenges {
    client: Client,
}

impl RedisSecrets {
    pub fn new(url: &str) -> Result<Self, RedisError> {
        let client = Client::open(url)?;
        // Vérifier la connexion au démarrage
        let mut con = client.get_connection()?;

        // Authentification Redis si un mot de passe est configuré
        if let Ok(redis_password) = std::env::var("REDIS_PASSWORD") {
            if !redis_password.is_empty() {
                let _: String = redis::cmd("AUTH").arg(&redis_password).query(&mut con)?;
            }
        }

        let _: String = redis::cmd("PING").query(&mut con)?;

        Ok(RedisSecrets { client })
    }

    // Méthode utilitaire pour obtenir une connexion
    fn get_connection(&self) -> ResultP<redis::Connection> {
        handle_redis_error!(self.client.get_connection())
    }

    // Méthode utilitaire pour construire la clé
    fn make_key(id: Uuid) -> String {
        format!("{}{}", SECRET_KEY_PREFIX, id)
    }
}

impl RedisChallenges {
    pub fn new(url: &str) -> Result<Self, RedisError> {
        let client = Client::open(url)?;
        // Vérifier la connexion au démarrage
        let mut con = client.get_connection()?;

        // Authentification Redis si un mot de passe est configuré
        if let Ok(redis_password) = std::env::var("REDIS_PASSWORD") {
            if !redis_password.is_empty() {
                let _: String = redis::cmd("AUTH").arg(&redis_password).query(&mut con)?;
            }
        }

        let _: String = redis::cmd("PING").query(&mut con)?;

        Ok(RedisChallenges { client })
    }

    // Méthode utilitaire pour obtenir une connexion
    fn get_connection(&self) -> ResultP<redis::Connection> {
        handle_redis_error!(self.client.get_connection())
    }

    // Méthode utilitaire pour construire la clé
    fn make_key(id: Uuid) -> String {
        format!("{}{}", CHALLENGE_KEY_PREFIX, id)
    }
}

impl SecretsT for RedisSecrets {
    fn get_secret(&self, id: Uuid) -> ResultP<Option<([u8; 32], [u8; KYBER_CIPHERTEXTBYTES])>> {
        let mut con = self.get_connection()?;
        let key = Self::make_key(id);

        match handle_redis_error!(con.get::<_, Vec<u8>>(key)) {
            Ok(bytes) => {
                if bytes.len() == 32 + KYBER_CIPHERTEXTBYTES {
                    let mut secret = [0u8; 32];
                    let mut ciphertext = [0u8; KYBER_CIPHERTEXTBYTES];

                    secret.copy_from_slice(&bytes[..32]);
                    ciphertext.copy_from_slice(&bytes[32..]);

                    Ok(Some((secret, ciphertext)))
                } else {
                    Ok(None)
                }
            }
            Err(_) => Ok(None),
        }
    }

    fn add_secret(&mut self, id: Uuid, secret: [u8; 32], ciphertext: [u8; KYBER_CIPHERTEXTBYTES]) {
        let mut con = match self.get_connection() {
            Ok(con) => con,
            Err(e) => {
                eprintln!("Failed to get Redis connection: {}", e);
                return;
            }
        };

        let key = Self::make_key(id);
        let expiry = Duration::from_secs(SECRET_EXPIRATION_SECS);

        let mut bytes = Vec::with_capacity(32 + KYBER_CIPHERTEXTBYTES);
        bytes.extend_from_slice(&secret);
        bytes.extend_from_slice(&ciphertext);

        if let Err(e) = con.set_ex::<_, _, ()>(key, bytes, expiry.as_secs()) {
            eprintln!("Error adding secret: {}", e);
        }
    }
}

impl ChallengesT for RedisChallenges {
    fn get_challenge(&self, id: Uuid) -> ResultP<[u8; 32]> {
        let mut con = self.get_connection()?;
        let bytes: Vec<u8> = handle_redis_error!(con.get(Self::make_key(id)))?;
        vec_to_array(bytes)
    }

    fn add_challenge(&mut self, id: Uuid, challenge: [u8; 32]) {
        if let Ok(mut con) = self.get_connection() {
            let key = Self::make_key(id);
            let expiry = Duration::from_secs(CHALLENGE_EXPIRATION_SECS);

            if let Err(e) = con.set_ex::<_, _, ()>(key, challenge.to_vec(), expiry.as_secs()) {
                eprintln!("Error adding challenge: {}", e);
            }
        } else {
            eprintln!("Failed to get Redis connection for adding challenge");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    const TEST_REDIS_URL: &str = "redis://127.0.0.1/";

    #[test]
    fn test_redis_secrets() {
        let result = RedisSecrets::new(TEST_REDIS_URL);
        assert!(result.is_ok());
    }

    #[test]
    fn test_redis_challenges() {
        let result = RedisChallenges::new(TEST_REDIS_URL);
        assert!(result.is_ok());
    }

    #[test]
    fn test_redis_secrets_storage() {
        let mut secrets =
            RedisSecrets::new(TEST_REDIS_URL).expect("Failed to create RedisSecrets in test");
        let id = Uuid::new_v4();
        let secret = [42u8; 32];
        let ciphertext = [45u8; KYBER_CIPHERTEXTBYTES];

        secrets.add_secret(id, secret, ciphertext);
        let retrieved = secrets.get_secret(id);
        assert!(retrieved.is_ok());
        if let Some((retrieved_secret, _)) = retrieved.expect("Failed to get secret in test") {
            assert_eq!(retrieved_secret, secret);
        }
    }

    #[test]
    fn test_redis_challenges_storage() {
        let mut challenges =
            RedisChallenges::new(TEST_REDIS_URL).expect("Failed to create RedisChallenges in test");
        let id = Uuid::new_v4();
        let challenge = [42u8; 32];

        challenges.add_challenge(id, challenge);
        let retrieved = challenges.get_challenge(id);
        assert!(retrieved.is_ok());
        assert_eq!(
            retrieved.expect("Failed to get challenge in test"),
            challenge
        );
    }

    #[test]
    fn test_vec_to_array() {
        // Test avec un vecteur de la bonne taille
        let vec = vec![1u8; 32];
        let result = vec_to_array(vec);
        assert!(result.is_ok());
        assert_eq!(
            result.expect("Failed to convert vec to array in test"),
            [1u8; 32]
        );

        // Test avec un vecteur trop petit
        let vec = vec![1u8; 16];
        let result = vec_to_array(vec);
        assert!(result.is_err());
    }
}
