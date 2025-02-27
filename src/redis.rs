use redis::{Client, Commands, RedisError};
use uuid::Uuid;
use crate::protocol::{SecretsT, ChallengesT, ProtocolError, ResultP};

pub struct RedisSecrets {
    client: Client,
}

pub struct RedisChallenges {
    client: Client,
}

impl RedisSecrets {
    pub fn new(url: &str) -> Result<Self, RedisError> {
        let client = Client::open(url)?;
        Ok(RedisSecrets { client })
    }
}

impl RedisChallenges {
    pub fn new(url: &str) -> Result<Self, RedisError> {
        let client = Client::open(url)?;
        Ok(RedisChallenges { client })
    }
}

impl SecretsT for RedisSecrets {
    fn get_secret(&self, id: Uuid) -> ResultP<[u8; 32]> {
        let mut con = self.client.get_connection()
            .map_err(|_| ProtocolError::StorageError)?;
        
        let bytes: Vec<u8> = con.get(format!("secret:{}", id))
            .map_err(|_| ProtocolError::StorageError)?;
            
        if bytes.len() != 32 {
            return Err(ProtocolError::StorageError);
        }
        
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(array)
    }

    fn add_secret(&mut self, id: Uuid, secret: [u8; 32]) {
        let mut con = self.client.get_connection()
            .map_err(|_| ProtocolError::StorageError)
            .unwrap();
            
        // Store secret with 1 hour expiration
        let _: () = con.set_ex(
            format!("secret:{}", id),
            secret.to_vec(),
            3600
        ).unwrap();
    }
}

impl ChallengesT for RedisChallenges {
    fn get_challenge(&self, id: Uuid) -> ResultP<[u8; 32]> {
        let mut con = self.client.get_connection()
            .map_err(|_| ProtocolError::StorageError)?;
            
        let bytes: Vec<u8> = con.get(format!("challenge:{}", id))
            .map_err(|_| ProtocolError::StorageError)?;
            
        if bytes.len() != 32 {
            return Err(ProtocolError::StorageError);
        }
        
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(array)
    }

    fn add_challenge(&mut self, id: Uuid, challenge: [u8; 32]) {
        let mut con = self.client.get_connection()
            .map_err(|_| ProtocolError::StorageError)
            .unwrap();
            
        // Store challenge with 5 minute expiration
        let _: () = con.set_ex(
            format!("challenge:{}", id),
            challenge.to_vec(),
            20
        ).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_redis_secrets() {
        let url = "redis://127.0.0.1/";
        let result = RedisSecrets::new(url);
        assert!(result.is_ok());
    }

    #[test]
    fn test_redis_challenges() {
        let url = "redis://127.0.0.1/";
        let result = RedisChallenges::new(url);
        assert!(result.is_ok());
    }

    #[test]
    fn test_redis_secrets_storage() {
        let url = "redis://127.0.0.1/";
        let mut secrets = RedisSecrets::new(url).unwrap();
        let id = Uuid::new_v4();
        let secret = [42u8; 32];
        
        secrets.add_secret(id, secret);
        let retrieved = secrets.get_secret(id);
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap(), secret);
    }

    #[test]
    fn test_redis_challenges_storage() {
        let url = "redis://127.0.0.1/";
        let mut challenges = RedisChallenges::new(url).unwrap();
        let id = Uuid::new_v4();
        let challenge = [42u8; 32];
        
        challenges.add_challenge(id, challenge);
        let retrieved = challenges.get_challenge(id);
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap(), challenge);
    }
}
