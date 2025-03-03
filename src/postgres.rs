use std::{fs::File, str::FromStr};
use std::error::Error;

use crate::protocol::{PassesT, ProtocolError, ResultP, UsersT, SharedPassesT, SharedByUser};
use deadpool_postgres::{tokio_postgres, GenericClient, Manager, ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres_tls::MakeRustlsConnect;
use uuid::Uuid;
use once_cell::sync::Lazy;

// Constantes pour les requêtes SQL
static SQL_INSERT_USER: &str = "INSERT INTO users (id, email, ky_public_key, di_public_key) VALUES ($1, $2, $3, $4)";
static SQL_SELECT_USER: &str = "SELECT email, ky_public_key, di_public_key FROM users WHERE id = $1";
static SQL_DELETE_USER: &str = "DELETE FROM users WHERE id = $1";
static SQL_SELECT_USER_BY_EMAIL: &str = "SELECT id, email, ky_public_key, di_public_key FROM users WHERE email = $1";
static SQL_SELECT_UUIDS_FROM_EMAILS: &str = "SELECT id FROM users WHERE email = ANY($1)";
static SQL_SELECT_EMAILS_FROM_UUIDS: &str = "SELECT email FROM users WHERE id = ANY($1)";
static SQL_SELECT_PUBLIC_KEY: &str = "SELECT ky_public_key FROM users WHERE id = $1";

static SQL_INSERT_PASS: &str = "INSERT INTO passes (id, user_id, data) VALUES ($2, $1, $3)";
static SQL_SELECT_PASS: &str = "SELECT data FROM passes WHERE id = $2 AND user_id = $1";
static SQL_DELETE_PASS: &str = "DELETE FROM passes WHERE id = $2 AND user_id = $1";
static SQL_UPDATE_PASS: &str = "UPDATE passes SET data = $3 WHERE id = $2 AND user_id = $1";
static SQL_SELECT_ALL_PASSES: &str = "SELECT data, id FROM passes WHERE user_id = $1";

static SQL_INSERT_SHARED_PASS: &str = "INSERT INTO shared_passes (owner_id, pass_id, recipient_id, data) VALUES ($1, $2, $3, $4)";
static SQL_SELECT_SHARED_PASS: &str = "SELECT data FROM shared_passes WHERE owner_id = $1 AND pass_id = $2 AND recipient_id = $3";
static SQL_DELETE_SHARED_PASS: &str = "DELETE FROM shared_passes WHERE owner_id = $1 AND pass_id = $2 AND recipient_id = $3";
static SQL_SELECT_ALL_SHARED_PASSES: &str = "SELECT data, pass_id, owner_id FROM shared_passes WHERE recipient_id = $1";
static SQL_SELECT_SHARED_BY_USER: &str = "SELECT pass_id, recipient_id FROM shared_passes WHERE owner_id = $1";
static SQL_SELECT_SHARED_BY_USER_AND_PASS: &str = "SELECT recipient_id FROM shared_passes WHERE owner_id = $1 AND pass_id = $2";
static SQL_UPDATE_SHARED_PASS: &str = "UPDATE shared_passes SET data = $4 WHERE owner_id = $1 AND pass_id = $2 AND recipient_id = $3";
// Macro pour gérer les erreurs de base de données de manière cohérente
macro_rules! handle_db_error {
    ($result:expr, $error_msg:expr) => {
        match $result {
            Ok(val) => Ok(val),
            Err(e) => {
                eprintln!("{}: {}", $error_msg, e);
                Err(ProtocolError::StorageError)
            }
        }
    };
}

pub struct Database {
    pool: Pool,
}

impl Database {
    pub async fn new(url: &str, file: &str) -> Result<Database, Box<dyn std::error::Error + Send + Sync>> {
        // Utiliser le fournisseur de crypto par défaut de rustls
        let _ = rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
        
        // Chargement des certificats
        let ca_file = File::open(file).map_err(|e| {
            eprintln!("Error opening CA file: {}", e);
            std::io::Error::new(std::io::ErrorKind::NotFound, "CA file not found")
        })?;
        
        let mut reader = std::io::BufReader::new(ca_file);
        let mut root_store = rustls::RootCertStore::empty();
        
        for cert_result in rustls_pemfile::certs(&mut reader) {
            let cert = cert_result.map_err(|e| {
                eprintln!("Error parsing certificate: {}", e);
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid certificate")
            })?;
            root_store.add(cert).map_err(|e| {
                eprintln!("Error adding certificate: {:?}", e);
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid certificate")
            })?;
        }
        
        // Ajouter également les certificats système si disponibles
        let native_certs = rustls_native_certs::load_native_certs();
        for cert in native_certs.certs {
            if let Err(e) = root_store.add(cert) {
                eprintln!("Error adding native certificate: {:?}", e);
            }
        }
        if !native_certs.errors.is_empty() {
            eprintln!("Errors loading native certificates: {:?}", native_certs.errors);
        }
        
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
            
        let tls = MakeRustlsConnect::new(config);
        let confiz = tokio_postgres::Config::from_str(url).map_err(|e| {
            eprintln!("Error parsing PostgreSQL connection string: {}", e);
            Box::<dyn std::error::Error + Send + Sync>::from(e)
        })?;
        
        let mgr_config = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        
        let mgr = Manager::from_config(confiz, tls, mgr_config);
        let pool = Pool::builder(mgr)
            .max_size(16)
            .build()
            .map_err(|e| {
                eprintln!("Error building connection pool: {}", e);
                Box::<dyn std::error::Error + Send + Sync>::from(e)
            })?;
            
        Ok(Database { pool })
    }

    pub async fn get(&self) -> Result<deadpool_postgres::Object, ProtocolError> {
        handle_db_error!(self.pool.get().await, "Error getting connection")
    }
}

pub struct PassesPostgres {
    pub database: Database,
}

pub struct UsersPostgres {
    pub database: Database,
}

impl UsersPostgres {
    pub async fn new(url: &str, file: &str) -> Result<UsersPostgres, Box<dyn std::error::Error + Send + Sync>> {
        Ok(UsersPostgres {
            database: Database::new(url, file).await?,
        })
    }
}

impl UsersT for UsersPostgres {
    async fn add_user(&mut self, id: uuid::Uuid, user: crate::protocol::CK) -> ResultP<()> {
        let database = self.database.get().await?;
        let stmt = handle_db_error!(database.prepare_cached(SQL_INSERT_USER).await, "Error preparing add_user statement")?;
        handle_db_error!(database.execute(&stmt, &[&id, &user.email, &user.ky_p, &user.di_p]).await, "Error adding user")?;
        Ok(())
    }

    async fn get_user(&self, id: uuid::Uuid) -> ResultP<crate::protocol::CK> {
        let database = self.database.get().await?;
        let stmt = handle_db_error!(database.prepare_cached(SQL_SELECT_USER).await, "Error preparing get_user statement")?;
        let row = handle_db_error!(database.query_one(&stmt, &[&id]).await, "Error getting user")?;
        
        Ok(crate::protocol::CK {
            email: row.get(0),
            ky_p: row.get(1),
            di_p: row.get(2),
            id: None,
        })
    }

    async fn remove_user(&mut self, id: uuid::Uuid) -> ResultP<()> {
        let database = self.database.get().await?;
        handle_db_error!(database.execute(SQL_DELETE_USER, &[&id]).await, "Error removing user")?;
        Ok(())
    }

    async fn get_user_from_email(&self, email: String) -> ResultP<crate::protocol::CK> {
        let database = self.database.get().await?;
        let stmt = handle_db_error!(database.prepare_cached(SQL_SELECT_USER_BY_EMAIL).await, "Error preparing get_user_from_email statement")?;
        let row = handle_db_error!(database.query_one(&stmt, &[&email]).await, "Error getting user from email")?;
        
        Ok(crate::protocol::CK {
            email: row.get(1),
            ky_p: row.get(2),
            di_p: row.get(3),
            id: Some(row.get(0)),
        })
    }

    async fn get_uuids_from_emails(&self, emails: Vec<String>) -> ResultP<Vec<Uuid>> {
        let database = self.database.get().await?;
        let stmt = handle_db_error!(database.prepare_cached(SQL_SELECT_UUIDS_FROM_EMAILS).await, "Error preparing get_uuids_from_emails statement")?;
        let rows = handle_db_error!(database.query(&stmt, &[&emails]).await, "Error getting uuids from emails")?;
        Ok(rows.iter().map(|r| r.get(0)).collect())
    }

    async fn get_emails_from_uuids(&self, uuids: Vec<Uuid>) -> ResultP<Vec<String>> {
        let database = self.database.get().await?;
        let stmt = handle_db_error!(database.prepare_cached(SQL_SELECT_EMAILS_FROM_UUIDS).await, "Error preparing get_emails_from_uuids statement")?;
        let rows = handle_db_error!(database.query(&stmt, &[&uuids]).await, "Error getting emails from uuids")?;
        Ok(rows.iter().map(|r| r.get(0)).collect())
    }
    
    async fn get_public_key(&self, id: Uuid) -> ResultP<[u8; crate::protocol::KYBER_PUBLICKEYBYTES]> {
        let database = self.database.get().await?;
        let stmt = handle_db_error!(database.prepare_cached(SQL_SELECT_PUBLIC_KEY).await, "Error preparing get_public_key statement")?;
        let row = handle_db_error!(database.query_one(&stmt, &[&id]).await, "Error getting public key")?;
        
        let a: Vec<u8> = row.get(0);
        let mut b = [0u8; crate::protocol::KYBER_PUBLICKEYBYTES];
        b.copy_from_slice(&a);
        Ok(b)
    }
}

impl PassesPostgres {
    pub async fn new(url: &str, file: &str) -> Result<PassesPostgres, Box<dyn std::error::Error + Send + Sync>> {
        Ok(PassesPostgres {
            database: Database::new(url, file).await?,
        })
    }
}

impl PassesT for PassesPostgres {
    async fn add_pass(
        &mut self,
        id: uuid::Uuid,
        pass_id: uuid::Uuid,
        pass: Vec<u8>,
    ) -> ResultP<()> {
        let database = self.database.get().await?;
        let stmt = handle_db_error!(database.prepare_cached(SQL_INSERT_PASS).await, "Error preparing add_pass statement")?;
        handle_db_error!(database.execute(&stmt, &[&id, &pass_id, &pass]).await, "Error adding pass")?;
        Ok(())
    }

    async fn get_pass(&self, id: uuid::Uuid, pass_id: uuid::Uuid) -> ResultP<Vec<u8>> {
        let database = self.database.get().await?;
        let stmt = handle_db_error!(database.prepare_cached(SQL_SELECT_PASS).await, "Error preparing get_pass statement")?;
        let row = handle_db_error!(database.query_one(&stmt, &[&id, &pass_id]).await, "Error getting pass")?;
        Ok(row.get(0))
    }

    async fn remove_pass(&mut self, id: uuid::Uuid, pass_id: uuid::Uuid) -> ResultP<()> {
        let database = self.database.get().await?;
        handle_db_error!(database.execute(SQL_DELETE_PASS, &[&id, &pass_id]).await, "Error removing pass")?;
        Ok(())
    }

    async fn update_pass(
        &mut self,
        id: uuid::Uuid,
        pass_id: uuid::Uuid,
        pass: Vec<u8>,
    ) -> ResultP<()> {
        let database = self.database.get().await?;
        handle_db_error!(database.execute(SQL_UPDATE_PASS, &[&id, &pass_id, &pass]).await, "Error updating pass")?;
        Ok(())
    }

    async fn get_all_pass(&self, id: uuid::Uuid) -> ResultP<Vec<(Vec<u8>, uuid::Uuid)>> {
        let database = self.database.get().await?;
        let stmt = handle_db_error!(database.prepare_cached(SQL_SELECT_ALL_PASSES).await, "Error preparing get_all_pass statement")?;
        let rows = handle_db_error!(database.query(&stmt, &[&id]).await, "Error getting all passes")?;
        Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
    }
}

pub struct SharedPassesPostgres {
    pub database: Database,
}

impl SharedPassesPostgres {
    pub async fn new(url: &str, file: &str) -> Result<SharedPassesPostgres, Box<dyn std::error::Error + Send + Sync>> {
        Ok(SharedPassesPostgres {
            database: Database::new(url, file).await?,
        })
    }
}

// Trait pour gérer les mots de passe partagés
impl SharedPassesT for SharedPassesPostgres {
    async fn store_shared_pass(
        &mut self,
        owner: Uuid,
        pass_id: Uuid,
        recipient: Uuid,
        shared_pass: Vec<u8>,
    ) -> ResultP<()> {
        let database = self.database.get().await?;
        if let Ok(_) = self.get_shared_pass(recipient, owner, pass_id).await {
            let stmt = handle_db_error!(
                database.prepare_cached(SQL_UPDATE_SHARED_PASS).await,
                "Error preparing update_shared_pass statement"
            )?;
            handle_db_error!(database.execute(&stmt, &[&owner, &pass_id, &recipient, &shared_pass]).await, "Error updating existing shared pass")?;
        } else {
            let stmt = handle_db_error!(
                database.prepare_cached(SQL_INSERT_SHARED_PASS).await,
                "Error preparing store_shared_pass statement"
            )?;

            handle_db_error!(
                database.execute(&stmt, &[&owner, &pass_id, &recipient, &shared_pass]).await,
                "Error storing shared pass"
            )?;
        }
        Ok(())
    }

    async fn get_shared_pass(
        &self,
        recipient: Uuid,
        owner: Uuid,
        pass_id: Uuid,
    ) -> ResultP<Vec<u8>> {
        let database = self.database.get().await?;
        let stmt = handle_db_error!(
            database.prepare_cached(SQL_SELECT_SHARED_PASS).await,
            "Error preparing get_shared_pass statement"
        )?;
        let row = handle_db_error!(
            database.query_one(&stmt, &[&owner, &pass_id, &recipient]).await,
            "Error getting shared pass"
        )?;

        Ok(row.get(0))
    }

    async fn remove_shared_pass(
        &mut self,
        owner: Uuid,
        pass_id: Uuid,
        recipient: Uuid,
    ) -> ResultP<()> {
        let database = self.database.get().await?;
        let stmt = handle_db_error!(
            database.prepare_cached(SQL_DELETE_SHARED_PASS).await,
            "Error preparing remove_shared_pass statement"
        )?;

        handle_db_error!(
            database.execute(&stmt, &[&owner, &pass_id, &recipient]).await,
            "Error removing shared pass"
        )?;
        Ok(())
    }
    
    async fn get_all_shared_passes(
        &self,
        recipient: Uuid,
    ) -> ResultP<Vec<(Vec<u8>, Uuid, Uuid)>> {
        let database = self.database.get().await?;
        let stmt = handle_db_error!(
            database.prepare_cached(SQL_SELECT_ALL_SHARED_PASSES).await,
            "Error preparing get_all_shared_passes statement"
        )?;

        let rows = handle_db_error!(
            database.query(&stmt, &[&recipient]).await,
            "Error getting all shared passes"
        )?;

        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            result.push((row.get(0), row.get(1), row.get(2)));
        }

        Ok(result)
    }

    async fn get_shared_by_user(
        &self,
        owner: Uuid
    ) -> ResultP<Vec<SharedByUser>> {
        let database = self.database.get().await?;
        let stmt = handle_db_error!(
            database.prepare_cached(SQL_SELECT_SHARED_BY_USER).await,
            "Error preparing get_shared_by_user statement"
        )?;
        
        let rows = handle_db_error!(
            database.query(&stmt, &[&owner]).await,
            "Error getting shared by user"
        )?;

        let mut result = Vec::new();
        let mut pass_map = std::collections::HashMap::new();
        
        for row in rows {
            let pass_id: Uuid = row.get(0);
            let recipient_id: Uuid = row.get(1);
            
            pass_map.entry(pass_id)
                .or_insert_with(Vec::new)
                .push(recipient_id);
        }
        
        for (pass_id, recipient_ids) in pass_map {
            result.push(SharedByUser { pass_id, recipient_ids });
        }
        
        Ok(result)
    }

    async fn get_shared_by_user_and_pass(
        &self,
        owner: Uuid,
        pass_id: Uuid
    ) -> ResultP<Vec<Uuid>> {
        let database = self.database.get().await?;
        let stmt = handle_db_error!(
            database.prepare_cached(SQL_SELECT_SHARED_BY_USER_AND_PASS).await,
            "Error preparing get_shared_by_user_and_pass statement"
        )?;
        
        let rows = handle_db_error!(
            database.query(&stmt, &[&owner, &pass_id]).await,
            "Error getting shared by user and pass"
        )?;
        
        Ok(rows.iter().map(|r| r.get(0)).collect())
    }
}