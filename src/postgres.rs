use std::{fs::File, str::FromStr};

use crate::protocol::{PassesT, ProtocolError, ResultP, UsersT};
use tokio_postgres::{Error, NoTls};
use deadpool_postgres::{tokio_postgres, GenericClient, Manager, ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres_tls::MakeRustlsConnect;

pub struct Database {
    pool: Pool,
}

impl Database {
    pub async fn new(url: &str, file: &str) -> Result<Database, Error> {
        let _ = rustls::crypto::CryptoProvider::install_default(rustls_rustcrypto::provider());
        let ca_file = File::open(file).unwrap();
        let mut reader = std::io::BufReader::new(ca_file);
        let mut root_store = rustls::RootCertStore::empty();
        let certs = rustls_pemfile::certs(&mut reader);
        for cert in certs {
            root_store
                .add(
                    cert.map_err(|x| {
                        eprintln!("{}", x);
                        x
                    })
                    .unwrap(),
                )
                .unwrap();
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let tls = MakeRustlsConnect::new(config);
        let confiz = tokio_postgres::Config::from_str(url)?;
        let mgr_config = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        let mgr = Manager::from_config(confiz, tls, mgr_config);
        let pool = Pool::builder(mgr).max_size(16).build().unwrap();
        Ok(Database { pool })
    }

    pub async fn get(&self) -> Result<deadpool_postgres::Object, ProtocolError> {
        self.pool.get().await.map_err(|e| {
            eprintln!("Error getting connection: {}", e);
            ProtocolError::StorageError
        })
    }
}

pub struct PassesPostgres {
    pub database: Database,
}

pub struct UsersPostgres {
    pub database: Database,
}

impl UsersPostgres {
    pub async fn new(url: &str, file: &str) -> Result<UsersPostgres, Error> {
        Ok(UsersPostgres {
            database: Database::new(url, file).await?,
        })
    }
}

impl UsersT for UsersPostgres {
    async fn add_user(&mut self, id: uuid::Uuid, user: crate::protocol::CK) -> ResultP<()> {
        let database = self.database.get().await?;
        let stmt = database.prepare_cached("INSERT INTO users (id, email, ky_public_key, di_public_key) VALUES ($1, $2, $3, $4)").await.map_err(|e| {
            eprintln!("Error adding user: {}", e);
            ProtocolError::StorageError
        })?;
        database.query(&stmt, &[&id, &user.email, &user.ky_p, &user.di_p]).await.map_err(|e| {
            eprintln!("Error adding user: {}", e);
            ProtocolError::StorageError
        })?;
        Ok(())
    }

    async fn get_user(&self, id: uuid::Uuid) -> ResultP<crate::protocol::CK> {
        let database = self.database.get().await?;
        let stmt = database.prepare_cached("SELECT email, ky_public_key, di_public_key FROM users WHERE id = $1").await.map_err(|e| {
            eprintln!("Error getting user: {}", e);
            ProtocolError::StorageError
        })?;
        let row = database
            .query_one(
                &stmt,
                &[&id],
            )
            .await
            .map_err(|e| {
                eprintln!("Error getting user: {}", e);
                ProtocolError::StorageError
            })?;
        let a = crate::protocol::CK {
            email: row.get(0),
            ky_p: row.get(1),
            di_p: row.get(2),
            id: None,
        };
        Ok(a)
    }

    async fn remove_user(&mut self, id: uuid::Uuid) -> ResultP<()> {
        let database = self.database.get().await?;
        database
            .query("DELETE FROM users WHERE id = $1", &[&id])
            .await
            .map_err(|e| {
                eprintln!("Error removing user: {}", e);
                ProtocolError::StorageError
            })?;
        Ok(())
    }
}

impl PassesPostgres {
    pub async fn new(url: &str, file: &str) -> Result<PassesPostgres, Error> {
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
        let stmt = database.prepare_cached("INSERT INTO passes (id, user_id, data) VALUES ($2, $1, $3)").await.map_err(|e| {
            eprintln!("Error adding pass: {}", e);
            ProtocolError::StorageError
        })?;
        database
            .query(
                &stmt,
                &[&id, &pass_id, &pass],
            )
            .await
            .map_err(|e| {
                eprintln!("Error adding pass: {}", e);
                ProtocolError::StorageError
            })?;
        Ok(())
    }

    async fn get_pass(&self, id: uuid::Uuid, pass_id: uuid::Uuid) -> ResultP<Vec<u8>> {
        let database = self.database.get().await?;
        let stmt = database.prepare_cached("SELECT data FROM passes WHERE id = $2 AND user_id = $1").await.map_err(|e| {
            eprintln!("Error getting pass: {}", e);
            ProtocolError::StorageError
        })?;
        let row = database
            .query_one(
                &stmt,
                &[&id, &pass_id],
            )
            .await
            .map_err(|e| {
                eprintln!("Error getting pass: {}", e);
                ProtocolError::StorageError
            })?;
        println!("{:?}", row);
        Ok(row.get(0))
    }

    async fn remove_pass(&mut self, id: uuid::Uuid, pass_id: uuid::Uuid) -> ResultP<()> {
        let database = self.database.get().await?;
        database
            .query(
                "DELETE FROM passes WHERE id = $2 AND user_id = $1",
                &[&id, &pass_id],
            )
            .await
            .map_err(|e| {
                eprintln!("Error removing pass: {}", e);
                ProtocolError::StorageError
            })?;
        Ok(())
    }

    async fn update_pass(
        &mut self,
        id: uuid::Uuid,
        pass_id: uuid::Uuid,
        pass: Vec<u8>,
    ) -> ResultP<()> {
        let database = self.database.get().await?;
        database
            .query(
                "UPDATE passes SET data = $3 WHERE id = $2 AND user_id = $1",
                &[&id, &pass_id, &pass],
            )
            .await
            .map_err(|e| {
                eprintln!("Error updating pass: {}", e);
                ProtocolError::StorageError
            })?;
        Ok(())
    }

    async fn get_all_pass(&self, id: uuid::Uuid) -> ResultP<Vec<(Vec<u8>, uuid::Uuid)>> {
        let database = self.database.get().await?;
        let stmt = database.prepare_cached("SELECT data, id FROM passes WHERE user_id = $1").await.map_err(|e| {
            eprintln!("Error getting all pass: {}", e);
            ProtocolError::StorageError
        })?;
        let rows = database
            .query(&stmt, &[&id])
            .await
            .map_err(|e| {
                eprintln!("Error getting all pass: {}", e);
                ProtocolError::StorageError
            })?;
        Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
    }
}
