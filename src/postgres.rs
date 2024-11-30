use tokio_postgres::{NoTls, Error};

use crate::protocol::{PassesT, ProtocolError, ResultP};

pub struct Database {
    pool: tokio_postgres::Client,
}

impl Database {
    pub async fn new(url: &str) -> Result<Database, Error> {
        let (client, connection) = tokio_postgres::connect(url, NoTls).await?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {}", e);
            }
        });
        Ok(Database { pool: client })
    }

    pub async fn get(&self) -> &tokio_postgres::Client {
        &self.pool
    }
}

pub struct PassesPostgres {
    pub database: Database,
}

impl PassesPostgres {
    pub async fn new(url: &str) -> Result<PassesPostgres, Error> {
        Ok(PassesPostgres {
            database: Database::new(url).await?,
        })
    }
}

impl PassesT for PassesPostgres {
    async fn add_pass(&mut self, id: uuid::Uuid, pass_id: uuid::Uuid, pass: Vec<u8>) -> ResultP<()> {
        let database = self.database.get().await;
        database.query("INSERT INTO passes (id, user_id, data) VALUES ($2, $1, $3)", &[&id, &pass_id, &pass]).await.map_err(|e| {
            eprintln!("Error adding pass: {}", e);
            ProtocolError::StorageError
        })?;
        Ok(())
    }

    async fn get_pass(&self, id: uuid::Uuid, pass_id: uuid::Uuid) -> ResultP<Vec<u8>> {
        let database = self.database.get().await;
        let row = database.query_one("SELECT data FROM passes WHERE id = $2 AND user_id = $1", &[&id, &pass_id]).await.map_err(|e| {
            eprintln!("Error getting pass: {}", e);
            ProtocolError::StorageError
        })?;
        println!("{:?}", row);
        Ok(row.get(0))
    }

     async fn remove_pass(&mut self, id: uuid::Uuid, pass_id: uuid::Uuid) -> ResultP<()> {
        let database = self.database.get().await;
        database.query("DELETE FROM passes WHERE id = $2 AND user_id = $1", &[&id, &pass_id]).await.map_err(|e| {
            eprintln!("Error removing pass: {}", e);
            ProtocolError::StorageError
        })?;
        Ok(())
    }
    
    async fn update_pass(&mut self, id: uuid::Uuid, pass_id: uuid::Uuid, pass: Vec<u8>) -> ResultP<()> {
        let database = self.database.get().await;
        database.query("UPDATE passes SET data = $3 WHERE id = $2 AND user_id = $1", &[&id, &pass_id, &pass]).await.map_err(|e| {
            eprintln!("Error updating pass: {}", e);
            ProtocolError::StorageError
        })?;
        Ok(())
    }

    async fn get_all_pass(&self, id: uuid::Uuid) -> ResultP<Vec<(Vec<u8>, uuid::Uuid)>> {
        let database = self.database.get().await;
        let rows = database.query("SELECT data, id FROM passes WHERE user_id = $1", &[&id]).await.map_err(|e| {
            eprintln!("Error getting all pass: {}", e);
            ProtocolError::StorageError
        })?;
        Ok(rows.iter().map(|r| (r.get(0),r.get(1))).collect())
    }
}
