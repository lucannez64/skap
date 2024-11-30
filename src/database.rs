use crate::protocol::*;
use surrealdb::Surreal;
use uuid::Uuid;
use std::sync::LazyLock;
use serde::{Serialize, Deserialize};
use surrealdb::engine::any::Any;

pub struct Database {
    pub db: LazyLock<Surreal<Any>>, 
}

impl Database {
    pub async fn new() -> Self {
        let db: LazyLock<Surreal<Any>> = LazyLock::new(Surreal::init);
        db.connect("ws://127.0.0.1:8000").await.unwrap();
        
        Database {
            db,
        }
    }

    pub fn get_db(&self) -> &LazyLock<Surreal<Any>> {
        &self.db
    }
}

pub struct PassesSureal {
    pub database: Database,
}

impl PassesSureal {
    pub async fn new() -> Self {
        PassesSureal {
            database: Database::new().await,
        }
    }

    pub fn from(database: Database) -> Self {
        PassesSureal {
            database
        }
    }
}

pub struct UsersSureal {
    pub database: Database,
}

impl UsersSureal {
    pub async fn new() -> Self {
        UsersSureal {
            database: Database::new().await,
        }
    }

    pub fn from(database: Database) -> Self {
        UsersSureal {
            database
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct DatabasePass {
    pub id: Uuid,
    pub user_id: Uuid,
    pub data: Vec<u8>,
}

impl PassesT for PassesSureal {
    async fn get_pass(&self, id: Uuid, pass_id: Uuid) -> ResultP<Vec<u8>> {
        let db = self.database.get_db();
       db.use_ns("namespace").use_db("database").await.unwrap();
        let mut result =db.query("SELECT * FROM passes WHERE user_id = $id AND id = $pass_id").bind(("pass_id", pass_id)).bind(("id", id)).await.unwrap();
        let pass: Vec<u8> = result.take(2).map_err(|_| ProtocolError::StorageError)?;
        return Ok(pass);
    }

    async fn add_pass(&mut self, id: Uuid, pass_id: Uuid, pass: Vec<u8>) -> ResultP<()> {
        let db = self.database.get_db();
        let pass = DatabasePass {
            id: pass_id,
            user_id: id,
            data: pass
        };
        db.use_ns("namespace").use_db("database").await.map_err(|_| ProtocolError::StorageError)?;
        println!("pass: {:?}", pass);
        let a: Option<DatabasePass> = db.insert(("passes", pass_id.to_string())).content(pass).await.map_err(|_| ProtocolError::StorageError)?.unwrap();

        return Ok(());
    }

    async fn update_pass(&mut self, id: Uuid, pass_id: Uuid, pass: Vec<u8>) -> ResultP<()> {
        let db = self.database.get_db();
        db.use_ns("namespace").use_db("database").await.unwrap();
        db.query("UPDATE passes SET data = $data WHERE id = $pass_id AND user_id = $id").bind(("pass_id", pass_id)).bind(("id", id)).bind(("data", pass)).await.unwrap();
        Ok(())
    }

    async fn remove_pass(&mut self, id: Uuid, pass_id: Uuid) -> ResultP<()> {
        let db = self.database.get_db();
        db.use_ns("namespace").use_db("database").await.map_err(|_| ProtocolError::StorageError)?;
        db.query("DELETE FROM passes WHERE id = $pass_id AND user_id = $id").bind(("id", id)).bind(("pass_id", pass_id)).await.map_err(|_| ProtocolError::StorageError)?;
        return Ok(());
    }
    async fn get_all_pass(&self, id: Uuid) -> ResultP<Vec<(Vec<u8>, Uuid)>> {
        let db = self.database.get_db();
        db.use_ns("namespace").use_db("database").await.unwrap();
        let mut result = db.query("SELECT data FROM passes WHERE user_id = $id").bind(("id", id)).await.unwrap();
        let passes : Vec<DatabasePass> = result.take(0).map_err(|_| ProtocolError::StorageError)?; 
        let pass : Vec<(Vec<u8>, Uuid)> = passes.iter().map(|p| (p.data.clone(), p.id)).collect();
        return Ok(pass);
    }    
}
