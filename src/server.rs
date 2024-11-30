use warp::Filter;
use crate::protocol::Challenges;
use crate::protocol::Passes;
use crate::postgres::PassesPostgres;
use crate::protocol::Secrets;
use crate::protocol::EP;
use crate::protocol::Server as Server2;
use serde::Serialize;
use crate::protocol::CK;
use std::convert::Infallible;
use std::sync::{Arc};
use tokio::sync::Mutex;


#[derive(Serialize)]
struct ErrorMessage {
    code: u16,
    message: String,
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let server2 = Arc::new(Mutex::new(
        Server2::<Secrets, PassesPostgres, Challenges>::new().await.unwrap()
    ));

    let server_filter = warp::any().map(move || Arc::clone(&server2));


    let send_all = warp::get()
        .and(warp::path("send_all"))
        .and(warp::path::param::<String>())
        .and(server_filter.clone())
        .and_then(|uui: String, server2: Arc<Mutex<Server2<Secrets, PassesPostgres, Challenges>>>| {
            async move {send_all_map(uui,&server2).await}
        });

    
    let create_user = warp::post()
        .and(warp::path("create_user"))
        .and(warp::body::bytes())
        .and(server_filter.clone())
        .and_then(|body: bytes::Bytes, server2: Arc<Mutex<Server2<Secrets, PassesPostgres, Challenges>>>| {
            async move {create_user_map(body, &server2).await}
        });

    let sync = warp::get()
        .and(warp::path("sync"))
        .and(warp::path::param::<String>())
        .and(server_filter.clone())
        .and_then(|uui: String, server2: Arc<Mutex<Server2<Secrets, PassesPostgres, Challenges>>>| {
            async move {sync_map(uui, &server2).await} 
        });

    let create_pass = warp::post()
        .and(warp::path("create_pass"))
        .and(warp::path::param::<String>())
        .and(warp::body::bytes())
        .and(server_filter.clone())
        .and_then(|uui: String,pass: bytes::Bytes,server2: Arc<Mutex<Server2<Secrets, PassesPostgres, Challenges>>>| {
            async move {create_pass_map(uui,pass,&server2).await}
        });

    let challenge = warp::get()
        .and(warp::path("challenge"))
        .and(warp::path::param::<String>())
        .and(server_filter.clone())
        .and_then(|uui: String, server2: Arc<Mutex<Server2<Secrets, PassesPostgres, Challenges>>>| {
            async move {challenge_map(uui, &server2).await}
        });

    let verify = warp::post()
        .and(warp::path("verify"))
        .and(warp::path::param::<String>())
        .and(warp::body::bytes())
        .and(server_filter.clone())
        .and_then(|uui: String, body: bytes::Bytes, server2: Arc<Mutex<Server2<Secrets, PassesPostgres, Challenges>>>| {
            async move {verify_map(uui, body, &server2).await}
        });

    let update_pass = warp::post()
        .and(warp::path("update_pass"))
        .and(warp::path::param::<String>())
        .and(warp::path::param::<String>())
        .and(warp::body::bytes())
        .and(server_filter.clone())
        .and_then(|uui: String,uui2: String,pass: bytes::Bytes,server2: Arc<Mutex<Server2<Secrets, PassesPostgres, Challenges>>>| {
            async move {update_pass_map(uui,uui2,pass,&server2).await}
        });

    let delete = warp::get()
        .and(warp::path("delete_pass"))
        .and(warp::path::param::<String>())
        .and(warp::path::param::<String>())
        .and(server_filter.clone())
        .and_then(|uui: String, uui2: String,server2: Arc<Mutex<Server2<Secrets, PassesPostgres, Challenges>>>| {
            async move {delete_map(uui,uui2, &server2).await}
        });


    let send = warp::get()
        .and(warp::path("send"))
        .and(warp::path::param::<String>())
        .and(warp::path::param::<String>())
        .and(server_filter.clone())
        .and_then(|uui: String, uui2: String, server2: Arc<Mutex<Server2<Secrets, PassesPostgres, Challenges>>>| {
            async move {send_map(uui, uui2, &server2).await}
        });

    let routes = create_user.or(challenge).or(sync).or(create_pass).or(send).or(verify).or(send_all).or(update_pass).or(delete);
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
    Ok(())
}

async fn delete_map(uui: String, uui2: String, server2: & Arc<Mutex<Server2<Secrets, PassesPostgres, Challenges>>>) -> Result<impl warp::Reply, Infallible> {
    let mut server = server2.lock().await;
    let id = uuid::Uuid::parse_str(&uui).unwrap();
    let uui2 = uuid::Uuid::parse_str(&uui2).unwrap();
    match server.delete_pass(id, uui2).await {
        Ok(()) => {
            Ok(warp::reply::Response::new(bincode::serialize(&"OK").unwrap().into()))
        },
        Err(_) => Ok(warp::reply::Response::new(bincode::serialize(&"INTERNAL_SERVER_ERROR").unwrap().into()))
    }
}

async fn challenge_map(uui: String, server2: & Arc<Mutex<Server2<Secrets, PassesPostgres, Challenges>>>) -> Result<impl warp::Reply, Infallible> {
    let mut server = server2.lock().await;
    let id = uuid::Uuid::parse_str(&uui).unwrap();
    match server.challenge(id).await {
        Ok(challenge) => {
            Ok(warp::reply::Response::new(bincode::serialize(&challenge).unwrap().into()))
        },
        Err(_) => Ok(warp::reply::Response::new(bincode::serialize(&"INTERNAL_SERVER_ERROR").unwrap().into()))
    }
}

async fn verify_map(uui: String, body: bytes::Bytes, server2: & Arc<Mutex<Server2<Secrets, PassesPostgres, Challenges>>>) -> Result<impl warp::Reply, Infallible> {
    let server = server2.lock().await;
    let id = uuid::Uuid::parse_str(&uui).unwrap();
    match server.verify(id, &body).await {
        Ok(r) => {
            Ok(warp::reply::Response::new(bincode::serialize(&r).unwrap().into()))
        },
        Err(_) => Ok(warp::reply::Response::new(bincode::serialize(&"INTERNAL_SERVER_ERROR").unwrap().into()))
    }
}

async fn update_pass_map(uui: String, uui2: String, pass: bytes::Bytes, server2: & Arc<Mutex<Server2<Secrets, PassesPostgres, Challenges>>>) -> Result<impl warp::Reply, Infallible> {
    let mut server = server2.lock().await;
    let id = uuid::Uuid::parse_str(&uui).unwrap();
    let id2 = uuid::Uuid::parse_str(&uui2).unwrap();
    let ep =bincode::deserialize::<EP>(&pass).unwrap();
    match server.update_pass(id, id2, ep).await {
    Ok(()) => {
        Ok(warp::reply::Response::new(bincode::serialize(&"OK").unwrap().into()))
    },
    Err(_) => Ok(warp::reply::Response::new(bincode::serialize(&"INTERNAL_SERVER_ERROR").unwrap().into()))
    }
}

async fn send_map(uui: String, uui2: String, server2: & Arc<Mutex<Server2<Secrets, PassesPostgres, Challenges>>>) -> Result<impl warp::Reply, Infallible> {
    let mut server = server2.lock().await;
    let id = uuid::Uuid::parse_str(&uui).unwrap();
    let id2 = uuid::Uuid::parse_str(&uui2).unwrap();
    match server.send(id, id2).await {
    Ok(r) => {
        Ok(warp::reply::Response::new(bincode::serialize(&r).unwrap().into()))
    },
    Err(_) => Ok(warp::reply::Response::new(bincode::serialize(&"INTERNAL_SERVER_ERROR").unwrap().into()))
    }
}

async fn create_pass_map(uui: String,pass: bytes::Bytes, server2: & Arc<Mutex<Server2<Secrets, PassesPostgres, Challenges>>>) -> Result<impl warp::Reply, Infallible> {
    let mut server = server2.lock().await;
    let id = uuid::Uuid::parse_str(&uui).unwrap();
    let ep =bincode::deserialize::<EP>(&pass).unwrap();
    match server.create_pass(id, ep).await {
        Ok(id2) => {
            Ok(warp::reply::Response::new(bincode::serialize(&id2).unwrap().into()))
        },
        Err(_) => Ok(warp::reply::Response::new(bincode::serialize(&"INTERNAL_SERVER_ERROR").unwrap().into()))
    }

}

async fn sync_map(uui: String, server2: & Arc<Mutex<Server2<Secrets, PassesPostgres, Challenges>>>) -> Result<impl warp::Reply, Infallible> {
    let mut server = server2.lock().await;
    let id = uuid::Uuid::parse_str(&uui).unwrap();
    match server.sync(id).await {
        Ok(ciphertextsync) => {
            Ok(warp::reply::Response::new(ciphertextsync.to_vec().into()))
        },
        Err(_) => Ok(warp::reply::Response::new(bincode::serialize(&"INTERNAL_SERVER_ERROR").unwrap().into()))
    }

}

async fn create_user_map(body: bytes::Bytes, server2: & Arc<Mutex<Server2<Secrets, PassesPostgres, Challenges>>>) -> Result<impl warp::Reply, Infallible> {
    match bincode::deserialize::<CK>(&body) {
        Ok(ck) => {
            let mut server = server2.lock().await;
            match server.add_user(ck.clone()).await {
                Ok(uuid) => {
                    println!("User created with uuid {} && name {}", uuid, ck.email); 
                    Ok(warp::reply::Response::new(bincode::serialize(&uuid).unwrap().into()))
                },
                Err(_) => Ok(warp::reply::Response::new(bincode::serialize(&"INTERNAL_SERVER_ERROR").unwrap().into()))
            }
        },
        Err(_) => Ok(warp::reply::Response::new(bincode::serialize(&"DESERIALIZATION_ERROR").unwrap().into()))
    }
}

async fn send_all_map(uui: String, server2: & Arc<Mutex<Server2<Secrets, PassesPostgres, Challenges>>>) -> Result<impl warp::Reply, Infallible> {
    let id = uuid::Uuid::parse_str(&uui).unwrap();
    let mut server = server2.lock().await;
    match server.send_all(id).await {
        Ok(r) => {
            Ok(warp::reply::Response::new(bincode::serialize(&r).unwrap().into()))
        },
        Err(_) => Ok(warp::reply::Response::new(bincode::serialize(&"INTERNAL_SERVER_ERROR").unwrap().into()))
    }
}
