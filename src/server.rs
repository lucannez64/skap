use warp::Filter;
use crate::protocol::Challenges;
use crate::protocol::Passes;
use crate::protocol::Secrets;
use crate::protocol::EP;
use crate::protocol::Server as Server2;
use serde::Serialize;
use crate::protocol::CK;
use std::sync::{Arc, Mutex};

#[derive(Serialize)]
struct ErrorMessage {
    code: u16,
    message: String,
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let server2 = Arc::new(Mutex::new(
        Server2::<Secrets, Passes, Challenges>::new().unwrap()
    ));

    let server_filter = warp::any().map(move || Arc::clone(&server2));

    let create_user = warp::post()
        .and(warp::path("create_user"))
        .and(warp::body::bytes())
        .and(server_filter.clone())
        .map(|body: bytes::Bytes, server2: Arc<Mutex<Server2<Secrets, Passes, Challenges>>>| {
            match bincode::deserialize::<CK>(&body) {
                Ok(ck) => {
                    let mut server = server2.lock().unwrap();
                    match server.add_user(ck.clone()) {
                        Ok(uuid) => {
                            println!("User created with uuid {} && name {}", uuid, ck.email); 
                            warp::reply::Response::new(bincode::serialize(&uuid).unwrap().into())},
                        Err(_) => warp::reply::Response::new(bincode::serialize(&"INTERNAL_SERVER_ERROR").unwrap().into())
                    }
                },
                Err(_) => warp::reply::Response::new(bincode::serialize(&"DESERIALIZATION_ERROR").unwrap().into())
            }
        });
    let challenge = warp::get()
        .and(warp::path("challenge"))
        .and(warp::path::param::<String>())
        .and(server_filter.clone())
        .map(|uui: String, server2: Arc<Mutex<Server2<Secrets, Passes, Challenges>>>| {
            let mut server = server2.lock().unwrap();
            let id = uuid::Uuid::parse_str(&uui).unwrap();
            match server.challenge(id) {
                Ok(challenge) => {
                    warp::reply::Response::new(bincode::serialize(&challenge).unwrap().into())
                },
                Err(_) => warp::reply::Response::new(bincode::serialize(&"INTERNAL_SERVER_ERROR").unwrap().into())
            }
        });

    let verify = warp::post()
        .and(warp::path("verify"))
        .and(warp::path::param::<String>())
        .and(warp::body::bytes())
        .and(server_filter.clone())
        .map(|uui: String, body: bytes::Bytes, server2: Arc<Mutex<Server2<Secrets, Passes, Challenges>>>| {
            let server = server2.lock().unwrap();
            let id = uuid::Uuid::parse_str(&uui).unwrap();
            match server.verify(id, &body) {
                Ok(r) => {
                    warp::reply::Response::new(bincode::serialize(&r).unwrap().into())
                },
                Err(_) => warp::reply::Response::new(bincode::serialize(&"INTERNAL_SERVER_ERROR").unwrap().into())
            }
        });

    let sync = warp::get()
        .and(warp::path("sync"))
        .and(warp::path::param::<String>())
        .and(server_filter.clone())
        .map(|uui: String, server2: Arc<Mutex<Server2<Secrets, Passes, Challenges>>>| {
            let mut server = server2.lock().unwrap();
            let id = uuid::Uuid::parse_str(&uui).unwrap();
            match server.sync(id) {
                Ok(ciphertextsync) => {
                    warp::reply::Response::new(ciphertextsync.to_vec().into())
                },
                Err(_) => warp::reply::Response::new(bincode::serialize(&"INTERNAL_SERVER_ERROR").unwrap().into())
            }
        });

    let create_pass = warp::post()
        .and(warp::path("create_pass"))
        .and(warp::path::param::<String>())
        .and(warp::body::bytes())
        .and(server_filter.clone())
        .map(|uui: String,pass: bytes::Bytes,server2: Arc<Mutex<Server2<Secrets, Passes, Challenges>>>| {
            let mut server = server2.lock().unwrap();
            let id = uuid::Uuid::parse_str(&uui).unwrap();
            let ep =bincode::deserialize::<EP>(&pass).unwrap();
            match server.create_pass(id, ep) {
                Ok(id2) => {
                    warp::reply::Response::new(bincode::serialize(&id2).unwrap().into())
                },
                Err(_) => warp::reply::Response::new(bincode::serialize(&"INTERNAL_SERVER_ERROR").unwrap().into())
            }
        });

    let send = warp::get()
        .and(warp::path("send"))
        .and(warp::path::param::<String>())
        .and(warp::path::param::<String>())
        .and(server_filter.clone())
        .map(|uui: String, uui2: String, server2: Arc<Mutex<Server2<Secrets, Passes, Challenges>>>| {
            let mut server = server2.lock().unwrap();
            let id = uuid::Uuid::parse_str(&uui).unwrap();
            let id2 = uuid::Uuid::parse_str(&uui2).unwrap();
            match server.send(id, id2) {
                Ok(r) => {
                    warp::reply::Response::new(bincode::serialize(&r).unwrap().into())
                },
                Err(_) => warp::reply::Response::new(bincode::serialize(&"INTERNAL_SERVER_ERROR").unwrap().into())
            }
        });

    let send_all = warp::get()
        .and(warp::path("send_all"))
        .and(warp::path::param::<String>())
        .and(server_filter.clone())
        .map(|uui: String, server2: Arc<Mutex<Server2<Secrets, Passes, Challenges>>>| {
            let mut server = server2.lock().unwrap();
            let id = uuid::Uuid::parse_str(&uui).unwrap();
            match server.send_all(id) {
                Ok(r) => {
                    warp::reply::Response::new(bincode::serialize(&r).unwrap().into())
                },
                Err(_) => warp::reply::Response::new(bincode::serialize(&"INTERNAL_SERVER_ERROR").unwrap().into())
            }
        });

    let routes = create_user.or(challenge).or(sync).or(create_pass).or(send).or(verify).or(send_all);
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
    Ok(())
}
