use warp::Filter;
use crate::protocol::Challenges;
use crate::protocol::Passes;
use crate::protocol::Secrets;
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

    let hello = warp::post()
        .and(warp::path("create_user"))
        .and(warp::body::bytes())
        .and(server_filter)
        .map(|body: bytes::Bytes, server2: Arc<Mutex<Server2<Secrets, Passes, Challenges>>>| {
            match bincode::deserialize(&body) {
                Ok(ck) => {
                    let mut server = server2.lock().unwrap();
                    match server.add_user(ck) {
                        Ok(uuid) => {
                            println!("User created with uuid {}", uuid); 
                            warp::reply::json(&uuid.to_string())},
                        Err(_) => warp::reply::json(&"INTERNAL_SERVER_ERROR".to_string())
                    }
                },
                Err(_) => warp::reply::json(&"DESERIALIZATION_ERROR".to_string())
            }
        });

    let routes = hello;
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
    Ok(())
}
