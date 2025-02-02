#[cfg(feature = "server")]
use server::run;
#[cfg(feature = "server")]
extern crate dotenv;
#[cfg(feature = "server")]
use dotenv::dotenv;


mod protocol;

#[cfg(feature = "server")]
mod postgres;
#[cfg(feature = "tui")]
mod client;

#[cfg(feature = "tui")]
mod tui;
#[cfg(feature = "server")]
mod server;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
/*     let mut server = protocol::Server::<Secrets, Passes, Challenges, Users>::new()?;
    println!("server started");
    let mut client = protocol::Client::new()?;
    let mut ck = CK::new(client.ky_p, client.di_p.clone(), "hery.dannez@gmail.com".to_string());
    let z = bincode::serialize(&ck).map_err(|_| protocol::ProtocolError::DataError)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open("key")?;
    file.write_all(&z)?;
    let uuid = server.add_user(&mut ck).await?;
    let encryptedbyclient = client.encrypt(Password {
        username: "username".to_string(),
        password: "password".to_string(),
        app_id: None,
        description: None,
        url: Some("google".to_string()),
        otp: None,
    } )?;
    println!("ciphertext : {:?}", encryptedbyclient.ciphertext);
    println!("nonce : {:?}", encryptedbyclient.nonce);
    let challenge = server.challenge(uuid).await?;
    let signature = client.sign(&challenge);
    server.verify(uuid, &signature).await?;
    let ciphertextsync = server.sync(uuid).await?;
    client.sync(&ciphertextsync)?;
    let ep = client.send(encryptedbyclient)?;
    let id2 = server.create_pass(uuid, ep).await?;
    let r = server.send(uuid, id2).await?;
    let password = client.receive(r)?;
    println!("{:?}", password);*/

    runer().await

/*         let client2 = reqwest::Client::new();
        let email = "hery.dannez@gmail".to_string();
        let (mut client, ck) = client::new(&client2, &email).await.unwrap();
        let uuid = ck.id.ok_or(protocol::ProtocolError::DataError)?;
        client::auth(&client2, uuid, &mut client).await.unwrap();
        for i in 0..10 {
            client::create_pass(&client2, uuid, &mut client, Password {
                username: i.to_string(),
                password: "password".to_string(),
                app_id: None,
                description: None,
                url: Some("google".to_string()),
                otp: None,
            }).await.unwrap();

        }
        
        let passwords = client::get_all(&client2, uuid, &mut client).await.unwrap();
        println!("{:?}", passwords);
        for i in 0..passwords.len() {
            client::delete_pass(&client2, uuid, passwords[i].1).await.unwrap();
        } */

}

#[cfg(feature = "server")]
async fn runer() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    run().await?;

    Ok(())
}

#[cfg(feature = "tui")]
async fn runer() -> Result<(), Box<dyn std::error::Error>> {
    tui::run_tui().await.unwrap();
    Ok(())
}

#[cfg(not(any(feature = "server", feature = "tui")))]
async fn runer() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}
