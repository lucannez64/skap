use protocol::{Challenges, Passes, Password, Secrets, CK};
use server::run;
use std::io::Write;

mod client;
mod protocol;
mod server;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut server = protocol::Server::<Secrets, Passes, Challenges>::new()?;
    let mut client = protocol::Client::new()?;
    let ck = CK::new(client.ky_p, client.di_p.clone(), "hery.dannez@gmail.com".to_string());
    let z = bincode::serialize(&ck).map_err(|_| protocol::ProtocolError::DataError)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open("key")?;
    file.write_all(&z)?;
    let uuid = server.add_user(ck)?;
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
    let challenge = server.challenge(uuid)?;
    let signature = client.sign(&challenge);
    server.verify(uuid, &signature)?;
    let ciphertextsync = server.sync(uuid)?;
    client.sync(&ciphertextsync)?;
    let ep = client.send(encryptedbyclient)?;
    let id2 = server.create_pass(uuid, ep)?;
    let r = server.send(uuid, id2)?;
    let password = client.receive(r)?;
    println!("{:?}", password);
    use std::io::{stdin};
    println!("Please choose an option: ");
    let mut s=String::new();
    stdin().read_line(&mut s).expect("Did not enter a correct string");
    s = s.trim().to_string();
    if &s == "serv" {
        run().await?;
    } else if &s == "client" {
        let client2 = reqwest::Client::new();
        let email = "hery.dannez@gmail".to_string();
        let (mut client, uuid) = client::new(&client2, &email).await.unwrap();
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
    }
    Ok(())
}
