use protocol::{Challenges, Passes, Password, Secrets, CK};
use server::run;

mod protocol;
mod server;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut server = protocol::Server::<Secrets, Passes, Challenges>::new()?;
    let mut client = protocol::Client::new()?;
    let ck = CK::new(client.ky_p, client.di_p.clone());
    let z = bincode::serialize(&ck).map_err(|_| protocol::ProtocolError::DataError)?;
    println!("z : {:?}", z);
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
    let signature = client.sign(challenge.clone());
    server.verify(uuid, signature)?;
    let ciphertextsync = server.sync(uuid)?;
    client.sync(ciphertextsync)?;
    let ep = client.send(encryptedbyclient)?;
    let id2 = server.create_pass(uuid, ep)?;
    let r = server.send(uuid, id2)?;
    let password = client.receive(r)?;
    println!("{:?}", password);
    run().await?;
    Ok(())
}
