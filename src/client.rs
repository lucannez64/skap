use crate::protocol::*;
use uuid::Uuid;
use warp::filters::body::bytes;

const BASE_URL: &str = "http://127.0.0.1:3030/";

pub async fn new(client2: &reqwest::Client , email: &str) -> Result<(Client, Uuid), reqwest::Error> {
    let client = crate::protocol::Client::new().unwrap();
    let ck = CK::new(client.ky_p, client.di_p.clone(), "hery.dannez@gmail.com".to_string());
    let res = client2.post(BASE_URL.to_string()+"create_user/")
        .body(bincode::serialize(&ck).unwrap())
        .send()
        .await?;
    Ok((client, bincode::deserialize::<Uuid>(&res.bytes().await?).unwrap()))
}

pub async fn auth(client2: &reqwest::Client, uuid: Uuid, client: &mut Client) -> Result<(), reqwest::Error> {
    let res = client2.get(BASE_URL.to_string()+"challenge/"+uuid.to_string().as_str()+"/")
        .send()
        .await?;
    let chall = res.bytes().await?;
    let sign = client.sign(&chall);
    let res = client2.post(BASE_URL.to_string()+"verify/"+uuid.to_string().as_str()+"/")
        .body(bincode::serialize(sign.as_slice()).unwrap())
        .send()
        .await?;
    let sync = client2.get(BASE_URL.to_string()+"sync/"+uuid.to_string().as_str()+"/")
        .send()
        .await?;
    let d = sync.bytes().await?;
    client.sync(&d).unwrap();
    Ok(())
}

pub async fn create_pass(client2: &reqwest::Client, uuid: Uuid, client: &mut Client, pass: Password) -> Result<(Uuid), reqwest::Error> {
    let encrypted = client.encrypt(pass.clone()).unwrap();
    let eq = client.send(encrypted).unwrap();
    let res = client2.post(BASE_URL.to_string()+"create_pass/"+uuid.to_string().as_str()+"/")
        .body(bincode::serialize(&eq).unwrap())
        .send()
        .await?;
    Ok(bincode::deserialize::<Uuid>(&res.bytes().await?).unwrap())
}

pub async fn get_all(client2: &reqwest::Client, uuid: Uuid, client: &mut Client) -> Result<(Vec<Password>), reqwest::Error> {
    let res = client2.get(BASE_URL.to_string()+"send_all/"+uuid.to_string().as_str()+"/")
        .send()
        .await?;
    let d = res.bytes().await?;
    let mut passwords: Vec<Password> = Vec::new();
    let da = bincode::deserialize::<Vec<EP>>(&d).unwrap();
    for g in da.iter() {
        let p = client.receive(g.clone()).unwrap();
        passwords.push(p);
    }
    Ok(passwords)
}