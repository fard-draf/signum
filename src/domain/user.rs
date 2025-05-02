#[derive(Debug)]
pub struct User {
    pub name: UserName,
    pub public_key: PublicKey,
}

#[derive(Debug)]
pub struct UserName {
    pub name: String,
}

#[derive(Debug)]
pub struct PublicKey {}
