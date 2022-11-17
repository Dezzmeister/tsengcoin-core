use std::{error::Error, num::{NonZeroU32}, fs::File, io::Write, path::Path, cmp::Ordering};
use chrono::{Utc, DateTime};
use ring::{pbkdf2, digest, aead::{SealingKey, AES_256_GCM, UnboundKey, BoundKey, Nonce, NonceSequence, Aad, OpeningKey, NONCE_LEN}, error::Unspecified};
use serde::{Serialize, Deserialize};
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use serde_big_array::BigArray;

use crate::blocks::{Blockchain, Block};

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
static PBKDF2_ROUNDS: u32 = 100_000;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;

/// We use the same nonce to generate the AES key to encrypt the private key file
/// because the key needs to be a deterministic function of the password
const AES_NONCE: [u8; NONCE_LEN] = [0x64; NONCE_LEN];

pub const PRIVATE_KEY_PATH: &str = "wallet-private.dat";
pub const PUBLIC_KEY_PATH: &str = "wallet-public.dat";

pub type Key = [u8; CREDENTIAL_LEN];

// An ECDSA public key, 65 bytes
pub type Wallet = [u8; 65];

const MAX_SIGNATURE_LEN: usize = 105;

#[derive(Debug, Serialize, Deserialize, Copy, Clone, PartialEq, Eq)]
pub struct Signature {
    #[serde(with = "BigArray")]
    pub value: [u8; MAX_SIGNATURE_LEN],
    pub len: usize,
}

#[derive(Debug, Serialize, Deserialize, Copy, Clone, PartialEq, Eq)]
pub struct Transaction {
    #[serde(with = "BigArray")]
    pub sender: Wallet,
    #[serde(with = "BigArray")]
    pub receiver: Wallet,

    // TODO: Date-time verification
    pub timestamp: DateTime<Utc>,
    /// The nonce prevents attacks in which a malicious party copies an
    /// existing transaction and broadcasts it. No two transactions can have
    /// every field equal, so the nonce adds some randomness to prevent this.
    pub nonce: [u8; 16],
    pub amount: u64,
    pub signature: Signature,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnsignedTransaction {
    #[serde(with = "BigArray")]
    pub sender: Wallet,
    #[serde(with = "BigArray")]
    pub receiver: Wallet,
    pub timestamp: DateTime<Utc>,
    pub nonce: [u8; 16],
    pub amount: u64,
}

impl Default for Transaction {
    fn default() -> Self {
        let mut out: Self = unsafe { std::mem::zeroed() };
        out.timestamp = Utc::now();

        out
    }
}

impl UnsignedTransaction {
    pub fn new(sender: Wallet, receiver: Wallet, amount: u64) -> Self {
        Self { sender, receiver, timestamp: Utc::now(), nonce: rand::random(), amount }
    }
}

struct NonceGen {
}

impl NonceSequence for NonceGen {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Ok(Nonce::assume_unique_for_key(AES_NONCE))
    }
}

pub fn balance_for_block(block: &Block, wallet: &Wallet) -> i128 {
    let mut out: i128 = 0;

    for transaction in block.transactions.iter() {
        if &transaction.sender == wallet {
            out -= transaction.amount as i128;
        } 
        
        if &transaction.receiver == wallet {
            out += transaction.amount as i128;
        }
    }

    out
}

pub fn verified_balance(blockchain: &Blockchain, wallet: &Wallet) -> i128 {
    let mut out: i128 = 0;

    for block in blockchain {
        out += balance_for_block(block, wallet);
    }

    out
}

pub fn pending_balance(blockchain: &Blockchain, pending: &Vec<Transaction>, wallet: &Wallet) -> i128 {
    let mut out: i128 = verified_balance(blockchain, wallet);

    for transaction in pending {
        if &transaction.sender == wallet {
            out -= transaction.amount as i128;
        }
        
        if &transaction.receiver == wallet {
            out += transaction.amount as i128;
        }
    }

    out
}

pub fn sign_transaction(transaction: UnsignedTransaction, sender: &EcdsaKeyPair) -> Transaction {
    let bytes = bincode::serialize(&transaction).expect("Failed to serialize transaction");
    let rng = ring::rand::SystemRandom::new();
    let sig = sender.sign(&rng, &bytes).expect("Failed to sign transaction");
    let sig_bytes = sig.as_ref();
    let mut sig_value = [0 as u8; MAX_SIGNATURE_LEN];
    let sig_len = sig_bytes.len();
    sig_value[0..sig_len].copy_from_slice(&sig_bytes);
    let signature = Signature{value: sig_value, len: sig_len};
    let UnsignedTransaction{sender, receiver, timestamp, nonce, amount} = transaction;

    Transaction { sender, receiver, timestamp, nonce, amount, signature }
}

fn salt_from_password(password: &str) -> [u8; 16] {
    let digest = ring::digest::digest(&digest::SHA256, password.as_bytes());
    let mut out = [0 as u8; 16];
    out.copy_from_slice(&digest.as_ref()[0..16]);

    out
}

/// The goal here is to create a public/private ECDSA keypair for signing and verifying transactions.
/// The private key should not be usable unless the correct password is provided, and it should be accessible
/// only to the user, so that even if an attacker knows the password, they can't get your private key unless
/// they have your device. This combination of logical and physical security is analogous to 2FA, where a password
/// is required in addition to a specific physical device.
/// 
/// The way we do this is as follows:
/// 1. Use a password-based key derivation function (PBKDF2) to generate a key from the wallet password.
///     PBKDF2 requires a salt, so we generate the salt deterministically from the password. This is a better
///     solution than a constant salt, but a random salt would be ideal. The only issue is where this salt
///     would be stored - it would need to be retrieved when the user tries to sign a transaction.
/// 2. Create a random ECDSA keypair (consisting of a public and private key). The private key is used by the wallet
///     owner to sign transactions, and the public key is used by other nodes to verify transactions.
/// 3. Use the PBKDF2 result to generate an AES_GCM key. This requires a nonce which again is ideally random,
///     but for our purposes a constant nonce is fine.
///     TODO: Generate nonce seed deterministically and try with pseudo-random nonces
/// 4. Use the AES_GCM key to encrypt the private key (from the ECDSA keypair).
/// 5. Save the encrypted ciphertext to a file.
/// 
/// Now if the wallet user has their private key file, they can get the private key back by:
/// 1. Using the same PBKDF2 and salt algorithm to get a key. This key will be the same as in Step 1 above.
/// 2. Using that result to generate an AES_GCM key with the same constant nonce. A different nonce would give
///     a different key, and this key needs to be the same as Step 3 above.
/// 3. Using the AES_GCM key to decrypt the ciphertext and get the private key out.
pub fn create_keypair(password: &str) -> Option<EcdsaKeyPair> {
    if Path::new(PRIVATE_KEY_PATH).exists() {
        println!("Private key already exists. If you really want to create a new wallet, move or delete {PRIVATE_KEY_PATH}");
        println!("Be warned though, this is irreversible! If you delete your key files, you won't be able to get them back.");
        return None;
    }

    println!("Generating keypair and wallet ID");

    let salt: [u8; 16] = salt_from_password(password);
    let rounds = NonZeroU32::new(PBKDF2_ROUNDS).unwrap();
    let mut key: Key = [0; CREDENTIAL_LEN];
    pbkdf2::derive(PBKDF2_ALG, rounds, &salt, password.as_bytes(), &mut key);

    let rng = ring::rand::SystemRandom::new();
    let alg = &ECDSA_P256_SHA256_ASN1_SIGNING;
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).expect("Failed to generate ECDSA pkcs8");
    let key_pair = EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref()).expect("Failed to create ECDSA key pair");

    let public_key = key_pair.public_key();
    let wallet = hex::encode(&public_key.as_ref());

    println!("Your wallet id is {}", wallet);

    let unbound_key = UnboundKey::new(&AES_256_GCM, &key).expect("Failed to create symmetric key");
    let mut sealing_key = SealingKey::new(unbound_key, NonceGen{});

    let mut data = pkcs8.as_ref().to_vec();
    sealing_key.seal_in_place_append_tag(Aad::empty(), &mut data).unwrap();

    let mut private_file = File::create(PRIVATE_KEY_PATH).expect("Failed to create private key file");
    private_file.write_all(&data).expect("Failed to write to private key file");

    let mut public_file = File::create(PUBLIC_KEY_PATH).expect("Failed to create public key file");
    public_file.write_all(wallet.as_bytes()).expect("Failed to write to public key file");

    println!("Saved private key to {PRIVATE_KEY_PATH} and public key to {PUBLIC_KEY_PATH}. Protect these files, especially the private key file!");

    Some(key_pair)
}

pub fn load_wallet(password: &str, private_key_path: &str) -> Option<EcdsaKeyPair> {
    if !Path::new(private_key_path).exists() {
        println!("You don't have a wallet. Create one with `tsengtoken-core.exe create-wallet <password>`");
        return None;
    }

    let salt: [u8; 16] = salt_from_password(password);
    let rounds = NonZeroU32::new(PBKDF2_ROUNDS).unwrap();
    let mut key: Key = [0; CREDENTIAL_LEN];
    pbkdf2::derive(PBKDF2_ALG, rounds, &salt, password.as_bytes(), &mut key);

    let mut private_key_ciphertext = std::fs::read(Path::new(private_key_path)).expect("Failed to read private key file");

    let unbound_key = UnboundKey::new(&AES_256_GCM, &key).expect("Failed to create symmetric key");
    let mut opening_key = OpeningKey::new(unbound_key, NonceGen{});

    let private_key_decrypted = opening_key.open_in_place(Aad::empty(), &mut private_key_ciphertext).expect("Failed to decrypt private key");

    let alg = &ECDSA_P256_SHA256_ASN1_SIGNING;

    Some(EcdsaKeyPair::from_pkcs8(alg, &private_key_decrypted).expect("Failed to create ECDSA keypair"))
}

pub fn hex_to_wallet(str: &str) -> Result<Wallet, Box<dyn Error>> {
    let bytes = hex::decode(str)?;
    let mut out = [0 as u8; 65];
    out.copy_from_slice(&bytes);

    Ok(out)
}

pub fn keypair_to_wallet(keypair: &EcdsaKeyPair) -> Wallet {
    let mut out = [0 as u8; 65];
    out.copy_from_slice(keypair.public_key().as_ref());

    out
}

pub fn transaction_time_comparator(a: &Transaction, b: &Transaction) -> Ordering {
    if a.timestamp > b.timestamp {
        Ordering::Greater
    } else if a.timestamp == b.timestamp {
        Ordering::Equal
    } else {
        Ordering::Less
    }
}
