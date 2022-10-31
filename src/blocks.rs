use std::{path::Path, fs::File, io::Write};

use chrono::{Utc, TimeZone};
use ring::signature::EcdsaKeyPair;
use serde::{Serialize, Deserialize};

use crate::{wallet::{Transaction, hex_to_wallet, load_wallet, UnsignedTransaction, sign_transaction, keypair_to_wallet}, hash::hash_block};
use crate::hash::Hash;

pub const BLOCK_REWARD: u64 = 100;

const BLOCKCHAIN_PATH: &str = "blockchain.dat";

#[derive(Debug, Serialize, Deserialize, Default, Clone, Copy)]
pub struct Block {
    pub prev_hash: Hash,
    pub transactions: [Transaction; 16],
    pub nonce: [u32; 8],
    pub hash: Hash
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnhashedBlock {
    pub prev_hash: Hash,
    pub transactions: [Transaction; 16],
    pub nonce: [u32; 8],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockList {
    pub prev: Option<Box<BlockList>>,
    pub block: Block,
}

// TODO: Merkle tree
pub type Blockchain = Vec<Block>;

pub fn load_blockchain() -> Blockchain {
    if !Path::new(BLOCKCHAIN_PATH).exists() {
        return vec![make_genesis_block()];
    }

    let bytes = std::fs::read(Path::new(BLOCKCHAIN_PATH)).expect("Failed to read blockchain file which supposedly exists");
    let blockchain: Blockchain = bincode::deserialize(&bytes).expect("Failed to deserialize blockchain from file");

    blockchain
}

pub fn save_blockchain(blockchain: &Blockchain) {
    let mut file = File::create(BLOCKCHAIN_PATH).expect("Failed to create file handle");
    let bytes = bincode::serialize(blockchain).expect("Failed to serialize blockchain to bytes");

    file.write_all(&bytes).expect("Failed to write blockchain to file");
}

pub fn append_blocks(blockchain: &Blockchain, new_blocks: &Vec<Block>) -> Blockchain {
    let mut out = vec![Block::default(); blockchain.len() + new_blocks.len()];

    out[0..blockchain.len()].copy_from_slice(blockchain);
    out[blockchain.len()..].copy_from_slice(new_blocks);

    out
}

///
/// This code is temporary! We just need it to create a genesis block which can then be serialized and loaded directly from a file.
/// Of course we don't want wallets with weak passwords like "horse" and "password1" to have all of the currency, so the final genesis block
/// won't contain these wallets.
/// 

pub const MINT_WALLET: &str = "04d37349ef94359620359581d2e33fa64e9e12015a2c48b6524b53c43e2539dd9262cfd7a68ab1cade279bae68c443063e91877a939af36625b51c15924849a74b";
const PASSWORD1_WALLET: &str = "04186ea3424efe14a5b06599335013b562743f26541d0b45d3ff63b83caaa53873a79cad91046d6dbbb04d7498de0ce7e0b480ba290681a3dbe945618b4ee6357c";
const HORSE_WALLET: &str = "04644746c2aa410c0acfcf737a3ff6f56b657ab350fbd8f2e8d6863a1175b16c26e041dda0971d686b807bb00a8681f29eba9f4b6c8298b209665a9270f65d628d";

pub fn make_genesis_block() -> Block {
    let mint_private = load_wallet("mint", "./wallets/mint/wallet-private.dat").unwrap();
    let password1_receiver = hex_to_wallet(PASSWORD1_WALLET).expect("Failed to convert password1 wallet");
    let horse_receiver = hex_to_wallet(HORSE_WALLET).expect("Failed to convert horse wallet");

    let mut transactions = [Transaction::default(); 16];
    
    for i in 0..8 {
        let transaction1 = make_genesis_transaction(&mint_private, password1_receiver, i);
        let transaction2 = make_genesis_transaction(&mint_private, horse_receiver, i + 8);

        transactions[i] = transaction1;
        transactions[i + 8] = transaction2;
    }

    let unhashed = UnhashedBlock{prev_hash: [0 as u32; 8], transactions, nonce: [0 as u32; 8]};
    let hash = hash_block(&unhashed).expect("Failed to hash genesis block");

    // TODO: Finish this, load wallets from files
    Block { prev_hash: [0 as u32; 8], transactions: unhashed.transactions, nonce: [0 as u32; 8], hash }
}

pub fn make_genesis_transaction(sender_keypair: &EcdsaKeyPair, receiver: [u8; 65], i: usize) -> Transaction {
    let sender = keypair_to_wallet(&sender_keypair);
    let timestamp = Utc.ymd(2022, 10, 28).and_hms(12, 0, 0);
    let mut nonce = [0 as u8; 16];
    nonce[15] = i as u8;
    let amount: u64 = 100_000;
    let unsigned_transaction = UnsignedTransaction{sender, receiver, timestamp, nonce, amount};

    sign_transaction(unsigned_transaction, sender_keypair)
}
