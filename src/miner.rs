use std::{sync::Mutex, thread};

use chrono::Utc;

use crate::{blocks::{UnhashedBlock, Block, make_block_reward}, hash::{Hash, hash_block}, State, wallet::Transaction};

pub struct MineResult {
    pub block: Block,
    pub tries: u32
}

/// Check if we have enough transactions to start mining a block. Assumes
/// the transactions are sorted by their timestamps.
pub fn check_and_start_miner(state_mut: &Mutex<State>) {
    let guard = state_mut.lock().unwrap();
    let state = &*guard;

    if state.pending_transactions.len() >= 15 {
        drop(guard);
        start_miner(state_mut);
    }
}

fn start_miner(state_mut: &Mutex<State>) {
    let guard = state_mut.lock().unwrap();
    let state = &*guard;

    if !state.is_miner {
        return;
    }

    let mut transactions: [Transaction; 16] = [Transaction::default(); 16];
    transactions[0..15].copy_from_slice(&state.pending_transactions[0..15]);
    transactions[15] = make_block_reward(state.wallet, &state.client_keypair);
    let prev_hash = state.blockchain.last().unwrap().hash;

    let unhashed_block = UnhashedBlock {
        prev_hash,
        transactions,
        timestamp: Utc::now(),
        nonce: [0 as u8; 32]
    };

    println!("Mining new block...");

    thread::spawn(move || {
        // TODO: Difficulty
        // This function call blocks until the block is mined. Of course the block may never be mined,
        // so this call may never return
        let mine_result = mine_block(prev_hash, unhashed_block, 0);
        println!("Mined the block in {} tries", mine_result.tries);
    });
}

/// TODO: Integrate GPU kernel and have miner choose most efficient device,
/// write difficulty algorithm
pub fn mine_block(prev_hash: Hash, raw_block: UnhashedBlock, _difficulty: u32) -> MineResult {
    let winning_hash = make_winning_hash();
    let mut nonce: [u8; 32] = [0 as u8; 32];
    let mut unhashed_block = raw_block;
    let mut hash: Hash = [0xFFFF_FFFF as u32; 8];
    let mut tries: u32 = 0;

    while !less_than(&hash, &winning_hash) {
        nonce = rand::random();
        unhashed_block.nonce = nonce;
        tries += 1;
        hash = hash_block(&unhashed_block).unwrap();
    }

    let block = Block {
        prev_hash,
        transactions: unhashed_block.transactions,
        timestamp: Utc::now(),
        nonce,
        hash,
    };
    
    MineResult { block, tries }
}   

/// Compare two things represented as arrays of orderable "digits".
/// Each element of the arrays can be treated as a separate digit.
/// The most significant digits are first. We also require that
/// a and b have the same size because this function needs to run
/// as quickly as possible.
fn less_than<T: PartialEq + PartialOrd, const N: usize>(a: &[T; N], b: &[T; N]) -> bool {
    for i in 0..N {
        if a[i] == b[i] {
            continue;
        }

        return a[i] < b[i]
    }

    false
}

fn make_winning_hash() -> Hash {
    let mut out: Hash = [0xFFFF_FFFF as u32; 8];
    out[0] = 0x00FF_FFFF;

    out
}
