// Verification rules:
//     1. Every transaction must be cryptographically and logically valid. This means that 
//        each transaction must be signed by the sender, and the sender must not have a negative
//        balance after conducting the transaction. The only exception to this is the mint wallet;
//        the mint wallet is allowed and even expected to have negative balance. In the case of a
//        block reward transaction, the sender should be the mint wallet, and the transaction should
//        be signed by the receiver. This is the ONLY case when the receiver can sign a transaction.
//     2. Every block must be cryptographically and logically valid. The hash of a block must match
//        the hash reported by the block winner. The block must consist of 16 valid transactions, with the
//        first 15 coming from the beginning of the pending transaction queue. The last transaction
//        must be a block reward.

use std::{collections::HashMap};

use ring::signature;

use crate::{wallet::{Transaction, verified_balance, hex_to_wallet, pending_balance, UnsignedTransaction}, blocks::{Block, MINT_WALLET, Blockchain, UnhashedBlock, BLOCK_REWARD}, error::Result, hash::{hash_block, to_bytes}};
use crate::error::ErrorKind::{InvalidTransactionLogic, InvalidBlockLogic, InvalidTransactionSignature, InvalidBlockHash, InvalidBlockTransaction, DuplicateTransaction};

/// Assume all pending transactions and all blocks are valid, then check if the new transaction is valid.
/// Does NOT validate block reward transactions. Those should only be validated when a full block is
/// submitted; they should never be broadcast individually.
/// 
/// After a transaction is verified, it can be added to the pending transactions. This is why we can assume
/// that all pending transactions here are valid.
pub fn verify_new_transaction(blocks: &Blockchain, pending: &Vec<Transaction>, new_transaction: &Transaction) -> Result<()> {
    let pending_sender_balance = pending_balance(blocks, pending, &new_transaction.sender);
    let new_balance = pending_sender_balance - (new_transaction.amount as i128);

    if new_balance < 0 {
        return Err(Box::new(InvalidTransactionLogic(*new_transaction)));
    }

    if !is_signature_valid(new_transaction, false) {
        return Err(Box::new(InvalidTransactionSignature(new_transaction.signature)));
    }

    if is_duplicate(blocks, pending, new_transaction) {
        return Err(Box::new(DuplicateTransaction(*new_transaction)));
    }

    Ok(())
}

pub fn verify_new_block(blockchain: &Blockchain, pending_transactions: &mut Vec<Transaction>, new_block: &Block) -> Result<()> {
    // First, check the hash of the block
    verify_block_hash(blockchain, new_block)?;

    // Now verify the transactions
    let mut verified_transactions: Vec<Transaction> = vec![];
    let transactions = new_block.transactions;
    let mint_wallet = hex_to_wallet(MINT_WALLET).expect("Failed to convert mint wallet to bytes");

    for transaction in transactions {
        // Handle block reward transactions separately
        if transaction.sender == mint_wallet {
            if !is_signature_valid(&transaction, true) {
                return Err(Box::new(InvalidTransactionSignature(transaction.signature)));
            }

            if transaction.amount != BLOCK_REWARD {
                return Err(Box::new(InvalidTransactionLogic(transaction)));
            }

            if is_duplicate(blockchain, pending_transactions, &transaction) {
                return Err(Box::new(DuplicateTransaction(transaction)));
            }

            continue;
        }

        // Check if the transaction in the block was actually pending or made-up
        if !pending_transactions.contains(&transaction) {
            return Err(Box::new(InvalidBlockTransaction(transaction)));
        }

        // Cryptographic verification, logical verification (is the sender trying to send coins he doesn't have?)
        // and checking if duplicate
        verify_new_transaction(blockchain, &verified_transactions, &transaction)?;
        verified_transactions.push(transaction);
    }

    // Take the verified transactions out of the pending queue now that the block has been verified
    let mut new_pending: Vec<Transaction> = 
        pending_transactions
            .iter()
            .filter(|t| {!verified_transactions.contains(*t)})
            .map(|t| {t.to_owned()})
            .collect();

    pending_transactions.clear();
    pending_transactions.append(&mut new_pending);

    Ok(())
}

// TODO: Remove
pub fn verify_transactions(blocks: &Vec<Block>, transactions: &Vec<Transaction>) -> Result<()> {
    let mut balance_map = HashMap::new();
    let mint_wallet = hex_to_wallet(MINT_WALLET).expect("Failed to convert mint wallet to bytes");

    for transaction in transactions {
        let sender = transaction.sender;
        let curr_balance = balance_map.get(&sender).cloned().unwrap_or_else(|| {verified_balance(blocks, &sender)});
        let new_balance = curr_balance - (transaction.amount as i128);

        if new_balance < 0 && sender != mint_wallet {
            return Err(Box::new(InvalidTransactionLogic(*transaction)));
        }



        balance_map.insert(sender, new_balance);
    }

    Ok(())
}

fn verify_block_hash(blockchain: &Blockchain, new_block: &Block) -> Result<()> {
    let last_block = blockchain[blockchain.len() - 1];

    if last_block.hash != new_block.prev_hash {
        return Err(Box::new(InvalidBlockLogic(*new_block)));
    }

    let unhashed_block = UnhashedBlock{
        prev_hash: new_block.prev_hash,
        transactions: new_block.transactions,
        nonce: new_block.nonce,
    };

    let computed_hash = hash_block(&unhashed_block).expect("Failed to hash block");
    let expected_hash = new_block.hash;

    if computed_hash != new_block.hash {
        let expected = hex::encode(to_bytes(expected_hash));
        let computed = hex::encode(to_bytes(computed_hash));

        return Err(Box::new(InvalidBlockHash(expected, computed)));
    }

    Ok(())
}

/// TODO: Implement other validity checks, like checking if the sender has enough coins to make this
/// transaction.
fn is_signature_valid(transaction: &Transaction, allow_block_reward: bool) -> bool {
    let Transaction{sender, receiver, timestamp, nonce, amount, signature} = *transaction;
    let mint_wallet = hex_to_wallet(MINT_WALLET).expect("Failed to convert mint wallet to bytes");

    let signer = match sender == mint_wallet && allow_block_reward {
        true => receiver,
        false => sender
    };

    let unsigned = UnsignedTransaction{ sender, receiver, timestamp, nonce, amount };
    let bytes = bincode::serialize(&unsigned).expect("Failed to serialize transaction");
    let public_key = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &signer);
    let sig_len = signature.len;
    let sig_bytes = &signature.value[..sig_len];

    public_key.verify(&bytes, &sig_bytes).is_ok()
}

fn is_duplicate(blockchain: &Blockchain, pending: &Vec<Transaction>, new_transaction: &Transaction) -> bool {
    if pending.contains(new_transaction) {
        return true;
    }

    for block in blockchain {
        if block.transactions.contains(new_transaction) {
            return true;
        }
    }

    return false;
}
