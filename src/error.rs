use std::error::{Error as StdError, self};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::blocks::Block;
use crate::wallet::{Transaction, Signature};

pub type Result<T> = std::result::Result<T, Error>;

pub type Error = Box<ErrorKind>;

#[derive(Debug, Serialize, Deserialize)]
pub enum ErrorKind {
    InvalidBlockHash(String, String),
    InvalidBlockTransaction(Transaction),
    InvalidBlockLogic(Block),
    InvalidTransactionSignature(Signature),
    InvalidTransactionLogic(Transaction),
    UnknownTransaction(Transaction),
    DuplicateTransaction(Transaction),
    ExpiredTransaction(Transaction),
}

impl StdError for ErrorKind {
    fn description(&self) -> &str {
        match *self {
            ErrorKind::InvalidBlockHash(_, _) => "Invalid block hash",
            ErrorKind::InvalidBlockTransaction(_) => "Unexpected transaction in block",
            ErrorKind::InvalidBlockLogic(_) => "Illogical block",
            ErrorKind::InvalidTransactionSignature(_) => "Invalid transaction signature (fradulent transaction)",
            ErrorKind::InvalidTransactionLogic(_) => "Illogical transaction",
            ErrorKind::UnknownTransaction(_) => "Unknown transaction",
            ErrorKind::DuplicateTransaction(_) => "Duplicate transaction",
            ErrorKind::ExpiredTransaction(_) => "Expired transaction",
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match &*self {
            ErrorKind::InvalidBlockHash(expected, received) => write!(fmt, "{}: Expected {}, computed {}", self.to_string(), expected, received),
            ErrorKind::InvalidBlockTransaction(_) => write!(fmt, "{}", self.to_string()),
            ErrorKind::InvalidBlockLogic(_) => write!(fmt, "{}", self.to_string()),
            ErrorKind::InvalidTransactionSignature(_) => write!(fmt, "{}", self.to_string()),
            ErrorKind::InvalidTransactionLogic(_) => write!(fmt, "{}", self.to_string()),
            ErrorKind::UnknownTransaction(transaction) => write!(fmt, "{}: signature {:x?}", self.to_string(), transaction.signature),
            ErrorKind::DuplicateTransaction(transaction) => write!(fmt, "{}: signature: {:x?}", self.to_string(), transaction.signature),
            ErrorKind::ExpiredTransaction(transaction) => write!(fmt, "{}: signature: {:x?}", self.to_string(), transaction.signature),
        }
    }
}
