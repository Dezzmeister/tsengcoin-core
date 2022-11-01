use std::{net::{IpAddr, TcpStream, TcpListener, Ipv4Addr, SocketAddr}, error::Error, sync::Mutex, vec, cmp::Ordering};
use chrono::{DateTime, Utc};
use rand::seq::SliceRandom;
use serde::{Serialize, Deserialize};

use crate::{State, CURRENT_VERSION, blocks::{Block, append_blocks}, wallet::Transaction, verify::{verify_new_transaction, verify_blocks}};

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum Request {
    GetNodes(GetNodesRequest),
    GetBlocks(GetBlocksRequest),
    GetPendingTransactions(GetTransactionsRequest),
    BroadcastTransaction(BroadcastTransactionRequest),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    GetNodes(GetNodesResponse),
    GetBlocks(GetBlocksResponse),
    GetPendingTransactions(GetTransactionsResponse),
    BroadcastTransaction(BroadcastTransactionResponse),
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct RemoteNode {
    pub ip: IpAddr,
    pub port: u16,
    pub version: u16,
    pub last_msg: DateTime<Utc>,
    pub best_height: usize,
    pub dead: bool,
}

impl Default for RemoteNode {
    fn default() -> Self {
        Self { 
            ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: Default::default(),
            version: Default::default(),
            last_msg: Default::default(),
            best_height: Default::default(),
            dead: Default::default()
        }
    }
}

impl PartialEq for RemoteNode {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip && self.port == other.port
    }
}

pub type NodeList = Vec<RemoteNode>;

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct GetNodesRequest {
    pub version: u16,
    pub best_height: usize,
    pub listen_port: u16,
}

impl Default for GetNodesRequest {
    fn default() -> Self {
        Self { version: CURRENT_VERSION, best_height: 1, listen_port: 0 }
    }
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct GetBlocksRequest {
    pub version: u16,
    pub best_height: usize
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct GetTransactionsRequest {
    pub version: u16,
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct BroadcastTransactionRequest {
    pub transaction: Transaction,
    pub version: u16
}

pub type BroadcastTransactionResponse = crate::error::Result<()>;

#[derive(Serialize, Deserialize, Debug)]
pub struct GetNodesResponse {
    pub nodes: Vec<RemoteNode>,
    pub your_ip: IpAddr,
    pub my_version: u16,
    pub my_best_height: usize,
}

pub type GetBlocksResponse = Option<Vec<Block>>;

pub type GetTransactionsResponse = Vec<Transaction>;

pub type ConnectionHandler = fn(&TcpStream, &Mutex<State>) -> ();

pub fn send_req(req: Request, stream: &TcpStream) -> bincode::Result<()> {
    bincode::serialize_into(stream, &req)
}

pub fn get_neighbors_nodes(neighbor: &SocketAddr, listen_port: u16, best_height: usize, version: u16) -> Result<GetNodesResponse, Box<dyn Error>> {
    let socket = TcpStream::connect(neighbor)?;

    let get_nodes_req = Request::GetNodes(GetNodesRequest { version, best_height, listen_port });
    
    send_req(get_nodes_req, &socket)?;

    let res: GetNodesResponse = bincode::deserialize_from(socket)?;

    Ok(res)
}

pub fn get_latest_blocks(neighbor: &SocketAddr, best_height: usize, version: u16) -> Result<GetBlocksResponse, Box<dyn Error>> {
    let socket = TcpStream::connect(neighbor)?;
    let get_blocks_req = Request::GetBlocks(GetBlocksRequest { version, best_height });

    send_req(get_blocks_req, &socket)?;

    let res: GetBlocksResponse = bincode::deserialize_from(socket)?;

    Ok(res)

}

pub fn get_pending_transactions(neighbor: &SocketAddr, version: u16) -> Result<GetTransactionsResponse, Box<dyn Error>> {
    let socket = TcpStream::connect(neighbor)?;
    let get_transactions_req = Request::GetPendingTransactions(GetTransactionsRequest { version });

    send_req(get_transactions_req, &socket)?;

    let res: GetTransactionsResponse = bincode::deserialize_from(socket)?;

    Ok(res)
}

pub fn broadcast_transaction(neighbor: &SocketAddr, transaction: Transaction, version: u16) -> Result<BroadcastTransactionResponse, Box<dyn Error>> {
    let socket = TcpStream::connect(neighbor)?;
    let req: Request = Request::BroadcastTransaction(BroadcastTransactionRequest { transaction, version });

    send_req(req, &socket)?;

    let res: BroadcastTransactionResponse = bincode::deserialize_from(socket)?;

    Ok(res)
}

pub fn handle_get_nodes_req(conn: &TcpStream, req_data: GetNodesRequest, state_mut: &Mutex<State>) {
    let mut state = state_mut.lock().unwrap();
    let caller_ip = conn.peer_addr().expect("Failed to get remote node's IP");

    let res = GetNodesResponse{ nodes: (*state).nodes.to_vec(), your_ip: caller_ip.ip(), my_version: CURRENT_VERSION, my_best_height: (*state).blockchain.len() };
    let new_node = RemoteNode{ip: caller_ip.ip(), port: (&req_data).listen_port, version: (&req_data).version, last_msg: Utc::now(), best_height: (&req_data).best_height, dead: false};

    // Add seen node to state
    if !(*state).nodes.contains(&new_node) {
        (*state).nodes.push(new_node);
    }
    
    bincode::serialize_into(conn, &res).expect("Failed to respond to get nodes request");

    if (*state).is_seed {
        let socket_addr = SocketAddr::new(new_node.ip, new_node.port);
        let local_best_height = (*state).blockchain.len();

        if local_best_height < new_node.best_height {
            let latest_blocks_opt = get_latest_blocks(&socket_addr, local_best_height, CURRENT_VERSION).expect("Failed to sync blocks with new node");
            if latest_blocks_opt.is_none() {
                return;
            }

            let latest_blocks = latest_blocks_opt.unwrap();
            append_blocks(&(*state).blockchain, &latest_blocks);
        }
    }
}

pub fn handle_get_blocks_req(conn: &TcpStream, req_data: GetBlocksRequest, state_mut: &Mutex<State>) {
    let state = state_mut.lock().unwrap();
    let local_best_height = state.blockchain.len();

    let res: GetBlocksResponse = {
        if local_best_height <= req_data.best_height {
            None
        } else {
            let blocks = state.blockchain[local_best_height..req_data.best_height].to_vec();

            Some(blocks)
        }
    };

    bincode::serialize_into(conn, &res).expect("Failed to respond to get blocks request");
}

pub fn handle_get_pending_transactions_req(conn: &TcpStream, _req_data: GetTransactionsRequest, state_mut: &Mutex<State>) {
    let state_guard = state_mut.lock().unwrap();
    let state = &(*state_guard);
    let mut res: GetTransactionsResponse = vec![Transaction::default(); state.pending_transactions.len()];
    res.copy_from_slice(&state.pending_transactions);

    bincode::serialize_into(conn, &res).expect("Failed to respond to get transactions request");
}

pub fn handle_broadcast_transaction_req(conn: &TcpStream, req_data: BroadcastTransactionRequest, state_mut: &Mutex<State>) {
    let mut state_guard = state_mut.lock().unwrap();
    let state = &mut (*state_guard);
    let new_transaction = req_data.transaction;

    let verify_res = verify_new_transaction(&state.blockchain, &state.pending_transactions, &new_transaction, true);

    // If we can't verify the transaction, don't propagate it. This prevents transactions with bad amounts or bad signatures from being accepted,
    // but it also prevents duplicate transactions from being accepted. This is primarily a security mechanism but it also conveniently
    // tells us when to stop propagating a new transaction.
    if verify_res.is_err() {
        let res: BroadcastTransactionResponse = verify_res;
        bincode::serialize_into(conn, &res).expect("Failed to respond to broadcast transaction request");
        return;
    }

    println!("Received transaction: {} TsengCoin: {} to {}", new_transaction.amount, hex::encode(new_transaction.sender), hex::encode(new_transaction.receiver));

    state.pending_transactions.push(new_transaction);
    
    for node in &mut state.nodes {
        let socket_addr = SocketAddr::new(node.ip, node.port);
        let res = broadcast_transaction(&socket_addr, new_transaction, node.version);

        if res.is_err() {
            node.dead = true;
        }
    }
}

pub fn listen_for_connections(this_addr: SocketAddr, handle_connection: ConnectionHandler, state_mut: &Mutex<State>) -> Result<(), Box<dyn Error>> {
    let socket = TcpListener::bind(this_addr)?;

    for stream in socket.incoming() {
        match stream {
            Err(err) => println!("Error receiving incoming connection: {}", err),
            Ok(conn) => handle_connection(&conn, state_mut),
        }
    }

    Ok(())
}

pub fn sync_blocks(state: &mut State ) {
    let nodes = &mut state.nodes;
    let best_height = &mut state.blockchain.len();

    println!("Syncing local copy of blockchain");
    
    if nodes.len() == 0 {
        println!("No nodes to sync with!");
        return;
    }

    nodes.sort_by(|x, y| {
        if x.best_height > y.best_height {
            Ordering::Greater
        } else if x.best_height < y.best_height {
            Ordering::Less
        } else {
            Ordering::Equal
        }
    });

    let remote_best_height = nodes[0].best_height;

    if remote_best_height <= *best_height {
        println!("Up to date.");
        return;
    }

    let mut nodes_to_choose_from: usize = 0;
    let mut curr_node = &nodes[0];

    while curr_node.best_height == remote_best_height {
        nodes_to_choose_from += 1;
        curr_node = &nodes[nodes_to_choose_from];
    }

    let nodes_to_use = &mut nodes[0..nodes_to_choose_from];
    nodes_to_use.shuffle(&mut rand::thread_rng());

    for i in 0..nodes_to_use.len() {
        let mut node = nodes_to_use[i];
        let socket_addr = SocketAddr::new(node.ip, node.port);
        let latest_blocks_res = get_latest_blocks(&socket_addr, *best_height, CURRENT_VERSION);

        if latest_blocks_res.is_ok() {
            // Append blocks
            let latest_blocks_opt = latest_blocks_res.unwrap();
            
            if latest_blocks_opt.is_none() {
                continue;
            }

            let latest_blocks = latest_blocks_opt.unwrap();
            let mut all_blocks = vec![Block::default(); state.blockchain.len() + latest_blocks.len()];
            all_blocks[0..state.blockchain.len()].copy_from_slice(&state.blockchain);
            all_blocks[state.blockchain.len()..].copy_from_slice(&latest_blocks);

            let verification = verify_blocks(&all_blocks);

            if verification.is_err() {
                println!("Received invalid blockchain from node");
                continue;
            }

            println!("Appending {} new blocks", latest_blocks.len());
            state.blockchain = latest_blocks;

            return;
        }

        // Mark the node for removal
        node.dead = true;
    }

    // All the nodes we needed were dead... ask for more nodes
}
