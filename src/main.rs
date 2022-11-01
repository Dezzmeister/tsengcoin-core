use std::{error::Error, env, net::{Ipv4Addr, IpAddr, SocketAddr, TcpStream}, sync::{Mutex, Arc}, collections::HashMap, thread, time::Duration};

use api::{RemoteNode, get_neighbors_nodes, Request, listen_for_connections, GetNodesResponse, handle_get_nodes_req, handle_get_blocks_req, handle_get_pending_transactions_req, get_pending_transactions, handle_broadcast_transaction_req};
use blocks::{Blockchain, load_blockchain, UnhashedBlock};
use command::dispatch_command;
use periodic::{Planner, Every};
use rand::{seq::SliceRandom};
use ring::signature::EcdsaKeyPair;
use wallet::{Wallet, create_keypair, load_wallet, PRIVATE_KEY_PATH, keypair_to_wallet, Transaction, pending_balance, UnsignedTransaction, sign_transaction};
use chrono::{Utc};

use crate::{command::CommandMap, wallet::hex_to_wallet, api::{sync_blocks, broadcast_transaction}, hash::hash_sha256};
use crate::error::ErrorKind::DuplicateTransaction;

pub mod api;
pub mod blocks;
pub mod wallet;
pub mod command;
pub mod hash;
pub mod error;
pub mod verify;
pub mod cuda;

pub const CURRENT_VERSION: u16 = 1;
const MAX_NEIGHBORS: usize = 5;

#[derive(Debug)]
pub struct State {
    nodes: Vec<RemoteNode>,
    min_nodes: usize,
    blockchain: Blockchain,
    wallet: Wallet,
    client_keypair: EcdsaKeyPair,
    pending_transactions: Vec<Transaction>,
    /// Public IP of this node
    _ip: Option<IpAddr>,
    /// Open port of this node
    port: u16,
    is_seed: bool,
}

impl State {
    fn new(password: &str, port: u16, is_seed: bool) -> Self {
        let keypair = load_wallet(password, PRIVATE_KEY_PATH).unwrap();
        let wallet = keypair_to_wallet(&keypair);

        State {
            nodes: Default::default(),
            min_nodes: Default::default(),
            blockchain: load_blockchain(),
            wallet,
            client_keypair: keypair,
            pending_transactions: Default::default(),
            _ip: Default::default(),
            port,
            is_seed
        }
    }
}

fn bootstrap(seed: SocketAddr, state: State) -> State {
    let GetNodesResponse{nodes, your_ip, my_version, my_best_height} = get_neighbors_nodes(&seed, state.port, state.blockchain.len(), 1).expect("Failed to bootstrap with seed node");
    let seed_node = RemoteNode{ip: seed.ip(), port: seed.port(), version: my_version, last_msg: Utc::now(), best_height: my_best_height, dead: false};
    let mut full_nodes = Vec::from(nodes);
    full_nodes.push(seed_node);
    let min_nodes = full_nodes.len();
    let mut state_out = State { nodes: full_nodes, min_nodes, _ip: Some(your_ip), ..state };

    sync_blocks(&mut state_out);

    let pending_transactions = get_pending_transactions(&seed, CURRENT_VERSION).expect("Failed to get pending transactions from seed");
    state_out.pending_transactions = pending_transactions;

    state_out
}

fn handle_connection(conn: &TcpStream, state_mut: &Mutex<State>) {
    let req_result: bincode::Result<Request> = bincode::deserialize_from(conn);

    if req_result.is_err() {
        println!("Error handling request: {:?}", req_result.err());
        return;
    }

    let req = req_result.unwrap();
    match req {
        Request::GetNodes(req_data) => handle_get_nodes_req(&conn, req_data, &state_mut),
        Request::GetBlocks(req_data) => handle_get_blocks_req(&conn, req_data, &state_mut),
        Request::GetPendingTransactions(req_data) => handle_get_pending_transactions_req(&conn, req_data, &state_mut),
        Request::BroadcastTransaction(req_data) => handle_broadcast_transaction_req(&conn, req_data, &state_mut)
    }
}

fn create_wallet(_command_name: &String, args: &Vec<String>, _state: Option<()>) -> Result<(), Box<dyn Error>> {
    let password = args.join(" ");
    let _keypair = create_keypair(&password);

    Ok(())
}

fn liveness_check(state_mut: &Mutex<State>) {
    let mut state_guard = state_mut.lock().unwrap();
    let mut state = &mut (*state_guard);
    let live_nodes: Vec<RemoteNode> = 
        state.nodes
        .iter()
        .filter(|n| {!n.dead})
        .map(|x| {x.to_owned()})
        .collect();

    let dead_nodes_ct = state.nodes.len() - live_nodes.len();

    if dead_nodes_ct != 0 {
        println!("Found {dead_nodes_ct} dead nodes. Cleaning up");
    }

    state.nodes = live_nodes;

    if state.nodes.len() >= state.min_nodes {
        return;
    } else if state.nodes.len() == 0 {
        println!("All nodes are dead! Waiting for more nodes to connect");
        return;
    }

    // Pick a random live node and ask it for more
    state.nodes.shuffle(&mut rand::thread_rng());
    for i in 0..state.nodes.len() {
        let mut node = state.nodes[i];
        let socket_addr = SocketAddr::new(node.ip, node.port);
        let more_nodes_res = get_neighbors_nodes(&socket_addr, state.port, state.blockchain.len(), CURRENT_VERSION);

        if more_nodes_res.is_err() {
            node.dead = true;
            continue;
        }

        let mut more_nodes = more_nodes_res.unwrap();
        state.nodes.append(&mut more_nodes.nodes);
    }

    if state.nodes.len() > MAX_NEIGHBORS {
        state.nodes.shuffle(&mut rand::thread_rng());
        state.nodes = state.nodes[0..MAX_NEIGHBORS].to_vec();
    }
}

fn start_scheduled_jobs(planner: &mut Planner, state_mut: &Arc<Mutex<State>>) {
    let state_mut_ref = Arc::clone(state_mut);

    planner.add(move || {
        liveness_check(&state_mut_ref);
    }, Every::new(Duration::from_secs(120)));
}

fn start(_command_name: &String, args: &Vec<String>, _state: Option<()>) -> Result<(), Box<dyn Error>> {
    let ip = args[0].parse::<IpAddr>()?;
    let seed_port = args[1].parse::<u16>()?;
    let listen_port = args[2].parse::<u16>()?;
    let password = args[3..].join(" ");
    let seed_addr = SocketAddr::new(ip, seed_port);
    let this_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), listen_port);
    let mut state = State::new(&password, listen_port, false);
    let mut planner = Planner::new();

    println!("Bootstrapping with seed at {seed_addr}");

    state = bootstrap(seed_addr, state);
    println!("State: {:#?}", state);

    // We need to use this mutex in two threads, which means it has two owners.
    // By default Rust doesn't allow this so we need to wrap the mutex in an
    // atomic reference counter.
    let state_mut = Arc::new(Mutex::new(state));
    let state_mut_ref = Arc::clone(&state_mut);

    println!("Starting as node on port {listen_port}");

    thread::spawn(move || {
        listen_for_connections(this_addr, handle_connection, &state_mut_ref).unwrap();
    });

    listen_for_commands(&state_mut);
    start_scheduled_jobs(&mut planner, &state_mut);

    Ok(())
}

fn start_as_seed(_command_name: &String, args: &Vec<String>, _state: Option<()>) -> Result<(), Box<dyn Error>> {
    let port = args[0].parse::<u16>()?;
    let password = args[1..].join(" ");
    let state = State::new(&password, port, true);
    let state_mut = Arc::new(Mutex::new(state));
    let state_mut_ref = Arc::clone(&state_mut);
    let this_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    let mut planner = Planner::new();

    println!("Starting as seed node without bootstrap on port {port}");

    thread::spawn(move || {
        listen_for_connections(this_addr, handle_connection, &state_mut_ref).unwrap();
    });

    listen_for_commands(&state_mut);
    start_scheduled_jobs(&mut planner, &state_mut);

    Ok(())
}

fn send_coins(_command_name: &String, args: &Vec<String>, state_opt: Option<&Mutex<State>>) -> Result<(), Box<dyn Error>> {
    let receiver = hex_to_wallet(&args[0])?;
    let amount = args[1].parse::<u64>()?;
    let state_mut = state_opt.unwrap();
    let mut state_guard = state_mut.lock().unwrap();
    let state = &mut (*state_guard);

    let curr_balance = pending_balance(&state.blockchain, &state.pending_transactions, &state.wallet);

    if (amount as i128) > curr_balance {
        println!("You don't have enough TsengCoin. Your current balance is {curr_balance}");
        return Ok(());
    }

    let unsigned_transaction = UnsignedTransaction{ sender: state.wallet, receiver, timestamp: Utc::now(), nonce: rand::random(), amount };
    let signed_transaction = sign_transaction(unsigned_transaction, &state.client_keypair);

    state.pending_transactions.push(signed_transaction);

    println!("Sending {} TsengCoin to {}, broadcasting to {} nodes", amount, hex::encode(receiver), state.nodes.len());

    for node in &mut state.nodes {
        let socket_addr = SocketAddr::new(node.ip, node.port);
        
        let res = broadcast_transaction(&socket_addr, signed_transaction, CURRENT_VERSION);

        if res.is_err() {
            node.dead = true;
        }

        let broadcast_response = res.unwrap();
        match broadcast_response {
            Ok(()) => (),
            Err(err_box) => {
                match *err_box {
                    DuplicateTransaction(_) => (),
                    err => println!("Rejected transaction due to error: {}", err),
                }
            }
        };
    }

    Ok(())
}

fn balance(_command_name: &String, args: &Vec<String>, state_opt: Option<&Mutex<State>>) -> Result<(), Box<dyn Error>> {
    let state_mut = state_opt.unwrap();
    let state_guard = state_mut.lock().unwrap();
    let state = &(*state_guard);
    let wallet = &(match args.len() < 1 {
        true => state.wallet,
        false => hex_to_wallet(&args[0]).expect("Failed to decode wallet ID"),
    });
    let wallet_balance = pending_balance(&state.blockchain, &state.pending_transactions, wallet);

    if args.len() < 1 {
        println!("You have {wallet_balance} TsengCoin");
    } else {
        println!("This wallet has {wallet_balance} TsengCoin");
    }

    Ok(())
}

fn listen_for_commands(state_mut: &Mutex<State>) {
    let mut command_map: CommandMap<&Mutex<State>> = HashMap::new();
    command_map.insert(String::from("send-coins"), send_coins);
    command_map.insert(String::from("balance"), balance);

    let mut buffer = String::new();
    let stdin = std::io::stdin();

    loop {
        let res = stdin.read_line(&mut buffer);

        if res.is_err() {
            println!("Error reading command: {:?}", res.err());
            continue;
        }

        let args: Vec<&str> = buffer.trim().split(' ').collect();

        if args.len() < 1 {
            println!("Need to supply a command");
            continue;
        }
        let cmd_args = args.to_vec().iter().map(|&s| s.into()).collect();

        dispatch_command(&cmd_args, &command_map, Some(state_mut));

        buffer.clear();
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut command_map: CommandMap<()> = HashMap::new();
    command_map.insert(String::from("create-wallet"), create_wallet);
    command_map.insert(String::from("start"), start);
    command_map.insert(String::from("start-seed"), start_as_seed);
    command_map.insert(String::from("test"), test);

    let args: Vec<String> = env::args().collect();

    dispatch_command(&args[1..].to_vec(), &command_map, None);

    Ok(())
}

fn test(_command_name: &String, _args: &Vec<String>, _state: Option<()>) -> Result<(), Box<dyn Error>> {
    println!("test");
    let blank_block = make_blank_block();
    let bytes = bincode::serialize(&blank_block)?;
    let len = bytes.len();

    let chunk76 = &bytes[(76 * 64)..(77 * 64)];
    let chunk77 = &bytes[(77 * 64)..];

    //println!("Bytes: {}", hex::encode(&bytes));
    println!("Block length: {}", len);
    println!("Chunk 76: {:x?}", chunk76);
    println!("Chunk 77: {:x?}", chunk77);
    // println!("{:x?}", bytes);

    let _hash = hash_sha256(&bytes);

    Ok(())
}

fn make_blank_block() -> UnhashedBlock {
    let mut unhashed_block = UnhashedBlock::default();
    unhashed_block.nonce[0] = 0xDEAD_BEEF;
    unhashed_block.nonce[7] = 0xDEAD_BEEF;

    unhashed_block
}
