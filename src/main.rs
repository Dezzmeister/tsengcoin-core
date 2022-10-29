use std::{error::Error, env, net::{SocketAddrV4, Ipv4Addr, IpAddr, SocketAddr, TcpStream}, sync::{Mutex, Arc}, collections::HashMap, thread};

use api::{RemoteNode, get_neighbors_nodes, Response, Request, send_req, listen_for_connections, GetNodesResponse, GetNodesRequest};
use blocks::{Block, Blockchain, load_blockchain};
use command::dispatch_command;
use ring::signature::EcdsaKeyPair;
use wallet::{Wallet, create_keypair, load_wallet, PRIVATE_KEY_PATH};
use chrono::{DateTime, Utc};

use crate::command::CommandMap;

pub mod api;
pub mod blocks;
pub mod wallet;
pub mod command;
pub mod hash;

pub const CURRENT_VERSION: u16 = 1;
const MAX_NEIGHBORS: usize = 5;

#[derive(Debug)]
pub struct State {
    nodes: Vec<RemoteNode>,
    blockchain: Blockchain,
    client_keypair: EcdsaKeyPair,
    /// Public IP of this node
    ip: Option<IpAddr>,
    /// Open port of this node
    port: u16,
}

impl State {
    fn new(password: &str, port: u16) -> Self {
        State {
            nodes: Default::default(),
            blockchain: load_blockchain(),
            client_keypair: load_wallet(password, PRIVATE_KEY_PATH).unwrap(),
            ip: Default::default(),
            port,
        }
    }
}

fn bootstrap(seed: SocketAddr, state: State) -> State {
    let GetNodesResponse{nodes, your_ip, my_version, my_best_height} = get_neighbors_nodes(&seed, state.port).expect("Failed to bootstrap with seed node");
    let seed_node = RemoteNode{ip: seed.ip(), port: seed.port(), version: my_version, last_msg: Utc::now(), best_height: my_best_height};
    let mut full_nodes = Vec::from(nodes);
    full_nodes.push(seed_node);

    State { nodes: full_nodes, ip: Some(your_ip), ..state }
}

fn handle_connection(conn: &TcpStream, state_mut: &Mutex<State>) {
    let req_result: bincode::Result<Request> = bincode::deserialize_from(conn);

    if req_result.is_err() {
        println!("Error handling request: {:?}", req_result.err());
        return;
    }

    let req = req_result.unwrap();
    match req {
        Request::GetNodes(req_data) => handle_get_nodes_req(&conn, req_data, &state_mut)
    }
}

fn handle_get_nodes_req(conn: &TcpStream, req_data: GetNodesRequest, state_mut: &Mutex<State>) {
    let mut state = state_mut.lock().unwrap();
    let caller_ip = conn.peer_addr().expect("Failed to get remote node's IP");

    let res = GetNodesResponse{ nodes: (*state).nodes.to_vec(), your_ip: caller_ip.ip(), my_version: CURRENT_VERSION, my_best_height: (*state).blockchain.height };
    let new_node = RemoteNode{ip: caller_ip.ip(), port: (&req_data).listen_port, version: (&req_data).version, last_msg: Utc::now(), best_height: (&req_data).best_height};

    // Add seen node to state
    (*state).nodes.push(new_node);
    
    bincode::serialize_into(conn, &res).expect("Failed to respond to get nodes request");
}

fn create_wallet(_command_name: &String, args: &Vec<String>, _state: Option<()>) -> Result<(), Box<dyn Error>> {
    let password = args.join(" ");
    let _keypair = create_keypair(&password);

    Ok(())
}

fn start(_command_name: &String, args: &Vec<String>, _state: Option<()>) -> Result<(), Box<dyn Error>> {
    let ip = args[0].parse::<IpAddr>()?;
    let seed_port = args[1].parse::<u16>()?;
    let listen_port = args[2].parse::<u16>()?;
    let password = args[3..].join(" ");
    let seed_addr = SocketAddr::new(ip, seed_port);
    let this_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), listen_port);
    let mut state = State::new(&password, listen_port);

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

    Ok(())
}

fn start_as_seed(_command_name: &String, args: &Vec<String>, _state: Option<()>) -> Result<(), Box<dyn Error>> {
    let port = args[0].parse::<u16>()?;
    let password = args[1..].join(" ");
    let state = State::new(&password, port);
    let state_mut = Arc::new(Mutex::new(state));
    let state_mut_ref = Arc::clone(&state_mut);
    let this_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

    println!("Starting as seed node without bootstrap on port {port}");

    thread::spawn(move || {
        listen_for_connections(this_addr, handle_connection, &state_mut_ref).unwrap();
    });

    listen_for_commands(&state_mut);

    Ok(())
}

fn send_coins(_command_name: &String, args: &Vec<String>, state_opt: Option<&Mutex<State>>) -> Result<(), Box<dyn Error>> {
    let recipient = hex::decode(&args[0])?;
    let amount = args[1].parse::<f32>()?;
    let state_mut = state_opt.unwrap();

    Ok(())
}

fn balance(_command_name: &String, args: &Vec<String>, state_opt: Option<&Mutex<State>>) -> Result<(), Box<dyn Error>> {

    Ok(())
}

fn listen_for_commands(state_mut: &Mutex<State>) {
    let mut command_map: CommandMap<&Mutex<State>> = HashMap::new();
    command_map.insert(String::from("send-coins"), send_coins);

    let mut buffer = String::new();
    let stdin = std::io::stdin();

    loop {
        let res = stdin.read_line(&mut buffer);

        if res.is_err() {
            println!("Error reading command: {:?}", res.err());
            continue;
        }

        let args: Vec<&str> = buffer.split(' ').collect();

        if args.len() < 1 {
            println!("Need to supply a command");
            continue;
        }
        let cmd_args = args[1..].to_vec().iter().map(|&s| s.into()).collect();

        dispatch_command(&cmd_args, &command_map, Some(state_mut));

        buffer.clear();
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut command_map: CommandMap<()> = HashMap::new();
    command_map.insert(String::from("create-wallet"), create_wallet);
    command_map.insert(String::from("start"), start);
    command_map.insert(String::from("start-seed"), start_as_seed);

    let args: Vec<String> = env::args().collect();

    dispatch_command(&args[1..].to_vec(), &command_map, None);

    Ok(())
}
