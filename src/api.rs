use std::{net::{IpAddr, TcpStream, ToSocketAddrs, TcpListener, Ipv4Addr, SocketAddr}, error::Error, sync::Mutex};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

use crate::{State, CURRENT_VERSION};

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct RemoteNode {
    pub ip: IpAddr,
    pub port: u16,
    pub version: u16,
    pub last_msg: DateTime<Utc>,
    pub best_height: u64
}

pub type NodeList = Vec<RemoteNode>;

#[derive(Serialize, Deserialize, Debug)]
pub struct GetNodesRequest {
    pub version: u16,
    pub best_height: u64,
    pub listen_port: u16,
}

impl GetNodesRequest {
    pub fn new(port: u16) -> GetNodesRequest {
        let mut out = GetNodesRequest::default();
        out.listen_port = port;

        out
    }
}

impl Default for GetNodesRequest {
    fn default() -> Self {
        Self { version: CURRENT_VERSION, best_height: 1, listen_port: 0 }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetNodesResponse {
    pub nodes: Vec<RemoteNode>,
    pub your_ip: IpAddr,
    pub my_version: u16,
    pub my_best_height: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Request {
    GetNodes(GetNodesRequest)
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Response {
    GetNodes(GetNodesResponse)
}

pub type ConnectionHandler = fn(&TcpStream, &Mutex<State>) -> ();

pub fn send_req(req: Request, stream: &TcpStream) -> bincode::Result<()> {
    bincode::serialize_into(stream, &req)
}

/// TODO: Send version and best height from prior state object
pub fn get_neighbors_nodes(neighbor: &SocketAddr, listen_port: u16) -> Result<GetNodesResponse, Box<dyn Error>> {
    let socket = TcpStream::connect(neighbor)?;
    let get_nodes_req = Request::GetNodes(GetNodesRequest::new(listen_port));
    
    send_req(get_nodes_req, &socket)?;

    let res: GetNodesResponse = bincode::deserialize_from(socket)?;

    Ok(res)
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
