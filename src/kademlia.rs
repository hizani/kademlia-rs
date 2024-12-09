use log::{error, info, trace, warn};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::{
    routing::{NodeAndDistance, NodeInfo, RoutingTable},
    rpc::{ReqHandle, Rpc},
    Key, A_PARAM, K_PARAM,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    Ping,
    Store(Key, String),
    FindNode(Key),
    FindValue(Key),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FindValueResult {
    Nodes(Vec<NodeAndDistance>),
    Value(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Reply {
    Ping,
    Store,
    FindNode(Vec<NodeAndDistance>),
    FindValue(FindValueResult),
}

#[derive(Default)]
pub struct KademliaBuilder {
    bootstrap_nodes: Option<Vec<NodeInfo>>,
    address: Option<IpAddr>,
    port: u16,
    key: Option<Key>,
}

#[derive(Debug, thiserror::Error)]
pub enum KademliaError {
    #[error("request has timed out")]
    RequestTimeout,
    #[error("can't serialize message: {}", 0)]
    CantSerializeMsg(serde_json::Error),
    #[error("can't bind udp socket: {}", 0)]
    CantBindUdpSocket(io::Error),
    #[error(transparent)]
    IoError(#[from] io::Error),
}

pub type Result<T> = core::result::Result<T, KademliaError>;

impl KademliaBuilder {
    pub fn new() -> Self {
        KademliaBuilder::default()
    }

    pub fn key<'a>(&'a mut self, key: Key) -> &'a mut Self {
        self.key = Some(key);
        self
    }

    pub fn address<'a>(&'a mut self, address: IpAddr) -> &'a mut Self {
        self.address = Some(address);
        self
    }

    pub fn port<'a>(&'a mut self, port: u16) -> &'a mut Self {
        self.port = port;
        self
    }

    pub fn bootstrap<'a>(&'a mut self, nodes: Vec<NodeInfo>) -> &'a mut Self {
        self.bootstrap_nodes = Some(nodes);
        self
    }

    pub fn read_bootstrap_nodes<'a>(&'a mut self, _: impl Read) -> &'a mut Self {
        todo!("bootstrap from file")
    }

    pub fn start(&self) -> Result<Kademlia> {
        let address = if let Some(address) = self.address {
            address
        } else {
            IpAddr::V4(Ipv4Addr::from_bits(0))
        };

        let key = if let Some(key) = self.key.clone() {
            key
        } else {
            Key::random()
        };

        let node_info = NodeInfo {
            addr: SocketAddr::new(address, self.port),
            id: key,
        };

        let routes = RoutingTable::new(node_info.clone());
        if let Some(bootstrap_nodes) = &self.bootstrap_nodes {
            for node in bootstrap_nodes {
                if let Err(err) = routes.update(node.clone()) {
                    error!("bootstrap: can't insert node {}: {}", node_info.id, err)
                }
            }
        }

        let (tx, rx) = mpsc::channel();
        let socket = UdpSocket::bind(node_info.addr)
            .or_else(|err| Err(KademliaError::CantBindUdpSocket(err)))?;

        let rpc = Rpc::new(socket, tx, node_info);

        let node = Kademlia {
            routes: Arc::new(routes),
            store: Arc::new(Mutex::new(HashMap::new())),
            rpc: Arc::new(rpc),
        };

        node.clone().start_req_handler(rx);

        Ok(node)
    }
}

#[derive(Clone)]
pub struct Kademlia {
    routes: Arc<RoutingTable>,
    store: Arc<Mutex<HashMap<Key, String>>>,
    rpc: Arc<Rpc>,
}

impl Kademlia {
    pub fn start() -> Result<Self> {
        KademliaBuilder::new().start()
    }

    pub fn new() -> KademliaBuilder {
        KademliaBuilder::new()
    }

    fn start_req_handler(self, rx: mpsc::Receiver<ReqHandle>) {
        thread::spawn(move || {
            for req_handle in rx.iter() {
                let node = self.clone();
                thread::spawn(move || {
                    let rep =
                        node.handle_req(req_handle.get_req().clone(), req_handle.get_src().clone());
                    if let Err(e) = req_handle.reply(rep) {
                        error!("Reply send error: {}", e)
                    }
                });
            }

            info!("Channel closed, since sender is dead.");
        });
    }

    fn handle_req(&self, req: Request, src: NodeInfo) -> Reply {
        self.append_with_refresh_no_error(src);

        match req {
            Request::Ping => Reply::Ping,
            Request::Store(k, v) => {
                self.store.lock().unwrap().insert(k, v);

                Reply::Store
            }
            Request::FindNode(id) => Reply::FindNode(self.routes.closest_nodes(&id, K_PARAM)),
            Request::FindValue(id) => {
                let lookup_res = self.store.lock().unwrap().remove(&id);

                match lookup_res {
                    Some(v) => Reply::FindValue(FindValueResult::Value(v)),
                    None => Reply::FindValue(FindValueResult::Nodes(
                        self.routes.closest_nodes(&id, K_PARAM),
                    )),
                }
            }
        }
    }

    pub fn ping_raw(&self, dst: NodeInfo) -> Result<Reply> {
        self.rpc.send_req(Request::Ping, dst).map_err(|err| {
            if let KademliaError::RequestTimeout = err {
                trace!("DST {} {}: Ping req timeout", dst.addr, dst.id);
                self.routes.remove(&dst.id);
            } else {
                error!("DST {} {}: Ping req error: {}", dst.addr, dst.id, err);
            }

            err
        })
    }

    // TODO: accept only v and evaluate the Key inside the function
    pub fn store_raw(&self, dst: NodeInfo, k: &Key, v: &str) -> Result<Reply> {
        self.rpc
            .send_req(Request::Store(k.to_owned(), v.to_owned()), dst)
            .map_err(|err| {
                if let KademliaError::RequestTimeout = err {
                    trace!("DST {} {}: Store req timeout", dst.addr, dst.id);
                    self.routes.remove(&dst.id);
                } else {
                    error!("DST {} {}: Store req error: {}", dst.addr, dst.id, err);
                }

                err
            })
    }

    pub fn find_node_raw(&self, dst: NodeInfo, k: &Key) -> Result<Reply> {
        self.rpc
            .send_req(Request::FindNode(k.to_owned()), dst)
            .map_err(|err| {
                if let KademliaError::RequestTimeout = err {
                    trace!("DST {} {}: Find node req timeout", dst.addr, dst.id);
                    self.routes.remove(&dst.id);
                } else {
                    error!("DST {} {}: Find node req error: {}", dst.addr, dst.id, err);
                }

                err
            })
    }

    pub fn find_value_raw(&self, dst: NodeInfo, k: &Key) -> Result<Reply> {
        self.rpc
            .send_req(Request::FindValue(k.to_owned()), dst)
            .map_err(|err| {
                if let KademliaError::RequestTimeout = err {
                    trace!("DST {} {}: Find  value req timeout", dst.addr, dst.id);
                    self.routes.remove(&dst.id);
                } else {
                    error!("DST {} {}: Find value req error: {}", dst.addr, dst.id, err);
                }

                err
            })
    }

    pub fn ping(&self, dst: NodeInfo) -> Result<()> {
        if let Err(e) = self.ping_raw(dst.clone()) {
            Err(e)
        } else {
            self.append_with_refresh_no_error(dst);
            Ok(())
        }
    }

    /// Pings dst without trying to clean K-Bucket if there is no room for
    /// dst insertion
    pub fn ping_discard(&self, dst: NodeInfo) -> Result<()> {
        if let Err(e) = self.ping_raw(dst.clone()) {
            Err(e)
        } else {
            _ = self.routes.update(dst);
            Ok(())
        }
    }

    // TODO: accept only v and evaluate the Key inside the function
    pub fn store(&self, dst: NodeInfo, k: &Key, v: &str) -> Result<()> {
        if let Err(e) = self.store_raw(dst.clone(), &k, &v) {
            Err(e)
        } else {
            Ok(self.append_with_refresh_no_error(dst))
        }
    }

    pub fn find_node(&self, dst: NodeInfo, id: &Key) -> Result<Vec<NodeAndDistance>> {
        match self.find_node_raw(dst.clone(), &id) {
            Err(e) => Err(e),
            Ok(reply) => {
                self.append_with_refresh_no_error(dst);

                if let Reply::FindNode(nodes) = reply {
                    Ok(nodes)
                } else {
                    Ok(vec![])
                }
            }
        }
    }

    pub fn find_value(&self, dst: NodeInfo, k: &Key) -> Result<Option<FindValueResult>> {
        match self.find_value_raw(dst.clone(), &k) {
            Err(e) => Err(e),
            Ok(reply) => {
                self.append_with_refresh_no_error(dst);

                if let Reply::FindValue(result) = reply {
                    Ok(Some(result))
                } else {
                    Ok(None)
                }
            }
        }
    }

    pub fn lookup_nodes(&self, id: &Key) -> Vec<NodeAndDistance> {
        let mut queried = HashSet::new();
        let mut nodes_distances = HashSet::new();

        // Add the closest nodes we know to our queue of nodes to query
        let mut to_query = self.routes.closest_nodes(id, K_PARAM);

        for entry in &to_query {
            queried.insert(entry.clone());
        }

        while !to_query.is_empty() {
            let mut joins = Vec::new();
            let mut queries = Vec::new();
            let mut results = Vec::new();
            for _ in 0..A_PARAM {
                match to_query.pop() {
                    Some(entry) => {
                        queries.push(entry);
                    }
                    None => {
                        break;
                    }
                }
            }

            let id = id.clone();

            for &NodeAndDistance(ref node_info, _) in &queries {
                let node_info = node_info.clone();
                let node = self.clone();
                joins.push(thread::spawn(move || node.find_node(node_info, &id)));
            }
            for j in joins {
                results.push(j.join().unwrap());
            }

            for (res, query) in results.into_iter().zip(queries) {
                if let Ok(entries) = res {
                    nodes_distances.insert(query);
                    for entry in entries {
                        if queried.insert(entry.clone()) {
                            to_query.push(entry);
                        }
                    }
                }
            }
        }

        let mut nodes_distances = nodes_distances.into_iter().collect::<Vec<_>>();
        nodes_distances.sort_by(|a, b| a.1.cmp(&b.1));
        nodes_distances.truncate(K_PARAM);
        nodes_distances
    }

    // TODO: return only Option<String>
    pub fn lookup_value(&self, id: &Key) -> (Option<String>, Vec<NodeAndDistance>) {
        let mut queried = HashSet::new();
        let mut potential_holders = HashSet::new();

        // Add the closest nodes we know to our queue of nodes to query
        let mut to_query = self.routes.closest_nodes(id, K_PARAM);

        for entry in &to_query {
            queried.insert(entry.clone());
        }

        while !to_query.is_empty() {
            let mut joins = Vec::new();
            let mut queries = Vec::new();
            let mut results = Vec::new();
            for _ in 0..A_PARAM {
                match to_query.pop() {
                    Some(entry) => {
                        queries.push(entry);
                    }
                    None => {
                        break;
                    }
                }
            }

            let id = id.clone();

            for &NodeAndDistance(ref ni, _) in &queries {
                let node_info = ni.clone();
                let node = self.clone();
                joins.push(thread::spawn(move || {
                    node.find_value(node_info.clone(), &id)
                }));
            }
            for j in joins {
                results.push(j.join().unwrap());
            }
            for (res, query) in results.into_iter().zip(queries) {
                if let Ok(fvres) = res {
                    if let Some(fvres) = fvres {
                        match fvres {
                            FindValueResult::Nodes(entries) => {
                                potential_holders.insert(query);
                                for entry in entries {
                                    if queried.insert(entry.clone()) {
                                        to_query.push(entry);
                                    }
                                }
                            }
                            FindValueResult::Value(val) => {
                                let mut potential_holders =
                                    potential_holders.into_iter().collect::<Vec<_>>();
                                potential_holders.sort_by(|a, b| a.1.cmp(&b.1));
                                potential_holders.truncate(K_PARAM);
                                return (Some(val), potential_holders);
                            }
                        }
                    }
                }
            }
        }

        (None, vec![])
    }

    pub fn put(&self, v: &str) {
        let k = Key::hash(v.as_bytes());
        info!("key: {}", k);
        let candidates = self.lookup_nodes(&k);

        if candidates.len() < K_PARAM {
            self.store
                .lock()
                .unwrap()
                .insert(k.to_owned(), v.to_owned());
        }

        for NodeAndDistance(node_info, _) in candidates {
            let node = self.clone();
            let k = k.to_owned();
            let v = v.to_owned();
            thread::spawn(move || {
                node.store(node_info, &k, &v).unwrap();
            });
        }
    }

    pub fn get(&self, k: &Key) -> Option<String> {
        if let Some(v) = self.store.lock().unwrap().get(&k) {
            return Some(v.to_owned());
        }

        // TODO: Store the value in nodes from closest bucket to the k
        let (v_opt, mut nodes) = self.lookup_value(k);
        v_opt.map(|v| {
            if let Some(NodeAndDistance(store_target, _)) = nodes.pop() {
                if let Err(e) = self.store(store_target, &k, &v) {
                    warn!(
                        "Can't store value {} in node {} {}: {}",
                        k, store_target.addr, store_target.id, e
                    );
                    self.store.lock().unwrap().insert(k.clone(), v.clone());
                }
            } else {
                self.store.lock().unwrap().insert(k.clone(), v.clone());
            }
            v
        })
    }

    /// Appends a node into the routing table and evicts non-responsive nodes
    /// from the bucket if there is no room for it.
    pub fn append_with_refresh(&self, node_info: NodeInfo) -> Result<()> {
        if let Err(update_err) = self.routes.update(node_info) {
            for node in update_err.nodes {
                if let Err(ping_err) = self.ping_discard(node) {
                    match ping_err {
                        KademliaError::RequestTimeout => break,
                        _ => return Err(ping_err),
                    }
                }
            }

            // discard dst if there is still no room after pinging whole K-Bucket
            _ = self.routes.update(update_err.node_info);
        }

        Ok(())
    }

    fn append_with_refresh_no_error(&self, node_info: NodeInfo) {
        if let Err(e) = self.append_with_refresh(node_info) {
            warn!(
                "{} {}: Can't update routing table: {}",
                node_info.addr, node_info.id, e
            )
        }
    }

    pub fn print_routes(&self) {
        self.routes.print();
    }
}
