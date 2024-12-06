use log::error;
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
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

    pub fn start(&self) -> Kademlia {
        let address = if let Some(address) = self.address {
            address
        } else {
            IpAddr::V4(Ipv4Addr::from_bits(0))
        };

        let key = if let Some(key) = self.key.clone() {
            key
        } else {
            Key::new()
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

        let socket = UdpSocket::bind(&node_info.addr).unwrap();

        let (tx, rx) = mpsc::channel();
        let rpc = Rpc::open(socket, tx, node_info);

        let node = Kademlia {
            routes: Arc::new(routes),
            node_info,
            store: Arc::new(Mutex::new(HashMap::new())),
            rpc: Arc::new(rpc),
        };

        node.clone().start_req_handler(rx);

        node
    }
}

#[derive(Clone)]
pub struct Kademlia {
    routes: Arc<RoutingTable>,
    store: Arc<Mutex<HashMap<Key, String>>>,
    rpc: Arc<Rpc>,
    node_info: NodeInfo,
}

impl Kademlia {
    pub fn start() -> Self {
        KademliaBuilder::new().start()
    }

    pub fn new() -> KademliaBuilder {
        KademliaBuilder::new()
    }

    fn start_req_handler(self, rx: Receiver<ReqHandle>) {
        thread::spawn(move || {
            for req_handle in rx.iter() {
                let node = self.clone();
                thread::spawn(move || {
                    let rep =
                        node.handle_req(req_handle.get_req().clone(), req_handle.get_src().clone());
                    req_handle.rep(rep);
                });
            }
            info!("Channel closed, since sender is dead.");
        });
    }

    fn handle_req(&self, req: Request, src: NodeInfo) -> Reply {
        self.update_table(src);
        match req {
            Request::Ping => Reply::Ping,
            Request::Store(k, v) => {
                self.store.lock().unwrap().insert(k, v);

                Reply::Ping
            }
            Request::FindNode(id) => Reply::FindNode(self.routes.closest_nodes(&id, K_PARAM)),
            Request::FindValue(id) => {
                let mut store = self.store.lock().unwrap();
                let lookup_res = store.remove(&id);
                drop(store);

                match lookup_res {
                    Some(v) => Reply::FindValue(FindValueResult::Value(v)),
                    None => Reply::FindValue(FindValueResult::Nodes(
                        self.routes.closest_nodes(&id, K_PARAM),
                    )),
                }
            }
        }
    }

    pub fn ping_raw(&self, dst: NodeInfo) -> Receiver<Option<Reply>> {
        self.rpc.send_req(Request::Ping, dst)
    }

    pub fn store_raw(&self, dst: NodeInfo, k: &Key, v: &str) -> Receiver<Option<Reply>> {
        self.rpc
            .send_req(Request::Store(k.to_owned(), v.to_owned()), dst)
    }

    pub fn find_node_raw(&self, dst: NodeInfo, k: &Key) -> Receiver<Option<Reply>> {
        self.rpc.send_req(Request::FindNode(k.to_owned()), dst)
    }

    pub fn find_value_raw(&self, dst: NodeInfo, k: &Key) -> Receiver<Option<Reply>> {
        self.rpc.send_req(Request::FindValue(k.clone()), dst)
    }

    pub fn ping(&self, dst: NodeInfo) -> Option<()> {
        let rep = self.ping_raw(dst.clone()).recv().unwrap(); // err: pending reply channel closed
        if let Some(Reply::Ping) = rep {
            self.update_table(dst);
            Some(())
        } else {
            self.routes.remove(&dst.id);
            None
        }
    }

    /// Pings dst without trying to clean K-Bucket if there is no room for
    /// dst insertion
    pub fn ping_discard(&self, dst: NodeInfo) -> Option<()> {
        let rep = self.ping_raw(dst.clone()).recv().unwrap(); // err: pending reply channel closed
        if let Some(Reply::Ping) = rep {
            _ = self.routes.update(dst);
            Some(())
        } else {
            self.routes.remove(&dst.id);
            None
        }
    }

    pub fn store(&self, dst: NodeInfo, k: &Key, v: &str) -> Option<()> {
        let rep = self.store_raw(dst.clone(), &k, &v).recv().unwrap(); // err: pending reply channel closed
        if let Some(Reply::Ping) = rep {
            self.update_table(dst);
            Some(())
        } else {
            self.routes.remove(&dst.id);
            None
        }
    }

    pub fn find_node(&self, dst: NodeInfo, id: &Key) -> Option<Vec<NodeAndDistance>> {
        let rep = self.find_node_raw(dst.clone(), id).recv().unwrap(); // err: pending reply channel closed
        if let Some(Reply::FindNode(entries)) = rep {
            self.update_table(dst);
            Some(entries)
        } else {
            self.routes.remove(&dst.id);
            None
        }
    }

    pub fn find_value(&self, dst: NodeInfo, k: &Key) -> Option<FindValueResult> {
        let rep = self.find_value_raw(dst.clone(), k).recv().unwrap(); // err: pending reply channel closed
        if let Some(Reply::FindValue(res)) = rep {
            self.update_table(dst);
            Some(res)
        } else {
            self.routes.remove(&dst.id);
            None
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
            for &NodeAndDistance(ref node_info, _) in &queries {
                let ni = node_info.clone();
                let node = self.clone();
                let id = id.clone();
                joins.push(thread::spawn(move || node.find_node(ni.clone(), &id)));
            }
            for j in joins {
                results.push(j.join().unwrap());
            }
            for (res, query) in results.into_iter().zip(queries) {
                if let Some(entries) = res {
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

    pub fn lookup_value(&self, k: &Key) -> (Option<String>, Vec<NodeAndDistance>) {
        let mut queried = HashSet::new();
        let mut nodes_distances = HashSet::new();

        // Add the closest nodes we know to our queue of nodes to query
        let mut to_query = self.routes.closest_nodes(k, K_PARAM);

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
            for &NodeAndDistance(ref ni, _) in &queries {
                let k = k.to_owned();
                let ni = ni.clone();
                let node = self.clone();
                joins.push(thread::spawn(move || node.find_value(ni.clone(), &k)));
            }
            for j in joins {
                results.push(j.join().unwrap());
            }
            for (res, query) in results.into_iter().zip(queries) {
                if let Some(fvres) = res {
                    match fvres {
                        FindValueResult::Nodes(entries) => {
                            nodes_distances.insert(query);
                            for entry in entries {
                                if queried.insert(entry.clone()) {
                                    to_query.push(entry);
                                }
                            }
                        }
                        FindValueResult::Value(val) => {
                            let mut nodes_distances =
                                nodes_distances.into_iter().collect::<Vec<_>>();
                            nodes_distances.sort_by(|a, b| a.1.cmp(&b.1));
                            nodes_distances.truncate(K_PARAM);
                            return (Some(val), nodes_distances);
                        }
                    }
                }
            }
        }

        let mut nodes_distances = nodes_distances.into_iter().collect::<Vec<_>>();
        nodes_distances.sort_by(|a, b| a.1.cmp(&b.1));
        nodes_distances.truncate(K_PARAM);

        (None, nodes_distances)
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

        let (v_opt, mut nodes) = self.lookup_value(k);
        v_opt.map(|v| {
            if let Some(NodeAndDistance(store_target, _)) = nodes.pop() {
                self.store(store_target, &k, &v);
            } else {
                self.store(self.node_info.clone(), k, &v);
            }
            v
        })
    }

    fn update_table(&self, dst: NodeInfo) {
        if let Err(err) = self.routes.update(dst) {
            for node in err.nodes {
                if let None = self.ping_discard(node) {
                    break;
                }
            }

            // discard dst if there is still no room after pinging whole K-Bucket
            _ = self.routes.update(err.node_info);
        }
    }

    pub fn print_routes(&self) {
        self.routes.print();
    }
}
