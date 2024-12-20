use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::mpmc::Receiver;
use std::sync::{mpmc, mpsc};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::routing::ParseNodeInfoError;
use crate::KEY_LEN;
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

#[derive(Clone)]
pub struct Kademlia {
    routes: Arc<RoutingTable>,
    store: Arc<Mutex<HashMap<Key, String>>>,
    rpc: Arc<Rpc>,
}

#[derive(Debug, thiserror::Error)]
pub enum KademliaStartError {
    #[error("can't bind udp socket: {}", 0)]
    CantBindUdpSocket(io::Error),
    #[error(transparent)]
    CantBootstrap(#[from] ParseNodeInfoError),
}

#[derive(Debug, thiserror::Error)]
pub enum KademliaError {
    #[error("request has timed out")]
    RequestTimeout,
    #[error("received unknown reply")]
    UnknownResponse,
    #[error("can't serialize message: {}", 0)]
    CantSerializeMsg(serde_json::Error),
    #[error("can't bind udp socket: {}", 0)]
    StartError(#[from] KademliaStartError),
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

    pub fn bootstrap_from_reader<'a>(&'a mut self, reader: impl Read) -> Result<&'a mut Self> {
        const BUFLEN: usize = 47 + KEY_LEN * 2;
        let mut buf = Vec::with_capacity(BUFLEN);
        let mut nodes = Vec::new();

        for byte in reader.bytes() {
            match byte {
                Ok(byte) => {
                    if byte == b'\n' {
                        let trim = buf.trim_ascii_end();

                        nodes.push(
                            NodeInfo::try_from(trim)
                                .or_else(|e| Err(KademliaStartError::CantBootstrap(e)))?,
                        );
                        buf.clear();
                        continue;
                    }

                    buf.push(byte);
                }
                Err(_) => {
                    nodes.push(
                        NodeInfo::try_from(buf.as_slice())
                            .or_else(|e| Err(KademliaStartError::CantBootstrap(e)))?,
                    );
                }
            }
        }

        self.bootstrap_nodes = Some(nodes);
        Ok(self)
    }

    pub fn start(&mut self) -> Result<Kademlia> {
        let address = if let Some(address) = self.address {
            address
        } else {
            IpAddr::V4(Ipv4Addr::from_bits(0))
        };

        let key = if let Some(key) = self.key {
            key
        } else {
            Key::random()
        };

        let socket = UdpSocket::bind(SocketAddr::new(address, self.port))
            .or_else(|err| Err(KademliaStartError::CantBindUdpSocket(err)))?;

        let node_info = NodeInfo {
            addr: socket
                .local_addr()
                .or_else(|err| Err(KademliaStartError::CantBindUdpSocket(err)))?,
            id: key,
        };

        let (req_tx, req_rx) = mpsc::channel();
        let rpc = Rpc::new(socket, req_tx, node_info);

        let node = Kademlia {
            routes: Arc::new(RoutingTable::new(node_info.clone())),
            store: Arc::new(Mutex::new(HashMap::new())),
            rpc: Arc::new(rpc),
        };

        info!("new node created {} {}", &node_info.addr, &node_info.id);

        if let Some(bootstrap_nodes) = &mut self.bootstrap_nodes {
            node.ping_slice(&bootstrap_nodes);
        }

        node.clone().start_req_handler(req_rx);

        Ok(node)
    }
}

// TODO: use async (tokio?) instead of bare threads.

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
                        error!("reply send error: {}", e)
                    }
                });
            }

            info!("channel closed, since sender is dead.");
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

    /// TODO: Maybe extract self.routes.remove from raw fns to the higher ones?
    pub fn ping_raw(&self, dst: NodeInfo) -> Result<Reply> {
        self.rpc.send_req(Request::Ping, dst).map_err(|err| {
            if let KademliaError::RequestTimeout = err {
                debug!("DST {} {}: Ping req timeout", dst.addr, dst.id);
                self.routes.remove(&dst.id);
            } else {
                error!("DST {} {}: Ping req error: {}", dst.addr, dst.id, err);
            }

            err
        })
    }

    pub fn store_raw(&self, dst: NodeInfo, v: &str) -> Result<Reply> {
        let k = Key::hash(v.as_bytes());

        self.rpc
            .send_req(Request::Store(k.to_owned(), v.to_owned()), dst)
            .map_err(|err| {
                if let KademliaError::RequestTimeout = err {
                    debug!("DST {} {}: Store req timeout", dst.addr, dst.id);
                    self.routes.remove(&dst.id);
                } else {
                    error!("DST {} {}: Store req error: {}", dst.addr, dst.id, err);
                }

                err
            })
    }

    pub fn find_node_raw(&self, dst: NodeInfo, key: Key) -> Result<Reply> {
        self.rpc
            .send_req(Request::FindNode(key), dst)
            .map_err(|err| {
                if let KademliaError::RequestTimeout = err {
                    debug!("DST {} {}: Find node req timeout", dst.addr, dst.id);
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
                    debug!("DST {} {}: Find  value req timeout", dst.addr, dst.id);
                    self.routes.remove(&dst.id);
                } else {
                    error!("DST {} {}: Find value req error: {}", dst.addr, dst.id, err);
                }

                err
            })
    }

    /// Returns [None] if at least one destination didn't respond.
    pub fn ping_slice(&self, dsts: &[NodeInfo]) -> Option<()> {
        if dsts.is_empty() {
            return None;
        }

        if dsts.len() == 1 {
            if let Ok(_) = self.ping_raw(dsts[0].clone()) {
                self.append_with_refresh_no_error(dsts[0]);
                return Some(());
            }

            return None;
        }

        let mut successful_pings = 0;

        let (jobs_sender, jobs_receiver) = mpmc::channel();
        let (results_sender, results_receiver) = mpsc::channel();

        for _ in 0..A_PARAM {
            let jobs: Receiver<NodeInfo> = jobs_receiver.clone();
            let results = results_sender.clone();
            let node = self.clone();
            thread::spawn(move || {
                for job in jobs {
                    trace!("ping_slice: new job: {:?}", job);

                    let job = job.clone();

                    results
                        .send((job, node.ping_raw(job)))
                        .expect("unreachable state: job receiver closed before the job sender");
                }

                drop(results)
            });
        }

        // TODO: make parallel
        for dst in dsts {
            jobs_sender
                .send(dst.clone())
                .expect("unreachable state: job receiver closed before the job sender");
        }

        drop(jobs_sender);

        for result in results_receiver {
            trace!("ping_slice: new result: {:?}", result);
            let (pinged_node, result) = result;
            if let Ok(_) = result {
                self.append_with_refresh_no_error(pinged_node);
                successful_pings += 1;
            }
        }

        if successful_pings != dsts.len() {
            None
        } else {
            Some(())
        }
    }

    /// Pings dst and saves it to the routing table if it is connectable.
    pub fn ping(&self, dst: NodeInfo) -> Result<()> {
        if let Err(e) = self.ping_raw(dst.clone()) {
            Err(e)
        } else {
            self.append_with_refresh_no_error(dst);
            Ok(())
        }
    }

    /// Pings dst and saves it to the routing table if it is connectable.
    /// Doesn't try to clean K-Bucket if there is no room for dst insertion
    pub fn ping_discard(&self, dst: NodeInfo) -> Result<()> {
        if let Err(e) = self.ping_raw(dst.clone()) {
            Err(e)
        } else {
            _ = self.routes.update(dst);
            Ok(())
        }
    }

    pub fn store(&self, dst: NodeInfo, v: &str) -> Result<()> {
        if let Err(e) = self.store_raw(dst.clone(), &v) {
            Err(e)
        } else {
            Ok(self.append_with_refresh_no_error(dst))
        }
    }

    pub fn find_node(&self, dst: NodeInfo, id: Key) -> Result<Vec<NodeAndDistance>> {
        match self.find_node_raw(dst, id) {
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

    pub fn find_value(&self, dst: NodeInfo, k: &Key) -> Result<FindValueResult> {
        match self.find_value_raw(dst.clone(), &k) {
            Err(e) => Err(e),
            Ok(reply) => {
                self.append_with_refresh_no_error(dst);

                if let Reply::FindValue(result) = reply {
                    Ok(result)
                } else {
                    Err(KademliaError::UnknownResponse)
                }
            }
        }
    }

    /// Finds at most [K_PARAM] closest nodes to the id.
    ///
    /// Returns [None] if there are no connectable nodes in the routing table.
    pub fn lookup_nodes(&self, id: &Key) -> Vec<NodeAndDistance> {
        let closest_local_nodes = self.routes.closest_nodes(id, K_PARAM);
        if closest_local_nodes.is_empty() {
            return Vec::new();
        }

        let id = id.clone();

        let mut closest_nodes = Vec::with_capacity(K_PARAM + 1);

        let (jobs_sender, jobs_receiver) = mpmc::channel();
        let (results_sender, results_receiver) = mpsc::channel();

        for _ in 0..A_PARAM {
            let jobs = jobs_receiver.clone();
            let results = results_sender.clone();
            let node = self.clone();
            thread::spawn(move || {
                for job in jobs {
                    trace!("new job: {:?}", job);

                    let node_info = job;

                    if let Err(e) = results.send((node_info, node.find_node(node_info, id))) {
                        trace!("can't send lookup_node result from {}: {}", node_info, e);
                    }
                }
            });
        }

        let mut jobs_counter = closest_local_nodes.len();
        let mut queried_nodes = HashSet::new();

        queried_nodes.insert(self.routes.get_self_node_info());

        for node in closest_local_nodes {
            jobs_sender
                .send(node.0)
                .expect("unreachable state: job receiver closed before the job sender");

            // queried_nodes.insert(node.0);
        }

        let mut insert_to_closest_nodes =
            |node_distance: NodeAndDistance| match closest_nodes.binary_search(&node_distance) {
                Err(pos) => {
                    if pos <= closest_nodes.len() {
                        closest_nodes.insert(pos, node_distance);

                        if closest_nodes.len() > K_PARAM {
                            closest_nodes.pop();
                        }
                    }
                }
                _ => unreachable!(),
            };

        for job_result in &results_receiver {
            trace!("new lookup node job result: {:?}", job_result);
            jobs_counter -= 1;

            // source is used only for nodes taken from the local routing table.
            let (source, result) = job_result;
            match result {
                Ok(result) => {
                    if let None = queried_nodes.get(&source) {
                        let source_distance =
                            self.routes.get_self_node_info().id.distance(&source.id);

                        insert_to_closest_nodes(NodeAndDistance(source, source_distance));
                    }

                    for node in result {
                        if let None = queried_nodes.get(&node.0) {
                            insert_to_closest_nodes(node.clone());

                            jobs_counter += 1;

                            jobs_sender.send(node.0).expect(
                                "unreachable state: job receiver closed before the job sender",
                            );

                            queried_nodes.insert(node.0);
                        }
                    }
                }
                _ => {}
            }

            queried_nodes.insert(source);

            if jobs_counter == 0 {
                break;
            }
        }

        closest_nodes
    }

    pub fn lookup_value(&self, id: &Key) -> Option<String> {
        let closest_nodes = self.routes.closest_nodes(id, K_PARAM);
        if closest_nodes.is_empty() {
            return None;
        }

        let id = id.clone();
        let (jobs_sender, jobs_receiver) = mpmc::channel();
        let (results_sender, results_receiver) = mpsc::channel();

        for _ in 0..A_PARAM {
            let jobs = jobs_receiver.clone();
            let results = results_sender.clone();
            let node = self.clone();
            thread::spawn(move || {
                for job in jobs {
                    trace!("new job: {:?}", job);

                    let node_info = job;

                    if let Err(e) = results.send(node.find_value(node_info, &id)) {
                        trace!("can't send lookup_value result from {}: {}", node_info, e);
                    }
                }
            });
        }

        let mut jobs_counter = closest_nodes.len();
        let mut queried_nodes = HashSet::new();

        queried_nodes.insert(self.routes.get_self_node_info());

        for node in closest_nodes {
            jobs_sender
                .send(node.0)
                .expect("unreachable state: job receiver closed before the job sender");

            queried_nodes.insert(node.0);
        }

        for job_result in &results_receiver {
            trace!("new job result: {:?}", job_result);
            jobs_counter -= 1;
            match job_result {
                Ok(result) => match result {
                    FindValueResult::Nodes(nodes) => {
                        for node in nodes {
                            if let None = queried_nodes.get(&node.0) {
                                jobs_counter += 1;

                                jobs_sender.send(node.0.clone()).expect(
                                    "unreachable state: job receiver closed before the job sender",
                                );
                                queried_nodes.insert(node.0.clone());
                            }
                        }
                    }
                    FindValueResult::Value(value) => {
                        return Some(value);
                    }
                },
                _ => {}
            }

            if jobs_counter == 0 {
                break;
            }
        }

        None
    }

    pub fn put(&self, v: &str) {
        let k = Key::hash(v.as_bytes());
        info!("key: {}", k);
        let candidates = self.routes.closest_nodes(&k, K_PARAM);

        if candidates.len() < K_PARAM {
            self.store
                .lock()
                .unwrap()
                .insert(k.to_owned(), v.to_owned());
        }

        for NodeAndDistance(node_info, _) in candidates {
            let node = self.clone();
            let v = v.to_owned();
            thread::spawn(move || {
                node.store(node_info, &v).unwrap();
            });
        }
    }

    pub fn get(&self, k: &Key) -> Option<String> {
        if let Some(v) = self.store.lock().unwrap().get(&k) {
            return Some(v.to_owned());
        }

        let value = self.lookup_value(k);
        value.map(|v| {
            if let Some(closest_node) = self.routes.closest_nodes(k, 1).pop() {
                if let Err(e) = self.store(closest_node.0.clone(), &v) {
                    warn!(
                        "Can't store value {} in node {} {}: {}",
                        k, closest_node.0.addr, closest_node.0.id, e
                    );
                }
            }
            self.store.lock().unwrap().insert(k.clone(), v.clone());
            v
        })
    }

    /// Appends a node into the routing table and evicts non-responsive nodes
    /// from the bucket if there is no room for it.
    pub fn append_with_refresh(&self, node_info: NodeInfo) -> Result<()> {
        if let Err(update_err) = self.routes.update(node_info) {
            for node in update_err.nodes {
                if let Err(ping_err) = self.ping_discard(node) {
                    return Err(ping_err);
                }
            }

            // discard dst if there is still no room after pinging whole K-Bucket
            _ = self.routes.update(update_err.node_info);
        }

        Ok(())
    }

    fn append_with_refresh_no_error(&self, node_info: NodeInfo) {
        if let Err(e) = self.append_with_refresh(node_info) {
            warn!("{}: Can't update routing table: {}", node_info.addr, e)
        }
    }

    pub fn print_routes(&self) {
        self.routes.print();
    }
}
