use async_channel as mpmc;
use dryoc::dryocbox::{KeyPair, SecretKey};
use dryoc::types::ByteArray;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tracing::{debug, debug_span, error, info, instrument, trace, warn};

use crate::routing::ParseNodeInfoError;
use crate::rpc::{InitRpcError, SendMsgError};
use crate::KEY_LEN;
use crate::{
    routing::{NodeAndDistance, NodeInfo, RoutingTable},
    rpc::{ReqContext, Rpc},
    DHTKey, A_PARAM, K_PARAM,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    Ping,
    Store(DHTKey, String),
    FindNode(DHTKey),
    FindValue(DHTKey),
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
    key_pair: Option<KeyPair>,
}

#[derive(Clone)]
pub struct KademliaNode {
    routes: Arc<RoutingTable>,
    store: Arc<Mutex<HashMap<DHTKey, String>>>,
    rpc: Arc<Rpc>,
    local_node_info: NodeInfo,
}

#[derive(Debug, thiserror::Error)]
#[error("can't read secret key: {0}")]
pub struct ReadSecretKeyError(#[from] io::Error);

#[derive(Debug, thiserror::Error)]
pub enum ReadBootstrapError {
    #[error("can't parse node: {0}")]
    CantParseNode(#[from] ParseNodeInfoError),
    #[error("can't read bootstrap nodes: {0}")]
    IoError(#[from] io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum KademliaStartError {
    #[error("can't bind udp socket: {0}")]
    CandInitRpc(#[from] InitRpcError),
}

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("request has timed out")]
    RequestTimeout,
    #[error("received unknown reply")]
    UnknownResponse,
    #[error(transparent)]
    CantSendMsg(#[from] SendMsgError),
}

pub type Result<T> = core::result::Result<T, RequestError>;

impl KademliaBuilder {
    /// Sets a keypair.
    pub fn keypair(&mut self, keys: KeyPair) -> &mut Self {
        self.key_pair = Some(keys);
        self
    }

    /// Derives a keypair from a secret key.
    pub fn keypair_from_sk(&mut self, sk: SecretKey) -> &mut Self {
        let key_pair = KeyPair::from_secret_key(sk);

        self.key_pair = Some(key_pair);
        self
    }

    /// Reads a secret key from reader and derives a keypair from it.
    pub fn keypair_read_sk(
        &mut self,
        reader: &mut impl Read,
    ) -> std::result::Result<&mut Self, ReadSecretKeyError> {
        const KEY_LEN: usize = dryoc::constants::CRYPTO_BOX_SECRETKEYBYTES;
        let mut buf = [0; KEY_LEN];

        reader.read_exact(&mut buf)?;

        let sk = SecretKey::from(buf);
        let key_pair = KeyPair::from_secret_key(sk);

        self.key_pair = Some(key_pair);
        Ok(self)
    }

    pub fn address(&mut self, address: IpAddr) -> &mut Self {
        self.address = Some(address);
        self
    }

    pub fn port(&mut self, port: u16) -> &mut Self {
        self.port = port;
        self
    }

    pub fn bootstrap(&mut self, nodes: Vec<NodeInfo>) -> &mut Self {
        self.bootstrap_nodes = Some(nodes);
        self
    }

    /// Read bootstrap nodes from reader.
    pub fn bootstrap_read(
        &mut self,
        reader: &mut impl Read,
    ) -> std::result::Result<&mut Self, ReadBootstrapError> {
        const BUFLEN: usize = 47 + KEY_LEN * 2;
        let mut buf = Vec::with_capacity(BUFLEN);
        let mut nodes = Vec::new();

        for byte in reader.bytes() {
            match byte {
                Ok(byte) => {
                    if byte == b'\n' {
                        let trim = buf.trim_ascii_end();

                        nodes.push(NodeInfo::try_from(trim)?);
                        buf.clear();
                        continue;
                    }

                    buf.push(byte);
                }
                Err(e) => Err(e)?,
            }
        }

        nodes.push(NodeInfo::try_from(buf.as_slice())?);

        self.bootstrap_nodes = Some(nodes);
        Ok(self)
    }

    /// Builds and starts a Kademlia node.
    pub async fn start(&mut self) -> std::result::Result<KademliaNode, KademliaStartError> {
        let address = if let Some(address) = self.address {
            address
        } else {
            IpAddr::V4(Ipv4Addr::from_bits(0))
        };

        let key_pair = if let Some(pair) = &self.key_pair {
            pair.clone()
        } else {
            KeyPair::gen()
        };

        let local_key = DHTKey::from(key_pair.public_key.as_array().clone());

        let (req_tx, req_rx) = tokio::sync::mpsc::channel(1024);
        let rpc = Rpc::new(SocketAddr::new(address, self.port), req_tx, key_pair).await?;

        let rpc_address = rpc.get_address().unwrap();

        info!("new node created {} {}", local_key, rpc_address);

        let node = KademliaNode {
            routes: Arc::new(RoutingTable::new(local_key.clone())),
            store: Arc::new(Mutex::new(HashMap::new())),
            rpc: Arc::new(rpc),
            local_node_info: NodeInfo {
                id: local_key.clone(),
                addr: rpc_address,
            },
        };

        if let Some(bootstrap_nodes) = &self.bootstrap_nodes {
            node.ping_slice(bootstrap_nodes, true).await;
        }

        node.clone().start_req_handler(req_rx);

        Ok(node)
    }
}

/// Alias to [Kademlia::start]
#[inline]
pub async fn start() -> std::result::Result<KademliaNode, KademliaStartError> {
    KademliaNode::start().await
}

impl KademliaNode {
    /// Starts Kademlia node with 0.0.0.0:0 socket and a random DHT key.
    pub async fn start() -> std::result::Result<Self, KademliaStartError> {
        KademliaBuilder::default().start().await
    }

    pub fn new() -> KademliaBuilder {
        KademliaBuilder::default()
    }

    fn start_req_handler(self, mut rx: mpsc::Receiver<ReqContext>) {
        tokio::spawn(async move {
            while let Some(req_context) = rx.recv().await {
                let node = self.clone();

                // TODO: add something like rate limiter to prevent DDOS attack.
                tokio::spawn(async move {
                    let span = debug_span!("reply", dst=%req_context.src.id);
                    let span_guard = span.enter();
                    let rep = node.handle_req(req_context.req, &req_context.src).await;
                    if let Err(e) = node
                        .rpc
                        .reply(req_context.req_id, &req_context.src, rep)
                        .await
                    {
                        error!("reply send error: {}", e)
                    }
                    drop(span_guard)
                });
            }

            debug!("channel closed, since sender is dead.");
        });
    }

    async fn handle_req(&self, req: Request, src: &NodeInfo) -> Reply {
        self.append_with_refresh_no_error(src.clone()).await;

        match req {
            Request::Ping => Reply::Ping,
            Request::Store(k, v) => {
                self.store.lock().await.insert(k, v);

                Reply::Store
            }
            Request::FindNode(id) => Reply::FindNode(self.routes.closest_nodes(&id, K_PARAM).await),
            Request::FindValue(id) => {
                let lookup_res = self.store.lock().await.remove(&id);

                match lookup_res {
                    Some(v) => Reply::FindValue(FindValueResult::Value(v)),
                    None => Reply::FindValue(FindValueResult::Nodes(
                        self.routes.closest_nodes(&id, K_PARAM).await,
                    )),
                }
            }
        }
    }

    #[instrument(skip(self))]
    async fn ping_raw(&self, dst: &NodeInfo) -> Result<Reply> {
        match self.rpc.send_req(Request::Ping, dst).await {
            Err(err) => {
                if let RequestError::RequestTimeout = err {
                    debug!("ping req timeout");
                    self.routes.remove_node(&dst.id).await;
                } else {
                    error!("ping req error: {}", err);
                }

                Err(err)
            }
            ok => ok,
        }
    }

    #[instrument(skip(self, v))]
    async fn store_raw(&self, dst: &NodeInfo, v: &str) -> Result<Reply> {
        let k = DHTKey::hash(v.as_bytes());

        match self
            .rpc
            .send_req(Request::Store(k.to_owned(), v.to_owned()), dst)
            .await
        {
            Err(err) => {
                if let RequestError::RequestTimeout = err {
                    debug!("store req timeout");
                    self.routes.remove_node(&dst.id).await;
                } else {
                    error!("store req error: {}", err);
                }

                Err(err)
            }
            ok => ok,
        }
    }

    #[instrument(skip(self))]
    async fn find_node_raw(&self, dst: &NodeInfo, key: &DHTKey) -> Result<Reply> {
        match self.rpc.send_req(Request::FindNode(key.clone()), dst).await {
            Err(err) => {
                if let RequestError::RequestTimeout = err {
                    debug!("find node req timeout");
                    self.routes.remove_node(&dst.id).await;
                } else {
                    error!("find node req error: {}", err);
                }

                Err(err)
            }
            ok => ok,
        }
    }

    #[instrument(skip(self))]
    async fn find_value_raw(&self, dst: &NodeInfo, k: &DHTKey) -> Result<Reply> {
        match self.rpc.send_req(Request::FindValue(k.clone()), dst).await {
            Err(err) => {
                if let RequestError::RequestTimeout = err {
                    debug!("find value req timeout");
                    self.routes.remove_node(&dst.id).await;
                } else {
                    error!("find value req error: {}", err);
                }

                Err(err)
            }
            ok => ok,
        }
    }

    /// Pings nodes from `dsts` and return the count of successful pings.
    ///
    /// Doesn't try to clean K-Bucket if there is no room for dst insertion if
    /// `discard` is true.
    pub async fn ping_slice(&self, dsts: &[NodeInfo], discard: bool) -> u32 {
        if dsts.is_empty() {
            return 0;
        }

        if dsts.len() == 1 {
            if let Ok(_) = self.ping_raw(&dsts[0]).await {
                self.append_with_refresh_no_error(dsts[0].clone()).await;
                return 1;
            }

            return 0;
        }

        let mut successful_pings = 0;

        let (jobs_sender, jobs_receiver) = mpmc::unbounded();
        let (results_sender, mut results_receiver) = mpsc::unbounded_channel();

        for _ in 0..A_PARAM {
            let jobs: mpmc::Receiver<NodeInfo> = jobs_receiver.clone();
            let results = results_sender.clone();
            let node = self.clone();
            tokio::spawn(async move {
                while let Ok(job) = jobs.recv().await {
                    trace!("ping_slice: new job: {:?}", job);

                    let job = job.clone();

                    let result = node.ping_raw(&job).await;

                    results
                        .send((job, result))
                        .expect("unreachable state: job receiver closed before the job sender");
                }

                drop(results)
            });
        }

        for dst in dsts {
            jobs_sender
                .send(dst.clone())
                .await
                .expect("unreachable state: job receiver closed before the job sender");
        }

        drop(jobs_sender);

        while let Some(result) = results_receiver.recv().await {
            trace!("ping_slice: new result: {:?}", result);
            let (pinged_node, result) = result;
            if let Ok(_) = result {
                if discard {
                    _ = self.routes.update(pinged_node, true);
                } else {
                    self.append_with_refresh_no_error(pinged_node).await;
                }

                successful_pings += 1;
                continue;
            }

            warn!("can't ping_slice a node: {pinged_node}")
        }

        successful_pings
    }

    /// Pings `dst` and saves it to the routing table if it is connectable.
    ///
    /// Doesn't try to clean K-Bucket if there is no room for dst insertion if
    /// `discard` is true.
    pub async fn ping(&self, dst: &NodeInfo, discard: bool) -> Result<()> {
        if let Err(e) = self.ping_raw(&dst).await {
            Err(e)
        } else {
            if discard {
                _ = self.routes.update(dst.clone(), true);
            } else {
                self.append_with_refresh_no_error(dst.clone()).await;
            }

            Ok(())
        }
    }

    /// Sends [Store](Request::Store) request to a `dst` node.
    ///
    /// The `dst` node must store `v` on request arrival.
    pub async fn store(&self, dst: &NodeInfo, v: &str) -> Result<()> {
        if let Err(e) = self.store_raw(dst, v).await {
            Err(e)
        } else {
            self.append_with_refresh_no_error(dst.clone()).await;
            Ok(())
        }
    }

    /// Sends [FindNode](Request::FindNode) request to a `dst` node.
    ///
    /// The `dst` node must reply with [NodeInfo](NodeInfo) of `id` or return a list
    /// of [K_PARAM] known nodes closest to `id`.
    pub async fn find_node(&self, dst: &NodeInfo, id: &DHTKey) -> Result<Vec<NodeAndDistance>> {
        match self.find_node_raw(dst, id).await {
            Err(e) => Err(e),
            Ok(reply) => {
                self.append_with_refresh_no_error(dst.clone()).await;

                if let Reply::FindNode(nodes) = reply {
                    Ok(nodes)
                } else {
                    warn!("wrong successful reply: {:#?}", reply);
                    Ok(vec![])
                }
            }
        }
    }

    /// Sends [FindValue](Request::FindValue) request to a `dst` node.
    ///
    /// The `dst` node must reply with [NodeInfo](NodeInfo) of a node keeping
    /// the value with `id` key or return a list of [K_PARAM] known nodes closest
    /// to `id`.
    pub async fn find_value(&self, dst: &NodeInfo, id: &DHTKey) -> Result<FindValueResult> {
        match self.find_value_raw(dst, id).await {
            Err(e) => Err(e),
            Ok(reply) => {
                self.append_with_refresh_no_error(dst.clone()).await;

                if let Reply::FindValue(result) = reply {
                    Ok(result)
                } else {
                    warn!("wrong successful reply: {:#?}", reply);
                    Err(RequestError::UnknownResponse)
                }
            }
        }
    }

    /// Finds at most [K_PARAM] closest nodes to the id.
    ///
    /// Returns [None] if there are no connectable nodes in the routing table.
    pub async fn lookup_nodes(&self, id: &DHTKey) -> Vec<NodeAndDistance> {
        let closest_local_nodes = self.routes.closest_nodes(id, K_PARAM).await;
        if closest_local_nodes.is_empty() {
            return Vec::new();
        }

        let mut closest_nodes = Vec::with_capacity(K_PARAM + 1);

        let (jobs_sender, jobs_receiver) = mpmc::unbounded();
        let (results_sender, mut results_receiver) = mpsc::unbounded_channel();

        for _ in 0..A_PARAM {
            let id = id.clone();
            let jobs = jobs_receiver.clone();
            let results = results_sender.clone();
            let node = self.clone();
            tokio::spawn(async move {
                while let Ok(job) = jobs.recv().await {
                    trace!("new job: {:?}", job);

                    let node_info: NodeInfo = job;

                    let result = node.find_node(&node_info, &id).await;

                    if let Err(e) = results.send((node_info, result)) {
                        trace!("can't send lookup_node result: {}", e);
                    }
                }
            });
        }

        let mut jobs_counter = closest_local_nodes.len();
        let mut queried_nodes = HashSet::new();

        queried_nodes.insert(self.local_node_info.clone());

        for node in closest_local_nodes {
            jobs_sender
                .send(node.0)
                .await
                .expect("unreachable state: job receiver closed before the job sender");
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

        while let Some(job_result) = results_receiver.recv().await {
            trace!("new lookup node job result: {:?}", job_result);
            jobs_counter -= 1;

            // source is used only for nodes taken from the local routing table.
            let (source, result) = job_result;
            match result {
                Ok(result) => {
                    if let None = queried_nodes.get(&source) {
                        let source_distance = self.local_node_info.id.distance(&source.id);

                        insert_to_closest_nodes(NodeAndDistance(source.clone(), source_distance));
                    }

                    for node in result {
                        if let None = queried_nodes.get(&node.0) {
                            insert_to_closest_nodes(node.clone());

                            jobs_counter += 1;

                            jobs_sender.send(node.0.clone()).await.expect(
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

    /// Recursively looks for a value with `id` key through DHT.
    ///
    /// Returns [None] if the value was not found.
    pub async fn lookup_value(&self, id: &DHTKey) -> Option<String> {
        let closest_nodes = self.routes.closest_nodes(id, K_PARAM).await;
        if closest_nodes.is_empty() {
            return None;
        }

        let (jobs_sender, jobs_receiver) = mpmc::unbounded();
        let (results_sender, mut results_receiver) = mpsc::unbounded_channel();

        for _ in 0..A_PARAM {
            let id = id.clone();
            let jobs = jobs_receiver.clone();
            let results = results_sender.clone();
            let node = self.clone();
            tokio::spawn(async move {
                while let Ok(job) = jobs.recv().await {
                    trace!("new job: {:?}", job);

                    let node_info = job;

                    if let Err(e) = results.send(node.find_value(&node_info, &id).await) {
                        trace!("can't send lookup_value result from: {}", e);
                    }
                }
            });
        }

        let mut jobs_counter = closest_nodes.len();
        let mut queried_nodes = HashSet::new();

        queried_nodes.insert(self.local_node_info.clone());

        for node in closest_nodes {
            jobs_sender
                .send(node.0.clone())
                .await
                .expect("unreachable state: job receiver closed before the job sender");

            queried_nodes.insert(node.0);
        }

        while let Some(job_result) = results_receiver.recv().await {
            trace!("new job result: {:?}", job_result);
            jobs_counter -= 1;
            match job_result {
                Ok(result) => match result {
                    FindValueResult::Nodes(nodes) => {
                        for node in nodes {
                            if let None = queried_nodes.get(&node.0) {
                                jobs_counter += 1;

                                jobs_sender.send(node.0.clone()).await.expect(
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

    /// Puts a value in DHT.
    ///
    /// Also saves the value in the local storage if there are less than
    /// [K_PARAM] nodes in the routing table.
    pub async fn put(&self, v: &str) {
        let k = DHTKey::hash(v.as_bytes());
        debug!("putting key: {}", k);

        let candidates = self.routes.closest_nodes(&k, K_PARAM).await;

        if candidates.len() < K_PARAM {
            self.store.lock().await.insert(k.to_owned(), v.to_owned());
        }

        for NodeAndDistance(node_info, _) in candidates {
            let node = self.clone();
            let v = v.to_owned();
            tokio::spawn(async move { _ = node.store(&node_info, &v).await });
        }
    }

    /// Gets a value with `id` key.
    ///
    /// Recursively looks for the value through DHT if the value is not present
    /// in the local storage.
    ///
    /// Returns [None] if the value was not found.
    pub async fn get(&self, k: &DHTKey) -> Option<String> {
        debug!("getting key: {}", k);

        if let Some(v) = self.store.lock().await.get(&k) {
            return Some(v.to_owned());
        }

        let value = self.lookup_value(k).await;
        if let Some(v) = value {
            if let Some(closest_node) = self.routes.closest_nodes(k, 1).await.pop() {
                if let Err(e) = self.store(&closest_node.0, &v).await {
                    warn!(
                        "Can't store value {} in node {} {}: {}",
                        k, closest_node.0.addr, closest_node.0.id, e
                    );
                }
            }
            self.store.lock().await.insert(k.clone(), v.clone());
            Some(v)
        } else {
            None
        }
    }

    /// Appends a node into the routing table and evicts non-responsive nodes
    /// from the bucket if there is no room for it.
    pub async fn append_with_refresh(&self, node_info: NodeInfo) -> Result<()> {
        if let Err(update_err) = self.routes.update(node_info, true).await {
            for node in update_err.nodes {
                if let Err(ping_err) = Box::pin(self.ping(&node, true)).await {
                    return Err(ping_err);
                }
            }

            // discard dst if there is still no room after pinging whole K-Bucket
            _ = self.routes.update(update_err.node_info, true);
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn append_with_refresh_no_error(&self, node_info: NodeInfo) {
        if let Err(e) = self.append_with_refresh(node_info).await {
            warn!("can't update routing table: {}", e)
        }
    }

    pub fn print_routes(&self) {
        self.routes.print();
    }
}
