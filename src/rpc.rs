use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::net::{SocketAddr, UdpSocket};
use std::str;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::{
    kademlia::{Reply, Request},
    routing::NodeInfo,
    Key, MESSAGE_LEN, TIMEOUT,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcMessage {
    token: Key,
    src: NodeInfo,
    dst: NodeInfo,
    msg: Message,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    Kill,
    Request(Request),
    Reply(Reply),
}

pub struct ReqHandle {
    token: Key,
    src: NodeInfo,
    req: Request,
    rpc: Rpc<Running>,
}

impl ReqHandle {
    pub fn get_req(&self) -> &Request {
        &self.req
    }
    pub fn get_src(&self) -> &NodeInfo {
        &self.src
    }
    pub fn rep(self, rep: Reply) {
        let rep_rmsg = RpcMessage {
            token: self.token,
            src: unsafe { self.rpc.node_info.assume_init().clone() },
            dst: self.src.clone(),
            msg: Message::Reply(rep),
        };
        self.rpc.send_msg(&rep_rmsg, self.src.addr);
    }
}

#[derive(Clone)]
pub struct Uninit;
#[derive(Clone)]
pub struct Running;

#[derive(Clone)]
pub(crate) struct Rpc<State = Uninit> {
    socket: Arc<MaybeUninit<UdpSocket>>,
    pending: Arc<MaybeUninit<Mutex<HashMap<Key, Sender<Option<Reply>>>>>>,
    node_info: MaybeUninit<NodeInfo>,
    node_state: PhantomData<State>,
}

impl Rpc<Running> {
    /// Passes a reply received through the Rpc socket to the appropriate pending Receiver
    fn handle_rep(self, token: Key, rep: Reply) {
        thread::spawn(move || {
            let pending = unsafe { self.pending.assume_init() };

            let mut pending = pending.lock().unwrap();
            let send_res = match pending.get(&token) {
                Some(tx) => tx.send(Some(rep)),
                None => {
                    warn!("Unsolicited reply received, ignoring.");
                    return;
                }
            };
            if let Ok(_) = send_res {
                pending.remove(&token);
            }
        });
    }

    /// Sends a message
    fn send_msg(&self, rmsg: &RpcMessage, addr: SocketAddr) {
        let socket = unsafe { self.socket.clone().assume_init() };

        let enc_msg = serde_json::to_vec(rmsg).unwrap();
        socket.send_to(&enc_msg, addr).unwrap();
        debug!("| OUT | {:?} ==> {:?} ", rmsg.msg, rmsg.dst.id);
    }

    /// Sends a request of data from src_info to dst_info, returning a Receiver for the reply
    pub fn send_req(&self, req: Request, dst: NodeInfo) -> Receiver<Option<Reply>> {
        let pending = unsafe { self.pending.clone().assume_init() };

        let (tx, rx) = mpsc::channel();
        let mut pending = pending.lock().unwrap();
        let mut token = Key::new();
        while pending.contains_key(&token) {
            token = Key::new();
        }
        pending.insert(token.to_owned(), tx.clone());
        drop(pending);

        let rmsg = RpcMessage {
            token: token.to_owned(),
            src: unsafe { self.node_info.assume_init() },
            dst: dst,
            msg: Message::Request(req),
        };
        self.send_msg(&rmsg, rmsg.dst.addr);

        let rpc = self.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(TIMEOUT));
            if let Ok(_) = tx.send(None) {
                let pending = unsafe { rpc.pending.assume_init() };

                let mut pending = pending.lock().unwrap();
                pending.remove(&token);
            }
        });
        rx
    }
}

impl Rpc {
    /// Initializes and runs RPC service
    pub fn open(socket: UdpSocket, tx: Sender<ReqHandle>, node_info: NodeInfo) -> Rpc<Running> {
        let rpc = Rpc {
            socket: Arc::new(MaybeUninit::new(socket)),
            pending: Arc::new(MaybeUninit::new(Mutex::new(HashMap::new()))),
            node_info: MaybeUninit::new(node_info),
            node_state: PhantomData::<Running>,
        };

        let rpc_clone = rpc.clone();
        thread::spawn(move || {
            let mut buf = [0u8; MESSAGE_LEN];
            loop {
                let node_info = unsafe { rpc.node_info.assume_init() };
                let socket = unsafe { rpc.socket.clone().assume_init() };

                let (len, src_addr) = socket.recv_from(&mut buf).unwrap();
                let buf_str = String::from(str::from_utf8(&buf[..len]).unwrap());
                let mut rmsg: RpcMessage = serde_json::from_str(&buf_str).unwrap();
                rmsg.src.addr = src_addr;

                debug!("|  IN | {:?} <== {:?} ", rmsg.msg, rmsg.src.id);

                if rmsg.dst.id != node_info.id {
                    warn!("Message received, but dst id does not match this node, ignoring.");
                    continue;
                }

                match rmsg.msg {
                    Message::Kill => {
                        break;
                    }
                    Message::Request(req) => {
                        let req_handle = ReqHandle {
                            token: rmsg.token,
                            src: rmsg.src,
                            req: req,
                            rpc: rpc.clone(),
                        };
                        if let Err(_) = tx.send(req_handle) {
                            info!("Closing channel, since receiver is dead.");
                            break;
                        }
                    }
                    Message::Reply(rep) => {
                        rpc.clone().handle_rep(rmsg.token, rep);
                    }
                }
            }
        });
        rpc_clone
    }
}

impl Rpc {
    pub fn uninit() -> Rpc<Uninit> {
        Rpc {
            socket: Arc::new_uninit(),
            pending: Arc::new_uninit(),
            node_info: MaybeUninit::uninit(),
            node_state: PhantomData::<Uninit>,
        }
    }
}
