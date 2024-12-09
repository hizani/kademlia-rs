use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::str;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::kademlia::{KademliaError, Result};
use crate::{
    kademlia::{Reply, Request},
    routing::NodeInfo,
    Key, MESSAGE_LEN, TIMEOUT,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RpcMessage {
    token: Key,
    src: NodeInfo,
    dst: NodeInfo,
    msg: Message,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum Message {
    Kill,
    Request(Request),
    Reply(Reply),
}

pub(crate) struct ReqHandle {
    token: Key,
    src: NodeInfo,
    req: Request,
    rpc: Rpc,
}

impl ReqHandle {
    pub fn get_req(&self) -> &Request {
        &self.req
    }
    pub fn get_src(&self) -> &NodeInfo {
        &self.src
    }
    pub fn reply(self, rep: Reply) -> Result<()> {
        let rep_rmsg = RpcMessage {
            token: self.token,
            src: self.rpc.node_info,
            dst: self.src.clone(),
            msg: Message::Reply(rep),
        };

        self.rpc.send_msg(&rep_rmsg, self.src.addr)
    }
}

#[derive(Clone)]
pub(crate) struct Rpc {
    socket: Arc<UdpSocket>,
    pending: Arc<Mutex<HashMap<Key, mpsc::Sender<Option<Reply>>>>>,
    node_info: NodeInfo,
}

impl Rpc {
    /// Initializes and runs RPC service
    pub fn new(socket: UdpSocket, tx: mpsc::Sender<ReqHandle>, node_info: NodeInfo) -> Rpc {
        let rpc = Rpc {
            socket: Arc::new(socket),
            pending: Arc::new(Mutex::new(HashMap::new())),
            node_info,
        };

        let rpc_clone = rpc.clone();
        thread::spawn(move || {
            let mut buf = [0u8; MESSAGE_LEN];
            loop {
                let (len, src_addr) = match rpc.socket.recv_from(&mut buf) {
                    Ok(node_info) => node_info,
                    Err(err) => {
                        error!("Failed to receive datagram from a socket: {}", err);
                        continue;
                    }
                };

                let mut rmsg: RpcMessage = match serde_json::from_slice(&buf[..len]) {
                    Ok(rmsg) => rmsg,
                    Err(err) => {
                        warn!("Message received, but cannot be parsed: {}", err);
                        continue;
                    }
                };
                rmsg.src.addr = src_addr;

                debug!("|  IN | {:?} <== {:?} ", rmsg.msg, rmsg.src.id);

                if rmsg.dst.id != rpc.node_info.id {
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

    /// Passes a reply received through the Rpc socket to the appropriate pending Receiver
    fn handle_rep(self, token: Key, rep: Reply) {
        thread::spawn(move || {
            let mut pending = self.pending.lock().unwrap();
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
    fn send_msg(&self, rmsg: &RpcMessage, addr: SocketAddr) -> Result<()> {
        let enc_msg =
            serde_json::to_vec(rmsg).or_else(|e| Err(KademliaError::CantSerializeMsg(e)))?;
        self.socket.send_to(&enc_msg, addr)?;
        debug!("| OUT | {:?} ==> {:?} ", rmsg.msg, rmsg.dst.id);
        Ok(())
    }

    /// Sends a request of data from src_info to dst_info
    pub fn send_req(&self, req: Request, dst: NodeInfo) -> Result<Reply> {
        let (tx, rx) = mpsc::channel();
        let mut pending = self.pending.lock().unwrap();
        let mut token = Key::random();
        while pending.contains_key(&token) {
            token = Key::random();
        }
        pending.insert(token.to_owned(), tx.clone());
        drop(pending);

        let rmsg = RpcMessage {
            token: token.to_owned(),
            src: self.node_info,
            dst: dst,
            msg: Message::Request(req),
        };
        self.send_msg(&rmsg, rmsg.dst.addr)?;

        let rpc = self.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(TIMEOUT));
            if let Ok(_) = tx.send(None) {
                let mut pending = rpc.pending.lock().unwrap();
                pending.remove(&token);
            }
        });

        match rx
            .recv()
            .expect("impossible state: response sender closed before response resierver")
        {
            Some(resp) => Ok(resp),
            None => Err(KademliaError::RequestTimeout),
        }
    }
}
