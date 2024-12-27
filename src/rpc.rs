use dryoc::dryocbox::{KeyPair, Nonce, PublicKey, VecBox};
use dryoc::types::{ByteArray, NewByteArray};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str;
use std::sync::Arc;
use tokio::io;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio::time::Duration;
use tracing::{debug, debug_span, error, info, warn};

use crate::kademlia::RequestError;
use crate::KEY_LEN;
use crate::{
    kademlia::{Reply, Request},
    routing::NodeInfo,
    DHTKey, MESSAGE_LEN, TIMEOUT,
};

type RequestId = u64;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedPayload {
    src_pubkey: PublicKey,
    nonce: Nonce,
    ciphertext: VecBox,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RpcMessage {
    msg: Message,
    req_id: RequestId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum Message {
    Request(Request),
    Reply(Reply),
}

/// ReqContext holds data needed to process an ongoing request.
pub(crate) struct ReqContext {
    req_id: RequestId,
    src: NodeInfo,
    req: Request,
}

impl ReqContext {
    #[inline]
    pub fn get_req(&self) -> Request {
        self.req.clone()
    }

    #[inline]
    pub fn get_src(&self) -> &NodeInfo {
        &self.src
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Rpc {
    socket: Arc<UdpSocket>,
    pending: Arc<Mutex<HashMap<RequestId, tokio::sync::oneshot::Sender<Reply>>>>,
    node_info: NodeInfo,
    key_pair: KeyPair,
}

#[derive(Debug, thiserror::Error)]
pub enum SendMsgError {
    #[error("can't serialize message: {}", 0)]
    CantSerializeMsg(rmp_serde::encode::Error),
    #[error("can't encrypt message: {}", 0)]
    CantEncryptMsg(dryoc::Error),
    #[error(transparent)]
    IoError(#[from] io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum InitRpcError {
    #[error(transparent)]
    FailedToBindSocket(#[from] io::Error),
}

impl Rpc {
    /// Initializes and runs RPC service
    pub async fn new(
        addr: SocketAddr,
        tx: Sender<ReqContext>,
        key_pair: KeyPair,
    ) -> Result<Rpc, InitRpcError> {
        let socket = UdpSocket::bind(addr).await?;

        let rpc = Rpc {
            node_info: NodeInfo {
                id: DHTKey::from(key_pair.public_key.as_array().clone()),
                addr: socket.local_addr()?,
            },
            key_pair,
            socket: Arc::new(socket),
            pending: Arc::new(Mutex::new(HashMap::new())),
        };

        let rpc_clone = rpc.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; MESSAGE_LEN];
            loop {
                let (len, src_addr) = match rpc.socket.recv_from(&mut buf).await {
                    Ok(node_info) => node_info,
                    Err(err) => {
                        error!("Failed to receive datagram from a socket: {}", err);
                        continue;
                    }
                };

                let payload: EncryptedPayload = match rmp_serde::from_slice(&buf[..len]) {
                    Ok(p) => p,
                    Err(err) => {
                        warn!("Message received, but cannot be parsed: {}", err);
                        continue;
                    }
                };

                let plaintext = match payload.ciphertext.decrypt_to_vec(
                    &payload.nonce,
                    &payload.src_pubkey,
                    &rpc.key_pair.secret_key,
                ) {
                    Ok(plaintext) => plaintext,
                    Err(err) => {
                        warn!("Message received, but cannot be decrypted: {}", err);
                        continue;
                    }
                };

                let rpc_msg: RpcMessage = match rmp_serde::from_slice(&plaintext) {
                    Ok(rmsg) => rmsg,
                    Err(err) => {
                        warn!("Message decrypted, but cannot be parsed: {}", err);
                        continue;
                    }
                };

                let src_dhtkey = DHTKey::from(payload.src_pubkey.as_array());

                debug_span!("incoming", src=%src_dhtkey).in_scope(|| {
                    debug!("{:?}", rpc_msg.msg);
                });

                match rpc_msg.msg {
                    Message::Request(req) => {
                        let req_handle = ReqContext {
                            req_id: rpc_msg.req_id,
                            src: NodeInfo {
                                addr: src_addr,
                                id: src_dhtkey,
                            },
                            req: req,
                        };
                        if let Err(_) = tx.send(req_handle).await {
                            info!("Closing channel, since receiver is dead.");
                            break;
                        }
                    }
                    Message::Reply(rep) => {
                        rpc.clone().handle_rep(rpc_msg.req_id, rep).await;
                    }
                }
            }
        });

        Ok(rpc_clone)
    }

    pub fn get_address(&self) -> Option<SocketAddr> {
        self.socket.local_addr().ok()
    }

    /// Passes a reply received through the Rpc socket to the appropriate pending Receiver
    async fn handle_rep(self, req_id: RequestId, rep: Reply) {
        tokio::spawn(async move {
            match self.pending.lock().await.remove(&req_id) {
                Some(tx) => _ = tx.send(rep),
                None => {
                    warn!("Unsolicited reply received, ignoring.");
                    return;
                }
            };
        });
    }

    #[inline]
    pub async fn reply(&self, context: ReqContext, rep: Reply) -> Result<(), SendMsgError> {
        let rep_rmsg = RpcMessage {
            req_id: context.req_id,
            msg: Message::Reply(rep),
        };

        self.send_msg(rep_rmsg, context.src).await
    }

    /// Sends a message
    async fn send_msg(&self, rpc_msg: RpcMessage, dst: NodeInfo) -> Result<(), SendMsgError> {
        let message =
            rmp_serde::to_vec(&rpc_msg).or_else(|e| Err(SendMsgError::CantSerializeMsg(e)))?;

        let recipient_public_key = PublicKey::from(<[u8; KEY_LEN]>::from(dst.id));
        let nonce = Nonce::gen();

        let encrypted_box = dryoc::dryocbox::VecBox::encrypt_to_vecbox(
            &message,
            &nonce,
            &recipient_public_key,
            &self.key_pair.secret_key,
        )
        .or_else(|e| Err(SendMsgError::CantEncryptMsg(e)))?;

        let payload = rmp_serde::to_vec(&EncryptedPayload {
            src_pubkey: PublicKey::from(<[u8; KEY_LEN]>::from(self.node_info.id.clone())),
            nonce,
            ciphertext: encrypted_box,
        })
        .or_else(|e| Err(SendMsgError::CantSerializeMsg(e)))?;

        self.socket.send_to(&payload, &dst.addr).await?;

        debug!("{:?}", rpc_msg.msg);

        Ok(())
    }

    /// Sends a request of data from src_info to dst_info
    pub async fn send_req(&self, req: Request, dst: &NodeInfo) -> Result<Reply, RequestError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut pending = self.pending.lock().await;
        let mut req_id = rand::random();
        while pending.contains_key(&req_id) {
            req_id = rand::random();
        }
        pending.insert(req_id.to_owned(), tx);
        drop(pending);

        let rmsg = RpcMessage {
            req_id: req_id.to_owned(),
            msg: Message::Request(req),
        };

        self.send_msg(rmsg, dst.clone()).await?;

        let rpc = self.clone();

        match tokio::time::timeout(Duration::from_millis(TIMEOUT), rx).await {
            Ok(resp) => {
                Ok(resp.expect("impossible condition: sender has dropped without sending a value"))
            }
            Err(_) => {
                rpc.pending.lock().await.remove(&req_id);
                Err(RequestError::RequestTimeout)
            }
        }
    }
}
