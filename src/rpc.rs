use dryoc::dryocbox::protected::LockedKeyPair;
use dryoc::dryocbox::{Nonce, PublicKey, VecBox};
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
use crate::session::SessionBox;
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
    pub req_id: RequestId,
    pub src: NodeInfo,
    pub req: Request,
}

#[derive(Clone)]
pub(crate) struct Rpc {
    socket: Arc<UdpSocket>,
    pending: Arc<Mutex<HashMap<RequestId, tokio::sync::oneshot::Sender<Reply>>>>,
    session_box: Arc<SessionBox>,
    key_pair: Arc<LockedKeyPair>,
}

#[derive(Debug, thiserror::Error)]
pub enum SendMsgError {
    #[error("can't serialize message: {0}")]
    CantSerializeMsg(#[from] rmp_serde::encode::Error),
    #[error("can't encrypt message: {0}")]
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
        key_pair: LockedKeyPair,
    ) -> Result<Rpc, InitRpcError> {
        let socket = UdpSocket::bind(addr).await?;

        let rpc = Rpc {
            key_pair: Arc::new(key_pair),
            socket: Arc::new(socket),
            pending: Arc::new(Mutex::new(HashMap::new())),
            session_box: Arc::new(SessionBox::new(
                Duration::from_secs(60),
                Duration::from_secs(30),
            )),
        };

        let rpc_clone = rpc.clone();
        tokio::spawn(rpc.message_recv(tx));

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
                }
            }
        });
    }

    #[inline]
    pub async fn reply(
        &self,
        req_id: RequestId,
        dst: &NodeInfo,
        rep: Reply,
    ) -> Result<(), SendMsgError> {
        let rep_rmsg = RpcMessage {
            req_id,
            msg: Message::Reply(rep),
        };

        self.send_msg(&rep_rmsg, dst).await
    }

    /// Sends a message
    async fn send_msg(&self, rpc_msg: &RpcMessage, dst: &NodeInfo) -> Result<(), SendMsgError> {
        let dst_key = &dst.id;

        let message = rmp_serde::encode::to_vec(rpc_msg)?;
        let nonce = Nonce::gen();

        let encrypted_box = match self
            .session_box
            .get_or_generate_session_key(dst_key.as_array(), &self.key_pair.secret_key)
            .await
        {
            Ok(session_key) => VecBox::precalc_encrypt_to_vecbox(&message, &nonce, &session_key)
                .map_err(SendMsgError::CantEncryptMsg)?,

            Err(err) => {
                error!("fallback to public key encryption: {}", err);

                VecBox::encrypt_to_vecbox(
                    &message,
                    &nonce,
                    dst_key.into(),
                    &self.key_pair.secret_key,
                )
                .map_err(SendMsgError::CantEncryptMsg)?
            }
        };

        let payload = rmp_serde::to_vec(&EncryptedPayload {
            src_pubkey: PublicKey::from(<[u8; KEY_LEN]>::from(DHTKey::from(
                *self.key_pair.public_key.as_array(),
            ))),
            nonce,
            ciphertext: encrypted_box,
        })
        .map_err(SendMsgError::CantSerializeMsg)?;

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

        self.send_msg(&rmsg, dst).await?;

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

    async fn message_recv(self, tx: Sender<ReqContext>) {
        let mut buf = [0u8; MESSAGE_LEN];
        loop {
            let (len, src_addr) = match self.socket.recv_from(&mut buf).await {
                Ok(node_info) => node_info,
                Err(err) => {
                    error!("failed to receive datagram from a socket: {}", err);
                    continue;
                }
            };

            let payload: EncryptedPayload = match rmp_serde::from_slice(&buf[..len]) {
                Ok(p) => p,
                Err(err) => {
                    warn!("message received, but cannot be parsed: {}", err);
                    continue;
                }
            };

            let plaintext = match self
                .session_box
                .get_or_generate_session_key(&payload.src_pubkey, &self.key_pair.secret_key)
                .await
            {
                Ok(session_key) => match payload
                    .ciphertext
                    .precalc_decrypt_to_vec(&payload.nonce, &session_key)
                {
                    Ok(plaintext) => plaintext,
                    Err(err) => {
                        warn!("message received, but cannot be decrypted: {}", err);
                        continue;
                    }
                },
                Err(err) => {
                    error!("fallback to public key encryption: {}", err);

                    match payload.ciphertext.decrypt_to_vec(
                        &payload.nonce,
                        &payload.src_pubkey,
                        &self.key_pair.secret_key,
                    ) {
                        Ok(plaintext) => plaintext,
                        Err(err) => {
                            warn!("message received, but cannot be decrypted: {}", err);
                            continue;
                        }
                    }
                }
            };

            let rpc_msg: RpcMessage = match rmp_serde::from_slice(&plaintext) {
                Ok(rmsg) => rmsg,
                Err(err) => {
                    warn!("message decrypted, but cannot be parsed: {}", err);
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
                        req,
                    };
                    if tx.send(req_handle).await.is_err() {
                        info!("Closing channel, since receiver is dead.");
                        break;
                    }
                }
                Message::Reply(rep) => {
                    self.clone().handle_rep(rpc_msg.req_id, rep).await;
                }
            }
        }
    }
}
