use const_hex::FromHex;
use core::str;
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, fmt::Display, net::SocketAddr, str::FromStr};
use tokio::sync::Mutex;
use tracing::{info, trace, warn};

use crate::{
    key::{DHTKey, Distance},
    K_PARAM, N_BUCKETS,
};

#[derive(Debug, thiserror::Error)]
#[error("kbucket {bucket_n} is full")]
pub struct ErrBucketIsFull {
    pub nodes: Vec<NodeInfo>,
    pub bucket_n: usize,
    pub node_info: NodeInfo,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ParseNodeInfoError(String);

#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: DHTKey,
    pub addr: SocketAddr,
}

impl TryFrom<&[u8]> for NodeInfo {
    type Error = ParseNodeInfoError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        NodeInfo::from_str(
            str::from_utf8(value).or_else(|e| Err(ParseNodeInfoError(e.to_string())))?,
        )
    }
}

impl FromStr for NodeInfo {
    type Err = ParseNodeInfoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split_whitespace();
        let socket_str = split
            .next()
            .ok_or(ParseNodeInfoError("string is empty".to_owned()))?;
        let key_str = split
            .next()
            .ok_or(ParseNodeInfoError("node key is not specified".to_owned()))?;

        Ok(NodeInfo {
            addr: SocketAddr::from_str(socket_str)
                .or_else(|e| Err(ParseNodeInfoError(e.to_string())))?,
            id: DHTKey::from_hex(key_str).or_else(|e| Err(ParseNodeInfoError(e.to_string())))?,
        })
    }
}

impl Display for NodeInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.addr, self.id)
    }
}

#[derive(Debug)]
struct Kbucket {
    nodes: Mutex<Vec<NodeInfo>>,
    max_size: usize,
}

#[derive(Debug)]
pub struct RoutingTable {
    local_key: DHTKey,
    buckets: Vec<Kbucket>,
}

#[derive(Eq, Hash, Clone, Debug, Serialize, Deserialize)]
pub struct NodeAndDistance(pub NodeInfo, pub Distance);

impl PartialEq for NodeAndDistance {
    fn eq(&self, other: &NodeAndDistance) -> bool {
        self.1.eq(&other.1)
    }
}

impl PartialOrd for NodeAndDistance {
    fn partial_cmp(&self, other: &NodeAndDistance) -> Option<Ordering> {
        Some(other.1.cmp(&self.1))
    }
}

impl Ord for NodeAndDistance {
    fn cmp(&self, other: &NodeAndDistance) -> Ordering {
        other.1.cmp(&self.1)
    }
}

impl RoutingTable {
    pub fn new(local_key: DHTKey) -> RoutingTable {
        let mut buckets = Vec::with_capacity(N_BUCKETS);
        for bucket_n in (0..N_BUCKETS).rev() {
            let max_size = if let Some(possible_bucket_len) = 2_usize.checked_pow(bucket_n as u32) {
                possible_bucket_len.min(K_PARAM)
            } else {
                K_PARAM
            };

            buckets.push(Kbucket {
                nodes: Mutex::new(Vec::with_capacity(max_size)),
                max_size,
            });

            trace!("create bucket {bucket_n} with size = {max_size}")
        }
        let routing_rable = RoutingTable { buckets, local_key };
        routing_rable
    }

    /// Update the appropriate bucket with the new node's info
    pub async fn update(&self, node_info: NodeInfo, evict: bool) -> Result<(), ErrBucketIsFull> {
        if let Some((bucket, bucket_n)) = self.get_bucket_by_key(&node_info.id) {
            let mut nodes = bucket.nodes.lock().await;

            let node_index = nodes.iter().position(|x| x.id == node_info.id);
            match node_index {
                Some(i) => {
                    let temp = nodes.remove(i);
                    nodes.push(temp);
                }
                None => {
                    if nodes.len() < bucket.max_size {
                        nodes.push(node_info);
                    } else {
                        let evict_index = if evict {
                            let distance = self.local_key.distance(&node_info.id);
                            nodes
                                .iter()
                                .position(|x| distance < self.local_key.distance(&x.id))
                        } else {
                            None
                        };

                        if let Some(evict_index) = evict_index {
                            let temp = nodes.remove(evict_index);
                            nodes.push(temp);
                            return Ok(());
                        } else {
                            return Err(ErrBucketIsFull {
                                bucket_n,
                                node_info,
                                nodes: nodes.clone(),
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Lookup the nodes closest to item in this table
    pub async fn closest_nodes(&self, item: &DHTKey, count: usize) -> Vec<NodeAndDistance> {
        if count == 0 {
            return Vec::new();
        }

        let (closest_bucket, closest_bucket_index) =
            if let Some((bucket, index)) = self.get_bucket_by_key(item) {
                (bucket, index)
            } else {
                (
                    self.buckets
                        .last()
                        .expect("impossible state: initialized routing table with no buckets"),
                    N_BUCKETS - 1,
                )
            };

        let mut closest_nodes: Vec<NodeAndDistance> = Vec::with_capacity(count);
        closest_nodes.extend(
            closest_bucket
                .nodes
                .lock()
                .await
                .iter()
                .map(|node_info| NodeAndDistance(node_info.clone(), node_info.id.distance(item))),
        );

        let mut delta = 0;

        while closest_nodes.len() < count {
            delta += 1;

            let (left_index, is_left_overflow) = closest_bucket_index.overflowing_sub(delta);
            let right_index = closest_bucket_index + delta;

            let check_buckets = if is_left_overflow {
                (None, self.buckets.get(right_index))
            } else {
                (self.buckets.get(left_index), self.buckets.get(right_index))
            };

            if check_buckets.0.is_none() && check_buckets.1.is_none() {
                break;
            }

            if let Some(left_bucket) = check_buckets.0 {
                closest_nodes.extend(left_bucket.nodes.lock().await.iter().map(|node_info| {
                    NodeAndDistance(node_info.clone(), node_info.id.distance(item))
                }));
            }

            if let Some(right_bucket) = check_buckets.1 {
                closest_nodes.extend(right_bucket.nodes.lock().await.iter().map(|node_info| {
                    NodeAndDistance(node_info.clone(), node_info.id.distance(item))
                }));
            }
        }

        closest_nodes.sort_by(|a, b| b.1.cmp(&a.1));
        closest_nodes.truncate(count);
        closest_nodes
    }

    pub async fn remove(&self, key: &DHTKey) {
        if let Some((bucket, _)) = self.get_bucket_by_key(key) {
            let mut nodes = bucket.nodes.lock().await;

            if let Some(item_index) = nodes.iter().position(|x| &x.id == key) {
                nodes.remove(item_index);
            } else {
                warn!("Tried to remove routing entry that doesn't exist.");
            }
        }
    }

    #[inline]
    fn get_bucket_by_key(&self, key: &DHTKey) -> Option<(&Kbucket, usize)> {
        let index = self.lookup_bucket_index(self.local_key.distance(key));
        self.buckets.get(index).zip(Some(index))
    }

    #[inline]
    pub fn print(&self) {
        info!("{:?}", self.buckets);
    }

    #[inline]
    fn lookup_bucket_index(&self, distance: Distance) -> usize {
        distance.zeroes_in_prefix()
    }
}
