use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, net::SocketAddr, ops::Index, sync::Mutex};

use crate::{
    key::{Distance, Key},
    K_PARAM, N_BUCKETS,
};

#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: Key,
    pub addr: SocketAddr,
    pub net_id: String,
}

#[derive(Debug)]
pub struct RoutingTable {
    node_info: NodeInfo,
    buckets: Vec<Mutex<Vec<NodeInfo>>>,
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
    pub fn new(node_info: NodeInfo) -> RoutingTable {
        let mut buckets = Vec::with_capacity(N_BUCKETS);
        for i in (1..=N_BUCKETS).rev() {
            buckets.push(Mutex::new(Vec::with_capacity(i.min(K_PARAM))));
        }
        let routing_rable = RoutingTable {
            buckets,
            node_info: node_info.clone(),
        };
        routing_rable
    }

    /// Update the appropriate bucket with the new node's info
    pub fn update(&self, node_info: NodeInfo) {
        let bucket_index =
            if let Some(bi) = self.lookup_bucket_index(self.node_info.id.distance(&node_info.id)) {
                bi
            } else {
                return;
            };

        let mut bucket = self.buckets[bucket_index].lock().unwrap();
        let node_index = bucket.iter().position(|x| x.id == node_info.id);
        match node_index {
            Some(i) => {
                let temp = bucket.remove(i);
                bucket.push(temp);
            }
            None => {
                if bucket.len() < K_PARAM {
                    bucket.push(node_info);
                } else {
                    // TODO: go through bucket, pinging nodes, replace one
                    // that doesn't respond.
                }
            }
        }
    }

    /// Lookup the nodes closest to item in this table
    pub fn closest_nodes(&self, item: &Key, count: usize) -> Vec<NodeAndDistance> {
        if count == 0 {
            return Vec::new();
        }

        let closest_bucket_index =
            if let Some(bi) = self.lookup_bucket_index(self.node_info.id.distance(item)) {
                bi
            } else {
                K_PARAM - 1
            };

        let closest_bucket = self.buckets.index(closest_bucket_index);

        let mut closest_nodes: Vec<NodeAndDistance> = Vec::with_capacity(count);
        closest_nodes.extend(
            closest_bucket
                .lock()
                .unwrap()
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
                closest_nodes.extend(left_bucket.lock().unwrap().iter().map(|node_info| {
                    NodeAndDistance(node_info.clone(), node_info.id.distance(item))
                }));
            }

            if let Some(right_bucket) = check_buckets.1 {
                closest_nodes.extend(right_bucket.lock().unwrap().iter().map(|node_info| {
                    NodeAndDistance(node_info.clone(), node_info.id.distance(item))
                }));
            }
        }

        closest_nodes.sort_by(|a, b| b.1.cmp(&a.1));
        closest_nodes.truncate(count);
        closest_nodes
    }

    pub fn remove(&self, key: &Key) {
        // TODO: Add fn get_bucket(key: &Key) and use it here to simplify the
        // code.
        let bucket_index =
            if let Some(bi) = self.lookup_bucket_index(self.node_info.id.distance(key)) {
                bi
            } else {
                return;
            };

        let mut bucket = self.buckets.index(bucket_index).lock().unwrap();
        if let Some(item_index) = bucket.iter().position(|x| &x.id == key) {
            bucket.remove(item_index);
        } else {
            warn!("Tried to remove routing entry that doesn't exist.");
        }
    }

    fn lookup_bucket_index(&self, distance: Distance) -> Option<usize> {
        match distance.zeroes_in_prefix() {
            bucket if bucket >= N_BUCKETS => None,
            bucket => Some(bucket),
        }
    }

    pub fn print(&self) {
        info!("{:?}", self.buckets);
    }
}
