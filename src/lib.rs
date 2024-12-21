#![cfg_attr(feature = "simd-unstable", feature(portable_simd))]

mod kademlia;
mod key;
mod routing;
mod rpc;

pub use kademlia::start;
pub use kademlia::Kademlia;
pub use key::Key;
pub use routing::NodeInfo;

/// Length of key in bytes
const KEY_LEN: usize = 32;
/// Number of buckets
const N_BUCKETS: usize = KEY_LEN * 8;
/// Entries per bucket
const K_PARAM: usize = 8;
/// Number of parallel requests
const A_PARAM: usize = 3;
/// Max message length
const MESSAGE_LEN: usize = 8196;
/// Default timeout
const TIMEOUT: u64 = 5000;
