#![cfg_attr(feature = "simd-unstable", feature(portable_simd))]

mod kademlia;
mod key;
mod routing;
mod rpc;
mod session;

pub use kademlia::start;
pub use kademlia::KademliaNode;
pub use key::DHTKey;
pub use routing::NodeInfo;

/// Length of key in bytes
const KEY_LEN: usize = dryoc::constants::CRYPTO_BOX_PUBLICKEYBYTES;
/// Number of buckets
const N_BUCKETS: usize = KEY_LEN * 8;
/// Entries per bucket
const K_PARAM: usize = 8;
/// Max message length
const MESSAGE_LEN: usize = 8196;
/// Default timeout
const TIMEOUT: u64 = 5000;
/// Number of parallel requests
const A_PARAM: u8 = 3;
