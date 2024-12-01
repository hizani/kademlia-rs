use const_hex::FromHex;
use hashes::sha1;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Error, Formatter},
    str::FromStr,
};

use crate::KEY_LEN;

#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Deserialize, Serialize)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    /// Returns a random, KEY_LEN long byte string.
    pub fn new() -> Key {
        Key(rand::random())
    }

    /// Returns the hashed Key of data.
    pub fn hash(data: &[u8]) -> Key {
        let hash = sha1::hash(data);
        Key(hash.into_bytes())
    }

    /// XORs two Keys
    pub fn distance(&self, y: Key) -> Distance {
        let mut res = [0; KEY_LEN];
        for i in 0usize..KEY_LEN {
            res[i] = self.0[i] ^ y.0[i];
        }
        Distance(res)
    }
}

impl Debug for Key {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        for x in self.0.iter() {
            write!(f, "{0:02x}", x)?;
        }
        Ok(())
    }
}

impl FromStr for Key {
    type Err = const_hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Key::from_hex(s)
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FromHex for Key {
    type Error = const_hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut key = [0u8; KEY_LEN];
        const_hex::decode_to_slice(hex, &mut key)?;
        Ok(Key(key))
    }
}

#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub struct Distance([u8; KEY_LEN]);

impl Distance {
    pub fn zeroes_in_prefix(&self) -> usize {
        for i in 0..KEY_LEN {
            for j in 8usize..0 {
                if (self.0[i] >> (7 - j)) & 0x1 != 0 {
                    return i * 8 + j;
                }
            }
        }
        KEY_LEN * 8 - 1
    }
}

impl Debug for Distance {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        for x in self.0.iter() {
            write!(f, "{0:02x}", x)?;
        }
        Ok(())
    }
}

impl AsRef<[u8]> for Distance {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FromHex for Distance {
    type Error = const_hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut distance = [0u8; KEY_LEN];
        const_hex::decode_to_slice(hex, &mut distance)?;
        Ok(Distance(distance))
    }
}
