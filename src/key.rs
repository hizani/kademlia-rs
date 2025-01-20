use const_hex::{FromHex, ToHexExt};
use dryoc::{dryocbox::PublicKey, types::ByteArray};
use hashes::sha2::sha256;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    fmt::{Debug, Display, Error, Formatter},
    str::FromStr,
};

#[cfg(feature = "simd-unstable")]
use std::simd;

use crate::KEY_LEN;

#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Clone, Deserialize, Serialize)]
pub struct DHTKey([u8; KEY_LEN]);

impl DHTKey {
    /// Initializes [DHTKey] with a random, [KEY_LEN] long array.
    #[inline]
    pub fn random() -> DHTKey {
        DHTKey(rand::random())
    }

    /// Returns the hashed [DHTKey] of data.
    pub fn hash(data: &[u8]) -> DHTKey {
        let hash = sha256::hash(data);
        DHTKey(hash.into_bytes())
    }

    #[inline]
    pub fn as_array(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// XORs two Keys.
    #[cfg(not(feature = "simd-unstable"))]
    pub fn distance(&self, y: &DHTKey) -> Distance {
        let mut result = [0; KEY_LEN];
        for (i, r) in result.iter_mut().enumerate() {
            *r = self.0[i] ^ y.0[i]
        }

        Distance(result)
    }

    /// XORs two Keys.
    #[cfg(feature = "simd-unstable")]
    pub fn distance(&self, y: &DHTKey) -> Distance {
        let simd1 = simd::Simd::<u8, 32>::from_array(self.0);
        let simd2 = simd::Simd::<u8, 32>::from_array(y.0);

        let result = simd1 ^ simd2;

        Distance(result.to_array())
    }
}

impl From<PublicKey> for DHTKey {
    #[inline]
    fn from(value: PublicKey) -> Self {
        DHTKey::from(value.as_array())
    }
}

impl From<&PublicKey> for &DHTKey {
    #[inline]
    fn from(value: &PublicKey) -> Self {
        unsafe { std::mem::transmute(value.as_array()) }
    }
}

impl From<DHTKey> for PublicKey {
    #[inline]
    fn from(value: DHTKey) -> Self {
        PublicKey::from(value.0)
    }
}

impl From<&DHTKey> for &PublicKey {
    #[inline]
    fn from(value: &DHTKey) -> Self {
        unsafe { std::mem::transmute(&value.0) }
    }
}

impl From<DHTKey> for [u8; KEY_LEN] {
    #[inline]
    fn from(value: DHTKey) -> Self {
        value.0
    }
}

impl From<[u8; KEY_LEN]> for DHTKey {
    #[inline]
    fn from(value: [u8; KEY_LEN]) -> Self {
        DHTKey(value)
    }
}

impl From<&[u8; KEY_LEN]> for DHTKey {
    #[inline]
    fn from(value: &[u8; KEY_LEN]) -> Self {
        DHTKey(*value)
    }
}

impl Display for DHTKey {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encode_hex_upper())
    }
}

impl Debug for DHTKey {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{}", self.encode_hex_with_prefix())
    }
}

impl FromStr for DHTKey {
    type Err = const_hex::FromHexError;
    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DHTKey::from_hex(s)
    }
}

impl AsRef<[u8]> for DHTKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FromHex for DHTKey {
    type Error = const_hex::FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut key = [0u8; KEY_LEN];
        const_hex::decode_to_slice(hex, &mut key)?;
        Ok(DHTKey(key))
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct Distance([u8; KEY_LEN]);

impl Distance {
    #[cfg(target_endian = "big")]
    pub fn zeroes_in_prefix(&self) -> usize {
        let mut zeroes_count = 0;

        for n in self.0 {
            if n == 0 {
                zeroes_count += 8;
                continue;
            }

            zeroes_count += n.trailing_zeros() as usize;

            break;
        }

        zeroes_count
    }

    #[cfg(target_endian = "little")]
    pub fn zeroes_in_prefix(&self) -> usize {
        let mut zeroes_count = 0;

        for n in self.0 {
            if n == 0 {
                zeroes_count += 8;
                continue;
            }

            zeroes_count += n.leading_zeros() as usize;

            break;
        }

        zeroes_count
    }
}

impl Ord for Distance {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for (x, y) in self.0.iter().zip(other.0.iter()) {
            match x.cmp(y) {
                Ordering::Equal => continue,
                Ordering::Greater => return Ordering::Greater,
                Ordering::Less => return Ordering::Less,
            }
        }

        Ordering::Equal
    }
}

impl PartialOrd for Distance {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
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
    #[inline]
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
